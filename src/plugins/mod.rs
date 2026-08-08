//! Bounded, host-owned extension runtime.
//!
//! Extensions are pure JavaScript orchestration. They can describe semantic
//! HTTP operations, but they receive no filesystem, process, or socket APIs;
//! HuntProxy validates and executes every operation and persists its evidence.

use crate::domain::*;
use crate::policy::url_is_in_scope;
use crate::reply::{ReplySendContext, ReplyService};
use base64::Engine;
use dashmap::DashMap;
use futures::{stream, StreamExt};
use rquickjs::{Context, Runtime};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const PLUGIN_API_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_SCRIPT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RESOURCE_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_RESOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_BODY_FOR_PLUGIN: usize = 256 * 1024;
const MAX_RAW_REQUEST_CONTEXT: usize = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u64 = 120_000;
const MAX_TIMEOUT_MS: u64 = 15 * 60_000;
const DEFAULT_MAX_OPERATIONS: usize = 100;
const MAX_OPERATIONS: usize = 10_000;
const DEFAULT_MEMORY_MB: usize = 16;
const MAX_MEMORY_MB: usize = 64;
const DEFAULT_JS_STAGE_TIMEOUT_MS: u64 = 2_000;
const MAX_JS_STAGE_TIMEOUT_MS: u64 = 15_000;
const MAX_ACTIVE_JOBS: usize = 4;
const MAX_RETAINED_JOBS: usize = 256;
const MAX_WORKFLOW_STEPS: usize = 64;
const MAX_WORKFLOW_EXTRACTS_PER_STEP: usize = 16;
const MAX_WORKFLOW_VALUE_BYTES: usize = 8 * 1024;
const MAX_WORKFLOW_VALUES_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub enabled: bool,
    pub entrypoint: String,
    /// Hex SHA-256 of the exact entrypoint bytes. This prevents unnoticed
    /// changes after a package has been reviewed/installed.
    pub entrypoint_sha256: String,
    #[serde(default)]
    pub resources: HashMap<String, PluginResource>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub actions: Vec<PluginAction>,
    #[serde(default)]
    pub limits: PluginLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResource {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginAction {
    pub name: String,
    pub description: String,
    #[serde(default = "object_schema")]
    pub input_schema: Value,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
}

fn object_schema() -> Value {
    json!({"type":"object"})
}

fn max_requested_exchange_contexts(manifest: &PluginManifest) -> usize {
    manifest
        .limits
        .max_operations
        .unwrap_or(DEFAULT_MAX_OPERATIONS)
        .clamp(1, MAX_OPERATIONS)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginLimits {
    pub timeout_ms: Option<u64>,
    /// CPU wall-clock budget for each synchronous QuickJS plan/analyze stage.
    /// Network execution remains governed by `timeout_ms`.
    pub js_stage_timeout_ms: Option<u64>,
    pub max_operations: Option<usize>,
    pub max_concurrency: Option<usize>,
    pub memory_mb: Option<usize>,
}

#[derive(Debug, Clone)]
struct LoadedPlugin {
    manifest: PluginManifest,
    script: Arc<str>,
    resources: Arc<HashMap<String, String>>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginJobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginJobView {
    pub id: Uuid,
    pub project_id: ProjectId,
    pub plugin_id: String,
    pub action: String,
    pub base_exchange_id: Option<ExchangeId>,
    pub state: PluginJobState,
    pub operation_count: usize,
    pub completed_operations: usize,
    pub result: Option<Value>,
    pub error: Option<String>,
}

struct PluginJob {
    view: parking_lot::RwLock<PluginJobView>,
    cancel: CancellationToken,
}

#[derive(Clone)]
pub struct PluginService {
    directory: PathBuf,
    reply: Arc<ReplyService>,
    db: Arc<crate::storage::Db>,
    plugins: Arc<HashMap<String, Arc<LoadedPlugin>>>,
    jobs: Arc<DashMap<Uuid, Arc<PluginJob>>>,
    active_jobs: Arc<tokio::sync::Semaphore>,
}

#[derive(Debug, Deserialize)]
struct PluginPlan {
    #[serde(default)]
    operations: Vec<PluginOperation>,
    #[serde(default)]
    result: Value,
    #[serde(default)]
    execution: PluginExecution,
    #[serde(default)]
    stop_on_error: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PluginExecution {
    #[default]
    Parallel,
    Sequential,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PluginOperation {
    HttpRequest(PluginHttpRequest),
    HttpWorkflow(PluginHttpWorkflow),
    RawHttp1(PluginRawHttp1),
    RawHttp2(PluginRawHttp2),
    RaceGroup(PluginRaceGroup),
}

impl PluginOperation {
    fn id(&self) -> &str {
        match self {
            Self::HttpRequest(request) => &request.id,
            Self::HttpWorkflow(workflow) => &workflow.id,
            Self::RawHttp1(request) => &request.id,
            Self::RawHttp2(request) => &request.id,
            Self::RaceGroup(group) => &group.id,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct PluginRaceGroup {
    id: String,
    technique: RaceTechnique,
    attempt: u64,
    requests: Vec<RaceRequest>,
    #[serde(default)]
    options: RaceOptions,
}

#[derive(Debug, Clone, Deserialize)]
struct RaceRequest {
    id: String,
    base_exchange_id: Option<ExchangeId>,
    method: Option<String>,
    url: Option<String>,
    #[serde(default)]
    headers: Vec<HeaderPatch>,
    #[serde(default)]
    header_tombstones: Vec<String>,
    body_text: Option<String>,
    body_base64: Option<String>,
    #[serde(default)]
    protocol: ProtocolPreference,
    #[serde(default)]
    use_project_cookies: bool,
    success: Option<RaceSuccessPredicate>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RaceSuccessPredicate {
    #[serde(default)]
    status_codes: Vec<u16>,
    #[serde(default)]
    headers: Vec<RaceHeaderPredicate>,
    body_contains: Option<String>,
    body_regex: Option<String>,
    #[serde(default)]
    json: Vec<RaceJsonPredicate>,
    redirect_location: Option<RaceTextPredicate>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RaceHeaderPredicate {
    name: String,
    #[serde(flatten)]
    value: RaceTextPredicate,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RaceTextPredicate {
    equals: Option<String>,
    contains: Option<String>,
    regex: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RaceJsonPredicate {
    pointer: String,
    equals: Option<Value>,
    exists: Option<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RaceTechnique {
    SequentialControl,
    Parallel,
    LastByteSync,
    H2SinglePacket,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RaceOptions {
    timeout_ms: Option<u64>,
    hold_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct PluginRawHttp1 {
    id: String,
    target_url: String,
    request_utf8: Option<String>,
    request_base64: Option<String>,
    #[serde(default)]
    use_project_cookies: bool,
    #[serde(default)]
    options: crate::reply::RawHttp1Options,
}

#[derive(Debug, Clone, Deserialize)]
struct PluginRawHttp2 {
    id: String,
    target_url: String,
    streams: Vec<crate::reply::RawHttp2Stream>,
    #[serde(default)]
    options: crate::reply::RawHttp2Options,
}

#[derive(Debug, Clone, Deserialize)]
struct PluginHttpRequest {
    id: String,
    base_exchange_id: Option<ExchangeId>,
    method: Option<String>,
    url: Option<String>,
    #[serde(default)]
    headers: Vec<HeaderPatch>,
    #[serde(default)]
    header_tombstones: Vec<String>,
    body_text: Option<String>,
    body_base64: Option<String>,
    #[serde(default)]
    protocol: ProtocolPreference,
    #[serde(default)]
    query_params: Vec<PluginParamPatch>,
    #[serde(default)]
    cookie_params: Vec<PluginParamPatch>,
    #[serde(default)]
    body_params: Vec<PluginParamPatch>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginHttpWorkflow {
    id: String,
    steps: Vec<PluginHttpWorkflowStep>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginHttpWorkflowStep {
    id: String,
    request: PluginHttpRequest,
    #[serde(default)]
    extract: Vec<PluginWorkflowExtract>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
enum PluginWorkflowExtract {
    BodyRegex {
        name: String,
        pattern: String,
        #[serde(default = "default_capture_group")]
        group: usize,
        #[serde(default)]
        encoding: PluginWorkflowEncoding,
        #[serde(default = "default_true")]
        required: bool,
    },
    Header {
        name: String,
        header: String,
        #[serde(default)]
        encoding: PluginWorkflowEncoding,
        #[serde(default = "default_true")]
        required: bool,
    },
    Json {
        name: String,
        pointer: String,
        #[serde(default)]
        encoding: PluginWorkflowEncoding,
        #[serde(default = "default_true")]
        required: bool,
    },
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PluginWorkflowEncoding {
    #[default]
    Raw,
    Url,
    Json,
    Base64,
}

impl PluginWorkflowExtract {
    fn name(&self) -> &str {
        match self {
            Self::BodyRegex { name, .. } | Self::Header { name, .. } | Self::Json { name, .. } => {
                name
            }
        }
    }

    fn encoding(&self) -> PluginWorkflowEncoding {
        match self {
            Self::BodyRegex { encoding, .. }
            | Self::Header { encoding, .. }
            | Self::Json { encoding, .. } => *encoding,
        }
    }

    fn required(&self) -> bool {
        match self {
            Self::BodyRegex { required, .. }
            | Self::Header { required, .. }
            | Self::Json { required, .. } => *required,
        }
    }

    fn validate(&self) -> DomainResult<()> {
        match self {
            Self::BodyRegex { pattern, group, .. } => {
                if pattern.len() > 2048 {
                    return Err(DomainError::new(
                        ErrorCode::CombinationLimit,
                        "http_workflow body regex exceeds 2048 bytes",
                    ));
                }
                let regex = regex::Regex::new(pattern).map_err(|error| {
                    DomainError::invalid(format!("invalid http_workflow body regex: {error}"))
                })?;
                if *group >= regex.captures_len() {
                    return Err(DomainError::invalid(format!(
                        "http_workflow body regex has no capture group {group}"
                    )));
                }
            }
            Self::Header { header, .. } => {
                if header.trim().is_empty() || header.contains(['\r', '\n']) {
                    return Err(DomainError::invalid(
                        "http_workflow extract header must be a valid header name",
                    ));
                }
            }
            Self::Json { pointer, .. } => {
                if !pointer.is_empty() && !pointer.starts_with('/') {
                    return Err(DomainError::invalid(
                        "http_workflow JSON pointer must be empty or start with /",
                    ));
                }
            }
        }
        Ok(())
    }

    fn extract(&self, observation: &Value) -> DomainResult<Option<String>> {
        let raw = match self {
            Self::BodyRegex { pattern, group, .. } => {
                let body = workflow_response_body(observation)?;
                let body = std::str::from_utf8(&body).map_err(|_| {
                    DomainError::invalid("http_workflow body regex requires a UTF-8 response body")
                })?;
                let regex = regex::Regex::new(pattern).map_err(|error| {
                    DomainError::invalid(format!("invalid http_workflow body regex: {error}"))
                })?;
                regex
                    .captures(body)
                    .and_then(|captures| captures.get(*group))
                    .map(|matched| matched.as_str().as_bytes().to_vec())
            }
            Self::Header { header, .. } => observation
                .get("response_headers")
                .and_then(Value::as_array)
                .and_then(|headers| {
                    headers.iter().find(|candidate| {
                        candidate
                            .get("name")
                            .and_then(Value::as_str)
                            .is_some_and(|name| name.eq_ignore_ascii_case(header))
                    })
                })
                .and_then(|header| header.get("value_base64"))
                .and_then(Value::as_str)
                .map(|value| {
                    base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .map_err(|error| {
                            DomainError::invalid(format!(
                                "invalid stored response header encoding: {error}"
                            ))
                        })
                })
                .transpose()?,
            Self::Json { pointer, .. } => {
                let body = workflow_response_body(observation)?;
                let document: Value = serde_json::from_slice(&body).map_err(|error| {
                    DomainError::invalid(format!(
                        "http_workflow could not parse response JSON: {error}"
                    ))
                })?;
                document.pointer(pointer).map(|value| match value {
                    Value::String(value) => value.as_bytes().to_vec(),
                    other => other.to_string().into_bytes(),
                })
            }
        };
        match raw {
            Some(raw) => Ok(Some(encode_workflow_value(&raw, self.encoding())?)),
            None if self.required() => Err(DomainError::invalid(format!(
                "required http_workflow extract {} was not found",
                self.name()
            ))),
            None => Ok(None),
        }
    }
}

fn default_capture_group() -> usize {
    1
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
struct PluginParamPatch {
    name: String,
    /// Null removes an existing parameter; a string sets/replaces it.
    value: Option<String>,
}

impl PluginService {
    pub fn load(
        directory: PathBuf,
        db: Arc<crate::storage::Db>,
        reply: Arc<ReplyService>,
    ) -> DomainResult<Self> {
        crate::config::create_private_dir(&directory)?;
        let mut plugins = HashMap::new();
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            DomainError::new(
                ErrorCode::StorageError,
                format!("read plugin directory: {error}"),
            )
        })?;
        for entry in entries {
            let entry = match entry {
                Ok(entry) if entry.path().is_dir() => entry,
                Ok(_) => continue,
                Err(error) => {
                    tracing::warn!(%error, "skipping unreadable plugin directory entry");
                    continue;
                }
            };
            match load_plugin(&entry.path()) {
                Ok(plugin) => {
                    if plugins
                        .insert(plugin.manifest.id.clone(), Arc::new(plugin))
                        .is_some()
                    {
                        return Err(DomainError::new(
                            ErrorCode::ConfigInvalid,
                            "duplicate plugin id",
                        ));
                    }
                }
                Err(error) => {
                    tracing::warn!(path=%entry.path().display(), %error, "plugin rejected")
                }
            }
        }
        Ok(Self {
            directory,
            reply,
            db,
            plugins: Arc::new(plugins),
            jobs: Arc::new(DashMap::new()),
            active_jobs: Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_JOBS)),
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn list(&self) -> Vec<PluginManifest> {
        let mut plugins = self
            .plugins
            .values()
            .map(|plugin| plugin.manifest.clone())
            .collect::<Vec<_>>();
        plugins.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        plugins
    }

    pub fn describe(&self, id: &str) -> DomainResult<PluginManifest> {
        self.plugins
            .get(id)
            .map(|plugin| plugin.manifest.clone())
            .ok_or_else(|| DomainError::not_found(format!("plugin {id}")))
    }

    pub async fn run(
        &self,
        project_id: ProjectId,
        plugin_id: &str,
        action: &str,
        base_exchange_id: Option<ExchangeId>,
        input: Value,
    ) -> DomainResult<PluginJobView> {
        let input_bytes = serde_json::to_vec(&input)
            .map_err(|error| DomainError::invalid(format!("invalid plugin input: {error}")))?;
        if input_bytes.len() > MAX_INPUT_BYTES {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                "plugin input exceeds 2 MiB",
            ));
        }
        let plugin = self
            .plugins
            .get(plugin_id)
            .cloned()
            .ok_or_else(|| DomainError::not_found(format!("plugin {plugin_id}")))?;
        if !plugin.manifest.enabled {
            return Err(DomainError::new(
                ErrorCode::Forbidden,
                format!("plugin {plugin_id} is installed but disabled"),
            ));
        }
        let action_manifest = plugin
            .manifest
            .actions
            .iter()
            .find(|candidate| candidate.name == action)
            .ok_or_else(|| DomainError::not_found(format!("plugin action {action}")))?;
        let declared = plugin.manifest.capabilities.iter().collect::<BTreeSet<_>>();
        if action_manifest
            .required_capabilities
            .iter()
            .any(|capability| !declared.contains(capability))
        {
            return Err(DomainError::new(
                ErrorCode::ConfigInvalid,
                "plugin action requires an undeclared capability",
            ));
        }
        self.db.get_project(project_id).await?;

        self.prune_finished_jobs();
        let active_job_permit = self.active_jobs.clone().try_acquire_owned().map_err(|_| {
            DomainError::new(
                ErrorCode::ConcurrencyLimited,
                format!("at most {MAX_ACTIVE_JOBS} extension jobs may run at once"),
            )
        })?;

        let id = Uuid::new_v4();
        let job = Arc::new(PluginJob {
            view: parking_lot::RwLock::new(PluginJobView {
                id,
                project_id,
                plugin_id: plugin_id.into(),
                action: action.into(),
                base_exchange_id,
                state: PluginJobState::Queued,
                operation_count: 0,
                completed_operations: 0,
                result: None,
                error: None,
            }),
            cancel: CancellationToken::new(),
        });
        self.jobs.insert(id, job.clone());
        let service = self.clone();
        let action = action.to_string();
        tokio::spawn(async move {
            let _active_job_permit = active_job_permit;
            service.execute_job(job, plugin, action, input).await;
        });
        Ok(self.status(id)?)
    }

    pub fn status(&self, id: Uuid) -> DomainResult<PluginJobView> {
        self.jobs
            .get(&id)
            .map(|job| job.view.read().clone())
            .ok_or_else(|| DomainError::not_found("plugin job"))
    }

    pub fn cancel(&self, id: Uuid) -> DomainResult<PluginJobView> {
        let job = self
            .jobs
            .get(&id)
            .ok_or_else(|| DomainError::not_found("plugin job"))?;
        job.cancel.cancel();
        let view = job.view.read().clone();
        Ok(view)
    }

    pub fn has_active_jobs(&self) -> bool {
        self.jobs.iter().any(|job| {
            matches!(
                job.view.read().state,
                PluginJobState::Queued | PluginJobState::Running
            )
        })
    }

    fn prune_finished_jobs(&self) {
        prune_finished_jobs(&self.jobs);
    }

    async fn execute_job(
        &self,
        job: Arc<PluginJob>,
        plugin: Arc<LoadedPlugin>,
        action: String,
        input: Value,
    ) {
        job.view.write().state = PluginJobState::Running;
        let timeout_ms = plugin
            .manifest
            .limits
            .timeout_ms
            .unwrap_or(DEFAULT_TIMEOUT_MS)
            .clamp(1_000, MAX_TIMEOUT_MS);
        let result = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            self.execute_job_inner(job.clone(), plugin, &action, &input),
        )
        .await;
        let mut view = job.view.write();
        match result {
            Ok(Ok(result)) => {
                view.state = PluginJobState::Completed;
                view.result = Some(result);
            }
            Ok(Err(error)) if error.code() == ErrorCode::Cancelled => {
                view.state = PluginJobState::Cancelled;
                view.error = Some(error.to_string());
            }
            Ok(Err(error)) => {
                view.state = PluginJobState::Failed;
                view.error = Some(error.to_string());
            }
            Err(_) => {
                job.cancel.cancel();
                view.state = PluginJobState::Failed;
                view.error = Some(format!("plugin job timed out after {timeout_ms} ms"));
            }
        }
    }

    async fn execute_job_inner(
        &self,
        job: Arc<PluginJob>,
        plugin: Arc<LoadedPlugin>,
        action: &str,
        input: &Value,
    ) -> DomainResult<Value> {
        let (project_id, base_exchange_id) = {
            let view = job.view.read();
            (view.project_id, view.base_exchange_id)
        };
        let privileged_identity = plugin
            .manifest
            .capabilities
            .iter()
            .any(|capability| capability == "identity.use");
        let raw_request_access = plugin
            .manifest
            .capabilities
            .iter()
            .any(|capability| capability == "http.raw");
        let base_exchange = self
            .plugin_exchange_context(
                project_id,
                base_exchange_id,
                privileged_identity,
                raw_request_access,
            )
            .await?;
        let related_exchanges = self
            .related_exchange_contexts(
                project_id,
                input,
                max_requested_exchange_contexts(&plugin.manifest),
            )
            .await?;
        let context = json!({
            "api_version": PLUGIN_API_VERSION,
            "plugin_id": plugin.manifest.id,
            "plugin_version": plugin.manifest.version,
            "action": action,
            "project_id": project_id.get(),
            "base_exchange": base_exchange,
            "related_exchanges": related_exchanges,
            "resources": &*plugin.resources,
        });
        let plan_value = run_js_stage(&plugin, "plan", input, &Value::Null, &context).await?;
        let plan: PluginPlan = serde_json::from_value(plan_value)
            .map_err(|error| DomainError::invalid(format!("invalid plugin plan: {error}")))?;
        if plan.stop_on_error && plan.execution != PluginExecution::Sequential {
            return Err(DomainError::invalid(
                "stop_on_error requires execution=sequential",
            ));
        }
        let max_operations = plugin
            .manifest
            .limits
            .max_operations
            .unwrap_or(DEFAULT_MAX_OPERATIONS)
            .clamp(1, MAX_OPERATIONS);
        let planned_requests = plan
            .operations
            .iter()
            .try_fold(0usize, |count, operation| {
                count.checked_add(operation_request_count(operation))
            })
            .unwrap_or(usize::MAX);
        if planned_requests > max_operations {
            return Err(DomainError::new(
                ErrorCode::CombinationLimit,
                format!("plugin planned {planned_requests} requests; limit is {max_operations}",),
            ));
        }
        for operation in &plan.operations {
            let required = match operation {
                PluginOperation::HttpRequest(_) => "http.semantic",
                PluginOperation::HttpWorkflow(_) => "http.semantic",
                PluginOperation::RawHttp1(_) => "http.raw",
                PluginOperation::RawHttp2(_) => "http.raw",
                PluginOperation::RaceGroup(_) => "http.race",
            };
            if !plugin
                .manifest
                .capabilities
                .iter()
                .any(|item| item == required)
            {
                return Err(DomainError::new(
                    ErrorCode::Forbidden,
                    format!("plugin operation requires {required} capability"),
                ));
            }
        }
        job.view.write().operation_count = planned_requests;
        let project_id = job.view.read().project_id;
        let project = self.db.get_project(project_id).await?;
        let concurrency = plugin
            .manifest
            .limits
            .max_concurrency
            .unwrap_or(4)
            .clamp(1, project.limits.max_concurrent_requests.max(1) as usize);
        let target_host = url::Url::parse(&project.target_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_ascii_lowercase));
        let rate = project.limits.requests_per_second.max(0.1);
        let operations = if plan.execution == PluginExecution::Sequential {
            let mut observations = Vec::with_capacity(plan.operations.len());
            let mut operations = plan.operations.into_iter().peekable();
            let mut index = 0usize;
            while let Some(operation) = operations.next() {
                if index > 0 {
                    tokio::select! {
                        _ = job.cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                        _ = tokio::time::sleep(Duration::from_secs_f64(1.0 / rate)) => {}
                    }
                }
                let operation_id = operation.id().to_string();
                let completed_count = operation_request_count(&operation);
                let result = self
                    .execute_operation(
                        project_id,
                        &plugin.manifest.id,
                        &plugin.manifest.name,
                        operation,
                        &project.scope,
                        target_host.as_deref(),
                        &job.cancel,
                    )
                    .await;
                job.view.write().completed_operations += completed_count;
                let observation = isolate_operation_result(operation_id, result);
                let failed = observation
                    .as_ref()
                    .ok()
                    .is_some_and(|value| value.get("error").is_some_and(|error| !error.is_null()));
                observations.push(observation);
                if failed && plan.stop_on_error {
                    for skipped in operations {
                        observations.push(Ok(json!({
                            "id": skipped.id(),
                            "skipped": {"reason":"previous operation failed"},
                        })));
                    }
                    break;
                }
                index += 1;
            }
            observations
        } else {
            stream::iter(plan.operations.into_iter().enumerate().map(|(index, operation)| {
                let service = self.clone();
                let job = job.clone();
                let plugin_id = plugin.manifest.id.clone();
                let plugin_name = plugin.manifest.name.clone();
                let scope = project.scope.clone();
                let target_host = target_host.clone();
                async move {
                    let operation_id = operation.id().to_string();
                    let completed_count = operation_request_count(&operation);
                    let wait = Duration::from_secs_f64(index as f64 / rate);
                    tokio::select! {
                        _ = job.cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                        _ = tokio::time::sleep(wait) => {}
                    }
                    let result = service
                        .execute_operation(project_id, &plugin_id, &plugin_name, operation, &scope, target_host.as_deref(), &job.cancel)
                        .await;
                    job.view.write().completed_operations += completed_count;
                    isolate_operation_result(operation_id, result)
                }
            }))
            .buffer_unordered(concurrency)
            .collect::<Vec<_>>()
            .await
        };
        let observations = operations.into_iter().collect::<DomainResult<Vec<_>>>()?;
        if job.cancel.is_cancelled() {
            return Err(DomainError::new(
                ErrorCode::Cancelled,
                "plugin job cancelled",
            ));
        }
        let analyzed =
            run_js_stage(&plugin, "analyze", input, &json!(observations), &context).await?;
        let analyzed = self
            .redact_plugin_output(project_id, base_exchange_id, analyzed)
            .await?;
        let mut persisted_findings = Vec::new();
        if let Some(findings) = analyzed.get("findings").and_then(Value::as_array) {
            if findings.len() > 1000 {
                return Err(DomainError::new(
                    ErrorCode::CombinationLimit,
                    "plugin returned more than 1000 findings",
                ));
            }
            for finding in findings {
                let title = finding
                    .get("title")
                    .and_then(Value::as_str)
                    .ok_or_else(|| DomainError::invalid("plugin finding requires title"))?;
                let evidence = finding
                    .get("evidence_exchange_ids")
                    .and_then(Value::as_array)
                    .map(|ids| {
                        ids.iter()
                            .map(|id| {
                                id.as_i64().map(ExchangeId).ok_or_else(|| {
                                    DomainError::invalid(
                                        "evidence_exchange_ids must contain integers",
                                    )
                                })
                            })
                            .collect::<DomainResult<Vec<_>>>()
                    })
                    .transpose()?
                    .or_else(|| {
                        finding
                            .get("exchange_id")
                            .and_then(Value::as_i64)
                            .map(|id| vec![ExchangeId(id)])
                    })
                    .ok_or_else(|| {
                        DomainError::invalid("plugin finding requires evidence_exchange_ids")
                    })?;
                let exchange_id = *evidence.first().ok_or_else(|| {
                    DomainError::invalid("plugin finding requires at least one evidence exchange")
                })?;
                for evidence_id in &evidence {
                    self.db
                        .get_exchange_detail(
                            project_id,
                            *evidence_id,
                            crate::policy::PresentationOptions::default(),
                        )
                        .await?;
                }
                let description = if let Some(description) =
                    finding.get("description").and_then(Value::as_str)
                {
                    description.to_string()
                } else {
                    let severity = finding
                        .get("severity")
                        .and_then(Value::as_str)
                        .unwrap_or("unspecified");
                    let confidence = finding
                        .get("confidence")
                        .and_then(Value::as_str)
                        .unwrap_or("unspecified");
                    let explanation = finding
                        .get("explanation")
                        .and_then(Value::as_str)
                        .unwrap_or("No explanation supplied.");
                    let remediation = finding
                        .get("remediation")
                        .and_then(Value::as_str)
                        .unwrap_or("No remediation supplied.");
                    format!("Severity: {severity}\nConfidence: {confidence}\n\n{explanation}\n\nRemediation: {remediation}\n\nEvidence exchanges: {}", evidence.iter().map(|id| id.get().to_string()).collect::<Vec<_>>().join(", "))
                };
                persisted_findings.push(
                    self.db
                        .create_finding(project_id, exchange_id, title.into(), description)
                        .await?,
                );
            }
        }
        let result = json!({"plan_result": plan.result, "analysis": analyzed, "persisted_findings": persisted_findings});
        let result = self
            .redact_plugin_output(project_id, base_exchange_id, result)
            .await?;
        if serde_json::to_vec(&result)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX)
            > MAX_RESULT_BYTES
        {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                "plugin result exceeds 8 MiB",
            ));
        }
        Ok(result)
    }

    async fn redact_plugin_output(
        &self,
        project_id: ProjectId,
        base_exchange_id: Option<ExchangeId>,
        mut value: Value,
    ) -> DomainResult<Value> {
        let mut secrets = Vec::new();
        if let Some(exchange_id) = base_exchange_id {
            for header in self
                .db
                .load_raw_headers(project_id, exchange_id, MessageSide::Request)
                .await?
            {
                if crate::policy::is_sensitive_header(&header.name) && !header.value.is_empty() {
                    if let Ok(text) = String::from_utf8(header.value.clone()) {
                        secrets.push(text);
                    }
                    secrets.push(base64::engine::general_purpose::STANDARD.encode(header.value));
                }
            }
        }
        redact_value(&mut value, &secrets, None);
        Ok(value)
    }

    async fn plugin_exchange_context(
        &self,
        project_id: ProjectId,
        exchange_id: Option<ExchangeId>,
        privileged_identity: bool,
        raw_request_access: bool,
    ) -> DomainResult<Value> {
        let Some(exchange_id) = exchange_id else {
            return Ok(Value::Null);
        };
        let detail = self
            .db
            .get_exchange_detail(
                project_id,
                exchange_id,
                crate::policy::PresentationOptions::default(),
            )
            .await?;
        let query = detail
            .summary
            .query
            .as_ref()
            .map(|query| format!("?{query}"))
            .unwrap_or_default();
        let mut context = json!({
            "exchange_id": exchange_id,
            "method": detail.summary.method.clone(),
            "url": format!("{}://{}{}{}", detail.summary.scheme, detail.summary.authority, detail.summary.path, query),
            "headers": detail.request_headers.clone(),
            "request_length": detail.summary.request_length,
            "request_body_hash": detail.request_body_hash.clone(),
            "request_preview": detail.request_preview.clone(),
        });
        if privileged_identity {
            let raw_headers = self
                .db
                .load_raw_headers(project_id, exchange_id, MessageSide::Request)
                .await?;
            let mut body = self
                .db
                .load_raw_body(project_id, exchange_id, MessageSide::Request)
                .await?
                .unwrap_or_default();
            let body_truncated = body.len() > MAX_RESPONSE_BODY_FOR_PLUGIN;
            body.truncate(MAX_RESPONSE_BODY_FOR_PLUGIN);
            context["identity"] = json!({
                "request_headers": raw_headers.into_iter().map(|header| json!({
                    "name": header.name,
                    "value_base64": base64::engine::general_purpose::STANDARD.encode(header.value),
                })).collect::<Vec<_>>(),
                "request_body_base64": base64::engine::general_purpose::STANDARD.encode(body),
                "request_body_truncated": body_truncated,
            });
        }
        if raw_request_access {
            let raw_headers = self
                .db
                .load_raw_headers(project_id, exchange_id, MessageSide::Request)
                .await?;
            let body = self
                .db
                .load_raw_body(project_id, exchange_id, MessageSide::Request)
                .await?
                .unwrap_or_default();
            let target = format!(
                "{}{}",
                detail.summary.path,
                detail
                    .summary
                    .query
                    .as_ref()
                    .map(|query| format!("?{query}"))
                    .unwrap_or_default()
            );
            let mut raw = format!("{} {} HTTP/1.1\r\n", detail.summary.method, target).into_bytes();
            for header in raw_headers {
                raw.extend_from_slice(header.name.as_bytes());
                raw.extend_from_slice(b": ");
                raw.extend_from_slice(&header.value);
                raw.extend_from_slice(b"\r\n");
            }
            raw.extend_from_slice(b"\r\n");
            raw.extend_from_slice(&body);
            if raw.len() <= MAX_RAW_REQUEST_CONTEXT {
                context["raw_request_base64"] =
                    Value::String(base64::engine::general_purpose::STANDARD.encode(raw));
                context["raw_request_reconstructed"] = Value::Bool(true);
            } else {
                context["raw_request_omitted"] = Value::Bool(true);
            }
        }
        Ok(context)
    }

    async fn related_exchange_contexts(
        &self,
        project_id: ProjectId,
        input: &Value,
        limit: usize,
    ) -> DomainResult<Vec<Value>> {
        let ids = input
            .get("exchange_ids")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if ids.len() > limit {
            return Err(DomainError::new(
                ErrorCode::CombinationLimit,
                format!("exchange_ids exceeds context limit {limit}"),
            ));
        }
        let mut contexts = Vec::with_capacity(ids.len());
        for id in ids {
            let id = id
                .as_i64()
                .map(ExchangeId)
                .ok_or_else(|| DomainError::invalid("exchange_ids must contain integers"))?;
            let detail = self
                .db
                .get_exchange_detail(
                    project_id,
                    id,
                    crate::policy::PresentationOptions::default(),
                )
                .await?;
            let query = detail
                .summary
                .query
                .as_ref()
                .map(|query| format!("?{query}"))
                .unwrap_or_default();
            contexts.push(json!({
                "exchange_id": id,
                "method": detail.summary.method,
                "url": format!("{}://{}{}{}", detail.summary.scheme, detail.summary.authority, detail.summary.path, query),
                "status_code": detail.summary.status_code,
            }));
        }
        Ok(contexts)
    }

    async fn execute_http_workflow(
        &self,
        project_id: ProjectId,
        plugin_id: &str,
        plugin_name: &str,
        workflow: PluginHttpWorkflow,
        scope: &ScopePolicy,
        target_host: Option<&str>,
        cancel: &CancellationToken,
    ) -> DomainResult<Value> {
        validate_workflow_name(&workflow.id, "id")?;
        if workflow.steps.is_empty() || workflow.steps.len() > MAX_WORKFLOW_STEPS {
            return Err(DomainError::new(
                ErrorCode::CombinationLimit,
                format!("http_workflow requires 1..={MAX_WORKFLOW_STEPS} steps"),
            ));
        }
        let project = self.db.get_project(project_id).await?;
        let rate = project.limits.requests_per_second.max(0.1);
        let mut step_ids = BTreeSet::new();
        let mut extract_names = BTreeSet::new();
        for step in &workflow.steps {
            validate_workflow_name(&step.id, "step id")?;
            if !step_ids.insert(step.id.clone()) {
                return Err(DomainError::invalid(format!(
                    "duplicate http_workflow step id: {}",
                    step.id
                )));
            }
            if step.extract.len() > MAX_WORKFLOW_EXTRACTS_PER_STEP {
                return Err(DomainError::new(
                    ErrorCode::CombinationLimit,
                    format!(
                        "http_workflow step {} exceeds {MAX_WORKFLOW_EXTRACTS_PER_STEP} extracts",
                        step.id
                    ),
                ));
            }
            for extract in &step.extract {
                let name = extract.name();
                validate_workflow_name(name, "extract name")?;
                if !extract_names.insert(name.to_string()) {
                    return Err(DomainError::invalid(format!(
                        "duplicate http_workflow extract name: {name}"
                    )));
                }
                extract.validate()?;
            }
        }

        let workflow_id = workflow.id;
        let mut values = HashMap::<String, String>::new();
        let mut total_value_bytes = 0usize;
        let mut observations = Vec::with_capacity(workflow.steps.len());
        for (index, step) in workflow.steps.into_iter().enumerate() {
            if index > 0 {
                tokio::select! {
                    _ = cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                    _ = tokio::time::sleep(Duration::from_secs_f64(1.0 / rate)) => {}
                }
            }
            let step_id = step.id;
            let operation_id = format!("{workflow_id}:{step_id}");
            let mut request = step.request;
            request.id = operation_id.clone();
            if let Err(error) = substitute_workflow_request(&mut request, &values) {
                return Ok(workflow_error_observation(
                    workflow_id,
                    observations,
                    &step_id,
                    error,
                ));
            }
            let result = Box::pin(self.execute_operation(
                project_id,
                plugin_id,
                plugin_name,
                PluginOperation::HttpRequest(request),
                scope,
                target_host,
                cancel,
            ))
            .await;
            let mut observation = match result {
                Ok(observation) => observation,
                Err(error) if error.code() == ErrorCode::Cancelled => return Err(error),
                Err(error) => {
                    return Ok(workflow_error_observation(
                        workflow_id,
                        observations,
                        &step_id,
                        error,
                    ));
                }
            };
            observation["id"] = Value::String(step_id.clone());
            observation["operation_id"] = Value::String(operation_id);

            for extract in &step.extract {
                let extracted = match extract.extract(&observation) {
                    Ok(value) => value,
                    Err(error) => {
                        observations.push(observation);
                        return Ok(workflow_error_observation(
                            workflow_id,
                            observations,
                            &step_id,
                            error,
                        ));
                    }
                };
                if let Some(value) = extracted {
                    if value.len() > MAX_WORKFLOW_VALUE_BYTES {
                        observations.push(observation);
                        return Ok(workflow_error_observation(
                            workflow_id,
                            observations,
                            &step_id,
                            DomainError::new(
                                ErrorCode::BodyTooLarge,
                                format!(
                                    "http_workflow extract {} exceeds {MAX_WORKFLOW_VALUE_BYTES} bytes",
                                    extract.name()
                                ),
                            ),
                        ));
                    }
                    total_value_bytes = total_value_bytes.saturating_add(value.len());
                    if total_value_bytes > MAX_WORKFLOW_VALUES_BYTES {
                        observations.push(observation);
                        return Ok(workflow_error_observation(
                            workflow_id,
                            observations,
                            &step_id,
                            DomainError::new(
                                ErrorCode::BodyTooLarge,
                                format!(
                                    "http_workflow extracted values exceed {MAX_WORKFLOW_VALUES_BYTES} bytes"
                                ),
                            ),
                        ));
                    }
                    values.insert(extract.name().to_string(), value);
                }
            }
            observations.push(observation);
        }

        let terminal = observations.last().cloned().unwrap_or(Value::Null);
        Ok(json!({
            "id": workflow_id,
            "steps": observations,
            "terminal": terminal,
            "extracted": values.keys().cloned().collect::<BTreeSet<_>>(),
            "error": null,
        }))
    }

    async fn execute_operation(
        &self,
        project_id: ProjectId,
        plugin_id: &str,
        plugin_name: &str,
        operation: PluginOperation,
        scope: &ScopePolicy,
        target_host: Option<&str>,
        cancel: &CancellationToken,
    ) -> DomainResult<Value> {
        match operation {
            PluginOperation::HttpRequest(request) => {
                let operation_id = request.id.clone();
                let effective_url = if let Some(url) = request.url.as_deref() {
                    url.to_string()
                } else if let Some(base_exchange_id) = request.base_exchange_id {
                    let detail = self
                        .db
                        .get_exchange_detail(
                            project_id,
                            base_exchange_id,
                            crate::policy::PresentationOptions::default(),
                        )
                        .await?;
                    let query = detail
                        .summary
                        .query
                        .as_ref()
                        .map(|query| format!("?{query}"))
                        .unwrap_or_default();
                    format!(
                        "{}://{}{}{}",
                        detail.summary.scheme, detail.summary.authority, detail.summary.path, query
                    )
                } else {
                    return Err(DomainError::invalid(
                        "plugin HTTP operation requires url or base_exchange_id",
                    ));
                };
                enforce_plugin_scope(&effective_url, scope, target_host)?;
                if request.body_text.is_some() && request.body_base64.is_some() {
                    return Err(DomainError::invalid(
                        "plugin request body_text and body_base64 are mutually exclusive",
                    ));
                }
                let mut body_override = request
                    .body_base64
                    .as_deref()
                    .map(|body| base64::engine::general_purpose::STANDARD.decode(body))
                    .transpose()
                    .map_err(|error| {
                        DomainError::invalid(format!("invalid plugin body_base64: {error}"))
                    })?;
                let mut url_override = request.url;
                let mut header_overrides = request.headers;
                if !request.query_params.is_empty() {
                    let mut url = url::Url::parse(&effective_url).map_err(|error| {
                        DomainError::invalid(format!("invalid plugin request URL: {error}"))
                    })?;
                    let pairs = url
                        .query_pairs()
                        .map(|(name, value)| (name.into_owned(), value.into_owned()))
                        .collect::<Vec<_>>();
                    url.set_query(None);
                    let mut serializer = url.query_pairs_mut();
                    for (name, value) in pairs {
                        if !request.query_params.iter().any(|patch| patch.name == name) {
                            serializer.append_pair(&name, &value);
                        }
                    }
                    for patch in &request.query_params {
                        if let Some(value) = &patch.value {
                            serializer.append_pair(&patch.name, value);
                        }
                    }
                    drop(serializer);
                    url_override = Some(url.into());
                }
                if !request.cookie_params.is_empty() {
                    let base = request.base_exchange_id.ok_or_else(|| {
                        DomainError::invalid("cookie_params requires base_exchange_id")
                    })?;
                    let raw = self
                        .db
                        .load_raw_headers(project_id, base, MessageSide::Request)
                        .await?;
                    let cookie = raw
                        .iter()
                        .find(|header| header.name.eq_ignore_ascii_case("cookie"))
                        .and_then(|header| String::from_utf8(header.value.clone()).ok())
                        .unwrap_or_default();
                    let mut cookies = cookie
                        .split(';')
                        .filter_map(|item| {
                            let (name, value) = item.trim().split_once('=')?;
                            Some((name.trim().to_string(), value.to_string()))
                        })
                        .collect::<Vec<_>>();
                    cookies.retain(|(name, _)| {
                        !request
                            .cookie_params
                            .iter()
                            .any(|patch| patch.name == *name)
                    });
                    cookies.extend(request.cookie_params.iter().filter_map(|patch| {
                        patch
                            .value
                            .as_ref()
                            .map(|value| (patch.name.clone(), value.clone()))
                    }));
                    header_overrides.retain(|header| !header.name.eq_ignore_ascii_case("cookie"));
                    header_overrides.push(HeaderPatch {
                        name: "Cookie".into(),
                        value: cookies
                            .into_iter()
                            .map(|(name, value)| format!("{name}={value}"))
                            .collect::<Vec<_>>()
                            .join("; ")
                            .into_bytes(),
                    });
                }
                if !request.body_params.is_empty() {
                    let base = request.base_exchange_id.ok_or_else(|| {
                        DomainError::invalid("body_params requires base_exchange_id")
                    })?;
                    let raw_headers = self
                        .db
                        .load_raw_headers(project_id, base, MessageSide::Request)
                        .await?;
                    let content_type = raw_headers
                        .iter()
                        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
                        .and_then(|header| std::str::from_utf8(&header.value).ok())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let original = self
                        .db
                        .load_raw_body(project_id, base, MessageSide::Request)
                        .await?
                        .unwrap_or_default();
                    if content_type.contains("application/x-www-form-urlencoded") {
                        let mut pairs = url::form_urlencoded::parse(&original)
                            .map(|(name, value)| (name.into_owned(), value.into_owned()))
                            .collect::<Vec<_>>();
                        pairs.retain(|(name, _)| {
                            !request.body_params.iter().any(|patch| patch.name == *name)
                        });
                        pairs.extend(request.body_params.iter().filter_map(|patch| {
                            patch
                                .value
                                .as_ref()
                                .map(|value| (patch.name.clone(), value.clone()))
                        }));
                        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
                        serializer.extend_pairs(pairs);
                        body_override = Some(serializer.finish().into_bytes());
                    } else if content_type.contains("application/json") {
                        let mut value: Value = serde_json::from_slice(&original).map_err(|_| {
                            DomainError::invalid("cannot mutate malformed JSON request body")
                        })?;
                        let object = value.as_object_mut().ok_or_else(|| {
                            DomainError::invalid("body_params only supports top-level JSON objects")
                        })?;
                        for patch in &request.body_params {
                            match &patch.value {
                                Some(value) => {
                                    object.insert(patch.name.clone(), Value::String(value.clone()));
                                }
                                None => {
                                    object.remove(&patch.name);
                                }
                            }
                        }
                        body_override = Some(
                            serde_json::to_vec(&value)
                                .map_err(|error| DomainError::invalid(error.to_string()))?,
                        );
                    } else {
                        return Err(DomainError::invalid(
                            "body_params supports JSON and form-urlencoded saved requests",
                        ));
                    }
                }
                let context = ReplySendContext {
                    source: ExchangeSource::Plugin,
                    lineage: ExchangeLineage::default(),
                };
                let draft = ReplyDraft {
                    method: request.method,
                    url: url_override,
                    header_overrides,
                    header_tombstones: request.header_tombstones,
                    body_override,
                    body_text: request.body_text,
                    ..Default::default()
                };
                let response = tokio::select! {
                    _ = cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                    response = self.reply.send_with_context(project_id, request.base_exchange_id, &draft, request.protocol, 0, context) => response?,
                };
                let mut response_headers = Vec::new();
                let mut response_body_base64 = None;
                let mut response_body_truncated = false;
                if let Some(exchange_id) = response.exchange_id {
                    self.annotate_plugin_exchange(
                        project_id,
                        exchange_id,
                        plugin_id,
                        plugin_name,
                        &operation_id,
                    )
                    .await?;
                    let raw_response_headers = self
                        .db
                        .load_raw_headers(project_id, exchange_id, MessageSide::Response)
                        .await?;
                    response_headers = raw_response_headers
                        .iter()
                        .map(|header| json!({"name": header.name, "value_base64": base64::engine::general_purpose::STANDARD.encode(&header.value)}))
                        .collect();
                    if let Some(body) = self
                        .db
                        .load_raw_body(project_id, exchange_id, MessageSide::Response)
                        .await?
                    {
                        let presented = plugin_response_body(&raw_response_headers, body);
                        response_body_base64 = presented.body_base64;
                        response_body_truncated = presented.truncated;
                    }
                }
                Ok(json!({
                    "id": request.id,
                    "exchange_id": response.exchange_id,
                    "status_code": response.status_code,
                    "duration_ms": response.duration_ms,
                    "response_length": response.response_length,
                    "response_body_hash": response.response_body_hash,
                    "response_preview": response.response_preview,
                    "response_headers": response_headers,
                    "response_body_base64": response_body_base64,
                    "response_body_truncated": response_body_truncated,
                }))
            }
            PluginOperation::HttpWorkflow(workflow) => {
                self.execute_http_workflow(
                    project_id,
                    plugin_id,
                    plugin_name,
                    workflow,
                    scope,
                    target_host,
                    cancel,
                )
                .await
            }
            PluginOperation::RawHttp1(request) => {
                let operation_id = request.id.clone();
                let has_utf8 = request.request_utf8.is_some();
                let has_base64 = request.request_base64.is_some();
                if has_utf8 == has_base64 {
                    return Err(DomainError::invalid(
                        "raw_http1 requires exactly one of request_utf8 or request_base64",
                    ));
                }
                enforce_plugin_scope(&request.target_url, scope, target_host)?;
                let bytes = match (request.request_utf8, request.request_base64) {
                    (Some(value), None) => value.into_bytes(),
                    (None, Some(value)) => base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .map_err(|error| {
                            DomainError::invalid(format!("invalid raw request_base64: {error}"))
                        })?,
                    _ => unreachable!(),
                };
                let response = tokio::select! {
                    _ = cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                    response = self.reply.send_raw_http1_with_context(
                        project_id,
                        &request.target_url,
                        bytes,
                        request.use_project_cookies,
                        request.options,
                        ReplySendContext {
                            source: ExchangeSource::Plugin,
                            lineage: ExchangeLineage::default(),
                        },
                    ) => response?,
                };
                if let Some(exchange_id) = response.exchange_id {
                    self.annotate_plugin_exchange(
                        project_id,
                        exchange_id,
                        plugin_id,
                        plugin_name,
                        &operation_id,
                    )
                    .await?;
                }
                let transcript = match response.exchange_id {
                    Some(exchange_id) => {
                        self.db
                            .load_raw_body(project_id, exchange_id, MessageSide::Response)
                            .await?
                    }
                    None => None,
                };
                let raw = plugin_raw_observation(&response, transcript)?;
                Ok(json!({"id":request.id,"raw":raw}))
            }
            PluginOperation::RawHttp2(request) => {
                let operation_id = request.id.clone();
                enforce_plugin_scope(&request.target_url, scope, target_host)?;
                let response = tokio::select! {
                    _ = cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                    response = self.reply.send_raw_http2_with_context(
                        project_id,
                        &request.target_url,
                        request.streams,
                        request.options,
                        ReplySendContext {
                            source: ExchangeSource::Plugin,
                            lineage: ExchangeLineage::default(),
                        },
                    ) => response?,
                };
                let mut streams = Vec::with_capacity(response.streams.len());
                for stream in response.streams {
                    let mut response_headers = Vec::new();
                    let mut response_body_base64 = None;
                    let mut response_body_hash = None;
                    let mut response_body_truncated = false;
                    if let Some(exchange_id) = stream.exchange_id {
                        self.annotate_plugin_exchange(
                            project_id,
                            exchange_id,
                            plugin_id,
                            plugin_name,
                            &format!("{}:{}", operation_id, stream.id),
                        )
                        .await?;
                        let raw_headers = self
                            .db
                            .load_raw_headers(project_id, exchange_id, MessageSide::Response)
                            .await?;
                        response_headers = raw_headers
                            .iter()
                            .map(|header| json!({"name": header.name, "value_base64": base64::engine::general_purpose::STANDARD.encode(&header.value)}))
                            .collect();
                        if let Some(body) = self
                            .db
                            .load_raw_body(project_id, exchange_id, MessageSide::Response)
                            .await?
                        {
                            let presented = plugin_response_body(&raw_headers, body);
                            response_body_hash = presented.body_base64.as_ref().map(|encoded| {
                                let bytes = base64::engine::general_purpose::STANDARD
                                    .decode(encoded)
                                    .unwrap_or_default();
                                hex::encode(Sha256::digest(bytes))
                            });
                            response_body_base64 = presented.body_base64;
                            response_body_truncated = presented.truncated;
                        }
                    }
                    streams.push(json!({
                        "id": stream.id,
                        "stream_id": stream.stream_id,
                        "exchange_id": stream.exchange_id,
                        "status_code": stream.status_code,
                        "response_length": stream.response_length,
                        "response_body_hash": response_body_hash,
                        "response_headers": response_headers,
                        "response_body_base64": response_body_base64,
                        "response_body_truncated": response_body_truncated,
                        "reset": stream.reset,
                        "complete": stream.complete,
                        "truncated": stream.truncated,
                    }));
                }
                Ok(json!({
                    "id": operation_id,
                    "protocol": response.negotiated_protocol,
                    "single_write_release": response.single_write_release,
                    "goaway": response.goaway,
                    "timed_out": response.timed_out,
                    "streams": streams,
                }))
            }
            PluginOperation::RaceGroup(group) => {
                if group.requests.is_empty() || group.requests.len() > 1000 {
                    return Err(DomainError::new(
                        ErrorCode::CombinationLimit,
                        "race_group requires 1..=1000 requests",
                    ));
                }
                let mut request_ids = BTreeSet::new();
                for request in &group.requests {
                    if request.id.trim().is_empty() || !request_ids.insert(request.id.clone()) {
                        return Err(DomainError::invalid(
                            "race_group request ids must be non-empty and unique",
                        ));
                    }
                    race_request_draft(request)?;
                    if let Some(predicate) = &request.success {
                        validate_race_success_predicate(predicate)?;
                    }
                }
                let timeout_ms = group
                    .options
                    .timeout_ms
                    .unwrap_or(60_000)
                    .clamp(1_000, 120_000);
                let project_limit = self
                    .db
                    .get_project(project_id)
                    .await?
                    .limits
                    .max_concurrent_requests
                    .max(1) as usize;
                if matches!(group.technique, RaceTechnique::LastByteSync)
                    && group.requests.len() > project_limit
                {
                    return Err(DomainError::new(
                        ErrorCode::ConcurrencyLimited,
                        format!("last_byte_sync requires {} concurrent connections; project limit is {project_limit}", group.requests.len()),
                    ));
                }
                let responses = match group.technique {
                    RaceTechnique::H2SinglePacket => {
                        return self
                            .send_race_h2_single_packet(
                                project_id,
                                plugin_id,
                                plugin_name,
                                group,
                                scope,
                                target_host,
                                cancel,
                            )
                            .await;
                    }
                    RaceTechnique::SequentialControl => {
                        let mut responses = Vec::with_capacity(group.requests.len());
                        for request in group.requests {
                            responses.push(
                                self.send_race_semantic(
                                    project_id,
                                    plugin_id,
                                    plugin_name,
                                    request,
                                    scope,
                                    target_host,
                                    cancel,
                                )
                                .await,
                            );
                        }
                        responses
                    }
                    RaceTechnique::Parallel => {
                        stream::iter(group.requests.into_iter().map(|request| {
                            let service = self.clone();
                            let cancel = cancel.clone();
                            let scope = scope.clone();
                            let plugin_id = plugin_id.to_string();
                            let plugin_name = plugin_name.to_string();
                            let target_host = target_host.map(str::to_string);
                            async move {
                                service
                                    .send_race_semantic(
                                        project_id,
                                        &plugin_id,
                                        &plugin_name,
                                        request,
                                        &scope,
                                        target_host.as_deref(),
                                        &cancel,
                                    )
                                    .await
                            }
                        }))
                        .buffer_unordered(project_limit)
                        .collect::<Vec<_>>()
                        .await
                    }
                    RaceTechnique::LastByteSync => {
                        let barrier = Arc::new(tokio::sync::Barrier::new(group.requests.len()));
                        let hold_timeout_ms = group
                            .options
                            .hold_timeout_ms
                            .unwrap_or(10_000)
                            .clamp(100, 30_000);
                        let futures = group.requests.into_iter().map(|request| {
                            let service = self.clone();
                            let barrier = barrier.clone();
                            let cancel = cancel.clone();
                            let scope = scope.clone();
                            let plugin_id = plugin_id.to_string();
                            let plugin_name = plugin_name.to_string();
                            let target_host = target_host.map(str::to_string);
                            async move {
                                service
                                    .send_race_last_byte(
                                        project_id,
                                        &plugin_id,
                                        &plugin_name,
                                        request,
                                        &scope,
                                        target_host.as_deref(),
                                        &cancel,
                                        barrier,
                                        hold_timeout_ms,
                                    )
                                    .await
                            }
                        });
                        tokio::time::timeout(
                            Duration::from_millis(timeout_ms),
                            futures::future::join_all(futures),
                        )
                        .await
                        .map_err(|_| {
                            DomainError::new(
                                ErrorCode::Timeout,
                                "last_byte_sync race group timed out",
                            )
                        })?
                    }
                };
                Ok(json!({
                    "id": group.id,
                    "technique": match group.technique { RaceTechnique::SequentialControl => "sequential_control", RaceTechnique::Parallel => "parallel", RaceTechnique::LastByteSync => "last_byte_sync", RaceTechnique::H2SinglePacket => "h2_single_packet" },
                    "attempt": group.attempt,
                    "synchronized": matches!(group.technique, RaceTechnique::LastByteSync),
                    "release_skew_ms": Value::Null,
                    "responses": responses,
                }))
            }
        }
    }

    async fn send_race_semantic(
        &self,
        project_id: ProjectId,
        plugin_id: &str,
        plugin_name: &str,
        request: RaceRequest,
        scope: &ScopePolicy,
        target_host: Option<&str>,
        cancel: &CancellationToken,
    ) -> Value {
        let result = async {
            let draft = race_request_draft(&request)?;
            let materialized = crate::reply::materialize_request(
                &self.db,
                project_id,
                request.base_exchange_id,
                &draft,
                self.reply.placeholder_key(),
            )
            .await?;
            let url = materialized.url;
            enforce_plugin_scope(&url, scope, target_host)?;
            let response = tokio::select! {
                _ = cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                response = self.reply.send_with_context(project_id, request.base_exchange_id, &draft, request.protocol, 0, ReplySendContext { source: ExchangeSource::Plugin, lineage: ExchangeLineage { parent_exchange_id: request.base_exchange_id, ..Default::default() } }) => response?,
            };
            if let Some(exchange_id) = response.exchange_id {
                self.annotate_plugin_exchange(
                    project_id,
                    exchange_id,
                    plugin_id,
                    plugin_name,
                    &request.id,
                )
                .await?;
            }
            let success = self
                .evaluate_race_exchange(project_id, response.exchange_id, request.success.as_ref())
                .await?;
            Ok::<_, DomainError>(json!({"id":request.id,"exchange_id":response.exchange_id,"status_code":response.status_code,"response_length":response.response_length,"response_body_hash":response.response_body_hash,"duration_ms":response.duration_ms,"success":success,"error":Value::Null}))
        }.await;
        result.unwrap_or_else(|error| json!({"id":request.id,"error":error.to_string()}))
    }

    async fn send_race_h2_single_packet(
        &self,
        project_id: ProjectId,
        plugin_id: &str,
        plugin_name: &str,
        group: PluginRaceGroup,
        scope: &ScopePolicy,
        target_host: Option<&str>,
        cancel: &CancellationToken,
    ) -> DomainResult<Value> {
        let group_id = group.id.clone();
        let attempt = group.attempt;
        let timeout_ms = group
            .options
            .timeout_ms
            .unwrap_or(60_000)
            .clamp(1_000, 120_000);
        let mut target_url = None::<String>;
        let mut streams = Vec::with_capacity(group.requests.len());
        let mut predicates = HashMap::new();
        for request in group.requests {
            let draft = race_request_draft(&request)?;
            let materialized = crate::reply::materialize_request(
                &self.db,
                project_id,
                request.base_exchange_id,
                &draft,
                self.reply.placeholder_key(),
            )
            .await?;
            enforce_plugin_scope(&materialized.url, scope, target_host)?;
            let parsed = url::Url::parse(&materialized.url).map_err(|error| {
                DomainError::invalid(format!("invalid race request URL: {error}"))
            })?;
            if parsed.scheme() != "https" {
                return Ok(json!({
                    "id": group_id,
                    "technique": "h2_single_packet",
                    "attempt": attempt,
                    "synchronized": false,
                    "release_skew_ms": Value::Null,
                    "responses": [],
                    "error": {"code":"protocol_incompatible","message":"h2_single_packet requires HTTPS with ALPN h2"},
                }));
            }
            let origin = format!(
                "{}://{}:{}",
                parsed.scheme(),
                parsed.host_str().unwrap_or_default(),
                parsed.port_or_known_default().unwrap_or(443)
            );
            if let Some(existing) = &target_url {
                let existing = url::Url::parse(existing).map_err(|error| {
                    DomainError::invalid(format!("invalid race target URL: {error}"))
                })?;
                let existing_origin = format!(
                    "{}://{}:{}",
                    existing.scheme(),
                    existing.host_str().unwrap_or_default(),
                    existing.port_or_known_default().unwrap_or(443)
                );
                if existing_origin != origin {
                    return Err(DomainError::invalid(
                        "h2_single_packet requests must share one HTTPS origin",
                    ));
                }
            } else {
                target_url = Some(materialized.url.clone());
            }
            let body = materialized.body.unwrap_or_default();
            if body.is_empty() {
                return Ok(json!({
                    "id": group_id,
                    "technique": "h2_single_packet",
                    "attempt": attempt,
                    "synchronized": false,
                    "release_skew_ms": Value::Null,
                    "responses": [],
                    "error": {"code":"protocol_incompatible","message":"h2_single_packet requires a non-empty request body on every request"},
                }));
            }
            let authority = match (parsed.host_str(), parsed.port()) {
                (Some(host), Some(port)) if host.contains(':') => format!("[{host}]:{port}"),
                (Some(host), Some(port)) => format!("{host}:{port}"),
                (Some(host), None) => host.to_string(),
                _ => return Err(DomainError::invalid("race request URL requires a host")),
            };
            let mut path = parsed.path().to_string();
            if let Some(query) = parsed.query() {
                path.push('?');
                path.push_str(query);
            }
            let mut headers = vec![
                crate::reply::RawHttp2Header {
                    name: ":method".into(),
                    value: materialized.method.clone(),
                },
                crate::reply::RawHttp2Header {
                    name: ":scheme".into(),
                    value: parsed.scheme().into(),
                },
                crate::reply::RawHttp2Header {
                    name: ":authority".into(),
                    value: authority,
                },
                crate::reply::RawHttp2Header {
                    name: ":path".into(),
                    value: path,
                },
            ];
            let mut ordinary = materialized.headers;
            if request.use_project_cookies {
                if let Some(profile) = self
                    .db
                    .get_cookie_profile_for_url(project_id, &materialized.url)
                    .await?
                {
                    if let Some(cookie) = profile.cookie_header_for_url(&materialized.url)? {
                        ordinary.retain(|(name, _)| !name.eq_ignore_ascii_case("cookie"));
                        ordinary.push(("cookie".into(), cookie.into_bytes()));
                    }
                }
            }
            let has_content_length = ordinary
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
            for (name, value) in ordinary {
                if [
                    "host",
                    "connection",
                    "proxy-connection",
                    "keep-alive",
                    "upgrade",
                    "transfer-encoding",
                ]
                .iter()
                .any(|removed| name.eq_ignore_ascii_case(removed))
                {
                    continue;
                }
                let value = String::from_utf8(value).map_err(|_| {
                    DomainError::invalid("h2_single_packet requires UTF-8 header values")
                })?;
                headers.push(crate::reply::RawHttp2Header {
                    name: name.to_ascii_lowercase(),
                    value,
                });
            }
            if !has_content_length {
                headers.push(crate::reply::RawHttp2Header {
                    name: "content-length".into(),
                    value: body.len().to_string(),
                });
            }
            predicates.insert(request.id.clone(), request.success);
            streams.push(crate::reply::RawHttp2Stream {
                id: request.id,
                stream_id: None,
                headers,
                body_text: None,
                body_base64: Some(base64::engine::general_purpose::STANDARD.encode(body)),
            });
        }
        let target_url = target_url.ok_or_else(|| DomainError::invalid("empty H2 race group"))?;
        let result = tokio::select! {
            _ = cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
            result = self.reply.send_raw_http2_with_context(
                project_id,
                &target_url,
                streams,
                crate::reply::RawHttp2Options {
                    timeout_ms: Some(timeout_ms),
                    final_data_together: true,
                    ..Default::default()
                },
                ReplySendContext {
                    source: ExchangeSource::Plugin,
                    lineage: ExchangeLineage::default(),
                },
            ) => result,
        };
        let result = match result {
            Ok(result) => result,
            Err(error) if error.code() == ErrorCode::ProtocolIncompatible => {
                return Ok(json!({
                    "id": group_id,
                    "technique": "h2_single_packet",
                    "attempt": attempt,
                    "synchronized": false,
                    "release_skew_ms": Value::Null,
                    "responses": [],
                    "error": {"code":"protocol_incompatible","message":error.to_string()},
                }));
            }
            Err(error) => return Err(error),
        };
        let mut responses = Vec::with_capacity(result.streams.len());
        for response in result.streams {
            if let Some(exchange_id) = response.exchange_id {
                self.annotate_plugin_exchange(
                    project_id,
                    exchange_id,
                    plugin_id,
                    plugin_name,
                    &response.id,
                )
                .await?;
            }
            let success = self
                .evaluate_race_exchange(
                    project_id,
                    response.exchange_id,
                    predicates.get(&response.id).and_then(Option::as_ref),
                )
                .await
                .unwrap_or(Value::Null);
            responses.push(json!({
                "id": response.id,
                "exchange_id": response.exchange_id,
                "status_code": response.status_code,
                "response_length": response.response_length,
                "success": success,
                "complete": response.complete,
                "truncated": response.truncated,
                "reset": response.reset,
                "error": Value::Null,
            }));
        }
        Ok(json!({
            "id": group_id,
            "technique": "h2_single_packet",
            "attempt": attempt,
            "synchronized": result.single_write_release,
            "release_skew_ms": if result.single_write_release { Value::from(0) } else { Value::Null },
            "responses": responses,
            "error": if result.timed_out { json!({"code":"timeout","message":"HTTP/2 race response timed out"}) } else { Value::Null },
            "goaway": result.goaway,
        }))
    }

    async fn send_race_last_byte(
        &self,
        project_id: ProjectId,
        plugin_id: &str,
        plugin_name: &str,
        request: RaceRequest,
        scope: &ScopePolicy,
        target_host: Option<&str>,
        cancel: &CancellationToken,
        barrier: Arc<tokio::sync::Barrier>,
        hold_timeout_ms: u64,
    ) -> Value {
        let result = async {
            if matches!(request.protocol, ProtocolPreference::H2) {
                return Err(DomainError::new(
                    ErrorCode::ProtocolIncompatible,
                    "last_byte_sync is exact HTTP/1 only",
                ));
            }
            let draft = race_request_draft(&request)?;
            let materialized = crate::reply::materialize_request(
                &self.db,
                project_id,
                request.base_exchange_id,
                &draft,
                self.reply.placeholder_key(),
            )
            .await?;
            let target_url = materialized.url.clone();
            enforce_plugin_scope(&target_url, scope, target_host)?;
            let bytes = materialized_http1_bytes(&materialized)?;
            if bytes.len() < 2 { return Err(DomainError::invalid("saved request is too short for last_byte_sync")); }
            let options = crate::reply::RawHttp1Options { pause_at_byte: Some(bytes.len() - 1), pause_ms: Some(hold_timeout_ms), release_barrier: Some(barrier), ..Default::default() };
            let response = tokio::select! {
                _ = cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                response = self.reply.send_raw_http1_with_context(
                    project_id,
                    &target_url,
                    bytes,
                    request.use_project_cookies,
                    options,
                    ReplySendContext {
                        source: ExchangeSource::Plugin,
                        lineage: ExchangeLineage {
                            parent_exchange_id: request.base_exchange_id,
                            ..Default::default()
                        },
                    },
                ) => response?,
            };
            if let Some(exchange_id) = response.exchange_id {
                self.annotate_plugin_exchange(
                    project_id,
                    exchange_id,
                    plugin_id,
                    plugin_name,
                    &request.id,
                )
                .await?;
            }
            let success = self
                .evaluate_race_exchange(project_id, response.exchange_id, request.success.as_ref())
                .await?;
            Ok::<_, DomainError>(json!({"id":request.id,"exchange_id":response.exchange_id,"status_code":response.status_code,"response_length":response.response_bytes,"response_body_hash":Value::Null,"duration_ms":Value::Null,"success":success,"error":Value::Null}))
        }.await;
        result.unwrap_or_else(|error| json!({"id":request.id,"error":error.to_string()}))
    }

    async fn evaluate_race_exchange(
        &self,
        project_id: ProjectId,
        exchange_id: Option<ExchangeId>,
        predicate: Option<&RaceSuccessPredicate>,
    ) -> DomainResult<Value> {
        let Some(predicate) = predicate else {
            return Ok(Value::Null);
        };
        let exchange_id = exchange_id.ok_or_else(|| {
            DomainError::new(ErrorCode::StorageError, "race response was not persisted")
        })?;
        let detail = self
            .db
            .get_exchange_detail(
                project_id,
                exchange_id,
                crate::policy::PresentationOptions::default(),
            )
            .await?;
        let headers = self
            .db
            .load_raw_headers(project_id, exchange_id, MessageSide::Response)
            .await?;
        let mut body = self
            .db
            .load_raw_body(project_id, exchange_id, MessageSide::Response)
            .await?
            .unwrap_or_default();
        let body_truncated = body.len() > MAX_RESPONSE_BODY_FOR_PLUGIN;
        body.truncate(MAX_RESPONSE_BODY_FOR_PLUGIN);
        evaluate_race_success(
            detail.summary.status_code,
            &headers,
            &body,
            body_truncated,
            predicate,
        )
    }

    async fn annotate_plugin_exchange(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        plugin_id: &str,
        plugin_name: &str,
        operation_id: &str,
    ) -> DomainResult<()> {
        let existing = self.db.get_annotation(project_id, exchange_id).await?;
        let mut labels = existing
            .as_ref()
            .map(|annotation| annotation.labels.clone())
            .unwrap_or_default();
        labels.extend([
            "plugin".into(),
            plugin_name.into(),
            format!("plugin:{plugin_id}"),
            format!("plugin-op:{}", normalize_operation_label(operation_id)),
        ]);
        labels.sort_by_key(|label| label.to_ascii_lowercase());
        labels.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        self.db
            .upsert_annotation(
                project_id,
                exchange_id,
                AnnotationUpdate {
                    display_title: existing
                        .as_ref()
                        .and_then(|annotation| annotation.display_title.clone()),
                    note: existing
                        .as_ref()
                        .and_then(|annotation| annotation.note.clone())
                        .or_else(|| Some(format!("Generated by HuntProxy plugin {plugin_id}"))),
                    labels,
                    expected_revision: existing.map(|annotation| annotation.revision),
                },
            )
            .await?;
        Ok(())
    }
}

struct PluginResponseBody {
    body_base64: Option<String>,
    truncated: bool,
}

/// Plugin analyzers compare semantic responses. Supplying compressed wire bytes
/// makes otherwise identical dynamic pages look unrelated, so decode bounded
/// bodies here. Oversized or unsupported encodings deliberately fall back to
/// Reply's already-decoded preview instead of exposing binary data as text.
fn plugin_response_body(headers: &[HeaderEntry], mut body: Vec<u8>) -> PluginResponseBody {
    let encodings = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
        .map(|header| String::from_utf8_lossy(&header.value).trim().to_string())
        .filter(|encoding| !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity"))
        .collect::<Vec<_>>();
    if !encodings.is_empty() {
        match crate::codec::decode_content_encodings(
            &body,
            &encodings.join(", "),
            MAX_RESPONSE_BODY_FOR_PLUGIN,
        ) {
            Ok(decoded) => body = decoded,
            Err(_) => {
                return PluginResponseBody {
                    body_base64: None,
                    truncated: true,
                };
            }
        }
    }
    let truncated = body.len() > MAX_RESPONSE_BODY_FOR_PLUGIN;
    body.truncate(MAX_RESPONSE_BODY_FOR_PLUGIN);
    PluginResponseBody {
        body_base64: Some(base64::engine::general_purpose::STANDARD.encode(body)),
        truncated,
    }
}

fn plugin_raw_observation(
    response: &crate::reply::RawReplyResult,
    transcript: Option<Vec<u8>>,
) -> DomainResult<Value> {
    let mut value = serde_json::to_value(response).map_err(|error| {
        DomainError::new(
            ErrorCode::Internal,
            format!("serialize raw plugin observation: {error}"),
        )
    })?;
    if let (Some(transcript), Some(object)) = (transcript, value.as_object_mut()) {
        let truncated = transcript.len() > MAX_RESPONSE_BODY_FOR_PLUGIN;
        let slice = &transcript[..transcript.len().min(MAX_RESPONSE_BODY_FOR_PLUGIN)];
        object.insert(
            "response_transcript_base64".into(),
            Value::String(base64::engine::general_purpose::STANDARD.encode(slice)),
        );
        object.insert(
            "response_transcript_truncated".into(),
            Value::Bool(truncated),
        );
    }
    Ok(value)
}

fn race_request_draft(request: &RaceRequest) -> DomainResult<ReplyDraft> {
    if request.base_exchange_id.is_none() && request.url.is_none() {
        return Err(DomainError::invalid(
            "race request requires base_exchange_id or an inline url",
        ));
    }
    if request.body_text.is_some() && request.body_base64.is_some() {
        return Err(DomainError::invalid(
            "race request accepts only one of body_text or body_base64",
        ));
    }
    let body_override = request
        .body_base64
        .as_deref()
        .map(|body| {
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .map_err(|error| DomainError::invalid(format!("invalid race body_base64: {error}")))
        })
        .transpose()?;
    Ok(ReplyDraft {
        method: request.method.clone(),
        url: request.url.clone(),
        header_overrides: request.headers.clone(),
        header_tombstones: request.header_tombstones.clone(),
        body_override,
        body_text: request.body_text.clone(),
        ..Default::default()
    })
}

fn materialized_http1_bytes(request: &crate::reply::MaterializedRequest) -> DomainResult<Vec<u8>> {
    let url = url::Url::parse(&request.url)
        .map_err(|error| DomainError::invalid(format!("invalid race request url: {error}")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(DomainError::invalid("race request url must be HTTP(S)"));
    }
    let authority = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_string(),
    };
    let mut target = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    }
    .to_string();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    let body = request.body.as_deref().unwrap_or_default();
    let mut bytes = format!("{} {} HTTP/1.1\r\n", request.method, target).into_bytes();
    if !request
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        bytes.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
    }
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        if name.contains(['\r', '\n']) || value.contains(&b'\r') || value.contains(&b'\n') {
            return Err(DomainError::invalid(
                "race request contains an invalid header",
            ));
        }
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value);
        bytes.extend_from_slice(b"\r\n");
    }
    if !body.is_empty() {
        bytes.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    bytes.extend_from_slice(b"Connection: close\r\n\r\n");
    bytes.extend_from_slice(body);
    Ok(bytes)
}

fn text_predicate_matches(value: &str, predicate: &RaceTextPredicate) -> DomainResult<bool> {
    if predicate.equals.is_none() && predicate.contains.is_none() && predicate.regex.is_none() {
        return Err(DomainError::invalid(
            "text predicate requires equals, contains, or regex",
        ));
    }
    if predicate
        .equals
        .as_deref()
        .is_some_and(|expected| value != expected)
    {
        return Ok(false);
    }
    if predicate
        .contains
        .as_deref()
        .is_some_and(|expected| !value.contains(expected))
    {
        return Ok(false);
    }
    if let Some(pattern) = &predicate.regex {
        let regex = regex::Regex::new(pattern)
            .map_err(|error| DomainError::invalid(format!("invalid success regex: {error}")))?;
        if !regex.is_match(value) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_race_success_predicate(predicate: &RaceSuccessPredicate) -> DomainResult<()> {
    if predicate.status_codes.is_empty()
        && predicate.headers.is_empty()
        && predicate.body_contains.is_none()
        && predicate.body_regex.is_none()
        && predicate.json.is_empty()
        && predicate.redirect_location.is_none()
    {
        return Err(DomainError::invalid("success predicate cannot be empty"));
    }
    for header in &predicate.headers {
        if header.name.trim().is_empty() {
            return Err(DomainError::invalid("header predicate name is required"));
        }
        text_predicate_matches("", &header.value)?;
    }
    if let Some(pattern) = &predicate.body_regex {
        regex::Regex::new(pattern)
            .map_err(|error| DomainError::invalid(format!("invalid body_regex: {error}")))?;
    }
    for json in &predicate.json {
        if !json.pointer.is_empty() && !json.pointer.starts_with('/') {
            return Err(DomainError::invalid(
                "JSON predicate pointer must be empty or start with /",
            ));
        }
    }
    if let Some(redirect) = &predicate.redirect_location {
        text_predicate_matches("", redirect)?;
    }
    Ok(())
}

fn evaluate_race_success(
    status_code: Option<u16>,
    headers: &[HeaderEntry],
    body: &[u8],
    body_truncated: bool,
    predicate: &RaceSuccessPredicate,
) -> DomainResult<Value> {
    let mut checks = Vec::new();
    let mut matched = true;
    validate_race_success_predicate(predicate)?;
    if !predicate.status_codes.is_empty() {
        let check = status_code.is_some_and(|status| predicate.status_codes.contains(&status));
        matched &= check;
        checks.push(json!({"type":"status","matched":check}));
    }
    for expected in &predicate.headers {
        let values = headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(&expected.name))
            .map(|header| String::from_utf8_lossy(&header.value).into_owned())
            .collect::<Vec<_>>();
        let mut check = false;
        for value in &values {
            check |= text_predicate_matches(value, &expected.value)?;
        }
        matched &= check;
        checks.push(json!({"type":"header","name":expected.name,"matched":check}));
    }
    let body_text = String::from_utf8_lossy(body);
    if let Some(expected) = &predicate.body_contains {
        let check = body_text.contains(expected);
        matched &= check;
        checks.push(json!({"type":"body_contains","matched":check}));
    }
    if let Some(pattern) = &predicate.body_regex {
        let regex = regex::Regex::new(pattern)
            .map_err(|error| DomainError::invalid(format!("invalid body_regex: {error}")))?;
        let check = regex.is_match(&body_text);
        matched &= check;
        checks.push(json!({"type":"body_regex","matched":check}));
    }
    if !predicate.json.is_empty() {
        let parsed: Option<Value> = serde_json::from_slice(body).ok();
        for expected in &predicate.json {
            let value = parsed
                .as_ref()
                .and_then(|json| json.pointer(&expected.pointer));
            let mut check = expected
                .exists
                .map_or(value.is_some(), |exists| exists == value.is_some());
            if let Some(equals) = &expected.equals {
                check &= value == Some(equals);
            }
            matched &= check;
            checks.push(json!({"type":"json","pointer":expected.pointer,"matched":check}));
        }
    }
    if let Some(expected) = &predicate.redirect_location {
        let location = headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("location"))
            .map(|header| String::from_utf8_lossy(&header.value).into_owned());
        let check = if status_code.is_some_and(|status| (300..400).contains(&status)) {
            match location.as_deref() {
                Some(value) => text_predicate_matches(value, expected)?,
                None => false,
            }
        } else {
            false
        };
        matched &= check;
        checks.push(json!({"type":"redirect_location","matched":check}));
    }
    let body_dependent = predicate.body_contains.is_some()
        || predicate.body_regex.is_some()
        || !predicate.json.is_empty();
    Ok(json!({
        "matched": matched,
        "checks": checks,
        "body_truncated": body_truncated,
        "indeterminate": body_truncated && body_dependent && !matched,
    }))
}

fn prune_finished_jobs(jobs: &DashMap<Uuid, Arc<PluginJob>>) {
    let excess = jobs
        .len()
        .saturating_sub(MAX_RETAINED_JOBS.saturating_sub(1));
    if excess == 0 {
        return;
    }
    let removable = jobs
        .iter()
        .filter_map(|job| {
            (!matches!(
                job.view.read().state,
                PluginJobState::Queued | PluginJobState::Running
            ))
            .then_some(*job.key())
        })
        .take(excess)
        .collect::<Vec<_>>();
    for id in removable {
        jobs.remove(&id);
    }
}

fn normalize_operation_label(operation_id: &str) -> String {
    let mut label = operation_id
        .chars()
        .take(80)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if label.is_empty() {
        label.push_str("operation");
    }
    label
}

fn operation_request_count(operation: &PluginOperation) -> usize {
    match operation {
        PluginOperation::RaceGroup(group) => group.requests.len(),
        PluginOperation::RawHttp2(request) => request.streams.len(),
        PluginOperation::HttpWorkflow(workflow) => workflow.steps.len(),
        _ => 1,
    }
}

fn validate_workflow_name(value: &str, field: &str) -> DomainResult<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(DomainError::invalid(format!(
            "http_workflow {field} must be 1..=64 ASCII letters, digits, '.', '-' or '_'"
        )));
    }
    Ok(())
}

fn workflow_response_body(observation: &Value) -> DomainResult<Vec<u8>> {
    let encoded = observation
        .get("response_body_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| DomainError::invalid("http_workflow response has no body to extract"))?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| DomainError::invalid(format!("invalid stored response body: {error}")))
}

fn encode_workflow_value(value: &[u8], encoding: PluginWorkflowEncoding) -> DomainResult<String> {
    match encoding {
        PluginWorkflowEncoding::Raw => String::from_utf8(value.to_vec()).map_err(|_| {
            DomainError::invalid("raw http_workflow extracts must contain valid UTF-8")
        }),
        PluginWorkflowEncoding::Url => Ok(percent_encoding::percent_encode(
            value,
            percent_encoding::NON_ALPHANUMERIC,
        )
        .to_string()),
        PluginWorkflowEncoding::Json => {
            let value = std::str::from_utf8(value).map_err(|_| {
                DomainError::invalid("JSON-encoded http_workflow extracts must contain UTF-8")
            })?;
            let quoted = serde_json::to_string(value)
                .map_err(|error| DomainError::invalid(error.to_string()))?;
            Ok(quoted[1..quoted.len() - 1].to_string())
        }
        PluginWorkflowEncoding::Base64 => {
            Ok(base64::engine::general_purpose::STANDARD.encode(value))
        }
    }
}

fn substitute_workflow_template(
    template: &str,
    values: &HashMap<String, String>,
) -> DomainResult<String> {
    const PREFIX: &str = "{{extract:";
    let mut output = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find(PREFIX) {
        output.push_str(&rest[..start]);
        let after_prefix = &rest[start + PREFIX.len()..];
        let end = after_prefix.find("}}").ok_or_else(|| {
            DomainError::invalid("unterminated http_workflow extract placeholder")
        })?;
        let name = &after_prefix[..end];
        validate_workflow_name(name, "placeholder name")?;
        let value = values.get(name).ok_or_else(|| {
            DomainError::invalid(format!(
                "http_workflow extract {name} is not available before this step"
            ))
        })?;
        output.push_str(value);
        rest = &after_prefix[end + 2..];
    }
    output.push_str(rest);
    Ok(output)
}

fn substitute_workflow_request(
    request: &mut PluginHttpRequest,
    values: &HashMap<String, String>,
) -> DomainResult<()> {
    if let Some(method) = &mut request.method {
        *method = substitute_workflow_template(method, values)?;
    }
    if let Some(url) = &mut request.url {
        *url = substitute_workflow_template(url, values)?;
    }
    if let Some(body) = &mut request.body_text {
        *body = substitute_workflow_template(body, values)?;
    }
    if request
        .body_base64
        .as_deref()
        .is_some_and(|body| body.contains("{{extract:"))
    {
        return Err(DomainError::invalid(
            "http_workflow placeholders are not supported in body_base64; use body_text or typed parameters",
        ));
    }
    for header in &mut request.headers {
        if !header
            .value
            .windows(10)
            .any(|window| window == b"{{extract:")
        {
            continue;
        }
        let value = std::str::from_utf8(&header.value).map_err(|_| {
            DomainError::invalid("templated http_workflow headers must contain UTF-8")
        })?;
        header.value = substitute_workflow_template(value, values)?.into_bytes();
    }
    for patch in request
        .query_params
        .iter_mut()
        .chain(request.cookie_params.iter_mut())
        .chain(request.body_params.iter_mut())
    {
        if let Some(value) = &mut patch.value {
            *value = substitute_workflow_template(value, values)?;
        }
    }
    Ok(())
}

fn workflow_error_observation(
    workflow_id: String,
    steps: Vec<Value>,
    step_id: &str,
    error: DomainError,
) -> Value {
    let terminal = steps.last().cloned().unwrap_or(Value::Null);
    json!({
        "id": workflow_id,
        "steps": steps,
        "terminal": terminal,
        "error": {
            "code": error.code().as_str(),
            "message": error.to_string(),
            "step_id": step_id,
        }
    })
}

fn isolate_operation_result(
    operation_id: String,
    result: DomainResult<Value>,
) -> DomainResult<Value> {
    match result {
        Err(error) if error.code() == ErrorCode::Cancelled => Err(error),
        Err(error) => Ok(json!({
            "id": operation_id,
            "error": {
                "code": error.code().as_str(),
                "message": error.to_string(),
            }
        })),
        Ok(observation) => Ok(observation),
    }
}

fn redact_value(value: &mut Value, secrets: &[String], key: Option<&str>) {
    let sensitive_key = key.is_some_and(|key| {
        let key = key.to_ascii_lowercase();
        ["cookie", "authorization", "token", "secret", "password"]
            .iter()
            .any(|word| key.contains(word))
    });
    match value {
        Value::String(text) => {
            if sensitive_key
                || secrets
                    .iter()
                    .any(|secret| !secret.is_empty() && text.contains(secret))
            {
                *text = "<redacted>".into();
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| redact_value(item, secrets, key)),
        Value::Object(object) => {
            for (name, value) in object {
                redact_value(value, secrets, Some(name));
            }
        }
        _ => {}
    }
}

fn enforce_plugin_scope(
    url: &str,
    scope: &ScopePolicy,
    target_host: Option<&str>,
) -> DomainResult<()> {
    if !url_is_in_scope(url, scope)? {
        return Err(DomainError::scope_denied(
            "plugin operation is outside project scope",
        ));
    }
    if scope.host_patterns.is_empty() {
        let host = url::Url::parse(url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_ascii_lowercase));
        if host.as_deref() != target_host {
            return Err(DomainError::scope_denied(
                "plugin operations default to the project target host; configure explicit project scope to test other hosts",
            ));
        }
    }
    Ok(())
}

fn load_plugin(directory: &Path) -> DomainResult<LoadedPlugin> {
    let manifest_path = directory.join("plugin.json");
    let metadata = std::fs::metadata(&manifest_path).map_err(|error| {
        DomainError::new(ErrorCode::ConfigInvalid, format!("plugin.json: {error}"))
    })?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "plugin manifest too large",
        ));
    }
    let manifest: PluginManifest = serde_json::from_slice(
        &std::fs::read(&manifest_path)
            .map_err(|error| DomainError::new(ErrorCode::ConfigInvalid, error.to_string()))?,
    )
    .map_err(|error| {
        DomainError::new(
            ErrorCode::ConfigInvalid,
            format!("plugin manifest: {error}"),
        )
    })?;
    validate_manifest(&manifest)?;
    let relative = Path::new(&manifest.entrypoint);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || relative.extension().and_then(|value| value.to_str()) != Some("js")
    {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "plugin entrypoint must be a relative .js file",
        ));
    }
    let entrypoint = directory.join(relative);
    let metadata = std::fs::metadata(&entrypoint).map_err(|error| {
        DomainError::new(
            ErrorCode::ConfigInvalid,
            format!("plugin entrypoint: {error}"),
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_SCRIPT_BYTES {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "plugin entrypoint is not a bounded regular file",
        ));
    }
    let bytes = std::fs::read(&entrypoint)
        .map_err(|error| DomainError::new(ErrorCode::ConfigInvalid, error.to_string()))?;
    let digest = hex::encode(Sha256::digest(&bytes));
    if !digest.eq_ignore_ascii_case(manifest.entrypoint_sha256.trim()) {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "plugin entrypoint integrity check failed",
        ));
    }
    let script = String::from_utf8(bytes).map_err(|_| {
        DomainError::new(ErrorCode::ConfigInvalid, "plugin entrypoint must be UTF-8")
    })?;
    let mut resources: HashMap<String, String> = HashMap::new();
    let mut total_resource_bytes = 0usize;
    for (name, resource) in &manifest.resources {
        if name.is_empty() || name.len() > 64 {
            return Err(DomainError::new(
                ErrorCode::ConfigInvalid,
                "invalid plugin resource name",
            ));
        }
        let relative = Path::new(&resource.path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(DomainError::new(
                ErrorCode::ConfigInvalid,
                "plugin resource path must be relative",
            ));
        }
        let path = directory.join(relative);
        let metadata = std::fs::metadata(&path).map_err(|error| {
            DomainError::new(
                ErrorCode::ConfigInvalid,
                format!("plugin resource: {error}"),
            )
        })?;
        if !metadata.is_file() || metadata.len() > MAX_RESOURCE_BYTES {
            return Err(DomainError::new(
                ErrorCode::ConfigInvalid,
                "plugin resource is not a bounded regular file",
            ));
        }
        let bytes = std::fs::read(path)
            .map_err(|error| DomainError::new(ErrorCode::ConfigInvalid, error.to_string()))?;
        if let Some(previous) = resources.get(name) {
            total_resource_bytes = total_resource_bytes.saturating_sub(previous.len());
        }
        total_resource_bytes = total_resource_bytes.saturating_add(bytes.len());
        if total_resource_bytes > MAX_TOTAL_RESOURCE_BYTES
            || !hex::encode(Sha256::digest(&bytes)).eq_ignore_ascii_case(resource.sha256.trim())
        {
            return Err(DomainError::new(
                ErrorCode::ConfigInvalid,
                "plugin resource integrity check failed or resource total is too large",
            ));
        }
        resources.insert(
            name.clone(),
            String::from_utf8(bytes).map_err(|_| {
                DomainError::new(ErrorCode::ConfigInvalid, "plugin resources must be UTF-8")
            })?,
        );
    }
    Ok(LoadedPlugin {
        manifest,
        script: script.into(),
        resources: Arc::new(resources),
    })
}

fn validate_manifest(manifest: &PluginManifest) -> DomainResult<()> {
    if manifest.schema_version != PLUGIN_API_VERSION {
        return Err(DomainError::new(
            ErrorCode::ProtocolIncompatible,
            "unsupported plugin schema_version",
        ));
    }
    let valid_slug = |value: &str| {
        !value.is_empty()
            && value.len() <= 64
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
    };
    if !valid_slug(&manifest.id) || manifest.name.trim().is_empty() || manifest.name.len() > 128 {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "invalid plugin id or name",
        ));
    }
    if manifest.version.trim().is_empty() || manifest.actions.is_empty() {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "plugin version and actions are required",
        ));
    }
    let mut actions = BTreeSet::new();
    for action in &manifest.actions {
        if !valid_slug(&action.name) || !actions.insert(&action.name) {
            return Err(DomainError::new(
                ErrorCode::ConfigInvalid,
                "invalid or duplicate plugin action",
            ));
        }
    }
    Ok(())
}

async fn run_js_stage(
    plugin: &LoadedPlugin,
    stage: &'static str,
    input: &Value,
    observations: &Value,
    context: &Value,
) -> DomainResult<Value> {
    let script = plugin.script.clone();
    let input =
        serde_json::to_string(input).map_err(|error| DomainError::invalid(error.to_string()))?;
    let observations = serde_json::to_string(observations)
        .map_err(|error| DomainError::invalid(error.to_string()))?;
    let context =
        serde_json::to_string(context).map_err(|error| DomainError::invalid(error.to_string()))?;
    let memory = plugin
        .manifest
        .limits
        .memory_mb
        .unwrap_or(DEFAULT_MEMORY_MB)
        .clamp(4, MAX_MEMORY_MB)
        * 1024
        * 1024;
    let js_stage_timeout_ms = plugin
        .manifest
        .limits
        .js_stage_timeout_ms
        .unwrap_or(DEFAULT_JS_STAGE_TIMEOUT_MS)
        .clamp(250, MAX_JS_STAGE_TIMEOUT_MS);
    tokio::task::spawn_blocking(move || {
        run_js_sync(
            &script,
            stage,
            &input,
            &observations,
            &context,
            memory,
            Duration::from_millis(js_stage_timeout_ms),
        )
    })
    .await
    .map_err(|error| {
        DomainError::new(ErrorCode::Internal, format!("plugin runtime task: {error}"))
    })?
}

fn run_js_sync(
    script: &str,
    stage: &str,
    input: &str,
    observations: &str,
    context: &str,
    memory_limit: usize,
    stage_timeout: Duration,
) -> DomainResult<Value> {
    let runtime = Runtime::new().map_err(|error| {
        DomainError::new(ErrorCode::Unavailable, format!("QuickJS runtime: {error}"))
    })?;
    runtime.set_memory_limit(memory_limit);
    runtime.set_max_stack_size(512 * 1024);
    let deadline = Instant::now() + stage_timeout;
    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupted_handler = interrupted.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        let expired = Instant::now() >= deadline;
        if expired {
            interrupted_handler.store(true, Ordering::Relaxed);
        }
        expired
    })));
    let context_handle = Context::full(&runtime).map_err(|error| {
        DomainError::new(ErrorCode::Unavailable, format!("QuickJS context: {error}"))
    })?;
    let output = context_handle.with(|ctx| -> Result<String, rquickjs::Error> {
        ctx.eval::<(), _>(script)?;
        let expression = match stage {
            "plan" => format!(
                "JSON.stringify(globalThis.HuntProxyPlugin.plan({input},{context}))"
            ),
            "analyze" => format!(
                "JSON.stringify(globalThis.HuntProxyPlugin.analyze({input},{observations},{context}))"
            ),
            _ => unreachable!(),
        };
        ctx.eval(expression)
    });
    if interrupted.load(Ordering::Relaxed) {
        return Err(DomainError::new(
            ErrorCode::Timeout,
            format!(
                "plugin JavaScript stage exceeded {} ms",
                stage_timeout.as_millis()
            ),
        ));
    }
    let output = output.map_err(|error| {
        DomainError::new(
            ErrorCode::ProtocolError,
            format!("plugin JavaScript {stage}: {error}"),
        )
    })?;
    serde_json::from_str(&output).map_err(|error| {
        DomainError::new(
            ErrorCode::ProtocolError,
            format!("plugin {stage} returned invalid JSON: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_job(state: PluginJobState) -> Arc<PluginJob> {
        Arc::new(PluginJob {
            view: parking_lot::RwLock::new(PluginJobView {
                id: Uuid::new_v4(),
                project_id: ProjectId(1),
                plugin_id: "test".into(),
                action: "run".into(),
                base_exchange_id: None,
                state,
                operation_count: 0,
                completed_operations: 0,
                result: None,
                error: None,
            }),
            cancel: CancellationToken::new(),
        })
    }

    #[test]
    fn javascript_plan_and_analysis_are_bounded_json() {
        let script = r#"globalThis.HuntProxyPlugin = {
          plan(input, context) { return {operations: [], result: {value: input.value, api: context.api_version}}; },
          analyze(input, observations) { return {count: observations.length, value: input.value}; }
        };"#;
        let plan = run_js_sync(
            script,
            "plan",
            r#"{"value":7}"#,
            "null",
            r#"{"api_version":1}"#,
            4 * 1024 * 1024,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(plan["result"]["value"], 7);
        let analysis = run_js_sync(
            script,
            "analyze",
            r#"{"value":7}"#,
            "[]",
            "{}",
            4 * 1024 * 1024,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(analysis, json!({"count":0,"value":7}));
    }

    #[test]
    fn javascript_stage_timeout_is_explicit_and_bounded() {
        let script = r#"globalThis.HuntProxyPlugin = {
          plan() { while (true) {} }, analyze() { return {}; }
        };"#;
        let error = run_js_sync(
            script,
            "plan",
            "{}",
            "null",
            "{}",
            4 * 1024 * 1024,
            Duration::from_millis(10),
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Timeout);
        assert!(error.to_string().contains("10 ms"));
    }

    #[test]
    fn plugin_plans_can_require_ordered_stop_on_error_execution() {
        let sequential: PluginPlan = serde_json::from_value(json!({
            "execution": "sequential",
            "stop_on_error": true,
            "operations": [],
            "result": {}
        }))
        .unwrap();
        assert_eq!(sequential.execution, PluginExecution::Sequential);
        assert!(sequential.stop_on_error);

        let default: PluginPlan = serde_json::from_value(json!({
            "operations": [],
            "result": {}
        }))
        .unwrap();
        assert_eq!(default.execution, PluginExecution::Parallel);
        assert!(!default.stop_on_error);
    }

    #[test]
    fn http_workflow_plan_is_bounded_and_counts_each_request() {
        let plan: PluginPlan = serde_json::from_value(json!({
            "operations": [{
                "type": "http_workflow",
                "id": "fresh-csrf",
                "steps": [{
                    "id": "acquire",
                    "request": {
                        "id": "ignored-by-host",
                        "url": "https://example.test/form"
                    },
                    "extract": [{
                        "from": "body_regex",
                        "name": "csrf",
                        "pattern": "name=\\\"csrf\\\" value=\\\"([^\\\"]+)\\\""
                    }]
                }, {
                    "id": "submit",
                    "request": {
                        "id": "ignored-by-host",
                        "base_exchange_id": 42,
                        "body_params": [{"name":"csrf","value":"{{extract:csrf}}"}]
                    }
                }]
            }]
        }))
        .unwrap();
        assert_eq!(operation_request_count(&plan.operations[0]), 2);
        let PluginOperation::HttpWorkflow(workflow) = &plan.operations[0] else {
            panic!("expected workflow")
        };
        assert_eq!(workflow.steps[0].extract[0].name(), "csrf");
    }

    #[test]
    fn http_workflow_extracts_and_substitutes_without_returning_values() {
        let observation = json!({
            "response_headers": [{
                "name": "X-Request-Token",
                "value_base64": base64::engine::general_purpose::STANDARD.encode(b"head token")
            }],
            "response_body_base64": base64::engine::general_purpose::STANDARD.encode(
                br#"{"csrf":"a+b/c","html":"token-123"}"#
            )
        });
        let json_extract = PluginWorkflowExtract::Json {
            name: "csrf".into(),
            pointer: "/csrf".into(),
            encoding: PluginWorkflowEncoding::Url,
            required: true,
        };
        let header_extract = PluginWorkflowExtract::Header {
            name: "header".into(),
            header: "x-request-token".into(),
            encoding: PluginWorkflowEncoding::Base64,
            required: true,
        };
        assert_eq!(
            json_extract.extract(&observation).unwrap(),
            Some("a%2Bb%2Fc".into())
        );
        assert_eq!(
            header_extract.extract(&observation).unwrap(),
            Some("aGVhZCB0b2tlbg==".into())
        );

        let mut values = HashMap::new();
        values.insert("csrf".into(), "a%2Bb%2Fc".into());
        let mut request: PluginHttpRequest = serde_json::from_value(json!({
            "id": "submit",
            "url": "https://example.test/submit?csrf={{extract:csrf}}",
            "headers": [{"name":"X-CSRF","value":"{{extract:csrf}}"}],
            "body_params": [{"name":"csrf","value":"{{extract:csrf}}"}]
        }))
        .unwrap();
        substitute_workflow_request(&mut request, &values).unwrap();
        assert!(request.url.as_deref().unwrap().ends_with("csrf=a%2Bb%2Fc"));
        assert_eq!(request.headers[0].value, b"a%2Bb%2Fc");
        assert_eq!(request.body_params[0].value.as_deref(), Some("a%2Bb%2Fc"));
        assert!(substitute_workflow_template("{{extract:missing}}", &values).is_err());
    }

    #[test]
    fn plugin_scope_defaults_to_exact_project_target() {
        let scope = ScopePolicy::default();
        assert!(
            enforce_plugin_scope("https://example.test/a", &scope, Some("example.test")).is_ok()
        );
        assert_eq!(
            enforce_plugin_scope("https://other.test/a", &scope, Some("example.test"))
                .unwrap_err()
                .code(),
            ErrorCode::ScopeDenied
        );
    }

    #[test]
    fn package_loader_checks_integrity_and_loads_bounded_resources() {
        let temp = tempfile::tempdir().unwrap();
        let plugin = temp.path().join("sample");
        std::fs::create_dir_all(plugin.join("resources")).unwrap();
        let script =
            b"globalThis.HuntProxyPlugin={plan(){return {operations:[]}},analyze(){return {}}};";
        std::fs::write(plugin.join("index.js"), script).unwrap();
        std::fs::write(plugin.join("resources/params.txt"), "alpha\nbeta\n").unwrap();
        let resource_bytes = b"alpha\nbeta\n";
        let manifest = json!({
            "schema_version": 1,
            "id": "sample-plugin",
            "name": "Sample Plugin",
            "version": "1.0.0",
            "description": "test",
            "enabled": true,
            "entrypoint": "index.js",
            "entrypoint_sha256": hex::encode(Sha256::digest(script)),
            "resources": {"params.txt": {"path":"resources/params.txt", "sha256":hex::encode(Sha256::digest(resource_bytes))}},
            "capabilities": [],
            "actions": [{"name":"inspect_request","description":"test","input_schema":{"type":"object"}}]
        });
        std::fs::write(
            plugin.join("plugin.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let loaded = load_plugin(&plugin).unwrap();
        assert_eq!(
            loaded.resources.get("params.txt").map(String::as_str),
            Some("alpha\nbeta\n")
        );

        std::fs::write(plugin.join("index.js"), "changed").unwrap();
        assert_eq!(
            load_plugin(&plugin).unwrap_err().code(),
            ErrorCode::ConfigInvalid
        );
    }

    #[test]
    fn completed_job_retention_is_bounded_without_removing_active_jobs() {
        let jobs = DashMap::new();
        for _ in 0..MAX_RETAINED_JOBS {
            let job = test_job(PluginJobState::Completed);
            jobs.insert(job.view.read().id, job.clone());
        }
        let active = test_job(PluginJobState::Running);
        let active_id = active.view.read().id;
        jobs.insert(active_id, active);

        prune_finished_jobs(&jobs);

        assert_eq!(jobs.len(), MAX_RETAINED_JOBS - 1);
        assert!(jobs.contains_key(&active_id));
    }

    #[test]
    fn operation_failures_become_observations_but_cancellation_still_stops_the_job() {
        let observation = isolate_operation_result(
            "probe:one".into(),
            Err(DomainError::new(ErrorCode::ProtocolError, "bad response")),
        )
        .unwrap();
        assert_eq!(observation["id"], "probe:one");
        assert_eq!(observation["error"]["code"], "protocol_error");

        let cancelled = isolate_operation_result(
            "probe:two".into(),
            Err(DomainError::new(ErrorCode::Cancelled, "cancelled")),
        )
        .unwrap_err();
        assert_eq!(cancelled.code(), ErrorCode::Cancelled);
        assert_eq!(normalize_operation_label("a:b/c"), "a_b_c");
    }

    #[test]
    fn semantic_plugin_bodies_are_decoded_before_analysis() {
        use std::io::Write;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"stable account body").unwrap();
        let compressed = encoder.finish().unwrap();
        let headers = vec![HeaderEntry {
            name: "Content-Encoding".into(),
            value: b"gzip".to_vec(),
            ordinal: 0,
        }];
        let presented = plugin_response_body(&headers, compressed);
        assert!(!presented.truncated);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(presented.body_base64.unwrap())
                .unwrap(),
            b"stable account body"
        );

        let unsupported = plugin_response_body(
            &[HeaderEntry {
                name: "Content-Encoding".into(),
                value: b"compress".to_vec(),
                ordinal: 0,
            }],
            b"binary".to_vec(),
        );
        assert!(unsupported.body_base64.is_none());
        assert!(unsupported.truncated);
    }

    #[test]
    fn raw_plugin_observations_include_a_bounded_response_transcript() {
        let response = crate::reply::RawReplyResult {
            exchange_id: Some(ExchangeId(9)),
            status_code: Some(200),
            response_bytes: 2,
            truncated: false,
            read_outcome: crate::reply::RawReadOutcome::Complete,
            responses: vec![],
            response_base64: None,
        };
        let value = plugin_raw_observation(&response, Some(b"ok".to_vec())).unwrap();
        assert_eq!(value["response_transcript_base64"], "b2s=");
        assert_eq!(value["response_transcript_truncated"], false);
    }

    #[test]
    fn raw_http2_plan_preserves_ordered_malformed_fields() {
        let plan: PluginPlan = serde_json::from_value(json!({
            "operations": [{
                "type": "raw_http2",
                "id": "h2-probe",
                "target_url": "https://example.test/",
                "streams": [{
                    "id": "stream-one",
                    "headers": [
                        {"name":":method","value":"POST"},
                        {"name":"x-smuggle","value":"a\r\nb: c"},
                        {"name":":path","value":"/first"},
                        {"name":":path","value":"/second"}
                    ],
                    "body_text": "x"
                }],
                "options": {"final_data_together": false}
            }]
        }))
        .unwrap();
        let PluginOperation::RawHttp2(operation) = &plan.operations[0] else {
            panic!("expected raw HTTP/2 operation")
        };
        assert_eq!(operation.streams[0].headers[1].value, "a\r\nb: c");
        assert_eq!(operation.streams[0].headers[3].value, "/second");
    }

    #[test]
    fn race_requests_accept_unsent_templates_and_overrides() {
        let request: RaceRequest = serde_json::from_value(json!({
            "id": "coupon-0",
            "method": "POST",
            "url": "https://example.test/cart/coupon",
            "headers": [{"name":"Content-Type","value":"application/json"}],
            "body_text": "{\"coupon\":\"TEST\"}",
            "protocol": "h1",
            "use_project_cookies": true,
            "success": {
                "status_codes": [200],
                "json": [{"pointer":"/applied","equals":true}]
            }
        }))
        .unwrap();
        let draft = race_request_draft(&request).unwrap();
        assert_eq!(draft.method.as_deref(), Some("POST"));
        assert_eq!(draft.body_text.as_deref(), Some("{\"coupon\":\"TEST\"}"));
        assert!(request.base_exchange_id.is_none());
        assert!(request.use_project_cookies);

        let inherited: RaceRequest = serde_json::from_value(json!({
            "id": "shape-0",
            "base_exchange_id": 42,
            "url": "https://example.test/alternate",
            "header_tombstones": ["If-Match"]
        }))
        .unwrap();
        assert_eq!(inherited.base_exchange_id, Some(ExchangeId(42)));
        assert_eq!(
            race_request_draft(&inherited).unwrap().header_tombstones,
            vec!["If-Match"]
        );
    }

    #[test]
    fn semantic_success_predicates_cover_status_headers_body_json_and_redirects() {
        let headers = vec![
            HeaderEntry {
                name: "X-State".into(),
                value: b"applied-twice".to_vec(),
                ordinal: 0,
            },
            HeaderEntry {
                name: "Location".into(),
                value: b"/orders/123".to_vec(),
                ordinal: 1,
            },
        ];
        let predicate: RaceSuccessPredicate = serde_json::from_value(json!({
            "status_codes": [302],
            "headers": [{"name":"X-State","contains":"twice"}],
            "body_contains": "confirmed",
            "body_regex": "order_[0-9]+",
            "json": [{"pointer":"/confirmed","equals":true}],
            "redirect_location": {"regex":"^/orders/[0-9]+$"}
        }))
        .unwrap();
        let result = evaluate_race_success(
            Some(302),
            &headers,
            br#"{"confirmed":true,"message":"confirmed order_123"}"#,
            false,
            &predicate,
        )
        .unwrap();
        assert_eq!(result["matched"], true);
        assert_eq!(result["indeterminate"], false);

        let mismatch: RaceSuccessPredicate =
            serde_json::from_value(json!({"body_contains":"missing"})).unwrap();
        let result = evaluate_race_success(Some(200), &[], b"partial", true, &mismatch).unwrap();
        assert_eq!(result["matched"], false);
        assert_eq!(result["indeterminate"], true);
    }

    #[test]
    fn inline_last_byte_requests_are_normalized_to_exact_http1() {
        let request = crate::reply::MaterializedRequest {
            method: "POST".into(),
            url: "https://example.test:8443/apply?mode=one".into(),
            headers: vec![
                ("Content-Type".into(), b"text/plain".to_vec()),
                ("Content-Length".into(), b"999".to_vec()),
            ],
            body: Some(b"go".to_vec()),
        };
        let bytes = materialized_http1_bytes(&request).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("POST /apply?mode=one HTTP/1.1\r\nHost: example.test:8443\r\n"));
        assert_eq!(text.matches("Content-Length:").count(), 1);
        assert!(text.ends_with("Connection: close\r\n\r\ngo"));
    }
}
