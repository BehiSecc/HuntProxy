//! Bounded, host-owned extension runtime.
//!
//! Extensions are pure JavaScript orchestration. They can describe bounded
//! HTTP and explicitly declared cloud operations, but receive no filesystem,
//! process, socket, or secret APIs; HuntProxy validates and executes them.

use crate::cookies::CookiePair;
use crate::domain::*;
use crate::policy::url_is_in_scope;
use crate::reply::{ReplySendContext, ReplyService};
use base64::Engine;
use dashmap::DashMap;
use futures::{stream, StreamExt};
use rquickjs::{
    function::This, CatchResultExt, Context, Function, Object, Runtime, Value as JsValue,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
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
const MAX_MEMORY_MB: usize = 128;
const MAX_ANALYSIS_OBSERVATION_BYTES: usize = 24 * 1024 * 1024;
const DEFAULT_JS_STAGE_TIMEOUT_MS: u64 = 2_000;
const MAX_JS_STAGE_TIMEOUT_MS: u64 = 120_000;
const MAX_ACTIVE_JOBS: usize = 4;
const MAX_RETAINED_JOBS: usize = 256;
const MAX_WORKFLOW_STEPS: usize = 64;
const MAX_WORKFLOW_EXTRACTS_PER_STEP: usize = 16;
const MAX_RACE_EXTRACTS_PER_PLAN: usize = 256;
const MAX_WORKFLOW_VALUE_BYTES: usize = 8 * 1024;
const MAX_WORKFLOW_VALUES_BYTES: usize = 64 * 1024;
const MAX_RAW_HTTP1_GROUP_MEMBERS: usize = 32;
const MAX_RAW_HTTP1_GROUP_AGGREGATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HTTP_REQUEST_DELAY_MS: u64 = 30_000;
const MAX_ANALYSIS_CHECKPOINT_BYTES: usize = 128 * 1024 * 1024;
const MAX_COMPRESSED_ANALYSIS_CHECKPOINT_BYTES: usize = 32 * 1024 * 1024;
const MAX_TOTAL_ANALYSIS_CHECKPOINT_BYTES: usize = 128 * 1024 * 1024;

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

#[derive(Debug, Clone, Serialize)]
pub struct PluginDescription {
    #[serde(flatten)]
    pub manifest: PluginManifest,
    pub effective_limits: EffectivePluginLimits,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectivePluginLimits {
    pub job_timeout_ms: u64,
    pub js_stage_timeout_ms: u64,
    pub host_max_js_stage_timeout_ms: u64,
    pub max_operations: usize,
    pub max_concurrency: usize,
    pub memory_mb: usize,
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
    #[serde(default)]
    pub requires_base_exchange: bool,
}

fn object_schema() -> Value {
    json!({"type":"object"})
}

fn validate_action_base_exchange(
    plugin: &PluginManifest,
    action: &PluginAction,
    base_exchange_id: Option<ExchangeId>,
) -> DomainResult<()> {
    if action.requires_base_exchange && base_exchange_id.is_none() {
        return Err(DomainError::invalid(format!(
            "{} requires base_exchange_id. Capture a saved request, then preview the {} action again.",
            plugin.name, action.name
        )));
    }
    Ok(())
}

fn max_requested_exchange_contexts(manifest: &PluginManifest) -> usize {
    manifest
        .limits
        .max_operations
        .unwrap_or(DEFAULT_MAX_OPERATIONS)
        .clamp(1, MAX_OPERATIONS)
}

fn effective_plugin_limits(manifest: &PluginManifest) -> EffectivePluginLimits {
    EffectivePluginLimits {
        job_timeout_ms: manifest
            .limits
            .timeout_ms
            .unwrap_or(DEFAULT_TIMEOUT_MS)
            .clamp(1_000, MAX_TIMEOUT_MS),
        js_stage_timeout_ms: manifest
            .limits
            .js_stage_timeout_ms
            .unwrap_or(DEFAULT_JS_STAGE_TIMEOUT_MS)
            .clamp(250, MAX_JS_STAGE_TIMEOUT_MS),
        host_max_js_stage_timeout_ms: MAX_JS_STAGE_TIMEOUT_MS,
        max_operations: manifest
            .limits
            .max_operations
            .unwrap_or(DEFAULT_MAX_OPERATIONS)
            .clamp(1, MAX_OPERATIONS),
        max_concurrency: manifest.limits.max_concurrency.unwrap_or(4).clamp(1, 100),
        memory_mb: manifest
            .limits
            .memory_mb
            .unwrap_or(DEFAULT_MEMORY_MB)
            .clamp(4, MAX_MEMORY_MB),
    }
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

#[derive(Debug, Clone, Serialize)]
pub struct PluginSummary {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub enabled: bool,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginLoadIssue {
    pub package: String,
    pub message: String,
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

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginJobPhase {
    Queued,
    Planning,
    Executing,
    Analyzing,
    Persisting,
    Finished,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginResultView {
    #[default]
    Summary,
    Findings,
    Full,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginJobView {
    pub id: Uuid,
    pub project_id: ProjectId,
    pub plugin_id: String,
    pub action: String,
    pub base_exchange_id: Option<ExchangeId>,
    pub state: PluginJobState,
    pub phase: PluginJobPhase,
    pub operation_count: usize,
    pub completed_operations: usize,
    /// Adaptive hint for agents and UIs. Omitted for terminal jobs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_poll_interval_ms: Option<u64>,
    pub analysis_resume_available: bool,
    pub analysis_checkpoint_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_resume_reason: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
struct PluginJobRecord {
    id: Uuid,
    project_id: ProjectId,
    plugin_id: String,
    action: String,
    base_exchange_id: Option<ExchangeId>,
    state: PluginJobState,
    phase: PluginJobPhase,
    operation_count: usize,
    completed_operations: usize,
    result: Option<Value>,
    analysis_resume_available: bool,
    analysis_checkpoint_status: String,
    analysis_resume_reason: Option<String>,
    error: Option<String>,
}

impl PluginJobRecord {
    fn status(&self) -> PluginJobView {
        PluginJobView {
            id: self.id,
            project_id: self.project_id,
            plugin_id: self.plugin_id.clone(),
            action: self.action.clone(),
            base_exchange_id: self.base_exchange_id,
            state: self.state,
            phase: self.phase,
            operation_count: self.operation_count,
            completed_operations: self.completed_operations,
            recommended_poll_interval_ms: recommended_poll_interval_ms(self),
            analysis_resume_available: self.analysis_resume_available,
            analysis_checkpoint_status: self.analysis_checkpoint_status.clone(),
            analysis_resume_reason: self.analysis_resume_reason.clone(),
            error: self.error.clone(),
        }
    }
}

struct PluginJob {
    view: parking_lot::RwLock<PluginJobRecord>,
    cancel: CancellationToken,
    analysis_checkpoint: parking_lot::Mutex<Option<AnalysisCheckpoint>>,
}

#[derive(Debug, Clone)]
struct AnalysisCheckpoint {
    plugin_version: String,
    entrypoint_sha256: String,
    input: Value,
    observations_zstd: Arc<Vec<u8>>,
    observations_bytes: usize,
    observations_fallback: Option<Value>,
    context: Value,
    plan_result: Value,
    execution_evidence_exchange_ids: Vec<ExchangeId>,
    _reservation: Arc<CheckpointReservation>,
}

#[derive(Debug)]
struct CheckpointReservation {
    bytes: usize,
    total: Arc<AtomicUsize>,
}

impl Drop for CheckpointReservation {
    fn drop(&mut self) {
        self.total.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

fn recommended_poll_interval_ms(job: &PluginJobRecord) -> Option<u64> {
    if matches!(
        job.state,
        PluginJobState::Completed | PluginJobState::Failed | PluginJobState::Cancelled
    ) {
        return None;
    }
    match job.phase {
        PluginJobPhase::Queued | PluginJobPhase::Planning | PluginJobPhase::Analyzing => Some(500),
        PluginJobPhase::Persisting => Some(250),
        PluginJobPhase::Finished => None,
        PluginJobPhase::Executing => {
            let remaining = job.operation_count.saturating_sub(job.completed_operations);
            Some(match remaining {
                0..=10 => 500,
                11..=100 => 1_000,
                101..=500 => 2_000,
                _ => 5_000,
            })
        }
    }
}

#[derive(Clone)]
pub struct PluginService {
    directory: PathBuf,
    reply: Arc<ReplyService>,
    db: Arc<crate::storage::Db>,
    browser: Option<Arc<crate::browser::BrowserService>>,
    plugins: Arc<HashMap<String, Arc<LoadedPlugin>>>,
    load_issues: Arc<Vec<PluginLoadIssue>>,
    jobs: Arc<DashMap<Uuid, Arc<PluginJob>>>,
    active_jobs: Arc<tokio::sync::Semaphore>,
    preview_slots: Arc<tokio::sync::Semaphore>,
    analysis_retry_slots: Arc<tokio::sync::Semaphore>,
    analysis_checkpoint_bytes: Arc<AtomicUsize>,
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
    #[serde(default)]
    preview: Option<PluginPlanPreview>,
}

struct PreparedPluginPlan {
    plan: PluginPlan,
    context: Value,
    resolved_identities: Arc<HashMap<String, ResolvedPluginIdentity>>,
    planned_requests: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
struct PluginPlanPreview {
    stage: Option<String>,
    scope: Option<String>,
    follow_up_expected: Option<bool>,
    candidate_count: Option<usize>,
    candidate_unit: Option<String>,
    candidate_breakdown: BTreeMap<String, usize>,
    selected_mode: Option<String>,
    supported_modes: Vec<String>,
    recommended_mode: Option<String>,
    recommendation: Option<String>,
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
    AwsApiGateway(PluginAwsApiGateway),
    RawHttp1(PluginRawHttp1),
    RawHttp1Group(PluginRawHttp1Group),
    RawHttp2(PluginRawHttp2),
    RaceGroup(PluginRaceGroup),
    BrowserCsrf(PluginBrowserCsrf),
}

impl PluginOperation {
    fn id(&self) -> &str {
        match self {
            Self::HttpRequest(request) => &request.id,
            Self::HttpWorkflow(workflow) => &workflow.id,
            Self::AwsApiGateway(operation) => operation.id(),
            Self::RawHttp1(request) => &request.id,
            Self::RawHttp1Group(group) => &group.id,
            Self::RawHttp2(request) => &request.id,
            Self::RaceGroup(group) => &group.id,
            Self::BrowserCsrf(probe) => &probe.id,
        }
    }
}

fn operation_type_name(operation: &PluginOperation) -> &'static str {
    match operation {
        PluginOperation::HttpRequest(_) => "http_request",
        PluginOperation::HttpWorkflow(_) => "http_workflow",
        PluginOperation::AwsApiGateway(_) => "aws_api_gateway",
        PluginOperation::RawHttp1(_) => "raw_http1",
        PluginOperation::RawHttp1Group(_) => "raw_http1_group",
        PluginOperation::RawHttp2(_) => "raw_http2",
        PluginOperation::RaceGroup(_) => "race_group",
        PluginOperation::BrowserCsrf(_) => "browser_csrf",
    }
}

fn operation_required_capability(operation: &PluginOperation) -> &'static str {
    match operation {
        PluginOperation::HttpRequest(_) | PluginOperation::HttpWorkflow(_) => "http.semantic",
        PluginOperation::AwsApiGateway(_) => "aws.api_gateway",
        PluginOperation::RawHttp1(_)
        | PluginOperation::RawHttp1Group(_)
        | PluginOperation::RawHttp2(_) => "http.raw",
        PluginOperation::RaceGroup(_) => "http.race",
        PluginOperation::BrowserCsrf(_) => "browser.csrf",
    }
}

fn validate_plugin_input_size(input: &Value) -> DomainResult<()> {
    let input_bytes = serde_json::to_vec(input)
        .map_err(|error| DomainError::invalid(format!("invalid plugin input: {error}")))?;
    if input_bytes.len() > MAX_INPUT_BYTES {
        return Err(DomainError::new(
            ErrorCode::BodyTooLarge,
            "plugin input exceeds 2 MiB",
        ));
    }
    Ok(())
}

fn reserve_checkpoint_bytes(
    total: &Arc<AtomicUsize>,
    compressed: Vec<u8>,
) -> Option<(Arc<Vec<u8>>, Arc<CheckpointReservation>)> {
    let bytes = compressed.len();
    let admitted = total.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        current
            .checked_add(bytes)
            .filter(|next| *next <= MAX_TOTAL_ANALYSIS_CHECKPOINT_BYTES)
    });
    admitted.ok()?;
    Some((
        Arc::new(compressed),
        Arc::new(CheckpointReservation {
            bytes,
            total: total.clone(),
        }),
    ))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum PluginAwsApiGateway {
    Enable {
        id: String,
        target_url: String,
        regions: Vec<String>,
        stage_name: String,
    },
    Disable {
        id: String,
        target_url: String,
    },
    Status {
        id: String,
    },
}

impl PluginAwsApiGateway {
    fn id(&self) -> &str {
        match self {
            Self::Enable { id, .. } | Self::Disable { id, .. } | Self::Status { id } => id,
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
    #[serde(default)]
    extract: Vec<PluginWorkflowExtract>,
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
#[serde(deny_unknown_fields)]
struct PluginRawHttp1Group {
    id: String,
    target_url: String,
    members: Vec<PluginRawHttp1GroupMember>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginRawHttp1GroupMember {
    id: String,
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
    #[serde(default)]
    delay_before_ms: u64,
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
    #[serde(default)]
    credential_mode: PluginCredentialMode,
    identity: Option<PluginIdentitySelector>,
    identity_comparison: Option<String>,
    observe: Option<PluginObservationPolicy>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PluginObservationPolicy {
    #[serde(default)]
    body_bytes: usize,
    #[serde(default)]
    body_contains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginIdentitySelector {
    profile: Option<String>,
    cookie_file: Option<String>,
}

#[derive(Debug, Clone)]
enum ResolvedPluginIdentity {
    Profile(crate::cookies::StoredCookieProfile),
    CookieInput(String),
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PluginCredentialMode {
    #[default]
    WithProjectCredentials,
    WithoutProjectCredentials,
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

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PluginBrowserCsrfMode {
    TopLevelGet,
    CrossSiteFormPost,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginBrowserCsrf {
    id: String,
    base_exchange_id: ExchangeId,
    mode: PluginBrowserCsrfMode,
    #[serde(default)]
    query_params: Vec<PluginParamPatch>,
    #[serde(default)]
    body_params: Vec<PluginParamPatch>,
    #[serde(default)]
    header_tombstones: Vec<String>,
    identity: Option<PluginIdentitySelector>,
    attacker_origin: Option<String>,
    #[serde(default = "default_browser_csrf_timeout_ms")]
    timeout_ms: u64,
}

fn default_browser_csrf_timeout_ms() -> u64 {
    15_000
}

impl PluginService {
    pub fn load(
        directory: PathBuf,
        db: Arc<crate::storage::Db>,
        reply: Arc<ReplyService>,
    ) -> DomainResult<Self> {
        Self::load_with_browser(directory, db, reply, None)
    }

    pub fn load_with_browser(
        directory: PathBuf,
        db: Arc<crate::storage::Db>,
        reply: Arc<ReplyService>,
        browser: Option<Arc<crate::browser::BrowserService>>,
    ) -> DomainResult<Self> {
        crate::config::create_private_dir(&directory)?;
        let mut plugins = HashMap::new();
        let mut load_issues = Vec::new();
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
                    let plugin_id = plugin.manifest.id.clone();
                    if plugins.contains_key(&plugin_id) {
                        load_issues.push(PluginLoadIssue {
                            package: entry.file_name().to_string_lossy().into_owned(),
                            message: format!("duplicate plugin id {plugin_id}"),
                        });
                    } else {
                        plugins.insert(plugin_id, Arc::new(plugin));
                    }
                }
                Err(error) => {
                    tracing::warn!(path=%entry.path().display(), %error, "plugin rejected");
                    load_issues.push(PluginLoadIssue {
                        package: entry.file_name().to_string_lossy().into_owned(),
                        message: error.to_string(),
                    });
                }
            }
        }
        load_issues.sort_by(|left, right| left.package.cmp(&right.package));
        Ok(Self {
            directory,
            reply,
            db,
            browser,
            plugins: Arc::new(plugins),
            load_issues: Arc::new(load_issues),
            jobs: Arc::new(DashMap::new()),
            active_jobs: Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_JOBS)),
            preview_slots: Arc::new(tokio::sync::Semaphore::new(2)),
            analysis_retry_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            analysis_checkpoint_bytes: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn list(&self) -> Vec<PluginSummary> {
        let mut plugins = self
            .plugins
            .values()
            .map(|plugin| PluginSummary {
                id: plugin.manifest.id.clone(),
                name: plugin.manifest.name.clone(),
                version: plugin.manifest.version.clone(),
                description: bounded_chars(&plugin.manifest.description, 240),
                enabled: plugin.manifest.enabled,
                actions: plugin
                    .manifest
                    .actions
                    .iter()
                    .map(|action| action.name.clone())
                    .collect(),
            })
            .collect::<Vec<_>>();
        plugins.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        plugins
    }

    pub fn load_issues(&self) -> &[PluginLoadIssue] {
        &self.load_issues
    }

    fn enabled_plugin_action(
        &self,
        plugin_id: &str,
        action: &str,
    ) -> DomainResult<Arc<LoadedPlugin>> {
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
        if !plugin
            .manifest
            .actions
            .iter()
            .any(|candidate| candidate.name == action)
        {
            return Err(DomainError::not_found(format!("plugin action {action}")));
        }
        Ok(plugin)
    }

    pub fn describe(&self, id: &str) -> DomainResult<PluginDescription> {
        self.plugins
            .get(id)
            .map(|plugin| PluginDescription {
                manifest: plugin.manifest.clone(),
                effective_limits: effective_plugin_limits(&plugin.manifest),
            })
            .ok_or_else(|| DomainError::not_found(format!("plugin {id}")))
    }

    pub async fn preview(
        &self,
        project_id: ProjectId,
        plugin_id: &str,
        action: &str,
        base_exchange_id: Option<ExchangeId>,
        input: Value,
    ) -> DomainResult<Value> {
        validate_plugin_input_size(&input)?;
        let _preview_permit = self
            .preview_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    "at most 2 extension previews may plan concurrently",
                )
            })?;
        let plugin = self.enabled_plugin_action(plugin_id, action)?;
        let action_manifest = plugin
            .manifest
            .actions
            .iter()
            .find(|candidate| candidate.name == action)
            .expect("enabled_plugin_action validated action");
        validate_action_base_exchange(&plugin.manifest, action_manifest, base_exchange_id)?;
        let started = Instant::now();
        let prepared = self
            .prepare_plugin_plan(project_id, base_exchange_id, plugin.clone(), action, &input)
            .await?;
        let project = self.db.get_project(project_id).await?;
        let mut by_type = BTreeMap::<String, usize>::new();
        for operation in &prepared.plan.operations {
            let kind = operation_type_name(operation).to_string();
            *by_type.entry(kind).or_default() += operation_request_count(operation);
        }
        let concurrency = if prepared.plan.execution == PluginExecution::Sequential {
            1
        } else {
            plugin
                .manifest
                .limits
                .max_concurrency
                .unwrap_or(4)
                .clamp(1, project.limits.max_concurrent_requests.max(1) as usize)
        };
        let rate = project.limits.requests_per_second.max(0.1);
        let rate_floor_ms = (prepared.planned_requests as f64 / rate * 1_000.0).ceil() as u64;
        let request_runtime_ms = ((prepared.planned_requests as u64 * 1_000)
            / concurrency.max(1) as u64)
            .max(rate_floor_ms);
        let preview = prepared.plan.preview.clone().unwrap_or_default();
        let preview = json!({
            "plugin_id": plugin.manifest.id,
            "plugin_version": plugin.manifest.version,
            "action": action,
            "planning_ms": started.elapsed().as_millis() as u64,
            "valid_for_ms": 30_000,
            "operations": {
                "requests": prepared.planned_requests,
                "top_level": prepared.plan.operations.len(),
                "limit": effective_plugin_limits(&plugin.manifest).max_operations,
                "execution": match prepared.plan.execution { PluginExecution::Sequential => "sequential", PluginExecution::Parallel => "parallel" },
                "by_type": by_type,
            },
            "runtime": {
                "likely_ms": request_runtime_ms,
                "low_ms": request_runtime_ms / 2,
                "high_ms": request_runtime_ms.saturating_mul(2),
                "confidence": "low",
                "basis": "project request rate, effective concurrency, and a conservative one-second request-latency fallback",
                "job_timeout_ms": effective_plugin_limits(&plugin.manifest).job_timeout_ms,
            },
            "stage": preview.stage,
            "scope": preview.scope.unwrap_or_else(|| "current_stage".into()),
            "follow_up_expected": preview.follow_up_expected,
            "candidates": preview.candidate_count.map(|total| json!({"total":total,"unit":preview.candidate_unit,"by_family":preview.candidate_breakdown})),
            "selected_mode": preview.selected_mode,
            "supported_modes": preview.supported_modes,
            "recommended_mode": preview.recommended_mode,
            "recommendation": preview.recommended_mode.as_ref().map(|mode| format!("Use {mode} for the extension's recommended coverage; preview and run use the same planner.")),
            "side_effects": false,
            "warning": "Preview is stage-scoped and sends no requests; runtime and later follow-up stages remain estimates.",
        });
        let preview = self
            .redact_plugin_output(project_id, base_exchange_id, preview)
            .await?;
        if serde_json::to_vec(&preview).map_or(true, |bytes| bytes.len() > 64 * 1024) {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                "extension preview exceeds 64 KiB",
            ));
        }
        Ok(preview)
    }

    pub async fn run(
        &self,
        project_id: ProjectId,
        plugin_id: &str,
        action: &str,
        base_exchange_id: Option<ExchangeId>,
        input: Value,
    ) -> DomainResult<PluginJobView> {
        validate_plugin_input_size(&input)?;
        let plugin = self.enabled_plugin_action(plugin_id, action)?;
        let action_manifest = plugin
            .manifest
            .actions
            .iter()
            .find(|candidate| candidate.name == action)
            .expect("enabled_plugin_action validated action");
        validate_action_base_exchange(&plugin.manifest, action_manifest, base_exchange_id)?;
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
            view: parking_lot::RwLock::new(PluginJobRecord {
                id,
                project_id,
                plugin_id: plugin_id.into(),
                action: action.into(),
                base_exchange_id,
                state: PluginJobState::Queued,
                phase: PluginJobPhase::Queued,
                operation_count: 0,
                completed_operations: 0,
                result: None,
                analysis_resume_available: false,
                analysis_checkpoint_status: "not_created".into(),
                analysis_resume_reason: None,
                error: None,
            }),
            cancel: CancellationToken::new(),
            analysis_checkpoint: parking_lot::Mutex::new(None),
        });
        self.jobs.insert(id, job.clone());
        let service = self.clone();
        let action = action.to_string();
        tokio::spawn(async move {
            let _active_job_permit = active_job_permit;
            service.execute_job(job, plugin, action, input).await;
        });
        self.status(id)
    }

    pub fn status(&self, id: Uuid) -> DomainResult<PluginJobView> {
        self.jobs
            .get(&id)
            .map(|job| job.view.read().status())
            .ok_or_else(|| DomainError::not_found("plugin job"))
    }

    pub fn cancel(&self, id: Uuid) -> DomainResult<PluginJobView> {
        let job = self
            .jobs
            .get(&id)
            .ok_or_else(|| DomainError::not_found("plugin job"))?;
        job.cancel.cancel();
        let status = job.view.read().status();
        Ok(status)
    }

    pub async fn resume_analysis(
        &self,
        id: Uuid,
        requested_timeout_ms: Option<u64>,
    ) -> DomainResult<PluginJobView> {
        let job = self
            .jobs
            .get(&id)
            .map(|entry| entry.clone())
            .ok_or_else(|| DomainError::not_found("plugin job"))?;
        let plugin = self
            .plugins
            .get(&job.view.read().plugin_id)
            .cloned()
            .ok_or_else(|| DomainError::not_found("plugin used by job is no longer installed"))?;
        let checkpoint = job.analysis_checkpoint.lock().clone().ok_or_else(|| {
            DomainError::new(
                ErrorCode::Conflict,
                "plugin job has no resumable analysis checkpoint",
            )
        })?;
        if plugin.manifest.version != checkpoint.plugin_version
            || plugin.manifest.entrypoint_sha256 != checkpoint.entrypoint_sha256
        {
            let mut view = job.view.write();
            view.state = PluginJobState::Failed;
            view.phase = PluginJobPhase::Finished;
            view.error = Some("plugin changed since execution; analysis retry refused".into());
            return Err(DomainError::new(
                ErrorCode::Conflict,
                "plugin changed since execution; analysis retry refused",
            ));
        }
        let retry_permit = self
            .analysis_retry_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    "another extension analysis retry is already running",
                )
            })?;
        {
            let mut view = job.view.write();
            if !view.analysis_resume_available || view.state == PluginJobState::Running {
                return Err(DomainError::new(
                    ErrorCode::Conflict,
                    "plugin analysis is not currently resumable",
                ));
            }
            view.state = PluginJobState::Running;
            view.phase = PluginJobPhase::Analyzing;
            view.analysis_resume_available = false;
            view.analysis_checkpoint_status = "retrying".into();
            view.analysis_resume_reason = None;
            view.error = None;
        }
        let manifest_timeout = effective_plugin_limits(&plugin.manifest).js_stage_timeout_ms;
        let timeout_ms = requested_timeout_ms
            .unwrap_or_else(|| manifest_timeout.saturating_mul(2).max(60_000))
            .clamp(manifest_timeout, MAX_JS_STAGE_TIMEOUT_MS);
        let service = self.clone();
        tokio::spawn(async move {
            let _retry_permit = retry_permit;
            let result = service
                .analyze_and_persist(job.clone(), plugin, checkpoint.clone(), Some(timeout_ms))
                .await;
            let mut view = job.view.write();
            match result {
                Ok(result) => {
                    view.state = PluginJobState::Completed;
                    view.phase = PluginJobPhase::Finished;
                    view.result = Some(result);
                    view.analysis_resume_available = false;
                    view.analysis_checkpoint_status = "consumed".into();
                    *job.analysis_checkpoint.lock() = None;
                }
                Err(error) if error.code() == ErrorCode::Cancelled => {
                    view.state = PluginJobState::Cancelled;
                    view.phase = PluginJobPhase::Finished;
                    view.analysis_resume_available = false;
                    view.analysis_checkpoint_status = "consumed".into();
                    view.analysis_resume_reason = None;
                    view.error = Some(error.to_string());
                    *job.analysis_checkpoint.lock() = None;
                }
                Err(error) => {
                    view.state = PluginJobState::Failed;
                    view.phase = PluginJobPhase::Finished;
                    view.analysis_resume_available = error.code() == ErrorCode::Timeout;
                    view.analysis_checkpoint_status = if error.code() == ErrorCode::Timeout {
                        "retained"
                    } else {
                        "unavailable"
                    }
                    .into();
                    view.analysis_resume_reason = (error.code() != ErrorCode::Timeout).then(|| "Analysis retry failed with a non-timeout error; the checkpoint cannot be retried automatically.".into());
                    view.error = Some(error.to_string());
                    if error.code() != ErrorCode::Timeout {
                        *job.analysis_checkpoint.lock() = None;
                    }
                }
            }
        });
        self.status(id)
    }

    pub fn results(
        &self,
        id: Uuid,
        result_view: PluginResultView,
        offset: usize,
        limit: usize,
    ) -> DomainResult<Value> {
        let job = self
            .jobs
            .get(&id)
            .ok_or_else(|| DomainError::not_found("plugin job"))?;
        let record = job.view.read();
        let status = record.status();
        let Some(stored) = record.result.as_ref() else {
            return Ok(json!({
                "job": status,
                "result_available": false,
            }));
        };
        let findings = stored
            .pointer("/analysis/findings")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let total_findings = findings.len();
        let persisted_findings_total = stored
            .get("persisted_findings")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let offset = offset.min(total_findings);
        let limit = limit.clamp(1, 100);
        let end = offset.saturating_add(limit).min(total_findings);
        let next_offset = (end < total_findings).then_some(end);
        let mut page = findings[offset..end].to_vec();
        for finding in &mut page {
            remove_remediation_fields(finding);
        }
        let pagination = json!({
            "offset": offset,
            "limit": limit,
            "returned": page.len(),
            "total": total_findings,
            "next_offset": next_offset,
        });
        match result_view {
            PluginResultView::Summary => Ok(json!({
                "job": status,
                "result_available": true,
                "summary": summarize_plugin_result(stored),
                "findings": { "total": total_findings },
            })),
            PluginResultView::Findings => Ok(json!({
                "job": status,
                "result_available": true,
                "pagination": pagination,
                "findings": page,
            })),
            PluginResultView::Full => {
                let mut result = stored.clone();
                remove_remediation_fields(&mut result);
                if let Some(items) = result
                    .pointer_mut("/analysis/findings")
                    .and_then(Value::as_array_mut)
                {
                    *items = page;
                }
                if let Some(object) = result.as_object_mut() {
                    object.remove("persisted_findings");
                }
                Ok(json!({
                    "job": status,
                    "result_available": true,
                    "pagination": pagination,
                    "persisted_findings_total": persisted_findings_total,
                    "result": result,
                }))
            }
        }
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

    async fn prepare_plugin_plan(
        &self,
        project_id: ProjectId,
        base_exchange_id: Option<ExchangeId>,
        plugin: Arc<LoadedPlugin>,
        action: &str,
        input: &Value,
    ) -> DomainResult<PreparedPluginPlan> {
        self.db.get_project(project_id).await?;
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
        let page_discovery_access = plugin
            .manifest
            .capabilities
            .iter()
            .any(|capability| capability == "page.discover")
            && input.get("target_url").is_none();
        let base_exchange = self
            .plugin_exchange_context(
                project_id,
                base_exchange_id,
                privileged_identity,
                raw_request_access,
                page_discovery_access,
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
            "execution_nonce": Uuid::new_v4().simple().to_string(),
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
        validate_plan_preview(plan.preview.as_ref())?;
        validate_race_data_flow(&plan)?;
        if plan.stop_on_error && plan.execution != PluginExecution::Sequential {
            return Err(DomainError::invalid(
                "stop_on_error requires execution=sequential",
            ));
        }
        let limits = effective_plugin_limits(&plugin.manifest);
        let planned_requests = plan
            .operations
            .iter()
            .try_fold(0usize, |count, operation| {
                count.checked_add(operation_request_count(operation))
            })
            .unwrap_or(usize::MAX);
        if planned_requests > limits.max_operations {
            return Err(DomainError::new(
                ErrorCode::CombinationLimit,
                format!(
                    "plugin planned {planned_requests} requests; limit is {}",
                    limits.max_operations
                ),
            ));
        }
        for operation in &plan.operations {
            let required = operation_required_capability(operation);
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
            if operation_identity_selectors(operation).next().is_some() && !privileged_identity {
                return Err(DomainError::new(
                    ErrorCode::Forbidden,
                    "plugin identity selectors require identity.use capability",
                ));
            }
            for policy in operation_observation_policies(operation) {
                validate_observation_policy(policy)?;
            }
        }
        let resolved_identities = Arc::new(
            self.resolve_plugin_identities(project_id, input, &plan.operations)
                .await?,
        );
        validate_resolved_identity_comparisons(&plan.operations, &resolved_identities)?;
        Ok(PreparedPluginPlan {
            plan,
            context,
            resolved_identities,
            planned_requests,
        })
    }

    async fn execute_job(
        &self,
        job: Arc<PluginJob>,
        plugin: Arc<LoadedPlugin>,
        action: String,
        input: Value,
    ) {
        {
            let mut view = job.view.write();
            view.state = PluginJobState::Running;
            view.phase = PluginJobPhase::Planning;
        }
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
                view.phase = PluginJobPhase::Finished;
                view.result = Some(result);
            }
            Ok(Err(error)) if error.code() == ErrorCode::Cancelled => {
                *job.analysis_checkpoint.lock() = None;
                view.state = PluginJobState::Cancelled;
                view.phase = PluginJobPhase::Finished;
                view.error = Some(error.to_string());
            }
            Ok(Err(error)) => {
                if error.code() != ErrorCode::Timeout {
                    *job.analysis_checkpoint.lock() = None;
                }
                view.state = PluginJobState::Failed;
                view.phase = PluginJobPhase::Finished;
                view.error = Some(error.to_string());
            }
            Err(_) => {
                job.cancel.cancel();
                *job.analysis_checkpoint.lock() = None;
                view.state = PluginJobState::Failed;
                view.phase = PluginJobPhase::Finished;
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
        let PreparedPluginPlan {
            plan,
            context,
            resolved_identities,
            planned_requests,
        } = self
            .prepare_plugin_plan(project_id, base_exchange_id, plugin.clone(), action, input)
            .await?;
        job.view.write().operation_count = planned_requests;
        job.view.write().phase = PluginJobPhase::Executing;
        let project_id = job.view.read().project_id;
        let project = self.db.get_project(project_id).await?;
        let concurrency = plugin
            .manifest
            .limits
            .max_concurrency
            .unwrap_or(4)
            .clamp(1, project.limits.max_concurrent_requests.max(1) as usize);
        // With no explicit host scope, base-exchange plugins must be able to
        // replay the selected request even when the project's landing page is
        // on a different host (for example, a lab catalog that opens a unique
        // lab subdomain). The job remains pinned to exactly one implicit host.
        let target_host =
            implicit_plugin_target_host(&project.target_url, base_exchange_id.is_some(), &context);
        let rate = project.limits.requests_per_second.max(0.1);
        let operations: Vec<DomainResult<Value>> = if plan.execution == PluginExecution::Sequential
        {
            let mut observations = Vec::with_capacity(plan.operations.len());
            let mut observation_bytes = 2usize;
            let mut operations = plan.operations.into_iter().peekable();
            let mut race_values = HashMap::<String, String>::new();
            let mut race_value_bytes = 0usize;
            let mut index = 0usize;
            while let Some(mut operation) = operations.next() {
                if index > 0 {
                    tokio::select! {
                        _ = job.cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                        _ = tokio::time::sleep(Duration::from_secs_f64(1.0 / rate)) => {}
                    }
                }
                let operation_id = operation.id().to_string();
                let completed_count = operation_request_count(&operation);
                let extraction_plan = race_extraction_plan(&operation);
                let result = match substitute_race_operation(&mut operation, &race_values) {
                    Ok(()) => {
                        self.execute_operation(
                            project_id,
                            &plugin.manifest.id,
                            &plugin.manifest.name,
                            operation,
                            &project.scope,
                            target_host.as_deref(),
                            &resolved_identities,
                            &job.cancel,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                job.view.write().completed_operations += completed_count;
                let mut observation = isolate_operation_result(operation_id, result)?;
                if !extraction_plan.is_empty() {
                    if let Err(error) = apply_race_extractions(
                        &mut observation,
                        &extraction_plan,
                        &mut race_values,
                        &mut race_value_bytes,
                    ) {
                        observation["error"] = json!({
                            "code": error.code().as_str(),
                            "message": error.to_string(),
                        });
                    }
                }
                let race_secrets = race_values.values().cloned().collect::<Vec<_>>();
                redact_value(&mut observation, &race_secrets, None);
                let failed = observation
                    .get("error")
                    .is_some_and(|error| !error.is_null());
                push_bounded_analysis_observation(
                    &mut observations,
                    observation,
                    &mut observation_bytes,
                )?;
                if failed && plan.stop_on_error {
                    for skipped in operations {
                        push_bounded_analysis_observation(
                            &mut observations,
                            skipped_operation_observation(&skipped),
                            &mut observation_bytes,
                        )?;
                    }
                    break;
                }
                index += 1;
            }
            observations.into_iter().map(Ok).collect()
        } else {
            let spacing = Duration::from_secs_f64(1.0 / rate);
            let next_slot = Arc::new(tokio::sync::Mutex::new(tokio::time::Instant::now()));
            let mut pending = Box::pin(stream::iter(plan.operations.into_iter().map(|operation| {
                let service = self.clone();
                let job = job.clone();
                let plugin_id = plugin.manifest.id.clone();
                let plugin_name = plugin.manifest.name.clone();
                let scope = project.scope.clone();
                let target_host = target_host.clone();
                let resolved_identities = resolved_identities.clone();
                let next_slot = next_slot.clone();
                async move {
                    let operation_id = operation.id().to_string();
                    let completed_count = operation_request_count(&operation);
                    let ready_at = {
                        let mut next = next_slot.lock().await;
                        reserve_plugin_request_slot(
                            &mut next,
                            tokio::time::Instant::now(),
                            spacing,
                        )
                    };
                    tokio::select! {
                        _ = job.cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                        _ = tokio::time::sleep_until(ready_at) => {}
                    }
                    let result = service
                        .execute_operation(project_id, &plugin_id, &plugin_name, operation, &scope, target_host.as_deref(), &resolved_identities, &job.cancel)
                        .await;
                    job.view.write().completed_operations += completed_count;
                    isolate_operation_result(operation_id, result)
                }
            }))
            .buffer_unordered(concurrency));
            let mut observations = Vec::new();
            let mut observation_bytes = 2usize;
            while let Some(observation) = pending.next().await {
                push_bounded_analysis_observation(
                    &mut observations,
                    observation?,
                    &mut observation_bytes,
                )?;
            }
            observations.into_iter().map(Ok).collect()
        };
        let raw_observations = operations.into_iter().collect::<DomainResult<Vec<_>>>()?;
        let mut observations = Vec::with_capacity(raw_observations.len());
        let mut observation_bytes = 2usize;
        for observation in raw_observations {
            push_bounded_analysis_observation(
                &mut observations,
                observation,
                &mut observation_bytes,
            )?;
        }
        if job.cancel.is_cancelled() {
            return Err(DomainError::new(
                ErrorCode::Cancelled,
                "plugin job cancelled",
            ));
        }
        let execution_evidence_exchange_ids = collect_exchange_ids(&json!(observations));
        let partial_result = json!({
            "plan_result": plan.result.clone(),
            "execution": {"evidence_exchange_ids": execution_evidence_exchange_ids},
            "analysis": Value::Null,
            "persisted_findings": [],
        });
        let partial_result = self
            .redact_plugin_output(project_id, base_exchange_id, partial_result)
            .await?;
        if serde_json::to_vec(&partial_result).map_or(true, |bytes| bytes.len() > MAX_RESULT_BYTES)
        {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                "plugin partial result exceeds 8 MiB",
            ));
        }
        job.view.write().result = Some(partial_result);
        let job_id = job.view.read().id;
        for exchange_id in &execution_evidence_exchange_ids {
            self.annotate_plugin_job_exchange(project_id, *exchange_id, job_id)
                .await?;
        }
        let observations = compact_analysis_observations(
            Value::Array(observations),
            MAX_ANALYSIS_OBSERVATION_BYTES,
        )?;
        let observations_json = serde_json::to_vec(&observations).map_err(|error| {
            DomainError::invalid(format!("serialize plugin observations: {error}"))
        })?;
        let resumable_observations = if observations_json.len() <= MAX_ANALYSIS_CHECKPOINT_BYTES {
            let bytes = observations_json.clone();
            tokio::task::spawn_blocking(move || zstd::stream::encode_all(bytes.as_slice(), 1))
                .await
                .ok()
                .and_then(Result::ok)
                .filter(|compressed| compressed.len() <= MAX_COMPRESSED_ANALYSIS_CHECKPOINT_BYTES)
                .and_then(|compressed| {
                    reserve_checkpoint_bytes(&self.analysis_checkpoint_bytes, compressed)
                })
        } else {
            None
        };
        let reservation = resumable_observations
            .as_ref()
            .map(|(_, reservation)| reservation.clone());
        let compressed = resumable_observations
            .as_ref()
            .map(|(bytes, _)| bytes.clone());
        let checkpoint = AnalysisCheckpoint {
            plugin_version: plugin.manifest.version.clone(),
            entrypoint_sha256: plugin.manifest.entrypoint_sha256.clone(),
            input: input.clone(),
            observations_zstd: compressed.clone().unwrap_or_else(|| Arc::new(Vec::new())),
            observations_bytes: observations_json.len(),
            observations_fallback: resumable_observations
                .is_none()
                .then(|| json!(observations)),
            context,
            plan_result: plan.result,
            execution_evidence_exchange_ids,
            _reservation: reservation.unwrap_or_else(|| {
                Arc::new(CheckpointReservation {
                    bytes: 0,
                    total: self.analysis_checkpoint_bytes.clone(),
                })
            }),
        };
        if compressed.is_some() {
            *job.analysis_checkpoint.lock() = Some(checkpoint.clone());
            job.view.write().analysis_checkpoint_status = "retained".into();
        } else {
            let mut view = job.view.write();
            view.analysis_checkpoint_status = "unavailable".into();
            view.analysis_resume_reason = Some("Observations exceeded the bounded in-memory analysis checkpoint; target probes remain available in History but automatic analysis retry is unavailable.".into());
        }
        job.view.write().phase = PluginJobPhase::Analyzing;
        self.analyze_and_persist(job, plugin, checkpoint, None)
            .await
    }

    async fn analyze_and_persist(
        &self,
        job: Arc<PluginJob>,
        plugin: Arc<LoadedPlugin>,
        checkpoint: AnalysisCheckpoint,
        timeout_override_ms: Option<u64>,
    ) -> DomainResult<Value> {
        let (project_id, base_exchange_id) = {
            let view = job.view.read();
            (view.project_id, view.base_exchange_id)
        };
        let observations = if checkpoint.observations_zstd.is_empty() {
            checkpoint.observations_fallback.clone().ok_or_else(|| {
                DomainError::new(
                    ErrorCode::StorageError,
                    "analysis checkpoint has no observations",
                )
            })?
        } else {
            let compressed = checkpoint.observations_zstd.clone();
            let observations_json = tokio::task::spawn_blocking(move || {
                zstd::stream::decode_all(compressed.as_slice())
            })
            .await
            .map_err(|error| {
                DomainError::new(
                    ErrorCode::Internal,
                    format!("analysis checkpoint task: {error}"),
                )
            })?
            .map_err(|error| {
                DomainError::new(
                    ErrorCode::StorageError,
                    format!("decode analysis checkpoint: {error}"),
                )
            })?;
            if observations_json.len() != checkpoint.observations_bytes
                || observations_json.len() > MAX_ANALYSIS_CHECKPOINT_BYTES
            {
                return Err(DomainError::new(
                    ErrorCode::StorageError,
                    "analysis checkpoint size mismatch",
                ));
            }
            serde_json::from_slice(&observations_json).map_err(|error| {
                DomainError::new(
                    ErrorCode::StorageError,
                    format!("parse analysis checkpoint: {error}"),
                )
            })?
        };
        let analyzed = run_js_stage_with_timeout(
            &plugin,
            "analyze",
            &checkpoint.input,
            &observations,
            &checkpoint.context,
            timeout_override_ms,
            Some(job.cancel.clone()),
        )
        .await;
        let analyzed = match analyzed {
            Ok(analyzed) => analyzed,
            Err(error) => {
                if error.code() == ErrorCode::Timeout {
                    let checkpoint_available = job.analysis_checkpoint.lock().is_some();
                    let mut view = job.view.write();
                    view.analysis_resume_available = checkpoint_available;
                    if checkpoint_available {
                        view.analysis_checkpoint_status = "retained".into();
                        view.analysis_resume_reason = Some("Aggregation timed out; retry before restarting HuntProxy or before this job is evicted from the 256-job in-memory retention window.".into());
                    }
                }
                return Err(error);
            }
        };
        let mut analyzed = self
            .redact_plugin_output(project_id, base_exchange_id, analyzed)
            .await?;
        remove_remediation_fields(&mut analyzed);
        if job.cancel.is_cancelled() {
            return Err(DomainError::new(
                ErrorCode::Cancelled,
                "plugin job cancelled before finding persistence",
            ));
        }
        let mut pending_findings = Vec::new();
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
                    format!("Severity: {severity}\nConfidence: {confidence}\n\n{explanation}\n\nEvidence exchanges: {}", evidence.iter().map(|id| id.get().to_string()).collect::<Vec<_>>().join(", "))
                };
                pending_findings.push((exchange_id, title.to_string(), description));
            }
        }
        let provisional_findings = pending_findings
            .iter()
            .map(|(exchange_id, title, description)| {
                json!({
                    "id": i64::MAX,
                    "project_id": project_id,
                    "exchange_id": exchange_id,
                    "title": title,
                    "description": description,
                    "created_at": "9999-12-31T23:59:59.999999999Z",
                    "updated_at": "9999-12-31T23:59:59.999999999Z",
                })
            })
            .collect::<Vec<_>>();
        let provisional_result = json!({"plan_result": checkpoint.plan_result.clone(), "execution": {"evidence_exchange_ids": checkpoint.execution_evidence_exchange_ids.clone()}, "analysis": analyzed.clone(), "persisted_findings": provisional_findings});
        let provisional_result = self
            .redact_plugin_output(project_id, base_exchange_id, provisional_result)
            .await?;
        if serde_json::to_vec(&provisional_result)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX)
            > MAX_RESULT_BYTES
        {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                "plugin result exceeds 8 MiB",
            ));
        }
        if job.cancel.is_cancelled() {
            return Err(DomainError::new(
                ErrorCode::Cancelled,
                "plugin job cancelled before finding persistence",
            ));
        }
        job.view.write().phase = PluginJobPhase::Persisting;
        let persisted_findings = self
            .db
            .create_findings_atomic(project_id, pending_findings)
            .await?;
        let result = json!({"plan_result": checkpoint.plan_result, "execution": {"evidence_exchange_ids": checkpoint.execution_evidence_exchange_ids}, "analysis": analyzed, "persisted_findings": persisted_findings});
        job.view.write().analysis_resume_available = false;
        job.view.write().analysis_checkpoint_status = "consumed".into();
        *job.analysis_checkpoint.lock() = None;
        Ok(result)
    }

    async fn resolve_plugin_identities(
        &self,
        project_id: ProjectId,
        input: &Value,
        operations: &[PluginOperation],
    ) -> DomainResult<HashMap<String, ResolvedPluginIdentity>> {
        let authorized = collect_input_identity_selector_keys(input)?;
        let selectors = operations
            .iter()
            .flat_map(operation_identity_selectors)
            .map(|selector| Ok((identity_selector_key(selector)?, selector.clone())))
            .collect::<DomainResult<Vec<_>>>()?;
        let mut resolved = HashMap::new();
        for (key, selector) in selectors {
            if !authorized.contains(&key) {
                return Err(DomainError::new(
                    ErrorCode::Forbidden,
                    "plugin planned an identity selector not explicitly supplied in action input",
                ));
            }
            if resolved.contains_key(&key) {
                continue;
            }
            let identity = if let Some(name) = selector.profile.as_deref() {
                let profile = self
                    .db
                    .get_named_cookie_profile(project_id, name)
                    .await?
                    .ok_or_else(|| {
                        DomainError::not_found(format!("named cookie profile {name}"))
                    })?;
                ResolvedPluginIdentity::Profile(profile)
            } else if let Some(path) = selector.cookie_file.as_deref() {
                ResolvedPluginIdentity::CookieInput(crate::cookies::read_cookie_file(Path::new(
                    path,
                ))?)
            } else {
                unreachable!()
            };
            resolved.insert(key, identity);
        }
        Ok(resolved)
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
        page_discovery_access: bool,
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
        if page_discovery_access {
            match crate::page_analyzer::discover_passive_targets(
                &self.db,
                project_id,
                exchange_id,
                64,
            )
            .await
            {
                Ok(analysis) => {
                    context["page_discovery"] = serde_json::to_value(analysis)
                        .unwrap_or_else(|_| json!({"available": false}));
                }
                Err(error) => {
                    context["page_discovery"] = json!({
                        "available": false,
                        "error": error.to_string(),
                    });
                }
            }
        }
        if privileged_identity && detail.protocol.ends_with(" raw") {
            return Err(DomainError::invalid(
                "identity-aware extensions require a semantic base exchange, not a raw-wire transcript",
            ));
        }
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
            match plugin_raw_request_bytes(
                &detail.protocol,
                &detail.summary.method,
                &target,
                &raw_headers,
                &body,
            ) {
                Some((raw, reconstructed)) if raw.len() <= MAX_RAW_REQUEST_CONTEXT => {
                    context["raw_request_base64"] =
                        Value::String(base64::engine::general_purpose::STANDARD.encode(raw));
                    context["raw_request_reconstructed"] = Value::Bool(reconstructed);
                }
                _ => {
                    context["raw_request_omitted"] = Value::Bool(true);
                }
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
        resolved_identities: &HashMap<String, ResolvedPluginIdentity>,
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
                resolved_identities,
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

    #[allow(clippy::too_many_arguments)]
    async fn execute_aws_api_gateway(
        &self,
        project_id: ProjectId,
        plugin_id: &str,
        _plugin_name: &str,
        operation: PluginAwsApiGateway,
        scope: &ScopePolicy,
        target_host: Option<&str>,
        cancel: &CancellationToken,
    ) -> DomainResult<Value> {
        if let PluginAwsApiGateway::Status { id } = operation {
            return Ok(json!({
                "id": id,
                "ip_rotation": {
                    "action": "status",
                    "profiles": self.db.list_ip_rotation_profiles(project_id).await?,
                }
            }));
        }
        match operation {
            PluginAwsApiGateway::Enable {
                id,
                target_url,
                regions,
                stage_name,
            } => {
                validate_gateway_target(&target_url)?;
                let target_url = crate::storage::canonical_rotation_origin(&target_url)?;
                enforce_plugin_scope(&target_url, scope, target_host)?;
                validate_gateway_stage(&stage_name)?;
                validate_regions(&regions)?;
                let helper = self
                    .plugins
                    .get(plugin_id)
                    .and_then(|plugin| plugin.resources.get("aws-control"))
                    .ok_or_else(|| {
                        DomainError::new(
                            ErrorCode::ConfigInvalid,
                            "IpRotate package is missing its verified aws-control resource",
                        )
                    })?;
                let credentials_path = self.directory.join(plugin_id).join("aws-credentials.toml");
                let credentials = load_aws_credentials(&credentials_path)?;
                if self
                    .db
                    .list_ip_rotation_profiles(project_id)
                    .await?
                    .iter()
                    .any(|profile| profile.target_origin == target_url)
                {
                    return Err(DomainError::new(
                        ErrorCode::Conflict,
                        "IP rotation is already configured for this target; disable it before enabling a replacement",
                    ));
                }
                let gateways = provision_rotation_gateways(
                    helper,
                    &credentials,
                    &target_url,
                    &stage_name,
                    &regions,
                    cancel,
                )
                .await?;
                let profile = match self
                    .db
                    .activate_ip_rotation(
                        project_id,
                        target_url.clone(),
                        stage_name,
                        gateways.clone(),
                    )
                    .await
                {
                    Ok(profile) => profile,
                    Err(error) => {
                        cleanup_rotation_gateways(helper, &credentials, &gateways).await;
                        return Err(error);
                    }
                };
                Ok(json!({
                    "id": id,
                    "ip_rotation": {
                        "action": "enabled",
                        "profile": profile,
                    }
                }))
            }
            PluginAwsApiGateway::Disable { id, target_url } => {
                let profile = self
                    .db
                    .deactivate_ip_rotation(project_id, target_url)
                    .await?;
                let helper = self
                    .plugins
                    .get(plugin_id)
                    .and_then(|plugin| plugin.resources.get("aws-control"))
                    .ok_or_else(|| {
                        DomainError::new(
                            ErrorCode::ConfigInvalid,
                            "IP rotation was disabled; gateway cleanup is pending because the package is missing its verified aws-control resource",
                        )
                    })?;
                let credentials_path = self.directory.join(plugin_id).join("aws-credentials.toml");
                let credentials = load_aws_credentials(&credentials_path).map_err(|error| {
                    DomainError::new(
                        error.code(),
                        format!("IP rotation was disabled; gateway cleanup is pending: {error}"),
                    )
                })?;
                let cleanup = delete_rotation_gateways(
                    &self.db,
                    project_id,
                    helper,
                    &credentials,
                    &profile,
                    cancel,
                )
                .await;
                if cleanup.cancelled {
                    return Err(DomainError::new(
                        ErrorCode::Cancelled,
                        "IP rotation was disabled; gateway cleanup was cancelled and can be retried with disable",
                    ));
                }
                let removed = self
                    .db
                    .remove_empty_ip_rotation_profile(project_id, profile.id)
                    .await?;
                Ok(json!({
                    "id": id,
                    "ip_rotation": {
                        "action": "disabled",
                        "target_origin": profile.target_origin,
                        "deleted_regions": cleanup.deleted_regions,
                        "cleanup_errors": cleanup.errors,
                        "profile_removed": removed,
                    }
                }))
            }
            PluginAwsApiGateway::Status { .. } => unreachable!(),
        }
    }

    async fn execute_operation(
        &self,
        project_id: ProjectId,
        plugin_id: &str,
        plugin_name: &str,
        operation: PluginOperation,
        scope: &ScopePolicy,
        target_host: Option<&str>,
        resolved_identities: &HashMap<String, ResolvedPluginIdentity>,
        cancel: &CancellationToken,
    ) -> DomainResult<Value> {
        match operation {
            PluginOperation::HttpRequest(request) => {
                let delay = plugin_http_request_delay(request.delay_before_ms)?;
                if !delay.is_zero() {
                    tokio::select! {
                        _ = cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
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
                let identity_cookie = resolve_operation_identity_cookie(
                    request.identity.as_ref(),
                    resolved_identities,
                    &effective_url,
                )?;
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
                let credential_mode = if request.identity.is_some() {
                    PluginCredentialMode::WithoutProjectCredentials
                } else {
                    request.credential_mode
                };
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
                    plugin_target_host: target_host.map(str::to_string),
                };
                if let Some(cookie) = identity_cookie {
                    header_overrides.retain(|header| !header.name.eq_ignore_ascii_case("cookie"));
                    header_overrides.push(HeaderPatch {
                        name: "Cookie".into(),
                        value: cookie.into_bytes(),
                    });
                }
                let draft = ReplyDraft {
                    method: request.method,
                    url: url_override,
                    header_overrides,
                    header_tombstones: request.header_tombstones,
                    body_override,
                    body_text: request.body_text,
                    credential_mode: match credential_mode {
                        PluginCredentialMode::WithProjectCredentials => {
                            ReplyCredentialMode::WithProjectCredentials
                        }
                        PluginCredentialMode::WithoutProjectCredentials => {
                            ReplyCredentialMode::WithoutProjectCredentials
                        }
                    },
                    ..Default::default()
                };
                let response = tokio::select! {
                    _ = cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                    response = self.reply.send_with_context(project_id, request.base_exchange_id, &draft, request.protocol, 0, context) => response?,
                };
                let mut response_headers = Vec::new();
                let mut response_body_base64 = None;
                let mut response_body_truncated = false;
                let mut response_body_contains = BTreeMap::<String, bool>::new();
                let mut response_body_search_complete = false;
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
                        let policy = request.observe.as_ref();
                        if let Some(policy) = policy {
                            validate_observation_policy(policy)?;
                        }
                        let body_limit =
                            policy.map_or(MAX_RESPONSE_BODY_FOR_PLUGIN, |value| value.body_bytes);
                        let presented = plugin_response_body(
                            &raw_response_headers,
                            body,
                            body_limit,
                            policy.map_or(&[], |value| value.body_contains.as_slice()),
                        );
                        response_body_base64 = presented.body_base64;
                        response_body_truncated = presented.truncated;
                        response_body_contains = presented.contains;
                        response_body_search_complete = presented.search_complete;
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
                    "response_body_contains": response_body_contains,
                    "response_body_search_complete": response_body_search_complete,
                }))
            }
            PluginOperation::AwsApiGateway(operation) => {
                self.execute_aws_api_gateway(
                    project_id,
                    plugin_id,
                    plugin_name,
                    operation,
                    scope,
                    target_host,
                    cancel,
                )
                .await
            }
            PluginOperation::HttpWorkflow(workflow) => {
                self.execute_http_workflow(
                    project_id,
                    plugin_id,
                    plugin_name,
                    workflow,
                    scope,
                    target_host,
                    resolved_identities,
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
                            plugin_target_host: None,
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
            PluginOperation::RawHttp1Group(group) => {
                validate_workflow_name(&group.id, "raw_http1_group id")?;
                if group.members.len() < 2 || group.members.len() > MAX_RAW_HTTP1_GROUP_MEMBERS {
                    return Err(DomainError::new(
                        ErrorCode::CombinationLimit,
                        format!(
                            "raw_http1_group requires 2..={MAX_RAW_HTTP1_GROUP_MEMBERS} members"
                        ),
                    ));
                }
                enforce_plugin_scope(&group.target_url, scope, target_host)?;
                let project = self.db.get_project(project_id).await?;
                let project_limit = project.limits.max_concurrent_requests.max(1) as usize;
                if group.members.len() > project_limit {
                    return Err(DomainError::new(
                        ErrorCode::ConcurrencyLimited,
                        format!("raw_http1_group requires {} concurrent connections; project limit is {project_limit}", group.members.len()),
                    ));
                }
                let aggregate_response_cap = project
                    .limits
                    .max_body_bytes
                    .saturating_add(64 * 1024)
                    .saturating_mul(group.members.len() as u64);
                if aggregate_response_cap > MAX_RAW_HTTP1_GROUP_AGGREGATE_BYTES {
                    return Err(DomainError::new(
                        ErrorCode::BodyTooLarge,
                        format!(
                            "raw_http1_group aggregate response allowance exceeds {} MiB; reduce members or the project body limit",
                            MAX_RAW_HTTP1_GROUP_AGGREGATE_BYTES / (1024 * 1024)
                        ),
                    ));
                }
                let mut ids = BTreeSet::new();
                let mut prepared = Vec::with_capacity(group.members.len());
                for (index, member) in group.members.into_iter().enumerate() {
                    validate_workflow_name(&member.id, "raw_http1_group member id")?;
                    if !ids.insert(member.id.clone()) {
                        return Err(DomainError::invalid(format!(
                            "duplicate raw_http1_group member id: {}",
                            member.id
                        )));
                    }
                    let has_utf8 = member.request_utf8.is_some();
                    let has_base64 = member.request_base64.is_some();
                    if has_utf8 == has_base64 {
                        return Err(DomainError::invalid(format!(
                            "raw_http1_group member {} requires exactly one of request_utf8 or request_base64",
                            member.id
                        )));
                    }
                    let bytes = match (member.request_utf8, member.request_base64) {
                        (Some(value), None) => value.into_bytes(),
                        (None, Some(value)) => base64::engine::general_purpose::STANDARD
                            .decode(value)
                            .map_err(|error| {
                                DomainError::invalid(format!(
                                    "invalid raw_http1_group request_base64 for {}: {error}",
                                    member.id
                                ))
                            })?,
                        _ => unreachable!(),
                    };
                    prepared.push((
                        index,
                        member.id,
                        bytes,
                        member.use_project_cookies,
                        member.options,
                    ));
                }
                let member_count = prepared.len();
                let barrier = Arc::new(tokio::sync::Barrier::new(member_count));
                let group_id = group.id;
                let target_url = group.target_url;
                let results = stream::iter(prepared.into_iter().map(|(index, member_id, bytes, use_project_cookies, mut options)| {
                    let service = self.clone();
                    let cancel = cancel.clone();
                    let barrier = barrier.clone();
                    let target_url = target_url.clone();
                    let plugin_id = plugin_id.to_string();
                    let plugin_name = plugin_name.to_string();
                    let operation_id = format!("{group_id}:{member_id}");
                    async move {
                        options.start_barrier = Some(barrier);
                        let result = tokio::select! {
                            _ = cancel.cancelled() => Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
                            response = service.reply.send_raw_http1_with_context(
                                project_id,
                                &target_url,
                                bytes,
                                use_project_cookies,
                                options,
                                ReplySendContext { source: ExchangeSource::Plugin, lineage: ExchangeLineage::default(), plugin_target_host: None },
                            ) => response,
                        };
                        let observation = match result {
                            Ok(response) => {
                                if let Some(exchange_id) = response.exchange_id {
                                    service.annotate_plugin_exchange(project_id, exchange_id, &plugin_id, &plugin_name, &operation_id).await?;
                                }
                                let transcript = match response.exchange_id {
                                    Some(exchange_id) => service.db.load_raw_body(project_id, exchange_id, MessageSide::Response).await?,
                                    None => None,
                                };
                                json!({"id":member_id,"raw":plugin_raw_observation(&response, transcript)?})
                            }
                            Err(error) if error.code() == ErrorCode::Cancelled => return Err(error),
                            Err(error) => json!({"id":member_id,"error":{"code":error.code().as_str(),"message":error.to_string()}}),
                        };
                        Ok::<_, DomainError>((index, observation))
                    }
                }))
                .buffer_unordered(member_count)
                .collect::<Vec<_>>()
                .await;
                let mut members = results.into_iter().collect::<DomainResult<Vec<_>>>()?;
                members.sort_by_key(|(index, _)| *index);
                Ok(json!({
                    "id": group_id,
                    "dispatch": "parallel_barrier",
                    "members": members.into_iter().map(|(_, observation)| observation).collect::<Vec<_>>(),
                }))
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
                            plugin_target_host: None,
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
                            let presented = plugin_response_body(
                                &raw_headers,
                                body,
                                MAX_RESPONSE_BODY_FOR_PLUGIN,
                                &[],
                            );
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
            PluginOperation::BrowserCsrf(probe) => {
                self.execute_browser_csrf(
                    project_id,
                    probe,
                    scope,
                    target_host,
                    resolved_identities,
                    cancel,
                )
                .await
            }
        }
    }

    async fn execute_browser_csrf(
        &self,
        project_id: ProjectId,
        probe: PluginBrowserCsrf,
        scope: &ScopePolicy,
        target_host: Option<&str>,
        resolved_identities: &HashMap<String, ResolvedPluginIdentity>,
        cancel: &CancellationToken,
    ) -> DomainResult<Value> {
        let unavailable = |reason: &str| {
            Ok(json!({
                "id": probe.id,
                "tested": false,
                "status": "not_tested",
                "reason": reason,
            }))
        };
        let Some(browser) = &self.browser else {
            return unavailable("browser_service_unavailable");
        };
        let install = browser.status();
        if !install.worker_available || !install.chromium_available {
            return unavailable("browser_runtime_unavailable");
        }
        if probe.timeout_ms < 1_000 || probe.timeout_ms > 30_000 {
            return Err(DomainError::invalid(
                "browser_csrf timeout_ms must be between 1000 and 30000",
            ));
        }
        if probe.attacker_origin.is_some() {
            return unavailable("custom_attacker_origin_not_supported");
        }
        if !probe.header_tombstones.is_empty() {
            return unavailable("browser_managed_headers_cannot_be_overridden");
        }
        let detail = self
            .db
            .get_exchange_detail(
                project_id,
                probe.base_exchange_id,
                crate::policy::PresentationOptions::default(),
            )
            .await?;
        let query = detail.summary.query.as_deref().unwrap_or_default();
        let mut target = url::Url::parse(&format!(
            "{}://{}{}{}{}",
            detail.summary.scheme,
            detail.summary.authority,
            detail.summary.path,
            if query.is_empty() { "" } else { "?" },
            query,
        ))
        .map_err(|error| DomainError::invalid(format!("invalid base exchange URL: {error}")))?;
        enforce_plugin_scope(target.as_str(), scope, target_host)?;
        let method = match probe.mode {
            PluginBrowserCsrfMode::TopLevelGet => "GET",
            PluginBrowserCsrfMode::CrossSiteFormPost => "POST",
        };
        let base_method = detail.summary.method.to_ascii_uppercase();
        if (method == "GET" && base_method != "GET") || (method == "POST" && base_method != "POST")
        {
            return Err(DomainError::invalid(
                "browser_csrf mode must match the base exchange method",
            ));
        }
        apply_url_param_patches(&mut target, &probe.query_params)?;
        let mut fields = if method == "POST" {
            let headers = self
                .db
                .load_raw_headers(project_id, probe.base_exchange_id, MessageSide::Request)
                .await?;
            let content_type = headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-type"))
                .and_then(|header| std::str::from_utf8(&header.value).ok())
                .unwrap_or_default();
            if !content_type
                .to_ascii_lowercase()
                .starts_with("application/x-www-form-urlencoded")
            {
                return unavailable("base_request_not_form_compatible");
            }
            let body = self
                .db
                .load_raw_body(project_id, probe.base_exchange_id, MessageSide::Request)
                .await?
                .unwrap_or_default();
            url::form_urlencoded::parse(&body)
                .into_owned()
                .collect::<Vec<_>>()
        } else {
            let pairs = target.query_pairs().into_owned().collect::<Vec<_>>();
            // HTML GET form submission constructs the query string from form
            // controls, so preserve the materialized base query as controls.
            target.set_query(None);
            pairs
        };
        apply_form_param_patches(&mut fields, &probe.body_params)?;
        if fields.len() > 128
            || fields
                .iter()
                .any(|(name, value)| name.len() > 1024 || value.len() > 64 * 1024)
        {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                "browser_csrf form parameters exceed host limits",
            ));
        }
        let Some(selector) = probe.identity.as_ref() else {
            return unavailable("identity_required");
        };
        let key = identity_selector_key(selector)?;
        let Some(ResolvedPluginIdentity::Profile(profile)) = resolved_identities.get(&key) else {
            return unavailable("managed_cookie_profile_required");
        };
        if profile.managed_cookies.is_none() {
            return unavailable("browser_cookie_metadata_required");
        }
        let session = match browser
            .start_ephemeral_with_profile(project_id, profile)
            .await
        {
            Ok(session) => session,
            Err(error)
                if matches!(
                    error.code(),
                    ErrorCode::BrowserDisabled
                        | ErrorCode::ChromiumNotInstalled
                        | ErrorCode::ConcurrencyLimited
                ) =>
            {
                return unavailable(error.code().as_str());
            }
            Err(error) => return Err(error),
        };
        let session_id = session.id;
        let result = tokio::select! {
            _ = cancel.cancelled() => Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
            result = browser.csrf_probe(project_id, session_id, target.as_str(), method, &fields, probe.timeout_ms) => result,
        };
        // Proxy persistence is asynchronous with respect to Playwright's load
        // event. Wait briefly for the bounded evidence set to become visible.
        let mut evidence_exchange_ids = Vec::new();
        if result.is_ok() {
            for delay in [0, 25, 75, 200, 500] {
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                evidence_exchange_ids = self
                    .db
                    .browser_session_exchange_ids(project_id, session_id, 128)
                    .await?;
                let target_seen = futures::future::try_join_all(evidence_exchange_ids.iter().map(
                    |exchange_id| async {
                        let evidence = self
                            .db
                            .get_exchange_detail(
                                project_id,
                                *exchange_id,
                                crate::policy::PresentationOptions::default(),
                            )
                            .await?;
                        Ok::<_, DomainError>(
                            evidence
                                .summary
                                .scheme
                                .eq_ignore_ascii_case(target.scheme())
                                && evidence
                                    .summary
                                    .authority
                                    .eq_ignore_ascii_case(target.authority())
                                && evidence.summary.path == target.path(),
                        )
                    },
                ))
                .await?
                .into_iter()
                .any(|matched| matched);
                if target_seen {
                    break;
                }
            }
        }
        let expected_cookie_header = profile
            .cookie_header_for_url(target.as_str())?
            .unwrap_or_default();
        let expected_cookie_pairs = crate::cookies::parse_cookie_header(&expected_cookie_header)?;
        let expected_cookie_names = expected_cookie_pairs
            .iter()
            .map(|pair| pair.name.clone())
            .collect::<BTreeSet<_>>();
        let mut sent_cookie_names = BTreeSet::new();
        for exchange_id in &evidence_exchange_ids {
            let evidence = self
                .db
                .get_exchange_detail(
                    project_id,
                    *exchange_id,
                    crate::policy::PresentationOptions::default(),
                )
                .await?;
            if !evidence
                .summary
                .scheme
                .eq_ignore_ascii_case(target.scheme())
                || !evidence
                    .summary
                    .authority
                    .eq_ignore_ascii_case(target.authority())
                || evidence.summary.path != target.path()
            {
                continue;
            }
            let headers = self
                .db
                .load_raw_headers(project_id, *exchange_id, MessageSide::Request)
                .await?;
            for header in headers
                .iter()
                .filter(|header| header.name.eq_ignore_ascii_case("cookie"))
            {
                let Ok(value) = std::str::from_utf8(&header.value) else {
                    continue;
                };
                sent_cookie_names.extend(matched_cookie_names(&expected_cookie_pairs, value)?);
            }
            // Only the initial target request proves the browser's cross-site
            // cookie decision; redirects may set or refresh cookies later.
            break;
        }
        let stop_result = browser.stop(project_id, session_id).await;
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                if let Err(stop_error) = stop_result {
                    tracing::warn!(%stop_error, session_id = session_id.get(), "failed to clean up isolated CSRF browser after probe error");
                }
                return Err(error);
            }
        };
        stop_result?;
        Ok(json!({
            "id": probe.id,
            "tested": true,
            "status": "completed",
            "exchanges": evidence_exchange_ids.iter().map(|id| json!({"exchange_id": id})).collect::<Vec<_>>(),
            "cookie_delivery": {
                "managed_cookie_delivered": !sent_cookie_names.is_empty(),
                "expected_count": expected_cookie_names.len(),
                "sent_matched_count": sent_cookie_names.len(),
            },
            "browser": {
                "isolated": true,
                "initiator": "opaque_cross_site_document",
                "final_url": result.final_url,
                "navigations": result.navigations,
            }
        }))
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
            let requires_extraction = !request.extract.is_empty();
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
                response = self.reply.send_with_context(project_id, request.base_exchange_id, &draft, request.protocol, 0, ReplySendContext { source: ExchangeSource::Plugin, lineage: ExchangeLineage { parent_exchange_id: request.base_exchange_id, ..Default::default() }, plugin_target_host: target_host.map(str::to_string) }) => response?,
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
            let mut observation = json!({"id":request.id,"exchange_id":response.exchange_id,"status_code":response.status_code,"response_length":response.response_length,"response_body_hash":response.response_body_hash,"duration_ms":response.duration_ms,"success":success,"error":Value::Null});
            if requires_extraction {
                observation["_extract"] = self
                    .race_extraction_material(project_id, response.exchange_id)
                    .await?;
            }
            Ok::<_, DomainError>(observation)
        }.await;
        result.unwrap_or_else(|error| json!({"id":request.id,"error":error.to_string()}))
    }

    async fn race_extraction_material(
        &self,
        project_id: ProjectId,
        exchange_id: Option<ExchangeId>,
    ) -> DomainResult<Value> {
        let exchange_id = exchange_id.ok_or_else(|| {
            DomainError::new(ErrorCode::StorageError, "race response was not persisted")
        })?;
        let headers = self
            .db
            .load_raw_headers(project_id, exchange_id, MessageSide::Response)
            .await?;
        let response_headers = headers
            .iter()
            .map(|header| json!({"name":header.name,"value_base64":base64::engine::general_purpose::STANDARD.encode(&header.value)}))
            .collect::<Vec<_>>();
        let body = self
            .db
            .load_raw_body(project_id, exchange_id, MessageSide::Response)
            .await?
            .map(|body| plugin_response_body(&headers, body, MAX_RESPONSE_BODY_FOR_PLUGIN, &[]));
        Ok(json!({
            "response_headers": response_headers,
            "response_body_base64": body.as_ref().and_then(|body| body.body_base64.clone()),
            "response_body_truncated": body.is_some_and(|body| body.truncated),
        }))
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
                    plugin_target_host: None,
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
                        plugin_target_host: None,
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

    async fn annotate_plugin_job_exchange(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        job_id: Uuid,
    ) -> DomainResult<()> {
        let existing = self.db.get_annotation(project_id, exchange_id).await?;
        let mut labels = existing
            .as_ref()
            .map(|value| value.labels.clone())
            .unwrap_or_default();
        labels.push(format!("plugin-job:{job_id}"));
        labels.sort_by_key(|label| label.to_ascii_lowercase());
        labels.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        self.db
            .upsert_annotation(
                project_id,
                exchange_id,
                AnnotationUpdate {
                    display_title: existing
                        .as_ref()
                        .and_then(|value| value.display_title.clone()),
                    note: existing.as_ref().and_then(|value| value.note.clone()),
                    labels,
                    expected_revision: existing.map(|value| value.revision),
                },
            )
            .await?;
        Ok(())
    }
}

fn validate_plan_preview(preview: Option<&PluginPlanPreview>) -> DomainResult<()> {
    let Some(preview) = preview else {
        return Ok(());
    };
    let slug = |value: &str| {
        value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    };
    for value in [
        preview.stage.as_deref(),
        preview.candidate_unit.as_deref(),
        preview.selected_mode.as_deref(),
        preview.recommended_mode.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !slug(value) {
            return Err(DomainError::invalid(
                "plugin plan preview identifiers must be bounded slugs",
            ));
        }
    }
    if preview
        .scope
        .as_deref()
        .is_some_and(|scope| !matches!(scope, "current_stage" | "complete_action"))
    {
        return Err(DomainError::invalid(
            "plugin plan preview scope must be current_stage or complete_action",
        ));
    }
    if preview.candidate_breakdown.len() > 16 || preview.supported_modes.len() > 16 {
        return Err(DomainError::new(
            ErrorCode::CombinationLimit,
            "plugin plan preview exceeds 16 breakdown entries or modes",
        ));
    }
    if preview.candidate_breakdown.keys().any(|key| !slug(key))
        || preview.supported_modes.iter().any(|mode| !slug(mode))
    {
        return Err(DomainError::invalid(
            "plugin plan preview breakdown keys and modes must be bounded slugs",
        ));
    }
    if preview
        .recommendation
        .as_ref()
        .is_some_and(|value| value.chars().count() > 512)
    {
        return Err(DomainError::new(
            ErrorCode::BodyTooLarge,
            "plugin plan preview recommendation exceeds 512 characters",
        ));
    }
    for selected in [
        preview.selected_mode.as_ref(),
        preview.recommended_mode.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if !preview.supported_modes.is_empty() && !preview.supported_modes.contains(selected) {
            return Err(DomainError::invalid(
                "selected and recommended preview modes must be declared in supported_modes",
            ));
        }
    }
    Ok(())
}

fn remove_remediation_fields(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("remediation");
            for child in object.values_mut() {
                remove_remediation_fields(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                remove_remediation_fields(item);
            }
        }
        _ => {}
    }
}

fn summarize_plugin_result(result: &Value) -> Value {
    let follow_up = result.pointer("/analysis/result/follow_up").map(|value| {
        if serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= 64 * 1024) {
            value.clone()
        } else {
            json!({
                "available": false,
                "error": "follow_up exceeds the 64 KiB compact-result limit; request view=full"
            })
        }
    });
    let mut plan_result = compact_json(result.get("plan_result").unwrap_or(&Value::Null), 0);
    if let Some(object) = plan_result.as_object_mut() {
        object.remove("coverage");
    }
    let mut analysis_result = compact_json(
        result.pointer("/analysis/result").unwrap_or(&Value::Null),
        0,
    );
    if let Some(object) = analysis_result.as_object_mut() {
        object.remove("follow_up");
    }
    json!({
        "plan_result": plan_result,
        "execution_evidence": {
            "count": result.pointer("/execution/evidence_exchange_ids").and_then(Value::as_array).map_or(0, Vec::len)
        },
        "analysis_result": analysis_result,
        "follow_up": follow_up,
        "persisted_findings": result
            .get("persisted_findings")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
    })
}

fn compact_json(value: &Value, depth: usize) -> Value {
    const MAX_DEPTH: usize = 3;
    const MAX_OBJECT_KEYS: usize = 24;
    const MAX_STRING_CHARS: usize = 240;
    match value {
        Value::String(text) => Value::String(bounded_chars(text, MAX_STRING_CHARS)),
        Value::Array(items) => json!({"count": items.len()}),
        Value::Object(object) if depth >= MAX_DEPTH => json!({"keys": object.len()}),
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            let total_keys = keys.len();
            let mut compact = serde_json::Map::new();
            for key in keys.into_iter().take(MAX_OBJECT_KEYS) {
                if key == "findings" || key == "remediation" {
                    continue;
                }
                compact.insert(key.clone(), compact_json(&object[key], depth + 1));
            }
            if total_keys > MAX_OBJECT_KEYS {
                compact.insert(
                    "_truncated_keys".into(),
                    json!(total_keys - MAX_OBJECT_KEYS),
                );
            }
            Value::Object(compact)
        }
        _ => value.clone(),
    }
}

fn bounded_chars(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let compact = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{compact}…")
    } else {
        compact
    }
}

const AWS_CREDENTIAL_FILE_MAX_BYTES: u64 = 8 * 1024;
const AWS_OPERATION_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsCredentialFile {
    access_key_id: String,
    secret_access_key: String,
    #[serde(default)]
    session_token: Option<String>,
}

fn load_aws_credentials(path: &Path) -> DomainResult<AwsCredentialFile> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        DomainError::new(
            ErrorCode::ConfigInvalid,
            format!(
                "IpRotate credential file {} is unavailable: {error}; copy aws-credentials.toml.example to aws-credentials.toml",
                path.display()
            ),
        )
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "IpRotate credential path must be a regular non-symlink file",
        ));
    }
    if metadata.len() == 0 || metadata.len() > AWS_CREDENTIAL_FILE_MAX_BYTES {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            format!(
                "IpRotate credential file must contain 1..={AWS_CREDENTIAL_FILE_MAX_BYTES} bytes"
            ),
        ));
    }
    let mut bytes = std::fs::read(path)
        .map_err(|error| DomainError::new(ErrorCode::ConfigInvalid, error.to_string()))?;
    let parsed = match std::str::from_utf8(&bytes) {
        Ok(text) => toml::from_str::<AwsCredentialFile>(text).map_err(|error| {
            DomainError::new(
                ErrorCode::ConfigInvalid,
                format!("invalid IpRotate credential file: {error}"),
            )
        }),
        Err(_) => Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "IpRotate credential file must be UTF-8 TOML",
        )),
    };
    bytes.fill(0);
    let mut parsed = parsed?;
    parsed.access_key_id = parsed.access_key_id.trim().to_string();
    parsed.secret_access_key = parsed.secret_access_key.trim().to_string();
    parsed.session_token = parsed
        .session_token
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if parsed.access_key_id.is_empty()
        || parsed.access_key_id.len() > 256
        || parsed.secret_access_key.is_empty()
        || parsed.secret_access_key.len() > 512
        || parsed
            .session_token
            .as_ref()
            .is_some_and(|value| value.len() > 4_096)
    {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "IpRotate credentials are empty or exceed their bounds",
        ));
    }
    Ok(parsed)
}

fn validate_aws_region(region: &str) -> DomainResult<()> {
    if !(3..=32).contains(&region.len())
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !region.contains('-')
    {
        return Err(DomainError::invalid("invalid AWS region"));
    }
    Ok(())
}

fn validate_regions(regions: &[String]) -> DomainResult<()> {
    if regions.is_empty() || regions.len() > 30 {
        return Err(DomainError::invalid("regions requires 1..=30 values"));
    }
    let mut unique = BTreeSet::new();
    for region in regions {
        validate_aws_region(region)?;
        if !unique.insert(region) {
            return Err(DomainError::invalid("regions must be unique"));
        }
    }
    Ok(())
}

fn validate_gateway_stage(stage: &str) -> DomainResult<()> {
    if stage.is_empty()
        || stage.len() > 64
        || !stage
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(DomainError::invalid("invalid API Gateway stage name"));
    }
    Ok(())
}

fn validate_rest_api_id(rest_api_id: &str) -> DomainResult<()> {
    if !(5..=32).contains(&rest_api_id.len())
        || !rest_api_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(DomainError::invalid("invalid API Gateway REST API id"));
    }
    Ok(())
}

fn validate_gateway_target(target_url: &str) -> DomainResult<()> {
    let parsed = url::Url::parse(target_url)
        .map_err(|error| DomainError::invalid(format!("invalid target_url: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(DomainError::invalid(
            "target_url must be an HTTP(S) origin without credentials, path, query, or fragment",
        ));
    }
    Ok(())
}

fn validate_gateway_endpoint(value: &str) -> DomainResult<String> {
    let parsed = url::Url::parse(value)
        .map_err(|error| DomainError::invalid(format!("invalid gateway endpoint: {error}")))?;
    let host = parsed
        .host_str()
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| DomainError::invalid("gateway endpoint requires a hostname"))?;
    let parts = host.split('.').collect::<Vec<_>>();
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port_or_known_default() != Some(443)
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() == "/"
        || parts.len() != 5
        || parts[1] != "execute-api"
        || parts[3] != "amazonaws"
        || parts[4] != "com"
    {
        return Err(DomainError::invalid(
            "gateway endpoint must be a regional HTTPS execute-api URL with a stage path",
        ));
    }
    validate_rest_api_id(parts[0])?;
    validate_aws_region(parts[2])?;
    Ok(value.trim_end_matches('/').to_string())
}

async fn provision_rotation_gateways(
    helper: &str,
    credentials: &AwsCredentialFile,
    target_url: &str,
    stage_name: &str,
    regions: &[String],
    cancel: &CancellationToken,
) -> DomainResult<Vec<crate::storage::IpRotationGateway>> {
    let results = stream::iter(regions.iter().cloned())
        .map(|region| async move {
            let result = run_aws_control_helper(
                helper,
                json!({
                    "action": "provision",
                    "region": region,
                    "target_url": target_url,
                    "stage_name": stage_name,
                }),
                credentials,
                cancel,
            )
            .await;
            (region, result)
        })
        .buffer_unordered(4)
        .collect::<Vec<_>>()
        .await;

    let mut gateways = Vec::new();
    let mut first_error = None;
    for (region, result) in results {
        match result.and_then(|value| parse_provisioned_gateway(&region, value)) {
            Ok(gateway) => gateways.push(gateway),
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    if let Some(error) = first_error {
        cleanup_rotation_gateways(helper, credentials, &gateways).await;
        return Err(error);
    }
    gateways.sort_by(|left, right| left.region.cmp(&right.region));
    Ok(gateways)
}

fn parse_provisioned_gateway(
    expected_region: &str,
    value: Value,
) -> DomainResult<crate::storage::IpRotationGateway> {
    if value.get("action").and_then(Value::as_str) != Some("provisioned")
        || value.get("region").and_then(Value::as_str) != Some(expected_region)
    {
        return Err(DomainError::new(
            ErrorCode::ProtocolError,
            "IpRotate AWS helper returned an unexpected provision result",
        ));
    }
    let rest_api_id = value
        .get("rest_api_id")
        .and_then(Value::as_str)
        .ok_or_else(|| DomainError::new(ErrorCode::ProtocolError, "AWS omitted REST API id"))?;
    validate_rest_api_id(rest_api_id)?;
    let endpoint = value
        .get("endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            DomainError::new(ErrorCode::ProtocolError, "AWS omitted gateway endpoint")
        })?;
    Ok(crate::storage::IpRotationGateway {
        region: expected_region.into(),
        rest_api_id: rest_api_id.into(),
        endpoint: validate_gateway_endpoint(endpoint)?,
    })
}

async fn cleanup_rotation_gateways(
    helper: &str,
    credentials: &AwsCredentialFile,
    gateways: &[crate::storage::IpRotationGateway],
) {
    let cleanup_cancel = CancellationToken::new();
    let _ = stream::iter(gateways.iter().cloned())
        .map(|gateway| {
            let cleanup_cancel = cleanup_cancel.clone();
            async move {
                run_aws_control_helper(
                    helper,
                    json!({
                        "action": "delete",
                        "region": gateway.region,
                        "rest_api_id": gateway.rest_api_id,
                    }),
                    credentials,
                    &cleanup_cancel,
                )
                .await
            }
        })
        .buffer_unordered(4)
        .collect::<Vec<_>>()
        .await;
}

struct RotationCleanupResult {
    deleted_regions: Vec<String>,
    errors: Vec<Value>,
    cancelled: bool,
}

async fn delete_rotation_gateways(
    db: &crate::storage::Db,
    project_id: ProjectId,
    helper: &str,
    credentials: &AwsCredentialFile,
    profile: &crate::storage::IpRotationProfile,
    cancel: &CancellationToken,
) -> RotationCleanupResult {
    let results = stream::iter(profile.gateways.iter().cloned())
        .map(|gateway| async move {
            let result = run_aws_control_helper(
                helper,
                json!({
                    "action": "delete",
                    "region": gateway.region,
                    "rest_api_id": gateway.rest_api_id,
                }),
                credentials,
                cancel,
            )
            .await;
            (gateway, result)
        })
        .buffer_unordered(4)
        .collect::<Vec<_>>()
        .await;
    let mut deleted_regions = Vec::new();
    let mut errors = Vec::new();
    let mut cancelled = false;
    for (gateway, result) in results {
        match result {
            Ok(_) => match db
                .remove_ip_rotation_gateway(project_id, profile.id, gateway.region.clone())
                .await
            {
                Ok(()) => deleted_regions.push(gateway.region),
                Err(error) => errors.push(json!({
                    "region": gateway.region,
                    "code": error.code(),
                    "message": error.to_string(),
                })),
            },
            Err(error) => {
                cancelled |= error.code() == ErrorCode::Cancelled;
                errors.push(json!({
                    "region": gateway.region,
                    "code": error.code(),
                    "message": error.to_string(),
                }));
            }
        }
    }
    deleted_regions.sort();
    RotationCleanupResult {
        deleted_regions,
        errors,
        cancelled,
    }
}

async fn run_aws_control_helper(
    helper: &str,
    payload: Value,
    credentials: &AwsCredentialFile,
    cancel: &CancellationToken,
) -> DomainResult<Value> {
    let payload = serde_json::to_vec(&payload)
        .map_err(|error| DomainError::invalid(format!("invalid AWS operation: {error}")))?;
    let mut command = tokio::process::Command::new("python3");
    command
        .arg("-c")
        .arg(helper)
        .env_clear()
        .env(
            "PATH",
            std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()),
        )
        .env("PYTHONUNBUFFERED", "1")
        .env("AWS_ACCESS_KEY_ID", &credentials.access_key_id)
        .env("AWS_SECRET_ACCESS_KEY", &credentials.secret_access_key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(session_token) = credentials.session_token.as_deref() {
        command.env("AWS_SESSION_TOKEN", session_token);
    }
    let mut child = command.spawn().map_err(|error| {
        DomainError::new(
            ErrorCode::Unavailable,
            format!("IpRotate requires Python 3 with boto3 available to HuntProxy: {error}"),
        )
    })?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        DomainError::new(ErrorCode::Unavailable, "IpRotate helper stdin unavailable")
    })?;
    stdin.write_all(&payload).await.map_err(|error| {
        DomainError::new(
            ErrorCode::Unavailable,
            format!("could not start IpRotate AWS operation: {error}"),
        )
    })?;
    drop(stdin);

    let output = tokio::select! {
        _ = cancel.cancelled() => return Err(DomainError::new(ErrorCode::Cancelled, "plugin job cancelled")),
        result = tokio::time::timeout(AWS_OPERATION_TIMEOUT, child.wait_with_output()) => match result {
            Err(_) => return Err(DomainError::new(ErrorCode::Timeout, format!("AWS API Gateway operation timed out after {} seconds", AWS_OPERATION_TIMEOUT.as_secs()))),
            Ok(Err(error)) => return Err(DomainError::new(ErrorCode::Unavailable, format!("IpRotate AWS helper failed: {error}"))),
            Ok(Ok(output)) => output,
        }
    };
    let redact = |bytes: &[u8]| {
        let mut text = String::from_utf8_lossy(bytes)
            .chars()
            .take(2_048)
            .collect::<String>();
        for secret in [
            Some(credentials.access_key_id.as_str()),
            Some(credentials.secret_access_key.as_str()),
            credentials.session_token.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !secret.is_empty() {
                text = text.replace(secret, "[redacted]");
            }
        }
        text
    };
    if !output.status.success() {
        let message = redact(&output.stderr);
        return Err(DomainError::new(
            ErrorCode::Unavailable,
            format!(
                "AWS API Gateway operation failed: {}",
                if message.trim().is_empty() {
                    format!("helper exited with {}", output.status)
                } else {
                    message.trim().to_string()
                }
            ),
        ));
    }
    if output.stdout.len() > 64 * 1024 {
        return Err(DomainError::new(
            ErrorCode::BodyTooLarge,
            "IpRotate AWS helper output exceeded 64 KiB",
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        DomainError::new(
            ErrorCode::ProtocolError,
            format!(
                "IpRotate AWS helper returned invalid JSON: {error}; stderr: {}",
                redact(&output.stderr)
            ),
        )
    })
}

struct PluginResponseBody {
    body_base64: Option<String>,
    truncated: bool,
    contains: BTreeMap<String, bool>,
    search_complete: bool,
}

/// Plugin analyzers compare semantic responses. Supplying compressed wire bytes
/// makes otherwise identical dynamic pages look unrelated, so decode bounded
/// bodies here. Oversized or unsupported encodings deliberately fall back to
/// Reply's already-decoded preview instead of exposing binary data as text.
fn plugin_response_body(
    headers: &[HeaderEntry],
    mut body: Vec<u8>,
    body_limit: usize,
    needles: &[String],
) -> PluginResponseBody {
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
                    contains: BTreeMap::new(),
                    search_complete: false,
                };
            }
        }
    }
    let contains = needles
        .iter()
        .map(|needle| {
            (
                needle.clone(),
                !needle.is_empty()
                    && body
                        .windows(needle.len())
                        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes())),
            )
        })
        .collect();
    let body_limit = body_limit.min(MAX_RESPONSE_BODY_FOR_PLUGIN);
    let truncated = body.len() > body_limit;
    body.truncate(body_limit);
    PluginResponseBody {
        body_base64: (body_limit > 0)
            .then(|| base64::engine::general_purpose::STANDARD.encode(body)),
        truncated,
        contains,
        search_complete: true,
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

fn plugin_raw_request_bytes(
    protocol: &str,
    method: &str,
    target: &str,
    headers: &[HeaderEntry],
    body: &[u8],
) -> Option<(Vec<u8>, bool)> {
    if protocol == "HTTP/1.1 raw" {
        return Some((body.to_vec(), false));
    }
    if protocol.ends_with(" raw") {
        return None;
    }
    let mut raw = format!("{method} {target} HTTP/1.1\r\n").into_bytes();
    for header in headers {
        raw.extend_from_slice(header.name.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(&header.value);
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(body);
    Some((raw, true))
}

fn plugin_http_request_delay(milliseconds: u64) -> DomainResult<Duration> {
    if milliseconds > MAX_HTTP_REQUEST_DELAY_MS {
        return Err(DomainError::invalid(format!(
            "plugin HTTP request delay_before_ms exceeds {MAX_HTTP_REQUEST_DELAY_MS} ms"
        )));
    }
    Ok(Duration::from_millis(milliseconds))
}

fn reserve_plugin_request_slot(
    next: &mut tokio::time::Instant,
    now: tokio::time::Instant,
    spacing: Duration,
) -> tokio::time::Instant {
    let ready_at = (*next).max(now);
    *next = ready_at + spacing;
    ready_at
}

fn apply_url_param_patches(url: &mut url::Url, patches: &[PluginParamPatch]) -> DomainResult<()> {
    let mut pairs = url.query_pairs().into_owned().collect::<Vec<_>>();
    apply_form_param_patches(&mut pairs, patches)?;
    url.set_query(None);
    if !pairs.is_empty() {
        url.query_pairs_mut().extend_pairs(pairs);
    }
    Ok(())
}

fn apply_form_param_patches(
    pairs: &mut Vec<(String, String)>,
    patches: &[PluginParamPatch],
) -> DomainResult<()> {
    for patch in patches {
        if patch.name.is_empty() || patch.name.len() > 1024 {
            return Err(DomainError::invalid(
                "browser_csrf parameter name is invalid",
            ));
        }
        pairs.retain(|(name, _)| name != &patch.name);
        if let Some(value) = &patch.value {
            pairs.push((patch.name.clone(), value.clone()));
        }
    }
    Ok(())
}

fn matched_cookie_names(
    expected: &[CookiePair],
    actual_header: &str,
) -> DomainResult<BTreeSet<String>> {
    let actual = crate::cookies::parse_cookie_header(actual_header)?;
    Ok(actual
        .iter()
        .filter(|actual| {
            expected
                .iter()
                .any(|expected| expected.name == actual.name && expected.value == actual.value)
        })
        .map(|pair| pair.name.clone())
        .collect())
}

fn operation_request_count(operation: &PluginOperation) -> usize {
    match operation {
        PluginOperation::RaceGroup(group) => group.requests.len(),
        PluginOperation::RawHttp2(request) => request.streams.len(),
        PluginOperation::RawHttp1Group(group) => group.members.len(),
        PluginOperation::HttpWorkflow(workflow) => workflow.steps.len(),
        PluginOperation::AwsApiGateway(PluginAwsApiGateway::Enable { regions, .. }) => {
            regions.len()
        }
        PluginOperation::AwsApiGateway(_) => 1,
        PluginOperation::BrowserCsrf(_) => 1,
        _ => 1,
    }
}

type RaceExtractionPlan = Vec<(String, Vec<PluginWorkflowExtract>)>;

fn race_request_has_placeholder(request: &RaceRequest) -> bool {
    const PREFIX: &str = "{{extract:";
    request
        .url
        .as_deref()
        .is_some_and(|value| value.contains(PREFIX))
        || request
            .body_text
            .as_deref()
            .is_some_and(|value| value.contains(PREFIX))
        || request
            .body_base64
            .as_deref()
            .is_some_and(|value| value.contains(PREFIX))
        || request.headers.iter().any(|header| {
            std::str::from_utf8(&header.value)
                .ok()
                .is_some_and(|value| value.contains(PREFIX))
        })
        || request
            .success
            .as_ref()
            .is_some_and(race_success_has_placeholder)
}

fn race_text_has_placeholder(predicate: &RaceTextPredicate) -> bool {
    [
        predicate.equals.as_deref(),
        predicate.contains.as_deref(),
        predicate.regex.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| value.contains("{{extract:"))
}

fn race_success_has_placeholder(predicate: &RaceSuccessPredicate) -> bool {
    predicate
        .body_contains
        .as_deref()
        .is_some_and(|value| value.contains("{{extract:"))
        || predicate
            .body_regex
            .as_deref()
            .is_some_and(|value| value.contains("{{extract:"))
        || predicate
            .headers
            .iter()
            .any(|header| race_text_has_placeholder(&header.value))
        || predicate
            .redirect_location
            .as_ref()
            .is_some_and(race_text_has_placeholder)
        || predicate.json.iter().any(|check| {
            check
                .equals
                .as_ref()
                .and_then(Value::as_str)
                .is_some_and(|value| value.contains("{{extract:"))
        })
}

fn validate_race_data_flow(plan: &PluginPlan) -> DomainResult<()> {
    let mut has_data_flow = false;
    let mut extract_names = BTreeSet::new();
    let mut total_extracts = 0usize;
    for operation in &plan.operations {
        let PluginOperation::RaceGroup(group) = operation else {
            continue;
        };
        let extract_count = group
            .requests
            .iter()
            .map(|request| request.extract.len())
            .sum::<usize>();
        total_extracts = total_extracts.saturating_add(extract_count);
        if total_extracts > MAX_RACE_EXTRACTS_PER_PLAN {
            return Err(DomainError::new(
                ErrorCode::CombinationLimit,
                format!("race plan exceeds {MAX_RACE_EXTRACTS_PER_PLAN} extracts"),
            ));
        }
        if extract_count > MAX_WORKFLOW_EXTRACTS_PER_STEP {
            return Err(DomainError::new(
                ErrorCode::CombinationLimit,
                format!(
                    "race group {} exceeds {MAX_WORKFLOW_EXTRACTS_PER_STEP} extracts",
                    group.id
                ),
            ));
        }
        if extract_count > 0 && !matches!(group.technique, RaceTechnique::SequentialControl) {
            return Err(DomainError::invalid(
                "race response extraction is allowed only on sequential control, setup, or validation groups",
            ));
        }
        for request in &group.requests {
            has_data_flow |= race_request_has_placeholder(request) || !request.extract.is_empty();
            for extract in &request.extract {
                validate_workflow_name(extract.name(), "race extract name")?;
                if !extract_names.insert(extract.name().to_string()) {
                    return Err(DomainError::invalid(format!(
                        "duplicate race extract name in plan: {}",
                        extract.name()
                    )));
                }
                extract.validate()?;
            }
        }
    }
    if has_data_flow && plan.execution != PluginExecution::Sequential {
        return Err(DomainError::invalid(
            "race extraction and {{extract:name}} placeholders require execution=sequential",
        ));
    }
    if has_data_flow && !plan.stop_on_error {
        return Err(DomainError::invalid(
            "race extraction and {{extract:name}} placeholders require stop_on_error=true",
        ));
    }
    Ok(())
}

fn race_extraction_plan(operation: &PluginOperation) -> RaceExtractionPlan {
    let PluginOperation::RaceGroup(group) = operation else {
        return Vec::new();
    };
    group
        .requests
        .iter()
        .filter(|request| !request.extract.is_empty())
        .map(|request| (request.id.clone(), request.extract.clone()))
        .collect()
}

fn substitute_race_operation(
    operation: &mut PluginOperation,
    values: &HashMap<String, String>,
) -> DomainResult<()> {
    let PluginOperation::RaceGroup(group) = operation else {
        return Ok(());
    };
    for request in &mut group.requests {
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
                "race extract placeholders are not supported in body_base64; use body_text or typed header/URL values",
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
            let value = std::str::from_utf8(&header.value)
                .map_err(|_| DomainError::invalid("templated race headers must contain UTF-8"))?;
            header.value = substitute_workflow_template(value, values)?.into_bytes();
        }
        if let Some(predicate) = &mut request.success {
            substitute_race_success(predicate, values)?;
        }
    }
    Ok(())
}

fn substitute_race_text(
    predicate: &mut RaceTextPredicate,
    values: &HashMap<String, String>,
) -> DomainResult<()> {
    if let Some(value) = &mut predicate.equals {
        *value = substitute_workflow_template(value, values)?;
    }
    if let Some(value) = &mut predicate.contains {
        *value = substitute_workflow_template(value, values)?;
    }
    if predicate
        .regex
        .as_deref()
        .is_some_and(|value| value.contains("{{extract:"))
    {
        return Err(DomainError::invalid(
            "race extract placeholders are not supported in regex predicates; use equals or contains",
        ));
    }
    Ok(())
}

fn substitute_race_success(
    predicate: &mut RaceSuccessPredicate,
    values: &HashMap<String, String>,
) -> DomainResult<()> {
    if let Some(value) = &mut predicate.body_contains {
        *value = substitute_workflow_template(value, values)?;
    }
    if predicate
        .body_regex
        .as_deref()
        .is_some_and(|value| value.contains("{{extract:"))
    {
        return Err(DomainError::invalid(
            "race extract placeholders are not supported in regex predicates; use body_contains",
        ));
    }
    for header in &mut predicate.headers {
        substitute_race_text(&mut header.value, values)?;
    }
    if let Some(redirect) = &mut predicate.redirect_location {
        substitute_race_text(redirect, values)?;
    }
    for check in &mut predicate.json {
        if let Some(Value::String(value)) = &mut check.equals {
            *value = substitute_workflow_template(value, values)?;
        }
    }
    Ok(())
}

fn apply_race_extractions(
    observation: &mut Value,
    plan: &RaceExtractionPlan,
    values: &mut HashMap<String, String>,
    total_value_bytes: &mut usize,
) -> DomainResult<()> {
    let mut material = HashMap::<String, Value>::new();
    if let Some(responses) = observation
        .get_mut("responses")
        .and_then(Value::as_array_mut)
    {
        for response in responses {
            let Some(object) = response.as_object_mut() else {
                continue;
            };
            let id = object.get("id").and_then(Value::as_str).map(str::to_string);
            let private = object.remove("_extract").unwrap_or(Value::Null);
            if let Some(id) = id {
                material.insert(id, private);
            }
        }
    }
    let mut extracted = BTreeSet::new();
    for (request_id, rules) in plan {
        let response = material.get(request_id).unwrap_or(&Value::Null);
        for rule in rules {
            if let Some(value) = rule.extract(response)? {
                if value.len() > MAX_WORKFLOW_VALUE_BYTES {
                    return Err(DomainError::new(
                        ErrorCode::BodyTooLarge,
                        format!(
                            "race extract {} exceeds {MAX_WORKFLOW_VALUE_BYTES} bytes",
                            rule.name()
                        ),
                    ));
                }
                *total_value_bytes = total_value_bytes.saturating_add(value.len());
                if *total_value_bytes > MAX_WORKFLOW_VALUES_BYTES {
                    return Err(DomainError::new(
                        ErrorCode::BodyTooLarge,
                        format!("race extracted values exceed {MAX_WORKFLOW_VALUES_BYTES} bytes"),
                    ));
                }
                values.insert(rule.name().to_string(), value);
                extracted.insert(rule.name().to_string());
            }
        }
    }
    observation["extracted"] = json!(extracted);
    Ok(())
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

fn collect_exchange_ids(value: &Value) -> Vec<ExchangeId> {
    fn visit(value: &Value, ids: &mut BTreeSet<i64>) {
        match value {
            Value::Object(object) => {
                if let Some(id) = object.get("exchange_id").and_then(Value::as_i64) {
                    if id > 0 {
                        ids.insert(id);
                    }
                }
                object.values().for_each(|child| visit(child, ids));
            }
            Value::Array(items) => items.iter().for_each(|child| visit(child, ids)),
            _ => {}
        }
    }
    let mut ids = BTreeSet::new();
    visit(value, &mut ids);
    ids.into_iter().map(ExchangeId).collect()
}

fn operation_identity_selectors(
    operation: &PluginOperation,
) -> Box<dyn Iterator<Item = &PluginIdentitySelector> + '_> {
    match operation {
        PluginOperation::HttpRequest(request) => Box::new(request.identity.iter()),
        PluginOperation::HttpWorkflow(workflow) => Box::new(
            workflow
                .steps
                .iter()
                .filter_map(|step| step.request.identity.as_ref()),
        ),
        PluginOperation::BrowserCsrf(probe) => Box::new(probe.identity.iter()),
        _ => Box::new(std::iter::empty()),
    }
}

fn operation_observation_policies(
    operation: &PluginOperation,
) -> Box<dyn Iterator<Item = &PluginObservationPolicy> + '_> {
    match operation {
        PluginOperation::HttpRequest(request) => Box::new(request.observe.iter()),
        PluginOperation::HttpWorkflow(workflow) => Box::new(
            workflow
                .steps
                .iter()
                .filter_map(|step| step.request.observe.as_ref()),
        ),
        _ => Box::new(std::iter::empty()),
    }
}

fn validate_observation_policy(policy: &PluginObservationPolicy) -> DomainResult<()> {
    if policy.body_bytes > MAX_RESPONSE_BODY_FOR_PLUGIN {
        return Err(DomainError::invalid(format!(
            "observe.body_bytes cannot exceed {MAX_RESPONSE_BODY_FOR_PLUGIN}"
        )));
    }
    if policy.body_contains.len() > 32
        || policy
            .body_contains
            .iter()
            .any(|value| value.is_empty() || value.len() > 200)
    {
        return Err(DomainError::invalid(
            "observe.body_contains accepts at most 32 non-empty strings of at most 200 bytes",
        ));
    }
    Ok(())
}

fn compact_analysis_observations(mut observations: Value, maximum: usize) -> DomainResult<Value> {
    if serde_json::to_vec(&observations).is_ok_and(|bytes| bytes.len() <= maximum) {
        return Ok(observations);
    }
    fn omit(value: &mut Value) {
        match value {
            Value::Object(object) => {
                if object
                    .get("response_body_base64")
                    .is_some_and(Value::is_string)
                {
                    object.insert("response_body_base64".into(), Value::Null);
                    object.insert("response_body_truncated".into(), Value::Bool(true));
                    object.insert(
                        "response_body_omitted_reason".into(),
                        Value::String("analysis_budget".into()),
                    );
                }
                if object.get("response_base64").is_some_and(Value::is_string) {
                    object.insert("response_base64".into(), Value::Null);
                    object.insert("truncated".into(), Value::Bool(true));
                    object.insert(
                        "response_transcript_omitted_reason".into(),
                        Value::String("analysis_budget".into()),
                    );
                }
                if object
                    .get("response_transcript_base64")
                    .is_some_and(Value::is_string)
                {
                    object.insert("response_transcript_base64".into(), Value::Null);
                    object.insert("response_transcript_truncated".into(), Value::Bool(true));
                    object.insert(
                        "response_transcript_omitted_reason".into(),
                        Value::String("analysis_budget".into()),
                    );
                }
                object.values_mut().for_each(omit);
            }
            Value::Array(items) => items.iter_mut().for_each(omit),
            _ => {}
        }
    }
    omit(&mut observations);
    let size = serde_json::to_vec(&observations)
        .map_err(|error| DomainError::invalid(error.to_string()))?
        .len();
    if size > maximum {
        return Err(DomainError::new(ErrorCode::BodyTooLarge, format!("plugin observations remain larger than {maximum} bytes after omitting captured bodies")));
    }
    Ok(observations)
}

fn push_bounded_analysis_observation(
    observations: &mut Vec<Value>,
    mut observation: Value,
    approximate_bytes: &mut usize,
) -> DomainResult<()> {
    let mut encoded = serde_json::to_vec(&observation)
        .map_err(|error| DomainError::invalid(error.to_string()))?;
    if approximate_bytes.saturating_add(encoded.len()) > MAX_ANALYSIS_OBSERVATION_BYTES {
        match compact_analysis_observations(observation.clone(), 256 * 1024) {
            Ok(compacted) => {
                observation = compacted;
                encoded = serde_json::to_vec(&observation)
                    .map_err(|error| DomainError::invalid(error.to_string()))?;
            }
            Err(error) if error.code() == ErrorCode::BodyTooLarge => {}
            Err(error) => return Err(error),
        }
    }
    if approximate_bytes.saturating_add(encoded.len()) > MAX_ANALYSIS_OBSERVATION_BYTES {
        let operation_id = observation.get("id").cloned().unwrap_or(Value::Null);
        let evidence = collect_exchange_ids(&observation)
            .into_iter()
            .map(|exchange_id| json!({"exchange_id": exchange_id}))
            .collect::<Vec<_>>();
        observation = json!({
            "id": operation_id,
            "error": {
                "code": ErrorCode::BodyTooLarge.as_str(),
                "message": "observation details omitted because the aggregate analysis budget was exhausted",
            },
            "evidence": evidence,
        });
        encoded = serde_json::to_vec(&observation)
            .map_err(|error| DomainError::invalid(error.to_string()))?;
        if approximate_bytes.saturating_add(encoded.len()) > MAX_ANALYSIS_OBSERVATION_BYTES {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                "plugin observation index exceeds the aggregate analysis budget",
            ));
        }
    }
    *approximate_bytes += encoded.len();
    observations.push(observation);
    Ok(())
}

fn collect_input_identity_selector_keys(input: &Value) -> DomainResult<BTreeSet<String>> {
    fn visit(value: &Value, keys: &mut BTreeSet<String>) -> DomainResult<()> {
        match value {
            Value::Object(object) => {
                let profile = object.get("profile").and_then(Value::as_str);
                let cookie_file = object.get("cookie_file").and_then(Value::as_str);
                if profile.is_some() || cookie_file.is_some() {
                    keys.insert(identity_selector_key(&PluginIdentitySelector {
                        profile: profile.map(str::to_string),
                        cookie_file: cookie_file.map(str::to_string),
                    })?);
                }
                for child in object.values() {
                    visit(child, keys)?;
                }
            }
            Value::Array(items) => {
                for child in items {
                    visit(child, keys)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut keys = BTreeSet::new();
    visit(input, &mut keys)?;
    Ok(keys)
}

fn identity_selector_key(selector: &PluginIdentitySelector) -> DomainResult<String> {
    match (selector.profile.as_deref(), selector.cookie_file.as_deref()) {
        (Some(name), None) if !name.is_empty() => Ok(format!("profile:{name}")),
        (None, Some(path)) if !path.is_empty() => Ok(format!("file:{path}")),
        _ => Err(DomainError::invalid(
            "plugin identity must provide exactly one non-empty profile or cookie_file",
        )),
    }
}

fn resolve_operation_identity_cookie(
    selector: Option<&PluginIdentitySelector>,
    resolved: &HashMap<String, ResolvedPluginIdentity>,
    target_url: &str,
) -> DomainResult<Option<String>> {
    let Some(selector) = selector else {
        return Ok(None);
    };
    let key = identity_selector_key(selector)?;
    let identity = resolved
        .get(&key)
        .ok_or_else(|| DomainError::new(ErrorCode::Internal, "plugin identity was not resolved"))?;
    let cookie = match identity {
        ResolvedPluginIdentity::Profile(profile) => profile.cookie_header_for_url(target_url)?,
        ResolvedPluginIdentity::CookieInput(input) => {
            crate::cookies::validate_cookie_profile(target_url, input.clone())?
                .cookie_header_for_url(target_url)?
        }
    };
    cookie
        .ok_or_else(|| {
            DomainError::invalid("plugin identity has no applicable cookies for request URL")
        })
        .map(Some)
}

fn validate_resolved_identity_comparisons(
    operations: &[PluginOperation],
    resolved: &HashMap<String, ResolvedPluginIdentity>,
) -> DomainResult<()> {
    let mut groups = HashMap::<String, HashMap<String, String>>::new();
    for operation in operations {
        let PluginOperation::HttpRequest(request) = operation else {
            continue;
        };
        let (Some(group), Some(selector), Some(base_id)) = (
            &request.identity_comparison,
            &request.identity,
            request.base_exchange_id,
        ) else {
            continue;
        };
        let key = identity_selector_key(selector)?;
        let identity = resolved.get(&key).ok_or_else(|| {
            DomainError::new(
                ErrorCode::Internal,
                "plugin comparison identity was not resolved",
            )
        })?;
        let fingerprint = match identity {
            ResolvedPluginIdentity::Profile(profile) => profile.cookie_header.clone(),
            ResolvedPluginIdentity::CookieInput(input) => input.clone(),
        };
        let comparison_key = format!("{group}:{base_id:?}");
        let members = groups.entry(comparison_key).or_default();
        if members
            .values()
            .any(|existing| existing == &fingerprint && !members.contains_key(&key))
        {
            return Err(DomainError::invalid(
                "identity comparison sources resolve to identical cookie credentials",
            ));
        }
        members.insert(key, fingerprint);
    }
    Ok(())
}

fn skipped_operation_observation(operation: &PluginOperation) -> Value {
    json!({
        "id": operation.id(),
        "skipped": {"reason":"previous operation failed"},
    })
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

fn implicit_plugin_target_host(
    project_target_url: &str,
    has_base_exchange: bool,
    context: &Value,
) -> Option<String> {
    let source = if has_base_exchange {
        context
            .pointer("/base_exchange/url")
            .and_then(Value::as_str)
    } else {
        Some(project_target_url)
    }?;
    url::Url::parse(source)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
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
    run_js_stage_with_timeout(plugin, stage, input, observations, context, None, None).await
}

async fn run_js_stage_with_timeout(
    plugin: &LoadedPlugin,
    stage: &'static str,
    input: &Value,
    observations: &Value,
    context: &Value,
    timeout_override_ms: Option<u64>,
    cancel: Option<CancellationToken>,
) -> DomainResult<Value> {
    let script = plugin.script.clone();
    let input =
        serde_json::to_string(input).map_err(|error| DomainError::invalid(error.to_string()))?;
    let observations = serde_json::to_string(observations)
        .map_err(|error| DomainError::invalid(error.to_string()))?;
    let context =
        serde_json::to_string(context).map_err(|error| DomainError::invalid(error.to_string()))?;
    let configured_memory = plugin
        .manifest
        .limits
        .memory_mb
        .unwrap_or(DEFAULT_MEMORY_MB)
        .clamp(4, MAX_MEMORY_MB)
        * 1024
        * 1024;
    // Parsing observations into QuickJS necessarily duplicates their serialized
    // representation, and analyzers may temporarily normalize or decode bodies.
    // Give large, bounded stages proportional headroom instead of applying a
    // fixed heap that can be smaller than the input plus its parse tree.
    let dynamic_memory = observations
        .len()
        .saturating_mul(4)
        .saturating_add(script.len())
        .saturating_add(input.len())
        .saturating_add(context.len())
        .saturating_add(16 * 1024 * 1024);
    let memory = configured_memory
        .max(dynamic_memory)
        .min(MAX_MEMORY_MB * 1024 * 1024);
    let configured_timeout_ms = plugin
        .manifest
        .limits
        .js_stage_timeout_ms
        .unwrap_or(DEFAULT_JS_STAGE_TIMEOUT_MS)
        .clamp(250, MAX_JS_STAGE_TIMEOUT_MS);
    let js_stage_timeout_ms = timeout_override_ms
        .unwrap_or(configured_timeout_ms)
        .clamp(configured_timeout_ms, MAX_JS_STAGE_TIMEOUT_MS);
    tokio::task::spawn_blocking(move || {
        run_js_sync(
            &script,
            stage,
            &input,
            &observations,
            &context,
            memory,
            Duration::from_millis(js_stage_timeout_ms),
            cancel,
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
    cancel: Option<CancellationToken>,
) -> DomainResult<Value> {
    let runtime = Runtime::new().map_err(|error| {
        DomainError::new(ErrorCode::Unavailable, format!("QuickJS runtime: {error}"))
    })?;
    runtime.set_memory_limit(memory_limit);
    runtime.set_max_stack_size(512 * 1024);
    let deadline = Instant::now() + stage_timeout;
    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupted_handler = interrupted.clone();
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancelled_handler = cancelled.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        if cancel.as_ref().is_some_and(CancellationToken::is_cancelled) {
            cancelled_handler.store(true, Ordering::Relaxed);
            return true;
        }
        let expired = Instant::now() >= deadline;
        if expired {
            interrupted_handler.store(true, Ordering::Relaxed);
        }
        expired
    })));
    let context_handle = Context::full(&runtime).map_err(|error| {
        DomainError::new(ErrorCode::Unavailable, format!("QuickJS context: {error}"))
    })?;
    let output = context_handle.with(|ctx| -> Result<String, String> {
        ctx.eval::<(), _>(script)
            .catch(&ctx)
            .map_err(|error| bounded_javascript_error(error.to_string()))?;
        let plugin: Object = ctx
            .globals()
            .get("HuntProxyPlugin")
            .catch(&ctx)
            .map_err(|error| bounded_javascript_error(error.to_string()))?;
        let function: Function = plugin
            .get(stage)
            .catch(&ctx)
            .map_err(|error| bounded_javascript_error(error.to_string()))?;
        let input_value = ctx
            .json_parse(input.as_bytes())
            .catch(&ctx)
            .map_err(|error| bounded_javascript_error(error.to_string()))?;
        let context_value = ctx
            .json_parse(context.as_bytes())
            .catch(&ctx)
            .map_err(|error| bounded_javascript_error(error.to_string()))?;
        let output: JsValue = if stage == "plan" {
            function.call((This(plugin.clone()), input_value, context_value))
        } else {
            let observations_value = ctx
                .json_parse(observations.as_bytes())
                .catch(&ctx)
                .map_err(|error| bounded_javascript_error(error.to_string()))?;
            function.call((
                This(plugin.clone()),
                input_value,
                observations_value,
                context_value,
            ))
        }
        .catch(&ctx)
        .map_err(|error| bounded_javascript_error(error.to_string()))?;
        ctx.json_stringify(output)
            .catch(&ctx)
            .map_err(|error| bounded_javascript_error(error.to_string()))?
            .map(|value| {
                value
                    .to_string()
                    .map_err(|error| bounded_javascript_error(error.to_string()))
            })
            .transpose()?
            .ok_or_else(|| "plugin returned undefined".to_string())
    });
    if cancelled.load(Ordering::Relaxed) {
        return Err(DomainError::new(
            ErrorCode::Cancelled,
            "plugin JavaScript stage cancelled",
        ));
    }
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

fn bounded_javascript_error(mut message: String) -> String {
    const MAX_ERROR_CHARS: usize = 2_048;
    if let Some((index, _)) = message.char_indices().nth(MAX_ERROR_CHARS) {
        message.truncate(index);
        message.push('…');
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnusedTransport;

    #[async_trait::async_trait]
    impl crate::transport::SemanticTransport for UnusedTransport {
        async fn send(
            &self,
            _dial: &ValidatedDial,
            _request: crate::transport::OutboundRequest,
        ) -> DomainResult<crate::transport::OutboundResponse> {
            Err(DomainError::new(
                ErrorCode::Internal,
                "semantic transport is unused by raw HTTP tests",
            ))
        }

        fn profile_name(&self) -> &str {
            "unused"
        }

        fn provenance(&self) -> TransportProvenance {
            TransportProvenance::GenericUnprofiled
        }
    }

    fn test_job(state: PluginJobState) -> Arc<PluginJob> {
        Arc::new(PluginJob {
            view: parking_lot::RwLock::new(PluginJobRecord {
                id: Uuid::new_v4(),
                project_id: ProjectId(1),
                plugin_id: "test".into(),
                action: "run".into(),
                base_exchange_id: None,
                state,
                phase: if matches!(
                    state,
                    PluginJobState::Completed | PluginJobState::Failed | PluginJobState::Cancelled
                ) {
                    PluginJobPhase::Finished
                } else {
                    PluginJobPhase::Executing
                },
                operation_count: 0,
                completed_operations: 0,
                result: None,
                analysis_resume_available: false,
                analysis_checkpoint_status: "not_created".into(),
                analysis_resume_reason: None,
                error: None,
            }),
            cancel: CancellationToken::new(),
            analysis_checkpoint: parking_lot::Mutex::new(None),
        })
    }

    #[test]
    fn plugin_http_credentials_default_to_project_and_support_explicit_opt_out() {
        let default_request: PluginHttpRequest = serde_json::from_value(json!({
            "id": "default",
            "url": "https://example.test/"
        }))
        .unwrap();
        assert_eq!(
            default_request.credential_mode,
            PluginCredentialMode::WithProjectCredentials
        );
        let anonymous_request: PluginHttpRequest = serde_json::from_value(json!({
            "id": "anonymous",
            "url": "https://example.test/",
            "credential_mode": "without_project_credentials"
        }))
        .unwrap();
        assert_eq!(
            anonymous_request.credential_mode,
            PluginCredentialMode::WithoutProjectCredentials
        );
    }

    #[test]
    fn compact_result_keeps_bounded_follow_up_and_removes_remediation() {
        let mut result = json!({
            "plan_result": {"mode": "full", "coverage": {"headers": {"tested": 10}}},
            "analysis": {
                "findings": [{"title": "test", "remediation": "do not surface"}],
                "result": {
                    "follow_up": {"action": "confirm", "candidate_ids": ["a", "b"]},
                    "large_diagnostic_array": [1, 2, 3]
                }
            },
            "persisted_findings": [{"id": 1}]
        });
        remove_remediation_fields(&mut result);
        assert!(result.pointer("/analysis/findings/0/remediation").is_none());
        let summary = summarize_plugin_result(&result);
        assert_eq!(summary["follow_up"]["candidate_ids"], json!(["a", "b"]));
        assert!(summary["plan_result"].get("coverage").is_none());
        assert!(summary["analysis_result"].get("follow_up").is_none());
        assert_eq!(
            summary["analysis_result"]["large_diagnostic_array"]["count"],
            3
        );
    }

    #[test]
    fn polling_hint_adapts_to_remaining_work_and_stops_when_terminal() {
        let job = test_job(PluginJobState::Running);
        {
            let mut view = job.view.write();
            view.operation_count = 1_000;
            view.completed_operations = 100;
        }
        assert_eq!(
            job.view.read().status().recommended_poll_interval_ms,
            Some(5_000)
        );
        {
            let mut view = job.view.write();
            view.completed_operations = 995;
        }
        assert_eq!(
            job.view.read().status().recommended_poll_interval_ms,
            Some(500)
        );
        {
            let mut view = job.view.write();
            view.state = PluginJobState::Completed;
            view.phase = PluginJobPhase::Finished;
        }
        assert_eq!(job.view.read().status().recommended_poll_interval_ms, None);
    }

    #[tokio::test]
    async fn job_status_is_result_free_and_result_findings_are_stably_paged() {
        let db = Arc::new(crate::storage::Db::open_in_memory().await.unwrap());
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: Arc::new(UnusedTransport),
            placeholder_key: crate::reply::PlaceholderKey::from_bytes(vec![9; 32]),
            upstream_proxies: Default::default(),
        });
        let service = PluginService {
            directory: PathBuf::from("plugins"),
            reply,
            db,
            browser: None,
            plugins: Arc::new(HashMap::new()),
            load_issues: Arc::new(Vec::new()),
            jobs: Arc::new(DashMap::new()),
            active_jobs: Arc::new(tokio::sync::Semaphore::new(1)),
            preview_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            analysis_retry_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            analysis_checkpoint_bytes: Arc::new(AtomicUsize::new(0)),
        };
        let job = test_job(PluginJobState::Completed);
        let id = job.view.read().id;
        job.view.write().result = Some(json!({
            "plan_result": {"mode": "full"},
            "analysis": {
                "findings": [
                    {"title": "one", "remediation": "hidden"},
                    {"title": "two"},
                    {"title": "three"}
                ],
                "result": {"follow_up": {"action": "confirm", "ids": [1, 2]}}
            },
            "persisted_findings": [{"id": 10}, {"id": 11}, {"id": 12}]
        }));
        service.jobs.insert(id, job);

        let status = serde_json::to_value(service.status(id).unwrap()).unwrap();
        assert!(status.get("result").is_none());
        assert!(status.get("recommended_poll_interval_ms").is_none());

        let summary = service
            .results(id, PluginResultView::Summary, 0, 25)
            .unwrap();
        assert_eq!(summary["findings"]["total"], 3);
        assert_eq!(summary["summary"]["follow_up"]["ids"], json!([1, 2]));

        let first = service
            .results(id, PluginResultView::Findings, 0, 2)
            .unwrap();
        assert_eq!(first["pagination"]["next_offset"], 2);
        assert_eq!(first["findings"][0]["title"], "one");
        assert!(first["findings"][0].get("remediation").is_none());
        let second = service
            .results(id, PluginResultView::Findings, 2, 2)
            .unwrap();
        assert_eq!(second["findings"][0]["title"], "three");
        assert!(second["pagination"]["next_offset"].is_null());

        let full = service.results(id, PluginResultView::Full, 0, 1).unwrap();
        assert_eq!(full["persisted_findings_total"], 3);
        assert!(full["result"].get("persisted_findings").is_none());
        assert_eq!(
            full["result"]["analysis"]["findings"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let failed = test_job(PluginJobState::Failed);
        let failed_id = failed.view.read().id;
        failed.view.write().result = Some(json!({
            "plan_result": {"request_shapes": 1},
            "execution": {"evidence_exchange_ids": [41, 42]},
            "analysis": null,
            "persisted_findings": []
        }));
        service.jobs.insert(failed_id, failed);
        let failed_summary = service
            .results(failed_id, PluginResultView::Summary, 0, 25)
            .unwrap();
        assert!(failed_summary["result_available"].as_bool().unwrap());
        assert_eq!(failed_summary["summary"]["execution_evidence"]["count"], 2);
        let failed_full = service
            .results(failed_id, PluginResultView::Full, 0, 25)
            .unwrap();
        assert_eq!(
            failed_full["result"]["execution"]["evidence_exchange_ids"],
            json!([41, 42])
        );
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
            None,
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
            None,
        )
        .unwrap();
        assert_eq!(analysis, json!({"count":0,"value":7}));
        let method_script = r#"globalThis.HuntProxyPlugin = {
          helper() { return 9; }, plan() { return {operations: [], result: {value: this.helper()}}; }, analyze() { return {}; }
        };"#;
        let method_plan = run_js_sync(
            method_script,
            "plan",
            "{}",
            "null",
            "{}",
            4 * 1024 * 1024,
            Duration::from_secs(2),
            None,
        )
        .unwrap();
        assert_eq!(
            method_plan["result"]["value"], 9,
            "native calls preserve HuntProxyPlugin as the JavaScript receiver"
        );
    }

    #[test]
    fn javascript_runtime_parses_large_observations_as_json_not_source() {
        let script = r#"globalThis.HuntProxyPlugin = {
          plan() { return {operations: []}; },
          analyze(input, observations) { return {count: observations.length, tail: observations[observations.length - 1].body.length}; }
        };"#;
        let observations = serde_json::to_string(
            &(0..770)
                .map(|index| json!({"id": index, "body": "x".repeat(9_500)}))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let started = Instant::now();
        let analysis = run_js_sync(
            script,
            "analyze",
            "{}",
            &observations,
            "{}",
            64 * 1024 * 1024,
            Duration::from_secs(10),
            None,
        )
        .unwrap();
        assert_eq!(analysis, json!({"count":770,"tail":9500}));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn analysis_observation_budget_omits_bodies_but_keeps_proof_metadata() {
        let observations = Value::Array((0..80).map(|index| json!({
            "id": format!("probe-{index}"), "exchange_id": index + 1,
            "response_body_hash": format!("hash-{index}"),
            "response_body_base64": base64::engine::general_purpose::STANDARD.encode(vec![index as u8; 4096]),
            "response_body_contains": {"marker": index == 79},
            "response_preview": {"text":"bounded"}
        })).collect());
        let compacted = compact_analysis_observations(observations, 32 * 1024).unwrap();
        assert!(serde_json::to_vec(&compacted).unwrap().len() <= 32 * 1024);
        assert!(compacted[0]["response_body_base64"].is_null());
        assert_eq!(
            compacted[0]["response_body_omitted_reason"],
            "analysis_budget"
        );
        assert_eq!(compacted[79]["response_body_contains"]["marker"], true);
        assert_eq!(compacted[79]["response_body_hash"], "hash-79");
        assert_eq!(compacted[79]["exchange_id"], 80);
        let raw = compact_analysis_observations(
            json!([{"response_transcript_base64":"eA==".repeat(100),"raw":{"exchange_id":9}}]),
            160,
        )
        .unwrap();
        assert!(raw[0]["response_transcript_base64"].is_null());
        assert_eq!(
            raw[0]["response_transcript_omitted_reason"],
            "analysis_budget"
        );
    }

    #[test]
    fn observation_policy_is_bounded_before_execution() {
        assert!(validate_observation_policy(&PluginObservationPolicy {
            body_bytes: 0,
            body_contains: vec!["marker".into()]
        })
        .is_ok());
        assert!(validate_observation_policy(&PluginObservationPolicy {
            body_bytes: MAX_RESPONSE_BODY_FOR_PLUGIN + 1,
            body_contains: vec![]
        })
        .is_err());
        assert!(validate_observation_policy(&PluginObservationPolicy {
            body_bytes: 0,
            body_contains: vec!["x".repeat(201)]
        })
        .is_err());
    }

    #[test]
    fn aggregate_budget_keeps_evidence_when_observation_metadata_is_oversized() {
        let mut observations = Vec::new();
        let mut bytes = MAX_ANALYSIS_OBSERVATION_BYTES - 1024;
        push_bounded_analysis_observation(
            &mut observations,
            json!({"id":"oversized","exchange_id":77,"metadata":"x".repeat(300_000)}),
            &mut bytes,
        )
        .unwrap();
        assert_eq!(observations[0]["id"], "oversized");
        assert_eq!(observations[0]["evidence"][0]["exchange_id"], 77);
        assert_eq!(observations[0]["error"]["code"], "body_too_large");
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
            None,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Timeout);
        assert!(error.to_string().contains("10 ms"));
    }

    #[test]
    fn required_base_exchange_is_rejected_before_plugin_planning() {
        let manifest = PluginManifest {
            schema_version: PLUGIN_API_VERSION,
            id: "saved-request-test".into(),
            name: "Saved Request Test".into(),
            version: "1.0.0".into(),
            description: "test".into(),
            enabled: true,
            entrypoint: "index.js".into(),
            entrypoint_sha256: "0".repeat(64),
            resources: HashMap::new(),
            capabilities: vec![],
            actions: vec![],
            limits: PluginLimits::default(),
        };
        let action = PluginAction {
            name: "scan".into(),
            description: "scan".into(),
            input_schema: object_schema(),
            required_capabilities: vec![],
            requires_base_exchange: true,
        };
        let error = validate_action_base_exchange(&manifest, &action, None).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert_eq!(error.to_string(), "Saved Request Test requires base_exchange_id. Capture a saved request, then preview the scan action again.");
        assert!(validate_action_base_exchange(&manifest, &action, Some(ExchangeId(42))).is_ok());
    }

    #[tokio::test]
    async fn preview_and_run_reject_required_base_before_javascript() {
        let directory = tempfile::tempdir().unwrap();
        let config = crate::config::Config::load(Some(directory.path().join("data"))).unwrap();
        let db = Arc::new(crate::storage::Db::open(&config).await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "saved request requirement".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let plugin_directory = directory.path().join("plugins");
        let package = plugin_directory.join("saved-request-test");
        crate::config::create_private_dir(&package).unwrap();
        let script = r#"globalThis.HuntProxyPlugin = {
          plan() { throw new Error('javascript planner must not run'); },
          analyze() { return {}; }
        };"#;
        std::fs::write(package.join("index.js"), script).unwrap();
        let digest = hex::encode(Sha256::digest(script.as_bytes()));
        std::fs::write(
            package.join("plugin.json"),
            serde_json::to_vec(&json!({
                "schema_version":1,"id":"saved-request-test","name":"Saved Request Test","version":"1.0.0","description":"test","enabled":true,
                "entrypoint":"index.js","entrypoint_sha256":digest,"capabilities":[],
                "limits":{"timeout_ms":3000,"js_stage_timeout_ms":250,"max_operations":1,"max_concurrency":1,"memory_mb":8},
                "actions":[{"name":"scan","description":"scan","requires_base_exchange":true,"input_schema":{"type":"object"}}]
            }))
            .unwrap(),
        )
        .unwrap();
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: Arc::new(UnusedTransport),
            placeholder_key: crate::reply::PlaceholderKey::from_bytes(vec![9; 32]),
            upstream_proxies: Default::default(),
        });
        let service = PluginService::load(plugin_directory, db, reply).unwrap();

        for error in [
            service
                .preview(project.id, "saved-request-test", "scan", None, json!({}))
                .await
                .unwrap_err(),
            service
                .run(project.id, "saved-request-test", "scan", None, json!({}))
                .await
                .unwrap_err(),
        ] {
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
            assert_eq!(error.to_string(), "Saved Request Test requires base_exchange_id. Capture a saved request, then preview the scan action again.");
            assert!(!error
                .to_string()
                .contains("javascript planner must not run"));
            assert!(!error.to_string().contains("eval_script"));
        }
    }

    #[test]
    fn javascript_stage_cancellation_interrupts_promptly() {
        let script = r#"globalThis.HuntProxyPlugin = {
          plan() { while (true) {} }, analyze() { return {}; }
        };"#;
        let cancel = CancellationToken::new();
        cancel.cancel();
        let started = Instant::now();
        let error = run_js_sync(
            script,
            "plan",
            "{}",
            "null",
            "{}",
            4 * 1024 * 1024,
            Duration::from_secs(60),
            Some(cancel),
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn effective_limits_expose_requested_fallback_and_host_ceiling() {
        let mut manifest: PluginManifest = serde_json::from_value(json!({
            "schema_version":1,"id":"test","name":"Test","version":"1.0.0","description":"test","enabled":true,
            "entrypoint":"index.js","entrypoint_sha256":"0".repeat(64),"actions":[{"name":"run","description":"run"}],
            "limits":{"timeout_ms":900000,"max_operations":700,"max_concurrency":1,"memory_mb":32}
        })).unwrap();
        assert_eq!(
            effective_plugin_limits(&manifest).js_stage_timeout_ms,
            2_000
        );
        manifest.limits.js_stage_timeout_ms = Some(60_000);
        let limits = effective_plugin_limits(&manifest);
        assert_eq!(limits.js_stage_timeout_ms, 60_000);
        assert_eq!(limits.host_max_js_stage_timeout_ms, 120_000);
    }

    #[test]
    fn plan_preview_metadata_is_strictly_bounded() {
        let mut preview = PluginPlanPreview {
            stage: Some("screen".into()),
            scope: Some("current_stage".into()),
            supported_modes: vec!["light".into(), "full".into()],
            selected_mode: Some("full".into()),
            recommended_mode: Some("full".into()),
            recommendation: Some("Complete coverage".into()),
            ..Default::default()
        };
        validate_plan_preview(Some(&preview)).unwrap();
        preview.recommendation = Some("x".repeat(513));
        assert_eq!(
            validate_plan_preview(Some(&preview)).unwrap_err().code(),
            ErrorCode::BodyTooLarge
        );
        preview.recommendation = None;
        preview.scope = Some("everything".into());
        assert_eq!(
            validate_plan_preview(Some(&preview)).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn analysis_checkpoint_reservations_enforce_and_release_global_budget() {
        let total = Arc::new(AtomicUsize::new(0));
        let (_, reservation) = reserve_checkpoint_bytes(&total, vec![0; 1024]).unwrap();
        assert_eq!(total.load(Ordering::Relaxed), 1024);
        total.store(MAX_TOTAL_ANALYSIS_CHECKPOINT_BYTES, Ordering::Relaxed);
        assert!(reserve_checkpoint_bytes(&total, vec![0]).is_none());
        total.store(1024, Ordering::Relaxed);
        drop(reservation);
        assert_eq!(total.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn timed_out_analysis_resumes_without_replaying_operations() {
        let directory = tempfile::tempdir().unwrap();
        let config = crate::config::Config::load(Some(directory.path().join("data"))).unwrap();
        let db = Arc::new(crate::storage::Db::open(&config).await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "analysis retry".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let plugin_directory = directory.path().join("plugins");
        let package = plugin_directory.join("retry-test");
        crate::config::create_private_dir(&package).unwrap();
        let script = r#"globalThis.HuntProxyPlugin = {
          plan() { return {operations: [], result: {planned: true}}; },
          analyze() { const end = Date.now() + 400; while (Date.now() < end) {} return {findings: [], result: {resumed: true}}; }
        };"#;
        std::fs::write(package.join("index.js"), script).unwrap();
        let digest = hex::encode(Sha256::digest(script.as_bytes()));
        std::fs::write(
            package.join("plugin.json"),
            serde_json::to_vec(&json!({
                "schema_version":1,"id":"retry-test","name":"Retry Test","version":"1.0.0","description":"test","enabled":true,
                "entrypoint":"index.js","entrypoint_sha256":digest,"capabilities":[],
                "limits":{"timeout_ms":3000,"js_stage_timeout_ms":250,"max_operations":1,"max_concurrency":1,"memory_mb":8},
                "actions":[{"name":"run","description":"run","input_schema":{"type":"object"}}]
            }))
            .unwrap(),
        )
        .unwrap();
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: Arc::new(UnusedTransport),
            placeholder_key: crate::reply::PlaceholderKey::from_bytes(vec![9; 32]),
            upstream_proxies: Default::default(),
        });
        let service = PluginService::load(plugin_directory, db, reply).unwrap();
        let initial = service
            .run(project.id, "retry-test", "run", None, json!({}))
            .await
            .unwrap();
        let failed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status = service.status(initial.id).unwrap();
                if status.state == PluginJobState::Failed {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(failed.completed_operations, 0);
        assert!(failed.analysis_resume_available);
        assert_eq!(failed.analysis_checkpoint_status, "retained");
        service
            .resume_analysis(initial.id, Some(1000))
            .await
            .unwrap();
        let completed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status = service.status(initial.id).unwrap();
                if status.state == PluginJobState::Completed {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            completed.completed_operations, 0,
            "analysis retry never replays target operations"
        );
        assert!(!completed.analysis_resume_available);
        assert_eq!(completed.analysis_checkpoint_status, "consumed");
        let result = service
            .results(initial.id, PluginResultView::Full, 0, 25)
            .unwrap();
        assert_eq!(result["result"]["analysis"]["result"]["resumed"], true);

        let cancelled_job = service
            .run(project.id, "retry-test", "run", None, json!({}))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if service
                    .status(cancelled_job.id)
                    .unwrap()
                    .analysis_resume_available
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        service
            .resume_analysis(cancelled_job.id, Some(1000))
            .await
            .unwrap();
        service.cancel(cancelled_job.id).unwrap();
        let cancelled = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status = service.status(cancelled_job.id).unwrap();
                if status.state == PluginJobState::Cancelled {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(cancelled.phase, PluginJobPhase::Finished);
        assert!(!cancelled.analysis_resume_available);
        assert_eq!(cancelled.analysis_checkpoint_status, "consumed");
    }

    #[test]
    fn javascript_stage_preserves_bounded_plugin_error_detail() {
        let script = r#"globalThis.HuntProxyPlugin = {
          plan() { throw new Error('confirm_intrusive is required'); },
          analyze() { return {}; }
        };"#;
        let error = run_js_sync(
            script,
            "plan",
            "{}",
            "null",
            "{}",
            4 * 1024 * 1024,
            Duration::from_secs(2),
            None,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProtocolError);
        assert!(error.to_string().contains("confirm_intrusive is required"));
        assert!(!error.to_string().contains("Exception generated by QuickJS"));
    }

    #[test]
    fn ip_rotate_credentials_are_bounded_and_host_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("aws-credentials.toml");
        std::fs::write(
            &path,
            "access_key_id = \"test-access\"\nsecret_access_key = \"test-secret\"\nsession_token = \"test-session\"\n",
        )
        .unwrap();
        let loaded = load_aws_credentials(&path).unwrap();
        assert_eq!(loaded.access_key_id, "test-access");
        assert_eq!(loaded.secret_access_key, "test-secret");
        assert_eq!(loaded.session_token.as_deref(), Some("test-session"));

        std::fs::write(&path, "access_key_id = \"\"\nsecret_access_key = \"\"\n").unwrap();
        let error = match load_aws_credentials(&path) {
            Ok(_) => panic!("empty credentials must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ErrorCode::ConfigInvalid);
        assert!(!error.to_string().contains("test-secret"));
    }

    #[test]
    fn ip_rotate_host_operation_is_strict_and_bounded() {
        let operation: PluginOperation = serde_json::from_value(json!({
            "type": "aws_api_gateway",
            "action": "enable",
            "id": "ip-rotation-enable",
            "target_url": "https://api.example.test",
            "regions": ["us-east-1", "eu-west-1"],
            "stage_name": "huntproxy"
        }))
        .unwrap();
        assert_eq!(operation.id(), "ip-rotation-enable");
        assert_eq!(operation_request_count(&operation), 2);
        let status: PluginOperation = serde_json::from_value(json!({
            "type": "aws_api_gateway",
            "action": "status",
            "id": "ip-rotation-status"
        }))
        .unwrap();
        assert_eq!(status.id(), "ip-rotation-status");
        assert!(serde_json::from_value::<PluginOperation>(json!({
            "type": "aws_api_gateway",
            "action": "enable",
            "id": "ip-rotation-enable",
            "target_url": "https://api.example.test",
            "regions": ["us-east-1"],
            "stage_name": "huntproxy",
            "credentials": "must-not-be-accepted"
        }))
        .is_err());
        assert!(validate_gateway_target("https://api.example.test").is_ok());
        assert!(validate_gateway_target("https://api.example.test/base").is_err());
        assert!(validate_gateway_target("https://user:pass@example.test").is_err());
        assert!(validate_gateway_endpoint(
            "https://abcde12345.execute-api.us-east-1.amazonaws.com/huntproxy"
        )
        .is_ok());
        assert!(validate_gateway_endpoint("https://example.test/huntproxy").is_err());
        assert!(validate_regions(&["us-east-1".into(), "eu-west-1".into()]).is_ok());
        assert!(validate_regions(&["us-east-1".into(), "us-east-1".into()]).is_err());
    }

    #[tokio::test]
    async fn ip_rotate_helper_is_bounded_and_redacts_credentials() {
        let credentials = AwsCredentialFile {
            access_key_id: "test-access".into(),
            secret_access_key: "test-secret".into(),
            session_token: Some("test-session".into()),
        };
        let result = run_aws_control_helper(
            "import json,sys; value=json.load(sys.stdin); print(json.dumps({'region': value['region']}))",
            json!({"region":"us-east-1"}),
            &credentials,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(result["region"], "us-east-1");

        let credentials = AwsCredentialFile {
            access_key_id: "test-access".into(),
            secret_access_key: "test-secret".into(),
            session_token: None,
        };
        let error = run_aws_control_helper(
            "import os,sys; print(os.environ['AWS_SECRET_ACCESS_KEY'], file=sys.stderr); raise SystemExit(1)",
            json!({}),
            &credentials,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(!error.to_string().contains("test-secret"));
        assert!(error.to_string().contains("[redacted]"));
    }

    #[tokio::test]
    async fn ip_rotate_disable_stops_routing_before_cleanup_configuration_is_loaded() {
        let directory = tempfile::tempdir().unwrap();
        let config = crate::config::Config::load(Some(directory.path().join("data"))).unwrap();
        let db = Arc::new(crate::storage::Db::open(&config).await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "rotation disable".into(),
                target_url: "https://api.example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        db.activate_ip_rotation(
            project.id,
            "https://api.example.test".into(),
            "huntproxy".into(),
            vec![crate::storage::IpRotationGateway {
                region: "us-east-1".into(),
                rest_api_id: "abcde12345".into(),
                endpoint: "https://abcde12345.execute-api.us-east-1.amazonaws.com/huntproxy".into(),
            }],
        )
        .await
        .unwrap();
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: Arc::new(UnusedTransport),
            placeholder_key: crate::reply::PlaceholderKey::from_bytes(vec![7; 32]),
            upstream_proxies: Default::default(),
        });
        let service =
            PluginService::load(directory.path().join("plugins"), db.clone(), reply).unwrap();
        let error = service
            .execute_aws_api_gateway(
                project.id,
                "ip-rotate",
                "IpRotate",
                PluginAwsApiGateway::Disable {
                    id: "disable".into(),
                    target_url: "https://api.example.test".into(),
                },
                &project.scope,
                Some("api.example.test"),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("was disabled"));
        assert!(db
            .next_ip_rotation_route(project.id, "https://api.example.test/path")
            .await
            .unwrap()
            .is_none());
        let profiles = db.list_ip_rotation_profiles(project.id).await.unwrap();
        assert_eq!(profiles.len(), 1);
        assert!(!profiles[0].enabled);
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

        let later: PluginOperation = serde_json::from_value(json!({
            "type": "race_group",
            "id": "race-1",
            "technique": "parallel",
            "attempt": 1,
            "requests": [{"id":"copy-0","url":"https://example.test/"}]
        }))
        .unwrap();
        let skipped = skipped_operation_observation(&later);
        assert_eq!(skipped["id"], "race-1");
        assert_eq!(skipped["skipped"]["reason"], "previous operation failed");
        assert_eq!(skipped.as_object().unwrap().len(), 2);
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
    fn browser_csrf_operation_is_bounded_and_uses_explicit_identity() {
        let operation: PluginOperation = serde_json::from_value(json!({
            "type": "browser_csrf",
            "id": "csrf-browser-1",
            "base_exchange_id": 42,
            "mode": "cross_site_form_post",
            "body_params": [{"name":"csrf","value":null}],
            "identity": {"profile":"victim"}
        }))
        .unwrap();
        assert_eq!(operation.id(), "csrf-browser-1");
        assert_eq!(operation_type_name(&operation), "browser_csrf");
        assert_eq!(operation_required_capability(&operation), "browser.csrf");
        assert_eq!(operation_request_count(&operation), 1);
        assert_eq!(operation_identity_selectors(&operation).count(), 1);
    }

    #[test]
    fn browser_csrf_operation_rejects_unknown_fields() {
        assert!(serde_json::from_value::<PluginOperation>(json!({
            "type": "browser_csrf",
            "id": "unsafe",
            "base_exchange_id": 42,
            "mode": "top_level_get",
            "script": "alert(1)"
        }))
        .is_err());
    }

    #[test]
    fn browser_csrf_get_materialization_preserves_and_mutates_query() {
        let mut url =
            url::Url::parse("https://example.test/change?email=old%40test&keep=1").unwrap();
        apply_url_param_patches(
            &mut url,
            &[
                PluginParamPatch {
                    name: "email".into(),
                    value: Some("new@test".into()),
                },
                PluginParamPatch {
                    name: "keep".into(),
                    value: None,
                },
            ],
        )
        .unwrap();
        assert_eq!(url.as_str(), "https://example.test/change?email=new%40test");
    }

    #[test]
    fn browser_csrf_cookie_delivery_requires_matching_identity_value() {
        let expected =
            crate::cookies::parse_cookie_header("session=secret; preference=dark").unwrap();
        assert!(matched_cookie_names(&expected, "unrelated=1")
            .unwrap()
            .is_empty());
        assert!(matched_cookie_names(&expected, "session=wrong")
            .unwrap()
            .is_empty());
        assert_eq!(
            matched_cookie_names(&expected, "session=secret; other=1")
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["session"]
        );
    }

    #[tokio::test]
    async fn raw_http1_group_barriers_two_connections_and_persists_provenance() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let arrived = Arc::new(AtomicUsize::new(0));
        let server_arrived = arrived.clone();
        let server = tokio::spawn(async move {
            let mut handlers = Vec::new();
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                server_arrived.fetch_add(1, Ordering::SeqCst);
                let observed = server_arrived.clone();
                handlers.push(tokio::spawn(async move {
                    let mut request = vec![0; 1024];
                    let size = socket.read(&mut request).await.unwrap();
                    let arrivals_when_request_arrived = observed.load(Ordering::SeqCst);
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await
                        .unwrap();
                    (request[..size].to_vec(), arrivals_when_request_arrived)
                }));
            }
            let mut received = Vec::new();
            for handler in handlers {
                received.push(handler.await.unwrap());
            }
            received
        });

        // A file-backed database is required here because the group deliberately
        // uses multiple pool connections at once; independent SQLite `:memory:`
        // connections do not share a schema.
        let directory = tempfile::tempdir().unwrap();
        let config = crate::config::Config::load(Some(directory.path().join("data"))).unwrap();
        let db = Arc::new(crate::storage::Db::open(&config).await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "raw group".into(),
                target_url: format!("http://{address}"),
                advanced: None,
            })
            .await
            .unwrap();
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: Arc::new(UnusedTransport),
            placeholder_key: crate::reply::PlaceholderKey::from_bytes(vec![7; 32]),
            upstream_proxies: Default::default(),
        });
        let plugin_directory = directory.path().join("plugins-under-test");
        let service = PluginService::load(plugin_directory, db.clone(), reply).unwrap();
        let operation: PluginOperation = serde_json::from_value(json!({
            "type": "raw_http1_group",
            "id": "pair",
            "target_url": format!("http://{address}/"),
            "members": [{
                "id": "first",
                "request_utf8": format!("GET /first HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
            }, {
                "id": "second",
                "request_utf8": format!("GET /second HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
            }]
        }))
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            service.execute_operation(
                project.id,
                "request-smuggler",
                "Request Smuggler",
                operation,
                &project.scope,
                Some("127.0.0.1"),
                &HashMap::new(),
                &CancellationToken::new(),
            ),
        )
        .await
        .expect("raw HTTP/1 group timed out")
        .unwrap();
        assert!(
            result["members"]
                .as_array()
                .unwrap()
                .iter()
                .all(|member| member.get("error").is_none()),
            "raw group member failed: {result}"
        );

        let received = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("local raw group server timed out")
            .unwrap();
        assert_eq!(received.len(), 2);
        assert!(received
            .iter()
            .all(|(_, arrivals_when_request_arrived)| *arrivals_when_request_arrived == 2));
        assert!(received
            .iter()
            .any(|(request, _)| request.starts_with(b"GET /first ")));
        assert!(received
            .iter()
            .any(|(request, _)| request.starts_with(b"GET /second ")));
        assert_eq!(result["dispatch"], "parallel_barrier");
        assert_eq!(result["members"][0]["id"], "first");
        assert_eq!(result["members"][1]["id"], "second");

        for (index, member) in ["first", "second"].iter().enumerate() {
            let exchange_id = ExchangeId(
                result["members"][index]["raw"]["exchange_id"]
                    .as_i64()
                    .unwrap(),
            );
            let annotation = db
                .get_annotation(project.id, exchange_id)
                .await
                .unwrap()
                .unwrap();
            assert!(annotation.labels.iter().any(|label| label == "plugin"));
            assert!(annotation
                .labels
                .iter()
                .any(|label| label == "plugin:request-smuggler"));
            assert!(annotation
                .labels
                .iter()
                .any(|label| label == &format!("plugin-op:pair_{member}")));
        }
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
    fn race_setup_extracts_are_sequential_bounded_and_private() {
        let plan_value = json!({
            "execution": "sequential",
            "stop_on_error": true,
            "operations": [{
                "id": "setup-0",
                "type": "race_group",
                "technique": "sequential_control",
                "attempt": 0,
                "requests": [{
                    "id": "setup-shape-0",
                    "url": "https://example.test/setup",
                    "extract": [{"from":"json","name":"csrf.0","pointer":"/csrf","encoding":"url"}]
                }]
            }, {
                "id": "race-0",
                "type": "race_group",
                "technique": "last_byte_sync",
                "attempt": 0,
                "requests": [{
                    "id": "race-shape-0-copy-0",
                    "url": "https://example.test/submit?csrf={{extract:csrf.0}}",
                    "headers": [{"name":"X-CSRF","value":"{{extract:csrf.0}}"}],
                    "body_text": "csrf={{extract:csrf.0}}"
                }]
            }, {
                "id": "validate-0-0",
                "type": "race_group",
                "technique": "sequential_control",
                "attempt": 0,
                "requests": [{
                    "id": "validation-shape-0",
                    "url": "https://example.test/message/one",
                    "extract": [{"from":"body_regex","name":"token.0","pattern":"token=([^&]+)","group":1}]
                }]
            }, {
                "id": "validate-0-1",
                "type": "race_group",
                "technique": "sequential_control",
                "attempt": 0,
                "requests": [{
                    "id": "validation-shape-1",
                    "url": "https://example.test/message/two",
                    "success": {"body_contains":"{{extract:token.0}}"}
                }]
            }]
        });
        let plan: PluginPlan = serde_json::from_value(plan_value).unwrap();
        validate_race_data_flow(&plan).unwrap();
        let extraction_plan = race_extraction_plan(&plan.operations[0]);
        let mut observation = json!({
            "id": "setup-0",
            "responses": [{
                "id": "setup-shape-0",
                "_extract": {
                    "response_headers": [],
                    "response_body_base64": base64::engine::general_purpose::STANDARD.encode(br#"{"csrf":"secret+/token"}"#)
                }
            }]
        });
        let mut values = HashMap::new();
        let mut total = 0;
        apply_race_extractions(&mut observation, &extraction_plan, &mut values, &mut total)
            .unwrap();
        assert_eq!(observation["extracted"], json!(["csrf.0"]));
        assert!(!observation.to_string().contains("secret"));
        assert!(!observation.to_string().contains("_extract"));
        let mut race = plan.operations[1].clone();
        substitute_race_operation(&mut race, &values).unwrap();
        let PluginOperation::RaceGroup(group) = race else {
            panic!("expected race group")
        };
        assert!(group.requests[0]
            .url
            .as_deref()
            .unwrap()
            .ends_with("csrf=secret%2B%2Ftoken"));
        assert_eq!(group.requests[0].headers[0].value, b"secret%2B%2Ftoken");
        assert_eq!(
            group.requests[0].body_text.as_deref(),
            Some("csrf=secret%2B%2Ftoken")
        );
        let validation_extraction = race_extraction_plan(&plan.operations[2]);
        let mut validation_observation = json!({
            "responses": [{
                "id": "validation-shape-0",
                "_extract": {
                    "response_headers": [],
                    "response_body_base64": base64::engine::general_purpose::STANDARD.encode(b"token=private-match&done=1")
                }
            }]
        });
        apply_race_extractions(
            &mut validation_observation,
            &validation_extraction,
            &mut values,
            &mut total,
        )
        .unwrap();
        let mut validation = plan.operations[3].clone();
        substitute_race_operation(&mut validation, &values).unwrap();
        let PluginOperation::RaceGroup(validation) = validation else {
            panic!("expected validation group")
        };
        assert_eq!(
            validation.requests[0]
                .success
                .as_ref()
                .unwrap()
                .body_contains
                .as_deref(),
            Some("private-match")
        );
        let mut transport_error = json!({
            "error": {"code":"protocol_error","message":"request https://example.test/submit?csrf=secret%2B%2Ftoken failed"},
            "success": {"checks":[{"type":"body_contains","expected":"private-match","matched":true}]}
        });
        let secrets = values.values().cloned().collect::<Vec<_>>();
        redact_value(&mut transport_error, &secrets, None);
        assert!(!transport_error.to_string().contains("secret%2B%2Ftoken"));
        assert!(!transport_error.to_string().contains("private-match"));
        assert_eq!(transport_error["error"]["message"], "<redacted>");
        assert_eq!(
            transport_error["success"]["checks"][0]["expected"],
            "<redacted>"
        );
    }

    #[test]
    fn race_extract_flow_rejects_unsafe_ordering_overwrite_and_missing_values() {
        let operation = json!({
            "id": "setup",
            "type": "race_group",
            "technique": "sequential_control",
            "attempt": 0,
            "requests": [{
                "id": "one",
                "url": "https://example.test/",
                "extract": [{"from":"body_regex","name":"token","pattern":"token=(\\w+)","group":1}]
            }]
        });
        for (execution, stop_on_error, expected) in [
            ("parallel", true, "execution=sequential"),
            ("sequential", false, "stop_on_error=true"),
        ] {
            let plan: PluginPlan = serde_json::from_value(json!({
                "execution": execution,
                "stop_on_error": stop_on_error,
                "operations": [operation.clone()]
            }))
            .unwrap();
            assert!(validate_race_data_flow(&plan)
                .unwrap_err()
                .to_string()
                .contains(expected));
        }
        let duplicate: PluginPlan = serde_json::from_value(json!({
            "execution": "sequential",
            "stop_on_error": true,
            "operations": [operation.clone(), operation]
        }))
        .unwrap();
        assert!(validate_race_data_flow(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate race extract name"));

        let mut missing = json!({
            "responses": [{"id":"one","_extract":{"response_headers":[]}}]
        });
        let extraction = race_extraction_plan(&duplicate.operations[0]);
        let error = apply_race_extractions(&mut missing, &extraction, &mut HashMap::new(), &mut 0)
            .unwrap_err();
        assert!(error.to_string().contains("response has no body"));
        assert!(!missing.to_string().contains("_extract"));

        let operations = (0..=MAX_RACE_EXTRACTS_PER_PLAN)
            .map(|index| json!({
                "id": format!("setup-{index}"),
                "type": "race_group",
                "technique": "sequential_control",
                "attempt": index,
                "requests": [{
                    "id": format!("request-{index}"),
                    "url": "https://example.test/",
                    "extract": [{"from":"header","name":format!("token.{index}"),"header":"X-Token"}]
                }]
            }))
            .collect::<Vec<_>>();
        let oversized: PluginPlan = serde_json::from_value(json!({
            "execution": "sequential",
            "stop_on_error": true,
            "operations": operations,
        }))
        .unwrap();
        assert_eq!(
            validate_race_data_flow(&oversized).unwrap_err().code(),
            ErrorCode::CombinationLimit
        );

        let mut regex_operation: PluginOperation = serde_json::from_value(json!({
            "id": "validate",
            "type": "race_group",
            "technique": "sequential_control",
            "attempt": 0,
            "requests": [{
                "id": "check",
                "url": "https://example.test/",
                "success": {"body_regex":"^{{extract:token}}$"}
            }]
        }))
        .unwrap();
        let mut values = HashMap::new();
        values.insert("token".into(), "private".into());
        assert!(substitute_race_operation(&mut regex_operation, &values)
            .unwrap_err()
            .to_string()
            .contains("not supported in regex predicates"));
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
    fn plugin_scope_uses_selected_base_host_as_implicit_boundary() {
        let context = json!({
            "base_exchange": {"url":"https://lab.web-security-academy.net/change"}
        });
        let host = implicit_plugin_target_host(
            "https://portswigger.net/web-security/all-labs",
            true,
            &context,
        );
        let scope = ScopePolicy::default();
        assert_eq!(host.as_deref(), Some("lab.web-security-academy.net"));
        assert!(enforce_plugin_scope(
            "https://lab.web-security-academy.net/change",
            &scope,
            host.as_deref(),
        )
        .is_ok());
        assert_eq!(
            enforce_plugin_scope(
                "https://portswigger.net/web-security/all-labs",
                &scope,
                host.as_deref(),
            )
            .unwrap_err()
            .code(),
            ErrorCode::ScopeDenied
        );
        assert_eq!(
            enforce_plugin_scope("https://unrelated.test/", &scope, host.as_deref())
                .unwrap_err()
                .code(),
            ErrorCode::ScopeDenied
        );
        assert_eq!(
            implicit_plugin_target_host(
                "https://portswigger.net/web-security/all-labs",
                false,
                &Value::Null,
            )
            .as_deref(),
            Some("portswigger.net")
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
    fn execution_evidence_collects_nested_exchange_ids_once() {
        let ids = collect_exchange_ids(&json!([
            {"exchange_id": 3},
            {"steps": [{"exchange_id": 1}, {"members": [{"exchange_id": 3}]}]},
            {"error": {"code": "protocol_error"}}
        ]));
        assert_eq!(ids, vec![ExchangeId(1), ExchangeId(3)]);
    }

    #[test]
    fn plugin_identity_selectors_are_exclusive_and_url_scoped() {
        let selector = PluginIdentitySelector {
            profile: Some("sco".into()),
            cookie_file: None,
        };
        assert_eq!(identity_selector_key(&selector).unwrap(), "profile:sco");
        assert!(identity_selector_key(&PluginIdentitySelector {
            profile: Some("a".into()),
            cookie_file: Some("b".into())
        })
        .is_err());
        let profile = crate::cookies::validate_cookie_profile("https://example.test/admin", r#"[{"name":"sid","value":"secret","domain":"example.test","path":"/admin","secure":true}]"#.into()).unwrap();
        let mut resolved = HashMap::new();
        resolved.insert(
            "profile:sco".into(),
            ResolvedPluginIdentity::Profile(crate::cookies::StoredCookieProfile {
                project_id: ProjectId(1),
                host: profile.host,
                target_url: profile.target_url,
                cookie_header: profile.cookie_header,
                names: profile.names,
                managed_cookies: profile.managed_cookies,
                created_at: String::new(),
                updated_at: String::new(),
            }),
        );
        assert_eq!(
            resolve_operation_identity_cookie(
                Some(&selector),
                &resolved,
                "https://example.test/admin/users"
            )
            .unwrap(),
            Some("sid=secret".into())
        );
        assert!(resolve_operation_identity_cookie(
            Some(&selector),
            &resolved,
            "https://example.test/public"
        )
        .is_err());
        let input =
            json!({"primary":{"profile":"sco"},"secondary":{"cookie_file":"/private/two.json"}});
        let keys = collect_input_identity_selector_keys(&input).unwrap();
        assert!(keys.contains("profile:sco"));
        assert!(keys.contains("file:/private/two.json"));

        let duplicate_operations: Vec<PluginOperation> = serde_json::from_value(json!([{
            "type":"http_request", "id":"one", "base_exchange_id":42,
            "identity":{"profile":"first"}, "identity_comparison":"auth-analyzer"
        }, {
            "type":"http_request", "id":"two", "base_exchange_id":42,
            "identity":{"profile":"second"}, "identity_comparison":"auth-analyzer"
        }]))
        .unwrap();
        let duplicate = crate::cookies::StoredCookieProfile {
            project_id: ProjectId(1),
            host: "example.test".into(),
            target_url: "https://example.test/".into(),
            cookie_header: "sid=same".into(),
            names: vec!["sid".into()],
            managed_cookies: None,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let mut duplicate_resolved = HashMap::new();
        duplicate_resolved.insert(
            "profile:first".into(),
            ResolvedPluginIdentity::Profile(duplicate.clone()),
        );
        duplicate_resolved.insert(
            "profile:second".into(),
            ResolvedPluginIdentity::Profile(duplicate),
        );
        assert!(
            validate_resolved_identity_comparisons(&duplicate_operations, &duplicate_resolved)
                .is_err()
        );
    }

    #[test]
    fn semantic_plugin_request_delays_are_bounded() {
        assert_eq!(plugin_http_request_delay(0).unwrap(), Duration::ZERO);
        assert_eq!(
            plugin_http_request_delay(MAX_HTTP_REQUEST_DELAY_MS).unwrap(),
            Duration::from_millis(MAX_HTTP_REQUEST_DELAY_MS)
        );
        assert_eq!(
            plugin_http_request_delay(MAX_HTTP_REQUEST_DELAY_MS + 1)
                .unwrap_err()
                .code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn concurrent_plugin_rate_slots_are_evenly_spaced_without_cumulative_waits() {
        let start = tokio::time::Instant::now();
        let spacing = Duration::from_millis(100);
        let mut next = start;

        assert_eq!(
            reserve_plugin_request_slot(&mut next, start, spacing),
            start
        );
        assert_eq!(
            reserve_plugin_request_slot(&mut next, start, spacing),
            start + spacing
        );
        assert_eq!(next, start + spacing * 2);

        let after_idle = start + Duration::from_secs(1);
        assert_eq!(
            reserve_plugin_request_slot(&mut next, after_idle, spacing),
            after_idle
        );
        assert_eq!(next, after_idle + spacing);
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
        let presented =
            plugin_response_body(&headers, compressed, MAX_RESPONSE_BODY_FOR_PLUGIN, &[]);
        assert!(!presented.truncated);
        assert!(presented.search_complete);
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
            MAX_RESPONSE_BODY_FOR_PLUGIN,
            &[],
        );
        assert!(!unsupported.search_complete);
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
    fn raw_plugin_context_preserves_http1_wire_bytes_without_double_wrapping() {
        let exact = b"GET /raw HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let (raw, reconstructed) =
            plugin_raw_request_bytes("HTTP/1.1 raw", "GET", "/raw", &[], exact).unwrap();
        assert_eq!(raw, exact);
        assert!(!reconstructed);
        assert!(plugin_raw_request_bytes("HTTP/2 raw", "GET", "/", &[], exact).is_none());

        let (semantic, reconstructed) = plugin_raw_request_bytes(
            "HTTP/1.1",
            "POST",
            "/submit",
            &[HeaderEntry {
                name: "Content-Type".into(),
                value: b"text/plain".to_vec(),
                ordinal: 0,
            }],
            b"ok",
        )
        .unwrap();
        assert!(reconstructed);
        assert_eq!(
            semantic,
            b"POST /submit HTTP/1.1\r\nContent-Type: text/plain\r\n\r\nok"
        );
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
