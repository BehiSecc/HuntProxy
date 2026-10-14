//! Browser worker supervision, real actions, and private per-project browser state.

use crate::config::{create_private_dir, write_private_file, Config};
use crate::cookies::{CookiePair, StoredCookieProfile};
use crate::domain::*;
use crate::storage::{CreateCaptureSession, Db};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

const WORKER_PROTOCOL_VERSION: u64 = 1;
const WORKER_RPC_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_BROWSER_PROXY: &str = "http://127.0.0.1:17891";
const BROWSER_CDP_PORT: u16 = 9222;
const DEFAULT_BROWSER_PROFILE: &str = "default";
const MAX_PERSISTENT_PROFILE_BYTES: usize = 25 * 1024 * 1024;
const MAX_BROWSER_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_BROWSER_REQUEST_RESPONSE_BYTES: u64 = 65_536;
const MAX_BROWSER_SCREENSHOT_BYTES: u64 = 8 * 1024 * 1024;
const EMBEDDED_WORKER: &str = include_str!("../../browser-worker/index.js");
const EMBEDDED_WORKER_PACKAGE: &str = include_str!("../../browser-worker/package.json");
const EMBEDDED_WORKER_LOCK: &str = include_str!("../../browser-worker/package-lock.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserInstallStatus {
    pub node_available: bool,
    pub worker_available: bool,
    pub chromium_available: bool,
    pub chromium_path: Option<String>,
    pub node_path: Option<String>,
    pub install_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserJavascriptFile {
    pub url: String,
    pub path: String,
    pub host: String,
    pub mime: Option<String>,
    pub status_code: Option<u16>,
    #[serde(default)]
    pub source_page_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserCdpInfo {
    pub port: u16,
    pub endpoint: String,
    pub devtools_url: String,
    pub hosted_devtools_url: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserProfileStatus {
    pub name: String,
    pub active: bool,
    pub session_id: Option<BrowserSessionId>,
    pub has_state: bool,
}

/// Compact resource observations for transition-time reuse. No page or private
/// browser state is included, and foreign CDP ownership is only a busy flag.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserResources {
    pub project_id: ProjectId,
    pub max_concurrent_browsers: u32,
    pub active_persistent: usize,
    pub active_ephemeral: usize,
    pub available_capacity: usize,
    pub cdp_port_in_use: bool,
    pub sessions: Vec<BrowserSessionResource>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserSessionResource {
    pub session_id: BrowserSessionId,
    pub profile: String,
    pub agent_control: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserStatus {
    pub sessions: Vec<BrowserSession>,
    pub resources: BrowserResources,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserCdpStatus {
    pub project_id: ProjectId,
    pub active: bool,
    pub agent_control: bool,
    pub session_id: Option<BrowserSessionId>,
    pub endpoint: Option<String>,
    pub devtools_url: Option<String>,
    pub hosted_devtools_url: Option<String>,
    pub ssh_forward_command: Option<String>,
}

/// Secret-bearing values live only in daemon memory. SQLite stores version/hash/status metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Checkpoint {
    pub url: Option<String>,
    pub title: Option<String>,
    pub cookies: Vec<Value>,
    pub local_storage: BTreeMap<String, BTreeMap<String, String>>,
    pub session_storage: BTreeMap<String, String>,
    pub version: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistentBrowserProfile {
    #[serde(default)]
    cookie_seed: Option<CookieSeed>,
    #[serde(default)]
    version: u64,
    #[serde(default)]
    checkpoint_hash: String,
    #[serde(default)]
    last_url: Option<String>,
    #[serde(default)]
    cookies: Vec<Value>,
    #[serde(default)]
    local_storage: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    session_storage: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CookieSeed {
    name: String,
    hash: String,
    #[serde(default)]
    identities: Vec<Value>,
}

struct CookieLaunchOverride {
    cookies: Vec<Value>,
    clear_cookies: Vec<Value>,
    seed: Option<CookieSeed>,
}

impl CookieLaunchOverride {
    fn from_profile(profile: &StoredCookieProfile) -> DomainResult<Self> {
        Ok(Self {
            cookies: browser_cookies(std::slice::from_ref(profile))?,
            clear_cookies: profile_cookie_identities(profile)?,
            seed: None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrowserAction {
    Navigate {
        url: String,
    },
    Snapshot {
        #[serde(default = "default_snapshot_format")]
        format: String,
        #[serde(default = "default_snapshot_max_bytes")]
        max_bytes: u64,
    },
    Click {
        locator: Locator,
    },
    Fill {
        locator: Locator,
        value: String,
    },
    Select {
        locator: Locator,
        value: String,
    },
    Upload {
        locator: Locator,
        files: Vec<String>,
        #[serde(default)]
        via_chooser: bool,
        #[serde(default = "default_browser_action_timeout")]
        timeout_ms: u64,
    },
    Inspect {
        locator: Option<Locator>,
        #[serde(default = "default_inspection_max_bytes")]
        max_bytes: u64,
    },
    Pages {
        op: String,
        page_id: Option<u64>,
        runtime_generation: Option<u64>,
        url: Option<String>,
    },
    Events {
        #[serde(default)]
        after_sequence: u64,
        runtime_generation: Option<u64>,
        #[serde(default = "default_browser_event_limit")]
        limit: u64,
        #[serde(default)]
        kinds: Vec<String>,
        #[serde(default)]
        wait_ms: u64,
    },
    Scroll {
        locator: Option<Locator>,
        #[serde(default)]
        delta_x: i64,
        #[serde(default)]
        delta_y: i64,
    },
    Screenshot {
        locator: Option<Locator>,
        #[serde(default)]
        full_page: bool,
        #[serde(default = "default_screenshot_max_bytes")]
        max_bytes: u64,
    },
    Request {
        method: String,
        url: String,
        #[serde(default)]
        headers: Vec<BrowserRequestHeader>,
        body_text: Option<String>,
        body_base64: Option<String>,
        #[serde(default = "default_browser_request_timeout")]
        timeout_ms: u64,
        #[serde(default = "default_browser_request_response_bytes")]
        max_response_bytes: u64,
    },
    Press {
        locator: Option<Locator>,
        key: String,
    },
    Wait {
        for_what: String,
        value: String,
    },
    Back,
    Forward,
    Close,
}

fn default_browser_action_timeout() -> u64 {
    10_000
}

fn default_inspection_max_bytes() -> u64 {
    4096
}

fn default_browser_event_limit() -> u64 {
    50
}

fn default_browser_request_timeout() -> u64 {
    15_000
}

fn default_browser_request_response_bytes() -> u64 {
    4096
}

fn default_screenshot_max_bytes() -> u64 {
    4 * 1024 * 1024
}

fn default_snapshot_format() -> String {
    "accessibility".into()
}

fn default_snapshot_max_bytes() -> u64 {
    200_000
}

fn validate_browser_action(action: &BrowserAction) -> DomainResult<()> {
    match action {
        BrowserAction::Upload {
            files,
            via_chooser,
            timeout_ms,
            ..
        } => {
            if files.len() > 16 || (*via_chooser && files.is_empty()) {
                return Err(DomainError::invalid(
                    "upload accepts at most 16 files; chooser uploads require at least one",
                ));
            }
            if !(1..=30_000).contains(timeout_ms) {
                return Err(DomainError::invalid("upload timeout_ms must be 1..30000"));
            }
            if files.iter().any(|file| {
                file.len() > 4096 || file.contains('\0') || !Path::new(file).is_absolute()
            }) {
                return Err(DomainError::invalid(
                    "upload files must be absolute paths of at most 4096 bytes",
                ));
            }
        }
        BrowserAction::Inspect { max_bytes, .. } if !(1..=65_536).contains(max_bytes) => {
            return Err(DomainError::invalid("inspect max_bytes must be 1..65536"));
        }
        BrowserAction::Pages {
            op,
            page_id,
            runtime_generation,
            url,
        } => match op.as_str() {
            "list" if page_id.is_none() && runtime_generation.is_none() && url.is_none() => {}
            "new" if page_id.is_none() && runtime_generation.is_none() => {
                if let Some(url) = url {
                    validate_browser_page_url(url)?;
                }
            }
            "select" | "close"
                if page_id.is_some_and(|value| value > 0)
                    && runtime_generation.is_some_and(|value| value > 0)
                    && url.is_none() => {}
            "list" => {
                return Err(DomainError::invalid(
                    "pages list does not accept page_id, runtime_generation, or url",
                ));
            }
            "new" => {
                return Err(DomainError::invalid(
                    "pages new accepts only an optional url",
                ));
            }
            "select" | "close" => {
                return Err(DomainError::invalid(
                    "pages select/close require page_id and runtime_generation",
                ));
            }
            _ => {
                return Err(DomainError::invalid(
                    "pages op must be list|select|new|close",
                ));
            }
        },
        BrowserAction::Events {
            after_sequence,
            runtime_generation,
            limit,
            kinds,
            wait_ms,
        } => {
            if !(1..=100).contains(limit) {
                return Err(DomainError::invalid("events limit must be 1..100"));
            }
            if *wait_ms > 30_000 {
                return Err(DomainError::invalid("events wait_ms must be 0..30000"));
            }
            if *after_sequence > 0 && runtime_generation.is_none() {
                return Err(DomainError::invalid(
                    "events runtime_generation is required with after_sequence",
                ));
            }
            if runtime_generation.is_some_and(|value| value == 0) {
                return Err(DomainError::invalid(
                    "events runtime_generation must be a positive integer",
                ));
            }
            const KINDS: &[&str] = &[
                "page",
                "popup",
                "navigation",
                "dialog",
                "console",
                "page_error",
                "request",
                "response",
                "request_failed",
                "window_message",
            ];
            if kinds.len() > KINDS.len() || kinds.iter().any(|kind| !KINDS.contains(&kind.as_str()))
            {
                return Err(DomainError::invalid("events contains an unsupported kind"));
            }
        }
        BrowserAction::Scroll {
            locator,
            delta_x,
            delta_y,
        } => {
            if delta_x.unsigned_abs() > 100_000 || delta_y.unsigned_abs() > 100_000 {
                return Err(DomainError::invalid(
                    "scroll deltas must be between -100000 and 100000",
                ));
            }
            if locator.is_none() && *delta_x == 0 && *delta_y == 0 {
                return Err(DomainError::invalid(
                    "scroll requires a locator or a non-zero delta",
                ));
            }
        }
        BrowserAction::Screenshot {
            locator,
            full_page,
            max_bytes,
        } => {
            if !(1..=MAX_BROWSER_SCREENSHOT_BYTES).contains(max_bytes) {
                return Err(DomainError::invalid(
                    "screenshot max_bytes must be 1..8388608",
                ));
            }
            if *full_page && locator.is_some() {
                return Err(DomainError::invalid(
                    "screenshot full_page cannot be combined with a locator",
                ));
            }
        }
        BrowserAction::Request {
            method,
            url,
            headers,
            body_text,
            body_base64,
            timeout_ms,
            max_response_bytes,
        } => {
            let method = method.to_ascii_uppercase();
            if !matches!(
                method.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
            ) {
                return Err(DomainError::invalid(
                    "request method must be GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS",
                ));
            }
            let parsed = url::Url::parse(url)
                .map_err(|error| DomainError::invalid(format!("invalid request URL: {error}")))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(DomainError::invalid("request URL must use HTTP or HTTPS"));
            }
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err(DomainError::invalid(
                    "request URL must not contain credentials",
                ));
            }
            if !(1_000..=30_000).contains(timeout_ms) {
                return Err(DomainError::invalid(
                    "request timeout_ms must be 1000..30000",
                ));
            }
            if !(1..=MAX_BROWSER_REQUEST_RESPONSE_BYTES).contains(max_response_bytes) {
                return Err(DomainError::invalid(
                    "request max_response_bytes must be 1..65536",
                ));
            }
            if body_text.is_some() && body_base64.is_some() {
                return Err(DomainError::invalid(
                    "request accepts only one of body_text or body_base64",
                ));
            }
            let body_len = if let Some(body) = body_text {
                body.len()
            } else if let Some(body) = body_base64 {
                if body.len() > MAX_BROWSER_REQUEST_BODY_BYTES.div_ceil(3) * 4 {
                    return Err(DomainError::new(
                        ErrorCode::BodyTooLarge,
                        "request body exceeds 2 MiB",
                    ));
                }
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .map_err(|_| DomainError::invalid("request body_base64 is invalid base64"))?
                    .len()
            } else {
                0
            };
            if body_len > MAX_BROWSER_REQUEST_BODY_BYTES {
                return Err(DomainError::new(
                    ErrorCode::BodyTooLarge,
                    "request body exceeds 2 MiB",
                ));
            }
            if matches!(method.as_str(), "GET" | "HEAD")
                && (body_text.is_some() || body_base64.is_some())
            {
                return Err(DomainError::invalid(
                    "GET and HEAD browser requests cannot include a body",
                ));
            }
            if headers.len() > 64 {
                return Err(DomainError::invalid("request accepts at most 64 headers"));
            }
            let mut header_bytes = 0usize;
            let mut header_names = HashSet::new();
            for header in headers {
                let name = http::header::HeaderName::from_bytes(header.name.as_bytes())
                    .map_err(|_| DomainError::invalid("request contains an invalid header name"))?;
                http::header::HeaderValue::from_bytes(header.value.as_bytes()).map_err(|_| {
                    DomainError::invalid("request contains an invalid header value")
                })?;
                let name = name.as_str();
                if browser_managed_request_header(name, &header.value) {
                    return Err(DomainError::invalid(format!(
                        "request header {name} is browser-managed"
                    )));
                }
                if !header_names.insert(name.to_string()) {
                    return Err(DomainError::invalid(format!(
                        "request header {name} is duplicated; browser fetch would combine its values"
                    )));
                }
                header_bytes = header_bytes
                    .saturating_add(header.name.len())
                    .saturating_add(header.value.len());
            }
            if header_bytes > 65_536 {
                return Err(DomainError::invalid(
                    "request header names and values exceed 65536 bytes",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn browser_managed_request_header(name: &str, value: &str) -> bool {
    const EXACT: &[&str] = &[
        "accept-charset",
        "accept-encoding",
        "access-control-request-headers",
        "access-control-request-method",
        "connection",
        "content-length",
        "cookie",
        "cookie2",
        "date",
        "dnt",
        "expect",
        "host",
        "keep-alive",
        "origin",
        "permissions-policy",
        "referer",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "user-agent",
        "via",
        "x-huntproxy-browser-origin",
        "x-huntproxy-internal-crawler",
    ];
    if EXACT.contains(&name) || name.starts_with("proxy-") || name.starts_with("sec-") {
        return true;
    }
    matches!(
        name,
        "x-http-method" | "x-http-method-override" | "x-method-override"
    ) && value.split(',').any(|method| {
        matches!(
            method.trim().to_ascii_uppercase().as_str(),
            "CONNECT" | "TRACE" | "TRACK"
        )
    })
}

fn validate_browser_page_url(value: &str) -> DomainResult<()> {
    if value == "about:blank" {
        return Ok(());
    }
    let url = url::Url::parse(value)
        .map_err(|error| DomainError::invalid(format!("invalid page URL: {error}")))?;
    if matches!(url.scheme(), "http" | "https") {
        Ok(())
    } else {
        Err(DomainError::invalid(
            "page URL must be about:blank, HTTP, or HTTPS",
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Locator {
    pub role: Option<String>,
    pub name: Option<String>,
    pub text: Option<String>,
    pub test_id: Option<String>,
    pub css: Option<String>,
    pub exact: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserRequestHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserActionContext {
    pub session_id: BrowserSessionId,
    pub profile: Option<String>,
    pub runtime_generation: u64,
    pub page_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub ok: bool,
    pub untrusted: bool,
    pub message: String,
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserActionContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

/// Result of a bounded, host-owned cross-site navigation template. Secret
/// browser state is intentionally absent; network evidence is persisted by the
/// normal proxy capture path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserCsrfProbeResult {
    pub final_url: String,
    pub navigations: Vec<Value>,
}

#[derive(Debug, Clone)]
struct RuntimeSession {
    project_id: ProjectId,
    capture_session_id: CaptureSessionId,
    persistent: bool,
    profile: Option<String>,
    cdp: Option<BrowserCdpInfo>,
}

#[derive(Debug, Deserialize)]
struct WorkerResponse {
    id: Option<u64>,
    result: Option<Value>,
    error: Option<WorkerRpcError>,
}

#[derive(Debug, Deserialize)]
struct WorkerRpcError {
    code: i64,
    message: String,
}

enum WorkerCallFailure {
    Rpc(DomainError),
    Transport(DomainError),
}

impl WorkerCallFailure {
    fn into_domain(self) -> DomainError {
        match self {
            Self::Rpc(error) | Self::Transport(error) => error,
        }
    }
}

struct WorkerProcess {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    child: Child,
    next_id: u64,
}

impl WorkerProcess {
    async fn spawn(
        node_path: &Path,
        worker_path: &Path,
        playwright_core_path: Option<&Path>,
        chromium_path: Option<&Path>,
    ) -> Result<Self, WorkerCallFailure> {
        let mut command = Command::new(node_path);
        command
            .arg(worker_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(false);
        if let Some(parent) = worker_path.parent() {
            command.current_dir(parent);
        }
        if let Some(path) = playwright_core_path {
            command.env("HUNTPROXY_PLAYWRIGHT_CORE_PATH", path);
            if path.join(".local-browsers").is_dir() {
                command.env("PLAYWRIGHT_BROWSERS_PATH", "0");
            }
        }
        if let Some(path) = chromium_path {
            command.env("HUNTPROXY_CHROME_EXECUTABLE", path);
        }
        #[cfg(unix)]
        {
            // Browser crashes should not leave large core files on a VPS.
            unsafe {
                command.pre_exec(|| {
                    let limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        let mut child = command.spawn().map_err(|error| {
            WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::BrowserDisabled,
                format!("start browser worker: {error}"),
            ))
        })?;
        let stdin = child.stdin.take().ok_or_else(|| {
            WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolError,
                "browser worker stdin unavailable",
            ))
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolError,
                "browser worker stdout unavailable",
            ))
        })?;
        let mut process = Self {
            stdin,
            stdout: BufReader::new(stdout),
            child,
            next_id: 1,
        };
        let hello = process.call("hello", json!({})).await?;
        let protocol = hello.get("protocol").and_then(Value::as_u64);
        if protocol != Some(WORKER_PROTOCOL_VERSION) {
            process.terminate().await;
            return Err(WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolIncompatible,
                format!("browser worker protocol {protocol:?}, expected {WORKER_PROTOCOL_VERSION}"),
            )));
        }
        if !hello
            .get("capabilities")
            .and_then(Value::as_array)
            .is_some_and(|capabilities| {
                capabilities
                    .iter()
                    .any(|value| value == "profile_isolation")
            })
        {
            process.terminate().await;
            return Err(WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolIncompatible,
                "browser worker cannot guarantee profile isolation; update the configured browser worker",
            )));
        }
        Ok(process)
    }

    async fn call(&mut self, method: &str, params: Value) -> Result<Value, WorkerCallFailure> {
        if let Ok(Some(status)) = self.child.try_wait() {
            return Err(WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::Unavailable,
                format!("browser worker exited with {status}"),
            )));
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let mut encoded = serde_json::to_vec(&request).map_err(|error| {
            WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolError,
                format!("encode browser worker request: {error}"),
            ))
        })?;
        encoded.push(b'\n');
        self.stdin.write_all(&encoded).await.map_err(|error| {
            WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::Unavailable,
                format!("write browser worker request: {error}"),
            ))
        })?;
        self.stdin.flush().await.map_err(|error| {
            WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::Unavailable,
                format!("flush browser worker request: {error}"),
            ))
        })?;

        let mut line = String::new();
        let bytes_read = tokio::time::timeout(WORKER_RPC_TIMEOUT, self.stdout.read_line(&mut line))
            .await
            .map_err(|_| {
                WorkerCallFailure::Transport(DomainError::new(
                    ErrorCode::Timeout,
                    format!("browser worker {method} timed out"),
                ))
            })?
            .map_err(|error| {
                WorkerCallFailure::Transport(DomainError::new(
                    ErrorCode::Unavailable,
                    format!("read browser worker response: {error}"),
                ))
            })?;
        if bytes_read == 0 {
            return Err(WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::Unavailable,
                "browser worker closed stdout",
            )));
        }
        let response: WorkerResponse = serde_json::from_str(line.trim()).map_err(|error| {
            WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolError,
                format!("decode browser worker response: {error}"),
            ))
        })?;
        if response.id != Some(id) {
            return Err(WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolError,
                "browser worker response id mismatch",
            )));
        }
        if let Some(error) = response.error {
            let code = match error.code {
                -32602 => ErrorCode::InvalidArgument,
                -32001 => ErrorCode::NotFound,
                -32003 => ErrorCode::ChromiumNotInstalled,
                _ => ErrorCode::Unavailable,
            };
            return Err(WorkerCallFailure::Rpc(DomainError::new(
                code,
                error.message,
            )));
        }
        response.result.ok_or_else(|| {
            WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolError,
                "browser worker response missing result",
            ))
        })
    }

    async fn terminate(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.start_kill();
        }
        match tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => {
                let _ = self.child.kill().await;
            }
        }
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.start_kill();
        }
    }
}

pub struct BrowserService {
    pub db: Arc<Db>,
    pub node_path: Option<PathBuf>,
    pub worker_path: Option<PathBuf>,
    proxy_server: String,
    ca_cert_path: Option<PathBuf>,
    profiles_root: PathBuf,
    playwright_core_path: Option<PathBuf>,
    chromium_path: Option<PathBuf>,
    checkpoints: Mutex<HashMap<i64, Checkpoint>>,
    runtime_sessions: Mutex<HashMap<i64, RuntimeSession>>,
    profile_leases: Mutex<HashSet<(i64, String)>>,
    lifecycle: Mutex<()>,
    profile_io: Mutex<()>,
    session_ops: Mutex<HashMap<i64, Arc<Mutex<()>>>>,
    worker: Mutex<Option<WorkerProcess>>,
}

/// Inspect the installed browser runtime without starting the daemon, launching
/// Chromium, or materializing the embedded worker.
pub fn inspect_browser_installation(config: &Config) -> BrowserInstallStatus {
    if let Some(prepared) = crate::installation::inspect(config) {
        return browser_install_status(
            Some(&prepared.node_path),
            Some(&prepared.worker_path),
            Some(&prepared.playwright_core_path),
            Some(&prepared.chromium_path),
        );
    }
    let node_path = existing_path(config.node_path.clone(), "node");
    let worker_path = inspect_worker_path(config.browser_worker_path.clone(), &config.data_dir);
    let playwright_core_path = worker_path
        .as_deref()
        .and_then(find_playwright_core)
        .or_else(find_playwright_from_environment);
    let chromium_path = chromium_executable(playwright_core_path.as_deref());

    browser_install_status(
        node_path.as_deref(),
        worker_path.as_deref(),
        playwright_core_path.as_deref(),
        chromium_path.as_deref(),
    )
}

fn browser_install_status(
    node_path: Option<&Path>,
    worker_path: Option<&Path>,
    playwright_core_path: Option<&Path>,
    chromium_path: Option<&Path>,
) -> BrowserInstallStatus {
    let node_available = node_path.is_some_and(Path::is_file);
    let worker_script_available = worker_path.is_some_and(Path::is_file);
    let worker_available =
        node_available && worker_script_available && playwright_core_path.is_some_and(Path::is_dir);
    let chromium_available = chromium_path.is_some_and(Path::is_file);

    let install_hint = if !node_available {
        Some("Install Node.js, then run: HuntProxy browser install".into())
    } else if !worker_script_available {
        Some(
            "Browser worker missing; reinstall HuntProxy or set HUNTPROXY_BROWSER_WORKER_PATH"
                .into(),
        )
    } else if !playwright_core_path.is_some_and(Path::is_dir) {
        let directory = worker_path
            .and_then(Path::parent)
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "browser-worker".into());
        Some(format!(
            "playwright-core missing; run `npm install` in {directory}"
        ))
    } else if !chromium_available {
        Some("Install Chromium: HuntProxy browser install".into())
    } else {
        None
    };

    BrowserInstallStatus {
        node_available,
        worker_available,
        chromium_available,
        chromium_path: chromium_path.map(|path| path.display().to_string()),
        node_path: node_path.map(|path| path.display().to_string()),
        install_hint,
    }
}

impl BrowserService {
    pub fn new(db: Arc<Db>, node_path: Option<PathBuf>, worker_path: Option<PathBuf>) -> Self {
        let profiles_root = default_profiles_root(&db);
        let proxy_server = std::env::var("HUNTPROXY_BROWSER_PROXY_SERVER")
            .or_else(|_| std::env::var("BB_BROWSER_PROXY_SERVER"))
            .unwrap_or_else(|_| DEFAULT_BROWSER_PROXY.to_string());
        let ca_cert_path = std::env::var_os("HUNTPROXY_BROWSER_CA_CERT")
            .or_else(|| std::env::var_os("BB_BROWSER_CA_CERT"))
            .map(PathBuf::from);
        Self::new_with_proxy_and_ca(
            db,
            node_path,
            worker_path,
            proxy_server,
            ca_cert_path,
            profiles_root,
        )
    }

    /// Proxy-aware constructor for daemon integration with non-default proxy binds.
    pub fn new_with_proxy(
        db: Arc<Db>,
        node_path: Option<PathBuf>,
        worker_path: Option<PathBuf>,
        proxy_server: String,
    ) -> Self {
        let profiles_root = default_profiles_root(&db);
        let ca_cert_path = std::env::var_os("HUNTPROXY_BROWSER_CA_CERT")
            .or_else(|| std::env::var_os("BB_BROWSER_CA_CERT"))
            .map(PathBuf::from);
        Self::new_with_proxy_and_ca(
            db,
            node_path,
            worker_path,
            proxy_server,
            ca_cert_path,
            profiles_root,
        )
    }

    /// Proxy- and CA-aware constructor for the daemon's managed browser sessions.
    pub fn new_with_proxy_and_ca(
        db: Arc<Db>,
        node_path: Option<PathBuf>,
        worker_path: Option<PathBuf>,
        proxy_server: String,
        ca_cert_path: Option<PathBuf>,
        profiles_root: PathBuf,
    ) -> Self {
        let worker_path = resolve_worker_path(worker_path);
        let playwright_core_path = worker_path
            .as_deref()
            .and_then(find_playwright_core)
            .or_else(find_playwright_from_environment);
        let chromium_path = chromium_executable(playwright_core_path.as_deref());
        Self {
            db,
            node_path: existing_path(node_path, "node"),
            worker_path,
            proxy_server,
            ca_cert_path: ca_cert_path.filter(|path| path.is_file()),
            profiles_root,
            playwright_core_path,
            chromium_path,
            checkpoints: Mutex::new(HashMap::new()),
            runtime_sessions: Mutex::new(HashMap::new()),
            profile_leases: Mutex::new(HashSet::new()),
            lifecycle: Mutex::new(()),
            profile_io: Mutex::new(()),
            session_ops: Mutex::new(HashMap::new()),
            worker: Mutex::new(None),
        }
    }

    /// Apply paths verified by the release installer without process-wide
    /// environment changes or changing an existing browser profile.
    pub(crate) fn with_runtime_paths(
        mut self,
        playwright_core_path: Option<PathBuf>,
        chromium_path: Option<PathBuf>,
    ) -> Self {
        if let Some(path) = playwright_core_path.filter(|path| path.is_dir()) {
            self.playwright_core_path = Some(path);
        }
        if let Some(path) = chromium_path.filter(|path| path.is_file()) {
            self.chromium_path = Some(path);
        }
        self
    }

    pub fn status(&self) -> BrowserInstallStatus {
        browser_install_status(
            self.node_path.as_deref(),
            self.worker_path.as_deref(),
            self.playwright_core_path.as_deref(),
            self.chromium_path.as_deref(),
        )
    }

    pub async fn start(&self, project_id: ProjectId, url: String) -> DomainResult<BrowserSession> {
        self.start_with_profile(project_id, url, DEFAULT_BROWSER_PROFILE)
            .await
    }

    pub async fn start_with_profile(
        &self,
        project_id: ProjectId,
        url: String,
        profile: &str,
    ) -> DomainResult<BrowserSession> {
        self.start_with_profile_and_cookie_profile(project_id, url, profile, None)
            .await
    }

    pub async fn start_with_profile_and_cookie_profile(
        &self,
        project_id: ProjectId,
        url: String,
        profile: &str,
        cookie_profile: Option<&str>,
    ) -> DomainResult<BrowserSession> {
        self.start_with_profile_options(project_id, url, profile, cookie_profile, false)
            .await
    }

    pub async fn start_with_profile_options(
        &self,
        project_id: ProjectId,
        url: String,
        profile: &str,
        cookie_profile: Option<&str>,
        refresh_cookies: bool,
    ) -> DomainResult<BrowserSession> {
        validate_browser_profile_name(profile)?;
        if cookie_profile.is_some_and(|name| name != profile) {
            return Err(DomainError::invalid(
                "cookie_profile must match the requested browser profile",
            ));
        }
        if refresh_cookies && cookie_profile.is_none() {
            return Err(DomainError::invalid(
                "refresh_cookies requires a matching cookie_profile",
            ));
        }
        self.start_with_persistence(
            project_id,
            url,
            true,
            Some(profile.to_string()),
            cookie_profile.map(str::to_string),
            refresh_cookies,
        )
        .await
    }

    pub async fn start_ephemeral(
        &self,
        project_id: ProjectId,
        url: String,
    ) -> DomainResult<BrowserSession> {
        self.start_with_persistence(project_id, url, false, None, None, false)
            .await
    }

    pub async fn start_ephemeral_with_profile(
        &self,
        project_id: ProjectId,
        profile: &StoredCookieProfile,
    ) -> DomainResult<BrowserSession> {
        let cookie_override = CookieLaunchOverride::from_profile(profile)?;
        let _lifecycle = self.lifecycle.lock().await;
        self.start_runtime_with_cookies(
            project_id,
            "about:blank".into(),
            false,
            None,
            Some(cookie_override),
        )
        .await
    }

    async fn start_with_persistence(
        &self,
        project_id: ProjectId,
        url: String,
        persistent: bool,
        profile: Option<String>,
        cookie_profile: Option<String>,
        refresh_cookies: bool,
    ) -> DomainResult<BrowserSession> {
        // Starting and stopping share one worker. Keep lifecycle transitions
        // atomic so a concurrent stop cannot terminate a worker between a new
        // session's launch and its registration, and concurrent starts cannot
        // race the per-project browser limit.
        let _lifecycle = self.lifecycle.lock().await;
        let mut cookie_override = match cookie_profile.as_deref() {
            Some(name) => {
                let stored = self
                    .db
                    .get_named_cookie_profile(project_id, name)
                    .await?
                    .ok_or_else(|| DomainError::not_found("cookie profile"))?;
                let mut cookie_override = CookieLaunchOverride::from_profile(&stored)?;
                let seed = CookieSeed {
                    name: name.to_string(),
                    identities: cookie_override.clear_cookies.clone(),
                    hash: hex::encode(Sha256::digest(
                        serde_json::to_vec(&cookie_override.cookies).map_err(|error| {
                            DomainError::new(ErrorCode::Internal, error.to_string())
                        })?,
                    )),
                };
                let saved_seed = self
                    .load_persistent_profile(project_id, name)
                    .await?
                    .and_then(|state| state.cookie_seed);
                if !refresh_cookies && saved_seed.as_ref() == Some(&seed) {
                    None
                } else {
                    if let Some(previous) = saved_seed {
                        for identity in previous.identities {
                            if !cookie_override.clear_cookies.contains(&identity) {
                                cookie_override.clear_cookies.push(identity);
                            }
                        }
                    }
                    cookie_override.seed = Some(seed);
                    Some(cookie_override)
                }
            }
            None => None,
        };
        if let Some(profile_name) = profile.as_deref().filter(|_| persistent) {
            let active_id = self
                .runtime_sessions
                .lock()
                .await
                .iter()
                .find_map(|(id, runtime)| {
                    (runtime.project_id == project_id
                        && runtime.persistent
                        && runtime.profile.as_deref() == Some(profile_name))
                    .then_some(BrowserSessionId(*id))
                });
            if let Some(session_id) = active_id {
                // Reuse only the exact verified identity, without relaunching or touching its cookies.
                let operation_lock = self.session_operation_lock(session_id).await;
                let _operation_guard = operation_lock.lock().await;
                let mut session = self.verified_session_status(project_id, session_id).await?;
                if let Some(cookie_override) = cookie_override.take() {
                    if self
                        .runtime_sessions
                        .lock()
                        .await
                        .get(&session_id.get())
                        .is_some_and(|runtime| runtime.cdp.is_some())
                    {
                        return Err(DomainError::new(
                            ErrorCode::Unavailable,
                            "return CDP control before refreshing profile cookies",
                        ));
                    }
                    let result = self
                        .call_worker(
                            "session.set_cookies",
                            json!({
                                "session_id": session_id.get(), "cookies": cookie_override.cookies,
                                "clear_cookies": cookie_override.clear_cookies,
                            }),
                        )
                        .await?;
                    self.save_cookie_checkpoint(project_id, session_id, &result)
                        .await?;
                    self.record_cookie_seed(project_id, profile_name, cookie_override.seed)
                        .await?;
                    session = self.verified_session_status(project_id, session_id).await?;
                }
                if url != "about:blank" {
                    if self
                        .runtime_sessions
                        .lock()
                        .await
                        .get(&session_id.get())
                        .is_some_and(|runtime| runtime.cdp.is_some())
                    {
                        return Err(DomainError::new(
                            ErrorCode::Unavailable,
                            "return CDP control before navigating the profile",
                        ));
                    }
                    let result = self.call_worker("session.action", json!({
                        "session_id": session_id.get(), "action": {"type":"navigate", "url":url},
                    })).await?;
                    self.save_cookie_checkpoint(project_id, session_id, &result)
                        .await?;
                    session = self.verified_session_status(project_id, session_id).await?;
                }
                return Ok(session);
            }
        }
        let lease = if persistent {
            let profile = profile.as_deref().ok_or_else(|| {
                DomainError::new(ErrorCode::Internal, "persistent browser profile missing")
            })?;
            validate_browser_profile_name(profile)?;
            Some((project_id.get(), profile.to_string()))
        } else {
            None
        };
        if let Some(lease) = lease.as_ref() {
            let mut leases = self.profile_leases.lock().await;
            if !leases.insert(lease.clone()) {
                drop(leases);
                let active_session_id =
                    self.runtime_sessions
                        .lock()
                        .await
                        .iter()
                        .find_map(|(id, runtime)| {
                            (runtime.project_id == project_id
                                && runtime.persistent
                                && runtime.profile.as_deref() == Some(lease.1.as_str()))
                            .then_some(*id)
                        });
                let detail = active_session_id
                    .map(|id| format!(" as session {id}"))
                    .unwrap_or_default();
                return Err(DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    format!(
                        "browser profile '{}' is already active{detail}; stop it before starting it again",
                        lease.1
                    ),
                ));
            }
        }
        let result = async {
            self.start_runtime_with_cookies(project_id, url, persistent, profile, cookie_override)
                .await
        }
        .await;
        if result.is_err() {
            if let Some(lease) = lease {
                self.profile_leases.lock().await.remove(&lease);
            }
        }
        result
    }

    async fn start_runtime_with_cookies(
        &self,
        project_id: ProjectId,
        mut url: String,
        persistent: bool,
        profile: Option<String>,
        cookie_override: Option<CookieLaunchOverride>,
    ) -> DomainResult<BrowserSession> {
        let status = self.status();
        if !status.worker_available {
            return Err(DomainError::new(
                ErrorCode::BrowserDisabled,
                status
                    .install_hint
                    .unwrap_or_else(|| "Browser runtime not installed".into()),
            ));
        }
        let project = self.db.get_project(project_id).await?;
        let profile_name = profile.as_deref();
        let runtimes = self.runtime_sessions.lock().await;
        let active_for_project = runtimes
            .values()
            .filter(|runtime| runtime.project_id == project_id)
            .count() as u32;
        if active_for_project >= project.limits.max_concurrent_browsers {
            return Err(DomainError::new(
                ErrorCode::ConcurrencyLimited,
                "project browser concurrency limit reached",
            ));
        }
        if persistent {
            let profile_name = profile_name.ok_or_else(|| {
                DomainError::new(ErrorCode::Internal, "persistent browser profile missing")
            })?;
            if let Some(active_session_id) = runtimes.iter().find_map(|(id, runtime)| {
                (runtime.project_id == project_id
                    && runtime.persistent
                    && runtime.profile.as_deref() == Some(profile_name))
                .then_some(*id)
            }) {
                return Err(DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    format!(
                        "browser profile '{profile_name}' is already active as session {active_session_id}; stop it before starting it again"
                    ),
                ));
            }
        }
        drop(runtimes);

        let restored_profile = if let Some(profile_name) = profile_name.filter(|_| persistent) {
            self.load_persistent_profile(project_id, profile_name)
                .await?
        } else {
            None
        };
        if url == "about:blank" {
            if let Some(last_url) = restored_profile
                .as_ref()
                .and_then(|profile| profile.last_url.as_ref())
            {
                url = last_url.clone();
            }
        }

        if !status.chromium_available {
            return Err(DomainError::new(
                ErrorCode::ChromiumNotInstalled,
                "Chromium not installed; run HuntProxy browser install",
            ));
        }

        // Persistent Chromium owns its jar. Only an explicitly selected seed
        // may import or clear cookies; project jars remain for ephemeral work.
        let clear_cookies = cookie_override
            .as_ref()
            .map(|cookies| cookies.clear_cookies.clone())
            .unwrap_or_default();
        let cookie_seed = cookie_override
            .as_ref()
            .and_then(|cookies| cookies.seed.clone());
        let cookies = self
            .cookies_for_launch(project_id, persistent, cookie_override)
            .await?;
        let profile_dir = match profile_name.filter(|_| persistent) {
            Some(profile_name) => Some(self.chromium_profile_dir(project_id, profile_name)?),
            None => None,
        };
        let prefer_profile_state = profile_dir
            .as_deref()
            .is_some_and(chromium_profile_has_state);
        let mut session = self
            .db
            .create_browser_session(project_id, profile.clone())
            .await?;
        let capture = self
            .db
            .create_capture_session(CreateCaptureSession {
                project_id,
                browser_session_id: Some(session.id),
                browser_action_id: None,
                is_browser_bound: true,
                ttl: None,
            })
            .await?;
        let token = capture.token_once.clone().ok_or_else(|| {
            DomainError::new(
                ErrorCode::Internal,
                "browser capture credential missing one-time token",
            )
        })?;
        let start_params = json!({
            "session_id": session.id.get(),
            "engine": "chromium",
            "url": url,
            "proxy": {
                "server": self.proxy_server.clone(),
                "bearer_token": token.clone(),
                "username": PROXY_BASIC_USER,
                "password": token,
            },
            "ca_cert_path": self.ca_cert_path.as_ref().map(|path| path.display().to_string()),
            "cookies": cookies,
            "clear_cookies": clear_cookies,
            "restore_state": restored_profile,
            "persistent": persistent,
            "profile": profile_name,
            // An initialized Chromium profile is authoritative because it may
            // contain manual login and service-worker state. An empty profile
            // imports the portable checkpoint left by an older browser build.
            "prefer_profile_state": prefer_profile_state,
            "profile_dir": if persistent {
                profile_dir.as_ref().map(|path| path.display().to_string())
            } else {
                None
            },
        });
        let checkpoint_status = if persistent && restored_profile.is_some() {
            "restored"
        } else {
            "ok"
        };
        let result = match self.call_worker("session.start", start_params).await {
            Ok(result) => result,
            Err(error) => {
                session.state = BrowserSessionState::Failed;
                session.checkpoint_status = Some("start_failed".into());
                let _ = self.db.update_browser_session(&session).await;
                let _ = self.db.revoke_capture_session(project_id, capture.id).await;
                return Err(error);
            }
        };
        if let Err(error) =
            verify_worker_identity(&result, session.id, profile_name, profile_dir.as_deref())
        {
            self.cleanup_failed_start(project_id, &mut session, capture.id)
                .await;
            return Err(error);
        }
        let checkpoint = match result.get("checkpoint") {
            Some(checkpoint) => checkpoint,
            None => {
                self.cleanup_failed_start(project_id, &mut session, capture.id)
                    .await;
                return Err(DomainError::new(
                    ErrorCode::ProtocolError,
                    "worker omitted checkpoint",
                ));
            }
        };
        let saved = match self
            .save_checkpoint(
                project_id,
                session.id,
                checkpoint,
                checkpoint_status,
                profile_name,
            )
            .await
        {
            Ok(saved) => saved,
            Err(error) => {
                self.cleanup_failed_start(project_id, &mut session, capture.id)
                    .await;
                return Err(error);
            }
        };
        session.engine = BrowserEngine::Chromium;
        session.current_url = saved.url;
        session.current_title = saved.title;
        session.state = BrowserSessionState::Ready;
        session.active_profile = profile.clone();
        session.checkpoint_status = Some(checkpoint_status.into());
        session.checkpoint_hash = Some(saved.hash);
        if let Err(error) = self.db.update_browser_session(&session).await {
            self.cleanup_failed_start(project_id, &mut session, capture.id)
                .await;
            return Err(error);
        }
        if let Some(profile_name) = profile_name {
            if let Err(error) = self
                .record_cookie_seed(project_id, profile_name, cookie_seed)
                .await
            {
                self.cleanup_failed_start(project_id, &mut session, capture.id)
                    .await;
                return Err(error);
            }
        }
        self.runtime_sessions.lock().await.insert(
            session.id.get(),
            RuntimeSession {
                project_id,
                capture_session_id: capture.id,
                persistent,
                profile,
                cdp: None,
            },
        );
        if let Err(error) = self
            .persist_javascript_files(project_id, session.id, session.current_url.as_deref())
            .await
        {
            tracing::warn!(%error, session_id = session.id.get(), "could not persist JavaScript provenance");
        }
        schedule_page_title_association(self.db.clone(), &session);
        Ok(session)
    }

    pub async fn csrf_probe(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        target_url: &str,
        method: &str,
        params: &[(String, String)],
        timeout_ms: u64,
    ) -> DomainResult<BrowserCsrfProbeResult> {
        let parsed = url::Url::parse(target_url)
            .map_err(|error| DomainError::invalid(format!("invalid CSRF target URL: {error}")))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(DomainError::invalid(
                "CSRF target URL must use HTTP or HTTPS",
            ));
        }
        if !matches!(method, "GET" | "POST") {
            return Err(DomainError::invalid(
                "CSRF browser probe method must be GET or POST",
            ));
        }
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        let active = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .is_some_and(|runtime| runtime.project_id == project_id && !runtime.persistent);
        if !active {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "isolated browser session is not active",
            ));
        }
        let result = self
            .call_worker(
                "session.csrf_probe",
                json!({
                    "session_id": session_id.get(),
                    "target_url": target_url,
                    "method": method,
                    "params": params.iter().map(|(name, value)| json!({"name":name,"value":value})).collect::<Vec<_>>(),
                    "timeout_ms": timeout_ms.clamp(1_000, 30_000),
                }),
            )
            .await?;
        serde_json::from_value(result)
            .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))
    }

    async fn cleanup_failed_start(
        &self,
        project_id: ProjectId,
        session: &mut BrowserSession,
        capture_session_id: CaptureSessionId,
    ) {
        let _ = self
            .call_worker("session.stop", json!({ "session_id": session.id.get() }))
            .await;
        session.state = BrowserSessionState::Failed;
        session.checkpoint_status = Some("start_failed".into());
        let _ = self.db.update_browser_session(session).await;
        self.checkpoints.lock().await.remove(&session.id.get());
        let _ = self
            .db
            .revoke_capture_session(project_id, capture_session_id)
            .await;
    }

    async fn cookies_for_launch(
        &self,
        project_id: ProjectId,
        persistent: bool,
        cookie_override: Option<CookieLaunchOverride>,
    ) -> DomainResult<Vec<Value>> {
        match cookie_override {
            Some(cookies) => Ok(cookies.cookies),
            None if persistent => Ok(Vec::new()),
            None => browser_cookies(&self.db.list_stored_cookie_profiles(project_id).await?),
        }
    }

    /// Apply managed project cookies only to ephemeral sessions. Persistent
    /// identities import cookies solely through an explicit cookie_profile.
    pub async fn apply_cookie_profile(
        &self,
        project_id: ProjectId,
        previous: Option<&StoredCookieProfile>,
        profile: &StoredCookieProfile,
    ) -> DomainResult<usize> {
        let cookies = browser_cookies(std::slice::from_ref(profile))?;
        let previous_names = previous
            .filter(|profile| profile.managed_cookies.is_none())
            .map(StoredCookieProfile::pairs)
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(|pair| pair.name)
            .collect::<Vec<_>>();
        let previous_cookies = previous
            .map(profile_cookie_identities)
            .transpose()?
            .unwrap_or_default();
        let session_ids = self.managed_cookie_session_ids(project_id).await;
        for session_id in &session_ids {
            let operation_lock = self.session_operation_lock(*session_id).await;
            let _operation_guard = operation_lock.lock().await;
            let result = self
                .call_worker(
                    "session.set_cookies",
                    json!({
                        "session_id": session_id.get(),
                        "cookies": cookies.clone(),
                        "target_url": profile.target_url,
                        "clear_names": previous_names,
                        "clear_cookies": previous_cookies,
                    }),
                )
                .await?;
            self.save_cookie_checkpoint(project_id, *session_id, &result)
                .await?;
        }
        Ok(session_ids.len())
    }

    pub async fn clear_cookie_profile(
        &self,
        project_id: ProjectId,
        profile: &StoredCookieProfile,
    ) -> DomainResult<usize> {
        let session_ids = self.managed_cookie_session_ids(project_id).await;
        let pairs = if profile.managed_cookies.is_none() {
            profile.pairs()?
        } else {
            Vec::new()
        };
        let cookies = profile_cookie_identities(profile)?;
        for session_id in &session_ids {
            let operation_lock = self.session_operation_lock(*session_id).await;
            let _operation_guard = operation_lock.lock().await;
            let result = self
                .call_worker(
                    "session.clear_cookies",
                    json!({
                        "session_id": session_id.get(),
                        "target_url": profile.target_url,
                        "names": pairs.iter().map(|pair| &pair.name).collect::<Vec<_>>(),
                        "cookies": cookies,
                    }),
                )
                .await?;
            self.save_cookie_checkpoint(project_id, *session_id, &result)
                .await?;
        }
        Ok(session_ids.len())
    }

    async fn managed_cookie_session_ids(&self, project_id: ProjectId) -> Vec<BrowserSessionId> {
        self.runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, runtime)| {
                (runtime.project_id == project_id && !runtime.persistent)
                    .then_some(BrowserSessionId(*id))
            })
            .collect()
    }

    pub async fn active_sessions(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Vec<BrowserSession>> {
        self.db.get_project(project_id).await?;
        let ids = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, runtime)| {
                (runtime.project_id == project_id && runtime.persistent)
                    .then_some(BrowserSessionId(*id))
            })
            .collect::<Vec<_>>();
        let mut sessions = Vec::with_capacity(ids.len());
        for session_id in ids {
            sessions.push(self.session_status(project_id, session_id).await?);
        }
        sessions.sort_by_key(|session| session.id.get());
        Ok(sessions)
    }

    pub async fn active_status(&self, project_id: ProjectId) -> DomainResult<BrowserStatus> {
        // Live identity checks may wait for browser actions. Do not hold the
        // global lifecycle or runtime map lock across them. The final sample
        // rejects persistent identities changed by an interleaved transition.
        let project = self.db.get_project(project_id).await?;
        let sessions = self.active_sessions(project_id).await?;
        let runtimes = self.runtime_sessions.lock().await;
        let resources = browser_resources(
            project_id,
            project.limits.max_concurrent_browsers,
            &sessions,
            &runtimes,
        )?;
        Ok(BrowserStatus {
            sessions,
            resources,
        })
    }

    pub async fn session_status(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<BrowserSession> {
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        self.verified_session_status(project_id, session_id).await
    }

    async fn verified_session_status(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<BrowserSession> {
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        let runtime = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .cloned();
        if let Some(runtime) = runtime {
            if runtime.project_id != project_id || runtime.profile != session.profile {
                return Err(DomainError::new(
                    ErrorCode::ProtocolError,
                    "requested browser profile does not match the active runtime",
                ));
            }
            let directory = runtime
                .profile
                .as_deref()
                .map(|name| self.chromium_profile_path(project_id, name));
            let directory = directory
                .map(std::fs::canonicalize)
                .transpose()
                .map_err(|error| {
                    DomainError::new(
                        ErrorCode::Unavailable,
                        format!("cannot verify browser profile directory: {error}"),
                    )
                })?;
            let result = self
                .call_worker("session.status", json!({"session_id":session_id.get()}))
                .await?;
            verify_worker_identity(
                &result,
                session_id,
                runtime.profile.as_deref(),
                directory.as_deref(),
            )?;
            session.active_profile = runtime.profile;
        } else if matches!(
            session.state,
            BrowserSessionState::Ready | BrowserSessionState::Busy | BrowserSessionState::Starting
        ) {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "requested browser profile is not active",
            ));
        }
        Ok(session)
    }

    async fn record_cookie_seed(
        &self,
        project_id: ProjectId,
        profile: &str,
        seed: Option<CookieSeed>,
    ) -> DomainResult<()> {
        if let Some(seed) = seed {
            self.update_persistent_profile(project_id, profile, |state| {
                state.cookie_seed = Some(seed)
            })
            .await?;
        }
        Ok(())
    }

    pub async fn cdp_status(&self, project_id: ProjectId) -> DomainResult<BrowserCdpStatus> {
        self.db.get_project(project_id).await?;
        let active = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .find_map(|(session_id, runtime)| {
                (runtime.project_id == project_id)
                    .then(|| runtime.cdp.clone().map(|cdp| (*session_id, cdp)))
                    .flatten()
            });
        Ok(cdp_status_view(project_id, active))
    }

    pub async fn cdp_status_for_session(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<BrowserCdpStatus> {
        self.session_status(project_id, session_id).await?;
        let cdp = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .and_then(|runtime| runtime.cdp.clone());
        let mut status = cdp_status_view(project_id, cdp.map(|cdp| (session_id.get(), cdp)));
        status.session_id = Some(session_id);
        Ok(status)
    }

    pub async fn enable_cdp(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<BrowserCdpStatus> {
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        let runtime = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .cloned()
            .ok_or_else(|| {
                DomainError::new(ErrorCode::Unavailable, "browser session is not active")
            })?;
        if runtime.project_id != project_id {
            return Err(DomainError::not_found("browser session"));
        }
        if !runtime.persistent {
            return Err(DomainError::invalid(
                "CDP handoff requires a persistent project browser",
            ));
        }
        if let Some(cdp) = runtime.cdp {
            return Ok(cdp_status_view(project_id, Some((session_id.get(), cdp))));
        }
        if let Some((active_session, _)) = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .find(|(_, active)| active.cdp.is_some())
        {
            return Err(DomainError::new(
                ErrorCode::ConcurrencyLimited,
                format!(
                    "CDP port {BROWSER_CDP_PORT} is already handed off by browser session {active_session}"
                ),
            ));
        }
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, BROWSER_CDP_PORT)).map_err(
            |error| {
                DomainError::new(
                    ErrorCode::Unavailable,
                    format!("CDP port {BROWSER_CDP_PORT} is unavailable on 127.0.0.1: {error}"),
                )
            },
        )?;
        let result = self
            .call_worker(
                "session.cdp_enable",
                json!({
                    "session_id": session_id.get(),
                    "cdp_port": BROWSER_CDP_PORT,
                }),
            )
            .await?;
        let cdp = parse_cdp_info(result.get("cdp"))?;
        if let Some(runtime) = self
            .runtime_sessions
            .lock()
            .await
            .get_mut(&session_id.get())
        {
            runtime.cdp = Some(cdp.clone());
        }
        self.save_cookie_checkpoint(project_id, session_id, &result)
            .await?;
        Ok(cdp_status_view(project_id, Some((session_id.get(), cdp))))
    }

    pub async fn disable_cdp(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<BrowserCdpStatus> {
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        let runtime = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .cloned()
            .ok_or_else(|| {
                DomainError::new(ErrorCode::Unavailable, "browser session is not active")
            })?;
        if runtime.project_id != project_id {
            return Err(DomainError::not_found("browser session"));
        }
        if runtime.cdp.is_none() {
            return Ok(cdp_status_view(project_id, None));
        }
        let result = self
            .call_worker(
                "session.cdp_disable",
                json!({ "session_id": session_id.get() }),
            )
            .await?;
        if let Some(runtime) = self
            .runtime_sessions
            .lock()
            .await
            .get_mut(&session_id.get())
        {
            runtime.cdp = None;
        }
        self.save_cookie_checkpoint(project_id, session_id, &result)
            .await?;
        Ok(cdp_status_view(project_id, None))
    }

    async fn session_persistent_profile(&self, session_id: BrowserSessionId) -> Option<String> {
        self.runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .filter(|runtime| runtime.persistent)
            .and_then(|runtime| runtime.profile.clone())
    }

    async fn session_operation_lock(&self, session_id: BrowserSessionId) -> Arc<Mutex<()>> {
        self.session_ops
            .lock()
            .await
            .entry(session_id.get())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Fetch a crawler candidate through the browser's cookie-sharing request
    /// context. Returns false when the session is inactive or has no cookies
    /// for this URL, allowing the crawler to use its regular HTTP transport.
    pub async fn authenticated_background_fetch(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        url: &str,
    ) -> DomainResult<bool> {
        let parsed = url::Url::parse(url)
            .map_err(|error| DomainError::invalid(format!("invalid crawler URL: {error}")))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(DomainError::invalid("crawler URL must use HTTP or HTTPS"));
        }
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        let active = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .is_some_and(|runtime| runtime.project_id == project_id && runtime.cdp.is_none());
        if !active {
            return Ok(false);
        }
        let result = self
            .call_worker(
                "session.authenticated_fetch",
                json!({ "session_id": session_id.get(), "url": url }),
            )
            .await?;
        Ok(result.get("used").and_then(Value::as_bool).unwrap_or(false))
    }

    async fn save_cookie_checkpoint(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        result: &Value,
    ) -> DomainResult<()> {
        let checkpoint = result.get("checkpoint").ok_or_else(|| {
            DomainError::new(ErrorCode::ProtocolError, "worker omitted checkpoint")
        })?;
        let profile = self.session_persistent_profile(session_id).await;
        let saved = self
            .save_checkpoint(project_id, session_id, checkpoint, "ok", profile.as_deref())
            .await?;
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        session.current_url = saved.url;
        session.current_title = saved.title;
        session.checkpoint_status = Some("ok".into());
        session.checkpoint_hash = Some(saved.hash);
        self.db.update_browser_session(&session).await
    }

    pub async fn action(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        action: BrowserAction,
    ) -> DomainResult<ActionResult> {
        validate_browser_action(&action)?;
        if matches!(&action, BrowserAction::Close) {
            self.stop(project_id, session_id).await?;
            return Ok(ActionResult {
                ok: true,
                untrusted: false,
                message: "session closed".into(),
                data: None,
                browser: None,
                error_code: None,
            });
        }
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        if matches!(
            session.state,
            BrowserSessionState::Interrupted
                | BrowserSessionState::Stopped
                | BrowserSessionState::Failed
        ) {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "browser session is not active",
            ));
        }
        let runtime = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .cloned();
        let Some(runtime) = runtime else {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "browser runtime is not attached; start a new browser session",
            ));
        };
        if runtime.cdp.is_some() {
            return Err(DomainError::new(
                ErrorCode::Conflict,
                "browser control is handed off through CDP; disable the CDP handoff before running agent browser actions",
            ));
        }
        session.state = BrowserSessionState::Busy;
        self.db.update_browser_session(&session).await?;
        let event_wait_ms = match &action {
            BrowserAction::Events { wait_ms, .. } => *wait_ms,
            _ => 0,
        };
        let mut worker_action = serde_json::to_value(&action)
            .map_err(|error| DomainError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        // A worker RPC is serialized behind one shared stdin/stdout stream. Keep
        // long-poll timing here so an empty event wait does not monopolize that
        // stream and block independent browser sessions.
        if event_wait_ms > 0 {
            worker_action["wait_ms"] = json!(0);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_millis(event_wait_ms);
        let worker_result = loop {
            let result = self
                .call_worker(
                    "session.action",
                    json!({
                        "session_id": session_id.get(),
                        "action": worker_action.clone(),
                    }),
                )
                .await;
            let should_wait = event_wait_ms > 0
                && result.as_ref().is_ok_and(|value| {
                    value
                        .get("data")
                        .and_then(|data| data.get("events"))
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
                })
                && tokio::time::Instant::now() < deadline;
            if !should_wait {
                break result;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            tokio::time::sleep(remaining.min(Duration::from_millis(50))).await;
        };
        let result = match worker_result {
            Ok(result) => result,
            Err(error) => {
                session.state = if self.worker.lock().await.is_some() {
                    BrowserSessionState::Ready
                } else {
                    BrowserSessionState::Interrupted
                };
                let _ = self.db.update_browser_session(&session).await;
                return Err(error);
            }
        };
        let checkpoint = result.get("checkpoint").ok_or_else(|| {
            DomainError::new(ErrorCode::ProtocolError, "worker omitted checkpoint")
        })?;
        let checkpoint_status = "ok";
        let saved = self
            .save_checkpoint(
                project_id,
                session_id,
                checkpoint,
                checkpoint_status,
                runtime.profile.as_deref().filter(|_| runtime.persistent),
            )
            .await?;
        session.current_url = saved.url;
        session.current_title = saved.title;
        session.state = BrowserSessionState::Ready;
        session.checkpoint_status = Some(checkpoint_status.into());
        session.checkpoint_hash = Some(saved.hash);
        self.db.update_browser_session(&session).await?;
        if let Err(error) = self
            .persist_javascript_files(project_id, session_id, session.current_url.as_deref())
            .await
        {
            tracing::warn!(%error, session_id = session_id.get(), "could not persist JavaScript provenance");
        }
        schedule_page_title_association(self.db.clone(), &session);

        Ok(ActionResult {
            ok: result.get("ok").and_then(Value::as_bool).unwrap_or(true),
            untrusted: result
                .get("untrusted")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            message: result
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("browser action completed")
                .to_string(),
            data: result.get("data").cloned().filter(|value| !value.is_null()),
            browser: result
                .get("browser")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    DomainError::new(
                        ErrorCode::ProtocolError,
                        format!("invalid browser action context: {error}"),
                    )
                })?,
            error_code: result
                .get("error_code")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    pub async fn javascript_files(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<Vec<BrowserJavascriptFile>> {
        let belongs_to_project = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .is_some_and(|runtime| runtime.project_id == project_id);
        if !belongs_to_project {
            return Err(DomainError::not_found("active browser session"));
        }
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        self.persist_javascript_files(project_id, session_id, None)
            .await
    }

    async fn persist_javascript_files(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        default_source_page_url: Option<&str>,
    ) -> DomainResult<Vec<BrowserJavascriptFile>> {
        let result = self
            .call_worker(
                "session.javascript_files",
                json!({ "session_id": session_id.get() }),
            )
            .await?;
        let files: Vec<BrowserJavascriptFile> =
            serde_json::from_value(result.get("files").cloned().unwrap_or_else(|| json!([])))
                .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
        let fallback = default_source_page_url
            .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
            .or_else(|| {
                files
                    .iter()
                    .find_map(|file| file.source_page_url.as_deref())
            });
        if let Some(fallback) = fallback {
            self.db
                .record_javascript_files(
                    project_id,
                    fallback,
                    files
                        .iter()
                        .map(|file| crate::storage::JavascriptProvenanceInput {
                            url: file.url.clone(),
                            source_page_url: file.source_page_url.clone(),
                        })
                        .collect(),
                    Some(session_id),
                    "browser",
                )
                .await?;
        }
        Ok(files)
    }

    pub async fn stop(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<()> {
        let _lifecycle = self.lifecycle.lock().await;
        self.stop_inner(project_id, session_id).await
    }

    async fn stop_inner(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<()> {
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        let runtime = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .cloned();
        let mut persistence_error = None;
        if let Some(runtime) = &runtime {
            if let Ok(result) = self
                .call_worker("session.stop", json!({ "session_id": session_id.get() }))
                .await
            {
                if let Some(checkpoint) = result.get("checkpoint") {
                    if let Err(error) = self
                        .save_checkpoint(
                            project_id,
                            session_id,
                            checkpoint,
                            "stopped",
                            runtime.profile.as_deref().filter(|_| runtime.persistent),
                        )
                        .await
                    {
                        persistence_error = Some(error);
                    }
                }
            }
        }
        self.runtime_sessions.lock().await.remove(&session_id.get());
        if let Some(profile) = runtime
            .as_ref()
            .filter(|runtime| runtime.persistent)
            .and_then(|runtime| runtime.profile.as_ref())
        {
            self.profile_leases
                .lock()
                .await
                .remove(&(project_id.get(), profile.clone()));
        }
        session.state = BrowserSessionState::Stopped;
        self.db.update_browser_session(&session).await?;
        self.checkpoints.lock().await.remove(&session_id.get());
        if let Some(runtime) = runtime {
            let _ = self
                .db
                .revoke_capture_session(project_id, runtime.capture_session_id)
                .await;
        }
        if self.runtime_sessions.lock().await.is_empty() {
            if let Some(mut idle_worker) = self.worker.lock().await.take() {
                idle_worker.terminate().await;
            }
        }
        self.session_ops.lock().await.remove(&session_id.get());
        match persistence_error {
            Some(error) => Err(DomainError::new(
                ErrorCode::StorageError,
                format!("browser stopped but final state save failed: {error}"),
            )),
            None => Ok(()),
        }
    }

    /// Stop every active browser in one project and release the worker when
    /// the final session closes.
    pub async fn stop_project(&self, project_id: ProjectId) -> DomainResult<usize> {
        let _lifecycle = self.lifecycle.lock().await;
        let sessions = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, runtime)| {
                (runtime.project_id == project_id).then_some((project_id, BrowserSessionId(*id)))
            })
            .collect::<Vec<_>>();
        self.stop_sessions_inner(sessions).await
    }

    /// Stop all active browsers across projects during daemon shutdown.
    pub async fn stop_all(&self) -> DomainResult<usize> {
        let _lifecycle = self.lifecycle.lock().await;
        let sessions = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .map(|(id, runtime)| (runtime.project_id, BrowserSessionId(*id)))
            .collect::<Vec<_>>();
        self.stop_sessions_inner(sessions).await
    }

    /// Terminate the shared worker and mark every attached session interrupted.
    /// Used only when graceful shutdown exceeds its bound.
    pub async fn force_stop_all(&self) {
        let _lifecycle = self.lifecycle.lock().await;
        if let Some(mut worker) = self.worker.lock().await.take() {
            worker.terminate().await;
        }
        self.interrupt_runtime_sessions().await;
    }

    async fn stop_sessions_inner(
        &self,
        sessions: Vec<(ProjectId, BrowserSessionId)>,
    ) -> DomainResult<usize> {
        let total = sessions.len();
        let mut first_error = None;
        for (project_id, session_id) in sessions {
            if let Err(error) = self.stop_inner(project_id, session_id).await {
                first_error.get_or_insert(error);
            }
        }
        if self.runtime_sessions.lock().await.is_empty() {
            if let Some(mut idle_worker) = self.worker.lock().await.take() {
                idle_worker.terminate().await;
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(total),
        }
    }

    async fn call_worker(&self, method: &str, params: Value) -> DomainResult<Value> {
        let node_path = self.node_path.as_deref().ok_or_else(|| {
            DomainError::new(ErrorCode::BrowserDisabled, "Node.js is not available")
        })?;
        let worker_path = self.worker_path.as_deref().ok_or_else(|| {
            DomainError::new(
                ErrorCode::BrowserDisabled,
                "browser worker is not available",
            )
        })?;
        let mut worker = self.worker.lock().await;
        if worker.is_none() {
            *worker = Some(
                WorkerProcess::spawn(
                    node_path,
                    worker_path,
                    self.playwright_core_path.as_deref(),
                    self.chromium_path.as_deref(),
                )
                .await
                .map_err(WorkerCallFailure::into_domain)?,
            );
        }
        let result = worker
            .as_mut()
            .expect("worker initialized")
            .call(method, params)
            .await;
        match result {
            Ok(value) => Ok(value),
            Err(WorkerCallFailure::Rpc(error)) => Err(error),
            Err(WorkerCallFailure::Transport(error)) => {
                if let Some(mut failed) = worker.take() {
                    failed.terminate().await;
                }
                drop(worker);
                self.interrupt_runtime_sessions().await;
                Err(error)
            }
        }
    }

    async fn interrupt_runtime_sessions(&self) {
        let runtimes = {
            let mut active = self.runtime_sessions.lock().await;
            std::mem::take(&mut *active)
        };
        self.checkpoints.lock().await.clear();
        self.session_ops.lock().await.clear();
        for (session_id, runtime) in runtimes {
            if let Some(profile) = runtime.profile.as_ref().filter(|_| runtime.persistent) {
                self.profile_leases
                    .lock()
                    .await
                    .remove(&(runtime.project_id.get(), profile.clone()));
            }
            if let Ok(mut session) = self
                .db
                .get_browser_session(runtime.project_id, BrowserSessionId(session_id))
                .await
            {
                session.state = BrowserSessionState::Interrupted;
                session.checkpoint_status = Some("worker_interrupted".into());
                let _ = self.db.update_browser_session(&session).await;
            }
            let _ = self
                .db
                .revoke_capture_session(runtime.project_id, runtime.capture_session_id)
                .await;
        }
    }

    fn project_profile_dir(&self, project_id: ProjectId) -> PathBuf {
        self.profiles_root
            .join("projects")
            .join(project_id.get().to_string())
    }

    fn profile_directory(&self, project_id: ProjectId, profile: &str) -> PathBuf {
        if profile == DEFAULT_BROWSER_PROFILE {
            self.project_profile_dir(project_id)
        } else {
            self.project_profile_dir(project_id)
                .join("profiles")
                .join(profile)
        }
    }

    fn profile_state_path(&self, project_id: ProjectId, profile: &str) -> PathBuf {
        self.profile_directory(project_id, profile)
            .join("state.json")
    }

    fn chromium_profile_path(&self, project_id: ProjectId, profile: &str) -> PathBuf {
        self.project_profile_dir(project_id)
            .join("chromium")
            .join(profile)
    }

    fn chromium_profile_dir(&self, project_id: ProjectId, profile: &str) -> DomainResult<PathBuf> {
        let directory = self.chromium_profile_path(project_id, profile);
        create_private_dir(&directory)?;
        let directory = std::fs::canonicalize(directory).map_err(|error| {
            DomainError::new(
                ErrorCode::Unavailable,
                format!("cannot verify browser profile directory: {error}"),
            )
        })?;
        // Detect case aliases and symlink aliases even across sequential launches.
        let identity_path = directory.join("huntproxy-identity.json");
        let identity = json!({"project_id":project_id.get(), "profile":profile});
        match std::fs::read(&identity_path) {
            Ok(bytes) if serde_json::from_slice::<Value>(&bytes).ok().as_ref() == Some(&identity) => {}
            Ok(_) => return Err(DomainError::new(ErrorCode::Unavailable,
                "browser profile directory belongs to a different identity; cannot guarantee isolation")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                write_private_file(&identity_path, &serde_json::to_vec(&identity)
                    .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?)?;
            }
            Err(error) => return Err(DomainError::new(ErrorCode::Unavailable,
                format!("cannot verify browser profile owner: {error}"))),
        }
        Ok(directory)
    }

    async fn load_persistent_profile(
        &self,
        project_id: ProjectId,
        profile: &str,
    ) -> DomainResult<Option<PersistentBrowserProfile>> {
        validate_browser_profile_name(profile)?;
        let _guard = self.profile_io.lock().await;
        let path = self.profile_state_path(project_id, profile);
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(DomainError::new(
                    ErrorCode::StorageError,
                    format!("read browser profile metadata: {error}"),
                ))
            }
        };
        if metadata.len() > MAX_PERSISTENT_PROFILE_BYTES as u64 {
            return Err(DomainError::new(
                ErrorCode::StorageError,
                "browser profile state exceeds the 25 MiB safety limit; reset the project browser profile",
            ));
        }
        let encoded = std::fs::read(&path).map_err(|error| {
            DomainError::new(
                ErrorCode::StorageError,
                format!("read browser profile state: {error}"),
            )
        })?;
        serde_json::from_slice(&encoded).map(Some).map_err(|_| {
            DomainError::new(
                ErrorCode::StorageError,
                "browser profile state is invalid; reset the project browser profile",
            )
        })
    }

    async fn update_persistent_profile(
        &self,
        project_id: ProjectId,
        profile_name: &str,
        update: impl FnOnce(&mut PersistentBrowserProfile),
    ) -> DomainResult<()> {
        validate_browser_profile_name(profile_name)?;
        let _guard = self.profile_io.lock().await;
        let path = self.profile_state_path(project_id, profile_name);
        let mut profile = match std::fs::read(&path) {
            Ok(encoded) if encoded.len() <= MAX_PERSISTENT_PROFILE_BYTES => {
                serde_json::from_slice(&encoded).map_err(|_| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        "browser profile state is invalid; reset the project browser profile",
                    )
                })?
            }
            Ok(_) => {
                return Err(DomainError::new(
                    ErrorCode::StorageError,
                    "browser profile state exceeds the 25 MiB safety limit; reset the project browser profile",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                PersistentBrowserProfile::default()
            }
            Err(error) => {
                return Err(DomainError::new(
                    ErrorCode::StorageError,
                    format!("read browser profile state: {error}"),
                ))
            }
        };
        update(&mut profile);
        let encoded = serde_json::to_vec(&profile)
            .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
        if encoded.len() > MAX_PERSISTENT_PROFILE_BYTES {
            return Err(DomainError::new(
                ErrorCode::StorageError,
                "browser profile state exceeds the 25 MiB safety limit",
            ));
        }
        let directory = path.parent().ok_or_else(|| {
            DomainError::new(
                ErrorCode::StorageError,
                "browser profile directory unavailable",
            )
        })?;
        create_private_dir(directory)?;
        let temporary = directory.join(format!(".state-{}.tmp", std::process::id()));
        write_private_file(&temporary, &encoded)?;
        std::fs::rename(&temporary, &path).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            DomainError::new(
                ErrorCode::StorageError,
                format!("commit browser profile state: {error}"),
            )
        })
    }

    async fn persist_checkpoint(
        &self,
        project_id: ProjectId,
        profile_name: &str,
        checkpoint: &Checkpoint,
    ) -> DomainResult<()> {
        validate_browser_profile_name(profile_name)?;
        let _guard = self.profile_io.lock().await;
        let path = self.profile_state_path(project_id, profile_name);
        let mut profile = match std::fs::read(&path) {
            Ok(encoded) if encoded.len() <= MAX_PERSISTENT_PROFILE_BYTES => {
                serde_json::from_slice(&encoded).map_err(|_| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        "browser profile state is invalid; reset the project browser profile",
                    )
                })?
            }
            Ok(_) => {
                return Err(DomainError::new(
                    ErrorCode::StorageError,
                    "browser profile state exceeds the 25 MiB safety limit; reset the project browser profile",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                PersistentBrowserProfile::default()
            }
            Err(error) => {
                return Err(DomainError::new(
                    ErrorCode::StorageError,
                    format!("read browser profile state: {error}"),
                ))
            }
        };
        if !checkpoint.hash.is_empty() && profile.checkpoint_hash == checkpoint.hash {
            return Ok(());
        }
        merge_persistent_profile(&mut profile, checkpoint);
        let encoded = serde_json::to_vec(&profile)
            .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
        if encoded.len() > MAX_PERSISTENT_PROFILE_BYTES {
            return Err(DomainError::new(
                ErrorCode::StorageError,
                "browser profile state exceeds the 25 MiB safety limit",
            ));
        }
        let directory = path.parent().ok_or_else(|| {
            DomainError::new(
                ErrorCode::StorageError,
                "browser profile directory unavailable",
            )
        })?;
        create_private_dir(directory)?;
        let temporary = directory.join(format!(".state-{}.tmp", std::process::id()));
        write_private_file(&temporary, &encoded)?;
        if let Ok(file) = std::fs::File::open(&temporary) {
            let _ = file.sync_all();
        }
        std::fs::rename(&temporary, &path).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            DomainError::new(
                ErrorCode::StorageError,
                format!("commit browser profile state: {error}"),
            )
        })?;
        Ok(())
    }

    pub async fn browser_profiles(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Vec<BrowserProfileStatus>> {
        let _lifecycle = self.lifecycle.lock().await;
        self.db.get_project(project_id).await?;
        let mut names = std::collections::BTreeSet::from([DEFAULT_BROWSER_PROFILE.to_string()]);
        for root in [
            self.project_profile_dir(project_id).join("profiles"),
            self.project_profile_dir(project_id).join("chromium"),
        ] {
            let entries = match std::fs::read_dir(&root) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(DomainError::new(
                        ErrorCode::StorageError,
                        format!("list browser profiles: {error}"),
                    ))
                }
            };
            for entry in entries {
                let entry = entry.map_err(|error| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        format!("list browser profiles: {error}"),
                    )
                })?;
                let file_type = entry.file_type().map_err(|error| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        format!("inspect browser profile: {error}"),
                    )
                })?;
                if !file_type.is_dir() {
                    continue;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if validate_browser_profile_name(&name).is_ok() {
                    names.insert(name);
                }
            }
        }
        let active = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(session_id, runtime)| {
                if runtime.project_id == project_id && runtime.persistent {
                    runtime
                        .profile
                        .as_ref()
                        .map(|profile| (profile.clone(), BrowserSessionId(*session_id)))
                } else {
                    None
                }
            })
            .collect::<HashMap<_, _>>();
        names.extend(active.keys().cloned());
        names.remove(DEFAULT_BROWSER_PROFILE);

        Ok(std::iter::once(DEFAULT_BROWSER_PROFILE.to_string())
            .chain(names)
            .map(|name| {
                let session_id = active.get(&name).copied();
                let has_state = self.profile_state_path(project_id, &name).is_file()
                    || chromium_profile_has_state(&self.chromium_profile_path(project_id, &name));
                BrowserProfileStatus {
                    name,
                    active: session_id.is_some(),
                    session_id,
                    has_state,
                }
            })
            .collect())
    }

    pub async fn create_browser_profile(
        &self,
        project_id: ProjectId,
        profile: &str,
    ) -> DomainResult<BrowserProfileStatus> {
        validate_browser_profile_name(profile)?;
        let _lifecycle = self.lifecycle.lock().await;
        self.db.get_project(project_id).await?;
        create_private_dir(&self.profile_directory(project_id, profile))?;
        let session_id =
            self.runtime_sessions
                .lock()
                .await
                .iter()
                .find_map(|(session_id, runtime)| {
                    (runtime.project_id == project_id
                        && runtime.persistent
                        && runtime.profile.as_deref() == Some(profile))
                    .then_some(BrowserSessionId(*session_id))
                });
        Ok(BrowserProfileStatus {
            name: profile.to_string(),
            active: session_id.is_some(),
            session_id,
            has_state: self.profile_state_path(project_id, profile).is_file()
                || chromium_profile_has_state(&self.chromium_profile_path(project_id, profile)),
        })
    }

    pub async fn delete_browser_profile(
        &self,
        project_id: ProjectId,
        profile: &str,
    ) -> DomainResult<bool> {
        validate_browser_profile_name(profile)?;
        if profile == DEFAULT_BROWSER_PROFILE {
            return Err(DomainError::invalid(
                "the default browser profile cannot be deleted; use browser_manage reset_profile",
            ));
        }
        let _lifecycle = self.lifecycle.lock().await;
        self.db.get_project(project_id).await?;
        let lease = (project_id.get(), profile.to_string());
        {
            let mut leases = self.profile_leases.lock().await;
            if !leases.insert(lease.clone()) {
                return Err(DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    format!("browser profile '{profile}' is active; stop it before deleting it"),
                ));
            }
        }
        let result = {
            let _guard = self.profile_io.lock().await;
            let removed_profile =
                remove_browser_profile_path(&self.profile_directory(project_id, profile));
            let removed_chromium =
                remove_browser_profile_path(&self.chromium_profile_path(project_id, profile));
            match (removed_profile, removed_chromium) {
                (Ok(profile), Ok(chromium)) => Ok(profile || chromium),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        };
        self.profile_leases.lock().await.remove(&lease);
        result
    }

    pub async fn reset_project_profile(&self, project_id: ProjectId) -> DomainResult<bool> {
        self.reset_browser_profile(project_id, DEFAULT_BROWSER_PROFILE)
            .await
    }

    pub async fn reset_browser_profile(
        &self,
        project_id: ProjectId,
        profile: &str,
    ) -> DomainResult<bool> {
        validate_browser_profile_name(profile)?;
        let _lifecycle = self.lifecycle.lock().await;
        self.db.get_project(project_id).await?;
        let active_session =
            self.runtime_sessions
                .lock()
                .await
                .iter()
                .find_map(|(session_id, runtime)| {
                    (runtime.project_id == project_id
                        && runtime.persistent
                        && runtime.profile.as_deref() == Some(profile))
                    .then_some(BrowserSessionId(*session_id))
                });
        if let Some(session_id) = active_session {
            self.stop_inner(project_id, session_id).await?;
        }

        let lease = (project_id.get(), profile.to_string());
        {
            let mut leases = self.profile_leases.lock().await;
            if !leases.insert(lease.clone()) {
                return Err(DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    format!(
                        "browser profile '{profile}' is starting or active; stop it before resetting it"
                    ),
                ));
            }
        }

        let result = {
            let _guard = self.profile_io.lock().await;
            let state_target = if profile == DEFAULT_BROWSER_PROFILE {
                self.profile_state_path(project_id, profile)
            } else {
                self.profile_directory(project_id, profile)
            };
            let removed_state = remove_browser_profile_path(&state_target);
            let removed_chromium =
                remove_browser_profile_path(&self.chromium_profile_path(project_id, profile));
            match (removed_state, removed_chromium) {
                (Ok(state), Ok(chromium)) => {
                    if profile != DEFAULT_BROWSER_PROFILE {
                        create_private_dir(&self.profile_directory(project_id, profile))
                            .map(|()| state || chromium)
                    } else {
                        Ok(state || chromium)
                    }
                }
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        };
        self.profile_leases.lock().await.remove(&lease);
        result
    }

    /// Atomically stop all browsers, remove every persistent identity, and
    /// delete the project while new browser starts remain blocked.
    pub async fn delete_project(&self, project_id: ProjectId) -> DomainResult<()> {
        let _lifecycle = self.lifecycle.lock().await;
        self.db.get_project(project_id).await?;
        let sessions = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, runtime)| {
                (runtime.project_id == project_id).then_some((project_id, BrowserSessionId(*id)))
            })
            .collect::<Vec<_>>();
        self.stop_sessions_inner(sessions).await?;
        {
            let _profile_io = self.profile_io.lock().await;
            remove_browser_profile_path(&self.project_profile_dir(project_id))?;
        }
        self.profile_leases
            .lock()
            .await
            .retain(|(id, _)| *id != project_id.get());
        self.db.delete_project(project_id).await
    }

    async fn save_checkpoint(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        value: &Value,
        status: &str,
        profile: Option<&str>,
    ) -> DomainResult<Checkpoint> {
        let mut checkpoint = decode_checkpoint(value)?;
        let mut checkpoints = self.checkpoints.lock().await;
        checkpoint.version = checkpoints
            .get(&session_id.get())
            .map_or(1, |previous| previous.version.saturating_add(1));
        checkpoint.hash = checkpoint_hash(&checkpoint)?;
        checkpoints.insert(session_id.get(), checkpoint.clone());
        drop(checkpoints);
        if let Some(profile) = profile {
            self.persist_checkpoint(project_id, profile, &checkpoint)
                .await?;
        }
        self.db
            .update_browser_checkpoint_metadata(
                project_id,
                session_id,
                checkpoint.url.clone(),
                checkpoint.title.clone(),
                status.to_string(),
                checkpoint.hash.clone(),
                checkpoint.version,
            )
            .await?;
        Ok(checkpoint)
    }
}

fn schedule_page_title_association(db: Arc<Db>, session: &BrowserSession) {
    let (Some(url), Some(title)) = (session.current_url.clone(), session.current_title.clone())
    else {
        return;
    };
    let project_id = session.project_id;
    let session_id = session.id;
    tokio::spawn(async move {
        // Browser navigation and proxy response persistence finish on separate
        // tasks. Retry briefly so either completion order produces a title.
        for delay in [0, 50, 150, 400, 1_000, 2_500] {
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            match db
                .associate_browser_page_title(project_id, session_id, &url, &title)
                .await
            {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => {
                    tracing::debug!(%error, session_id = session_id.get(), "could not associate browser page title");
                    break;
                }
            }
        }
    });
}

fn decode_checkpoint(value: &Value) -> DomainResult<Checkpoint> {
    let private = value.get("_private").ok_or_else(|| {
        DomainError::new(ErrorCode::ProtocolError, "checkpoint missing private state")
    })?;
    let cookies = private
        .get("cookies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let local_storage: BTreeMap<String, String> = serde_json::from_value(
        private
            .get("local_storage")
            .cloned()
            .unwrap_or_else(|| json!({})),
    )
    .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
    let session_storage: BTreeMap<String, String> = serde_json::from_value(
        private
            .get("session_storage")
            .cloned()
            .unwrap_or_else(|| json!({})),
    )
    .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
    let origin = private
        .get("origin")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut local_by_origin = BTreeMap::new();
    if let Some(origin) = origin {
        local_by_origin.insert(origin, local_storage);
    }
    Ok(Checkpoint {
        url: value.get("url").and_then(Value::as_str).map(str::to_string),
        title: value
            .get("title")
            .and_then(Value::as_str)
            .filter(|title| !title.is_empty())
            .map(str::to_string),
        cookies,
        local_storage: local_by_origin,
        session_storage,
        version: 0,
        hash: String::new(),
    })
}

fn checkpoint_hash(checkpoint: &Checkpoint) -> DomainResult<String> {
    let mut cookies = checkpoint.cookies.clone();
    cookies.sort_by_key(|cookie| serde_json::to_string(cookie).unwrap_or_default());
    let hashable = json!({
        "url": checkpoint.url.clone(),
        "title": checkpoint.title.clone(),
        "cookies": cookies,
        "local_storage": checkpoint.local_storage.clone(),
        "session_storage": checkpoint.session_storage.clone(),
    });
    let encoded = serde_json::to_vec(&hashable)
        .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn default_profiles_root(db: &Db) -> PathBuf {
    db.path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| path.join("browser-profiles"))
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("huntproxy-browser-profiles-{}", std::process::id()))
        })
}

fn validate_browser_profile_name(profile: &str) -> DomainResult<()> {
    if (1..=64).contains(&profile.len())
        && profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(());
    }
    Err(DomainError::invalid(
        "browser profile must be 1-64 ASCII letters, numbers, '_' or '-'",
    ))
}

fn remove_browser_profile_path(path: &Path) -> DomainResult<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(DomainError::new(
                ErrorCode::StorageError,
                format!("inspect browser profile: {error}"),
            ))
        }
    };
    let result = if metadata.file_type().is_symlink() || metadata.is_file() {
        std::fs::remove_file(path)
    } else {
        std::fs::remove_dir_all(path)
    };
    result.map_err(|error| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("remove browser profile: {error}"),
        )
    })?;
    Ok(true)
}

fn verify_worker_identity(
    result: &Value,
    session_id: BrowserSessionId,
    profile: Option<&str>,
    directory: Option<&Path>,
) -> DomainResult<()> {
    let directory = directory.map(|path| path.to_string_lossy());
    if result.get("session_id").and_then(Value::as_i64) != Some(session_id.get())
        || result.get("requested_profile").and_then(Value::as_str) != profile
        || result.get("active_profile").and_then(Value::as_str) != profile
        || result.get("profile_dir").and_then(Value::as_str) != directory.as_deref()
        || result.get("persistent").and_then(Value::as_bool) != Some(profile.is_some())
    {
        return Err(DomainError::new(ErrorCode::ProtocolError,
            "browser worker cannot guarantee the requested profile is active; session identity or profile directory mismatch"));
    }
    Ok(())
}

fn chromium_profile_has_state(profile_dir: &Path) -> bool {
    profile_dir.join("Local State").is_file()
        || profile_dir
            .join("Default")
            .read_dir()
            .is_ok_and(|mut entries| entries.next().is_some())
}

fn merge_persistent_profile(profile: &mut PersistentBrowserProfile, checkpoint: &Checkpoint) {
    profile.version = profile.version.saturating_add(1);
    profile.checkpoint_hash.clone_from(&checkpoint.hash);
    profile.last_url.clone_from(&checkpoint.url);
    profile.cookies.clone_from(&checkpoint.cookies);
    for (origin, values) in &checkpoint.local_storage {
        profile.local_storage.insert(origin.clone(), values.clone());
    }
    if let Some(origin) = checkpoint.local_storage.keys().next() {
        profile
            .session_storage
            .insert(origin.clone(), checkpoint.session_storage.clone());
    }
}

fn browser_cookies(profiles: &[StoredCookieProfile]) -> DomainResult<Vec<Value>> {
    let mut output = BTreeMap::<(String, String, String), Value>::new();
    for profile in profiles {
        if let Some(cookies) = &profile.managed_cookies {
            for cookie in cookies {
                let mut value = serde_json::Map::from_iter([
                    ("name".into(), json!(cookie.name)),
                    ("value".into(), json!(cookie.value)),
                    (
                        "domain".into(),
                        json!(if cookie.host_only {
                            cookie.domain.clone()
                        } else {
                            format!(".{}", cookie.domain)
                        }),
                    ),
                    ("path".into(), json!(cookie.path)),
                    ("httpOnly".into(), json!(cookie.http_only)),
                    ("secure".into(), json!(cookie.secure)),
                ]);
                if let Some(same_site) = &cookie.same_site {
                    value.insert("sameSite".into(), json!(same_site));
                }
                if let Some(expires) = cookie.expires {
                    value.insert("expires".into(), json!(expires));
                }
                output.insert(
                    (
                        cookie.name.clone(),
                        if cookie.host_only {
                            cookie.domain.clone()
                        } else {
                            format!(".{}", cookie.domain)
                        },
                        cookie.path.clone(),
                    ),
                    Value::Object(value),
                );
            }
            continue;
        }
        // A Cookie header can contain duplicate names from different paths,
        // but it carries no path metadata. For browser import, the last value
        // wins and becomes a host-only, root-path session cookie.
        let mut pairs = BTreeMap::<String, CookiePair>::new();
        for pair in profile.pairs()? {
            pairs.insert(pair.name.clone(), pair);
        }
        for pair in pairs.into_values() {
            output.insert(
                (pair.name.clone(), profile.host.clone(), "/".into()),
                json!({
                    "name": pair.name,
                    "value": pair.value,
                    "url": profile.target_url,
                }),
            );
        }
    }
    Ok(output.into_values().collect())
}

fn cookie_identities(cookies: &[crate::cookies::ManagedCookie]) -> Vec<Value> {
    cookies
        .iter()
        .map(|cookie| {
            json!({
                "name": cookie.name,
                "domain": if cookie.host_only {
                    cookie.domain.clone()
                } else {
                    format!(".{}", cookie.domain)
                },
                "path": cookie.path,
            })
        })
        .collect()
}

fn profile_cookie_identities(profile: &StoredCookieProfile) -> DomainResult<Vec<Value>> {
    if let Some(cookies) = &profile.managed_cookies {
        return Ok(cookie_identities(cookies));
    }
    Ok(profile
        .pairs()?
        .into_iter()
        .map(|pair| {
            json!({
                "name": pair.name,
                "domain": profile.host,
                "path": "/",
            })
        })
        .collect())
}

fn parse_cdp_info(value: Option<&Value>) -> DomainResult<BrowserCdpInfo> {
    let info: BrowserCdpInfo = serde_json::from_value(value.cloned().ok_or_else(|| {
        DomainError::new(
            ErrorCode::ProtocolError,
            "browser worker omitted CDP details",
        )
    })?)
    .map_err(|error| {
        DomainError::new(
            ErrorCode::ProtocolError,
            format!("browser worker returned invalid CDP details: {error}"),
        )
    })?;
    if info.port != BROWSER_CDP_PORT
        || info.endpoint != format!("http://127.0.0.1:{BROWSER_CDP_PORT}")
        || info.devtools_url.len() > 4_096
        || info.hosted_devtools_url.len() > 4_096
        || !info.devtools_url.starts_with(&format!(
            "http://127.0.0.1:{BROWSER_CDP_PORT}/devtools/inspector.html?ws=127.0.0.1:{BROWSER_CDP_PORT}/devtools/page/"
        ))
        || !info
            .hosted_devtools_url
            .starts_with("https://chrome-devtools-frontend.appspot.com/")
    {
        return Err(DomainError::new(
            ErrorCode::ProtocolError,
            "browser worker returned unexpected CDP details",
        ));
    }
    Ok(info)
}

fn browser_resources(
    project_id: ProjectId,
    max_concurrent_browsers: u32,
    sessions: &[BrowserSession],
    runtimes: &HashMap<i64, RuntimeSession>,
) -> DomainResult<BrowserResources> {
    let mut active_persistent = 0;
    let mut active_ephemeral = 0;
    for runtime in runtimes
        .values()
        .filter(|runtime| runtime.project_id == project_id)
    {
        if runtime.persistent {
            active_persistent += 1;
        } else {
            active_ephemeral += 1;
        }
    }
    let mut resources = Vec::with_capacity(sessions.len());
    for session in sessions {
        let runtime = runtimes.get(&session.id.get()).ok_or_else(|| {
            DomainError::new(
                ErrorCode::Unavailable,
                "requested browser profile is not active",
            )
        })?;
        let profile = session.active_profile.as_ref().ok_or_else(|| {
            DomainError::new(
                ErrorCode::ProtocolError,
                "active browser profile was not verified",
            )
        })?;
        if session.project_id != project_id
            || runtime.project_id != project_id
            || !runtime.persistent
            || runtime.profile.as_ref() != Some(profile)
            || session.profile.as_ref() != Some(profile)
            || !matches!(
                session.state,
                BrowserSessionState::Ready
                    | BrowserSessionState::Busy
                    | BrowserSessionState::Starting
            )
        {
            return Err(DomainError::new(
                ErrorCode::ProtocolError,
                "requested browser profile does not match the active runtime",
            ));
        }
        resources.push(BrowserSessionResource {
            session_id: session.id,
            profile: profile.clone(),
            agent_control: runtime.cdp.is_none(),
        });
    }
    if resources.len() != active_persistent {
        return Err(DomainError::new(
            ErrorCode::Unavailable,
            "active browser sessions changed during status verification",
        ));
    }
    Ok(BrowserResources {
        project_id,
        max_concurrent_browsers,
        active_persistent,
        active_ephemeral,
        available_capacity: (max_concurrent_browsers as usize)
            .saturating_sub(active_persistent + active_ephemeral),
        cdp_port_in_use: runtimes.values().any(|runtime| runtime.cdp.is_some()),
        sessions: resources,
    })
}

fn cdp_status_view(
    project_id: ProjectId,
    active: Option<(i64, BrowserCdpInfo)>,
) -> BrowserCdpStatus {
    match active {
        Some((session_id, cdp)) => BrowserCdpStatus {
            project_id,
            active: true,
            agent_control: false,
            session_id: Some(BrowserSessionId(session_id)),
            endpoint: Some(cdp.endpoint),
            devtools_url: Some(cdp.devtools_url),
            hosted_devtools_url: Some(cdp.hosted_devtools_url),
            ssh_forward_command: ssh_forward_command(),
        },
        None => BrowserCdpStatus {
            project_id,
            active: false,
            agent_control: true,
            session_id: None,
            endpoint: None,
            devtools_url: None,
            hosted_devtools_url: None,
            ssh_forward_command: None,
        },
    }
}

fn ssh_forward_command() -> Option<String> {
    let user = runtime_username()?;
    let ip = runtime_host_ip()?;
    let host = match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    Some(format!("ssh -N -L 9222:127.0.0.1:9222 {user}@{host}"))
}

fn runtime_username() -> Option<String> {
    (|| {
        let output = StdCommand::new("id").arg("-un").output().ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    })()
    .filter(|value| valid_ssh_username(value))
    .or_else(|| {
        ["USER", "LOGNAME"]
            .into_iter()
            .filter_map(|name| std::env::var(name).ok())
            .map(|value| value.trim().to_owned())
            .find(|value| valid_ssh_username(value))
    })
    .filter(|value| valid_ssh_username(value))
}

fn valid_ssh_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn runtime_host_ip() -> Option<IpAddr> {
    if let Some(ip) = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|connection| ssh_server_ip(&connection))
    {
        return Some(ip);
    }
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
}

fn ssh_server_ip(connection: &str) -> Option<IpAddr> {
    connection.split_whitespace().nth(2)?.parse().ok()
}

fn existing_path(configured: Option<PathBuf>, executable_name: &str) -> Option<PathBuf> {
    configured
        .filter(|path| path.exists())
        .or_else(|| which(executable_name))
        .or_else(|| {
            let executable = std::env::current_exe().ok()?;
            let sibling = executable.parent()?.join(executable_name);
            sibling.is_file().then_some(sibling)
        })
        .map(|path| path.canonicalize().unwrap_or(path))
}

fn chromium_executable(playwright_core_path: Option<&Path>) -> Option<PathBuf> {
    [
        "HUNTPROXY_CHROME_EXECUTABLE",
        "BB_CHROME_EXECUTABLE",
        "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH",
    ]
    .iter()
    .find_map(|name| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|path| path.exists())
    })
    .or_else(|| {
        playwright_core_path.and_then(|path| find_chromium_binary(&path.join(".local-browsers"), 8))
    })
    .or_else(|| {
        [
            "google-chrome-stable",
            "google-chrome",
            "chromium",
            "chromium-browser",
        ]
        .iter()
        .find_map(|name| which(name))
    })
    .or_else(|| {
        [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
    })
    .or_else(|| find_playwright_chromium(playwright_core_path))
}

fn find_playwright_chromium(playwright_core_path: Option<&Path>) -> Option<PathBuf> {
    let mut roots = Vec::new();
    if let Some(path) = std::env::var_os("PLAYWRIGHT_BROWSERS_PATH") {
        if path != "0" {
            roots.push(PathBuf::from(path));
        }
    }
    if let Some(path) = playwright_core_path {
        roots.push(path.join(".local-browsers"));
        if let Some(parent) = path.parent() {
            roots.push(parent.join(".local-browsers"));
        }
    }
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME") {
        roots.push(PathBuf::from(path).join("ms-playwright"));
    }
    if let Some(path) = std::env::var_os("HOME") {
        let home = PathBuf::from(path);
        roots.push(home.join(".cache/ms-playwright"));
        roots.push(home.join("Library/Caches/ms-playwright"));
    }
    if let Some(path) = std::env::var_os("LOCALAPPDATA") {
        roots.push(PathBuf::from(path).join("ms-playwright"));
    }

    roots.into_iter().find_map(|root| {
        let mut browser_directories = std::fs::read_dir(root)
            .ok()?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("chromium-"))
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        browser_directories.sort_by(|left, right| right.cmp(left));
        browser_directories
            .into_iter()
            .find_map(|directory| find_chromium_binary(&directory, 8))
    })
}

fn find_chromium_binary(directory: &Path, remaining_depth: usize) -> Option<PathBuf> {
    if remaining_depth == 0 {
        return None;
    }
    let mut entries = std::fs::read_dir(directory)
        .ok()?
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in &entries {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name();
        if matches!(
            name.to_str(),
            Some("chrome" | "chromium" | "chrome.exe" | "Chromium" | "Google Chrome for Testing")
        ) {
            return Some(path);
        }
    }
    entries.into_iter().find_map(|entry| {
        let path = entry.path();
        path.is_dir()
            .then(|| find_chromium_binary(&path, remaining_depth - 1))
            .flatten()
    })
}

fn resolve_worker_path(explicit: Option<PathBuf>) -> Option<PathBuf> {
    let mut candidates = worker_path_candidates(explicit);
    if let Ok(materialized) = materialize_embedded_worker(&crate::config::default_data_dir()) {
        candidates.push(materialized);
    }
    append_source_worker_candidate(&mut candidates);
    first_existing_worker(candidates)
}

fn inspect_worker_path(explicit: Option<PathBuf>, data_dir: &Path) -> Option<PathBuf> {
    let managed = explicit.or_else(|| Some(browser_worker_path(data_dir)));
    let mut candidates = worker_path_candidates(managed);
    append_source_worker_candidate(&mut candidates);
    first_existing_worker(candidates)
}

fn worker_path_candidates(explicit: Option<PathBuf>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = explicit {
        candidates.push(path);
    }
    if let Some(path) = std::env::var_os("HUNTPROXY_BROWSER_WORKER_PATH")
        .or_else(|| std::env::var_os("BB_BROWSER_WORKER_PATH"))
    {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(bin_dir) = executable.parent() {
            candidates.push(bin_dir.join("browser-worker/index.js"));
            candidates.push(bin_dir.join("../libexec/huntproxy/browser-worker/index.js"));
            candidates.push(bin_dir.join("../share/huntproxy/browser-worker/index.js"));
            candidates.push(bin_dir.join("../share/bb/browser-worker/index.js"));
        }
    }
    candidates
}

fn append_source_worker_candidate(candidates: &mut Vec<PathBuf>) {
    if let Ok(current) = std::env::current_dir() {
        candidates.push(current.join("browser-worker/index.js"));
    }
}

fn first_existing_worker(candidates: Vec<PathBuf>) -> Option<PathBuf> {
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .map(|path| path.canonicalize().unwrap_or(path))
}

fn browser_worker_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join(format!("browser-worker-{}", env!("CARGO_PKG_VERSION")))
        .join("index.js")
}

/// Materialize the version-matched worker and package manifest in a stable,
/// per-user location. The CLI install command should run `npm install` in the
/// returned directory instead of relying on its current working directory.
pub fn prepare_browser_worker_installation(data_dir: &Path) -> DomainResult<PathBuf> {
    let worker = materialize_embedded_worker(data_dir).map_err(|error| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("prepare browser worker: {error}"),
        )
    })?;
    worker
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| DomainError::new(ErrorCode::Internal, "worker directory unavailable"))
}

fn materialize_embedded_worker(data_dir: &Path) -> std::io::Result<PathBuf> {
    let worker_path = browser_worker_path(data_dir);
    let directory = worker_path
        .parent()
        .expect("browser worker path always has a parent");
    std::fs::create_dir_all(directory)?;
    let package_path = directory.join("package.json");
    let lock_path = directory.join("package-lock.json");
    write_if_changed(&worker_path, EMBEDDED_WORKER.as_bytes())?;
    write_if_changed(&package_path, EMBEDDED_WORKER_PACKAGE.as_bytes())?;
    write_if_changed(&lock_path, EMBEDDED_WORKER_LOCK.as_bytes())?;
    Ok(worker_path)
}

fn write_if_changed(path: &Path, content: &[u8]) -> std::io::Result<()> {
    if std::fs::read(path).ok().as_deref() == Some(content) {
        return Ok(());
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, content)?;
    std::fs::rename(temporary, path)
}

fn find_playwright_from_environment() -> Option<PathBuf> {
    std::env::var_os("HUNTPROXY_PLAYWRIGHT_CORE_PATH")
        .or_else(|| std::env::var_os("BB_PLAYWRIGHT_CORE_PATH"))
        .map(PathBuf::from)
        .filter(|path| path.exists())
}

fn find_playwright_core(worker_path: &Path) -> Option<PathBuf> {
    worker_path.parent().and_then(|directory| {
        directory.ancestors().find_map(|ancestor| {
            let package = ancestor.join("node_modules/playwright-core/package.json");
            package
                .exists()
                .then(|| ancestor.join("node_modules/playwright-core"))
        })
    })
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|directory| {
            let path = directory.join(name);
            path.is_file().then_some(path)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_action_has_agent_friendly_defaults() {
        let action: BrowserAction = serde_json::from_value(json!({ "type": "snapshot" })).unwrap();
        match action {
            BrowserAction::Snapshot { format, max_bytes } => {
                assert_eq!(format, "accessibility");
                assert_eq!(max_bytes, 200_000);
            }
            _ => panic!("wrong browser action"),
        }
    }

    #[test]
    fn structured_browser_actions_have_bounded_defaults() {
        let request: BrowserAction = serde_json::from_value(json!({
            "type": "request",
            "method": "POST",
            "url": "https://example.com/api/items"
        }))
        .unwrap();
        match &request {
            BrowserAction::Request {
                headers,
                timeout_ms,
                max_response_bytes,
                ..
            } => {
                assert!(headers.is_empty());
                assert_eq!(*timeout_ms, 15_000);
                assert_eq!(*max_response_bytes, 4096);
            }
            _ => panic!("wrong browser action"),
        }
        validate_browser_action(&request).unwrap();

        let events: BrowserAction = serde_json::from_value(json!({"type":"events"})).unwrap();
        match &events {
            BrowserAction::Events {
                after_sequence,
                limit,
                wait_ms,
                ..
            } => {
                assert_eq!(*after_sequence, 0);
                assert_eq!(*limit, 50);
                assert_eq!(*wait_ms, 0);
            }
            _ => panic!("wrong browser action"),
        }
        validate_browser_action(&events).unwrap();
    }

    #[test]
    fn structured_browser_actions_reject_ambiguous_or_unsafe_inputs() {
        for value in [
            json!({"type":"pages","op":"select","page_id":0,"runtime_generation":1}),
            json!({"type":"pages","op":"new","url":"file:///etc/passwd"}),
            json!({"type":"events","after_sequence":1}),
            json!({"type":"events","runtime_generation":0}),
            json!({"type":"scroll"}),
            json!({"type":"screenshot","full_page":true,"locator":{"css":"main"}}),
            json!({"type":"request","method":"GET","url":"https://example.com/","body_text":"data"}),
            json!({"type":"request","method":"GET","url":"https://example.com/","body_text":""}),
            json!({"type":"request","method":"POST","url":"https://user@example.com/"}),
            json!({"type":"request","method":"POST","url":"https://example.com/","body_text":"a","body_base64":"Yg=="}),
            json!({"type":"request","method":"POST","url":"https://example.com/","body_base64":"not base64"}),
            json!({"type":"request","method":"POST","url":"https://example.com/","headers":[{"name":"Cookie","value":"sid=1"}]}),
            json!({"type":"request","method":"POST","url":"https://example.com/","headers":[{"name":"Connection","value":"close"}]}),
            json!({"type":"request","method":"POST","url":"https://example.com/","headers":[{"name":"Sec-Fetch-Site","value":"same-origin"}]}),
            json!({"type":"request","method":"POST","url":"https://example.com/","headers":[{"name":"X-HTTP-Method-Override","value":"PATCH, TRACE"}]}),
            json!({"type":"request","method":"POST","url":"https://example.com/","headers":[{"name":"x-note","value":"one"},{"name":"X-Note","value":"two"}]}),
        ] {
            let action: BrowserAction = serde_json::from_value(value).unwrap();
            assert!(validate_browser_action(&action).is_err());
        }
        assert!(serde_json::from_value::<BrowserAction>(json!({
            "type":"request",
            "method":"POST",
            "url":"https://example.com/",
            "headers":[{"name":"x-test","value":"ok","extra":true}]
        }))
        .is_err());
    }

    #[test]
    fn decodes_checkpoint_without_exposing_private_shape() {
        let value = json!({
            "url": "https://example.com/app",
            "title": "Example application",
            "_private": {
                "origin": "https://example.com",
                "cookies": [{"name":"sid","value":"secret"}],
                "local_storage": {"theme":"dark"},
                "session_storage": {"csrf":"secret"}
            }
        });
        let checkpoint = decode_checkpoint(&value).unwrap();
        assert_eq!(checkpoint.url.as_deref(), Some("https://example.com/app"));
        assert_eq!(checkpoint.title.as_deref(), Some("Example application"));
        assert_eq!(checkpoint.cookies.len(), 1);
        assert_eq!(
            checkpoint.local_storage["https://example.com"]["theme"],
            "dark"
        );
        assert_eq!(checkpoint.session_storage["csrf"], "secret");
    }

    #[tokio::test]
    async fn browser_session_title_round_trips_for_client_reattachment() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "reattach".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let mut session = db
            .create_browser_session(project.id, Some(DEFAULT_BROWSER_PROFILE.into()))
            .await
            .unwrap();
        session.current_url = Some("https://example.test/dashboard".into());
        session.current_title = Some("Dashboard".into());
        session.state = BrowserSessionState::Ready;
        db.update_browser_session(&session).await.unwrap();

        let restored = db
            .get_browser_session(project.id, session.id)
            .await
            .unwrap();
        assert_eq!(restored.profile.as_deref(), Some(DEFAULT_BROWSER_PROFILE));
        assert_eq!(restored.current_url, session.current_url);
        assert_eq!(restored.current_title.as_deref(), Some("Dashboard"));
        assert_eq!(restored.engine, BrowserEngine::Chromium);
        assert_eq!(restored.state, BrowserSessionState::Ready);
    }

    #[tokio::test]
    async fn browser_resources_count_ephemeral_capacity_and_hide_foreign_cdp_identity() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "Resource observation".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let mut session = db
            .create_browser_session(project.id, Some("account1".into()))
            .await
            .unwrap();
        session.active_profile = Some("account1".into());
        session.state = BrowserSessionState::Ready;
        session.current_url = Some("https://example.test/private?value=hidden".into());
        session.current_title = Some("Private page".into());
        let cdp = BrowserCdpInfo {
            port: BROWSER_CDP_PORT,
            endpoint: "http://127.0.0.1:9222".into(),
            devtools_url: "foreign-devtools".into(),
            hosted_devtools_url: "foreign-hosted-devtools".into(),
        };
        let mut runtimes = HashMap::from([
            (
                session.id.get(),
                RuntimeSession {
                    project_id: project.id,
                    capture_session_id: CaptureSessionId(1),
                    persistent: true,
                    profile: Some("account1".into()),
                    cdp: None,
                },
            ),
            (
                session.id.get() + 1,
                RuntimeSession {
                    project_id: project.id,
                    capture_session_id: CaptureSessionId(2),
                    persistent: false,
                    profile: None,
                    cdp: None,
                },
            ),
            (
                999,
                RuntimeSession {
                    project_id: ProjectId(project.id.get() + 1),
                    capture_session_id: CaptureSessionId(3),
                    persistent: true,
                    profile: Some("foreign-account".into()),
                    cdp: Some(cdp.clone()),
                },
            ),
        ]);
        let observed = browser_resources(project.id, 2, &[session.clone()], &runtimes).unwrap();
        assert_eq!(
            serde_json::to_value(observed).unwrap(),
            json!({
                "project_id": project.id,
                "max_concurrent_browsers": 2,
                "active_persistent": 1,
                "active_ephemeral": 1,
                "available_capacity": 0,
                "cdp_port_in_use": true,
                "sessions": [{"session_id": session.id, "profile": "account1", "agent_control": true}],
            })
        );

        runtimes.remove(&(session.id.get() + 1));
        runtimes.remove(&999);
        let observed = browser_resources(project.id, 2, &[session.clone()], &runtimes).unwrap();
        assert_eq!(observed.available_capacity, 1);
        assert!(!observed.cdp_port_in_use);
        runtimes.get_mut(&session.id.get()).unwrap().cdp = Some(cdp);
        let observed = browser_resources(project.id, 0, &[session.clone()], &runtimes).unwrap();
        assert_eq!(observed.available_capacity, 0);
        assert!(!observed.sessions[0].agent_control);
        assert!(observed.cdp_port_in_use);

        let mut unverified = session.clone();
        unverified.active_profile = None;
        assert!(browser_resources(project.id, 2, &[unverified], &runtimes).is_err());
        let mut mismatched = session.clone();
        mismatched.active_profile = Some("account2".into());
        assert!(browser_resources(project.id, 2, &[mismatched], &runtimes).is_err());
        assert!(browser_resources(project.id, 2, &[], &runtimes).is_err());
        runtimes.clear();
        let error = browser_resources(project.id, 2, &[session], &runtimes).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn browser_resource_status_wait_does_not_block_other_project_lifecycle() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "Busy local workspace".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let other_project = db
            .create_project(CreateProjectRequest {
                name: "Other local workspace".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let own = db
            .create_browser_session(project.id, Some("default".into()))
            .await
            .unwrap();
        let other = db
            .create_browser_session(other_project.id, Some("default".into()))
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            Some(directory.path().join("missing-worker.js")),
            DEFAULT_BROWSER_PROXY.into(),
            None,
            directory.path().join("profiles"),
        );
        service.runtime_sessions.lock().await.insert(
            own.id.get(),
            RuntimeSession {
                project_id: project.id,
                capture_session_id: CaptureSessionId(1),
                persistent: true,
                profile: Some("default".into()),
                cdp: None,
            },
        );
        let operation = service.session_operation_lock(own.id).await;
        let operation_guard = operation.lock().await;
        let observation = service.active_status(project.id);
        tokio::pin!(observation);
        // Poll status until it is waiting for the busy session. Cancellation
        // here only drops the timer; the observation future remains pinned.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut observation)
                .await
                .is_err()
        );
        tokio::time::timeout(
            Duration::from_secs(1),
            service.stop(other_project.id, other.id),
        )
        .await
        .expect("status blocked an unrelated project's lifecycle")
        .unwrap();
        drop(operation_guard);
        // This fixture has no live worker or directory, so normal identity
        // verification still returns its existing unavailable error.
        assert_eq!(
            observation.await.unwrap_err().code(),
            ErrorCode::Unavailable
        );
    }

    #[test]
    fn checkpoint_hash_excludes_version_and_hash_fields() {
        let mut checkpoint = Checkpoint {
            url: Some("https://example.com".into()),
            cookies: vec![json!({"name":"sid","value":"secret"})],
            ..Default::default()
        };
        let first = checkpoint_hash(&checkpoint).unwrap();
        checkpoint.version = 99;
        checkpoint.hash = "old".into();
        assert_eq!(first, checkpoint_hash(&checkpoint).unwrap());
    }

    #[test]
    fn cdp_details_are_bounded_and_status_makes_control_ownership_explicit() {
        let info = parse_cdp_info(Some(&json!({
            "port": 9222,
            "endpoint": "http://127.0.0.1:9222",
            "devtools_url": "http://127.0.0.1:9222/devtools/inspector.html?ws=127.0.0.1:9222/devtools/page/1",
            "hosted_devtools_url": "https://chrome-devtools-frontend.appspot.com/serve_rev/@abc/inspector.html?ws=127.0.0.1:9222/devtools/page/1"
        })))
        .unwrap();
        let handed_off = cdp_status_view(ProjectId(7), Some((9, info)));
        assert!(handed_off.active);
        assert!(!handed_off.agent_control);
        assert_eq!(handed_off.session_id, Some(BrowserSessionId(9)));
        let command = handed_off.ssh_forward_command.unwrap();
        assert!(command.starts_with("ssh -N -L 9222:127.0.0.1:9222 "));
        assert!(command.contains('@'));

        let available = cdp_status_view(ProjectId(7), None);
        assert!(!available.active);
        assert!(available.agent_control);
        assert!(parse_cdp_info(Some(&json!({
            "port": 9223,
            "endpoint": "http://127.0.0.1:9223",
            "devtools_url": "https://example.test/",
            "hosted_devtools_url": "https://example.test/"
        })))
        .is_err());
    }

    #[test]
    fn ssh_connection_server_address_is_parsed_at_runtime() {
        assert_eq!(
            ssh_server_ip("192.0.2.10 54321 198.51.100.20 22"),
            Some("198.51.100.20".parse().unwrap())
        );
        assert_eq!(ssh_server_ip("invalid"), None);
    }

    #[test]
    fn persistent_profile_merges_origins_and_replaces_the_cookie_jar() {
        let mut profile = PersistentBrowserProfile::default();
        let first = Checkpoint {
            url: Some("https://one.test/app".into()),
            cookies: vec![json!({"name":"one","value":"1","domain":"one.test","path":"/"})],
            local_storage: BTreeMap::from([(
                "https://one.test".into(),
                BTreeMap::from([("theme".into(), "dark".into())]),
            )]),
            session_storage: BTreeMap::from([("nonce".into(), "first".into())]),
            ..Default::default()
        };
        merge_persistent_profile(&mut profile, &first);

        let second = Checkpoint {
            url: Some("https://two.test/".into()),
            cookies: vec![json!({"name":"two","value":"2","domain":"two.test","path":"/"})],
            local_storage: BTreeMap::from([(
                "https://two.test".into(),
                BTreeMap::from([("visit".into(), "2".into())]),
            )]),
            session_storage: BTreeMap::from([("nonce".into(), "second".into())]),
            ..Default::default()
        };
        merge_persistent_profile(&mut profile, &second);

        assert_eq!(profile.version, 2);
        assert_eq!(profile.last_url.as_deref(), Some("https://two.test/"));
        assert_eq!(profile.cookies.len(), 1);
        assert_eq!(profile.cookies[0]["name"], "two");
        assert_eq!(profile.local_storage["https://one.test"]["theme"], "dark");
        assert_eq!(profile.local_storage["https://two.test"]["visit"], "2");
        assert_eq!(
            profile.session_storage["https://one.test"]["nonce"],
            "first"
        );
        assert_eq!(
            profile.session_storage["https://two.test"]["nonce"],
            "second"
        );
    }

    #[tokio::test]
    async fn persistent_profile_file_round_trips_privately() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        let project_id = ProjectId(42);
        let checkpoint = Checkpoint {
            url: Some("https://example.test/".into()),
            cookies: vec![
                json!({"name":"sid","value":"secret","domain":"example.test","path":"/"}),
            ],
            local_storage: BTreeMap::from([(
                "https://example.test".into(),
                BTreeMap::from([("key".into(), "value".into())]),
            )]),
            ..Default::default()
        };

        service
            .persist_checkpoint(project_id, DEFAULT_BROWSER_PROFILE, &checkpoint)
            .await
            .unwrap();
        let loaded = service
            .load_persistent_profile(project_id, DEFAULT_BROWSER_PROFILE)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.last_url, checkpoint.url);
        assert_eq!(loaded.cookies, checkpoint.cookies);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                std::fs::metadata(service.profile_state_path(project_id, DEFAULT_BROWSER_PROFILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[tokio::test]
    async fn named_browser_profiles_persist_independently() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "named profiles".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        service
            .create_browser_profile(project.id, "account1")
            .await
            .unwrap();
        service
            .create_browser_profile(project.id, "account2")
            .await
            .unwrap();

        let first = Checkpoint {
            url: Some("https://example.test/account1".into()),
            cookies: vec![json!({"name":"sid","value":"one"})],
            ..Default::default()
        };
        let second = Checkpoint {
            url: Some("https://example.test/account2".into()),
            cookies: vec![json!({"name":"sid","value":"two"})],
            ..Default::default()
        };
        service
            .persist_checkpoint(project.id, "account1", &first)
            .await
            .unwrap();
        service
            .persist_checkpoint(project.id, "account2", &second)
            .await
            .unwrap();

        let first_loaded = service
            .load_persistent_profile(project.id, "account1")
            .await
            .unwrap()
            .unwrap();
        let second_loaded = service
            .load_persistent_profile(project.id, "account2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_loaded.last_url, first.url);
        assert_eq!(second_loaded.last_url, second.url);
        assert_eq!(first_loaded.cookies[0]["value"], "one");
        assert_eq!(second_loaded.cookies[0]["value"], "two");
        assert_ne!(
            service.profile_state_path(project.id, "account1"),
            service.profile_state_path(project.id, "account2")
        );

        let profiles = service.browser_profiles(project.id).await.unwrap();
        assert_eq!(
            profiles
                .iter()
                .map(|profile| profile.name.as_str())
                .collect::<Vec<_>>(),
            vec!["default", "account1", "account2"]
        );
        assert!(profiles
            .iter()
            .filter(|profile| profile.name != DEFAULT_BROWSER_PROFILE)
            .all(|profile| profile.has_state));
    }

    #[tokio::test]
    async fn resetting_one_named_profile_preserves_other_identities() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "profile reset isolation".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        for (profile, url) in [
            (DEFAULT_BROWSER_PROFILE, "https://example.test/default"),
            ("account1", "https://example.test/one"),
            ("account2", "https://example.test/two"),
        ] {
            service
                .persist_checkpoint(
                    project.id,
                    profile,
                    &Checkpoint {
                        url: Some(url.into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        }

        assert!(service
            .reset_browser_profile(project.id, "account1")
            .await
            .unwrap());
        assert!(service
            .load_persistent_profile(project.id, "account1")
            .await
            .unwrap()
            .is_none());
        assert!(service
            .load_persistent_profile(project.id, "account2")
            .await
            .unwrap()
            .is_some());
        assert!(service
            .load_persistent_profile(project.id, DEFAULT_BROWSER_PROFILE)
            .await
            .unwrap()
            .is_some());
        let profiles = service.browser_profiles(project.id).await.unwrap();
        assert!(profiles.iter().any(|profile| profile.name == "account1"));
    }

    #[tokio::test]
    async fn failed_named_profile_reset_releases_its_lease() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "profile reset failure".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        let profiles_parent = service.project_profile_dir(project.id).join("profiles");
        write_private_file(&profiles_parent, b"not a directory").unwrap();

        assert!(service
            .reset_browser_profile(project.id, "account1")
            .await
            .is_err());
        assert!(!service
            .profile_leases
            .lock()
            .await
            .contains(&(project.id.get(), "account1".into())));

        std::fs::remove_file(profiles_parent).unwrap();
        service
            .create_browser_profile(project.id, "account1")
            .await
            .unwrap();
    }

    #[test]
    fn browser_profile_names_are_path_safe() {
        for valid in ["default", "account1", "qa-user", "qa_user"] {
            validate_browser_profile_name(valid).unwrap();
        }
        for invalid in ["", "../escape", "a/b", "space name", "."] {
            assert!(validate_browser_profile_name(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn persistent_launch_requires_an_explicit_cookie_override() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "Google workspace".into(),
                target_url: "https://accounts.google.com".into(),
                advanced: None,
            })
            .await
            .unwrap();
        db.upsert_cookie_profile(
            project.id,
            crate::cookies::validate_cookie_profile(
                "https://accounts.google.com",
                "SID=project-account".into(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let stored = db
            .get_cookie_profile_for_url(project.id, "https://accounts.google.com")
            .await
            .unwrap()
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            PathBuf::from("unused-profiles"),
        );
        assert!(service
            .cookies_for_launch(project.id, true, None)
            .await
            .unwrap()
            .is_empty());
        let explicit = service
            .cookies_for_launch(
                project.id,
                true,
                Some(CookieLaunchOverride::from_profile(&stored).unwrap()),
            )
            .await
            .unwrap();
        assert_eq!(explicit[0]["value"], "project-account");
        // Raw project headers and named imports use equivalent host-only
        // identities even though their Playwright serialization differs.
        let ephemeral = service
            .cookies_for_launch(project.id, false, None)
            .await
            .unwrap();
        assert_eq!(ephemeral.len(), 1);
        assert_eq!(ephemeral[0]["name"], "SID");
        assert_eq!(ephemeral[0]["value"], "project-account");
        assert_eq!(ephemeral[0]["url"], "https://accounts.google.com/");
    }

    #[test]
    fn legacy_project_cookie_metadata_cannot_modify_persistent_state() {
        let state: PersistentBrowserProfile = serde_json::from_value(json!({
            "managed_cookie_hash":"old-seed",
            "pending_cookie_clears":[{"name":"SID", "domain":".google.com", "path":"/"}],
            "cookies":[{"name":"SID", "value":"native-account", "domain":".google.com", "path":"/"}]
        }))
        .unwrap();
        let saved = serde_json::to_value(state).unwrap();
        assert_eq!(saved["cookies"][0]["value"], "native-account");
        assert!(saved.get("managed_cookie_hash").is_none());
        assert!(saved.get("pending_cookie_clears").is_none());
    }

    #[tokio::test]
    async fn reset_profile_recovers_from_corrupt_state() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "reset profile".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        let state_path = service.profile_state_path(project.id, DEFAULT_BROWSER_PROFILE);
        write_private_file(&state_path, b"not json").unwrap();

        assert!(service.reset_project_profile(project.id).await.unwrap());
        assert!(!service
            .profile_state_path(project.id, DEFAULT_BROWSER_PROFILE)
            .exists());
        assert!(service
            .load_persistent_profile(project.id, DEFAULT_BROWSER_PROFILE)
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn browser_cookie_import_is_host_only_and_last_duplicate_wins() {
        let profile = StoredCookieProfile {
            project_id: ProjectId(1),
            host: "example.com".into(),
            target_url: "https://example.com/".into(),
            cookie_header: "sid=old; theme=dark; sid=new".into(),
            names: vec!["sid".into(), "theme".into()],
            managed_cookies: None,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let cookies = browser_cookies(&[profile]).unwrap();
        assert_eq!(cookies.len(), 2);
        assert!(cookies.iter().any(|cookie| {
            cookie["name"] == "sid"
                && cookie["value"] == "new"
                && cookie["url"] == "https://example.com/"
        }));
        let identities = profile_cookie_identities(&StoredCookieProfile {
            project_id: ProjectId(1),
            host: "example.com".into(),
            target_url: "https://example.com/".into(),
            cookie_header: "sid=value".into(),
            names: vec!["sid".into()],
            managed_cookies: None,
            created_at: String::new(),
            updated_at: String::new(),
        })
        .unwrap();
        assert_eq!(
            identities,
            vec![json!({"name":"sid","domain":"example.com","path":"/"})]
        );
    }

    #[test]
    fn browser_cookie_import_preserves_json_attributes_and_paths() {
        let validated = crate::cookies::validate_cookie_profile(
            "https://app.example.com/admin",
            r#"[{"domain":".example.com","name":"sid","path":"/","secure":true,"session":true,"value":"root"},{"domain":".example.com","expirationDate":4102444800.5,"httpOnly":true,"name":"sid","path":"/admin","sameSite":"lax","secure":true,"value":"admin"}]"#.into(),
        )
        .unwrap();
        let profile = StoredCookieProfile {
            project_id: ProjectId(1),
            host: validated.host,
            target_url: validated.target_url,
            cookie_header: validated.cookie_header,
            names: validated.names,
            managed_cookies: validated.managed_cookies,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let launch_override = CookieLaunchOverride::from_profile(&profile).unwrap();
        let cookies = launch_override.cookies;
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0]["domain"], ".example.com");
        assert_eq!(cookies[0]["path"], "/");
        assert_eq!(cookies[0]["secure"], true);
        assert!(cookies[0].get("expires").is_none());
        assert_eq!(cookies[1]["path"], "/admin");
        assert_eq!(cookies[1]["httpOnly"], true);
        assert_eq!(cookies[1]["sameSite"], "Lax");
        assert_eq!(cookies[1]["expires"], 4102444800.5_f64);
        assert_eq!(launch_override.clear_cookies.len(), 2);
        assert!(launch_override
            .clear_cookies
            .iter()
            .all(|cookie| cookie.get("value").is_none()));
    }

    #[test]
    fn browser_cookie_import_deduplicates_identity_with_latest_profile_winning() {
        let make_profile = |value: &str| {
            let validated = crate::cookies::validate_cookie_profile(
                "https://app.example.com/",
                format!(
                    r#"[{{"domain":".example.com","name":"sid","path":"/","secure":true,"session":true,"value":"{value}"}}]"#
                ),
            )
            .unwrap();
            StoredCookieProfile {
                project_id: ProjectId(1),
                host: "app.example.com".into(),
                target_url: validated.target_url,
                cookie_header: validated.cookie_header,
                names: validated.names,
                managed_cookies: validated.managed_cookies,
                created_at: String::new(),
                updated_at: String::new(),
            }
        };
        let cookies = browser_cookies(&[make_profile("older"), make_profile("newer")]).unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0]["value"], "newer");
    }

    #[test]
    fn browser_cookie_import_keeps_host_and_domain_cookie_identities_distinct() {
        let validated = crate::cookies::validate_named_cookie_profile(
            "https://www.example.com",
            json!([
                {"name":"sid","value":"host","domain":"www.example.com","hostOnly":true},
                {"name":"sid","value":"domain","domain":".www.example.com","hostOnly":false},
            ])
            .to_string(),
        )
        .unwrap();
        let stored = StoredCookieProfile {
            project_id: ProjectId(1),
            host: validated.host,
            target_url: validated.target_url,
            cookie_header: validated.cookie_header,
            names: validated.names,
            managed_cookies: validated.managed_cookies,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let cookies = browser_cookies(&[stored]).unwrap();
        assert_eq!(cookies.len(), 2);
        assert!(cookies
            .iter()
            .any(|cookie| cookie["domain"] == "www.example.com" && cookie["value"] == "host"));
        assert!(cookies
            .iter()
            .any(|cookie| cookie["domain"] == ".www.example.com" && cookie["value"] == "domain"));
    }

    #[test]
    fn explicit_worker_path_wins() {
        let directory = tempfile::tempdir().unwrap();
        let worker = directory.path().join("index.js");
        std::fs::write(&worker, "// worker").unwrap();
        assert_eq!(resolve_worker_path(Some(worker.clone())), Some(worker));
    }

    #[test]
    fn browser_install_status_requires_the_complete_local_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let node = directory.path().join("node");
        let worker = directory.path().join("index.js");
        let playwright = directory.path().join("playwright-core");
        let chromium = directory.path().join("chromium");
        std::fs::write(&node, "node").unwrap();
        std::fs::write(&worker, "worker").unwrap();
        std::fs::create_dir(&playwright).unwrap();
        std::fs::write(&chromium, "chromium").unwrap();

        let ready = browser_install_status(
            Some(&node),
            Some(&worker),
            Some(&playwright),
            Some(&chromium),
        );
        assert!(ready.node_available);
        assert!(ready.worker_available);
        assert!(ready.chromium_available);
        assert_eq!(ready.install_hint, None);

        let missing_playwright =
            browser_install_status(Some(&node), Some(&worker), None, Some(&chromium));
        assert!(!missing_playwright.worker_available);
        assert!(missing_playwright
            .install_hint
            .as_deref()
            .is_some_and(|hint| hint.contains("playwright-core missing")));
    }

    #[test]
    fn browser_installation_inspection_does_not_materialize_the_worker() {
        let directory = tempfile::tempdir().unwrap();
        let expected_worker = browser_worker_path(directory.path());
        let config = Config {
            data_dir: directory.path().to_path_buf(),
            browser_worker_path: Some(directory.path().join("missing-worker.js")),
            ..Config::default()
        };

        assert!(!expected_worker.exists());
        let _ = inspect_browser_installation(&config);
        assert!(!expected_worker.exists());
    }

    #[test]
    fn chromium_profile_requires_real_browser_state() {
        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("chromium");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        assert!(!chromium_profile_has_state(&profile));

        std::fs::write(profile.join("Default").join("Preferences"), "{}").unwrap();
        assert!(chromium_profile_has_state(&profile));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn aliased_profile_directories_cannot_claim_another_identity() {
        std::fs::create_dir_all("/tmp/artis").unwrap();
        let directory = tempfile::Builder::new()
            .prefix("huntproxy-profile-owner-")
            .tempdir_in("/tmp/artis")
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            Arc::new(Db::open_in_memory().await.unwrap()),
            None,
            None,
            DEFAULT_BROWSER_PROXY.into(),
            None,
            directory.path().join("profiles"),
        );
        let first = service.chromium_profile_dir(ProjectId(1), "acc1").unwrap();
        std::os::unix::fs::symlink(&first, service.chromium_profile_path(ProjectId(1), "acc2"))
            .unwrap();
        let error = service
            .chromium_profile_dir(ProjectId(1), "acc2")
            .unwrap_err();
        assert!(error.to_string().contains("different identity"));
        assert_eq!(
            first,
            service.chromium_profile_dir(ProjectId(1), "acc1").unwrap()
        );
    }

    #[test]
    fn worker_identity_requires_exact_session_profile_and_directory() {
        let identity = json!({
            "session_id": 8, "requested_profile": "acc2", "active_profile": "acc2",
            "profile_dir": "/profiles/acc2", "persistent": true,
        });
        verify_worker_identity(
            &identity,
            BrowserSessionId(8),
            Some("acc2"),
            Some(Path::new("/profiles/acc2")),
        )
        .unwrap();
        for field in [
            "session_id",
            "requested_profile",
            "active_profile",
            "profile_dir",
            "persistent",
        ] {
            let mut missing = identity.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(verify_worker_identity(
                &missing,
                BrowserSessionId(8),
                Some("acc2"),
                Some(Path::new("/profiles/acc2"))
            )
            .is_err());
        }
        assert!(verify_worker_identity(
            &identity,
            BrowserSessionId(7),
            Some("acc2"),
            Some(Path::new("/profiles/acc2"))
        )
        .is_err());
        assert!(verify_worker_identity(
            &identity,
            BrowserSessionId(8),
            Some("acc1"),
            Some(Path::new("/profiles/acc2"))
        )
        .is_err());
        assert!(verify_worker_identity(
            &identity,
            BrowserSessionId(8),
            Some("acc2"),
            Some(Path::new("/profiles/acc1"))
        )
        .is_err());
    }

    #[test]
    fn browser_worker_installation_uses_selected_data_directory() {
        let directory = tempfile::tempdir().unwrap();
        let worker_dir = prepare_browser_worker_installation(directory.path()).unwrap();
        assert!(worker_dir.starts_with(directory.path()));
        assert!(worker_dir.join("index.js").is_file());
        assert!(worker_dir.join("package.json").is_file());
        assert!(worker_dir.join("package-lock.json").is_file());
    }

    #[test]
    fn chromium_finder_handles_nested_macos_app_layout() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory
            .path()
            .join("chromium-1248/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, "browser").unwrap();
        assert_eq!(find_chromium_binary(directory.path(), 8), Some(executable));
    }
}
