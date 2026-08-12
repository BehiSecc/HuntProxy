//! Browser worker supervision, real actions, and private per-project browser state.

use crate::config::{create_private_dir, write_private_file};
use crate::cookies::{CookiePair, StoredCookieProfile};
use crate::domain::*;
use crate::storage::{CreateCaptureSession, Db};
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
const MAX_PERSISTENT_PROFILE_BYTES: usize = 25 * 1024 * 1024;
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
    #[serde(default)]
    pending_cookie_clears: Vec<Value>,
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

fn default_snapshot_format() -> String {
    "accessibility".into()
}

fn default_snapshot_max_bytes() -> u64 {
    200_000
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
pub struct ActionResult {
    pub ok: bool,
    pub untrusted: bool,
    pub message: String,
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

#[derive(Debug, Clone)]
struct RuntimeSession {
    project_id: ProjectId,
    capture_session_id: CaptureSessionId,
    persistent: bool,
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
    profile_leases: Mutex<HashSet<i64>>,
    profile_io: Mutex<()>,
    session_ops: Mutex<HashMap<i64, Arc<Mutex<()>>>>,
    worker: Mutex<Option<WorkerProcess>>,
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
            profile_io: Mutex::new(()),
            session_ops: Mutex::new(HashMap::new()),
            worker: Mutex::new(None),
        }
    }

    pub fn status(&self) -> BrowserInstallStatus {
        let node_available = self.node_path.as_ref().is_some_and(|path| path.exists());
        let worker_script_available = self.worker_path.as_ref().is_some_and(|path| path.exists());
        let worker_available =
            node_available && worker_script_available && self.playwright_core_path.is_some();
        let chromium_available = self
            .chromium_path
            .as_ref()
            .is_some_and(|path| path.is_file());

        let install_hint = if !node_available {
            Some("Install Node.js, then run: HuntProxy browser install".into())
        } else if !worker_script_available {
            Some(
                "Browser worker missing; reinstall HuntProxy or set HUNTPROXY_BROWSER_WORKER_PATH"
                    .into(),
            )
        } else if self.playwright_core_path.is_none() {
            let directory = self
                .worker_path
                .as_deref()
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
            chromium_path: self
                .chromium_path
                .as_ref()
                .map(|path| path.display().to_string()),
            node_path: self
                .node_path
                .as_ref()
                .map(|path| path.display().to_string()),
            install_hint,
        }
    }

    pub async fn start(&self, project_id: ProjectId, url: String) -> DomainResult<BrowserSession> {
        self.start_with_persistence(project_id, url, true).await
    }

    pub async fn start_ephemeral(
        &self,
        project_id: ProjectId,
        url: String,
    ) -> DomainResult<BrowserSession> {
        self.start_with_persistence(project_id, url, false).await
    }

    async fn start_with_persistence(
        &self,
        project_id: ProjectId,
        url: String,
        persistent: bool,
    ) -> DomainResult<BrowserSession> {
        if persistent {
            let mut leases = self.profile_leases.lock().await;
            if !leases.insert(project_id.get()) {
                drop(leases);
                let active_session_id =
                    self.runtime_sessions
                        .lock()
                        .await
                        .iter()
                        .find_map(|(id, runtime)| {
                            (runtime.project_id == project_id && runtime.persistent).then_some(*id)
                        });
                let detail = active_session_id
                    .map(|id| format!(" as session {id}"))
                    .unwrap_or_default();
                return Err(DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    format!(
                        "project persistent browser is already active{detail}; stop it before starting another"
                    ),
                ));
            }
        }
        let result = self.start_runtime(project_id, url, persistent).await;
        if result.is_err() && persistent {
            self.profile_leases.lock().await.remove(&project_id.get());
        }
        result
    }

    async fn start_runtime(
        &self,
        project_id: ProjectId,
        mut url: String,
        persistent: bool,
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
            if let Some(active_session_id) = runtimes.iter().find_map(|(id, runtime)| {
                (runtime.project_id == project_id && runtime.persistent).then_some(*id)
            }) {
                return Err(DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    format!(
                        "project persistent browser is already active as session {active_session_id}; stop it before starting another"
                    ),
                ));
            }
        }
        drop(runtimes);

        let restored_profile = if persistent {
            self.load_persistent_profile(project_id).await?
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

        let mut session = self.db.create_browser_session(project_id).await?;
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
        let managed_cookies =
            browser_cookies(&self.db.list_stored_cookie_profiles(project_id).await?)?;
        let pending_cookie_clears = restored_profile
            .as_ref()
            .map(|profile| profile.pending_cookie_clears.clone())
            .unwrap_or_default();
        let profile_dir = persistent
            .then(|| self.chromium_profile_dir(project_id))
            .transpose()?;
        let prefer_profile_state = profile_dir
            .as_deref()
            .is_some_and(chromium_profile_has_state);
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
            "cookies": managed_cookies,
            "clear_cookies": pending_cookie_clears.clone(),
            "restore_state": restored_profile,
            "persistent": persistent,
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
                persistent,
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
        if persistent {
            if let Err(error) = self
                .acknowledge_cookie_clears(project_id, &pending_cookie_clears)
                .await
            {
                self.cleanup_failed_start(project_id, &mut session, capture.id)
                    .await;
                return Err(error);
            }
        }
        session.engine = BrowserEngine::Chromium;
        session.current_url = saved.url;
        session.current_title = saved.title;
        session.state = BrowserSessionState::Ready;
        session.checkpoint_status = Some(checkpoint_status.into());
        session.checkpoint_hash = Some(saved.hash);
        if let Err(error) = self.db.update_browser_session(&session).await {
            self.cleanup_failed_start(project_id, &mut session, capture.id)
                .await;
            return Err(error);
        }
        self.runtime_sessions.lock().await.insert(
            session.id.get(),
            RuntimeSession {
                project_id,
                capture_session_id: capture.id,
                persistent,
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

    /// Apply a managed cookie profile to every active browser session in the
    /// project. The worker checkpoints each session so imported cookies survive
    /// browser suspension and daemon restarts.
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
        let current_identities = profile_cookie_identities(profile)?;
        let removed_identities = previous_cookies
            .iter()
            .filter(|identity| !current_identities.contains(identity))
            .cloned()
            .collect::<Vec<_>>();
        self.queue_cookie_clears(project_id, &removed_identities)
            .await?;
        let session_ids = self.active_session_ids(project_id).await;
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
        let session_ids = self.active_session_ids(project_id).await;
        let pairs = if profile.managed_cookies.is_none() {
            profile.pairs()?
        } else {
            Vec::new()
        };
        let cookies = profile_cookie_identities(profile)?;
        self.queue_cookie_clears(project_id, &cookies).await?;
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

    async fn active_session_ids(&self, project_id: ProjectId) -> Vec<BrowserSessionId> {
        self.runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, runtime)| {
                (runtime.project_id == project_id).then_some(BrowserSessionId(*id))
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
            sessions.push(self.db.get_browser_session(project_id, session_id).await?);
        }
        sessions.sort_by_key(|session| session.id.get());
        Ok(sessions)
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

    async fn session_is_persistent(&self, session_id: BrowserSessionId) -> bool {
        self.runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .is_some_and(|runtime| runtime.persistent)
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
        let active = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .is_some_and(|runtime| runtime.project_id == project_id && runtime.cdp.is_none());
        if !active {
            return Ok(false);
        }
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
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
        let persistent = self.session_is_persistent(session_id).await;
        let saved = self
            .save_checkpoint(project_id, session_id, checkpoint, "ok", persistent)
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
        if matches!(&action, BrowserAction::Close) {
            self.stop(project_id, session_id).await?;
            return Ok(ActionResult {
                ok: true,
                untrusted: false,
                message: "session closed".into(),
                data: None,
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
        let worker_result = self
            .call_worker(
                "session.action",
                json!({
                    "session_id": session_id.get(),
                    "action": serde_json::to_value(&action).map_err(|error| {
                        DomainError::new(ErrorCode::InvalidArgument, error.to_string())
                    })?,
                }),
            )
            .await;
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
                runtime.persistent,
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
                            runtime.persistent,
                        )
                        .await
                    {
                        persistence_error = Some(error);
                    }
                }
            }
        }
        self.runtime_sessions.lock().await.remove(&session_id.get());
        if runtime.as_ref().is_some_and(|runtime| runtime.persistent) {
            self.profile_leases.lock().await.remove(&project_id.get());
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
        let sessions = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, runtime)| {
                (runtime.project_id == project_id).then_some((project_id, BrowserSessionId(*id)))
            })
            .collect::<Vec<_>>();
        self.stop_sessions(sessions).await
    }

    /// Stop all active browsers across projects during daemon shutdown.
    pub async fn stop_all(&self) -> DomainResult<usize> {
        let sessions = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .map(|(id, runtime)| (runtime.project_id, BrowserSessionId(*id)))
            .collect::<Vec<_>>();
        self.stop_sessions(sessions).await
    }

    /// Terminate the shared worker and mark every attached session interrupted.
    /// Used only when graceful shutdown exceeds its bound.
    pub async fn force_stop_all(&self) {
        if let Some(mut worker) = self.worker.lock().await.take() {
            worker.terminate().await;
        }
        self.interrupt_runtime_sessions().await;
    }

    async fn stop_sessions(
        &self,
        sessions: Vec<(ProjectId, BrowserSessionId)>,
    ) -> DomainResult<usize> {
        let total = sessions.len();
        let mut first_error = None;
        for (project_id, session_id) in sessions {
            if let Err(error) = self.stop(project_id, session_id).await {
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
            if runtime.persistent {
                self.profile_leases
                    .lock()
                    .await
                    .remove(&runtime.project_id.get());
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

    fn profile_state_path(&self, project_id: ProjectId) -> PathBuf {
        self.project_profile_dir(project_id).join("state.json")
    }

    fn chromium_profile_dir(&self, project_id: ProjectId) -> DomainResult<PathBuf> {
        let directory = self
            .project_profile_dir(project_id)
            .join("chromium")
            .join("default");
        create_private_dir(&directory)?;
        Ok(directory)
    }

    async fn load_persistent_profile(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Option<PersistentBrowserProfile>> {
        let _guard = self.profile_io.lock().await;
        let path = self.profile_state_path(project_id);
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

    async fn queue_cookie_clears(
        &self,
        project_id: ProjectId,
        identities: &[Value],
    ) -> DomainResult<()> {
        if identities.is_empty() {
            return Ok(());
        }
        self.update_persistent_profile(project_id, |profile| {
            for identity in identities {
                if !profile.pending_cookie_clears.contains(identity) {
                    profile.pending_cookie_clears.push(identity.clone());
                }
            }
        })
        .await
    }

    async fn acknowledge_cookie_clears(
        &self,
        project_id: ProjectId,
        acknowledged: &[Value],
    ) -> DomainResult<()> {
        self.update_persistent_profile(project_id, |profile| {
            profile
                .pending_cookie_clears
                .retain(|identity| !acknowledged.contains(identity));
        })
        .await
    }

    async fn update_persistent_profile(
        &self,
        project_id: ProjectId,
        update: impl FnOnce(&mut PersistentBrowserProfile),
    ) -> DomainResult<()> {
        let _guard = self.profile_io.lock().await;
        let path = self.profile_state_path(project_id);
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
        let directory = self.project_profile_dir(project_id);
        create_private_dir(&directory)?;
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
        checkpoint: &Checkpoint,
    ) -> DomainResult<()> {
        let _guard = self.profile_io.lock().await;
        let path = self.profile_state_path(project_id);
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
        let directory = self.project_profile_dir(project_id);
        create_private_dir(&directory)?;
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

    pub async fn reset_project_profile(&self, project_id: ProjectId) -> DomainResult<bool> {
        self.db.get_project(project_id).await?;
        let _ = self.stop_project(project_id).await;
        {
            let mut leases = self.profile_leases.lock().await;
            if !leases.insert(project_id.get()) {
                return Err(DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    "project browser is starting or active; stop it before resetting the profile",
                ));
            }
        }
        let _guard = self.profile_io.lock().await;
        let directory = self.project_profile_dir(project_id);
        let result = (|| {
            let metadata = match std::fs::symlink_metadata(&directory) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => {
                    return Err(DomainError::new(
                        ErrorCode::StorageError,
                        format!("inspect browser profile: {error}"),
                    ))
                }
            };
            let removed = if metadata.file_type().is_symlink() || metadata.is_file() {
                std::fs::remove_file(&directory)
            } else {
                std::fs::remove_dir_all(&directory)
            };
            removed.map_err(|error| {
                DomainError::new(
                    ErrorCode::StorageError,
                    format!("reset browser profile: {error}"),
                )
            })?;
            Ok(true)
        })();
        drop(_guard);
        self.profile_leases.lock().await.remove(&project_id.get());
        result
    }

    async fn save_checkpoint(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        value: &Value,
        status: &str,
        persistent: bool,
    ) -> DomainResult<Checkpoint> {
        let mut checkpoint = decode_checkpoint(value)?;
        let mut checkpoints = self.checkpoints.lock().await;
        checkpoint.version = checkpoints
            .get(&session_id.get())
            .map_or(1, |previous| previous.version.saturating_add(1));
        checkpoint.hash = checkpoint_hash(&checkpoint)?;
        checkpoints.insert(session_id.get(), checkpoint.clone());
        drop(checkpoints);
        if persistent {
            self.persist_checkpoint(project_id, &checkpoint).await?;
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
                        cookie.domain.clone(),
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
            Some("chrome" | "chromium" | "chrome.exe" | "Chromium")
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
    if let Ok(materialized) = materialize_embedded_worker(&crate::config::default_data_dir()) {
        candidates.push(materialized);
    }
    if let Ok(current) = std::env::current_dir() {
        candidates.push(current.join("browser-worker/index.js"));
    }
    if let Some(found) = candidates.into_iter().find(|path| path.is_file()) {
        return Some(found.canonicalize().unwrap_or(found));
    }
    None
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
    let directory = data_dir.join(format!("browser-worker-{}", env!("CARGO_PKG_VERSION")));
    std::fs::create_dir_all(&directory)?;
    let worker_path = directory.join("index.js");
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
        let mut session = db.create_browser_session(project.id).await.unwrap();
        session.current_url = Some("https://example.test/dashboard".into());
        session.current_title = Some("Dashboard".into());
        session.state = BrowserSessionState::Ready;
        db.update_browser_session(&session).await.unwrap();

        let restored = db
            .get_browser_session(project.id, session.id)
            .await
            .unwrap();
        assert_eq!(restored.current_url, session.current_url);
        assert_eq!(restored.current_title.as_deref(), Some("Dashboard"));
        assert_eq!(restored.engine, BrowserEngine::Chromium);
        assert_eq!(restored.state, BrowserSessionState::Ready);
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
            .persist_checkpoint(project_id, &checkpoint)
            .await
            .unwrap();
        let loaded = service
            .load_persistent_profile(project_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.last_url, checkpoint.url);
        assert_eq!(loaded.cookies, checkpoint.cookies);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(service.profile_state_path(project_id))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[tokio::test]
    async fn pending_cookie_clears_survive_until_browser_start_consumes_them() {
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
        let project_id = ProjectId(43);
        let identity = json!({"name":"sid","domain":".example.test","path":"/admin"});
        service
            .queue_cookie_clears(project_id, std::slice::from_ref(&identity))
            .await
            .unwrap();
        let loaded = service
            .load_persistent_profile(project_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.pending_cookie_clears, vec![identity.clone()]);

        let second = json!({"name":"other","domain":"example.test","path":"/"});
        service
            .queue_cookie_clears(project_id, std::slice::from_ref(&second))
            .await
            .unwrap();
        service
            .acknowledge_cookie_clears(project_id, std::slice::from_ref(&identity))
            .await
            .unwrap();
        let loaded = service
            .load_persistent_profile(project_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.pending_cookie_clears, vec![second]);
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
        let state_path = service.profile_state_path(project.id);
        write_private_file(&state_path, b"not json").unwrap();

        assert!(service.reset_project_profile(project.id).await.unwrap());
        assert!(!service.project_profile_dir(project.id).exists());
        assert!(service
            .load_persistent_profile(project.id)
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
        let cookies = browser_cookies(&[profile]).unwrap();
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0]["domain"], ".example.com");
        assert_eq!(cookies[0]["path"], "/");
        assert_eq!(cookies[0]["secure"], true);
        assert!(cookies[0].get("expires").is_none());
        assert_eq!(cookies[1]["path"], "/admin");
        assert_eq!(cookies[1]["httpOnly"], true);
        assert_eq!(cookies[1]["sameSite"], "Lax");
        assert_eq!(cookies[1]["expires"], 4102444800.5_f64);
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
    fn explicit_worker_path_wins() {
        let directory = tempfile::tempdir().unwrap();
        let worker = directory.path().join("index.js");
        std::fs::write(&worker, "// worker").unwrap();
        assert_eq!(resolve_worker_path(Some(worker.clone())), Some(worker));
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
            .join("chromium-1148/chrome-mac/Chromium.app/Contents/MacOS/Chromium");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, "browser").unwrap();
        assert_eq!(find_chromium_binary(directory.path(), 8), Some(executable));
    }
}
