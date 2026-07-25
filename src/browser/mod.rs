//! Browser worker supervision, real actions, and memory-only session checkpoints.

use crate::cookies::{CookiePair, StoredCookieProfile};
use crate::domain::*;
use crate::storage::{CreateCaptureSession, Db};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

const WORKER_PROTOCOL_VERSION: u64 = 1;
const WORKER_RPC_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_BROWSER_PROXY: &str = "http://127.0.0.1:17891";
const EMBEDDED_WORKER: &str = include_str!("../../browser-worker/index.js");
const EMBEDDED_WORKER_PACKAGE: &str = include_str!("../../browser-worker/package.json");
const EMBEDDED_WORKER_LOCK: &str = include_str!("../../browser-worker/package-lock.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserInstallStatus {
    pub node_available: bool,
    pub worker_available: bool,
    pub lightpanda_available: bool,
    pub chromium_available: bool,
    pub lightpanda_path: Option<String>,
    pub node_path: Option<String>,
    pub install_hint: Option<String>,
}

/// Secret-bearing values live only in daemon memory. SQLite stores version/hash/status metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Checkpoint {
    pub url: Option<String>,
    pub cookies: Vec<Value>,
    pub local_storage: BTreeMap<String, BTreeMap<String, String>>,
    pub session_storage: BTreeMap<String, String>,
    pub version: u64,
    pub hash: String,
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
        lightpanda_path: Option<&Path>,
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
        if let Some(path) = lightpanda_path {
            command.env("LIGHTPANDA_PATH", path);
        }
        if let Some(path) = playwright_core_path {
            command.env("BB_PLAYWRIGHT_CORE_PATH", path);
            if path.join(".local-browsers").is_dir() {
                command.env("PLAYWRIGHT_BROWSERS_PATH", "0");
            }
        }
        if let Some(path) = chromium_path {
            command.env("BB_CHROME_EXECUTABLE", path);
        }
        command.env("LIGHTPANDA_DISABLE_TELEMETRY", "true");
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
                -32004 => ErrorCode::LightpandaNotInstalled,
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
    pub lightpanda_path: Option<PathBuf>,
    pub node_path: Option<PathBuf>,
    pub worker_path: Option<PathBuf>,
    proxy_server: String,
    ca_cert_path: Option<PathBuf>,
    playwright_core_path: Option<PathBuf>,
    chromium_path: Option<PathBuf>,
    checkpoints: Mutex<HashMap<i64, Checkpoint>>,
    runtime_sessions: Mutex<HashMap<i64, RuntimeSession>>,
    worker: Mutex<Option<WorkerProcess>>,
}

impl BrowserService {
    pub fn new(
        db: Arc<Db>,
        lightpanda_path: Option<PathBuf>,
        node_path: Option<PathBuf>,
        worker_path: Option<PathBuf>,
    ) -> Self {
        let proxy_server = std::env::var("BB_BROWSER_PROXY_SERVER")
            .unwrap_or_else(|_| DEFAULT_BROWSER_PROXY.to_string());
        let ca_cert_path = std::env::var_os("BB_BROWSER_CA_CERT").map(PathBuf::from);
        Self::new_with_proxy_and_ca(
            db,
            lightpanda_path,
            node_path,
            worker_path,
            proxy_server,
            ca_cert_path,
        )
    }

    /// Proxy-aware constructor for daemon integration with non-default proxy binds.
    pub fn new_with_proxy(
        db: Arc<Db>,
        lightpanda_path: Option<PathBuf>,
        node_path: Option<PathBuf>,
        worker_path: Option<PathBuf>,
        proxy_server: String,
    ) -> Self {
        let ca_cert_path = std::env::var_os("BB_BROWSER_CA_CERT").map(PathBuf::from);
        Self::new_with_proxy_and_ca(
            db,
            lightpanda_path,
            node_path,
            worker_path,
            proxy_server,
            ca_cert_path,
        )
    }

    /// Proxy- and CA-aware constructor for the daemon's managed browser sessions.
    pub fn new_with_proxy_and_ca(
        db: Arc<Db>,
        lightpanda_path: Option<PathBuf>,
        node_path: Option<PathBuf>,
        worker_path: Option<PathBuf>,
        proxy_server: String,
        ca_cert_path: Option<PathBuf>,
    ) -> Self {
        let worker_path = resolve_worker_path(worker_path);
        let playwright_core_path = worker_path
            .as_deref()
            .and_then(find_playwright_core)
            .or_else(find_playwright_from_environment);
        let chromium_path = chromium_executable(playwright_core_path.as_deref());
        Self {
            db,
            lightpanda_path: existing_path(lightpanda_path, "lightpanda"),
            node_path: existing_path(node_path, "node"),
            worker_path,
            proxy_server,
            ca_cert_path: ca_cert_path.filter(|path| path.is_file()),
            playwright_core_path,
            chromium_path,
            checkpoints: Mutex::new(HashMap::new()),
            runtime_sessions: Mutex::new(HashMap::new()),
            worker: Mutex::new(None),
        }
    }

    pub fn status(&self) -> BrowserInstallStatus {
        let node_available = self.node_path.as_ref().is_some_and(|path| path.exists());
        let lightpanda_available = self
            .lightpanda_path
            .as_ref()
            .is_some_and(|path| path.exists());
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
            Some("Browser worker missing; reinstall HuntProxy or set BB_BROWSER_WORKER_PATH".into())
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
        } else if !lightpanda_available && !chromium_available {
            Some("Install Lightpanda or Chromium: HuntProxy browser install".into())
        } else {
            None
        };

        BrowserInstallStatus {
            node_available,
            worker_available,
            lightpanda_available,
            chromium_available,
            lightpanda_path: self
                .lightpanda_path
                .as_ref()
                .map(|path| path.display().to_string()),
            node_path: self
                .node_path
                .as_ref()
                .map(|path| path.display().to_string()),
            install_hint,
        }
    }

    pub async fn start(
        &self,
        project_id: ProjectId,
        url: String,
        policy: EnginePolicy,
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
        let active_for_project = self
            .runtime_sessions
            .lock()
            .await
            .values()
            .filter(|runtime| runtime.project_id == project_id)
            .count() as u32;
        if active_for_project >= project.limits.max_concurrent_browsers {
            return Err(DomainError::new(
                ErrorCode::ConcurrencyLimited,
                "project browser concurrency limit reached",
            ));
        }

        let engine = match policy {
            EnginePolicy::Chromium => {
                if !status.chromium_available {
                    return Err(DomainError::new(
                        ErrorCode::ChromiumNotInstalled,
                        "Chromium not installed; run HuntProxy browser install",
                    ));
                }
                BrowserEngine::Chromium
            }
            EnginePolicy::Auto => {
                if status.lightpanda_available {
                    BrowserEngine::Lightpanda
                } else if status.chromium_available {
                    BrowserEngine::Chromium
                } else {
                    return Err(DomainError::new(
                        ErrorCode::BrowserNotInstalled,
                        "No browser engine installed",
                    ));
                }
            }
        };

        let mut session = self
            .db
            .create_browser_session(project_id, engine, policy)
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
        let managed_cookies =
            browser_cookies(&self.db.list_stored_cookie_profiles(project_id).await?)?;
        let mut start_params = json!({
            "session_id": session.id.get(),
            "engine": engine_name(engine),
            "url": url,
            "proxy": {
                "server": self.proxy_server.clone(),
                "bearer_token": token.clone(),
                "username": PROXY_BASIC_USER,
                "password": token,
            },
            "ca_cert_path": self.ca_cert_path.as_ref().map(|path| path.display().to_string()),
            "cookies": managed_cookies,
        });
        let mut effective_engine = engine;
        let mut checkpoint_status = "ok";
        let mut worker_result = self
            .call_worker("session.start", start_params.clone())
            .await;
        if worker_result.is_err()
            && policy == EnginePolicy::Auto
            && engine == BrowserEngine::Lightpanda
            && status.chromium_available
        {
            start_params["engine"] = json!(engine_name(BrowserEngine::Chromium));
            worker_result = self.call_worker("session.start", start_params).await;
            if worker_result.is_ok() {
                effective_engine = BrowserEngine::Chromium;
                checkpoint_status = "fallback_chromium";
                session.fallback_used = true;
            }
        }
        let result = match worker_result {
            Ok(result) => result,
            Err(error) => {
                session.state = BrowserSessionState::Failed;
                session.checkpoint_status = Some("start_failed".into());
                let _ = self.db.update_browser_session(&session).await;
                let _ = self.db.revoke_capture_session(project_id, capture.id).await;
                return Err(error);
            }
        };
        let checkpoint = result.get("checkpoint").ok_or_else(|| {
            DomainError::new(ErrorCode::ProtocolError, "worker omitted checkpoint")
        })?;
        let saved = self
            .save_checkpoint(project_id, session.id, checkpoint, checkpoint_status)
            .await?;
        session.engine = effective_engine;
        session.current_url = saved.url;
        session.state = BrowserSessionState::Ready;
        session.checkpoint_status = Some(checkpoint_status.into());
        session.checkpoint_hash = Some(saved.hash);
        self.db.update_browser_session(&session).await?;
        self.runtime_sessions.lock().await.insert(
            session.id.get(),
            RuntimeSession {
                project_id,
                capture_session_id: capture.id,
            },
        );
        Ok(session)
    }

    /// Apply a managed cookie profile to every active browser session in the
    /// project. The worker checkpoints each session so Lightpanda→Chromium
    /// migration carries the imported cookies forward.
    pub async fn apply_cookie_profile(
        &self,
        project_id: ProjectId,
        previous: Option<&StoredCookieProfile>,
        profile: &StoredCookieProfile,
    ) -> DomainResult<usize> {
        let cookies = browser_cookies(std::slice::from_ref(profile))?;
        let previous_names = previous
            .map(StoredCookieProfile::pairs)
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(|pair| pair.name)
            .collect::<Vec<_>>();
        let session_ids = self.active_session_ids(project_id).await;
        for session_id in &session_ids {
            let result = self
                .call_worker(
                    "session.set_cookies",
                    json!({
                        "session_id": session_id.get(),
                        "cookies": cookies.clone(),
                        "target_url": profile.target_url,
                        "clear_names": previous_names,
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
        let pairs = profile.pairs()?;
        for session_id in &session_ids {
            let result = self
                .call_worker(
                    "session.clear_cookies",
                    json!({
                        "session_id": session_id.get(),
                        "target_url": profile.target_url,
                        "names": pairs.iter().map(|pair| &pair.name).collect::<Vec<_>>(),
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

    async fn save_cookie_checkpoint(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        result: &Value,
    ) -> DomainResult<()> {
        let checkpoint = result.get("checkpoint").ok_or_else(|| {
            DomainError::new(ErrorCode::ProtocolError, "worker omitted checkpoint")
        })?;
        let saved = self
            .save_checkpoint(project_id, session_id, checkpoint, "ok")
            .await?;
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        session.current_url = saved.url;
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
        if !self
            .runtime_sessions
            .lock()
            .await
            .contains_key(&session_id.get())
        {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "browser runtime is not attached; start a new browser session",
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
        let saved = self
            .save_checkpoint(project_id, session_id, checkpoint, "ok")
            .await?;
        session.current_url = saved.url;
        session.state = BrowserSessionState::Ready;
        session.checkpoint_status = Some("ok".into());
        session.checkpoint_hash = Some(saved.hash);
        self.db.update_browser_session(&session).await?;

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
            error_code: None,
        })
    }

    pub async fn stop(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<()> {
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        let runtime = self.runtime_sessions.lock().await.remove(&session_id.get());
        if runtime.is_some() {
            let _ = self
                .call_worker("session.stop", json!({ "session_id": session_id.get() }))
                .await;
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
        Ok(())
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

    pub async fn switch_to_chromium(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<BrowserSession> {
        let status = self.status();
        if !status.chromium_available {
            return Err(DomainError::new(
                ErrorCode::ChromiumNotInstalled,
                "Chromium not installed; run HuntProxy browser install",
            ));
        }
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        if session.engine != BrowserEngine::Lightpanda {
            return Err(DomainError::new(
                ErrorCode::EngineFallback,
                "only Lightpanda sessions can switch to Chromium",
            ));
        }
        if session.fallback_used {
            return Err(DomainError::new(
                ErrorCode::EngineFallback,
                "fallback already used for this session",
            ));
        }
        if !self
            .runtime_sessions
            .lock()
            .await
            .contains_key(&session_id.get())
        {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "browser runtime is not attached; start a new browser session",
            ));
        }

        session.state = BrowserSessionState::Migrating;
        self.db.update_browser_session(&session).await?;
        let result = match self
            .call_worker(
                "session.migrate_to_chromium",
                json!({ "session_id": session_id.get() }),
            )
            .await
        {
            Ok(result) => result,
            Err(error) => {
                session.state = if self.worker.lock().await.is_some() {
                    BrowserSessionState::Ready
                } else {
                    BrowserSessionState::Interrupted
                };
                session.checkpoint_status = Some("migration_failed".into());
                let _ = self.db.update_browser_session(&session).await;
                return Err(error);
            }
        };
        let migration_status = result
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("migrated_partial")
            .to_string();
        let checkpoint = result.get("checkpoint").ok_or_else(|| {
            DomainError::new(ErrorCode::ProtocolError, "worker omitted checkpoint")
        })?;
        let saved = self
            .save_checkpoint(project_id, session_id, checkpoint, &migration_status)
            .await?;
        session.engine = BrowserEngine::Chromium;
        session.fallback_used = true;
        session.state = BrowserSessionState::Ready;
        session.current_url = saved.url;
        session.checkpoint_status = Some(migration_status);
        session.checkpoint_hash = Some(saved.hash);
        self.db.update_browser_session(&session).await?;
        Ok(session)
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
                    self.lightpanda_path.as_deref(),
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
        for (session_id, runtime) in runtimes {
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

    async fn save_checkpoint(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        value: &Value,
        status: &str,
    ) -> DomainResult<Checkpoint> {
        let mut checkpoint = decode_checkpoint(value)?;
        let mut checkpoints = self.checkpoints.lock().await;
        checkpoint.version = checkpoints
            .get(&session_id.get())
            .map_or(1, |previous| previous.version.saturating_add(1));
        checkpoint.hash = checkpoint_hash(&checkpoint)?;
        checkpoints.insert(session_id.get(), checkpoint.clone());
        drop(checkpoints);
        self.db
            .update_browser_checkpoint_metadata(
                project_id,
                session_id,
                checkpoint.url.clone(),
                status.to_string(),
                checkpoint.hash.clone(),
                checkpoint.version,
            )
            .await?;
        Ok(checkpoint)
    }
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
        "cookies": cookies,
        "local_storage": checkpoint.local_storage.clone(),
        "session_storage": checkpoint.session_storage.clone(),
    });
    let encoded = serde_json::to_vec(&hashable)
        .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn engine_name(engine: BrowserEngine) -> &'static str {
    match engine {
        BrowserEngine::Lightpanda => "lightpanda",
        BrowserEngine::Chromium => "chromium",
    }
}

fn browser_cookies(profiles: &[StoredCookieProfile]) -> DomainResult<Vec<Value>> {
    let mut output = Vec::new();
    for profile in profiles {
        // A Cookie header can contain duplicate names from different paths,
        // but it carries no path metadata. For browser import, the last value
        // wins and becomes a host-only, root-path session cookie.
        let mut pairs = BTreeMap::<String, CookiePair>::new();
        for pair in profile.pairs()? {
            pairs.insert(pair.name.clone(), pair);
        }
        output.extend(pairs.into_values().map(|pair| {
            json!({
                "name": pair.name,
                "value": pair.value,
                "url": profile.target_url,
            })
        }));
    }
    Ok(output)
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
    if let Some(path) = std::env::var_os("BB_BROWSER_WORKER_PATH") {
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
    std::env::var_os("BB_PLAYWRIGHT_CORE_PATH")
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
            "_private": {
                "origin": "https://example.com",
                "cookies": [{"name":"sid","value":"secret"}],
                "local_storage": {"theme":"dark"},
                "session_storage": {"csrf":"secret"}
            }
        });
        let checkpoint = decode_checkpoint(&value).unwrap();
        assert_eq!(checkpoint.url.as_deref(), Some("https://example.com/app"));
        assert_eq!(checkpoint.cookies.len(), 1);
        assert_eq!(
            checkpoint.local_storage["https://example.com"]["theme"],
            "dark"
        );
        assert_eq!(checkpoint.session_storage["csrf"], "secret");
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
    fn browser_cookie_import_is_host_only_and_last_duplicate_wins() {
        let profile = StoredCookieProfile {
            project_id: ProjectId(1),
            host: "example.com".into(),
            target_url: "https://example.com/".into(),
            cookie_header: "sid=old; theme=dark; sid=new".into(),
            names: vec!["sid".into(), "theme".into()],
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
    }

    #[test]
    fn explicit_worker_path_wins() {
        let directory = tempfile::tempdir().unwrap();
        let worker = directory.path().join("index.js");
        std::fs::write(&worker, "// worker").unwrap();
        assert_eq!(resolve_worker_path(Some(worker.clone())), Some(worker));
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
