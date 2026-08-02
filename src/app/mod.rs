//! Application service wiring, daemon lifecycle, graceful shutdown.

use crate::browser::BrowserService;
use crate::config::Config;
use crate::crawler::CrawlerService;
use crate::domain::*;
use crate::fuzzer::FuzzerService;
use crate::reply::{PlaceholderKey, ReplyService};
use crate::storage::Db;
use crate::transport::{build_default_transport, SemanticTransport};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Serialize)]
pub struct AppEvent {
    pub project_id: i64,
    pub kind: String,
    pub payload: serde_json::Value,
}

pub struct AppState {
    pub db: Arc<Db>,
    pub config: Config,
    pub transport: Arc<dyn SemanticTransport>,
    pub reply: Arc<ReplyService>,
    pub fuzzer: Arc<FuzzerService>,
    pub browser: Arc<BrowserService>,
    pub crawler: Arc<CrawlerService>,
    pub events: broadcast::Sender<AppEvent>,
    pub shutdown: CancellationToken,
    pub activity: ActivityTracker,
}

#[derive(Clone)]
pub struct ActivityTracker {
    last_control_activity: Arc<parking_lot::Mutex<Instant>>,
}

impl ActivityTracker {
    pub fn new() -> Self {
        Self {
            last_control_activity: Arc::new(parking_lot::Mutex::new(Instant::now())),
        }
    }

    pub fn touch(&self) {
        *self.last_control_activity.lock() = Instant::now();
    }

    pub fn idle_for(&self) -> Duration {
        self.last_control_activity.lock().elapsed()
    }
}

impl Default for ActivityTracker {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn run_daemon(config: Config) -> DomainResult<()> {
    config.ensure_layout()?;
    let _daemon_lock = acquire_daemon_lock(&config)?;

    let state = bootstrap_state(config.clone()).await?;
    let shutdown = state.shutdown.clone();

    // Bind every public/private listener before spawning any server. This makes
    // readiness atomic: a port/socket conflict fails startup and is never
    // reported as a ready daemon.
    let api_listener = crate::api::bind_api(config.api_listen).await?;
    let proxy_listener = crate::proxy::bind_proxy(config.proxy_listen).await?;
    #[cfg(unix)]
    let uds_listener = crate::api::bind_uds(&config.socket_path())?;

    let mut servers = tokio::task::JoinSet::new();

    let idle_monitor = if config.idle_timeout_seconds == 0 {
        None
    } else {
        let state = state.clone();
        let timeout = Duration::from_secs(config.idle_timeout_seconds);
        Some(tokio::spawn(async move {
            loop {
                let idle_for = state.activity.idle_for();
                if idle_for >= timeout {
                    if state.fuzzer.has_active_jobs() {
                        tokio::select! {
                            _ = state.shutdown.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_secs(30)) => continue,
                        }
                    }
                    tracing::info!(
                        idle_seconds = idle_for.as_secs(),
                        "control-plane inactivity timeout reached; shutting down"
                    );
                    state.shutdown.cancel();
                    break;
                }
                tokio::select! {
                    _ = state.shutdown.cancelled() => break,
                    _ = tokio::time::sleep(timeout - idle_for) => {}
                }
            }
        }))
    };

    // API
    {
        let st = state.clone();
        let token = shutdown.clone();
        servers.spawn(async move {
            crate::api::serve_api_listener(st, api_listener, token)
                .await
                .map_err(|error| ("api", error))
        });
    }

    // Proxy
    {
        let st = state.clone();
        let token = shutdown.clone();
        servers.spawn(async move {
            crate::proxy::serve_proxy_listener(st, proxy_listener, token)
                .await
                .map_err(|error| ("proxy", error))
        });
    }

    // Private UDS
    #[cfg(unix)]
    {
        let st = state.clone();
        let token = shutdown.clone();
        servers.spawn(async move {
            crate::api::serve_uds_listener(st, uds_listener, token)
                .await
                .map_err(|error| ("private socket", error))
        });
    }

    tracing::info!(
        api = %config.api_listen,
        proxy = %config.proxy_listen,
        "daemon ready"
    );

    let server_error = tokio::select! {
        _ = shutdown.cancelled() => None,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("ctrl-c received, shutting down");
            state.shutdown.cancel();
            None
        }
        _ = termination_signal() => {
            tracing::info!("termination signal received, shutting down");
            state.shutdown.cancel();
            None
        }
        result = servers.join_next() => {
            if shutdown.is_cancelled() {
                None
            } else {
                state.shutdown.cancel();
                match result {
                    Some(Ok(Err((name, error)))) => Some(DomainError::new(
                        ErrorCode::Unavailable,
                        format!("{name} server exited: {error}"),
                    )),
                    Some(Err(error)) => Some(DomainError::new(
                        ErrorCode::Unavailable,
                        format!("server task failed: {error}"),
                    )),
                    Some(Ok(Ok(()))) => Some(DomainError::new(
                        ErrorCode::Unavailable,
                        "server exited unexpectedly",
                    )),
                    None => Some(DomainError::new(ErrorCode::Unavailable, "no server tasks")),
                }
            }
        }
    };
    state.shutdown.cancel();
    match tokio::time::timeout(Duration::from_secs(5), state.browser.stop_all()).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => tracing::warn!(%error, "failed to stop every browser during shutdown"),
        Err(_) => {
            tracing::warn!("browser shutdown timed out; terminating the worker");
            state.browser.force_stop_all().await;
        }
    }
    while servers.join_next().await.is_some() {}
    if let Some(idle_monitor) = idle_monitor {
        let _ = idle_monitor.await;
    }
    cleanup_daemon_files(&config);
    match server_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn termination_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let _ = signal.recv().await;
            return;
        }
    }
    std::future::pending::<()>().await;
}

pub async fn bootstrap_state(config: Config) -> DomainResult<Arc<AppState>> {
    let db = Arc::new(Db::open(&config).await?);
    let interrupted = db.mark_browser_sessions_interrupted().await.unwrap_or(0);
    if interrupted > 0 {
        tracing::warn!(count = interrupted, "marked browser sessions interrupted");
    }
    let interrupted_fuzz = db.mark_fuzz_jobs_interrupted().await.unwrap_or(0);
    if interrupted_fuzz > 0 {
        tracing::warn!(count = interrupted_fuzz, "marked fuzz jobs interrupted");
    }

    let transport = build_default_transport(config.max_body_bytes);
    let key_bytes = std::fs::read(config.placeholder_key_path()).unwrap_or_else(|_| {
        let key = PlaceholderKey::load_or_create(&config.placeholder_key_path())
            .map(|_| ())
            .ok();
        let _ = key;
        std::fs::read(config.placeholder_key_path()).unwrap_or_else(|_| {
            let mut b = vec![0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
            let _ = crate::config::write_private_file(&config.placeholder_key_path(), &b);
            b
        })
    });

    let reply = Arc::new(ReplyService {
        db: db.clone(),
        transport: transport.clone(),
        placeholder_key: PlaceholderKey::from_bytes(key_bytes.clone()),
    });
    let fuzzer = Arc::new(FuzzerService::new(
        db.clone(),
        reply.clone(),
        PlaceholderKey::from_bytes(key_bytes),
    ));
    let managed_worker = config.browser_worker_path.clone().or_else(|| {
        crate::browser::prepare_browser_worker_installation(&config.data_dir)
            .ok()
            .map(|directory| directory.join("index.js"))
    });
    let browser = Arc::new(BrowserService::new_with_proxy_and_ca(
        db.clone(),
        config.lightpanda_path.clone(),
        config.node_path.clone(),
        managed_worker,
        format!("http://{}", config.proxy_listen),
        Some(config.ca_cert_path()),
        config.browser_profiles_dir(),
    ));
    let (events, _) = broadcast::channel(256);
    let crawler = Arc::new(CrawlerService::new(
        db.clone(),
        reply.clone(),
        browser.clone(),
        events.clone(),
    ));
    Ok(Arc::new(AppState {
        db,
        config,
        transport,
        reply,
        fuzzer,
        browser,
        crawler,
        events,
        shutdown: CancellationToken::new(),
        activity: ActivityTracker::new(),
    }))
}

#[derive(Debug)]
struct DaemonLock {
    #[cfg(unix)]
    _file: nix::fcntl::Flock<File>,
    #[cfg(not(unix))]
    _file: File,
}

fn acquire_daemon_lock(config: &Config) -> DomainResult<DaemonLock> {
    let lock_path = config.daemon_lock_path();
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| DomainError::new(ErrorCode::StorageError, format!("daemon lock: {e}")))?;
    #[cfg(unix)]
    let mut file = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|_| DomainError::new(ErrorCode::DaemonAlreadyRunning, "daemon already running"))?;
    #[cfg(not(unix))]
    let mut file = file;
    file.set_len(0)
        .map_err(|e| DomainError::new(ErrorCode::StorageError, format!("daemon lock: {e}")))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| DomainError::new(ErrorCode::StorageError, format!("daemon lock: {e}")))?;
    writeln!(file, "{}", std::process::id())
        .map_err(|e| DomainError::new(ErrorCode::StorageError, format!("daemon lock: {e}")))?;
    file.sync_data()
        .map_err(|e| DomainError::new(ErrorCode::StorageError, format!("daemon lock: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(DaemonLock { _file: file })
}

fn cleanup_daemon_files(config: &Config) {
    let _ = std::fs::remove_file(config.socket_path());
    let _ = std::fs::remove_file(config.daemon_lock_path());
}

pub async fn stop_daemon(config: &Config) -> DomainResult<()> {
    #[cfg(unix)]
    if request_private_shutdown(config).await.is_ok() {
        for _ in 0..50 {
            if !config.socket_path().exists() && !config.daemon_lock_path().exists() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[cfg(unix)]
    if daemon_lock_is_stale(config)? {
        cleanup_daemon_files(config);
        return Err(DomainError::new(
            ErrorCode::DaemonNotRunning,
            "daemon not running; removed stale runtime files",
        ));
    }

    if let Ok(pid_str) = std::fs::read_to_string(config.daemon_lock_path()) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            #[cfg(unix)]
            {
                if !process_is_huntproxy(pid) {
                    return Err(DomainError::new(
                        ErrorCode::DaemonNotRunning,
                        "daemon lock does not identify a HuntProxy process; refusing to signal it",
                    ));
                }
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGTERM,
                );
                for _ in 0..50 {
                    if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
                        cleanup_daemon_files(config);
                        return Ok(());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                return Err(DomainError::new(
                    ErrorCode::Timeout,
                    "daemon did not stop in time",
                ));
            }
        }
    }
    Err(DomainError::new(
        ErrorCode::DaemonNotRunning,
        "daemon not running",
    ))
}

#[cfg(unix)]
async fn request_private_shutdown(config: &Config) -> DomainResult<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::UnixStream::connect(config.socket_path())
        .await
        .map_err(|error| DomainError::new(ErrorCode::DaemonNotRunning, error.to_string()))?;
    stream
        .write_all(
            b"POST /internal/shutdown HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .map_err(|_| DomainError::new(ErrorCode::Timeout, "private shutdown timed out"))?
        .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
    if response.starts_with(b"HTTP/1.1 2") || response.starts_with(b"HTTP/1.0 2") {
        Ok(())
    } else {
        Err(DomainError::new(
            ErrorCode::ProtocolError,
            "private shutdown request failed",
        ))
    }
}

#[cfg(unix)]
fn daemon_lock_is_stale(config: &Config) -> DomainResult<bool> {
    let path = config.daemon_lock_path();
    let file = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => {
            return Err(DomainError::new(
                ErrorCode::StorageError,
                format!("daemon lock: {error}"),
            ))
        }
    };
    match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
        Ok(_) => Ok(true),
        Err((_file, nix::errno::Errno::EWOULDBLOCK)) => Ok(false),
        Err((_file, error)) => Err(DomainError::new(
            ErrorCode::StorageError,
            format!("daemon lock: {error}"),
        )),
    }
}

#[cfg(target_os = "linux")]
fn process_is_huntproxy(pid: i32) -> bool {
    let Ok(executable) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    executable
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("HuntProxy"))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_is_huntproxy(pid: i32) -> bool {
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|path| {
            std::path::Path::new(path.trim())
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .is_some_and(|name| name.eq_ignore_ascii_case("HuntProxy"))
}

pub fn daemon_status(config: &Config) -> DomainResult<serde_json::Value> {
    let lock = config.daemon_lock_path();
    if !lock.exists() {
        return Ok(serde_json::json!({
            "running": false,
            "data_dir": config.data_dir,
        }));
    }
    let pid = std::fs::read_to_string(&lock)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok());
    let alive = pid
        .map(|p| {
            #[cfg(unix)]
            {
                nix::sys::signal::kill(nix::unistd::Pid::from_raw(p), None).is_ok()
            }
            #[cfg(not(unix))]
            {
                let _ = p;
                true
            }
        })
        .unwrap_or(false);
    Ok(serde_json::json!({
        "running": alive,
        "pid": pid,
        "socket": config.socket_path().exists(),
        "data_dir": config.data_dir,
        "api_listen": config.api_listen.to_string(),
        "proxy_listen": config.proxy_listen.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_lock_is_exclusive_and_reusable() {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            data_dir: temp.path().to_path_buf(),
            ..Config::default()
        };
        config.ensure_layout().unwrap();

        let first = acquire_daemon_lock(&config).unwrap();
        let second = acquire_daemon_lock(&config).unwrap_err();
        assert_eq!(second.code(), ErrorCode::DaemonAlreadyRunning);
        drop(first);
        acquire_daemon_lock(&config).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stop_removes_stale_runtime_files_without_signaling_pid() {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            data_dir: temp.path().to_path_buf(),
            runtime_dir: temp.path().join("runtime"),
            ..Config::default()
        };
        config.ensure_layout().unwrap();
        std::fs::write(config.daemon_lock_path(), std::process::id().to_string()).unwrap();
        std::fs::write(config.socket_path(), b"stale").unwrap();

        let error = stop_daemon(&config).await.unwrap_err();

        assert_eq!(error.code(), ErrorCode::DaemonNotRunning);
        assert!(!config.daemon_lock_path().exists());
        assert!(!config.socket_path().exists());
    }
}
