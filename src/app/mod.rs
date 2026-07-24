//! Application service wiring, daemon lifecycle, graceful shutdown.

use crate::browser::BrowserService;
use crate::config::Config;
use crate::domain::*;
use crate::fuzzer::FuzzerService;
use crate::reply::{PlaceholderKey, ReplyService};
use crate::storage::Db;
use crate::transport::{build_default_transport, SemanticTransport};
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
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
    pub events: broadcast::Sender<AppEvent>,
    pub shutdown: CancellationToken,
}

pub async fn run_daemon(config: Config) -> DomainResult<()> {
    config.ensure_layout()?;
    acquire_daemon_lock(&config)?;

    let state = bootstrap_state(config.clone()).await?;
    let shutdown = state.shutdown.clone();

    // API
    {
        let st = state.clone();
        let token = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::api::serve_api(st, token).await {
                tracing::error!(error = %e, "api server exited");
            }
        });
    }

    // Proxy
    {
        let st = state.clone();
        let token = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::proxy::serve_proxy(st, token).await {
                tracing::error!(error = %e, "proxy server exited");
            }
        });
    }

    // Private UDS
    {
        let st = state.clone();
        let token = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::api::serve_uds(st, token).await {
                tracing::error!(error = %e, "private socket exited");
            }
        });
    }

    tracing::info!(
        api = %config.api_listen,
        proxy = %config.proxy_listen,
        "daemon ready"
    );

    tokio::select! {
        _ = shutdown.cancelled() => {}
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("ctrl-c received, shutting down");
            state.shutdown.cancel();
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    cleanup_daemon_files(&config);
    Ok(())
}

pub async fn bootstrap_state(config: Config) -> DomainResult<Arc<AppState>> {
    let db = Arc::new(Db::open(&config).await?);
    let interrupted = db.mark_browser_sessions_interrupted().await.unwrap_or(0);
    if interrupted > 0 {
        tracing::warn!(count = interrupted, "marked browser sessions interrupted");
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
    let browser = Arc::new(BrowserService::new(
        db.clone(),
        config.lightpanda_path.clone(),
        config.node_path.clone(),
        config.browser_worker_path.clone().or_else(|| {
            let p = PathBuf::from("browser-worker/index.js");
            if p.exists() {
                Some(p)
            } else {
                None
            }
        }),
    ));
    let (events, _) = broadcast::channel(256);
    Ok(Arc::new(AppState {
        db,
        config,
        transport,
        reply,
        fuzzer,
        browser,
        events,
        shutdown: CancellationToken::new(),
    }))
}

fn acquire_daemon_lock(config: &Config) -> DomainResult<()> {
    let lock_path = config.daemon_lock_path();
    if lock_path.exists() {
        if let Ok(pid_str) = std::fs::read_to_string(&lock_path) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                #[cfg(unix)]
                {
                    if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok() {
                        return Err(DomainError::new(
                            ErrorCode::DaemonAlreadyRunning,
                            format!("daemon already running (pid {pid})"),
                        ));
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&lock_path);
        let _ = std::fs::remove_file(config.socket_path());
    }
    let mut f = File::create(&lock_path).map_err(|e| {
        DomainError::new(ErrorCode::StorageError, format!("daemon lock: {e}"))
    })?;
    writeln!(f, "{}", std::process::id()).ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn cleanup_daemon_files(config: &Config) {
    let _ = std::fs::remove_file(config.socket_path());
    let _ = std::fs::remove_file(config.daemon_lock_path());
}

pub async fn stop_daemon(config: &Config) -> DomainResult<()> {
    if let Ok(pid_str) = std::fs::read_to_string(config.daemon_lock_path()) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            #[cfg(unix)]
            {
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
