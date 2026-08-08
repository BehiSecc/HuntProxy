//! HuntProxy CLI entry points.

use bb::app;
use bb::config::Config;
use bb::domain::{CreateProjectRequest, DomainError, DomainResult, ErrorCode};
use clap::{Parser, Subcommand};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

const MAX_DAEMON_LOG_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Parser, Debug)]
#[command(
    name = "HuntProxy",
    version,
    about = "Local-first agent-safe HTTP workbench"
)]
struct Cli {
    #[arg(long, global = true, env = "HUNTPROXY_DATA_DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create data directory, config, database, and CA.
    Init,
    /// Run the daemon (API, proxy, private socket).
    Serve {
        #[arg(long, default_value_t = true)]
        foreground: bool,
    },
    /// Stdio MCP bridge (auto-starts daemon if needed).
    Mcp,
    /// Diagnostics.
    Doctor,
    /// Daemon status.
    Status,
    /// Graceful stop.
    Stop,
    /// Project commands.
    Project {
        #[command(subcommand)]
        cmd: ProjectCmd,
    },
    /// History retention commands.
    History {
        #[command(subcommand)]
        cmd: HistoryCmd,
    },
    /// Create a consistent SQLite database backup.
    Backup { destination: PathBuf },
    /// HAR 1.2 history import/export.
    Har {
        #[command(subcommand)]
        cmd: HarCmd,
    },
    /// Browser artifact install helper.
    Browser {
        #[command(subcommand)]
        cmd: BrowserCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ProjectCmd {
    Create {
        name: String,
        target_url: String,
    },
    List,
    Rename {
        id: i64,
        name: String,
    },
    Delete {
        id: i64,
    },
    Usage {
        id: i64,
    },
    /// Recalculate persisted usage counters (all projects when ID is omitted).
    Reconcile {
        id: Option<i64>,
    },
    Export {
        id: i64,
        output: PathBuf,
        /// Include credentials, bodies, replay state, and browser state.
        #[arg(long)]
        include_secrets: bool,
        /// Include the best-effort, same-platform Chromium profile.
        #[arg(long, requires = "include_secrets")]
        include_chromium_profile: bool,
    },
    Import {
        input: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum HarCmd {
    Export {
        project_id: i64,
        output: PathBuf,
        #[arg(long)]
        include_secrets: bool,
    },
    Import {
        project_id: i64,
        input: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum HistoryCmd {
    /// Delete exchanges strictly older than an RFC 3339 timestamp.
    Clear {
        project_id: i64,
        #[arg(long)]
        before: String,
    },
}

#[derive(Subcommand, Debug)]
enum BrowserCmd {
    Install {
        /// Also ask Playwright to install Linux browser system dependencies.
        #[arg(long)]
        with_deps: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> DomainResult<()> {
    match cli.command {
        Commands::Init => {
            init_logging("info");
            let mut cfg = Config::default();
            if let Some(d) = cli.data_dir {
                cfg.data_dir = d;
                cfg.spool_dir = cfg.data_dir.join("spool");
                cfg.export_dir = cfg.data_dir.join("exports");
                cfg.runtime_dir = cfg.data_dir.join("runtime");
                cfg.plugin_dir = cfg.data_dir.join("plugins");
            }
            cfg.ensure_layout()?;
            cfg.write_default_config()?;
            // Create DB via open
            let db = bb::storage::Db::open(&cfg).await?;
            let ver = db.schema_version().await?;
            // Generate CA
            generate_ca(&cfg)?;
            // Placeholder key
            let _ = bb::reply::PlaceholderKey::load_or_create(&cfg.placeholder_key_path())?;
            println!("Initialized {}", cfg.data_dir.display());
            println!("  database: {} (schema v{ver})", cfg.db_path().display());
            println!("  CA cert:  {}", cfg.ca_cert_path().display());
            println!("  config:   {}", cfg.data_dir.join("config.toml").display());
            println!();
            println!("Next: HuntProxy serve");
            println!("  UI:    http://{}", cfg.api_listen);
            println!("  proxy: {}", cfg.proxy_listen);
            Ok(())
        }
        Commands::Serve { foreground: _ } => {
            let mut cfg = Config::load(cli.data_dir)?;
            bb::mcp::clear_stop_guard(&cfg);
            let auto_started = std::env::var_os("HUNTPROXY_DAEMONIZED").is_some();
            configure_daemon_mode(&mut cfg, auto_started);
            let mirror_to_stderr = !auto_started;
            init_daemon_logging(&cfg.log_level, cfg.daemon_log_path(), mirror_to_stderr);
            // Ensure CA exists
            if !cfg.ca_cert_path().exists() {
                generate_ca(&cfg)?;
            }
            println!(
                "HuntProxy serve\n  UI:    http://{}\n  proxy: {}\n  data:  {}",
                cfg.api_listen,
                cfg.proxy_listen,
                cfg.data_dir.display()
            );
            app::run_daemon(cfg).await
        }
        Commands::Mcp => {
            // MCP: logs to stderr only
            init_logging_stderr("warn");
            let cfg = Config::load(cli.data_dir.clone())?;
            if bb::mcp::stop_guard_blocks_start(&cfg) {
                return Err(DomainError::new(
                    ErrorCode::DaemonNotRunning,
                    "HuntProxy was explicitly stopped for this MCP client; restart the client to use it again",
                ));
            }
            ensure_daemon(&cfg).await?;
            bb::mcp::run_stdio_mcp_client(cfg).await
        }
        Commands::Doctor => {
            init_logging("error");
            let cfg = Config::load(cli.data_dir)?;
            println!("HuntProxy doctor");
            println!("  data_dir: {}", cfg.data_dir.display());
            println!(
                "  db:       {} exists={}",
                cfg.db_path().display(),
                cfg.db_path().exists()
            );
            println!(
                "  ca:       {} exists={}",
                cfg.ca_cert_path().display(),
                cfg.ca_cert_path().exists()
            );
            println!(
                "  socket:   {} exists={}",
                cfg.socket_path().display(),
                cfg.socket_path().exists()
            );
            println!("  api:      {}", cfg.api_listen);
            println!("  proxy:    {}", cfg.proxy_listen);
            println!("  idle:     {} seconds", cfg.idle_timeout_seconds);
            println!("  log:      {}", cfg.daemon_log_path().display());
            if let Some(p) = &cfg.node_path {
                println!("  node:       {} exists={}", p.display(), p.exists());
            } else {
                println!("  node:       (not in PATH)");
            }
            if cfg.socket_path().exists() {
                match daemon_get(&cfg, "/api/v1/doctor").await {
                    Ok(v) => println!("  daemon:     running\n{v}"),
                    Err(e) => println!("  daemon:     socket present but unhealthy: {e}"),
                }
            } else {
                println!("  daemon:     not running");
            }
            if let Some(output) = read_log_tail(&cfg.daemon_startup_log_path(), 4 * 1024) {
                println!("  last startup output:\n{output}");
            }
            Ok(())
        }
        Commands::Status => {
            init_logging("error");
            let cfg = Config::load(cli.data_dir)?;
            if !cfg.socket_path().exists() {
                println!("daemon: not running");
                return Ok(());
            }
            match daemon_get(&cfg, "/api/v1/health").await {
                Ok(v) => {
                    println!("daemon: running");
                    println!("{v}");
                }
                Err(e) => println!("daemon: unhealthy ({e})"),
            }
            Ok(())
        }
        Commands::Stop => {
            init_logging("error");
            let cfg = Config::load(cli.data_dir)?;
            app::stop_daemon(&cfg).await?;
            println!("daemon stopped");
            Ok(())
        }
        Commands::Project { cmd } => {
            init_logging("error");
            let cfg = Config::load(cli.data_dir)?;
            ensure_daemon(&cfg).await?;
            match cmd {
                ProjectCmd::Create { name, target_url } => {
                    let body = serde_json::to_string(&CreateProjectRequest {
                        name,
                        target_url,
                        advanced: None,
                    })
                    .unwrap();
                    let v = daemon_post(&cfg, "/api/v1/projects", &body).await?;
                    println!("{v}");
                }
                ProjectCmd::List => {
                    let v = daemon_get(&cfg, "/api/v1/projects").await?;
                    println!("{v}");
                }
                ProjectCmd::Rename { id, name } => {
                    let body = serde_json::json!({ "name": name }).to_string();
                    let value = daemon_request(
                        &cfg,
                        "PATCH",
                        &format!("/api/v1/projects/{id}"),
                        Some(&body),
                    )
                    .await?;
                    println!("{value}");
                }
                ProjectCmd::Delete { id } => {
                    daemon_request(&cfg, "DELETE", &format!("/api/v1/projects/{id}"), None).await?;
                    println!("Deleted project {id}");
                }
                ProjectCmd::Usage { id } => {
                    let value = daemon_get(&cfg, &format!("/api/v1/projects/{id}/usage")).await?;
                    println!("{value}");
                }
                ProjectCmd::Reconcile { id } => {
                    let db = bb::storage::Db::open(&cfg).await?;
                    let project_ids = match id {
                        Some(id) => vec![bb::domain::ProjectId(id)],
                        None => db
                            .list_projects()
                            .await?
                            .into_iter()
                            .map(|project| project.id)
                            .collect(),
                    };
                    for project_id in project_ids {
                        let result = db.reconcile_project_usage(project_id).await?;
                        println!(
                            "project {}: {} -> {} bytes{}",
                            project_id.get(),
                            result.previous_accounted_bytes,
                            result.accounted_bytes,
                            if result.changed { " (repaired)" } else { "" }
                        );
                    }
                }
                ProjectCmd::Export {
                    id,
                    output,
                    include_secrets,
                    include_chromium_profile,
                } => {
                    let db = bb::storage::Db::open(&cfg).await?;
                    db.export_bundle(
                        &cfg,
                        bb::domain::ProjectId(id),
                        output.clone(),
                        bb::transfer::BundleExportOptions {
                            secrets: if include_secrets {
                                bb::transfer::SecretMode::Full
                            } else {
                                bb::transfer::SecretMode::Sanitized
                            },
                            include_chromium_profile,
                        },
                    )
                    .await?;
                    println!("Exported project {id} to {}", output.display());
                }
                ProjectCmd::Import { input } => {
                    let db = bb::storage::Db::open(&cfg).await?;
                    let project = if input
                        .extension()
                        .is_some_and(|extension| extension == "json")
                    {
                        let encoded = std::fs::read(&input).map_err(|error| {
                            DomainError::new(ErrorCode::StorageError, error.to_string())
                        })?;
                        let archive: bb::storage::ProjectArchive = serde_json::from_slice(&encoded)
                            .map_err(|error| {
                                DomainError::invalid(format!("invalid v1 project archive: {error}"))
                            })?;
                        db.import_project(archive).await?
                    } else {
                        db.import_bundle(&cfg, input, None).await?.project
                    };
                    println!("Imported project {} ({})", project.id.get(), project.name);
                }
            }
            Ok(())
        }
        Commands::History { cmd } => {
            init_logging("error");
            let cfg = Config::load(cli.data_dir)?;
            ensure_daemon(&cfg).await?;
            match cmd {
                HistoryCmd::Clear { project_id, before } => {
                    let query = url::form_urlencoded::Serializer::new(String::new())
                        .append_pair("before", &before)
                        .finish();
                    let value = daemon_request(
                        &cfg,
                        "DELETE",
                        &format!("/api/v1/projects/{project_id}/history?{query}"),
                        None,
                    )
                    .await?;
                    println!("{value}");
                }
            }
            Ok(())
        }
        Commands::Backup { destination } => {
            init_logging("error");
            let cfg = Config::load(cli.data_dir)?;
            let db = bb::storage::Db::open(&cfg).await?;
            let path = db.backup_to(destination).await?;
            println!("Backup written to {}", path.display());
            Ok(())
        }
        Commands::Har { cmd } => {
            init_logging("error");
            let cfg = Config::load(cli.data_dir)?;
            let db = bb::storage::Db::open(&cfg).await?;
            match cmd {
                HarCmd::Export {
                    project_id,
                    output,
                    include_secrets,
                } => {
                    let har = db
                        .export_har(bb::domain::ProjectId(project_id), include_secrets)
                        .await?;
                    if let Some(parent) = output.parent() {
                        bb::config::create_private_dir(parent)?;
                    }
                    let file = std::fs::OpenOptions::new()
                        .create(true)
                        .truncate(true)
                        .write(true)
                        .open(&output)
                        .map_err(|error| {
                            DomainError::new(ErrorCode::StorageError, error.to_string())
                        })?;
                    serde_json::to_writer(file, &har).map_err(|error| {
                        DomainError::new(ErrorCode::StorageError, error.to_string())
                    })?;
                    println!("Exported HAR to {}", output.display());
                }
                HarCmd::Import { project_id, input } => {
                    let result = db
                        .import_har_file(bb::domain::ProjectId(project_id), &input)
                        .await?;
                    println!("Imported {} HAR entries", result.imported_entries);
                }
            }
            Ok(())
        }
        Commands::Browser { cmd } => {
            init_logging("info");
            match cmd {
                BrowserCmd::Install { with_deps } => {
                    let cfg = Config::load(cli.data_dir)?;
                    println!("Installing browser-worker dependencies…");
                    let worker = bb::browser::prepare_browser_worker_installation(&cfg.data_dir)?;
                    let status = std::process::Command::new("npm")
                        .args(["ci"])
                        .current_dir(&worker)
                        .status()
                        .map_err(|e| DomainError::new(ErrorCode::Unavailable, e.to_string()))?;
                    if !status.success() {
                        return Err(DomainError::new(
                            ErrorCode::Unavailable,
                            "npm install failed",
                        ));
                    }
                    let playwright_cli = worker.join("node_modules/playwright-core/cli.js");
                    let mut args = vec!["install"];
                    if with_deps {
                        args.push("--with-deps");
                    }
                    args.push("chromium");
                    println!("Installing Playwright Chromium…");
                    let status = std::process::Command::new("node")
                        .arg(playwright_cli)
                        .args(args)
                        .current_dir(&worker)
                        .env("PLAYWRIGHT_BROWSERS_PATH", "0")
                        .status()
                        .map_err(|e| DomainError::new(ErrorCode::Unavailable, e.to_string()))?;
                    if !status.success() {
                        return Err(DomainError::new(
                            ErrorCode::Unavailable,
                            "Playwright Chromium installation failed",
                        ));
                    }
                    println!("Browser runtime installed in {}", worker.display());
                    Ok(())
                }
            }
        }
    }
}

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

fn configure_daemon_mode(config: &mut Config, auto_started: bool) {
    if !auto_started {
        config.idle_timeout_seconds = 0;
    }
}

fn init_logging_stderr(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

#[derive(Clone)]
struct DaemonLogMakeWriter {
    path: PathBuf,
    mirror_to_stderr: bool,
    lock: Arc<Mutex<()>>,
}

struct DaemonLogWriter {
    path: PathBuf,
    mirror_to_stderr: bool,
    lock: Arc<Mutex<()>>,
}

impl<'a> MakeWriter<'a> for DaemonLogMakeWriter {
    type Writer = DaemonLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        DaemonLogWriter {
            path: self.path.clone(),
            mirror_to_stderr: self.mirror_to_stderr,
            lock: self.lock.clone(),
        }
    }
}

impl std::io::Write for DaemonLogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.mirror_to_stderr {
            let _ = std::io::stderr().write_all(bytes);
        }
        let Ok(_guard) = self.lock.lock() else {
            return Ok(bytes.len());
        };
        if let Some(parent) = self.path.parent() {
            let _ = bb::config::create_private_dir(parent);
        }
        let current = std::fs::metadata(&self.path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if current.saturating_add(bytes.len() as u64) > MAX_DAEMON_LOG_BYTES {
            let rotated = self.path.with_extension("log.1");
            let _ = std::fs::remove_file(&rotated);
            let _ = std::fs::rename(&self.path, rotated);
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if let Ok(mut file) = options.open(&self.path) {
            let slice = if bytes.len() as u64 > MAX_DAEMON_LOG_BYTES {
                &bytes[bytes.len() - MAX_DAEMON_LOG_BYTES as usize..]
            } else {
                bytes
            };
            let _ = file.write_all(slice);
            let _ = file.flush();
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.mirror_to_stderr {
            let _ = std::io::stderr().flush();
        }
        Ok(())
    }
}

fn init_daemon_logging(level: &str, path: PathBuf, mirror_to_stderr: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let writer = DaemonLogMakeWriter {
        path,
        mirror_to_stderr,
        lock: Arc::new(Mutex::new(())),
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_target(false)
        .try_init();
}

fn read_log_tail(path: &std::path::Path, max_bytes: usize) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let start = bytes.len().saturating_sub(max_bytes);
    Some(String::from_utf8_lossy(&bytes[start..]).into_owned())
}

fn generate_ca(cfg: &Config) -> DomainResult<()> {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let mut params = CertificateParams::new(vec!["HuntProxy local CA".into()])
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate()
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    bb::config::write_private_file(cfg.ca_cert_path().as_path(), cert.pem().as_bytes())?;
    bb::config::write_private_file(cfg.ca_key_path().as_path(), key.serialize_pem().as_bytes())?;
    Ok(())
}

async fn ensure_daemon(cfg: &Config) -> DomainResult<()> {
    if cfg.socket_path().exists() && daemon_get(cfg, "/api/v1/health").await.is_ok() {
        return Ok(());
    }
    if !cfg.auto_start_daemon {
        return Err(DomainError::new(
            ErrorCode::DaemonNotRunning,
            "daemon not running; start with HuntProxy serve",
        ));
    }
    // Serialize auto-start attempts. Re-check health after acquiring the lock:
    // another CLI may have started the daemon while this process was waiting.
    let boot = cfg.bootstrap_lock_path();
    let boot_file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&boot)
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    #[cfg(unix)]
    let _bootstrap_lock = tokio::task::spawn_blocking(move || {
        nix::fcntl::Flock::lock(boot_file, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_, error)| error)
    })
    .await
    .map_err(|e| DomainError::new(ErrorCode::Internal, format!("bootstrap lock task: {e}")))?
    .map_err(|e| DomainError::new(ErrorCode::StorageError, format!("bootstrap lock: {e}")))?;
    #[cfg(not(unix))]
    let _bootstrap_lock = boot_file;

    if daemon_get(cfg, "/api/v1/health").await.is_ok() {
        return Ok(());
    }

    let bin = std::env::current_exe()
        .map_err(|e| DomainError::new(ErrorCode::Internal, e.to_string()))?;
    let startup_log_path = cfg.daemon_startup_log_path();
    let mut startup_options = OpenOptions::new();
    startup_options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        startup_options.mode(0o600);
    }
    let startup_stdout = startup_options.open(&startup_log_path).map_err(|error| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("startup log {}: {error}", startup_log_path.display()),
        )
    })?;
    let startup_stderr = startup_stdout.try_clone().map_err(|error| {
        DomainError::new(ErrorCode::StorageError, format!("startup log: {error}"))
    })?;
    let mut cmd = std::process::Command::new(bin);
    cmd.arg("serve")
        .arg("--data-dir")
        .arg(&cfg.data_dir)
        .env("HUNTPROXY_DAEMONIZED", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(startup_stdout))
        .stderr(Stdio::from(startup_stderr));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| DomainError::new(ErrorCode::Unavailable, format!("auto-start failed: {e}")))?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });

    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if daemon_get(cfg, "/api/v1/health").await.is_ok() {
            return Ok(());
        }
    }
    let detail = read_log_tail(&startup_log_path, 4 * 1024)
        .filter(|output| !output.trim().is_empty())
        .map(|output| format!("\nlast startup output:\n{}", output.trim_end()))
        .unwrap_or_default();
    Err(DomainError::new(
        ErrorCode::Unavailable,
        format!(
            "daemon did not become ready; check {}{detail}",
            startup_log_path.display()
        ),
    ))
}

async fn daemon_get(cfg: &Config, path: &str) -> DomainResult<String> {
    let url = format!("http://{}{path}", cfg.api_listen);
    let client = reqwest_get(&url).await?;
    Ok(client)
}

async fn daemon_post(cfg: &Config, path: &str, body: &str) -> DomainResult<String> {
    let url = format!("http://{}{path}", cfg.api_listen);
    // Use hyper client manually to avoid requiring reqwest in bin always —
    // use tokio tcp + simple HTTP.
    simple_http("POST", &url, Some(body)).await
}

async fn daemon_request(
    cfg: &Config,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> DomainResult<String> {
    let url = format!("http://{}{path}", cfg.api_listen);
    simple_http(method, &url, body).await
}

async fn reqwest_get(url: &str) -> DomainResult<String> {
    simple_http("GET", url, None).await
}

async fn simple_http(method: &str, url: &str, body: Option<&str>) -> DomainResult<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let u = url::Url::parse(url).map_err(|e| DomainError::invalid(e.to_string()))?;
    let host = u.host_str().unwrap_or("127.0.0.1");
    let port = u.port_or_known_default().unwrap_or(80);
    let path = if u.query().is_some() {
        format!("{}?{}", u.path(), u.query().unwrap())
    } else {
        u.path().to_string()
    };
    let mut stream = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| DomainError::new(ErrorCode::DaemonNotRunning, e.to_string()))?;
    let payload = body.unwrap_or("");
    let req = if body.is_some() {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        )
    } else {
        format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n")
    };
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    if text.starts_with("HTTP/1.1 2") || text.starts_with("HTTP/1.0 2") {
        Ok(body)
    } else {
        Err(DomainError::new(
            ErrorCode::Unavailable,
            format!(
                "daemon HTTP error: {}",
                body.chars().take(200).collect::<String>()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_log_rotates_at_the_size_limit() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("daemon.log");
        std::fs::write(&path, vec![b'a'; MAX_DAEMON_LOG_BYTES as usize]).unwrap();
        let mut writer = DaemonLogWriter {
            path: path.clone(),
            mirror_to_stderr: false,
            lock: Arc::new(Mutex::new(())),
        };

        std::io::Write::write_all(&mut writer, b"next\n").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"next\n");
        assert_eq!(
            std::fs::metadata(path.with_extension("log.1"))
                .unwrap()
                .len(),
            MAX_DAEMON_LOG_BYTES
        );
    }

    #[test]
    fn explicitly_started_daemon_has_no_idle_shutdown() {
        let mut explicit = Config {
            idle_timeout_seconds: 3600,
            ..Config::default()
        };
        configure_daemon_mode(&mut explicit, false);
        assert_eq!(explicit.idle_timeout_seconds, 0);

        let mut automatic = Config {
            idle_timeout_seconds: 3600,
            ..Config::default()
        };
        configure_daemon_mode(&mut automatic, true);
        assert_eq!(automatic.idle_timeout_seconds, 3600);
    }
}
