//! HuntProxy CLI entry points.

use bb::app;
use bb::config::Config;
use bb::domain::{CreateProjectRequest, DomainError, DomainResult, ErrorCode};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

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
    /// Browser artifact install helper.
    Browser {
        #[command(subcommand)]
        cmd: BrowserCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ProjectCmd {
    Create { name: String, target_url: String },
    List,
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
            let cfg = Config::load(cli.data_dir)?;
            bb::mcp::clear_stop_guard(&cfg);
            init_logging(&cfg.log_level);
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
            if let Some(p) = &cfg.lightpanda_path {
                println!("  lightpanda: {} exists={}", p.display(), p.exists());
            } else {
                println!("  lightpanda: (not in PATH)");
            }
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

fn init_logging_stderr(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
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
    let mut cmd = std::process::Command::new(bin);
    cmd.arg("serve")
        .arg("--data-dir")
        .arg(&cfg.data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
    Err(DomainError::new(
        ErrorCode::Unavailable,
        format!(
            "daemon did not become ready; check logs under {}",
            cfg.data_dir.display()
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
    let req = if method == "POST" {
        format!(
            "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        )
    } else {
        format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n")
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
