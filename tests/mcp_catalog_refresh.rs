//! Verify that a long-lived MCP bridge follows daemon tool-catalog upgrades.
#![cfg(unix)]

use huntproxy::config::Config;
use serde_json::{json, Value};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

struct Bridge {
    child: Child,
    input: ChildStdin,
    output: Lines<BufReader<ChildStdout>>,
    next_id: u64,
    _directory: TempDir,
}

impl Bridge {
    async fn start(auto_start_daemon: bool) -> (Self, Config) {
        std::fs::create_dir_all("/tmp/artis").unwrap();
        let directory = tempfile::Builder::new()
            .prefix("huntproxy-mcp-catalog-")
            .tempdir_in("/tmp/artis")
            .unwrap();
        let mut config = Config {
            data_dir: directory.path().to_owned(),
            spool_dir: directory.path().join("spool"),
            export_dir: directory.path().join("exports"),
            runtime_dir: directory.path().join("runtime"),
            plugin_dir: directory.path().join("plugins"),
            auto_start_daemon,
            ..Config::default()
        };
        config.ensure_layout().unwrap();
        config.write_default_config().unwrap();
        // The bridge reloads this file, including auto_start_daemon.
        config = Config::load(Some(directory.path().to_owned())).unwrap();

        let mut child = Command::new(env!("CARGO_BIN_EXE_HuntProxy"))
            .args(["mcp", "--data-dir"])
            .arg(directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap()).lines();
        (
            Self {
                child,
                input,
                output,
                next_id: 0,
                _directory: directory,
            },
            config,
        )
    }

    async fn send(&mut self, value: Value) {
        self.input
            .write_all(format!("{value}\n").as_bytes())
            .await
            .unwrap();
        self.input.flush().await.unwrap();
    }

    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .await;
        loop {
            let message = self.next_message(Duration::from_secs(10)).await;
            if message["id"] == id {
                return message;
            }
        }
    }

    async fn next_message(&mut self, timeout: Duration) -> Value {
        let line = tokio::time::timeout(timeout, self.output.next_line())
            .await
            .expect("MCP message timed out")
            .unwrap()
            .expect("MCP bridge closed stdout");
        serde_json::from_str(&line).unwrap()
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

#[derive(Clone)]
struct FakeDaemon {
    catalog: Arc<RwLock<Option<Value>>>,
    calls: Arc<Mutex<Vec<Value>>>,
}

impl FakeDaemon {
    fn new(catalog: Option<Value>) -> Self {
        Self {
            catalog: Arc::new(RwLock::new(catalog)),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn serve(self, listener: UnixListener, cancel: CancellationToken) -> std::io::Result<()> {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let daemon = self.clone();
                    tokio::spawn(async move {
                        daemon.handle(stream).await.unwrap();
                    });
                }
            }
        }
    }

    async fn handle(&self, mut stream: UnixStream) -> std::io::Result<()> {
        let mut request = Vec::new();
        let header_end = loop {
            let mut buffer = [0_u8; 1024];
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                return Ok(());
            }
            request.extend_from_slice(&buffer[..count]);
            if let Some(index) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break index + 4;
            }
            assert!(request.len() < 64 * 1024, "oversized synthetic request");
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let request_line = headers.lines().next().unwrap_or_default().to_owned();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let mut buffer = [0_u8; 1024];
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
        }

        let (status, body) = if request_line.starts_with("GET /api/v1/health ") {
            ("200 OK", json!({"ok": true}))
        } else if request_line.starts_with("GET /internal/mcp/tools ") {
            match self.catalog.read().await.clone() {
                Some(catalog) => ("200 OK", catalog),
                None => ("404 Not Found", json!({"error": "older daemon"})),
            }
        } else if request_line.starts_with("POST /internal/mcp/call ") {
            let call: Value = serde_json::from_slice(
                &request[header_end..header_end.saturating_add(content_length)],
            )
            .unwrap();
            self.calls.lock().await.push(call.clone());
            (
                "200 OK",
                json!({"result": {"accepted": call}, "error": null}),
            )
        } else {
            ("404 Not Found", json!({"error": "not found"}))
        };
        let body = serde_json::to_vec(&body).unwrap();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await?;
        stream.write_all(&body).await?;
        stream.shutdown().await
    }
}

fn catalog(version: &str, extra_tool: &str) -> Value {
    json!({
        "version": version,
        "protocol": 1,
        "tools": [
            {"name": "huntproxy_restart", "description": "Restart", "inputSchema": {"type": "object"}},
            {"name": extra_tool, "description": "Synthetic", "inputSchema": {"type": "object"}}
        ]
    })
}

async fn uds_get(path: &std::path::Path, route: &str) -> Value {
    let mut stream = UnixStream::connect(path).await.unwrap();
    stream
        .write_all(
            format!("GET {route} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let body_start = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    serde_json::from_slice(&response[body_start..]).unwrap()
}

#[tokio::test]
async fn connected_bridge_refreshes_tools_and_forwards_new_call_once() {
    let (mut bridge, config) = Bridge::start(false).await;
    let daemon = FakeDaemon::new(Some(catalog(env!("CARGO_PKG_VERSION"), "existing_action")));
    let listener = UnixListener::bind(config.socket_path()).unwrap();
    let cancel = CancellationToken::new();
    let server = tokio::spawn(daemon.clone().serve(listener, cancel.clone()));

    let initialized = bridge.rpc("initialize", json!({})).await;
    assert_eq!(
        initialized["result"]["capabilities"]["tools"]["listChanged"],
        true
    );
    bridge
        .send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    let initial_tools = bridge.rpc("tools/list", json!({})).await;
    assert!(initial_tools.to_string().contains("existing_action"));

    *daemon.catalog.write().await = Some(catalog(
        &format!("{}-next", env!("CARGO_PKG_VERSION")),
        "new_action",
    ));
    let notification = bridge.next_message(Duration::from_secs(8)).await;
    assert_eq!(notification["method"], "notifications/tools/list_changed");

    let refreshed = bridge.rpc("tools/list", json!({})).await;
    assert!(refreshed.to_string().contains("new_action"));
    assert!(!refreshed.to_string().contains("existing_action"));
    let called = bridge
        .rpc(
            "tools/call",
            json!({"name": "new_action", "arguments": {"value": 17}}),
        )
        .await;
    assert_eq!(
        called["result"]["structuredContent"]["accepted"]["name"],
        "new_action"
    );
    assert_eq!(
        daemon.calls.lock().await.as_slice(),
        &[json!({
            "name": "new_action",
            "arguments": {"value": 17}
        })]
    );

    cancel.cancel();
    server.await.unwrap().unwrap();
    std::fs::remove_file(config.socket_path()).unwrap();
    let while_stopped = bridge.rpc("tools/list", json!({})).await;
    assert!(while_stopped.to_string().contains("new_action"));
    assert!(!while_stopped.to_string().contains("existing_action"));
    assert!(
        !config.socket_path().exists(),
        "catalog fallback must not auto-start the daemon"
    );
}

#[tokio::test]
async fn stopped_or_older_daemon_uses_local_restart_definition() {
    let (mut stopped_bridge, stopped_config) = Bridge::start(false).await;
    let initialized = stopped_bridge.rpc("initialize", json!({})).await;
    assert_eq!(
        initialized["result"]["capabilities"]["tools"]["listChanged"],
        true
    );
    stopped_bridge
        .send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    let tools = stopped_bridge.rpc("tools/list", json!({})).await;
    assert!(tools.to_string().contains("huntproxy_restart"));
    assert!(!stopped_config.socket_path().exists());

    // Starting a newer daemon after initialization is still a catalog change,
    // even though there was no socket from which to establish the baseline.
    let new_daemon = FakeDaemon::new(Some(catalog(
        &format!("{}-next", env!("CARGO_PKG_VERSION")),
        "new_after_stop",
    )));
    let listener = UnixListener::bind(stopped_config.socket_path()).unwrap();
    let stopped_cancel = CancellationToken::new();
    let stopped_server = tokio::spawn(new_daemon.clone().serve(listener, stopped_cancel.clone()));
    let notification = stopped_bridge.next_message(Duration::from_secs(8)).await;
    assert_eq!(notification["method"], "notifications/tools/list_changed");
    let tools = stopped_bridge.rpc("tools/list", json!({})).await;
    assert!(tools.to_string().contains("new_after_stop"));
    stopped_cancel.cancel();
    stopped_server.await.unwrap().unwrap();

    let (mut older_bridge, older_config) = Bridge::start(false).await;
    let daemon = FakeDaemon::new(None);
    let listener = UnixListener::bind(older_config.socket_path()).unwrap();
    let cancel = CancellationToken::new();
    let server = tokio::spawn(daemon.serve(listener, cancel.clone()));
    older_bridge.rpc("initialize", json!({})).await;
    let tools = older_bridge.rpc("tools/list", json!({})).await;
    assert!(tools.to_string().contains("huntproxy_restart"));

    cancel.cancel();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn private_catalog_route_is_read_only_and_returns_current_tools() {
    std::fs::create_dir_all("/tmp/artis").unwrap();
    let directory = tempfile::Builder::new()
        .prefix("huntproxy-mcp-route-")
        .tempdir_in("/tmp/artis")
        .unwrap();
    let config = Config {
        data_dir: directory.path().to_owned(),
        spool_dir: directory.path().join("spool"),
        export_dir: directory.path().join("exports"),
        runtime_dir: directory.path().join("runtime"),
        plugin_dir: directory.path().join("plugins"),
        ..Config::default()
    };
    let state = huntproxy::app::bootstrap_state(config.clone())
        .await
        .unwrap();
    let listener = huntproxy::api::bind_uds(&config.socket_path()).unwrap();
    let cancel = CancellationToken::new();
    let server = tokio::spawn(huntproxy::api::serve_uds_listener(
        state.clone(),
        listener,
        cancel.clone(),
    ));

    tokio::time::sleep(Duration::from_millis(40)).await;
    let idle_before = state.activity.idle_for();
    let response = uds_get(&config.socket_path(), "/internal/mcp/tools").await;
    let idle_after = state.activity.idle_for();
    assert_eq!(response["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(response["protocol"], huntproxy::INTERNAL_PROTOCOL_VERSION);
    assert!(response["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| tool["name"] == "huntproxy_restart"));
    assert!(
        idle_after >= idle_before,
        "catalog polling must not extend daemon lifetime"
    );

    cancel.cancel();
    server.await.unwrap().unwrap();
}
