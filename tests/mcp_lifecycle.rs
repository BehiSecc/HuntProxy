//! Exercise lifecycle operations through a real, continuously connected agent.
#![cfg(unix)]

use huntproxy::config::Config;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

fn local_browser_fixture() -> PathBuf {
    for name in [
        "HUNTPROXY_CHROME_EXECUTABLE",
        "BB_CHROME_EXECUTABLE",
        "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH",
    ] {
        if let Some(path) = std::env::var_os(name).map(PathBuf::from) {
            assert!(
                path.is_file(),
                "{name} does not point to a local browser: {}",
                path.display()
            );
            return path;
        }
    }

    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            for executable in [
                "google-chrome",
                "google-chrome-stable",
                "chromium",
                "chromium-browser",
            ] {
                let candidate = directory.join(executable);
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }

    for candidate in [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
    ] {
        let candidate = Path::new(candidate);
        if candidate.is_file() {
            return candidate.to_owned();
        }
    }

    panic!("mcp lifecycle tests require a local Chromium fixture; set HUNTPROXY_CHROME_EXECUTABLE");
}

struct Agent {
    bridge: Child,
    input: ChildStdin,
    output: Lines<BufReader<ChildStdout>>,
    config: Config,
    _directory: TempDir,
    next_id: u64,
}

impl Agent {
    async fn start(auto_start_daemon: bool) -> Self {
        std::fs::create_dir_all("/tmp/artis").unwrap();
        let directory = tempfile::Builder::new()
            .prefix("huntproxy-mcp-lifecycle-")
            .tempdir_in("/tmp/artis")
            .unwrap();
        let api = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let config = Config {
            data_dir: directory.path().to_owned(),
            spool_dir: directory.path().join("spool"),
            export_dir: directory.path().join("exports"),
            runtime_dir: directory.path().join("runtime"),
            plugin_dir: directory.path().join("plugins"),
            api_listen: api.local_addr().unwrap(),
            proxy_listen: proxy.local_addr().unwrap(),
            idle_timeout_seconds: 1,
            auto_start_daemon,
            ..Config::default()
        };
        config.ensure_layout().unwrap();
        config.write_default_config().unwrap();
        drop((api, proxy));
        let browser = local_browser_fixture();
        // Prepare the installation before measuring lifecycle RPC responses.
        // Fresh Node provisioning and browser validation have their own limits.
        let prepared = Command::new(env!("CARGO_BIN_EXE_HuntProxy"))
            .args(["prepare-update", "--data-dir"])
            .arg(directory.path())
            .env("HUNTPROXY_CHROME_EXECUTABLE", &browser)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .await
            .expect("prepare local runtime fixture");
        assert!(prepared.success(), "local runtime fixture did not prepare");
        let mut command = Command::new(env!("CARGO_BIN_EXE_HuntProxy"));
        command
            .args(["mcp", "--data-dir"])
            .arg(directory.path())
            // Lifecycle coverage should not include a managed-browser download.
            // CI and developer hosts provide this maintained browser fixture.
            .env("HUNTPROXY_CHROME_EXECUTABLE", browser)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let mut bridge = command.spawn().unwrap();
        let input = bridge.stdin.take().unwrap();
        let output = BufReader::new(bridge.stdout.take().unwrap()).lines();
        Self {
            bridge,
            input,
            output,
            config,
            _directory: directory,
            next_id: 0,
        }
    }

    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let request =
            json!({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params});
        self.input
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        self.input.flush().await.unwrap();
        let line = tokio::time::timeout(Duration::from_secs(20), self.output.next_line())
            .await
            .expect("MCP response timed out")
            .unwrap()
            .expect("MCP bridge closed the connection");
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], self.next_id);
        response
    }

    async fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let response = self
            .rpc("tools/call", json!({"name": name, "arguments": arguments}))
            .await;
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["isError"], false, "{response}");
        response["result"]["structuredContent"].clone()
    }

    async fn wait_stopped(&self) {
        for _ in 0..100 {
            if !huntproxy::app::daemon_is_active(&self.config).unwrap() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("daemon did not stop");
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.bridge.start_kill();
        let _ = std::process::Command::new(env!("CARGO_BIN_EXE_HuntProxy"))
            .args(["stop", "--data-dir"])
            .arg(&self.config.data_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[tokio::test]
async fn agent_continues_after_idle_explicit_stop_restart_and_crash() {
    let mut agent = Agent::start(true).await;
    let initialized = agent.rpc("initialize", json!({})).await;
    assert_eq!(initialized["result"]["serverInfo"]["name"], "HuntProxy");
    let tools = agent.rpc("tools/list", json!({})).await;
    assert!(tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| tool["name"] == "huntproxy_restart"));
    let project = agent
        .tool(
            "projects",
            json!({"action": "create", "name": "Session persistence", "target_url": "https://example.test"}),
        )
        .await;

    // The daemon may go idle, but the connected agent can keep working.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    agent.wait_stopped().await;
    agent.tool("projects", json!({"action": "list"})).await;

    agent.tool("huntproxy_stop", json!({})).await;
    agent.wait_stopped().await;
    let blocked = agent
        .rpc(
            "tools/call",
            json!({"name": "projects", "arguments": {"action": "list"}}),
        )
        .await;
    assert_eq!(blocked["error"]["data"]["code"], "daemon_not_running");
    assert!(blocked["error"]["message"]
        .as_str()
        .unwrap()
        .contains("huntproxy_restart"));
    let restarted = agent.tool("huntproxy_restart", json!({})).await;
    assert_eq!(restarted["ok"], true);
    let saved = agent.tool("projects", json!({"action": "list"})).await;
    assert!(saved.to_string().contains("Session persistence"));
    assert!(saved.to_string().contains(&project["id"].to_string()));

    // Recover a stale socket/lock after abrupt termination without replaying
    // the previous operation or replacing the agent's stdio connection.
    let pid: i32 = std::fs::read_to_string(agent.config.daemon_lock_path())
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    agent.wait_stopped().await;
    let recovered = agent.tool("projects", json!({"action": "list"})).await;
    assert!(recovered.to_string().contains("Session persistence"));

    // Explicit restart also succeeds while a daemon is already running.
    agent.tool("huntproxy_restart", json!({})).await;
    agent.tool("projects", json!({"action": "list"})).await;
}

#[tokio::test]
async fn explicit_restart_is_available_when_auto_start_is_disabled() {
    let mut agent = Agent::start(false).await;
    let initialized = agent.rpc("initialize", json!({})).await;
    assert!(initialized.get("error").is_none());
    let stopped = agent
        .rpc(
            "tools/call",
            json!({"name": "projects", "arguments": {"action": "list"}}),
        )
        .await;
    assert_eq!(stopped["error"]["data"]["code"], "daemon_not_running");
    assert!(!huntproxy::app::daemon_is_active(&agent.config).unwrap());
    let restarted = agent.tool("huntproxy_restart", json!({})).await;
    assert_eq!(restarted["ok"], true);
    agent.tool("projects", json!({"action": "list"})).await;
}
