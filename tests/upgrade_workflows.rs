//! Black-box compatibility coverage for upgrading an actual v0.1.1 data directory.
//!
//! This is deliberately ignored in ordinary test runs. CI or a release engineer must
//! provide a verified official v0.1.1 executable in `HUNTPROXY_LEGACY_BINARY`.

#![cfg(unix)]

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const TEST_ROOT: &str = "/tmp/artis";

struct Daemon {
    child: Child,
    binary: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Fixture {
    address: SocketAddr,
    stopping: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Fixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = stopping.clone();
        let worker = thread::spawn(move || {
            while !worker_stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut request = [0_u8; 16 * 1024];
                        let count = stream.read(&mut request).unwrap_or(0);
                        let request_text = String::from_utf8_lossy(&request[..count]);
                        let path = request_text
                            .lines()
                            .next()
                            .and_then(|line| line.split_whitespace().nth(1))
                            .unwrap_or("/");
                        let body = format!(r#"{{"fixture":"legacy-upgrade","path":"{path}"}}"#);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            stopping,
            thread: Some(worker),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(worker) = self.thread.take() {
            worker.join().unwrap();
        }
    }
}

#[test]
#[ignore = "requires HUNTPROXY_LEGACY_BINARY pointing to a verified official v0.1.1 binary"]
fn v011_data_and_full_bundle_upgrade_to_current_release() {
    let legacy = required_legacy_binary();
    let current = PathBuf::from(env!("CARGO_BIN_EXE_HuntProxy"));
    fs::create_dir_all(TEST_ROOT).unwrap();
    let workspace = tempfile::Builder::new()
        .prefix("legacy-upgrade-")
        .tempdir_in(TEST_ROOT)
        .unwrap();
    let data_dir = workspace.path().join("data");
    let bundle = workspace.path().join("v0.1.1-full.huntproxy");
    let fixture = Fixture::start();
    let api_port = available_port();
    let proxy_port = available_port();
    let api_base = format!("http://127.0.0.1:{api_port}");

    assert_success(&run(&legacy, &data_dir, &["init"]), "legacy init");
    configure_ports(&data_dir, api_port, proxy_port);
    let mut daemon = start_daemon(&legacy, &data_dir);
    wait_for_health(&api_base, &mut daemon);
    let client = http_client();

    let project = request_json(
        &client,
        "POST",
        &format!("{api_base}/api/v1/projects"),
        Some(json!({
            "name": "Legacy upgrade fixture",
            "target_url": fixture.url("/account")
        })),
    );
    let project_id = project["id"].as_i64().expect("created project id");

    let capture = request_json(
        &client,
        "POST",
        &format!("{api_base}/api/v1/projects/{project_id}/capture-sessions"),
        None,
    );
    let token = capture["token_once"]
        .as_str()
        .expect("one-time proxy token");
    send_captured_request(proxy_port, &fixture.url("/captured?source=v011"), token);
    wait_until(Duration::from_secs(10), || {
        request_json(
            &client,
            "GET",
            &format!("{api_base}/api/v1/projects/{project_id}/history"),
            None,
        )["items"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    });

    request_json(
        &client,
        "PUT",
        &format!("{api_base}/api/v1/projects/{project_id}/cookies"),
        Some(json!({
            "target_url": fixture.url("/account"),
            "profile_name": "member",
            "cookie": "session=legacy-member; Path=/"
        })),
    );
    request_json(
        &client,
        "POST",
        &format!("{api_base}/api/v1/projects/{project_id}/reply-tabs"),
        Some(json!({
            "name": "Legacy saved request",
            "protocol": "h1",
            "draft": {
                "method": "POST",
                "url": fixture.url("/draft"),
                "body_text": "legacy-draft-body"
            }
        })),
    );

    let legacy_browser_state = data_dir
        .join("browser-profiles/projects")
        .join(project_id.to_string())
        .join("state.json");
    fs::create_dir_all(legacy_browser_state.parent().unwrap()).unwrap();
    fs::write(
        &legacy_browser_state,
        serde_json::to_vec(&json!({
            "version": 7,
            "last_url": fixture.url("/remembered"),
            "local_storage": {
                format!("http://{}", fixture.address): {"upgrade-marker": "v0.1.1"}
            }
        }))
        .unwrap(),
    )
    .unwrap();

    assert_success(
        &run(
            &legacy,
            &data_dir,
            &[
                "project",
                "export",
                &project_id.to_string(),
                bundle.to_str().unwrap(),
                "--include-secrets",
            ],
        ),
        "legacy full bundle export",
    );
    assert!(bundle.is_file(), "legacy bundle was not created");

    write_custom_plugin(&data_dir);

    // Exercise the same coordinated installation transaction used by the
    // upstream installer. Seed a realistic installation with the verified
    // legacy executable while its daemon is still serving this data directory.
    let install_dir = workspace.path().join("install");
    fs::create_dir_all(&install_dir).unwrap();
    let installed = install_dir.join("HuntProxy");
    fs::copy(&legacy, &installed).unwrap();
    fs::set_permissions(&installed, fs::metadata(&legacy).unwrap().permissions()).unwrap();
    let legacy_hash = sha256_file(&legacy);

    let installation = run(
        &current,
        &data_dir,
        &[
            "install-release",
            "--executable",
            installed.to_str().unwrap(),
        ],
    );
    assert_success(&installation, "coordinated current release installation");
    let installation_stdout = String::from_utf8_lossy(&installation.stdout);
    assert!(
        installation_stdout.contains("Installed HuntProxy 0.2.0"),
        "unexpected installation output: {installation_stdout}"
    );
    assert!(
        installation_stdout.contains("daemon restarted"),
        "running legacy daemon was not restarted: {installation_stdout}"
    );

    let legacy_status = wait_for_child_exit(&mut daemon.child, Duration::from_secs(10))
        .expect("legacy daemon did not exit during coordinated installation");
    assert!(
        legacy_status.success(),
        "legacy daemon exited with {legacy_status}"
    );
    let installed_version = run(&installed, &data_dir, &["--version"]);
    assert_success(&installed_version, "installed release version");
    assert_eq!(
        String::from_utf8_lossy(&installed_version.stdout).trim(),
        "HuntProxy 0.2.0"
    );
    assert_eq!(
        sha256_file(&install_dir.join("HuntProxy.previous")),
        legacy_hash,
        "rollback binary must match the verified legacy executable"
    );
    let restore_points = fs::read_dir(data_dir.join("runtime/updates"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(restore_points.len(), 1, "keep one release restore point");
    assert!(restore_points[0].join("restore.json").is_file());
    assert!(!data_dir.join("runtime/update-journal.json").exists());

    // The transaction restarts a managed daemon with the installed release.
    // Stop it before continuing the foreground restart/import checks below.
    assert_project_state(&client, &api_base, project_id, &fixture);
    assert_success(
        &run(&installed, &data_dir, &["stop"]),
        "stop installed daemon after coordinated installation",
    );

    let prepared = run(&installed, &data_dir, &["prepare-update"]);
    assert_success(&prepared, "current prepare-update");
    let prepared_json: Value = serde_json::from_slice(&prepared.stdout).unwrap();
    assert_eq!(prepared_json["ok"], true);
    assert_eq!(prepared_json["version"], env!("CARGO_PKG_VERSION"));
    assert_latest_plugins_and_custom_plugin(&data_dir);

    let mut daemon = start_daemon(&installed, &data_dir);
    wait_for_health(&api_base, &mut daemon);
    assert_custom_plugin_loaded(&client, &api_base);
    assert_project_state(&client, &api_base, project_id, &fixture);
    let profiles = request_json(
        &client,
        "GET",
        &format!("{api_base}/api/v1/projects/{project_id}/browser-profiles"),
        None,
    );
    let default = profiles["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|profile| profile["name"] == "default")
        .expect("default browser profile");
    assert_eq!(default["has_state"], true);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&legacy_browser_state).unwrap()).unwrap()
            ["local_storage"][format!("http://{}", fixture.address)]["upgrade-marker"],
        "v0.1.1"
    );
    assert_browser_roundtrip(&client, &api_base, project_id, &fixture);

    stop_daemon(&installed, &data_dir, &mut daemon);
    let imported = run(
        &installed,
        &data_dir,
        &["project", "import", bundle.to_str().unwrap()],
    );
    assert_success(&imported, "current import of legacy full bundle");
    let imported_id = imported_project_id(&String::from_utf8_lossy(&imported.stdout));

    // A repeated preparation/startup is the normal path after a restart and must
    // leave user-owned plugin content and already-migrated data unchanged.
    assert_success(
        &run(&installed, &data_dir, &["prepare-update"]),
        "second prepare-update",
    );
    assert_latest_plugins_and_custom_plugin(&data_dir);
    let mut daemon = start_daemon(&installed, &data_dir);
    wait_for_health(&api_base, &mut daemon);
    assert_custom_plugin_loaded(&client, &api_base);
    assert_project_state(&client, &api_base, project_id, &fixture);
    assert_project_state(&client, &api_base, imported_id, &fixture);
    let projects = request_json(&client, "GET", &format!("{api_base}/api/v1/projects"), None);
    assert_eq!(projects["projects"].as_array().unwrap().len(), 2);
    stop_daemon(&installed, &data_dir, &mut daemon);
}

fn sha256_file(path: &Path) -> String {
    hex::encode(Sha256::digest(fs::read(path).unwrap()))
}

fn required_legacy_binary() -> PathBuf {
    let path = std::env::var_os("HUNTPROXY_LEGACY_BINARY")
        .map(PathBuf::from)
        .expect("HUNTPROXY_LEGACY_BINARY is required for this ignored integration test");
    assert!(
        path.is_file(),
        "legacy binary does not exist: {}",
        path.display()
    );
    path
}

fn command(binary: &Path, data_dir: &Path) -> Command {
    let mut command = Command::new(binary);
    command.args(["--data-dir"]).arg(data_dir);
    if let Some(path) = std::env::var_os("HUNTPROXY_PLAYWRIGHT_CORE_PATH") {
        command.env("HUNTPROXY_PLAYWRIGHT_CORE_PATH", path);
    }
    if let Some(path) = std::env::var_os("HUNTPROXY_CHROME_EXECUTABLE") {
        command.env("HUNTPROXY_CHROME_EXECUTABLE", path);
    }
    command
}

fn run(binary: &Path, data_dir: &Path, args: &[&str]) -> Output {
    command(binary, data_dir).args(args).output().unwrap()
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed ({}):\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn start_daemon(binary: &Path, data_dir: &Path) -> Daemon {
    let child = command(binary, data_dir)
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    Daemon {
        child,
        binary: binary.to_path_buf(),
    }
}

fn stop_daemon(binary: &Path, data_dir: &Path, daemon: &mut Daemon) {
    assert_success(
        &run(binary, data_dir, &["stop"]),
        &format!("stop daemon {}", binary.display()),
    );
    let mut status = wait_for_child_exit(&mut daemon.child, Duration::from_secs(10));
    if status.is_none() {
        // The private shutdown reply can race the foreground server's final
        // accept loop. A second normal stop exercises the supported retry path.
        assert_success(
            &run(binary, data_dir, &["stop"]),
            &format!("retry stop daemon {}", binary.display()),
        );
        status = wait_for_child_exit(&mut daemon.child, Duration::from_secs(10));
    }
    let status = status.unwrap_or_else(|| {
        panic!(
            "daemon {} did not exit after two graceful stop requests",
            daemon.binary.display()
        )
    });
    if !status.success() {
        let mut stderr = String::new();
        if let Some(mut pipe) = daemon.child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        panic!(
            "daemon {} exited with {status}:\nstderr:\n{stderr}",
            daemon.binary.display()
        );
    }
}

fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_health(api_base: &str, daemon: &mut Daemon) {
    let client = http_client();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = daemon.child.try_wait().unwrap() {
            let mut stderr = String::new();
            if let Some(mut pipe) = daemon.child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("daemon exited before health check ({status}): {stderr}");
        }
        if client
            .get(format!("{api_base}/api/v1/health"))
            .send()
            .is_ok_and(|response| response.status().is_success())
        {
            return;
        }
        assert!(Instant::now() < deadline, "daemon health check timed out");
        thread::sleep(Duration::from_millis(100));
    }
}

fn http_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

fn request_json(
    client: &reqwest::blocking::Client,
    method: &str,
    url: &str,
    body: Option<Value>,
) -> Value {
    let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
    let mut request = client.request(method, url);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().unwrap();
    let status = response.status();
    let bytes = response.bytes().unwrap();
    assert!(
        status.is_success(),
        "request {url} failed with {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "request {url} returned invalid JSON: {error}: {}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

fn request_no_content(client: &reqwest::blocking::Client, method: &str, url: &str) {
    let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
    let response = client.request(method, url).send().unwrap();
    assert!(
        response.status().is_success(),
        "request {url} failed with {}: {}",
        response.status(),
        response.text().unwrap_or_default()
    );
}

fn available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn configure_ports(data_dir: &Path, api_port: u16, proxy_port: u16) {
    let path = data_dir.join("config.toml");
    let config = fs::read_to_string(&path).unwrap();
    let config = config
        .replace("127.0.0.1:17890", &format!("127.0.0.1:{api_port}"))
        .replace("127.0.0.1:17891", &format!("127.0.0.1:{proxy_port}"));
    assert!(config.contains(&api_port.to_string()));
    assert!(config.contains(&proxy_port.to_string()));
    fs::write(path, config).unwrap();
}

fn send_captured_request(proxy_port: u16, target: &str, token: &str) {
    let url = url::Url::parse(target).unwrap();
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Bearer {token}\r\nConnection: close\r\n\r\n",
        url.authority()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200") || response.starts_with(b"HTTP/1.0 200"),
        "captured request failed: {}",
        String::from_utf8_lossy(&response)
    );
}

fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(Instant::now() < deadline, "condition timed out");
        thread::sleep(Duration::from_millis(100));
    }
}

fn write_custom_plugin(data_dir: &Path) {
    let package = data_dir.join("plugins/local-helper");
    fs::create_dir_all(&package).unwrap();
    let script = b"globalThis.HuntProxyPlugin = { plan() { return {operations: []}; }, analyze() { return {}; } };\n";
    fs::write(package.join("index.js"), script).unwrap();
    fs::write(
        package.join("plugin.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "id": "local-helper",
            "name": "Local Helper",
            "version": "1.0.0",
            "description": "User-owned upgrade fixture",
            "enabled": false,
            "entrypoint": "index.js",
            "entrypoint_sha256": hex::encode(Sha256::digest(script)),
            "capabilities": [],
            "actions": [{"name": "inspect", "description": "Inspect local fixture state"}]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(package.join("owner-note.txt"), b"preserve-user-copy\n").unwrap();
}

fn assert_latest_plugins_and_custom_plugin(data_dir: &Path) {
    assert!(data_dir.join("plugins/racer/plugin.json").is_file());
    assert_eq!(
        fs::read(data_dir.join("plugins/local-helper/owner-note.txt")).unwrap(),
        b"preserve-user-copy\n"
    );
}

fn assert_custom_plugin_loaded(client: &reqwest::blocking::Client, api_base: &str) {
    let extensions = request_json(
        client,
        "GET",
        &format!("{api_base}/api/v1/extensions"),
        None,
    );
    assert!(extensions["plugins"]
        .as_array()
        .is_some_and(|plugins| plugins.iter().any(|plugin| plugin["id"] == "local-helper")));
    assert_eq!(extensions["load_issues"], json!([]));
}

fn assert_project_state(
    client: &reqwest::blocking::Client,
    api_base: &str,
    project_id: i64,
    fixture: &Fixture,
) {
    let history = request_json(
        client,
        "GET",
        &format!("{api_base}/api/v1/projects/{project_id}/history"),
        None,
    );
    assert!(history["items"]
        .as_array()
        .is_some_and(|items| { items.iter().any(|item| item["path"] == "/captured") }));

    let tabs = request_json(
        client,
        "GET",
        &format!("{api_base}/api/v1/projects/{project_id}/reply-tabs"),
        None,
    );
    let tab = tabs["tabs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tab| tab["name"] == "Legacy saved request")
        .expect("saved request draft");
    assert_eq!(tab["draft"]["body_text"], "legacy-draft-body");
    assert_eq!(tab["draft"]["url"], fixture.url("/draft"));

    let cookies = request_json(
        client,
        "GET",
        &format!("{api_base}/api/v1/projects/{project_id}/cookies"),
        None,
    );
    let named = cookies["named_profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|profile| profile["name"] == "member")
        .expect("named cookie profile");
    assert!(named["profile"]["names"]
        .as_array()
        .is_some_and(|names| names.iter().any(|name| name == "session")));
}

fn assert_browser_roundtrip(
    client: &reqwest::blocking::Client,
    api_base: &str,
    project_id: i64,
    fixture: &Fixture,
) {
    let started = request_json(
        client,
        "POST",
        &format!("{api_base}/api/v1/projects/{project_id}/browser-sessions"),
        Some(json!({"url": fixture.url("/remembered"), "profile": "default"})),
    );
    let session_id = started["id"].as_i64().expect("browser session id");
    let snapshot = request_json(
        client,
        "POST",
        &format!("{api_base}/api/v1/projects/{project_id}/browser-sessions/{session_id}/action"),
        Some(json!({"type": "snapshot", "format": "accessibility", "max_bytes": 32_000})),
    );
    assert_eq!(snapshot["ok"], true);
    request_no_content(
        client,
        "POST",
        &format!("{api_base}/api/v1/projects/{project_id}/browser-sessions/{session_id}/stop"),
    );
}

fn imported_project_id(output: &str) -> i64 {
    let line = output
        .lines()
        .find(|line| line.starts_with("Imported project "))
        .expect("project import output");
    line.split_whitespace()
        .nth(2)
        .expect("imported project id")
        .parse()
        .unwrap()
}
