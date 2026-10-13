//! Real Chromium regressions for named identities. All traffic stays on a local
//! fixture, including its WebSocket and service worker; no real sessions are used.
//!
//! Run with an installed browser runtime:
//! `cargo test --test browser_profile_isolation -- --ignored --nocapture`

use futures::{FutureExt, SinkExt, StreamExt};
use huntproxy::browser::{BrowserAction, BrowserService, Locator};
use huntproxy::config::Config;
use huntproxy::cookies::{validate_cookie_profile, validate_named_cookie_profile};
use huntproxy::domain::{BrowserSessionId, CreateProjectRequest, ProjectId};
use huntproxy::storage::Db;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_tungstenite::tungstenite::Message;

const APP: &str = r#"<!doctype html><html><head><title>Profile fixture</title></head>
<body><button id="seed">Save identity</button><button id="read">Read state</button>
<pre id="state">Loading</pre>
<input id="direct-file" type="file" multiple>
<input id="chooser-file" type="file" multiple hidden>
<input id="single-file" type="file" hidden>
<button id="browse" type="button">Browse</button>
<button id="browse-single" type="button">Browse one document</button>
<button id="no-chooser" type="button">Keep browsing</button>
<button id="warning" type="button">Show diagnostic</button>
<input id="slow-metadata" type="checkbox">
<pre id="upload-state">No selection</pre><script>
// A finite but slow application getter exercises the inspection watchdog.
Object.defineProperty(document.getElementById('slow-metadata'), 'disabled', {
  get() { const started = Date.now(); while (Date.now() - started < 2500) {} return false; }
});
document.getElementById('browse').onclick = () => document.getElementById('chooser-file').click();
document.getElementById('browse-single').onclick = () => document.getElementById('single-file').click();
document.getElementById('no-chooser').onclick = () => document.body.dataset.noChooserClicked = 'true';
document.getElementById('warning').onclick = () => console.warn('Local fixture diagnostic');
for (const id of ['direct-file', 'chooser-file']) {
  document.getElementById(id).onchange = async event => {
    const names = Array.from(event.target.files).map(file => file.name);
    const form = new FormData();
    for (const file of event.target.files) form.append('document', file);
    const response = await fetch('/upload', {method: 'POST', body: form});
    document.getElementById('upload-state').textContent = JSON.stringify({names, status: response.status});
    document.getElementById('upload-state').dataset.ready = 'true';
  };
}
const output = document.getElementById('state');
const cookieIdentity = () => document.cookie.split('; ').find(v => v.startsWith('sid='))?.slice(4) || null;
const database = new Promise((resolve, reject) => {
  const request = indexedDB.open('identity-store', 1);
  request.onupgradeneeded = () => request.result.createObjectStore('values');
  request.onsuccess = () => resolve(request.result);
  request.onerror = () => reject(request.error);
});
const socket = new WebSocket(location.origin.replace('http:', 'ws:') + '/socket');
let websocketIdentity;
const socketReady = new Promise((resolve, reject) => {
  socket.onmessage = event => { websocketIdentity = event.data; resolve(); };
  socket.onerror = () => reject(new Error('WebSocket fixture unavailable'));
});
async function read() {
  output.removeAttribute('data-ready');
  await socketReady;
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('WebSocket identity reply timed out')), 2000);
    socket.onmessage = event => { clearTimeout(timeout); websocketIdentity = event.data; resolve(); };
    if (socket.readyState !== WebSocket.OPEN) { clearTimeout(timeout); reject(new Error('WebSocket closed')); return; }
    socket.send('identity');
  });
  const db = await database;
  const indexed = await new Promise((resolve, reject) => {
    const request = db.transaction('values').objectStore('values').get('identity');
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error);
  });
  const cached = await (await caches.open('identity-cache')).match('/identity');
  const workers = (await navigator.serviceWorker.getRegistrations()).map(r =>
    new URL((r.active || r.waiting || r.installing).scriptURL).searchParams.get('identity'));
  output.textContent = JSON.stringify({cookie: cookieIdentity(), cookie_names: document.cookie.split('; ').filter(Boolean).map(cookie => cookie.split('=')[0]), local: localStorage.getItem('identity'),
    session: sessionStorage.getItem('identity'), indexed, cache: cached ? await cached.text() : null,
    workers, websocket: websocketIdentity, url: location.href});
  output.setAttribute('data-ready', 'true');
}
async function save() {
  output.removeAttribute('data-ready');
  const identity = cookieIdentity();
  if (!identity) throw new Error('Missing fixture identity');
  localStorage.setItem('identity', identity);
  sessionStorage.setItem('identity', identity);
  const db = await database;
  await new Promise((resolve, reject) => {
    const transaction = db.transaction('values', 'readwrite');
    transaction.objectStore('values').put(identity, 'identity');
    transaction.oncomplete = resolve; transaction.onerror = () => reject(transaction.error);
  });
  await (await caches.open('identity-cache')).put('/identity', new Response(identity));
  await navigator.serviceWorker.register('/sw.js?identity=' + identity);
  await navigator.serviceWorker.ready;
  // A server-rotated cookie must survive a repeated seed and a profile restart.
  document.cookie = 'sid=' + identity + '-live; Path=/; Max-Age=3600; SameSite=Lax';
  await read();
}
function failure(error) { output.textContent = JSON.stringify({error: String(error)}); output.setAttribute('data-ready', 'true'); }
document.getElementById('seed').onclick = () => save().catch(failure);
document.getElementById('read').onclick = () => read().catch(failure);
read().catch(failure);
</script></body></html>"#;

struct LocalFixture {
    port: u16,
    task: JoinHandle<()>,
}

impl LocalFixture {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        connections.spawn(serve_connection(stream));
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Self { port, task }
    }

    fn url(&self, host: &str, profile: &str) -> String {
        format!("http://{host}:{}/app?profile={profile}", self.port)
    }

    fn proxy(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for LocalFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_connection(mut stream: TcpStream) {
    // Peeking preserves the HTTP upgrade for tungstenite's normal handshake.
    let mut peek = vec![0_u8; 16 * 1024];
    let request = loop {
        let Ok(count) = stream.peek(&mut peek).await else {
            return;
        };
        if count == 0 {
            return;
        }
        let text = String::from_utf8_lossy(&peek[..count]);
        if text.contains("\r\n\r\n") {
            // Chromium tunnels WebSockets through its authenticated HTTP proxy,
            // even when the WebSocket itself uses plain ws://. Keep that local
            // tunnel on this socket and handle its following upgrade normally.
            if text.starts_with("CONNECT ") {
                let destination = text
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                let port = stream.local_addr().unwrap().port();
                let allowed = ["localhost", "www.localhost", "127.0.0.1"]
                    .iter()
                    .any(|host| destination == format!("{host}:{port}"));
                let mut consumed = vec![0_u8; count];
                if stream.read_exact(&mut consumed).await.is_err() {
                    return;
                }
                if !allowed {
                    let _ = stream.write_all(b"HTTP/1.1 502 Local fixture only\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    return;
                }
                if stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
            break text.into_owned();
        }
        tokio::task::yield_now().await;
    };
    let header = |name: &str| {
        request.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    };
    if header("upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket")) {
        let identity = header("cookie")
            .and_then(|cookies| {
                cookies
                    .split(';')
                    .find_map(|part| part.trim().strip_prefix("sid=").map(str::to_owned))
            })
            .unwrap_or_else(|| "anonymous".into());
        let mut socket = match tokio_tungstenite::accept_async(stream).await {
            Ok(socket) => socket,
            Err(error) => {
                eprintln!("Local fixture WebSocket handshake failed: {error}");
                return;
            }
        };
        if socket
            .send(Message::Text(identity.clone().into()))
            .await
            .is_err()
        {
            return;
        }
        while let Some(Ok(message)) = socket.next().await {
            if message.is_close() {
                break;
            }
            if message.is_text()
                && socket
                    .send(Message::Text(identity.clone().into()))
                    .await
                    .is_err()
            {
                break;
            }
        }
        return;
    }
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let path = if target.starts_with("http://") {
        url::Url::parse(target).unwrap().path().to_owned()
    } else {
        target.split('?').next().unwrap_or("/").to_owned()
    };
    let (mime, body) = if path == "/sw.js" {
        ("application/javascript", "self.addEventListener('install', event => event.waitUntil(self.skipWaiting())); self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));")
    } else if path == "/app" {
        ("text/html", APP)
    } else {
        ("text/plain", "Local profile fixture")
    };
    let mut consumed = vec![0_u8; request.len()];
    if stream.read_exact(&mut consumed).await.is_err() {
        return;
    }
    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = stream.write_all(response.as_bytes()).await;
}

struct Harness {
    _directory: TempDir,
    fixture: LocalFixture,
    service: BrowserService,
    project: ProjectId,
}

impl Harness {
    async fn new() -> Self {
        Self::new_in(Path::new("/tmp/artis")).await
    }

    async fn new_in(parent: &Path) -> Self {
        std::fs::create_dir_all(parent).unwrap();
        let directory = tempfile::Builder::new()
            .prefix("huntproxy-profile-regression-")
            .tempdir_in(parent)
            .unwrap();
        let fixture = LocalFixture::start().await;
        let config = Config {
            data_dir: directory.path().to_path_buf(),
            spool_dir: directory.path().join("spool"),
            export_dir: directory.path().join("exports"),
            runtime_dir: directory.path().join("runtime"),
            plugin_dir: directory.path().join("plugins"),
            ..Config::default()
        };
        let db = Arc::new(Db::open(&config).await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "Local profile isolation regression".into(),
                target_url: fixture.url("localhost", "acc1"),
                advanced: None,
            })
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("browser-worker/index.js")),
            fixture.proxy(),
            None,
            directory.path().join("profiles"),
        );
        let status = service.status();
        assert!(
            status.node_available && status.worker_available && status.chromium_available,
            "Real profile regressions require the installed browser runtime: {status:?}"
        );
        Self {
            _directory: directory,
            fixture,
            service,
            project: project.id,
        }
    }

    async fn seed(&self, profile: &str, host: &str) {
        let cookies = json!([{"name":"sid", "value":profile, "domain":host,
            "hostOnly":true, "path":"/", "secure":false, "httpOnly":false,
            "expirationDate":4102444800.0}]);
        self.service
            .db
            .upsert_named_cookie_profile(
                self.project,
                profile,
                validate_cookie_profile(&self.fixture.url(host, profile), cookies.to_string())
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    async fn state(&self, session: BrowserSessionId) -> Value {
        self.service
            .action(
                self.project,
                session,
                BrowserAction::Wait {
                    for_what: "selector".into(),
                    value: "#state[data-ready='true']".into(),
                },
            )
            .await
            .unwrap();
        let snapshot = self
            .service
            .action(
                self.project,
                session,
                BrowserAction::Snapshot {
                    format: "dom".into(),
                    max_bytes: 200_000,
                },
            )
            .await
            .unwrap();
        let html = snapshot.data.unwrap()["content"]
            .as_str()
            .unwrap()
            .to_owned();
        let element = html
            .split("<pre id=\"state\"")
            .nth(1)
            .expect("fixture state element");
        let text = element
            .split_once('>')
            .unwrap()
            .1
            .split("</pre>")
            .next()
            .unwrap();
        let state: Value = serde_json::from_str(&html_escape::decode_html_entities(text)).unwrap();
        assert!(state.get("error").is_none(), "fixture error: {state}");
        state
    }

    async fn click(&self, session: BrowserSessionId, selector: &str) -> Value {
        self.service
            .action(
                self.project,
                session,
                BrowserAction::Click {
                    locator: Locator {
                        role: None,
                        name: None,
                        text: None,
                        test_id: None,
                        css: Some(selector.into()),
                        exact: None,
                    },
                },
            )
            .await
            .unwrap();
        self.state(session).await
    }
}

#[tokio::test]
#[ignore = "requires installed Node.js, playwright-core, and Chromium; uses only a local fixture"]
async fn browser_resource_status_preserves_profiles_at_capacity_and_reports_cdp_ownership() {
    let h = Harness::new_in(&std::env::temp_dir()).await;
    let result = std::panic::AssertUnwindSafe(verify_browser_resources(&h))
        .catch_unwind()
        .await;
    h.service.force_stop_all().await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn css_locator(selector: &str) -> Locator {
    Locator {
        role: None,
        name: None,
        text: None,
        test_id: None,
        css: Some(selector.into()),
        exact: None,
    }
}

async fn runtime_inspection(
    h: &Harness,
    session: BrowserSessionId,
    selector: Option<&str>,
) -> Value {
    let result = h
        .service
        .action(
            h.project,
            session,
            BrowserAction::Inspect {
                locator: selector.map(css_locator),
                max_bytes: 65_536,
            },
        )
        .await
        .unwrap();
    let data = result.data.unwrap();
    assert_eq!(data["truncated"], false);
    serde_json::from_str(data["content"].as_str().unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires installed Node.js, playwright-core, and Chromium; uses only a local fixture"]
async fn native_file_selection_and_passive_inspection_preserve_owned_profiles() {
    let h = Harness::new_in(&std::env::temp_dir()).await;
    let result = std::panic::AssertUnwindSafe(verify_native_file_selection(&h))
        .catch_unwind()
        .await;
    h.service.force_stop_all().await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
#[ignore = "requires installed Node.js, playwright-core, and Chromium; captures only a local fixture"]
async fn native_file_upload_uses_normal_proxy_capture_and_session_lineage() {
    let mut h = Harness::new_in(&std::env::temp_dir()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let directory = h._directory.path();
    let config = Config {
        data_dir: directory.to_path_buf(),
        spool_dir: directory.join("spool"),
        export_dir: directory.join("exports"),
        runtime_dir: directory.join("runtime"),
        plugin_dir: directory.join("plugins"),
        proxy_listen: address,
        browser_worker_path: Some(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("browser-worker/index.js"),
        ),
        ..Config::default()
    };
    let key = rcgen::KeyPair::generate().unwrap();
    let mut parameters =
        rcgen::CertificateParams::new(vec!["Local browser fixture CA".into()]).unwrap();
    parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let certificate = parameters.self_signed(&key).unwrap();
    huntproxy::config::write_private_file(&config.ca_cert_path(), certificate.pem().as_bytes())
        .unwrap();
    huntproxy::config::write_private_file(&config.ca_key_path(), key.serialize_pem().as_bytes())
        .unwrap();
    let state = huntproxy::app::bootstrap_state(config).await.unwrap();
    h.service = BrowserService::new_with_proxy_and_ca(
        state.db.clone(),
        None,
        Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("browser-worker/index.js")),
        format!("http://{address}"),
        None,
        directory.join("profiles"),
    );
    let cancel = tokio_util::sync::CancellationToken::new();
    let proxy_cancel = cancel.clone();
    let proxy = tokio::spawn(huntproxy::proxy::serve_proxy_listener(
        state,
        listener,
        proxy_cancel,
    ));
    let result = std::panic::AssertUnwindSafe(async {
        let session = h
            .service
            .start(h.project, h.fixture.url("localhost", "default"))
            .await
            .unwrap();
        let capture_id = h
            .service
            .db
            .list_capture_sessions(h.project)
            .await
            .unwrap()
            .into_iter()
            .find(|capture| capture.browser_session_id == Some(session.id))
            .unwrap()
            .id;
        let file = h._directory.path().join("reading-list.csv");
        std::fs::write(&file, "title\nAutumn edition\n").unwrap();
        h.service
            .action(
                h.project,
                session.id,
                BrowserAction::Upload {
                    locator: css_locator("#browse"),
                    files: vec![file.display().to_string()],
                    via_chooser: true,
                    timeout_ms: 5000,
                },
            )
            .await
            .unwrap();
        h.service
            .action(
                h.project,
                session.id,
                BrowserAction::Wait {
                    for_what: "selector".into(),
                    value: "#upload-state[data-ready='true']".into(),
                },
            )
            .await
            .unwrap();
        let filter = huntproxy::history::parse_text_query("method:POST path:/upload").unwrap();
        let (history, _) = h
            .service
            .db
            .list_history_filtered(h.project, Some(filter), 10, None, None)
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        let exchange = h
            .service
            .db
            .get_exchange_detail(h.project, history[0].exchange_id, Default::default())
            .await
            .unwrap();
        assert_eq!(exchange.summary.status_code, Some(200));
        assert_eq!(exchange.lineage.browser_session_id, Some(session.id));
        assert_eq!(exchange.lineage.capture_session_id, Some(capture_id));
        assert!(exchange.summary.request_length.unwrap_or_default() > 20);
        let body = h
            .service
            .db
            .load_raw_body(
                h.project,
                history[0].exchange_id,
                huntproxy::domain::MessageSide::Request,
            )
            .await
            .unwrap()
            .unwrap();
        let body = String::from_utf8(body).unwrap();
        assert!(body.contains("reading-list.csv"));
        assert!(body.contains("Autumn edition"));
    })
    .catch_unwind()
    .await;
    h.service.force_stop_all().await;
    cancel.cancel();
    proxy.await.unwrap().unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

async fn verify_native_file_selection(h: &Harness) {
    h.seed("default", "localhost").await;
    h.seed("acc2", "localhost").await;
    let first = h
        .service
        .start_with_profile_and_cookie_profile(
            h.project,
            h.fixture.url("localhost", "default"),
            "default",
            Some("default"),
        )
        .await
        .unwrap();
    let second = h
        .service
        .start_with_profile_and_cookie_profile(
            h.project,
            h.fixture.url("localhost", "acc2"),
            "acc2",
            Some("acc2"),
        )
        .await
        .unwrap();
    let captures = h
        .service
        .db
        .list_capture_sessions(h.project)
        .await
        .unwrap()
        .into_iter()
        .map(|capture| capture.id)
        .collect::<Vec<_>>();
    let file = h._directory.path().join("catalog.csv");
    std::fs::write(&file, "title,author\nSpring edition,Alex River\n").unwrap();
    let upload = |selector: &str, chooser, timeout| BrowserAction::Upload {
        locator: css_locator(selector),
        files: vec![file.display().to_string()],
        via_chooser: chooser,
        timeout_ms: timeout,
    };
    let direct = h
        .service
        .action(h.project, first.id, upload("#direct-file", false, 5000))
        .await
        .unwrap();
    assert_eq!(direct.data.unwrap()["files"], json!(["catalog.csv"]));
    assert_eq!(
        runtime_inspection(h, first.id, Some("#direct-file")).await["element"]["file_count"],
        1
    );
    assert_eq!(
        runtime_inspection(h, second.id, Some("#direct-file")).await["element"]["file_count"],
        0
    );
    h.service
        .action(h.project, second.id, upload("#browse", true, 5000))
        .await
        .unwrap();
    assert_eq!(
        runtime_inspection(h, second.id, Some("#chooser-file")).await["element"]["file_count"],
        1
    );
    h.service
        .action(
            h.project,
            second.id,
            BrowserAction::Wait {
                for_what: "selector".into(),
                value: "#upload-state[data-ready='true']".into(),
            },
        )
        .await
        .unwrap();

    let missing = BrowserAction::Upload {
        locator: css_locator("#no-chooser"),
        files: vec![h
            ._directory
            .path()
            .join("missing.csv")
            .display()
            .to_string()],
        via_chooser: true,
        timeout_ms: 100,
    };
    assert_eq!(
        h.service
            .action(h.project, first.id, missing)
            .await
            .unwrap_err()
            .code(),
        huntproxy::domain::ErrorCode::InvalidArgument
    );
    let before = h
        .service
        .action(
            h.project,
            first.id,
            BrowserAction::Snapshot {
                format: "dom".into(),
                max_bytes: 200_000,
            },
        )
        .await
        .unwrap();
    assert!(!before.data.unwrap()["content"]
        .as_str()
        .unwrap()
        .contains("data-no-chooser-clicked"));
    assert!(h
        .service
        .action(h.project, first.id, upload("#no-chooser", true, 100))
        .await
        .is_err());
    // A timed-out chooser listener must not steal the next legitimate chooser.
    h.service
        .action(h.project, first.id, upload("#browse", true, 5000))
        .await
        .unwrap();
    assert_eq!(
        runtime_inspection(h, first.id, Some("#chooser-file")).await["element"]["file_count"],
        1
    );
    let other_file = h._directory.path().join("notes.txt");
    std::fs::write(&other_file, "Autumn reading notes\n").unwrap();
    assert!(h
        .service
        .action(
            h.project,
            first.id,
            BrowserAction::Upload {
                locator: css_locator("#browse-single"),
                files: vec![file.display().to_string(), other_file.display().to_string()],
                via_chooser: true,
                timeout_ms: 5000,
            }
        )
        .await
        .is_err());
    let started = std::time::Instant::now();
    assert!(h
        .service
        .action(
            h.project,
            first.id,
            BrowserAction::Inspect {
                locator: Some(css_locator("#slow-metadata")),
                max_bytes: 4096,
            }
        )
        .await
        .is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(
        runtime_inspection(h, second.id, None).await["ready_state"],
        "complete"
    );
    // An actual chooser rejected for a single-file input is cleared as well.
    h.service
        .action(h.project, first.id, upload("#browse-single", true, 5000))
        .await
        .unwrap();
    assert_eq!(
        runtime_inspection(h, first.id, Some("#single-file")).await["element"]["file_count"],
        1
    );
    assert!(h
        .service
        .action(
            h.project,
            first.id,
            BrowserAction::Upload {
                locator: css_locator("#browse-single"),
                files: vec![file.display().to_string(), other_file.display().to_string()],
                via_chooser: true,
                timeout_ms: 5000,
            }
        )
        .await
        .is_err());
    assert_eq!(
        runtime_inspection(h, first.id, Some("#single-file")).await["element"]["file_count"],
        1,
        "A canceled replacement must preserve the previous selection"
    );
    h.service
        .action(
            h.project,
            first.id,
            BrowserAction::Upload {
                locator: css_locator("#direct-file"),
                files: vec![],
                via_chooser: false,
                timeout_ms: 5000,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        runtime_inspection(h, first.id, Some("#direct-file")).await["element"]["file_count"],
        0
    );

    h.service
        .action(
            h.project,
            first.id,
            BrowserAction::Click {
                locator: css_locator("#warning"),
            },
        )
        .await
        .unwrap();
    let inspection = runtime_inspection(h, first.id, None).await;
    assert!(inspection["runtime_error_count"].as_u64().unwrap() >= 1);
    assert!(!inspection.to_string().contains("Local fixture diagnostic"));
    assert!(!inspection["url"].as_str().unwrap().contains('?'));
    let short = h
        .service
        .action(
            h.project,
            first.id,
            BrowserAction::Inspect {
                locator: None,
                max_bytes: 30,
            },
        )
        .await
        .unwrap()
        .data
        .unwrap();
    assert_eq!(short["truncated"], true);
    assert!(short["content"].as_str().unwrap().len() <= 30);
    assert!(h
        .service
        .action(
            h.project,
            first.id,
            BrowserAction::Inspect {
                locator: Some(css_locator("#absent")),
                max_bytes: 4096,
            }
        )
        .await
        .is_err());
    assert_eq!(
        h.service
            .session_status(h.project, first.id)
            .await
            .unwrap()
            .state,
        huntproxy::domain::BrowserSessionState::Ready
    );

    let foreign = h
        .service
        .db
        .create_project(CreateProjectRequest {
            name: "Other local browser owner".into(),
            target_url: h.fixture.url("localhost", "other"),
            advanced: None,
        })
        .await
        .unwrap();
    assert!(h
        .service
        .action(foreign.id, first.id, upload("#direct-file", false, 5000))
        .await
        .is_err());
    h.service.enable_cdp(h.project, first.id).await.unwrap();
    for action in [
        upload("#browse", true, 5000),
        BrowserAction::Inspect {
            locator: None,
            max_bytes: 4096,
        },
    ] {
        assert_eq!(
            h.service
                .action(h.project, first.id, action)
                .await
                .unwrap_err()
                .code(),
            huntproxy::domain::ErrorCode::Conflict
        );
    }
    h.service.disable_cdp(h.project, first.id).await.unwrap();
    assert_eq!(
        runtime_inspection(h, first.id, None).await["ready_state"],
        "complete"
    );
    assert_eq!(
        h.service
            .session_status(h.project, second.id)
            .await
            .unwrap()
            .active_profile
            .as_deref(),
        Some("acc2")
    );
    assert_eq!(
        h.service
            .db
            .list_capture_sessions(h.project)
            .await
            .unwrap()
            .into_iter()
            .map(|capture| capture.id)
            .collect::<Vec<_>>(),
        captures
    );
    h.service.stop(h.project, first.id).await.unwrap();
    let resumed = h
        .service
        .start_with_profile(h.project, "about:blank".into(), "default")
        .await
        .unwrap();
    assert_eq!(h.state(resumed.id).await["cookie"], "default");
}

async fn verify_browser_resources(h: &Harness) {
    let empty = h.service.active_status(h.project).await.unwrap();
    assert!(empty.sessions.is_empty());
    assert_eq!(empty.resources.available_capacity, 2);
    h.seed("default", "localhost").await;
    h.seed("acc2", "localhost").await;
    let first = h
        .service
        .start_with_profile_and_cookie_profile(
            h.project,
            h.fixture.url("localhost", "default"),
            "default",
            Some("default"),
        )
        .await
        .unwrap();
    let second = h
        .service
        .start_with_profile_and_cookie_profile(
            h.project,
            h.fixture.url("localhost", "acc2"),
            "acc2",
            Some("acc2"),
        )
        .await
        .unwrap();
    let full = h.service.active_status(h.project).await.unwrap();
    assert_eq!(full.sessions.len(), 2);
    assert_eq!(full.resources.active_persistent, 2);
    assert_eq!(full.resources.active_ephemeral, 0);
    assert_eq!(full.resources.available_capacity, 0);
    assert_eq!(full.resources.sessions.len(), 2);
    for actual in &full.sessions {
        let expected = h
            .service
            .session_status(h.project, actual.id)
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
    }
    assert_saved(&h.click(first.id, "#seed").await, "default");
    assert_saved(&h.click(second.id, "#seed").await, "acc2");
    let resumed = h
        .service
        .start(h.project, "about:blank".into())
        .await
        .unwrap();
    assert_eq!(resumed.id, first.id);
    assert_eq!(resumed.active_profile.as_deref(), Some("default"));
    assert_eq!(resumed.current_url, first.current_url);
    assert_saved(&h.state(resumed.id).await, "default");
    assert_saved(&h.state(second.id).await, "acc2");
    let denied = h
        .service
        .start_with_profile(h.project, "about:blank".into(), "acc3")
        .await
        .unwrap_err();
    assert_eq!(
        denied.code(),
        huntproxy::domain::ErrorCode::ConcurrencyLimited
    );

    let handed_off = h.service.enable_cdp(h.project, second.id).await.unwrap();
    let local = h.service.active_status(h.project).await.unwrap();
    assert!(local.resources.cdp_port_in_use);
    assert!(
        local
            .resources
            .sessions
            .iter()
            .find(|session| session.session_id == first.id)
            .unwrap()
            .agent_control
    );
    assert!(
        !local
            .resources
            .sessions
            .iter()
            .find(|session| session.session_id == second.id)
            .unwrap()
            .agent_control
    );
    assert_eq!(handed_off.session_id, Some(second.id));
    h.service.disable_cdp(h.project, second.id).await.unwrap();

    h.service.stop(h.project, second.id).await.unwrap();
    let ephemeral = h
        .service
        .start_ephemeral(h.project, "about:blank".into())
        .await
        .unwrap();
    let mixed = h.service.active_status(h.project).await.unwrap();
    assert_eq!(mixed.sessions.len(), 1);
    assert_eq!(mixed.resources.active_persistent, 1);
    assert_eq!(mixed.resources.active_ephemeral, 1);
    assert_eq!(mixed.resources.available_capacity, 0);
    assert_eq!(mixed.resources.sessions.len(), 1);
    assert_eq!(mixed.resources.sessions[0].session_id, first.id);

    let foreign = h
        .service
        .db
        .create_project(CreateProjectRequest {
            name: "Separate local workspace".into(),
            target_url: h.fixture.url("localhost", "foreign"),
            advanced: None,
        })
        .await
        .unwrap();
    let foreign_session = h
        .service
        .start_with_profile(foreign.id, "about:blank".into(), "foreign-account")
        .await
        .unwrap();
    h.service
        .enable_cdp(foreign.id, foreign_session.id)
        .await
        .unwrap();
    let observed = h.service.active_status(h.project).await.unwrap();
    assert!(observed.resources.cdp_port_in_use);
    assert!(observed.resources.sessions[0].agent_control);
    assert_eq!(observed.resources.sessions.len(), 1);
    assert_eq!(observed.resources.sessions[0].profile, "default");
    let serialized = serde_json::to_value(&observed.resources).unwrap();
    assert_eq!(serialized.as_object().unwrap().len(), 7);
    assert_eq!(serialized["sessions"][0].as_object().unwrap().len(), 3);
    assert!(!serialized.to_string().contains("foreign-account"));
    h.service
        .disable_cdp(foreign.id, foreign_session.id)
        .await
        .unwrap();
    h.service.stop(h.project, first.id).await.unwrap();
    let ephemeral_only = h.service.active_status(h.project).await.unwrap();
    assert!(ephemeral_only.sessions.is_empty());
    assert!(ephemeral_only.resources.sessions.is_empty());
    assert_eq!(ephemeral_only.resources.active_persistent, 0);
    assert_eq!(ephemeral_only.resources.active_ephemeral, 1);
    assert_eq!(ephemeral_only.resources.available_capacity, 1);
    h.service.stop(h.project, ephemeral.id).await.unwrap();
    let available = h.service.active_status(h.project).await.unwrap();
    assert_eq!(available.resources.available_capacity, 2);
    assert!(!available.resources.cdp_port_in_use);
    h.service.stop_all().await.unwrap();
    assert_eq!(
        h.service
            .active_status(h.project)
            .await
            .unwrap()
            .resources
            .available_capacity,
        2
    );
}

fn assert_saved(state: &Value, identity: &str) {
    assert_eq!(
        state["cookie"],
        format!("{identity}-live"),
        "cookie was overwritten: {state}"
    );
    for key in ["local", "session", "indexed", "cache"] {
        assert_eq!(state[key], identity, "{key} leaked or was lost: {state}");
    }
    assert_eq!(
        state["workers"],
        json!([identity]),
        "service workers leaked or were lost: {state}"
    );
}

#[tokio::test]
#[ignore = "requires installed Node.js, playwright-core, and Chromium; uses only a local fixture"]
async fn named_profiles_isolate_all_browser_state_and_preserve_identity() {
    let harness = Harness::new().await;
    let result = std::panic::AssertUnwindSafe(verify_named_profiles(&harness))
        .catch_unwind()
        .await;
    harness.service.force_stop_all().await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

async fn verify_named_profiles(h: &Harness) {
    h.seed("acc1", "localhost").await;
    h.seed("acc2", "localhost").await;
    h.service.db.upsert_named_cookie_profile(h.project, "acc2",
        validate_cookie_profile(&h.fixture.url("localhost", "acc2"), json!([
            {"name":"sid", "value":"acc2", "domain":"localhost", "hostOnly":true, "path":"/", "expirationDate":4102444800.0},
            {"name":"theme", "value":"blue", "domain":"localhost", "hostOnly":true, "path":"/", "expirationDate":4102444800.0}
        ]).to_string()).unwrap()).await.unwrap();
    let first = h
        .service
        .start_with_profile_and_cookie_profile(
            h.project,
            h.fixture.url("localhost", "acc1"),
            "acc1",
            Some("acc1"),
        )
        .await
        .unwrap();
    let initial = h.state(first.id).await;
    assert_eq!(initial["cookie"], "acc1");
    assert_saved(&h.click(first.id, "#seed").await, "acc1");

    let second = h
        .service
        .start_with_profile_and_cookie_profile(
            h.project,
            h.fixture.url("localhost", "acc2"),
            "acc2",
            Some("acc2"),
        )
        .await
        .unwrap();
    assert_ne!(
        first.id, second.id,
        "acc2 returned the already running acc1"
    );
    assert_eq!(first.profile.as_deref(), Some("acc1"));
    assert_eq!(second.profile.as_deref(), Some("acc2"));
    assert_eq!(first.requested_profile.as_deref(), Some("acc1"));
    assert_eq!(first.active_profile.as_deref(), Some("acc1"));
    assert_eq!(second.requested_profile.as_deref(), Some("acc2"));
    assert_eq!(second.active_profile.as_deref(), Some("acc2"));
    let initial = h.state(second.id).await;
    assert_eq!(
        initial["cookie"], "acc2",
        "original matching-profile identity mismatch"
    );
    for key in ["local", "session", "indexed", "cache"] {
        assert!(initial[key].is_null(), "{key} shared: {initial}");
    }
    assert_eq!(initial["workers"], json!([]));
    assert!(initial["cookie_names"]
        .as_array()
        .unwrap()
        .contains(&json!("theme")));
    assert_eq!(initial["websocket"], "acc2");
    assert_saved(&h.click(second.id, "#seed").await, "acc2");
    let first_state = h.click(first.id, "#read").await;
    assert_saved(&first_state, "acc1");
    assert_eq!(
        first_state["websocket"], "acc1",
        "switch closed/replaced the original socket"
    );
    assert_eq!(h.service.active_sessions(h.project).await.unwrap().len(), 2);

    // Selecting the same profile is idempotent, preserving its page, live socket,
    // and server-rotated cookie instead of rebuilding/reimporting the seed.
    for (profile, expected) in [("acc1", first.id), ("acc2", second.id), ("acc1", first.id)] {
        let resumed = h
            .service
            .start_with_profile_and_cookie_profile(
                h.project,
                "about:blank".into(),
                profile,
                Some(profile),
            )
            .await
            .unwrap();
        assert_eq!(resumed.id, expected);
        assert_eq!(resumed.requested_profile.as_deref(), Some(profile));
        assert_eq!(resumed.active_profile.as_deref(), Some(profile));
        let state = h.click(resumed.id, "#read").await;
        assert_saved(&state, profile);
        assert_eq!(state["websocket"], profile);
    }
    let mismatch = h
        .service
        .start_with_profile_and_cookie_profile(
            h.project,
            h.fixture.url("localhost", "acc2"),
            "acc2",
            Some("acc1"),
        )
        .await;
    assert!(
        mismatch.is_err(),
        "mismatched cookie seed must be rejected clearly"
    );
    assert_saved(&h.click(second.id, "#read").await, "acc2");

    h.service.stop(h.project, first.id).await.unwrap();
    let restarted = h
        .service
        .start_with_profile_and_cookie_profile(
            h.project,
            h.fixture.url("localhost", "acc1"),
            "acc1",
            Some("acc1"),
        )
        .await
        .unwrap();
    assert_ne!(first.id, restarted.id);
    let state = h.state(restarted.id).await;
    assert_saved(&state, "acc1");
    assert_eq!(state["websocket"], "acc1-live");
    assert_saved(&h.click(second.id, "#read").await, "acc2");

    // CDP's bounded handoff owns one port. Handing each session off in turn must
    // expose only that profile's page and service worker targets.
    for (session, profile, other) in [(restarted.id, "acc1", "acc2"), (second.id, "acc2", "acc1")] {
        let cdp = h.service.enable_cdp(h.project, session).await.unwrap();
        assert_eq!(cdp.session_id, Some(session));
        let other_session = if session == restarted.id {
            second.id
        } else {
            restarted.id
        };
        let selected = h
            .service
            .cdp_status_for_session(h.project, session)
            .await
            .unwrap();
        assert!(selected.active);
        assert_eq!(selected.session_id, Some(session));
        let other_status = h
            .service
            .cdp_status_for_session(h.project, other_session)
            .await
            .unwrap();
        assert!(
            !other_status.active,
            "foreign handoff returned for selected session: {other_status:?}"
        );
        assert_eq!(other_status.session_id, Some(other_session));
        assert!(other_status.endpoint.is_none());
        let targets: Value = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get("http://127.0.0.1:9222/json/list")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let urls = targets
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|target| target["url"].as_str())
            .collect::<Vec<_>>();
        assert!(
            urls.iter()
                .any(|url| url.contains(&format!("profile={profile}"))),
            "requested profile page absent: {targets}"
        );
        assert!(
            urls.iter()
                .all(|url| !url.contains(&format!("profile={other}"))
                    && !url.contains(&format!("identity={other}"))),
            "foreign CDP target exposed: {targets}"
        );
        h.service.disable_cdp(h.project, session).await.unwrap();
    }

    assert!(h
        .service
        .reset_browser_profile(h.project, "acc1")
        .await
        .unwrap());
    assert_saved(&h.click(second.id, "#read").await, "acc2");
    let reset = h
        .service
        .start_with_profile(h.project, h.fixture.url("localhost", "acc1"), "acc1")
        .await
        .unwrap();
    let empty = h.state(reset.id).await;
    for key in ["cookie", "local", "session", "indexed", "cache"] {
        assert!(empty[key].is_null(), "reset retained {key}: {empty}");
    }
    assert_eq!(empty["workers"], json!([]));
    assert_eq!(empty["websocket"], "anonymous");
    h.service.stop(h.project, reset.id).await.unwrap();

    // A host-only www cookie belongs to that exact host, not its stripped root.
    h.seed("www-account", "www.localhost").await;
    let www = h
        .service
        .start_with_profile_and_cookie_profile(
            h.project,
            h.fixture.url("www.localhost", "www-account"),
            "www-account",
            Some("www-account"),
        )
        .await
        .unwrap();
    assert_eq!(h.state(www.id).await["cookie"], "www-account");
    h.service
        .action(
            h.project,
            www.id,
            BrowserAction::Navigate {
                url: h.fixture.url("localhost", "www-account"),
            },
        )
        .await
        .unwrap();
    assert!(
        h.state(www.id).await["cookie"].is_null(),
        "host-only www cookie leaked to the root host"
    );
    h.service
        .action(
            h.project,
            www.id,
            BrowserAction::Navigate {
                url: h.fixture.url("www.localhost", "www-account"),
            },
        )
        .await
        .unwrap();
    assert_eq!(h.state(www.id).await["cookie"], "www-account");

    // A replaced seed may remove an imported cookie as well as refresh sid.
    h.seed("acc2", "localhost").await;
    let refreshed = h
        .service
        .start_with_profile_options(h.project, "about:blank".into(), "acc2", Some("acc2"), true)
        .await
        .unwrap();
    assert_eq!(refreshed.id, second.id);
    let state = h.click(second.id, "#read").await;
    assert_eq!(
        state["cookie"], "acc2",
        "explicit refresh did not apply the matching seed"
    );
    for key in ["local", "session", "indexed", "cache"] {
        assert_eq!(
            state[key], "acc2",
            "cookie refresh discarded {key}: {state}"
        );
    }
    assert_eq!(state["workers"], json!(["acc2"]));
    assert!(
        !state["cookie_names"]
            .as_array()
            .unwrap()
            .contains(&json!("theme")),
        "removed seed cookie remained active: {state}"
    );
    assert_eq!(
        state["websocket"], "acc2-live",
        "cookie refresh replaced the live socket"
    );
    assert_eq!(
        h.click(www.id, "#read").await["cookie"],
        "www-account",
        "cookie refresh modified another profile"
    );

    // Even the unnamed/default profile requires an explicit cookie selection.
    // Project cookie changes cannot overwrite its own persistent identity.
    h.service.stop_all().await.unwrap();
    h.service
        .db
        .upsert_cookie_profile(
            h.project,
            validate_cookie_profile(&h.fixture.url("localhost", "default"), "sid=default".into())
                .unwrap(),
        )
        .await
        .unwrap();
    let default = h
        .service
        .start(h.project, h.fixture.url("localhost", "default"))
        .await
        .unwrap();
    assert_eq!(default.active_profile.as_deref(), Some("default"));
    assert!(h.state(default.id).await["cookie"].is_null());
    h.seed("default", "localhost").await;
    let injected = h
        .service
        .start_with_profile_and_cookie_profile(
            h.project,
            "about:blank".into(),
            "default",
            Some("default"),
        )
        .await
        .unwrap();
    assert_eq!(injected.id, default.id);
    assert_eq!(h.click(default.id, "#read").await["cookie"], "default");
    assert_saved(&h.click(default.id, "#seed").await, "default");
    let resumed = h
        .service
        .start(h.project, "about:blank".into())
        .await
        .unwrap();
    assert_eq!(resumed.id, default.id);
    assert_saved(&h.click(default.id, "#read").await, "default");
    h.service.stop(h.project, default.id).await.unwrap();
    let restarted = h
        .service
        .start(h.project, "about:blank".into())
        .await
        .unwrap();
    assert_saved(&h.state(restarted.id).await, "default");

    let target = h.fixture.url("localhost", "default");
    let previous = h
        .service
        .db
        .get_cookie_profile_for_url(h.project, &target)
        .await
        .unwrap()
        .unwrap();
    h.service
        .db
        .upsert_cookie_profile(
            h.project,
            validate_cookie_profile(&target, "sid=default2".into()).unwrap(),
        )
        .await
        .unwrap();
    let updated = h
        .service
        .db
        .get_cookie_profile_for_url(h.project, &target)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        h.service
            .apply_cookie_profile(h.project, Some(&previous), &updated)
            .await
            .unwrap(),
        0
    );
    assert_saved(&h.click(restarted.id, "#read").await, "default");
    let ephemeral = h
        .service
        .start_ephemeral(h.project, target.clone())
        .await
        .unwrap();
    assert_eq!(h.state(ephemeral.id).await["cookie"], "default2");
    assert_eq!(
        h.service
            .apply_cookie_profile(h.project, Some(&previous), &updated)
            .await
            .unwrap(),
        1
    );
    assert_saved(&h.click(restarted.id, "#read").await, "default");
    assert_eq!(
        h.service
            .clear_cookie_profile(h.project, &updated)
            .await
            .unwrap(),
        1
    );
    assert!(h.click(ephemeral.id, "#read").await["cookie"].is_null());
    h.service.stop(h.project, ephemeral.id).await.unwrap();
    assert_saved(&h.click(restarted.id, "#read").await, "default");
    h.service.stop(h.project, restarted.id).await.unwrap();
    let restarted = h
        .service
        .start(h.project, "about:blank".into())
        .await
        .unwrap();
    assert_saved(&h.state(restarted.id).await, "default");
}

// Synthetic Google cookies never contact Google: profiles stay at about:blank.
// Domain, host-only, Secure, HttpOnly, and session-cookie attributes match the
// conflicting account jars involved in CookieMismatch/401 failures.
fn google_cookies(account: &str) -> Value {
    json!([
        {"name":"SID", "value":format!("{account}-sid"), "domain":".google.com", "path":"/", "httpOnly":true, "secure":true, "expires":4102444800.0, "sameSite":"Lax"},
        {"name":"__Secure-1PSID", "value":format!("{account}-secure"), "domain":".google.com", "path":"/", "httpOnly":true, "secure":true, "expires":4102444800.0, "sameSite":"None"},
        {"name":"ACCOUNT_CHOOSER", "value":format!("{account}-chooser"), "domain":"accounts.google.com", "hostOnly":true, "path":"/", "httpOnly":true, "secure":true, "expires":-1.0, "sameSite":"Lax"}
    ])
}

fn google_project_cookies(account: &str) -> Value {
    let mut cookies = google_cookies(account);
    cookies.as_array_mut().unwrap().push(json!({
        "name":"SID", "value":format!("{account}-host-sid"),
        "domain":"accounts.google.com", "hostOnly":true, "path":"/",
        "httpOnly":true, "secure":true, "expires":4102444800.0,
    }));
    cookies
}

fn checkpoint_path(h: &Harness, profile: &str) -> std::path::PathBuf {
    let root = h
        ._directory
        .path()
        .join("profiles/projects")
        .join(h.project.get().to_string());
    if profile == "default" {
        root.join("state.json")
    } else {
        root.join("profiles").join(profile).join("state.json")
    }
}

fn assert_google_account(h: &Harness, profile: &str, account: &str) {
    let saved: Value =
        serde_json::from_slice(&std::fs::read(checkpoint_path(h, profile)).unwrap()).unwrap();
    let actual = saved["cookies"].as_array().unwrap();
    assert_eq!(actual.len(), 3, "extra or missing Google account cookies");
    for expected in google_cookies(account).as_array().unwrap() {
        let cookie = actual
            .iter()
            .find(|cookie| cookie["name"] == expected["name"])
            .unwrap();
        for field in ["value", "domain", "path", "httpOnly", "secure", "sameSite"] {
            assert_eq!(
                cookie[field], expected[field],
                "{profile}: {} {field}",
                expected["name"]
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires installed Node.js, playwright-core, and Chromium; Google cookies are synthetic and no Google requests are made"]
async fn persistent_google_accounts_require_explicit_cookie_injection() {
    let h = Harness::new().await;
    let result = std::panic::AssertUnwindSafe(verify_google_cookie_selection(&h))
        .catch_unwind()
        .await;
    h.service.force_stop_all().await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

async fn verify_google_cookie_selection(h: &Harness) {
    for (profile, account) in [("default", "primary"), ("google2", "secondary")] {
        let path = checkpoint_path(h, profile);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Bootstrap profile-owned state as if saved after an interactive login.
        // Also exercise legacy queued project-cookie removals on upgrade.
        std::fs::write(
            path,
            json!({"cookies":google_cookies(account),
                "managed_cookie_hash":"legacy",
                "pending_cookie_clears":[{"name":"SID","domain":".google.com","path":"/"}]
            })
            .to_string(),
        )
        .unwrap();
        h.service
            .db
            .upsert_named_cookie_profile(
                h.project,
                profile,
                validate_named_cookie_profile(
                    "https://accounts.google.com",
                    google_cookies("imported").to_string(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
    }
    h.service
        .db
        .upsert_cookie_profile(
            h.project,
            validate_cookie_profile(
                "https://accounts.google.com",
                google_project_cookies("project").to_string(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let primary = h
        .service
        .start(h.project, "about:blank".into())
        .await
        .unwrap();
    let secondary = h
        .service
        .start_with_profile(h.project, "about:blank".into(), "google2")
        .await
        .unwrap();
    assert_ne!(primary.id, secondary.id);
    assert_google_account(h, "default", "primary");
    assert_google_account(h, "google2", "secondary");
    let previous = h
        .service
        .db
        .get_cookie_profile_for_url(h.project, "https://accounts.google.com")
        .await
        .unwrap()
        .unwrap();
    h.service
        .db
        .upsert_cookie_profile(
            h.project,
            validate_cookie_profile(
                "https://accounts.google.com",
                google_project_cookies("updated-project").to_string(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let updated = h
        .service
        .db
        .get_cookie_profile_for_url(h.project, "https://accounts.google.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        h.service
            .apply_cookie_profile(h.project, Some(&previous), &updated)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        h.service
            .clear_cookie_profile(h.project, &updated)
            .await
            .unwrap(),
        0
    );
    h.service.stop(h.project, primary.id).await.unwrap();
    let restarted = h
        .service
        .start(h.project, "about:blank".into())
        .await
        .unwrap();
    assert_ne!(restarted.id, primary.id);
    assert_google_account(h, "default", "primary");
    assert_google_account(h, "google2", "secondary");

    // Named imports require explicit selection, including on an already active profile.
    let injected = h
        .service
        .start_with_profile_and_cookie_profile(
            h.project,
            "about:blank".into(),
            "google2",
            Some("google2"),
        )
        .await
        .unwrap();
    assert_eq!(injected.id, secondary.id);
    assert_google_account(h, "google2", "imported");
    assert_google_account(h, "default", "primary");
    h.service.stop(h.project, secondary.id).await.unwrap();
    h.service
        .start_with_profile(h.project, "about:blank".into(), "google2")
        .await
        .unwrap();
    assert_google_account(h, "google2", "imported");

    // A changed named jar also remains inert until explicitly requested.
    h.service
        .db
        .upsert_named_cookie_profile(
            h.project,
            "google2",
            validate_named_cookie_profile(
                "https://accounts.google.com",
                google_cookies("new-import").to_string(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    h.service.stop_all().await.unwrap();
    h.service
        .start(h.project, "about:blank".into())
        .await
        .unwrap();
    h.service
        .start_with_profile(h.project, "about:blank".into(), "google2")
        .await
        .unwrap();
    assert_google_account(h, "default", "primary");
    assert_google_account(h, "google2", "imported");
    h.service.stop_all().await.unwrap();
    h.service
        .start_with_profile_and_cookie_profile(
            h.project,
            "about:blank".into(),
            "google2",
            Some("google2"),
        )
        .await
        .unwrap();
    assert_google_account(h, "google2", "new-import");
}
