//! Real Chromium regressions for named identities. All traffic stays on a local
//! fixture, including its WebSocket and service worker; no real sessions are used.
//!
//! Run with an installed browser runtime:
//! `cargo test --test browser_profile_isolation -- --ignored --nocapture`

use futures::{FutureExt, SinkExt, StreamExt};
use huntproxy::browser::{BrowserAction, BrowserService, Locator};
use huntproxy::config::Config;
use huntproxy::cookies::validate_cookie_profile;
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
<pre id="state">Loading</pre><script>
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
        std::fs::create_dir_all("/tmp/artis").unwrap();
        let directory = tempfile::Builder::new()
            .prefix("huntproxy-profile-regression-")
            .tempdir_in("/tmp/artis")
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

    // The legacy unnamed start still seeds project cookies, then treats its
    // persistent jar as authoritative when the original seed has not changed.
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
    assert_eq!(h.state(default.id).await["cookie"], "default");
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
        1
    );
    assert_eq!(h.click(restarted.id, "#read").await["cookie"], "default2");
    assert_saved(&h.click(restarted.id, "#seed").await, "default2");
    h.service.stop(h.project, restarted.id).await.unwrap();
    let restarted = h
        .service
        .start(h.project, "about:blank".into())
        .await
        .unwrap();
    assert_saved(&h.state(restarted.id).await, "default2");
}
