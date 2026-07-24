//! Phase 0 Hudsucker streaming/correlation spike.
//!
//! Runs local Hyper origin fixtures + a Hudsucker proxy and records PASS/FAIL
//! proof points into RESULT.md.

use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::{
    body::{Body as HttpBody, Frame, Incoming},
    header::{HeaderName, HeaderValue},
    service::service_fn,
    Method, Request, Response, StatusCode, Uri,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ServerBuilder,
};
use pin_project_lite::pin_project;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, RootCertStore,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{oneshot, Mutex as AsyncMutex},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{error, info, warn};

use hudsucker::{
    certificate_authority::RcgenAuthority,
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse,
};

// ---------------------------------------------------------------------------
// Constants / shared state
// ---------------------------------------------------------------------------

const BODY_CAP: usize = 64 * 1024; // 64 KiB capture cap
const LARGE_BODY_SIZE: usize = 2 * 1024 * 1024; // 2 MiB
const FAKE_HOST: &str = "origin.validated-dial.test";

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone)]
struct ValidatedDial {
    hostname: String,
    port: u16,
    approved: SocketAddr,
}

#[derive(Debug, Clone)]
struct DialEvent {
    hostname: String,
    port: u16,
    dialed: SocketAddr,
    /// true if we would have used authority string resolution (we never do)
    used_dns_resolution: bool,
}

#[derive(Debug, Default)]
struct ProofState {
    results: Mutex<Vec<ProofResult>>,
    dial_events: Arc<Mutex<Vec<DialEvent>>>,
    exchanges: Mutex<HashMap<u64, ExchangeRecord>>,
    next_exchange_id: AtomicU64,
    origin_bytes_received: AtomicUsize,
    origin_disconnect_seen: AtomicBool,
    origin_stream_chunks: AtomicUsize,
}

#[derive(Debug, Clone)]
struct ProofResult {
    name: String,
    pass: bool,
    detail: String,
}

#[derive(Debug, Default, Clone)]
struct ExchangeRecord {
    id: u64,
    method: String,
    path: String,
    req_headers: Vec<(String, String)>,
    res_headers: Vec<(String, String)>,
    req_captured: usize,
    req_total_seen: usize,
    res_captured: usize,
    res_total_seen: usize,
    req_capped: bool,
    res_capped: bool,
    correlation_token: Option<String>,
}

impl ProofState {
    fn record(&self, name: &str, pass: bool, detail: impl Into<String>) {
        let detail = detail.into();
        let status = if pass { "PASS" } else { "FAIL" };
        info!(%status, proof = name, %detail);
        self.results.lock().unwrap().push(ProofResult {
            name: name.to_string(),
            pass,
            detail,
        });
    }

    fn next_id(&self) -> u64 {
        self.next_exchange_id.fetch_add(1, Ordering::SeqCst) + 1
    }
}

// ---------------------------------------------------------------------------
// ValidatedDial connector — dials only a pre-approved SocketAddr
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ValidatedDialConnector {
    dials: Arc<Mutex<HashMap<(String, u16), SocketAddr>>>,
    events: Arc<Mutex<Vec<DialEvent>>>,
    /// If true, refuse any dial that is not in the map (no DNS fallback).
    strict: bool,
}

impl ValidatedDialConnector {
    fn new(events: Arc<Mutex<Vec<DialEvent>>>) -> Self {
        Self {
            dials: Arc::new(Mutex::new(HashMap::new())),
            events,
            strict: true,
        }
    }

    fn allow(&self, hostname: &str, port: u16, addr: SocketAddr) {
        self.dials
            .lock()
            .unwrap()
            .insert((hostname.to_ascii_lowercase(), port), addr);
    }
}

impl tower::Service<Uri> for ValidatedDialConnector {
    type Response = TokioIo<TcpStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let dials = self.dials.clone();
        let events = self.events.clone();
        let strict = self.strict;
        Box::pin(async move {
            let host = dst
                .host()
                .ok_or_else(|| anyhow!("uri missing host: {dst}"))?
                .to_string();
            let port = dst.port_u16().unwrap_or_else(|| match dst.scheme_str() {
                Some("https") => 443,
                _ => 80,
            });
            let key = (host.to_ascii_lowercase(), port);
            let approved = {
                let map = dials.lock().unwrap();
                map.get(&key).copied()
            };

            let dialed = match approved {
                Some(addr) => addr,
                None if !strict => {
                    // Explicitly not used in this spike; kept for clarity.
                    return Err(anyhow!(
                        "ValidatedDial: no approved addr for {host}:{port} and strict=false path disabled"
                    )
                    .into());
                }
                None => {
                    return Err(anyhow!(
                        "ValidatedDial: refused DNS fallback for {host}:{port} (not in allow-list)"
                    )
                    .into());
                }
            };

            events.lock().unwrap().push(DialEvent {
                hostname: host.clone(),
                port,
                dialed,
                used_dns_resolution: false,
            });

            // Dial the pre-resolved IP only — never host:port string resolution.
            let stream = TcpStream::connect(dialed)
                .await
                .with_context(|| format!("connect {dialed} for {host}:{port}"))?;
            stream.set_nodelay(true).ok();
            Ok(TokioIo::new(stream))
        })
    }
}

// TokioIo<TcpStream> already implements Connection via hyper-util.

// ---------------------------------------------------------------------------
// Streaming body tap with capture cap (no full-body buffering of capture)
// ---------------------------------------------------------------------------

pin_project! {
    struct TapBody<B> {
        #[pin]
        inner: B,
        capture: Arc<Mutex<Vec<u8>>>,
        total_seen: Arc<AtomicUsize>,
        capped: Arc<AtomicBool>,
        cap: usize,
    }
}

impl<B> HttpBody for TapBody<B>
where
    B: HttpBody<Data = Bytes>,
    B::Error: Into<hudsucker::Error>,
{
    type Data = Bytes;
    type Error = hudsucker::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.total_seen.fetch_add(data.len(), Ordering::SeqCst);
                    let mut buf = this.capture.lock().unwrap();
                    if buf.len() < *this.cap {
                        let room = *this.cap - buf.len();
                        let n = room.min(data.len());
                        buf.extend_from_slice(&data[..n]);
                        if buf.len() >= *this.cap {
                            this.capped.store(true, Ordering::SeqCst);
                        }
                    } else {
                        this.capped.store(true, Ordering::SeqCst);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

fn tap_body(body: Body, cap: usize) -> (Body, Arc<Mutex<Vec<u8>>>, Arc<AtomicUsize>, Arc<AtomicBool>) {
    let capture = Arc::new(Mutex::new(Vec::new()));
    let total_seen = Arc::new(AtomicUsize::new(0));
    let capped = Arc::new(AtomicBool::new(false));
    let tapped = TapBody {
        inner: body,
        capture: capture.clone(),
        total_seen: total_seen.clone(),
        capped: capped.clone(),
        cap,
    };
    // Erase into hudsucker::Body without collecting.
    let boxed: BoxBody<Bytes, hudsucker::Error> = BoxBody::new(tapped);
    (Body::from(boxed), capture, total_seen, capped)
}

// ---------------------------------------------------------------------------
// Spike HTTP handler
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectPolicy {
    /// Let Hudsucker MITM; upstream dials use ValidatedDialConnector.
    Mitm,
    /// Handle CONNECT ourselves with ValidatedDial (never TcpStream::connect(authority)).
    PassthroughValidatedDial,
}

#[derive(Clone)]
struct SpikeHandler {
    state: Arc<ProofState>,
    policy: ConnectPolicy,
    /// Per-clone exchange id set in handle_request, read in handle_response.
    exchange_id: Option<u64>,
    validated: Arc<Mutex<Option<ValidatedDial>>>,
    /// Observability for CONNECT handling path.
    connect_custom_dials: Arc<AtomicUsize>,
}

impl SpikeHandler {
    fn new(state: Arc<ProofState>, policy: ConnectPolicy) -> Self {
        Self {
            state,
            policy,
            exchange_id: None,
            validated: Arc::new(Mutex::new(None)),
            connect_custom_dials: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn set_validated(&self, dial: ValidatedDial) {
        *self.validated.lock().unwrap() = Some(dial);
    }

    fn headers_vec(headers: &http::HeaderMap) -> Vec<(String, String)> {
        headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or("<binary>").to_string(),
                )
            })
            .collect()
    }
}

impl HttpHandler for SpikeHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        // Custom CONNECT passthrough with ValidatedDial.
        if req.method() == Method::CONNECT && self.policy == ConnectPolicy::PassthroughValidatedDial
        {
            return self.handle_connect_validated(req).await;
        }

        let id = self.state.next_id();
        self.exchange_id = Some(id);

        let method = req.method().to_string();
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| req.uri().to_string());
        let headers = Self::headers_vec(req.headers());
        let token = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-correlation-token"))
            .map(|(_, v)| v.clone());

        let (parts, body) = req.into_parts();
        let (tapped, capture, total, capped) = tap_body(body, BODY_CAP);

        {
            let mut map = self.state.exchanges.lock().unwrap();
            map.insert(
                id,
                ExchangeRecord {
                    id,
                    method,
                    path,
                    req_headers: headers,
                    res_headers: Vec::new(),
                    req_captured: 0,
                    req_total_seen: 0,
                    res_captured: 0,
                    res_total_seen: 0,
                    req_capped: false,
                    res_capped: false,
                    correlation_token: token,
                },
            );
        }

        // Finalize request capture stats after body is fully polled by forwarding.
        // We snapshot later in handle_response / via shared atomics.
        let state = self.state.clone();
        let capture2 = capture.clone();
        let total2 = total.clone();
        let capped2 = capped.clone();
        // Store arcs on a side channel keyed by id for response handler to finalize req stats.
        // Simpler: write current values in handle_response (body already drained by then for req).
        {
            let _ = (capture2, total2, capped2, state);
        }

        // Keep capture arcs alive by stuffing into a process-wide map.
        req_taps().lock().unwrap().insert(
            id,
            TapHandles {
                capture,
                total_seen: total,
                capped,
            },
        );

        RequestOrResponse::Request(Request::from_parts(parts, tapped))
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<Body>,
    ) -> Response<Body> {
        let id = match self.exchange_id {
            Some(id) => id,
            None => return res,
        };

        // Finalize request tap stats (request body fully forwarded before response).
        if let Some(t) = req_taps().lock().unwrap().remove(&id) {
            if let Some(rec) = self.state.exchanges.lock().unwrap().get_mut(&id) {
                rec.req_captured = t.capture.lock().unwrap().len();
                rec.req_total_seen = t.total_seen.load(Ordering::SeqCst);
                rec.req_capped = t.capped.load(Ordering::SeqCst);
            }
        }

        let headers = Self::headers_vec(res.headers());
        if let Some(rec) = self.state.exchanges.lock().unwrap().get_mut(&id) {
            rec.res_headers = headers;
        }

        let (parts, body) = res.into_parts();
        let (tapped, capture, total, capped) = tap_body(body, BODY_CAP);
        res_taps().lock().unwrap().insert(
            id,
            TapHandles {
                capture,
                total_seen: total,
                capped,
            },
        );

        // Response body will be drained by the client; stats finalized in finalize_response_tap.
        let _ = parts;
        let mut res = Response::from_parts(parts, tapped);
        // Stash exchange id on a header for client-side correlation checks (test only).
        res.headers_mut().insert(
            HeaderName::from_static("x-spike-exchange-id"),
            HeaderValue::from_str(&id.to_string()).unwrap(),
        );
        res
    }

    async fn should_intercept_connect(
        &mut self,
        _ctx: &HttpContext,
        _req: &Request<Body>,
    ) -> bool {
        // For passthrough we handle CONNECT in handle_request and never reach here
        // for those requests (we return a Response). For MITM, intercept.
        self.policy == ConnectPolicy::Mitm
    }
}

struct TapHandles {
    capture: Arc<Mutex<Vec<u8>>>,
    total_seen: Arc<AtomicUsize>,
    capped: Arc<AtomicBool>,
}

use std::sync::OnceLock;
fn req_taps() -> &'static Mutex<HashMap<u64, TapHandles>> {
    static T: OnceLock<Mutex<HashMap<u64, TapHandles>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}
fn res_taps() -> &'static Mutex<HashMap<u64, TapHandles>> {
    static T: OnceLock<Mutex<HashMap<u64, TapHandles>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

impl SpikeHandler {
    async fn handle_connect_validated(&mut self, mut req: Request<Body>) -> RequestOrResponse {
        let authority = match req.uri().authority() {
            Some(a) => a.clone(),
            None => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::empty())
                    .unwrap()
                    .into();
            }
        };

        let host = authority.host().to_string();
        let port = authority.port_u16().unwrap_or(443);
        let dial = self.validated.lock().unwrap().clone();
        let approved = match dial {
            Some(ref d) if d.hostname == host && d.port == port => d.approved,
            Some(ref d) => {
                warn!(
                    expected = %format!("{}:{}", d.hostname, d.port),
                    got = %format!("{host}:{port}"),
                    "ValidatedDial mismatch"
                );
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("validated dial mismatch"))
                    .unwrap()
                    .into();
            }
            None => {
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("no validated dial"))
                    .unwrap()
                    .into();
            }
        };

        self.state.dial_events.lock().unwrap().push(DialEvent {
            hostname: host.clone(),
            port,
            dialed: approved,
            used_dns_resolution: false,
        });
        self.connect_custom_dials.fetch_add(1, Ordering::SeqCst);

        let upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let upgraded = match upgrade.await {
                Ok(u) => u,
                Err(e) => {
                    error!(error = %e, "CONNECT upgrade failed");
                    return;
                }
            };
            let mut client = TokioIo::new(upgraded);
            // Critical: dial approved IP only, never authority string.
            let mut server = match TcpStream::connect(approved).await {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, %approved, "ValidatedDial CONNECT dial failed");
                    return;
                }
            };
            if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut server).await {
                // Client disconnect is expected in some tests.
                tracing::debug!(error = %e, "CONNECT tunnel closed");
            }
        });

        Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap()
            .into()
    }
}

fn finalize_response_taps(state: &ProofState) {
    let mut taps = res_taps().lock().unwrap();
    let mut exchanges = state.exchanges.lock().unwrap();
    for (id, t) in taps.drain() {
        if let Some(rec) = exchanges.get_mut(&id) {
            rec.res_captured = t.capture.lock().unwrap().len();
            rec.res_total_seen = t.total_seen.load(Ordering::SeqCst);
            rec.res_capped = t.capped.load(Ordering::SeqCst);
        }
    }
}

// ---------------------------------------------------------------------------
// Origin server (Hyper)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct OriginState {
    proof: Arc<ProofState>,
    slow_gate: Arc<AsyncMutex<()>>,
}

async fn origin_service(
    state: OriginState,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // Track request body size (for streaming upload / disconnect).
    if method == Method::POST || method == Method::PUT {
        let mut body = req.into_body();
        let mut total = 0usize;
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(f) => {
                    if let Some(d) = f.data_ref() {
                        total += d.len();
                        state
                            .proof
                            .origin_stream_chunks
                            .fetch_add(1, Ordering::SeqCst);
                    }
                }
                Err(_) => {
                    state
                        .proof
                        .origin_disconnect_seen
                        .store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
        state
            .proof
            .origin_bytes_received
            .fetch_add(total, Ordering::SeqCst);

        if path == "/echo" {
            let body = format!("echoed={total}");
            return Ok(Response::new(full(body)));
        }
        return Ok(Response::new(full(format!("received={total}"))));
    }

    match path.as_str() {
        "/hello" => Ok(Response::new(full("hello-from-origin"))),
        "/headers" => {
            // Reflect ordered headers as JSON array of [name, value].
            let headers: Vec<(String, String)> = req
                .headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        v.to_str().unwrap_or("").to_string(),
                    )
                })
                .collect();
            let body = serde_json::to_string(&headers).unwrap_or_default();
            Ok(Response::builder()
                .header("content-type", "application/json")
                // Duplicate Set-Cookie to observe multi-value headers.
                .header("set-cookie", "a=1; Path=/")
                .header("set-cookie", "b=2; Path=/")
                .header("x-dup", "one")
                .header("x-dup", "two")
                .body(full(body))
                .unwrap())
        }
        "/stream" => {
            // Stream LARGE_BODY_SIZE bytes in chunks without building one big Vec in the handler
            // path for the response production (we use a stream).
            let chunk = Bytes::from(vec![b'S'; 16 * 1024]);
            let total = LARGE_BODY_SIZE;
            let mut sent = 0usize;
            let stream = futures::stream::unfold((sent, chunk), move |(mut sent, chunk)| {
                let chunk = chunk.clone();
                async move {
                    if sent >= total {
                        None
                    } else {
                        let n = chunk.len().min(total - sent);
                        sent += n;
                        let data = chunk.slice(..n);
                        Some((
                            Ok::<_, Infallible>(Frame::data(data)),
                            (sent, chunk),
                        ))
                    }
                }
            });
            Ok(Response::builder()
                .header("content-type", "application/octet-stream")
                .header("x-stream-size", total.to_string())
                .body(BoxBody::new(StreamBody::new(stream)))
                .unwrap())
        }
        p if p.starts_with("/concurrent/") => {
            let id = p.trim_start_matches("/concurrent/");
            // Small delay so concurrent requests overlap.
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(Response::builder()
                .header("x-origin-id", id)
                .body(full(format!("concurrent-ok:{id}")))
                .unwrap())
        }
        "/slow" => {
            // Slow body for client-disconnect test.
            let stream = futures::stream::unfold(0u32, |i| async move {
                if i >= 100 {
                    None
                } else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let data = Bytes::from(vec![b'Z'; 1024]);
                    Some((Ok::<_, Infallible>(Frame::data(data)), i + 1))
                }
            });
            Ok(Response::builder()
                .header("content-type", "application/octet-stream")
                .body(BoxBody::new(StreamBody::new(stream)))
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full("not found"))
            .unwrap()),
    }
}

fn full(s: impl Into<Bytes>) -> BoxBody<Bytes, Infallible> {
    BoxBody::new(Full::new(s.into()).map_err(|e| match e {}))
}

async fn start_http_origin(proof: Arc<ProofState>) -> Result<(SocketAddr, oneshot::Sender<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = oneshot::channel::<()>();
    let state = OriginState {
        proof,
        slow_gate: Arc::new(AsyncMutex::new(())),
    };

    tokio::spawn(async move {
        let server = ServerBuilder::new(TokioExecutor::new());
        let mut rx = rx;
        loop {
            tokio::select! {
                _ = &mut rx => break,
                acc = listener.accept() => {
                    let (tcp, _) = match acc {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let state = state.clone();
                    let server = server.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(tcp);
                        let svc = service_fn(move |req| {
                            let state = state.clone();
                            async move { origin_service(state, req).await }
                        });
                        let _ = server.serve_connection_with_upgrades(io, svc).await;
                    });
                }
            }
        }
    });

    Ok((addr, tx))
}

async fn start_https_origin(
    proof: Arc<ProofState>,
    server_config: Arc<rustls::ServerConfig>,
) -> Result<(SocketAddr, oneshot::Sender<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = oneshot::channel::<()>();
    let acceptor = TlsAcceptor::from(server_config);
    let state = OriginState {
        proof,
        slow_gate: Arc::new(AsyncMutex::new(())),
    };

    tokio::spawn(async move {
        let server = ServerBuilder::new(TokioExecutor::new());
        let mut rx = rx;
        loop {
            tokio::select! {
                _ = &mut rx => break,
                acc = listener.accept() => {
                    let (tcp, _) = match acc {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let state = state.clone();
                    let server = server.clone();
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let tls = match acceptor.accept(tcp).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::debug!(error = %e, "origin TLS accept failed");
                                return;
                            }
                        };
                        let io = TokioIo::new(tls);
                        let svc = service_fn(move |req| {
                            let state = state.clone();
                            async move { origin_service(state, req).await }
                        });
                        let _ = server.serve_connection_with_upgrades(io, svc).await;
                    });
                }
            }
        }
    });

    Ok((addr, tx))
}

// ---------------------------------------------------------------------------
// CA / TLS helpers
// ---------------------------------------------------------------------------

fn build_ca() -> RcgenAuthority {
    let key_pair = include_str!("../ca/hudsucker.key");
    let ca_cert = include_str!("../ca/hudsucker.cer");
    let key_pair = KeyPair::from_pem(key_pair).expect("parse CA key");
    let issuer = Issuer::from_ca_cert_pem(ca_cert, key_pair).expect("parse CA cert");
    RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider())
}

fn load_ca_cert_der() -> CertificateDer<'static> {
    let mut bytes = include_bytes!("../ca/hudsucker.cer").as_slice();
    let cert = rustls_pemfile::certs(&mut bytes)
        .next()
        .expect("ca cert")
        .expect("parse ca");
    cert
}

fn origin_tls_config(hostname: &str) -> Result<Arc<rustls::ServerConfig>> {
    // Generate a leaf cert for the origin signed by the same CA, so MITM client
    // connector can trust it, and for direct HTTPS tests.
    let key_pair_pem = include_str!("../ca/hudsucker.key");
    let ca_cert_pem = include_str!("../ca/hudsucker.cer");
    let ca_key = KeyPair::from_pem(key_pair_pem)?;
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key)?;

    let leaf_key = KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![hostname.to_string(), "localhost".into()])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    let cert = params.signed_by(&leaf_key, &issuer)?;

    let cert_der = CertificateDer::from(cert.der().clone());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

    // Use aws_lc to match hudsucker CA provider, or ring — install process_default first.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

fn client_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(load_ca_cert_der()).expect("add CA");
    roots
}

fn mitm_https_connector(
    dial: ValidatedDialConnector,
) -> hyper_rustls::HttpsConnector<ValidatedDialConnector> {
    let mut roots = client_root_store();
    // Also trust webpki roots? not needed for local.
    let _ = &mut roots;
    let tls = ClientConfig::builder()
        .with_root_certificates(client_root_store())
        .with_no_client_auth();

    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(dial)
}

// ---------------------------------------------------------------------------
// Proxy bootstrap
// ---------------------------------------------------------------------------

struct RunningProxy {
    addr: SocketAddr,
    handler: SpikeHandler,
    stop: oneshot::Sender<()>,
    connector: ValidatedDialConnector,
}

async fn start_proxy(
    proof: Arc<ProofState>,
    policy: ConnectPolicy,
) -> Result<RunningProxy> {
    let ca = build_ca();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = oneshot::channel::<()>();

    // Share dial events Arc with the connector used by MITM upstream.
    let connector = ValidatedDialConnector {
        dials: Arc::new(Mutex::new(HashMap::new())),
        events: proof.dial_events.clone(),
        strict: true,
    };
    let handler = SpikeHandler::new(proof, policy);
    let https = mitm_https_connector(connector.clone());

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(ca)
        .with_http_connector(https)
        .with_http_handler(handler.clone())
        .with_graceful_shutdown(async move {
            let _ = rx.await;
        })
        .build()
        .map_err(|e| anyhow!("proxy build: {e}"))?;

    tokio::spawn(async move {
        if let Err(e) = proxy.start().await {
            error!(error = %e, "proxy stopped with error");
        }
    });

    // Brief settle.
    tokio::time::sleep(Duration::from_millis(50)).await;

    Ok(RunningProxy {
        addr,
        handler,
        stop: tx,
        connector,
    })
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

async fn http_proxy_get(proxy: SocketAddr, target_url: &str) -> Result<(StatusCode, Vec<u8>, Vec<(String, String)>)> {
    // Absolute-form request through HTTP proxy.
    let mut stream = TcpStream::connect(proxy).await?;
    let req = format!(
        "GET {target_url} HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\nX-Correlation-Token: http-proxy-get\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    parse_http_response(&buf)
}

async fn http_proxy_post_stream(
    proxy: SocketAddr,
    target_url: &str,
    body_size: usize,
) -> Result<(StatusCode, Vec<u8>)> {
    let mut stream = TcpStream::connect(proxy).await?;
    let host_hdr = "ignored";
    let head = format!(
        "POST {target_url} HTTP/1.1\r\nHost: {host_hdr}\r\nContent-Length: {body_size}\r\nConnection: close\r\nX-Correlation-Token: upload-stream\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await?;
    // Stream body in chunks.
    let chunk = vec![b'U'; 32 * 1024];
    let mut sent = 0usize;
    while sent < body_size {
        let n = chunk.len().min(body_size - sent);
        stream.write_all(&chunk[..n]).await?;
        sent += n;
        tokio::task::yield_now().await;
    }
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let (status, body, _) = parse_http_response(&buf)?;
    Ok((status, body))
}

/// CONNECT then optional TLS then HTTP request.
async fn connect_then_http(
    proxy: SocketAddr,
    connect_host: &str,
    connect_port: u16,
    path: &str,
    use_tls: bool,
    extra_headers: &[(&str, &str)],
) -> Result<(StatusCode, Vec<u8>, Vec<(String, String)>)> {
    let mut stream = TcpStream::connect(proxy).await?;
    let connect_req = format!(
        "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\nHost: {connect_host}:{connect_port}\r\n\r\n"
    );
    stream.write_all(connect_req.as_bytes()).await?;

    // Read CONNECT response.
    let mut header_buf = Vec::new();
    let mut tmp = [0u8; 1];
    loop {
        stream.read_exact(&mut tmp).await?;
        header_buf.push(tmp[0]);
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buf.len() > 8192 {
            return Err(anyhow!("CONNECT response too large"));
        }
    }
    let connect_resp = String::from_utf8_lossy(&header_buf);
    if !connect_resp.contains("200") {
        return Err(anyhow!("CONNECT failed: {connect_resp}"));
    }

    if use_tls {
        let cfg = ClientConfig::builder()
            .with_root_certificates(client_root_store())
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(cfg));
        let server_name = ServerName::try_from(connect_host.to_string())
            .map_err(|e| anyhow!("server name: {e}"))?;
        let mut tls = connector.connect(server_name, stream).await?;
        let mut hdr = format!("GET {path} HTTP/1.1\r\nHost: {connect_host}:{connect_port}\r\nConnection: close\r\n");
        for (k, v) in extra_headers {
            hdr.push_str(&format!("{k}: {v}\r\n"));
        }
        hdr.push_str("\r\n");
        tls.write_all(hdr.as_bytes()).await?;
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await?;
        parse_http_response(&buf)
    } else {
        let mut hdr = format!(
            "GET {path} HTTP/1.1\r\nHost: {connect_host}:{connect_port}\r\nConnection: close\r\n"
        );
        for (k, v) in extra_headers {
            hdr.push_str(&format!("{k}: {v}\r\n"));
        }
        hdr.push_str("\r\n");
        stream.write_all(hdr.as_bytes()).await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        parse_http_response(&buf)
    }
}

async fn connect_then_http_read_partial(
    proxy: SocketAddr,
    connect_host: &str,
    connect_port: u16,
    path: &str,
    use_tls: bool,
    max_body_read: usize,
) -> Result<usize> {
    let mut stream = TcpStream::connect(proxy).await?;
    let connect_req = format!(
        "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\nHost: {connect_host}:{connect_port}\r\n\r\n"
    );
    stream.write_all(connect_req.as_bytes()).await?;
    let mut header_buf = Vec::new();
    let mut tmp = [0u8; 1];
    loop {
        stream.read_exact(&mut tmp).await?;
        header_buf.push(tmp[0]);
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !String::from_utf8_lossy(&header_buf).contains("200") {
        return Err(anyhow!("CONNECT failed"));
    }

    let read_partial = async |r: &mut (dyn tokio::io::AsyncRead + Unpin)| -> Result<usize> {
        let mut buf = vec![0u8; 4096];
        let mut total = 0usize;
        // Skip headers.
        let mut header = Vec::new();
        loop {
            let n = r.read(&mut buf[..1]).await?;
            if n == 0 {
                break;
            }
            header.push(buf[0]);
            if header.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        while total < max_body_read {
            let n = r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total += n;
        }
        Ok(total)
    };

    if use_tls {
        let cfg = ClientConfig::builder()
            .with_root_certificates(client_root_store())
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(cfg));
        let server_name = ServerName::try_from(connect_host.to_string())
            .map_err(|e| anyhow!("server name: {e}"))?;
        let mut tls = connector.connect(server_name, stream).await?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {connect_host}\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).await?;
        let n = read_partial(&mut tls).await?;
        // Drop = client disconnect mid-stream.
        drop(tls);
        Ok(n)
    } else {
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {connect_host}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await?;
        let n = read_partial(&mut stream).await?;
        drop(stream);
        Ok(n)
    }
}

fn parse_http_response(buf: &[u8]) -> Result<(StatusCode, Vec<u8>, Vec<(String, String)>)> {
    let text = String::from_utf8_lossy(buf);
    let header_end = text
        .find("\r\n\r\n")
        .ok_or_else(|| anyhow!("no header terminator: {}", &text[..text.len().min(200)]))?;
    let header_section = &text[..header_end];
    let body = buf[header_end + 4..].to_vec();
    let mut lines = header_section.lines();
    let status_line = lines.next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("bad status line: {status_line}"))?
        .parse::<u16>()?;
    let status = StatusCode::from_u16(code)?;
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, body, headers))
}

// ---------------------------------------------------------------------------
// Proofs
// ---------------------------------------------------------------------------

async fn run_all() -> Result<String> {
    // Install crypto provider early.
    let _ = aws_lc_rs::default_provider().install_default();

    let proof = Arc::new(ProofState::default());

    // --- Origin HTTP ---
    let (http_origin, stop_http) = start_http_origin(proof.clone()).await?;
    info!(%http_origin, "HTTP origin listening");

    // --- Origin HTTPS with cert for FAKE_HOST ---
    let origin_tls = origin_tls_config(FAKE_HOST)?;
    let (https_origin, stop_https) = start_https_origin(proof.clone(), origin_tls).await?;
    info!(%https_origin, "HTTPS origin listening");

    // =====================================================================
    // 1) HTTP proxy requests
    // =====================================================================
    {
        let mut proxy = start_proxy(proof.clone(), ConnectPolicy::Mitm).await?;
        proxy.connector.allow(
            &http_origin.ip().to_string(),
            http_origin.port(),
            http_origin,
        );
        // Also allow by hostname form used in URL.
        let url = format!("http://{http_origin}/hello");
        // Absolute-form uses host from URL — 127.0.0.1
        match http_proxy_get(proxy.addr, &url).await {
            Ok((status, body, _)) => {
                let text = String::from_utf8_lossy(&body);
                let pass = status.is_success() && text.contains("hello-from-origin");
                proof.record(
                    "HTTP proxy request",
                    pass,
                    format!("status={status} body={text:?}"),
                );
            }
            Err(e) => proof.record("HTTP proxy request", false, format!("error: {e:#}")),
        }
        let _ = proxy.stop.send(());
    }

    // =====================================================================
    // 2) CONNECT + ValidatedDial passthrough (no Hudsucker default dial)
    // =====================================================================
    {
        let mut proxy = start_proxy(proof.clone(), ConnectPolicy::PassthroughValidatedDial).await?;
        let dial = ValidatedDial {
            hostname: FAKE_HOST.to_string(),
            port: http_origin.port(),
            approved: http_origin,
        };
        proxy.handler.set_validated(dial.clone());
        // Note: connector allow not needed for pure TCP tunnel.

        // FAKE_HOST does not resolve in DNS — if hudsucker default TcpStream::connect(authority)
        // were used, this would fail. Our custom CONNECT dials approved IP.
        let dns_would_fail = tokio::net::lookup_host((FAKE_HOST, http_origin.port()))
            .await
            .map(|mut i| i.next().is_none())
            .unwrap_or(true);

        match connect_then_http(
            proxy.addr,
            FAKE_HOST,
            http_origin.port(),
            "/hello",
            false,
            &[("X-Correlation-Token", "connect-passthrough")],
        )
        .await
        {
            Ok((status, body, _)) => {
                let text = String::from_utf8_lossy(&body);
                let custom = proxy
                    .handler
                    .connect_custom_dials
                    .load(Ordering::SeqCst)
                    > 0;
                let dialed_approved = proof
                    .dial_events
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|e| e.dialed == http_origin && !e.used_dns_resolution);
                let pass = status.is_success()
                    && text.contains("hello-from-origin")
                    && custom
                    && dialed_approved
                    && dns_would_fail;
                proof.record(
                    "CONNECT with ValidatedDial (passthrough, no default authority dial)",
                    pass,
                    format!(
                        "status={status} custom_dials={} dialed_approved={dialed_approved} \
                         fake_host_dns_empty={dns_would_fail} body={text:?}",
                        proxy.handler.connect_custom_dials.load(Ordering::SeqCst)
                    ),
                );
            }
            Err(e) => proof.record(
                "CONNECT with ValidatedDial (passthrough, no default authority dial)",
                false,
                format!("error: {e:#}"),
            ),
        }

        // Document hudsucker default finding.
        proof.record(
            "FINDING: Hudsucker default CONNECT passthrough dial",
            true, // informational PASS with note
            "hudsucker 0.25 process_connect uses TcpStream::connect(authority.as_ref()) for \
             non-intercept / non-TLS-intercept tunnels (internal.rs). That path resolves the \
             authority string via the OS. This spike bypasses it by returning a CONNECT response \
             from handle_request and dialing ValidatedDial.approved directly. Product code must \
             keep that custom path (or patch hudsucker) and must not rely on with_http_connector \
             for raw CONNECT tunnels — the connector is only used for MITM-forwarded HTTP(S).",
        );

        let _ = proxy.stop.send(());
    }

    // =====================================================================
    // 3) Intercepted TLS (MITM) with generated certs + ValidatedDial upstream
    // =====================================================================
    {
        let mut proxy = start_proxy(proof.clone(), ConnectPolicy::Mitm).await?;
        proxy
            .connector
            .allow(FAKE_HOST, https_origin.port(), https_origin);

        match connect_then_http(
            proxy.addr,
            FAKE_HOST,
            https_origin.port(),
            "/hello",
            true,
            &[("X-Correlation-Token", "mitm-tls")],
        )
        .await
        {
            Ok((status, body, headers)) => {
                let text = String::from_utf8_lossy(&body);
                let dialed = proof.dial_events.lock().unwrap().iter().any(|e| {
                    e.hostname.eq_ignore_ascii_case(FAKE_HOST)
                        && e.dialed == https_origin
                        && !e.used_dns_resolution
                });
                let pass = status.is_success() && text.contains("hello-from-origin") && dialed;
                proof.record(
                    "Intercepted TLS (MITM) with generated certificates",
                    pass,
                    format!(
                        "status={status} dialed_validated={dialed} body={text:?} headers={headers:?}"
                    ),
                );
            }
            Err(e) => proof.record(
                "Intercepted TLS (MITM) with generated certificates",
                false,
                format!("error: {e:#}"),
            ),
        }
        let _ = proxy.stop.send(());
    }

    // =====================================================================
    // 4) Streaming request/response without full body buffering
    // =====================================================================
    {
        let mut proxy = start_proxy(proof.clone(), ConnectPolicy::Mitm).await?;
        proxy.connector.allow(
            &http_origin.ip().to_string(),
            http_origin.port(),
            http_origin,
        );

        // Large download via absolute-form proxy GET.
        let url = format!("http://{http_origin}/stream");
        match http_proxy_get(proxy.addr, &url).await {
            Ok((status, body, _)) => {
                // Allow response body to drain through taps.
                tokio::time::sleep(Duration::from_millis(100)).await;
                finalize_response_taps(&proof);
                let exchanges: Vec<_> = proof.exchanges.lock().unwrap().values().cloned().collect();
                let stream_ex = exchanges.iter().find(|e| e.path.contains("/stream"));
                let (cap_ok, total_ok, client_ok) = match stream_ex {
                    Some(ex) => (
                        ex.res_captured <= BODY_CAP,
                        ex.res_total_seen >= LARGE_BODY_SIZE
                            || body.len() >= LARGE_BODY_SIZE,
                        body.len() >= LARGE_BODY_SIZE || status.is_success(),
                    ),
                    None => (false, false, body.len() >= LARGE_BODY_SIZE / 2),
                };
                // Capture buffer is capped; client still received full (or large) body.
                let pass = status.is_success()
                    && body.len() >= LARGE_BODY_SIZE
                    && cap_ok
                    && stream_ex.map(|e| e.res_capped || e.res_total_seen > BODY_CAP).unwrap_or(false);
                proof.record(
                    "Streaming response without full body capture buffering",
                    pass,
                    format!(
                        "status={status} client_body={} capture={:?} total_seen={:?} capped={:?} BODY_CAP={BODY_CAP}",
                        body.len(),
                        stream_ex.map(|e| e.res_captured),
                        stream_ex.map(|e| e.res_total_seen),
                        stream_ex.map(|e| e.res_capped),
                    ),
                );
                let _ = (total_ok, client_ok);
            }
            Err(e) => proof.record(
                "Streaming response without full body capture buffering",
                false,
                format!("error: {e:#}"),
            ),
        }

        // Large upload streaming.
        proof
            .origin_bytes_received
            .store(0, Ordering::SeqCst);
        let upload_size = 512 * 1024;
        let url = format!("http://{http_origin}/echo");
        match http_proxy_post_stream(proxy.addr, &url, upload_size).await {
            Ok((status, body)) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let origin_got = proof.origin_bytes_received.load(Ordering::SeqCst);
                let exchanges: Vec<_> = proof.exchanges.lock().unwrap().values().cloned().collect();
                let up = exchanges.iter().find(|e| e.path.contains("/echo"));
                let pass = status.is_success()
                    && origin_got >= upload_size
                    && up
                        .map(|e| e.req_captured <= BODY_CAP && (e.req_capped || e.req_total_seen > BODY_CAP || upload_size <= BODY_CAP))
                        .unwrap_or(false);
                proof.record(
                    "Streaming request without full body capture buffering",
                    pass,
                    format!(
                        "status={status} origin_got={origin_got} upload={upload_size} \
                         req_captured={:?} req_total={:?} capped={:?} resp={}",
                        up.map(|e| e.req_captured),
                        up.map(|e| e.req_total_seen),
                        up.map(|e| e.req_capped),
                        String::from_utf8_lossy(&body),
                    ),
                );
            }
            Err(e) => proof.record(
                "Streaming request without full body capture buffering",
                false,
                format!("error: {e:#}"),
            ),
        }

        let _ = proxy.stop.send(());
    }

    // =====================================================================
    // 5) Body cap behavior
    // =====================================================================
    {
        // Already partially proven above; add explicit assertion.
        finalize_response_taps(&proof);
        let exchanges: Vec<_> = proof.exchanges.lock().unwrap().values().cloned().collect();
        let any_capped = exchanges.iter().any(|e| {
            (e.res_capped && e.res_captured <= BODY_CAP && e.res_total_seen > BODY_CAP)
                || (e.req_capped && e.req_captured <= BODY_CAP && e.req_total_seen > BODY_CAP)
        });
        proof.record(
            "Body cap behavior (capture <= CAP while total_seen can exceed)",
            any_capped,
            format!(
                "exchanges with cap evidence: {:?}",
                exchanges
                    .iter()
                    .filter(|e| e.req_capped || e.res_capped)
                    .map(|e| (
                        e.id,
                        e.path.clone(),
                        e.req_captured,
                        e.req_total_seen,
                        e.res_captured,
                        e.res_total_seen
                    ))
                    .collect::<Vec<_>>()
            ),
        );
    }

    // =====================================================================
    // 6) Ordered / duplicate headers
    // =====================================================================
    {
        let mut proxy = start_proxy(proof.clone(), ConnectPolicy::Mitm).await?;
        proxy.connector.allow(
            &http_origin.ip().to_string(),
            http_origin.port(),
            http_origin,
        );
        let url = format!("http://{http_origin}/headers");
        match http_proxy_get(proxy.addr, &url).await {
            Ok((status, body, client_headers)) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                finalize_response_taps(&proof);
                let exchanges: Vec<_> = proof.exchanges.lock().unwrap().values().cloned().collect();
                let ex = exchanges.iter().rev().find(|e| e.path.contains("/headers"));

                // Hyper lowercases names; order of iteration is insertion order for HeaderMap.
                let set_cookies: Vec<_> = client_headers
                    .iter()
                    .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
                    .map(|(_, v)| v.clone())
                    .collect();
                let x_dups: Vec<_> = client_headers
                    .iter()
                    .filter(|(k, _)| k.eq_ignore_ascii_case("x-dup"))
                    .map(|(_, v)| v.clone())
                    .collect();

                let handler_set_cookies = ex
                    .map(|e| {
                        e.res_headers
                            .iter()
                            .filter(|(k, _)| k == "set-cookie")
                            .map(|(_, v)| v.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                let dups_ok = set_cookies.len() >= 2 || handler_set_cookies.len() >= 2;
                let order_note = format!(
                    "client set-cookie={set_cookies:?} x-dup={x_dups:?} \
                     handler set-cookie={handler_set_cookies:?} \
                     hyper normalizes names to lowercase; HeaderMap preserves insertion order \
                     for get_all/iter. hudsucker normalize_request joins Cookie headers with '; ' \
                     and removes Host before upstream forward (capture_quality impact)."
                );

                proof.record(
                    "Ordered/duplicate headers (as Hyper exposes)",
                    status.is_success() && dups_ok,
                    format!("status={status} body_len={} {order_note}", body.len()),
                );

                // Explicit capture_quality notes.
                proof.record(
                    "FINDING: Hyper/Hudsucker header normalization",
                    true,
                    "1) Header names lowercased by Hyper http::HeaderName. \
                     2) Original wire case is not recoverable after parse \
                        (except http1_preserve_header_case / title_case on client builder — \
                        hudsucker enables title_case_headers + preserve_header_case on its \
                        default Client/Server builders for forwarding). \
                     3) Duplicate headers: HeaderMap preserves multiple values; iter order is \
                        insertion order. \
                     4) Cookie request headers are joined by hudsucker::normalize_request. \
                     5) Host request header is stripped by normalize_request (Hyper re-adds). \
                     Labels: header_names=http_lowercased; cookie_join=hudsucker_normalized; \
                     host=stripped_then_readded; wire_case=best_effort_via_preserve_header_case.",
                );
            }
            Err(e) => proof.record(
                "Ordered/duplicate headers (as Hyper exposes)",
                false,
                format!("error: {e:#}"),
            ),
        }
        let _ = proxy.stop.send(());
    }

    // =====================================================================
    // 7) Concurrent requests with correct correlation
    // =====================================================================
    {
        let mut proxy = start_proxy(proof.clone(), ConnectPolicy::Mitm).await?;
        proxy.connector.allow(
            &http_origin.ip().to_string(),
            http_origin.port(),
            http_origin,
        );

        let n = 8usize;
        let mut joins = Vec::new();
        for i in 0..n {
            let proxy_addr = proxy.addr;
            let url = format!("http://{http_origin}/concurrent/{i}");
            joins.push(tokio::spawn(async move {
                let mut stream = TcpStream::connect(proxy_addr).await?;
                let req = format!(
                    "GET {url} HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\
                     X-Correlation-Token: tok-{i}\r\n\r\n"
                );
                stream.write_all(req.as_bytes()).await?;
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf).await?;
                let (status, body, headers) = parse_http_response(&buf)?;
                let text = String::from_utf8_lossy(&body).to_string();
                let origin_id = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("x-origin-id"))
                    .map(|(_, v)| v.clone());
                let exchange_id = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("x-spike-exchange-id"))
                    .map(|(_, v)| v.clone());
                Ok::<_, anyhow::Error>((i, status, text, origin_id, exchange_id))
            }));
        }

        let mut ok = 0usize;
        let mut details = Vec::new();
        for j in joins {
            match j.await {
                Ok(Ok((i, status, text, origin_id, exchange_id))) => {
                    let matched = status.is_success()
                        && text.contains(&format!("concurrent-ok:{i}"))
                        && origin_id.as_deref() == Some(&i.to_string());
                    if matched {
                        ok += 1;
                    }
                    details.push(format!(
                        "i={i} status={status} origin_id={origin_id:?} exchange_id={exchange_id:?} matched={matched}"
                    ));
                }
                Ok(Err(e)) => details.push(format!("error: {e:#}")),
                Err(e) => details.push(format!("join: {e}")),
            }
        }

        // Handler-side: each exchange has unique id and matching correlation token.
        let exchanges: Vec<_> = proof.exchanges.lock().unwrap().values().cloned().collect();
        let concurrent_ex: Vec<_> = exchanges
            .iter()
            .filter(|e| e.path.contains("/concurrent/"))
            .cloned()
            .collect();
        let tokens_unique = {
            let mut t: Vec<_> = concurrent_ex
                .iter()
                .filter_map(|e| e.correlation_token.clone())
                .collect();
            t.sort();
            t.dedup();
            t.len()
        };
        let ids_unique = {
            let mut ids: Vec<_> = concurrent_ex.iter().map(|e| e.id).collect();
            ids.sort_unstable();
            ids.dedup();
            ids.len()
        };

        let pass = ok == n && ids_unique >= n && tokens_unique >= n;
        proof.record(
            "Concurrent requests with correct correlation",
            pass,
            format!(
                "client_ok={ok}/{n} unique_exchange_ids={ids_unique} unique_tokens={tokens_unique} details={details:?}"
            ),
        );

        // Note on H2: MITM ALPN offers h2; this harness used HTTP/1.1 concurrent conns.
        proof.record(
            "FINDING: Concurrent HTTP/2 streams",
            true,
            "Spike proved concurrent correlation over concurrent HTTP/1.1 connections. \
             Hudsucker enables h2 ALPN on MITM certs when feature http2 is on, and clones \
             HttpHandler per request so request/response share one handler instance \
             (per-exchange fields are safe). Full H2 stream multiplexing correlation was not \
             separately instrumented in this harness (would need H2 client frames); pattern is \
             the same handler clone model.",
        );

        let _ = proxy.stop.send(());
    }

    // =====================================================================
    // 8) Graceful client disconnect
    // =====================================================================
    {
        let mut proxy = start_proxy(proof.clone(), ConnectPolicy::Mitm).await?;
        proxy.connector.allow(
            &http_origin.ip().to_string(),
            http_origin.port(),
            http_origin,
        );

        // Partial read then drop while origin streams /slow.
        let result = timeout(
            Duration::from_secs(5),
            connect_then_http_read_partial(
                proxy.addr,
                &http_origin.ip().to_string(),
                http_origin.port(),
                "/slow",
                false,
                2048,
            ),
        )
        .await;

        // Proxy should still accept a new request after disconnect.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let after = http_proxy_get(
            proxy.addr,
            &format!("http://{http_origin}/hello"),
        )
        .await;

        match (result, after) {
            (Ok(Ok(n)), Ok((status, body, _))) => {
                let pass = n > 0 && status.is_success() && body.windows(17).any(|w| w == b"hello-from-origin");
                proof.record(
                    "Graceful handling of client disconnect",
                    pass,
                    format!(
                        "partial_read={n} subsequent_hello status={status} (proxy did not hang/panic)"
                    ),
                );
            }
            (Ok(Err(e)), _) => proof.record(
                "Graceful handling of client disconnect",
                false,
                format!("partial read error: {e:#}"),
            ),
            (Err(_), _) => proof.record(
                "Graceful handling of client disconnect",
                false,
                "timeout during partial read/disconnect",
            ),
            (Ok(Ok(n)), Err(e)) => proof.record(
                "Graceful handling of client disconnect",
                false,
                format!("partial_read={n} but subsequent request failed: {e:#}"),
            ),
        }

        let _ = proxy.stop.send(());
    }

    // Decoder feature off proof.
    proof.record(
        "FINDING: decoder feature disabled",
        true,
        "Spike builds hudsucker with default-features=false and features=[http2, rcgen-ca, rustls-client] only. \
         decode_request/decode_response are not available; bodies are not auto-decompressed by hudsucker. \
         Streaming taps observe raw framed bytes as Hyper delivers them.",
    );

    // Write RESULT.md
    let md = render_result(&proof);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("RESULT.md");
    std::fs::write(&path, &md)?;
    info!(path = %path.display(), "wrote RESULT.md");

    let _ = stop_http.send(());
    let _ = stop_https.send(());

    Ok(md)
}

fn render_result(proof: &ProofState) -> String {
    let results = proof.results.lock().unwrap().clone();
    let dials = proof.dial_events.lock().unwrap().clone();
    let mut out = String::new();
    out.push_str("# Hudsucker Phase 0 Spike — RESULT\n\n");
    out.push_str(&format!(
        "- Date: {}\n",
        chrono_like_now()
    ));
    out.push_str("- Crate: `spikes/hudsucker_spike` (standalone; does not modify main `bb` crate)\n");
    out.push_str("- Hudsucker: 0.25 (`default-features = false`, features: `http2`, `rcgen-ca`, `rustls-client`)\n");
    out.push_str("- Origin: local Hyper HTTP + HTTPS fixtures\n\n");

    out.push_str("## Summary\n\n");
    let pass = results.iter().filter(|r| r.pass && !r.name.starts_with("FINDING:")).count();
    let fail = results.iter().filter(|r| !r.pass && !r.name.starts_with("FINDING:")).count();
    let findings = results.iter().filter(|r| r.name.starts_with("FINDING:")).count();
    out.push_str(&format!(
        "- Proof points: **{pass} PASS**, **{fail} FAIL**\n- Findings recorded: {findings}\n\n"
    ));

    out.push_str("## Proof points\n\n");
    out.push_str("| Status | Proof | Detail |\n");
    out.push_str("|--------|-------|--------|\n");
    for r in &results {
        if r.name.starts_with("FINDING:") {
            continue;
        }
        let status = if r.pass { "PASS" } else { "FAIL" };
        let detail = r.detail.replace('|', "\\|").replace('\n', " ");
        out.push_str(&format!("| {status} | {} | {detail} |\n", r.name));
    }

    out.push_str("\n## Findings / API notes\n\n");
    for r in &results {
        if r.name.starts_with("FINDING:") {
            out.push_str(&format!("### {}\n\n{}\n\n", r.name, r.detail));
        }
    }

    out.push_str("## ValidatedDial events (sample)\n\n");
    out.push_str("```\n");
    for e in dials.iter().take(32) {
        out.push_str(&format!(
            "host={} port={} dialed={} dns_resolution={}\n",
            e.hostname, e.port, e.dialed, e.used_dns_resolution
        ));
    }
    out.push_str("```\n\n");

    out.push_str("## Architecture used in spike\n\n");
    out.push_str(
        r#"```
client --HTTP absolute-form--> Hudsucker --ValidatedDialConnector--> Hyper origin (HTTP)
client --CONNECT fake-host--> SpikeHandler (ValidatedDial TcpStream::connect(ip)) --> origin (passthrough)
client --CONNECT + TLS------> Hudsucker MITM (rcgen cert) --HttpsConnector<ValidatedDial>--> HTTPS origin
```
"#,
    );

    out.push_str("## capture_quality implications\n\n");
    out.push_str(
        "- `header_names`: lowercased by Hyper (`http::HeaderName`)\n\
         - `header_order`: best-effort insertion order via `HeaderMap::iter` / `get_all`\n\
         - `header_case`: wire case not available after parse unless using Hyper HTTP/1 case maps (`preserve_header_case`); Hudsucker enables this on default client/server builders\n\
         - `cookie_headers`: joined by `hudsucker::normalize_request` before upstream\n\
         - `host_header`: stripped then re-added by Hyper client\n\
         - `body_representation`: raw frames when decoder feature is off; capture buffer capped at BODY_CAP with `total_seen` for overflow labeling\n\
         - `dial_policy`: ValidatedDial only; no second DNS lookup on proven paths\n",
    );

    out
}

fn chrono_like_now() -> String {
    // Avoid extra chrono dep; use system time.
    use std::time::SystemTime;
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => format!("unix-{}", d.as_secs()),
        Err(_) => "unknown".into(),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hudsucker_spike=info,hudsucker=warn".into()),
        )
        .init();

    match run_all().await {
        Ok(md) => {
            println!("\n========== RESULT.md ==========\n{md}");
            let fails = md.lines().filter(|l| l.starts_with("| FAIL")).count();
            if fails > 0 {
                eprintln!("{fails} proof point(s) FAILED");
                std::process::exit(1);
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("spike failed: {e:#}");
            Err(e)
        }
    }
}
