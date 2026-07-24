//! Local HTTP/HTTPS origin servers used as dial targets for the spike.
//!
//! They record peer address, Host header, HTTP version, and body metrics so
//! the client side can prove Host/SNI preservation and approved-IP dialing.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use futures::stream;
use rcgen::generate_simple_self_signed;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

pub type BoxErr = Box<dyn std::error::Error + Send + Sync>;
pub type RespBody = BoxBody<Bytes, Infallible>;

#[derive(Debug, Default, Clone)]
pub struct ObservedRequest {
    pub peer: Option<SocketAddr>,
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub version: String,
    pub body_len: usize,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct OriginState {
    pub last: Mutex<Option<ObservedRequest>>,
    pub request_count: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
}

impl OriginState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            last: Mutex::new(None),
            request_count: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
        })
    }

    pub async fn take_last(&self) -> Option<ObservedRequest> {
        self.last.lock().await.take()
    }
}

pub struct OriginHandles {
    pub addr: SocketAddr,
    pub state: Arc<OriginState>,
    /// PEM of the self-signed CA/server cert (HTTPS only).
    pub ca_pem: Option<String>,
    /// Join handle — abort when done.
    pub task: tokio::task::JoinHandle<()>,
}

fn full_body(s: impl Into<Bytes>) -> RespBody {
    Full::new(s.into()).boxed()
}

async fn handle(
    peer: Option<SocketAddr>,
    req: Request<Incoming>,
    state: Arc<OriginState>,
) -> Result<Response<RespBody>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let version = format!("{:?}", req.version());
    // HTTP/1 uses Host; HTTP/2 usually carries :authority (exposed as req.uri().authority()).
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()));

    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let body_len = body_bytes.len();
    state
        .bytes_received
        .fetch_add(body_len as u64, Ordering::SeqCst);
    state.request_count.fetch_add(1, Ordering::SeqCst);

    {
        let mut g = state.last.lock().await;
        *g = Some(ObservedRequest {
            peer,
            method: method.to_string(),
            path: path.clone(),
            host,
            version: version.clone(),
            body_len,
            headers,
        });
    }

    // Routes
    if path == "/health" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("x-origin", "transport-spike")
            .header("x-http-version", version)
            .body(full_body("ok"))
            .unwrap());
    }

    if path == "/echo" {
        state
            .bytes_sent
            .fetch_add(body_len as u64, Ordering::SeqCst);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(full_body(body_bytes))
            .unwrap());
    }

    if path == "/stream-download" {
        // Stream ~256 KiB in small chunks so cancellation can interrupt mid-body.
        let total_chunks = 64u32; // 256 KiB
        let state2 = state.clone();
        let s = stream::unfold(0u32, move |i| {
            let state2 = state2.clone();
            async move {
                if i >= total_chunks {
                    return None;
                }
                state2.bytes_sent.fetch_add(4096, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                let frame: Result<Frame<Bytes>, Infallible> =
                    Ok(Frame::data(Bytes::from(vec![0xABu8; 4096])));
                Some((frame, i + 1))
            }
        });
        let body = StreamBody::new(s).boxed();
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(body)
            .unwrap());
    }

    if path == "/slow" {
        tokio::time::sleep(Duration::from_secs(30)).await;
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(full_body("too-slow"))
            .unwrap());
    }

    if method == Method::POST && path == "/upload-stats" {
        let msg = format!("received={body_len}");
        state
            .bytes_sent
            .fetch_add(msg.len() as u64, Ordering::SeqCst);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(full_body(msg))
            .unwrap());
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(full_body("not found"))
        .unwrap())
}

/// Plain HTTP origin (HTTP/1.1 + HTTP/2 cleartext if client speaks prior knowledge).
pub async fn start_http_origin() -> Result<OriginHandles> {
    let state = OriginState::new();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind http origin")?;
    let addr = listener.local_addr()?;
    let state_clone = state.clone();

    let task = tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let state = state_clone.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let state = state.clone();
                    async move { handle(Some(peer), req, state).await }
                });
                let builder = AutoBuilder::new(TokioExecutor::new());
                let _ = builder.serve_connection(io, svc).await;
            });
        }
    });

    Ok(OriginHandles {
        addr,
        state,
        ca_pem: None,
        task,
    })
}

/// Install a process-level rustls CryptoProvider once (ring).
fn ensure_rustls_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// HTTPS origin with a self-signed cert for `hostname` SAN (ALPN http/1.1 + h2).
pub async fn start_https_origin(hostname: &str) -> Result<OriginHandles> {
    ensure_rustls_provider();
    let state = OriginState::new();

    let certified = generate_simple_self_signed(vec![
        hostname.to_string(),
        "localhost".into(),
        "127.0.0.1".into(),
    ])
    .context("generate self-signed cert")?;
    let ca_pem = certified.cert.pem();
    let cert_der = certified.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.to_vec())],
            PrivateKeyDer::Pkcs8(key_der),
        )
        .context("server cert")?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind https origin")?;
    let addr = listener.local_addr()?;
    let state_clone = state.clone();

    let task = tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let state = state_clone.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let io = TokioIo::new(tls);
                let svc = service_fn(move |req| {
                    let state = state.clone();
                    async move { handle(Some(peer), req, state).await }
                });
                let builder = AutoBuilder::new(TokioExecutor::new());
                let _ = builder.serve_connection(io, svc).await;
            });
        }
    });

    Ok(OriginHandles {
        addr,
        state,
        ca_pem: Some(ca_pem),
        task,
    })
}

/// Tiny helper: set a default Host if missing (not used by clients).
#[allow(dead_code)]
pub fn ensure_host(headers: &mut HeaderMap, host: &str) {
    if !headers.contains_key(http::header::HOST) {
        headers.insert(
            http::header::HOST,
            HeaderValue::from_str(host).expect("host"),
        );
    }
}

// Re-export Version for assertions without extra deps in bins.
pub use http::Version as HttpVersion;
