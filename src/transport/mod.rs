//! Semantic outbound HTTP transport.
//!
//! The primary path uses Wreq's pinned Chrome-compatible protocol profile. Both
//! the primary and fallback paths use the addresses resolved for each send;
//! neither transport silently performs a second DNS lookup.

use crate::domain::{DomainError, DomainResult, ErrorCode, TransportProvenance, ValidatedDial};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use wreq::dns::Resolve;
use wreq_util::Emulation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProfile {
    Chrome,
    TransportOnly,
    GenericUnprofiled,
}

#[derive(Debug, Clone)]
pub enum OutboundBody {
    Empty,
    Bytes(Bytes),
    Spool { path: PathBuf, len: u64 },
}

impl OutboundBody {
    fn len(&self) -> u64 {
        match self {
            Self::Empty => 0,
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::Spool { len, .. } => *len,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: OutboundBody,
    pub protocol: ProtocolMode,
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
    pub max_body_bytes: u64,
    /// Preserve caller-supplied identity headers. Wreq's protocol profile still
    /// controls TLS/HTTP2 characteristics, while explicit headers win.
    pub preserve_identity_headers: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolMode {
    Auto,
    Http1,
    Http2,
}

#[derive(Debug, Clone)]
pub struct OutboundResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Bytes,
    pub body_truncated: bool,
    pub protocol: String,
    pub transport_provenance: TransportProvenance,
    pub transport_profile: String,
    pub duration: Duration,
}

pub type OutboundByteStream = Pin<Box<dyn Stream<Item = DomainResult<Bytes>> + Send>>;

pub struct StreamingOutboundResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: OutboundByteStream,
    pub protocol: String,
    pub transport_provenance: TransportProvenance,
    pub transport_profile: String,
}

#[async_trait]
pub trait SemanticTransport: Send + Sync {
    async fn send(
        &self,
        dial: &ValidatedDial,
        req: OutboundRequest,
    ) -> DomainResult<OutboundResponse>;

    async fn send_stream(
        &self,
        dial: &ValidatedDial,
        req: OutboundRequest,
    ) -> DomainResult<StreamingOutboundResponse> {
        let response = self.send(dial, req).await?;
        let body = response.body;
        Ok(StreamingOutboundResponse {
            status: response.status,
            headers: response.headers,
            body: Box::pin(futures::stream::once(async move { Ok(body) })),
            protocol: response.protocol,
            transport_provenance: response.transport_provenance,
            transport_profile: response.transport_profile,
        })
    }

    fn profile_name(&self) -> &str;
    fn provenance(&self) -> TransportProvenance;
}

#[derive(Clone)]
struct ApprovedResolver {
    hostname: String,
    addresses: Vec<std::net::SocketAddr>,
}

impl ApprovedResolver {
    fn new(dial: &ValidatedDial) -> DomainResult<Self> {
        if dial.approved_socket_addrs.is_empty() {
            return Err(DomainError::scope_denied(
                "no approved address in ValidatedDial",
            ));
        }
        Ok(Self {
            hostname: dial.hostname.trim_end_matches('.').to_ascii_lowercase(),
            addresses: dial.approved_socket_addrs.clone(),
        })
    }
}

impl Resolve for ApprovedResolver {
    fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
        let requested = name.as_str().trim_end_matches('.').to_ascii_lowercase();
        let expected = self.hostname.clone();
        let addresses = self.addresses.clone();
        Box::pin(async move {
            if requested != expected {
                return Err(format!(
                    "ValidatedDial refused DNS fallback for {requested}; expected {expected}"
                )
                .into());
            }
            let addrs: wreq::dns::Addrs = Box::new(addresses.into_iter());
            Ok(addrs)
        })
    }
}

/// Chrome-profiled semantic egress. A client is built per request because the
/// resolved DNS answer is request-specific. This prevents a pooled connection
/// from silently surviving a new resolution.
pub struct WreqTransport;

impl WreqTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SemanticTransport for WreqTransport {
    async fn send(
        &self,
        dial: &ValidatedDial,
        req: OutboundRequest,
    ) -> DomainResult<OutboundResponse> {
        let started = std::time::Instant::now();
        let max_body_bytes = req.max_body_bytes;
        let response = self.send_stream(dial, req).await?;
        let (body, body_truncated) = collect_stream_body(response.body, max_body_bytes).await?;
        Ok(OutboundResponse {
            status: response.status,
            headers: response.headers,
            body,
            body_truncated,
            protocol: response.protocol,
            transport_provenance: response.transport_provenance,
            transport_profile: response.transport_profile,
            duration: started.elapsed(),
        })
    }

    async fn send_stream(
        &self,
        dial: &ValidatedDial,
        req: OutboundRequest,
    ) -> DomainResult<StreamingOutboundResponse> {
        let resolver = ApprovedResolver::new(dial)?;
        let mut builder = wreq::Client::builder()
            .no_proxy()
            .redirect(wreq::redirect::Policy::none())
            .connect_timeout(req.connect_timeout)
            .timeout(req.total_timeout)
            .pool_max_idle_per_host(0)
            .dns_resolver(resolver)
            .emulation(Emulation::Chrome147);

        builder = match req.protocol {
            ProtocolMode::Auto => builder,
            ProtocolMode::Http1 => builder.http1_only(),
            ProtocolMode::Http2 => builder.http2_only(),
        };

        let client = builder.build().map_err(|e| {
            DomainError::new(ErrorCode::ProtocolError, format!("transport build: {e}"))
        })?;

        let mut request = client.request(req.method.clone(), &req.url);
        let body_len = req.body.len();
        let headers = canonical_headers(&req.headers, body_len)?;
        request = request.headers(headers);
        match req.body {
            OutboundBody::Empty => {}
            OutboundBody::Bytes(body) => {
                request = request.body(wreq::Body::from(body));
            }
            OutboundBody::Spool { path, len } => {
                let file = tokio::fs::File::open(&path).await.map_err(|error| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        format!("open request spool {}: {error}", path.display()),
                    )
                })?;
                let stream = ReaderStream::new(file.take(len));
                request = request.body(wreq::Body::wrap_stream(stream));
            }
        }

        let response = request.send().await.map_err(map_wreq_error)?;
        let status = StatusCode::from_u16(response.status().as_u16())
            .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?;
        let protocol = match response.version() {
            wreq::Version::HTTP_2 => "HTTP/2",
            wreq::Version::HTTP_10 => "HTTP/1.0",
            _ => "HTTP/1.1",
        }
        .to_string();
        let response_headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
            .collect();
        let body = Box::pin(
            response
                .bytes_stream()
                .map(|chunk| chunk.map_err(map_wreq_error)),
        );

        Ok(StreamingOutboundResponse {
            status,
            headers: response_headers,
            body,
            protocol,
            transport_provenance: TransportProvenance::ProtocolProfileOnly,
            transport_profile: "wreq_chrome147_protocol_profile".into(),
        })
    }

    fn profile_name(&self) -> &str {
        "wreq_chrome147_protocol_profile"
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::ProtocolProfileOnly
    }
}

async fn collect_stream_body(
    mut stream: OutboundByteStream,
    max_body_bytes: u64,
) -> DomainResult<(Bytes, bool)> {
    let cap = usize::try_from(max_body_bytes).unwrap_or(usize::MAX);
    let mut out = BytesMut::with_capacity(cap.min(64 * 1024));
    let mut truncated = false;

    while let Some(next) = stream.next().await {
        let chunk = next?;
        let room = cap.saturating_sub(out.len());
        if chunk.len() > room {
            out.extend_from_slice(&chunk[..room]);
            truncated = true;
            break;
        }
        out.extend_from_slice(&chunk);
        if out.len() == cap {
            // If no Content-Length was available, one more frame is required to
            // distinguish an exact-cap body from a truncated stream.
            if let Some(next) = stream.next().await {
                let next = next?;
                truncated |= !next.is_empty();
            }
            break;
        }
    }
    Ok((out.freeze(), truncated))
}

fn map_wreq_error(error: wreq::Error) -> DomainError {
    if error.is_timeout() {
        DomainError::new(ErrorCode::Timeout, error.to_string())
    } else if error.is_connect() {
        DomainError::new(ErrorCode::Unavailable, error.to_string())
    } else {
        DomainError::new(ErrorCode::ProtocolError, error.to_string())
    }
}

fn canonical_headers(headers: &[(String, Vec<u8>)], body_len: u64) -> DomainResult<HeaderMap> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| DomainError::invalid(format!("header name: {e}")))?;
        let value = HeaderValue::from_bytes(value)
            .map_err(|e| DomainError::invalid(format!("header value: {e}")))?;
        map.append(name, value);
    }
    if body_len > 0 {
        map.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&body_len.to_string())
                .map_err(|e| DomainError::invalid(e.to_string()))?,
        );
    }
    Ok(map)
}

/// The generic factory remains as a compatibility name for callers. The
/// runtime now uses the pinned profile-aware transport by default.
pub fn build_default_transport(_max_body: u64) -> std::sync::Arc<dyn SemanticTransport> {
    std::sync::Arc::new(WreqTransport::new())
}

pub fn try_wreq_transport(_max_body: u64) -> Option<std::sync::Arc<dyn SemanticTransport>> {
    Some(std::sync::Arc::new(WreqTransport::new()))
}

pub fn headers_to_map(headers: &[(String, Vec<u8>)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value),
        ) {
            map.append(name, value);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full, StreamBody};
    use hyper::body::Frame;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    #[test]
    fn canonicalization_removes_stale_framing() {
        let headers = vec![
            ("Transfer-Encoding".into(), b"chunked".to_vec()),
            ("Content-Length".into(), b"999".to_vec()),
            ("X-Test".into(), b"ok".to_vec()),
        ];
        let map = canonical_headers(&headers, 3).unwrap();
        assert_eq!(map.get("content-length").unwrap(), "3");
        assert!(!map.contains_key("transfer-encoding"));
        assert_eq!(map.get("x-test").unwrap(), "ok");
    }

    #[test]
    fn approved_resolver_rejects_other_hosts() {
        let resolver = ApprovedResolver {
            hostname: "example.com".into(),
            addresses: vec!["127.0.0.1:443".parse().unwrap()],
        };
        let name = wreq::dns::Name::new("other.example".into());
        let result = futures::executor::block_on(resolver.resolve(name));
        let error = match result {
            Ok(_) => panic!("unexpected resolver success"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("refused DNS fallback"));
    }

    #[tokio::test]
    async fn profiled_transport_decodes_chunked_and_enforces_capture_cap() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(|_: Request<hyper::body::Incoming>| async move {
                let chunks = futures::stream::iter(vec![
                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"abc"))),
                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"def"))),
                ]);
                Ok::<_, Infallible>(Response::new(StreamBody::new(chunks)))
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });
        let dial = ValidatedDial {
            hostname: "profile.test".into(),
            port: addr.port(),
            approved_socket_addrs: vec![addr],
            policy_epoch: 1,
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
            scheme: "http".into(),
            path: "/".into(),
        };
        let response = WreqTransport::new()
            .send(
                &dial,
                OutboundRequest {
                    method: Method::GET,
                    url: format!("http://profile.test:{}/", addr.port()),
                    headers: vec![],
                    body: OutboundBody::Empty,
                    protocol: ProtocolMode::Http1,
                    connect_timeout: Duration::from_secs(2),
                    total_timeout: Duration::from_secs(2),
                    max_body_bytes: 5,
                    preserve_identity_headers: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(response.protocol, "HTTP/1.1");
        assert_eq!(response.body.as_ref(), b"abcde");
        assert!(response.body_truncated);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn streaming_response_exposes_first_chunk_before_upstream_eof() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(|_: Request<hyper::body::Incoming>| async move {
                let chunks = async_stream::stream! {
                    yield Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"first")));
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    yield Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"second")));
                };
                Ok::<_, Infallible>(Response::new(StreamBody::new(chunks)))
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        let dial = ValidatedDial {
            hostname: "stream.test".into(),
            port: addr.port(),
            approved_socket_addrs: vec![addr],
            policy_epoch: 1,
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
            scheme: "http".into(),
            path: "/".into(),
        };
        let mut response = WreqTransport::new()
            .send_stream(
                &dial,
                OutboundRequest {
                    method: Method::GET,
                    url: format!("http://stream.test:{}/", addr.port()),
                    headers: vec![],
                    body: OutboundBody::Empty,
                    protocol: ProtocolMode::Http1,
                    connect_timeout: Duration::from_secs(2),
                    total_timeout: Duration::from_secs(10),
                    max_body_bytes: 1024,
                    preserve_identity_headers: true,
                },
            )
            .await
            .unwrap();
        let first = tokio::time::timeout(Duration::from_secs(1), response.body.next())
            .await
            .expect("first chunk should arrive before upstream EOF")
            .unwrap()
            .unwrap();
        assert_eq!(first, Bytes::from_static(b"first"));
        drop(response);
        server.abort();
    }

    #[tokio::test]
    async fn spool_backed_request_body_is_streamed_to_upstream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (payload_sender, payload_receiver) = tokio::sync::oneshot::channel();
        let payload_sender = std::sync::Arc::new(tokio::sync::Mutex::new(Some(payload_sender)));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let payload_sender = payload_sender.clone();
                async move {
                    let payload = request.into_body().collect().await.unwrap().to_bytes();
                    if let Some(sender) = payload_sender.lock().await.take() {
                        let _ = sender.send(payload);
                    }
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
                }
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("request.spool");
        let payload = vec![0x41; 512 * 1024];
        std::fs::write(&path, &payload).unwrap();
        let dial = ValidatedDial {
            hostname: "upload.test".into(),
            port: addr.port(),
            approved_socket_addrs: vec![addr],
            policy_epoch: 1,
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
            scheme: "http".into(),
            path: "/".into(),
        };
        WreqTransport::new()
            .send(
                &dial,
                OutboundRequest {
                    method: Method::POST,
                    url: format!("http://upload.test:{}/", addr.port()),
                    headers: vec![],
                    body: OutboundBody::Spool {
                        path,
                        len: payload.len() as u64,
                    },
                    protocol: ProtocolMode::Http1,
                    connect_timeout: Duration::from_secs(2),
                    total_timeout: Duration::from_secs(5),
                    max_body_bytes: 1024,
                    preserve_identity_headers: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(payload_receiver.await.unwrap(), payload);
        server.await.unwrap();
    }
}
