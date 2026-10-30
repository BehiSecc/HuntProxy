//! Semantic outbound HTTP transport.
//!
//! The primary path uses Wreq's pinned Chrome-compatible protocol profile.
//! Identity-scoped clients reuse connections only while the approved address set
//! and policy epoch remain unchanged; the resolver never performs a hidden
//! second DNS lookup.

use crate::domain::{
    CaptureSession, DomainError, DomainResult, ErrorCode, ProjectId, TransportProvenance,
    ValidatedDial,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::hash::Hash;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_util::io::ReaderStream;
use wreq::dns::Resolve;
use wreq_util::Emulation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProfile {
    Chrome,
    TransportOnly,
    GenericUnprofiled,
}

/// Separate connection pools and TLS session tickets for independent identities.
/// Browser action capture tokens change frequently, so browser traffic uses its
/// stable workspace session instead of the short-lived capture session token.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportIdentity {
    Browser {
        project_id: ProjectId,
        session_id: i64,
    },
    Capture {
        project_id: ProjectId,
        session_id: i64,
    },
    Reply {
        project_id: ProjectId,
        credential_digest: [u8; 32],
    },
}

impl TransportIdentity {
    pub fn for_capture(session: &CaptureSession) -> Self {
        match session.browser_session_id {
            Some(browser) => Self::Browser {
                project_id: session.project_id,
                session_id: browser.get(),
            },
            None => Self::Capture {
                project_id: session.project_id,
                session_id: session.id.get(),
            },
        }
    }

    pub fn for_reply(project_id: ProjectId, headers: &[(String, Vec<u8>)]) -> Self {
        let mut credentials = headers
            .iter()
            .filter(|(name, _)| crate::policy::is_sensitive_header(name))
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .collect::<Vec<_>>();
        credentials.sort_by(|left, right| left.0.cmp(&right.0));
        let mut digest = Sha256::new();
        for (name, value) in credentials {
            digest.update((name.len() as u64).to_be_bytes());
            digest.update(name.as_bytes());
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        Self::Reply {
            project_id,
            credential_digest: digest.finalize().into(),
        }
    }
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
    pub identity: TransportIdentity,
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: OutboundBody,
    pub protocol: ProtocolMode,
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
    pub max_body_bytes: u64,
    /// Preserve caller identity headers, including intentional omissions.
    /// Wreq's protocol profile still controls TLS/HTTP2 characteristics, but
    /// its default headers are disabled when true and enabled when false.
    pub preserve_identity_headers: bool,
    /// Explicit upstream proxy URL selected by the caller. None is direct.
    pub upstream_proxy: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

pub trait TransportSocket: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TransportSocket for T {}

/// An HTTP/1 upgrade keeps the same profiled TLS connection and preserves any
/// bytes received immediately after the response headers.
pub struct OutboundUpgradeResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Bytes,
    pub body_truncated: bool,
    /// Preserve a received response head and partial body on read/upgrade failure.
    pub error: Option<DomainError>,
    pub upgraded: Option<Box<dyn TransportSocket>>,
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

    async fn send_upgrade(
        &self,
        _dial: &ValidatedDial,
        _req: OutboundRequest,
    ) -> DomainResult<OutboundUpgradeResponse> {
        Err(DomainError::new(
            ErrorCode::ProtocolError,
            "transport does not support HTTP upgrades",
        ))
    }

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

const CLIENT_CACHE_TTL: Duration = Duration::from_secs(300);
const MAX_CACHED_CLIENTS: usize = 64;
const MAX_IDLE_CONNECTIONS_PER_HOST: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClientKey {
    identity: TransportIdentity,
    url_credentials: Option<[u8; 32]>,
    hostname: String,
    port: u16,
    scheme: String,
    addresses: Vec<std::net::SocketAddr>,
    policy_epoch: u64,
    protocol: ProtocolMode,
    connect_timeout: Duration,
    total_timeout: Duration,
    upstream_proxy: Option<String>,
}

impl ClientKey {
    fn new(dial: &ValidatedDial, req: &OutboundRequest) -> Self {
        let mut addresses = dial.approved_socket_addrs.clone();
        addresses.sort_unstable();
        addresses.dedup();
        Self {
            identity: req.identity.clone(),
            // Wreq may synthesize Basic authentication from URL userinfo after
            // the caller supplied its headers. It must also partition pools.
            url_credentials: url::Url::parse(&req.url).ok().and_then(|url| {
                if url.username().is_empty() && url.password().is_none() {
                    return None;
                }
                let mut digest = Sha256::new();
                digest.update((url.username().len() as u64).to_be_bytes());
                digest.update(url.username().as_bytes());
                digest.update(url.password().unwrap_or_default().as_bytes());
                Some(digest.finalize().into())
            }),
            hostname: dial.hostname.trim_end_matches('.').to_ascii_lowercase(),
            port: dial.port,
            scheme: dial.scheme.to_ascii_lowercase(),
            addresses,
            policy_epoch: dial.policy_epoch,
            protocol: req.protocol,
            connect_timeout: req.connect_timeout,
            total_timeout: req.total_timeout,
            upstream_proxy: req.upstream_proxy.clone(),
        }
    }

    fn same_origin(&self, other: &Self) -> bool {
        self.hostname == other.hostname && self.port == other.port && self.scheme == other.scheme
    }

    fn same_resolution_and_policy(&self, other: &Self) -> bool {
        self.addresses == other.addresses && self.policy_epoch == other.policy_epoch
    }
}

struct CachedClient {
    client: wreq::Client,
    created_at: Instant,
    last_used_at: Instant,
    expires_at: Instant,
}

/// Chrome-profiled semantic egress with a small connection pool and bounded idle lifetime.
/// Cache entries are pinned to the validated DNS answer and policy epoch.
/// A changed answer or policy immediately drops older clients for that origin.
pub struct WreqTransport {
    clients: Mutex<HashMap<ClientKey, CachedClient>>,
    emulation: wreq_util::Profile,
    profile_name: String,
    #[cfg(test)]
    test_cert_store: Option<wreq::tls::trust::CertStore>,
}

impl WreqTransport {
    pub fn new() -> Self {
        Self::with_chrome_major(153).expect("pinned Chrome153 transport profile")
    }

    pub fn with_chrome_major(major: u32) -> DomainResult<Self> {
        let emulation = match major {
            146 => Emulation::Chrome146,
            149 => Emulation::Chrome149,
            153 => Emulation::Chrome153,
            _ => {
                return Err(DomainError::new(
                    ErrorCode::ConfigInvalid,
                    format!(
                        "no tested transport profile for Chromium {major}; supported: 146, 149, 153"
                    ),
                ))
            }
        };
        Ok(Self {
            clients: Mutex::new(HashMap::new()),
            emulation,
            profile_name: format!("wreq_chrome{major}_protocol_profile"),
            #[cfg(test)]
            test_cert_store: None,
        })
    }

    fn client_for(
        &self,
        dial: &ValidatedDial,
        req: &OutboundRequest,
    ) -> DomainResult<wreq::Client> {
        let resolver = ApprovedResolver::new(dial)?;
        let key = ClientKey::new(dial, req);
        let now = Instant::now();
        // An idle TLS session may outlive the previous DNS approval, but each
        // use must supply a fresh approval with the identical address set and
        // policy epoch. Never let a cached client authorize an expired dial.
        if dial.expires_at <= time::OffsetDateTime::now_utc() {
            return Err(DomainError::scope_denied(
                "DNS approval expired; resolve destination again",
            ));
        }
        let ttl = CLIENT_CACHE_TTL;
        let mut clients = self.clients.lock();
        clients.retain(|cached_key, cached| {
            cached.expires_at > now
                && (!cached_key.same_origin(&key) || cached_key.same_resolution_and_policy(&key))
        });
        if let Some(cached) = clients.get_mut(&key) {
            // Only fresh matching validation can extend an active identity's
            // pool lifetime. Unused identities expire after the bounded idle time.
            cached.last_used_at = now;
            cached.expires_at = now + ttl;
            return Ok(cached.client.clone());
        }

        let mut builder = wreq::Client::builder()
            .no_proxy()
            .redirect(wreq::redirect::Policy::none())
            .connect_timeout(req.connect_timeout)
            .timeout(req.total_timeout)
            .pool_idle_timeout(ttl)
            .pool_max_idle_per_host(MAX_IDLE_CONNECTIONS_PER_HOST)
            .pool_max_size(MAX_CACHED_CLIENTS)
            .emulation(self.emulation);

        #[cfg(test)]
        if let Some(store) = &self.test_cert_store {
            builder = builder.tls_cert_store(store.clone());
        }

        if let Some(proxy_url) = &req.upstream_proxy {
            let proxy = wreq::Proxy::all(proxy_url).map_err(|_| {
                DomainError::new(ErrorCode::ConfigInvalid, "invalid upstream proxy URL")
            })?;
            builder = builder.proxy(proxy);
        } else {
            builder = builder.dns_resolver(resolver);
        }

        builder = match req.protocol {
            ProtocolMode::Auto => builder,
            ProtocolMode::Http1 => builder.http1_only(),
            ProtocolMode::Http2 => builder.http2_only(),
        };
        let client = builder.build().map_err(|error| {
            DomainError::new(
                ErrorCode::ProtocolError,
                format!("transport build: {error}"),
            )
        })?;

        if clients.len() >= MAX_CACHED_CLIENTS {
            if let Some(oldest) = clients
                .iter()
                .min_by_key(|(_, cached)| (cached.last_used_at, cached.created_at))
                .map(|(key, _)| key.clone())
            {
                clients.remove(&oldest);
            }
        }
        clients.insert(
            key,
            CachedClient {
                client: client.clone(),
                created_at: now,
                last_used_at: now,
                expires_at: now + ttl,
            },
        );
        Ok(client)
    }

    async fn execute(
        &self,
        dial: &ValidatedDial,
        req: OutboundRequest,
    ) -> DomainResult<wreq::Response> {
        let client = self.client_for(dial, &req)?;

        let mut request = client
            .request(req.method.clone(), &req.url)
            .default_headers(!req.preserve_identity_headers);
        let body_len = req.body.len();
        let headers = canonical_headers(&req.headers, body_len)?;
        let navigation = preserved_document_navigation(&req, &headers);
        if let Some(order) = measured_navigation_header_order(&req, &headers) {
            request = request.orig_headers(order);
        }
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

        let mut request = request.build().map_err(map_wreq_error)?;
        // Native Chromium sends document HEADERS with weight 256. Keep the
        // previous profile's 220 fallback for other requests; newer upstream
        // profiles default every request to 256. Both share one identity pool.
        request
            .extensions_mut()
            .insert(wreq::http2::StreamDependency::new(
                wreq::http2::StreamId::zero(),
                if navigation { 255 } else { 219 },
                true,
            ));
        client
            .execute(request)
            .await
            .map_err(|error| map_wreq_execute_error(error, req.upstream_proxy.as_deref()))
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
        let response = self.execute(dial, req).await?;
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
            transport_profile: self.profile_name.clone(),
        })
    }

    async fn send_upgrade(
        &self,
        dial: &ValidatedDial,
        mut req: OutboundRequest,
    ) -> DomainResult<OutboundUpgradeResponse> {
        // Traditional browser WebSocket upgrades use HTTP/1.1. Negotiate the
        // corresponding ALPN through the same TLS profile used for HTTPS.
        req.protocol = ProtocolMode::Http1;
        let max_body_bytes = req.max_body_bytes;
        let response = self.execute(dial, req).await?;
        let status = response.status();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
            .collect();
        let (body, body_truncated, upgraded, error) = if status == StatusCode::SWITCHING_PROTOCOLS {
            match response.upgrade().await {
                Ok(socket) => (
                    Bytes::new(),
                    false,
                    Some(Box::new(socket) as Box<dyn TransportSocket>),
                    None,
                ),
                Err(error) => (Bytes::new(), false, None, Some(map_wreq_error(error))),
            }
        } else {
            let stream = Box::pin(
                response
                    .bytes_stream()
                    .map(|chunk| chunk.map_err(map_wreq_error)),
            );
            let (body, truncated, error) =
                collect_stream_body_partial(stream, max_body_bytes).await;
            (body, truncated, None, error)
        };
        Ok(OutboundUpgradeResponse {
            status,
            headers,
            body,
            body_truncated,
            error,
            upgraded,
            transport_provenance: self.provenance(),
            transport_profile: self.profile_name.clone(),
        })
    }

    fn profile_name(&self) -> &str {
        &self.profile_name
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::ProtocolProfileOnly
    }
}

async fn collect_stream_body(
    stream: OutboundByteStream,
    max_body_bytes: u64,
) -> DomainResult<(Bytes, bool)> {
    let (body, truncated, error) = collect_stream_body_partial(stream, max_body_bytes).await;
    if let Some(error) = error {
        return Err(error);
    }
    Ok((body, truncated))
}

async fn collect_stream_body_partial(
    mut stream: OutboundByteStream,
    max_body_bytes: u64,
) -> (Bytes, bool, Option<DomainError>) {
    let cap = usize::try_from(max_body_bytes).unwrap_or(usize::MAX);
    let mut out = BytesMut::with_capacity(cap.min(64 * 1024));
    let mut truncated = false;
    while let Some(next) = stream.next().await {
        let chunk = match next {
            Ok(chunk) => chunk,
            Err(error) => return (out.freeze(), truncated, Some(error)),
        };
        let room = cap.saturating_sub(out.len());
        if chunk.len() > room {
            out.extend_from_slice(&chunk[..room]);
            truncated = true;
            break;
        }
        out.extend_from_slice(&chunk);
        if out.len() == cap {
            // Read one more frame to distinguish an exact-cap body from a
            // truncated stream, retaining partial evidence on read failure.
            if let Some(next) = stream.next().await {
                match next {
                    Ok(chunk) => truncated |= !chunk.is_empty(),
                    Err(error) => return (out.freeze(), truncated, Some(error)),
                }
            }
            break;
        }
    }
    (out.freeze(), truncated, None)
}

fn wreq_error_code(error: &wreq::Error) -> ErrorCode {
    if error.is_timeout() {
        ErrorCode::Timeout
    } else if error.is_connect() {
        ErrorCode::Unavailable
    } else {
        ErrorCode::ProtocolError
    }
}

fn map_wreq_error(error: wreq::Error) -> DomainError {
    let code = wreq_error_code(&error);
    DomainError::new(code, error.without_uri().to_string())
}

pub(crate) const UPSTREAM_PROXY_ERROR_DETAIL: &str = "huntproxy_upstream_proxy_error";

fn map_wreq_execute_error(error: wreq::Error, proxy: Option<&str>) -> DomainError {
    let endpoint = proxy
        .filter(|_| error.is_proxy_connect())
        .and_then(|proxy| url::Url::parse(proxy).ok())
        .and_then(|url| Some((url.host()?.to_string(), url.port_or_known_default()?)));
    let Some((host, port)) = endpoint else {
        return map_wreq_error(error);
    };

    let mut message = format!("upstream proxy {host}:{port} error");
    let mut source = std::error::Error::source(&error);
    let mut os_error = None;
    while let Some(cause) = source {
        if let Some(code) = cause
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
        {
            message.push_str(&format!(": {}", std::io::Error::from_raw_os_error(code)));
            os_error = Some(code);
            break;
        }
        source = cause.source();
    }
    DomainError::with_details(
        wreq_error_code(&error),
        message,
        serde_json::json!({ (UPSTREAM_PROXY_ERROR_DETAIL): { "host": host, "port": port, "os_error": os_error } }),
    )
}

// Measured GET navigation shapes from native Chromium146/149: direct and
// authenticated-proxy navigation, including link/reload with Referer and Cookie.
// This is not recovered incoming wire order; Hyper's HeaderMap cannot supply that.
// Leave requests with other shapes/headers alone until separately measured.
const MEASURED_NAVIGATION_HEADERS: &[&str] = &[
    "Host",
    "Connection",
    "Pragma",
    "Cache-Control",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "Upgrade-Insecure-Requests",
    "User-Agent",
    "Accept",
    "Sec-Fetch-Site",
    "Sec-Fetch-Mode",
    "Sec-Fetch-User",
    "Sec-Fetch-Dest",
    "Referer",
    "Accept-Encoding",
    "Accept-Language",
    "Cookie",
    "Priority",
];

fn preserved_document_navigation(req: &OutboundRequest, headers: &HeaderMap) -> bool {
    req.preserve_identity_headers
        && headers
            .get("sec-fetch-mode")
            .is_some_and(|value| value.as_bytes() == b"navigate")
        && headers
            .get("sec-fetch-dest")
            .is_some_and(|value| value.as_bytes() == b"document")
}

fn measured_navigation_header_order(
    req: &OutboundRequest,
    headers: &HeaderMap,
) -> Option<wreq::header::OrigHeaderMap> {
    if !preserved_document_navigation(req, headers)
        || req.method != Method::GET
        || req.body.len() != 0
    {
        return None;
    }
    if headers.keys().any(|name| {
        !MEASURED_NAVIGATION_HEADERS
            .iter()
            .any(|known| name.as_str().eq_ignore_ascii_case(known))
    }) {
        return None;
    }
    let mut order = wreq::header::OrigHeaderMap::new();
    for &name in MEASURED_NAVIGATION_HEADERS {
        order.insert(name);
    }
    Some(order)
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
    use tokio::io::AsyncWriteExt;

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

    fn cache_request() -> OutboundRequest {
        OutboundRequest {
            identity: TransportIdentity::for_reply(ProjectId(1), &[]),
            method: Method::GET,
            url: "https://cache.test/".into(),
            headers: vec![],
            body: OutboundBody::Empty,
            protocol: ProtocolMode::Auto,
            connect_timeout: Duration::from_secs(2),
            total_timeout: Duration::from_secs(5),
            max_body_bytes: 1024,
            preserve_identity_headers: true,
            upstream_proxy: None,
        }
    }

    fn cache_dial(address: &str, policy_epoch: u64) -> ValidatedDial {
        ValidatedDial {
            hostname: "cache.test".into(),
            port: 443,
            approved_socket_addrs: vec![address.parse().unwrap()],
            policy_epoch,
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
            scheme: "https".into(),
            path: "/".into(),
        }
    }

    #[tokio::test]
    async fn document_and_resource_priorities_share_one_http2_connection() {
        use rustls::pki_types::PrivatePkcs8KeyDer;
        let certificate = rcgen::generate_simple_self_signed(vec!["priority.test".into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let mut tls = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], key.into())
        .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls));
        let mut transport = WreqTransport::new();
        transport.test_cert_store = Some(
            wreq::tls::trust::CertStore::from_der_certs([certificate.cert.der().as_ref()]).unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // Accept exactly one TCP/TLS connection for all five requests.
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let mut preface = [0; 24];
            socket.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            socket
                .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut observed = Vec::new();
            while observed.len() < 5 {
                let mut head = [0; 9];
                socket.read_exact(&mut head).await.unwrap();
                let length =
                    ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
                let mut payload = vec![0; length];
                socket.read_exact(&mut payload).await.unwrap();
                if head[3] == 1 {
                    assert_ne!(head[4] & 0x20, 0, "HEADERS retains priority information");
                    assert_eq!(&payload[..4], &[0x80, 0, 0, 0], "exclusive root dependency");
                    observed.push((
                        u32::from_be_bytes(head[5..9].try_into().unwrap()),
                        payload[4],
                    ));
                    let mut response = vec![0, 0, 1, 1, 5];
                    response.extend_from_slice(&head[5..9]);
                    response.push(0x88); // HPACK :status 200, END_HEADERS | END_STREAM.
                    socket.write_all(&response).await.unwrap();
                }
            }
            observed
        });
        let mut dial = cache_dial(&address.to_string(), 1);
        dial.hostname = "priority.test".into();
        dial.port = address.port();
        for (path, preserved, method, destination) in [
            ("first", true, Method::GET, "document"),
            ("asset", true, Method::GET, "image"),
            ("again", true, Method::GET, "document"),
            ("generated", false, Method::GET, "document"),
            ("post", true, Method::POST, "document"),
        ] {
            let mut request = cache_request();
            request.url = format!("https://priority.test:{}/{path}", address.port());
            request.method = method;
            request.preserve_identity_headers = preserved;
            request.headers = vec![
                ("sec-fetch-mode".into(), b"navigate".to_vec()),
                ("sec-fetch-dest".into(), destination.as_bytes().to_vec()),
                ("priority".into(), b"u=0, i".to_vec()),
            ];
            assert_eq!(
                transport.send(&dial, request).await.unwrap().status,
                StatusCode::OK
            );
        }
        assert_eq!(
            server.await.unwrap(),
            [(1, 255), (3, 219), (5, 255), (7, 219), (9, 255)]
        );
        assert_eq!(transport.clients.lock().len(), 1);
    }

    #[test]
    fn client_cache_reuses_only_the_same_resolution_and_policy() {
        let transport = WreqTransport::new();
        let request = cache_request();
        let first = cache_dial("192.0.2.10:443", 1);
        transport.client_for(&first, &request).unwrap();
        let first_created = transport.clients.lock().values().next().unwrap().created_at;
        transport.client_for(&first, &request).unwrap();
        let clients = transport.clients.lock();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients.values().next().unwrap().created_at, first_created);
        drop(clients);

        let changed_dns = cache_dial("192.0.2.11:443", 1);
        transport.client_for(&changed_dns, &request).unwrap();
        let clients = transport.clients.lock();
        assert_eq!(clients.len(), 1);
        assert_eq!(
            clients.keys().next().unwrap().addresses,
            vec!["192.0.2.11:443".parse().unwrap()]
        );
        drop(clients);

        let changed_policy = cache_dial("192.0.2.11:443", 2);
        transport.client_for(&changed_policy, &request).unwrap();
        let clients = transport.clients.lock();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients.keys().next().unwrap().policy_epoch, 2);
    }

    #[test]
    fn expired_dns_approval_is_never_cached_or_reused() {
        let transport = WreqTransport::new();
        let request = cache_request();
        let current = cache_dial("192.0.2.10:443", 1);
        transport.client_for(&current, &request).unwrap();
        assert_eq!(transport.clients.lock().len(), 1);

        let mut expired = current;
        expired.expires_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let original_created = transport.clients.lock().values().next().unwrap().created_at;
        assert!(transport.client_for(&expired, &request).is_err());
        // A fresh matching approval reuses the same isolated TLS session cache
        // after the previous approval expired, without accepting that old dial.
        let mut fresh = expired;
        fresh.expires_at = time::OffsetDateTime::now_utc() + time::Duration::minutes(1);
        transport.client_for(&fresh, &request).unwrap();
        assert_eq!(
            transport.clients.lock().values().next().unwrap().created_at,
            original_created
        );
    }

    #[test]
    fn transport_identity_separates_projects_captures_and_final_reply_credentials() {
        let first = vec![("Cookie".into(), b"sid=first".to_vec())];
        let same_case = vec![("cookie".into(), b"sid=first".to_vec())];
        let second = vec![("Cookie".into(), b"sid=second".to_vec())];
        let identity = TransportIdentity::for_reply(ProjectId(1), &first);
        assert_eq!(
            identity,
            TransportIdentity::for_reply(ProjectId(1), &same_case)
        );
        assert_ne!(identity, TransportIdentity::for_reply(ProjectId(2), &first));
        assert_ne!(
            identity,
            TransportIdentity::for_reply(ProjectId(1), &second)
        );
        assert_ne!(identity, TransportIdentity::for_reply(ProjectId(1), &[]));
        let transport = WreqTransport::new();
        let dial = cache_dial("192.0.2.10:443", 1);
        let mut request = cache_request();
        request.identity = identity;
        transport.client_for(&dial, &request).unwrap();
        request.identity = TransportIdentity::Capture {
            project_id: ProjectId(1),
            session_id: 1,
        };
        transport.client_for(&dial, &request).unwrap();
        request.identity = TransportIdentity::Browser {
            project_id: ProjectId(1),
            session_id: 1,
        };
        transport.client_for(&dial, &request).unwrap();
        assert_eq!(transport.clients.lock().len(), 3);
        request.url = "https://member:first@cache.test/".into();
        transport.client_for(&dial, &request).unwrap();
        request.url = "https://member:second@cache.test/".into();
        transport.client_for(&dial, &request).unwrap();
        assert_eq!(transport.clients.lock().len(), 5);
        // A changed policy evicts every identity for this origin.
        let changed = cache_dial("192.0.2.10:443", 2);
        transport.client_for(&changed, &request).unwrap();
        assert_eq!(transport.clients.lock().len(), 1);
    }

    #[test]
    fn active_client_lifetime_extends_only_with_matching_fresh_approval_and_cache_is_bounded() {
        let transport = WreqTransport::new();
        let request = cache_request();
        let dial = cache_dial("192.0.2.10:443", 1);
        transport.client_for(&dial, &request).unwrap();
        let original_created = transport.clients.lock().values().next().unwrap().created_at;
        let soon = Instant::now() + Duration::from_secs(1);
        transport
            .clients
            .lock()
            .values_mut()
            .next()
            .unwrap()
            .expires_at = soon;
        transport.client_for(&dial, &request).unwrap();
        let clients = transport.clients.lock();
        let cached = clients.values().next().unwrap();
        assert!(cached.expires_at > soon);
        assert_eq!(cached.created_at, original_created);
        drop(clients);
        for id in 1..=MAX_CACHED_CLIENTS + 2 {
            let mut request = cache_request();
            request.identity = TransportIdentity::Browser {
                project_id: ProjectId(1),
                session_id: id as i64,
            };
            transport.client_for(&dial, &request).unwrap();
        }
        assert_eq!(transport.clients.lock().len(), MAX_CACHED_CLIENTS);
    }

    #[tokio::test]
    async fn distinct_identities_use_distinct_connections_and_resume_their_own_pool() {
        for protocol in [ProtocolMode::Http1, ProtocolMode::Http2] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let mut connection_id = 0;
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    connection_id += 1;
                    tokio::spawn(async move {
                        let service =
                            service_fn(move |_: Request<hyper::body::Incoming>| async move {
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                                    connection_id.to_string(),
                                ))))
                            });
                        if protocol == ProtocolMode::Http2 {
                            let _ = hyper::server::conn::http2::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            )
                            .serve_connection(TokioIo::new(socket), service)
                            .await;
                        } else {
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(socket), service)
                                .await;
                        }
                    });
                }
            });
            let mut dial = cache_dial(&address.to_string(), 1);
            dial.scheme = "http".into();
            dial.port = address.port();
            let transport = WreqTransport::new();
            for (project, browser, expected_connection) in
                [(1, 1, "1"), (1, 2, "2"), (2, 1, "3"), (1, 1, "1")]
            {
                let mut request = cache_request();
                request.url = format!("http://cache.test:{}/", address.port());
                request.protocol = protocol;
                request.identity = TransportIdentity::Browser {
                    project_id: ProjectId(project),
                    session_id: browser,
                };
                assert_eq!(
                    transport.send(&dial, request).await.unwrap().body,
                    expected_connection
                );
            }
            server.abort();
        }
    }

    #[tokio::test]
    async fn tls_session_tickets_resume_only_within_the_same_identity() {
        use rustls::pki_types::PrivatePkcs8KeyDer;
        let certificate = rcgen::generate_simple_self_signed(vec!["tickets.test".into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let mut tls = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], key.into())
        .unwrap();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls));
        let mut transport = WreqTransport::new();
        transport.test_cert_store = Some(
            wreq::tls::trust::CertStore::from_der_certs([certificate.cert.der().as_ref()]).unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            for _ in 0..4 {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                observed_tx
                    .send(socket.get_ref().1.handshake_kind().unwrap())
                    .unwrap();
                let mut raw = Vec::new();
                loop {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).await.unwrap();
                    raw.push(byte[0]);
                    if raw.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
                socket.shutdown().await.unwrap();
            }
        });
        let mut dial = cache_dial(&address.to_string(), 1);
        dial.hostname = "tickets.test".into();
        dial.port = address.port();
        for (browser, expected) in [
            (1, rustls::HandshakeKind::Full),
            (1, rustls::HandshakeKind::Resumed),
            (2, rustls::HandshakeKind::Full),
            (1, rustls::HandshakeKind::Resumed),
        ] {
            let mut request = cache_request();
            request.url = format!("https://tickets.test:{}/", address.port());
            request.protocol = ProtocolMode::Http1;
            request.identity = TransportIdentity::Browser {
                project_id: ProjectId(1),
                session_id: browser,
            };
            assert_eq!(transport.send(&dial, request).await.unwrap().body, "ok");
            assert_eq!(observed_rx.recv().await.unwrap(), expected);
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn raw_document_navigation_header_order_matches_native_chromium() {
        // Captured at owned HTTP/1 origins, directly and through an authenticated
        // CONNECT proxy. Cache headers originate in Playwright proxy credentials;
        // the transport must retain them and order them as the browser does.
        let cases: &[&[&str]] = &[
            &[
                "Host",
                "Connection",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "Upgrade-Insecure-Requests",
                "User-Agent",
                "Accept",
                "Sec-Fetch-Site",
                "Sec-Fetch-Mode",
                "Sec-Fetch-User",
                "Sec-Fetch-Dest",
                "Accept-Encoding",
                "Accept-Language",
            ],
            &[
                "Host",
                "Connection",
                "Pragma",
                "Cache-Control",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "Upgrade-Insecure-Requests",
                "User-Agent",
                "Accept",
                "Sec-Fetch-Site",
                "Sec-Fetch-Mode",
                "Sec-Fetch-User",
                "Sec-Fetch-Dest",
                "Accept-Encoding",
                "Accept-Language",
            ],
            &[
                "Host",
                "Connection",
                "Pragma",
                "Cache-Control",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "Upgrade-Insecure-Requests",
                "User-Agent",
                "Accept",
                "Sec-Fetch-Site",
                "Sec-Fetch-Mode",
                "Sec-Fetch-User",
                "Sec-Fetch-Dest",
                "Referer",
                "Accept-Encoding",
                "Accept-Language",
                "Cookie",
            ],
            &[
                "Host",
                "Connection",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "Upgrade-Insecure-Requests",
                "User-Agent",
                "Accept",
                "Sec-Fetch-Site",
                "Sec-Fetch-Mode",
                "Sec-Fetch-User",
                "Sec-Fetch-Dest",
                "Referer",
                "Accept-Encoding",
                "Accept-Language",
                "Cookie",
            ],
        ];
        for major in [146, 149, 153] {
            for &expected in cases {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let server = tokio::spawn(async move {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut raw = Vec::new();
                    loop {
                        let mut byte = [0];
                        socket.read_exact(&mut byte).await.unwrap();
                        raw.push(byte[0]);
                        if raw.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await
                        .unwrap();
                    String::from_utf8(raw).unwrap()
                });
                let mut dial = cache_dial(&address.to_string(), 1);
                dial.scheme = "http".into();
                dial.port = address.port();
                let mut request = cache_request();
                request.url = format!("http://cache.test:{}/", address.port());
                request.protocol = ProtocolMode::Http1;
                request.headers = expected
                    .iter()
                    .rev()
                    .map(|name| {
                        let name = name.to_ascii_lowercase();
                        let value = match name.as_str() {
                            "host" => format!("cache.test:{}", address.port()).into_bytes(),
                            "sec-fetch-mode" => b"navigate".to_vec(),
                            "sec-fetch-dest" => b"document".to_vec(),
                            "connection" => b"keep-alive".to_vec(),
                            "pragma" | "cache-control" => b"no-cache".to_vec(),
                            "referer" => b"https://localhost/initial".to_vec(),
                            "cookie" => b"visitor=local-visit".to_vec(),
                            _ => b"supplied".to_vec(),
                        };
                        (name, value)
                    })
                    .collect();
                request
                    .headers
                    .push(("Proxy-Authorization".into(), b"Basic local-only".to_vec()));
                request
                    .headers
                    .push(("Proxy-Connection".into(), b"keep-alive".to_vec()));
                WreqTransport::with_chrome_major(major)
                    .unwrap()
                    .send(&dial, request)
                    .await
                    .unwrap();
                let wire = server.await.unwrap();
                let names = wire
                    .lines()
                    .skip(1)
                    .filter_map(|line| line.split_once(':').map(|(name, _)| name.to_string()))
                    .collect::<Vec<_>>();
                assert_eq!(names, expected, "Chrome{major}: {wire}");
                assert!(!wire.contains("local-only"));
                if expected.contains(&"Cache-Control") {
                    assert!(wire.contains("Pragma: no-cache\r\n"));
                    assert!(wire.contains("Cache-Control: no-cache\r\n"));
                }
                if expected.contains(&"Cookie") {
                    assert!(wire.contains("Cookie: visitor=local-visit\r\n"));
                    assert!(wire.contains("Referer: https://localhost/initial\r\n"));
                }
            }
        }
    }

    #[test]
    fn unmeasured_navigation_headers_keep_their_values_without_assuming_native_order() {
        let mut request = cache_request();
        request.headers = vec![
            ("sec-fetch-mode".into(), b"navigate".to_vec()),
            ("sec-fetch-dest".into(), b"document".to_vec()),
            ("cache-control".into(), b"no-cache".to_vec()),
            ("x-visitor-preference".into(), b"comfortable".to_vec()),
        ];
        let headers = canonical_headers(&request.headers, 0).unwrap();
        assert!(measured_navigation_header_order(&request, &headers).is_none());
        assert_eq!(headers["x-visitor-preference"], "comfortable");
        assert_eq!(headers["cache-control"], "no-cache");
    }

    #[tokio::test]
    async fn secure_websocket_upgrade_uses_profiled_tls_and_preserves_nonce_protocol_and_early_frames(
    ) {
        use futures::SinkExt;
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use tokio_tungstenite::tungstenite::protocol::Role;
        use tokio_tungstenite::tungstenite::Message;
        for major in [146, 149, 153] {
            let certificate =
                rcgen::generate_simple_self_signed(vec!["socket.test".into()]).unwrap();
            let key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
            let mut tls = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()], key.into())
            .unwrap();
            tls.alpn_protocols = vec![b"http/1.1".to_vec()];
            let mut transport = WreqTransport::with_chrome_major(major).unwrap();
            transport.test_cert_store = Some(
                wreq::tls::trust::CertStore::from_der_certs([certificate.cert.der().as_ref()])
                    .unwrap(),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let hello = tokio_rustls::LazyConfigAcceptor::new(
                    rustls::server::Acceptor::default(),
                    socket,
                )
                .await
                .unwrap();
                assert_eq!(
                    hello.client_hello().alpn().unwrap().collect::<Vec<_>>(),
                    [b"http/1.1".as_slice()]
                );
                let ciphers = hello
                    .client_hello()
                    .cipher_suites()
                    .iter()
                    .copied()
                    .map(u16::from)
                    .filter(|cipher| !(cipher >> 8 == cipher & 255 && cipher & 0x0f0f == 0x0a0a))
                    .collect::<Vec<_>>();
                assert_eq!(
                    ciphers,
                    [
                        4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172,
                        156, 157, 47, 53
                    ],
                    "cipher order measured from native Chromium146/149"
                );
                let mut socket = hello.into_stream(std::sync::Arc::new(tls)).await.unwrap();
                let mut raw = Vec::new();
                loop {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).await.unwrap();
                    raw.push(byte[0]);
                    if raw.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let wire = String::from_utf8(raw).unwrap();
                assert!(wire.contains("dGhlIHNhbXBsZSBub25jZQ=="));
                // A frame immediately following 101 must survive Wreq's read buffer.
                socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: updates\r\n\r\n\x81\x05hello").await.unwrap();
                let mut socket =
                    tokio_tungstenite::WebSocketStream::from_raw_socket(socket, Role::Server, None)
                        .await;
                assert_eq!(
                    socket.next().await.unwrap().unwrap(),
                    Message::Text("received".into())
                );
            });
            let mut dial = cache_dial(&address.to_string(), 1);
            dial.hostname = "socket.test".into();
            dial.port = address.port();
            let mut request = cache_request();
            request.url = format!("https://socket.test:{}/events", address.port());
            request.headers = vec![
                ("Connection".into(), b"Upgrade".to_vec()),
                ("Upgrade".into(), b"websocket".to_vec()),
                (
                    "Sec-WebSocket-Key".into(),
                    b"dGhlIHNhbXBsZSBub25jZQ==".to_vec(),
                ),
                ("Sec-WebSocket-Version".into(), b"13".to_vec()),
                ("Sec-WebSocket-Protocol".into(), b"updates".to_vec()),
            ];
            let response = transport.send_upgrade(&dial, request).await.unwrap();
            assert_eq!(
                response.transport_profile,
                format!("wreq_chrome{major}_protocol_profile")
            );
            assert_eq!(response.status, StatusCode::SWITCHING_PROTOCOLS);
            assert!(response
                .headers
                .iter()
                .any(|(name, value)| name == "sec-websocket-protocol" && value == b"updates"));
            let mut socket = tokio_tungstenite::WebSocketStream::from_raw_socket(
                response.upgraded.unwrap(),
                Role::Client,
                None,
            )
            .await;
            assert_eq!(
                socket.next().await.unwrap().unwrap(),
                Message::Text("hello".into())
            );
            socket.send(Message::Text("received".into())).await.unwrap();
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn identity_header_preservation_controls_defaults_per_request_on_the_wire() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                observed_tx.send(request.headers().clone()).unwrap();
                async { Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok")))) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        let dial = ValidatedDial {
            hostname: "identity.test".into(),
            port: address.port(),
            approved_socket_addrs: vec![address],
            policy_epoch: 1,
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
            scheme: "http".into(),
            path: "/".into(),
        };
        let request = |preserve_identity_headers, headers| OutboundRequest {
            identity: TransportIdentity::for_reply(ProjectId(1), &[]),
            method: Method::GET,
            url: format!("http://identity.test:{}/", address.port()),
            headers,
            body: OutboundBody::Empty,
            protocol: ProtocolMode::Http1,
            connect_timeout: Duration::from_secs(2),
            total_timeout: Duration::from_secs(2),
            max_body_bytes: 1024,
            preserve_identity_headers,
            upstream_proxy: None,
        };
        let transport = WreqTransport::new();

        let response = transport.send(&dial, request(true, vec![])).await.unwrap();
        assert_eq!(response.transport_profile, transport.profile_name());
        assert_eq!(transport.profile_name(), "wreq_chrome153_protocol_profile");
        let absent = observed_rx.recv().await.unwrap();
        for name in ["user-agent", "accept", "accept-language", "accept-encoding"] {
            assert!(
                !absent.contains_key(name),
                "unexpected default header {name}"
            );
        }
        assert!(!absent.keys().any(|name| name.as_str().starts_with("sec-")));

        let supplied = vec![
            ("User-Agent".into(), b"Chrome/149.0.0.0".to_vec()),
            ("Sec-CH-UA".into(), b"\"Chromium\";v=\"149\"".to_vec()),
            ("Sec-Fetch-Mode".into(), b"cors".to_vec()),
            ("Accept-Language".into(), b"fr-CA,fr;q=0.9".to_vec()),
            ("X-Client-Tag".into(), b"first".to_vec()),
            ("X-Client-Tag".into(), b"second".to_vec()),
        ];
        transport
            .send(&dial, request(true, supplied.clone()))
            .await
            .unwrap();
        let preserved = observed_rx.recv().await.unwrap();
        for (name, value) in &supplied[..4] {
            assert_eq!(preserved.get(name).unwrap().as_bytes(), value);
        }
        assert_eq!(
            preserved.get_all("x-client-tag").iter().collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        for name in [
            "accept",
            "sec-ch-ua-platform",
            "sec-ch-ua-mobile",
            "sec-fetch-site",
            "sec-fetch-dest",
        ] {
            assert!(
                !preserved.contains_key(name),
                "unexpected default header {name}"
            );
        }

        transport.send(&dial, request(false, vec![])).await.unwrap();
        let defaults = observed_rx.recv().await.unwrap();
        for name in [
            "user-agent",
            "accept",
            "accept-language",
            "sec-ch-ua",
            "sec-ch-ua-platform",
            "sec-fetch-mode",
        ] {
            assert!(
                defaults.contains_key(name),
                "missing enabled default header {name}"
            );
        }
        assert!(defaults["user-agent"]
            .to_str()
            .unwrap()
            .contains("Chrome/153."));
        assert!(defaults["sec-ch-ua"]
            .to_str()
            .unwrap()
            .contains("v=\"153\""));
        // Switching the per-request policy must not leave defaults enabled on
        // the pooled client for later browser or Reply requests.
        transport.send(&dial, request(true, vec![])).await.unwrap();
        assert_eq!(observed_rx.recv().await.unwrap(), absent);
        assert_eq!(transport.clients.lock().len(), 1);
        server.abort();
    }

    #[tokio::test]
    async fn protocol_modes_advertise_the_expected_upstream_alpn() {
        for (protocol, expected) in [
            (
                ProtocolMode::Auto,
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            ),
            (ProtocolMode::Http1, vec![b"http/1.1".to_vec()]),
            (ProtocolMode::Http2, vec![b"h2".to_vec()]),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let hello = tokio_rustls::LazyConfigAcceptor::new(
                    rustls::server::Acceptor::default(),
                    stream,
                )
                .await
                .unwrap();
                let client_hello = hello.client_hello();
                let protocols = client_hello
                    .alpn()
                    .unwrap()
                    .map(Vec::from)
                    .collect::<Vec<_>>();
                protocols
            });
            let dial = ValidatedDial {
                hostname: "alpn.test".into(),
                port: address.port(),
                approved_socket_addrs: vec![address],
                policy_epoch: 1,
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
                scheme: "https".into(),
                path: "/".into(),
            };
            let mut request = cache_request();
            request.url = format!("https://alpn.test:{}/", address.port());
            request.protocol = protocol;
            // Only ClientHello is needed; the local peer closes before any
            // certificate or HTTP traffic, without weakening certificate checks.
            assert!(WreqTransport::new().send(&dial, request).await.is_err());
            assert_eq!(server.await.unwrap(), expected, "{protocol:?}");
        }
    }

    #[tokio::test]
    async fn short_lived_pool_reuses_a_live_connection() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = std::sync::Arc::new(AtomicUsize::new(0));
        let requests = std::sync::Arc::new(AtomicUsize::new(0));
        let server_connections = connections.clone();
        let server_requests = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                server_connections.fetch_add(1, Ordering::SeqCst);
                let server_requests = server_requests.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |_: Request<hyper::body::Incoming>| {
                        let server_requests = server_requests.clone();
                        async move {
                            server_requests.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let dial = ValidatedDial {
            hostname: "pool.test".into(),
            port: address.port(),
            approved_socket_addrs: vec![address],
            policy_epoch: 1,
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
            scheme: "http".into(),
            path: "/".into(),
        };
        let request = || OutboundRequest {
            identity: TransportIdentity::for_reply(ProjectId(1), &[]),
            method: Method::GET,
            url: format!("http://pool.test:{}/", address.port()),
            headers: vec![],
            body: OutboundBody::Empty,
            protocol: ProtocolMode::Http1,
            connect_timeout: Duration::from_secs(2),
            total_timeout: Duration::from_secs(2),
            max_body_bytes: 1024,
            preserve_identity_headers: true,
            upstream_proxy: None,
        };
        let transport = WreqTransport::new();
        assert_eq!(transport.send(&dial, request()).await.unwrap().body, "ok");
        assert_eq!(transport.send(&dial, request()).await.unwrap().body, "ok");
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn semantic_request_uses_explicit_http_proxy() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                socket.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nproxied",
                )
                .await
                .unwrap();
            request
        });
        let dial = cache_dial("192.0.2.55:80", 1);
        let response = WreqTransport::new()
            .send(
                &dial,
                OutboundRequest {
                    identity: TransportIdentity::for_reply(ProjectId(1), &[]),
                    method: Method::GET,
                    url: "http://cache.test/proxy-check".into(),
                    headers: vec![],
                    body: OutboundBody::Empty,
                    protocol: ProtocolMode::Http1,
                    connect_timeout: Duration::from_secs(2),
                    total_timeout: Duration::from_secs(2),
                    max_body_bytes: 1024,
                    preserve_identity_headers: true,
                    upstream_proxy: Some(format!("http://{proxy_addr}")),
                },
            )
            .await
            .unwrap();
        assert_eq!(response.body, "proxied");
        let request = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(request.starts_with("GET http://cache.test/proxy-check HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn proxy_connection_errors_show_endpoint_without_credentials() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        drop(listener);
        let expected_cause = std::net::TcpStream::connect(proxy_addr)
            .unwrap_err()
            .to_string();
        let dial = cache_dial("192.0.2.55:443", 1);
        let transport = WreqTransport::new();

        for (proxy_scheme, target_scheme) in [
            ("http", "http"),
            ("http", "https"),
            ("socks5", "https"),
            ("socks5h", "https"),
        ] {
            let mut request = cache_request();
            request.url = format!("{target_scheme}://cache.test/");
            request.upstream_proxy = Some(format!(
                "{proxy_scheme}://privateuser:privatepass@{proxy_addr}"
            ));

            let errors = [
                transport.send(&dial, request.clone()).await.err().unwrap(),
                transport
                    .send_stream(&dial, request.clone())
                    .await
                    .err()
                    .unwrap(),
                transport.send_upgrade(&dial, request).await.err().unwrap(),
            ];
            for error in errors {
                let message = error.to_string();
                assert!(
                    message.contains(&format!("upstream proxy {proxy_addr}")),
                    "{message}"
                );
                assert!(!message.contains("privateuser"), "{message}");
                assert!(!message.contains("privatepass"), "{message}");
                if proxy_scheme == "http" {
                    assert!(message.contains(&expected_cause), "{message}");
                }
                let DomainError::App {
                    details: Some(details),
                    ..
                } = error
                else {
                    panic!("proxy connection error is missing safe endpoint details");
                };
                let detail = &details[UPSTREAM_PROXY_ERROR_DETAIL];
                assert_eq!(detail["host"], "127.0.0.1");
                assert_eq!(detail["port"], proxy_addr.port());
                let serialized = details.to_string();
                assert!(!serialized.contains("privateuser"));
                assert!(!serialized.contains("privatepass"));
            }
        }
    }

    #[tokio::test]
    async fn transport_errors_do_not_expose_credentials_or_query_in_request_uri() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let dial = cache_dial(&address.to_string(), 1);
        let mut request = cache_request();
        request.url =
            "http://fixture-user:fixture-password@cache.test/private?token=fixture-token".into();
        let error = WreqTransport::new()
            .send(&dial, request)
            .await
            .err()
            .unwrap();
        let message = error.to_string();
        for secret in ["fixture-user", "fixture-password", "fixture-token"] {
            assert!(!message.contains(secret), "{message}");
        }
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
                    identity: TransportIdentity::for_reply(ProjectId(1), &[]),
                    method: Method::GET,
                    url: format!("http://profile.test:{}/", addr.port()),
                    headers: vec![],
                    body: OutboundBody::Empty,
                    protocol: ProtocolMode::Http1,
                    connect_timeout: Duration::from_secs(2),
                    total_timeout: Duration::from_secs(2),
                    max_body_bytes: 5,
                    preserve_identity_headers: true,
                    upstream_proxy: None,
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
                    identity: TransportIdentity::for_reply(ProjectId(1), &[]),
                    method: Method::GET,
                    url: format!("http://stream.test:{}/", addr.port()),
                    headers: vec![],
                    body: OutboundBody::Empty,
                    protocol: ProtocolMode::Http1,
                    connect_timeout: Duration::from_secs(2),
                    total_timeout: Duration::from_secs(10),
                    max_body_bytes: 1024,
                    preserve_identity_headers: true,
                    upstream_proxy: None,
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
                    identity: TransportIdentity::for_reply(ProjectId(1), &[]),
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
                    upstream_proxy: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(payload_receiver.await.unwrap(), payload);
        server.await.unwrap();
    }
}
