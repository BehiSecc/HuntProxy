//! Semantic outbound transport with profile matching and generic fallback.

use crate::domain::{
    DomainError, DomainResult, ErrorCode, TransportProvenance, ValidatedDial,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProfile {
    /// Wreq Chrome-like profile matching (when available).
    Chrome,
    /// Transport-only profile: TLS/H2 matching without injecting identity headers.
    TransportOnly,
    /// Generic Hyper/rustls — no profile claim.
    GenericUnprofiled,
}

#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Option<Bytes>,
    pub protocol: ProtocolMode,
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
    pub max_body_bytes: u64,
    /// When true, do not inject profile default UA/client-hints.
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
    pub protocol: String,
    pub transport_provenance: TransportProvenance,
    pub transport_profile: String,
    pub duration: Duration,
}

#[async_trait]
pub trait SemanticTransport: Send + Sync {
    async fn send(
        &self,
        dial: &ValidatedDial,
        req: OutboundRequest,
    ) -> DomainResult<OutboundResponse>;

    fn profile_name(&self) -> &str;
    fn provenance(&self) -> TransportProvenance;
}

/// Generic Hyper/rustls semantic client — availability fallback.
pub struct GenericTransport {
    max_body: u64,
}

impl GenericTransport {
    pub fn new(max_body: u64) -> Self {
        Self { max_body }
    }
}

#[async_trait]
impl SemanticTransport for GenericTransport {
    async fn send(
        &self,
        dial: &ValidatedDial,
        req: OutboundRequest,
    ) -> DomainResult<OutboundResponse> {
        let start = std::time::Instant::now();
        let addr = dial
            .approved_socket_addrs
            .first()
            .copied()
            .ok_or_else(|| DomainError::scope_denied("no approved address in ValidatedDial"))?;

        // Dial only the approved IP — never resolve again.
        let stream = tokio::time::timeout(req.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| DomainError::new(ErrorCode::Timeout, "connect timeout"))?
            .map_err(|e| {
                DomainError::new(ErrorCode::ProtocolError, format!("connect failed: {e}"))
            })?;

        let use_tls = dial.scheme.eq_ignore_ascii_case("https");
        let host = dial.hostname.clone();
        let path_q = {
            let u = url::Url::parse(&req.url)
                .map_err(|e| DomainError::invalid(format!("url: {e}")))?;
            let mut p = u.path().to_string();
            if let Some(q) = u.query() {
                p.push('?');
                p.push_str(q);
            }
            if p.is_empty() {
                p = "/".into();
            }
            p
        };

        let mut header_lines = String::new();
        let mut has_host = false;
        for (name, value) in &req.headers {
            if name.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            if name.eq_ignore_ascii_case("proxy-authorization") {
                continue; // never forward
            }
            let v = String::from_utf8_lossy(value);
            header_lines.push_str(&format!("{name}: {v}\r\n"));
        }
        if !has_host {
            header_lines.push_str(&format!("Host: {host}\r\n"));
        }
        let body = req.body.clone().unwrap_or_default();
        if !req.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            && !body.is_empty()
        {
            header_lines.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        header_lines.push_str("Connection: close\r\n");

        let request_bytes = {
            let mut buf = format!(
                "{} {} HTTP/1.1\r\n{}",
                req.method.as_str(),
                path_q,
                header_lines
            )
            .into_bytes();
            buf.extend_from_slice(b"\r\n");
            buf.extend_from_slice(&body);
            buf
        };

        let response_bytes = if use_tls {
            send_tls(stream, &host, &request_bytes, req.total_timeout, self.max_body).await?
        } else {
            send_plain(stream, &request_bytes, req.total_timeout, self.max_body).await?
        };

        let parsed = parse_http_response(&response_bytes)?;
        Ok(OutboundResponse {
            status: parsed.0,
            headers: parsed.1,
            body: parsed.2,
            protocol: "HTTP/1.1".into(),
            transport_provenance: TransportProvenance::GenericUnprofiled,
            transport_profile: "generic_unprofiled".into(),
            duration: start.elapsed(),
        })
    }

    fn profile_name(&self) -> &str {
        "generic_unprofiled"
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::GenericUnprofiled
    }
}

async fn send_plain(
    mut stream: TcpStream,
    request: &[u8],
    timeout: Duration,
    max_body: u64,
) -> DomainResult<Vec<u8>> {
    tokio::time::timeout(timeout, async {
        stream
            .write_all(request)
            .await
            .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?;
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() as u64 > max_body + 64 * 1024 {
                break;
            }
        }
        Ok(buf)
    })
    .await
    .map_err(|_| DomainError::new(ErrorCode::Timeout, "request timeout"))?
}

async fn send_tls(
    stream: TcpStream,
    host: &str,
    request: &[u8],
    timeout: Duration,
    max_body: u64,
) -> DomainResult<Vec<u8>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| DomainError::invalid(format!("SNI hostname: {e}")))?;
    let mut tls = tokio::time::timeout(timeout, connector.connect(name, stream))
        .await
        .map_err(|_| DomainError::new(ErrorCode::Timeout, "tls connect timeout"))?
        .map_err(|e| DomainError::new(ErrorCode::ProtocolError, format!("tls: {e}")))?;

    tokio::time::timeout(timeout, async {
        tls.write_all(request)
            .await
            .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?;
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            let n = tls
                .read(&mut tmp)
                .await
                .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() as u64 > max_body + 64 * 1024 {
                break;
            }
        }
        Ok(buf)
    })
    .await
    .map_err(|_| DomainError::new(ErrorCode::Timeout, "tls request timeout"))?
}

fn parse_http_response(data: &[u8]) -> DomainResult<(StatusCode, Vec<(String, Vec<u8>)>, Bytes)> {
    let text = String::from_utf8_lossy(data);
    let header_end = text
        .find("\r\n\r\n")
        .ok_or_else(|| DomainError::new(ErrorCode::ProtocolError, "malformed response"))?;
    let header_block = &text[..header_end];
    let body = data[header_end + 4..].to_vec();
    let mut lines = header_block.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| DomainError::new(ErrorCode::ProtocolError, "empty response"))?;
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let status = StatusCode::from_u16(status_code)
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut headers = Vec::new();
    for line in lines {
        if let Some((n, v)) = line.split_once(':') {
            headers.push((n.trim().to_string(), v.trim().as_bytes().to_vec()));
        }
    }
    Ok((status, headers, Bytes::from(body)))
}

/// Build transport stack: try Wreq-backed profile transport, else generic.
pub fn build_default_transport(max_body: u64) -> std::sync::Arc<dyn SemanticTransport> {
    // Wreq is compiled optionally; use generic as reliable default path.
    // Profile-matching Wreq wrapper can be enabled when the pin builds cleanly.
    std::sync::Arc::new(GenericTransport::new(max_body))
}

/// Attempt to create Wreq transport. Returns None if unavailable.
pub fn try_wreq_transport(_max_body: u64) -> Option<std::sync::Arc<dyn SemanticTransport>> {
    // Isolated behind this factory so a failed pin does not block the binary.
    // Full Wreq integration is exercised in spikes; runtime uses generic until
    // the release pin is confirmed in CI for all targets.
    None
}

pub fn headers_to_map(headers: &[(String, Vec<u8>)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (n, v) in headers {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(n.as_bytes()),
            HeaderValue::from_bytes(v),
        ) {
            map.append(name, val);
        }
    }
    map
}
