//! Explicit raw HTTP/1.1 Reply transport for protocol-level security testing.

use super::{ReplySendContext, ReplyService};
use crate::domain::*;
use crate::policy::TargetRef;
use crate::storage::NewExchange;
use rustls::pki_types::ServerName;
use std::io;
use std::pin::Pin;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

trait RawIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RawIo for T {}

/// Result returned by the raw Reply endpoint and MCP tool.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RawReplyResult {
    pub exchange_id: Option<ExchangeId>,
    pub status_code: Option<u16>,
    pub response_bytes: usize,
    pub truncated: bool,
    /// Full wire response when capture scope excludes this exchange.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_base64: Option<String>,
}

impl ReplyService {
    /// Send `request_bytes` without parsing, normalizing, or adding headers.
    ///
    /// `target_url` selects the TCP/TLS destination only. The complete HTTP/1.1
    /// request, including request line and CRLF framing, comes from the caller.
    pub async fn send_raw_http1(
        &self,
        project_id: ProjectId,
        tab_id: Option<ReplyTabId>,
        target_url: &str,
        mut request_bytes: Vec<u8>,
        use_project_cookies: bool,
    ) -> DomainResult<RawReplyResult> {
        let project = self.db.get_project(project_id).await?;
        let target = TargetRef::from_url(target_url)?;
        if request_bytes.is_empty() {
            return Err(DomainError::invalid("raw HTTP/1.1 request cannot be empty"));
        }
        if use_project_cookies {
            let profile = self
                .db
                .get_cookie_profile_for_url(project_id, target_url)
                .await?
                .ok_or_else(|| {
                    DomainError::not_found("no managed cookies configured for target host")
                })?;
            request_bytes = inject_cookie_header(&request_bytes, &profile.cookie_header)?;
        }
        let request_cap = project.limits.max_body_bytes.saturating_add(64 * 1024);
        if request_bytes.len() as u64 > request_cap {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                format!("raw request exceeds {request_cap} byte limit"),
            ));
        }

        // Raw Reply is an explicit egress feature. Project scope determines
        // capture/storage, never which destination the operator may contact.
        let addresses = tokio::net::lookup_host((target.host.as_str(), target.port))
            .await
            .map_err(|error| {
                DomainError::new(
                    ErrorCode::Unavailable,
                    format!("DNS failed for {}: {error}", target.host),
                )
            })?
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "DNS returned no addresses",
            ));
        }

        let started = Instant::now();
        let mut stream = connect_any(&addresses, Duration::from_secs(10)).await?;
        if target.scheme == "https" {
            stream = connect_tls(stream, &target.host).await?;
        }
        stream.write_all(&request_bytes).await.map_err(io_error)?;
        stream.flush().await.map_err(io_error)?;

        let response_cap = project.limits.max_body_bytes.saturating_add(64 * 1024);
        let (raw_response, truncated) =
            read_raw_response(&mut stream, response_cap, Duration::from_secs(60)).await?;
        let parsed = parse_response(&raw_response);
        let method = parse_request_method(&request_bytes).unwrap_or_else(|| "RAW".into());
        let mime = parsed
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-type"))
            .map(|header| String::from_utf8_lossy(&header.value).into_owned());

        // Scope is capture-only: the request was already sent regardless. An
        // out-of-scope response is returned to the caller but is not persisted.
        let should_capture = crate::policy::url_is_in_scope(target_url, &project.scope)?;
        let exchange_id = if should_capture {
            // Store the exact caller-provided request bytes as the request evidence
            // body. This preserves deliberately malformed lines and duplicate CRLFs.
            Some(
                self.db
                    .insert_exchange(NewExchange {
                        project_id,
                        source: ExchangeSource::Reply,
                        protocol: "HTTP/1.1 raw".into(),
                        method,
                        scheme: target.scheme.clone(),
                        authority: target.authority(),
                        host: target.host.clone(),
                        port: target.port,
                        path: target.path.clone(),
                        query: target.query.clone(),
                        status_code: parsed.status_code,
                        mime,
                        completion: if truncated {
                            CompletionState::TruncatedByPolicy
                        } else {
                            CompletionState::Complete
                        },
                        capture_quality: CaptureQuality::WirePreserved,
                        header_representation: HeaderRepresentation::WirePreserved,
                        body_representation: BodyRepresentation::WireEncoded,
                        cache_provenance: CacheProvenance::None,
                        transport_provenance: Some(TransportProvenance::GenericUnprofiled),
                        transport_profile: Some("raw_http1".into()),
                        request_headers: Vec::new(),
                        response_headers: parsed.headers,
                        request_body: Some(request_bytes),
                        response_body: Some(parsed.body),
                        duration_ms: Some(started.elapsed().as_millis() as i64),
                        lineage: ReplySendContext::reply(None, tab_id).lineage,
                        page_title: None,
                        error_message: truncated.then(|| {
                            "raw response truncated by project body limit or read timeout".into()
                        }),
                    })
                    .await?,
            )
        } else {
            None
        };

        if let Some(exchange_id) = exchange_id {
            let _ = self
                .db
                .audit(
                    Some(project_id),
                    "reply_send_raw",
                    Some("reply"),
                    Some("exchange"),
                    Some(&exchange_id.to_string()),
                    serde_json::json!({ "target_url": target_url }),
                )
                .await;
        }

        Ok(RawReplyResult {
            exchange_id,
            status_code: parsed.status_code,
            response_bytes: raw_response.len(),
            truncated,
            response_base64: (!should_capture).then(|| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&raw_response)
            }),
        })
    }
}

async fn connect_any(
    addresses: &[std::net::SocketAddr],
    timeout: Duration,
) -> DomainResult<Pin<Box<dyn RawIo>>> {
    let mut last_error = None;
    for address in addresses {
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(Box::pin(stream)),
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some(format!("connect to {address} timed out")),
        }
    }
    Err(DomainError::new(
        ErrorCode::Unavailable,
        last_error.unwrap_or_else(|| "connection failed".into()),
    ))
}

async fn connect_tls(stream: Pin<Box<dyn RawIo>>, host: &str) -> DomainResult<Pin<Box<dyn RawIo>>> {
    let config = raw_tls_client_config()?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| DomainError::invalid(format!("invalid TLS server name: {host}")))?;
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| DomainError::new(ErrorCode::Timeout, "TLS handshake timed out"))?
    .map_err(|error| {
        DomainError::new(ErrorCode::ProtocolError, format!("TLS handshake: {error}"))
    })?;
    Ok(Box::pin(tls))
}

fn raw_tls_client_config() -> DomainResult<rustls::ClientConfig> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))
    .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

fn io_error(error: io::Error) -> DomainError {
    DomainError::new(ErrorCode::ProtocolError, error.to_string())
}

async fn read_raw_response(
    stream: &mut Pin<Box<dyn RawIo>>,
    cap: u64,
    total_timeout: Duration,
) -> DomainResult<(Vec<u8>, bool)> {
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    let deadline = tokio::time::Instant::now() + total_timeout;
    let mut bytes = Vec::with_capacity(cap.min(64 * 1024));
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if response_is_complete(&bytes) {
            return Ok((bytes, false));
        }
        if bytes.len() >= cap {
            return Ok((bytes, true));
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return if find_header_end(&bytes).is_some() {
                Ok((bytes, true))
            } else {
                Err(DomainError::new(
                    ErrorCode::Timeout,
                    "raw response timed out",
                ))
            };
        }
        let read_len = chunk.len().min(cap - bytes.len());
        match tokio::time::timeout(remaining, stream.read(&mut chunk[..read_len])).await {
            Ok(Ok(0)) => return Ok((bytes, false)),
            Ok(Ok(n)) => bytes.extend_from_slice(&chunk[..n]),
            Ok(Err(error)) => return Err(io_error(error)),
            Err(_) if find_header_end(&bytes).is_some() => return Ok((bytes, true)),
            Err(_) => {
                return Err(DomainError::new(
                    ErrorCode::Timeout,
                    "raw response timed out",
                ))
            }
        }
    }
}

fn response_is_complete(bytes: &[u8]) -> bool {
    let Some(header_end) = find_header_end(bytes) else {
        return false;
    };
    let header_text = String::from_utf8_lossy(&bytes[..header_end]);
    let status = header_text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok());
    if status.is_some_and(|status| status < 200 || status == 204 || status == 304) {
        return true;
    }
    if let Some(length) = header_value(&header_text, "content-length")
        .and_then(|value| value.trim().parse::<usize>().ok())
    {
        return bytes.len().saturating_sub(header_end) >= length;
    }
    if header_value(&header_text, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        return chunked_complete(&bytes[header_end..]);
    }
    false
}

fn chunked_complete(mut body: &[u8]) -> bool {
    loop {
        let Some(line_end) = find_bytes(body, b"\r\n") else {
            return false;
        };
        let size_text = String::from_utf8_lossy(&body[..line_end]);
        let Some(size) =
            usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16).ok()
        else {
            return false;
        };
        body = &body[line_end + 2..];
        if size == 0 {
            // Empty trailer block or one/more trailer lines ending in CRLFCRLF.
            return body.starts_with(b"\r\n") || find_bytes(body, b"\r\n\r\n").is_some();
        }
        if body.len() < size + 2 || &body[size..size + 2] != b"\r\n" {
            return false;
        }
        body = &body[size + 2..];
    }
}

struct ParsedResponse {
    status_code: Option<u16>,
    headers: Vec<HeaderEntry>,
    body: Vec<u8>,
}

fn parse_response(raw: &[u8]) -> ParsedResponse {
    let Some(header_end) = find_header_end(raw) else {
        return ParsedResponse {
            status_code: None,
            headers: Vec::new(),
            body: raw.to_vec(),
        };
    };
    let head = String::from_utf8_lossy(&raw[..header_end - 4]);
    let mut lines = head.split("\r\n");
    let status_code = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok());
    let headers = lines
        .enumerate()
        .filter_map(|(ordinal, line)| {
            let (name, value) = line.split_once(':')?;
            Some(HeaderEntry {
                name: name.trim().to_string(),
                value: value.trim_start().as_bytes().to_vec(),
                ordinal: ordinal as u32,
            })
        })
        .collect();
    ParsedResponse {
        status_code,
        headers,
        body: raw[header_end..].to_vec(),
    }
}

fn parse_request_method(raw: &[u8]) -> Option<String> {
    let line_end = find_bytes(raw, b"\r\n").unwrap_or(raw.len());
    let line = std::str::from_utf8(&raw[..line_end]).ok()?;
    line.split_ascii_whitespace().next().map(str::to_string)
}

fn header_value<'a>(headers: &'a str, wanted: &str) -> Option<&'a str> {
    headers.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(wanted).then_some(value.trim())
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    find_bytes(bytes, b"\r\n\r\n").map(|index| index + 4)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Replace or add a Cookie header in a conventional CRLF-framed raw request.
/// This is used only when the caller explicitly opts into managed cookies.
pub fn inject_cookie_header(request: &[u8], cookie_value: &str) -> DomainResult<Vec<u8>> {
    let header_end = find_header_end(request).ok_or_else(|| {
        DomainError::invalid("managed cookie injection requires a CRLF-framed header block")
    })?;
    let head = &request[..header_end - 4];
    let body = &request[header_end..];
    let lines = head.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    if lines.is_empty() || lines[0].strip_suffix(b"\r").is_none() {
        return Err(DomainError::invalid("invalid raw HTTP/1.1 request line"));
    }
    let line_count = lines.len();
    let mut output = Vec::with_capacity(request.len() + cookie_value.len() + 12);
    output.extend_from_slice(lines[0]);
    output.push(b'\n');
    let mut replaced = false;
    for (index, line) in lines.into_iter().enumerate().skip(1) {
        let line_without_cr = if index + 1 < line_count {
            line.strip_suffix(b"\r").ok_or_else(|| {
                DomainError::invalid("managed cookie injection requires CRLF header lines")
            })?
        } else {
            line
        };
        if line_without_cr.starts_with(b" ") || line_without_cr.starts_with(b"\t") {
            return Err(DomainError::invalid(
                "managed cookie injection requires ordinary HTTP header lines",
            ));
        }
        let colon = line_without_cr
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| DomainError::invalid("raw header line is missing ':'"))?;
        let name = &line_without_cr[..colon];
        if name.eq_ignore_ascii_case(b"cookie") {
            if !replaced {
                output.extend_from_slice(name);
                output.extend_from_slice(b": ");
                output.extend_from_slice(cookie_value.as_bytes());
                output.extend_from_slice(b"\r\n");
                replaced = true;
            }
        } else {
            output.extend_from_slice(line_without_cr);
            output.extend_from_slice(b"\r\n");
        }
    }
    if !replaced {
        output.extend_from_slice(b"Cookie: ");
        output.extend_from_slice(cookie_value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(body);
    Ok(output)
}

/// Best-effort presentation redaction for raw HTTP requests stored as bodies.
pub fn redact_raw_request_headers(request: &[u8]) -> Vec<u8> {
    let (head_end, body_start) = if let Some(index) = find_bytes(request, b"\r\n\r\n") {
        (index, index + 4)
    } else if let Some(index) = find_bytes(request, b"\n\n") {
        (index, index + 2)
    } else {
        (request.len(), request.len())
    };
    let mut output = Vec::with_capacity(request.len());
    let head = &request[..head_end];
    for (index, line) in head.split(|byte| *byte == b'\n').enumerate() {
        if index > 0 {
            output.push(b'\n');
        }
        let line_without_cr = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line_without_cr.iter().position(|byte| *byte == b':') else {
            output.extend_from_slice(line);
            continue;
        };
        let name = &line_without_cr[..colon];
        let sensitive = std::str::from_utf8(name)
            .ok()
            .is_some_and(crate::policy::is_sensitive_header);
        if sensitive {
            output.extend_from_slice(name);
            output.extend_from_slice(b": <redacted>");
            if line.ends_with(b"\r") {
                output.push(b'\r');
            }
        } else {
            output.extend_from_slice(line);
        }
    }
    output.extend_from_slice(&request[head_end..body_start]);
    output.extend_from_slice(&request[body_start..]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_content_length_and_chunked_completion() {
        raw_tls_client_config().unwrap();
        assert!(response_is_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest"
        ));
        assert!(!response_is_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ntest"
        ));
        assert!(response_is_complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n"
        ));
    }

    #[test]
    fn response_parser_preserves_duplicate_headers_and_body() {
        let parsed = parse_response(
            b"HTTP/1.1 201 Created\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nbody",
        );
        assert_eq!(parsed.status_code, Some(201));
        assert_eq!(parsed.headers.len(), 2);
        assert_eq!(parsed.body, b"body");
    }

    #[test]
    fn managed_cookie_injection_replaces_cookie_and_preserves_body() {
        let request =
            b"POST / HTTP/1.1\r\nHost: example.com\r\nCookie: old=1\r\nX-Test: yes\r\n\r\nbody";
        let injected = inject_cookie_header(request, "sid=a==; theme=dark").unwrap();
        assert_eq!(
            injected,
            b"POST / HTTP/1.1\r\nHost: example.com\r\nCookie: sid=a==; theme=dark\r\nX-Test: yes\r\n\r\nbody"
        );
        let presented = redact_raw_request_headers(&injected);
        assert!(!String::from_utf8_lossy(&presented).contains("a=="));
        assert!(String::from_utf8_lossy(&presented).contains("Cookie: <redacted>"));
        assert_eq!(
            redact_raw_request_headers(b"GET / HTTP/1.1\nCookie: secret"),
            b"GET / HTTP/1.1\nCookie: <redacted>"
        );

        let added = inject_cookie_header(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "sid=managed",
        )
        .unwrap();
        assert_eq!(
            added,
            b"GET / HTTP/1.1\r\nHost: example.com\r\nCookie: sid=managed\r\n\r\n"
        );
        assert!(inject_cookie_header(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n folded\r\n\r\n",
            "sid=managed"
        )
        .is_err());
    }

    #[tokio::test]
    async fn raw_socket_preserves_crlf_bytes_exactly() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let expected =
            b"GET / HTTP/1.1\r\nHost: local\r\nX-Test: first\r\n injected\r\n\r\n".to_vec();
        let server_expected = expected.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = vec![0; server_expected.len()];
            socket.read_exact(&mut received).await.unwrap();
            assert_eq!(received, server_expected);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let mut stream = connect_any(&[address], Duration::from_secs(1))
            .await
            .unwrap();
        stream.write_all(&expected).await.unwrap();
        let (response, truncated) = read_raw_response(&mut stream, 1024, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(!truncated);
        assert_eq!(parse_response(&response).body, b"ok");
        server.await.unwrap();
    }
}
