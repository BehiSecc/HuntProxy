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

const MAX_PAUSE_MS: u64 = 120_000;
const MAX_READ_TIMEOUT_MS: u64 = 120_000;
const MAX_IDLE_TIMEOUT_MS: u64 = 10_000;

#[derive(Debug, Clone, Copy, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RawResponseMode {
    /// Stop after the first complete framed response, preserving prior behavior.
    #[default]
    Auto,
    /// Keep reading responses until the connection is quiet for `idle_timeout_ms`.
    UntilIdle,
    /// Keep reading until the peer closes, the cap is reached, or total timeout expires.
    UntilClose,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct RawHttp1Options {
    /// Split the exact request at this byte offset and pause before writing the remainder.
    pub pause_at_byte: Option<usize>,
    pub pause_ms: Option<u64>,
    pub half_close_write: bool,
    pub response_mode: RawResponseMode,
    pub read_timeout_ms: u64,
    pub idle_timeout_ms: u64,
}

impl Default for RawHttp1Options {
    fn default() -> Self {
        Self {
            pause_at_byte: None,
            pause_ms: None,
            half_close_write: false,
            response_mode: RawResponseMode::Auto,
            read_timeout_ms: 60_000,
            idle_timeout_ms: 1_000,
        }
    }
}

impl RawHttp1Options {
    fn validate(&self, request_len: usize) -> DomainResult<()> {
        match (self.pause_at_byte, self.pause_ms) {
            (None, None) => {}
            (Some(offset), Some(pause_ms)) => {
                if offset == 0 || offset >= request_len {
                    return Err(DomainError::invalid(
                        "pause_at_byte must split the request between its first and last byte",
                    ));
                }
                if pause_ms == 0 || pause_ms > MAX_PAUSE_MS {
                    return Err(DomainError::invalid(
                        "pause_ms must be between 1 and 120000",
                    ));
                }
            }
            _ => {
                return Err(DomainError::invalid(
                    "pause_at_byte and pause_ms must be provided together",
                ));
            }
        }
        if self.read_timeout_ms == 0 || self.read_timeout_ms > MAX_READ_TIMEOUT_MS {
            return Err(DomainError::invalid(
                "read_timeout_ms must be between 1 and 120000",
            ));
        }
        if self.idle_timeout_ms == 0 || self.idle_timeout_ms > MAX_IDLE_TIMEOUT_MS {
            return Err(DomainError::invalid(
                "idle_timeout_ms must be between 1 and 10000",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RawReadOutcome {
    Complete,
    Idle,
    Closed,
    Timeout,
    Limit,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct RawResponseSummary {
    pub status_code: Option<u16>,
    pub offset: usize,
    pub length: usize,
}

trait RawIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RawIo for T {}

/// Result returned by the raw Reply endpoint and MCP tool.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RawReplyResult {
    pub exchange_id: Option<ExchangeId>,
    pub status_code: Option<u16>,
    pub response_bytes: usize,
    pub truncated: bool,
    pub read_outcome: RawReadOutcome,
    pub responses: Vec<RawResponseSummary>,
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
        options: RawHttp1Options,
    ) -> DomainResult<RawReplyResult> {
        let project = self.db.get_project(project_id).await?;
        let target = TargetRef::from_url(target_url)?;
        if request_bytes.is_empty() {
            return Err(DomainError::invalid("raw HTTP/1.1 request cannot be empty"));
        }
        options.validate(request_bytes.len())?;
        if use_project_cookies && options.pause_at_byte.is_some() {
            return Err(DomainError::invalid(
                "split writes cannot be combined with managed cookie injection because injection changes wire byte offsets",
            ));
        }
        if use_project_cookies {
            let profile = self
                .db
                .get_cookie_profile_for_url(project_id, target_url)
                .await?
                .ok_or_else(|| {
                    DomainError::not_found("no managed cookies configured for target host")
                })?;
            let cookie_header = profile.cookie_header_for_url(target_url)?.ok_or_else(|| {
                DomainError::not_found("no managed cookies apply to the target URL")
            })?;
            request_bytes = inject_cookie_header(&request_bytes, &cookie_header)?;
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
        write_raw_request(&mut stream, &request_bytes, &options).await?;

        let response_cap = project.limits.max_body_bytes.saturating_add(64 * 1024);
        let response_to_head = parse_request_method(&request_bytes)
            .is_some_and(|method| method.eq_ignore_ascii_case("HEAD"));
        let read = read_raw_response(&mut stream, response_cap, &options, response_to_head).await?;
        let raw_response = read.bytes;
        let truncated =
            read.outcome == RawReadOutcome::Limit || read.outcome == RawReadOutcome::Timeout;
        let responses = parse_response_summaries_for(&raw_response, response_to_head);
        let parsed = parse_response(&raw_response);
        let method = parse_request_method(&request_bytes).unwrap_or_else(|| "RAW".into());
        let mime = parsed
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-type"))
            .map(|header| String::from_utf8_lossy(&header.value).into_owned());
        let encoded = parsed.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-encoding")
                && !String::from_utf8_lossy(&header.value)
                    .trim()
                    .eq_ignore_ascii_case("identity")
        });
        let page_title = (!encoded && crate::page_title::is_html_mime(mime.as_deref()))
            .then(|| crate::page_title::extract_html_title(&parsed.body))
            .flatten();

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
                        transport_profile: Some("raw_http1_transcript_v2".into()),
                        request_headers: Vec::new(),
                        response_headers: parsed.headers,
                        request_body: Some(request_bytes),
                        response_body: Some(raw_response.clone()),
                        duration_ms: Some(started.elapsed().as_millis() as i64),
                        lineage: ReplySendContext::reply(None, tab_id).lineage,
                        page_title,
                        error_message: truncated.then(|| match read.outcome {
                            RawReadOutcome::Limit => {
                                "raw response transcript truncated by project body limit".into()
                            }
                            _ => "raw response transcript ended at read timeout".into(),
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
            read_outcome: read.outcome,
            responses,
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

async fn write_raw_request(
    stream: &mut Pin<Box<dyn RawIo>>,
    request: &[u8],
    options: &RawHttp1Options,
) -> DomainResult<()> {
    async fn write_part(stream: &mut Pin<Box<dyn RawIo>>, bytes: &[u8]) -> DomainResult<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            stream.write_all(bytes).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| DomainError::new(ErrorCode::Timeout, "raw request write timed out"))?
        .map_err(io_error)
    }

    if let (Some(offset), Some(pause_ms)) = (options.pause_at_byte, options.pause_ms) {
        write_part(stream, &request[..offset]).await?;
        tokio::time::sleep(Duration::from_millis(pause_ms)).await;
        write_part(stream, &request[offset..]).await?;
    } else {
        write_part(stream, request).await?;
    }
    if options.half_close_write {
        tokio::time::timeout(Duration::from_secs(10), stream.shutdown())
            .await
            .map_err(|_| DomainError::new(ErrorCode::Timeout, "raw write shutdown timed out"))?
            .map_err(io_error)?;
    }
    Ok(())
}

struct RawReadResult {
    bytes: Vec<u8>,
    outcome: RawReadOutcome,
}

async fn read_raw_response(
    stream: &mut Pin<Box<dyn RawIo>>,
    cap: u64,
    options: &RawHttp1Options,
    response_to_head: bool,
) -> DomainResult<RawReadResult> {
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(options.read_timeout_ms);
    let mut bytes = Vec::with_capacity(cap.min(64 * 1024));
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if options.response_mode == RawResponseMode::Auto
            && response_is_complete(&bytes, response_to_head)
        {
            return Ok(RawReadResult {
                bytes,
                outcome: RawReadOutcome::Complete,
            });
        }
        if bytes.len() >= cap {
            return Ok(RawReadResult {
                bytes,
                outcome: RawReadOutcome::Limit,
            });
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return if find_header_end(&bytes).is_some() {
                Ok(RawReadResult {
                    bytes,
                    outcome: RawReadOutcome::Timeout,
                })
            } else {
                Err(DomainError::new(
                    ErrorCode::Timeout,
                    "raw response timed out",
                ))
            };
        }
        let read_len = chunk.len().min(cap - bytes.len());
        let at_response_boundary = transcript_ends_at_complete_response(&bytes, response_to_head);
        let read_wait =
            if options.response_mode == RawResponseMode::UntilIdle && at_response_boundary {
                remaining.min(Duration::from_millis(options.idle_timeout_ms))
            } else {
                remaining
            };
        match tokio::time::timeout(read_wait, stream.read(&mut chunk[..read_len])).await {
            Ok(Ok(0)) => {
                return Ok(RawReadResult {
                    bytes,
                    outcome: RawReadOutcome::Closed,
                });
            }
            Ok(Ok(n)) => bytes.extend_from_slice(&chunk[..n]),
            Ok(Err(error)) => return Err(io_error(error)),
            Err(_)
                if options.response_mode == RawResponseMode::UntilIdle && at_response_boundary =>
            {
                return Ok(RawReadResult {
                    bytes,
                    outcome: RawReadOutcome::Idle,
                });
            }
            Err(_) if find_header_end(&bytes).is_some() => {
                return Ok(RawReadResult {
                    bytes,
                    outcome: RawReadOutcome::Timeout,
                });
            }
            Err(_) => {
                return Err(DomainError::new(
                    ErrorCode::Timeout,
                    "raw response timed out",
                ))
            }
        }
    }
}

fn response_is_complete(bytes: &[u8], response_to_head: bool) -> bool {
    response_sequence_length(bytes, response_to_head).is_some_and(|length| bytes.len() >= length)
}

/// Find the end of the first final response, including any preceding interim
/// responses. A 101 response is terminal because the connection has switched
/// protocols and no ordinary final HTTP response follows it.
fn response_sequence_length(bytes: &[u8], response_to_head: bool) -> Option<usize> {
    let mut offset = 0;
    loop {
        let remaining = bytes.get(offset..)?;
        let length = response_message_length(remaining, response_to_head)?;
        if length > remaining.len() {
            return None;
        }
        let status = response_status(remaining);
        offset = offset.checked_add(length)?;
        if !status.is_some_and(|status| (100..200).contains(&status) && status != 101) {
            return Some(offset);
        }
    }
}

fn response_message_length(bytes: &[u8], response_to_head: bool) -> Option<usize> {
    let header_end = find_header_end(bytes)?;
    let header_text = String::from_utf8_lossy(&bytes[..header_end]);
    let status = response_status(bytes);
    if response_to_head
        || status.is_some_and(|status| status < 200 || status == 204 || status == 304)
    {
        return Some(header_end);
    }
    let transfer_encodings = header_values(&header_text, "transfer-encoding");
    if transfer_encodings
        .iter()
        .any(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        return chunked_message_length(&bytes[header_end..]).map(|length| header_end + length);
    }
    // A non-chunked transfer coding is close-delimited. Conflicting or invalid
    // Content-Length values are deliberately treated as ambiguous so Auto mode
    // cannot stop early and discard response evidence.
    if !transfer_encodings.is_empty() {
        return None;
    }
    if let Some(length) = unambiguous_content_length(&header_text) {
        return header_end.checked_add(length);
    }
    None
}

fn chunked_message_length(body: &[u8]) -> Option<usize> {
    let original_len = body.len();
    let mut body = body;
    loop {
        let line_end = find_bytes(body, b"\r\n")?;
        let size_text = String::from_utf8_lossy(&body[..line_end]);
        let size =
            usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16).ok()?;
        body = &body[line_end + 2..];
        if size == 0 {
            // Empty trailer block or one/more trailer lines ending in CRLFCRLF.
            let trailer_length = if body.starts_with(b"\r\n") {
                2
            } else {
                find_bytes(body, b"\r\n\r\n")?.checked_add(4)?
            };
            return Some(original_len - body.len() + trailer_length);
        }
        if body.len() < size + 2 || &body[size..size + 2] != b"\r\n" {
            return None;
        }
        body = &body[size + 2..];
    }
}

fn parse_response_summaries_for(raw: &[u8], response_to_head: bool) -> Vec<RawResponseSummary> {
    let mut summaries = Vec::new();
    let mut offset = 0;
    while raw
        .get(offset..)
        .is_some_and(|bytes| bytes.starts_with(b"HTTP/"))
    {
        let remaining = &raw[offset..];
        let Some(length) = response_message_length(remaining, response_to_head) else {
            break;
        };
        if length > remaining.len() {
            break;
        }
        let status_code = find_header_end(remaining)
            .and_then(|header_end| std::str::from_utf8(&remaining[..header_end]).ok())
            .and_then(|head| head.lines().next())
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok());
        summaries.push(RawResponseSummary {
            status_code,
            offset,
            length,
        });
        offset += length;
    }
    summaries
}

fn transcript_ends_at_complete_response(raw: &[u8], response_to_head: bool) -> bool {
    let summaries = parse_response_summaries_for(raw, response_to_head);
    let Some(last) = summaries.last() else {
        return false;
    };
    last.offset.checked_add(last.length) == Some(raw.len())
        && summaries.iter().any(|summary| {
            summary
                .status_code
                .is_some_and(|status| status >= 200 || status == 101)
        })
}

fn response_status(bytes: &[u8]) -> Option<u16> {
    let header_end = find_header_end(bytes)?;
    std::str::from_utf8(&bytes[..header_end])
        .ok()?
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Return the first response entity for normal presentation. New raw exchanges
/// store the exact response transcript; older exchanges already contain only
/// the entity and therefore pass through unchanged.
pub fn presented_raw_response_body(raw: &[u8]) -> Vec<u8> {
    let raw = first_final_response(raw);
    if !raw.starts_with(b"HTTP/") {
        return raw.to_vec();
    }
    let Some(header_end) = find_header_end(raw) else {
        return raw.to_vec();
    };
    let end = response_message_length(raw, false)
        .unwrap_or(raw.len())
        .min(raw.len());
    raw[header_end..end].to_vec()
}

fn first_final_response(mut raw: &[u8]) -> &[u8] {
    loop {
        if !raw.starts_with(b"HTTP/") {
            return raw;
        }
        let Some(header_end) = find_header_end(raw) else {
            return raw;
        };
        match response_status(raw) {
            Some(status) if (100..200).contains(&status) && status != 101 => {
                raw = &raw[header_end..];
            }
            _ => return raw,
        }
    }
}

struct ParsedResponse {
    status_code: Option<u16>,
    headers: Vec<HeaderEntry>,
    body: Vec<u8>,
}

fn parse_response(raw: &[u8]) -> ParsedResponse {
    let raw = first_final_response(raw);
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
    let message_end = response_message_length(raw, false)
        .unwrap_or(raw.len())
        .min(raw.len());
    ParsedResponse {
        status_code,
        headers,
        body: raw[header_end..message_end].to_vec(),
    }
}

fn parse_request_method(raw: &[u8]) -> Option<String> {
    let line_end = find_bytes(raw, b"\r\n").unwrap_or(raw.len());
    let line = std::str::from_utf8(&raw[..line_end]).ok()?;
    line.split_ascii_whitespace().next().map(str::to_string)
}

fn header_values<'a>(headers: &'a str, wanted: &str) -> Vec<&'a str> {
    headers
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(wanted).then_some(value.trim())
        })
        .collect()
}

fn unambiguous_content_length(headers: &str) -> Option<usize> {
    let values = header_values(headers, "content-length");
    let mut parsed = values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .map(str::parse::<usize>);
    let first = parsed.next()?.ok()?;
    parsed.all(|value| value == Ok(first)).then_some(first)
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
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest",
            false,
        ));
        assert!(!response_is_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ntest",
            false,
        ));
        assert!(response_is_complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n",
            false,
        ));
        assert!(response_is_complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n",
            false,
        ));
        assert!(!response_is_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\ntest",
            false,
        ));
        assert!(response_is_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n",
            true,
        ));
    }

    #[test]
    fn auto_completion_skips_interim_responses() {
        assert!(!response_is_complete(
            b"HTTP/1.1 100 Continue\r\n\r\n",
            false,
        ));
        assert!(response_is_complete(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            false,
        ));
        assert!(response_is_complete(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n",
            false,
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
    fn advanced_options_are_explicit_and_bounded() {
        let request_len = 10;
        assert!(RawHttp1Options::default().validate(request_len).is_ok());
        assert!(RawHttp1Options {
            pause_at_byte: Some(5),
            pause_ms: Some(100),
            ..Default::default()
        }
        .validate(request_len)
        .is_ok());
        assert!(RawHttp1Options {
            pause_at_byte: Some(10),
            pause_ms: Some(100),
            ..Default::default()
        }
        .validate(request_len)
        .is_err());
        assert!(RawHttp1Options {
            pause_at_byte: Some(5),
            pause_ms: None,
            ..Default::default()
        }
        .validate(request_len)
        .is_err());
    }

    #[test]
    fn response_summaries_find_pipelined_messages() {
        let transcript = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 404 Nope\r\nContent-Length: 3\r\n\r\nend";
        let summaries = parse_response_summaries_for(transcript, false);
        assert_eq!(
            summaries
                .iter()
                .map(|summary| summary.status_code)
                .collect::<Vec<_>>(),
            vec![Some(100), Some(200), Some(404)]
        );
        assert_eq!(presented_raw_response_body(transcript), b"ok");
        assert_eq!(presented_raw_response_body(b"legacy body"), b"legacy body");
        assert!(transcript_ends_at_complete_response(transcript, false));
        assert!(!transcript_ends_at_complete_response(
            b"HTTP/1.1 100 Continue\r\n\r\n",
            false,
        ));
        assert!(!transcript_ends_at_complete_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\non",
            false,
        ));
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
        let options = RawHttp1Options {
            read_timeout_ms: 1_000,
            ..Default::default()
        };
        let response = read_raw_response(&mut stream, 1024, &options, false)
            .await
            .unwrap();
        assert_eq!(response.outcome, RawReadOutcome::Complete);
        assert_eq!(parse_response(&response.bytes).body, b"ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn split_write_pauses_at_the_exact_byte_offset() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut first = [0_u8; 3];
            socket.read_exact(&mut first).await.unwrap();
            let started = Instant::now();
            let mut second = [0_u8; 3];
            socket.read_exact(&mut second).await.unwrap();
            (first, second, started.elapsed())
        });
        let mut stream = connect_any(&[address], Duration::from_secs(1))
            .await
            .unwrap();
        write_raw_request(
            &mut stream,
            b"abcdef",
            &RawHttp1Options {
                pause_at_byte: Some(3),
                pause_ms: Some(60),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let (first, second, elapsed) = server.await.unwrap();
        assert_eq!(&first, b"abc");
        assert_eq!(&second, b"def");
        assert!(elapsed >= Duration::from_millis(45));
    }

    #[tokio::test]
    async fn until_idle_collects_multiple_responses_on_one_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            socket.read_exact(&mut request).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            socket
                .write_all(b"HTTP/1.1 201 OK\r\nContent-Length: 3\r\n\r\ntwo")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let mut stream = connect_any(&[address], Duration::from_secs(1))
            .await
            .unwrap();
        stream.write_all(b"test").await.unwrap();
        let result = read_raw_response(
            &mut stream,
            4096,
            &RawHttp1Options {
                response_mode: RawResponseMode::UntilIdle,
                read_timeout_ms: 500,
                idle_timeout_ms: 50,
                ..Default::default()
            },
            false,
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, RawReadOutcome::Idle);
        let summaries = parse_response_summaries_for(&result.bytes, false);
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].status_code, Some(200));
        assert_eq!(summaries[1].status_code, Some(201));
        server.abort();
    }

    #[tokio::test]
    async fn half_close_allows_a_server_to_respond_after_request_eof() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .await
                .unwrap();
            request
        });
        let mut stream = connect_any(&[address], Duration::from_secs(1))
            .await
            .unwrap();
        let options = RawHttp1Options {
            half_close_write: true,
            read_timeout_ms: 1_000,
            ..Default::default()
        };
        write_raw_request(&mut stream, b"request", &options)
            .await
            .unwrap();
        let response = read_raw_response(&mut stream, 1024, &options, false)
            .await
            .unwrap();
        assert_eq!(response.outcome, RawReadOutcome::Complete);
        assert_eq!(server.await.unwrap(), b"request");
    }
}
