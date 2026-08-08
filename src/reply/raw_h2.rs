//! Bounded raw HTTP/2 transport for extension-owned protocol tests.
//!
//! Callers supply the exact ordered HPACK fields, including pseudo headers.
//! HuntProxy owns the connection, validation, response decoding, persistence,
//! and resource limits. This deliberately permits values a semantic HTTP/2
//! client would normalize while keeping arbitrary frame injection out of the
//! plugin runtime.

use super::raw::{connect_target, RawIo};
use super::{ReplySendContext, ReplyService};
use crate::domain::*;
use crate::policy::TargetRef;
use crate::storage::NewExchange;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http2::frame::{Frame, Settings};
use rustls::pki_types::ServerName;
use std::collections::{BTreeMap, HashSet};
use std::pin::Pin;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

const MAX_STREAMS: usize = 100;
const MAX_HEADER_FIELDS: usize = 256;
const MAX_HEADER_NAME_BYTES: usize = 8 * 1024;
const MAX_HEADER_VALUE_BYTES: usize = 64 * 1024;
const MAX_HEADER_BLOCK_BYTES: usize = 1024 * 1024;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_OUTBOUND_BODY_BYTES: usize = 65_535;
const DEFAULT_MAX_FRAME_SIZE: usize = 16_384;
const MAX_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_RESPONSE_WINDOW: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawHttp2Header {
    pub name: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawHttp2Stream {
    pub id: String,
    /// Optional explicit odd client stream ID. When omitted HuntProxy assigns
    /// 1, 3, 5, ... in list order.
    pub stream_id: Option<u32>,
    /// Exact HPACK field order. Pseudo fields are not synthesized or reordered.
    pub headers: Vec<RawHttp2Header>,
    pub body_text: Option<String>,
    pub body_base64: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawHttp2Options {
    pub upstream_proxy: Option<String>,
    pub timeout_ms: Option<u64>,
    /// Flush every stream except the final DATA byte, then write all final
    /// one-byte DATA frames together. This is the HTTP/2 single-packet race
    /// primitive; it never silently degrades to ordinary parallel requests.
    pub final_data_together: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RawHttp2StreamResult {
    pub id: String,
    pub stream_id: u32,
    pub exchange_id: Option<ExchangeId>,
    pub status_code: Option<u16>,
    pub response_length: usize,
    pub reset: Option<String>,
    pub complete: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RawHttp2Result {
    pub streams: Vec<RawHttp2StreamResult>,
    pub negotiated_protocol: String,
    pub single_write_release: bool,
    pub goaway: Option<String>,
    pub timed_out: bool,
}

struct PreparedStream {
    id: String,
    stream_id: u32,
    headers: Vec<RawHttp2Header>,
    body: Vec<u8>,
}

#[derive(Default)]
struct ReceivedStream {
    status: Option<u16>,
    headers: Vec<HeaderEntry>,
    body: Vec<u8>,
    complete: bool,
    truncated: bool,
    reset: Option<String>,
}

impl ReplyService {
    pub async fn send_raw_http2_with_context(
        &self,
        project_id: ProjectId,
        target_url: &str,
        streams: Vec<RawHttp2Stream>,
        options: RawHttp2Options,
        context: ReplySendContext,
    ) -> DomainResult<RawHttp2Result> {
        let project = self.db.get_project(project_id).await?;
        let target = TargetRef::from_url(target_url)?;
        if target.scheme != "https" {
            return Err(DomainError::new(
                ErrorCode::ProtocolIncompatible,
                "raw HTTP/2 requires HTTPS with ALPN h2",
            ));
        }
        let request_cap = usize::try_from(project.limits.max_body_bytes.saturating_add(64 * 1024))
            .unwrap_or(usize::MAX)
            .min(MAX_BODY_BYTES);
        let prepared = prepare_streams(streams, request_cap, options.final_data_together)?;
        let timeout_ms = options
            .timeout_ms
            .unwrap_or(60_000)
            .clamp(1_000, MAX_TIMEOUT_MS);
        let upstream_proxy = self
            .upstream_proxies
            .proxy_for(&target.host, options.upstream_proxy.as_deref())?;
        let mut io = tokio::time::timeout(
            Duration::from_secs(15),
            connect_target(&target, upstream_proxy.as_deref()),
        )
        .await
        .map_err(|_| DomainError::new(ErrorCode::Timeout, "upstream connection timed out"))??;
        io = connect_tls_h2(io, &target.host).await?;

        let started = Instant::now();
        let (prefix, release) = encode_connection(&prepared, options.final_data_together)?;
        write_all_bounded(&mut io, &prefix).await?;
        if !release.is_empty() {
            write_all_bounded(&mut io, &release).await?;
        }

        let expected = prepared
            .iter()
            .map(|stream| stream.stream_id)
            .collect::<HashSet<_>>();
        let response_cap = usize::try_from(project.limits.max_body_bytes.saturating_add(64 * 1024))
            .unwrap_or(usize::MAX)
            .min(MAX_BODY_BYTES);
        let mut received = BTreeMap::<u32, ReceivedStream>::new();
        let mut goaway = None;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let mut timed_out = false;
        let mut codec = http2::Codec::<_, Bytes>::new(io);
        loop {
            if expected.iter().all(|id| {
                received
                    .get(id)
                    .is_some_and(|response| response.complete || response.reset.is_some())
            }) {
                break;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                timed_out = true;
                break;
            }
            let frame = match tokio::time::timeout(remaining, codec.next()).await {
                Ok(Some(Ok(frame))) => frame,
                Ok(Some(Err(error))) => {
                    return Err(DomainError::new(
                        ErrorCode::ProtocolError,
                        format!("HTTP/2 response framing: {error}"),
                    ))
                }
                Ok(None) => break,
                Err(_) => {
                    timed_out = true;
                    break;
                }
            };
            match frame {
                Frame::Settings(settings) if !settings.is_ack() => {
                    codec.send(Settings::ack().into()).await.map_err(|error| {
                        DomainError::new(
                            ErrorCode::ProtocolError,
                            format!("HTTP/2 SETTINGS acknowledgement: {error}"),
                        )
                    })?;
                }
                Frame::Headers(headers) => {
                    let stream_id = u32::from(headers.stream_id());
                    if !expected.contains(&stream_id) {
                        continue;
                    }
                    let end_stream = headers.is_end_stream();
                    let (pseudo, fields) = headers.into_parts();
                    let response = received.entry(stream_id).or_default();
                    response.status = pseudo.status.map(|status| status.as_u16());
                    let mut ordinal = response.headers.len() as u32;
                    for name in fields.keys() {
                        for value in fields.get_all(name) {
                            response.headers.push(HeaderEntry {
                                name: name.as_str().to_string(),
                                value: value.as_bytes().to_vec(),
                                ordinal,
                            });
                            ordinal += 1;
                        }
                    }
                    response.complete |= end_stream;
                }
                Frame::Data(data) => {
                    let stream_id = u32::from(data.stream_id());
                    if !expected.contains(&stream_id) {
                        continue;
                    }
                    let end_stream = data.is_end_stream();
                    let response = received.entry(stream_id).or_default();
                    if response.body.len() < response_cap {
                        let remaining = response_cap - response.body.len();
                        response.truncated |= data.payload().len() > remaining;
                        response.body.extend_from_slice(
                            &data.payload()[..data.payload().len().min(remaining)],
                        );
                    } else if !data.payload().is_empty() {
                        response.truncated = true;
                    }
                    response.complete |= end_stream;
                }
                Frame::Reset(reset) => {
                    let stream_id = u32::from(reset.stream_id());
                    if expected.contains(&stream_id) {
                        received.entry(stream_id).or_default().reset =
                            Some(format!("{:?}", reset.reason()));
                    }
                }
                Frame::GoAway(frame) => {
                    goaway = Some(format!("{:?}", frame.reason()));
                    break;
                }
                _ => {}
            }
        }

        let should_capture = crate::policy::url_is_in_scope(target_url, &project.scope)?;
        let mut results = Vec::with_capacity(prepared.len());
        for stream in prepared {
            let response = received.remove(&stream.stream_id).unwrap_or_default();
            let exchange_id = if should_capture {
                let (method, path, query) = request_metadata(&stream.headers, &target);
                let mime = response
                    .headers
                    .iter()
                    .find(|header| header.name.eq_ignore_ascii_case("content-type"))
                    .map(|header| String::from_utf8_lossy(&header.value).into_owned());
                Some(
                    self.db
                        .insert_exchange(NewExchange {
                            project_id,
                            source: context.source,
                            protocol: "HTTP/2 raw".into(),
                            method,
                            scheme: target.scheme.clone(),
                            authority: target.authority(),
                            host: target.host.clone(),
                            port: target.port,
                            path,
                            query,
                            status_code: response.status,
                            mime,
                            completion: if response.complete && !response.truncated {
                                CompletionState::Complete
                            } else {
                                CompletionState::TruncatedByPolicy
                            },
                            capture_quality: CaptureQuality::WirePreserved,
                            header_representation: HeaderRepresentation::WirePreserved,
                            body_representation: BodyRepresentation::WireEncoded,
                            cache_provenance: CacheProvenance::None,
                            transport_provenance: Some(TransportProvenance::GenericUnprofiled),
                            transport_profile: Some("raw_http2_frames_v1".into()),
                            request_headers: stream
                                .headers
                                .iter()
                                .filter(|header| !header.name.starts_with(':'))
                                .enumerate()
                                .map(|(ordinal, header)| HeaderEntry {
                                    name: header.name.clone(),
                                    value: header.value.as_bytes().to_vec(),
                                    ordinal: ordinal as u32,
                                })
                                .collect(),
                            response_headers: response.headers.clone(),
                            request_body: Some(encode_stream_wire(
                                &stream,
                                options.final_data_together,
                            )?),
                            response_body: Some(response.body.clone()),
                            duration_ms: Some(started.elapsed().as_millis() as i64),
                            lineage: context.lineage.clone(),
                            page_title: None,
                            error_message: response.reset.clone().or_else(|| {
                                (!response.complete).then(|| {
                                    if timed_out {
                                        "raw HTTP/2 response timed out"
                                    } else {
                                        "raw HTTP/2 connection ended before END_STREAM"
                                    }
                                    .to_string()
                                })
                            }),
                        })
                        .await?,
                )
            } else {
                None
            };
            results.push(RawHttp2StreamResult {
                id: stream.id,
                stream_id: stream.stream_id,
                exchange_id,
                status_code: response.status,
                response_length: response.body.len(),
                reset: response.reset,
                complete: response.complete,
                truncated: response.truncated,
            });
        }
        Ok(RawHttp2Result {
            streams: results,
            negotiated_protocol: "h2".into(),
            single_write_release: options.final_data_together,
            goaway,
            timed_out,
        })
    }
}

fn prepare_streams(
    streams: Vec<RawHttp2Stream>,
    request_cap: usize,
    final_data_together: bool,
) -> DomainResult<Vec<PreparedStream>> {
    if streams.is_empty() || streams.len() > MAX_STREAMS {
        return Err(DomainError::new(
            ErrorCode::CombinationLimit,
            "raw HTTP/2 requires 1..=100 streams",
        ));
    }
    if final_data_together && streams.len() < 2 {
        return Err(DomainError::invalid(
            "final_data_together requires at least two streams",
        ));
    }
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    let mut output = Vec::with_capacity(streams.len());
    let mut total_body_bytes = 0usize;
    for (index, stream) in streams.into_iter().enumerate() {
        if stream.id.trim().is_empty() || !names.insert(stream.id.clone()) {
            return Err(DomainError::invalid(
                "raw HTTP/2 stream ids must be non-empty and unique",
            ));
        }
        let stream_id = stream.stream_id.unwrap_or(1 + index as u32 * 2);
        if stream_id == 0 || stream_id % 2 == 0 || stream_id > 0x7fff_ffff || !ids.insert(stream_id)
        {
            return Err(DomainError::invalid(
                "raw HTTP/2 stream_id must be a unique odd 31-bit integer",
            ));
        }
        if stream.headers.is_empty() || stream.headers.len() > MAX_HEADER_FIELDS {
            return Err(DomainError::new(
                ErrorCode::CombinationLimit,
                "raw HTTP/2 requires 1..=256 ordered header fields per stream",
            ));
        }
        for header in &stream.headers {
            if header.name.is_empty() || header.name.len() > MAX_HEADER_NAME_BYTES {
                return Err(DomainError::invalid(
                    "invalid raw HTTP/2 header name length",
                ));
            }
            if header.value.len() > MAX_HEADER_VALUE_BYTES {
                return Err(DomainError::invalid("raw HTTP/2 header value is too large"));
            }
        }
        let has_text = stream.body_text.is_some();
        let has_base64 = stream.body_base64.is_some();
        if has_text && has_base64 {
            return Err(DomainError::invalid(
                "raw HTTP/2 body_text and body_base64 are mutually exclusive",
            ));
        }
        let body = match (stream.body_text, stream.body_base64) {
            (Some(body), None) => body.into_bytes(),
            (None, Some(body)) => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .map_err(|error| {
                        DomainError::invalid(format!("invalid raw HTTP/2 body_base64: {error}"))
                    })?
            }
            (None, None) => Vec::new(),
            _ => unreachable!(),
        };
        if body.len() > request_cap {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                format!("raw HTTP/2 body exceeds {request_cap} byte limit"),
            ));
        }
        total_body_bytes = total_body_bytes.checked_add(body.len()).ok_or_else(|| {
            DomainError::new(ErrorCode::BodyTooLarge, "raw HTTP/2 bodies overflow")
        })?;
        if total_body_bytes > MAX_OUTBOUND_BODY_BYTES {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                "raw HTTP/2 request bodies exceed the initial 65535-byte connection window",
            ));
        }
        if final_data_together && body.is_empty() {
            return Err(DomainError::invalid(
                "final_data_together requires a non-empty body on every stream",
            ));
        }
        output.push(PreparedStream {
            id: stream.id,
            stream_id,
            headers: stream.headers,
            body,
        });
    }
    Ok(output)
}

fn encode_connection(
    streams: &[PreparedStream],
    final_data_together: bool,
) -> DomainResult<(Vec<u8>, Vec<u8>)> {
    let mut prefix = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    // SETTINGS_INITIAL_WINDOW_SIZE, followed by a connection window update.
    append_frame(&mut prefix, 4, 0, 0, &[0, 4, 0x01, 0, 0, 0])?;
    append_frame(
        &mut prefix,
        8,
        0,
        0,
        &(DEFAULT_RESPONSE_WINDOW - 65_535).to_be_bytes(),
    )?;
    let mut release = Vec::new();
    for stream in streams {
        let mut header_block = Vec::new();
        for header in &stream.headers {
            encode_hpack_literal(
                &mut header_block,
                header.name.as_bytes(),
                header.value.as_bytes(),
            )?;
        }
        if header_block.len() > MAX_HEADER_BLOCK_BYTES || header_block.len() > 0x00ff_ffff {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                "raw HTTP/2 HPACK block exceeds 1 MiB",
            ));
        }
        let end_on_headers = stream.body.is_empty();
        append_header_block_frames(&mut prefix, stream.stream_id, &header_block, end_on_headers)?;
        if !stream.body.is_empty() {
            if final_data_together {
                if stream.body.len() > 1 {
                    append_data_frames(
                        &mut prefix,
                        stream.stream_id,
                        &stream.body[..stream.body.len() - 1],
                        false,
                    )?;
                }
                append_frame(
                    &mut release,
                    0,
                    0x1,
                    stream.stream_id,
                    &stream.body[stream.body.len() - 1..],
                )?;
            } else {
                append_data_frames(&mut prefix, stream.stream_id, &stream.body, true)?;
            }
        }
    }
    Ok((prefix, release))
}

fn encode_stream_wire(stream: &PreparedStream, final_data_together: bool) -> DomainResult<Vec<u8>> {
    let mut output = Vec::new();
    let mut header_block = Vec::new();
    for header in &stream.headers {
        encode_hpack_literal(
            &mut header_block,
            header.name.as_bytes(),
            header.value.as_bytes(),
        )?;
    }
    append_header_block_frames(
        &mut output,
        stream.stream_id,
        &header_block,
        stream.body.is_empty(),
    )?;
    if !stream.body.is_empty() {
        if final_data_together && stream.body.len() > 1 {
            append_data_frames(
                &mut output,
                stream.stream_id,
                &stream.body[..stream.body.len() - 1],
                false,
            )?;
            append_frame(
                &mut output,
                0,
                0x1,
                stream.stream_id,
                &stream.body[stream.body.len() - 1..],
            )?;
        } else {
            append_data_frames(&mut output, stream.stream_id, &stream.body, true)?;
        }
    }
    Ok(output)
}

fn append_header_block_frames(
    output: &mut Vec<u8>,
    stream_id: u32,
    header_block: &[u8],
    end_stream: bool,
) -> DomainResult<()> {
    let chunks = header_block
        .chunks(DEFAULT_MAX_FRAME_SIZE)
        .collect::<Vec<_>>();
    for (index, chunk) in chunks.iter().enumerate() {
        let first = index == 0;
        let last = index + 1 == chunks.len();
        let frame_type = if first { 1 } else { 9 };
        let flags = if last { 0x4 } else { 0 } | if first && end_stream { 0x1 } else { 0 };
        append_frame(output, frame_type, flags, stream_id, chunk)?;
    }
    Ok(())
}

fn append_data_frames(
    output: &mut Vec<u8>,
    stream_id: u32,
    body: &[u8],
    end_stream: bool,
) -> DomainResult<()> {
    let chunks = body.chunks(DEFAULT_MAX_FRAME_SIZE).collect::<Vec<_>>();
    for (index, chunk) in chunks.iter().enumerate() {
        let flags = if end_stream && index + 1 == chunks.len() {
            0x1
        } else {
            0
        };
        append_frame(output, 0, flags, stream_id, chunk)?;
    }
    Ok(())
}

fn append_frame(
    output: &mut Vec<u8>,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> DomainResult<()> {
    if payload.len() > 0x00ff_ffff {
        return Err(DomainError::new(
            ErrorCode::BodyTooLarge,
            "HTTP/2 frame is too large",
        ));
    }
    let length = payload.len() as u32;
    output.extend_from_slice(&length.to_be_bytes()[1..]);
    output.push(frame_type);
    output.push(flags);
    output.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    output.extend_from_slice(payload);
    Ok(())
}

fn encode_hpack_literal(output: &mut Vec<u8>, name: &[u8], value: &[u8]) -> DomainResult<()> {
    // Literal header field without indexing, with a literal name. Huffman is
    // intentionally disabled so the provided bytes remain inspectable.
    output.push(0);
    encode_hpack_integer(output, name.len(), 7)?;
    output.extend_from_slice(name);
    encode_hpack_integer(output, value.len(), 7)?;
    output.extend_from_slice(value);
    Ok(())
}

fn encode_hpack_integer(output: &mut Vec<u8>, value: usize, prefix_bits: u8) -> DomainResult<()> {
    let max = (1usize << prefix_bits) - 1;
    if value < max {
        output.push(value as u8);
        return Ok(());
    }
    output.push(max as u8);
    let mut remaining = value - max;
    while remaining >= 128 {
        output.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    output.push(remaining as u8);
    Ok(())
}

async fn write_all_bounded(stream: &mut Pin<Box<dyn RawIo>>, bytes: &[u8]) -> DomainResult<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        stream.write_all(bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| DomainError::new(ErrorCode::Timeout, "raw HTTP/2 write timed out"))?
    .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))
}

async fn connect_tls_h2(
    stream: Pin<Box<dyn RawIo>>,
    host: &str,
) -> DomainResult<Pin<Box<dyn RawIo>>> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
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
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(DomainError::new(
            ErrorCode::ProtocolIncompatible,
            "target did not negotiate HTTP/2",
        ));
    }
    Ok(Box::pin(tls))
}

fn request_metadata(
    headers: &[RawHttp2Header],
    target: &TargetRef,
) -> (String, String, Option<String>) {
    let method = headers
        .iter()
        .find(|header| header.name == ":method")
        .map(|header| header.value.clone())
        .unwrap_or_else(|| "H2".into());
    let raw_path = headers
        .iter()
        .find(|header| header.name == ":path")
        .map(|header| header.value.as_str())
        .unwrap_or(&target.path);
    let (path, query) = raw_path
        .split_once('?')
        .map(|(path, query)| (path.to_string(), Some(query.to_string())))
        .unwrap_or_else(|| (raw_path.to_string(), None));
    (method, path, query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpack_literals_preserve_order_and_crlf_values() {
        let headers = vec![
            RawHttp2Header {
                name: ":method".into(),
                value: "POST".into(),
            },
            RawHttp2Header {
                name: "x-test".into(),
                value: "a\r\nb: c".into(),
            },
            RawHttp2Header {
                name: ":path".into(),
                value: "/first".into(),
            },
            RawHttp2Header {
                name: ":path".into(),
                value: "/second".into(),
            },
        ];
        let prepared = prepare_streams(
            vec![RawHttp2Stream {
                id: "probe".into(),
                stream_id: Some(7),
                headers,
                body_text: Some("x".into()),
                body_base64: None,
            }],
            1024,
            false,
        )
        .unwrap();
        let (wire, release) = encode_connection(&prepared, false).unwrap();
        assert!(release.is_empty());
        assert!(wire.windows(7).any(|value| value == b"a\r\nb: c"));
        assert!(wire.windows(6).any(|value| value == b"/first"));
        assert!(wire.windows(7).any(|value| value == b"/second"));
    }

    #[test]
    fn single_packet_release_contains_only_final_data_frames() {
        let streams = (0..2)
            .map(|index| RawHttp2Stream {
                id: format!("request-{index}"),
                stream_id: None,
                headers: vec![RawHttp2Header {
                    name: ":method".into(),
                    value: "POST".into(),
                }],
                body_text: Some("ab".into()),
                body_base64: None,
            })
            .collect();
        let prepared = prepare_streams(streams, 1024, true).unwrap();
        let (prefix, release) = encode_connection(&prepared, true).unwrap();
        assert!(prefix.windows(1).any(|value| value == b"a"));
        assert_eq!(release.len(), 20);
        assert_eq!(release[3], 0);
        assert_eq!(release[4], 1);
        assert_eq!(release[9], b'b');
        assert_eq!(release[13], 0);
        assert_eq!(release[14], 1);
        assert_eq!(release[19], b'b');
    }

    #[test]
    fn rejects_even_or_duplicate_stream_ids() {
        let result = prepare_streams(
            vec![RawHttp2Stream {
                id: "bad".into(),
                stream_id: Some(2),
                headers: vec![RawHttp2Header {
                    name: ":method".into(),
                    value: "GET".into(),
                }],
                body_text: None,
                body_base64: None,
            }],
            1024,
            false,
        );
        assert!(result.is_err());
    }
}
