//! Safe, bounded comparison of saved HTTP exchanges.
//!
//! Raw evidence is used to detect changes, but sensitive header values are
//! never included in the returned comparison.

use crate::codec::decode_content_encodings;
use crate::domain::{
    BodyRepresentation, CompletionState, DomainResult, ExchangeId, ExchangeSummary, HeaderEntry,
    MessageSide, ProjectId,
};
use crate::policy::{is_noisy_header, is_sensitive_header, REDACTED_PLACEHOLDER};
use crate::storage::Db;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_COMPARE_TEXT_BYTES: usize = 64 * 1024;
const MAX_DIFF_LINES: usize = 400;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompareOptions {
    /// Noisy browser headers are excluded unless explicitly requested.
    #[serde(default)]
    pub include_noisy_headers: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueChange<T> {
    pub left: T,
    pub right: T,
    pub changed: bool,
}

impl<T: PartialEq> ValueChange<T> {
    fn new(left: T, right: T) -> Self {
        let changed = left != right;
        Self {
            left,
            right,
            changed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderChange {
    /// Lowercase name used to coalesce case-insensitive duplicate fields.
    pub name: String,
    pub kind: HeaderChangeKind,
    pub sensitive: bool,
    pub left_count: usize,
    pub right_count: usize,
    /// Values remain in wire ordinal order. Sensitive values are replaced.
    pub left_values: Vec<String>,
    pub right_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderComparison {
    pub changes: Vec<HeaderChange>,
    pub noisy_hidden: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyWarning {
    LeftMissing,
    RightMissing,
    LeftUnavailable,
    RightUnavailable,
    LeftBinary,
    RightBinary,
    LeftTruncated,
    RightTruncated,
    LeftDecodeFailed,
    RightDecodeFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyEvidence {
    pub present: bool,
    pub length: Option<u64>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyComparison {
    pub left: BodyEvidence,
    pub right: BodyEvidence,
    pub equal: Option<bool>,
    /// A bounded, line-oriented diff of decoded UTF-8 text.
    pub text_diff: Option<String>,
    pub warnings: Vec<BodyWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestComparison {
    pub method: ValueChange<String>,
    pub url: ValueChange<String>,
    pub headers: HeaderComparison,
    pub body: BodyComparison,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseComparison {
    pub status: ValueChange<Option<u16>>,
    pub mime: ValueChange<Option<String>>,
    pub duration_ms: ValueChange<Option<i64>>,
    pub headers: HeaderComparison,
    pub body: BodyComparison,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeComparison {
    pub left_exchange_id: ExchangeId,
    pub right_exchange_id: ExchangeId,
    pub request: RequestComparison,
    pub response: ResponseComparison,
}

#[derive(Debug, Clone)]
pub struct CompareExchange {
    pub summary: ExchangeSummary,
    pub body_representation: BodyRepresentation,
    pub request_headers: Vec<HeaderEntry>,
    pub response_headers: Vec<HeaderEntry>,
    pub request_body: Option<Vec<u8>>,
    pub response_body: Option<Vec<u8>>,
}

/// Compare two saved exchanges. This is the service entry point for API, MCP,
/// or UI adapters; it intentionally returns no raw sensitive header values.
pub async fn compare_saved_exchanges(
    db: &Db,
    project_id: ProjectId,
    left_id: ExchangeId,
    right_id: ExchangeId,
    options: CompareOptions,
) -> DomainResult<ExchangeComparison> {
    let left = load_exchange(db, project_id, left_id).await?;
    let right = load_exchange(db, project_id, right_id).await?;
    Ok(compare_exchange_data(&left, &right, &options))
}

async fn load_exchange(
    db: &Db,
    project_id: ProjectId,
    exchange_id: ExchangeId,
) -> DomainResult<CompareExchange> {
    let detail = db
        .get_exchange_detail(project_id, exchange_id, Default::default())
        .await?;
    let request_headers = db
        .load_raw_headers(project_id, exchange_id, MessageSide::Request)
        .await?;
    let response_headers = db
        .load_raw_headers(project_id, exchange_id, MessageSide::Response)
        .await?;
    let request_body = db
        .load_raw_body(project_id, exchange_id, MessageSide::Request)
        .await?;
    let response_body = db
        .load_raw_body(project_id, exchange_id, MessageSide::Response)
        .await?;
    Ok(CompareExchange {
        summary: detail.summary,
        body_representation: detail.body_representation,
        request_headers,
        response_headers,
        request_body,
        response_body,
    })
}

/// Pure comparison entry point, primarily useful to callers with ephemeral
/// exchanges and to focused tests.
pub fn compare_exchange_data(
    left: &CompareExchange,
    right: &CompareExchange,
    options: &CompareOptions,
) -> ExchangeComparison {
    let left_request_mime = header_value(&left.request_headers, "content-type");
    let right_request_mime = header_value(&right.request_headers, "content-type");
    // Browser-observed bodies are already decoded even if the observed
    // response headers still contain Content-Encoding.
    let left_response_encoding = (left.body_representation != BodyRepresentation::BrowserDecoded)
        .then(|| header_value(&left.response_headers, "content-encoding"))
        .flatten();
    let right_response_encoding = (right.body_representation != BodyRepresentation::BrowserDecoded)
        .then(|| header_value(&right.response_headers, "content-encoding"))
        .flatten();

    ExchangeComparison {
        left_exchange_id: left.summary.exchange_id,
        right_exchange_id: right.summary.exchange_id,
        request: RequestComparison {
            method: ValueChange::new(left.summary.method.clone(), right.summary.method.clone()),
            url: ValueChange::new(exchange_url(&left.summary), exchange_url(&right.summary)),
            headers: compare_headers(
                &left.request_headers,
                &right.request_headers,
                options.include_noisy_headers,
            ),
            body: compare_bodies(
                &left.request_body,
                &right.request_body,
                left.summary.request_length,
                right.summary.request_length,
                left_request_mime.as_deref(),
                right_request_mime.as_deref(),
                None,
                None,
                left.body_representation == BodyRepresentation::Unavailable,
                right.body_representation == BodyRepresentation::Unavailable,
                false,
                false,
            ),
        },
        response: ResponseComparison {
            status: ValueChange::new(left.summary.status_code, right.summary.status_code),
            mime: ValueChange::new(left.summary.mime.clone(), right.summary.mime.clone()),
            duration_ms: ValueChange::new(left.summary.duration_ms, right.summary.duration_ms),
            headers: compare_headers(
                &left.response_headers,
                &right.response_headers,
                options.include_noisy_headers,
            ),
            body: compare_bodies(
                &left.response_body,
                &right.response_body,
                left.summary.response_length,
                right.summary.response_length,
                left.summary.mime.as_deref(),
                right.summary.mime.as_deref(),
                left_response_encoding.as_deref(),
                right_response_encoding.as_deref(),
                left.body_representation == BodyRepresentation::Unavailable,
                right.body_representation == BodyRepresentation::Unavailable,
                left.summary.completion == CompletionState::TruncatedByPolicy,
                right.summary.completion == CompletionState::TruncatedByPolicy,
            ),
        },
    }
}

fn exchange_url(summary: &ExchangeSummary) -> String {
    let query = summary
        .query
        .as_deref()
        .filter(|query| !query.is_empty())
        .map(|query| format!("?{query}"))
        .unwrap_or_default();
    format!(
        "{}://{}{}{}",
        summary.scheme, summary.authority, summary.path, query
    )
}

fn header_value(headers: &[HeaderEntry], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| String::from_utf8_lossy(&header.value).into_owned())
}

fn compare_headers(
    left: &[HeaderEntry],
    right: &[HeaderEntry],
    include_noisy: bool,
) -> HeaderComparison {
    let left = grouped_headers(left);
    let right = grouped_headers(right);
    let names = left
        .keys()
        .chain(right.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut changes = Vec::new();
    let mut noisy_hidden = 0;

    for name in names {
        let left_values = left.get(&name).cloned().unwrap_or_default();
        let right_values = right.get(&name).cloned().unwrap_or_default();
        if left_values == right_values {
            continue;
        }
        if is_noisy_header(&name) && !include_noisy {
            noisy_hidden += 1;
            continue;
        }
        let kind = if left_values.is_empty() {
            HeaderChangeKind::Added
        } else if right_values.is_empty() {
            HeaderChangeKind::Removed
        } else {
            HeaderChangeKind::Changed
        };
        let sensitive = is_sensitive_header(&name);
        changes.push(HeaderChange {
            name,
            kind,
            sensitive,
            left_count: left_values.len(),
            right_count: right_values.len(),
            left_values: presented_values(&left_values, sensitive),
            right_values: presented_values(&right_values, sensitive),
        });
    }
    HeaderComparison {
        changes,
        noisy_hidden,
    }
}

fn grouped_headers(headers: &[HeaderEntry]) -> BTreeMap<String, Vec<Vec<u8>>> {
    let mut ordered = headers.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|header| header.ordinal);
    let mut grouped = BTreeMap::<String, Vec<Vec<u8>>>::new();
    for header in ordered {
        grouped
            .entry(header.name.to_ascii_lowercase())
            .or_default()
            .push(header.value.clone());
    }
    grouped
}

fn presented_values(values: &[Vec<u8>], sensitive: bool) -> Vec<String> {
    if sensitive {
        return vec![REDACTED_PLACEHOLDER.to_string(); values.len()];
    }
    values
        .iter()
        .map(|value| String::from_utf8_lossy(value).into_owned())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn compare_bodies(
    left: &Option<Vec<u8>>,
    right: &Option<Vec<u8>>,
    left_recorded_length: Option<i64>,
    right_recorded_length: Option<i64>,
    left_mime: Option<&str>,
    right_mime: Option<&str>,
    left_encoding: Option<&str>,
    right_encoding: Option<&str>,
    left_unavailable: bool,
    right_unavailable: bool,
    left_known_truncated: bool,
    right_known_truncated: bool,
) -> BodyComparison {
    let left_evidence = body_evidence(left);
    let right_evidence = body_evidence(right);
    let equal = match (&left_evidence.sha256, &right_evidence.sha256) {
        (Some(left), Some(right)) => Some(left == right),
        (None, None) => Some(true),
        _ => Some(false),
    };
    let mut warnings = Vec::new();
    note_body_state(
        left,
        left_recorded_length,
        left_unavailable,
        BodyWarning::LeftMissing,
        BodyWarning::LeftUnavailable,
        BodyWarning::LeftTruncated,
        &mut warnings,
    );
    if left_known_truncated {
        warnings.push(BodyWarning::LeftTruncated);
    }
    if right_known_truncated {
        warnings.push(BodyWarning::RightTruncated);
    }
    note_body_state(
        right,
        right_recorded_length,
        right_unavailable,
        BodyWarning::RightMissing,
        BodyWarning::RightUnavailable,
        BodyWarning::RightTruncated,
        &mut warnings,
    );
    if left.is_none() && right.is_some() && !left_unavailable {
        warnings.push(BodyWarning::LeftMissing);
    }
    if right.is_none() && left.is_some() && !right_unavailable {
        warnings.push(BodyWarning::RightMissing);
    }

    let left_text = prepare_text(
        left.as_deref(),
        left_mime,
        left_encoding,
        BodyWarning::LeftBinary,
        BodyWarning::LeftTruncated,
        BodyWarning::LeftDecodeFailed,
        &mut warnings,
    );
    let right_text = prepare_text(
        right.as_deref(),
        right_mime,
        right_encoding,
        BodyWarning::RightBinary,
        BodyWarning::RightTruncated,
        BodyWarning::RightDecodeFailed,
        &mut warnings,
    );
    let text_diff = match (left_text, right_text) {
        (Some(left), Some(right)) if left != right => Some(bounded_line_diff(&left, &right)),
        (Some(_), Some(_)) => Some(String::new()),
        _ => None,
    };
    warnings.sort_by_key(body_warning_order);
    warnings.dedup();

    BodyComparison {
        left: left_evidence,
        right: right_evidence,
        equal,
        text_diff,
        warnings,
    }
}

fn body_evidence(body: &Option<Vec<u8>>) -> BodyEvidence {
    BodyEvidence {
        present: body.is_some(),
        length: body.as_ref().map(|body| body.len() as u64),
        sha256: body.as_ref().map(|body| {
            let digest = Sha256::digest(body);
            hex::encode(digest)
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn note_body_state(
    body: &Option<Vec<u8>>,
    recorded_length: Option<i64>,
    unavailable: bool,
    missing_warning: BodyWarning,
    unavailable_warning: BodyWarning,
    truncated_warning: BodyWarning,
    warnings: &mut Vec<BodyWarning>,
) {
    if unavailable {
        warnings.push(unavailable_warning);
    } else if body.is_none() && recorded_length.unwrap_or_default() > 0 {
        warnings.push(missing_warning);
    }
    if let (Some(body), Some(recorded)) = (body, recorded_length) {
        if recorded >= 0 && recorded as usize > body.len() {
            warnings.push(truncated_warning);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_text(
    body: Option<&[u8]>,
    mime: Option<&str>,
    encoding: Option<&str>,
    binary_warning: BodyWarning,
    truncated_warning: BodyWarning,
    decode_warning: BodyWarning,
    warnings: &mut Vec<BodyWarning>,
) -> Option<String> {
    let body = body?;
    if !is_textual_mime(mime) {
        warnings.push(binary_warning);
        return None;
    }
    let decoded = match encoding.filter(|value| !value.trim().is_empty()) {
        Some(encoding) => match decode_content_encodings(body, encoding, MAX_COMPARE_TEXT_BYTES) {
            Ok(decoded) => decoded,
            Err(error) => {
                if matches!(error.code(), crate::domain::ErrorCode::BodyTooLarge) {
                    warnings.push(truncated_warning);
                } else {
                    warnings.push(decode_warning);
                }
                return None;
            }
        },
        None if body.len() > MAX_COMPARE_TEXT_BYTES => {
            warnings.push(truncated_warning);
            return None;
        }
        None => body.to_vec(),
    };
    match String::from_utf8(decoded) {
        Ok(text) => Some(text),
        Err(_) => {
            warnings.push(binary_warning);
            None
        }
    }
}

fn is_textual_mime(mime: Option<&str>) -> bool {
    let Some(mime) = mime else {
        return true;
    };
    let mime = mime
        .split(';')
        .next()
        .unwrap_or(mime)
        .trim()
        .to_ascii_lowercase();
    mime.starts_with("text/")
        || mime.contains("json")
        || mime.contains("xml")
        || mime.contains("javascript")
        || mime == "application/x-www-form-urlencoded"
        || mime == "application/graphql"
}

fn bounded_line_diff(left: &str, right: &str) -> String {
    let left = left.lines().collect::<Vec<_>>();
    let right = right.lines().collect::<Vec<_>>();
    let mut output = String::new();
    for index in 0..left.len().max(right.len()).min(MAX_DIFF_LINES) {
        let left_line = left.get(index).copied().unwrap_or("");
        let right_line = right.get(index).copied().unwrap_or("");
        if left_line == right_line {
            continue;
        }
        push_bounded(&mut output, &format!("- {left_line}\n+ {right_line}\n"));
        if output.len() >= MAX_COMPARE_TEXT_BYTES {
            break;
        }
    }
    if left.len().max(right.len()) > MAX_DIFF_LINES && output.len() < MAX_COMPARE_TEXT_BYTES {
        push_bounded(
            &mut output,
            &format!("... diff truncated after {MAX_DIFF_LINES} lines\n"),
        );
    }
    output
}

fn push_bounded(output: &mut String, addition: &str) {
    let remaining = MAX_COMPARE_TEXT_BYTES.saturating_sub(output.len());
    if remaining == 0 {
        return;
    }
    if addition.len() <= remaining {
        output.push_str(addition);
        return;
    }
    let mut end = remaining;
    while !addition.is_char_boundary(end) {
        end -= 1;
    }
    output.push_str(&addition[..end]);
}

fn body_warning_order(warning: &BodyWarning) -> u8 {
    match warning {
        BodyWarning::LeftMissing => 0,
        BodyWarning::RightMissing => 1,
        BodyWarning::LeftUnavailable => 2,
        BodyWarning::RightUnavailable => 3,
        BodyWarning::LeftBinary => 4,
        BodyWarning::RightBinary => 5,
        BodyWarning::LeftTruncated => 6,
        BodyWarning::RightTruncated => 7,
        BodyWarning::LeftDecodeFailed => 8,
        BodyWarning::RightDecodeFailed => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{CaptureQuality, CompletionState, ExchangeSource, TransportProvenance};
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    use time::OffsetDateTime;

    fn header(name: &str, value: &[u8], ordinal: u32) -> HeaderEntry {
        HeaderEntry {
            name: name.into(),
            value: value.to_vec(),
            ordinal,
        }
    }

    fn exchange(id: i64) -> CompareExchange {
        CompareExchange {
            summary: ExchangeSummary {
                project_id: ProjectId(1),
                exchange_id: ExchangeId(id),
                source: ExchangeSource::Reply,
                started_at: OffsetDateTime::UNIX_EPOCH,
                duration_ms: Some(10),
                method: "GET".into(),
                scheme: "https".into(),
                authority: "example.test".into(),
                host: "example.test".into(),
                port: 443,
                path: "/a".into(),
                query: Some("x=1".into()),
                status_code: Some(200),
                mime: Some("text/plain".into()),
                request_length: Some(0),
                response_length: Some(3),
                completion: CompletionState::Complete,
                capture_quality: CaptureQuality::Semantic,
                page_title: None,
                display_title: None,
                labels: Vec::new(),
                parent_exchange_id: None,
                transport_provenance: Some(TransportProvenance::SemanticProxy),
            },
            body_representation: BodyRepresentation::SemanticEncoded,
            request_headers: Vec::new(),
            response_headers: vec![header("Content-Type", b"text/plain", 0)],
            request_body: Some(Vec::new()),
            response_body: Some(b"one".to_vec()),
        }
    }

    #[test]
    fn compares_metadata_duplicate_headers_and_noisy_opt_in() {
        let mut left = exchange(1);
        let mut right = exchange(2);
        right.summary.method = "POST".into();
        right.summary.path = "/b".into();
        right.summary.status_code = Some(201);
        right.summary.duration_ms = Some(30);
        left.request_headers = vec![
            header("X-Test", b"one", 0),
            header("x-test", b"two", 1),
            header("Sec-Fetch-Mode", b"navigate", 2),
        ];
        right.request_headers = vec![
            header("X-Test", b"one", 0),
            header("x-test", b"three", 1),
            header("Sec-Fetch-Mode", b"cors", 2),
        ];

        let hidden = compare_exchange_data(&left, &right, &CompareOptions::default());
        assert!(hidden.request.method.changed);
        assert!(hidden.request.url.changed);
        assert!(hidden.response.status.changed);
        assert!(hidden.response.duration_ms.changed);
        assert_eq!(hidden.request.headers.changes.len(), 1);
        assert_eq!(
            hidden.request.headers.changes[0].left_values,
            ["one", "two"]
        );
        assert_eq!(hidden.request.headers.noisy_hidden, 1);

        let shown = compare_exchange_data(
            &left,
            &right,
            &CompareOptions {
                include_noisy_headers: true,
            },
        );
        assert_eq!(shown.request.headers.changes.len(), 2);
    }

    #[test]
    fn reports_secret_change_without_disclosing_values() {
        let mut left = exchange(1);
        let mut right = exchange(2);
        left.request_headers = vec![header("Authorization", b"Bearer first", 0)];
        right.request_headers = vec![
            header("authorization", b"Bearer second", 0),
            header("Authorization", b"Bearer third", 1),
        ];

        let comparison = compare_exchange_data(&left, &right, &CompareOptions::default());
        let change = &comparison.request.headers.changes[0];
        assert!(change.sensitive);
        assert_eq!(change.left_count, 1);
        assert_eq!(change.right_count, 2);
        assert_eq!(change.left_values, [REDACTED_PLACEHOLDER]);
        assert_eq!(
            change.right_values,
            [REDACTED_PLACEHOLDER, REDACTED_PLACEHOLDER]
        );
        let json = serde_json::to_string(&comparison).unwrap();
        assert!(!json.contains("first"));
        assert!(!json.contains("second"));
        assert!(!json.contains("third"));
    }

    #[test]
    fn hashes_raw_bodies_and_diffs_decoded_gzip_text() {
        let mut left = exchange(1);
        let mut right = exchange(2);
        left.response_headers
            .push(header("Content-Encoding", b"gzip", 1));
        right
            .response_headers
            .push(header("Content-Encoding", b"gzip", 1));
        left.response_body = Some(gzip(b"one\ntwo\n"));
        right.response_body = Some(gzip(b"one\nchanged\n"));
        left.summary.response_length = Some(left.response_body.as_ref().unwrap().len() as i64);
        right.summary.response_length = Some(right.response_body.as_ref().unwrap().len() as i64);

        let comparison = compare_exchange_data(&left, &right, &CompareOptions::default());
        assert_eq!(comparison.response.body.equal, Some(false));
        assert_ne!(
            comparison.response.body.left.sha256,
            comparison.response.body.right.sha256
        );
        let diff = comparison.response.body.text_diff.unwrap();
        assert!(diff.contains("- two"));
        assert!(diff.contains("+ changed"));
        assert!(comparison.response.body.warnings.is_empty());
    }

    #[test]
    fn does_not_decode_browser_decoded_body_twice() {
        let mut left = exchange(1);
        let mut right = exchange(2);
        left.body_representation = BodyRepresentation::BrowserDecoded;
        right.body_representation = BodyRepresentation::BrowserDecoded;
        left.response_headers
            .push(header("Content-Encoding", b"gzip", 1));
        right
            .response_headers
            .push(header("Content-Encoding", b"gzip", 1));
        left.response_body = Some(b"decoded left".to_vec());
        right.response_body = Some(b"decoded right".to_vec());
        left.summary.response_length = Some(12);
        right.summary.response_length = Some(13);

        let comparison = compare_exchange_data(&left, &right, &CompareOptions::default());
        assert!(comparison
            .response
            .body
            .text_diff
            .unwrap()
            .contains("decoded right"));
        assert!(!comparison
            .response
            .body
            .warnings
            .contains(&BodyWarning::LeftDecodeFailed));
    }

    #[test]
    fn warns_for_missing_binary_unavailable_and_truncated_bodies() {
        let mut left = exchange(1);
        let mut right = exchange(2);
        left.summary.mime = Some("application/octet-stream".into());
        left.response_body = Some(vec![0, 159, 146, 150]);
        left.summary.response_length = Some(20);
        right.response_body = None;
        right.summary.response_length = Some(5);
        right.body_representation = BodyRepresentation::Unavailable;

        let comparison = compare_exchange_data(&left, &right, &CompareOptions::default());
        assert_eq!(comparison.response.body.equal, Some(false));
        assert!(comparison
            .response
            .body
            .warnings
            .contains(&BodyWarning::LeftBinary));
        assert!(comparison
            .response
            .body
            .warnings
            .contains(&BodyWarning::LeftTruncated));
        assert!(comparison
            .response
            .body
            .warnings
            .contains(&BodyWarning::RightUnavailable));
        assert!(comparison.response.body.text_diff.is_none());
    }

    #[test]
    fn text_diff_never_exceeds_64_kib() {
        let mut left = exchange(1);
        let mut right = exchange(2);
        let left_body = (0..400)
            .map(|_| "a".repeat(100))
            .collect::<Vec<_>>()
            .join("\n");
        let right_body = (0..400)
            .map(|_| "b".repeat(100))
            .collect::<Vec<_>>()
            .join("\n");
        left.summary.response_length = Some(left_body.len() as i64);
        right.summary.response_length = Some(right_body.len() as i64);
        left.response_body = Some(left_body.into_bytes());
        right.response_body = Some(right_body.into_bytes());

        let comparison = compare_exchange_data(&left, &right, &CompareOptions::default());
        assert!(comparison.response.body.text_diff.unwrap().len() <= MAX_COMPARE_TEXT_BYTES);
    }

    fn gzip(body: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }
}
