//! Immutable exchange records.

use crate::domain::*;
use crate::policy::{present_headers, PresentationOptions};
use crate::storage::bodies::store_body_conn;
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::Db;
use rusqlite::params;

#[derive(Debug, Clone)]
pub struct NewExchange {
    pub project_id: ProjectId,
    pub source: ExchangeSource,
    pub protocol: String,
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
    pub status_code: Option<u16>,
    pub mime: Option<String>,
    pub completion: CompletionState,
    pub capture_quality: CaptureQuality,
    pub header_representation: HeaderRepresentation,
    pub body_representation: BodyRepresentation,
    pub cache_provenance: CacheProvenance,
    pub transport_provenance: Option<TransportProvenance>,
    pub transport_profile: Option<String>,
    pub request_headers: Vec<HeaderEntry>,
    pub response_headers: Vec<HeaderEntry>,
    pub request_body: Option<Vec<u8>>,
    pub response_body: Option<Vec<u8>>,
    pub duration_ms: Option<i64>,
    pub lineage: ExchangeLineage,
    pub page_title: Option<String>,
    pub error_message: Option<String>,
}

impl Db {
    pub async fn insert_exchange(&self, ex: NewExchange) -> DomainResult<ExchangeId> {
        self.with_conn(move |conn| insert_exchange_conn(conn, ex))
            .await
    }

    pub async fn list_history(
        &self,
        project_id: ProjectId,
        limit: u32,
        before_started: Option<String>,
        before_id: Option<i64>,
    ) -> DomainResult<(Vec<ExchangeSummary>, Option<(String, i64)>)> {
        let limit = limit.clamp(1, 200) as i64;
        self.with_conn(move |conn| {
            let fetch = limit + 1;
            let map_row = |row: &rusqlite::Row<'_>| raw_summary(project_id, row);

            let mut items = if let (Some(bs), Some(bid)) = (before_started, before_id) {
                let mut stmt = conn
                    .prepare(
                        "SELECT exchange_id, source, started_at, duration_ms, method, scheme, authority, host, port, path, query,
                                status_code, mime, request_length, response_length, completion, capture_quality,
                                page_title, display_title, parent_exchange_id, transport_provenance
                         FROM exchanges WHERE project_id=?1
                           AND (started_at < ?2 OR (started_at = ?2 AND exchange_id < ?3))
                         ORDER BY started_at DESC, exchange_id DESC LIMIT ?4",
                    )
                    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                let rows = stmt
                    .query_map(params![project_id.get(), bs, bid, fetch], map_row)
                    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                collect_rows(rows)?
            } else {
                let mut stmt = conn
                    .prepare(
                        "SELECT exchange_id, source, started_at, duration_ms, method, scheme, authority, host, port, path, query,
                                status_code, mime, request_length, response_length, completion, capture_quality,
                                page_title, display_title, parent_exchange_id, transport_provenance
                         FROM exchanges WHERE project_id=?1
                         ORDER BY started_at DESC, exchange_id DESC LIMIT ?2",
                    )
                    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                let rows = stmt
                    .query_map(params![project_id.get(), fetch], map_row)
                    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                collect_rows(rows)?
            };

            let next = if items.len() as i64 > limit {
                items.truncate(limit as usize);
                items.last().map(|e| {
                    let s = e
                        .started_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default();
                    (s, e.exchange_id.get())
                })
            } else {
                None
            };
            Ok((items, next))
        })
        .await
    }

    pub async fn get_exchange_detail(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        opts: PresentationOptions,
    ) -> DomainResult<ExchangeDetail> {
        self.with_conn(move |conn| {
            let row = conn
                .query_row(
                    "SELECT exchange_id, source, started_at, duration_ms, method, scheme, authority, host, port, path, query,
                            status_code, mime, request_length, response_length, completion, capture_quality,
                            page_title, display_title, parent_exchange_id, transport_provenance,
                            protocol, header_representation, body_representation, cache_provenance,
                            request_body_hash, response_body_hash,
                            redirect_parent_id, reply_tab_id, fuzz_job_id, fuzz_case_id,
                            browser_session_id, browser_action_id, capture_session_id
                     FROM exchanges WHERE project_id=?1 AND exchange_id=?2",
                    params![project_id.get(), exchange_id.get()],
                    |row| {
                        let summary = raw_summary(project_id, row)?;
                        Ok((
                            summary,
                            row.get::<_, String>(21)?,
                            row.get::<_, String>(22)?,
                            row.get::<_, String>(23)?,
                            row.get::<_, String>(24)?,
                            row.get::<_, Option<String>>(25)?,
                            row.get::<_, Option<String>>(26)?,
                            row.get::<_, Option<i64>>(27)?,
                            row.get::<_, Option<i64>>(28)?,
                            row.get::<_, Option<i64>>(29)?,
                            row.get::<_, Option<i64>>(30)?,
                            row.get::<_, Option<i64>>(31)?,
                            row.get::<_, Option<i64>>(32)?,
                            row.get::<_, Option<i64>>(33)?,
                        ))
                    },
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => DomainError::not_found(format!(
                        "exchange {}/{}",
                        project_id.get(),
                        exchange_id.get()
                    )),
                    other => DomainError::new(ErrorCode::StorageError, other.to_string()),
                })?;

            let (
                summary,
                protocol,
                header_rep,
                body_rep,
                cache_prov,
                req_hash,
                resp_hash,
                redirect_parent,
                reply_tab,
                fuzz_job,
                fuzz_case,
                browser_session,
                browser_action,
                capture_session,
            ) = row;

            let req_headers = load_headers(conn, project_id, exchange_id, "request")?;
            let resp_headers = load_headers(conn, project_id, exchange_id, "response")?;
            let req_pres = present_headers(&req_headers, &opts);
            let resp_pres = present_headers(&resp_headers, &opts);
            let parent = summary.parent_exchange_id;

            Ok(ExchangeDetail {
                summary,
                protocol,
                header_representation: parse_header_rep(&header_rep),
                body_representation: parse_body_rep(&body_rep),
                cache_provenance: parse_cache_prov(&cache_prov),
                request_headers: req_pres.headers,
                response_headers: resp_pres.headers,
                request_preview: None,
                response_preview: None,
                redacted_count: req_pres.redacted_count + resp_pres.redacted_count,
                noisy_hidden_count: req_pres.noisy_hidden_count + resp_pres.noisy_hidden_count,
                request_body_hash: req_hash,
                response_body_hash: resp_hash,
                lineage: ExchangeLineage {
                    parent_exchange_id: parent,
                    redirect_parent_id: redirect_parent.map(ExchangeId),
                    reply_tab_id: reply_tab.map(ReplyTabId),
                    fuzz_job_id: fuzz_job.map(FuzzJobId),
                    fuzz_case_id: fuzz_case,
                    browser_session_id: browser_session.map(BrowserSessionId),
                    browser_action_id: browser_action.map(BrowserActionId),
                    capture_session_id: capture_session.map(CaptureSessionId),
                },
            })
        })
        .await
    }

    /// Load raw headers for internal replay (includes secrets). Never expose via API.
    pub async fn load_raw_headers(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        side: MessageSide,
    ) -> DomainResult<Vec<HeaderEntry>> {
        let side_s = match side {
            MessageSide::Request => "request",
            MessageSide::Response => "response",
        };
        self.with_conn(move |conn| load_headers(conn, project_id, exchange_id, side_s))
            .await
    }

    pub async fn load_raw_body(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        side: MessageSide,
    ) -> DomainResult<Option<Vec<u8>>> {
        let col = match side {
            MessageSide::Request => "request_body_id",
            MessageSide::Response => "response_body_id",
        };
        let sql = format!("SELECT {col} FROM exchanges WHERE project_id=?1 AND exchange_id=?2");
        self.with_conn(move |conn| {
            let body_id: Option<i64> = conn
                .query_row(&sql, params![project_id.get(), exchange_id.get()], |r| {
                    r.get(0)
                })
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => DomainError::not_found("exchange"),
                    other => DomainError::new(ErrorCode::StorageError, other.to_string()),
                })?;
            if let Some(id) = body_id {
                let (codec, content): (String, Vec<u8>) = conn
                    .query_row(
                        "SELECT codec, content FROM bodies WHERE id=?1",
                        params![id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                let raw = match codec.as_str() {
                    "zstd" => zstd::decode_all(&content[..])
                        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?,
                    _ => content,
                };
                Ok(Some(raw))
            } else {
                Ok(None)
            }
        })
        .await
    }
}

fn collect_rows<T, E>(rows: impl Iterator<Item = Result<T, E>>) -> DomainResult<Vec<T>>
where
    E: std::fmt::Display,
{
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?);
    }
    Ok(out)
}

fn raw_summary(project_id: ProjectId, row: &rusqlite::Row<'_>) -> rusqlite::Result<ExchangeSummary> {
    let started: String = row.get(2)?;
    Ok(ExchangeSummary {
        project_id,
        exchange_id: ExchangeId(row.get(0)?),
        source: parse_source(&row.get::<_, String>(1)?),
        started_at: parse_time(&started),
        duration_ms: row.get(3)?,
        method: row.get(4)?,
        scheme: row.get(5)?,
        authority: row.get(6)?,
        host: row.get(7)?,
        port: row.get::<_, i64>(8)? as u16,
        path: row.get(9)?,
        query: row.get(10)?,
        status_code: row.get::<_, Option<i64>>(11)?.map(|v| v as u16),
        mime: row.get(12)?,
        request_length: row.get(13)?,
        response_length: row.get(14)?,
        completion: parse_completion(&row.get::<_, String>(15)?),
        capture_quality: parse_capture_quality(&row.get::<_, String>(16)?),
        page_title: row.get(17)?,
        display_title: row.get(18)?,
        labels: vec![],
        parent_exchange_id: row.get::<_, Option<i64>>(19)?.map(ExchangeId),
        transport_provenance: row
            .get::<_, Option<String>>(20)?
            .as_deref()
            .map(parse_transport_prov),
    })
}

pub fn insert_exchange_conn(
    conn: &rusqlite::Connection,
    ex: NewExchange,
) -> DomainResult<ExchangeId> {
    let exchange_id = alloc_exchange_id(conn, ex.project_id)?;
    let started = now_rfc3339();
    let mut req_body_id = None;
    let mut req_hash = None;
    let mut req_len = None;
    if let Some(body) = &ex.request_body {
        let stored = store_body_conn(conn, body, None)?;
        req_body_id = Some(stored.id.get());
        req_hash = Some(stored.sha256);
        req_len = Some(stored.original_length);
    }
    let mut resp_body_id = None;
    let mut resp_hash = None;
    let mut resp_len = None;
    if let Some(body) = &ex.response_body {
        let stored = store_body_conn(conn, body, ex.mime.as_deref())?;
        resp_body_id = Some(stored.id.get());
        resp_hash = Some(stored.sha256);
        resp_len = Some(stored.original_length);
    }

    conn.execute(
        "INSERT INTO exchanges (
            project_id, exchange_id, source, started_at, duration_ms, protocol, method, scheme,
            authority, host, port, path, query, status_code, mime, request_length, response_length,
            completion, capture_quality, header_representation, body_representation, cache_provenance,
            transport_provenance, transport_profile, page_title, parent_exchange_id, redirect_parent_id,
            reply_tab_id, fuzz_job_id, fuzz_case_id, browser_session_id, browser_action_id, capture_session_id,
            request_body_id, response_body_id, request_body_hash, response_body_hash, error_message
         ) VALUES (
            ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,
            ?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38
         )",
        params![
            ex.project_id.get(),
            exchange_id.get(),
            source_str(ex.source),
            started,
            ex.duration_ms,
            ex.protocol,
            ex.method,
            ex.scheme,
            ex.authority,
            ex.host,
            ex.port as i64,
            ex.path,
            ex.query,
            ex.status_code.map(|s| s as i64),
            ex.mime,
            req_len,
            resp_len,
            completion_str(ex.completion),
            capture_quality_str(ex.capture_quality),
            header_rep_str(ex.header_representation),
            body_rep_str(ex.body_representation),
            cache_prov_str(ex.cache_provenance),
            ex.transport_provenance.map(transport_prov_str),
            ex.transport_profile,
            ex.page_title,
            ex.lineage.parent_exchange_id.map(|i| i.get()),
            ex.lineage.redirect_parent_id.map(|i| i.get()),
            ex.lineage.reply_tab_id.map(|i| i.get()),
            ex.lineage.fuzz_job_id.map(|i| i.get()),
            ex.lineage.fuzz_case_id,
            ex.lineage.browser_session_id.map(|i| i.get()),
            ex.lineage.browser_action_id.map(|i| i.get()),
            ex.lineage.capture_session_id.map(|i| i.get()),
            req_body_id,
            resp_body_id,
            req_hash,
            resp_hash,
            ex.error_message,
        ],
    )
    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;

    for h in &ex.request_headers {
        conn.execute(
            "INSERT INTO message_headers (project_id, exchange_id, side, ordinal, name, value)
             VALUES (?1,?2,'request',?3,?4,?5)",
            params![
                ex.project_id.get(),
                exchange_id.get(),
                h.ordinal as i64,
                h.name,
                h.value
            ],
        )
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    }
    for h in &ex.response_headers {
        conn.execute(
            "INSERT INTO message_headers (project_id, exchange_id, side, ordinal, name, value)
             VALUES (?1,?2,'response',?3,?4,?5)",
            params![
                ex.project_id.get(),
                exchange_id.get(),
                h.ordinal as i64,
                h.name,
                h.value
            ],
        )
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    }

    Ok(exchange_id)
}

fn alloc_exchange_id(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
) -> DomainResult<ExchangeId> {
    conn.execute(
        "UPDATE project_seq SET next_exchange_id = next_exchange_id + 1 WHERE project_id=?1",
        params![project_id.get()],
    )
    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    let next: i64 = conn
        .query_row(
            "SELECT next_exchange_id FROM project_seq WHERE project_id=?1",
            params![project_id.get()],
            |r| r.get(0),
        )
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    Ok(ExchangeId(next - 1))
}

fn load_headers(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
    exchange_id: ExchangeId,
    side: &str,
) -> DomainResult<Vec<HeaderEntry>> {
    let mut stmt = conn
        .prepare(
            "SELECT ordinal, name, value FROM message_headers
             WHERE project_id=?1 AND exchange_id=?2 AND side=?3 ORDER BY ordinal",
        )
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    let rows = stmt
        .query_map(
            params![project_id.get(), exchange_id.get(), side],
            |row| {
                Ok(HeaderEntry {
                    ordinal: row.get::<_, i64>(0)? as u32,
                    name: row.get(1)?,
                    value: row.get(2)?,
                })
            },
        )
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    collect_rows(rows)
}

fn source_str(s: ExchangeSource) -> &'static str {
    match s {
        ExchangeSource::Browser => "browser",
        ExchangeSource::Reply => "reply",
        ExchangeSource::Fuzzer => "fuzzer",
        ExchangeSource::Proxy => "proxy",
    }
}
fn parse_source(s: &str) -> ExchangeSource {
    match s {
        "browser" => ExchangeSource::Browser,
        "reply" => ExchangeSource::Reply,
        "fuzzer" => ExchangeSource::Fuzzer,
        _ => ExchangeSource::Proxy,
    }
}
fn completion_str(c: CompletionState) -> &'static str {
    match c {
        CompletionState::InProgress => "in_progress",
        CompletionState::Complete => "complete",
        CompletionState::Timeout => "timeout",
        CompletionState::Cancelled => "cancelled",
        CompletionState::ConnectionError => "connection_error",
        CompletionState::ProtocolError => "protocol_error",
        CompletionState::TruncatedByPolicy => "truncated_by_policy",
        CompletionState::Interrupted => "interrupted",
    }
}
fn parse_completion(s: &str) -> CompletionState {
    match s {
        "in_progress" => CompletionState::InProgress,
        "timeout" => CompletionState::Timeout,
        "cancelled" => CompletionState::Cancelled,
        "connection_error" => CompletionState::ConnectionError,
        "protocol_error" => CompletionState::ProtocolError,
        "truncated_by_policy" => CompletionState::TruncatedByPolicy,
        "interrupted" => CompletionState::Interrupted,
        _ => CompletionState::Complete,
    }
}
fn capture_quality_str(c: CaptureQuality) -> &'static str {
    match c {
        CaptureQuality::WirePreserved => "wire_preserved",
        CaptureQuality::Semantic => "semantic",
        CaptureQuality::BrowserObserved => "browser_observed",
    }
}
fn parse_capture_quality(s: &str) -> CaptureQuality {
    match s {
        "wire_preserved" => CaptureQuality::WirePreserved,
        "browser_observed" => CaptureQuality::BrowserObserved,
        _ => CaptureQuality::Semantic,
    }
}
fn header_rep_str(h: HeaderRepresentation) -> &'static str {
    match h {
        HeaderRepresentation::WirePreserved => "wire_preserved",
        HeaderRepresentation::Semantic => "semantic",
        HeaderRepresentation::BrowserObserved => "browser_observed",
    }
}
fn parse_header_rep(s: &str) -> HeaderRepresentation {
    match s {
        "wire_preserved" => HeaderRepresentation::WirePreserved,
        "browser_observed" => HeaderRepresentation::BrowserObserved,
        _ => HeaderRepresentation::Semantic,
    }
}
fn body_rep_str(b: BodyRepresentation) -> &'static str {
    match b {
        BodyRepresentation::WireEncoded => "wire_encoded",
        BodyRepresentation::SemanticEncoded => "semantic_encoded",
        BodyRepresentation::BrowserDecoded => "browser_decoded",
        BodyRepresentation::Unavailable => "unavailable",
    }
}
fn parse_body_rep(s: &str) -> BodyRepresentation {
    match s {
        "wire_encoded" => BodyRepresentation::WireEncoded,
        "browser_decoded" => BodyRepresentation::BrowserDecoded,
        "unavailable" => BodyRepresentation::Unavailable,
        _ => BodyRepresentation::SemanticEncoded,
    }
}
fn cache_prov_str(c: CacheProvenance) -> &'static str {
    match c {
        CacheProvenance::Unknown => "unknown",
        CacheProvenance::RouteCacheDisabled => "route_cache_disabled",
        CacheProvenance::BrowserCache => "browser_cache",
        CacheProvenance::None => "none",
    }
}
fn parse_cache_prov(s: &str) -> CacheProvenance {
    match s {
        "route_cache_disabled" => CacheProvenance::RouteCacheDisabled,
        "browser_cache" => CacheProvenance::BrowserCache,
        "none" => CacheProvenance::None,
        _ => CacheProvenance::Unknown,
    }
}
fn transport_prov_str(t: TransportProvenance) -> &'static str {
    match t {
        TransportProvenance::ProtocolProfileOnly => "protocol_profile_only",
        TransportProvenance::IdentityInconsistent => "identity_inconsistent",
        TransportProvenance::GenericUnprofiled => "generic_unprofiled",
        TransportProvenance::ChromiumWireFidelity => "chromium_wire_fidelity",
        TransportProvenance::SemanticProxy => "semantic_proxy",
    }
}
fn parse_transport_prov(s: &str) -> TransportProvenance {
    match s {
        "protocol_profile_only" => TransportProvenance::ProtocolProfileOnly,
        "identity_inconsistent" => TransportProvenance::IdentityInconsistent,
        "generic_unprofiled" => TransportProvenance::GenericUnprofiled,
        "chromium_wire_fidelity" => TransportProvenance::ChromiumWireFidelity,
        _ => TransportProvenance::SemanticProxy,
    }
}
