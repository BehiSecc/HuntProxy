//! Immutable exchange records.

use crate::domain::*;
use crate::history::{filter_to_sql, pins_exchange_id, uses_body_search, FilterNode};
use crate::policy::{present_headers, PresentationOptions};
use crate::storage::annotations::load_labels_conn;
use crate::storage::bodies::{
    prepare_body, prepare_body_file, store_body_conn, store_body_file_conn,
    store_prepared_body_conn, PreparedBody, PreparedBodyFile, StoredBody,
};
use crate::storage::db::BodySearchScope;
use crate::storage::headers::{insert_headers_conn, load_headers_conn};
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::Db;
use rusqlite::params;
use rusqlite::types::Value;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use time::{Duration, OffsetDateTime};

pub(crate) const EXCHANGE_ACCOUNTING_OVERHEAD: u64 = 512;
pub(crate) const HEADER_ACCOUNTING_OVERHEAD: u64 = 64;

/// A body captured off the wire, waiting to be stored with its exchange. A
/// small body is held in memory; one too large for that is in a spool file.
#[derive(Debug)]
pub enum CapturedBody {
    Memory(bytes::Bytes),
    Spool(PathBuf),
}

/// A [`CapturedBody`] hashed and, unless it is already stored, encoded.
enum PreparedCapture<'body> {
    Memory(&'body [u8], PreparedBody),
    Spool(&'body std::path::Path, PreparedBodyFile),
}

impl<'body> PreparedCapture<'body> {
    fn of(conn: &rusqlite::Connection, body: &'body CapturedBody) -> DomainResult<Self> {
        Ok(match body {
            CapturedBody::Memory(data) => Self::Memory(data, prepare_body(conn, data)),
            CapturedBody::Spool(path) => Self::Spool(path, prepare_body_file(conn, path)?),
        })
    }

    fn store(
        self,
        conn: &rusqlite::Connection,
        mime_class: Option<&str>,
    ) -> DomainResult<StoredBody> {
        match self {
            Self::Memory(data, prepared) => {
                store_prepared_body_conn(conn, data, prepared, mime_class)
            }
            Self::Spool(path, prepared) => store_body_file_conn(conn, path, prepared, mime_class),
        }
    }
}

const HISTORY_COLUMNS: &str =
    "exchange_id, source, started_at, duration_ms, method, scheme, authority, host, port, path, query,
            status_code, mime, request_length, response_length, completion, capture_quality,
            page_title, display_title, parent_exchange_id, transport_provenance";

/// One page of [`Db::search_history`].
#[derive(Debug, Clone)]
pub struct HistoryPage {
    pub items: Vec<ExchangeSummary>,
    /// `(started_at, exchange_id)` to pass as the cursor of the next page.
    pub next: Option<(String, i64)>,
    /// Set when the time budget stopped a body search: the stored
    /// `started_at` back to which it searched. Every exchange newer than it
    /// was searched; `next` continues from it.
    pub searched_back_to: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

#[derive(Debug, Clone, serde::Serialize)]
pub struct JavascriptFileRecord {
    pub exchange_id: Option<ExchangeId>,
    pub url: String,
    pub path: String,
    pub host: String,
    pub mime: Option<String>,
    pub status_code: Option<u16>,
    pub related_page_urls: Vec<String>,
    pub related_page_hosts: Vec<String>,
    /// True only when a domain filter includes this file through a browser
    /// session with matching captured or discovered evidence, without a
    /// matching resource/page host on this file.
    /// Always false without a domain filter.
    pub related_via_session: bool,
}

#[derive(Debug, Clone)]
pub struct JavascriptProvenanceInput {
    pub url: String,
    pub source_page_url: Option<String>,
}

impl Db {
    pub async fn browser_session_exchange_ids(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        limit: usize,
    ) -> DomainResult<Vec<ExchangeId>> {
        let limit = limit.clamp(1, 128) as i64;
        self.with_conn(move |conn| {
            let mut statement = conn
                .prepare(
                    "SELECT exchange_id FROM exchanges
                     WHERE project_id=?1 AND browser_session_id=?2
                     ORDER BY exchange_id ASC LIMIT ?3",
                )
                .map_err(storage_error)?;
            let rows = statement
                .query_map(params![project_id.get(), session_id.get(), limit], |row| {
                    row.get::<_, i64>(0).map(ExchangeId)
                })
                .map_err(storage_error)?;
            collect_rows(rows)
        })
        .await
    }

    pub async fn set_static_page_title(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        title: String,
    ) -> DomainResult<bool> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE exchanges SET page_title=?1
                     WHERE project_id=?2 AND exchange_id=?3 AND page_title IS NULL",
                    params![title, project_id.get(), exchange_id.get()],
                )
                .map_err(storage_error)?;
            Ok(changed > 0)
        })
        .await
    }

    /// Attach a rendered main-page title to the newest matching managed-browser
    /// HTML document. Exact URL/session matching prevents titles leaking onto
    /// subresources or another browser workspace.
    pub async fn associate_browser_page_title(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        page_url: &str,
        title: &str,
    ) -> DomainResult<bool> {
        let parsed = url::Url::parse(page_url)
            .map_err(|error| DomainError::invalid(format!("invalid browser page URL: {error}")))?;
        let Some(host) = parsed.host_str().map(str::to_ascii_lowercase) else {
            return Ok(false);
        };
        let Some(port) = parsed.port_or_known_default() else {
            return Ok(false);
        };
        let scheme = parsed.scheme().to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https") {
            return Ok(false);
        }
        let path = parsed.path().to_string();
        let query = parsed.query().unwrap_or_default().to_string();
        let title = title.split_whitespace().collect::<Vec<_>>().join(" ");
        let title = title.chars().take(1024).collect::<String>();
        if title.is_empty() {
            return Ok(false);
        }
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE exchanges SET page_title=?1
                     WHERE project_id=?2 AND exchange_id=(
                       SELECT exchange_id FROM exchanges
                       WHERE project_id=?2 AND browser_session_id=?3
                         AND lower(scheme)=?4 AND lower(host)=?5 AND port=?6
                         AND path=?7 AND COALESCE(query,'')=?8
                         AND (lower(COALESCE(mime,'')) LIKE 'text/html%'
                              OR lower(COALESCE(mime,'')) LIKE 'application/xhtml+xml%')
                       ORDER BY exchange_id DESC LIMIT 1
                     )",
                    params![
                        title,
                        project_id.get(),
                        session_id.get(),
                        scheme,
                        host,
                        port,
                        path,
                        query
                    ],
                )
                .map_err(storage_error)?;
            Ok(changed > 0)
        })
        .await
    }

    /// Remove URLs already present in project history while preserving the
    /// caller's order. Used by the background crawler to avoid duplicating
    /// resources the browser loaded itself.
    pub async fn filter_uncaptured_urls(
        &self,
        project_id: ProjectId,
        urls: Vec<String>,
    ) -> DomainResult<Vec<String>> {
        let mut unique = Vec::new();
        let mut seen = HashSet::new();
        for url in urls.into_iter().take(256) {
            if seen.insert(url.clone()) {
                unique.push(url);
            }
        }
        if unique.is_empty() {
            return Ok(unique);
        }
        let query_urls = unique.clone();
        self.with_conn(move |conn| {
            let authorities = query_urls
                .iter()
                .filter_map(|url| url_authority(url))
                .collect::<HashSet<_>>();
            let mut values = Vec::with_capacity(1 + authorities.len() + query_urls.len());
            values.push(Value::Integer(project_id.get()));
            values.extend(authorities.iter().map(|a| Value::Text((*a).to_owned())));
            values.extend(query_urls.iter().cloned().map(Value::Text));
            let sql = uncaptured_urls_sql(authorities.len(), query_urls.len());
            let mut statement = conn.prepare(&sql).map_err(storage_error)?;
            let rows = statement
                .query_map(rusqlite::params_from_iter(values), |row| {
                    row.get::<_, String>(0)
                })
                .map_err(storage_error)?;
            let captured = rows
                .collect::<Result<HashSet<_>, _>>()
                .map_err(storage_error)?;
            Ok(unique
                .into_iter()
                .filter(|url| !captured.contains(url))
                .collect())
        })
        .await
    }

    pub async fn list_javascript_files(
        &self,
        project_id: ProjectId,
        browser_session_id: Option<BrowserSessionId>,
        domain: Option<String>,
        limit: u32,
    ) -> DomainResult<(Vec<JavascriptFileRecord>, bool)> {
        let limit = limit.clamp(1, 10_000) as usize;
        self.with_conn(move |conn| {
            let matching_sessions = "WITH matching_sessions AS (
                SELECT DISTINCT browser_session_id
                  FROM javascript_provenance
                 WHERE project_id=?1 AND browser_session_id IS NOT NULL
                   AND (
                       lower(source_page_host)=?3
                       OR substr(lower(source_page_host), -(length(?3) + 1))='.' || ?3
                       OR lower(javascript_host)=?3
                       OR substr(lower(javascript_host), -(length(?3) + 1))='.' || ?3
                   )
                UNION
                SELECT browser_session_id
                  FROM exchanges
                 WHERE project_id=?1 AND browser_session_id IS NOT NULL
                   AND (
                       lower(host)=?3
                       OR substr(lower(host), -(length(?3) + 1))='.' || ?3
                   )
            )";
            let sql = format!("{matching_sessions}, matching_urls AS (
                SELECT javascript_url, source_page_host, browser_session_id
                  FROM javascript_provenance
                 WHERE project_id=?1
                   AND (
                       ?3 IS NULL
                       OR lower(source_page_host)=?3
                       OR substr(lower(source_page_host), -(length(?3) + 1))='.' || ?3
                       OR lower(javascript_host)=?3
                       OR substr(lower(javascript_host), -(length(?3) + 1))='.' || ?3
                       OR browser_session_id IN (SELECT browser_session_id FROM matching_sessions)
                   )
            ), ranked AS (
                SELECT exchange_id, scheme, authority, host, path, query, mime, status_code,
                       ROW_NUMBER() OVER (
                           PARTITION BY scheme, authority, path, COALESCE(query, '')
                           ORDER BY exchange_id DESC
                       ) AS row_number
                  FROM exchanges
                 WHERE project_id=?1
                   AND (?2 IS NULL OR browser_session_id=?2)
                   AND (
                       ?3 IS NULL
                       OR lower(host)=?3
                       OR substr(lower(host), -(length(?3) + 1))='.' || ?3
                       OR EXISTS (
                           SELECT 1 FROM matching_urls
                            WHERE matching_urls.javascript_url=(exchanges.scheme || '://' || exchanges.authority || exchanges.path || CASE WHEN exchanges.query IS NULL OR exchanges.query='' THEN '' ELSE '?' || exchanges.query END)
                              AND (
                                  lower(matching_urls.source_page_host)=?3
                                  OR substr(lower(matching_urls.source_page_host), -(length(?3) + 1))='.' || ?3
                                  OR matching_urls.browser_session_id=exchanges.browser_session_id
                              )
                       )
                   )
                   AND (
                       lower(path) LIKE '%.js'
                       OR lower(path) LIKE '%.mjs'
                       OR lower(path) LIKE '%.cjs'
                       OR lower(COALESCE(mime, '')) LIKE '%javascript%'
                       OR lower(COALESCE(mime, '')) LIKE '%ecmascript%'
                   )
            )
            SELECT exchange_id, scheme, authority, host, path, query, mime, status_code
              FROM ranked
             WHERE row_number=1
             ORDER BY exchange_id ASC
             LIMIT ?4");
            let mut stmt = conn.prepare(&sql).map_err(storage_error)?;
            let rows = stmt
                .query_map(
                    params![
                        project_id.get(),
                        browser_session_id.map(BrowserSessionId::get),
                        domain,
                        (limit + 1) as i64
                    ],
                    |row| {
                        let exchange_id = Some(ExchangeId(row.get(0)?));
                        let scheme: String = row.get(1)?;
                        let authority: String = row.get(2)?;
                        let host: String = row.get(3)?;
                        let path: String = row.get(4)?;
                        let query: Option<String> = row.get(5)?;
                        let mut url = format!("{scheme}://{authority}{path}");
                        if let Some(query) = query.filter(|query| !query.is_empty()) {
                            url.push('?');
                            url.push_str(&query);
                        }
                        Ok(JavascriptFileRecord {
                            exchange_id,
                            url,
                            path,
                            host,
                            mime: row.get(6)?,
                            status_code: row.get::<_, Option<i64>>(7)?.map(|value| value as u16),
                            related_page_urls: Vec::new(),
                            related_page_hosts: Vec::new(),
                            related_via_session: false,
                        })
                    },
                )
                .map_err(storage_error)?;
            let mut files = collect_rows(rows)?;
            let mut discovered = conn
                .prepare(
                    &format!("{matching_sessions}
                     SELECT javascript_url, javascript_path, javascript_host
                       FROM javascript_provenance
                      WHERE project_id=?1
                        AND (?2 IS NULL OR browser_session_id=?2)
                        AND (
                            ?3 IS NULL
                            OR lower(source_page_host)=?3
                            OR substr(lower(source_page_host), -(length(?3) + 1))='.' || ?3
                            OR lower(javascript_host)=?3
                            OR substr(lower(javascript_host), -(length(?3) + 1))='.' || ?3
                            OR browser_session_id IN (SELECT browser_session_id FROM matching_sessions)
                        )
                      ORDER BY lower(javascript_url), javascript_url
                      LIMIT ?4"),
                )
                .map_err(storage_error)?;
            let discovered_rows = discovered
                .query_map(
                    params![
                        project_id.get(),
                        browser_session_id.map(BrowserSessionId::get),
                        domain,
                        (limit + 1) as i64,
                    ],
                    |row| {
                        Ok(JavascriptFileRecord {
                            exchange_id: None,
                            url: row.get(0)?,
                            path: row.get(1)?,
                            host: row.get(2)?,
                            mime: None,
                            status_code: None,
                            related_page_urls: Vec::new(),
                            related_page_hosts: Vec::new(),
                            related_via_session: false,
                        })
                    },
                )
                .map_err(storage_error)?;
            let mut known_urls = files
                .iter()
                .map(|file| file.url.clone())
                .collect::<HashSet<_>>();
            for discovered_file in discovered_rows {
                let discovered_file = discovered_file.map_err(storage_error)?;
                if known_urls.insert(discovered_file.url.clone()) {
                    files.push(discovered_file);
                }
            }
            let mut related_by_url: HashMap<String, Vec<(String, String)>> = HashMap::new();
            if !known_urls.is_empty() {
                let placeholders = (0..known_urls.len())
                    .map(|index| format!("?{}", index + 2))
                    .collect::<Vec<_>>()
                    .join(",");
                let query = format!(
                    "SELECT javascript_url, source_page_url, source_page_host
                       FROM javascript_provenance
                      WHERE project_id=?1 AND javascript_url IN ({placeholders})
                      ORDER BY lower(source_page_host), source_page_url"
                );
                let mut values = Vec::with_capacity(known_urls.len() + 1);
                values.push(Value::Integer(project_id.get()));
                values.extend(known_urls.iter().cloned().map(Value::Text));
                let mut provenance = conn.prepare(&query).map_err(storage_error)?;
                let rows = provenance
                    .query_map(rusqlite::params_from_iter(values), |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })
                    .map_err(storage_error)?;
                for row in rows {
                    let (javascript_url, page_url, page_host) = row.map_err(storage_error)?;
                    related_by_url
                        .entry(javascript_url)
                        .or_default()
                        .push((page_url, page_host));
                }
            }
            for file in &mut files {
                for (url, host) in related_by_url.remove(&file.url).unwrap_or_default() {
                    file.related_page_urls.push(url);
                    if !file.related_page_hosts.contains(&host) {
                        file.related_page_hosts.push(host);
                    }
                }
                if let Some(domain) = &domain {
                    let matches_domain = |host: &str| {
                        let host = host.to_ascii_lowercase();
                        host == *domain || host.ends_with(&format!(".{domain}"))
                    };
                    file.related_via_session = !matches_domain(&file.host)
                        && !file.related_page_hosts.iter().any(|host| matches_domain(host));
                }
            }
            files.sort_by(|left, right| {
                left.url
                    .to_ascii_lowercase()
                    .cmp(&right.url.to_ascii_lowercase())
                    .then_with(|| left.url.cmp(&right.url))
            });
            let truncated = files.len() > limit;
            if truncated {
                files.truncate(limit);
            }
            Ok((files, truncated))
        })
        .await
    }

    /// Record that pages included or loaded JavaScript resources. Invalid or
    /// non-HTTP resource URLs are ignored so passive discovery cannot poison
    /// later host-scoped queries.
    pub async fn record_javascript_files(
        &self,
        project_id: ProjectId,
        default_source_page_url: &str,
        files: Vec<JavascriptProvenanceInput>,
        browser_session_id: Option<BrowserSessionId>,
        discovery_kind: &str,
    ) -> DomainResult<usize> {
        let default_source_page_url = default_source_page_url.to_string();
        let discovery_kind = discovery_kind.to_string();
        self.with_conn(move |conn| {
            let default_source = normalized_http_url(&default_source_page_url)?;
            if !matches!(discovery_kind.as_str(), "browser" | "source") {
                return Err(DomainError::invalid(
                    "JavaScript discovery_kind must be browser or source",
                ));
            }
            let now = now_rfc3339();
            let tx = crate::storage::write_transaction(conn)
                .map_err(storage_error)?;
            let mut changed = 0;
            for file in files {
                let source = match file.source_page_url.as_deref() {
                    Some(value) => normalized_http_url(value).unwrap_or_else(|_| default_source.clone()),
                    None => default_source.clone(),
                };
                let resource = normalized_http_url(&file.url)
                    .or_else(|_| normalized_join_http_url(&source, &file.url));
                let Ok(resource) = resource else {
                    continue;
                };
                changed += tx
                    .execute(
                        "INSERT INTO javascript_provenance (
                            project_id, javascript_url, javascript_host, javascript_path,
                            source_page_url, source_page_host, browser_session_id,
                            discovery_kind, created_at
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                         ON CONFLICT(project_id, javascript_url, source_page_url) DO UPDATE SET
                            browser_session_id=COALESCE(excluded.browser_session_id, browser_session_id),
                            discovery_kind=excluded.discovery_kind",
                        params![
                            project_id.get(),
                            resource.as_str(),
                            resource.host_str().unwrap_or_default().to_ascii_lowercase(),
                            resource.path(),
                            source.as_str(),
                            source.host_str().unwrap_or_default().to_ascii_lowercase(),
                            browser_session_id.map(BrowserSessionId::get),
                            discovery_kind,
                            now,
                        ],
                    )
                    .map_err(storage_error)?;
            }
            tx.commit().map_err(storage_error)?;
            Ok(changed)
        })
        .await
    }

    pub async fn insert_exchange(&self, ex: NewExchange) -> DomainResult<ExchangeId> {
        self.with_conn(move |conn| {
            // Hash and compress the bodies before taking the write lock.
            let request = ex
                .request_body
                .as_deref()
                .map(|body| prepare_body(conn, body));
            let response = ex
                .response_body
                .as_deref()
                .map(|body| prepare_body(conn, body));
            let tx = crate::storage::write_transaction(conn).map_err(storage_error)?;
            let request_body = ex
                .request_body
                .as_deref()
                .zip(request)
                .map(|(body, prepared)| store_prepared_body_conn(&tx, body, prepared, None))
                .transpose()?;
            let response_body = ex
                .response_body
                .as_deref()
                .zip(response)
                .map(|(body, prepared)| {
                    store_prepared_body_conn(&tx, body, prepared, ex.mime.as_deref())
                })
                .transpose()?;
            let exchange_id = insert_exchange_record_conn(&tx, ex, request_body, response_body)?;
            tx.commit().map_err(storage_error)?;
            Ok(exchange_id)
        })
        .await
    }

    pub async fn insert_exchange_from_spools(
        &self,
        ex: NewExchange,
        request_spool: Option<PathBuf>,
        response_spool: Option<PathBuf>,
    ) -> DomainResult<ExchangeId> {
        self.insert_captured_exchange(
            ex,
            request_spool.map(CapturedBody::Spool),
            response_spool.map(CapturedBody::Spool),
        )
        .await
    }

    /// Stores an exchange whose bodies were captured off the wire, each one
    /// in memory or in a spool file.
    pub async fn insert_captured_exchange(
        &self,
        ex: NewExchange,
        request_body: Option<CapturedBody>,
        response_body: Option<CapturedBody>,
    ) -> DomainResult<ExchangeId> {
        if ex.request_body.is_some() || ex.response_body.is_some() {
            return Err(DomainError::new(
                ErrorCode::InvalidArgument,
                "an exchange with captured bodies must not also contain in-memory bodies",
            ));
        }
        self.with_conn(move |conn| {
            // Hash and compress the bodies before taking the write lock.
            let request = request_body
                .as_ref()
                .map(|body| PreparedCapture::of(conn, body))
                .transpose()?;
            let response = response_body
                .as_ref()
                .map(|body| PreparedCapture::of(conn, body))
                .transpose()?;
            let tx = crate::storage::write_transaction(conn).map_err(storage_error)?;
            let request_body = request
                .map(|prepared| prepared.store(&tx, None))
                .transpose()?;
            let response_body = response
                .map(|prepared| prepared.store(&tx, ex.mime.as_deref()))
                .transpose()?;
            let exchange_id = insert_exchange_record_conn(&tx, ex, request_body, response_body)?;
            tx.commit().map_err(storage_error)?;
            Ok(exchange_id)
        })
        .await
    }

    pub async fn list_history(
        &self,
        project_id: ProjectId,
        limit: u32,
        before_started: Option<String>,
        before_id: Option<i64>,
    ) -> DomainResult<(Vec<ExchangeSummary>, Option<(String, i64)>)> {
        self.list_history_filtered(project_id, None, limit, before_started, before_id)
            .await
    }

    pub async fn list_history_filtered(
        &self,
        project_id: ProjectId,
        filter: Option<FilterNode>,
        limit: u32,
        before_started: Option<String>,
        before_id: Option<i64>,
    ) -> DomainResult<(Vec<ExchangeSummary>, Option<(String, i64)>)> {
        let page = self
            .search_history(project_id, filter, limit, before_started, before_id, None)
            .await?;
        Ok((page.items, page.next))
    }

    /// [`Self::list_history_filtered`] with a time budget for body searches
    /// (`request:` and `response:` terms). A body search that runs past
    /// `budget` stops and returns the rows it matched, with
    /// [`HistoryPage::searched_back_to`] set and `next` continuing it.
    pub async fn search_history(
        &self,
        project_id: ProjectId,
        filter: Option<FilterNode>,
        limit: u32,
        before_started: Option<String>,
        before_id: Option<i64>,
        budget: Option<std::time::Duration>,
    ) -> DomainResult<HistoryPage> {
        let limit = limit.clamp(1, 500) as usize;
        // A filter that names its exchange ids is bounded by the primary key.
        let budget = budget.filter(|_| {
            filter
                .as_ref()
                .is_some_and(|filter| uses_body_search(filter) && !pins_exchange_id(filter))
        });
        let (filter_sql, filter_binds) = match filter {
            Some(filter) => filter_to_sql(&filter)?,
            None => ("1=1".into(), Vec::new()),
        };
        self.with_conn(move |conn| {
            let scope = BodySearchScope::begin(budget);
            let mut bind_values: Vec<Value> = filter_binds.into_iter().map(Value::Text).collect();
            let project_idx = bind_values.len() + 1;
            bind_values.push(Value::Integer(project_id.get()));
            let mut where_sql = format!("project_id=?{project_idx}");
            if let (Some(started_at), Some(exchange_id)) = (before_started, before_id) {
                let started_idx = bind_values.len() + 1;
                bind_values.push(Value::Text(started_at));
                let exchange_idx = bind_values.len() + 1;
                bind_values.push(Value::Integer(exchange_id));
                where_sql.push_str(&format!(
                    " AND (started_at < ?{started_idx} OR (started_at = ?{started_idx} AND exchange_id < ?{exchange_idx}))"
                ));
            }
            // A budgeted search walks the started_at index newest first, so
            // the rows it reaches before it stops are exactly the newest ones.
            // SQLite checks terms without subqueries first, in order, so the
            // budget is checked on every row after the cursor, from index
            // columns alone, before any filter term reads the row. Once it
            // has stopped, the rest of the scan reads only index entries.
            let mut from = "exchanges";
            if budget.is_some() {
                from = "exchanges INDEXED BY idx_exchanges_started";
                where_sql.push_str(" AND huntproxy_search_open(started_at)");
            }
            where_sql.push_str(&format!(" AND ({filter_sql})"));
            let limit_idx = bind_values.len() + 1;
            bind_values.push(Value::Integer((limit + 1) as i64));
            let sql = format!(
                "SELECT {HISTORY_COLUMNS} FROM {from} WHERE {where_sql} ORDER BY started_at DESC, exchange_id DESC LIMIT ?{limit_idx}"
            );
            let mut stmt = conn.prepare(&sql).map_err(storage_error)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(bind_values.iter()), |row| {
                    raw_summary(project_id, row)
                })
                .map_err(storage_error)?;
            let items = collect_rows(rows)?;
            let stopped_at = scope.stopped_at();
            drop(scope);
            let mut page = history_page(items, limit, stopped_at);
            for item in &mut page.items {
                item.labels = load_labels_conn(conn, project_id, item.exchange_id)?;
            }
            Ok(page)
        })
        .await
    }

    pub async fn count_history_filtered(
        &self,
        project_id: ProjectId,
        filter: Option<FilterNode>,
    ) -> DomainResult<u64> {
        let (filter_sql, filter_binds) = match filter {
            Some(filter) => filter_to_sql(&filter)?,
            None => ("1=1".into(), Vec::new()),
        };
        self.with_conn(move |conn| {
            let mut bind_values: Vec<Value> = filter_binds.into_iter().map(Value::Text).collect();
            let project_idx = bind_values.len() + 1;
            bind_values.push(Value::Integer(project_id.get()));
            let sql = format!(
                "SELECT COUNT(*) FROM exchanges WHERE ({filter_sql}) AND project_id=?{project_idx}"
            );
            let count = conn
                .query_row(
                    &sql,
                    rusqlite::params_from_iter(bind_values.iter()),
                    |row| row.get::<_, i64>(0),
                )
                .map_err(storage_error)?;
            u64::try_from(count)
                .map_err(|_| DomainError::new(ErrorCode::StorageError, "negative history count"))
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
                mut summary,
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
            summary.labels = load_labels_conn(conn, project_id, exchange_id)?;
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

/// Cursor id that continues a stopped search at the start of its
/// `started_at`: above any exchange id, and exact as a JavaScript number
/// (2^53 - 1), so clients that parse JSON numbers as doubles send it back
/// unchanged.
pub const STOPPED_SEARCH_CURSOR_ID: i64 = (1 << 53) - 1;

/// One page from up to `limit + 1` rows in page order. `stopped_at` is the
/// `started_at` where a budgeted search stopped, if it did.
fn history_page(
    mut items: Vec<ExchangeSummary>,
    limit: usize,
    stopped_at: Option<String>,
) -> HistoryPage {
    let has_more = items.len() > limit;
    // A full page is exact when the search stopped at a time older than its
    // last row: every row at or above that row's time was searched. Rows
    // sharing one started_at are read in rowid order, not page order, so
    // when it stopped within that time a refused row could belong on this
    // page; the stop then wins.
    let searched_back_to = stopped_at
        .filter(|stopped_at| !has_more || parse_time(stopped_at) >= items[limit - 1].started_at);
    items.truncate(limit);
    let next = if let Some(stopped_at) = &searched_back_to {
        // Rows sharing the stopped row's time may not all have been
        // searched; the continuation, which starts at that time, returns
        // them instead.
        let stopped = parse_time(stopped_at);
        items.retain(|item| item.started_at != stopped);
        Some((stopped_at.clone(), STOPPED_SEARCH_CURSOR_ID))
    } else {
        has_more.then(|| {
            let last = items.last().expect("history overflow must contain an item");
            let started_at = last
                .started_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            (started_at, last.exchange_id.get())
        })
    };
    HistoryPage {
        items,
        next,
        searched_back_to,
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

fn raw_summary(
    project_id: ProjectId,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ExchangeSummary> {
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

/// The text between `://` and the path or query of `url`: the only stored
/// `authority` whose `scheme://authority/path?query` can equal `url`.
fn url_authority(url: &str) -> Option<&str> {
    let rest = &url[url.find("://")? + 3..];
    Some(&rest[..rest.find(['/', '?']).unwrap_or(rest.len())])
}

/// Saved URLs among `?{authorities+2}..` hosts that equal one of the URLs
/// after them. Matching the authorities first lets SQLite use
/// `idx_exchanges_authority` instead of rebuilding every saved URL.
fn uncaptured_urls_sql(authorities: usize, urls: usize) -> String {
    let placeholders = |from: usize, count: usize| {
        (from..from + count)
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "SELECT scheme || '://' || authority || path ||
                CASE WHEN query IS NULL OR query='' THEN '' ELSE '?' || query END
           FROM exchanges
          WHERE project_id=?1 AND authority IN ({}) AND
                (scheme || '://' || authority || path ||
                 CASE WHEN query IS NULL OR query='' THEN '' ELSE '?' || query END)
                IN ({})",
        placeholders(2, authorities),
        placeholders(2 + authorities, urls)
    )
}

pub fn insert_exchange_conn(
    conn: &rusqlite::Connection,
    ex: NewExchange,
) -> DomainResult<ExchangeId> {
    let request_body = ex
        .request_body
        .as_deref()
        .map(|body| store_body_conn(conn, body, None))
        .transpose()?;
    let response_body = ex
        .response_body
        .as_deref()
        .map(|body| store_body_conn(conn, body, ex.mime.as_deref()))
        .transpose()?;
    insert_exchange_record_conn(conn, ex, request_body, response_body)
}

/// Exchanges are saved when capture finishes, so the real start is the save
/// time minus the measured duration (the save time when the duration is unknown).
fn exchange_started_at(duration_ms: Option<i64>) -> String {
    let started =
        OffsetDateTime::now_utc() - Duration::milliseconds(duration_ms.unwrap_or(0).max(0));
    started
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| now_rfc3339())
}

fn insert_exchange_record_conn(
    conn: &rusqlite::Connection,
    ex: NewExchange,
    request_body: Option<StoredBody>,
    response_body: Option<StoredBody>,
) -> DomainResult<ExchangeId> {
    enforce_project_disk_quota(
        conn,
        &ex,
        request_body.as_ref().map(|body| body.original_length),
        response_body.as_ref().map(|body| body.original_length),
    )?;
    let exchange_id = alloc_exchange_id(conn, ex.project_id)?;
    let started = exchange_started_at(ex.duration_ms);
    let (req_body_id, req_hash, req_len) = match request_body {
        Some(stored) => (
            Some(stored.id.get()),
            Some(stored.sha256),
            Some(stored.original_length),
        ),
        None => (None, None, None),
    };
    let (resp_body_id, resp_hash, resp_len) = match response_body {
        Some(stored) => (
            Some(stored.id.get()),
            Some(stored.sha256),
            Some(stored.original_length),
        ),
        None => (None, None, None),
    };

    crate::storage::cached_execute(
        conn,
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

    insert_headers_conn(
        conn,
        ex.project_id.get(),
        exchange_id.get(),
        "request",
        &ex.request_headers,
    )?;
    insert_headers_conn(
        conn,
        ex.project_id.get(),
        exchange_id.get(),
        "response",
        &ex.response_headers,
    )?;

    let request_bytes = nonnegative_length(req_len);
    let response_bytes = nonnegative_length(resp_len);
    let header_bytes =
        ex.request_headers
            .iter()
            .chain(&ex.response_headers)
            .fold(0_u64, |total, header| {
                total
                    .saturating_add(header.name.len() as u64)
                    .saturating_add(header.value.len() as u64)
            });
    let accounted_bytes = estimated_exchange_bytes(&ex, req_len, resp_len);
    let changed = crate::storage::cached_execute(
        conn,
        "UPDATE project_usage SET
            exchange_count=exchange_count+1,
            request_body_bytes=request_body_bytes+?1,
            response_body_bytes=response_body_bytes+?2,
            header_bytes=header_bytes+?3,
            accounted_bytes=accounted_bytes+?4,
            updated_at=?5
         WHERE project_id=?6",
        params![
            as_i64(request_bytes),
            as_i64(response_bytes),
            as_i64(header_bytes),
            as_i64(accounted_bytes),
            now_rfc3339(),
            ex.project_id.get(),
        ],
    )
    .map_err(storage_error)?;
    if changed != 1 {
        return Err(DomainError::new(
            ErrorCode::StorageError,
            "project usage counter missing; run `HuntProxy project reconcile`",
        ));
    }

    Ok(exchange_id)
}

fn enforce_project_disk_quota(
    conn: &rusqlite::Connection,
    ex: &NewExchange,
    request_length: Option<i64>,
    response_length: Option<i64>,
) -> DomainResult<()> {
    let (limits_json, current_usage): (String, i64) = crate::storage::cached_query_row(
        conn,
        "SELECT p.limits_json, u.accounted_bytes
         FROM projects p JOIN project_usage u ON u.project_id=p.id
         WHERE p.id=?1",
        params![ex.project_id.get()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .map_err(|error| match error {
        rusqlite::Error::QueryReturnedNoRows => {
            crate::storage::lifecycle::missing_usage_or_project(conn, ex.project_id)
        }
        other => storage_error(other),
    })?;
    let limits: ProjectLimits = serde_json::from_str(&limits_json).map_err(|error| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("invalid project limits: {error}"),
        )
    })?;

    let current_usage = u64::try_from(current_usage).unwrap_or(u64::MAX);
    let incoming_usage = estimated_exchange_bytes(ex, request_length, response_length);
    let projected_usage = current_usage.saturating_add(incoming_usage);
    if projected_usage > limits.max_disk_bytes {
        return Err(DomainError::with_details(
            ErrorCode::DiskQuotaExceeded,
            format!(
                "project capture quota exceeded: projected {projected_usage} logical bytes exceeds the {:.2} GiB limit ({} bytes); export evidence or clear older History before capturing more",
                limits.max_disk_bytes as f64 / (1024_f64 * 1024_f64 * 1024_f64),
                limits.max_disk_bytes,
            ),
            serde_json::json!({
                "current_bytes": current_usage,
                "incoming_bytes": incoming_usage,
                "projected_bytes": projected_usage,
                "max_disk_bytes": limits.max_disk_bytes,
                "quota_basis": "logical_capture_bytes",
                "action": "export evidence or clear older History before capturing more",
            }),
        ));
    }
    Ok(())
}

fn estimated_exchange_bytes(
    ex: &NewExchange,
    request_length: Option<i64>,
    response_length: Option<i64>,
) -> u64 {
    let mut total = EXCHANGE_ACCOUNTING_OVERHEAD
        .saturating_add(nonnegative_length(request_length))
        .saturating_add(nonnegative_length(response_length));
    for value in [
        Some(ex.protocol.as_str()),
        Some(ex.method.as_str()),
        Some(ex.scheme.as_str()),
        Some(ex.authority.as_str()),
        Some(ex.host.as_str()),
        Some(ex.path.as_str()),
        ex.query.as_deref(),
        ex.mime.as_deref(),
        ex.transport_profile.as_deref(),
        ex.page_title.as_deref(),
        ex.error_message.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        total = total.saturating_add(value.len() as u64);
    }
    for header in ex.request_headers.iter().chain(&ex.response_headers) {
        total = total
            .saturating_add(HEADER_ACCOUNTING_OVERHEAD)
            .saturating_add(header.name.len() as u64)
            .saturating_add(header.value.len() as u64);
    }
    total
}

fn nonnegative_length(value: Option<i64>) -> u64 {
    value
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0)
}

fn as_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn alloc_exchange_id(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
) -> DomainResult<ExchangeId> {
    crate::storage::cached_execute(
        conn,
        "UPDATE project_seq SET next_exchange_id = next_exchange_id + 1 WHERE project_id=?1",
        params![project_id.get()],
    )
    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    let next: i64 = crate::storage::cached_query_row(
        conn,
        "SELECT next_exchange_id FROM project_seq WHERE project_id=?1",
        params![project_id.get()],
        |r| r.get(0),
    )
    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    Ok(ExchangeId(next - 1))
}

pub(crate) fn load_headers(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
    exchange_id: ExchangeId,
    side: &str,
) -> DomainResult<Vec<HeaderEntry>> {
    load_headers_conn(conn, project_id.get(), exchange_id.get(), side)
}

fn source_str(s: ExchangeSource) -> &'static str {
    match s {
        ExchangeSource::Browser => "browser",
        ExchangeSource::Reply => "reply",
        ExchangeSource::Fuzzer => "fuzzer",
        ExchangeSource::Plugin => "plugin",
        ExchangeSource::Proxy => "proxy",
        ExchangeSource::Imported => "imported",
    }
}
pub(crate) fn parse_source(s: &str) -> ExchangeSource {
    match s {
        "browser" => ExchangeSource::Browser,
        "reply" => ExchangeSource::Reply,
        "fuzzer" => ExchangeSource::Fuzzer,
        "plugin" => ExchangeSource::Plugin,
        "imported" => ExchangeSource::Imported,
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
pub(crate) fn parse_completion(s: &str) -> CompletionState {
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
        CaptureQuality::Mixed => "mixed",
        CaptureQuality::Semantic => "semantic",
        CaptureQuality::BrowserObserved => "browser_observed",
    }
}
pub(crate) fn parse_capture_quality(s: &str) -> CaptureQuality {
    match s {
        "wire_preserved" => CaptureQuality::WirePreserved,
        "mixed" => CaptureQuality::Mixed,
        "browser_observed" => CaptureQuality::BrowserObserved,
        _ => CaptureQuality::Semantic,
    }
}
fn header_rep_str(h: HeaderRepresentation) -> &'static str {
    match h {
        HeaderRepresentation::WirePreserved => "wire_preserved",
        HeaderRepresentation::Mixed => "mixed",
        HeaderRepresentation::Semantic => "semantic",
        HeaderRepresentation::BrowserObserved => "browser_observed",
    }
}
pub(crate) fn parse_header_rep(s: &str) -> HeaderRepresentation {
    match s {
        "wire_preserved" => HeaderRepresentation::WirePreserved,
        "mixed" => HeaderRepresentation::Mixed,
        "browser_observed" => HeaderRepresentation::BrowserObserved,
        _ => HeaderRepresentation::Semantic,
    }
}
fn body_rep_str(b: BodyRepresentation) -> &'static str {
    match b {
        BodyRepresentation::WireEncoded => "wire_encoded",
        BodyRepresentation::Mixed => "mixed",
        BodyRepresentation::SemanticEncoded => "semantic_encoded",
        BodyRepresentation::BrowserDecoded => "browser_decoded",
        BodyRepresentation::Unavailable => "unavailable",
    }
}
pub(crate) fn parse_body_rep(s: &str) -> BodyRepresentation {
    match s {
        "wire_encoded" => BodyRepresentation::WireEncoded,
        "mixed" => BodyRepresentation::Mixed,
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
pub(crate) fn parse_cache_prov(s: &str) -> CacheProvenance {
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
        TransportProvenance::RequestRuleBlock => "request_rule_block",
    }
}
pub(crate) fn parse_transport_prov(s: &str) -> TransportProvenance {
    match s {
        "protocol_profile_only" => TransportProvenance::ProtocolProfileOnly,
        "identity_inconsistent" => TransportProvenance::IdentityInconsistent,
        "generic_unprofiled" => TransportProvenance::GenericUnprofiled,
        "chromium_wire_fidelity" => TransportProvenance::ChromiumWireFidelity,
        "request_rule_block" => TransportProvenance::RequestRuleBlock,
        _ => TransportProvenance::SemanticProxy,
    }
}

fn normalized_http_url(value: &str) -> DomainResult<url::Url> {
    let mut parsed = url::Url::parse(value.trim())
        .map_err(|error| DomainError::invalid(format!("invalid URL: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(DomainError::invalid(
            "URL must use http or https and have a host",
        ));
    }
    parsed.set_fragment(None);
    Ok(parsed)
}

fn normalized_join_http_url(base: &url::Url, value: &str) -> DomainResult<url::Url> {
    let mut parsed = base
        .join(value.trim())
        .map_err(|error| DomainError::invalid(format!("invalid relative URL: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(DomainError::invalid(
            "URL must use http or https and have a host",
        ));
    }
    parsed.set_fragment(None);
    Ok(parsed)
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn uncaptured_urls_are_found_through_the_authority_index() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "crawl".into(),
                target_url: "https://example.com/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        for (authority, path, query) in [
            ("example.com", "/app.js", None),
            ("example.com", "/", Some("q=1")),
            ("cdn.example.com:8443", "/lib.css", None),
        ] {
            db.insert_exchange(NewExchange {
                authority: authority.into(),
                host: authority.split(':').next().unwrap().into(),
                method: "GET".into(),
                path: path.into(),
                query: query.map(str::to_owned),
                ..spool_exchange(project.id)
            })
            .await
            .unwrap();
        }
        let urls = [
            "https://example.com/app.js",
            "https://example.com/?q=1",
            "https://example.com/?q=2",
            "https://cdn.example.com:8443/lib.css",
            "https://cdn.example.com/lib.css",
            "https://other.test/app.js",
            "not a url",
        ];
        let left = db
            .filter_uncaptured_urls(project.id, urls.iter().map(|url| url.to_string()).collect())
            .await
            .unwrap();
        assert_eq!(
            left,
            [
                "https://example.com/?q=2",
                "https://cdn.example.com/lib.css",
                "https://other.test/app.js",
                "not a url",
            ]
        );

        assert_eq!(url_authority("https://a.test:1/x?y"), Some("a.test:1"));
        assert_eq!(url_authority("https://a.test?y"), Some("a.test"));
        assert_eq!(url_authority("https://a.test"), Some("a.test"));
        assert_eq!(url_authority("a.test/x"), None);
        let plan = db
            .with_conn(|conn| {
                let mut statement = conn
                    .prepare(&format!("EXPLAIN QUERY PLAN {}", uncaptured_urls_sql(2, 3)))
                    .map_err(storage_error)?;
                let rows = statement
                    .query_map(params![1, "a", "b", "x", "y", "z"], |row| {
                        row.get::<_, String>(3)
                    })
                    .map_err(storage_error)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(storage_error)?;
                Ok(rows.join("\n"))
            })
            .await
            .unwrap();
        assert!(plan.contains("idx_exchanges_authority"), "{plan}");
    }

    #[test]
    fn mixed_evidence_representations_round_trip() {
        assert_eq!(capture_quality_str(CaptureQuality::Mixed), "mixed");
        assert_eq!(parse_capture_quality("mixed"), CaptureQuality::Mixed);
        assert_eq!(header_rep_str(HeaderRepresentation::Mixed), "mixed");
        assert_eq!(parse_header_rep("mixed"), HeaderRepresentation::Mixed);
        assert_eq!(body_rep_str(BodyRepresentation::Mixed), "mixed");
        assert_eq!(parse_body_rep("mixed"), BodyRepresentation::Mixed);
    }

    async fn storage_counts(db: &Db, project_id: ProjectId) -> (i64, i64, i64, i64) {
        db.with_conn(move |conn| {
            let exchanges = conn
                .query_row(
                    "SELECT COUNT(*) FROM exchanges WHERE project_id=?1",
                    params![project_id.get()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            let headers = conn
                .query_row(
                    "SELECT COUNT(*) FROM message_headers WHERE project_id=?1",
                    params![project_id.get()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            let bodies = conn
                .query_row("SELECT COUNT(*) FROM bodies", [], |row| row.get(0))
                .map_err(storage_error)?;
            let next_exchange_id = conn
                .query_row(
                    "SELECT next_exchange_id FROM project_seq WHERE project_id=?1",
                    params![project_id.get()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            Ok((exchanges, headers, bodies, next_exchange_id))
        })
        .await
        .unwrap()
    }

    fn spool_exchange(project_id: ProjectId) -> NewExchange {
        NewExchange {
            project_id,
            source: ExchangeSource::Proxy,
            protocol: "HTTP/2".into(),
            method: "POST".into(),
            scheme: "https".into(),
            authority: "example.com".into(),
            host: "example.com".into(),
            port: 443,
            path: "/upload".into(),
            query: None,
            status_code: Some(200),
            mime: Some("application/octet-stream".into()),
            completion: CompletionState::Complete,
            capture_quality: CaptureQuality::Semantic,
            header_representation: HeaderRepresentation::Semantic,
            body_representation: BodyRepresentation::SemanticEncoded,
            cache_provenance: CacheProvenance::None,
            transport_provenance: Some(TransportProvenance::ProtocolProfileOnly),
            transport_profile: Some("test".into()),
            request_headers: vec![],
            response_headers: vec![],
            request_body: None,
            response_body: None,
            duration_ms: Some(12),
            lineage: ExchangeLineage::default(),
            page_title: None,
            error_message: None,
        }
    }

    #[tokio::test]
    async fn started_at_is_save_time_minus_duration() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "started".into(),
                target_url: "https://example.com/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let mut slow = spool_exchange(project.id);
        slow.duration_ms = Some(90_000);
        let mut unknown = spool_exchange(project.id);
        unknown.duration_ms = None;
        let before = OffsetDateTime::now_utc();
        db.insert_exchange(slow).await.unwrap();
        db.insert_exchange(unknown).await.unwrap();
        let after = OffsetDateTime::now_utc();

        let (items, _) = db.list_history(project.id, 10, None, None).await.unwrap();
        let started = |id: i64| {
            items
                .iter()
                .find(|item| item.exchange_id.get() == id)
                .unwrap()
                .started_at
        };
        assert!(started(1) <= after - Duration::seconds(89));
        assert!(started(1) >= before - Duration::seconds(91));
        assert!(started(2) >= before - Duration::seconds(1) && started(2) <= after);
        // History is ordered by real start, so the long request sorts first-seen last.
        assert_eq!(items[0].exchange_id.get(), 2);
    }

    #[tokio::test]
    async fn javascript_files_are_deduplicated_and_safely_filtered() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "javascript files".into(),
                target_url: "https://target.test/".into(),
                advanced: None,
            })
            .await
            .unwrap();

        for (host, path, query, mime, browser_session_id) in [
            ("target.test", "/app.js", Some("v=1"), None, Some(7)),
            ("target.test", "/app.js", Some("v=1"), None, Some(7)),
            (
                "cdn.target.test",
                "/loader",
                None,
                Some("application/javascript; charset=utf-8"),
                Some(7),
            ),
            ("target.test", "/module.mjs", None, None, None),
            ("target.test", "/bundle.cjs", None, None, None),
            (
                "target.test",
                "/app.js.map",
                None,
                Some("application/json"),
                None,
            ),
            ("eviltarget.test", "/evil.js", None, None, Some(7)),
        ] {
            let mut exchange = spool_exchange(project.id);
            exchange.method = "GET".into();
            exchange.host = host.into();
            exchange.authority = host.into();
            exchange.path = path.into();
            exchange.query = query.map(str::to_string);
            exchange.mime = mime.map(str::to_string);
            exchange.lineage.browser_session_id = browser_session_id.map(BrowserSessionId);
            db.insert_exchange(exchange).await.unwrap();
        }

        let (history, truncated) = db
            .list_javascript_files(project.id, None, Some("target.test".into()), 20)
            .await
            .unwrap();
        assert!(!truncated);
        assert_eq!(history.len(), 4);
        assert!(history.iter().any(|file| file.url.ends_with("/app.js?v=1")));
        assert!(history.iter().any(|file| file.path == "/loader"));
        assert!(history.iter().all(|file| file.host != "eviltarget.test"));
        assert!(history.iter().all(|file| file.path != "/app.js.map"));

        let (session, _) = db
            .list_javascript_files(
                project.id,
                Some(BrowserSessionId(7)),
                Some("target.test".into()),
                20,
            )
            .await
            .unwrap();
        assert_eq!(session.len(), 2);

        let (limited, truncated) = db
            .list_javascript_files(project.id, None, Some("target.test".into()), 1)
            .await
            .unwrap();
        assert_eq!(limited.len(), 1);
        assert!(truncated);
    }

    #[tokio::test]
    async fn javascript_provenance_ties_cross_origin_and_relative_files_to_page_host() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "javascript provenance".into(),
                target_url: "https://target.test/".into(),
                advanced: None,
            })
            .await
            .unwrap();

        db.record_javascript_files(
            project.id,
            "https://target.test/products/one#section",
            vec![
                JavascriptProvenanceInput {
                    url: "https://assets.cdn.test/app.js?v=1#ignored".into(),
                    source_page_url: Some("https://shop.target.test/cart#total".into()),
                },
                JavascriptProvenanceInput {
                    url: "/static/local.js#ignored".into(),
                    source_page_url: None,
                },
                JavascriptProvenanceInput {
                    url: "data:text/javascript,ignored".into(),
                    source_page_url: None,
                },
            ],
            Some(BrowserSessionId(11)),
            "source",
        )
        .await
        .unwrap();

        let (target_files, truncated) = db
            .list_javascript_files(project.id, None, Some("target.test".into()), 20)
            .await
            .unwrap();
        assert!(!truncated);
        assert_eq!(target_files.len(), 2);
        assert!(target_files.iter().all(|file| file.exchange_id.is_none()));
        assert!(target_files
            .iter()
            .any(|file| file.url == "https://assets.cdn.test/app.js?v=1"));
        assert!(target_files
            .iter()
            .any(|file| file.url == "https://target.test/static/local.js"));

        let cdn = target_files
            .iter()
            .find(|file| file.host == "assets.cdn.test")
            .unwrap();
        assert_eq!(cdn.related_page_hosts, vec!["shop.target.test"]);
        assert_eq!(cdn.related_page_urls, vec!["https://shop.target.test/cart"]);

        let (session_files, _) = db
            .list_javascript_files(
                project.id,
                Some(BrowserSessionId(11)),
                Some("target.test".into()),
                20,
            )
            .await
            .unwrap();
        assert_eq!(session_files.len(), 2);
    }

    #[tokio::test]
    async fn javascript_provenance_includes_nested_session_files_without_unrelated_sessions() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "nested javascript provenance".into(),
                target_url: "https://target.test/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        for (url, page, session) in [
            (
                "https://cdn.vendor.test/main.js",
                "https://app.target.test/home",
                Some(11),
            ),
            (
                "https://cdn.vendor.test/nested.js",
                "https://frames.vendor.test/inner",
                Some(11),
            ),
            (
                "https://target.test/helper.js",
                "https://outer.partner.test/frame",
                Some(22),
            ),
            (
                "https://cdn.vendor.test/source-only.js",
                "https://frames.vendor.test/deeper",
                Some(22),
            ),
            (
                "https://cdn.vendor.test/unrelated.js",
                "https://other.test/home",
                Some(33),
            ),
            (
                "https://cdn.vendor.test/unsessioned.js",
                "https://frames.vendor.test/inner",
                None,
            ),
            (
                "https://cdn.vendor.test/direct.js",
                "https://target.test/start",
                None,
            ),
            (
                "https://target.test/local.js",
                "https://other.test/home",
                None,
            ),
            (
                "https://cdn.vendor.test/near-match.js",
                "https://eviltarget.test/home",
                Some(44),
            ),
        ] {
            db.record_javascript_files(
                project.id,
                page,
                vec![JavascriptProvenanceInput {
                    url: url.into(),
                    source_page_url: None,
                }],
                session.map(BrowserSessionId),
                "browser",
            )
            .await
            .unwrap();
        }
        let mut captured = spool_exchange(project.id);
        captured.host = "cdn.vendor.test".into();
        captured.authority = captured.host.clone();
        captured.path = "/nested.js".into();
        captured.mime = Some("application/javascript".into());
        captured.lineage.browser_session_id = Some(BrowserSessionId(11));
        let target_exchange_id = db.insert_exchange(captured.clone()).await.unwrap();
        captured.lineage.browser_session_id = Some(BrowserSessionId(33));
        db.insert_exchange(captured.clone()).await.unwrap();
        captured.lineage.browser_session_id = None;
        db.insert_exchange(captured).await.unwrap();

        let (files, truncated) = db
            .list_javascript_files(project.id, None, Some("target.test".into()), 20)
            .await
            .unwrap();
        assert!(!truncated);
        assert_eq!(files.len(), 6);
        let nested = files.iter().find(|file| file.path == "/nested.js").unwrap();
        assert_eq!(nested.exchange_id, Some(target_exchange_id));
        assert_eq!(
            nested.related_page_urls,
            ["https://frames.vendor.test/inner"]
        );
        assert!(nested.related_via_session);
        let discovered = files
            .iter()
            .find(|file| file.path == "/source-only.js")
            .unwrap();
        assert!(discovered.exchange_id.is_none());
        assert!(discovered.related_via_session);
        for file in &files {
            assert_eq!(
                file.related_via_session,
                matches!(file.path.as_str(), "/nested.js" | "/source-only.js")
            );
        }
        let (session, _) = db
            .list_javascript_files(
                project.id,
                Some(BrowserSessionId(11)),
                Some("target.test".into()),
                20,
            )
            .await
            .unwrap();
        assert_eq!(session.len(), 2);
        let (unrelated, _) = db
            .list_javascript_files(
                project.id,
                Some(BrowserSessionId(33)),
                Some("target.test".into()),
                20,
            )
            .await
            .unwrap();
        assert!(unrelated.is_empty());
        let (unfiltered, _) = db
            .list_javascript_files(project.id, None, None, 20)
            .await
            .unwrap();
        assert!(unfiltered.iter().all(|file| !file.related_via_session));
        assert!(unfiltered.iter().any(|file| file.path == "/unsessioned.js"));
        let (limited, truncated) = db
            .list_javascript_files(project.id, None, Some("target.test".into()), 1)
            .await
            .unwrap();
        assert_eq!(limited.len(), 1);
        assert!(truncated);
    }

    #[tokio::test]
    async fn target_document_anchors_nested_javascript_without_direct_javascript_provenance() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "document session provenance".into(),
                target_url: "https://target.test/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let mut document = spool_exchange(project.id);
        document.method = "GET".into();
        document.host = "app.target.test".into();
        document.authority = document.host.clone();
        document.path = "/home".into();
        document.mime = Some("text/html".into());
        document.lineage.browser_session_id = Some(BrowserSessionId(17));
        db.insert_exchange(document).await.unwrap();
        for (path, session) in [("/nested.js", 17), ("/other.js", 18)] {
            db.record_javascript_files(
                project.id,
                "https://frames.vendor.test/inner",
                vec![JavascriptProvenanceInput {
                    url: format!("https://cdn.vendor.test{path}"),
                    source_page_url: None,
                }],
                Some(BrowserSessionId(session)),
                "browser",
            )
            .await
            .unwrap();
        }
        let (files, truncated) = db
            .list_javascript_files(project.id, None, Some("target.test".into()), 20)
            .await
            .unwrap();
        assert!(!truncated);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].url, "https://cdn.vendor.test/nested.js");
        assert_eq!(
            files[0].related_page_urls,
            ["https://frames.vendor.test/inner"]
        );
        assert!(files[0].related_via_session);
    }

    #[tokio::test]
    async fn javascript_provenance_rejects_unknown_discovery_kind() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "javascript provenance validation".into(),
                target_url: "https://target.test/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let error = db
            .record_javascript_files(project.id, "https://target.test/", vec![], None, "unknown")
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn history_request_contains_searches_headers_and_compressed_bodies() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "request search".into(),
                target_url: "https://example.com/".into(),
                advanced: None,
            })
            .await
            .unwrap();

        let mut body_match = spool_exchange(project.id);
        body_match.method = "PUT".into();
        body_match.path = "/body".into();
        body_match.request_body = Some(format!("this{}", "x".repeat(2048)).into_bytes());
        let body_id = db.insert_exchange(body_match).await.unwrap();

        let mut header_match = spool_exchange(project.id);
        header_match.method = "PUT".into();
        header_match.path = "/header".into();
        header_match.request_headers = vec![HeaderEntry {
            name: "X-Test".into(),
            value: b"that".to_vec(),
            ordinal: 0,
        }];
        let header_id = db.insert_exchange(header_match).await.unwrap();

        let mut wrong_method = spool_exchange(project.id);
        wrong_method.method = "GET".into();
        wrong_method.path = "/:smtg".into();
        db.insert_exchange(wrong_method).await.unwrap();

        let filter = crate::history::parse_text_query(
            r#"(request:~this OR request:~that OR request:~":smtg") method:PUT"#,
        )
        .unwrap();
        let (items, next) = db
            .list_history_filtered(project.id, Some(filter), 20, None, None)
            .await
            .unwrap();
        assert!(next.is_none());
        let ids = items
            .into_iter()
            .map(|item| item.exchange_id)
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&body_id));
        assert!(ids.contains(&header_id));

        // Header names match too, and only on the side searched.
        for (query, expected) in [
            ("request:~x-tes", vec![header_id]),
            ("response:~that", vec![]),
            ("response:~X-Test", vec![]),
        ] {
            let filter = crate::history::parse_text_query(query).unwrap();
            let (items, _) = db
                .list_history_filtered(project.id, Some(filter), 20, None, None)
                .await
                .unwrap();
            let ids = items
                .into_iter()
                .map(|item| item.exchange_id)
                .collect::<Vec<_>>();
            assert_eq!(ids, expected, "{query}");
        }
    }

    #[tokio::test]
    async fn history_body_search_reads_through_content_encoding() {
        use std::io::Write;
        let gzip = |text: &[u8]| {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(text).unwrap();
            encoder.finish().unwrap()
        };
        let brotli = |text: &[u8]| {
            let mut output = Vec::new();
            let mut writer = brotli::CompressorWriter::new(&mut output, 4096, 5, 22);
            writer.write_all(text).unwrap();
            drop(writer);
            output
        };
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "encoded search".into(),
                target_url: "https://example.com/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let insert = |path: &str, encodings: &[&str], body: Vec<u8>| {
            let mut exchange = spool_exchange(project.id);
            exchange.path = path.into();
            exchange.response_headers = encodings
                .iter()
                .enumerate()
                .map(|(ordinal, encoding)| HeaderEntry {
                    name: if ordinal == 0 {
                        "Content-Encoding".into()
                    } else {
                        "content-encoding".into()
                    },
                    value: encoding.as_bytes().to_vec(),
                    ordinal: ordinal as u32,
                })
                .collect();
            exchange.response_body = Some(body);
            let db = db.clone();
            async move { db.insert_exchange(exchange).await.unwrap() }
        };
        let gzipped = insert("/gzip", &["gzip"], gzip(b"<p>Secret-In-Gzip</p>")).await;
        let brotlied = insert("/br", &["br"], brotli(b"{\"k\":\"secret-in-br\"}")).await;
        // gzip applied first, then br, in two headers.
        let chained = insert("/chain", &["gzip", "br"], brotli(&gzip(b"chained-secret"))).await;
        // Claims gzip but is not: searched as stored instead of failing the query.
        let mislabelled = insert("/plain", &["gzip"], b"needle-plain".to_vec()).await;
        let unencoded = insert("/raw", &[], b"needle-raw".to_vec()).await;

        for (query, expected) in [
            ("response:~secret-in-gzip", vec![gzipped]),
            ("response:~secret-in-br", vec![brotlied]),
            ("response:~chained-secret", vec![chained]),
            ("response:~needle-plain", vec![mislabelled]),
            ("response:~needle-raw", vec![unencoded]),
            ("request:~secret-in-gzip", vec![]),
        ] {
            let filter = crate::history::parse_text_query(query).unwrap();
            let (items, _) = db
                .list_history_filtered(project.id, Some(filter), 20, None, None)
                .await
                .unwrap();
            let ids = items
                .into_iter()
                .map(|item| item.exchange_id)
                .collect::<Vec<_>>();
            assert_eq!(ids, expected, "{query}");
        }
    }

    #[tokio::test]
    async fn a_body_search_out_of_budget_returns_the_newest_matches_and_continues() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "budgeted search".into(),
                target_url: "https://example.com/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        // Oldest first; the third and fourth share one started_at.
        let mut ids = Vec::new();
        for (index, body) in ["needle", "hay", "hay", "needle", "hay", "NEEDLE"]
            .into_iter()
            .enumerate()
        {
            let mut exchange = spool_exchange(project.id);
            exchange.path = format!("/{index}");
            exchange.response_body = Some(format!("{body} {index}").into_bytes());
            let id = db.insert_exchange(exchange).await.unwrap();
            let second = if index == 3 { 2 } else { index };
            let started_at = format!("2026-11-24T06:30:0{second}Z");
            db.with_conn(move |conn| {
                conn.execute(
                    "UPDATE exchanges SET started_at=?1 WHERE exchange_id=?2",
                    params![started_at, id.get()],
                )
                .map_err(storage_error)?;
                Ok(())
            })
            .await
            .unwrap();
            ids.push(id);
        }
        let filter = crate::history::parse_text_query("response:~needle").unwrap();
        let expected = vec![ids[5], ids[3], ids[0]];
        let unbudgeted = db
            .search_history(project.id, Some(filter.clone()), 50, None, None, None)
            .await
            .unwrap();
        assert_eq!(
            unbudgeted
                .items
                .iter()
                .map(|item| item.exchange_id)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(unbudgeted.searched_back_to.is_none() && unbudgeted.next.is_none());

        // A zero budget searches the rows at one started_at per call; the
        // continuations return every match exactly once, newest first.
        let mut seen = Vec::new();
        let mut stops = Vec::new();
        let mut cursor = (None, None);
        for _ in 0..10 {
            let page = db
                .search_history(
                    project.id,
                    Some(filter.clone()),
                    50,
                    cursor.0.clone(),
                    cursor.1,
                    Some(std::time::Duration::ZERO),
                )
                .await
                .unwrap();
            seen.extend(page.items.iter().map(|item| item.exchange_id));
            if let Some(stopped) = &page.searched_back_to {
                assert_eq!(page.next, Some((stopped.clone(), STOPPED_SEARCH_CURSOR_ID)));
                stops.push(stopped.clone());
            }
            match page.next {
                Some((started_at, id)) => cursor = (Some(started_at), Some(id)),
                None => break,
            }
        }
        assert_eq!(seen, expected);
        assert_eq!(
            stops,
            [
                "2026-11-24T06:30:04Z",
                "2026-11-24T06:30:02Z",
                "2026-11-24T06:30:01Z",
                "2026-11-24T06:30:00Z",
            ]
        );

        // Within the budget a page ends as it always did.
        let page = db
            .search_history(
                project.id,
                Some(filter.clone()),
                1,
                None,
                None,
                Some(std::time::Duration::from_secs(60)),
            )
            .await
            .unwrap();
        assert!(page.searched_back_to.is_none());
        assert_eq!(page.items[0].exchange_id, ids[5]);
        assert_eq!(
            page.next,
            Some(("2026-11-24T06:30:05Z".into(), ids[5].get()))
        );

        // Searches without a body term have no budget.
        let filter = crate::history::parse_text_query("path:/1").unwrap();
        let page = db
            .search_history(
                project.id,
                Some(filter),
                50,
                None,
                None,
                Some(std::time::Duration::ZERO),
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert!(page.searched_back_to.is_none());

        // The budget is checked on rows a plain term rejects too, so a
        // selective filter cannot walk the whole project past it.
        let search = |q: String| {
            let db = db.clone();
            async move {
                db.search_history(
                    project.id,
                    Some(crate::history::parse_text_query(&q).unwrap()),
                    50,
                    None,
                    None,
                    Some(std::time::Duration::ZERO),
                )
                .await
                .unwrap()
            }
        };
        let page = search("path:/0 response:~needle".into()).await;
        assert!(page.items.is_empty());
        assert_eq!(
            page.searched_back_to.as_deref(),
            Some("2026-11-24T06:30:04Z")
        );
        // A filter that names its exchange id uses the key and no budget.
        let page = search(format!("exchange_id:{} response:~needle", ids[0].get())).await;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].exchange_id, ids[0]);
        assert!(page.searched_back_to.is_none() && page.next.is_none());
    }

    #[test]
    fn a_page_that_ends_where_the_search_stopped_is_partial() {
        let row = |id: i64, started_at: &str| ExchangeSummary {
            project_id: ProjectId(1),
            exchange_id: ExchangeId(id),
            source: ExchangeSource::Proxy,
            started_at: parse_time(started_at),
            duration_ms: None,
            method: "GET".into(),
            scheme: "https".into(),
            authority: "example.com".into(),
            host: "example.com".into(),
            port: 443,
            path: "/".into(),
            query: None,
            status_code: None,
            mime: None,
            request_length: None,
            response_length: None,
            completion: CompletionState::Complete,
            capture_quality: CaptureQuality::Semantic,
            page_title: None,
            display_title: None,
            labels: Vec::new(),
            parent_exchange_id: None,
            transport_provenance: None,
        };
        let newer = "2026-11-24T06:30:01Z";
        let group = "2026-11-24T06:30:00Z";
        // Group ids 5, 10 and 20 were read in that order and the search
        // stopped before 20: a page of two ending at 10, with 5 as overflow,
        // must not hand out a cursor below 10 that skips 20.
        let page = history_page(
            vec![row(30, newer), row(10, group), row(5, group)],
            2,
            Some(group.into()),
        );
        assert_eq!(page.searched_back_to.as_deref(), Some(group));
        assert_eq!(
            page.items
                .iter()
                .map(|item| item.exchange_id.get())
                .collect::<Vec<_>>(),
            [30]
        );
        assert_eq!(page.next, Some((group.into(), STOPPED_SEARCH_CURSOR_ID)));
        // Stopped at a time older than the last row: the full page is exact.
        let page = history_page(
            vec![row(30, newer), row(10, newer), row(5, group)],
            2,
            Some(group.into()),
        );
        assert!(page.searched_back_to.is_none());
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.next, Some((newer.into(), 10)));
    }

    #[tokio::test]
    async fn a_budgeted_body_search_walks_the_started_at_index() {
        let db = Db::open_in_memory().await.unwrap();
        // The plan the budgeted query uses, for a body term with a filter
        // that has its own index: rows must come in started_at order, without
        // a sort of the whole result.
        let plan = db
            .with_conn(|conn| {
                let (filter_sql, binds) = filter_to_sql(
                    &crate::history::parse_text_query("method:GET response:~a OR request:~b")
                        .unwrap(),
                )?;
                let sql = format!(
                    "EXPLAIN QUERY PLAN SELECT {HISTORY_COLUMNS} FROM exchanges INDEXED BY idx_exchanges_started \
                     WHERE project_id=1 AND huntproxy_search_open(started_at) AND ({filter_sql}) \
                     ORDER BY started_at DESC, exchange_id DESC LIMIT 51"
                );
                let mut stmt = conn.prepare(&sql).map_err(storage_error)?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(binds.iter()), |row| {
                        row.get::<_, String>(3)
                    })
                    .map_err(storage_error)?;
                collect_rows(rows)
            })
            .await
            .unwrap();
        assert!(
            plan.iter()
                .any(|step| step.contains("USING INDEX idx_exchanges_started")),
            "{plan:?}"
        );
        assert!(
            !plan
                .iter()
                .any(|step| step == "USE TEMP B-TREE FOR ORDER BY"),
            "{plan:?}"
        );
    }

    #[tokio::test]
    async fn inserts_file_backed_bodies_without_loading_them_into_exchange() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "spool persistence".into(),
                target_url: "https://example.com/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let request_path = directory.path().join("request.spool");
        let response_path = directory.path().join("response.spool");
        let request_body = b"request-body-from-file";
        let response_body = vec![0x5a; 256 * 1024];
        std::fs::write(&request_path, request_body).unwrap();
        std::fs::write(&response_path, &response_body).unwrap();

        let exchange_id = db
            .insert_exchange_from_spools(
                spool_exchange(project.id),
                Some(request_path),
                Some(response_path),
            )
            .await
            .unwrap();

        assert_eq!(
            db.load_raw_body(project.id, exchange_id, MessageSide::Request)
                .await
                .unwrap()
                .unwrap(),
            request_body
        );
        assert_eq!(
            db.load_raw_body(project.id, exchange_id, MessageSide::Response)
                .await
                .unwrap()
                .unwrap(),
            response_body
        );
        let detail = db
            .get_exchange_detail(project.id, exchange_id, PresentationOptions::default())
            .await
            .unwrap();
        assert_eq!(
            detail.summary.request_length,
            Some(request_body.len() as i64)
        );
        assert_eq!(
            detail.summary.response_length,
            Some(response_body.len() as i64)
        );
    }

    #[tokio::test]
    async fn disk_quota_rejects_crossing_insert_and_rolls_back_all_artifacts() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "quota rollback".into(),
                target_url: "https://example.com/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let mut first = spool_exchange(project.id);
        first.source = ExchangeSource::Fuzzer;
        first.request_headers = vec![HeaderEntry {
            name: "content-type".into(),
            value: b"application/octet-stream".to_vec(),
            ordinal: 0,
        }];
        first.response_headers = vec![HeaderEntry {
            name: "x-result".into(),
            value: b"first".to_vec(),
            ordinal: 0,
        }];
        first.request_body = Some(vec![0x11; 128]);
        first.response_body = Some(vec![0x22; 96]);
        let quota = estimated_exchange_bytes(&first, Some(128), Some(96));
        let mut limits = project.limits.clone();
        limits.max_disk_bytes = quota;
        db.update_project_scope(project.id, project.scope.clone(), Some(limits))
            .await
            .unwrap();

        let first_id = db.insert_exchange(first).await.unwrap();
        assert_eq!(first_id.get(), 1);
        let before_rejection = storage_counts(&db, project.id).await;
        assert_eq!(before_rejection, (1, 2, 2, 2));

        let mut second = spool_exchange(project.id);
        second.source = ExchangeSource::Fuzzer;
        second.request_headers = vec![HeaderEntry {
            name: "content-type".into(),
            value: b"application/json".to_vec(),
            ordinal: 0,
        }];
        second.request_body = Some(vec![0x33; 64]);
        second.response_body = Some(vec![0x44; 64]);
        let error = db.insert_exchange(second).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::DiskQuotaExceeded);
        assert!(error.to_string().contains("logical bytes"));
        assert!(error.to_string().contains("GiB limit"));
        assert_eq!(storage_counts(&db, project.id).await, before_rejection);
    }

    #[tokio::test]
    async fn disk_quota_rejects_spool_insert_without_persisting_artifacts() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "spool quota rollback".into(),
                target_url: "https://example.com/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let mut limits = project.limits.clone();
        limits.max_disk_bytes = 1;
        db.update_project_scope(project.id, project.scope.clone(), Some(limits))
            .await
            .unwrap();

        let directory = tempfile::tempdir().unwrap();
        let request_path = directory.path().join("request.spool");
        let response_path = directory.path().join("response.spool");
        std::fs::write(&request_path, vec![0x55; 4096]).unwrap();
        std::fs::write(&response_path, vec![0x66; 4096]).unwrap();

        let error = db
            .insert_exchange_from_spools(
                spool_exchange(project.id),
                Some(request_path.clone()),
                Some(response_path.clone()),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::DiskQuotaExceeded);
        assert_eq!(storage_counts(&db, project.id).await, (0, 0, 0, 1));
        assert!(request_path.exists());
        assert!(response_path.exists());
    }

    #[tokio::test]
    async fn rendered_title_association_matches_session_url_and_html_only() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "titles".into(),
                target_url: "https://example.com/app?a=1".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let session = db
            .create_browser_session(project.id, Some("default".into()))
            .await
            .unwrap();
        let mut document = spool_exchange(project.id);
        document.host = "example.com".into();
        document.authority = "example.com".into();
        document.path = "/app".into();
        document.query = Some("a=1".into());
        document.mime = Some("text/html; charset=utf-8".into());
        document.lineage.browser_session_id = Some(session.id);
        let document_id = db.insert_exchange(document).await.unwrap();
        let mut asset = spool_exchange(project.id);
        asset.host = "example.com".into();
        asset.authority = "example.com".into();
        asset.path = "/app".into();
        asset.query = Some("a=1".into());
        asset.mime = Some("application/javascript".into());
        asset.lineage.browser_session_id = Some(session.id);
        let asset_id = db.insert_exchange(asset).await.unwrap();

        assert!(db
            .associate_browser_page_title(
                project.id,
                session.id,
                "https://example.com/app?a=1",
                "  Rendered   title ",
            )
            .await
            .unwrap());
        assert_eq!(
            db.get_exchange_detail(
                project.id,
                document_id,
                crate::policy::PresentationOptions::default(),
            )
            .await
            .unwrap()
            .summary
            .page_title
            .as_deref(),
            Some("Rendered title")
        );
        assert!(db
            .get_exchange_detail(
                project.id,
                asset_id,
                crate::policy::PresentationOptions::default(),
            )
            .await
            .unwrap()
            .summary
            .page_title
            .is_none());
    }
}
