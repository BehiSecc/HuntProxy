//! MCP presentation of history_search, js_files and sitemap: compact rows that
//! fit [`MAX_OUTPUT_BYTES`] by construction, with an exact continuation.

use super::budget::{json_len, rows_that_fit, MAX_OUTPUT_BYTES};
use super::view::exchange_row;
use super::{
    host_matches_domain, normalize_domain_filter, parse_history_cursor, require_project_id,
};
use crate::app::AppState;
use crate::domain::*;
use crate::history::{
    filter_to_text, parse_text_query, query_error, uses_body_search, validate_filter, FilterNode,
    HISTORY_QUERY_SYNTAX,
};
use serde_json::{json, Map, Value};

const DEFAULT_HISTORY_LIMIT: u64 = 50;
/// Top-level AND terms checked on their own when a search matches nothing.
const MAX_NO_MATCH_CHECKS: usize = 6;
/// How long one history_search call searches bodies before it returns what
/// it found so far.
const BODY_SEARCH_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
const PARTIAL_NOTE: &str = "Body search stopped after 10 s; exchanges newer than searched_back_to were searched. Pass next as cursor to continue, or narrow with host:, path: or time>=.";
/// Longer than any RFC 3339 timestamp, so the reserved `next` is an upper bound.
const LONGEST_STARTED_AT: &str = "0000-00-00T00:00:00.000000000+00:00:00";
/// The storage cap, requested on every js_files page so offsets index one stable list.
const MAX_JAVASCRIPT_FILES: u32 = 10_000;
const DEFAULT_JAVASCRIPT_LIMIT: u64 = 2_000;
/// Related page URLs listed per JavaScript file; `page_count` gives the total.
const MAX_LISTED_PAGES: usize = 3;

pub(super) async fn history_search(state: &AppState, args: &Value) -> DomainResult<Value> {
    search_with_budget(state, args, BODY_SEARCH_BUDGET).await
}

async fn search_with_budget(
    state: &AppState,
    args: &Value,
    budget: std::time::Duration,
) -> DomainResult<Value> {
    let project_id = require_project_id(args)?;
    let query = match args.get("q") {
        None => None,
        Some(Value::String(query)) => Some(query.as_str()),
        Some(_) => {
            return Err(query_error(format!(
                "history_search q must be a query string; omit q to list history. {HISTORY_QUERY_SYNTAX}"
            )))
        }
    };
    let filter = query
        .filter(|query| !query.trim().is_empty())
        .map(parse_text_query)
        .transpose()?;
    if let Some(filter) = &filter {
        validate_filter(filter)?;
    }
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_HISTORY_LIMIT)
        .clamp(1, 500) as u32;
    let (before_started, before_id) = parse_history_cursor(args.get("cursor"))?;
    let first_page = before_id.is_none();
    let page = state
        .db
        .search_history(
            project_id,
            filter.clone(),
            limit,
            before_started,
            before_id,
            Some(budget),
        )
        .await?;
    let items = page.items;
    let mut rows = items.iter().map(exchange_row).collect::<Vec<_>>();
    let mut envelope = json!({"items": [], "next": [LONGEST_STARTED_AT, i64::MAX]});
    if let Some(searched_back_to) = &page.searched_back_to {
        envelope["partial"] = json!(true);
        envelope["searched_back_to"] = json!(searched_back_to);
        envelope["note"] = json!(PARTIAL_NOTE);
    }
    let kept = rows_that_fit(&rows, MAX_OUTPUT_BYTES.saturating_sub(json_len(&envelope)))?;
    // `next` is exclusive, so the last row returned is the cursor whether the
    // page ended at `limit` or at the byte budget. A stopped body search
    // continues where it stopped.
    let next = if kept < rows.len() {
        Some(history_cursor(&items[kept - 1])?)
    } else {
        page.next
            .map(|(started_at, exchange_id)| json!([started_at, exchange_id]))
    };
    rows.truncate(kept);
    let mut result = Map::new();
    let no_rows = rows.is_empty();
    result.insert("items".into(), Value::Array(rows));
    if let Some(next) = next {
        result.insert("next".into(), next);
    }
    if let Some(searched_back_to) = page.searched_back_to {
        result.insert("partial".into(), json!(true));
        result.insert("searched_back_to".into(), json!(searched_back_to));
        result.insert("note".into(), json!(PARTIAL_NOTE));
    } else if let Some(filter) = filter.filter(|_| no_rows && first_page) {
        let terms = no_match_terms(state, project_id, &filter).await?;
        if !terms.is_empty() {
            result.insert("no_match_terms".into(), json!(terms));
        }
    }
    Ok(Value::Object(result))
}

/// The `[started_at, exchange_id]` cursor for the page after `summary`, in the
/// format `list_history_filtered` compares against.
fn history_cursor(summary: &ExchangeSummary) -> DomainResult<Value> {
    let started_at = summary
        .started_at
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| DomainError::Other(error.into()))?;
    Ok(json!([started_at, summary.exchange_id]))
}

/// Top-level terms of an AND query that match no exchange on their own, found
/// with single-row lookups. Body searches are skipped because each would scan
/// decoded bodies.
async fn no_match_terms(
    state: &AppState,
    project_id: ProjectId,
    filter: &FilterNode,
) -> DomainResult<Vec<String>> {
    let FilterNode::And { and: terms } = filter else {
        return Ok(Vec::new());
    };
    if terms.len() < 2 {
        return Ok(Vec::new());
    }
    let mut missing = Vec::new();
    for term in terms
        .iter()
        .filter(|term| !uses_body_search(term))
        .take(MAX_NO_MATCH_CHECKS)
    {
        let (items, _) = state
            .db
            .list_history_filtered(project_id, Some(term.clone()), 1, None, None)
            .await?;
        if items.is_empty() {
            missing.push(filter_to_text(term));
        }
    }
    Ok(missing)
}

/// One JavaScript file before presentation; history and page loads share it.
struct JavascriptFile {
    exchange_id: Option<ExchangeId>,
    url: String,
    mime: Option<String>,
    status_code: Option<u16>,
    pages: Vec<String>,
    related_via_session: bool,
}

fn javascript_row(file: JavascriptFile) -> Value {
    let mut row = Map::new();
    row.insert("url".into(), json!(file.url));
    if let Some(exchange_id) = file.exchange_id {
        row.insert("exchange_id".into(), json!(exchange_id));
    }
    if let Some(status_code) = file.status_code.filter(|status| *status != 200) {
        row.insert("status_code".into(), json!(status_code));
    }
    if let Some(mime) = file.mime {
        row.insert("mime".into(), json!(mime));
    }
    let mut pages = Vec::<String>::new();
    for page in file.pages {
        if !pages.contains(&page) {
            pages.push(page);
        }
    }
    if pages.len() > MAX_LISTED_PAGES {
        row.insert("page_count".into(), json!(pages.len()));
        pages.truncate(MAX_LISTED_PAGES);
    }
    if !pages.is_empty() {
        row.insert("pages".into(), json!(pages));
    }
    if file.related_via_session {
        row.insert("related_via_session".into(), json!(true));
    }
    Value::Object(row)
}

pub(super) async fn js_files(state: &AppState, args: &Value) -> DomainResult<Value> {
    let project_id = require_project_id(args)?;
    let domain = normalize_domain_filter(args.get("domain").and_then(Value::as_str))?;
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_JAVASCRIPT_LIMIT)
        .clamp(1, u64::from(MAX_JAVASCRIPT_FILES)) as usize;
    let offset = offset_arg(args);
    let mut envelope = Map::new();
    let files = if let Some(url) = args.get("url").and_then(Value::as_str) {
        let (session, mut files) = load_javascript_files(state, project_id, url, args).await?;
        if let Some(domain) = domain.as_deref() {
            files.retain(|file| {
                host_matches_domain(&file.host, domain)
                    || file
                        .source_page_url
                        .as_deref()
                        .and_then(page_host)
                        .is_some_and(|host| host_matches_domain(&host, domain))
            });
        }
        files.sort_by(|left, right| {
            left.url
                .to_ascii_lowercase()
                .cmp(&right.url.to_ascii_lowercase())
                .then_with(|| left.url.cmp(&right.url))
        });
        envelope.insert("source".into(), json!("load"));
        envelope.insert(
            "browser".into(),
            json!({"session_id": session.id, "engine": session.engine, "stopped": true}),
        );
        files
            .into_iter()
            .map(|file| JavascriptFile {
                exchange_id: None,
                url: file.url,
                mime: file.mime,
                status_code: file.status_code,
                pages: file.source_page_url.into_iter().collect(),
                related_via_session: false,
            })
            .collect::<Vec<_>>()
    } else {
        let (files, capped) = state
            .db
            .list_javascript_files(project_id, None, domain.clone(), MAX_JAVASCRIPT_FILES)
            .await?;
        envelope.insert("source".into(), json!("history"));
        if capped {
            envelope.insert("truncated".into(), json!(true));
        }
        files
            .into_iter()
            .map(|file| JavascriptFile {
                exchange_id: file.exchange_id,
                url: file.url,
                mime: file.mime,
                status_code: file.status_code,
                pages: file.related_page_urls,
                related_via_session: file.related_via_session,
            })
            .collect()
    };
    if let Some(domain) = domain {
        envelope.insert("domain".into(), json!(domain));
    }
    let rows = files.into_iter().map(javascript_row).collect();
    offset_page(envelope, "files", rows, offset, limit)
}

/// Loads `url` in a fresh browser session, collects its JavaScript files and
/// stops the session, reporting a stop failure only after a successful load.
async fn load_javascript_files(
    state: &AppState,
    project_id: ProjectId,
    url: &str,
    args: &Value,
) -> DomainResult<(BrowserSession, Vec<crate::browser::BrowserJavascriptFile>)> {
    let parsed = url::Url::parse(url)
        .map_err(|error| DomainError::invalid(format!("invalid load URL: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(DomainError::invalid(
            "load URL must be an absolute http or https URL",
        ));
    }
    let session = state
        .browser
        .start_ephemeral(project_id, url.to_string())
        .await?;
    let settle_ms = args
        .get("settle_ms")
        .and_then(Value::as_u64)
        .unwrap_or(2_000)
        .min(30_000);
    tokio::time::sleep(std::time::Duration::from_millis(settle_ms)).await;
    let files_result = state.browser.javascript_files(project_id, session.id).await;
    let stop_result = state.browser.stop(project_id, session.id).await;
    let files = files_result?;
    stop_result?;
    Ok((session, files))
}

fn page_host(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
}

pub(super) async fn sitemap(state: &AppState, args: &Value) -> DomainResult<Value> {
    let project_id = require_project_id(args)?;
    let text_arg = |name: &str| {
        args.get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    let host = text_arg("host");
    let path_prefix = text_arg("path_prefix");
    let offset = offset_arg(args);
    match host {
        Some(host) => {
            let routes = state
                .db
                .list_sitemap_subtree(project_id, Some(host), path_prefix)
                .await?
                .into_iter()
                .flat_map(|host| host.routes)
                .map(route_row)
                .collect();
            offset_page(Map::new(), "routes", routes, offset, usize::MAX)
        }
        None if path_prefix.is_some() => {
            Err(DomainError::invalid("sitemap path_prefix requires host"))
        }
        None => {
            let hosts = state
                .db
                .list_sitemap_hosts(project_id)
                .await?
                .iter()
                .map(|host| json!(host))
                .collect();
            offset_page(Map::new(), "hosts", hosts, offset, usize::MAX)
        }
    }
}

/// A route without empty lists, and with `exchange_count` only above one.
fn route_row(route: SitemapRoute) -> Value {
    let mut row = Map::new();
    row.insert("path".into(), json!(route.path));
    row.insert("methods".into(), json!(route.methods));
    if !route.status_codes.is_empty() {
        row.insert("status_codes".into(), json!(route.status_codes));
    }
    if !route.content_types.is_empty() {
        row.insert("content_types".into(), json!(route.content_types));
    }
    if !route.parameters.is_empty() {
        row.insert("parameters".into(), json!(route.parameters));
    }
    if route.exchange_count > 1 {
        row.insert("exchange_count".into(), json!(route.exchange_count));
    }
    Value::Object(row)
}

pub(super) fn offset_arg(args: &Value) -> usize {
    args.get("offset")
        .and_then(Value::as_u64)
        .map_or(0, |offset| usize::try_from(offset).unwrap_or(usize::MAX))
}

/// Adds `rows[offset..]` to `envelope` under `key`, cut to `limit` rows and to
/// the output budget. When rows remain, `total` and `next_offset` say how many
/// and where the next page starts.
pub(super) fn offset_page(
    mut envelope: Map<String, Value>,
    key: &str,
    rows: Vec<Value>,
    offset: usize,
    limit: usize,
) -> DomainResult<Value> {
    let total = rows.len();
    let start = offset.min(total);
    let mut page = rows.into_iter().skip(start).take(limit).collect::<Vec<_>>();
    let mut reserved = envelope.clone();
    reserved.insert(key.into(), json!([]));
    reserved.insert("total".into(), json!(u64::MAX));
    reserved.insert("next_offset".into(), json!(u64::MAX));
    let budget = MAX_OUTPUT_BYTES.saturating_sub(json_len(&Value::Object(reserved)));
    let kept = rows_that_fit(&page, budget)?;
    page.truncate(kept);
    let end = start + kept;
    envelope.insert(key.into(), Value::Array(page));
    if end < total {
        envelope.insert("total".into(), json!(total));
        envelope.insert("next_offset".into(), json!(end));
    }
    Ok(Value::Object(envelope))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(path: &str, count: u64) -> SitemapRoute {
        SitemapRoute {
            path: path.into(),
            methods: vec!["GET".into()],
            status_codes: Vec::new(),
            parameters: Vec::new(),
            content_types: Vec::new(),
            exchange_count: count,
        }
    }

    #[tokio::test]
    async fn a_stopped_body_search_says_so_and_continues_with_next() {
        let directory = tempfile::tempdir().unwrap();
        let state = crate::app::bootstrap_state(crate::config::Config {
            data_dir: directory.path().to_path_buf(),
            spool_dir: directory.path().join("spool"),
            export_dir: directory.path().join("exports"),
            runtime_dir: directory.path().join("runtime"),
            plugin_dir: directory.path().join("plugins"),
            ..crate::config::Config::default()
        })
        .await
        .unwrap();
        let project = state
            .db
            .create_project(CreateProjectRequest {
                name: "stopped search".into(),
                target_url: "https://example.com/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let mut ids = Vec::new();
        for body in ["needle one", "hay", "needle two"] {
            let exchange = crate::storage::NewExchange {
                project_id: project.id,
                source: ExchangeSource::Proxy,
                protocol: "HTTP/1.1".into(),
                method: "GET".into(),
                scheme: "https".into(),
                authority: "example.com".into(),
                host: "example.com".into(),
                port: 443,
                path: "/".into(),
                query: None,
                status_code: Some(200),
                mime: Some("text/plain".into()),
                completion: CompletionState::Complete,
                capture_quality: CaptureQuality::Semantic,
                header_representation: HeaderRepresentation::Semantic,
                body_representation: BodyRepresentation::SemanticEncoded,
                cache_provenance: CacheProvenance::None,
                transport_provenance: None,
                transport_profile: None,
                request_headers: Vec::new(),
                response_headers: Vec::new(),
                request_body: None,
                response_body: Some(body.as_bytes().to_vec()),
                duration_ms: None,
                lineage: ExchangeLineage::default(),
                page_title: None,
                error_message: None,
            };
            ids.push(json!(state.db.insert_exchange(exchange).await.unwrap()));
        }
        let mut args = json!({"project_id": project.id.get(), "q": "response:~needle"});
        let mut seen = Vec::new();
        let mut stopped = 0;
        loop {
            let page = search_with_budget(&state, &args, std::time::Duration::ZERO)
                .await
                .unwrap();
            seen.extend(
                page["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| row["exchange_id"].clone()),
            );
            if page.get("partial").is_some() {
                stopped += 1;
                assert_eq!(page["partial"], true);
                assert_eq!(page["note"], PARTIAL_NOTE);
                let back_to = page["searched_back_to"].as_str().unwrap();
                assert_eq!(page["next"], json!([back_to, i64::MAX]));
                // A stopped search is not an empty result to explain.
                assert!(page.get("no_match_terms").is_none() && page.get("hint").is_none());
            }
            match page.get("next") {
                Some(next) => args["cursor"] = next.clone(),
                None => break,
            }
        }
        assert_eq!(stopped, 2);
        assert_eq!(seen, [ids[2].clone(), ids[0].clone()]);
        // Within the budget nothing changes.
        let page = history_search(
            &state,
            &json!({"project_id": project.id.get(), "q": "response:~needle"}),
        )
        .await
        .unwrap();
        assert_eq!(page.as_object().unwrap().len(), 1, "{page}");
    }

    #[test]
    fn history_search_schema_stays_under_the_codex_description_limit() {
        let tools = crate::mcp::tool_defs();
        let tool = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "history_search")
            .unwrap();
        let schema = &tool["inputSchema"];
        // Codex drops every description of a tool whose schema passes 5,000 bytes.
        let size = schema.to_string().len();
        assert!(size <= 4_700, "history_search inputSchema is {size} bytes");
        assert_eq!(schema["additionalProperties"], false);
        let description = tool["description"].as_str().unwrap();
        assert!(description.contains("partial:true"), "{description}");
    }

    #[test]
    fn offset_pages_cover_every_row_once_within_the_budget() {
        let rows = (0..3_000)
            .map(|index| json!({"path": format!("/route/{index}")}))
            .collect::<Vec<_>>();
        let mut offset = 0;
        let mut seen = Vec::new();
        loop {
            let page = offset_page(Map::new(), "routes", rows.clone(), offset, 1_000).unwrap();
            assert!(json_len(&page) <= MAX_OUTPUT_BYTES);
            seen.extend(page["routes"].as_array().unwrap().iter().cloned());
            match page.get("next_offset") {
                Some(next) => {
                    assert_eq!(page["total"], 3_000);
                    offset = next.as_u64().unwrap() as usize;
                }
                None => break,
            }
        }
        assert_eq!(seen, rows);
        let past_end = offset_page(Map::new(), "routes", rows, 5_000, 10).unwrap();
        assert_eq!(past_end, json!({"routes": []}));
    }

    #[test]
    fn route_rows_omit_empty_lists_and_single_counts() {
        assert_eq!(
            route_row(route("/a", 1)),
            json!({"path": "/a", "methods": ["GET"]})
        );
        let mut full = route("/b", 3);
        full.status_codes = vec![200];
        full.parameters = vec!["id".into()];
        full.content_types = vec!["text/html".into()];
        assert_eq!(
            route_row(full),
            json!({
                "path": "/b",
                "methods": ["GET"],
                "status_codes": [200],
                "content_types": ["text/html"],
                "parameters": ["id"],
                "exchange_count": 3
            })
        );
    }

    #[test]
    fn javascript_rows_list_three_distinct_pages_and_omit_defaults() {
        let row = javascript_row(JavascriptFile {
            exchange_id: None,
            url: "https://cdn.test/a.js".into(),
            mime: None,
            status_code: Some(200),
            pages: ["p1", "p2", "p1", "p3", "p4"].map(String::from).to_vec(),
            related_via_session: false,
        });
        assert_eq!(
            row,
            json!({"url": "https://cdn.test/a.js", "pages": ["p1", "p2", "p3"], "page_count": 4})
        );
        let row = javascript_row(JavascriptFile {
            exchange_id: Some(ExchangeId(9)),
            url: "https://cdn.test/b.js".into(),
            mime: Some("text/javascript".into()),
            status_code: Some(404),
            pages: Vec::new(),
            related_via_session: true,
        });
        assert_eq!(
            row,
            json!({
                "url": "https://cdn.test/b.js",
                "exchange_id": 9,
                "status_code": 404,
                "mime": "text/javascript",
                "related_via_session": true
            })
        );
    }
}
