//! Lightweight static discovery of endpoints, absolute URLs, and emails in
//! captured JavaScript and HTML responses.

use base64::Engine as _;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::future::Future;

use crate::domain::{DomainError, DomainResult, ErrorCode, ExchangeId, MessageSide, ProjectId};
use crate::storage::Db;

const MAX_CANDIDATE_LEN: usize = 2_048;
const MAX_PASSIVE_DISCOVERY_BODY: usize = 1024 * 1024;
const MAX_SCRIPT_DISCOVERY_BODY: usize = 1024 * 1024;
const MAX_SCRIPT_TARGETS_PER_BODY: usize = 128;
const MAX_SCRIPT_BUNDLES: usize = 64;
const MAX_SCRIPT_BUNDLE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SCRIPT_ANALYSIS_BYTES: usize = 32 * 1024 * 1024;

static ABSOLUTE_URL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:https?|wss?)://[^\s"'<>\\]{4,2048}"#).expect("absolute-url regex")
});

static PROTOCOL_RELATIVE_URL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)//[a-z0-9](?:[a-z0-9.-]*\.)[a-z]{2,24}(?::\d{1,5})?(?:/[^\s"'<>\\]{0,2000})?"#,
    )
    .expect("protocol-relative-url regex")
});

static DIRECT_PATH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)["']((?:/|\./|\.\./)[^"'<>\\\s]{2,2048})["']"#).expect("direct-path regex")
});

static EMAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)[a-z0-9._%+\-]+@[a-z0-9.-]+\.[a-z]{2,24}").expect("email regex"));

static SCRIPT_SRC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)<script\b[^>]*?\bsrc\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s\"'=<>`]+))"#)
        .expect("script-src regex")
});
static LINK_HREF: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)<link\b[^>]*?\bhref\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s\"'=<>`]+))"#)
        .expect("link-href regex")
});
static BASE_HREF: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)<base\b[^>]*?\bhref\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s\"'=<>`]+))"#)
        .expect("base-href regex")
});
static MODERNJS_MANIFEST_ASSIGNMENT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)window\s*\.\s*_MODERNJS_ROUTE_MANIFEST\s*=")
        .expect("modernjs route manifest assignment regex")
});
static PASSIVE_EXTENSION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\.(?:js|mjs|css|json)$").expect("passive extension regex"));

static QUERY_PARAMETER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:[?&]|&amp;)([A-Za-z_][A-Za-z0-9_.\-]{0,127})=").expect("query parameter regex")
});
static PARAMETER_METHOD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:URLSearchParams|FormData)?\s*\.?\s*(?:append|set|get|has|delete)\s*\(\s*["']([A-Za-z_][A-Za-z0-9_.\-]{0,127})["']"#)
        .expect("parameter method regex")
});
static REQUEST_BODY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)(?:JSON\.stringify\s*\(|axios\.(?:post|put|patch)\s*\([^,]+,\s*)\{([^{}]{1,1000}[^{}]{0,1000}[^{}]{0,1000}[^{}]{0,1000}[^{}]{0,96})\}")
        .expect("request body regex")
});
static OBJECT_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:^|,)\s*(?:["']([A-Za-z_][A-Za-z0-9_.\-]{0,127})["']|([A-Za-z_][A-Za-z0-9_.\-]{0,127}))\s*:"#)
        .expect("object key regex")
});
static GRAPHQL_VARIABLE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$([_A-Za-z][_0-9A-Za-z]*)\s*:").expect("graphql variable regex"));
static HTML_NAME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)<(?:input|select|textarea|button)\b[^>]*?\bname\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'=<>`]+))"#)
        .expect("html field name regex")
});

static STATIC_ASSET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\.(?:css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webm|mp3|wav|webp)(?:[?#].*)?$",
    )
    .expect("static-asset regex")
});

static ROUTE_SEGMENT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^(?::?[A-Za-z0-9_.@%\-]+|\{[A-Za-z0-9_.\-]+\}|[A-Za-z0-9_.@%\-]+:[A-Za-z0-9_.\-]+)$",
    )
    .expect("route-segment regex")
});

const RELATIVE_ROUTE_PREFIXES: &[&str] = &[
    "account/",
    "accounts/",
    "admin/",
    "api/",
    "auth/",
    "callback/",
    "config/",
    "credential/",
    "credentials/",
    "dashboard/",
    "debug/",
    "download/",
    "graphql/",
    "internal/",
    "login/",
    "logout/",
    "member/",
    "members/",
    "oauth/",
    "org/",
    "orgs/",
    "private/",
    "project/",
    "projects/",
    "rest/",
    "settings/",
    "token/",
    "upload/",
    "user/",
    "users/",
    "v1/",
    "v2/",
    "v3/",
    "webhook/",
    "webhooks/",
];

const ROUTE_KEYWORDS: &[&str] = &[
    "account", "accounts", "admin", "api", "auth", "callback", "config", "create", "delete",
    "download", "export", "graphql", "import", "internal", "list", "login", "logout", "member",
    "members", "oauth", "org", "orgs", "private", "profile", "project", "projects", "rest",
    "search", "settings", "sso", "token", "update", "upload", "user", "users", "v1", "v2", "v3",
    "webhook", "webhooks",
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PageAnalysisStats {
    pub endpoints: usize,
    pub urls: usize,
    pub emails: usize,
    pub parameters: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PageAnalysis {
    pub endpoints: Vec<String>,
    pub urls: Vec<String>,
    pub emails: Vec<String>,
    pub parameters: Vec<String>,
    pub stats: PageAnalysisStats,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ScriptTreeAnalysis {
    pub analysis: PageAnalysis,
    /// Same-origin JavaScript resources requested in traversal order.
    pub js_bundles: Vec<String>,
    pub js_bundles_truncated: bool,
    pub js_bundle_failures: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptBundleContent {
    /// Effective URL after request rules. Nested relative imports are resolved
    /// from this URL rather than the pre-rewrite discovery URL.
    pub source_url: String,
    pub body: Vec<u8>,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
    pub completion: crate::domain::CompletionState,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExchangePageAnalysis {
    pub project_id: ProjectId,
    pub exchange_id: ExchangeId,
    pub source_url: String,
    pub decoded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    pub body_truncated: bool,
    pub analysis_incomplete: bool,
    pub completion: crate::domain::CompletionState,
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(flatten)]
    pub analysis: PageAnalysis,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PassiveTargetDiscovery {
    pub source_url: String,
    pub targets: Vec<String>,
    pub total: usize,
    pub truncated: bool,
}

#[derive(Debug)]
pub(crate) struct DecodedExchangeContent {
    pub source_url: String,
    pub body: Vec<u8>,
    pub decoded: bool,
    pub content_encoding: Option<String>,
    pub body_truncated: bool,
    pub completion: crate::domain::CompletionState,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
}

fn looks_like_html_document(body: &[u8]) -> bool {
    let prefix = String::from_utf8_lossy(&body[..body.len().min(512)]);
    let prefix = prefix
        .trim_start_matches(|character: char| character.is_whitespace() || character == '\u{feff}');
    let prefix = prefix.to_ascii_lowercase();
    prefix.starts_with("<!doctype html")
        || prefix.starts_with("<html")
        || prefix.starts_with("<head")
        || prefix.starts_with("<body")
}

fn acceptable_script_response(content: &ScriptBundleContent) -> bool {
    content
        .status_code
        .is_some_and(|status| (200..300).contains(&status))
        && !crate::page_title::is_html_mime(content.content_type.as_deref())
        && !looks_like_html_document(&content.body)
}

fn attribute_value<'a>(captures: &'a regex::Captures<'a>) -> Option<&'a str> {
    (1..=3).find_map(|index| captures.get(index).map(|value| value.as_str()))
}

fn same_origin(left: &url::Url, right: &url::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn passive_targets(source_url: &str, content: &[u8], limit: usize) -> PassiveTargetDiscovery {
    let text = String::from_utf8_lossy(content);
    let source = url::Url::parse(source_url).ok();
    let mut base = source.clone();
    if let (Some(source), Some(captures)) = (source.as_ref(), BASE_HREF.captures(&text)) {
        if let Some(value) = attribute_value(&captures) {
            if let Ok(candidate) = source.join(value) {
                base = Some(candidate);
            }
        }
    }
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    if let (Some(source), Some(base)) = (source.as_ref(), base.as_ref()) {
        for captures in SCRIPT_SRC
            .captures_iter(&text)
            .chain(LINK_HREF.captures_iter(&text))
        {
            let Some(value) = attribute_value(&captures) else {
                continue;
            };
            let Ok(mut target) = base.join(value) else {
                continue;
            };
            if !matches!(target.scheme(), "http" | "https")
                || !same_origin(source, &target)
                || !target.username().is_empty()
                || target.password().is_some()
            {
                continue;
            }
            target.set_fragment(None);
            if target.as_str().len() > MAX_CANDIDATE_LEN
                || !PASSIVE_EXTENSION.is_match(target.path())
                || target.query_pairs().any(|(name, value)| {
                    !matches!(
                        name.to_ascii_lowercase().as_str(),
                        "callback"
                            | "cb"
                            | "v"
                            | "ver"
                            | "version"
                            | "lang"
                            | "locale"
                            | "theme"
                            | "format"
                            | "module"
                    ) || value.len() > 128
                        || !value.chars().all(|character| {
                            character.is_ascii_alphanumeric()
                                || matches!(character, '.' | '_' | '~' | '-')
                        })
                })
            {
                continue;
            }
            let canonical = target.to_string();
            if seen.insert(canonical.clone()) {
                targets.push(canonical);
            }
        }
    }
    let total = targets.len();
    targets.truncate(limit.min(64));
    PassiveTargetDiscovery {
        source_url: source_url.to_string(),
        truncated: total > targets.len(),
        total,
        targets,
    }
}

#[derive(Debug)]
struct ScriptTargetDiscovery {
    targets: Vec<String>,
    truncated: bool,
}

/// Resolve a URL after host request rules and verify that it still has the
/// same origin as the explicitly requested page.
pub(crate) fn same_origin_url(left: &str, right: &str) -> bool {
    url::Url::parse(left)
        .ok()
        .zip(url::Url::parse(right).ok())
        .is_some_and(|(left, right)| same_origin(&left, &right))
}

fn script_targets(source_url: &str, content: &[u8]) -> ScriptTargetDiscovery {
    let body_limited = content.len() > MAX_SCRIPT_DISCOVERY_BODY;
    let text = String::from_utf8_lossy(&content[..content.len().min(MAX_SCRIPT_DISCOVERY_BODY)]);
    let normalized = normalize_source(&text);
    let Some(source) = url::Url::parse(source_url).ok() else {
        return ScriptTargetDiscovery {
            targets: Vec::new(),
            truncated: body_limited,
        };
    };

    let mut base = source.clone();
    if let Some(captures) = BASE_HREF.captures(&normalized) {
        if let Some(value) = attribute_value(&captures) {
            if let Ok(candidate) = source.join(value) {
                // Resolve script src values using the document's actual base
                // even when it is cross-origin; the sanitizer below will then
                // reject those resources instead of probing a same-origin
                // path the page never requested.
                base = candidate;
            }
        }
    }

    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    let mut truncated = body_limited;
    for captures in SCRIPT_SRC.captures_iter(&normalized) {
        if let Some(value) = attribute_value(&captures) {
            if let Some(target) = sanitize_script_target(&source, &base, value) {
                if seen.insert(target.clone()) {
                    targets.push(target);
                }
            }
        }
    }

    let (manifest_assets, manifest_truncated) = modernjs_route_assets(&normalized);
    truncated |= manifest_truncated;
    for value in manifest_assets {
        let path = if is_absolute_http_url(&value)
            || value.starts_with('/')
            || value.starts_with("./")
            || value.starts_with("../")
        {
            value
        } else {
            // Modern.js route manifest asset paths are public-path entries
            // such as "static/js/async/123.js", rooted at the site origin.
            format!("/{}", value.trim_start_matches('/'))
        };
        if let Some(target) = sanitize_script_target(&source, &source, &path) {
            if seen.insert(target.clone()) {
                targets.push(target);
            }
        }
    }

    if targets.len() > MAX_SCRIPT_TARGETS_PER_BODY {
        targets.truncate(MAX_SCRIPT_TARGETS_PER_BODY);
        truncated = true;
    }
    ScriptTargetDiscovery { targets, truncated }
}

fn is_absolute_http_url(value: &str) -> bool {
    url::Url::parse(value)
        .ok()
        .is_some_and(|url| matches!(url.scheme(), "http" | "https"))
}

fn sanitize_script_target(source: &url::Url, base: &url::Url, value: &str) -> Option<String> {
    let value = html_escape::decode_html_entities(value).trim().to_string();
    let mut target = base.join(&value).ok()?;
    if !matches!(target.scheme(), "http" | "https")
        || !same_origin(source, &target)
        || !target.username().is_empty()
        || target.password().is_some()
    {
        return None;
    }
    target.set_fragment(None);
    if target.as_str().len() > MAX_CANDIDATE_LEN
        || !target.path().rsplit('/').next().is_some_and(|name| {
            let lower = name.to_ascii_lowercase();
            lower.ends_with(".js") || lower.ends_with(".mjs")
        })
        || target.query_pairs().any(|(name, value)| {
            !matches!(
                name.to_ascii_lowercase().as_str(),
                "callback"
                    | "cb"
                    | "v"
                    | "ver"
                    | "version"
                    | "lang"
                    | "locale"
                    | "theme"
                    | "format"
                    | "module"
            ) || value.len() > 128
                || !value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '~' | '-')
                })
        })
    {
        return None;
    }
    Some(target.to_string())
}

fn modernjs_route_assets(source: &str) -> (Vec<String>, bool) {
    let mut assets = Vec::new();
    for assignment in MODERNJS_MANIFEST_ASSIGNMENT.find_iter(source) {
        let mut start = assignment.end();
        while source
            .as_bytes()
            .get(start)
            .is_some_and(u8::is_ascii_whitespace)
        {
            start += 1;
        }
        if source.as_bytes().get(start) != Some(&b'{') {
            continue;
        }
        let Some(end) = balanced_object_end(source, start) else {
            continue;
        };
        let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&source[start..end]) else {
            continue;
        };
        let Some(route_assets) = manifest
            .get("routeAssets")
            .and_then(serde_json::Value::as_object)
        else {
            continue;
        };
        for route in route_assets.values() {
            let Some(route) = route.as_object() else {
                continue;
            };
            let Some(route_files) = route.get("assets").and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            for asset in route_files.iter().filter_map(serde_json::Value::as_str) {
                assets.push(asset.to_string());
            }
        }
    }
    (assets, false)
}

fn balanced_object_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut line_comment = false;
    let mut block_comment = false;
    let mut cursor = start;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        let next = bytes.get(cursor + 1).copied();
        if line_comment {
            if matches!(byte, b'\n' | b'\r') {
                line_comment = false;
            }
            cursor += 1;
            continue;
        }
        if block_comment {
            if byte == b'*' && next == Some(b'/') {
                block_comment = false;
                cursor += 2;
            } else {
                cursor += 1;
            }
            continue;
        }
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
            cursor += 1;
            continue;
        }
        if byte == b'/' && next == Some(b'/') {
            line_comment = true;
            cursor += 2;
            continue;
        }
        if byte == b'/' && next == Some(b'*') {
            block_comment = true;
            cursor += 2;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
        } else if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(cursor + 1);
            }
        }
        cursor += 1;
    }
    None
}

/// Analyze a page and the same-origin JavaScript resources it references.
/// Fetches run sequentially, and both response count and analyzed bytes are
/// capped so cyclic manifests and very large bundles cannot run indefinitely.
pub async fn analyze_script_tree<F, Fut>(
    source_url: &str,
    root_body: &[u8],
    mut fetch: F,
) -> ScriptTreeAnalysis
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = DomainResult<Option<ScriptBundleContent>>>,
{
    let mut analysis = analyze_page(root_body);
    let first = script_targets(source_url, root_body);
    let mut truncated = first.truncated;
    let mut queue: VecDeque<_> = first.targets.into();
    let mut queued: HashSet<String> = queue.iter().cloned().collect();
    let mut visited = HashSet::new();
    let mut bundles = Vec::new();
    let mut failures = 0usize;
    let mut remaining_bytes = MAX_SCRIPT_ANALYSIS_BYTES;

    while let Some(url) = queue.pop_front() {
        if !visited.insert(url.clone()) {
            continue;
        }
        if bundles.len() >= MAX_SCRIPT_BUNDLES {
            truncated = true;
            break;
        }
        bundles.push(url.clone());
        let fetched = match fetch(url.clone()).await {
            Ok(Some(fetched)) => fetched,
            Ok(None) | Err(_) => {
                failures += 1;
                continue;
            }
        };
        if !same_origin_url(source_url, &fetched.source_url) {
            failures += 1;
            continue;
        }
        if !acceptable_script_response(&fetched) {
            failures += 1;
            truncated |= fetched.completion != crate::domain::CompletionState::Complete;
            continue;
        }
        if fetched.completion != crate::domain::CompletionState::Complete {
            // A partial response can still contain useful static discoveries,
            // but it did not complete successfully and must be reported as
            // both incomplete analysis and a failed bundle fetch.
            failures += 1;
            truncated = true;
        }
        let effective_url = fetched.source_url;
        let body = fetched.body;
        let take = body.len().min(MAX_SCRIPT_BUNDLE_BYTES).min(remaining_bytes);
        if take < body.len() {
            truncated = true;
        }
        if take == 0 {
            if remaining_bytes == 0 {
                truncated = true;
                break;
            }
            continue;
        }
        remaining_bytes -= take;
        merge_analysis(&mut analysis, analyze_page(&body[..take]));

        let discovered = script_targets(&effective_url, &body[..take]);
        truncated |= discovered.truncated;
        for target in discovered.targets {
            if queued.insert(target.clone()) {
                if visited.len() + queue.len() >= MAX_SCRIPT_BUNDLES {
                    truncated = true;
                    break;
                }
                queue.push_back(target);
            }
        }
        if remaining_bytes == 0 {
            if !queue.is_empty() {
                truncated = true;
            }
            break;
        }
    }

    ScriptTreeAnalysis {
        analysis,
        js_bundles: bundles,
        js_bundles_truncated: truncated,
        js_bundle_failures: failures,
    }
}

fn merge_analysis(target: &mut PageAnalysis, source: PageAnalysis) {
    merge_values(&mut target.endpoints, source.endpoints);
    merge_values(&mut target.urls, source.urls);
    merge_values(&mut target.emails, source.emails);
    merge_values(&mut target.parameters, source.parameters);
    target.stats = PageAnalysisStats {
        endpoints: target.endpoints.len(),
        urls: target.urls.len(),
        emails: target.emails.len(),
        parameters: target.parameters.len(),
    };
}

fn merge_values(target: &mut Vec<String>, values: Vec<String>) {
    let mut seen: HashSet<String> = target.iter().cloned().collect();
    target.extend(
        values
            .into_iter()
            .filter(|value| seen.insert(value.clone())),
    );
    sort_case_insensitive(target);
}

/// Resolve and sanitize passive same-origin resources referenced by the saved
/// base response. Only script and link targets with safe static extensions are
/// returned; emails and flat application routes are deliberately excluded.
pub async fn discover_passive_targets(
    db: &Db,
    project_id: ProjectId,
    exchange_id: ExchangeId,
    limit: usize,
) -> DomainResult<PassiveTargetDiscovery> {
    let detail = db
        .get_exchange_detail(
            project_id,
            exchange_id,
            crate::policy::PresentationOptions::default(),
        )
        .await?;
    let mut body = db
        .load_raw_body(project_id, exchange_id, MessageSide::Response)
        .await?
        .unwrap_or_default();
    if detail.protocol == "HTTP/1.1 raw" {
        body = crate::reply::presented_raw_response_body(&body);
    }
    let headers = db
        .load_raw_headers(project_id, exchange_id, MessageSide::Response)
        .await?;
    let encodings = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
        .map(|header| String::from_utf8_lossy(&header.value).trim().to_string())
        .filter(|encoding| !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity"))
        .collect::<Vec<_>>();
    if !encodings.is_empty() {
        body = crate::codec::decode_content_encodings(
            &body,
            &encodings.join(", "),
            MAX_PASSIVE_DISCOVERY_BODY,
        )?;
    }
    body.truncate(MAX_PASSIVE_DISCOVERY_BODY);
    let query = detail
        .summary
        .query
        .as_deref()
        .filter(|query| !query.is_empty())
        .map(|query| format!("?{query}"))
        .unwrap_or_default();
    let source_url = format!(
        "{}://{}{}{}",
        detail.summary.scheme, detail.summary.authority, detail.summary.path, query
    );
    Ok(passive_targets(&source_url, &body, limit))
}

/// Analyze the full stored response body, decoding HTTP content encodings first.
pub async fn analyze_exchange(
    db: &Db,
    project_id: ProjectId,
    exchange_id: ExchangeId,
) -> DomainResult<ExchangePageAnalysis> {
    let content = load_exchange_content(db, project_id, exchange_id).await?;
    Ok(ExchangePageAnalysis {
        project_id,
        exchange_id,
        source_url: content.source_url,
        decoded: content.decoded,
        content_encoding: content.content_encoding,
        body_truncated: content.body_truncated,
        analysis_incomplete: content.body_truncated,
        completion: content.completion,
        status_code: content.status_code,
        content_type: content.content_type,
        analysis: analyze_page(&content.body),
    })
}

pub(crate) async fn load_exchange_content(
    db: &Db,
    project_id: ProjectId,
    exchange_id: ExchangeId,
) -> DomainResult<DecodedExchangeContent> {
    let detail = db
        .get_exchange_detail(
            project_id,
            exchange_id,
            crate::policy::PresentationOptions::default(),
        )
        .await?;
    let mut body = db
        .load_raw_body(project_id, exchange_id, MessageSide::Response)
        .await?
        .unwrap_or_default();
    if detail.protocol == "HTTP/1.1 raw" {
        body = crate::reply::presented_raw_response_body(&body);
    }
    let headers = db
        .load_raw_headers(project_id, exchange_id, MessageSide::Response)
        .await?;
    let encodings = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
        .map(|header| String::from_utf8_lossy(&header.value).trim().to_string())
        .filter(|encoding| !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity"))
        .collect::<Vec<_>>();
    let content_encoding = (!encodings.is_empty()).then(|| encodings.join(", "));
    let decoded = content_encoding.is_some();
    if let Some(encoding) = &content_encoding {
        body = crate::codec::decode_content_encodings(
            &body,
            encoding,
            crate::codec::MAX_DECODED_BODY_OUTPUT,
        )?;
    }
    let query = detail
        .summary
        .query
        .as_deref()
        .filter(|query| !query.is_empty())
        .map(|query| format!("?{query}"))
        .unwrap_or_default();
    Ok(DecodedExchangeContent {
        source_url: format!(
            "{}://{}{}{}",
            detail.summary.scheme, detail.summary.authority, detail.summary.path, query
        ),
        body,
        decoded,
        content_encoding,
        body_truncated: detail.summary.completion != crate::domain::CompletionState::Complete,
        completion: detail.summary.completion,
        status_code: detail.summary.status_code,
        content_type: detail.summary.mime,
    })
}

pub(crate) fn decode_ephemeral_response(
    response: &crate::reply::EphemeralReplyResponse,
) -> DomainResult<(Vec<u8>, bool, Option<String>)> {
    let mut body = base64::engine::general_purpose::STANDARD
        .decode(response.body_base64.as_bytes())
        .map_err(|error| {
            DomainError::new(
                ErrorCode::Internal,
                format!("invalid internal response body: {error}"),
            )
        })?;
    let encodings = response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
        .map(|header| header.value.trim().to_string())
        .filter(|encoding| !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity"))
        .collect::<Vec<_>>();
    let content_encoding = (!encodings.is_empty()).then(|| encodings.join(", "));
    if let Some(encoding) = &content_encoding {
        body = crate::codec::decode_content_encodings(
            &body,
            encoding,
            crate::codec::MAX_DECODED_BODY_OUTPUT,
        )?;
    }
    Ok((body, content_encoding.is_some(), content_encoding))
}

/// Analyze JavaScript, HTML, or other text without executing it.
///
/// JavaScript slash escapes and common unicode slash escapes are normalized so
/// bundles using `https:\/\/host` or `\u002Fapi` remain discoverable.
pub fn analyze_page(content: &[u8]) -> PageAnalysis {
    let text = String::from_utf8_lossy(content);
    let normalized = normalize_source(&text);
    let mut endpoints = HashSet::new();
    let mut urls = HashSet::new();
    let mut emails = HashSet::new();
    let mut parameters = HashSet::new();

    for matched in ABSOLUTE_URL.find_iter(&normalized) {
        if normalized
            .as_bytes()
            .get(matched.end())
            .is_some_and(u8::is_ascii_whitespace)
        {
            // A quoted URL may legally contain spaces. Let the complete
            // string-literal pass below handle it instead of returning a
            // misleading truncated prefix.
            continue;
        }
        if let Some(value) = clean_url(matched.as_str()) {
            urls.insert(value);
        }
    }
    for matched in PROTOCOL_RELATIVE_URL.find_iter(&normalized) {
        if matched.start() > 0 && normalized.as_bytes()[matched.start() - 1] == b':' {
            continue;
        }
        if let Some(value) = clean_url(matched.as_str()) {
            urls.insert(value);
        }
    }

    // A targeted path pass remains reliable when surrounding minified code
    // contains regex literals or other JavaScript grammar constructs.
    for captures in DIRECT_PATH.captures_iter(&normalized) {
        let Some(value) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        if value.starts_with("//") {
            continue;
        }
        if let Some(endpoint) = clean_endpoint(value) {
            endpoints.insert(endpoint);
        }
    }

    for value in quoted_values(&normalized) {
        let value = value.trim();
        if value.len() > MAX_CANDIDATE_LEN {
            continue;
        }
        if ["http://", "https://", "ws://", "wss://", "//"]
            .iter()
            .any(|prefix| value.starts_with(prefix))
        {
            if let Some(url) = clean_url(value) {
                urls.insert(url);
            }
            continue;
        }
        if let Some(endpoint) = clean_endpoint(value) {
            endpoints.insert(endpoint);
        }
    }

    for matched in EMAIL.find_iter(&normalized) {
        let value = matched.as_str();
        if valid_email(&normalized, matched.start(), value) {
            emails.insert(value.to_string());
        }
    }

    // Normalizing JavaScript slash escapes can expose `//host/path` inside an
    // absolute URL already collected above. Prefer the explicit-scheme form
    // instead of returning both representations of the same source value.
    let absolute_urls = urls
        .iter()
        .filter(|value| !value.starts_with("//"))
        .cloned()
        .collect::<HashSet<_>>();
    urls.retain(|value| {
        !value.starts_with("//")
            || (!absolute_urls.contains(&format!("http:{value}"))
                && !absolute_urls.contains(&format!("https:{value}"))
                && !absolute_urls.contains(&format!("ws:{value}"))
                && !absolute_urls.contains(&format!("wss:{value}")))
    });

    extract_parameters(&normalized, &endpoints, &urls, &mut parameters);

    let mut endpoints: Vec<_> = endpoints.into_iter().collect();
    let mut urls: Vec<_> = urls.into_iter().collect();
    let mut emails: Vec<_> = emails.into_iter().collect();
    let mut parameters: Vec<_> = parameters.into_iter().collect();
    sort_case_insensitive(&mut endpoints);
    sort_case_insensitive(&mut urls);
    sort_case_insensitive(&mut emails);
    sort_case_insensitive(&mut parameters);
    let stats = PageAnalysisStats {
        endpoints: endpoints.len(),
        urls: urls.len(),
        emails: emails.len(),
        parameters: parameters.len(),
    };
    PageAnalysis {
        endpoints,
        urls,
        emails,
        parameters,
        stats,
    }
}

fn extract_parameters(
    source: &str,
    endpoints: &HashSet<String>,
    urls: &HashSet<String>,
    parameters: &mut HashSet<String>,
) {
    for captures in QUERY_PARAMETER.captures_iter(source) {
        if let Some(name) = captures.get(1) {
            parameters.insert(name.as_str().to_string());
        }
    }

    if source.contains("URLSearchParams")
        || source.contains("FormData")
        || source.contains(".append(")
        || source.contains(".set(")
    {
        for captures in PARAMETER_METHOD.captures_iter(source) {
            if let Some(name) = captures.get(1) {
                parameters.insert(name.as_str().to_string());
            }
        }
    }

    let lower = source.to_ascii_lowercase();
    if ["<input", "<select", "<textarea"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        for captures in HTML_NAME.captures_iter(source) {
            for index in 1..=3 {
                if let Some(name) = captures.get(index) {
                    parameters.insert(name.as_str().to_string());
                    break;
                }
            }
        }
    }

    if source.contains("JSON.stringify")
        || source.contains("axios.post")
        || source.contains("axios.put")
        || source.contains("axios.patch")
    {
        for body in REQUEST_BODY
            .captures_iter(source)
            .filter_map(|captures| captures.get(1))
        {
            for captures in OBJECT_KEY.captures_iter(body.as_str()) {
                let name = captures.get(1).or_else(|| captures.get(2));
                if let Some(name) = name {
                    parameters.insert(name.as_str().to_string());
                }
            }
        }
    }

    if source.contains("query") || source.contains("mutation") || source.contains("subscription") {
        for captures in GRAPHQL_VARIABLE.captures_iter(source) {
            if let Some(name) = captures.get(1) {
                parameters.insert(name.as_str().to_string());
            }
        }
    }

    for value in endpoints.iter().chain(urls.iter()) {
        collect_url_parameters(value, parameters);
        collect_route_parameters(value, parameters);
    }
}

fn collect_url_parameters(value: &str, parameters: &mut HashSet<String>) {
    let parsed_value = if value.starts_with("//") {
        format!("https:{value}")
    } else if value.starts_with('/') || value.starts_with("./") || value.starts_with("../") {
        let path = value.trim_start_matches(['.', '/']);
        format!("https://jshound.invalid/{path}")
    } else {
        value.to_string()
    };
    if let Ok(parsed) = url::Url::parse(&parsed_value) {
        for (name, _) in parsed.query_pairs() {
            if !name.is_empty() {
                parameters.insert(name.into_owned());
            }
        }
    }
}

fn collect_route_parameters(value: &str, parameters: &mut HashSet<String>) {
    let path = value.split(['?', '#']).next().unwrap_or(value);
    for segment in path.split('/') {
        let name = if let Some(name) = segment.strip_prefix(':') {
            Some(name)
        } else if segment.starts_with('{') && segment.ends_with('}') {
            Some(&segment[1..segment.len() - 1])
        } else {
            None
        };
        if let Some(name) = name.filter(|name| !name.is_empty()) {
            parameters.insert(name.to_string());
        }
    }
}

/// Walk JavaScript string literals without losing synchronization on empty or
/// very large strings. A bounded regex can otherwise treat the closing quote
/// of an ignored literal as the opening quote of the next one.
fn quoted_values(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut values = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let quote = bytes[cursor];
        if !matches!(quote, b'\'' | b'"' | b'`') {
            cursor += 1;
            continue;
        }

        let start = cursor + 1;
        let mut end = start;
        let mut escaped = false;
        let mut closed = false;
        while end < bytes.len() {
            let byte = bytes[end];
            if escaped {
                escaped = false;
                end += 1;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
                end += 1;
                continue;
            }
            if byte == quote {
                closed = true;
                break;
            }
            if quote != b'`' && matches!(byte, b'\r' | b'\n') {
                break;
            }
            end += 1;
        }

        if closed {
            if end - start <= MAX_CANDIDATE_LEN {
                values.push(&source[start..end]);
            }
            cursor = end + 1;
        } else {
            cursor = start;
        }
    }
    values
}

fn normalize_source(content: &str) -> String {
    html_escape::decode_html_entities(content)
        .replace("\\u002f", "/")
        .replace("\\u002F", "/")
        .replace("\\x2f", "/")
        .replace("\\x2F", "/")
        .replace("\\/", "/")
}

fn clean_url(candidate: &str) -> Option<String> {
    let value = candidate
        .trim()
        .trim_end_matches(['\\', ',', '.', ';', ':', ')', ']', '}', '*']);
    if value.len() < 8 || value.contains("${") || value.contains('{') {
        return None;
    }
    let parsed = if value.starts_with("//") {
        url::Url::parse(&format!("https:{value}"))
    } else {
        url::Url::parse(value)
    }
    .ok()?;
    if !matches!(parsed.scheme(), "http" | "https" | "ws" | "wss") || parsed.host_str().is_none() {
        return None;
    }
    Some(value.to_string())
}

fn clean_endpoint(candidate: &str) -> Option<String> {
    let value = candidate
        .trim_matches(['\\', '"', '\''])
        .trim_end_matches(['\\', ',', ';', ')', ']', '}', '>']);
    if value.len() < 3
        || value.len() > MAX_CANDIDATE_LEN
        || value.chars().any(char::is_whitespace)
        || value.starts_with('#')
        || value.starts_with("data:")
        || value.contains("${")
        || STATIC_ASSET.is_match(value)
    {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "application/json"
            | "application/xml"
            | "application/x-www-form-urlencoded"
            | "multipart/form-data"
            | "text/css"
            | "text/html"
            | "text/javascript"
            | "text/plain"
    ) {
        return None;
    }

    let root_relative = value.starts_with('/') && !value.starts_with("//");
    let dot_relative = value.starts_with("./") || value.starts_with("../");
    let relative = !root_relative && !dot_relative;
    if relative && !value.contains('/') {
        return None;
    }

    let structural = value
        .split(['?', '#'])
        .next()
        .unwrap_or(value)
        .trim_start_matches("../")
        .trim_start_matches("./")
        .trim_matches('/');
    let parts: Vec<_> = structural
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty()
        || parts.iter().all(|part| part.len() < 2)
        || !parts.iter().all(|part| ROUTE_SEGMENT.is_match(part))
    {
        return None;
    }

    if relative {
        let high_signal_prefix = RELATIVE_ROUTE_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix));
        let high_signal_segment = parts.iter().any(|part| {
            let part = part.trim_start_matches(':').to_ascii_lowercase();
            ROUTE_KEYWORDS.contains(&part.as_str())
        });
        let parameterized = parts.iter().any(|part| part.starts_with(':'));
        let web_extension = parts.last().is_some_and(|part| {
            [
                ".action", ".asp", ".aspx", ".cgi", ".do", ".html", ".js", ".json", ".jsp", ".php",
                ".txt", ".xml",
            ]
            .iter()
            .any(|extension| part.to_ascii_lowercase().ends_with(extension))
        });
        if !(high_signal_prefix || high_signal_segment || parameterized || web_extension) {
            return None;
        }
    }

    Some(value.to_string())
}

fn valid_email(content: &str, start: usize, value: &str) -> bool {
    let (_, domain) = value.rsplit_once('@').unwrap_or_default();
    let domain = domain.to_ascii_lowercase();
    if matches!(
        domain.as_str(),
        "example.com" | "test.com" | "domain.com" | "placeholder.com" | "email.com"
    ) || domain.contains("w3.org")
    {
        return false;
    }
    if start > 0 && content.as_bytes()[start - 1] == b':' {
        return false;
    }
    let context_start = start.saturating_sub(12);
    let prefix = content[context_start..start].to_ascii_lowercase();
    !prefix.contains("://")
        && !prefix.contains("mongodb")
        && !prefix.contains("postgres")
        && !prefix.contains("mysql")
}

fn sort_case_insensitive(values: &mut [String]) {
    values.sort_by(|left, right| {
        left.to_ascii_lowercase()
            .cmp(&right.to_ascii_lowercase())
            .then_with(|| left.cmp(right))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_from_javascript_and_html_without_secrets() {
        let result = analyze_page(
            br#"
              <a href="/account/settings?tab=security">Settings</a>
              <script>
                const api = '/api/v2/users/:id';
                const escaped = 'https:\/\/api.target.test\/v1\/users';
                const websocket = 'wss://events.target.test/socket';
                const email = 'security@target.test';
                const placeholder = 'admin@example.com';
                const secret = 'sk_live_012345678901234567890123';
              </script>
            "#,
        );

        assert_eq!(
            result.endpoints,
            ["/account/settings?tab=security", "/api/v2/users/:id"]
        );
        assert_eq!(
            result.urls,
            [
                "https://api.target.test/v1/users",
                "wss://events.target.test/socket"
            ]
        );
        assert_eq!(result.emails, ["security@target.test"]);
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("sk_live_"));
    }

    #[test]
    fn filters_static_assets_and_credential_style_emails() {
        let result = analyze_page(
            br#"'/images/logo.png' '/api/logo.png' 'mongodb://user:pass@db.target.test/x'"#,
        );
        assert!(result.endpoints.is_empty());
        assert!(result.emails.is_empty());
    }

    #[test]
    fn extracts_jshound_compatible_parameters_from_routes_forms_and_requests() {
        let result = analyze_page(
            br#"
              <input name="csrf_token"><select name="team"></select>
              fetch('/api/users/:id?tenant=acme&amp;page=2');
              const params = new URLSearchParams();
              params.append('page_size', '50'); params.get('sort');
              const body = JSON.stringify({username: 'alice', remember_me: true});
              query CurrentUser($id: ID!, $input: Input!) { user { id } }
            "#,
        );
        assert_eq!(
            result.parameters,
            [
                "csrf_token",
                "id",
                "input",
                "page",
                "page_size",
                "remember_me",
                "sort",
                "team",
                "tenant",
                "username"
            ]
        );
        assert_eq!(result.stats.parameters, 10);
    }

    #[test]
    fn keeps_relative_high_signal_routes_and_javascript_files() {
        let result = analyze_page(br#"'auth/callback' 'assets/app.js' 'random/library/path'"#);
        assert_eq!(result.endpoints, ["assets/app.js", "auth/callback"]);
    }

    #[test]
    fn adjacent_empty_literals_do_not_hide_following_endpoints() {
        let result = analyze_page(br#""".concat(prefix,"/aigc/cover-art")"#);
        assert_eq!(result.endpoints, ["/aigc/cover-art"]);
    }

    #[test]
    fn oversized_literals_do_not_hide_following_endpoints() {
        let input = format!(r#""{}".concat(prefix,"/api/visible")"#, "x".repeat(3_000));
        let result = analyze_page(input.as_bytes());
        assert_eq!(result.endpoints, ["/api/visible"]);
    }

    #[test]
    fn quoted_urls_with_spaces_are_not_returned_as_truncated_prefixes() {
        let result = analyze_page(br#"'https://cdn.example.test/contracts/Program Terms.pdf'"#);
        assert_eq!(
            result.urls,
            ["https://cdn.example.test/contracts/Program Terms.pdf"]
        );
    }

    #[test]
    fn passive_target_discovery_is_same_origin_bounded_and_secret_safe() {
        let result = passive_targets(
            "https://example.test/app/index.html",
            br#"
              <base href="/assets/">
              <script src="../resources/js/geolocate.js"></script>
              <script src="https://example.test/app.js#fragment"></script>
              <script src="https://other.test/foreign.js"></script>
              <script src="signed.js?token=secret"></script>
              <script src="cloud.js?X-Amz-Credential=credential&amp;X-Amz-Signature=signature"></script>
              <link rel="stylesheet" href="theme.css">
              <a href="/logout">logout</a>
            "#,
            2,
        );
        assert_eq!(result.total, 3);
        assert_eq!(result.targets.len(), 2);
        assert!(result.truncated);
        assert!(result
            .targets
            .contains(&"https://example.test/resources/js/geolocate.js".to_string()));
        assert!(result
            .targets
            .contains(&"https://example.test/app.js".to_string()));
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("credential"));
        assert!(!serialized.contains("signature"));
        assert!(!serialized.contains("other.test"));
        assert!(!serialized.contains("logout"));
    }

    #[test]
    fn passive_discovery_does_not_misresolve_external_base_paths_to_source_origin() {
        let result = passive_targets(
            "https://example.test/app/page",
            br#"
              <base href="https://cdn.example.test/assets/">
              <script src="/static/js/app.js"></script>
              <script src="https://example.test/static/js/explicit.js"></script>
            "#,
            64,
        );
        assert_eq!(
            result.targets,
            ["https://example.test/static/js/explicit.js"]
        );
    }

    #[test]
    fn modernjs_route_manifest_discovers_only_safe_same_origin_javascript_assets() {
        let result = script_targets(
            "https://example.test/album-cover/page",
            br#"
              <script src="/static/js/async/main.js#duplicate"></script>
              window._MODERNJS_ROUTE_MANIFEST = {"routeAssets": {
                "album-cover/page": {"assets": [
                  "static/js/async/main.js",
                  "static/js/async/page.mjs",
                  "static/css/async/page.css",
                  "static/js/app.js.map",
                  "https://cdn.example.test/foreign.js",
                  "/private.js?token=secret"
                ], "referenceCssAssets": ["static/css/async/page.css"]}
              }};
            "#,
        );
        assert_eq!(
            result.targets,
            [
                "https://example.test/static/js/async/main.js",
                "https://example.test/static/js/async/page.mjs"
            ]
        );
        let serialized = serde_json::to_string(&result.targets).unwrap();
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("cdn.example.test"));
        assert!(!serialized.contains(".css"));
    }

    #[test]
    fn manifest_noise_does_not_hide_later_javascript_assets() {
        let noisy_assets = (0..MAX_SCRIPT_TARGETS_PER_BODY + 1)
            .map(|index| format!(r#""static/css/route-{index}.css""#))
            .collect::<Vec<_>>()
            .join(",");
        let source = format!(
            r#"window._MODERNJS_ROUTE_MANIFEST = {{"routeAssets": {{"home": {{"assets": [{noisy_assets}, "static/js/late.js"]}}}}}};"#
        );
        let result = script_targets("https://example.test/", source.as_bytes());
        assert_eq!(result.targets, ["https://example.test/static/js/late.js"]);
        assert!(!result.truncated);
    }

    #[test]
    fn cross_origin_base_href_does_not_turn_external_script_paths_into_same_origin_requests() {
        let result = script_targets(
            "https://example.test/app/page",
            br#"
              <base href="https://cdn.example.test/assets/">
              <script src="/static/js/app.js"></script>
              <script src="https://example.test/static/js/explicit.js"></script>
            "#,
        );
        assert_eq!(
            result.targets,
            ["https://example.test/static/js/explicit.js"]
        );
    }

    #[tokio::test]
    async fn script_tree_fetches_manifest_bundles_sequentially_and_deduplicates() {
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        let root = br#"
          <input name="csrf_token">
          <script src="/static/js/main.js"></script>
          window._MODERNJS_ROUTE_MANIFEST = {"routeAssets": {"home": {"assets": [
            "static/js/main.js", "static/missing.mjs", "static/css/app.css",
            "https://cdn.example.test/foreign.js"
          ]}}};
        "#;
        let main_url = "https://example.test/static/js/main.js".to_string();
        let missing_url = "https://example.test/static/missing.mjs".to_string();
        let next_url = "https://example.test/static/next.js".to_string();
        let responses = Arc::new(HashMap::from([
            (
                main_url.clone(),
                br#"
                  fetch('/api/v1/users/:id?tab=profile');
                  window._MODERNJS_ROUTE_MANIFEST = {"routeAssets": {"home": {"assets": [
                    "static/next.js", "static/js/main.js", "static/theme.css"
                  ]}}};
                "#
                .to_vec(),
            ),
            (
                next_url.clone(),
                br#"fetch('../api/v1/accounts/{accountId}?sort=created');"#.to_vec(),
            ),
        ]));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fetch = {
            let responses = Arc::clone(&responses);
            let calls = Arc::clone(&calls);
            move |url: String| {
                let responses = Arc::clone(&responses);
                let calls = Arc::clone(&calls);
                async move {
                    calls.lock().unwrap().push(url.clone());
                    Ok(responses
                        .get(&url)
                        .cloned()
                        .map(|body| ScriptBundleContent {
                            source_url: url,
                            body,
                            status_code: Some(200),
                            content_type: Some("application/javascript".into()),
                            completion: crate::domain::CompletionState::Complete,
                        }))
                }
            }
        };
        let result =
            analyze_script_tree("https://example.test/album-cover/page", root, fetch).await;

        assert_eq!(
            *calls.lock().unwrap(),
            [main_url.clone(), missing_url.clone(), next_url.clone()]
        );
        assert_eq!(result.js_bundles, [main_url, missing_url, next_url]);
        assert_eq!(result.js_bundle_failures, 1);
        assert!(!result.js_bundles_truncated);
        assert_eq!(
            result.analysis.parameters,
            ["accountId", "csrf_token", "id", "sort", "tab"]
        );
    }

    #[tokio::test]
    async fn script_tree_stops_at_the_bundle_limit() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let root = (0..MAX_SCRIPT_BUNDLES + 4)
            .map(|index| format!("<script src=\"/static/{index}.js\"></script>"))
            .collect::<String>();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = {
            let calls = Arc::clone(&calls);
            move |url: String| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(Some(ScriptBundleContent {
                        source_url: url,
                        body: b" ".to_vec(),
                        status_code: Some(200),
                        content_type: Some("application/javascript".into()),
                        completion: crate::domain::CompletionState::Complete,
                    }))
                }
            }
        };
        let result =
            analyze_script_tree("https://example.test/index.html", root.as_bytes(), fetch).await;
        assert_eq!(calls.load(Ordering::SeqCst), MAX_SCRIPT_BUNDLES);
        assert_eq!(result.js_bundles.len(), MAX_SCRIPT_BUNDLES);
        assert!(result.js_bundles_truncated);
    }

    #[tokio::test]
    async fn script_tree_continues_after_an_empty_bundle() {
        let root = br#"
          <script src="/static/empty.js"></script>
          <script src="/static/next.js"></script>
        "#;
        let result = analyze_script_tree(
            "https://example.test/index.html",
            root,
            |url: String| async move {
                let body = if url.ends_with("/empty.js") {
                    Vec::new()
                } else {
                    b"fetch('/api/users/:user_id?include=teams');".to_vec()
                };
                Ok(Some(ScriptBundleContent {
                    source_url: url,
                    body,
                    status_code: Some(200),
                    content_type: Some("text/plain".into()),
                    completion: crate::domain::CompletionState::Complete,
                }))
            },
        )
        .await;

        assert_eq!(result.js_bundles.len(), 2);
        assert_eq!(result.analysis.parameters, ["include", "user_id"]);
        assert!(!result.js_bundles_truncated);
    }

    #[tokio::test]
    async fn script_tree_reports_source_capture_truncation() {
        let result = analyze_script_tree(
            "https://example.test/index.html",
            br#"<script src="/static/app.js"></script>"#,
            |url: String| async move {
                Ok(Some(ScriptBundleContent {
                    source_url: url,
                    body: b"fetch('/api/health');".to_vec(),
                    status_code: Some(200),
                    content_type: Some("application/javascript".into()),
                    completion: crate::domain::CompletionState::Timeout,
                }))
            },
        )
        .await;

        assert!(result.js_bundles_truncated);
        assert_eq!(result.js_bundle_failures, 1);
    }

    #[tokio::test]
    async fn script_tree_rejects_http_and_html_error_bundles_but_accepts_plain_text_javascript() {
        let root = br#"
          <script src="/missing.js"></script>
          <script src="/error.js"></script>
          <script src="/plain.js"></script>
        "#;
        let result = analyze_script_tree(
            "https://example.test/index.html",
            root,
            |url: String| async move {
                let (status_code, content_type, body) = if url.ends_with("missing.js") {
                    (
                        404,
                        "text/html",
                        b"<html>missing /api/false-positive</html>".to_vec(),
                    )
                } else if url.ends_with("error.js") {
                    (
                        200,
                        "text/html; charset=utf-8",
                        b"<html>error /api/also-false</html>".to_vec(),
                    )
                } else {
                    (200, "text/plain", b"fetch('/api/accepted');".to_vec())
                };
                Ok(Some(ScriptBundleContent {
                    source_url: url,
                    body,
                    status_code: Some(status_code),
                    content_type: Some(content_type.into()),
                    completion: crate::domain::CompletionState::Complete,
                }))
            },
        )
        .await;

        assert_eq!(result.js_bundle_failures, 2);
        assert!(result
            .analysis
            .endpoints
            .contains(&"/api/accepted".to_string()));
        assert!(!result
            .analysis
            .endpoints
            .contains(&"/api/false-positive".to_string()));
        assert!(!result
            .analysis
            .endpoints
            .contains(&"/api/also-false".to_string()));
    }

    #[tokio::test]
    async fn script_tree_resolves_nested_scripts_from_the_effective_bundle_url() {
        let result = analyze_script_tree(
            "https://example.test/index.html",
            br#"<script src="/assets/entry.js"></script>"#,
            |url: String| async move {
                let (source_url, body) = if url.ends_with("/assets/entry.js") {
                    (
                        "https://example.test/rewritten/nested/entry.js".to_string(),
                        br#"<script src="./child.js"></script>"#.to_vec(),
                    )
                } else {
                    (url.clone(), b"fetch('/api/from-child');".to_vec())
                };
                Ok(Some(ScriptBundleContent {
                    source_url,
                    body,
                    status_code: Some(200),
                    content_type: Some("text/plain".into()),
                    completion: crate::domain::CompletionState::Complete,
                }))
            },
        )
        .await;

        assert_eq!(
            result.js_bundles,
            [
                "https://example.test/assets/entry.js",
                "https://example.test/rewritten/nested/child.js",
            ]
        );
        assert!(result
            .analysis
            .endpoints
            .contains(&"/api/from-child".to_string()));
        assert_eq!(result.js_bundle_failures, 0);
    }
}
