//! Lightweight static discovery of endpoints, absolute URLs, and emails in
//! captured JavaScript and HTML responses.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;

use crate::domain::{DomainResult, ExchangeId, MessageSide, ProjectId};
use crate::storage::Db;

const MAX_CANDIDATE_LEN: usize = 2_048;

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
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PageAnalysis {
    pub endpoints: Vec<String>,
    pub urls: Vec<String>,
    pub emails: Vec<String>,
    pub stats: PageAnalysisStats,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExchangePageAnalysis {
    pub project_id: ProjectId,
    pub exchange_id: ExchangeId,
    pub source_url: String,
    pub decoded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(flatten)]
    pub analysis: PageAnalysis,
}

/// Analyze the full stored response body, decoding HTTP content encodings first.
pub async fn analyze_exchange(
    db: &Db,
    project_id: ProjectId,
    exchange_id: ExchangeId,
) -> DomainResult<ExchangePageAnalysis> {
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
    Ok(ExchangePageAnalysis {
        project_id,
        exchange_id,
        source_url: format!(
            "{}://{}{}{}",
            detail.summary.scheme, detail.summary.authority, detail.summary.path, query
        ),
        decoded,
        content_encoding,
        analysis: analyze_page(&body),
    })
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

    let mut endpoints: Vec<_> = endpoints.into_iter().collect();
    let mut urls: Vec<_> = urls.into_iter().collect();
    let mut emails: Vec<_> = emails.into_iter().collect();
    sort_case_insensitive(&mut endpoints);
    sort_case_insensitive(&mut urls);
    sort_case_insensitive(&mut emails);
    let stats = PageAnalysisStats {
        endpoints: endpoints.len(),
        urls: urls.len(),
        emails: emails.len(),
    };
    PageAnalysis {
        endpoints,
        urls,
        emails,
        stats,
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
}
