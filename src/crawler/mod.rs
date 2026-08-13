//! Small, one-level background crawler for browser-loaded HTML pages.

use crate::app::AppEvent;
use crate::browser::BrowserService;
use crate::codec::decode_content_encodings;
use crate::domain::*;
use crate::policy::{url_is_in_scope, PresentationOptions};
use crate::reply::{ReplySendContext, ReplyService};
use crate::storage::{Db, JavascriptProvenanceInput};
use dashmap::DashSet;
use futures::{stream, StreamExt};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{broadcast, Semaphore};
use url::Url;

const MAX_LINKS_PER_PAGE: usize = 64;
const MAX_HTML_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONCURRENT_FETCHES: usize = 4;
const MAX_SEEN_URLS: usize = 50_000;

static CRAWL_TAG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)<\s*(a|script|img|link|source|video|audio|track)\b([^>]*)>"#)
        .expect("valid crawler tag regex")
});

static CRAWL_ATTRIBUTE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\b(href|src|srcset|poster|rel)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
        .expect("valid crawler attribute regex")
});

static SCRIPT_SRC_ATTRIBUTE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)<script\b[^>]*\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
        .expect("valid crawler script source regex")
});

pub struct CrawlerService {
    db: Arc<Db>,
    reply: Arc<ReplyService>,
    browser: Arc<BrowserService>,
    events: broadcast::Sender<AppEvent>,
    seen: DashSet<(ProjectId, String)>,
    permits: Arc<Semaphore>,
}

impl CrawlerService {
    pub fn new(
        db: Arc<Db>,
        reply: Arc<ReplyService>,
        browser: Arc<BrowserService>,
        events: broadcast::Sender<AppEvent>,
    ) -> Self {
        Self {
            db,
            reply,
            browser,
            events,
            seen: DashSet::new(),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_FETCHES)),
        }
    }

    /// Crawl links found in one persisted browser HTML response. Crawler
    /// responses do not trigger another crawl, which intentionally keeps this
    /// background helper at one level.
    pub async fn crawl_exchange(&self, project_id: ProjectId, exchange_id: ExchangeId) {
        if let Err(error) = self.crawl_exchange_inner(project_id, exchange_id).await {
            tracing::debug!(%project_id, %exchange_id, %error, "background crawl skipped");
        }
    }

    async fn crawl_exchange_inner(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
    ) -> DomainResult<()> {
        let detail = self
            .db
            .get_exchange_detail(project_id, exchange_id, PresentationOptions::default())
            .await?;
        if !is_html_mime(detail.summary.mime.as_deref()) {
            return Ok(());
        }

        let Some(mut body) = self
            .db
            .load_raw_body(project_id, exchange_id, MessageSide::Response)
            .await?
        else {
            return Ok(());
        };
        let headers = self
            .db
            .load_raw_headers(project_id, exchange_id, MessageSide::Response)
            .await?;
        if let Some(encoding) = headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-encoding"))
            .and_then(|header| std::str::from_utf8(&header.value).ok())
        {
            body = decode_content_encodings(&body, encoding, MAX_HTML_BYTES)?;
        }
        if body.len() > MAX_HTML_BYTES {
            body.truncate(MAX_HTML_BYTES);
        }

        let base_url = exchange_url(&detail.summary)?;
        let html = String::from_utf8_lossy(&body);
        let project = self.db.get_project(project_id).await?;
        let discovered_links = discover_links(&base_url, &html)?;
        let script_urls = discover_javascript_links(&base_url, &html, &discovered_links)?
            .into_iter()
            .filter(|url| url_is_in_scope(url, &project.scope).unwrap_or(false))
            .take(MAX_LINKS_PER_PAGE)
            .collect::<Vec<_>>();
        if !script_urls.is_empty() {
            if let Err(error) = self
                .db
                .record_javascript_files(
                    project_id,
                    &base_url,
                    script_urls
                        .into_iter()
                        .map(|url| JavascriptProvenanceInput {
                            url,
                            source_page_url: None,
                        })
                        .collect(),
                    detail.lineage.browser_session_id,
                    "source",
                )
                .await
            {
                tracing::debug!(%project_id, %exchange_id, %error, "could not record page JavaScript sources");
            }
        }
        if self.seen.len() >= MAX_SEEN_URLS {
            self.seen.clear();
        }
        self.seen.insert((project_id, base_url.clone()));
        let candidates = discovered_links
            .into_iter()
            .filter_map(|url| match url_is_in_scope(&url, &project.scope) {
                Ok(true) => Some(url),
                Ok(false) => None,
                Err(error) => {
                    tracing::debug!(%url, %error, "crawler rejected malformed candidate");
                    None
                }
            })
            .filter(|url| self.seen.insert((project_id, url.clone())))
            .take(MAX_LINKS_PER_PAGE)
            .collect::<Vec<_>>();
        let candidates = self
            .db
            .filter_uncaptured_urls(project_id, candidates)
            .await?;

        stream::iter(candidates)
            .for_each_concurrent(MAX_CONCURRENT_FETCHES, |url| async move {
                let Ok(_permit) = self.permits.clone().acquire_owned().await else {
                    return;
                };
                if let Some(session_id) = detail.lineage.browser_session_id {
                    match self
                        .browser
                        .authenticated_background_fetch(project_id, session_id, &url)
                        .await
                    {
                        Ok(true) => return,
                        Ok(false) => {}
                        Err(error) => {
                            tracing::debug!(%url, %error, "authenticated browser crawl unavailable; using HTTP transport");
                        }
                    }
                }
                let draft = ReplyDraft {
                    method: Some("GET".into()),
                    url: Some(url.clone()),
                    body_cleared: true,
                    ..Default::default()
                };
                let context = ReplySendContext {
                    source: ExchangeSource::Browser,
                    lineage: ExchangeLineage {
                        parent_exchange_id: Some(exchange_id),
                        browser_session_id: detail.lineage.browser_session_id,
                        browser_action_id: detail.lineage.browser_action_id,
                        ..Default::default()
                    },
                    plugin_target_host: None,
                };
                match self
                    .reply
                    .send_with_context(
                        project_id,
                        None,
                        &draft,
                        ProtocolPreference::Auto,
                        0,
                        context,
                    )
                    .await
                {
                    Ok(result) => {
                        if let Some(crawled_exchange_id) = result.exchange_id {
                            let _ = self.events.send(AppEvent {
                                project_id: project_id.get(),
                                kind: "exchange".into(),
                                payload: serde_json::json!({
                                    "exchange_id": crawled_exchange_id.get(),
                                    "source": "browser",
                                    "crawler": true,
                                    "parent_exchange_id": exchange_id.get(),
                                }),
                            });
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%url, %error, "background crawler request failed");
                    }
                }
            })
            .await;
        Ok(())
    }
}

fn is_html_mime(mime: Option<&str>) -> bool {
    mime.is_some_and(|mime| {
        let mime = mime
            .split(';')
            .next()
            .unwrap_or(mime)
            .trim()
            .to_ascii_lowercase();
        mime == "text/html" || mime == "application/xhtml+xml"
    })
}

fn exchange_url(summary: &ExchangeSummary) -> DomainResult<String> {
    let mut url = format!("{}://{}{}", summary.scheme, summary.authority, summary.path);
    if let Some(query) = &summary.query {
        url.push('?');
        url.push_str(query);
    }
    normalize_http_url(&url)
        .ok_or_else(|| DomainError::invalid("browser exchange has an invalid HTTP URL"))
}

fn discover_links(base: &str, html: &str) -> DomainResult<Vec<String>> {
    let base = Url::parse(base).map_err(|error| DomainError::invalid(error.to_string()))?;
    let mut found = Vec::new();
    let mut unique = HashSet::new();

    for captures in CRAWL_TAG.captures_iter(html) {
        let tag = captures
            .get(1)
            .map(|value| value.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        let attributes = captures
            .get(2)
            .map(|value| crawl_attributes(value.as_str()))
            .unwrap_or_default();
        match tag.as_str() {
            "a" => {
                add_attribute_candidate(&base, &attributes, "href", true, &mut unique, &mut found)
            }
            "script" => {
                add_attribute_candidate(&base, &attributes, "src", false, &mut unique, &mut found)
            }
            "img" => {
                add_attribute_candidate(&base, &attributes, "src", false, &mut unique, &mut found);
                if let Some(srcset) = attributes.get("srcset") {
                    for item in srcset.split(',') {
                        if let Some(raw) = item.split_whitespace().next() {
                            push_candidate(&base, raw, false, &mut unique, &mut found);
                        }
                    }
                }
            }
            "source" => {
                add_attribute_candidate(&base, &attributes, "src", false, &mut unique, &mut found);
                if let Some(srcset) = attributes.get("srcset") {
                    for item in srcset.split(',') {
                        if let Some(raw) = item.split_whitespace().next() {
                            push_candidate(&base, raw, false, &mut unique, &mut found);
                        }
                    }
                }
            }
            "link" if passive_link_rel(attributes.get("rel").map(String::as_str)) => {
                add_attribute_candidate(&base, &attributes, "href", false, &mut unique, &mut found)
            }
            "video" => {
                add_attribute_candidate(&base, &attributes, "src", false, &mut unique, &mut found);
                add_attribute_candidate(
                    &base,
                    &attributes,
                    "poster",
                    false,
                    &mut unique,
                    &mut found,
                );
            }
            "audio" | "track" => {
                add_attribute_candidate(&base, &attributes, "src", false, &mut unique, &mut found)
            }
            _ => {}
        }
    }
    Ok(found)
}

fn add_attribute_candidate(
    base: &Url,
    attributes: &HashMap<String, String>,
    name: &str,
    navigation: bool,
    unique: &mut HashSet<String>,
    found: &mut Vec<String>,
) {
    if let Some(raw) = attributes.get(name) {
        push_candidate(base, raw, navigation, unique, found);
    }
}

fn crawl_attributes(raw: &str) -> HashMap<String, String> {
    CRAWL_ATTRIBUTE
        .captures_iter(raw)
        .filter_map(|captures| {
            let name = captures.get(1)?.as_str().to_ascii_lowercase();
            let value = captures
                .get(2)
                .or_else(|| captures.get(3))
                .or_else(|| captures.get(4))?
                .as_str()
                .to_string();
            Some((name, value))
        })
        .collect()
}

fn passive_link_rel(rel: Option<&str>) -> bool {
    rel.is_some_and(|rel| {
        rel.split_ascii_whitespace().any(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "stylesheet" | "icon" | "preload" | "modulepreload" | "prefetch"
            )
        })
    })
}

fn discover_script_links(base: &str, html: &str) -> DomainResult<Vec<String>> {
    let base = Url::parse(base).map_err(|error| DomainError::invalid(error.to_string()))?;
    let mut found = Vec::new();
    let mut unique = HashSet::new();
    for captures in SCRIPT_SRC_ATTRIBUTE.captures_iter(html) {
        if let Some(raw) = capture_value(&captures) {
            push_candidate(&base, raw, false, &mut unique, &mut found);
        }
    }
    Ok(found)
}

fn discover_javascript_links(
    base: &str,
    html: &str,
    discovered_links: &[String],
) -> DomainResult<Vec<String>> {
    let mut scripts = discover_script_links(base, html)?;
    let mut unique = scripts.iter().cloned().collect::<HashSet<_>>();
    for url in discovered_links {
        if javascript_path(url) && unique.insert(url.clone()) {
            scripts.push(url.clone());
        }
    }
    Ok(scripts)
}

fn javascript_path(raw: &str) -> bool {
    Url::parse(raw).ok().is_some_and(|url| {
        let path = url.path().to_ascii_lowercase();
        path.ends_with(".js") || path.ends_with(".mjs") || path.ends_with(".cjs")
    })
}

fn capture_value<'a>(captures: &'a regex::Captures<'_>) -> Option<&'a str> {
    captures
        .get(1)
        .or_else(|| captures.get(2))
        .or_else(|| captures.get(3))
        .map(|value| value.as_str())
}

fn push_candidate(
    base: &Url,
    raw: &str,
    navigation: bool,
    unique: &mut HashSet<String>,
    found: &mut Vec<String>,
) {
    let decoded = html_escape::decode_html_entities(raw.trim());
    if decoded.is_empty()
        || decoded.starts_with('#')
        || ["data:", "javascript:", "mailto:", "tel:", "blob:", "about:"]
            .iter()
            .any(|scheme| decoded.to_ascii_lowercase().starts_with(scheme))
    {
        return;
    }
    let Ok(joined) = base.join(decoded.as_ref()) else {
        return;
    };
    if navigation && !is_clearly_safe_navigation(base, &joined) {
        return;
    }
    let Some(candidate) = normalize_url(joined) else {
        return;
    };
    if unique.insert(candidate.clone()) {
        found.push(candidate);
    }
}

fn is_clearly_safe_navigation(base: &Url, candidate: &Url) -> bool {
    if base.origin() != candidate.origin()
        || candidate.query().is_some()
        || !candidate.username().is_empty()
        || candidate.password().is_some()
    {
        return false;
    }
    const RISKY: &[&str] = &[
        "logout",
        "signout",
        "delete",
        "remove",
        "destroy",
        "revoke",
        "unsubscribe",
        "disable",
        "deactivate",
        "reset",
        "confirm",
        "activate",
        "toggle",
        "switch",
        "impersonate",
        "checkout",
        "purchase",
        "payment",
        "pay",
    ];
    !candidate
        .path_segments()
        .into_iter()
        .flatten()
        .any(|segment| {
            let stem = segment.split('.').next().unwrap_or(segment);
            let normalized = stem
                .chars()
                .filter(|character| character.is_ascii_alphanumeric())
                .collect::<String>()
                .to_ascii_lowercase();
            RISKY.iter().any(|risky| normalized.starts_with(risky))
        })
}

fn normalize_http_url(raw: &str) -> Option<String> {
    Url::parse(raw).ok().and_then(normalize_url)
}

fn normalize_url(mut url: Url) -> Option<String> {
    if url.scheme() != "http" && url.scheme() != "https" {
        return None;
    }
    url.set_fragment(None);
    Some(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_passive_assets_and_clearly_safe_navigations_only() {
        let html = r#"
            <a href="/about">About</a>
            <form action='contact?from=home'></form>
            <a href="/logout">Log out</a>
            <a href="/search?q=test">Search</a>
            <a href="https://other.example/about">Other site</a>
            <script src="//scripts.example.com/main.js"></script>
            <img srcset="/small.png 1x, https://cdn.example.net/large.png 2x">
            <video src="/intro.mp4" poster="/poster.jpg"></video>
            <audio src="/intro.ogg"></audio>
            <track src="/captions.vtt">
            <source src="/fallback.webm" srcset="/wide.webm 2x">
            <link rel="stylesheet" href="/app.css">
            <link href="/not-loaded.css">
            <a href="javascript:void(0)">skip</a>
            <a href="/about#team">duplicate without fragment</a>
        "#;
        let links = discover_links("https://example.com/base/", html).unwrap();
        assert_eq!(
            links,
            vec![
                "https://example.com/about",
                "https://scripts.example.com/main.js",
                "https://example.com/small.png",
                "https://cdn.example.net/large.png",
                "https://example.com/intro.mp4",
                "https://example.com/poster.jpg",
                "https://example.com/intro.ogg",
                "https://example.com/captions.vtt",
                "https://example.com/fallback.webm",
                "https://example.com/wide.webm",
                "https://example.com/app.css",
            ]
        );
    }

    #[test]
    fn recognizes_html_content_types_only() {
        assert!(is_html_mime(Some("text/html; charset=utf-8")));
        assert!(is_html_mime(Some("application/xhtml+xml")));
        assert!(!is_html_mime(Some("application/javascript")));
        assert!(!is_html_mime(None));
    }

    #[test]
    fn discovers_script_sources_for_page_provenance() {
        let html = r#"
            <script defer src="/app.js?v=2"></script>
            <script src='//cdn.example.com/lib.js'></script>
            <link href="/not-a-script.js">
        "#;
        assert_eq!(
            discover_javascript_links(
                "https://example.com/home",
                html,
                &discover_links("https://example.com/home", html).unwrap(),
            )
            .unwrap(),
            vec![
                "https://example.com/app.js?v=2",
                "https://cdn.example.com/lib.js",
            ]
        );
    }

    #[test]
    fn exclusions_override_wildcard_scope_for_crawl_candidates() {
        let scope = ScopePolicy {
            host_patterns: vec!["*.test.com".into()],
            excluded_host_patterns: vec!["private.test.com".into()],
            ..Default::default()
        };
        assert!(url_is_in_scope("https://cdn.test.com/app.js", &scope).unwrap());
        assert!(!url_is_in_scope("https://private.test.com/app.js", &scope).unwrap());
        assert!(!url_is_in_scope("https://unrelated.example/app.js", &scope).unwrap());
    }
}
