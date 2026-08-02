//! Bounded extraction of static HTML document titles.

use crate::domain::{DomainResult, ExchangeId, MessageSide, ProjectId};
use crate::storage::Db;
use regex::Regex;
use std::sync::LazyLock;

const MAX_SCAN_BYTES: usize = 1024 * 1024;
const MAX_TITLE_CHARS: usize = 1024;

static TITLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<title(?:\s[^>]*)?>(.*?)</title\s*>").expect("valid title regex")
});
static TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<[^>]*>").expect("valid tag regex"));
static NUMERIC_ENTITY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)&#(?:x([0-9a-f]{1,6})|([0-9]{1,7}));").expect("valid entity regex")
});

pub fn is_html_mime(mime: Option<&str>) -> bool {
    mime.is_some_and(|mime| {
        matches!(
            mime.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "text/html" | "application/xhtml+xml"
        )
    })
}

pub fn extract_html_title(body: &[u8]) -> Option<String> {
    let scan = &body[..body.len().min(MAX_SCAN_BYTES)];
    let text = String::from_utf8_lossy(scan);
    let captured = TITLE.captures(&text)?.get(1)?.as_str();
    let without_tags = TAG.replace_all(captured, " ");
    let numeric = NUMERIC_ENTITY.replace_all(&without_tags, |captures: &regex::Captures<'_>| {
        let parsed = captures
            .get(1)
            .and_then(|value| u32::from_str_radix(value.as_str(), 16).ok())
            .or_else(|| {
                captures
                    .get(2)
                    .and_then(|value| value.as_str().parse().ok())
            });
        parsed
            .and_then(char::from_u32)
            .map(|value| value.to_string())
            .unwrap_or_else(|| captures[0].to_string())
    });
    let named = numeric
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ");
    let normalized = named
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_TITLE_CHARS)
        .collect::<String>();
    (!normalized.is_empty()).then_some(normalized)
}

pub async fn populate_static_exchange_title(
    db: &Db,
    project_id: ProjectId,
    exchange_id: ExchangeId,
) -> DomainResult<bool> {
    let detail = db
        .get_exchange_detail(
            project_id,
            exchange_id,
            crate::policy::PresentationOptions::default(),
        )
        .await?;
    if !is_html_mime(detail.summary.mime.as_deref()) {
        return Ok(false);
    }
    let Some(mut body) = db
        .load_raw_body(project_id, exchange_id, MessageSide::Response)
        .await?
    else {
        return Ok(false);
    };
    let headers = db
        .load_raw_headers(project_id, exchange_id, MessageSide::Response)
        .await?;
    let encodings = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
        .map(|header| String::from_utf8_lossy(&header.value).trim().to_string())
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("identity"))
        .collect::<Vec<_>>();
    if !encodings.is_empty() {
        body = crate::codec::decode_content_encodings(
            &body,
            &encodings.join(", "),
            crate::codec::MAX_DECODED_BODY_OUTPUT,
        )?;
    }
    let Some(title) = extract_html_title(&body) else {
        return Ok(false);
    };
    db.set_static_page_title(project_id, exchange_id, title)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_normalized_bounded_html_title() {
        assert_eq!(
            extract_html_title(b"<HTML><title>  Acme &amp; Co &#x2713; </title></HTML>").as_deref(),
            Some("Acme & Co ✓")
        );
        assert_eq!(extract_html_title(b"<html>No title</html>"), None);
    }

    #[test]
    fn recognizes_html_content_types_only() {
        assert!(is_html_mime(Some("text/html; charset=utf-8")));
        assert!(is_html_mime(Some("application/xhtml+xml")));
        assert!(!is_html_mime(Some("application/javascript")));
    }
}
