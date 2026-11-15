//! Compact MCP-only projections of domain records. The REST API and web UI
//! keep the full serde shapes from `crate::domain`.

use crate::domain::ExchangeSummary;
use serde_json::{json, Map, Value};

/// One sentence for tool descriptions that return [`exchange_row`] rows.
pub(crate) const EXCHANGE_ROW_NOTE: &str = "Rows give url instead of host/path/query and omit null fields and defaults (source proxy, completion complete, capture_quality semantic, no labels).";

const OPTIONAL_FIELDS: [&str; 8] = [
    "status_code",
    "mime",
    "request_length",
    "response_length",
    "duration_ms",
    "page_title",
    "display_title",
    "parent_exchange_id",
];

const DEFAULTED_FIELDS: [(&str, &str); 3] = [
    ("source", "proxy"),
    ("completion", "complete"),
    ("capture_quality", "semantic"),
];

/// Compact row for one exchange: `exchange_id`, `started_at` (the stored
/// RFC 3339 value), `method` and a single `url`, plus only the fields that are
/// set or differ from their default. See [`EXCHANGE_ROW_NOTE`].
pub(crate) fn exchange_row(summary: &ExchangeSummary) -> Value {
    // Reuse the domain serialization so values match the REST shape exactly.
    let Value::Object(mut full) = json!(summary) else {
        unreachable!("ExchangeSummary serializes as a JSON object");
    };
    let mut row = Map::new();
    for key in ["exchange_id", "started_at", "method"] {
        if let Some(value) = full.remove(key) {
            row.insert(key.into(), value);
        }
    }
    row.insert("url".into(), json!(exchange_url(summary)));
    for key in OPTIONAL_FIELDS {
        if let Some(value) = full.remove(key).filter(|value| !value.is_null()) {
            row.insert(key.into(), value);
        }
    }
    for (key, default) in DEFAULTED_FIELDS {
        if let Some(value) = full.remove(key).filter(|value| value != default) {
            row.insert(key.into(), value);
        }
    }
    if !summary.labels.is_empty() {
        row.insert("labels".into(), json!(summary.labels));
    }
    Value::Object(row)
}

fn exchange_url(summary: &ExchangeSummary) -> String {
    let mut url = format!("{}://{}{}", summary.scheme, summary.authority, summary.path);
    if let Some(query) = summary.query.as_deref().filter(|query| !query.is_empty()) {
        url.push('?');
        url.push_str(query);
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::*;
    use time::OffsetDateTime;

    fn summary() -> ExchangeSummary {
        ExchangeSummary {
            project_id: ProjectId(1),
            exchange_id: ExchangeId(42),
            source: ExchangeSource::Proxy,
            started_at: OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_456_789)
                .unwrap(),
            duration_ms: None,
            method: "GET".into(),
            scheme: "https".into(),
            authority: "example.test:8443".into(),
            host: "example.test".into(),
            port: 8443,
            path: "/api/items".into(),
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
            transport_provenance: Some(TransportProvenance::SemanticProxy),
        }
    }

    #[test]
    fn defaults_and_nulls_are_omitted() {
        let summary = summary();
        let full = json!(summary);
        assert_eq!(
            exchange_row(&summary),
            json!({
                "exchange_id": 42,
                "started_at": full["started_at"],
                "method": "GET",
                "url": "https://example.test:8443/api/items",
            })
        );
        assert_eq!(full["started_at"], "2023-11-14T22:13:20.123456789Z");
    }

    #[test]
    fn set_and_non_default_fields_are_kept() {
        let mut summary = summary();
        summary.query = Some("q=1&x=%20".into());
        summary.source = ExchangeSource::Browser;
        summary.completion = CompletionState::Timeout;
        summary.capture_quality = CaptureQuality::BrowserObserved;
        summary.status_code = Some(200);
        summary.mime = Some("application/json".into());
        summary.request_length = Some(0);
        summary.response_length = Some(17);
        summary.duration_ms = Some(5);
        summary.page_title = Some("Items".into());
        summary.display_title = Some("GET items".into());
        summary.labels = vec!["auth".into()];
        summary.parent_exchange_id = Some(ExchangeId(7));
        let row = exchange_row(&summary);
        assert_eq!(row["url"], "https://example.test:8443/api/items?q=1&x=%20");
        assert_eq!(row["source"], "browser");
        assert_eq!(row["completion"], "timeout");
        assert_eq!(row["capture_quality"], "browser_observed");
        assert_eq!(row["status_code"], 200);
        assert_eq!(row["mime"], "application/json");
        assert_eq!(row["request_length"], 0);
        assert_eq!(row["response_length"], 17);
        assert_eq!(row["duration_ms"], 5);
        assert_eq!(row["page_title"], "Items");
        assert_eq!(row["display_title"], "GET items");
        assert_eq!(row["labels"], json!(["auth"]));
        assert_eq!(row["parent_exchange_id"], 7);
        assert_eq!(row.as_object().unwrap().len(), 16);
        for absent in [
            "project_id",
            "transport_provenance",
            "scheme",
            "authority",
            "host",
            "port",
            "path",
            "query",
        ] {
            assert!(row.get(absent).is_none(), "{absent}");
        }
    }

    #[test]
    fn an_empty_query_adds_no_question_mark() {
        let mut summary = summary();
        summary.query = Some(String::new());
        assert_eq!(
            exchange_row(&summary)["url"],
            "https://example.test:8443/api/items"
        );
    }
}
