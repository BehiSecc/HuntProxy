//! MCP exchange reads: compact exchange_get with inline bodies and batches,
//! budget-fitted exchange_body pages, search and save, evidence_export bodies,
//! compact exchange_compare and the reply_send base comparison.

use base64::Engine as _;
use huntproxy::app::{bootstrap_state, AppState};
use huntproxy::config::Config;
use huntproxy::domain::*;
use huntproxy::mcp::call_tool;
use huntproxy::policy::REDACTED_PLACEHOLDER;
use huntproxy::storage::NewExchange;
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::TempDir;

/// `MAX_OUTPUT_BYTES` in `src/mcp/budget.rs`.
const BUDGET: usize = 24_000;

async fn test_state() -> (TempDir, Arc<AppState>, ProjectId) {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: directory.path().to_path_buf(),
        spool_dir: directory.path().join("spool"),
        export_dir: directory.path().join("exports"),
        runtime_dir: directory.path().join("runtime"),
        plugin_dir: directory.path().join("plugins"),
        ..Config::default()
    };
    let state = bootstrap_state(config).await.unwrap();
    let project = state
        .db
        .create_project(CreateProjectRequest {
            name: "MCP exchange output".into(),
            target_url: "https://example.com/".into(),
            advanced: None,
        })
        .await
        .unwrap();
    (directory, state, project.id)
}

fn header(name: &str, value: &str, ordinal: u32) -> HeaderEntry {
    HeaderEntry {
        name: name.into(),
        value: value.as_bytes().to_vec(),
        ordinal,
    }
}

fn exchange(project_id: ProjectId, path: &str) -> NewExchange {
    NewExchange {
        project_id,
        source: ExchangeSource::Proxy,
        protocol: "HTTP/2".into(),
        method: "POST".into(),
        scheme: "https".into(),
        authority: "example.com".into(),
        host: "example.com".into(),
        port: 443,
        path: path.into(),
        query: Some("q=1".into()),
        status_code: Some(200),
        mime: Some("text/plain".into()),
        completion: CompletionState::Complete,
        capture_quality: CaptureQuality::Semantic,
        header_representation: HeaderRepresentation::Semantic,
        body_representation: BodyRepresentation::SemanticEncoded,
        cache_provenance: CacheProvenance::None,
        transport_provenance: Some(TransportProvenance::ProtocolProfileOnly),
        transport_profile: Some("test".into()),
        request_headers: vec![
            header("Authorization", "Bearer s3cret", 0),
            header("Accept-Language", "en", 1),
            header("Content-Type", "application/json", 2),
        ],
        response_headers: vec![header("Content-Type", "text/plain", 0)],
        request_body: Some(br#"{"a":1}"#.to_vec()),
        response_body: Some(b"hello".to_vec()),
        duration_ms: Some(3),
        lineage: ExchangeLineage::default(),
        page_title: None,
        error_message: None,
    }
}

async fn insert(state: &AppState, exchange: NewExchange) -> i64 {
    state.db.insert_exchange(exchange).await.unwrap().get()
}

async fn call(state: &Arc<AppState>, tool: &str, args: Value) -> Value {
    let result = call_tool(state.clone(), tool, args).await.unwrap();
    assert_fits(&result);
    result
}

async fn call_err(state: &Arc<AppState>, tool: &str, args: Value) -> DomainError {
    call_tool(state.clone(), tool, args).await.unwrap_err()
}

fn assert_fits(result: &Value) {
    let len = result.to_string().len();
    assert!(len <= BUDGET, "result is {len} bytes");
    assert!(result.get("output_truncated").is_none());
}

/// Makes every audit insert fail, as a full or read-only audit log would.
async fn break_audit_log(state: &AppState) {
    state
        .db
        .with_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER audit_down BEFORE INSERT ON audit_events \
                 BEGIN SELECT RAISE(ABORT, 'audit log unavailable'); END;",
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))
        })
        .await
        .unwrap();
}

async fn audit_count(state: &AppState, event_type: &'static str) -> i64 {
    state
        .db
        .with_conn(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE event_type=?1",
                [event_type],
                |row| row.get(0),
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))
        })
        .await
        .unwrap()
}

fn base64_decode(value: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value.as_str().unwrap())
        .unwrap()
}

/// Text with every kind of character JSON has to escape, plus multibyte ones.
fn escape_heavy_text(len: usize) -> String {
    let unit = "line \"quoted\" \\ é€🦀\t\u{1}\n";
    unit.repeat(len / unit.len() + 1)
}

fn headers_from(pairs: Vec<(String, String)>) -> Vec<HeaderEntry> {
    pairs
        .iter()
        .enumerate()
        .map(|(ordinal, (name, value))| header(name, value, ordinal as u32))
        .collect()
}

/// A browser exchange shaped like audited agent traffic: sixteen stored cookie
/// entries, client-hint request headers, a very long vendor header and
/// policy-heavy response headers with repeated `set-cookie` lines.
fn browser_exchange(project_id: ProjectId, index: usize) -> NewExchange {
    let pair = |name: &str, value: &str| (name.to_string(), value.to_string());
    let mut request = vec![
        pair("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
        pair("accept-encoding", "gzip, deflate, br, zstd"),
        pair("accept-language", "en-US,en;q=0.9"),
        pair("cache-control", "max-age=0"),
    ];
    request.extend((0..16).map(|n| pair("cookie", &format!("cookie_{n}={}", "c".repeat(60)))));
    request.extend([
        pair("mcn-clientinfo-digest", &"d".repeat(900)),
        pair("priority", "u=0, i"),
        pair("referer", "https://example.com/search?q=widgets"),
        pair("sec-ch-ua", "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\""),
        pair("sec-ch-ua-arch", "\"x86\""),
        pair("sec-ch-ua-bitness", "\"64\""),
        pair("sec-ch-ua-form-factors", "\"Desktop\""),
        pair("sec-ch-ua-full-version", "\"146.0.7680.80\""),
        pair("sec-ch-ua-full-version-list", "\"Chromium\";v=\"146.0.7680.80\", \"Not-A.Brand\";v=\"24.0.0.0\", \"Google Chrome\";v=\"146.0.7680.80\""),
        pair("sec-ch-ua-mobile", "?0"),
        pair("sec-ch-ua-model", "\"\""),
        pair("sec-ch-ua-platform", "\"Linux\""),
        pair("sec-ch-ua-platform-version", "\"6.8.0\""),
        pair("sec-ch-ua-wow64", "?0"),
        pair("sec-fetch-dest", "document"),
        pair("sec-fetch-mode", "navigate"),
        pair("sec-fetch-site", "same-origin"),
        pair("sec-fetch-user", "?1"),
        pair("upgrade-insecure-requests", "1"),
        pair("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"),
    ]);
    let mut response = vec![
        pair("accept-ch", "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-Platform-Version"),
        pair("alt-svc", "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000"),
        pair("cache-control", "private, max-age=0"),
        pair("content-security-policy", &format!("default-src 'self'; script-src 'self' 'nonce-abc123' {}; img-src 'self' data:", "https://cdn.example.com ".repeat(24))),
        pair("content-security-policy-report-only", &format!("default-src 'none'; script-src {}; report-uri /csp-report", "https://stats.example.com ".repeat(12))),
        pair("content-type", "text/html; charset=utf-8"),
        pair("cross-origin-opener-policy", "same-origin-allow-popups"),
        pair("date", "Wed, 25 Nov 2026 10:11:12 GMT"),
        pair("nel", "{\"report_to\":\"default\",\"max_age\":2592000}"),
        pair("permissions-policy", "accelerometer=(), autoplay=(), camera=(), geolocation=(self), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"),
        pair("report-to", "{\"group\":\"default\",\"max_age\":2592000,\"endpoints\":[{\"url\":\"https://example.com/reports\"}]}"),
        pair("server", "nginx"),
    ];
    response.extend((0..3).map(|n| {
        pair(
            "set-cookie",
            &format!("track_{n}=1; Path=/; Secure; HttpOnly"),
        )
    }));
    response.extend([
        pair("vary", "Accept-Encoding"),
        pair("x-xss-protection", "0"),
    ]);

    let mut captured = exchange(project_id, &format!("/page/{index}"));
    captured.method = "GET".into();
    captured.mime = Some("text/html".into());
    captured.request_headers = headers_from(request);
    captured.response_headers = headers_from(response);
    captured.request_body = None;
    captured.response_body = Some(format!("<p>row {index}</p>\n").repeat(100).into_bytes());
    captured
}

fn lines(result: &Value, key: &str) -> Vec<String> {
    result[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} missing in {result}"))
        .iter()
        .map(|line| line.as_str().unwrap().to_string())
        .collect()
}

fn stored_value(entries: &[HeaderEntry], name: &str) -> String {
    let entry = entries.iter().find(|entry| entry.name == name).unwrap();
    String::from_utf8(entry.value.clone()).unwrap()
}

/// Reads `ids` in one call and returns the output size, the ids that came
/// back and `not_returned`. `extra` holds more arguments.
async fn read_batch(
    state: &Arc<AppState>,
    project_id: ProjectId,
    ids: &[i64],
    extra: Value,
) -> (usize, Vec<i64>, Vec<i64>) {
    let mut args = json!({"project_id": project_id.get(), "exchange_ids": ids});
    for (key, value) in extra.as_object().unwrap() {
        args[key] = value.clone();
    }
    let result = call(state, "exchange_get", args).await;
    let ids_of = |ids: &Value| -> Vec<i64> {
        ids.as_array()
            .map(|ids| ids.iter().map(|id| id.as_i64().unwrap()).collect())
            .unwrap_or_default()
    };
    let returned = result["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["exchange_id"].as_i64().unwrap())
        .collect();
    (
        result.to_string().len(),
        returned,
        ids_of(&result["not_returned"]),
    )
}

#[tokio::test]
async fn exchange_get_lists_a_repeated_redacted_header_once() {
    let (_directory, state, project_id) = test_state().await;
    let mut captured = exchange(project_id, "/cookies");
    captured.request_headers = vec![
        header("Cookie", "a=1", 0),
        header("Accept", "*/*", 1),
        header("cookie", "b=2", 2),
        header("Cookie", "c=3", 3),
        header("X-Dup", "one", 4),
        header("X-Dup", "one", 5),
        header("Authorization", "Bearer s3cret", 6),
    ];
    captured.response_headers = vec![
        header("Set-Cookie", "a=1; Path=/", 0),
        header("Content-Type", "text/plain", 1),
        header("set-cookie", "b=2", 2),
    ];
    let id = insert(&state, captured).await;
    let project = project_id.get();

    for headers in [None, Some("full"), Some("compact")] {
        let mut args = json!({"project_id": project, "exchange_id": id});
        if let Some(headers) = headers {
            args["headers"] = json!(headers);
        }
        let result = call(&state, "exchange_get", args).await;
        assert_eq!(
            lines(&result, "request_headers"),
            [
                "Cookie: <redacted>",
                "Accept: */*",
                "X-Dup: one",
                "X-Dup: one",
                "Authorization: <redacted>"
            ],
            "{headers:?}"
        );
        assert_eq!(
            lines(&result, "response_headers"),
            ["Set-Cookie: <redacted>", "Content-Type: text/plain"]
        );
        // Every redacted entry is still counted.
        assert_eq!(result["redacted_count"], 6);
        assert!(!result.to_string().contains("s3cret"));
    }

    // A batch lists them once as well.
    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_ids": [id]}),
    )
    .await;
    assert_eq!(
        result["exchanges"][0]["response_headers"],
        json!(["Set-Cookie: <redacted>", "Content-Type: text/plain"])
    );
}

#[tokio::test]
async fn exchange_get_default_headers_are_unchanged_apart_from_collapsed_redactions() {
    use huntproxy::policy::{is_sensitive_header, NOISY_HEADERS};

    let (_directory, state, project_id) = test_state().await;
    let captured = browser_exchange(project_id, 0);
    let (stored_request, stored_response) = (
        captured.request_headers.clone(),
        captured.response_headers.clone(),
    );
    let id = insert(&state, captured).await;
    let project = project_id.get();

    // Every stored header that was listed before is still listed in order, in
    // full, with sensitive values redacted and a repeated redaction once.
    let expected = |entries: &[HeaderEntry]| -> Vec<String> {
        let mut redacted = std::collections::HashSet::new();
        entries
            .iter()
            .filter(|entry| !NOISY_HEADERS.contains(&entry.name.as_str()))
            .filter_map(|entry| {
                if !is_sensitive_header(&entry.name) {
                    let value = String::from_utf8(entry.value.clone()).unwrap();
                    Some(format!("{}: {value}", entry.name))
                } else if redacted.insert(entry.name.clone()) {
                    Some(format!("{}: {REDACTED_PLACEHOLDER}", entry.name))
                } else {
                    None
                }
            })
            .collect()
    };
    let default = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_id": id}),
    )
    .await;
    assert_eq!(
        lines(&default, "request_headers"),
        expected(&stored_request)
    );
    assert_eq!(
        lines(&default, "response_headers"),
        expected(&stored_response)
    );
    assert_eq!(lines(&default, "request_headers").len(), 9);
    assert_eq!(lines(&default, "response_headers").len(), 15);
    let digest = stored_value(&stored_request, "mcn-clientinfo-digest");
    assert!(
        lines(&default, "request_headers").contains(&format!("mcn-clientinfo-digest: {digest}"))
    );
    assert!(lines(&default, "request_headers")
        .iter()
        .any(|line| line.starts_with("user-agent: Mozilla")));
    assert!(lines(&default, "response_headers")
        .iter()
        .any(|line| line.starts_with("date: ")));
    assert_eq!(default["redacted_count"], 19);
    assert_eq!(default["noisy_hidden_count"], 16);
    assert!(default.get("hidden_headers").is_none());

    // Naming the default, or sending null as some clients do, changes nothing.
    for headers in [json!("full"), Value::Null] {
        let same = call(
            &state,
            "exchange_get",
            json!({"project_id": project, "exchange_id": id, "headers": headers}),
        )
        .await;
        assert_eq!(same, default);
    }
}

#[tokio::test]
async fn exchange_get_compact_hides_low_signal_headers_and_cuts_long_values() {
    let (_directory, state, project_id) = test_state().await;
    let captured = browser_exchange(project_id, 0);
    let (stored_request, stored_response) = (
        captured.request_headers.clone(),
        captured.response_headers.clone(),
    );
    let id = insert(&state, captured).await;
    let project = project_id.get();

    let full = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_id": id}),
    )
    .await;
    let compact = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_id": id, "headers": "compact"}),
    )
    .await;

    let cut = |value: String| {
        let dropped = value.chars().count() - 256;
        format!("{}... [{dropped} chars dropped]", &value[..256])
    };
    assert_eq!(
        lines(&compact, "request_headers"),
        [
            format!("accept: {}", stored_value(&stored_request, "accept")),
            "cache-control: max-age=0".to_string(),
            "cookie: <redacted>".to_string(),
            format!(
                "mcn-clientinfo-digest: {}",
                cut(stored_value(&stored_request, "mcn-clientinfo-digest"))
            ),
            "referer: https://example.com/search?q=widgets".to_string(),
        ]
    );
    assert_eq!(
        lines(&compact, "response_headers"),
        [
            "cache-control: private, max-age=0".to_string(),
            format!(
                "content-security-policy: {}",
                cut(stored_value(&stored_response, "content-security-policy"))
            ),
            "content-type: text/html; charset=utf-8".to_string(),
            "cross-origin-opener-policy: same-origin-allow-popups".to_string(),
            "server: nginx".to_string(),
            "set-cookie: <redacted>".to_string(),
            "vary: Accept-Encoding".to_string(),
        ]
    );
    // Each hidden name once: what headers=full would add.
    assert_eq!(
        compact["hidden_headers"],
        json!([
            "accept-encoding",
            "sec-ch-ua-form-factors",
            "sec-ch-ua-full-version-list",
            "user-agent",
            "accept-ch",
            "alt-svc",
            "content-security-policy-report-only",
            "date",
            "nel",
            "permissions-policy",
            "report-to",
            "x-xss-protection"
        ])
    );
    let listed = |result: &Value| {
        [
            lines(result, "request_headers"),
            lines(result, "response_headers"),
        ]
        .concat()
        .into_iter()
        .map(|line| line.split(": ").next().unwrap().to_string())
        .collect::<std::collections::BTreeSet<_>>()
    };
    let added = listed(&full)
        .difference(&listed(&compact))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let hidden = compact["hidden_headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap().to_string())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(added, hidden, "hidden_headers names exactly what full adds");
    // Counts keep their meaning; the body and the rest of the row are as before.
    assert_eq!(compact["redacted_count"], full["redacted_count"]);
    assert_eq!(compact["noisy_hidden_count"], 16);
    assert_eq!(compact["response_body"], full["response_body"]);
    assert!(full.get("hidden_headers").is_none());
    assert!(compact.to_string().len() < full.to_string().len());
    let keys = |result: &Value| {
        result
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
    };
    let mut expected_keys = keys(&full);
    expected_keys.insert("hidden_headers".into());
    assert_eq!(keys(&compact), expected_keys);

    // Short values are never cut, and a value at the limit is kept whole.
    let mut limits = exchange(project_id, "/limits");
    limits.request_headers = vec![
        header("X-Exact", &"e".repeat(256), 0),
        header("X-Over", &"o".repeat(257), 1),
        header("X-Euro", &"€".repeat(300), 2),
        header("Pragma", "no-cache", 3),
    ];
    limits.response_headers = vec![header("Pragma", "no-cache", 0)];
    let limits_id = insert(&state, limits).await;
    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_id": limits_id, "headers": "compact"}),
    )
    .await;
    assert_eq!(
        lines(&result, "request_headers"),
        [
            format!("X-Exact: {}", "e".repeat(256)),
            format!("X-Over: {}... [1 chars dropped]", "o".repeat(256)),
            format!("X-Euro: {}... [44 chars dropped]", "€".repeat(256)),
        ]
    );
    // pragma is hidden on the request side only.
    assert_eq!(lines(&result, "response_headers"), ["Pragma: no-cache"]);
    assert_eq!(result["hidden_headers"], json!(["pragma"]));

    // Nothing hidden: no hidden_headers.
    let plain = insert(&state, exchange(project_id, "/plain")).await;
    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_id": plain, "headers": "compact"}),
    )
    .await;
    assert!(result.get("hidden_headers").is_none());
    assert_eq!(
        lines(&result, "request_headers"),
        [
            format!("Authorization: {REDACTED_PLACEHOLDER}"),
            "Content-Type: application/json".to_string()
        ]
    );
}

#[tokio::test]
async fn exchange_get_headers_none_omits_both_lists_and_keeps_the_counts() {
    let (_directory, state, project_id) = test_state().await;
    let id = insert(&state, browser_exchange(project_id, 0)).await;

    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project_id.get(), "exchange_id": id, "headers": "none"}),
    )
    .await;
    for absent in ["request_headers", "response_headers", "hidden_headers"] {
        assert!(result.get(absent).is_none(), "{absent}");
    }
    assert_eq!(result["redacted_count"], 19);
    assert_eq!(result["noisy_hidden_count"], 16);
    assert_eq!(result["exchange_id"], id);
    assert_eq!(result["response_body"]["total"], 1_300);
}

#[tokio::test]
async fn compact_and_none_headers_return_more_of_a_batch() {
    let (_directory, state, project_id) = test_state().await;
    let mut ids = Vec::new();
    for index in 0..20 {
        ids.push(insert(&state, browser_exchange(project_id, index)).await);
    }

    let mut returned_counts = Vec::new();
    for extra in [
        json!({}),
        json!({"headers": "full"}),
        json!({"headers": "compact"}),
        json!({"headers": "none"}),
    ] {
        let (bytes, returned, not_returned) = read_batch(&state, project_id, &ids, extra).await;
        assert!(bytes <= BUDGET);
        assert_eq!([returned.clone(), not_returned].concat(), ids);
        assert_eq!(returned, ids[..returned.len()], "request order is kept");
        returned_counts.push(returned.len());
    }
    let (default, full, compact, none) = (
        returned_counts[0],
        returned_counts[1],
        returned_counts[2],
        returned_counts[3],
    );
    assert_eq!(default, full);
    assert!(
        full < 20,
        "the full headers of 20 browser exchanges do not fit"
    );
    assert!(compact > full, "compact {compact} vs full {full}");
    assert!(none > compact, "none {none} vs compact {compact}");

    // Headers-only reads (the usual body_bytes 0) gain the same way.
    let mut counts = Vec::new();
    for headers in ["full", "compact", "none"] {
        let (_, returned, _) = read_batch(
            &state,
            project_id,
            &ids,
            json!({"headers": headers, "body_bytes": 0}),
        )
        .await;
        counts.push(returned.len());
    }
    assert!(counts[0] < counts[1] && counts[1] < counts[2], "{counts:?}");
    assert_eq!(counts[2], 20, "rows without headers or bodies are small");
}

#[tokio::test]
async fn exchange_get_validates_headers_and_treats_null_like_absent() {
    let (_directory, state, project_id) = test_state().await;
    let id = insert(&state, exchange(project_id, "/api")).await;
    let project = project_id.get();

    for bad in [
        json!("all"),
        json!(""),
        json!("Compact"),
        json!(true),
        json!(1),
    ] {
        let error = call_err(
            &state,
            "exchange_get",
            json!({"project_id": project, "exchange_id": id, "headers": bad}),
        )
        .await;
        assert_eq!(error.code(), ErrorCode::InvalidArgument, "{bad}");
        assert!(error.to_string().contains("full|compact|none"));
    }
    let error = call_err(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_ids": [id], "headers": "wide"}),
    )
    .await;
    assert_eq!(error.code(), ErrorCode::InvalidArgument);

    // A client that sends every property, null for the unused ones.
    let single = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_id": id}),
    )
    .await;
    let nulls = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_id": id, "exchange_ids": null,
               "body_bytes": null, "headers": null}),
    )
    .await;
    assert_eq!(nulls, single);
    let batch = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_id": null, "exchange_ids": [id],
               "body_bytes": null, "headers": null}),
    )
    .await;
    assert_eq!(batch["exchanges"], json!([single]));
}

#[tokio::test]
async fn exchange_get_is_compact_and_inlines_small_bodies() {
    let (_directory, state, project_id) = test_state().await;
    let id = insert(&state, exchange(project_id, "/api")).await;

    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project_id.get(), "exchange_id": id}),
    )
    .await;
    assert_eq!(result["exchange_id"], id);
    assert_eq!(result["url"], "https://example.com/api?q=1");
    assert_eq!(result["protocol"], "HTTP/2");
    assert_eq!(
        result["request_headers"],
        json!([
            format!("Authorization: {REDACTED_PLACEHOLDER}"),
            "Content-Type: application/json"
        ])
    );
    assert_eq!(
        result["response_headers"],
        json!(["Content-Type: text/plain"])
    );
    assert_eq!(result["redacted_count"], 1);
    assert_eq!(result["noisy_hidden_count"], 1);
    assert_eq!(
        result["request_body"],
        json!({"text": r#"{"a":1}"#, "total": 7})
    );
    assert_eq!(
        result["response_body"],
        json!({"text": "hello", "total": 5})
    );
    for absent in [
        "annotation",
        "applied_request_rules",
        "lineage",
        "header_representation",
        "body_representation",
        "cache_provenance",
        "transport_provenance",
        "summary",
        "host",
        "request_preview",
        "request_body_hash",
        "source",
    ] {
        assert!(result.get(absent).is_none(), "{absent} should be omitted");
    }
    assert!(!result.to_string().contains("s3cret"));

    // Non-default provenance, lineage and annotations are kept.
    let mut browser = exchange(project_id, "/browser");
    browser.body_representation = BodyRepresentation::BrowserDecoded;
    let browser_id = insert(&state, browser).await;
    call(
        &state,
        "exchange_annotate",
        json!({"project_id": project_id.get(), "exchange_id": browser_id, "note": "look here"}),
    )
    .await;
    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project_id.get(), "exchange_id": browser_id}),
    )
    .await;
    assert_eq!(result["body_representation"], "browser_decoded");
    assert_eq!(result["annotation"]["note"], "look here");
    assert!(result["annotation"]["revision"].is_i64());
    assert!(result.get("header_representation").is_none());
}

#[tokio::test]
async fn exchange_get_cuts_large_bodies_and_marks_binary_and_missing_ones() {
    let (_directory, state, project_id) = test_state().await;
    let large = "é".repeat(5_000); // 10,000 bytes
    let mut captured = exchange(project_id, "/large");
    captured.request_body = None;
    captured.response_body = Some(large.clone().into_bytes());
    let large_id = insert(&state, captured).await;

    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project_id.get(), "exchange_id": large_id}),
    )
    .await;
    assert!(result.get("request_body").is_none(), "no request body");
    let body = &result["response_body"];
    assert_eq!(body["total"], 10_000);
    assert_eq!(body["truncated"], true);
    assert_eq!(body["next_offset"], 4096);
    assert_eq!(body["text"].as_str().unwrap(), &large[..4096]);
    assert_eq!(body["hash"].as_str().unwrap().len(), 64);

    // The continuation reads exactly the rest.
    let rest = call(
        &state,
        "exchange_body",
        json!({"project_id": project_id.get(), "exchange_id": large_id, "offset": 4096}),
    )
    .await;
    assert_eq!(rest["preview"].as_str().unwrap(), &large[4096..]);
    assert_eq!(rest["truncated"], false);

    // A cut never splits a character.
    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project_id.get(), "exchange_id": large_id, "body_bytes": 5}),
    )
    .await;
    assert_eq!(result["response_body"]["text"], "éé");
    assert_eq!(result["response_body"]["next_offset"], 4);

    let mut binary = exchange(project_id, "/binary");
    binary.response_body = Some(vec![0xff, 0xfe, 0x00]);
    let binary_id = insert(&state, binary).await;
    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project_id.get(), "exchange_id": binary_id}),
    )
    .await;
    let body = result["response_body"].as_object().unwrap();
    assert_eq!(body["binary"], true);
    assert_eq!(body["total"], 3);
    assert!(body.contains_key("hash"));
    assert!(!body.contains_key("text"));

    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project_id.get(), "exchange_id": binary_id, "body_bytes": 0}),
    )
    .await;
    assert!(result.get("request_body").is_none());
    assert!(result.get("response_body").is_none());

    // A single exchange with two large escape-heavy bodies still fits.
    let mut heavy = exchange(project_id, "/heavy");
    heavy.request_body = Some(escape_heavy_text(40_000).into_bytes());
    heavy.response_body = Some(escape_heavy_text(40_000).into_bytes());
    let heavy_id = insert(&state, heavy).await;
    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project_id.get(), "exchange_id": heavy_id, "body_bytes": 16_384}),
    )
    .await;
    for side in ["request_body", "response_body"] {
        let next = result[side]["next_offset"].as_u64().unwrap() as usize;
        assert_eq!(result[side]["text"].as_str().unwrap().len(), next);
        assert!(next > 2_000, "{side} keeps a fair share: {next}");
    }

    let error = call_err(
        &state,
        "exchange_get",
        json!({"project_id": project_id.get(), "exchange_id": 999_999}),
    )
    .await;
    assert_eq!(error.code(), ErrorCode::NotFound);
}

#[tokio::test]
async fn exchange_get_batches_share_the_budget_in_request_order() {
    let (_directory, state, project_id) = test_state().await;
    let mut ids = Vec::new();
    for index in 0..8 {
        let mut captured = exchange(project_id, &format!("/item/{index}"));
        captured.response_body = Some(format!("{index}").repeat(20_000).into_bytes());
        ids.push(insert(&state, captured).await);
    }
    let small = insert(&state, exchange(project_id, "/small")).await;

    let requested = vec![ids[3], 999_999, small, ids[0], ids[1], ids[2], ids[4]];
    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project_id.get(), "exchange_ids": requested, "body_bytes": 16_384}),
    )
    .await;
    assert!(result.get("not_returned").is_none());
    let exchanges = result["exchanges"].as_array().unwrap();
    let order = exchanges
        .iter()
        .map(|entry| entry["exchange_id"].as_i64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(order, requested);
    assert!(exchanges[1]["error"].as_str().unwrap().contains("999999"));
    assert_eq!(
        exchanges[2]["response_body"],
        json!({"text": "hello", "total": 5})
    );
    let shares = [0, 3, 4, 5, 6].map(|index| {
        exchanges[index]["response_body"]["next_offset"]
            .as_u64()
            .unwrap()
    });
    assert!(shares.iter().all(|share| *share == shares[0]), "{shares:?}");
    assert!(shares[0] > 2_000, "{shares:?}");

    // When even small shares do not fit, trailing ids are not returned.
    let mut many = Vec::new();
    for index in 0..20 {
        let mut captured = exchange(project_id, &format!("/wide/{index}"));
        captured.response_headers = (0..4)
            .map(|ordinal| header(&format!("X-Wide-{ordinal}"), &"w".repeat(400), ordinal))
            .collect();
        many.push(insert(&state, captured).await);
    }
    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project_id.get(), "exchange_ids": many}),
    )
    .await;
    let returned = result["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["exchange_id"].as_i64().unwrap())
        .collect::<Vec<_>>();
    let not_returned = result["not_returned"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_i64().unwrap())
        .collect::<Vec<_>>();
    assert!(!returned.is_empty() && !not_returned.is_empty());
    assert_eq!([returned, not_returned].concat(), many);

    for args in [
        json!({"project_id": project_id.get()}),
        json!({"project_id": project_id.get(), "exchange_id": small, "exchange_ids": [small]}),
        json!({"project_id": project_id.get(), "exchange_ids": []}),
        json!({"project_id": project_id.get(), "exchange_ids": (0..21).collect::<Vec<_>>()}),
        json!({"project_id": project_id.get(), "exchange_ids": ["one"]}),
        json!({"project_id": project_id.get(), "exchange_id": small, "body_bytes": -1}),
    ] {
        let error = call_err(&state, "exchange_get", args).await;
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }
}

async fn read_all_pages(
    state: &Arc<AppState>,
    project_id: ProjectId,
    id: i64,
    encoding: &str,
) -> (Vec<u8>, usize) {
    let mut bytes = Vec::new();
    let mut offset = 0;
    let mut pages = 0;
    loop {
        let page = call(
            state,
            "exchange_body",
            json!({"project_id": project_id.get(), "exchange_id": id, "offset": offset,
                   "max_bytes": 1_048_576, "encoding": encoding}),
        )
        .await;
        pages += 1;
        let chunk = if encoding == "base64" {
            base64_decode(&page["preview"])
        } else {
            page["preview"].as_str().unwrap().as_bytes().to_vec()
        };
        assert_eq!(chunk.len(), page["length"].as_u64().unwrap() as usize);
        bytes.extend(chunk);
        match page["next_offset"].as_u64() {
            Some(next) => {
                assert_eq!(page["truncated"], true);
                assert_eq!(
                    next as usize,
                    offset + page["length"].as_u64().unwrap() as usize
                );
                offset = next as usize;
            }
            None => {
                assert_eq!(page["truncated"], false);
                return (bytes, pages);
            }
        }
    }
}

#[tokio::test]
async fn a_body_that_fails_to_decode_points_to_the_raw_read() {
    let (_directory, state, project_id) = test_state().await;
    let project = project_id.get();
    let mut broken = exchange(project_id, "/broken");
    broken.response_headers = vec![
        header("Content-Type", "text/plain", 0),
        header("Content-Encoding", "gzip", 1),
    ];
    broken.response_body = Some(b"not gzip at all".to_vec());
    let id = insert(&state, broken).await;

    // exchange_get still succeeds; the body carries the error and the way out.
    let result = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_id": id}),
    )
    .await;
    let message = result["response_body"]["error"].as_str().unwrap();
    assert!(message.starts_with("gzip decode:"), "{message}");
    assert!(
        message.ends_with("; retry exchange_body with raw=true to read the stored bytes"),
        "{message}"
    );
    assert_eq!(
        result["request_body"],
        json!({"text": r#"{"a":1}"#, "total": 7}),
        "the request side is not decoded"
    );
    let batch = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_ids": [id]}),
    )
    .await;
    assert_eq!(
        batch["exchanges"][0]["response_body"]["error"],
        result["response_body"]["error"]
    );

    // exchange_body fails with the same hint, whatever it was asked to do.
    for args in [
        json!({"project_id": project, "exchange_id": id}),
        json!({"project_id": project, "exchange_id": id, "search": "gzip"}),
        json!({"project_id": project, "exchange_id": id, "save": true}),
    ] {
        let error = call_err(&state, "exchange_body", args).await;
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error
                .to_string()
                .ends_with("; retry exchange_body with raw=true to read the stored bytes"),
            "{error}"
        );
    }

    // raw=true reads the stored bytes, and the hint's advice works.
    let raw = call(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": id, "raw": true}),
    )
    .await;
    assert_eq!(raw["preview"], "not gzip at all");

    // An unsupported encoding gets the same advice; other errors are unchanged.
    let mut unknown = exchange(project_id, "/unknown");
    unknown.response_headers = vec![header("Content-Encoding", "x-custom", 0)];
    let unknown_id = insert(&state, unknown).await;
    let error = call_err(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": unknown_id}),
    )
    .await;
    assert!(error.to_string().contains("unsupported content encoding"));
    assert!(error.to_string().contains("raw=true"));
    let error = call_err(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": 999_999}),
    )
    .await;
    assert_eq!(error.code(), ErrorCode::NotFound);
    assert!(!error.to_string().contains("raw=true"));
}

#[tokio::test]
async fn exchange_body_pages_fit_the_budget_and_reassemble_exactly() {
    let (_directory, state, project_id) = test_state().await;
    let text = escape_heavy_text(100_000);
    let mut captured = exchange(project_id, "/text");
    captured.response_body = Some(text.clone().into_bytes());
    let text_id = insert(&state, captured).await;
    let (bytes, pages) = read_all_pages(&state, project_id, text_id, "utf8").await;
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        text,
        "lossless for UTF-8"
    );
    assert!(pages > 4, "escaping shrinks pages: {pages}");

    let binary = (0..200_000u32)
        .map(|n| (n.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect::<Vec<_>>();
    let mut captured = exchange(project_id, "/binary");
    captured.response_body = Some(binary.clone());
    let binary_id = insert(&state, captured).await;
    let (bytes, _) = read_all_pages(&state, project_id, binary_id, "base64").await;
    assert_eq!(bytes, binary);

    // The default page is 16 KiB of plain text.
    let mut plain = exchange(project_id, "/plain");
    plain.response_body = Some(vec![b'p'; 20_000]);
    let plain_id = insert(&state, plain).await;
    let page = call(
        &state,
        "exchange_body",
        json!({"project_id": project_id.get(), "exchange_id": plain_id}),
    )
    .await;
    assert_eq!(page["length"], 16_384);
    assert_eq!(page["next_offset"], 16_384);
    for absent in [
        "available",
        "encoding",
        "decoded",
        "content_encoding",
        "raw_total",
    ] {
        assert!(page.get(absent).is_none(), "{absent}");
    }
}

#[tokio::test]
async fn exchange_body_search_returns_offsets_for_follow_up_reads() {
    let (_directory, state, project_id) = test_state().await;
    let body = "ééé start Token=abc; middle TOKEN=def; end token".to_string();
    let mut captured = exchange(project_id, "/search");
    captured.response_body = Some(body.clone().into_bytes());
    let id = insert(&state, captured).await;
    let project = project_id.get();

    let result = call(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": id, "search": "token", "context_bytes": 8}),
    )
    .await;
    assert_eq!(result["match_count"], 3);
    assert!(result.get("next_offset").is_none());
    assert!(result.get("preview").is_none());
    let matches = result["matches"].as_array().unwrap();
    let offsets = matches
        .iter()
        .map(|hit| hit["offset"].as_u64().unwrap() as usize)
        .collect::<Vec<_>>();
    let expected = body
        .to_ascii_lowercase()
        .match_indices("token")
        .map(|(offset, _)| offset)
        .collect::<Vec<_>>();
    assert_eq!(offsets, expected);
    for (hit, &offset) in matches.iter().zip(&offsets) {
        assert!(hit["context"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .contains("token"));
        assert_eq!(&body[offset..offset + 5].to_ascii_lowercase(), "token");
    }
    let read = call(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": id, "offset": offsets[1], "max_bytes": 9}),
    )
    .await;
    assert_eq!(read["preview"], "TOKEN=def");

    // Context near the start never splits the multibyte prefix.
    let result = call(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": id, "search": "start", "context_bytes": 9}),
    )
    .await;
    assert!(!result["matches"][0]["context"]
        .as_str()
        .unwrap()
        .contains('\u{fffd}'));

    // Searching from an offset skips earlier matches.
    let result = call(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": id, "search": "TOKEN", "offset": offsets[0] + 1}),
    )
    .await;
    assert_eq!(result["match_count"], 2);
    assert_eq!(result["matches"][0]["offset"], offsets[1]);

    for args in [
        json!({"project_id": project, "exchange_id": id, "search": ""}),
        json!({"project_id": project, "exchange_id": id, "search": "x", "encoding": "base64"}),
        json!({"project_id": project, "exchange_id": id, "search": "x", "save": true}),
        json!({"project_id": project, "exchange_id": id, "search": 5}),
    ] {
        let error = call_err(&state, "exchange_body", args).await;
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }
}

#[tokio::test]
async fn exchange_body_search_caps_the_count_and_continues_after_the_last_match() {
    let (_directory, state, project_id) = test_state().await;
    let body = "needle ".repeat(12_000);
    let mut captured = exchange(project_id, "/many");
    captured.response_body = Some(body.into_bytes());
    let id = insert(&state, captured).await;

    let mut offset = 0;
    let mut seen = Vec::new();
    for call_index in 0..3 {
        let result = call(
            &state,
            "exchange_body",
            json!({"project_id": project_id.get(), "exchange_id": id, "search": "NEEDLE",
                   "offset": offset, "context_bytes": 2_000}),
        )
        .await;
        let matches = result["matches"].as_array().unwrap();
        assert!(
            !matches.is_empty() && matches.len() < 100,
            "{}",
            matches.len()
        );
        if call_index == 0 {
            assert_eq!(result["match_count"], 10_000);
            assert_eq!(result["match_count_capped"], true);
        }
        let offsets = matches
            .iter()
            .map(|hit| hit["offset"].as_u64().unwrap())
            .collect::<Vec<_>>();
        let next = result["next_offset"].as_u64().unwrap();
        assert_eq!(next, offsets.last().unwrap() + 6);
        seen.extend(offsets);
        offset = next;
    }
    let expected = (0..seen.len() as u64).map(|n| n * 7).collect::<Vec<_>>();
    assert_eq!(seen, expected, "continuation neither skips nor repeats");
}

#[tokio::test]
async fn exchange_body_save_writes_the_decoded_body_privately_and_audits_it() {
    let (directory, state, project_id) = test_state().await;
    let json_body = br#"{"items":[1,2,3]}"#.repeat(1_000);
    let compressed = zstd::encode_all(json_body.as_slice(), 1).unwrap();
    let mut captured = exchange(project_id, "/saved");
    captured.mime = Some("application/json; charset=utf-8".into());
    captured.response_headers = vec![
        header("Content-Type", "application/json; charset=utf-8", 0),
        header("Content-Encoding", "zstd", 1),
    ];
    captured.response_body = Some(compressed.clone());
    let id = insert(&state, captured).await;
    let project = project_id.get();

    let result = call(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": id, "save": true}),
    )
    .await;
    assert_eq!(result.as_object().unwrap().len(), 2, "{result}");
    assert_eq!(result["bytes"], json_body.len());
    let path = std::path::PathBuf::from(result["path"].as_str().unwrap());
    assert_eq!(
        path,
        directory
            .path()
            .join("exports")
            .join(format!("exchange_{project}_{id}_response.json"))
    );
    assert_eq!(std::fs::read(&path).unwrap(), json_body);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(audit_count(&state, "exchange_body_save").await, 1);

    let raw = call(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": id, "save": true, "raw": true}),
    )
    .await;
    assert!(raw["path"].as_str().unwrap().ends_with("_response_raw.bin"));
    assert_eq!(
        std::fs::read(raw["path"].as_str().unwrap()).unwrap(),
        compressed
    );

    let request = call(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": id, "save": true, "side": "request"}),
    )
    .await;
    assert!(request["path"].as_str().unwrap().ends_with("_request.json"));

    let error = call_err(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": id, "save": true, "offset": 3}),
    )
    .await;
    assert_eq!(error.code(), ErrorCode::InvalidArgument);

    // Nothing is written when the save cannot be audited.
    std::fs::remove_file(&path).unwrap();
    break_audit_log(&state).await;
    let error = call_err(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": id, "save": true}),
    )
    .await;
    assert_eq!(error.code(), ErrorCode::StorageError);
    assert!(!path.exists());
}

#[tokio::test]
async fn evidence_export_includes_bodies_by_default() {
    let (_directory, state, project_id) = test_state().await;
    let mut captured = exchange(project_id, "/evidence");
    captured.response_body = Some(vec![0xff, 0x00, 0x01]);
    let id = insert(&state, captured).await;
    let project = project_id.get();

    let result = call(
        &state,
        "evidence_export",
        json!({"project_id": project, "exchange_id": id}),
    )
    .await;
    let path = result["path"].as_str().unwrap();
    let data = std::fs::read(path).unwrap();
    assert_eq!(result["bytes"], data.len());
    let evidence: Value = serde_json::from_slice(&data).unwrap();
    assert_eq!(evidence["summary"]["exchange_id"], id);
    assert_eq!(
        evidence["request_body"],
        json!({"bytes": 7, "text": r#"{"a":1}"#})
    );
    assert_eq!(evidence["response_body"]["bytes"], 3);
    assert_eq!(
        base64_decode(&evidence["response_body"]["base64"]),
        [0xff, 0x00, 0x01]
    );
    assert!(!String::from_utf8_lossy(&data).contains("s3cret"));
    assert_eq!(audit_count(&state, "evidence_export").await, 1);

    let result = call(
        &state,
        "evidence_export",
        json!({"project_id": project, "exchange_id": id, "include_bodies": false}),
    )
    .await;
    let evidence: Value =
        serde_json::from_slice(&std::fs::read(result["path"].as_str().unwrap()).unwrap()).unwrap();
    assert!(evidence.get("request_body").is_none());
    assert!(evidence.get("response_body").is_none());
    assert_eq!(evidence["summary"]["exchange_id"], id);

    std::fs::remove_file(path).unwrap();
    break_audit_log(&state).await;
    let error = call_err(
        &state,
        "evidence_export",
        json!({"project_id": project, "exchange_id": id}),
    )
    .await;
    assert_eq!(error.code(), ErrorCode::StorageError);
    assert!(!std::path::Path::new(path).exists());
}

#[tokio::test]
async fn exchange_compare_lists_only_differences_within_the_budget() {
    let (_directory, state, project_id) = test_state().await;
    let project = project_id.get();
    let lines = |tag: &str| {
        (0..1_500)
            .map(|n| format!("{tag} line {n} with some padding text\n"))
            .collect::<String>()
    };
    let mut left = exchange(project_id, "/compare");
    left.response_body = Some(lines("left").into_bytes());
    left.response_headers = (0..40)
        .map(|n| header("Set-Cookie", &format!("c{n}=left"), n))
        .collect();
    let mut right = exchange(project_id, "/compare");
    right.response_body = Some(lines("right").into_bytes());
    right.response_headers = (0..40)
        .map(|n| header("Set-Cookie", &format!("c{n}=right"), n))
        .collect();
    let left = insert(&state, left).await;
    let right = insert(&state, right).await;

    let result = call(
        &state,
        "exchange_compare",
        json!({"project_id": project, "left_exchange_id": left, "right_exchange_id": right}),
    )
    .await;
    assert_eq!(
        result["request"]["unchanged"],
        json!(["method", "url", "headers", "body"])
    );
    assert_eq!(
        result["response"]["unchanged"],
        json!(["status", "mime", "duration_ms"])
    );
    assert_eq!(
        result["response"]["headers"],
        json!([{"name": "set-cookie", "kind": "changed", "redacted": true,
                "left_count": 40, "right_count": 40}])
    );
    let body = &result["response"]["body"];
    assert_eq!(body["equal"], false);
    assert_eq!(body["text_diff_truncated"], true);
    let diff = body["text_diff"].as_str().unwrap();
    assert!(
        diff.len() > 10_000 && diff.ends_with('\n'),
        "{}",
        diff.len()
    );
    assert!(body["text_diff_bytes"].as_u64().unwrap() as usize > diff.len());
    assert!(!result.to_string().contains("=left"));

    // Many long changed headers are cut with explicit markers.
    let wide = |value: &str| {
        let mut captured = exchange(project_id, "/wide");
        captured.response_headers = (0..300)
            .map(|n| header(&format!("X-H{n}"), &value.repeat(200), n))
            .collect();
        captured
    };
    let left = insert(&state, wide("l")).await;
    let right = insert(&state, wide("r")).await;
    let result = call(
        &state,
        "exchange_compare",
        json!({"project_id": project, "left_exchange_id": left, "right_exchange_id": right}),
    )
    .await;
    let response = &result["response"];
    let rows = response["headers"].as_array().unwrap();
    assert!(!rows.is_empty());
    assert_eq!(
        rows.len() + response["headers_omitted"].as_u64().unwrap() as usize,
        300
    );
    assert_eq!(rows[0]["left"], json!(["l".repeat(200)]));
}

#[tokio::test]
async fn reply_send_reports_a_compact_comparison_with_its_base() {
    use axum::routing::get;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().route(
        "/item",
        get(|query: axum::extract::RawQuery| async move {
            match query.0.as_deref() {
                Some("v=2") => "changed body".to_string(),
                _ => "base body".to_string(),
            }
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let (_directory, state, _) = test_state().await;
    let project = state
        .db
        .create_project(CreateProjectRequest {
            name: "Reply diff".into(),
            target_url: format!("http://{address}/"),
            advanced: None,
        })
        .await
        .unwrap()
        .id
        .get();
    let url = format!("http://{address}/item");
    let base = call(
        &state,
        "reply_send",
        json!({"project_id": project, "draft": {"url": url}}),
    )
    .await;
    assert!(base.get("diff").is_none(), "no base, no diff: {base}");
    let base_id = base["exchange_id"].as_i64().unwrap();

    let same = call(
        &state,
        "reply_send",
        json!({"project_id": project, "base_exchange_id": base_id}),
    )
    .await;
    assert_eq!(
        same["diff"],
        json!({"base_status": 200, "base_length": 9, "same_body": true})
    );
    let changed = call(
        &state,
        "reply_send",
        json!({"project_id": project, "base_exchange_id": base_id,
               "draft": {"url": format!("{url}?v=2")}}),
    )
    .await;
    assert_eq!(
        changed["diff"],
        json!({"base_status": 200, "base_length": 9, "same_body": false})
    );
    assert!(changed["diff"].to_string().len() < 150);

    // An out-of-scope reply is not saved, and is still compared with its base.
    state
        .db
        .update_project_scope(
            ProjectId(project),
            ScopePolicy {
                schemes: vec!["http".into()],
                host_patterns: vec!["127.0.0.1".into()],
                excluded_host_patterns: vec!["localhost".into()],
                ports: vec![address.port()],
                path_prefixes: vec![],
            },
            None,
        )
        .await
        .unwrap();
    let uncaptured = call(
        &state,
        "reply_send",
        json!({"project_id": project, "base_exchange_id": base_id,
               "draft": {"url": format!("http://localhost:{}/item", address.port())}}),
    )
    .await;
    assert!(uncaptured["exchange_id"].is_null(), "{uncaptured}");
    assert_eq!(
        uncaptured["diff"],
        json!({"base_status": 200, "base_length": 9, "same_body": true})
    );
    server.abort();
}

#[tokio::test]
async fn exchange_tools_accept_numeric_strings_for_integer_arguments() {
    let (_directory, state, project_id) = test_state().await;
    let first = insert(&state, exchange(project_id, "/first")).await;
    let second = insert(&state, exchange(project_id, "/second")).await;
    let project = project_id.get().to_string();

    let single = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_id": first.to_string(), "body_bytes": "0"}),
    )
    .await;
    assert_eq!(single["exchange_id"], first);
    assert!(single.get("response_body").is_none(), "{single}");

    let batch = call(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_ids": [first.to_string(), second]}),
    )
    .await;
    assert_eq!(batch["exchanges"].as_array().unwrap().len(), 2);

    let body = call(
        &state,
        "exchange_body",
        json!({"project_id": project, "exchange_id": second.to_string(), "max_bytes": "64"}),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");

    let error = call_err(
        &state,
        "exchange_get",
        json!({"project_id": project, "exchange_id": "abc"}),
    )
    .await;
    assert_eq!(error.to_string(), "exchange_id must be an integer");
}
