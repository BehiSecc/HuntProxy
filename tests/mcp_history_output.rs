//! MCP output of history_search, js_files and sitemap: compact rows that fit
//! the output budget, with exact continuations.

use huntproxy::app::{bootstrap_state, AppState};
use huntproxy::config::Config;
use huntproxy::domain::*;
use huntproxy::mcp::call_tool;
use huntproxy::storage::{JavascriptProvenanceInput, NewExchange};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use tempfile::TempDir;

/// The MCP output budget every result must fit (`budget::MAX_OUTPUT_BYTES`).
const MAX_OUTPUT_BYTES: usize = 24_000;

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
            name: "MCP history output".into(),
            target_url: "https://example.com/".into(),
            advanced: None,
        })
        .await
        .unwrap();
    (directory, state, project.id)
}

fn exchange(project_id: ProjectId, method: &str, path: &str) -> NewExchange {
    NewExchange {
        project_id,
        source: ExchangeSource::Proxy,
        protocol: "HTTP/2".into(),
        method: method.into(),
        scheme: "https".into(),
        authority: "example.com".into(),
        host: "example.com".into(),
        port: 443,
        path: path.into(),
        query: None,
        status_code: Some(200),
        mime: Some("text/plain".into()),
        completion: CompletionState::Complete,
        capture_quality: CaptureQuality::Semantic,
        header_representation: HeaderRepresentation::Semantic,
        body_representation: BodyRepresentation::SemanticEncoded,
        cache_provenance: CacheProvenance::None,
        transport_provenance: Some(TransportProvenance::ProtocolProfileOnly),
        transport_profile: Some("test".into()),
        request_headers: vec![HeaderEntry {
            name: "X-Trace".into(),
            value: b"trace-token".to_vec(),
            ordinal: 0,
        }],
        response_headers: vec![HeaderEntry {
            name: "X-Server".into(),
            value: b"edge-7".to_vec(),
            ordinal: 0,
        }],
        request_body: None,
        response_body: Some(b"{\"account\":\"acme\"}".to_vec()),
        duration_ms: Some(3),
        lineage: ExchangeLineage::default(),
        page_title: None,
        error_message: None,
    }
}

async fn call(state: &Arc<AppState>, name: &str, args: Value) -> Value {
    let result = call_tool(state.clone(), name, args).await.unwrap();
    let len = result.to_string().len();
    assert!(len <= MAX_OUTPUT_BYTES, "{name} returned {len} bytes");
    assert!(result.get("output_truncated").is_none(), "{name} was cut");
    result
}

async fn search(state: &Arc<AppState>, project_id: ProjectId, q: &str) -> Value {
    call(
        state,
        "history_search",
        json!({"project_id": project_id.get(), "q": q}),
    )
    .await
}

fn item_ids(result: &Value) -> Vec<i64> {
    result["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["exchange_id"].as_i64().unwrap())
        .collect()
}

#[tokio::test]
async fn history_rows_are_compact_and_the_envelope_has_no_constants() {
    let (_directory, state, project_id) = test_state().await;
    let mut item = exchange(project_id, "GET", "/items");
    item.query = Some("id=5".into());
    let id = state.db.insert_exchange(item).await.unwrap();

    let result = call(
        &state,
        "history_search",
        json!({"project_id": project_id.get()}),
    )
    .await;
    assert_eq!(result.as_object().unwrap().len(), 1, "{result}");
    let row = &result["items"][0];
    assert_eq!(row["exchange_id"], id.get());
    assert_eq!(row["url"], "https://example.com/items?id=5");
    assert_eq!(row["method"], "GET");
    assert_eq!(row["status_code"], 200);
    for absent in ["host", "path", "query", "project_id", "source", "labels"] {
        assert!(row.get(absent).is_none(), "{absent} in {row}");
    }
}

#[tokio::test]
async fn a_large_history_fits_the_budget_and_pages_through_every_row_once() {
    let (_directory, state, project_id) = test_state().await;
    let mut inserted = Vec::new();
    for index in 0..500 {
        let mut item = exchange(
            project_id,
            "GET",
            &format!("/api/v1/accounts/{index}/settings/notifications/preferences"),
        );
        item.query = Some(format!("session=abcdef0123456789&page={index}"));
        item.page_title = Some(format!("Account {index} notification preferences"));
        inserted.push(state.db.insert_exchange(item).await.unwrap().get());
    }

    let mut seen = Vec::new();
    let mut cursor = Value::Null;
    let mut budget_cut = false;
    for _ in 0..100 {
        let mut args = json!({"project_id": project_id.get(), "limit": 500});
        if !cursor.is_null() {
            args["cursor"] = cursor.clone();
        }
        let page = call(&state, "history_search", args).await;
        let ids = item_ids(&page);
        cursor = page.get("next").cloned().unwrap_or(Value::Null);
        budget_cut |= !cursor.is_null() && ids.len() < 500;
        seen.extend(ids);
        if cursor.is_null() {
            break;
        }
    }
    assert!(budget_cut, "500 rows of this size must exceed one page");
    inserted.reverse();
    assert_eq!(seen, inserted, "newest first, each row exactly once");

    // A `limit` cut and a byte-budget cut produce the same kind of cursor.
    let mut seen = Vec::new();
    let mut cursor = Value::Null;
    loop {
        let mut args = json!({"project_id": project_id.get(), "limit": 7});
        if !cursor.is_null() {
            args["cursor"] = cursor.clone();
        }
        let page = call(&state, "history_search", args).await;
        seen.extend(item_ids(&page));
        cursor = page.get("next").cloned().unwrap_or(Value::Null);
        if cursor.is_null() {
            break;
        }
    }
    assert_eq!(seen, inserted);
}

#[tokio::test]
async fn an_empty_and_query_names_the_terms_that_match_nothing_alone() {
    let (_directory, state, project_id) = test_state().await;
    state
        .db
        .insert_exchange(exchange(project_id, "GET", "/one"))
        .await
        .unwrap();
    state
        .db
        .insert_exchange(exchange(project_id, "POST", "/two"))
        .await
        .unwrap();

    let result = search(&state, project_id, "path:/missing method:GET status>=500").await;
    assert_eq!(result["items"], json!([]));
    assert_eq!(
        result["no_match_terms"],
        json!(["path:/missing", "status>=500"])
    );

    // Each term matches on its own: only the combination is empty.
    let result = search(&state, project_id, "path:/one method:POST").await;
    assert_eq!(
        result,
        json!({
            "items": [],
            "hint": "Each term matches some exchanges on its own, but no exchange matches all of them."
        })
    );
    // A query of one term names it: the search itself checked it alone.
    for q in [
        "path:/missing",
        "response:~nowhere",
        "zzzz",
        "NOT host:example.com",
        "path:/missing OR method:PATCH",
    ] {
        let result = search(&state, project_id, q).await;
        assert_eq!(result["items"], json!([]), "{q}");
        if q.contains(" OR ") {
            // OR queries are not checked branch by branch.
            assert_eq!(result, json!({"items": []}), "{q}");
        } else {
            assert_eq!(result["no_match_terms"], json!([q]), "{q}");
        }
    }
    // Body searches are never checked on their own.
    let result = search(&state, project_id, "response:~nowhere path:/missing").await;
    assert_eq!(result["no_match_terms"], json!(["path:/missing"]));
    assert!(result.get("hint").is_none());
    let result = search(&state, project_id, "response:~nowhere path:/one").await;
    assert_eq!(
        result,
        json!({
            "items": [],
            "hint": "Each term checked alone matches some exchanges; not checked alone: response:~nowhere."
        })
    );
    let result = search(&state, project_id, "response:~nowhere request:~nothing").await;
    assert_eq!(result, json!({"items": []}));
    // Quoted and bare terms are shown in query syntax.
    let result = search(&state, project_id, "path:~\"no such\" zzzz method:GET").await;
    assert_eq!(
        result["no_match_terms"],
        json!(["path:~\"no such\"", "zzzz"])
    );
    // Rows that match: no hint.
    let result = search(&state, project_id, "path:/one method:GET").await;
    assert_eq!(item_ids(&result).len(), 1);
    assert!(result.get("no_match_terms").is_none());
    // The end of paging is not an over-constrained query.
    let result = call(
        &state,
        "history_search",
        json!({
            "project_id": project_id.get(),
            "q": "path:/missing method:GET",
            "cursor": ["0000-01-01T00:00:00Z", 1]
        }),
    )
    .await;
    assert_eq!(result, json!({"items": []}));
}

#[tokio::test]
async fn query_language_additions_find_the_expected_exchanges() {
    let (_directory, state, project_id) = test_state().await;
    let mut with_query = exchange(project_id, "GET", "/search");
    with_query.query = Some("id=5&sort=asc".into());
    let with_query = state.db.insert_exchange(with_query).await.unwrap().get();
    let mut other = exchange(project_id, "POST", "/upload");
    other.request_headers.clear();
    other.response_headers.clear();
    other.response_body = Some(b"plain".to_vec());
    let other = state.db.insert_exchange(other).await.unwrap().get();
    let project = project_id.get();

    for (q, expected) in [
        // JSON-escaped quotes, as agents often send them.
        (r#"path:~\"search\""#.to_string(), vec![with_query]),
        (r#"path:~\"upload" method:POST"#.into(), vec![other]),
        (r#"path:~\"upload\" method:POST"#.into(), vec![other]),
        // Any text operator on request is a contains search.
        ("request:trace-token".into(), vec![with_query]),
        ("request=trace-token".into(), vec![with_query]),
        (r#"query:~"id=5""#.into(), vec![with_query]),
        ("query:~sort=asc".into(), vec![with_query]),
        (
            "url:~\"https://example.com/search?id=5\"".into(),
            vec![with_query],
        ),
        ("url:https://example.com/upload".into(), vec![other]),
        ("response:~acme".into(), vec![with_query]),
        ("response:~edge-7".into(), vec![with_query]),
        ("response:~plain".into(), vec![other]),
        (format!("project_id:{project} method:POST"), vec![other]),
        (format!("project:{project} method:POST"), vec![other]),
        ("project_id:999999".into(), vec![]),
    ] {
        let result = search(&state, project_id, &q).await;
        assert_eq!(item_ids(&result), expected, "{q}");
    }

    let words = (0..18)
        .map(|index| format!("word{index}"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let result = search(&state, project_id, &format!("{words} OR upload")).await;
    assert_eq!(item_ids(&result), vec![other]);

    let error = call_tool(
        state.clone(),
        "history_search",
        json!({"project_id": project, "q": "user_id:5"}),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(
        error.to_string().contains(r#"query:~"user_id=5""#),
        "{error}"
    );
}

#[tokio::test]
async fn colon_comparisons_header_hints_and_null_arguments() {
    let (_directory, state, project_id) = test_state().await;
    let mut small = exchange(project_id, "GET", "/small");
    small.response_body = Some(vec![b'a'; 100]);
    let small = state.db.insert_exchange(small).await.unwrap().get();
    let mut large = exchange(project_id, "GET", "/large");
    large.response_body = Some(vec![b'a'; 30_000]);
    let large = state.db.insert_exchange(large).await.unwrap().get();
    let project = project_id.get();

    for (q, expected) in [
        ("response_size:>25000", vec![large]),
        ("response_size:<=25000", vec![small]),
        ("time:>=2000-01-01T00:00:00Z", vec![large, small]),
        ("time:<2000-01-01T00:00:00Z", vec![]),
    ] {
        assert_eq!(
            item_ids(&search(&state, project_id, q).await),
            expected,
            "{q}"
        );
    }

    // A header name used as a field points at the header search.
    let error = call_tool(
        state.clone(),
        "history_search",
        json!({"project_id": project, "q": "cache-control:~public"}),
    )
    .await
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains(r#"response:~"public""#), "{message}");
    assert!(!message.contains("query:~"), "{message}");

    // Clients that send every property send the unused ones as null.
    let result = call(
        &state,
        "history_search",
        json!({"project_id": project, "q": null, "limit": null, "cursor": null}),
    )
    .await;
    assert_eq!(item_ids(&result), vec![large, small]);
}

#[tokio::test]
async fn over_escaped_quotes_find_rows_in_one_call() {
    let (_directory, state, project_id) = test_state().await;
    let post = state
        .db
        .insert_exchange(exchange(project_id, "POST", "/api/v2/orders"))
        .await
        .unwrap()
        .get();
    state
        .db
        .insert_exchange(exchange(project_id, "GET", "/api/v2/orders"))
        .await
        .unwrap();
    for q in [
        r#"path:~\"api/v2" method:POST"#,
        r#"path:~\"api/v2\" method:POST"#,
        r#"path:~"api/v2" method:POST"#,
    ] {
        assert_eq!(
            item_ids(&search(&state, project_id, q).await),
            vec![post],
            "{q}"
        );
    }
}

async fn record_scripts(state: &AppState, project_id: ProjectId, page: &str, urls: &[String]) {
    state
        .db
        .record_javascript_files(
            project_id,
            page,
            urls.iter()
                .map(|url| JavascriptProvenanceInput {
                    url: url.clone(),
                    source_page_url: None,
                })
                .collect(),
            None,
            "browser",
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn js_files_rows_are_lean_and_page_with_offsets() {
    let (_directory, state, project_id) = test_state().await;
    let mut script = exchange(project_id, "GET", "/static/app.js");
    script.mime = Some("application/javascript".into());
    let script_id = state.db.insert_exchange(script).await.unwrap().get();
    let app = "https://example.com/static/app.js".to_string();
    for page in ["a", "b", "c", "d"] {
        record_scripts(
            &state,
            project_id,
            &format!("https://example.com/{page}"),
            std::slice::from_ref(&app),
        )
        .await;
    }
    let result = call(&state, "js_files", json!({"project_id": project_id.get()})).await;
    assert_eq!(
        result,
        json!({
            "source": "history",
            "files": [{
                "url": app,
                "exchange_id": script_id,
                "mime": "application/javascript",
                "pages": [
                    "https://example.com/a",
                    "https://example.com/b",
                    "https://example.com/c"
                ],
                "page_count": 4
            }]
        })
    );

    let urls = (0..400)
        .map(|index| {
            format!("https://cdn.example.com/assets/chunks/vendor-{index:04}-0123456789abcdef.js")
        })
        .collect::<Vec<_>>();
    record_scripts(&state, project_id, "https://example.com/home", &urls).await;
    let mut seen = Vec::new();
    let mut offset = 0;
    let mut pages = 0;
    loop {
        let page = call(
            &state,
            "js_files",
            json!({"project_id": project_id.get(), "domain": "example.com", "offset": offset}),
        )
        .await;
        pages += 1;
        assert_eq!(page["domain"], "example.com");
        assert!(page.get("urls").is_none() && page.get("paths").is_none());
        for file in page["files"].as_array().unwrap() {
            seen.push(file["url"].as_str().unwrap().to_string());
        }
        match page.get("next_offset") {
            Some(next) => {
                assert_eq!(page["total"], 401);
                offset = next.as_u64().unwrap();
            }
            None => break,
        }
    }
    assert!(pages > 1, "401 files must not fit one page");
    let mut expected = urls.clone();
    expected.push(app);
    expected.sort();
    assert_eq!(seen, expected, "every file exactly once, sorted by URL");

    let limited = call(
        &state,
        "js_files",
        json!({"project_id": project_id.get(), "limit": 2, "offset": 398}),
    )
    .await;
    assert_eq!(limited["files"].as_array().unwrap().len(), 2);
    assert_eq!(limited["next_offset"], 400);
    let last = call(
        &state,
        "js_files",
        json!({"project_id": project_id.get(), "offset": 401}),
    )
    .await;
    assert_eq!(last["files"].as_array().unwrap().len(), 0);
    assert!(last.get("next_offset").is_none());
}

#[tokio::test]
async fn sitemap_lists_flat_routes_and_pages_with_offsets() {
    let (_directory, state, project_id) = test_state().await;
    let mut first = exchange(project_id, "GET", "/api/users");
    first.query = Some("page=2".into());
    state.db.insert_exchange(first).await.unwrap();
    let mut second = exchange(project_id, "POST", "/api/users");
    second.status_code = Some(201);
    second.mime = Some("application/json; charset=utf-8".into());
    state.db.insert_exchange(second).await.unwrap();
    state
        .db
        .insert_exchange(exchange(project_id, "GET", "/api"))
        .await
        .unwrap();

    let result = call(
        &state,
        "sitemap",
        json!({"project_id": project_id.get(), "host": "example.com", "path_prefix": "/api"}),
    )
    .await;
    assert_eq!(
        result,
        json!({"routes": [
            {"path": "/api", "methods": ["GET"], "status_codes": [200], "content_types": ["text/plain"]},
            {
                "path": "/api/users",
                "methods": ["GET", "POST"],
                "status_codes": [200, 201],
                "content_types": ["application/json", "text/plain"],
                "parameters": ["page"],
                "exchange_count": 2
            }
        ]})
    );

    for index in 0..800 {
        state
            .db
            .insert_exchange(exchange(
                project_id,
                "GET",
                &format!("/catalog/products/{index:04}/reviews/summary"),
            ))
            .await
            .unwrap();
    }
    let mut seen = BTreeSet::new();
    let mut paths = Vec::new();
    let mut offset = 0;
    loop {
        let page = call(
            &state,
            "sitemap",
            json!({"project_id": project_id.get(), "host": "EXAMPLE.com", "offset": offset}),
        )
        .await;
        for route in page["routes"].as_array().unwrap() {
            let path = route["path"].as_str().unwrap().to_string();
            assert!(seen.insert(path.clone()), "{path} repeated");
            paths.push(path);
        }
        match page.get("next_offset") {
            Some(next) => {
                assert_eq!(page["total"], 802);
                offset = next.as_u64().unwrap();
            }
            None => break,
        }
    }
    assert_eq!(paths.len(), 802);
    assert!(offset > 0, "802 routes must not fit one page");
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted);
}
