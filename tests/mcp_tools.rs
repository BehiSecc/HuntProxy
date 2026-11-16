//! Exercise MCP tool handlers against a real in-process state.

use huntproxy::app::{bootstrap_state, AppState};
use huntproxy::config::Config;
use huntproxy::domain::*;
use huntproxy::mcp::call_tool;
use huntproxy::storage::NewExchange;
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::TempDir;

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
            name: "MCP tools".into(),
            target_url: "https://example.com/".into(),
            advanced: None,
        })
        .await
        .unwrap();
    (directory, state, project.id)
}

fn exchange(project_id: ProjectId, path: &str) -> NewExchange {
    NewExchange {
        project_id,
        source: ExchangeSource::Proxy,
        protocol: "HTTP/2".into(),
        method: "GET".into(),
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
            name: "Authorization".into(),
            value: b"Bearer s3cret".to_vec(),
            ordinal: 0,
        }],
        response_headers: Vec::new(),
        request_body: None,
        response_body: Some(b"response".to_vec()),
        duration_ms: Some(3),
        lineage: ExchangeLineage::default(),
        page_title: None,
        error_message: None,
    }
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

#[tokio::test]
async fn history_search_pages_with_the_returned_next_cursor() {
    let (_directory, state, project_id) = test_state().await;
    for index in 0..5 {
        state
            .db
            .insert_exchange(exchange(project_id, &format!("/page/{index}")))
            .await
            .unwrap();
    }

    let mut seen = Vec::new();
    let mut cursor = Value::Null;
    for _ in 0..5 {
        let mut args = json!({"project_id": project_id.get(), "limit": 2});
        if !cursor.is_null() {
            args["cursor"] = cursor.clone();
        }
        let page = call_tool(state.clone(), "history_search", args)
            .await
            .unwrap();
        for item in page["items"].as_array().unwrap() {
            seen.push(item["exchange_id"].as_i64().unwrap());
        }
        cursor = page["next"].clone();
        if cursor.is_null() {
            break;
        }
    }
    assert_eq!(seen.len(), 5, "paging must reach every exchange: {seen:?}");
    let mut unique = seen.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), 5, "pages must not overlap: {seen:?}");

    let invalid = call_tool(
        state,
        "history_search",
        json!({"project_id": project_id.get(), "cursor": {"bad": true}}),
    )
    .await
    .unwrap_err();
    assert_eq!(invalid.code(), ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn projects_set_limits_changes_only_the_request_budget() {
    let (_directory, state, project_id) = test_state().await;
    let set = call_tool(
        state.clone(),
        "projects",
        json!({"action":"set_limits","project_id":project_id.get(),"requests_per_second":12.5}),
    )
    .await
    .unwrap();
    assert_eq!(
        set,
        json!({"project_id":project_id.get(),"requests_per_second":12.5,"max_concurrent_requests":32})
    );
    for args in [
        json!({"action":"set_limits","project_id":project_id.get()}),
        json!({"action":"set_limits","project_id":project_id.get(),"requests_per_second":"fast"}),
        json!({"action":"set_limits","project_id":project_id.get(),"max_concurrent_requests":-1}),
        json!({"action":"set_limits","project_id":project_id.get(),"max_concurrent_requests":1.5}),
        json!({"action":"set_limits","project_id":project_id.get(),"requests_per_second":1000.5}),
    ] {
        let error = call_tool(state.clone(), "projects", args.clone())
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument, "{args}");
    }
    let project = state.db.get_project(project_id).await.unwrap();
    assert_eq!(project.limits.requests_per_second, 12.5);
    assert_eq!(project.limits.max_concurrent_requests, 32);
}

#[tokio::test]
async fn request_drafts_with_unknown_fields_are_rejected_not_dropped() {
    let (_directory, state, project_id) = test_state().await;
    let project = project_id.get();

    let error = call_tool(
        state.clone(),
        "reply_send",
        json!({"project_id": project, "draft": {
            "url": "https://example.com/",
            "headers": [{"name": "X-Test", "value": "1"}],
        }}),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.to_string().contains("`headers`"), "{error}");
    assert!(error.to_string().contains("header_overrides"), "{error}");

    let error = call_tool(
        state.clone(),
        "reply_tabs",
        json!({"project_id": project, "action": "create", "draft": {"body": "x=1"}}),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.to_string().contains("body_text"), "{error}");

    let error = call_tool(
        state.clone(),
        "fuzz_start",
        json!({"project_id": project, "template": {
            "draft": {"url": "https://example.com/§a§", "body": "x"},
            "insertion_points": [{"name": "a", "location": "url"}],
            "wordlists": [["one"]],
        }}),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.to_string().contains("body_text"), "{error}");

    // Valid drafts still work and stored tabs keep loading.
    let tab = call_tool(
        state,
        "reply_tabs",
        json!({"project_id": project, "action": "create", "name": "ok",
               "draft": {"url": "https://example.com/", "body_text": "x"}}),
    )
    .await
    .unwrap();
    assert_eq!(tab["draft"]["body_text"], "x");
}

#[tokio::test]
async fn secret_reveals_fail_closed_when_the_audit_log_is_unavailable() {
    let (_directory, state, project_id) = test_state().await;
    let exchange_id = state
        .db
        .insert_exchange(exchange(project_id, "/secret"))
        .await
        .unwrap();
    let reveal = json!({
        "project_id": project_id.get(),
        "exchange_id": exchange_id.get(),
        "header": "authorization",
    });
    let copy = json!({
        "project_id": project_id.get(),
        "exchange_id": exchange_id.get(),
        "format": "curl",
    });

    let revealed = call_tool(state.clone(), "secret_reveal", reveal.clone())
        .await
        .unwrap();
    assert_eq!(revealed["value"], "Bearer s3cret");
    let copied = call_tool(state.clone(), "copy_as", copy.clone())
        .await
        .unwrap();
    assert!(copied.to_string().contains("s3cret"));

    break_audit_log(&state).await;

    let error = call_tool(state.clone(), "secret_reveal", reveal)
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("s3cret"));
    let error = call_tool(state.clone(), "copy_as", copy).await.unwrap_err();
    assert!(!error.to_string().contains("s3cret"));

    // Redacted copies reveal nothing and stay available.
    call_tool(
        state,
        "copy_as",
        json!({
            "project_id": project_id.get(),
            "exchange_id": exchange_id.get(),
            "format": "curl",
            "include_secrets": false,
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn cookie_changes_report_audit_failures() {
    let (_directory, state, project_id) = test_state().await;
    huntproxy::cookies::set_project_cookie(
        &state,
        project_id,
        "https://example.com/",
        "sid=one".into(),
    )
    .await
    .unwrap();

    break_audit_log(&state).await;

    let error = huntproxy::cookies::set_project_cookie(
        &state,
        project_id,
        "https://example.com/",
        "sid=two".into(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::StorageError);
    let error =
        huntproxy::cookies::clear_project_cookie(&state, project_id, "https://example.com/")
            .await
            .unwrap_err();
    assert_eq!(error.code(), ErrorCode::StorageError);
}
