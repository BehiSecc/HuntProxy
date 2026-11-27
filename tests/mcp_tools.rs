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

#[tokio::test]
async fn websocket_messages_page_within_the_budget_and_long_payloads_read_whole() {
    let (_directory, state, project_id) = test_state().await;
    let connection = state
        .db
        .create_websocket_connection(project_id, None, "wss://example.com/live".into(), None)
        .await
        .unwrap();
    let long = |index: usize| format!("{index:04}{}", "x".repeat(30_000)).into_bytes();
    let mut ids = Vec::new();
    for index in 0..40 {
        let payload = match index {
            0 => Vec::new(),
            1 => vec![0xff, 0x00],
            _ => long(index),
        };
        let opcode = if index == 1 { "binary" } else { "text" };
        let id = state
            .db
            .insert_websocket_message(
                project_id,
                connection.id,
                "to_client",
                opcode,
                &payload,
                u64::MAX,
            )
            .await
            .unwrap();
        ids.push(id);
    }

    let mut seen = Vec::new();
    let mut after_id: Option<i64> = None;
    loop {
        let mut args = json!({"action":"messages","project_id":project_id.get(),"connection_id":connection.id});
        if let Some(after_id) = after_id {
            args["after_id"] = json!(after_id);
        }
        let page = call_tool(state.clone(), "websocket_manage", args)
            .await
            .unwrap();
        assert!(page.to_string().len() <= 24_000);
        for message in page["messages"].as_array().unwrap() {
            seen.push(message["id"].as_i64().unwrap());
            if message["payload_length"] == 30_004 {
                assert_eq!(message["payload_cut"], true);
                assert_eq!(message["payload"].as_str().unwrap().len(), 2_048);
            } else {
                assert!(message.get("payload_cut").is_none());
            }
        }
        match page.get("next_after_id") {
            Some(next) => after_id = next.as_i64(),
            None => break,
        }
    }
    assert_eq!(seen, ids);

    let mut read = Vec::new();
    let mut offset = 0;
    loop {
        let page = call_tool(
            state.clone(),
            "websocket_manage",
            json!({"action":"message","project_id":project_id.get(),"message_id":ids[5],"offset":offset}),
        )
        .await
        .unwrap();
        assert!(page.to_string().len() <= 24_000);
        assert_eq!(page["connection_id"], connection.id);
        read.extend_from_slice(page["preview"].as_str().unwrap().as_bytes());
        match page.get("next_offset") {
            Some(next) => offset = next.as_u64().unwrap(),
            None => break,
        }
    }
    assert_eq!(read, long(5));

    let binary = call_tool(
        state.clone(),
        "websocket_manage",
        json!({"action":"message","project_id":project_id.get(),"message_id":ids[1]}),
    )
    .await
    .unwrap();
    assert_eq!(binary["encoding"], "base64");
    assert_eq!(binary["preview"], "/wA=");

    for (args, code) in [
        (
            json!({"action":"message","project_id":project_id.get()}),
            ErrorCode::InvalidArgument,
        ),
        (
            json!({"action":"message","project_id":project_id.get(),"message_id":999_999}),
            ErrorCode::NotFound,
        ),
    ] {
        let error = call_tool(state.clone(), "websocket_manage", args)
            .await
            .unwrap_err();
        assert_eq!(error.code(), code);
    }
}

#[tokio::test]
async fn a_tool_call_about_a_project_counts_as_its_browser_activity() {
    let (_directory, state, project_id) = test_state().await;
    let idle = |project: ProjectId| state.browser.project_idle_for(project);
    call_tool(state.clone(), "extension_list", json!({}))
        .await
        .unwrap();
    assert_eq!(idle(project_id), std::time::Duration::MAX);

    call_tool(
        state.clone(),
        "history_search",
        json!({"project_id": project_id.get(), "limit": 1}),
    )
    .await
    .unwrap();
    assert!(idle(project_id) < std::time::Duration::from_secs(60));
    // A call that fails is still the agent at work.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let before = idle(project_id);
    call_tool(
        state.clone(),
        "browser_action",
        json!({"project_id": project_id.get(), "session_id": 999_999, "action": {"type": "snapshot"}}),
    )
    .await
    .unwrap_err();
    assert!(idle(project_id) < before);
    assert_eq!(
        idle(ProjectId(project_id.get() + 1)),
        std::time::Duration::MAX
    );
}

#[tokio::test]
async fn integer_arguments_may_be_numeric_strings_and_null_is_absent() {
    let (_directory, state, project_id) = test_state().await;
    let project = project_id.get().to_string();
    let exchange_id = state
        .db
        .insert_exchange(exchange(project_id, "/quoted"))
        .await
        .unwrap();
    let id = exchange_id.get().to_string();

    // Quoted ids work wherever an id is read, and count as project activity.
    let overview = call_tool(state.clone(), "overview", json!({"project_id": project}))
        .await
        .unwrap();
    assert_eq!(overview["total_exchanges"], 1);
    assert!(state.browser.project_idle_for(project_id) < std::time::Duration::from_secs(60));
    let reveal = call_tool(
        state.clone(),
        "secret_reveal",
        json!({"project_id": project, "exchange_id": id, "header": "authorization"}),
    )
    .await
    .unwrap();
    assert_eq!(reveal["value"], "Bearer s3cret");
    let finding = call_tool(
        state.clone(),
        "findings",
        json!({"project_id": project, "action": "add", "exchange_id": id,
               "title": "t", "description": "d"}),
    )
    .await
    .unwrap();
    call_tool(
        state.clone(),
        "findings",
        json!({"project_id": project, "action": "remove",
               "finding_id": finding["id"].as_i64().unwrap().to_string()}),
    )
    .await
    .unwrap();
    let session = call_tool(
        state.clone(),
        "capture_sessions",
        json!({"project_id": project, "action": "create"}),
    )
    .await
    .unwrap();
    call_tool(
        state.clone(),
        "capture_sessions",
        json!({"project_id": project, "action": "revoke",
               "session_id": session["id"].as_i64().unwrap().to_string()}),
    )
    .await
    .unwrap();
    let annotation = call_tool(
        state.clone(),
        "exchange_annotate",
        json!({"project_id": project, "exchange_id": id, "note": "n", "expected_revision": "0"}),
    )
    .await
    .unwrap();
    assert_eq!(annotation["note"], "n");

    // Null means the argument was not given.
    let list = call_tool(
        state.clone(),
        "projects",
        json!({"action": "list", "project_id": null}),
    )
    .await
    .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    call_tool(
        state.clone(),
        "projects",
        json!({"action": "set_limits", "project_id": project, "requests_per_second": 5.0,
               "max_concurrent_requests": "7"}),
    )
    .await
    .unwrap();
    let limits = call_tool(
        state.clone(),
        "projects",
        json!({"action": "set_limits", "project_id": project_id.get(),
               "requests_per_second": null, "max_concurrent_requests": 9}),
    )
    .await
    .unwrap();
    assert_eq!(limits["requests_per_second"], 5.0);
    assert_eq!(limits["max_concurrent_requests"], 9);

    // Missing and null ids are "required"; anything else is "must be an integer".
    for (tool, args, message) in [
        ("overview", json!({}), "project_id required"),
        (
            "overview",
            json!({"project_id": null}),
            "project_id required",
        ),
        (
            "overview",
            json!({"project_id": "abc"}),
            "project_id must be an integer",
        ),
        (
            "overview",
            json!({"project_id": ""}),
            "project_id must be an integer",
        ),
        (
            "overview",
            json!({"project_id": true}),
            "project_id must be an integer",
        ),
        (
            "overview",
            json!({"project_id": 1.5}),
            "project_id must be an integer",
        ),
        (
            "secret_reveal",
            json!({"project_id": project, "exchange_id": null, "header": "authorization"}),
            "exchange_id required",
        ),
        (
            "secret_reveal",
            json!({"project_id": project, "exchange_id": "x", "header": "authorization"}),
            "exchange_id must be an integer",
        ),
        (
            "capture_sessions",
            json!({"project_id": project, "action": "revoke", "session_id": ["1"]}),
            "session_id must be an integer",
        ),
    ] {
        let error = call_tool(state.clone(), tool, args.clone())
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument, "{args}");
        assert_eq!(error.to_string(), message, "{args}");
    }
}

#[tokio::test]
async fn a_session_id_that_cannot_be_read_never_falls_back_to_the_project_listing() {
    let (_directory, state, project_id) = test_state().await;
    let project = project_id.get();
    for tool in ["browser_manage", "browser_cdp"] {
        for session_id in [json!("abc"), json!(true), json!(1.5), json!({})] {
            let error = call_tool(
                state.clone(),
                tool,
                json!({"project_id": project, "op": "status", "session_id": session_id}),
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
            assert_eq!(error.to_string(), "session_id must be an integer", "{tool}");
        }
    }
    for tool in ["browser_action", "browser_evaluate", "browser_input"] {
        let error = call_tool(
            state.clone(),
            tool,
            json!({"project_id": project, "session_id": "abc", "op": "click",
                   "action": {"type": "snapshot"}}),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "session_id must be an integer", "{tool}");
    }

    // A quoted number is read as the id, so the error is about the session.
    for (tool, args) in [
        (
            "browser_manage",
            json!({"project_id": project, "op": "status", "session_id": "999999"}),
        ),
        (
            "browser_cdp",
            json!({"project_id": project, "op": "status", "session_id": "999999"}),
        ),
        (
            "browser_action",
            json!({"project_id": project, "session_id": "999999", "action": {"type": "snapshot"}}),
        ),
    ] {
        let error = call_tool(state.clone(), tool, args).await.unwrap_err();
        assert!(
            !error.to_string().contains("must be an integer"),
            "{tool}: {error}"
        );
        assert!(!error.to_string().contains("required"), "{tool}: {error}");
    }
}

/// A server that answers every request with `<method> <body>`.
async fn echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(|method: axum::http::Method, body: String| async move {
        format!("{method} {body}")
    });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (address, server)
}

async fn project_for(state: &AppState, address: std::net::SocketAddr) -> i64 {
    state
        .db
        .create_project(CreateProjectRequest {
            name: "Reply".into(),
            target_url: format!("http://{address}/"),
            advanced: None,
        })
        .await
        .unwrap()
        .id
        .get()
}

#[tokio::test]
async fn reply_send_and_reply_tabs_take_request_fields_beside_the_draft() {
    let (address, server) = echo_server().await;
    let (_directory, state, _) = test_state().await;
    let project = project_for(&state, address).await;
    let url = format!("http://{address}/echo");
    let send = |args: Value| {
        let state = state.clone();
        async move { call_tool(state, "reply_send", args).await }
    };

    // Everything beside `draft` is read as if it were inside it.
    let flat = send(json!({
        "project_id": project, "url": url, "method": "POST", "body_text": "hello",
        "identity": {"mode": "anonymous"},
    }))
    .await
    .unwrap();
    assert_eq!(flat["response_preview"]["text"], "POST hello");
    assert_eq!(flat["identity"], json!({"mode": "anonymous"}));
    let mixed = send(json!({
        "project_id": project, "url": url, "body_text": "hello",
        "draft": {"method": "PUT"},
    }))
    .await
    .unwrap();
    assert_eq!(mixed["response_preview"]["text"], "PUT hello");
    // The same value twice is harmless.
    send(json!({"project_id": project, "method": "GET", "draft": {"url": url, "method": "GET"}}))
        .await
        .unwrap();

    // Two different values for one field are an error naming it.
    let error = send(json!({
        "project_id": project, "method": "GET", "draft": {"url": url, "method": "POST"},
    }))
    .await
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.to_string().contains("`method`"), "{error}");
    assert!(error.to_string().contains("different values"), "{error}");

    // `headers` and `body` are not request fields; the error points to the right ones.
    let error = send(json!({"project_id": project, "draft": {"url": url}, "headers": {"X": "1"}}))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("header_overrides"), "{error}");

    // A client that fills every property with null still sends a plain request.
    let nulls = send(json!({
        "project_id": project, "draft": null, "tab_id": null, "base_exchange_id": null,
        "protocol": null, "upstream_proxy": null, "identity": null, "url": url,
    }))
    .await
    .unwrap();
    assert_eq!(nulls["response_preview"]["text"], "GET ");
    let nested_nulls = send(json!({
        "project_id": project,
        "draft": {"url": url, "method": null, "header_overrides": null, "body_text": null,
                  "body_params": null, "identity": null},
    }))
    .await
    .unwrap();
    assert_eq!(nested_nulls["response_preview"]["text"], "GET ");

    // Tabs store the lifted fields in their draft.
    let tab = call_tool(
        state.clone(),
        "reply_tabs",
        json!({"project_id": project, "action": "create", "name": "flat",
               "url": url, "identity": {"mode": "anonymous"}, "draft": {"method": "POST"}}),
    )
    .await
    .unwrap();
    assert_eq!(tab["draft"]["url"], url);
    assert_eq!(tab["draft"]["method"], "POST");
    assert_eq!(tab["draft"]["identity"], json!({"mode": "anonymous"}));
    server.abort();
}

#[tokio::test]
async fn reply_send_accepts_http_version_aliases_and_lenient_body_rules() {
    let (address, server) = echo_server().await;
    let (_directory, state, _) = test_state().await;
    let project = project_for(&state, address).await;
    let url = format!("http://{address}/echo");
    let send = |draft: Value, protocol: Value| {
        let state = state.clone();
        let args = json!({"project_id": project, "draft": draft, "protocol": protocol});
        async move { call_tool(state, "reply_send", args).await }
    };

    for protocol in ["h1", "http1", "HTTP/1.1", "http/1.1", "auto"] {
        let sent = send(json!({"url": url}), json!(protocol)).await.unwrap();
        assert_eq!(sent["status_code"], 200, "{protocol}");
    }
    let error = send(json!({"url": url}), json!("h3")).await.unwrap_err();
    assert!(error.to_string().contains("auto, h1 or h2"), "{error}");

    // body_cleared wins over a format without a body and over an empty body.
    for extra in [
        json!({"body_cleared": true, "body_format": "json"}),
        json!({"body_cleared": true, "body_text": ""}),
        json!({"body_cleared": true, "body_format": "raw", "body_text": ""}),
    ] {
        let mut draft = json!({"url": url, "method": "POST"});
        draft
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let sent = send(draft, Value::Null).await.unwrap();
        assert_eq!(sent["response_preview"]["text"], "POST ", "{extra}");
    }
    let error = send(
        json!({"url": url, "body_cleared": true, "body_text": "x"}),
        Value::Null,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("body_cleared"), "{error}");

    // A GET has nothing to format, so a body_format is dropped; a POST still needs a body.
    let sent = send(json!({"url": url, "body_format": "raw"}), Value::Null)
        .await
        .unwrap();
    assert_eq!(sent["response_preview"]["text"], "GET ");
    let error = send(
        json!({"url": url, "method": "POST", "body_format": "raw"}),
        Value::Null,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("explicit body"), "{error}");
    server.abort();
}

#[tokio::test]
async fn reply_send_returns_response_headers_and_a_sized_preview_on_request() {
    use axum::http::header;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(|| async {
        (
            [
                (header::CONTENT_TYPE, "text/plain"),
                (header::SET_COOKIE, "sid=topsecret"),
                (header::HeaderName::from_static("x-custom"), "custom-value"),
            ],
            "a".repeat(20_000),
        )
    });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (_directory, state, _) = test_state().await;
    let project = project_for(&state, address).await;
    let url = format!("http://{address}/big");
    let send = |extra: Value| {
        let state = state.clone();
        let mut args = json!({"project_id": project, "draft": {"url": url}});
        args.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        async move { call_tool(state, "reply_send", args).await }
    };

    // The default result is unchanged: a 4 KiB preview and no headers.
    let plain = send(json!({})).await.unwrap();
    assert_eq!(
        plain["response_preview"]["text"].as_str().unwrap().len(),
        4096
    );
    assert_eq!(plain["response_preview"]["truncated"], true);
    assert!(plain.get("response_headers").is_none());
    for extra in [
        json!({"response_headers": false}),
        json!({"response_headers": null, "preview_bytes": null}),
    ] {
        let same = send(extra).await.unwrap();
        assert!(same.get("response_headers").is_none());
        assert_eq!(
            same["response_preview"]["text"].as_str().unwrap().len(),
            4096
        );
    }

    // Headers come back as exchange_get renders them: redacted secrets, one line each.
    let with = send(json!({"response_headers": true, "preview_bytes": 10_000}))
        .await
        .unwrap();
    assert_eq!(
        with["response_preview"]["text"].as_str().unwrap().len(),
        10_000
    );
    assert_eq!(with["response_preview"]["truncated"], true);
    let lines = with["response_headers"].as_array().unwrap();
    assert!(
        lines.contains(&json!("x-custom: custom-value")),
        "{lines:?}"
    );
    assert!(
        lines.contains(&json!("content-type: text/plain")),
        "{lines:?}"
    );
    assert!(!with.to_string().contains("topsecret"));
    let stored = call_tool(
        state.clone(),
        "exchange_get",
        json!({"project_id": project, "exchange_id": with["exchange_id"], "body_bytes": 0}),
    )
    .await
    .unwrap();
    assert_eq!(with["response_headers"], stored["response_headers"]);

    // Sizes: 0 returns no text, more than the maximum is cut to it, quoted numbers work.
    let none = send(json!({"preview_bytes": 0})).await.unwrap();
    assert_eq!(none["response_preview"]["text"], "");
    assert_eq!(none["response_preview"]["truncated"], true);
    let huge = send(json!({"preview_bytes": 1_000_000})).await.unwrap();
    assert_eq!(
        huge["response_preview"]["text"].as_str().unwrap().len(),
        16_384
    );
    let quoted = send(json!({"preview_bytes": "100"})).await.unwrap();
    assert_eq!(
        quoted["response_preview"]["text"].as_str().unwrap().len(),
        100
    );
    let error = send(json!({"preview_bytes": -1})).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "preview_bytes must be a non-negative integer"
    );
    let error = send(json!({"response_headers": "yes"})).await.unwrap_err();
    assert_eq!(error.to_string(), "response_headers must be a boolean");

    // A reply outside the capture scope is not saved, and still returns its headers.
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
    let unsaved = call_tool(
        state.clone(),
        "reply_send",
        json!({"project_id": project, "response_headers": true,
               "draft": {"url": format!("http://localhost:{}/big", address.port())}}),
    )
    .await
    .unwrap();
    assert!(unsaved["exchange_id"].is_null(), "{unsaved}");
    let lines = unsaved["response_headers"].as_array().unwrap();
    assert!(
        lines.contains(&json!("x-custom: custom-value")),
        "{lines:?}"
    );
    assert!(!unsaved.to_string().contains("topsecret"));
    server.abort();
}
