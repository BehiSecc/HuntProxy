use axum::body::Body;
use bb::app::bootstrap_state;
use bb::config::Config;
use bb::domain::*;
use bb::storage::NewExchange;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

async fn test_state() -> (TempDir, std::sync::Arc<bb::app::AppState>, ProjectId) {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: directory.path().to_path_buf(),
        spool_dir: directory.path().join("spool"),
        export_dir: directory.path().join("exports"),
        runtime_dir: directory.path().join("runtime"),
        browser_worker_path: Some(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("browser-worker")
                .join("index.js"),
        ),
        ..Config::default()
    };
    let state = bootstrap_state(config).await.unwrap();
    let project = state
        .db
        .create_project(CreateProjectRequest {
            name: "API integration".into(),
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
        request_headers: Vec::new(),
        response_headers: Vec::new(),
        request_body: None,
        response_body: Some(b"response".to_vec()),
        duration_ms: Some(3),
        lineage: ExchangeLineage::default(),
        page_title: None,
        error_message: None,
    }
}

async fn json_response(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn history_filter_and_annotation_work_through_http_api() {
    let (_directory, state, project_id) = test_state().await;
    let get_id = state
        .db
        .insert_exchange(exchange(project_id, "GET", "/get"))
        .await
        .unwrap();
    state
        .db
        .insert_exchange(exchange(project_id, "POST", "/post"))
        .await
        .unwrap();
    let app = bb::api::router(state);

    let filtered = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/history?q=method%3AGET",
                project_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(filtered.status(), StatusCode::OK);
    let filtered = json_response(filtered).await;
    assert_eq!(filtered["items"].as_array().unwrap().len(), 1);
    assert_eq!(filtered["items"][0]["method"], "GET");

    let empty = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/history?q=method%3ATRACE",
                project_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(json_response(empty).await["items"]
        .as_array()
        .unwrap()
        .is_empty());

    let annotation = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/projects/{}/exchanges/{}/annotation",
                project_id.get(),
                get_id.get()
            ))
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "display_title": "Login probe",
                    "note": "Check the alternate flow",
                    "labels": ["auth", "interesting"],
                    "expected_revision": 0
                })
                .to_string(),
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(annotation.status(), StatusCode::OK);
    let annotation = json_response(annotation).await;
    assert_eq!(annotation["display_title"], "Login probe");
    assert_eq!(annotation["labels"].as_array().unwrap().len(), 2);

    let detail = app
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/exchanges/{}",
                project_id.get(),
                get_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let detail = json_response(detail).await;
    assert_eq!(detail["annotation"]["note"], "Check the alternate flow");
    assert_eq!(detail["summary"]["labels"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn embedded_ui_exposes_the_complete_workbench() {
    let (_directory, state, _project_id) = test_state().await;
    let response = bb::api::router(state)
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap();
    for expected in [
        "HuntProxy",
        "History",
        "Sitemap",
        "Findings",
        "Reply",
        "Fuzzer",
        "Browser",
        "Codec",
        "Save annotation",
        "Body format",
    ] {
        assert!(html.contains(expected), "missing UI workflow: {expected}");
    }
}

#[tokio::test]
async fn optional_capture_scope_can_be_updated_through_http_api() {
    let (_directory, state, project_id) = test_state().await;
    let app = bb::api::router(state);
    let response = app
        .oneshot(
            Request::post(format!("/api/v1/projects/{}/scope", project_id.get()))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "schemes": ["http", "https"],
                        "host_patterns": ["*.example.com"],
                        "ports": [],
                        "path_prefixes": []
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let project = json_response(response).await;
    assert_eq!(project["scope"]["host_patterns"][0], "*.example.com");
}

#[tokio::test]
async fn managed_cookies_are_configured_without_exposing_values() {
    let (_directory, state, project_id) = test_state().await;
    let app = bb::api::router(state);
    let set = app
        .clone()
        .oneshot(
            Request::put(format!("/api/v1/projects/{}/cookies", project_id.get()))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "target_url": "https://example.com/login",
                        "cookie": "sid=super-secret; csrf=also-secret"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(set.status(), StatusCode::OK);
    let set_text =
        String::from_utf8(set.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(!set_text.contains("super-secret"));
    assert!(set_text.contains("sid"));

    let list = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/projects/{}/cookies", project_id.get()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let list_text = String::from_utf8(
        list.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(!list_text.contains("super-secret"));
    assert!(list_text.contains("example.com"));

    let clear = app
        .oneshot(
            Request::delete(format!("/api/v1/projects/{}/cookies", project_id.get()))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "target_url": "https://example.com" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(clear.status(), StatusCode::OK);
}

#[tokio::test]
async fn response_body_api_decodes_gzip_and_preserves_raw_access() {
    use base64::Engine;
    use std::io::Write;

    let (_directory, state, project_id) = test_state().await;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(b"readable response").unwrap();
    let compressed = encoder.finish().unwrap();
    let mut captured = exchange(project_id, "GET", "/compressed");
    captured.response_headers = vec![HeaderEntry {
        name: "Content-Encoding".into(),
        value: b"gzip".to_vec(),
        ordinal: 0,
    }];
    captured.response_body = Some(compressed.clone());
    let exchange_id = state.db.insert_exchange(captured).await.unwrap();
    let app = bb::api::router(state);

    let decoded = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/exchanges/{}/body?side=response",
                project_id.get(),
                exchange_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let decoded = json_response(decoded).await;
    assert_eq!(decoded["decoded"], true);
    assert_eq!(decoded["content_encoding"], "gzip");
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(decoded["data"].as_str().unwrap())
            .unwrap(),
        b"readable response"
    );

    let raw = app
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/exchanges/{}/body?side=response&raw=true",
                project_id.get(),
                exchange_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let raw = json_response(raw).await;
    assert_eq!(raw["decoded"], false);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(raw["data"].as_str().unwrap())
            .unwrap(),
        compressed
    );
}

#[tokio::test]
async fn sitemap_and_findings_work_through_http_api() {
    let (_directory, state, project_id) = test_state().await;
    let mut first = exchange(project_id, "GET", "/z-route");
    first.host = "Example.COM".into();
    first.authority = "Example.COM".into();
    let exchange_id = state.db.insert_exchange(first).await.unwrap();

    let mut second = exchange(project_id, "POST", "/a-route");
    second.host = "example.com".into();
    second.authority = "example.com".into();
    state.db.insert_exchange(second.clone()).await.unwrap();
    state.db.insert_exchange(second).await.unwrap();

    let mut third = exchange(project_id, "GET", "/cdn");
    third.host = "cdn.example.com".into();
    third.authority = "cdn.example.com".into();
    state.db.insert_exchange(third).await.unwrap();
    let app = bb::api::router(state);

    let sitemap = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/projects/{}/sitemap", project_id.get()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let sitemap = json_response(sitemap).await;
    assert_eq!(sitemap["hosts"][0]["host"], "cdn.example.com");
    assert_eq!(sitemap["hosts"][1]["host"], "example.com");
    assert_eq!(
        sitemap["hosts"][1]["paths"],
        serde_json::json!(["/a-route", "/z-route"])
    );

    let filtered = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/sitemap?host=EXAMPLE.COM",
                project_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        json_response(filtered).await["hosts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let created = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/projects/{}/findings", project_id.get()))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "exchange_id": exchange_id.get(),
                        "title": "Access control issue",
                        "description": "A lower-privileged account can access the record."
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let finding = json_response(created).await;
    assert_eq!(finding["exchange_id"], exchange_id.get());

    let listed = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/projects/{}/findings", project_id.get()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        json_response(listed).await["findings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let removed = app
        .clone()
        .oneshot(
            Request::delete(format!(
                "/api/v1/projects/{}/findings/{}",
                project_id.get(),
                finding["id"].as_i64().unwrap()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(removed.status(), StatusCode::NO_CONTENT);
}
