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
        "Reply",
        "Fuzzer",
        "Browser",
        "Codec",
        "Save annotation",
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
