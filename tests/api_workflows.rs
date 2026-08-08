use axum::body::Body;
use bb::app::bootstrap_state;
use bb::config::Config;
use bb::domain::*;
use bb::storage::NewExchange;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn test_state() -> (TempDir, std::sync::Arc<bb::app::AppState>, ProjectId) {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: directory.path().to_path_buf(),
        spool_dir: directory.path().join("spool"),
        export_dir: directory.path().join("exports"),
        runtime_dir: directory.path().join("runtime"),
        plugin_dir: directory.path().join("plugins"),
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
async fn api_body_limits_are_route_specific() {
    let (_directory, state, project_id) = test_state().await;
    let app = bb::api::router(state);
    let large_text = "x".repeat(140 * 1024);
    let rename = serde_json::json!({ "name": large_text }).to_string();
    let rejected = app
        .clone()
        .oneshot(
            Request::patch(format!("/api/v1/projects/{}", project_id.get()))
                .header("content-type", "application/json")
                .body(Body::from(rename))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let codec = serde_json::json!({ "steps": ["raw"], "input_text": large_text }).to_string();
    let accepted = app
        .oneshot(
            Request::post("/api/v1/codec")
                .header("content-type", "application/json")
                .body(Body::from(codec))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
}

#[tokio::test]
async fn dynamic_api_responses_are_never_browser_cached() {
    let (_directory, state, _project_id) = test_state().await;
    let response = bb::api::router(state)
        .oneshot(
            Request::get("/api/v1/projects")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(http::header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
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
    assert_eq!(filtered["total"], 1);
    assert_eq!(filtered["items"][0]["method"], "GET");

    let first_page = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/history?limit=1",
                project_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let first_page = json_response(first_page).await;
    assert_eq!(first_page["items"].as_array().unwrap().len(), 1);
    assert_eq!(first_page["total"], 2);
    assert!(first_page["next_cursor"].is_string());

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
        "Get Words",
        "Findings",
        "Reply",
        "Fuzzer",
        "Browser",
        "Codec",
        "Save annotation",
        "Analyze page",
        "Copy as cURL",
        "Exclude hosts",
        "Body format",
        "Different from baseline only",
        "Load more",
        "Open response",
    ] {
        assert!(html.contains(expected), "missing UI workflow: {expected}");
    }
}

#[tokio::test]
async fn reply_send_rejects_flat_request_fields_instead_of_sending_defaults() {
    let (_directory, state, project_id) = test_state().await;
    let response = bb::api::router(state)
        .oneshot(
            Request::post(format!("/api/v1/projects/{}/reply-send", project_id.get()))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"method":"GET","url":"https://example.com/"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let message = String::from_utf8_lossy(&body);
    assert!(message.contains("unknown field `method`"));
}

#[tokio::test]
async fn fuzzer_number_generator_runs_through_http_api() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/item"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let (_directory, state, project_id) = test_state().await;
    let app = bb::api::router(state.clone());
    let response = app
        .oneshot(
            Request::post(format!("/api/v1/projects/{}/fuzz-jobs", project_id.get()))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "template": {
                            "draft": {"url": format!("{}/item?id=§id§", server.uri())},
                            "insertion_points": [{"name": "id", "location": "url"}],
                            "payload_generators": [{
                                "type": "numbers", "from": 1, "to": 10, "step": 3
                            }]
                        },
                        "confirm": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let job = json_response(response).await;
    assert_eq!(job["estimated_cases"], 4);

    for _ in 0..40 {
        if state
            .db
            .get_fuzz_job(project_id, FuzzJobId(job["id"].as_i64().unwrap()))
            .await
            .unwrap()
            .state
            == FuzzJobState::Completed
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let requests = server.received_requests().await.unwrap();
    let mut ids = requests
        .iter()
        .filter_map(|request| {
            request
                .url
                .query_pairs()
                .find(|(name, _)| name == "id")
                .map(|(_, value)| value.into_owned())
        })
        .collect::<Vec<_>>();
    ids.sort();
    assert_eq!(ids, ["1", "10", "4", "7"]);

    let groups = bb::api::router(state)
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/fuzz-jobs/{}/groups",
                project_id.get(),
                job["id"].as_i64().unwrap()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(groups.status(), StatusCode::OK);
    let groups = json_response(groups).await;
    assert_eq!(groups["groups"][0]["body_hash_matches_baseline"], true);
    assert_eq!(groups["groups"][0]["different_from_baseline"], false);
}

#[tokio::test]
async fn page_analyzer_extracts_saved_response_findings_through_http_api() {
    let (_directory, state, project_id) = test_state().await;
    let mut captured = exchange(project_id, "GET", "/app.js");
    captured.mime = Some("application/javascript".into());
    captured.response_body = Some(
        br#"const route = '/api/v1/profile';
            const docs = 'https://docs.example.test/Program Terms.pdf';
            const email = 'security@example.test';"#
            .to_vec(),
    );
    let exchange_id = state.db.insert_exchange(captured).await.unwrap();

    let response = bb::api::router(state)
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/exchanges/{}/analyze",
                project_id.get(),
                exchange_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let analysis = json_response(response).await;
    assert_eq!(
        analysis["endpoints"],
        serde_json::json!(["/api/v1/profile"])
    );
    assert_eq!(
        analysis["urls"],
        serde_json::json!(["https://docs.example.test/Program Terms.pdf"])
    );
    assert_eq!(
        analysis["emails"],
        serde_json::json!(["security@example.test"])
    );
}

#[tokio::test]
async fn get_words_includes_javascript_related_to_the_requested_site_by_default() {
    let (_directory, state, project_id) = test_state().await;

    let mut page = exchange(project_id, "GET", "/partner-dashboard");
    page.query = Some("account_name=one".into());
    page.mime = Some("text/html".into());
    page.response_body = Some(b"<h1>Partner Workspace</h1>".to_vec());
    state.db.insert_exchange(page).await.unwrap();

    let mut javascript = exchange(project_id, "GET", "/static/app.js");
    javascript.scheme = "https".into();
    javascript.authority = "assets.cdn.test".into();
    javascript.host = "assets.cdn.test".into();
    javascript.mime = Some("application/javascript".into());
    javascript.response_body = Some(b"const workspaceManager = true;".to_vec());
    state.db.insert_exchange(javascript).await.unwrap();
    state
        .db
        .record_javascript_files(
            project_id,
            "https://example.com/partner-dashboard",
            vec![bb::storage::JavascriptProvenanceInput {
                url: "https://assets.cdn.test/static/app.js".into(),
                source_page_url: None,
            }],
            None,
            "source",
        )
        .await
        .unwrap();

    let app = bb::api::router(state);
    let included = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/words?domain=example.com",
                project_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(included.status(), StatusCode::OK);
    let included = json_response(included).await;
    let words = included["words"].as_array().unwrap();
    assert!(words.iter().any(|word| word == "Partner"));
    assert!(words.iter().any(|word| word == "workspaceManager"));
    assert!(
        included["stats"]["javascript_exchanges_examined"]
            .as_u64()
            .unwrap()
            >= 1
    );

    let excluded = app
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/words?domain=example.com&include_js=false",
                project_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let excluded = json_response(excluded).await;
    assert!(!excluded["words"]
        .as_array()
        .unwrap()
        .iter()
        .any(|word| word == "workspaceManager"));
}

#[tokio::test]
async fn background_crawler_fetches_one_level_and_obeys_scope_exclusions() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/about"))
        .respond_with(ResponseTemplate::new(200).set_body_string("About page"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/app.js"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/javascript")
                .set_body_string("const projectWord = true;"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/app.css"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/css")
                .set_body_string("body { color: black; }"),
        )
        .mount(&server)
        .await;

    let (_directory, state, project_id) = test_state().await;
    let base = url::Url::parse(&server.uri()).unwrap();
    let host = base.host_str().unwrap().to_string();
    let port = base.port().unwrap();
    state
        .db
        .update_project_scope(
            project_id,
            ScopePolicy {
                schemes: vec!["http".into()],
                host_patterns: vec![host.clone()],
                excluded_host_patterns: vec!["localhost".into()],
                ports: vec![port],
                path_prefixes: vec![],
            },
            None,
        )
        .await
        .unwrap();

    let mut page = exchange(project_id, "GET", "/");
    page.source = ExchangeSource::Browser;
    page.scheme = "http".into();
    page.authority = format!("{host}:{port}");
    page.host = host.clone();
    page.port = port;
    page.mime = Some("text/html".into());
    page.response_body = Some(
        format!(
            r#"<a href="{}/about">About</a>
                <script src="{}/app.js"></script>
                <link rel="stylesheet" href="{}/app.css">
                <form action="{}/delete-account"></form>
                <a href="{}/logout">Log out</a>
                <a href="{}/search?q=test">Search</a>
                <a href="http://localhost:{port}/excluded">Excluded</a>"#,
            server.uri(),
            server.uri(),
            server.uri(),
            server.uri(),
            server.uri(),
            server.uri(),
        )
        .into_bytes(),
    );
    let page_id = state.db.insert_exchange(page).await.unwrap();

    let mut browser_script = exchange(project_id, "GET", "/app.js");
    browser_script.source = ExchangeSource::Proxy;
    browser_script.scheme = "http".into();
    browser_script.authority = format!("{host}:{port}");
    browser_script.host = host.clone();
    browser_script.port = port;
    browser_script.mime = Some("application/javascript".into());
    browser_script.response_body = Some(b"const alreadyLoaded = true;".to_vec());
    state.db.insert_exchange(browser_script).await.unwrap();

    state.crawler.crawl_exchange(project_id, page_id).await;

    let sitemap = state
        .db
        .list_sitemap(project_id, Some(host.clone()))
        .await
        .unwrap();
    assert_eq!(sitemap.len(), 1);
    assert!(sitemap[0].paths.contains(&"/about".to_string()));
    assert!(sitemap[0].paths.contains(&"/app.js".to_string()));
    assert!(!sitemap[0].paths.contains(&"/excluded".to_string()));
    let requests = server.received_requests().await.unwrap();
    assert!(requests
        .iter()
        .any(|request| request.url.path() == "/about"));
    assert!(requests
        .iter()
        .any(|request| request.url.path() == "/app.css"));
    assert!(!requests
        .iter()
        .any(|request| request.url.path() == "/app.js"));
    assert!(!requests
        .iter()
        .any(|request| request.url.path() == "/excluded"));
    assert!(!requests.iter().any(|request| matches!(
        request.url.path(),
        "/delete-account" | "/logout" | "/search"
    )));

    let (scripts, _) = state
        .db
        .list_javascript_files(project_id, None, Some(host), 20)
        .await
        .unwrap();
    let script = scripts
        .iter()
        .find(|script| script.path == "/app.js")
        .unwrap();
    assert!(script
        .related_page_urls
        .iter()
        .any(|url| url == &format!("{}/", server.uri())));
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
                        "host_patterns": ["*.example.com", "test.org"],
                        "excluded_host_patterns": ["admin.example.com", "*.private.example.com"],
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
    assert_eq!(project["scope"]["host_patterns"][1], "test.org");
    assert_eq!(
        project["scope"]["excluded_host_patterns"][0],
        "admin.example.com"
    );
    assert_eq!(
        project["scope"]["excluded_host_patterns"][1],
        "*.private.example.com"
    );
}

#[tokio::test]
async fn managed_cookies_are_configured_without_exposing_values() {
    let (_directory, state, project_id) = test_state().await;
    let app = bb::api::router(state.clone());
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

    let json_set = app
        .clone()
        .oneshot(
            Request::put(format!("/api/v1/projects/{}/cookies", project_id.get()))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "target_url": "https://example.com/login",
                        "cookie": [
                            {
                                "domain": ".example.com",
                                "name": "json_sid",
                                "value": "json-super-secret",
                                "secure": true,
                                "session": true
                            },
                            {
                                "domain": "unrelated.example",
                                "name": "ignored",
                                "value": "unrelated-secret"
                            }
                        ]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json_set.status(), StatusCode::OK);
    let json_set_text = String::from_utf8(
        json_set
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(json_set_text.contains("json_sid"));
    assert!(!json_set_text.contains("json-super-secret"));
    assert!(!json_set_text.contains("unrelated-secret"));
    let stored = state
        .db
        .get_cookie_profile_for_url(project_id, "https://example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.cookie_header, "json_sid=json-super-secret");
    let managed = &stored.managed_cookies.as_ref().unwrap()[0];
    assert!(managed.secure);
    assert_eq!(managed.domain, "example.com");

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
    second.query = Some("page=1&tag=first".into());
    second.mime = Some("application/json; charset=utf-8".into());
    state.db.insert_exchange(second.clone()).await.unwrap();
    second.method = "GET".into();
    second.status_code = Some(404);
    second.query = Some("page=2&tag=second".into());
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
    assert_eq!(
        sitemap["hosts"][1]["routes"][0],
        serde_json::json!({
            "path": "/a-route",
            "methods": ["GET", "POST"],
            "status_codes": [200, 404],
            "parameters": ["page", "tag"],
            "content_types": ["application/json"],
            "exchange_count": 2
        })
    );
    assert_eq!(sitemap["hosts"][1]["tree"][0]["path"], "/a-route");

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

#[tokio::test]
async fn copy_as_includes_secrets_by_default_and_can_explicitly_redact_them() {
    let (_directory, state, project_id) = test_state().await;
    let mut captured = exchange(project_id, "POST", "/submit");
    captured.query = Some("from=history".into());
    captured.request_headers = vec![
        HeaderEntry {
            name: "Authorization".into(),
            value: b"Bearer top-secret".to_vec(),
            ordinal: 0,
        },
        HeaderEntry {
            name: "X-Repeat".into(),
            value: b"one".to_vec(),
            ordinal: 1,
        },
        HeaderEntry {
            name: "X-Repeat".into(),
            value: b"two".to_vec(),
            ordinal: 2,
        },
    ];
    captured.request_body = Some(br#"{"ok":true}"#.to_vec());
    let exchange_id = state.db.insert_exchange(captured).await.unwrap();
    let app = bb::api::router(state);

    let included = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/exchanges/{}/copy-as?format=curl",
                project_id.get(),
                exchange_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(included.status(), StatusCode::OK);
    let included = json_response(included).await;
    assert_eq!(included["redacted_headers"], 0);
    assert!(included["content"]
        .as_str()
        .unwrap()
        .contains("Authorization: Bearer top-secret"));
    assert_eq!(
        included["content"]
            .as_str()
            .unwrap()
            .matches("--header 'X-Repeat:")
            .count(),
        2
    );

    let redacted = app
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/exchanges/{}/copy-as?format=python_requests&include_secrets=false",
                project_id.get(),
                exchange_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(redacted.status(), StatusCode::OK);
    let redacted = json_response(redacted).await;
    assert_eq!(redacted["redacted_headers"], 1);
    let content = redacted["content"].as_str().unwrap();
    assert!(content.contains("<redacted>"));
    assert!(!content.contains("Bearer top-secret"));
    assert!(content.contains("\"X-Repeat\": \"one, two\""));
    assert!(content.contains("https://example.com/submit?from=history"));
}

#[tokio::test]
async fn raw_reply_preserves_framing_and_collects_response_sequences() {
    let (_directory, state, project_id) = test_state().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let raw_request = format!(
        "POST / HTTP/1.1\r\nHost: {address}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: {address}\r\n\r\n"
    );
    let expected = raw_request.as_bytes().to_vec();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = vec![0_u8; expected.len()];
        socket.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        socket
            .write_all(b"HTTP/1.1 201 OK\r\nContent-Length: 3\r\n\r\ntwo")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });
    let app = bb::api::router(state.clone());
    let sent = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/projects/{}/reply-send-raw",
                project_id.get()
            ))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "target_url": format!("http://{address}/"),
                    "request": raw_request,
                    "encoding": "utf8",
                    "response_mode": "until_idle",
                    "idle_timeout_ms": 50,
                    "read_timeout_ms": 1000
                })
                .to_string(),
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sent.status(), StatusCode::OK);
    let sent = json_response(sent).await;
    assert_eq!(sent["read_outcome"], "idle");
    assert_eq!(sent["responses"].as_array().unwrap().len(), 2);
    let exchange_id = sent["exchange_id"].as_i64().unwrap();

    let presented = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/exchanges/{exchange_id}/body?side=response",
                project_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let presented = json_response(presented).await;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(presented["data"].as_str().unwrap())
            .unwrap(),
        b"one"
    );

    let raw = app
        .oneshot(
            Request::get(format!(
                "/api/v1/projects/{}/exchanges/{exchange_id}/body?side=response&raw=true",
                project_id.get()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let raw = json_response(raw).await;
    let transcript = base64::engine::general_purpose::STANDARD
        .decode(raw["data"].as_str().unwrap())
        .unwrap();
    assert!(transcript
        .windows(b"HTTP/1.1 201 ".len())
        .any(|window| window == b"HTTP/1.1 201 "));

    let mcp_presented = bb::mcp::call_tool(
        state.clone(),
        "exchange_body",
        serde_json::json!({
            "project_id": project_id.get(),
            "exchange_id": exchange_id,
            "side": "response"
        }),
    )
    .await
    .unwrap();
    assert_eq!(mcp_presented["preview"], "one");
    assert_eq!(mcp_presented["total"], 3);

    let mcp_raw = bb::mcp::call_tool(
        state,
        "exchange_body",
        serde_json::json!({
            "project_id": project_id.get(),
            "exchange_id": exchange_id,
            "side": "response",
            "raw": true
        }),
    )
    .await
    .unwrap();
    assert!(mcp_raw["preview"]
        .as_str()
        .unwrap()
        .starts_with("HTTP/1.1 200 OK\r\n"));
    server.abort();
}
