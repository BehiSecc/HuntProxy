//! Live project routing uses isolated stores and local/mock transports.

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use huntproxy::app::{bootstrap_state, AppState};
use huntproxy::config::{Config, ProjectUpstreamProxyRule, UpstreamProxyConfig, UpstreamProxyRule};
use huntproxy::domain::*;
use huntproxy::reply::{PlaceholderKey, ReplyService};
use huntproxy::storage::Db;
use huntproxy::transfer::{BundleExportOptions, SecretMode};
use huntproxy::transport::{OutboundRequest, OutboundResponse, SemanticTransport};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tower::ServiceExt;

fn configuration() -> (TempDir, Config) {
    std::fs::create_dir_all("/tmp/artis").unwrap();
    let directory = tempfile::Builder::new()
        .prefix("huntproxy-live-upstream-")
        .tempdir_in("/tmp/artis")
        .unwrap();
    let config = Config {
        data_dir: directory.path().to_path_buf(),
        spool_dir: directory.path().join("spool"),
        export_dir: directory.path().join("exports"),
        runtime_dir: directory.path().join("runtime"),
        plugin_dir: directory.path().join("plugins"),
        browser_worker_path: Some(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("browser-worker/index.js"),
        ),
        ..Config::default()
    };
    (directory, config)
}

async fn project(db: &Db, name: &str) -> ProjectId {
    db.create_project(CreateProjectRequest {
        name: name.into(),
        target_url: "http://127.0.0.1/".into(),
        advanced: None,
    })
    .await
    .unwrap()
    .id
}

async fn resolved(db: &Db, id: ProjectId, config: &UpstreamProxyConfig) -> Option<String> {
    db.resolve_upstream_proxy(id, config, "127.0.0.1", None)
        .await
        .unwrap()
}

#[tokio::test]
async fn live_routing_is_persistent_and_explicit_direct_overrides_all_static_routes() {
    let (_directory, config) = configuration();
    let db = Db::open(&config).await.unwrap();
    let id = project(&db, "Primary workspace").await;
    let other = project(&db, "Secondary workspace").await;
    let routes = UpstreamProxyConfig {
        default: Some("http://default.example:8080".into()),
        project_rules: vec![ProjectUpstreamProxyRule {
            project_id: id.get(),
            proxy: "http://project.example:8080".into(),
        }],
        rules: vec![UpstreamProxyRule {
            host: "127.0.0.1".into(),
            proxy: "http://host.example:8080".into(),
        }],
    };
    assert_eq!(
        resolved(&db, id, &routes).await.as_deref(),
        Some("http://project.example:8080")
    );
    let proxy = "http://fixture-user:fixture-password@127.0.0.1:8081";
    let status = db
        .set_project_upstream_proxy(id, Some(proxy.into()))
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(status).unwrap(),
        json!({"project_id":id.get(),"mode":"proxy"})
    );
    let cloned = db.clone();
    assert_eq!(resolved(&cloned, id, &routes).await.as_deref(), Some(proxy));
    assert_eq!(
        resolved(&cloned, other, &routes).await.as_deref(),
        Some("http://host.example:8080")
    );
    db.set_project_upstream_proxy(id, None).await.unwrap();
    assert!(resolved(&cloned, id, &routes).await.is_none());
    let reopened = Db::open(&config).await.unwrap();
    assert!(resolved(&reopened, id, &routes).await.is_none());
    assert_eq!(
        reopened
            .resolve_upstream_proxy(
                id,
                &routes,
                "127.0.0.1",
                Some("http://override.example:8080")
            )
            .await
            .unwrap()
            .as_deref(),
        Some("http://override.example:8080")
    );
    let public = serde_json::to_string(&db.list_projects().await.unwrap()).unwrap();
    assert!(!public.contains("fixture-password"));
    assert!(!public.contains("fixture-user"));
    db.delete_project(id).await.unwrap();
    let rows: i64 = db
        .with_conn(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM project_upstream_proxies WHERE project_id=?1",
                [id.get()],
                |row| row.get(0),
            )
            .map_err(|_| DomainError::new(ErrorCode::StorageError, "count failed"))
        })
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn invalid_updates_do_not_change_existing_routing_or_expose_credentials() {
    let (_directory, config) = configuration();
    let db = Db::open(&config).await.unwrap();
    let id = project(&db, "Working area").await;
    let routes = UpstreamProxyConfig::default();
    db.set_project_upstream_proxy(id, Some("http://127.0.0.1:8080".into()))
        .await
        .unwrap();
    for proxy in [
        "",
        "https://fixture-secret@proxy.example:443",
        "http://fixture-secret@proxy.example:8080/path",
        "not-a-url",
    ] {
        let error = db
            .set_project_upstream_proxy(id, Some(proxy.into()))
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("fixture-secret"));
        assert_eq!(
            resolved(&db, id, &routes).await.as_deref(),
            Some("http://127.0.0.1:8080")
        );
    }
    for id in [ProjectId(0), ProjectId(-1), ProjectId(99999)] {
        assert_eq!(
            db.set_project_upstream_proxy(id, None)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::NotFound
        );
    }
}

async fn state() -> (TempDir, Arc<AppState>, ProjectId) {
    let (directory, config) = configuration();
    let state = bootstrap_state(config).await.unwrap();
    let id = project(&state.db, "API workspace").await;
    (directory, state, id)
}

#[tokio::test]
async fn api_and_mcp_require_an_explicit_proxy_and_return_safe_status() {
    let (_directory, state, id) = state().await;
    let app = huntproxy::api::router(state.clone());
    let proxy = "http://fixture-user:fixture-secret@127.0.0.1:8080";
    for (body, expected) in [
        (json!({"proxy":proxy}), StatusCode::OK),
        (json!({"proxy":null}), StatusCode::OK),
        (json!({}), StatusCode::UNPROCESSABLE_ENTITY),
        (json!({"proxy":123}), StatusCode::BAD_REQUEST),
        (
            json!({"proxy":"https://fixture-secret@127.0.0.1:8080"}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::put(format!("/api/v1/projects/{}/upstream-proxy", id.get()))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("fixture-secret"));
        if expected == StatusCode::OK {
            let result: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                result,
                json!({"project_id":id.get(),"mode":if body["proxy"].is_null(){"direct"}else{"proxy"}})
            );
        }
    }
    let result = huntproxy::mcp::call_tool(
        state.clone(),
        "projects",
        json!({"action":"set_upstream_proxy","project_id":id.get(),"proxy":proxy}),
    )
    .await
    .unwrap();
    assert_eq!(result, json!({"project_id":id.get(),"mode":"proxy"}));
    let result = huntproxy::mcp::call_tool(
        state.clone(),
        "projects",
        json!({"action":"set_upstream_proxy","project_id":id.get(),"proxy":null}),
    )
    .await
    .unwrap();
    assert_eq!(result["mode"], "direct");
    for args in [
        json!({"action":"set_upstream_proxy","project_id":id.get()}),
        json!({"action":"set_upstream_proxy","project_id":id.get(),"proxy":false}),
    ] {
        assert_eq!(
            huntproxy::mcp::call_tool(state.clone(), "projects", args)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::InvalidArgument
        );
    }
    let response = app
        .oneshot(
            Request::put("/api/v1/projects/99999/upstream-proxy")
                .header("content-type", "application/json")
                .body(Body::from("{\"proxy\":null}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[derive(Default)]
struct Recorder(Mutex<Vec<Option<String>>>);

#[async_trait::async_trait]
impl SemanticTransport for Recorder {
    async fn send(
        &self,
        _dial: &ValidatedDial,
        request: OutboundRequest,
    ) -> DomainResult<OutboundResponse> {
        self.0.lock().unwrap().push(request.upstream_proxy);
        Ok(OutboundResponse {
            status: StatusCode::OK,
            headers: vec![],
            body: bytes::Bytes::new(),
            body_truncated: false,
            protocol: "HTTP/1.1".into(),
            transport_provenance: TransportProvenance::GenericUnprofiled,
            transport_profile: "fixture".into(),
            duration: Duration::from_millis(1),
        })
    }

    fn profile_name(&self) -> &str {
        "fixture"
    }
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::GenericUnprofiled
    }
}

#[tokio::test]
async fn an_existing_reply_service_uses_runtime_updates_and_request_override_priority() {
    let (_directory, config) = configuration();
    let db = Arc::new(Db::open(&config).await.unwrap());
    let id = project(&db, "Reply workspace").await;
    let recorder = Arc::new(Recorder::default());
    let reply = ReplyService {
        db: db.clone(),
        transport: recorder.clone(),
        placeholder_key: PlaceholderKey::from_bytes(vec![9; 32]),
        upstream_proxies: UpstreamProxyConfig {
            default: Some("http://static.example:8080".into()),
            ..Default::default()
        },
    };
    let draft = ReplyDraft {
        url: Some("http://127.0.0.1/".into()),
        ..Default::default()
    };
    reply
        .send(id, None, None, &draft, ProtocolPreference::H1, 0)
        .await
        .unwrap();
    db.set_project_upstream_proxy(id, Some("http://first.example:8080".into()))
        .await
        .unwrap();
    reply
        .send(id, None, None, &draft, ProtocolPreference::H1, 0)
        .await
        .unwrap();
    db.set_project_upstream_proxy(id, Some("http://second.example:8080".into()))
        .await
        .unwrap();
    reply
        .send(id, None, None, &draft, ProtocolPreference::H1, 0)
        .await
        .unwrap();
    db.set_project_upstream_proxy(id, None).await.unwrap();
    reply
        .send(id, None, None, &draft, ProtocolPreference::H1, 0)
        .await
        .unwrap();
    reply
        .send_with_proxy(
            id,
            None,
            None,
            &draft,
            ProtocolPreference::H1,
            0,
            Some("http://override.example:8080"),
        )
        .await
        .unwrap();
    assert_eq!(
        *recorder.0.lock().unwrap(),
        vec![
            Some("http://static.example:8080".into()),
            Some("http://first.example:8080".into()),
            Some("http://second.example:8080".into()),
            None,
            Some("http://override.example:8080".into())
        ]
    );
}

#[tokio::test]
async fn bundles_include_proxy_credentials_only_in_full_exports() {
    let (_directory, config) = configuration();
    let db = Db::open(&config).await.unwrap();
    let id = project(&db, "Export workspace").await;
    let proxy = "http://fixture-user:fixture-secret@127.0.0.1:8080";
    db.set_project_upstream_proxy(id, Some(proxy.into()))
        .await
        .unwrap();
    for (name, mode, expected) in [
        ("full", SecretMode::Full, Some(proxy)),
        ("sanitized", SecretMode::Sanitized, None),
    ] {
        let path = config.runtime_dir.join(format!("{name}.huntproxy"));
        db.export_bundle(
            &config,
            id,
            path.clone(),
            BundleExportOptions {
                secrets: mode,
                include_chromium_profile: false,
            },
        )
        .await
        .unwrap();
        let imported = db.import_bundle(&config, path, None).await.unwrap();
        assert_eq!(
            resolved(&db, imported.project.id, &UpstreamProxyConfig::default())
                .await
                .as_deref(),
            expected
        );
    }
}
