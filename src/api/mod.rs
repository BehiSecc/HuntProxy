//! Versioned HTTP API, SSE, embedded UI, and private UDS.

use crate::app::{AppEvent, AppState};
use crate::domain::*;
use crate::fuzzer::FuzzTemplate;
use crate::history::parse_text_query;
use crate::policy::PresentationOptions;
use crate::storage::CreateCaptureSession;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use futures::stream::Stream;
use futures::StreamExt;
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub async fn bind_api(addr: std::net::SocketAddr) -> DomainResult<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| DomainError::new(ErrorCode::Unavailable, format!("api bind {addr}: {e}")))
}

pub async fn serve_api(state: Arc<AppState>, cancel: CancellationToken) -> DomainResult<()> {
    let listener = bind_api(state.config.api_listen).await?;
    serve_api_listener(state, listener, cancel).await
}

pub async fn serve_api_listener(
    state: Arc<AppState>,
    listener: tokio::net::TcpListener,
    cancel: CancellationToken,
) -> DomainResult<()> {
    let app = router(state.clone());
    let addr = listener
        .local_addr()
        .map_err(|e| DomainError::new(ErrorCode::Unavailable, e.to_string()))?;
    tracing::info!(%addr, "api/ui listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await
        .map_err(|e| DomainError::new(ErrorCode::Unavailable, e.to_string()))
}

pub async fn serve_uds(state: Arc<AppState>, cancel: CancellationToken) -> DomainResult<()> {
    #[cfg(unix)]
    {
        let listener = bind_uds(&state.config.socket_path())?;
        serve_uds_listener(state, listener, cancel).await?;
    }
    Ok(())
}

#[cfg(unix)]
pub fn bind_uds(path: &std::path::Path) -> DomainResult<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = tokio::net::UnixListener::bind(path)
        .map_err(|e| DomainError::new(ErrorCode::Unavailable, format!("uds bind: {e}")))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| DomainError::new(ErrorCode::Unavailable, format!("uds permissions: {e}")))?;
    Ok(listener)
}

#[cfg(unix)]
pub async fn serve_uds_listener(
    state: Arc<AppState>,
    listener: tokio::net::UnixListener,
    cancel: CancellationToken,
) -> DomainResult<()> {
    let path = state.config.socket_path();
    tracing::info!(path=%path.display(), "private socket listening");
    let app = private_router(state);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let app = app.clone();
                        tokio::spawn(async move {
                            let io = hyper_util::rt::TokioIo::new(stream);
                            let hyper_service = hyper::service::service_fn(
                                move |request: axum::http::Request<hyper::body::Incoming>| {
                                    let app = app.clone();
                                    async move {
                                        match tower::ServiceExt::oneshot(app, request.map(axum::body::Body::new)).await {
                                            Ok(res) => Ok::<_, std::convert::Infallible>(res),
                                            Err(_) => Ok(axum::response::Response::builder()
                                                .status(500)
                                                .body(axum::body::Body::from("internal"))
                                                .unwrap()),
                                        }
                                    }
                                },
                            );
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, hyper_service)
                                .await;
                        });
                    }
                    Err(e) => tracing::warn!(error=%e, "uds accept failed"),
                }
            }
        }
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

pub fn router(state: Arc<AppState>) -> Router {
    let activity_state = state.clone();
    const SMALL_BODY_LIMIT: usize = 128 * 1024;
    let payload_body_limit = api_payload_body_limit(state.config.max_body_bytes);
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/version", get(version))
        .route(
            "/api/v1/projects",
            get(list_projects)
                .post(create_project)
                .layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
        .route(
            "/api/v1/projects/import",
            post(import_project).layer(DefaultBodyLimit::max(payload_body_limit)),
        )
        .route(
            "/api/v1/projects/{id}",
            get(get_project)
                .patch(rename_project)
                .delete(delete_project)
                .layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
        .route("/api/v1/projects/{id}/usage", get(project_usage))
        .route("/api/v1/projects/{id}/export", get(export_project))
        .route("/api/v1/projects/{id}/bundle", get(export_bundle))
        .route(
            "/api/v1/projects/{id}/har",
            get(export_har)
                .post(import_har)
                .layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/projects/import-bundle",
            post(import_bundle).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/projects/{id}/scope",
            post(update_project_scope).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
        .route(
            "/api/v1/projects/{id}/request-rules",
            get(list_request_rules)
                .post(create_request_rule)
                .layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
        .route(
            "/api/v1/projects/{id}/request-rules/preview",
            post(preview_request_rules).layer(DefaultBodyLimit::max(payload_body_limit)),
        )
        .route(
            "/api/v1/projects/{id}/request-rules/{rid}",
            patch(update_request_rule).delete(delete_request_rule),
        )
        .route(
            "/api/v1/projects/{id}/cookies",
            get(list_project_cookies)
                .put(set_project_cookie)
                .delete(clear_project_cookie)
                .layer(DefaultBodyLimit::max(payload_body_limit)),
        )
        .route(
            "/api/v1/projects/{id}/capture-sessions",
            get(list_capture_sessions).post(create_capture_session),
        )
        .route(
            "/api/v1/projects/{id}/capture-sessions/{sid}/revoke",
            post(revoke_capture_session),
        )
        .route(
            "/api/v1/projects/{id}/capture-sessions/{sid}/renew",
            post(renew_capture_session),
        )
        .route(
            "/api/v1/projects/{id}/history",
            get(history).delete(clear_history),
        )
        .route("/api/v1/projects/{id}/sitemap", get(sitemap))
        .route("/api/v1/projects/{id}/words", get(get_words))
        .route(
            "/api/v1/projects/{id}/findings",
            get(list_findings)
                .post(create_finding)
                .layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
        .route(
            "/api/v1/projects/{id}/findings/{fid}",
            delete(delete_finding),
        )
        .route(
            "/api/v1/projects/{id}/exchanges/compare",
            get(compare_exchanges),
        )
        .route("/api/v1/projects/{id}/exchanges/{eid}", get(get_exchange))
        .route(
            "/api/v1/projects/{id}/exchanges/{eid}/annotation",
            get(get_annotation)
                .post(upsert_annotation)
                .layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
        .route("/api/v1/projects/{id}/exchanges/{eid}/body", get(get_body))
        .route(
            "/api/v1/projects/{id}/exchanges/{eid}/analyze",
            get(analyze_exchange),
        )
        .route(
            "/api/v1/projects/{id}/exchanges/{eid}/copy-as",
            get(copy_as),
        )
        .route(
            "/api/v1/projects/{id}/reply-tabs",
            get(list_reply_tabs)
                .post(upsert_reply_tab)
                .layer(DefaultBodyLimit::max(payload_body_limit)),
        )
        .route(
            "/api/v1/projects/{id}/reply-send",
            post(reply_send).layer(DefaultBodyLimit::max(payload_body_limit)),
        )
        .route(
            "/api/v1/projects/{id}/reply-send-raw",
            post(reply_send_raw).layer(DefaultBodyLimit::max(payload_body_limit)),
        )
        .route(
            "/api/v1/projects/{id}/fuzz-jobs",
            get(list_fuzz_jobs)
                .post(start_fuzz)
                .layer(DefaultBodyLimit::max(payload_body_limit)),
        )
        .route(
            "/api/v1/projects/{id}/fuzz-jobs/{jid}/cancel",
            post(cancel_fuzz),
        )
        .route(
            "/api/v1/projects/{id}/fuzz-jobs/{jid}/cases",
            get(list_fuzz_cases),
        )
        .route(
            "/api/v1/projects/{id}/fuzz-jobs/{jid}/groups",
            get(list_fuzz_groups),
        )
        .route(
            "/api/v1/projects/{id}/fuzz-jobs/{jid}/cases/{case_id}/diff",
            get(fuzz_case_diff),
        )
        .route(
            "/api/v1/projects/{id}/websockets",
            get(list_websocket_connections),
        )
        .route(
            "/api/v1/projects/{id}/websockets/{wid}/messages",
            get(list_websocket_messages),
        )
        .route(
            "/api/v1/projects/{id}/websockets/{wid}/send",
            post(send_websocket_message).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
        .route(
            "/api/v1/projects/{id}/browser-sessions",
            get(browser_status)
                .post(start_browser)
                .layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
        .route(
            "/api/v1/projects/{id}/browser-sessions/{bid}/action",
            post(browser_action).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
        .route(
            "/api/v1/projects/{id}/browser-sessions/{bid}/stop",
            post(stop_browser),
        )
        .route(
            "/api/v1/projects/{id}/browser-cdp",
            post(browser_cdp).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
        .route("/api/v1/projects/{id}/events", get(events))
        .route("/api/v1/doctor", get(doctor))
        .route("/api/v1/extensions", get(list_extensions))
        .route("/api/v1/extensions/{plugin_id}", get(describe_extension))
        .route(
            "/api/v1/projects/{id}/extension-jobs",
            post(run_extension).layer(DefaultBodyLimit::max(payload_body_limit)),
        )
        .route(
            "/api/v1/projects/{id}/extension-jobs/{job_id}",
            get(extension_job),
        )
        .route(
            "/api/v1/projects/{id}/extension-jobs/{job_id}/results",
            get(extension_job_results),
        )
        .route(
            "/api/v1/projects/{id}/extension-jobs/{job_id}/cancel",
            post(cancel_extension_job),
        )
        .route("/api/v1/projects/{id}/ip-rotation", get(ip_rotation_status))
        .route(
            "/api/v1/codec",
            post(codec_transform).layer(DefaultBodyLimit::max(payload_body_limit)),
        )
        .route("/", get(ui_index))
        .layer(axum::middleware::from_fn(prevent_api_caching))
        .layer(axum::middleware::from_fn_with_state(
            activity_state,
            track_control_activity,
        ))
        .with_state(state)
}

async fn prevent_api_caching(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    if is_api {
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
    }
    response
}

async fn track_control_activity(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !matches!(
        request.uri().path(),
        "/api/v1/health" | "/api/v1/version" | "/api/v1/doctor"
    ) {
        state.activity.touch();
    }
    next.run(request).await
}

fn private_router(state: Arc<AppState>) -> Router {
    let payload_body_limit = api_payload_body_limit(state.config.max_body_bytes);
    router(state.clone()).merge(
        Router::new()
            .route(
                "/internal/mcp/call",
                post(internal_mcp_call).layer(DefaultBodyLimit::max(payload_body_limit)),
            )
            .route("/internal/shutdown", post(internal_shutdown))
            .with_state(state),
    )
}

fn api_payload_body_limit(max_body_bytes: u64) -> usize {
    // Raw byte vectors may arrive as JSON integer arrays (up to roughly 4x
    // their decoded size), while base64/text representations are smaller.
    usize::try_from(max_body_bytes)
        .unwrap_or(usize::MAX / 5)
        .saturating_mul(5)
        .max(128 * 1024)
}

async fn internal_shutdown(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.shutdown.cancel();
    Json(serde_json::json!({ "ok": true }))
}

#[derive(Deserialize)]
struct InternalMcpCall {
    name: String,
    #[serde(default)]
    arguments: serde_json::Value,
}

async fn internal_mcp_call(
    State(state): State<Arc<AppState>>,
    Json(body): Json<InternalMcpCall>,
) -> Response {
    state.activity.touch();
    match crate::mcp::call_tool(state, &body.name, body.arguments).await {
        Ok(result) => Json(serde_json::json!({
            "result": result,
            "error": null,
        }))
        .into_response(),
        Err(error) => {
            let status = status_for_error(&error);
            let envelope = ErrorEnvelope::from(&error);
            (
                status,
                Json(serde_json::json!({
                    "result": null,
                    "error": envelope,
                })),
            )
                .into_response()
        }
    }
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "ok": true,
        "name": crate::DISPLAY_NAME,
        "protocol": crate::INTERNAL_PROTOCOL_VERSION,
        "api": crate::API_VERSION,
        "schema": state.db.schema_version().await.unwrap_or(-1),
    }))
}

async fn version() -> impl IntoResponse {
    Json(serde_json::json!({
        "name": crate::DISPLAY_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": crate::INTERNAL_PROTOCOL_VERSION,
    }))
}

async fn list_extensions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "plugin_directory": state.plugins.directory(),
        "plugins": state.plugins.list(),
        "load_issues": state.plugins.load_issues(),
    }))
}

async fn describe_extension(
    State(state): State<Arc<AppState>>,
    Path(plugin_id): Path<String>,
) -> Response {
    match state.plugins.describe(&plugin_id) {
        Ok(plugin) => Json(plugin).into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct RunExtensionBody {
    plugin_id: String,
    action: String,
    #[serde(alias = "exchange_id")]
    base_exchange_id: Option<i64>,
    #[serde(default = "empty_json_object")]
    input: serde_json::Value,
}

fn empty_json_object() -> serde_json::Value {
    serde_json::json!({})
}

async fn run_extension(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<RunExtensionBody>,
) -> Response {
    match state
        .plugins
        .run(
            ProjectId(id),
            &body.plugin_id,
            &body.action,
            body.base_exchange_id.map(ExchangeId),
            body.input,
        )
        .await
    {
        Ok(job) => (StatusCode::ACCEPTED, Json(job)).into_response(),
        Err(error) => error_response(error),
    }
}

fn parse_project_job(
    state: &AppState,
    project_id: i64,
    job_id: &str,
) -> DomainResult<crate::plugins::PluginJobView> {
    let job_id = job_id
        .parse::<uuid::Uuid>()
        .map_err(|_| DomainError::invalid("job_id must be a UUID"))?;
    let job = state.plugins.status(job_id)?;
    if job.project_id != ProjectId(project_id) {
        return Err(DomainError::not_found("plugin job"));
    }
    Ok(job)
}

async fn extension_job(
    State(state): State<Arc<AppState>>,
    Path((id, job_id)): Path<(i64, String)>,
) -> Response {
    match parse_project_job(&state, id, &job_id) {
        Ok(job) => Json(job).into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Debug, Deserialize)]
struct ExtensionJobResultsQuery {
    view: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
}

async fn extension_job_results(
    State(state): State<Arc<AppState>>,
    Path((id, job_id)): Path<(i64, String)>,
    Query(query): Query<ExtensionJobResultsQuery>,
) -> Response {
    let job_id = match job_id.parse::<uuid::Uuid>() {
        Ok(job_id) => job_id,
        Err(_) => return error_response(DomainError::invalid("job_id must be a UUID")),
    };
    let status = match state.plugins.status(job_id) {
        Ok(status) if status.project_id == ProjectId(id) => status,
        Ok(_) => return error_response(DomainError::not_found("plugin job")),
        Err(error) => return error_response(error),
    };
    let _ = status;
    let view = match query.view.as_deref().unwrap_or("summary") {
        "summary" => crate::plugins::PluginResultView::Summary,
        "findings" => crate::plugins::PluginResultView::Findings,
        "full" => crate::plugins::PluginResultView::Full,
        _ => {
            return error_response(DomainError::invalid(
                "view must be summary, findings, or full",
            ))
        }
    };
    match state.plugins.results(
        job_id,
        view,
        query.offset.unwrap_or(0),
        query.limit.unwrap_or(25),
    ) {
        Ok(result) => Json(result).into_response(),
        Err(error) => error_response(error),
    }
}

async fn ip_rotation_status(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.db.list_ip_rotation_profiles(ProjectId(id)).await {
        Ok(profiles) => Json(serde_json::json!({ "profiles": profiles })).into_response(),
        Err(error) => error_response(error),
    }
}

async fn cancel_extension_job(
    State(state): State<Arc<AppState>>,
    Path((id, job_id)): Path<(i64, String)>,
) -> Response {
    let job = match parse_project_job(&state, id, &job_id) {
        Ok(job) => job,
        Err(error) => return error_response(error),
    };
    match state.plugins.cancel(job.id) {
        Ok(job) => Json(job).into_response(),
        Err(error) => error_response(error),
    }
}

async fn list_projects(State(state): State<Arc<AppState>>) -> Response {
    match state.db.list_projects().await {
        Ok(p) => Json(serde_json::json!({"projects": p})).into_response(),
        Err(e) => error_response(e),
    }
}

async fn create_project(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateProjectRequest>,
) -> Response {
    match state.db.create_project(req).await {
        Ok(project) => {
            let _ = state.events.send(AppEvent {
                project_id: project.id.get(),
                kind: "project".into(),
                payload: serde_json::json!({ "project_id": project.id.get() }),
            });
            (StatusCode::CREATED, Json(project)).into_response()
        }
        Err(e) => error_response(e),
    }
}

async fn get_project(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.db.get_project(ProjectId(id)).await {
        Ok(p) => Json(p).into_response(),
        Err(e) => error_response(e),
    }
}

#[derive(Deserialize)]
struct RenameProjectBody {
    name: String,
}

async fn rename_project(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<RenameProjectBody>,
) -> Response {
    match state.db.rename_project(ProjectId(id), body.name).await {
        Ok(project) => Json(project).into_response(),
        Err(error) => error_response(error),
    }
}

async fn delete_project(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    let project_id = ProjectId(id);
    match state.fuzzer.list(project_id).await {
        Ok(jobs)
            if jobs.iter().any(|job| {
                !matches!(
                    job.state,
                    FuzzJobState::Completed | FuzzJobState::Failed | FuzzJobState::Interrupted
                )
            }) =>
        {
            return error_response(DomainError::conflict(
                "cancel active fuzz jobs before deleting the project",
            ));
        }
        Err(error) => return error_response(error),
        _ => {}
    }
    match state.db.list_ip_rotation_profiles(project_id).await {
        Ok(profiles) if !profiles.is_empty() => {
            return error_response(DomainError::conflict(
                "disable IP rotation and finish gateway cleanup before deleting the project",
            ));
        }
        Err(error) => return error_response(error),
        _ => {}
    }
    if let Err(error) = state.browser.reset_project_profile(project_id).await {
        return error_response(error);
    }
    match state.db.delete_project(project_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(error),
    }
}

async fn project_usage(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.db.project_usage(ProjectId(id)).await {
        Ok(usage) => Json(usage).into_response(),
        Err(error) => error_response(error),
    }
}

async fn export_project(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.db.export_project(ProjectId(id)).await {
        Ok(archive) => Json(archive).into_response(),
        Err(error) => error_response(error),
    }
}

async fn import_project(
    State(state): State<Arc<AppState>>,
    Json(archive): Json<crate::storage::ProjectArchive>,
) -> Response {
    match state.db.import_project(archive).await {
        Ok(project) => (StatusCode::CREATED, Json(project)).into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct BundleQuery {
    include_secrets: Option<bool>,
    include_chromium_profile: Option<bool>,
}

async fn export_bundle(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(query): Query<BundleQuery>,
) -> Response {
    let include_secrets = query.include_secrets.unwrap_or(false);
    let include_chromium_profile = query.include_chromium_profile.unwrap_or(false);
    if include_chromium_profile && !include_secrets {
        return error_response(DomainError::invalid(
            "Chromium profile export requires include_secrets=true",
        ));
    }
    let path = state.config.export_dir.join(format!(
        "huntproxy-project-{id}-{}.huntproxy",
        uuid::Uuid::new_v4()
    ));
    match state
        .db
        .export_bundle(
            &state.config,
            ProjectId(id),
            path.clone(),
            crate::transfer::BundleExportOptions {
                secrets: if include_secrets {
                    crate::transfer::SecretMode::Full
                } else {
                    crate::transfer::SecretMode::Sanitized
                },
                include_chromium_profile,
            },
        )
        .await
    {
        Ok(_) => match tokio::fs::File::open(&path).await {
            Ok(file) => {
                let mut reader = tokio_util::io::ReaderStream::new(file);
                let cleanup = DeleteOnDrop(path.clone());
                let stream = async_stream::stream! {
                    while let Some(chunk) = reader.next().await {
                        yield chunk;
                    }
                    drop(cleanup);
                };
                let name = format!("huntproxy-project-{id}.huntproxy");
                let mut response = Body::from_stream(stream).into_response();
                response.headers_mut().insert(
                    CONTENT_TYPE,
                    "application/vnd.huntproxy.project+zstd".parse().unwrap(),
                );
                response.headers_mut().insert(
                    CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{name}\"").parse().unwrap(),
                );
                response
            }
            Err(error) => {
                error_response(DomainError::new(ErrorCode::StorageError, error.to_string()))
            }
        },
        Err(error) => error_response(error),
    }
}

async fn import_bundle(State(state): State<Arc<AppState>>, body: Body) -> Response {
    let path = state
        .config
        .runtime_dir
        .join(format!("bundle-upload-{}.huntproxy", uuid::Uuid::new_v4()));
    match stream_body_to_file(body, &path, crate::transfer::MAX_BUNDLE_UPLOAD_BYTES).await {
        Ok(()) => {
            let result = state
                .db
                .import_bundle(&state.config, path.clone(), None)
                .await;
            let _ = tokio::fs::remove_file(path).await;
            match result {
                Ok(result) => (StatusCode::CREATED, Json(result)).into_response(),
                Err(error) => error_response(error),
            }
        }
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct HarQuery {
    include_secrets: Option<bool>,
}

async fn export_har(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(query): Query<HarQuery>,
) -> Response {
    match state
        .db
        .export_har(ProjectId(id), query.include_secrets.unwrap_or(false))
        .await
    {
        Ok(har) => Json(har).into_response(),
        Err(error) => error_response(error),
    }
}

async fn import_har(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    body: Body,
) -> Response {
    let path = state
        .config
        .runtime_dir
        .join(format!("har-upload-{}.har", uuid::Uuid::new_v4()));
    match stream_body_to_file(body, &path, crate::har::MAX_HAR_FILE_BYTES).await {
        Ok(()) => {
            let result = state.db.import_har_file(ProjectId(id), &path).await;
            let _ = tokio::fs::remove_file(path).await;
            match result {
                Ok(result) => Json(result).into_response(),
                Err(error) => error_response(error),
            }
        }
        Err(error) => error_response(error),
    }
}

async fn stream_body_to_file(
    body: Body,
    path: &std::path::Path,
    max_bytes: u64,
) -> DomainResult<()> {
    use tokio::io::AsyncWriteExt;
    let mut stream = body.into_data_stream();
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .await
        .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
    let mut written = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| DomainError::invalid(format!("upload body: {error}")))?;
        written = written.saturating_add(chunk.len() as u64);
        if written > max_bytes {
            let _ = tokio::fs::remove_file(path).await;
            return Err(DomainError::invalid("upload exceeds size limit"));
        }
        file.write_all(&chunk)
            .await
            .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
    }
    file.flush()
        .await
        .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))
}

struct DeleteOnDrop(std::path::PathBuf);

impl Drop for DeleteOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[derive(Deserialize)]
struct SetCookieBody {
    target_url: String,
    cookie: serde_json::Value,
    profile_name: Option<String>,
}

async fn list_project_cookies(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    let project_id = ProjectId(id);
    match (
        state.db.list_cookie_profiles(project_id).await,
        state.db.list_named_cookie_profiles(project_id).await,
    ) {
        (Ok(profiles), Ok(named)) => Json(serde_json::json!({
            "profiles": profiles,
            "named_profiles": named.into_iter().map(|(name, profile)| serde_json::json!({"name":name,"profile":profile})).collect::<Vec<_>>()
        })).into_response(),
        (Err(error), _) | (_, Err(error)) => error_response(error),
    }
}

async fn set_project_cookie(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<SetCookieBody>,
) -> Response {
    let cookie = match crate::cookies::cookie_input_from_json_value(&body.cookie) {
        Ok(cookie) => cookie,
        Err(error) => return error_response(error),
    };
    if let Some(name) = body.profile_name.as_deref() {
        let profile = match crate::cookies::validate_cookie_profile(&body.target_url, cookie) {
            Ok(profile) => profile,
            Err(error) => return error_response(error),
        };
        match state
            .db
            .upsert_named_cookie_profile(ProjectId(id), name, profile)
            .await
        {
            Ok(profile) => Json(serde_json::json!({"name":name,"profile":profile,"active":false}))
                .into_response(),
            Err(error) => error_response(error),
        }
    } else {
        match crate::cookies::set_project_cookie(&state, ProjectId(id), &body.target_url, cookie)
            .await
        {
            Ok(result) => Json(result).into_response(),
            Err(error) => error_response(error),
        }
    }
}

#[derive(Deserialize)]
struct ClearCookieBody {
    target_url: Option<String>,
    profile_name: Option<String>,
}

async fn clear_project_cookie(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<ClearCookieBody>,
) -> Response {
    if let Some(name) = body.profile_name.as_deref() {
        return match state
            .db
            .delete_named_cookie_profile(ProjectId(id), name)
            .await
        {
            Ok(true) => StatusCode::NO_CONTENT.into_response(),
            Ok(false) => StatusCode::NO_CONTENT.into_response(),
            Err(error) => error_response(error),
        };
    }
    let Some(target_url) = body.target_url.as_deref() else {
        return error_response(DomainError::invalid("target_url or profile_name required"));
    };
    match crate::cookies::clear_project_cookie(&state, ProjectId(id), target_url).await {
        Ok(Some(result)) => Json(result).into_response(),
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(error),
    }
}

async fn update_project_scope(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(scope): Json<ScopePolicy>,
) -> Response {
    match state
        .db
        .update_project_scope(ProjectId(id), scope, None)
        .await
    {
        Ok(project) => Json(project).into_response(),
        Err(error) => error_response(error),
    }
}

async fn list_request_rules(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.db.list_request_rules(ProjectId(id)).await {
        Ok(rules) => Json(serde_json::json!({ "rules": rules })).into_response(),
        Err(error) => error_response(error),
    }
}

async fn create_request_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(input): Json<crate::request_rules::RequestRuleInput>,
) -> Response {
    match state.db.create_request_rule(ProjectId(id), input).await {
        Ok(rule) => (StatusCode::CREATED, Json(rule)).into_response(),
        Err(error) => error_response(error),
    }
}

async fn update_request_rule(
    State(state): State<Arc<AppState>>,
    Path((id, rid)): Path<(i64, i64)>,
    Json(input): Json<crate::request_rules::RequestRuleInput>,
) -> Response {
    match state
        .db
        .update_request_rule(ProjectId(id), rid, input)
        .await
    {
        Ok(rule) => Json(rule).into_response(),
        Err(error) => error_response(error),
    }
}

async fn delete_request_rule(
    State(state): State<Arc<AppState>>,
    Path((id, rid)): Path<(i64, i64)>,
) -> Response {
    match state.db.delete_request_rule(ProjectId(id), rid).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct RequestRulePreviewBody {
    url: String,
    #[serde(default)]
    headers: Vec<RequestRulePreviewHeader>,
    #[serde(default)]
    body: String,
}

#[derive(Deserialize)]
struct RequestRulePreviewHeader {
    name: String,
    value: String,
}

async fn preview_request_rules(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<RequestRulePreviewBody>,
) -> Response {
    let headers = body
        .headers
        .into_iter()
        .map(|header| (header.name, header.value.into_bytes()))
        .collect();
    match crate::request_rules::preview(
        &state.db,
        ProjectId(id),
        body.url,
        headers,
        body.body.into_bytes(),
    )
    .await
    {
        Ok(result) => Json(result).into_response(),
        Err(error) => error_response(error),
    }
}

async fn create_capture_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Response {
    match state
        .db
        .create_capture_session(CreateCaptureSession {
            project_id: ProjectId(id),
            browser_session_id: None,
            browser_action_id: None,
            is_browser_bound: false,
            ttl: None,
        })
        .await
    {
        Ok(session) => {
            let _ = state.events.send(AppEvent {
                project_id: id,
                kind: "capture".into(),
                payload: serde_json::json!({ "session_id": session.id.get(), "state": "created" }),
            });
            (StatusCode::CREATED, Json(session)).into_response()
        }
        Err(e) => error_response(e),
    }
}

async fn list_capture_sessions(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Response {
    match state.db.list_capture_sessions(ProjectId(id)).await {
        Ok(s) => Json(serde_json::json!({"sessions": s})).into_response(),
        Err(e) => error_response(e),
    }
}

async fn revoke_capture_session(
    State(state): State<Arc<AppState>>,
    Path((id, sid)): Path<(i64, i64)>,
) -> Response {
    match state
        .db
        .revoke_capture_session(ProjectId(id), CaptureSessionId(sid))
        .await
    {
        Ok(()) => {
            let _ = state.events.send(AppEvent {
                project_id: id,
                kind: "capture".into(),
                payload: serde_json::json!({ "session_id": sid, "state": "revoked" }),
            });
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => error_response(e),
    }
}

async fn renew_capture_session(
    State(state): State<Arc<AppState>>,
    Path((id, sid)): Path<(i64, i64)>,
) -> Response {
    match state
        .db
        .renew_capture_session(ProjectId(id), CaptureSessionId(sid))
        .await
    {
        Ok(session) => {
            let _ = state.events.send(AppEvent {
                project_id: id,
                kind: "capture".into(),
                payload: serde_json::json!({ "session_id": session.id.get(), "state": "renewed" }),
            });
            Json(session).into_response()
        }
        Err(e) => error_response(e),
    }
}

#[derive(Deserialize)]
struct HistoryQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    q: Option<String>,
    include_noisy_headers: Option<bool>,
}

#[derive(Deserialize)]
struct ClearHistoryQuery {
    before: String,
}

async fn clear_history(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(query): Query<ClearHistoryQuery>,
) -> Response {
    match state
        .db
        .clear_history_before(ProjectId(id), query.before)
        .await
    {
        Ok(result) => Json(result).into_response(),
        Err(error) => error_response(error),
    }
}

async fn history(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    let limit = q.limit.unwrap_or(50);
    let (before_started, before_id) = match q.cursor.as_deref().and_then(|c| {
        let (s, i) = c.rsplit_once(':')?;
        Some((s.to_string(), i.parse::<i64>().ok()?))
    }) {
        Some((s, i)) => (Some(s), Some(i)),
        None => (None, None),
    };

    let filter = match q.q.as_deref() {
        Some(text) if !text.trim().is_empty() => match parse_text_query(text).and_then(|node| {
            crate::history::validate_filter(&node)?;
            Ok(node)
        }) {
            Ok(filter) => Some(filter),
            Err(error) => return error_response(error),
        },
        _ => None,
    };

    // `request:~text` may decode and scan every candidate request body. An
    // exact total would execute that same expensive filter a second time.
    let total_exact = filter
        .as_ref()
        .is_none_or(|filter| !crate::history::uses_request_body_search(filter));
    let count_filter = total_exact.then(|| filter.clone()).flatten();
    match state
        .db
        .list_history_filtered(ProjectId(id), filter, limit, before_started, before_id)
        .await
    {
        Ok((items, next)) => {
            let total = if total_exact {
                match state
                    .db
                    .count_history_filtered(ProjectId(id), count_filter)
                    .await
                {
                    Ok(total) => Some(total),
                    Err(error) => return error_response(error),
                }
            } else {
                None
            };
            let cursor = next.map(|(s, i)| format!("{s}:{i}"));
            Json(serde_json::json!({
                "items": items,
                "next_cursor": cursor,
                "total": total,
                "total_exact": total_exact
            }))
            .into_response()
        }
        Err(e) => error_response(e),
    }
}

#[derive(Deserialize)]
struct SitemapQuery {
    host: Option<String>,
}

async fn sitemap(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(query): Query<SitemapQuery>,
) -> Response {
    match state.db.list_sitemap(ProjectId(id), query.host).await {
        Ok(hosts) => Json(serde_json::json!({ "hosts": hosts })).into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct GetWordsQuery {
    domain: Option<String>,
    include_js: Option<bool>,
    limit: Option<usize>,
}

async fn get_words(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(query): Query<GetWordsQuery>,
) -> Response {
    match crate::get_words::get_words(
        &state.db,
        ProjectId(id),
        crate::get_words::GetWordsOptions {
            domain: query.domain,
            include_js: query.include_js.unwrap_or(true),
            limit: query
                .limit
                .unwrap_or(crate::get_words::DEFAULT_WORD_LIMIT)
                .clamp(1, crate::get_words::MAX_WORD_LIMIT),
        },
    )
    .await
    {
        Ok(result) => Json(result).into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct CreateFindingBody {
    exchange_id: i64,
    title: String,
    description: String,
}

async fn list_findings(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.db.list_findings(ProjectId(id)).await {
        Ok(findings) => Json(serde_json::json!({ "findings": findings })).into_response(),
        Err(error) => error_response(error),
    }
}

async fn create_finding(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<CreateFindingBody>,
) -> Response {
    match state
        .db
        .create_finding(
            ProjectId(id),
            ExchangeId(body.exchange_id),
            body.title,
            body.description,
        )
        .await
    {
        Ok(finding) => {
            let _ = state.events.send(AppEvent {
                project_id: id,
                kind: "finding".into(),
                payload: serde_json::json!({ "finding_id": finding.id.get(), "action": "added" }),
            });
            Json(finding).into_response()
        }
        Err(error) => error_response(error),
    }
}

async fn delete_finding(
    State(state): State<Arc<AppState>>,
    Path((id, finding_id)): Path<(i64, i64)>,
) -> Response {
    match state
        .db
        .delete_finding(ProjectId(id), FindingId(finding_id))
        .await
    {
        Ok(()) => {
            let _ = state.events.send(AppEvent {
                project_id: id,
                kind: "finding".into(),
                payload: serde_json::json!({ "finding_id": finding_id, "action": "removed" }),
            });
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct CompareExchangesQuery {
    left: i64,
    right: i64,
    #[serde(default)]
    include_noisy_headers: bool,
}

async fn compare_exchanges(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(query): Query<CompareExchangesQuery>,
) -> Response {
    match crate::compare::compare_saved_exchanges(
        &state.db,
        ProjectId(id),
        ExchangeId(query.left),
        ExchangeId(query.right),
        crate::compare::CompareOptions {
            include_noisy_headers: query.include_noisy_headers,
        },
    )
    .await
    {
        Ok(comparison) => Json(comparison).into_response(),
        Err(error) => error_response(error),
    }
}

async fn get_exchange(
    State(state): State<Arc<AppState>>,
    Path((id, eid)): Path<(i64, i64)>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    let opts = PresentationOptions {
        include_noisy_headers: q.include_noisy_headers.unwrap_or(false),
        ..Default::default()
    };
    match state
        .db
        .get_exchange_detail(ProjectId(id), ExchangeId(eid), opts)
        .await
    {
        Ok(detail) => {
            let annotation = match state
                .db
                .get_annotation(ProjectId(id), ExchangeId(eid))
                .await
            {
                Ok(annotation) => annotation,
                Err(error) => return error_response(error),
            };
            let applied_rules = match state
                .db
                .list_exchange_request_rules(ProjectId(id), ExchangeId(eid))
                .await
            {
                Ok(rules) => rules,
                Err(error) => return error_response(error),
            };
            let mut value = match serde_json::to_value(detail) {
                Ok(value) => value,
                Err(error) => {
                    return error_response(DomainError::new(
                        ErrorCode::Internal,
                        error.to_string(),
                    ));
                }
            };
            if let Some(object) = value.as_object_mut() {
                object.insert("annotation".into(), serde_json::json!(annotation));
                object.insert(
                    "applied_request_rules".into(),
                    serde_json::json!(applied_rules),
                );
            }
            Json(value).into_response()
        }
        Err(e) => error_response(e),
    }
}

async fn analyze_exchange(
    State(state): State<Arc<AppState>>,
    Path((id, eid)): Path<(i64, i64)>,
) -> Response {
    match crate::page_analyzer::analyze_exchange(&state.db, ProjectId(id), ExchangeId(eid)).await {
        Ok(result) => Json(result).into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct CopyAsQuery {
    format: crate::copy_as::CopyAsFormat,
    #[serde(default = "copy_as_includes_secrets_by_default")]
    include_secrets: bool,
}

fn copy_as_includes_secrets_by_default() -> bool {
    true
}

async fn copy_as(
    State(state): State<Arc<AppState>>,
    Path((id, eid)): Path<(i64, i64)>,
    Query(query): Query<CopyAsQuery>,
) -> Response {
    let project_id = ProjectId(id);
    let exchange_id = ExchangeId(eid);
    match crate::copy_as::copy_exchange_as(
        &state.db,
        project_id,
        exchange_id,
        query.format,
        query.include_secrets,
    )
    .await
    {
        Ok(result) => {
            if query.include_secrets {
                let _ = state
                    .db
                    .audit(
                        Some(project_id),
                        "copy_as_secret_reveal",
                        Some("api"),
                        Some("exchange"),
                        Some(&eid.to_string()),
                        serde_json::json!({ "format": query.format }),
                    )
                    .await;
            }
            Json(result).into_response()
        }
        Err(error) => error_response(error),
    }
}

async fn get_annotation(
    State(state): State<Arc<AppState>>,
    Path((id, eid)): Path<(i64, i64)>,
) -> Response {
    match state
        .db
        .get_annotation(ProjectId(id), ExchangeId(eid))
        .await
    {
        Ok(annotation) => Json(serde_json::json!({ "annotation": annotation })).into_response(),
        Err(error) => error_response(error),
    }
}

async fn upsert_annotation(
    State(state): State<Arc<AppState>>,
    Path((id, eid)): Path<(i64, i64)>,
    Json(update): Json<AnnotationUpdate>,
) -> Response {
    match state
        .db
        .upsert_annotation(ProjectId(id), ExchangeId(eid), update)
        .await
    {
        Ok(annotation) => {
            let _ = state.events.send(AppEvent {
                project_id: id,
                kind: "annotation".into(),
                payload: serde_json::json!({ "exchange_id": eid }),
            });
            Json(annotation).into_response()
        }
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct BodyQuery {
    side: Option<String>,
    offset: Option<usize>,
    max_bytes: Option<usize>,
    raw: Option<bool>,
}

async fn get_body(
    State(state): State<Arc<AppState>>,
    Path((id, eid)): Path<(i64, i64)>,
    Query(q): Query<BodyQuery>,
) -> Response {
    let side = match q.side.as_deref().unwrap_or("response") {
        "request" => MessageSide::Request,
        _ => MessageSide::Response,
    };
    let offset = q.offset.unwrap_or(0);
    let max_bytes = q.max_bytes.unwrap_or(64 * 1024).min(1024 * 1024);
    match state
        .db
        .load_raw_body(ProjectId(id), ExchangeId(eid), side)
        .await
    {
        Ok(Some(mut body)) => {
            let raw_total = body.len();
            let mut content_encoding = None;
            let mut decoded = false;
            if side == MessageSide::Request {
                if let Ok(detail) = state
                    .db
                    .get_exchange_detail(
                        ProjectId(id),
                        ExchangeId(eid),
                        PresentationOptions::default(),
                    )
                    .await
                {
                    if detail.protocol == "HTTP/1.1 raw" {
                        body = crate::reply::redact_raw_request_headers(&body);
                    }
                }
            } else if !q.raw.unwrap_or(false) {
                if let Ok(detail) = state
                    .db
                    .get_exchange_detail(
                        ProjectId(id),
                        ExchangeId(eid),
                        PresentationOptions::default(),
                    )
                    .await
                {
                    if detail.protocol == "HTTP/1.1 raw" {
                        body = crate::reply::presented_raw_response_body(&body);
                    }
                }
                let headers = match state
                    .db
                    .load_raw_headers(ProjectId(id), ExchangeId(eid), MessageSide::Response)
                    .await
                {
                    Ok(headers) => headers,
                    Err(error) => return error_response(error),
                };
                let encodings = headers
                    .iter()
                    .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
                    .map(|header| String::from_utf8_lossy(&header.value).trim().to_string())
                    .filter(|encoding| {
                        !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity")
                    })
                    .collect::<Vec<_>>();
                if !encodings.is_empty() {
                    let encoding = encodings.join(", ");
                    body = match crate::codec::decode_content_encodings(
                        &body,
                        &encoding,
                        crate::codec::MAX_DECODED_BODY_OUTPUT,
                    ) {
                        Ok(body) => body,
                        Err(error) => return error_response(error),
                    };
                    content_encoding = Some(encoding);
                    decoded = true;
                }
            }
            let total = body.len();
            let end = (offset + max_bytes).min(total);
            let slice = if offset >= total {
                &body[..0]
            } else {
                &body[offset..end]
            };
            let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, slice);
            Json(serde_json::json!({
                "total_length": total,
                "offset": offset,
                "length": slice.len(),
                "truncated": end < total,
                "sha256": crate::storage::sha256_hex(&body),
                "encoding": "base64",
                "data": b64,
                "untrusted": true,
                "decoded": decoded,
                "content_encoding": content_encoding,
                "raw_total_length": raw_total,
            }))
            .into_response()
        }
        Ok(None) => Json(serde_json::json!({
            "total_length": 0, "offset": 0, "length": 0, "truncated": false, "data": null
        }))
        .into_response(),
        Err(e) => error_response(e),
    }
}

async fn list_reply_tabs(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.db.list_reply_tabs(ProjectId(id)).await {
        Ok(t) => Json(serde_json::json!({"tabs": t})).into_response(),
        Err(e) => error_response(e),
    }
}

#[derive(Deserialize)]
struct UpsertTab {
    id: Option<i64>,
    name: String,
    base_exchange_id: Option<i64>,
    protocol: Option<String>,
    draft: ReplyDraft,
    revision: Option<i64>,
}

async fn upsert_reply_tab(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<UpsertTab>,
) -> Response {
    let protocol = match body.protocol.as_deref() {
        Some("h1") => ProtocolPreference::H1,
        Some("h2") => ProtocolPreference::H2,
        _ => ProtocolPreference::Auto,
    };
    match state
        .db
        .upsert_reply_tab(
            ProjectId(id),
            body.id.map(ReplyTabId),
            body.name,
            body.base_exchange_id.map(ExchangeId),
            protocol,
            body.draft,
            body.revision,
        )
        .await
    {
        Ok(t) => Json(t).into_response(),
        Err(e) => error_response(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplySendBody {
    tab_id: Option<i64>,
    base_exchange_id: Option<i64>,
    draft: Option<ReplyDraft>,
    protocol: Option<String>,
    upstream_proxy: Option<String>,
}

async fn reply_send(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<ReplySendBody>,
) -> Response {
    let protocol = match body.protocol.as_deref() {
        Some("h1") => ProtocolPreference::H1,
        Some("h2") => ProtocolPreference::H2,
        _ => ProtocolPreference::Auto,
    };
    let draft = if let Some(d) = body.draft {
        d
    } else if let Some(tid) = body.tab_id {
        match state.db.get_reply_tab(ProjectId(id), ReplyTabId(tid)).await {
            Ok(t) => t.draft,
            Err(e) => return error_response(e),
        }
    } else {
        ReplyDraft::default()
    };
    let base = if body.base_exchange_id.is_some() {
        body.base_exchange_id.map(ExchangeId)
    } else if let Some(tid) = body.tab_id {
        state
            .db
            .get_reply_tab(ProjectId(id), ReplyTabId(tid))
            .await
            .ok()
            .and_then(|t| t.base_exchange_id)
    } else {
        None
    };
    match state
        .reply
        .send_with_proxy(
            ProjectId(id),
            body.tab_id.map(ReplyTabId),
            base,
            &draft,
            protocol,
            0,
            body.upstream_proxy.as_deref(),
        )
        .await
    {
        Ok(result) => {
            if let Some(exchange_id) = result.exchange_id {
                let _ = state.events.send(AppEvent {
                    project_id: id,
                    kind: "exchange".into(),
                    payload: serde_json::json!({ "exchange_id": exchange_id.get(), "source": "reply" }),
                });
            }
            Json(result).into_response()
        }
        Err(e) => error_response(e),
    }
}

#[derive(Deserialize)]
struct RawReplySendBody {
    target_url: String,
    request: String,
    #[serde(default)]
    encoding: Option<String>,
    tab_id: Option<i64>,
    #[serde(default)]
    use_project_cookies: bool,
    #[serde(flatten)]
    options: crate::reply::RawHttp1Options,
}

async fn reply_send_raw(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<RawReplySendBody>,
) -> Response {
    let request_bytes = match body.encoding.as_deref().unwrap_or("utf8") {
        "utf8" => body.request.into_bytes(),
        "base64" => match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            body.request.as_bytes(),
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                return error_response(DomainError::invalid(format!(
                    "invalid base64 request: {error}"
                )))
            }
        },
        _ => return error_response(DomainError::invalid("encoding must be utf8 or base64")),
    };
    match state
        .reply
        .send_raw_http1(
            ProjectId(id),
            body.tab_id.map(ReplyTabId),
            &body.target_url,
            request_bytes,
            body.use_project_cookies,
            body.options,
        )
        .await
    {
        Ok(result) => {
            if let Some(exchange_id) = result.exchange_id {
                let _ = state.events.send(AppEvent {
                    project_id: id,
                    kind: "exchange".into(),
                    payload: serde_json::json!({
                        "exchange_id": exchange_id.get(),
                        "source": "reply",
                        "mode": "raw_http1"
                    }),
                });
            }
            Json(result).into_response()
        }
        Err(error) => error_response(error),
    }
}

async fn list_fuzz_jobs(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.db.list_fuzz_jobs(ProjectId(id)).await {
        Ok(j) => Json(serde_json::json!({"jobs": j})).into_response(),
        Err(e) => error_response(e),
    }
}

#[derive(Deserialize)]
struct StartFuzzBody {
    template: FuzzTemplate,
    confirm: Option<bool>,
}

async fn start_fuzz(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<StartFuzzBody>,
) -> Response {
    match state
        .fuzzer
        .start(ProjectId(id), body.template, body.confirm.unwrap_or(false))
        .await
    {
        Ok(job) => {
            let _ = state.events.send(AppEvent {
                project_id: id,
                kind: "fuzz".into(),
                payload: serde_json::json!({ "job_id": job.id.get(), "state": job.state }),
            });
            (StatusCode::CREATED, Json(job)).into_response()
        }
        Err(e) => error_response(e),
    }
}

async fn cancel_fuzz(
    State(state): State<Arc<AppState>>,
    Path((id, jid)): Path<(i64, i64)>,
) -> Response {
    match state
        .fuzzer
        .cancel_for_project(ProjectId(id), FuzzJobId(jid))
        .await
    {
        Ok(()) => {
            let _ = state.events.send(AppEvent {
                project_id: id,
                kind: "fuzz".into(),
                payload: serde_json::json!({ "job_id": jid, "state": "cancelling" }),
            });
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => error_response(e),
    }
}

#[derive(Deserialize)]
struct FuzzCasesQuery {
    limit: Option<u32>,
    before_case_index: Option<u64>,
    group_id: Option<String>,
}

async fn list_fuzz_cases(
    State(state): State<Arc<AppState>>,
    Path((id, jid)): Path<(i64, i64)>,
    Query(query): Query<FuzzCasesQuery>,
) -> Response {
    let result = if let Some(group_id) = query.group_id {
        state
            .fuzzer
            .list_group_cases(
                ProjectId(id),
                FuzzJobId(jid),
                group_id,
                query.limit.unwrap_or(100).min(500),
                query.before_case_index,
            )
            .await
    } else {
        state
            .fuzzer
            .list_cases(
                ProjectId(id),
                FuzzJobId(jid),
                query.limit.unwrap_or(100).min(500),
                query.before_case_index,
            )
            .await
    };
    match result {
        Ok((cases, next)) => Json(serde_json::json!({
            "cases": cases,
            "next_before_case_index": next,
        }))
        .into_response(),
        Err(error) => error_response(error),
    }
}

async fn list_fuzz_groups(
    State(state): State<Arc<AppState>>,
    Path((id, jid)): Path<(i64, i64)>,
) -> Response {
    match state
        .fuzzer
        .list_response_groups(ProjectId(id), FuzzJobId(jid))
        .await
    {
        Ok(groups) => Json(serde_json::json!({ "groups": groups })).into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct FuzzDiffQuery {
    baseline_case_id: Option<i64>,
    #[serde(default)]
    include_text: bool,
}

async fn fuzz_case_diff(
    State(state): State<Arc<AppState>>,
    Path((id, jid, case_id)): Path<(i64, i64, i64)>,
    Query(query): Query<FuzzDiffQuery>,
) -> Response {
    match state
        .fuzzer
        .response_diff(
            ProjectId(id),
            FuzzJobId(jid),
            case_id,
            query.baseline_case_id,
            query.include_text,
        )
        .await
    {
        Ok(diff) => Json(diff).into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct WebSocketListQuery {
    limit: Option<u32>,
}

async fn list_websocket_connections(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(query): Query<WebSocketListQuery>,
) -> Response {
    match state
        .db
        .list_websocket_connections(ProjectId(id), query.limit.unwrap_or(100))
        .await
    {
        Ok(connections) => Json(serde_json::json!({ "connections": connections })).into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct WebSocketMessagesQuery {
    after_id: Option<i64>,
    limit: Option<u32>,
}

async fn list_websocket_messages(
    State(state): State<Arc<AppState>>,
    Path((id, wid)): Path<(i64, i64)>,
    Query(query): Query<WebSocketMessagesQuery>,
) -> Response {
    match state
        .db
        .list_websocket_messages(
            ProjectId(id),
            wid,
            query.after_id,
            query.limit.unwrap_or(250),
        )
        .await
    {
        Ok(messages) => Json(serde_json::json!({ "messages": messages })).into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct SendWebSocketMessage {
    direction: String,
    #[serde(default = "default_websocket_encoding")]
    encoding: String,
    payload: String,
}

fn default_websocket_encoding() -> String {
    "text".into()
}

async fn send_websocket_message(
    State(state): State<Arc<AppState>>,
    Path((id, wid)): Path<(i64, i64)>,
    Json(body): Json<SendWebSocketMessage>,
) -> Response {
    let to_server = match body.direction.as_str() {
        "to_server" => true,
        "to_client" => false,
        _ => {
            return error_response(DomainError::invalid(
                "direction must be to_server or to_client",
            ))
        }
    };
    match state
        .websocket
        .send(ProjectId(id), wid, to_server, &body.encoding, &body.payload)
        .await
    {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(error) => error_response(error),
    }
}

async fn browser_status(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.browser.active_sessions(ProjectId(id)).await {
        Ok(sessions) => Json(serde_json::json!({
            "runtime": state.browser.status(),
            "sessions": sessions,
        }))
        .into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct StartBrowser {
    url: String,
    engine_policy: Option<String>,
}

async fn start_browser(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<StartBrowser>,
) -> Response {
    if body
        .engine_policy
        .as_deref()
        .is_some_and(|policy| !matches!(policy, "auto" | "chromium"))
    {
        return error_response(DomainError::invalid(
            "engine_policy is obsolete; omit it to use Chromium",
        ));
    }
    match state.browser.start(ProjectId(id), body.url).await {
        Ok(session) => {
            let _ = state.events.send(AppEvent {
                project_id: id,
                kind: "browser".into(),
                payload: serde_json::json!({ "session_id": session.id.get(), "state": session.state }),
            });
            (StatusCode::CREATED, Json(session)).into_response()
        }
        Err(e) => error_response(e),
    }
}

async fn browser_action(
    State(state): State<Arc<AppState>>,
    Path((id, bid)): Path<(i64, i64)>,
    Json(action): Json<crate::browser::BrowserAction>,
) -> Response {
    match state
        .browser
        .action(ProjectId(id), BrowserSessionId(bid), action)
        .await
    {
        Ok(result) => {
            let _ = state.events.send(AppEvent {
                project_id: id,
                kind: "browser".into(),
                payload: serde_json::json!({ "session_id": bid, "action": "completed", "ok": result.ok }),
            });
            Json(result).into_response()
        }
        Err(e) => error_response(e),
    }
}

async fn stop_browser(
    State(state): State<Arc<AppState>>,
    Path((id, bid)): Path<(i64, i64)>,
) -> Response {
    match state
        .browser
        .stop(ProjectId(id), BrowserSessionId(bid))
        .await
    {
        Ok(()) => {
            let _ = state.events.send(AppEvent {
                project_id: id,
                kind: "browser".into(),
                payload: serde_json::json!({ "session_id": bid, "state": "stopped" }),
            });
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => error_response(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserCdpRequest {
    op: String,
    session_id: Option<i64>,
}

async fn browser_cdp(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<BrowserCdpRequest>,
) -> Response {
    let project_id = ProjectId(id);
    let result = match body.op.as_str() {
        "status" => state.browser.cdp_status(project_id).await,
        "enable" | "disable" => {
            let session_id = match body.session_id {
                Some(session_id) => BrowserSessionId(session_id),
                None => {
                    return error_response(DomainError::invalid(
                        "session_id is required for CDP enable and disable",
                    ))
                }
            };
            if body.op == "enable" {
                state.browser.enable_cdp(project_id, session_id).await
            } else {
                state.browser.disable_cdp(project_id, session_id).await
            }
        }
        _ => {
            return error_response(DomainError::invalid(
                "CDP op must be enable, status, or disable",
            ))
        }
    };
    match result {
        Ok(status) => Json(status).into_response(),
        Err(error) => error_response(error),
    }
}

async fn events(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events.subscribe();
    let stream = futures::stream::unfold(Some(rx), move |state_rx| {
        let id = id;
        async move {
            let mut rx = state_rx?;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(15)) => {
                        return Some((Ok(Event::default().event("ping").data("{}")), Some(rx)));
                    }
                    msg = rx.recv() => {
                        match msg {
                            Ok(ev) if ev.project_id == id => {
                                if let Ok(data) = serde_json::to_string(&ev) {
                                    return Some((
                                        Ok(Event::default().event(ev.kind).data(data)),
                                        Some(rx),
                                    ));
                                }
                            }
                            Ok(_) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                return Some((
                                    Ok(Event::default()
                                        .event("lagged")
                                        .data(r#"{"action":"refetch"}"#)),
                                    Some(rx),
                                ));
                            }
                            Err(_) => return None,
                        }
                    }
                }
            }
        }
    });
    let ready = futures::stream::once(async move {
        Ok::<_, Infallible>(
            Event::default()
                .event("ready")
                .data(format!(r#"{{"project_id":{id}}}"#)),
        )
    });
    Sse::new(ready.chain(stream)).keep_alive(KeepAlive::default())
}

async fn doctor(State(state): State<Arc<AppState>>) -> Response {
    let browser = state.browser.status();
    let schema = state.db.schema_version().await.ok();
    let daemon_log = state.config.daemon_log_path();
    let startup_log = state.config.daemon_startup_log_path();
    Json(serde_json::json!({
        "data_dir": state.config.data_dir,
        "db": state.config.db_path(),
        "schema_version": schema,
        "api_listen": state.config.api_listen.to_string(),
        "proxy_listen": state.config.proxy_listen.to_string(),
        "idle_timeout_seconds": state.config.idle_timeout_seconds,
        "ca_cert": state.config.ca_cert_path().exists(),
        "browser": browser,
        "daemon_log": daemon_log,
        "daemon_log_tail": read_file_tail(&daemon_log, 4096),
        "last_startup_output": read_file_tail(&startup_log, 4096),
    }))
    .into_response()
}

fn read_file_tail(path: &std::path::Path, max_bytes: usize) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let start = bytes.len().saturating_sub(max_bytes);
    Some(String::from_utf8_lossy(&bytes[start..]).into_owned())
}

#[derive(Deserialize)]
struct CodecBody {
    steps: Vec<crate::codec::Transform>,
    input_base64: Option<String>,
    input_text: Option<String>,
}

async fn codec_transform(Json(body): Json<CodecBody>) -> Response {
    let input = if let Some(b64) = body.input_base64 {
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64) {
            Ok(v) => v,
            Err(e) => return error_response(DomainError::invalid(format!("base64: {e}"))),
        }
    } else {
        body.input_text.unwrap_or_default().into_bytes()
    };
    match crate::codec::apply_pipeline(&body.steps, &input) {
        Ok(out) => Json(serde_json::json!({
            "output_base64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &out),
            "output_text": String::from_utf8(out.clone()).ok(),
            "length": out.len(),
        }))
        .into_response(),
        Err(e) => error_response(e),
    }
}

async fn ui_index() -> impl IntoResponse {
    Html(include_str!("../../web/index.html"))
}

fn error_response(e: DomainError) -> Response {
    let env = ErrorEnvelope::from(&e);
    let status = status_for_error(&e);
    (status, Json(env)).into_response()
}

fn status_for_error(e: &DomainError) -> StatusCode {
    match e.code() {
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::InvalidArgument | ErrorCode::PlaceholderInvalid | ErrorCode::ConfigInvalid => {
            StatusCode::BAD_REQUEST
        }
        ErrorCode::Unauthorized | ErrorCode::ProxyAuthRequired => StatusCode::UNAUTHORIZED,
        ErrorCode::Forbidden | ErrorCode::ScopeDenied => StatusCode::FORBIDDEN,
        ErrorCode::Conflict | ErrorCode::RevisionConflict => StatusCode::CONFLICT,
        ErrorCode::RateLimited | ErrorCode::ConcurrencyLimited => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::DiskQuotaExceeded => StatusCode::INSUFFICIENT_STORAGE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// silence unused import warning for AppEvent in some builds
#[allow(dead_code)]
fn _event_type_check(e: AppEvent) -> AppEvent {
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_supplied_config_values_are_bad_requests() {
        let error = DomainError::new(ErrorCode::ConfigInvalid, "invalid upstream proxy URL");
        assert_eq!(status_for_error(&error), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn disk_quota_errors_use_insufficient_storage() {
        let error = DomainError::new(ErrorCode::DiskQuotaExceeded, "project quota exceeded");
        assert_eq!(status_for_error(&error), StatusCode::INSUFFICIENT_STORAGE);
    }
}
