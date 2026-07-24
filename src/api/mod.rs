//! Versioned HTTP API, SSE, embedded UI, and private UDS.

use crate::app::{AppEvent, AppState};
use crate::domain::*;
use crate::fuzzer::FuzzTemplate;
use crate::history::parse_text_query;
use crate::policy::PresentationOptions;
use crate::storage::CreateCaptureSession;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::stream::Stream;
use futures::StreamExt;
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;


pub async fn serve_api(state: Arc<AppState>, cancel: CancellationToken) -> DomainResult<()> {
    let app = router(state.clone());
    let addr = state.config.api_listen;
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        DomainError::new(ErrorCode::Unavailable, format!("api bind {addr}: {e}"))
    })?;
    tracing::info!(%addr, "api/ui listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await
        .map_err(|e| DomainError::new(ErrorCode::Unavailable, e.to_string()))
}

pub async fn serve_uds(state: Arc<AppState>, cancel: CancellationToken) -> DomainResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = state.config.socket_path();
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        let listener = tokio::net::UnixListener::bind(&path).map_err(|e| {
            DomainError::new(ErrorCode::Unavailable, format!("uds bind: {e}"))
        })?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        tracing::info!(path=%path.display(), "private socket listening");
        let app = router(state);
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
    }
    Ok(())
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/version", get(version))
        .route("/api/v1/projects", get(list_projects).post(create_project))
        .route("/api/v1/projects/{id}", get(get_project))
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
        .route("/api/v1/projects/{id}/history", get(history))
        .route("/api/v1/projects/{id}/exchanges/{eid}", get(get_exchange))
        .route(
            "/api/v1/projects/{id}/exchanges/{eid}/body",
            get(get_body),
        )
        .route(
            "/api/v1/projects/{id}/reply-tabs",
            get(list_reply_tabs).post(upsert_reply_tab),
        )
        .route("/api/v1/projects/{id}/reply-send", post(reply_send))
        .route(
            "/api/v1/projects/{id}/fuzz-jobs",
            get(list_fuzz_jobs).post(start_fuzz),
        )
        .route(
            "/api/v1/projects/{id}/fuzz-jobs/{jid}/cancel",
            post(cancel_fuzz),
        )
        .route(
            "/api/v1/projects/{id}/browser-sessions",
            get(browser_status).post(start_browser),
        )
        .route(
            "/api/v1/projects/{id}/browser-sessions/{bid}/action",
            post(browser_action),
        )
        .route(
            "/api/v1/projects/{id}/browser-sessions/{bid}/stop",
            post(stop_browser),
        )
        .route("/api/v1/projects/{id}/events", get(events))
        .route("/api/v1/doctor", get(doctor))
        .route("/api/v1/codec", post(codec_transform))
        .route("/", get(ui_index))
        .with_state(state)
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
        Ok(p) => (StatusCode::CREATED, Json(p)).into_response(),
        Err(e) => error_response(e),
    }
}

async fn get_project(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.db.get_project(ProjectId(id)).await {
        Ok(p) => Json(p).into_response(),
        Err(e) => error_response(e),
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
        Ok(s) => (StatusCode::CREATED, Json(s)).into_response(),
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
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
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
        Ok(s) => Json(s).into_response(),
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

    if let Some(text) = &q.q {
        if let Err(e) = parse_text_query(text).and_then(|n| {
            crate::history::validate_filter(&n)?;
            Ok(n)
        }) {
            return error_response(e);
        }
    }

    match state
        .db
        .list_history(ProjectId(id), limit, before_started, before_id)
        .await
    {
        Ok((items, next)) => {
            let cursor = next.map(|(s, i)| format!("{s}:{i}"));
            Json(serde_json::json!({"items": items, "next_cursor": cursor})).into_response()
        }
        Err(e) => error_response(e),
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
        Ok(d) => Json(d).into_response(),
        Err(e) => error_response(e),
    }
}

#[derive(Deserialize)]
struct BodyQuery {
    side: Option<String>,
    offset: Option<usize>,
    max_bytes: Option<usize>,
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
        Ok(Some(body)) => {
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
struct ReplySendBody {
    tab_id: Option<i64>,
    base_exchange_id: Option<i64>,
    draft: Option<ReplyDraft>,
    protocol: Option<String>,
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
        .send(
            ProjectId(id),
            body.tab_id.map(ReplyTabId),
            base,
            &draft,
            protocol,
            0,
        )
        .await
    {
        Ok((eid, diff)) => Json(serde_json::json!({
            "exchange_id": eid.get(),
            "diff": diff
        }))
        .into_response(),
        Err(e) => error_response(e),
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
        Ok(j) => (StatusCode::CREATED, Json(j)).into_response(),
        Err(e) => error_response(e),
    }
}

async fn cancel_fuzz(
    State(state): State<Arc<AppState>>,
    Path((_id, jid)): Path<(i64, i64)>,
) -> Response {
    match state.fuzzer.cancel(FuzzJobId(jid)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => error_response(e),
    }
}

async fn browser_status(State(state): State<Arc<AppState>>) -> Response {
    Json(state.browser.status()).into_response()
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
    let policy = match body.engine_policy.as_deref() {
        Some("chromium") => EnginePolicy::Chromium,
        _ => EnginePolicy::Auto,
    };
    match state.browser.start(ProjectId(id), body.url, policy).await {
        Ok(s) => (StatusCode::CREATED, Json(s)).into_response(),
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
        Ok(r) => Json(r).into_response(),
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
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => error_response(e),
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
    Json(serde_json::json!({
        "data_dir": state.config.data_dir,
        "db": state.config.db_path(),
        "schema_version": schema,
        "api_listen": state.config.api_listen.to_string(),
        "proxy_listen": state.config.proxy_listen.to_string(),
        "ca_cert": state.config.ca_cert_path().exists(),
        "browser": browser,
    }))
    .into_response()
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
    let status = match e.code() {
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::InvalidArgument | ErrorCode::PlaceholderInvalid => StatusCode::BAD_REQUEST,
        ErrorCode::Unauthorized | ErrorCode::ProxyAuthRequired => StatusCode::UNAUTHORIZED,
        ErrorCode::Forbidden | ErrorCode::ScopeDenied => StatusCode::FORBIDDEN,
        ErrorCode::Conflict | ErrorCode::RevisionConflict => StatusCode::CONFLICT,
        ErrorCode::RateLimited | ErrorCode::ConcurrencyLimited => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(env)).into_response()
}

// silence unused import warning for AppEvent in some builds
#[allow(dead_code)]
fn _event_type_check(e: AppEvent) -> AppEvent {
    e
}
