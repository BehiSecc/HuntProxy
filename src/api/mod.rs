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
use axum::routing::{delete, get, patch, post, put};
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
    let addr = listener
        .local_addr()
        .map_err(|e| DomainError::new(ErrorCode::Unavailable, e.to_string()))?;
    let app = tcp_router(state.clone(), addr);
    tracing::info!(%addr, "api/ui listening");
    // Streamed responses (events, downloads) are several small writes; see
    // the proxy listener for why Nagle's algorithm is turned off.
    let listener = axum::serve::ListenerExt::tap_io(listener, |stream| {
        if let Err(error) = stream.set_nodelay(true) {
            tracing::debug!(%error, "could not disable Nagle on an API connection");
        }
    });
    // The guard needs the peer address to tell local clients from remote ones.
    let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
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
        .route(
            "/api/v1/projects/{id}/upstream-proxy",
            put(set_project_upstream_proxy).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
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
            "/api/v1/projects/{id}/limits",
            post(update_project_request_budget).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
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
            "/api/v1/projects/{id}/browser-profiles",
            get(list_browser_profiles)
                .post(create_browser_profile)
                .layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
        )
        .route(
            "/api/v1/projects/{id}/browser-profiles/{profile}",
            delete(delete_browser_profile),
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
            "/api/v1/projects/{id}/extension-plans/preview",
            post(preview_extension).layer(DefaultBodyLimit::max(payload_body_limit)),
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
        .route(
            "/api/v1/projects/{id}/extension-jobs/{job_id}/resume-analysis",
            post(resume_extension_analysis).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)),
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

/// The TCP listener serves the UI and API. A request is accepted when it is
/// local or authenticated:
///
/// - Local: the peer is loopback and the request passes the browser guard. Any
///   web page a browser loads can send requests to a loopback port, and DNS
///   rebinding can make those requests look same-origin, so the guard requires
///   a loopback Host and rejects a foreign Origin and `Sec-Fetch-Site:
///   cross-site`.
/// - Authenticated: the request carries `remote_auth_token` as a Bearer token,
///   or the UI session cookie that the sign-in link (`/?token=…`) sets. The
///   Host check is skipped, so a LAN address or a DNS name works. A browser
///   sends the cookie on its own, so a cookie request must also be same-origin.
///
/// Every other non-loopback peer gets 401. The private Unix socket does not
/// need this guard.
pub fn tcp_router(state: Arc<AppState>, listen: std::net::SocketAddr) -> Router {
    let access = TcpAccess::new(state.config.auth_token(), listen.port());
    router(state).layer(axum::middleware::from_fn_with_state(
        access,
        guard_tcp_requests,
    ))
}

/// The UI address printed by `HuntProxy status` and `init`. A non-loopback
/// listener needs authentication, so its address is the sign-in link.
pub fn ui_link(listen: std::net::SocketAddr, token: Option<&str>) -> String {
    if listen.ip().is_loopback() {
        return format!("http://{listen}/");
    }
    let host = if listen.ip().is_unspecified() {
        format!("<this-host>:{}", listen.port())
    } else {
        listen.to_string()
    };
    match token {
        Some(token) => {
            let token: String = url::form_urlencoded::byte_serialize(token.as_bytes()).collect();
            format!("http://{host}/?{SIGN_IN_PARAM}={token}")
        }
        None => format!("http://{host}/"),
    }
}

const SIGN_IN_PARAM: &str = "token";
/// Marks the one automatic retry of the sign-in required page.
const SIGN_IN_RETRY_PARAM: &str = "signin";
const SESSION_MAX_AGE_SECONDS: u32 = 30 * 24 * 60 * 60;

#[derive(Clone)]
struct TcpAccess {
    /// SHA-256 of the token, so comparing a candidate does not leak its length.
    token_digest: Option<[u8; 32]>,
    /// The session cookie value: derived from the token rather than equal to
    /// it, stable across daemon restarts, and invalid once the token changes.
    session: Option<Arc<str>>,
    /// Includes the port, so two instances on one host keep separate cookies.
    cookie_name: Arc<str>,
}

impl TcpAccess {
    fn new(token: Option<&str>, port: u16) -> Self {
        use sha2::{Digest, Sha256};
        Self {
            token_digest: token.map(|token| Sha256::digest(token.as_bytes()).into()),
            session: token.map(|token| {
                hex::encode(Sha256::digest(
                    format!("huntproxy-ui-session-v1:{token}").as_bytes(),
                ))
                .into()
            }),
            cookie_name: format!("huntproxy_session_{port}").into(),
        }
    }

    fn token_matches(&self, candidate: &str) -> bool {
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;
        self.token_digest.is_some_and(|expected| {
            let candidate: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
            bool::from(expected.ct_eq(&candidate))
        })
    }

    fn has_valid_bearer(&self, headers: &http::HeaderMap) -> bool {
        headers
            .get_all(http::header::AUTHORIZATION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| {
                let (scheme, credential) = value.trim().split_once(' ')?;
                scheme
                    .eq_ignore_ascii_case("bearer")
                    .then(|| credential.trim())
            })
            .any(|credential| self.token_matches(credential))
    }

    fn has_valid_session(&self, headers: &http::HeaderMap) -> bool {
        use subtle::ConstantTimeEq;
        let Some(session) = self.session.as_deref() else {
            return false;
        };
        headers
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .any(|(name, value)| {
                name == &*self.cookie_name && bool::from(value.as_bytes().ct_eq(session.as_bytes()))
            })
    }

    fn session_cookie(&self) -> Option<String> {
        let session = self.session.as_deref()?;
        Some(format!(
            "{}={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_MAX_AGE_SECONDS}",
            self.cookie_name
        ))
    }
}

async fn guard_tcp_requests(
    State(access): State<TcpAccess>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // Without connect info the peer is unknown and treated as remote.
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip().to_canonical());
    let headers = request.headers();

    if request.method() == http::Method::GET && request.uri().path() == "/" {
        if let Some(candidate) = query_value(request.uri().query(), SIGN_IN_PARAM) {
            if access.token_matches(&candidate) {
                return sign_in_response(&access, request.uri().query().unwrap_or(""));
            }
            tracing::warn!(?peer, "rejected a ui sign-in link with a wrong token");
            return unauthorized_response(&request);
        }
    }
    if access.has_valid_bearer(headers) {
        return next.run(request).await;
    }
    if access.has_valid_session(headers) {
        if is_same_origin_browser_request(request.method(), headers) {
            return next.run(request).await;
        }
        return forbidden_response(headers);
    }
    if !peer.is_some_and(|ip| ip.is_loopback()) {
        tracing::warn!(?peer, "rejected an unauthenticated api request");
        return unauthorized_response(&request);
    }
    if is_local_browser_request(request.method(), headers) {
        return next.run(request).await;
    }
    forbidden_response(headers)
}

/// Host is `localhost` or a loopback IP, and the request is same-origin with
/// it.
fn is_local_browser_request(method: &http::Method, headers: &http::HeaderMap) -> bool {
    header_str(headers, http::header::HOST).is_some_and(is_loopback_authority)
        && is_same_origin_browser_request(method, headers)
}

/// Origin (if any) is `http://` plus this request's Host, so a page on another
/// port of the same host does not pass. `Sec-Fetch-Site` (if any) is
/// `same-origin` or `none`; `same-site` is accepted only for a top-level GET
/// navigation, so links from other local pages keep working. Clients that send
/// neither header (curl, the CLI) pass.
fn is_same_origin_browser_request(method: &http::Method, headers: &http::HeaderMap) -> bool {
    let origin_ok = match headers.get(http::header::ORIGIN) {
        None => true,
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|origin| origin.strip_prefix("http://"))
            .zip(header_str(headers, http::header::HOST))
            .is_some_and(|(origin, host)| origin.eq_ignore_ascii_case(host)),
    };
    let is = |name: &str, expected: &str| {
        header_str(headers, name).is_some_and(|value| value.eq_ignore_ascii_case(expected))
    };
    let site_ok = match header_str(headers, "sec-fetch-site") {
        None => true,
        Some(site) if site.eq_ignore_ascii_case("same-origin") => true,
        Some(site) if site.eq_ignore_ascii_case("none") => true,
        Some(site) if site.eq_ignore_ascii_case("same-site") => {
            method == http::Method::GET
                && is("sec-fetch-mode", "navigate")
                && is("sec-fetch-dest", "document")
        }
        Some(_) => false,
    };
    origin_ok && site_ok
}

fn header_str(headers: &http::HeaderMap, name: impl http::header::AsHeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// The first value of a query parameter, decoded.
fn query_value(query: Option<&str>, name: &str) -> Option<String> {
    url::form_urlencoded::parse(query?.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Sets the session cookie and redirects to `/` without the token, so it does
/// not stay in the address bar, the history or a Referer.
fn sign_in_response(access: &TcpAccess, query: &str) -> Response {
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            url::form_urlencoded::parse(pair.as_bytes())
                .next()
                .is_some_and(|(key, _)| key != SIGN_IN_PARAM)
        })
        .collect();
    let location = if kept.is_empty() {
        "/".to_string()
    } else {
        format!("/?{}", kept.join("&"))
    };
    let mut response = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(http::header::LOCATION, location)
        .header(http::header::REFERRER_POLICY, "no-referrer")
        .header(http::header::CACHE_CONTROL, "no-store");
    if let Some(cookie) = access.session_cookie() {
        response = response.header(http::header::SET_COOKIE, cookie);
    }
    response
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

const SIGN_IN_REQUIRED_PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HuntProxy sign-in</title>
<style>
:root { color-scheme: light dark; }
body { margin: 0; padding: 18vh 16px; font: 16px/1.5 system-ui, sans-serif; background: #f6f7f9; color: #1d2330; }
main { max-width: 34rem; margin: 0 auto; }
h1 { font-size: 1.25rem; margin: 0 0 .75rem; }
code { padding: .1rem .3rem; border-radius: 4px; background: #e4e7ec; }
@media (prefers-color-scheme: dark) {
  body { background: #14171c; color: #e3e6eb; }
  code { background: #2a2f38; }
}
</style>
</head>
<body>
<main>
<h1>Sign-in link required</h1>
<p>This HuntProxy is reachable from other machines, so its UI needs a sign-in link. On the machine running HuntProxy, run <code>HuntProxy status</code> and open the <code>ui:</code> link it prints.</p>
</main>
</body>
</html>
"#;

fn unauthorized_response(request: &axum::extract::Request) -> Response {
    let wants_html = request
        .headers()
        .get_all(http::header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|accept| accept.contains("text/html"));
    let mut response = if wants_html {
        // A sign-in link opened from a web page reaches `/` through a
        // cross-site redirect, so the browser withholds the Strict session
        // cookie. Navigate once more from this page: that request is
        // same-origin and carries the cookie. The marker prevents a loop.
        let query = request.uri().query();
        let retry = request.method() == http::Method::GET
            && request.uri().path() == "/"
            && query_value(query, SIGN_IN_RETRY_PARAM).is_none()
            && query_value(query, SIGN_IN_PARAM).is_none();
        let page = if retry {
            SIGN_IN_REQUIRED_PAGE.replacen(
                "<title>",
                &format!(
                    "<meta http-equiv=\"refresh\" content=\"0; url=/?{SIGN_IN_RETRY_PARAM}=1\">\n<title>"
                ),
                1,
            )
        } else {
            SIGN_IN_REQUIRED_PAGE.to_string()
        };
        (StatusCode::UNAUTHORIZED, Html(page)).into_response()
    } else {
        error_response(DomainError::new(
            ErrorCode::Unauthorized,
            "send Authorization: Bearer <remote_auth_token>, or open the sign-in link shown by HuntProxy status",
        ))
    };
    let headers = response.headers_mut();
    headers.insert(
        http::header::WWW_AUTHENTICATE,
        http::HeaderValue::from_static("Bearer"),
    );
    headers.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        http::header::REFERRER_POLICY,
        http::HeaderValue::from_static("no-referrer"),
    );
    response
}

fn forbidden_response(headers: &http::HeaderMap) -> Response {
    tracing::warn!(
        host = header_str(headers, http::header::HOST).unwrap_or("-"),
        "rejected api request with a foreign host or origin"
    );
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": {
                "code": "forbidden",
                "message": "requests must use a loopback host or authenticate, and must not come from another site"
            }
        })),
    )
        .into_response()
}

/// Accept `localhost` or a loopback IP. Reject every other name, so a rebound
/// domain cannot pass. Any port is accepted, because a container or SSH tunnel
/// can publish the API on a different local port.
fn is_loopback_authority(authority: &str) -> bool {
    let host = match authority.rsplit_once(':') {
        Some((host, _)) if !host.ends_with(']') && host.contains(':') => authority,
        Some((host, port)) if port.parse::<u16>().is_ok() => host,
        Some(_) => return false,
        None => authority,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.to_canonical().is_loopback())
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
    if let Some(project_id) = project_control_target(request.method(), request.uri().path()) {
        state.browser.touch_project(project_id);
    }
    next.run(request).await
}

/// The project a request acts on, for the browser idle rule. Only changes
/// count: the UI reloads project data, browser status included, whenever the
/// proxy captures traffic, so reads would let an idle page keep its own
/// browser open. Every browser control request is a POST or DELETE.
fn project_control_target(method: &http::Method, path: &str) -> Option<ProjectId> {
    if matches!(
        *method,
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS
    ) {
        return None;
    }
    let rest = path.strip_prefix("/api/v1/projects/")?;
    let id = rest.split('/').next()?;
    id.parse().ok().map(ProjectId)
}

fn private_router(state: Arc<AppState>) -> Router {
    let payload_body_limit = api_payload_body_limit(state.config.max_body_bytes);
    router(state.clone()).merge(
        Router::new()
            .route(
                "/internal/mcp/call",
                post(internal_mcp_call).layer(DefaultBodyLimit::max(payload_body_limit)),
            )
            .route("/internal/mcp/tools", get(internal_mcp_tools))
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

async fn internal_mcp_tools() -> impl IntoResponse {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": crate::INTERNAL_PROTOCOL_VERSION,
        "tools": crate::mcp::tool_defs(),
    }))
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

async fn preview_extension(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<RunExtensionBody>,
) -> Response {
    match state
        .plugins
        .preview(
            ProjectId(id),
            &body.plugin_id,
            &body.action,
            body.base_exchange_id.map(ExchangeId),
            body.input,
        )
        .await
    {
        Ok(preview) => Json(preview).into_response(),
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

#[derive(Debug, Default, Deserialize)]
struct ResumeAnalysisBody {
    js_stage_timeout_ms: Option<u64>,
}

async fn resume_extension_analysis(
    State(state): State<Arc<AppState>>,
    Path((id, job_id)): Path<(i64, String)>,
    Json(body): Json<ResumeAnalysisBody>,
) -> Response {
    let job = match parse_project_job(&state, id, &job_id) {
        Ok(job) => job,
        Err(error) => return error_response(error),
    };
    match state
        .plugins
        .resume_analysis(job.id, body.js_stage_timeout_ms)
        .await
    {
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
    match state.project_detail(ProjectId(id)).await {
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
    match state.browser.delete_project(project_id).await {
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
        let profile = match crate::cookies::validate_named_cookie_profile(&body.target_url, cookie)
        {
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

async fn update_project_request_budget(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(update): Json<RequestBudgetUpdate>,
) -> Response {
    match state
        .db
        .update_project_request_budget(ProjectId(id), update)
        .await
    {
        Ok(project) => {
            // Running jobs hold the project's budget; apply the limits now.
            state.reply.request_limiter.budget(&project);
            Json(project).into_response()
        }
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct ProjectUpstreamProxyBody {
    proxy: serde_json::Value,
}

async fn set_project_upstream_proxy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<ProjectUpstreamProxyBody>,
) -> Response {
    let proxy = match body.proxy {
        serde_json::Value::Null => None,
        serde_json::Value::String(proxy) => Some(proxy),
        _ => {
            return error_response(DomainError::invalid(
                "proxy must be a URL string, direct, or null",
            ))
        }
    };
    match state
        .db
        .set_project_upstream_proxy(ProjectId(id), proxy)
        .await
    {
        Ok(_) => match state.upstream_proxy_setting(ProjectId(id)).await {
            Ok(setting) => Json(setting).into_response(),
            Err(error) => error_response(error),
        },
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
    /// HTTP method for block rules with a method filter; defaults to GET.
    #[serde(default)]
    method: Option<String>,
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
        body.method,
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

    // `request:~text` and `response:~text` may decode and scan every candidate
    // body. An exact total would execute that same expensive filter a second time.
    let total_exact = filter
        .as_ref()
        .is_none_or(|filter| !crate::history::uses_body_search(filter));
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
                // An unaudited secret reveal must not succeed.
                if let Err(error) = state
                    .db
                    .audit(
                        Some(project_id),
                        "copy_as_secret_reveal",
                        Some("api"),
                        Some("exchange"),
                        Some(&eid.to_string()),
                        serde_json::json!({ "format": query.format }),
                    )
                    .await
                {
                    return error_response(error);
                }
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
        .prepared_body(ProjectId(id), ExchangeId(eid), side, q.raw.unwrap_or(false))
        .await
    {
        Ok(Some(prepared)) => {
            let body = &prepared.data;
            let total = body.len();
            let end = offset.saturating_add(max_bytes).min(total);
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
                "sha256": prepared.sha256,
                "encoding": "base64",
                "data": b64,
                "untrusted": true,
                "decoded": prepared.decoded,
                "content_encoding": prepared.content_encoding,
                "raw_total_length": prepared.raw_total,
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
#[serde(deny_unknown_fields)]
struct UpsertTab {
    id: Option<i64>,
    name: String,
    base_exchange_id: Option<i64>,
    protocol: Option<String>,
    #[serde(deserialize_with = "deserialize_reply_draft_request")]
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
    #[serde(default, deserialize_with = "deserialize_optional_reply_draft_request")]
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
#[serde(deny_unknown_fields)]
struct StartFuzzBody {
    #[serde(deserialize_with = "deserialize_fuzz_template_request")]
    template: FuzzTemplate,
    confirm: Option<bool>,
}

/// Rejects unknown keys inside `template.draft` before they are silently dropped.
fn deserialize_fuzz_template_request<'de, D>(deserializer: D) -> Result<FuzzTemplate, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if let Some(draft) = value.get("draft") {
        validate_reply_draft_request(draft).map_err(serde::de::Error::custom)?;
    }
    serde_json::from_value(value).map_err(serde::de::Error::custom)
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
            crate::websocket::MESSAGE_PRESENTATION_BYTES,
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

async fn list_browser_profiles(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Response {
    match state.browser.browser_profiles(ProjectId(id)).await {
        Ok(profiles) => Json(serde_json::json!({ "profiles": profiles })).into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBrowserProfile {
    profile: String,
}

async fn create_browser_profile(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<CreateBrowserProfile>,
) -> Response {
    match state
        .browser
        .create_browser_profile(ProjectId(id), &body.profile)
        .await
    {
        Ok(profile) => (StatusCode::CREATED, Json(profile)).into_response(),
        Err(error) => error_response(error),
    }
}

async fn delete_browser_profile(
    State(state): State<Arc<AppState>>,
    Path((id, profile)): Path<(i64, String)>,
) -> Response {
    match state
        .browser
        .delete_browser_profile(ProjectId(id), &profile)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error_response(DomainError::not_found("browser profile")),
        Err(error) => error_response(error),
    }
}

async fn browser_status(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.browser.active_status(ProjectId(id)).await {
        Ok(status) => Json(serde_json::json!({
            "runtime": state.browser.status(),
            "transport": state.transport_status,
            "sessions": status.sessions,
            "resources": status.resources,
        }))
        .into_response(),
        Err(error) => error_response(error),
    }
}

#[derive(Deserialize)]
struct StartBrowser {
    #[serde(default = "default_browser_start_url")]
    url: String,
    profile: Option<String>,
    cookie_profile: Option<String>,
    #[serde(default)]
    refresh_cookies: bool,
    engine_policy: Option<String>,
}

fn default_browser_start_url() -> String {
    "about:blank".into()
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
    match state
        .browser
        .start_with_profile_options(
            ProjectId(id),
            body.url,
            body.profile.as_deref().unwrap_or("default"),
            body.cookie_profile.as_deref(),
            body.refresh_cookies,
        )
        .await
    {
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
        "status" => match body.session_id {
            Some(session_id) => {
                state
                    .browser
                    .cdp_status_for_session(project_id, BrowserSessionId(session_id))
                    .await
            }
            None => state.browser.cdp_status(project_id).await,
        },
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
    let cancel = state.shutdown.clone();
    let stream = futures::stream::unfold(Some(rx), move |state_rx| {
        let id = id;
        let cancel = cancel.clone();
        async move {
            let mut rx = state_rx?;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return None,
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
        "transport": state.transport_status,
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
    // No other page may frame the UI.
    (
        [(
            http::header::CONTENT_SECURITY_POLICY,
            "frame-ancestors 'none'",
        )],
        Html(include_str!("../../web/index.html")),
    )
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
    fn request_drafts_with_unknown_fields_are_rejected() {
        let tab = |draft: serde_json::Value| {
            serde_json::from_value::<UpsertTab>(serde_json::json!({"name": "t", "draft": draft}))
        };
        assert!(tab(serde_json::json!({"headers": []}))
            .err()
            .unwrap()
            .to_string()
            .contains("header_overrides"));
        assert!(tab(serde_json::json!({"url": "https://example.test/"})).is_ok());

        let send = |draft: serde_json::Value| {
            serde_json::from_value::<ReplySendBody>(serde_json::json!({"draft": draft}))
        };
        assert!(send(serde_json::json!({"body": "x"}))
            .err()
            .unwrap()
            .to_string()
            .contains("body_text"));
        assert!(send(serde_json::json!({"body_text": "x"})).is_ok());
        assert!(serde_json::from_value::<ReplySendBody>(serde_json::json!({"tab_id": 1})).is_ok());

        let fuzz = |draft: serde_json::Value| {
            serde_json::from_value::<StartFuzzBody>(serde_json::json!({"template": {
                "draft": draft,
                "insertion_points": [{"name": "a", "location": "url"}],
                "wordlists": [["x"]],
            }}))
        };
        assert!(fuzz(serde_json::json!({"headers": []}))
            .err()
            .unwrap()
            .to_string()
            .contains("header_overrides"));
        assert!(fuzz(serde_json::json!({"url": "https://example.test/§a§"})).is_ok());
    }

    #[test]
    fn disk_quota_errors_use_insufficient_storage() {
        let error = DomainError::new(ErrorCode::DiskQuotaExceeded, "project quota exceeded");
        assert_eq!(status_for_error(&error), StatusCode::INSUFFICIENT_STORAGE);
    }
}

#[cfg(test)]
mod foreign_request_guard_tests {
    use super::*;
    use tower::ServiceExt;

    const TOKEN: &str = "s3cret token/+";
    const LOOPBACK: &str = "127.0.0.1:50000";
    const LAN_PEER: &str = "192.168.1.20:50000";

    #[test]
    fn allows_only_loopback_authorities_on_any_port() {
        for ok in [
            "127.0.0.1:17890",
            "127.0.0.1",
            "localhost:17890",
            "LOCALHOST",
            "[::1]:17890",
            "::1",
            "127.0.0.2:17890",
            "localhost:8080",
            "127.0.0.1:1",
            "[::ffff:127.0.0.1]:17890",
        ] {
            assert!(is_loopback_authority(ok), "{ok}");
        }
        for bad in [
            "evil.example",
            "evil.example:17890",
            "localhost:notaport",
            "localhost.evil.example:17890",
            "192.168.1.3:17890",
            // A non-loopback listen IP is not local: once every non-loopback
            // peer must authenticate, an authenticated request skips the Host
            // check, so the listen IP needs no exception here.
            "10.0.0.5:17890",
            "0.0.0.0:17890",
            "",
        ] {
            assert!(!is_loopback_authority(bad), "{bad}");
        }
    }

    fn app(token: Option<&str>) -> Router {
        Router::new()
            .route("/", get(|| async { "ui" }))
            .route(
                "/api/v1/projects",
                get(|| async { "ok" }).post(|| async { "ok" }),
            )
            .layer(axum::middleware::from_fn_with_state(
                TcpAccess::new(token, 17890),
                guard_tcp_requests,
            ))
    }

    async fn send(
        token: Option<&str>,
        peer: Option<&str>,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> Response {
        send_as(http::Method::GET, token, peer, uri, headers).await
    }

    async fn send_as(
        method: http::Method,
        token: Option<&str>,
        peer: Option<&str>,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> Response {
        let mut request = axum::http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut request = request.body(Body::empty()).unwrap();
        if let Some(peer) = peer {
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                peer.parse::<std::net::SocketAddr>().unwrap(),
            ));
        }
        app(token).oneshot(request).await.unwrap()
    }

    async fn status(token: Option<&str>, peer: &str, headers: &[(&str, &str)]) -> StatusCode {
        send(token, Some(peer), "/api/v1/projects", headers)
            .await
            .status()
    }

    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn session_cookie(token: &str, port: u16) -> String {
        let access = TcpAccess::new(Some(token), port);
        format!(
            "{}={}",
            access.cookie_name,
            access.session.as_deref().unwrap()
        )
    }

    fn encoded(value: &str) -> String {
        url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
    }

    #[tokio::test]
    async fn loopback_peers_need_no_token_but_must_pass_the_browser_guard() {
        for token in [None, Some(TOKEN)] {
            for peer in [LOOPBACK, "[::1]:50000", "[::ffff:127.0.0.1]:50000"] {
                assert_eq!(
                    status(token, peer, &[("host", "127.0.0.1:17890")]).await,
                    StatusCode::OK
                );
            }
            assert_eq!(
                status(
                    token,
                    LOOPBACK,
                    &[
                        ("host", "localhost:17890"),
                        ("origin", "http://localhost:17890"),
                        ("sec-fetch-site", "same-origin"),
                    ]
                )
                .await,
                StatusCode::OK
            );
            for headers in [
                &[][..],
                &[("host", "rebind.evil.example:17890")][..],
                &[("host", "0.0.0.0:17890")][..],
                &[
                    ("host", "127.0.0.1:17890"),
                    ("origin", "http://evil.example"),
                ][..],
                &[("host", "127.0.0.1:17890"), ("origin", "null")][..],
                &[
                    ("host", "127.0.0.1:17890"),
                    ("sec-fetch-site", "cross-site"),
                ][..],
            ] {
                assert_eq!(
                    status(token, LOOPBACK, headers).await,
                    StatusCode::FORBIDDEN,
                    "{headers:?}"
                );
            }
        }
        // A loopback peer may also authenticate, which skips the Host check.
        let bearer = format!("Bearer {TOKEN}");
        assert_eq!(
            status(
                Some(TOKEN),
                LOOPBACK,
                &[("host", "0.0.0.0:17890"), ("authorization", &bearer)]
            )
            .await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn remote_peers_without_credentials_get_401() {
        let response = send(
            Some(TOKEN),
            Some(LAN_PEER),
            "/api/v1/projects",
            &[("host", "10.0.0.5:17890")],
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers()[CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/json"));
        let body: serde_json::Value = serde_json::from_str(&body_text(response).await).unwrap();
        assert_eq!(body["code"], "unauthorized");

        let response = send(
            Some(TOKEN),
            Some(LAN_PEER),
            "/",
            &[
                ("host", "10.0.0.5:17890"),
                ("accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers()[CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html"));
        let page = body_text(response).await;
        assert!(page.contains("HuntProxy status"));
        for field in ["<form", "<input", "<textarea", "<script"] {
            assert!(!page.contains(field), "{field}");
        }

        // No connect info means an unknown peer, which is treated as remote.
        assert_eq!(
            send(
                Some(TOKEN),
                None,
                "/api/v1/projects",
                &[("host", "127.0.0.1:17890")]
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn without_a_token_remote_peers_are_always_refused() {
        for headers in [
            &[("host", "127.0.0.1:17890")][..],
            &[("host", "127.0.0.1:17890"), ("authorization", "Bearer ")][..],
            &[("host", "127.0.0.1:17890"), ("authorization", "Bearer x")][..],
        ] {
            assert_eq!(
                status(None, LAN_PEER, headers).await,
                StatusCode::UNAUTHORIZED,
                "{headers:?}"
            );
        }
        assert_eq!(
            send(
                None,
                Some(LAN_PEER),
                "/?token=",
                &[("host", "127.0.0.1:17890")]
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn a_bearer_token_authenticates_any_host() {
        let host = ("host", "huntproxy.lan:17890");
        assert_eq!(
            status(
                Some(TOKEN),
                LAN_PEER,
                &[host, ("authorization", "Bearer wrong")]
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(Some(TOKEN), LAN_PEER, &[host, ("authorization", TOKEN)]).await,
            StatusCode::UNAUTHORIZED
        );
        for scheme in ["Bearer", "bearer"] {
            let value = format!("{scheme} {TOKEN}");
            assert_eq!(
                status(
                    Some(TOKEN),
                    LAN_PEER,
                    &[
                        host,
                        ("authorization", &value),
                        // A Bearer request is not a browser's ambient
                        // credential, so its Origin is not checked.
                        ("origin", "http://elsewhere.example"),
                    ]
                )
                .await,
                StatusCode::OK
            );
        }
    }

    #[tokio::test]
    async fn the_session_cookie_authenticates_same_origin_requests() {
        let cookie = session_cookie(TOKEN, 17890);
        assert!(!cookie.contains(TOKEN));
        let host = ("host", "10.0.0.5:17890");
        let with_others = format!("theme=dark; {cookie}; other=1");
        for headers in [
            &[host, ("cookie", &cookie)][..],
            &[host, ("cookie", &with_others)][..],
            &[
                host,
                ("cookie", &cookie),
                ("origin", "http://10.0.0.5:17890"),
                ("sec-fetch-site", "same-origin"),
            ][..],
            &[("host", "huntproxy.lan:17890"), ("cookie", &cookie)][..],
        ] {
            assert_eq!(
                status(Some(TOKEN), LAN_PEER, headers).await,
                StatusCode::OK,
                "{headers:?}"
            );
        }
        for headers in [
            &[host, ("cookie", &cookie), ("origin", "http://evil.example")][..],
            &[
                host,
                ("cookie", &cookie),
                ("origin", "http://10.0.0.5:8080"),
            ][..],
            &[
                host,
                ("cookie", &cookie),
                ("origin", "https://10.0.0.5:17890"),
            ][..],
            &[host, ("cookie", &cookie), ("sec-fetch-site", "cross-site")][..],
        ] {
            assert_eq!(
                status(Some(TOKEN), LAN_PEER, headers).await,
                StatusCode::FORBIDDEN,
                "{headers:?}"
            );
        }
        let stale = session_cookie("an older token", 17890);
        let other_port = session_cookie(TOKEN, 17891);
        let raw_token = format!("huntproxy_session_17890={TOKEN}");
        for wrong in [&stale, &other_port, &raw_token] {
            assert_eq!(
                status(Some(TOKEN), LAN_PEER, &[host, ("cookie", wrong)]).await,
                StatusCode::UNAUTHORIZED,
                "{wrong}"
            );
        }
    }

    #[tokio::test]
    async fn the_sign_in_link_sets_the_cookie_and_drops_the_token() {
        let uri = format!("/?project=7&token={}&view=a%20b", encoded(TOKEN));
        let response = send(
            Some(TOKEN),
            Some(LAN_PEER),
            &uri,
            &[("host", "10.0.0.5:17890"), ("accept", "text/html")],
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let headers = response.headers();
        assert_eq!(headers[http::header::LOCATION], "/?project=7&view=a%20b");
        assert_eq!(headers[http::header::REFERRER_POLICY], "no-referrer");
        assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
        let set_cookie = headers[http::header::SET_COOKIE].to_str().unwrap();
        let cookie = session_cookie(TOKEN, 17890);
        assert_eq!(
            set_cookie,
            format!("{cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000")
        );
        assert!(!set_cookie.contains("Secure"));

        let response = send(
            Some(TOKEN),
            Some(LAN_PEER),
            &format!("/?token={}", encoded(TOKEN)),
            &[("host", "10.0.0.5:17890")],
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[http::header::LOCATION], "/");

        for wrong in ["/?token=wrong", "/?token=", "/?project=7&token=s3cret"] {
            let response = send(
                Some(TOKEN),
                Some(LAN_PEER),
                wrong,
                &[("host", "10.0.0.5:17890"), ("accept", "text/html")],
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{wrong}");
            assert!(response.headers().get(http::header::SET_COOKIE).is_none());
            assert!(body_text(response).await.contains("HuntProxy status"));
        }
    }

    #[test]
    fn the_ui_link_signs_in_only_on_non_loopback_binds() {
        let link = |listen: &str, token| ui_link(listen.parse().unwrap(), token);
        assert_eq!(
            link("127.0.0.1:17890", Some(TOKEN)),
            "http://127.0.0.1:17890/"
        );
        assert_eq!(link("[::1]:17890", None), "http://[::1]:17890/");
        let token = encoded(TOKEN);
        assert_eq!(
            link("10.0.0.5:17890", Some(TOKEN)),
            format!("http://10.0.0.5:17890/?token={token}")
        );
        assert_eq!(
            link("0.0.0.0:17890", Some(TOKEN)),
            format!("http://<this-host>:17890/?token={token}")
        );
        assert_eq!(
            link("[::]:17890", Some(TOKEN)),
            format!("http://<this-host>:17890/?token={token}")
        );
        let signed_in = link("10.0.0.5:17890", Some(TOKEN));
        let query = signed_in.split_once('?').unwrap().1;
        assert_eq!(
            query_value(Some(query), SIGN_IN_PARAM).as_deref(),
            Some(TOKEN)
        );
    }

    #[tokio::test]
    async fn browser_requests_must_be_same_origin_except_top_level_navigations() {
        let cookie = session_cookie(TOKEN, 17890);
        // The same checks apply to local requests and to cookie requests.
        let cases: [(&str, &str, Option<&str>); 2] = [
            (LOOPBACK, "127.0.0.1:17890", None),
            (LAN_PEER, "10.0.0.5:17890", Some(&cookie)),
        ];
        for (peer, host, cookie) in cases {
            let origin = format!("http://{host}");
            let other_port = format!("http://{}:8080", host.split_once(':').unwrap().0);
            let check = |method: http::Method, uri: &'static str, extra: Vec<(&str, String)>| {
                let mut headers = vec![("host".to_string(), host.to_string())];
                if let Some(cookie) = cookie {
                    headers.push(("cookie".into(), cookie.to_string()));
                }
                headers.extend(
                    extra
                        .into_iter()
                        .map(|(name, value)| (name.to_string(), value)),
                );
                async move {
                    let headers: Vec<(&str, &str)> = headers
                        .iter()
                        .map(|(name, value)| (name.as_str(), value.as_str()))
                        .collect();
                    send_as(method, Some(TOKEN), Some(peer), uri, &headers)
                        .await
                        .status()
                }
            };
            let navigation = |site: &str, dest: &str| {
                vec![
                    ("sec-fetch-site", site.to_string()),
                    ("sec-fetch-mode", "navigate".to_string()),
                    ("sec-fetch-dest", dest.to_string()),
                ]
            };
            let ok = StatusCode::OK;
            let forbidden = StatusCode::FORBIDDEN;
            for (method, uri, extra, expected) in [
                // curl and the CLI send neither header.
                (http::Method::POST, "/api/v1/projects", vec![], ok),
                (
                    http::Method::POST,
                    "/api/v1/projects",
                    vec![
                        ("origin", origin.clone()),
                        ("sec-fetch-site", "same-origin".into()),
                    ],
                    ok,
                ),
                (http::Method::GET, "/", navigation("none", "document"), ok),
                (
                    http::Method::GET,
                    "/",
                    navigation("same-site", "document"),
                    ok,
                ),
                (
                    http::Method::POST,
                    "/api/v1/projects",
                    vec![("origin", other_port.clone())],
                    forbidden,
                ),
                (
                    http::Method::POST,
                    "/api/v1/projects",
                    vec![
                        ("origin", other_port.clone()),
                        ("sec-fetch-site", "same-site".into()),
                        ("sec-fetch-mode", "no-cors".into()),
                        ("sec-fetch-dest", "empty".into()),
                    ],
                    forbidden,
                ),
                (
                    http::Method::GET,
                    "/api/v1/projects",
                    vec![
                        ("sec-fetch-site", "same-site".into()),
                        ("sec-fetch-mode", "cors".into()),
                        ("sec-fetch-dest", "empty".into()),
                    ],
                    forbidden,
                ),
                (
                    http::Method::GET,
                    "/",
                    navigation("same-site", "iframe"),
                    forbidden,
                ),
                (
                    http::Method::POST,
                    "/api/v1/projects",
                    navigation("same-site", "document"),
                    forbidden,
                ),
                (
                    http::Method::GET,
                    "/",
                    navigation("cross-site", "document"),
                    forbidden,
                ),
            ] {
                assert_eq!(
                    check(method.clone(), uri, extra.clone()).await,
                    expected,
                    "{peer} {method} {uri} {extra:?}"
                );
            }
        }

        // An SSH tunnel publishes the UI on another local port.
        assert_eq!(
            status(
                None,
                LOOPBACK,
                &[
                    ("host", "localhost:8754"),
                    ("origin", "http://localhost:8754"),
                    ("sec-fetch-site", "same-origin"),
                ]
            )
            .await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn the_ui_document_cannot_be_framed() {
        let response = ui_index().await.into_response();
        assert_eq!(
            response.headers()[http::header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'none'"
        );
    }

    #[tokio::test]
    async fn the_sign_in_page_retries_once_so_the_session_cookie_is_sent() {
        let host = ("host", "10.0.0.5:17890");
        let html = ("accept", "text/html,*/*;q=0.8");
        let refresh = "<meta http-equiv=\"refresh\" content=\"0; url=/?signin=1\">";

        // After a cross-site sign-in redirect, the navigation to `/` has no cookie.
        let response = send(
            Some(TOKEN),
            Some(LAN_PEER),
            "/",
            &[host, html, ("sec-fetch-site", "cross-site")],
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = body_text(response).await;
        assert!(body.contains(refresh), "{body}");

        // The retry without a cookie gets the static page, so there is no loop.
        // A wrong sign-in token and other paths never retry.
        for uri in ["/?signin=1", "/?token=wrong", "/api/v1/projects"] {
            let response = send(Some(TOKEN), Some(LAN_PEER), uri, &[host, html]).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
            let body = body_text(response).await;
            assert!(!body.contains("http-equiv"), "{uri}: {body}");
            assert!(body.contains("HuntProxy status"), "{uri}");
        }

        // The retry is same-origin, so the browser sends the cookie.
        let cookie = session_cookie(TOKEN, 17890);
        let response = send(
            Some(TOKEN),
            Some(LAN_PEER),
            "/?signin=1",
            &[
                host,
                html,
                ("cookie", &cookie),
                ("sec-fetch-site", "same-origin"),
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-dest", "document"),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
