//! Explicit HTTP/HTTPS proxy with project-bound capture authentication.
//!
//! HTTPS CONNECT requests are intercepted with the local CA so decrypted
//! requests and responses are stored in History. Upstream traffic still goes
//! through the semantic transport and its `ValidatedDial` resolver.

mod websocket;

use crate::app::AppState;
use crate::domain::*;
use crate::policy::scope::{resolve_validated_dial, url_is_in_scope, TargetRef};
use crate::storage::{extract_proxy_token, NewExchange};
use crate::transport::{
    OutboundBody, OutboundRequest, ProtocolMode, StreamingOutboundResponse, TransportIdentity,
};
use base64::Engine as _;
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

// Only Chrome background endpoints observed in History belong here: broad host
// filters would discard evidence when a user tests a Google target.
const CHROME_BACKGROUND_REQUESTS: &[(&str, &str, &str, bool, bool)] = &[
    (
        "POST",
        "android.clients.google.com",
        "/checkin",
        false,
        false,
    ),
    (
        "POST",
        "android.clients.google.com",
        "/c2dm/register3",
        false,
        false,
    ),
    ("POST", "accounts.google.com", "/ListAccounts", false, true),
    ("GET", "www.google.com", "/async/folae", false, false),
    (
        "GET",
        "content-autofill.googleapis.com",
        "/v1/pages/",
        true,
        false,
    ),
    (
        "POST",
        "content-autofill.googleapis.com",
        "/v1/forms:",
        true,
        false,
    ),
];
static SKIPPED_CHROME_REQUESTS: AtomicU64 = AtomicU64::new(0);
const PROJECT_HINT_HEADER: &str = "x-huntproxy-project-id";

fn is_chrome_background_request(
    session: &CaptureSession,
    target: &TargetRef,
    method: &Method,
) -> bool {
    session.browser_session_id.is_some()
        && target.scheme == "https"
        && target.port == 443
        && CHROME_BACKGROUND_REQUESTS.iter().any(
            |(allowed_method, host, path, prefix, chromium_source)| {
                method.as_str() == *allowed_method
                    && target.host == *host
                    && (if *prefix {
                        target.path.starts_with(path)
                    } else {
                        target.path == *path
                    })
                    && (!chromium_source
                        || target.query.as_deref().is_some_and(|query| {
                            url::form_urlencoded::parse(query.as_bytes())
                                .any(|(key, value)| key == "source" && value == "ChromiumBrowser")
                        }))
            },
        )
}

fn skip_chrome_background_request(
    session: &CaptureSession,
    target: &TargetRef,
    method: &Method,
) -> bool {
    if !is_chrome_background_request(session, target, method) {
        return false;
    }
    let count = SKIPPED_CHROME_REQUESTS.fetch_add(1, Ordering::Relaxed) + 1;
    tracing::debug!(count, "skipped Chrome background requests");
    true
}

fn is_own_api_target(target: &TargetRef, listener: SocketAddr) -> bool {
    if target.port != listener.port() {
        return false;
    }
    let accepts_loopback = listener.ip().is_loopback() || listener.ip().is_unspecified();
    if target.host == "localhost" {
        return accepts_loopback;
    }
    let Ok(ip) = target
        .host
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
    else {
        return false;
    };
    (accepts_loopback && ip.is_loopback())
        || ip == listener.ip()
        || (listener.ip().is_unspecified()
            && !ip.is_unspecified()
            && std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok())
}

fn pin_api_dial(mut dial: ValidatedDial, listener: SocketAddr) -> Option<ValidatedDial> {
    dial.approved_socket_addrs.retain(|addr| {
        if listener.ip().is_unspecified() {
            addr.is_ipv4() == listener.is_ipv4()
                && (addr.ip().is_loopback()
                    || std::net::UdpSocket::bind(SocketAddr::new(addr.ip(), 0)).is_ok())
        } else {
            addr.ip() == listener.ip()
        }
    });
    (!dial.approved_socket_addrs.is_empty()).then_some(dial)
}

type ProxyBody = UnsyncBoxBody<Bytes, Infallible>;
const PROXY_ERROR_HEADER: &str = "x-huntproxy-proxy-error";

fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).boxed_unsync()
}

pub async fn bind_proxy(addr: SocketAddr) -> DomainResult<TcpListener> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| DomainError::new(ErrorCode::Unavailable, format!("proxy bind {addr}: {e}")))
}

pub async fn serve_proxy(state: Arc<AppState>, cancel: CancellationToken) -> DomainResult<()> {
    let listener = bind_proxy(state.config.proxy_listen).await?;
    serve_proxy_listener(state, listener, cancel).await
}

pub async fn serve_proxy_listener(
    state: Arc<AppState>,
    listener: TcpListener,
    cancel: CancellationToken,
) -> DomainResult<()> {
    let addr = listener
        .local_addr()
        .map_err(|e| DomainError::new(ErrorCode::Unavailable, e.to_string()))?;
    let authority = Arc::new(MitmAuthority::load(&state)?);
    tracing::info!(%addr, "proxy listening");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::warn!(%error, "proxy accept failed");
                        continue;
                    }
                };
                let state = state.clone();
                let authority = authority.clone();
                let connection_cancel = cancel.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let state = state.clone();
                        let authority = authority.clone();
                        async move { handle_outer(state, authority, request, peer).await }
                    });
                    let connection = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .with_upgrades();
                    tokio::select! {
                        _ = connection_cancel.cancelled() => {}
                        result = connection => {
                            if let Err(error) = result {
                                tracing::debug!(%error, "proxy connection closed");
                            }
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_outer(
    state: Arc<AppState>,
    authority: Arc<MitmAuthority>,
    request: Request<Incoming>,
    _peer: SocketAddr,
) -> Result<Response<ProxyBody>, hyper::Error> {
    let result = handle_authenticated(state, authority, request).await;
    Ok(match result {
        Ok(response) => response,
        Err(error) => proxy_error_response(error),
    })
}

async fn handle_authenticated(
    state: Arc<AppState>,
    authority: Arc<MitmAuthority>,
    mut request: Request<Incoming>,
) -> DomainResult<Response<ProxyBody>> {
    let auth = request
        .headers()
        .get("proxy-authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            DomainError::new(ErrorCode::ProxyAuthRequired, "missing Proxy-Authorization")
        })?;
    let token = extract_proxy_token(auth).ok_or_else(|| {
        DomainError::new(ErrorCode::ProxyAuthRequired, "invalid Proxy-Authorization")
    })?;
    let session = state.db.auth_capture_token(&token).await?;
    request.headers_mut().remove("proxy-authorization");

    if request.method() == Method::CONNECT {
        handle_connect(state, authority, request, session).await
    } else {
        forward_request(state, request, session, None).await
    }
}

async fn forward_request(
    state: Arc<AppState>,
    mut request: Request<Incoming>,
    session: CaptureSession,
    forced_scheme: Option<&str>,
) -> DomainResult<Response<ProxyBody>> {
    request.headers_mut().remove(PROJECT_HINT_HEADER);
    if websocket::is_upgrade(&request) {
        return websocket::handle(state, request, session, forced_scheme).await;
    }
    let project = state.db.get_project(session.project_id).await?;
    let (mut parts, incoming) = request.into_parts();
    let internal_crawler_request =
        take_internal_crawler_marker(&mut parts.headers, session.is_browser_bound);
    let browser_origin = take_browser_origin_marker(&mut parts.headers, session.is_browser_bound)?;
    let mut url = request_url(&parts, forced_scheme)?;
    let original_url = url.clone();
    let original_target = TargetRef::from_url(&url)?;
    enforce_browser_request_origin(browser_origin.as_deref(), &url, false)?;
    let mut applied_rules =
        crate::request_rules::apply_url_rules(&state.db, session.project_id, &mut url).await?;
    enforce_browser_request_origin(browser_origin.as_deref(), &url, true)?;
    let target = TargetRef::from_url(&url)?;
    // Requests to this daemon stay on its listener, independent of project
    // egress settings. A rewrite to or from another target is not internal.
    let api_listen = state.config.api_listen;
    let api_dial = if is_own_api_target(&original_target, api_listen)
        && is_own_api_target(&target, api_listen)
    {
        let original_dial =
            resolve_validated_dial(&original_url, &project.scope, Duration::from_secs(60)).await?;
        let target_dial = if original_url == url {
            original_dial.clone()
        } else {
            resolve_validated_dial(&url, &project.scope, Duration::from_secs(60)).await?
        };
        if pin_api_dial(original_dial, api_listen).is_some() {
            pin_api_dial(target_dial, api_listen)
        } else {
            None
        }
    } else {
        None
    };
    let rotation = if api_dial.is_some() {
        None
    } else {
        state
            .db
            .next_ip_rotation_route(session.project_id, &url)
            .await?
    };
    let wire_url = match &rotation {
        Some(route) => route.wire_url(&url)?,
        None => url.clone(),
    };
    let wire_target = TargetRef::from_url(&wire_url)?;
    let upstream_proxy = if api_dial.is_some() {
        None
    } else {
        state
            .db
            .resolve_upstream_proxy(
                session.project_id,
                &state.config.upstream_proxies,
                &wire_target.host,
                None,
            )
            .await?
    };
    let capture = url_is_in_scope(&url, &project.scope)?
        && !is_own_api_target(&target, state.config.api_listen)
        && !is_own_api_target(&wire_target, state.config.api_listen);
    let hint_project = api_dial.is_some()
        && parts.method == Method::GET
        && original_target.path == "/api/v1/projects"
        && target.path == "/api/v1/projects";
    let dial = match api_dial {
        Some(dial) => dial,
        None => resolve_validated_dial(&wire_url, &project.scope, Duration::from_secs(60)).await?,
    };
    let method = parts.method.clone();
    let mut headers = parts
        .headers
        .iter()
        .filter(|(name, _)| !name.as_str().eq_ignore_ascii_case("proxy-connection"))
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let mut request_spool = spool_request_body(
        incoming,
        project.limits.capture_body_bytes,
        &state.config.spool_dir,
    )
    .await?;
    let rewrite_body =
        crate::request_rules::has_applicable_body_rules(&state.db, session.project_id, &url)
            .await?;
    let mut body = if rewrite_body {
        if request_spool.as_ref().is_some_and(|(_, length)| {
            *length > crate::request_rules::MAX_REWRITE_BODY_BYTES as u64
        }) {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                "request body exceeds 2 MiB rewrite limit",
            ));
        }
        match &request_spool {
            Some((spool, _)) => tokio::fs::read(spool.path())
                .await
                .map_err(spool_io_error)?,
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };
    applied_rules.extend(
        crate::request_rules::apply_message_rules(
            &state.db,
            session.project_id,
            &url,
            &mut headers,
            rewrite_body.then_some(&mut body),
        )
        .await?,
    );
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case(PROJECT_HINT_HEADER));
    let mut wire_headers = headers.clone();
    if rotation.is_some() {
        wire_headers.retain(|(name, _)| !name.eq_ignore_ascii_case("host"));
    }
    if rewrite_body {
        if let Some((spool, length)) = request_spool.as_mut() {
            tokio::fs::write(spool.path(), &body)
                .await
                .map_err(spool_io_error)?;
            *length = body.len() as u64;
        } else if !body.is_empty() {
            let (spool, mut file) = create_private_spool(&state.config.spool_dir, "request")?;
            file.write_all(&body).await.map_err(spool_io_error)?;
            file.flush().await.map_err(spool_io_error)?;
            file.sync_data().await.map_err(spool_io_error)?;
            drop(file);
            request_spool = Some((spool, body.len() as u64));
        }
    }
    let request_body = request_spool
        .as_ref()
        .map(|(spool, len)| OutboundBody::Spool {
            path: spool.path().to_path_buf(),
            len: *len,
        })
        .unwrap_or(OutboundBody::Empty);
    let start = std::time::Instant::now();
    let outbound = state
        .transport
        .send_stream(
            &dial,
            OutboundRequest {
                identity: TransportIdentity::for_capture(&session),
                method: method.clone(),
                url: wire_url,
                headers: wire_headers,
                body: request_body,
                // The intercepted connection's version describes the browser
                // talking to HuntProxy. Negotiate independently with the origin.
                protocol: ProtocolMode::Auto,
                connect_timeout: Duration::from_secs(10),
                total_timeout: Duration::from_secs(60),
                max_body_bytes: project.limits.capture_body_bytes,
                preserve_identity_headers: true,
                upstream_proxy,
            },
        )
        .await;

    let mut outbound = match outbound {
        Ok(outbound) => outbound,
        Err(error) => {
            if capture {
                record_failed_exchange(
                    &state,
                    &session,
                    &target,
                    &method,
                    &headers,
                    request_spool,
                    start.elapsed(),
                    &error,
                    &applied_rules,
                    rotation.as_ref(),
                )
                .await;
            }
            return Err(error);
        }
    };
    if let Some(route) = &rotation {
        outbound.transport_profile = route.transport_profile(&outbound.transport_profile);
    }
    let project_id = session.project_id;
    let mut response = streaming_response(
        state,
        session,
        target,
        method,
        headers,
        request_spool,
        outbound,
        project.limits.capture_body_bytes,
        start,
        capture,
        internal_crawler_request,
        applied_rules,
    )?;
    response.headers_mut().remove(PROJECT_HINT_HEADER);
    if hint_project && response.status() == StatusCode::OK {
        response.headers_mut().insert(
            PROJECT_HINT_HEADER,
            project_id
                .get()
                .to_string()
                .parse()
                .expect("numeric project ID"),
        );
    }
    Ok(response)
}

async fn spool_request_body(
    mut body: Incoming,
    max_bytes: u64,
    spool_dir: &Path,
) -> DomainResult<Option<(SpoolGuard, u64)>> {
    let (spool, mut file) = create_private_spool(spool_dir, "request")?;
    let mut length = 0u64;
    while let Some(frame) = body.frame().await {
        let frame =
            frame.map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
        if let Ok(data) = frame.into_data() {
            let chunk_len = u64::try_from(data.len())
                .map_err(|_| DomainError::new(ErrorCode::BodyTooLarge, "request body too large"))?;
            if chunk_len > max_bytes.saturating_sub(length) {
                return Err(DomainError::new(
                    ErrorCode::BodyTooLarge,
                    format!("request body exceeds project limit of {max_bytes} bytes"),
                ));
            }
            file.write_all(&data).await.map_err(spool_io_error)?;
            length += chunk_len;
        }
    }
    file.flush().await.map_err(spool_io_error)?;
    file.sync_data().await.map_err(spool_io_error)?;
    drop(file);
    if length == 0 {
        drop(spool);
        Ok(None)
    } else {
        Ok(Some((spool, length)))
    }
}

fn request_url(parts: &http::request::Parts, forced_scheme: Option<&str>) -> DomainResult<String> {
    if parts.uri.scheme().is_some() {
        return Ok(parts.uri.to_string());
    }
    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| parts.uri.authority().map(|authority| authority.as_str()))
        .ok_or_else(|| DomainError::invalid("missing Host"))?;
    let scheme = forced_scheme.unwrap_or("http");
    Ok(format!("{scheme}://{host}{}", parts.uri))
}

fn header_entries(headers: &[(String, Vec<u8>)]) -> Vec<HeaderEntry> {
    headers
        .iter()
        .enumerate()
        .map(|(index, (name, value))| HeaderEntry {
            name: name.clone(),
            value: value.clone(),
            ordinal: index as u32,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn record_failed_exchange(
    state: &AppState,
    session: &CaptureSession,
    target: &TargetRef,
    method: &Method,
    headers: &[(String, Vec<u8>)],
    request_spool: Option<(SpoolGuard, u64)>,
    duration: Duration,
    error: &DomainError,
    applied_rules: &[crate::request_rules::AppliedRequestRule],
    rotation: Option<&crate::storage::IpRotationRoute>,
) {
    if skip_chrome_background_request(session, target, method) {
        return;
    }
    let completion = completion_for_error(error);
    let request_path = request_spool
        .as_ref()
        .map(|(spool, _)| spool.path().to_path_buf());
    let result = state
        .db
        .insert_exchange_from_spools(
            NewExchange {
                project_id: session.project_id,
                source: ExchangeSource::Proxy,
                protocol: "unknown".into(),
                method: method.as_str().into(),
                scheme: target.scheme.clone(),
                authority: target.authority(),
                host: target.host.clone(),
                port: target.port,
                path: target.path.clone(),
                query: target.query.clone(),
                status_code: None,
                mime: None,
                completion,
                capture_quality: CaptureQuality::Semantic,
                header_representation: HeaderRepresentation::Semantic,
                body_representation: BodyRepresentation::SemanticEncoded,
                cache_provenance: CacheProvenance::None,
                transport_provenance: Some(state.transport.provenance()),
                transport_profile: Some(match rotation {
                    Some(route) => route.transport_profile(state.transport.profile_name()),
                    None => state.transport.profile_name().into(),
                }),
                request_headers: header_entries(headers),
                response_headers: Vec::new(),
                request_body: None,
                response_body: None,
                duration_ms: Some(duration.as_millis() as i64),
                lineage: ExchangeLineage {
                    capture_session_id: Some(session.id),
                    browser_session_id: session.browser_session_id,
                    browser_action_id: session.browser_action_id,
                    ..Default::default()
                },
                page_title: None,
                error_message: Some(error.to_string()),
            },
            request_path,
            None,
        )
        .await;
    match result {
        Ok(exchange_id) => {
            let _ = state
                .db
                .record_exchange_request_rules(
                    session.project_id,
                    exchange_id,
                    applied_rules.to_vec(),
                )
                .await;
            let _ = state.events.send(crate::app::AppEvent {
                project_id: session.project_id.get(),
                kind: "exchange".into(),
                payload: serde_json::json!({
                    "exchange_id": exchange_id.get(),
                    "source": "proxy",
                    "completion": completion,
                }),
            });
        }
        Err(storage_error) => {
            tracing::warn!(%storage_error, "failed to preserve failed proxy exchange");
        }
    }
}

fn is_html_content_type(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|content_type| {
        matches!(
            content_type
                .split(';')
                .next()
                .unwrap_or(content_type)
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "text/html" | "application/xhtml+xml"
        )
    })
}

fn take_internal_crawler_marker(headers: &mut http::HeaderMap, browser_bound: bool) -> bool {
    // This marker must never be persisted or forwarded to the target. Only a
    // browser-bound capture credential may use it to suppress recursive crawl.
    let marked = browser_bound
        && headers
            .get("x-huntproxy-internal-crawler")
            .is_some_and(|value| value.as_bytes() == b"1");
    headers.remove("x-huntproxy-internal-crawler");
    marked
}

fn take_browser_origin_marker(
    headers: &mut http::HeaderMap,
    browser_bound: bool,
) -> DomainResult<Option<String>> {
    // The marker is private proxy metadata. Strip it for every credential and
    // only trust it on browser-bound capture sessions.
    let values = headers
        .get_all("x-huntproxy-browser-origin")
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    headers.remove("x-huntproxy-browser-origin");
    if !browser_bound || values.is_empty() {
        return Ok(None);
    }
    if values.len() != 1 {
        return Err(DomainError::invalid(
            "browser origin marker must have exactly one value",
        ));
    }
    let raw = values[0]
        .to_str()
        .map_err(|_| DomainError::invalid("browser origin marker is not valid text"))?;
    let parsed = url::Url::parse(raw)
        .map_err(|_| DomainError::invalid("browser origin marker is not a valid HTTP origin"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(DomainError::invalid(
            "browser origin marker is not a valid HTTP origin",
        ));
    }
    Ok(Some(parsed.origin().ascii_serialization()))
}

fn enforce_browser_request_origin(
    origin: Option<&str>,
    url: &str,
    after_request_rules: bool,
) -> DomainResult<()> {
    if origin.is_some_and(|origin| !crate::page_analyzer::same_origin_url(origin, url)) {
        let message = if after_request_rules {
            "request rules moved a browser request outside its active page origin"
        } else {
            "browser request does not match its active page origin"
        };
        return Err(DomainError::scope_denied(message));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn streaming_response(
    state: Arc<AppState>,
    session: CaptureSession,
    target: TargetRef,
    method: Method,
    request_headers: Vec<(String, Vec<u8>)>,
    request_spool: Option<(SpoolGuard, u64)>,
    outbound: StreamingOutboundResponse,
    capture_limit: u64,
    started: std::time::Instant,
    capture: bool,
    suppress_crawl: bool,
    applied_rules: Vec<crate::request_rules::AppliedRequestRule>,
) -> DomainResult<Response<ProxyBody>> {
    let (response_spool, response_file) =
        create_private_spool(&state.config.spool_dir, "response")?;
    let status = outbound.status;
    let mut builder = Response::builder().status(outbound.status);
    for (name, value) in &outbound.headers {
        if name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("keep-alive")
            || name.eq_ignore_ascii_case(PROXY_ERROR_HEADER)
        {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_slice());
    }
    let (sender, receiver) = mpsc::channel::<Bytes>(8);
    let body = StreamBody::new(
        ReceiverStream::new(receiver).map(|chunk| Ok::<_, Infallible>(Frame::data(chunk))),
    )
    .boxed_unsync();
    let response = builder
        .body(body)
        .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
    tokio::spawn(pump_streaming_response(
        state,
        session,
        target,
        method,
        request_headers,
        request_spool,
        response_spool,
        response_file,
        outbound,
        status,
        capture_limit,
        started,
        sender,
        capture,
        suppress_crawl,
        applied_rules,
    ));
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
async fn pump_streaming_response(
    state: Arc<AppState>,
    session: CaptureSession,
    target: TargetRef,
    method: Method,
    request_headers: Vec<(String, Vec<u8>)>,
    request_spool: Option<(SpoolGuard, u64)>,
    response_spool: SpoolGuard,
    mut response_file: tokio::fs::File,
    mut outbound: StreamingOutboundResponse,
    status: StatusCode,
    capture_limit: u64,
    started: std::time::Instant,
    sender: mpsc::Sender<Bytes>,
    capture: bool,
    suppress_crawl: bool,
    applied_rules: Vec<crate::request_rules::AppliedRequestRule>,
) {
    let response_headers = header_entries(&outbound.headers);
    let mime = response_headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .map(|header| String::from_utf8_lossy(&header.value).into_owned());
    let html_response = is_html_content_type(mime.as_deref());
    let crawl_html = session.is_browser_bound && !suppress_crawl && html_response;
    let mut captured = 0u64;
    let mut truncated = false;
    let mut completion = CompletionState::Complete;
    let mut error_message = None;
    let mut response_spool_valid = true;

    loop {
        let next = tokio::select! {
            _ = sender.closed() => {
                completion = CompletionState::Cancelled;
                error_message = Some("downstream client disconnected".into());
                break;
            }
            next = outbound.body.next() => next,
        };
        let Some(next) = next else {
            break;
        };
        let chunk = match next {
            Ok(chunk) => chunk,
            Err(error) => {
                completion = completion_for_error(&error);
                error_message = Some(error.to_string());
                break;
            }
        };
        if response_spool_valid {
            let room = capture_limit.saturating_sub(captured);
            let write_len = usize::try_from(room.min(chunk.len() as u64)).unwrap_or(chunk.len());
            if write_len > 0 {
                if let Err(error) = response_file.write_all(&chunk[..write_len]).await {
                    response_spool_valid = false;
                    completion = CompletionState::Interrupted;
                    error_message = Some(format!("response capture spool write failed: {error}"));
                } else {
                    captured += write_len as u64;
                }
            }
            if write_len < chunk.len() {
                truncated = true;
            }
        }
        if sender.send(chunk).await.is_err() {
            completion = CompletionState::Cancelled;
            error_message = Some("downstream client disconnected".into());
            break;
        }
    }
    drop(sender);

    if !capture || skip_chrome_background_request(&session, &target, &method) {
        return;
    }

    if response_spool_valid {
        if let Err(error) = response_file.flush().await {
            response_spool_valid = false;
            completion = CompletionState::Interrupted;
            error_message = Some(format!("response capture spool flush failed: {error}"));
        } else if let Err(error) = response_file.sync_data().await {
            response_spool_valid = false;
            completion = CompletionState::Interrupted;
            error_message = Some(format!("response capture spool sync failed: {error}"));
        }
    }
    drop(response_file);
    if completion == CompletionState::Complete && truncated {
        completion = CompletionState::TruncatedByPolicy;
        error_message = Some("response body truncated by project capture limit".into());
    }

    let request_path = request_spool
        .as_ref()
        .map(|(spool, _)| spool.path().to_path_buf());
    let response_path = response_spool_valid.then(|| response_spool.path().to_path_buf());
    let document_url = format!(
        "{}://{}{}{}",
        target.scheme,
        target.authority(),
        target.path,
        target
            .query
            .as_deref()
            .filter(|query| !query.is_empty())
            .map(|query| format!("?{query}"))
            .unwrap_or_default()
    );
    let result = state
        .db
        .insert_exchange_from_spools(
            NewExchange {
                project_id: session.project_id,
                source: ExchangeSource::Proxy,
                protocol: outbound.protocol,
                method: method.as_str().to_string(),
                scheme: target.scheme.clone(),
                authority: target.authority(),
                host: target.host,
                port: target.port,
                path: target.path,
                query: target.query,
                status_code: Some(status.as_u16()),
                mime,
                completion,
                capture_quality: CaptureQuality::Semantic,
                header_representation: HeaderRepresentation::Semantic,
                body_representation: if response_spool_valid {
                    BodyRepresentation::SemanticEncoded
                } else {
                    BodyRepresentation::Unavailable
                },
                cache_provenance: CacheProvenance::None,
                transport_provenance: Some(outbound.transport_provenance),
                transport_profile: Some(outbound.transport_profile),
                request_headers: header_entries(&request_headers),
                response_headers,
                request_body: None,
                response_body: None,
                duration_ms: Some(started.elapsed().as_millis() as i64),
                lineage: ExchangeLineage {
                    capture_session_id: Some(session.id),
                    browser_session_id: session.browser_session_id,
                    browser_action_id: session.browser_action_id,
                    ..Default::default()
                },
                page_title: None,
                error_message,
            },
            request_path,
            response_path,
        )
        .await;
    match result {
        Ok(exchange_id) => {
            let _ = state
                .db
                .record_exchange_request_rules(session.project_id, exchange_id, applied_rules)
                .await;
            let _ = state.events.send(crate::app::AppEvent {
                project_id: session.project_id.get(),
                kind: "exchange".into(),
                payload: serde_json::json!({
                    "exchange_id": exchange_id.get(),
                    "source": "proxy",
                    "completion": completion,
                }),
            });
            if html_response {
                if let Err(error) = crate::page_title::populate_static_exchange_title(
                    &state.db,
                    session.project_id,
                    exchange_id,
                )
                .await
                {
                    tracing::debug!(%error, exchange_id = exchange_id.get(), "could not extract static page title");
                }
            }
            if crawl_html {
                if let Some(browser_session_id) = session.browser_session_id {
                    if let Ok(browser_session) = state
                        .db
                        .get_browser_session(session.project_id, browser_session_id)
                        .await
                    {
                        if let Some(title) = browser_session.current_title.as_deref() {
                            let _ = state
                                .db
                                .associate_browser_page_title(
                                    session.project_id,
                                    browser_session_id,
                                    &document_url,
                                    title,
                                )
                                .await;
                        }
                    }
                }
            }
            if crawl_html {
                let crawler = state.crawler.clone();
                tokio::spawn(async move {
                    crawler
                        .crawl_exchange(session.project_id, exchange_id)
                        .await;
                });
            }
        }
        Err(error) => tracing::warn!(%error, "failed to persist streamed proxy exchange"),
    }
}

fn completion_for_error(error: &DomainError) -> CompletionState {
    match error.code() {
        ErrorCode::Timeout => CompletionState::Timeout,
        ErrorCode::ProtocolError => CompletionState::ProtocolError,
        ErrorCode::Cancelled => CompletionState::Cancelled,
        _ => CompletionState::ConnectionError,
    }
}

struct SpoolGuard {
    path: PathBuf,
}

impl SpoolGuard {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SpoolGuard {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path=%self.path.display(), %error, "failed to remove proxy spool");
            }
        }
    }
}

fn create_private_spool(
    spool_dir: &Path,
    kind: &str,
) -> DomainResult<(SpoolGuard, tokio::fs::File)> {
    for _ in 0..8 {
        let path = spool_dir.join(format!(".{kind}-{}.spool", uuid::Uuid::new_v4()));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                return Ok((SpoolGuard { path }, tokio::fs::File::from_std(file)));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(DomainError::new(
                    ErrorCode::StorageError,
                    format!("create proxy spool {}: {error}", path.display()),
                ));
            }
        }
    }
    Err(DomainError::new(
        ErrorCode::StorageError,
        "could not allocate a unique proxy spool",
    ))
}

fn spool_io_error(error: std::io::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

async fn handle_connect(
    state: Arc<AppState>,
    authority: Arc<MitmAuthority>,
    request: Request<Incoming>,
    session: CaptureSession,
) -> DomainResult<Response<ProxyBody>> {
    let connect_authority = request
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_string())
        .ok_or_else(|| DomainError::invalid("CONNECT missing authority"))?;
    let scope_url = format!("https://{connect_authority}/");
    let project = state.db.get_project(session.project_id).await?;
    // Resolve before acknowledging the tunnel so an invalid/unresolvable
    // authority fails early. Decrypted requests resolve their own targets.
    resolve_validated_dial(&scope_url, &project.scope, Duration::from_secs(60)).await?;
    let host = TargetRef::from_url(&scope_url)?.host;
    let tls_config = authority.server_config(&host)?;
    let shutdown = state.shutdown.clone();

    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(request).await {
            Ok(upgraded) => upgraded,
            Err(error) => {
                tracing::debug!(%error, "CONNECT upgrade failed");
                return;
            }
        };
        // Chromium tunnels both ws:// and wss:// through CONNECT. Keep the
        // prelude buffered so selecting plaintext HTTP never consumes its GET,
        // while TLS still follows the existing certificate/interception path.
        let mut stream = BufReader::new(TokioIo::new(upgraded));
        let first = tokio::select! {
            _ = shutdown.cancelled() => return,
            result = stream.fill_buf() => match result {
                Ok(bytes) => bytes.first().copied(),
                Err(error) => {
                    tracing::debug!(%error, "CONNECT protocol detection failed");
                    return;
                }
            },
        };
        match first {
            Some(0x16) => {
                let acceptor = TlsAcceptor::from(tls_config);
                let tls = tokio::select! {
                    _ = shutdown.cancelled() => return,
                    result = acceptor.accept(stream) => match result {
                        Ok(tls) => tls,
                        Err(error) => {
                            tracing::debug!(%error, "CONNECT TLS interception failed");
                            return;
                        }
                    },
                };
                serve_connect_io(tls, state, session, "https").await;
            }
            Some(first) if first.is_ascii_alphabetic() => {
                serve_connect_io(stream, state, session, "http").await;
            }
            Some(_) => {
                tracing::debug!("CONNECT requires TLS or an HTTP request");
            }
            None => {}
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(full_body(Bytes::new()))
        .expect("static CONNECT response"))
}

async fn serve_connect_io<I>(
    io: I,
    state: Arc<AppState>,
    session: CaptureSession,
    scheme: &'static str,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service_state = state.clone();
    let service_session = session.clone();
    let service = service_fn(move |inner| {
        let state = service_state.clone();
        let session = service_session.clone();
        async move {
            let response = match forward_request(state, inner, session, Some(scheme)).await {
                Ok(response) => response,
                Err(error) => proxy_error_response(error),
            };
            Ok::<_, Infallible>(response)
        }
    });
    let shutdown = state.shutdown.clone();
    let revocation = async move {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if !capture_session_active(&state, &session).await {
                tracing::debug!(
                    session_id = session.id.get(),
                    "closing revoked CONNECT tunnel"
                );
                break;
            }
        }
    };
    let builder = AutoServerBuilder::new(TokioExecutor::new());
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    tokio::select! {
        _ = shutdown.cancelled() => {}
        _ = revocation => {}
        result = connection => {
            if let Err(error) = result {
                tracing::debug!(%error, "intercepted CONNECT closed");
            }
        }
    }
}

async fn capture_session_active(state: &AppState, session: &CaptureSession) -> bool {
    let project_id = session.project_id.get();
    let session_id = session.id.get();
    let now = crate::storage::now_rfc3339();
    state
        .db
        .with_conn(move |connection| {
            let active: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_sessions
                     WHERE id=?1 AND project_id=?2 AND status='active'
                       AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?3)",
                    rusqlite::params![session_id, project_id, now],
                    |row| row.get(0),
                )
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            Ok(active == 1)
        })
        .await
        .unwrap_or(false)
}

fn proxy_error_response(error: DomainError) -> Response<ProxyBody> {
    if error.code() == ErrorCode::ProxyAuthRequired {
        let message = "Proxy authentication required";
        return Response::builder()
            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .header(PROXY_ERROR_HEADER, proxy_error_marker(message))
            .header("Cache-Control", "no-store")
            .header("Content-Type", "text/plain; charset=utf-8")
            .header("Proxy-Authenticate", "Basic realm=\"HuntProxy\"")
            .header("Proxy-Authenticate", "Bearer")
            .body(full_body(Bytes::from_static(message.as_bytes())))
            .expect("static proxy auth response");
    }
    let status = match error.code() {
        ErrorCode::ScopeDenied | ErrorCode::DnsBlocked => StatusCode::FORBIDDEN,
        ErrorCode::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::Timeout => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::BAD_GATEWAY,
    };
    let message = proxy_error_message(&error);
    Response::builder()
        .status(status)
        .header(PROXY_ERROR_HEADER, proxy_error_marker(&message))
        .header("Cache-Control", "no-store")
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(full_body(Bytes::from(message)))
        .expect("static proxy error response")
}

fn proxy_error_marker(message: &str) -> String {
    format!(
        "v1:{}",
        base64::engine::general_purpose::STANDARD.encode(message)
    )
}

fn proxy_error_message(error: &DomainError) -> String {
    if let DomainError::App {
        details: Some(details),
        ..
    } = error
    {
        if let Some(detail) = details.get(crate::transport::UPSTREAM_PROXY_ERROR_DETAIL) {
            let host = detail
                .get("host")
                .and_then(|value| value.as_str())
                .and_then(|value| url::Host::parse(value).ok());
            let port = detail
                .get("port")
                .and_then(|value| value.as_u64())
                .and_then(|value| u16::try_from(value).ok());
            if let (Some(host), Some(port)) = (host, port) {
                let mut message = format!("upstream proxy {host}:{port} error");
                if let Some(code) = detail
                    .get("os_error")
                    .and_then(|value| value.as_i64())
                    .and_then(|value| i32::try_from(value).ok())
                {
                    message.push_str(&format!(": {}", std::io::Error::from_raw_os_error(code)));
                }
                return message;
            }
        }
    }
    match error.code() {
        ErrorCode::ScopeDenied => "request denied by scope".into(),
        ErrorCode::DnsBlocked => "DNS lookup failed".into(),
        ErrorCode::BodyTooLarge => "request body too large".into(),
        ErrorCode::Timeout => "request timed out".into(),
        ErrorCode::Unavailable => "upstream unavailable".into(),
        ErrorCode::ProtocolError => "upstream protocol error".into(),
        code => format!("proxy request failed ({})", code.as_str()),
    }
}

struct MitmAuthority {
    ca_certificate: rcgen::Certificate,
    ca_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl MitmAuthority {
    fn load(state: &AppState) -> DomainResult<Self> {
        let cert_pem = std::fs::read_to_string(state.config.ca_cert_path()).map_err(|error| {
            DomainError::new(ErrorCode::ConfigInvalid, format!("read proxy CA: {error}"))
        })?;
        let key_pem = std::fs::read_to_string(state.config.ca_key_path()).map_err(|error| {
            DomainError::new(
                ErrorCode::ConfigInvalid,
                format!("read proxy CA key: {error}"),
            )
        })?;
        let ca_key = KeyPair::from_pem(&key_pem).map_err(|error| {
            DomainError::new(
                ErrorCode::ConfigInvalid,
                format!("parse proxy CA key: {error}"),
            )
        })?;
        let ca_params = CertificateParams::from_ca_cert_pem(&cert_pem).map_err(|error| {
            DomainError::new(ErrorCode::ConfigInvalid, format!("parse proxy CA: {error}"))
        })?;
        let ca_certificate = ca_params.self_signed(&ca_key).map_err(|error| {
            DomainError::new(ErrorCode::ConfigInvalid, format!("load proxy CA: {error}"))
        })?;
        Ok(Self {
            ca_certificate,
            ca_key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn server_config(&self, host: &str) -> DomainResult<Arc<rustls::ServerConfig>> {
        if let Some(config) = self
            .cache
            .lock()
            .map_err(|_| DomainError::new(ErrorCode::Internal, "certificate cache poisoned"))?
            .get(host)
            .cloned()
        {
            return Ok(config);
        }

        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, host);
        params.distinguished_name = distinguished_name;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate()
            .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?;
        let leaf = params
            .signed_by(&leaf_key, &self.ca_certificate, &self.ca_key)
            .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(leaf.der().to_vec())], key)
            .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = Arc::new(config);
        self.cache
            .lock()
            .map_err(|_| DomainError::new(ErrorCode::Internal, "certificate cache poisoned"))?
            .insert(host.to_string(), config.clone());
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::BrowserService;
    use crate::config::Config;
    use crate::fuzzer::FuzzerService;
    use crate::reply::{PlaceholderKey, ReplyService};
    use crate::storage::{CreateCaptureSession, Db};
    use crate::transport::build_default_transport;

    async fn proxy_test_fixture(
        directory: &tempfile::TempDir,
    ) -> (Arc<AppState>, Project, CaptureSession) {
        let mut config = Config::default();
        config.data_dir = directory.path().join("data");
        config.spool_dir = config.data_dir.join("spool");
        config.export_dir = config.data_dir.join("exports");
        config.runtime_dir = config.data_dir.join("runtime");
        config.plugin_dir = config.data_dir.join("plugins");
        config.ensure_layout().unwrap();
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params =
            rcgen::CertificateParams::new(vec!["HuntProxy test CA".into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        crate::config::write_private_file(&config.ca_cert_path(), ca_cert.pem().as_bytes())
            .unwrap();
        crate::config::write_private_file(&config.ca_key_path(), ca_key.serialize_pem().as_bytes())
            .unwrap();
        let worker = directory.path().join("worker.js");
        std::fs::write(&worker, "// test worker").unwrap();

        let db = Arc::new(Db::open(&config).await.unwrap());
        let transport = build_default_transport(config.max_body_bytes);
        let key = PlaceholderKey::from_bytes(vec![7; 32]);
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: transport.clone(),
            placeholder_key: key.clone(),
            upstream_proxies: Default::default(),
        });
        let fuzzer = Arc::new(FuzzerService::new(db.clone(), reply.clone(), key));
        let browser = Arc::new(BrowserService::new_with_proxy_and_ca(
            db.clone(),
            None,
            Some(worker),
            "http://127.0.0.1:17891".into(),
            None,
            config.browser_profiles_dir(),
        ));
        let (events, _) = tokio::sync::broadcast::channel(8);
        let crawler = Arc::new(crate::crawler::CrawlerService::new(
            db.clone(),
            reply.clone(),
            browser.clone(),
            events.clone(),
        ));
        let plugins = Arc::new(
            crate::plugins::PluginService::load(
                config.plugin_dir.clone(),
                db.clone(),
                reply.clone(),
            )
            .unwrap(),
        );
        let state = Arc::new(AppState {
            db: db.clone(),
            config,
            transport,
            transport_status: crate::app::TransportStatus::for_browser_version(Some("149.0.0.0")),
            reply,
            fuzzer,
            browser,
            crawler,
            plugins,
            websocket: Arc::new(crate::websocket::WebSocketService::new()),
            events,
            shutdown: CancellationToken::new(),
            activity: crate::app::ActivityTracker::new(),
        });
        let project = db
            .create_project(CreateProjectRequest {
                name: "streaming proxy".into(),
                target_url: "https://example.com/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let session = db
            .create_capture_session(CreateCaptureSession {
                project_id: project.id,
                browser_session_id: None,
                browser_action_id: None,
                is_browser_bound: false,
                ttl: None,
            })
            .await
            .unwrap();
        (state, project, session)
    }

    async fn wait_for_exchange(state: &AppState, project_id: ProjectId) -> ExchangeDetail {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let (items, _) = state
                    .db
                    .list_history(project_id, 10, None, None)
                    .await
                    .unwrap();
                if let Some(item) = items.first() {
                    break state
                        .db
                        .get_exchange_detail(
                            project_id,
                            item.exchange_id,
                            crate::policy::PresentationOptions::default(),
                        )
                        .await
                        .unwrap();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("streamed evidence should finalize promptly")
    }

    #[tokio::test]
    async fn chrome_background_matcher_is_narrow_and_session_bound() {
        let directory = tempfile::tempdir().unwrap();
        let (_, _, mut session) = proxy_test_fixture(&directory).await;
        session.browser_session_id = Some(BrowserSessionId(1));
        let cases = [
            ("POST", "https://android.clients.google.com/checkin", true),
            (
                "POST",
                "https://android.clients.google.com/c2dm/register3",
                true,
            ),
            (
                "POST",
                "https://accounts.google.com/ListAccounts?foo=1&source=ChromiumBrowser",
                true,
            ),
            ("GET", "https://www.google.com/async/folae", true),
            (
                "GET",
                "https://content-autofill.googleapis.com/v1/pages/example",
                true,
            ),
            (
                "POST",
                "https://content-autofill.googleapis.com/v1/forms:vote?alt=proto",
                true,
            ),
            (
                "GET",
                "https://content-autofill.googleapis.com/v1/forms:vote",
                false,
            ),
            (
                "POST",
                "https://content-autofill.googleapis.com/v1/forms/vote",
                false,
            ),
            ("POST", "https://android.clients.google.com/other", false),
            ("POST", "https://accounts.google.com/ListAccounts", false),
            (
                "POST",
                "https://accounts.google.com/ListAccounts?source=OtherChromiumBrowser",
                false,
            ),
            ("GET", "https://android.clients.google.com/checkin", false),
            ("POST", "http://android.clients.google.com/checkin", false),
            (
                "POST",
                "https://accounts.google.com.evil.test/ListAccounts?source=ChromiumBrowser",
                false,
            ),
            (
                "GET",
                "https://content-autofill.googleapis.com/v1/pages",
                false,
            ),
            ("GET", "https://www.google.com:444/async/folae", false),
        ];
        for (method, url, expected) in cases {
            assert_eq!(
                is_chrome_background_request(
                    &session,
                    &TargetRef::from_url(url).unwrap(),
                    &method.parse().unwrap()
                ),
                expected,
                "{method} {url}"
            );
        }
        session.browser_session_id = None;
        assert!(!is_chrome_background_request(
            &session,
            &TargetRef::from_url("https://android.clients.google.com/checkin").unwrap(),
            &Method::POST
        ));
        assert!(!is_chrome_background_request(
            &session,
            &TargetRef::from_url("https://content-autofill.googleapis.com/v1/forms:vote?alt=proto")
                .unwrap(),
            &Method::POST
        ));
    }

    #[test]
    fn own_api_target_matches_listener_port_and_hosts() {
        let listener = "127.0.0.1:17890".parse().unwrap();
        for (url, expected) in [
            ("http://localhost:17890/", true),
            ("http://127.0.0.1:17890/api", true),
            ("http://127.0.0.2:17890/", true),
            ("http://[::1]:17890/", true),
            ("http://192.0.2.10:17890/", false),
            ("http://192.0.2.11:17890/", false),
            ("http://localhost:17891/", false),
            ("http://localhost.example:17890/", false),
        ] {
            assert_eq!(
                is_own_api_target(&TargetRef::from_url(url).unwrap(), listener),
                expected,
                "{url}"
            );
        }
        let specific = "192.0.2.10:17890".parse().unwrap();
        assert!(is_own_api_target(
            &TargetRef::from_url("http://192.0.2.10:17890/").unwrap(),
            specific
        ));
        assert!(!is_own_api_target(
            &TargetRef::from_url("http://127.0.0.1:17890/").unwrap(),
            specific
        ));
        let wildcard = "0.0.0.0:17890".parse().unwrap();
        assert!(!is_own_api_target(
            &TargetRef::from_url("http://192.0.2.11:17890/").unwrap(),
            wildcard
        ));
    }

    #[tokio::test]
    async fn project_hint_is_bound_to_own_api_and_spoofed_headers_are_removed() {
        use crate::request_rules::{
            RequestRuleInput, RequestRuleMatchKind, RequestRuleOperation, RequestRuleTarget,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        async fn send(proxy: SocketAddr, url: &str, token: &str) -> String {
            let mut socket = TcpStream::connect(proxy).await.unwrap();
            socket.write_all(format!(
                "GET {url} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Bearer {token}\r\nX-HuntProxy-Project-Id: 999\r\nConnection: close\r\n\r\n",
                url::Url::parse(url).unwrap().authority()
            ).as_bytes()).await.unwrap();
            let mut response = Vec::new();
            socket.read_to_end(&mut response).await.unwrap();
            String::from_utf8(response).unwrap().to_ascii_lowercase()
        }

        async fn run_origin(listener: TcpListener, seen: mpsc::UnboundedSender<String>) {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                    let read = socket.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                seen.send(String::from_utf8(request).unwrap().to_ascii_lowercase())
                    .unwrap();
                socket.write_all(b"HTTP/1.1 200 OK\r\nX-HuntProxy-Project-Id: 999\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let (mut state, project, session) = proxy_test_fixture(&directory).await;
        let own = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let own_addr = own.local_addr().unwrap();
        let external = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let external_addr = external.local_addr().unwrap();
        Arc::get_mut(&mut state).unwrap().config.api_listen = own_addr;
        let (own_tx, mut own_rx) = mpsc::unbounded_channel();
        let (external_tx, mut external_rx) = mpsc::unbounded_channel();
        let own_server = tokio::spawn(run_origin(own, own_tx));
        let external_server = tokio::spawn(run_origin(external, external_tx));
        let listener = bind_proxy("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let proxy = tokio::spawn(serve_proxy_listener(
            state.clone(),
            listener,
            cancel.clone(),
        ));
        let token = session.token_once.as_deref().unwrap();
        let own_base = format!("http://localhost:{}", own_addr.port());
        let external_base = format!("http://{external_addr}");

        // Internal UI requests work even if the project's upstream is unavailable.
        state
            .db
            .set_project_upstream_proxy(project.id, Some("http://127.0.0.1:9".into()))
            .await
            .unwrap();
        for path in ["/", "/api/v1/projects/1", "/api/v1/projects"] {
            let response = send(proxy_addr, &format!("{own_base}{path}"), token).await;
            assert!(response.starts_with("http/1.1 200"), "{response}");
            let hints: Vec<_> = response
                .lines()
                .filter(|line| line.starts_with("x-huntproxy-project-id:"))
                .collect();
            if path == "/api/v1/projects" {
                assert_eq!(
                    hints,
                    vec![format!("x-huntproxy-project-id: {}", project.id.get())]
                );
            } else {
                assert!(hints.is_empty(), "{response}");
            }
            assert!(!own_rx
                .recv()
                .await
                .unwrap()
                .contains("x-huntproxy-project-id:"));
        }
        let response = send(
            proxy_addr,
            &format!("{external_base}/api/v1/projects"),
            token,
        )
        .await;
        assert!(
            !response.starts_with("http/1.1 200"),
            "external traffic bypassed its upstream"
        );

        // A URL rewrite in either direction must not turn external traffic into
        // trusted daemon traffic or bypass the configured upstream.
        for (from, to) in [
            (
                format!("{own_base}/api/v1/projects"),
                format!("{external_base}/api/v1/projects"),
            ),
            (
                format!("{external_base}/api/v1/projects"),
                format!("{own_base}/api/v1/projects"),
            ),
        ] {
            let rule = state
                .db
                .create_request_rule(
                    project.id,
                    RequestRuleInput {
                        name: "route test".into(),
                        enabled: true,
                        position: 0,
                        host_pattern: None,
                        target: RequestRuleTarget::Url,
                        operation: RequestRuleOperation::Replace,
                        header_name: None,
                        match_kind: RequestRuleMatchKind::Literal,
                        pattern: from.clone(),
                        replacement: Some(to),
                        replace_all: true,
                    },
                )
                .await
                .unwrap();
            let response = send(proxy_addr, &from, token).await;
            assert!(
                !response.starts_with("http/1.1 200"),
                "rewrite bypassed its upstream"
            );
            assert!(!response.contains("x-huntproxy-project-id:"));
            state
                .db
                .delete_request_rule(project.id, rule.id)
                .await
                .unwrap();
        }

        state
            .db
            .set_project_upstream_proxy(project.id, None)
            .await
            .unwrap();
        let response = send(
            proxy_addr,
            &format!("{external_base}/api/v1/projects"),
            token,
        )
        .await;
        assert!(response.starts_with("http/1.1 200"), "{response}");
        assert!(!response.contains("x-huntproxy-project-id:"));
        assert!(!external_rx
            .recv()
            .await
            .unwrap()
            .contains("x-huntproxy-project-id:"));

        cancel.cancel();
        proxy.await.unwrap().unwrap();
        own_server.abort();
        external_server.abort();
    }

    #[tokio::test]
    async fn own_api_is_forwarded_without_http_or_websocket_history() {
        use futures::SinkExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

        let directory = tempfile::tempdir().unwrap();
        let (mut state, project, external) = proxy_test_fixture(&directory).await;
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        Arc::get_mut(&mut state).unwrap().config.api_listen = origin_addr;
        let browser = state
            .db
            .create_browser_session(project.id, Some("default".into()))
            .await
            .unwrap();
        let browser_capture = state
            .db
            .create_capture_session(CreateCaptureSession {
                project_id: project.id,
                browser_session_id: Some(browser.id),
                browser_action_id: None,
                is_browser_bound: true,
                ttl: None,
            })
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = origin.accept().await.unwrap();
                let mut request = [0; 4096];
                let read = socket.read(&mut request).await.unwrap();
                assert!(String::from_utf8_lossy(&request[..read]).contains("/api/v1/projects"));
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            }
            let (socket, _) = origin.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            let message = ws.next().await.unwrap().unwrap();
            ws.send(message).await.unwrap();
        });
        let listener = bind_proxy("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let proxy = tokio::spawn(serve_proxy_listener(
            state.clone(),
            listener,
            cancel.clone(),
        ));
        for session in [&external, &browser_capture] {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            client.write_all(format!("GET http://{origin_addr}/api/v1/projects HTTP/1.1\r\nHost: {origin_addr}\r\nProxy-Authorization: Bearer {}\r\nConnection: close\r\n\r\n", session.token_once.as_deref().unwrap()).as_bytes()).await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(String::from_utf8_lossy(&response).ends_with("ok"));
        }
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut request = format!("ws://{origin_addr}/events")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "proxy-authorization",
            format!("Bearer {}", external.token_once.as_deref().unwrap())
                .parse()
                .unwrap(),
        );
        let (mut ws, _) = tokio_tungstenite::client_async(request, stream)
            .await
            .unwrap();
        ws.send(Message::Text("hello".into())).await.unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap().into_text().unwrap(),
            "hello"
        );
        server.await.unwrap();
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(format!("GET http://{origin_addr}/api/v1/projects HTTP/1.1\r\nHost: {origin_addr}\r\nProxy-Authorization: Bearer {}\r\nConnection: close\r\n\r\n", external.token_once.as_deref().unwrap()).as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(!String::from_utf8_lossy(&response).contains("200 OK"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(state
            .db
            .list_history(project.id, 10, None, None)
            .await
            .unwrap()
            .0
            .is_empty());
        assert!(state
            .db
            .list_websocket_connections(project.id, 10)
            .await
            .unwrap()
            .is_empty());
        cancel.cancel();
        proxy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn chrome_background_is_forwarded_but_only_external_capture_is_saved() {
        use crate::storage::IpRotationGateway;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let directory = tempfile::tempdir().unwrap();
        let (state, project, external) = proxy_test_fixture(&directory).await;
        let browser = state
            .db
            .create_browser_session(project.id, Some("default".into()))
            .await
            .unwrap();
        let browser_capture = state
            .db
            .create_capture_session(CreateCaptureSession {
                project_id: project.id,
                browser_session_id: Some(browser.id),
                browser_action_id: None,
                is_browser_bound: true,
                ttl: None,
            })
            .await
            .unwrap();
        let gateway = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_addr = gateway.local_addr().unwrap();
        state
            .db
            .activate_ip_rotation(
                project.id,
                "https://android.clients.google.com".into(),
                "huntproxy".into(),
                vec![IpRotationGateway {
                    region: "local".into(),
                    rest_api_id: "test-gateway".into(),
                    endpoint: format!("http://{gateway_addr}/huntproxy"),
                }],
            )
            .await
            .unwrap();
        let observed = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = gateway.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let read = socket.read(&mut chunk).await.unwrap();
                    assert!(read > 0);
                    bytes.extend_from_slice(&chunk[..read]);
                    if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                assert!(String::from_utf8_lossy(&bytes)
                    .starts_with("POST /huntproxy/checkin HTTP/1.1\r\n"));
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            }
        });
        let listener = bind_proxy("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let proxy = tokio::spawn(serve_proxy_listener(
            state.clone(),
            listener,
            cancel.clone(),
        ));
        let mut events = state.events.subscribe();
        let usage_before = state.db.project_usage(project.id).await.unwrap();
        for (index, session) in [&browser_capture, &external].iter().enumerate() {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            client.write_all(format!("POST https://android.clients.google.com/checkin HTTP/1.1\r\nHost: android.clients.google.com\r\nProxy-Authorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", session.token_once.as_deref().unwrap()).as_bytes()).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(String::from_utf8_lossy(&response).contains("ok"));
            if index == 0 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let (items, _) = state
                    .db
                    .list_history(project.id, 10, None, None)
                    .await
                    .unwrap();
                assert!(items.is_empty());
                let usage_after = state.db.project_usage(project.id).await.unwrap();
                assert_eq!(usage_before.quota_used_bytes, usage_after.quota_used_bytes);
                assert_eq!(usage_after.exchange_count, 0);
                assert!(events.try_recv().is_err());
                assert_eq!(
                    std::fs::read_dir(&state.config.spool_dir).unwrap().count(),
                    0
                );
                let rows: (i64, i64) = state
                    .db
                    .with_conn(|conn| {
                        Ok((
                            conn.query_row("SELECT count(*) FROM search_fts", [], |row| row.get(0))
                                .unwrap(),
                            conn.query_row("SELECT count(*) FROM bodies", [], |row| row.get(0))
                                .unwrap(),
                        ))
                    })
                    .await
                    .unwrap();
                assert_eq!(rows, (0, 0));
            }
        }
        let detail = wait_for_exchange(&state, project.id).await;
        assert_eq!(detail.summary.path, "/checkin");
        assert_eq!(detail.lineage.capture_session_id, Some(external.id));
        observed.await.unwrap();
        cancel.cancel();
        proxy.await.unwrap().unwrap();
    }

    #[test]
    fn absolute_and_origin_form_urls() {
        let request = Request::builder()
            .uri("/a?b=1")
            .header("host", "example.com")
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        assert_eq!(
            request_url(&parts, Some("https")).unwrap(),
            "https://example.com/a?b=1"
        );
    }

    #[tokio::test]
    async fn intercepted_http2_request_can_reach_an_http1_only_origin() {
        let directory = tempfile::Builder::new()
            .prefix("hp-protocol-")
            .tempdir()
            .unwrap();
        let (state, _, session) = proxy_test_fixture(&directory).await;
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let origin_server = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let service = service_fn(|request: Request<Incoming>| async move {
                assert_eq!(request.version(), http::Version::HTTP_11);
                assert_eq!(request.headers()["user-agent"], "Chrome/149.0.0.0");
                assert!(!request.headers().contains_key("sec-ch-ua"));
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"origin ok"))))
            });
            http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        // Exercise the same forwarding handler used after CONNECT decryption,
        // receiving a real HTTP/2 request and negotiating the origin separately.
        let intercepted = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let intercepted_addr = intercepted.local_addr().unwrap();
        let proxy_server = tokio::spawn(async move {
            let (stream, _) = intercepted.accept().await.unwrap();
            let service = service_fn(move |request: Request<Incoming>| {
                assert_eq!(request.version(), http::Version::HTTP_2);
                let state = state.clone();
                let session = session.clone();
                async move {
                    let response = forward_request(state, request, session, None)
                        .await
                        .unwrap_or_else(proxy_error_response);
                    Ok::<_, Infallible>(response)
                }
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        let stream = tokio::net::TcpStream::connect(intercepted_addr)
            .await
            .unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        let client_connection = tokio::spawn(connection);
        let request = Request::builder()
            .uri(format!("http://{origin_addr}/registration"))
            .header("user-agent", "Chrome/149.0.0.0")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), http::Version::HTTP_2);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "origin ok"
        );
        origin_server.await.unwrap();
        client_connection.abort();
        proxy_server.abort();
    }

    #[tokio::test]
    async fn proxy_rotates_enabled_origin_and_preserves_original_history() {
        use crate::storage::IpRotationGateway;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let directory = tempfile::tempdir().unwrap();
        let (state, project, session) = proxy_test_fixture(&directory).await;
        let gateway = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_addr = gateway.local_addr().unwrap();
        state
            .db
            .activate_ip_rotation(
                project.id,
                "https://example.com".into(),
                "huntproxy".into(),
                vec![IpRotationGateway {
                    region: "us-east-1".into(),
                    rest_api_id: "test-gateway".into(),
                    endpoint: format!("http://{gateway_addr}/huntproxy"),
                }],
            )
            .await
            .unwrap();

        let observed = tokio::spawn(async move {
            let (mut socket, _) = gateway.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..read]);
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nrotated",
                )
                .await
                .unwrap();
            String::from_utf8(bytes).unwrap()
        });

        let listener = bind_proxy("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let proxy = tokio::spawn(serve_proxy_listener(
            state.clone(),
            listener,
            cancel.clone(),
        ));
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                format!(
                    "GET https://example.com/rotated?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Bearer {}\r\nConnection: close\r\n\r\n",
                    session.token_once.as_deref().unwrap()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response).contains("rotated"));

        let wire_request = observed.await.unwrap();
        assert!(wire_request.starts_with("GET /huntproxy/rotated?q=1 HTTP/1.1\r\n"));
        assert!(wire_request
            .lines()
            .any(|line| line.eq_ignore_ascii_case(&format!("host: {gateway_addr}"))));
        assert!(!wire_request
            .lines()
            .any(|line| line.eq_ignore_ascii_case("host: example.com")));

        let detail = wait_for_exchange(&state, project.id).await;
        assert_eq!(detail.summary.scheme, "https");
        assert_eq!(detail.summary.host, "example.com");
        assert_eq!(detail.summary.path, "/rotated");
        assert_eq!(detail.summary.query.as_deref(), Some("q=1"));
        let exchange_id = detail.summary.exchange_id;
        let transport_profile = state
            .db
            .with_conn(move |connection| {
                connection
                    .query_row(
                        "SELECT transport_profile FROM exchanges WHERE project_id=?1 AND exchange_id=?2",
                        rusqlite::params![project.id.get(), exchange_id.get()],
                        |row| row.get::<_, Option<String>>(0),
                    )
                    .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))
            })
            .await
            .unwrap();
        assert!(transport_profile.unwrap().contains("+ip_rotate:us-east-1"));

        cancel.cancel();
        proxy.await.unwrap().unwrap();
    }

    async fn open_test_connect(
        proxy: SocketAddr,
        target: SocketAddr,
        token: &str,
    ) -> tokio::net::TcpStream {
        use tokio::io::AsyncReadExt;
        let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {token}\r\n\r\n").as_bytes()).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), async {
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                assert!(response.len() < 4096);
                response.push(stream.read_u8().await.unwrap());
            }
            response
        })
        .await
        .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        stream
    }

    #[allow(clippy::result_large_err)] // Tungstenite fixes the callback's error response type.
    async fn assert_websocket_proxy_captures_relays_and_injects_messages(tunneled: bool) {
        use futures::SinkExt;
        use tokio::net::TcpStream;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::Message;

        let directory = tempfile::tempdir().unwrap();
        let (state, project, session) = proxy_test_fixture(&directory).await;
        state
            .db
            .create_request_rule(
                project.id,
                crate::request_rules::RequestRuleInput {
                    name: "WebSocket marker".into(),
                    enabled: true,
                    position: 0,
                    host_pattern: None,
                    target: crate::request_rules::RequestRuleTarget::Header,
                    operation: crate::request_rules::RequestRuleOperation::Set,
                    header_name: Some("X-HuntProxy-Rule".into()),
                    match_kind: crate::request_rules::RequestRuleMatchKind::Literal,
                    pattern: String::new(),
                    replacement: Some("applied".into()),
                    replace_all: true,
                },
            )
            .await
            .unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (socket, _) = target.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_hdr_async(
                socket,
                |request: &http::Request<()>, mut response: http::Response<()>| {
                    assert_eq!(
                        request.headers()["sec-websocket-key"],
                        "dGhlIHNhbXBsZSBub25jZQ=="
                    );
                    assert_eq!(
                        request.headers()["sec-websocket-protocol"],
                        "updates, events"
                    );
                    assert!(!request.headers().contains_key("proxy-authorization"));
                    assert!(!request.headers().contains_key("sec-websocket-extensions"));
                    response
                        .headers_mut()
                        .insert("sec-websocket-protocol", "updates".parse().unwrap());
                    Ok(response)
                },
            )
            .await
            .unwrap();
            while let Some(message) = websocket.next().await {
                let message = message.unwrap();
                let closed = matches!(message, Message::Close(_));
                if closed {
                    break;
                }
                websocket.send(message).await.unwrap();
            }
        });

        let listener = bind_proxy("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let proxy = tokio::spawn(serve_proxy_listener(
            state.clone(),
            listener,
            cancel.clone(),
        ));
        let stream = if tunneled {
            open_test_connect(
                proxy_addr,
                target_addr,
                session.token_once.as_deref().unwrap(),
            )
            .await
        } else {
            TcpStream::connect(proxy_addr).await.unwrap()
        };
        let url = format!("ws://{target_addr}/events");
        let mut request = url.clone().into_client_request().unwrap();
        request.headers_mut().insert(
            "sec-websocket-key",
            "dGhlIHNhbXBsZSBub25jZQ==".parse().unwrap(),
        );
        request
            .headers_mut()
            .insert("sec-websocket-protocol", "updates, events".parse().unwrap());
        request.headers_mut().insert(
            "sec-websocket-extensions",
            "permessage-deflate".parse().unwrap(),
        );
        if !tunneled {
            request.headers_mut().insert(
                "proxy-authorization",
                format!("Bearer {}", session.token_once.as_deref().unwrap())
                    .parse()
                    .unwrap(),
            );
        }
        let (mut client, response) = tokio_tungstenite::client_async(request, stream)
            .await
            .unwrap();
        assert_eq!(response.headers()["sec-websocket-protocol"], "updates");
        client.send(Message::Text("hello".into())).await.unwrap();
        assert_eq!(
            client.next().await.unwrap().unwrap().into_text().unwrap(),
            "hello"
        );

        let connection = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(connection) = state
                    .db
                    .list_websocket_connections(project.id, 10)
                    .await
                    .unwrap()
                    .into_iter()
                    .next()
                {
                    break connection;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        state
            .websocket
            .send(project.id, connection.id, true, "text", "injected")
            .await
            .unwrap();
        assert_eq!(
            client.next().await.unwrap().unwrap().into_text().unwrap(),
            "injected"
        );
        client.close(None).await.unwrap();
        echo.await.unwrap();

        let messages = state
            .db
            .list_websocket_messages(project.id, connection.id, None, 20)
            .await
            .unwrap();
        assert!(messages.len() >= 4);
        assert!(messages
            .iter()
            .any(|message| message.direction == "injected_to_server"));
        let handshake_id = ExchangeId(connection.handshake_exchange_id.unwrap());
        let request_headers = state
            .db
            .load_raw_headers(project.id, handshake_id, MessageSide::Request)
            .await
            .unwrap();
        assert!(request_headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("x-huntproxy-rule") && header.value == b"applied"
        }));
        assert_eq!(
            state
                .db
                .list_exchange_request_rules(project.id, handshake_id)
                .await
                .unwrap()[0]
                .name,
            "WebSocket marker"
        );
        cancel.cancel();
        proxy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn websocket_proxy_captures_relays_and_injects_messages() {
        assert_websocket_proxy_captures_relays_and_injects_messages(false).await;
    }

    #[tokio::test]
    async fn connect_websocket_proxy_captures_relays_and_injects_messages() {
        assert_websocket_proxy_captures_relays_and_injects_messages(true).await;
    }

    #[tokio::test]
    async fn tls_connect_still_intercepts_and_forwards_http() {
        let directory = tempfile::tempdir().unwrap();
        let (state, project, session) = proxy_test_fixture(&directory).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (stream, _) = target.accept().await.unwrap();
            let service = service_fn(|request: Request<Incoming>| async move {
                assert_eq!(request.uri().path(), "/verification");
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                    b"verified TLS tunnel",
                ))))
            });
            http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });
        let listener = bind_proxy("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let proxy = tokio::spawn(serve_proxy_listener(
            state.clone(),
            listener,
            cancel.clone(),
        ));
        let stream = open_test_connect(
            proxy_addr,
            target_addr,
            session.token_once.as_deref().unwrap(),
        )
        .await;
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        let pem = std::fs::read(state.config.ca_cert_path()).unwrap();
        for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(&pem) {
            roots.add(certificate.unwrap()).unwrap();
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::IpAddress(
                    "127.0.0.1".parse::<std::net::IpAddr>().unwrap().into(),
                ),
                stream,
            )
            .await
            .unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        let client = tokio::spawn(connection);
        // Absolute-form HTTP remains accepted inside the intercepted TLS
        // stream, as before; the test origin needs no separate trust bypass.
        let response = sender
            .send_request(
                Request::builder()
                    .uri(format!("http://{target_addr}/verification"))
                    .header("host", target_addr.to_string())
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "verified TLS tunnel"
        );
        assert_eq!(
            wait_for_exchange(&state, project.id).await.summary.path,
            "/verification"
        );
        origin.await.unwrap();
        client.abort();
        cancel.cancel();
        proxy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connect_rejects_non_http_non_tls_starts_without_dialing_origin() {
        use tokio::io::AsyncReadExt;
        let directory = tempfile::tempdir().unwrap();
        let (state, _, session) = proxy_test_fixture(&directory).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = bind_proxy("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let proxy = tokio::spawn(serve_proxy_listener(state, listener, cancel.clone()));
        let mut stream = open_test_connect(
            proxy_addr,
            target.local_addr().unwrap(),
            session.token_once.as_deref().unwrap(),
        )
        .await;
        stream.write_all(&[0x01, 0x02]).await.unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), target.accept())
                .await
                .is_err()
        );
        cancel.cancel();
        proxy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn failed_websocket_handshakes_preserve_origin_evidence() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (origin_response, expected_status, expected_completion, expected_body) in [
            ("HTTP/1.1 403 Forbidden\r\nContent-Length: 12\r\nConnection: close\r\n\r\nplease retry", 403, CompletionState::Complete, Some(b"please retry".as_slice())),
            ("HTTP/1.1 403 Forbidden\r\nContent-Length: 30\r\nConnection: close\r\n\r\nplease retry", 403, CompletionState::ProtocolError, Some(b"please retry".as_slice())),
            ("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: incorrect\r\n\r\n", 101, CompletionState::ProtocolError, None),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let (state, project, session) = proxy_test_fixture(&directory).await;
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_addr = target.local_addr().unwrap();
            let origin = tokio::spawn(async move {
                let (mut socket, _) = target.accept().await.unwrap();
                let mut raw = Vec::new();
                loop {
                    let mut byte = [0]; socket.read_exact(&mut byte).await.unwrap(); raw.push(byte[0]);
                    if raw.ends_with(b"\r\n\r\n") { break; }
                }
                socket.write_all(origin_response.as_bytes()).await.unwrap();
            });
            let listener = bind_proxy("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let proxy_addr = listener.local_addr().unwrap();
            let cancel = CancellationToken::new();
            let proxy = tokio::spawn(serve_proxy_listener(state.clone(), listener, cancel.clone()));
            let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
            client.write_all(format!("GET http://{target_addr}/events HTTP/1.1\r\nHost: {target_addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nProxy-Authorization: Bearer {}\r\n\r\n", session.token_once.as_deref().unwrap()).as_bytes()).await.unwrap();
            let mut raw = Vec::new();
            loop {
                let mut byte = [0]; client.read_exact(&mut byte).await.unwrap(); raw.push(byte[0]);
                if raw.ends_with(b"\r\n\r\n") { break; }
            }
            let status = if expected_status == 101 { 502 } else { expected_status };
            assert!(String::from_utf8(raw).unwrap().starts_with(&format!("HTTP/1.1 {status} ")));
            let detail = wait_for_exchange(&state, project.id).await;
            assert_eq!(detail.summary.status_code, Some(expected_status));
            assert_eq!(detail.summary.completion, expected_completion);
            assert_eq!(detail.summary.capture_quality, CaptureQuality::Semantic);
            assert_eq!(state.db.load_raw_body(project.id, detail.summary.exchange_id, MessageSide::Response).await.unwrap().as_deref(), expected_body);
            assert!(state.db.list_websocket_connections(project.id, 10).await.unwrap().is_empty());
            origin.await.unwrap();
            cancel.cancel(); proxy.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn proxy_bind_reports_conflict_before_readiness() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let error = bind_proxy(occupied.local_addr().unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unavailable);
    }

    #[test]
    fn proxy_authentication_challenges_are_separate_header_fields() {
        let response = proxy_error_response(DomainError::new(
            ErrorCode::ProxyAuthRequired,
            "missing proxy credentials",
        ));
        let challenges = response
            .headers()
            .get_all("proxy-authenticate")
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(challenges, vec!["Basic realm=\"HuntProxy\"", "Bearer"]);
        assert_eq!(
            response.headers()[PROXY_ERROR_HEADER],
            proxy_error_marker("Proxy authentication required")
        );
    }

    #[tokio::test]
    async fn synthetic_proxy_errors_expose_only_safe_diagnostics() {
        let secret = "http://fixture-user:fixture-password@proxy.example:8080";
        let errors = vec![
            DomainError::new(ErrorCode::DnsBlocked, secret),
            DomainError::new(ErrorCode::BodyTooLarge, secret),
            DomainError::new(ErrorCode::Timeout, secret),
            DomainError::new(ErrorCode::Unavailable, secret),
            DomainError::new(ErrorCode::ProtocolError, secret),
            DomainError::Other(anyhow::anyhow!("nested cause: {secret}").context("outer error")),
            DomainError::with_details(
                ErrorCode::Unavailable,
                secret,
                serde_json::json!({ (crate::transport::UPSTREAM_PROXY_ERROR_DETAIL): {
                    "host": "fixture-user:fixture-password@proxy.example", "port": 8080,
                    "os_error": 111,
                }}),
            ),
        ];
        for error in errors {
            let response = proxy_error_response(error);
            let marker = response.headers()[PROXY_ERROR_HEADER]
                .to_str()
                .unwrap()
                .strip_prefix("v1:")
                .unwrap();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(marker)
                .unwrap();
            assert_eq!(response.headers()["cache-control"], "no-store");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(decoded.as_slice(), body.as_ref());
            let message = std::str::from_utf8(&body).unwrap();
            assert!(!message.contains("fixture-user"), "{message}");
            assert!(!message.contains("fixture-password"), "{message}");
            assert!(!message.contains("nested cause"), "{message}");
        }
        let safe = DomainError::with_details(
            ErrorCode::Unavailable,
            secret,
            serde_json::json!({ (crate::transport::UPSTREAM_PROXY_ERROR_DETAIL): {
                "host": "127.0.0.1", "port": 8080, "os_error": 111,
            }}),
        );
        let response = proxy_error_response(safe);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let message = std::str::from_utf8(&body).unwrap();
        assert!(message.contains("upstream proxy 127.0.0.1:8080 error"));
        assert!(message.contains(&std::io::Error::from_raw_os_error(111).to_string()));
        assert!(!message.contains("fixture-password"));
    }

    #[tokio::test]
    async fn origin_response_cannot_spoof_proxy_error_marker() {
        let directory = tempfile::tempdir().unwrap();
        let (state, _, session) = proxy_test_fixture(&directory).await;
        let response = streaming_response(
            state,
            session,
            TargetRef::from_url("https://example.com/").unwrap(),
            Method::GET,
            vec![],
            None,
            StreamingOutboundResponse {
                status: StatusCode::BAD_GATEWAY,
                headers: vec![
                    ("X-HuntProxy-Proxy-Error".into(), b"v1:Zm9yZ2Vk".to_vec()),
                    ("content-type".into(), b"text/plain".to_vec()),
                ],
                body: Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(
                    b"origin failure",
                ))])),
                protocol: "HTTP/1.1".into(),
                transport_provenance: TransportProvenance::ProtocolProfileOnly,
                transport_profile: "test".into(),
            },
            1024,
            std::time::Instant::now(),
            false,
            false,
            vec![],
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(!response.headers().contains_key(PROXY_ERROR_HEADER));
        assert_eq!(response.headers()["content-type"], "text/plain");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "origin failure"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires the installed Chromium browser runtime"]
    async fn browser_navigation_reports_real_proxy_failures_without_credentials() {
        use crate::browser::BrowserAction;
        use futures::FutureExt;

        let directory = tempfile::tempdir().unwrap();
        let (state, project, _) = proxy_test_fixture(&directory).await;
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            loop {
                let (stream, _) = origin.accept().await.unwrap();
                tokio::spawn(async move {
                    let service = service_fn(|request: Request<Incoming>| async move {
                        let status = match request.uri().path() {
                            "/missing" => StatusCode::NOT_FOUND,
                            "/server-error" => StatusCode::BAD_GATEWAY,
                            _ => StatusCode::OK,
                        };
                        let response = Response::builder()
                            .status(status)
                            .header(PROXY_ERROR_HEADER, "v1:Zm9yZ2Vk")
                            .header("cache-control", "no-store")
                            .body(Full::new(Bytes::from_static(b"local fixture")))
                            .unwrap();
                        Ok::<_, Infallible>(response)
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let proxy_task = tokio::spawn(serve_proxy_listener(
            state.clone(),
            listener,
            cancel.clone(),
        ));
        let service = BrowserService::new_with_proxy_and_ca(
            state.db.clone(),
            None,
            Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("browser-worker/index.js")),
            format!("http://{proxy_addr}"),
            Some(state.config.ca_cert_path()),
            directory.path().join("profiles"),
        );
        let session = service
            .start_ephemeral(project.id, "about:blank".into())
            .await
            .unwrap();
        let outcome = std::panic::AssertUnwindSafe(async {
            for (path, status) in [("/missing", 404), ("/server-error", 502)] {
                let result = service
                    .action(
                        project.id,
                        session.id,
                        BrowserAction::Navigate {
                            url: format!("http://{origin_addr}{path}"),
                        },
                    )
                    .await
                    .unwrap();
                assert!(result.ok);
                assert_eq!(result.data.unwrap()["status"], status);
            }
            let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let upstream_addr = unavailable.local_addr().unwrap();
            drop(unavailable);
            state
                .db
                .set_project_upstream_proxy(
                    project.id,
                    Some(format!(
                        "http://fixture-user:fixture-password@{upstream_addr}"
                    )),
                )
                .await
                .unwrap();
            let error = service
                .action(
                    project.id,
                    session.id,
                    BrowserAction::Navigate {
                        url: format!("http://{origin_addr}/failure"),
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), ErrorCode::Unavailable);
            let message = error.to_string();
            assert!(
                message.contains(&format!("upstream proxy {upstream_addr} error")),
                "{message}"
            );
            assert!(message.contains("Connection refused"), "{message}");
            assert!(!message.contains("fixture-user"), "{message}");
            assert!(!message.contains("fixture-password"), "{message}");
        })
        .catch_unwind()
        .await;
        let _ = service.stop(project.id, session.id).await;
        cancel.cancel();
        let _ = proxy_task.await;
        origin_task.abort();
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn spool_guard_removes_private_file_on_drop() {
        let directory = tempfile::tempdir().unwrap();
        let (spool, file) = create_private_spool(directory.path(), "cleanup").unwrap();
        let path = spool.path().to_path_buf();
        drop(file);
        assert!(path.exists());
        drop(spool);
        assert!(!path.exists());
    }

    #[test]
    fn internal_crawler_marker_is_private_and_browser_bound() {
        let mut browser_headers = http::HeaderMap::new();
        browser_headers.insert("x-huntproxy-internal-crawler", "1".parse().unwrap());
        assert!(take_internal_crawler_marker(&mut browser_headers, true));
        assert!(!browser_headers.contains_key("x-huntproxy-internal-crawler"));

        let mut external_headers = http::HeaderMap::new();
        external_headers.insert("x-huntproxy-internal-crawler", "1".parse().unwrap());
        assert!(!take_internal_crawler_marker(&mut external_headers, false));
        assert!(!external_headers.contains_key("x-huntproxy-internal-crawler"));
    }

    #[test]
    fn browser_origin_marker_is_private_validated_and_browser_bound() {
        let mut browser_headers = http::HeaderMap::new();
        browser_headers.insert(
            "x-huntproxy-browser-origin",
            "https://example.com".parse().unwrap(),
        );
        assert_eq!(
            take_browser_origin_marker(&mut browser_headers, true).unwrap(),
            Some("https://example.com".into())
        );
        assert!(!browser_headers.contains_key("x-huntproxy-browser-origin"));

        let mut external_headers = http::HeaderMap::new();
        external_headers.insert(
            "x-huntproxy-browser-origin",
            "not an origin".parse().unwrap(),
        );
        assert_eq!(
            take_browser_origin_marker(&mut external_headers, false).unwrap(),
            None
        );
        assert!(!external_headers.contains_key("x-huntproxy-browser-origin"));

        for invalid in [
            "file:///tmp/page",
            "https://user@example.com",
            "https://example.com/path",
            "https://example.com/?query=1",
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert("x-huntproxy-browser-origin", invalid.parse().unwrap());
            assert!(take_browser_origin_marker(&mut headers, true).is_err());
            assert!(!headers.contains_key("x-huntproxy-browser-origin"));
        }
    }

    #[test]
    fn browser_origin_constraint_survives_url_rewrites() {
        assert!(enforce_browser_request_origin(
            Some("https://example.com"),
            "https://example.com/api/items",
            false,
        )
        .is_ok());
        assert!(enforce_browser_request_origin(
            Some("https://example.com"),
            "https://example.com/rewritten",
            true,
        )
        .is_ok());
        let original_error = enforce_browser_request_origin(
            Some("https://example.com"),
            "https://other.example/api/items",
            false,
        )
        .unwrap_err();
        assert_eq!(original_error.code(), ErrorCode::ScopeDenied);
        let rewritten_error = enforce_browser_request_origin(
            Some("https://example.com"),
            "http://example.com/rewritten",
            true,
        )
        .unwrap_err();
        assert_eq!(rewritten_error.code(), ErrorCode::ScopeDenied);
        assert!(
            enforce_browser_request_origin(None, "https://other.example/api/items", true,).is_ok()
        );
    }

    #[tokio::test]
    async fn downstream_disconnect_finalizes_partial_evidence_and_cleans_spools() {
        let directory = tempfile::tempdir().unwrap();
        let (state, project, session) = proxy_test_fixture(&directory).await;
        let db = state.db.clone();
        let stream = async_stream::stream! {
            yield Ok(Bytes::from_static(b"first"));
            futures::future::pending::<()>().await;
        };
        let response = streaming_response(
            state.clone(),
            session,
            TargetRef::from_url("https://example.com/").unwrap(),
            Method::GET,
            vec![],
            None,
            StreamingOutboundResponse {
                status: StatusCode::OK,
                headers: vec![("content-type".into(), b"text/plain".to_vec())],
                body: Box::pin(stream),
                protocol: "HTTP/2".into(),
                transport_provenance: TransportProvenance::ProtocolProfileOnly,
                transport_profile: "test".into(),
            },
            1024,
            std::time::Instant::now(),
            true,
            false,
            vec![],
        )
        .unwrap();
        let mut body = response.into_body();
        let frame = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .expect("first response frame should stream before EOF")
            .unwrap()
            .unwrap();
        assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"first"));
        drop(body);

        let detail = wait_for_exchange(&state, project.id).await;
        assert_eq!(detail.summary.completion, CompletionState::Cancelled);
        assert_eq!(
            db.load_raw_body(
                project.id,
                detail.summary.exchange_id,
                MessageSide::Response
            )
            .await
            .unwrap()
            .unwrap(),
            b"first"
        );
        assert_eq!(
            std::fs::read_dir(&state.config.spool_dir).unwrap().count(),
            0
        );
    }

    #[tokio::test]
    async fn successful_stream_persists_body_and_cleans_spools() {
        let directory = tempfile::tempdir().unwrap();
        let (state, project, session) = proxy_test_fixture(&directory).await;
        let stream = futures::stream::iter(vec![
            Ok(Bytes::from_static(b"abc")),
            Ok(Bytes::from_static(b"def")),
        ]);
        let response = streaming_response(
            state.clone(),
            session,
            TargetRef::from_url("https://example.com/").unwrap(),
            Method::GET,
            vec![],
            None,
            StreamingOutboundResponse {
                status: StatusCode::OK,
                headers: vec![],
                body: Box::pin(stream),
                protocol: "HTTP/2".into(),
                transport_provenance: TransportProvenance::ProtocolProfileOnly,
                transport_profile: "test".into(),
            },
            1024,
            std::time::Instant::now(),
            true,
            false,
            vec![],
        )
        .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"abcdef")
        );
        let detail = wait_for_exchange(&state, project.id).await;
        assert_eq!(detail.summary.completion, CompletionState::Complete);
        assert_eq!(
            state
                .db
                .load_raw_body(
                    project.id,
                    detail.summary.exchange_id,
                    MessageSide::Response
                )
                .await
                .unwrap()
                .unwrap(),
            b"abcdef"
        );
        assert_eq!(
            std::fs::read_dir(&state.config.spool_dir).unwrap().count(),
            0
        );
    }

    #[tokio::test]
    async fn out_of_scope_stream_is_delivered_without_being_persisted() {
        let directory = tempfile::tempdir().unwrap();
        let (state, project, session) = proxy_test_fixture(&directory).await;
        let response = streaming_response(
            state.clone(),
            session,
            TargetRef::from_url("http://127.0.0.1/internal").unwrap(),
            Method::GET,
            vec![],
            None,
            StreamingOutboundResponse {
                status: StatusCode::OK,
                headers: vec![],
                body: Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(b"ok"))])),
                protocol: "HTTP/1.1".into(),
                transport_provenance: TransportProvenance::ProtocolProfileOnly,
                transport_profile: "test".into(),
            },
            1024,
            std::time::Instant::now(),
            false,
            false,
            vec![],
        )
        .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"ok")
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (items, _) = state
            .db
            .list_history(project.id, 10, None, None)
            .await
            .unwrap();
        assert!(items.is_empty());
        assert_eq!(
            std::fs::read_dir(&state.config.spool_dir).unwrap().count(),
            0
        );
    }

    #[tokio::test]
    async fn upstream_stream_error_persists_partial_body_and_cleans_spools() {
        let directory = tempfile::tempdir().unwrap();
        let (state, project, session) = proxy_test_fixture(&directory).await;
        let stream = futures::stream::iter(vec![
            Ok(Bytes::from_static(b"partial")),
            Err(DomainError::new(
                ErrorCode::ProtocolError,
                "upstream failed",
            )),
        ]);
        let response = streaming_response(
            state.clone(),
            session,
            TargetRef::from_url("https://example.com/").unwrap(),
            Method::GET,
            vec![],
            None,
            StreamingOutboundResponse {
                status: StatusCode::OK,
                headers: vec![],
                body: Box::pin(stream),
                protocol: "HTTP/2".into(),
                transport_provenance: TransportProvenance::ProtocolProfileOnly,
                transport_profile: "test".into(),
            },
            1024,
            std::time::Instant::now(),
            true,
            false,
            vec![],
        )
        .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"partial")
        );
        let detail = wait_for_exchange(&state, project.id).await;
        assert_eq!(detail.summary.completion, CompletionState::ProtocolError);
        assert_eq!(
            state
                .db
                .load_raw_body(
                    project.id,
                    detail.summary.exchange_id,
                    MessageSide::Response
                )
                .await
                .unwrap()
                .unwrap(),
            b"partial"
        );
        assert_eq!(
            std::fs::read_dir(&state.config.spool_dir).unwrap().count(),
            0
        );
    }
}
