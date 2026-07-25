//! Explicit HTTP/HTTPS proxy with project-bound capture authentication.
//!
//! HTTPS CONNECT requests are intercepted with the local CA so decrypted
//! requests and responses are stored in History. Upstream traffic still goes
//! through the semantic transport and its `ValidatedDial` resolver.

use crate::app::AppState;
use crate::domain::*;
use crate::policy::scope::{resolve_validated_dial, url_is_in_scope, TargetRef};
use crate::storage::{extract_proxy_token, NewExchange};
use crate::transport::{OutboundBody, OutboundRequest, ProtocolMode, StreamingOutboundResponse};
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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

type ProxyBody = UnsyncBoxBody<Bytes, Infallible>;

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
    request: Request<Incoming>,
    session: CaptureSession,
    forced_scheme: Option<&str>,
) -> DomainResult<Response<ProxyBody>> {
    let project = state.db.get_project(session.project_id).await?;
    let (parts, incoming) = request.into_parts();
    let url = request_url(&parts, forced_scheme)?;
    let target = TargetRef::from_url(&url)?;
    let capture = url_is_in_scope(&url, &project.scope)?;
    let dial = resolve_validated_dial(&url, &project.scope, Duration::from_secs(60)).await?;
    let method = parts.method.clone();
    let protocol = if parts.version == http::Version::HTTP_2 {
        ProtocolMode::Http2
    } else {
        ProtocolMode::Auto
    };
    let headers = parts
        .headers
        .iter()
        .filter(|(name, _)| !name.as_str().eq_ignore_ascii_case("proxy-connection"))
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let request_spool = spool_request_body(
        incoming,
        project.limits.capture_body_bytes,
        &state.config.spool_dir,
    )
    .await?;
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
                method: method.clone(),
                url: url.clone(),
                headers: headers.clone(),
                body: request_body,
                protocol,
                connect_timeout: Duration::from_secs(10),
                total_timeout: Duration::from_secs(60),
                max_body_bytes: project.limits.capture_body_bytes,
                preserve_identity_headers: true,
            },
        )
        .await;

    let outbound = match outbound {
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
                )
                .await;
            }
            return Err(error);
        }
    };
    streaming_response(
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
    )
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
) {
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
                transport_profile: Some(state.transport.profile_name().into()),
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
) {
    let response_headers = header_entries(&outbound.headers);
    let mime = response_headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .map(|header| String::from_utf8_lossy(&header.value).into_owned());
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

    if !capture {
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
        let acceptor = TlsAcceptor::from(tls_config);
        let tls = match acceptor.accept(TokioIo::new(upgraded)).await {
            Ok(tls) => tls,
            Err(error) => {
                tracing::debug!(%error, "CONNECT TLS interception failed");
                return;
            }
        };
        let service_state = state.clone();
        let service_session = session.clone();
        let service = service_fn(move |inner| {
            let state = service_state.clone();
            let session = service_session.clone();
            async move {
                let response = match forward_request(state, inner, session, Some("https")).await {
                    Ok(response) => response,
                    Err(error) => proxy_error_response(error),
                };
                Ok::<_, Infallible>(response)
            }
        });
        let monitor_state = state.clone();
        let monitor_session = session.clone();
        let revocation = async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if !capture_session_active(&monitor_state, &monitor_session).await {
                    tracing::debug!(
                        session_id = monitor_session.id.get(),
                        "closing revoked CONNECT tunnel"
                    );
                    break;
                }
            }
        };
        let builder = AutoServerBuilder::new(TokioExecutor::new());
        let connection = builder.serve_connection(TokioIo::new(tls), service);
        tokio::select! {
            _ = shutdown.cancelled() => {}
            _ = revocation => {}
            result = connection => {
                if let Err(error) = result {
                    tracing::debug!(%error, "intercepted CONNECT closed");
                }
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(full_body(Bytes::new()))
        .expect("static CONNECT response"))
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
        return Response::builder()
            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .header("Proxy-Authenticate", "Basic realm=\"bb\"")
            .header("Proxy-Authenticate", "Bearer")
            .body(full_body(Bytes::from("Proxy authentication required")))
            .expect("static proxy auth response");
    }
    let status = match error.code() {
        ErrorCode::ScopeDenied | ErrorCode::DnsBlocked => StatusCode::FORBIDDEN,
        ErrorCode::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::Timeout => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::BAD_GATEWAY,
    };
    Response::builder()
        .status(status)
        .body(full_body(Bytes::from(error.to_string())))
        .expect("static proxy error response")
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
        config.ensure_layout().unwrap();
        let worker = directory.path().join("worker.js");
        std::fs::write(&worker, "// test worker").unwrap();

        let db = Arc::new(Db::open(&config).await.unwrap());
        let transport = build_default_transport(config.max_body_bytes);
        let key = PlaceholderKey::from_bytes(vec![7; 32]);
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: transport.clone(),
            placeholder_key: key.clone(),
        });
        let fuzzer = Arc::new(FuzzerService::new(db.clone(), reply.clone(), key));
        let browser = Arc::new(BrowserService::new_with_proxy_and_ca(
            db.clone(),
            None,
            None,
            Some(worker),
            "http://127.0.0.1:17891".into(),
            None,
        ));
        let (events, _) = tokio::sync::broadcast::channel(8);
        let state = Arc::new(AppState {
            db: db.clone(),
            config,
            transport,
            reply,
            fuzzer,
            browser,
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
        assert_eq!(challenges, vec!["Basic realm=\"bb\"", "Bearer"]);
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
