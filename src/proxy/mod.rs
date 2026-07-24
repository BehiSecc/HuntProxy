//! Explicit HTTP proxy with capture-session auth and ValidatedDial dialing.

use crate::app::AppState;
use crate::domain::*;
use crate::policy::scope::{resolve_validated_dial, TargetRef};
use crate::storage::{extract_proxy_token, NewExchange};
use crate::transport::{OutboundRequest, ProtocolMode};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

pub async fn serve_proxy(state: Arc<AppState>, cancel: CancellationToken) -> DomainResult<()> {
    let addr = state.config.proxy_listen;
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        DomainError::new(ErrorCode::Unavailable, format!("proxy bind {addr}: {e}"))
    })?;
    tracing::info!(%addr, "proxy listening");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error=%e, "proxy accept failed");
                        continue;
                    }
                };
                let state = state.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let state = state.clone();
                        async move { handle(state, req, peer).await }
                    });
                    let conn = http1::Builder::new().serve_connection(io, svc).with_upgrades();
                    tokio::select! {
                        _ = cancel.cancelled() => {}
                        r = conn => {
                            if let Err(e) = r {
                                tracing::debug!(error=%e, "proxy connection closed");
                            }
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle(
    state: Arc<AppState>,
    req: Request<Incoming>,
    _peer: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match handle_inner(state, req).await {
        Ok(r) => Ok(r),
        Err(e) => {
            if e.code() == ErrorCode::ProxyAuthRequired {
                Ok(Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header("Proxy-Authenticate", "Basic realm=\"bb\", Bearer")
                    .body(Full::new(Bytes::from("Proxy authentication required")))
                    .unwrap())
            } else {
                let status = match e.code() {
                    ErrorCode::ScopeDenied
                    | ErrorCode::PrivateNetworkBlocked
                    | ErrorCode::DnsBlocked => StatusCode::FORBIDDEN,
                    ErrorCode::Timeout => StatusCode::GATEWAY_TIMEOUT,
                    _ => StatusCode::BAD_GATEWAY,
                };
                Ok(Response::builder()
                    .status(status)
                    .body(Full::new(Bytes::from(e.to_string())))
                    .unwrap())
            }
        }
    }
}

async fn handle_inner(
    state: Arc<AppState>,
    mut req: Request<Incoming>,
) -> DomainResult<Response<Full<Bytes>>> {
    // Authenticate
    let auth = req
        .headers()
        .get("proxy-authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            DomainError::new(ErrorCode::ProxyAuthRequired, "missing Proxy-Authorization")
        })?;
    let token = extract_proxy_token(auth).ok_or_else(|| {
        DomainError::new(ErrorCode::ProxyAuthRequired, "invalid Proxy-Authorization")
    })?;
    let session = state.db.auth_capture_token(&token).await?;
    // Strip proxy auth
    req.headers_mut().remove("proxy-authorization");

    if req.method() == Method::CONNECT {
        return handle_connect(state, req, session).await;
    }

    // Absolute-form or origin-form HTTP proxy request
    let uri = req.uri().clone();
    let url = if uri.scheme().is_some() {
        uri.to_string()
    } else {
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| DomainError::invalid("missing Host"))?;
        format!("http://{host}{uri}")
    };

    let project = state.db.get_project(session.project_id).await?;
    let dial = resolve_validated_dial(&url, &project.scope, Duration::from_secs(60)).await?;

    let method = req.method().clone();
    let mut headers = Vec::new();
    for (name, value) in req.headers().iter() {
        if name.as_str().eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        headers.push((name.as_str().to_string(), value.as_bytes().to_vec()));
    }
    let body = req
        .into_body()
        .collect()
        .await
        .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?
        .to_bytes();

    let start = std::time::Instant::now();
    let out = state
        .transport
        .send(
            &dial,
            OutboundRequest {
                method: method.clone(),
                url: url.clone(),
                headers: headers.clone(),
                body: if body.is_empty() {
                    None
                } else {
                    Some(body.clone())
                },
                protocol: ProtocolMode::Auto,
                connect_timeout: Duration::from_secs(10),
                total_timeout: Duration::from_secs(60),
                max_body_bytes: project.limits.capture_body_bytes,
                preserve_identity_headers: true,
            },
        )
        .await?;

    let target = TargetRef::from_url(&url)?;
    let req_headers: Vec<HeaderEntry> = headers
        .iter()
        .enumerate()
        .map(|(i, (n, v))| HeaderEntry {
            name: n.clone(),
            value: v.clone(),
            ordinal: i as u32,
        })
        .collect();
    let resp_headers: Vec<HeaderEntry> = out
        .headers
        .iter()
        .enumerate()
        .map(|(i, (n, v))| HeaderEntry {
            name: n.clone(),
            value: v.clone(),
            ordinal: i as u32,
        })
        .collect();
    let mime = resp_headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-type"))
        .map(|h| String::from_utf8_lossy(&h.value).into_owned());

    let _eid = state
        .db
        .insert_exchange(NewExchange {
            project_id: session.project_id,
            source: ExchangeSource::Proxy,
            protocol: out.protocol.clone(),
            method: method.as_str().to_string(),
            scheme: target.scheme.clone(),
            authority: target.authority(),
            host: target.host.clone(),
            port: target.port,
            path: target.path.clone(),
            query: target.query.clone(),
            status_code: Some(out.status.as_u16()),
            mime,
            completion: CompletionState::Complete,
            capture_quality: CaptureQuality::Semantic,
            header_representation: HeaderRepresentation::Semantic,
            body_representation: BodyRepresentation::SemanticEncoded,
            cache_provenance: CacheProvenance::None,
            transport_provenance: Some(out.transport_provenance),
            transport_profile: Some(out.transport_profile.clone()),
            request_headers: req_headers,
            response_headers: resp_headers.clone(),
            request_body: if body.is_empty() {
                None
            } else {
                Some(body.to_vec())
            },
            response_body: Some(out.body.to_vec()),
            duration_ms: Some(start.elapsed().as_millis() as i64),
            lineage: ExchangeLineage {
                capture_session_id: Some(session.id),
                browser_session_id: session.browser_session_id,
                browser_action_id: session.browser_action_id,
                ..Default::default()
            },
            page_title: None,
            error_message: None,
        })
        .await?;

    let mut builder = Response::builder().status(out.status);
    for (n, v) in &out.headers {
        if n.eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        builder = builder.header(n.as_str(), v.as_slice());
    }
    Ok(builder.body(Full::new(out.body)).unwrap())
}

async fn handle_connect(
    state: Arc<AppState>,
    req: Request<Incoming>,
    session: CaptureSession,
) -> DomainResult<Response<Full<Bytes>>> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .ok_or_else(|| DomainError::invalid("CONNECT missing authority"))?;
    // CONNECT host:port — treat as https for scope scheme default
    let url = if authority.contains("://") {
        authority.clone()
    } else {
        format!("https://{authority}/")
    };
    let project = state.db.get_project(session.project_id).await?;
    let dial = resolve_validated_dial(&url, &project.scope, Duration::from_secs(60)).await?;
    let addr = *dial
        .approved_socket_addrs
        .first()
        .ok_or_else(|| DomainError::scope_denied("no approved address"))?;

    // Spawn tunnel after 200 response
    let cancel = state.shutdown.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Ok(upstream) = TcpStream::connect(addr).await {
                    let mut client = TokioIo::new(upgraded);
                    let mut server = upstream;
                    let _ = copy_bidirectional(&mut client, &mut server, cancel).await;
                }
            }
            Err(e) => tracing::debug!(error=%e, "CONNECT upgrade failed"),
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

async fn copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    cancel: CancellationToken,
) -> std::io::Result<()>
where
    A: AsyncReadExt + AsyncWriteExt + Unpin,
    B: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buf_a = [0u8; 16384];
    let mut buf_b = [0u8; 16384];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = a.read(&mut buf_a) => {
                let n = r?;
                if n == 0 { break; }
                b.write_all(&buf_a[..n]).await?;
            }
            r = b.read(&mut buf_b) => {
                let n = r?;
                if n == 0 { break; }
                a.write_all(&buf_b[..n]).await?;
            }
        }
    }
    Ok(())
}
