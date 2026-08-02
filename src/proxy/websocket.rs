use super::{full_body, header_entries, request_url, ProxyBody};
use crate::app::{AppEvent, AppState};
use crate::domain::*;
use crate::policy::scope::{resolve_validated_dial, url_is_in_scope, TargetRef};
use crate::storage::NewExchange;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{client_async_with_config, WebSocketStream};
use url::Url;

trait AsyncSocket: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncSocket for T {}
type BoxedSocket = Box<dyn AsyncSocket>;

pub(super) fn is_upgrade<B>(request: &Request<B>) -> bool {
    request
        .headers()
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && request
            .headers()
            .get(http::header::CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
}

pub(super) async fn handle(
    state: Arc<AppState>,
    mut request: Request<Incoming>,
    session: CaptureSession,
    forced_scheme: Option<&str>,
) -> DomainResult<Response<ProxyBody>> {
    let project = state.db.get_project(session.project_id).await?;
    let upgrade = hyper::upgrade::on(&mut request);
    let (parts, _body) = request.into_parts();
    let mut http_url = websocket_policy_url(&request_url(&parts, forced_scheme)?)?;
    let mut applied_rules =
        crate::request_rules::apply_url_rules(&state.db, session.project_id, &mut http_url).await?;
    let target = TargetRef::from_url(&http_url)?;
    let capture = url_is_in_scope(&http_url, &project.scope)?;
    let dial = resolve_validated_dial(&http_url, &project.scope, Duration::from_secs(60)).await?;
    let websocket_url = websocket_url(&http_url)?;
    let mut request_headers = parts
        .headers
        .iter()
        .filter(|(name, _)| !name.as_str().eq_ignore_ascii_case("proxy-connection"))
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    applied_rules.extend(
        crate::request_rules::apply_message_rules(
            &state.db,
            session.project_id,
            &http_url,
            &mut request_headers,
            None,
        )
        .await?,
    );
    let upstream_request = upstream_request(&websocket_url, &request_headers)?;
    let socket = connect_socket(&dial).await?;
    let cap = usize::try_from(project.limits.capture_body_bytes).unwrap_or(usize::MAX);
    let websocket_config = WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(16 * 1024)
        .max_message_size(Some(cap))
        .max_frame_size(Some(cap));
    let started = Instant::now();
    let (upstream, upstream_response) =
        client_async_with_config(upstream_request, socket, Some(websocket_config))
            .await
            .map_err(ws_error)?;

    let response_headers = upstream_response
        .headers()
        .iter()
        .filter(|(name, _)| {
            !name
                .as_str()
                .eq_ignore_ascii_case("sec-websocket-extensions")
        })
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let protocol = upstream_response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let handshake_exchange_id = if capture {
        match state
            .db
            .insert_exchange(NewExchange {
                project_id: session.project_id,
                source: ExchangeSource::Proxy,
                protocol: "HTTP/1.1".into(),
                method: "GET".into(),
                scheme: target.scheme.clone(),
                authority: target.authority(),
                host: target.host.clone(),
                port: target.port,
                path: target.path.clone(),
                query: target.query.clone(),
                status_code: Some(upstream_response.status().as_u16()),
                mime: None,
                completion: CompletionState::Complete,
                capture_quality: CaptureQuality::WirePreserved,
                header_representation: HeaderRepresentation::WirePreserved,
                body_representation: BodyRepresentation::Unavailable,
                cache_provenance: CacheProvenance::None,
                transport_provenance: Some(TransportProvenance::GenericUnprofiled),
                transport_profile: Some("websocket_raw_tunnel".into()),
                request_headers: header_entries(&request_headers),
                response_headers: header_entries(&response_headers),
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
                error_message: None,
            })
            .await
        {
            Ok(exchange_id) => {
                let _ = state
                    .db
                    .record_exchange_request_rules(
                        session.project_id,
                        exchange_id,
                        applied_rules.clone(),
                    )
                    .await;
                let _ = state.events.send(AppEvent {
                    project_id: session.project_id.get(),
                    kind: "exchange".into(),
                    payload: serde_json::json!({
                        "exchange_id": exchange_id.get(),
                        "source": "proxy",
                        "websocket": true,
                    }),
                });
                Some(exchange_id.get())
            }
            Err(error) => {
                tracing::warn!(%error, "could not save WebSocket handshake");
                None
            }
        }
    } else {
        None
    };

    let connection = if capture {
        match state
            .db
            .create_websocket_connection(
                session.project_id,
                handshake_exchange_id,
                websocket_url.clone(),
                protocol.clone(),
            )
            .await
        {
            Ok(connection) => Some(connection),
            Err(error) => {
                tracing::warn!(%error, "could not save WebSocket connection");
                None
            }
        }
    } else {
        None
    };

    let (inject_tx, inject_rx) = tokio::sync::mpsc::channel(64);
    if let Some(connection) = &connection {
        state
            .websocket
            .register(session.project_id, connection.id, inject_tx);
        let _ = state.events.send(AppEvent {
            project_id: session.project_id.get(),
            kind: "websocket".into(),
            payload: serde_json::json!({"connection_id": connection.id, "state": "open"}),
        });
    }

    let task_state = state.clone();
    let connection_id = connection.map(|connection| connection.id);
    tokio::spawn(async move {
        let result = match upgrade.await {
            Ok(client_socket) => {
                let client = WebSocketStream::from_raw_socket(
                    TokioIo::new(client_socket),
                    Role::Server,
                    Some(websocket_config),
                )
                .await;
                relay(
                    task_state.clone(),
                    session.project_id,
                    connection_id,
                    project.limits.capture_body_bytes,
                    client,
                    upstream,
                    inject_rx,
                )
                .await
            }
            Err(error) => Err(DomainError::new(
                ErrorCode::ProtocolError,
                error.to_string(),
            )),
        };
        if let Some(connection_id) = connection_id {
            task_state
                .websocket
                .unregister(session.project_id, connection_id);
            let error = result.as_ref().err().map(ToString::to_string);
            let _ = task_state
                .db
                .close_websocket_connection(session.project_id, connection_id, error.clone())
                .await;
            let _ = task_state.events.send(AppEvent {
                project_id: session.project_id.get(),
                kind: "websocket".into(),
                payload: serde_json::json!({
                    "connection_id": connection_id,
                    "state": if error.is_some() { "failed" } else { "closed" },
                }),
            });
        }
        if let Err(error) = result {
            tracing::debug!(%error, "WebSocket relay closed");
        }
    });

    let mut response = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (name, value) in response_headers {
        response = response.header(name, value);
    }
    response
        .body(full_body(Bytes::new()))
        .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))
}

async fn relay<C, U>(
    state: Arc<AppState>,
    project_id: ProjectId,
    connection_id: Option<i64>,
    capture_limit: u64,
    mut client: WebSocketStream<C>,
    mut upstream: WebSocketStream<U>,
    mut injected: tokio::sync::mpsc::Receiver<crate::websocket::InjectedMessage>,
) -> DomainResult<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            message = client.next() => {
                let Some(message) = message else { break; };
                let message = message.map_err(ws_error)?;
                save_message(&state, project_id, connection_id, "client_to_server", &message, capture_limit).await;
                let closed = matches!(message, Message::Close(_));
                upstream.send(message).await.map_err(ws_error)?;
                if closed { break; }
            }
            message = upstream.next() => {
                let Some(message) = message else { break; };
                let message = message.map_err(ws_error)?;
                save_message(&state, project_id, connection_id, "server_to_client", &message, capture_limit).await;
                let closed = matches!(message, Message::Close(_));
                client.send(message).await.map_err(ws_error)?;
                if closed { break; }
            }
            injection = injected.recv(), if connection_id.is_some() => {
                let Some(injection) = injection else { continue; };
                let direction = if injection.to_server { "injected_to_server" } else { "injected_to_client" };
                save_message(&state, project_id, connection_id, direction, &injection.message, capture_limit).await;
                if injection.to_server {
                    upstream.send(injection.message).await.map_err(ws_error)?;
                } else {
                    client.send(injection.message).await.map_err(ws_error)?;
                }
            }
        }
    }
    Ok(())
}

async fn save_message(
    state: &AppState,
    project_id: ProjectId,
    connection_id: Option<i64>,
    direction: &str,
    message: &Message,
    capture_limit: u64,
) {
    let Some(connection_id) = connection_id else {
        return;
    };
    let (opcode, payload) = message_payload(message);
    match state
        .db
        .insert_websocket_message(
            project_id,
            connection_id,
            direction,
            opcode,
            &payload,
            capture_limit,
        )
        .await
    {
        Ok(message_id) => {
            let _ = state.events.send(AppEvent {
                project_id: project_id.get(),
                kind: "websocket".into(),
                payload: serde_json::json!({
                    "connection_id": connection_id,
                    "message_id": message_id,
                    "direction": direction,
                }),
            });
        }
        Err(error) => tracing::warn!(%error, connection_id, "could not save WebSocket message"),
    }
}

fn message_payload(message: &Message) -> (&'static str, Vec<u8>) {
    match message {
        Message::Text(value) => ("text", value.as_str().as_bytes().to_vec()),
        Message::Binary(value) => ("binary", value.to_vec()),
        Message::Ping(value) => ("ping", value.to_vec()),
        Message::Pong(value) => ("pong", value.to_vec()),
        Message::Close(value) => (
            "close",
            value
                .as_ref()
                .map(|frame| format!("{} {}", u16::from(frame.code), frame.reason).into_bytes())
                .unwrap_or_default(),
        ),
        Message::Frame(_) => ("frame", Vec::new()),
    }
}

fn websocket_url(http_url: &str) -> DomainResult<String> {
    let mut url = Url::parse(http_url).map_err(|error| DomainError::invalid(error.to_string()))?;
    let scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        _ => return Err(DomainError::invalid("WebSocket URL must use HTTP or HTTPS")),
    };
    url.set_scheme(scheme)
        .map_err(|_| DomainError::invalid("invalid WebSocket scheme"))?;
    Ok(url.into())
}

fn websocket_policy_url(raw: &str) -> DomainResult<String> {
    let mut url = Url::parse(raw).map_err(|error| DomainError::invalid(error.to_string()))?;
    let scheme = match url.scheme() {
        "ws" => "http",
        "wss" => "https",
        "http" | "https" => return Ok(url.into()),
        _ => return Err(DomainError::invalid("WebSocket URL must use ws or wss")),
    };
    url.set_scheme(scheme)
        .map_err(|_| DomainError::invalid("invalid WebSocket scheme"))?;
    Ok(url.into())
}

fn upstream_request(url: &str, headers: &[(String, Vec<u8>)]) -> DomainResult<http::Request<()>> {
    let mut request = http::Request::builder()
        .method("GET")
        .uri(url)
        .body(())
        .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("sec-websocket-extensions")
        {
            continue;
        }
        let name = http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| DomainError::invalid(format!("WebSocket header name: {error}")))?;
        let value = http::HeaderValue::from_bytes(value)
            .map_err(|error| DomainError::invalid(format!("WebSocket header value: {error}")))?;
        request.headers_mut().append(name, value);
    }
    Ok(request)
}

async fn connect_socket(dial: &ValidatedDial) -> DomainResult<BoxedSocket> {
    let mut last_error = None;
    let mut stream = None;
    for address in &dial.approved_socket_addrs {
        match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(address)).await {
            Ok(Ok(candidate)) => {
                stream = Some(candidate);
                break;
            }
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some("connect timed out".into()),
        }
    }
    let stream = stream.ok_or_else(|| {
        DomainError::new(
            ErrorCode::Unavailable,
            last_error.unwrap_or_else(|| "no approved WebSocket address".into()),
        )
    })?;
    if dial.scheme == "https" {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = ServerName::try_from(dial.hostname.clone())
            .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
        let tls = TlsConnector::from(Arc::new(config))
            .connect(server_name, stream)
            .await
            .map_err(|error| DomainError::new(ErrorCode::Unavailable, error.to_string()))?;
        Ok(Box::new(tls))
    } else {
        Ok(Box::new(stream))
    }
}

fn ws_error(error: tokio_tungstenite::tungstenite::Error) -> DomainError {
    DomainError::new(ErrorCode::ProtocolError, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_websocket_upgrade_and_converts_scheme() {
        let request = Request::builder()
            .header("upgrade", "websocket")
            .header("connection", "keep-alive, Upgrade")
            .body(())
            .unwrap();
        assert!(is_upgrade(&request));
        assert_eq!(
            websocket_policy_url("ws://example.test/chat").unwrap(),
            "http://example.test/chat"
        );
        assert_eq!(
            websocket_url("https://example.test/chat").unwrap(),
            "wss://example.test/chat"
        );
    }
}
