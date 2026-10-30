use super::{full_body, header_entries, is_own_api_target, request_url, ProxyBody};
use crate::app::{AppEvent, AppState};
use crate::domain::*;
use crate::policy::scope::{resolve_validated_dial, url_is_in_scope, TargetRef};
use crate::storage::NewExchange;
use crate::transport::{OutboundBody, OutboundRequest, ProtocolMode, TransportIdentity};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use url::Url;

pub(super) fn is_upgrade<B>(request: &Request<B>) -> bool {
    request
        .headers()
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && request
            .headers()
            .get_all(http::header::CONNECTION)
            .iter()
            .any(|value| {
                value.to_str().is_ok_and(|value| {
                    value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
                })
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
    let capture = url_is_in_scope(&http_url, &project.scope)?
        && !is_own_api_target(&target, state.config.api_listen);
    let dial = resolve_validated_dial(&http_url, &project.scope, Duration::from_secs(60)).await?;
    let upstream_proxy = state
        .db
        .resolve_upstream_proxy(
            session.project_id,
            &state.config.upstream_proxies,
            &target.host,
            None,
        )
        .await?;
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
    // Compression extensions are not supported by the existing frame relay.
    // Preserve the browser's nonce, cookies, Origin and subprotocol list.
    request_headers.retain(|(name, _)| !name.eq_ignore_ascii_case("sec-websocket-extensions"));
    validate_request_headers(&request_headers)?;
    let cap = usize::try_from(project.limits.capture_body_bytes).unwrap_or(usize::MAX);
    let websocket_config = WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(16 * 1024)
        .max_message_size(Some(cap))
        .max_frame_size(Some(cap));
    let started = Instant::now();
    let mut upstream_response = state
        .transport
        .send_upgrade(
            &dial,
            OutboundRequest {
                identity: TransportIdentity::for_capture(&session),
                method: http::Method::GET,
                url: http_url.clone(),
                headers: request_headers.clone(),
                body: OutboundBody::Empty,
                protocol: ProtocolMode::Http1,
                connect_timeout: Duration::from_secs(10),
                total_timeout: Duration::from_secs(60),
                max_body_bytes: project.limits.capture_body_bytes,
                preserve_identity_headers: true,
                upstream_proxy,
            },
        )
        .await?;
    let handshake_error = upstream_response.error.take().or_else(|| {
        if upstream_response.status == StatusCode::SWITCHING_PROTOCOLS {
            validate_response_headers(&request_headers, &upstream_response.headers).err()
        } else {
            None
        }
    });

    let response_headers = upstream_response.headers.clone();
    let protocol = response_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-protocol"))
        .map(|(_, value)| String::from_utf8_lossy(value).into_owned());

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
                status_code: Some(upstream_response.status.as_u16()),
                mime: None,
                completion: if let Some(error) = &handshake_error {
                    match error.code() {
                        ErrorCode::Timeout => CompletionState::Timeout,
                        ErrorCode::ProtocolError | ErrorCode::InvalidArgument => {
                            CompletionState::ProtocolError
                        }
                        _ => CompletionState::ConnectionError,
                    }
                } else if upstream_response.body_truncated {
                    CompletionState::TruncatedByPolicy
                } else {
                    CompletionState::Complete
                },
                capture_quality: CaptureQuality::Semantic,
                header_representation: HeaderRepresentation::Semantic,
                body_representation: if upstream_response.status == StatusCode::SWITCHING_PROTOCOLS
                {
                    BodyRepresentation::Unavailable
                } else {
                    BodyRepresentation::SemanticEncoded
                },
                cache_provenance: CacheProvenance::None,
                transport_provenance: Some(upstream_response.transport_provenance),
                transport_profile: Some(upstream_response.transport_profile.clone()),
                request_headers: header_entries(&request_headers),
                response_headers: header_entries(&response_headers),
                request_body: None,
                response_body: (upstream_response.status != StatusCode::SWITCHING_PROTOCOLS)
                    .then(|| upstream_response.body.to_vec()),
                duration_ms: Some(started.elapsed().as_millis() as i64),
                lineage: ExchangeLineage {
                    capture_session_id: Some(session.id),
                    browser_session_id: session.browser_session_id,
                    browser_action_id: session.browser_action_id,
                    ..Default::default()
                },
                page_title: None,
                error_message: handshake_error.as_ref().map(ToString::to_string),
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

    if upstream_response.status == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(error) = handshake_error {
            return Err(error);
        }
    }
    if upstream_response.status != StatusCode::SWITCHING_PROTOCOLS {
        // Keep an origin's failed handshake visible to the browser and History.
        let mut response = Response::builder().status(upstream_response.status);
        for (name, value) in response_headers {
            if !name.eq_ignore_ascii_case("transfer-encoding")
                && !name.eq_ignore_ascii_case("content-length")
            {
                response = response.header(name, value);
            }
        }
        return response
            .body(full_body(upstream_response.body))
            .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()));
    }
    let upstream_socket = upstream_response.upgraded.take().ok_or_else(|| {
        DomainError::new(
            ErrorCode::ProtocolError,
            "successful WebSocket handshake has no upgraded socket",
        )
    })?;
    let upstream =
        WebSocketStream::from_raw_socket(upstream_socket, Role::Client, Some(websocket_config))
            .await;

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

fn header_values<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Vec<&'a [u8]> {
    headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
        .collect()
}

fn single_header<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> DomainResult<&'a str> {
    let values = header_values(headers, name);
    if values.len() != 1 {
        return Err(DomainError::invalid(format!(
            "WebSocket requires one {name} header"
        )));
    }
    std::str::from_utf8(values[0])
        .map_err(|_| DomainError::invalid(format!("invalid WebSocket {name}")))
}

fn validate_request_headers(headers: &[(String, Vec<u8>)]) -> DomainResult<()> {
    use base64::Engine;
    let key = single_header(headers, "sec-websocket-key")?;
    if !base64::engine::general_purpose::STANDARD
        .decode(key)
        .is_ok_and(|decoded| decoded.len() == 16)
    {
        return Err(DomainError::invalid("invalid WebSocket key"));
    }
    if single_header(headers, "sec-websocket-version")? != "13" {
        return Err(DomainError::invalid("unsupported WebSocket version"));
    }
    Ok(())
}

fn validate_response_headers(
    request: &[(String, Vec<u8>)],
    response: &[(String, Vec<u8>)],
) -> DomainResult<()> {
    let error = || {
        DomainError::new(
            ErrorCode::ProtocolError,
            "invalid upstream WebSocket handshake",
        )
    };
    let upgrade = single_header(response, "upgrade").map_err(|_| error())?;
    let connections = header_values(response, "connection");
    let accept = single_header(response, "sec-websocket-accept").map_err(|_| error())?;
    let key = single_header(request, "sec-websocket-key")?;
    if !upgrade.eq_ignore_ascii_case("websocket")
        || !connections.iter().any(|value| {
            std::str::from_utf8(value).is_ok_and(|value| {
                value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
        || accept != tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes())
        || !header_values(response, "sec-websocket-extensions").is_empty()
    {
        return Err(error());
    }
    let selected = header_values(response, "sec-websocket-protocol");
    if selected.len() > 1 {
        return Err(error());
    }
    let offered = header_values(request, "sec-websocket-protocol");
    if selected.is_empty()
        && offered.iter().any(|value| {
            std::str::from_utf8(value)
                .is_ok_and(|value| value.split(',').any(|protocol| !protocol.trim().is_empty()))
        })
    {
        return Err(error());
    }
    if let Some(selected) = selected.first() {
        let selected = std::str::from_utf8(selected).map_err(|_| error())?;
        if selected.is_empty()
            || !offered.iter().any(|value| {
                std::str::from_utf8(value)
                    .is_ok_and(|value| value.split(',').any(|protocol| protocol.trim() == selected))
            })
        {
            return Err(error());
        }
    }
    Ok(())
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
        let repeated = Request::builder()
            .header("upgrade", "websocket")
            .header("connection", "keep-alive")
            .header("connection", "Upgrade")
            .body(())
            .unwrap();
        assert!(is_upgrade(&repeated));
        assert_eq!(
            websocket_policy_url("ws://example.test/chat").unwrap(),
            "http://example.test/chat"
        );
        assert_eq!(
            websocket_url("https://example.test/chat").unwrap(),
            "wss://example.test/chat"
        );
    }
    #[test]
    fn upstream_handshake_requires_the_original_nonce_and_valid_protocol_selection() {
        let request = vec![
            (
                "sec-websocket-key".into(),
                b"dGhlIHNhbXBsZSBub25jZQ==".to_vec(),
            ),
            ("sec-websocket-version".into(), b"13".to_vec()),
            ("sec-websocket-protocol".into(), b"updates, events".to_vec()),
        ];
        let response = vec![
            ("upgrade".into(), b"websocket".to_vec()),
            ("connection".into(), b"Upgrade".to_vec()),
            (
                "sec-websocket-accept".into(),
                b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".to_vec(),
            ),
        ];
        assert!(validate_request_headers(&request).is_ok());
        assert!(
            validate_response_headers(&request, &response).is_err(),
            "missing selected protocol"
        );
        let mut valid = response.clone();
        valid.push(("sec-websocket-protocol".into(), b"updates".to_vec()));
        assert!(validate_response_headers(&request, &valid).is_ok());
        let mut wrong = response.clone();
        wrong.push(("sec-websocket-protocol".into(), b"archive".to_vec()));
        assert!(validate_response_headers(&request, &wrong).is_err());
        valid.push(("Sec-WebSocket-Protocol".into(), b"events".to_vec()));
        assert!(validate_response_headers(&request, &valid).is_err());
        let mut no_protocol = request.clone();
        no_protocol.pop();
        assert!(validate_response_headers(&no_protocol, &response).is_ok());
        let mut repeated_connection = response.clone();
        repeated_connection.push(("Connection".into(), b"keep-alive".to_vec()));
        assert!(validate_response_headers(&no_protocol, &repeated_connection).is_ok());
        repeated_connection[1].1 = b"keep-alive".to_vec();
        repeated_connection.last_mut().unwrap().1 = b"Upgrade".to_vec();
        assert!(validate_response_headers(&no_protocol, &repeated_connection).is_ok());
        let mut wrong_nonce = response.clone();
        wrong_nonce[2].1 = b"incorrect".to_vec();
        assert!(validate_response_headers(&no_protocol, &wrong_nonce).is_err());
    }
}
