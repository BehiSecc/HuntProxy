//! Local TLS regression fixtures. No external endpoints or trust-store changes.

use super::*;
use crate::app::{bootstrap_state, AppState};
use crate::config::{Config, CONFIG_FILE_NAME};
use crate::domain::*;
use crate::reply::{
    RawHttp1Options, RawHttp2Header, RawHttp2Options, RawHttp2Stream, ReplySendContext,
};
use futures::SinkExt;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_tungstenite::tungstenite::{protocol::Role, Message};

#[derive(Clone, Copy, Debug)]
pub(crate) enum CertificateKind {
    SelfSigned,
    PrivateCa,
    Expired,
    WrongHostname,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum WireProtocol {
    Http1,
    Http2,
    WebSocket,
}

pub(crate) struct TlsOrigin {
    pub url: String,
    pub certificate: Vec<u8>,
    task: JoinHandle<()>,
}

impl Drop for TlsOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TlsOrigin {
    pub async fn start(
        kind: CertificateKind,
        protocol: WireProtocol,
        version: &'static rustls::SupportedProtocolVersion,
    ) -> Self {
        let name = if matches!(kind, CertificateKind::WrongHostname) {
            "other.invalid"
        } else {
            "127.0.0.1"
        };
        let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
        if matches!(kind, CertificateKind::Expired) {
            params.not_before = rcgen::date_time_ymd(2000, 1, 1);
            params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = if matches!(kind, CertificateKind::PrivateCa) {
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let mut ca_params = rcgen::CertificateParams::default();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca = ca_params.self_signed(&ca_key).unwrap();
            params.signed_by(&key, &ca, &ca_key).unwrap()
        } else {
            params.self_signed(&key).unwrap()
        };
        let certificate = cert.der().to_vec();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
        config.alpn_protocols = vec![match protocol {
            WireProtocol::Http2 => b"h2".to_vec(),
            _ => b"http/1.1".to_vec(),
        }];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}/", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (socket, _) = result.unwrap();
                        let acceptor = acceptor.clone();
                        connections.spawn(async move {
                            let Ok(tls) = acceptor.accept(socket).await else {
                                return; // Expected when the client rejects the certificate.
                            };
                            if matches!(protocol, WireProtocol::WebSocket) {
                                let Ok(mut ws) = tokio_tungstenite::accept_async(tls).await else {
                                    return;
                                };
                                if let Some(Ok(message)) = ws.next().await {
                                    let _ = ws.send(message).await;
                                }
                            } else {
                                let service = service_fn(|_| async {
                                    Ok::<_, Infallible>(hyper::Response::new(Full::new(
                                        Bytes::from_static(b"tls-ok"),
                                    )))
                                });
                                if matches!(protocol, WireProtocol::Http2) {
                                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                                        .serve_connection(TokioIo::new(tls), service).await;
                                } else {
                                    let _ = hyper::server::conn::http1::Builder::new()
                                        .keep_alive(false)
                                        .serve_connection(TokioIo::new(tls), service).await;
                                }
                            }
                        });
                    }
                    Some(result) = connections.join_next() => result.unwrap(),
                }
            }
        });
        Self {
            url,
            certificate,
            task,
        }
    }
}

pub(crate) fn configuration(setting: Option<bool>) -> (tempfile::TempDir, Config) {
    let directory = tempfile::tempdir().unwrap();
    if let Some(value) = setting {
        std::fs::write(
            directory.path().join(CONFIG_FILE_NAME),
            format!("verify_upstream_tls = {value}\n"),
        )
        .unwrap();
    } else {
        // An existing configuration that predates this option.
        std::fs::write(
            directory.path().join(CONFIG_FILE_NAME),
            "log_level = 'info'\n",
        )
        .unwrap();
    }
    let mut config = Config::load(Some(directory.path().to_owned())).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = params.self_signed(&key).unwrap();
    std::fs::write(config.ca_cert_path(), ca.pem()).unwrap();
    std::fs::write(config.ca_key_path(), key.serialize_pem()).unwrap();
    config.browser_worker_path =
        Some(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("browser-worker/index.js"));
    (directory, config)
}

#[derive(Clone, Copy, Debug)]
enum TargetPath {
    ReplyHttp1,
    ReplyHttp2,
    RawHttp1,
    RawHttp2,
    WebSocket,
    Proxy,
}

async fn request(
    state: &Arc<AppState>,
    project: ProjectId,
    origin: &TlsOrigin,
    path: TargetPath,
) -> DomainResult<()> {
    match path {
        TargetPath::ReplyHttp1 | TargetPath::ReplyHttp2 => {
            let result = state
                .reply
                .send(
                    project,
                    None,
                    None,
                    &ReplyDraft {
                        url: Some(origin.url.clone()),
                        ..Default::default()
                    },
                    if matches!(path, TargetPath::ReplyHttp2) {
                        ProtocolPreference::H2
                    } else {
                        ProtocolPreference::H1
                    },
                    0,
                )
                .await?;
            assert_eq!(result.response_preview.text, "tls-ok");
        }
        TargetPath::RawHttp1 => {
            let result = state
                .reply
                .send_raw_http1(
                    project,
                    None,
                    &origin.url,
                    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".to_vec(),
                    false,
                    RawHttp1Options::default(),
                )
                .await?;
            assert_eq!(result.status_code, Some(200));
            assert!(result.response_complete);
        }
        TargetPath::RawHttp2 => {
            let headers = [
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "127.0.0.1"),
                (":path", "/"),
            ]
            .into_iter()
            .map(|(name, value)| RawHttp2Header {
                name: name.into(),
                value: value.into(),
            })
            .collect();
            let result = state
                .reply
                .send_raw_http2_with_context(
                    project,
                    &origin.url,
                    vec![RawHttp2Stream {
                        id: "tls".into(),
                        stream_id: None,
                        headers,
                        body_text: None,
                        body_base64: None,
                    }],
                    RawHttp2Options::default(),
                    ReplySendContext::reply(None, None),
                )
                .await?;
            assert_eq!(result.negotiated_protocol, "h2");
            assert_eq!(result.streams[0].status_code, Some(200));
            assert!(result.streams[0].complete);
            assert_eq!(result.streams[0].response_length, 6);
        }
        TargetPath::WebSocket => {
            let dial = crate::policy::resolve_validated_dial(
                &origin.url,
                &ScopePolicy::default(),
                Duration::from_secs(60),
            )
            .await?;
            let response = state
                .transport
                .send_upgrade(
                    &dial,
                    OutboundRequest {
                        headers: vec![
                            ("Connection".into(), b"Upgrade".to_vec()),
                            ("Upgrade".into(), b"websocket".to_vec()),
                            (
                                "Sec-WebSocket-Key".into(),
                                b"dGhlIHNhbXBsZSBub25jZQ==".to_vec(),
                            ),
                            ("Sec-WebSocket-Version".into(), b"13".to_vec()),
                        ],
                        ..outbound(project, &origin.url)
                    },
                )
                .await?;
            assert_eq!(response.status, StatusCode::SWITCHING_PROTOCOLS);
            let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                response.upgraded.unwrap(),
                Role::Client,
                None,
            )
            .await;
            ws.send(Message::Text("tls-ok".into())).await.unwrap();
            assert_eq!(
                ws.next().await.unwrap().unwrap(),
                Message::Text("tls-ok".into())
            );
        }
        TargetPath::Proxy => {
            let session = state
                .db
                .create_capture_session(crate::storage::CreateCaptureSession {
                    project_id: project,
                    browser_session_id: None,
                    browser_action_id: None,
                    is_browser_bound: false,
                    ttl: None,
                })
                .await?;
            let listener = crate::proxy::bind_proxy("127.0.0.1:0".parse().unwrap()).await?;
            let address = listener.local_addr().unwrap();
            let cancel = tokio_util::sync::CancellationToken::new();
            let proxy = tokio::spawn(crate::proxy::serve_proxy_listener(
                state.clone(),
                listener,
                cancel.clone(),
            ));
            let mut client = TcpStream::connect(address).await.unwrap();
            client.write_all(format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: Bearer {}\r\nConnection: close\r\n\r\n", origin.url, session.token_once.unwrap()).as_bytes()).await.unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).await.unwrap();
            cancel.cancel();
            proxy.await.unwrap()?;
            if !response.starts_with("HTTP/1.1 200 ") {
                assert!(response.starts_with("HTTP/1.1 502 "), "{response}");
                return Err(DomainError::new(ErrorCode::ProtocolError, response));
            }
            assert!(response.ends_with("tls-ok"), "{response}");
        }
    }
    Ok(())
}

fn outbound(project: ProjectId, url: &str) -> OutboundRequest {
    OutboundRequest {
        identity: TransportIdentity::for_reply(project, &[]),
        method: Method::GET,
        url: url.into(),
        headers: vec![],
        body: OutboundBody::Empty,
        protocol: ProtocolMode::Http1,
        connect_timeout: Duration::from_secs(2),
        total_timeout: Duration::from_secs(5),
        max_body_bytes: 1024,
        preserve_identity_headers: true,
        upstream_proxy: None,
    }
}

pub(crate) async fn assert_target_connects(config: &Config, origin: &TlsOrigin) {
    let state = bootstrap_state(config.clone()).await.unwrap();
    let dial = crate::policy::resolve_validated_dial(
        &origin.url,
        &ScopePolicy::default(),
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let response = state
        .transport
        .send(&dial, outbound(ProjectId(1), &origin.url))
        .await
        .unwrap();
    assert_eq!(response.body, "tls-ok");
    state.shutdown.cancel();
}

pub(crate) fn assert_certificate_error(error: &wreq::Error) {
    let mut messages = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        messages.push_str(&cause.to_string());
        source = cause.source();
    }
    assert!(
        messages
            .to_ascii_lowercase()
            .replace('_', " ")
            .contains("certificate verify failed"),
        "{messages}"
    );
}

async fn exercise(path: TargetPath) {
    for setting in [None, Some(true), Some(false)] {
        let (_directory, config) = configuration(setting);
        let state = bootstrap_state(config).await.unwrap();
        let project = state
            .db
            .create_project(CreateProjectRequest {
                name: "TLS regression".into(),
                target_url: "https://127.0.0.1/".into(),
                advanced: None,
            })
            .await
            .unwrap()
            .id;
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            for kind in [
                CertificateKind::SelfSigned,
                CertificateKind::PrivateCa,
                CertificateKind::Expired,
                CertificateKind::WrongHostname,
            ] {
                let protocol = match path {
                    TargetPath::ReplyHttp2 | TargetPath::RawHttp2 => WireProtocol::Http2,
                    TargetPath::WebSocket => WireProtocol::WebSocket,
                    _ => WireProtocol::Http1,
                };
                let origin = TlsOrigin::start(kind, protocol, version).await;
                let result = tokio::time::timeout(
                    Duration::from_secs(10),
                    request(&state, project, &origin, path),
                )
                .await
                .expect("target request timed out");
                assert_eq!(
                    result.is_ok(),
                    setting == Some(false),
                    "{path:?}, {kind:?}, {version:?}, setting {setting:?}: {result:?}"
                );
            }
        }
        state.shutdown.cancel();
    }
}

#[tokio::test]
async fn upstream_tls_reply_http1() {
    exercise(TargetPath::ReplyHttp1).await;
}

#[tokio::test]
async fn upstream_tls_reply_http2() {
    exercise(TargetPath::ReplyHttp2).await;
}

#[tokio::test]
async fn upstream_tls_raw_http1() {
    exercise(TargetPath::RawHttp1).await;
}

#[tokio::test]
async fn upstream_tls_raw_http2() {
    exercise(TargetPath::RawHttp2).await;
}

#[tokio::test]
async fn upstream_tls_websocket() {
    exercise(TargetPath::WebSocket).await;
}

#[tokio::test]
async fn upstream_tls_proxy() {
    exercise(TargetPath::Proxy).await;
}

#[tokio::test]
async fn upstream_tls_hostname_checks_follow_policy_with_a_trusted_certificate() {
    let origin = TlsOrigin::start(
        CertificateKind::WrongHostname,
        WireProtocol::Http1,
        &rustls::version::TLS13,
    )
    .await;
    let dial = crate::policy::resolve_validated_dial(
        &origin.url,
        &ScopePolicy::default(),
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    for verify in [true, false] {
        let mut transport =
            WreqTransport::with_chrome_major_and_tls_verification(153, verify).unwrap();
        transport.test_cert_store = Some(
            wreq::tls::trust::CertStore::from_der_certs([origin.certificate.as_slice()]).unwrap(),
        );
        let result = transport
            .send(&dial, outbound(ProjectId(1), &origin.url))
            .await;
        assert_eq!(result.is_ok(), !verify);
        if let Ok(response) = result {
            assert_eq!(response.body, "tls-ok");
        }
    }
}
