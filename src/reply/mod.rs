//! Reply drafts, placeholder resolution, send orchestration.

mod raw;

pub use raw::*;

use crate::domain::*;
use crate::history::{diff_exchanges, ResponseDiff};
use crate::policy::{
    is_sensitive_header, present_headers, PresentationOptions, REDACTED_PLACEHOLDER,
};
use crate::policy::{resolve_validated_dial, url_is_in_scope, TargetRef};
use crate::storage::{Db, NewExchange};
use crate::transport::{OutboundBody, OutboundRequest, ProtocolMode, SemanticTransport};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

/// Presentation placeholder: `{{bb:v1:<b64-mac>:<project>:<exchange>:<side>:<header>:<rev>}}`
#[derive(Clone)]
pub struct PlaceholderKey {
    key: Vec<u8>,
}

impl PlaceholderKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    pub fn from_bytes(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn load_or_create(path: &std::path::Path) -> DomainResult<Self> {
        if path.exists() {
            let key = std::fs::read(path).map_err(|e| {
                DomainError::new(ErrorCode::StorageError, format!("placeholder key: {e}"))
            })?;
            return Ok(Self { key });
        }
        let mut key = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
        crate::config::write_private_file(path, &key)?;
        Ok(Self { key })
    }

    fn mac(&self, payload: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac");
        mac.update(payload.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    pub fn mint(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        side: &str,
        header: &str,
        rev: i64,
    ) -> String {
        let payload = format!(
            "{}:{}:{}:{}:{}",
            project_id.get(),
            exchange_id.get(),
            side,
            header.to_ascii_lowercase(),
            rev
        );
        let sig = self.mac(&payload);
        format!(
            "{{{{bb:v1:{sig}:{proj}:{ex}:{side}:{hdr}:{rev}}}}}",
            sig = sig,
            proj = project_id.get(),
            ex = exchange_id.get(),
            side = side,
            hdr = header.to_ascii_lowercase(),
            rev = rev
        )
    }

    pub fn verify_and_parse(&self, token: &str) -> DomainResult<PlaceholderRef> {
        let inner = token
            .strip_prefix("{{bb:v1:")
            .and_then(|s| s.strip_suffix("}}"))
            .ok_or_else(|| DomainError::new(ErrorCode::PlaceholderInvalid, "bad placeholder"))?;
        let parts: Vec<&str> = inner.split(':').collect();
        if parts.len() != 6 {
            return Err(DomainError::new(
                ErrorCode::PlaceholderInvalid,
                "placeholder field count",
            ));
        }
        let sig = parts[0];
        let project_id: i64 = parts[1]
            .parse()
            .map_err(|_| DomainError::new(ErrorCode::PlaceholderInvalid, "project id"))?;
        let exchange_id: i64 = parts[2]
            .parse()
            .map_err(|_| DomainError::new(ErrorCode::PlaceholderInvalid, "exchange id"))?;
        let side = parts[3].to_string();
        let header = parts[4].to_string();
        let rev: i64 = parts[5]
            .parse()
            .map_err(|_| DomainError::new(ErrorCode::PlaceholderInvalid, "rev"))?;
        let payload = format!("{project_id}:{exchange_id}:{side}:{header}:{rev}");
        let expected = self.mac(&payload);
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            expected.as_bytes(),
            sig.as_bytes(),
        )) {
            return Err(DomainError::new(
                ErrorCode::PlaceholderInvalid,
                "placeholder mac mismatch",
            ));
        }
        Ok(PlaceholderRef {
            project_id: ProjectId(project_id),
            exchange_id: ExchangeId(exchange_id),
            side,
            header,
            rev,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PlaceholderRef {
    pub project_id: ProjectId,
    pub exchange_id: ExchangeId,
    pub side: String,
    pub header: String,
    pub rev: i64,
}

/// Build sanitized presented headers with placeholders for sensitive values.
pub fn present_request_for_editor(
    project_id: ProjectId,
    exchange_id: ExchangeId,
    headers: &[HeaderEntry],
    key: &PlaceholderKey,
    rev: i64,
) -> Vec<PresentedHeader> {
    let mut out = Vec::new();
    for h in headers {
        if is_sensitive_header(&h.name) {
            out.push(PresentedHeader {
                name: h.name.clone(),
                value: key.mint(project_id, exchange_id, "request", &h.name, rev),
                redacted: true,
                noisy: false,
            });
        } else {
            let pres = present_headers(
                std::slice::from_ref(h),
                &PresentationOptions {
                    include_noisy_headers: true,
                    ..Default::default()
                },
            );
            out.extend(pres.headers);
        }
    }
    out
}

/// Resolve a draft against a base exchange into concrete method/url/headers/body.
pub async fn materialize_request(
    db: &Db,
    project_id: ProjectId,
    base_exchange_id: Option<ExchangeId>,
    draft: &ReplyDraft,
    key: &PlaceholderKey,
) -> DomainResult<MaterializedRequest> {
    let mut method = draft.method.clone().unwrap_or_else(|| "GET".into());
    let mut url = draft
        .url
        .clone()
        .unwrap_or_else(|| "http://localhost/".into());
    let mut headers: Vec<(String, Vec<u8>)> = Vec::new();
    let mut body = draft.body_override.clone();

    if let Some(base_id) = base_exchange_id {
        let base_headers = db
            .load_raw_headers(project_id, base_id, MessageSide::Request)
            .await?;
        // Start from base headers
        for h in &base_headers {
            if draft
                .header_tombstones
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&h.name))
            {
                continue;
            }
            if draft
                .header_overrides
                .iter()
                .any(|o| o.name.eq_ignore_ascii_case(&h.name))
            {
                continue;
            }
            headers.push((h.name.clone(), h.value.clone()));
        }
        if draft.method.is_none() || draft.url.is_none() {
            let detail = db
                .get_exchange_detail(project_id, base_id, PresentationOptions::default())
                .await?;
            if draft.method.is_none() {
                method = detail.summary.method;
            }
            if draft.url.is_none() {
                let q = detail
                    .summary
                    .query
                    .as_ref()
                    .map(|q| format!("?{q}"))
                    .unwrap_or_default();
                url = format!(
                    "{}://{}{}{}",
                    detail.summary.scheme, detail.summary.authority, detail.summary.path, q
                );
            }
        }
        if body.is_none() && !draft.body_cleared {
            body = db
                .load_raw_body(project_id, base_id, MessageSide::Request)
                .await?;
        }
    }

    for o in &draft.header_overrides {
        // If value looks like a placeholder, resolve to original secret
        let val = if let Ok(s) = std::str::from_utf8(&o.value) {
            if s.starts_with("{{bb:v1:") {
                let pref = key.verify_and_parse(s)?;
                if pref.project_id != project_id {
                    return Err(DomainError::new(
                        ErrorCode::PlaceholderInvalid,
                        "cross-project placeholder",
                    ));
                }
                if let Some(base_id) = base_exchange_id {
                    if pref.exchange_id != base_id {
                        return Err(DomainError::new(
                            ErrorCode::PlaceholderInvalid,
                            "placeholder exchange mismatch",
                        ));
                    }
                }
                let raw = db
                    .load_raw_headers(project_id, pref.exchange_id, MessageSide::Request)
                    .await?;
                raw.iter()
                    .find(|h| h.name.eq_ignore_ascii_case(&pref.header))
                    .map(|h| h.value.clone())
                    .ok_or_else(|| {
                        DomainError::new(ErrorCode::PlaceholderInvalid, "header not found")
                    })?
            } else if s == REDACTED_PLACEHOLDER {
                return Err(DomainError::invalid(
                    "cannot send literal <redacted>; use inheritance or secret_reveal",
                ));
            } else {
                o.value.clone()
            }
        } else {
            o.value.clone()
        };
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case(&o.name));
        headers.push((o.name.clone(), val));
    }

    Ok(MaterializedRequest {
        method,
        url,
        headers,
        body,
    })
}

#[derive(Debug, Clone)]
pub struct MaterializedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ReplySendContext {
    pub source: ExchangeSource,
    pub lineage: ExchangeLineage,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EphemeralReplyResponse {
    pub protocol: String,
    pub status_code: u16,
    pub headers: Vec<PresentedHeader>,
    pub body_base64: String,
    pub body_truncated: bool,
    pub duration_ms: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReplySendResult {
    pub exchange_id: Option<ExchangeId>,
    pub diff: Option<ResponseDiff>,
    /// Present only when capture scope excludes the exchange.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<EphemeralReplyResponse>,
    #[serde(skip)]
    pub response_length: i64,
    #[serde(skip)]
    pub response_body_hash: String,
    #[serde(skip)]
    pub duration_ms: i64,
    #[serde(skip)]
    pub status_code: u16,
}

impl ReplySendContext {
    pub fn reply(base_exchange_id: Option<ExchangeId>, tab_id: Option<ReplyTabId>) -> Self {
        Self {
            source: ExchangeSource::Reply,
            lineage: ExchangeLineage {
                parent_exchange_id: base_exchange_id,
                reply_tab_id: tab_id,
                ..Default::default()
            },
        }
    }

    pub fn fuzzer(base_exchange_id: Option<ExchangeId>, job_id: FuzzJobId, case_id: i64) -> Self {
        Self {
            source: ExchangeSource::Fuzzer,
            lineage: ExchangeLineage {
                parent_exchange_id: base_exchange_id,
                fuzz_job_id: Some(job_id),
                fuzz_case_id: Some(case_id),
                ..Default::default()
            },
        }
    }
}

pub struct ReplyService {
    pub db: Arc<Db>,
    pub transport: Arc<dyn SemanticTransport>,
    pub placeholder_key: PlaceholderKey,
}

impl ReplyService {
    pub fn placeholder_key(&self) -> &PlaceholderKey {
        &self.placeholder_key
    }
}

impl ReplyService {
    pub async fn send(
        &self,
        project_id: ProjectId,
        tab_id: Option<ReplyTabId>,
        base_exchange_id: Option<ExchangeId>,
        draft: &ReplyDraft,
        protocol: ProtocolPreference,
        follow_redirects: u32,
    ) -> DomainResult<ReplySendResult> {
        self.send_with_context(
            project_id,
            base_exchange_id,
            draft,
            protocol,
            follow_redirects,
            ReplySendContext::reply(base_exchange_id, tab_id),
        )
        .await
    }

    pub async fn send_with_context(
        &self,
        project_id: ProjectId,
        base_exchange_id: Option<ExchangeId>,
        draft: &ReplyDraft,
        protocol: ProtocolPreference,
        follow_redirects: u32,
        context: ReplySendContext,
    ) -> DomainResult<ReplySendResult> {
        let project = self.db.get_project(project_id).await?;
        let mat = materialize_request(
            &self.db,
            project_id,
            base_exchange_id,
            draft,
            &self.placeholder_key,
        )
        .await?;

        // Scope controls persistence only; it never blocks egress.
        let should_capture = url_is_in_scope(&mat.url, &project.scope)?;
        let dial =
            resolve_validated_dial(&mat.url, &project.scope, Duration::from_secs(60)).await?;

        let method = mat.method.parse::<http::Method>().map_err(|error| {
            DomainError::invalid(format!("invalid HTTP method {}: {error}", mat.method))
        })?;
        let target = TargetRef::from_url(&mat.url)?;
        let req_headers: Vec<HeaderEntry> = mat
            .headers
            .iter()
            .enumerate()
            .map(|(i, (n, v))| HeaderEntry {
                name: n.clone(),
                value: v.clone(),
                ordinal: i as u32,
            })
            .collect();
        let started = std::time::Instant::now();
        let out = self
            .transport
            .send(
                &dial,
                OutboundRequest {
                    method,
                    url: mat.url.clone(),
                    headers: mat.headers.clone(),
                    body: mat
                        .body
                        .clone()
                        .map(bytes::Bytes::from)
                        .map(OutboundBody::Bytes)
                        .unwrap_or(OutboundBody::Empty),
                    protocol: match protocol {
                        ProtocolPreference::Auto => ProtocolMode::Auto,
                        ProtocolPreference::H1 => ProtocolMode::Http1,
                        ProtocolPreference::H2 => ProtocolMode::Http2,
                    },
                    connect_timeout: Duration::from_secs(10),
                    total_timeout: Duration::from_secs(60),
                    max_body_bytes: project.limits.max_body_bytes,
                    preserve_identity_headers: true,
                },
            )
            .await;
        let out = match out {
            Ok(out) => out,
            Err(error) => {
                let completion = match error.code() {
                    ErrorCode::Timeout => CompletionState::Timeout,
                    ErrorCode::ProtocolError => CompletionState::ProtocolError,
                    ErrorCode::Cancelled => CompletionState::Cancelled,
                    _ => CompletionState::ConnectionError,
                };
                let insert = if should_capture {
                    self.db
                        .insert_exchange(NewExchange {
                            project_id,
                            source: context.source,
                            protocol: "unknown".into(),
                            method: mat.method.clone(),
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
                            transport_provenance: Some(self.transport.provenance()),
                            transport_profile: Some(self.transport.profile_name().into()),
                            request_headers: req_headers.clone(),
                            response_headers: Vec::new(),
                            request_body: mat.body.clone(),
                            response_body: None,
                            duration_ms: Some(started.elapsed().as_millis() as i64),
                            lineage: context.lineage.clone(),
                            page_title: None,
                            error_message: Some(error.to_string()),
                        })
                        .await
                        .map(Some)
                } else {
                    Ok(None)
                };
                if let Err(storage_error) = insert {
                    tracing::warn!(%storage_error, "failed to preserve failed Reply exchange");
                }
                return Err(error);
            }
        };
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

        let response_length = out.body.len() as i64;
        let response_body_hash = crate::storage::sha256_hex(&out.body);
        let duration_ms = out.duration.as_millis() as i64;
        let status_code = out.status.as_u16();
        let ephemeral_response = (!should_capture).then(|| {
            let presented = present_headers(&resp_headers, &PresentationOptions::default());
            EphemeralReplyResponse {
                protocol: out.protocol.clone(),
                status_code,
                headers: presented.headers,
                body_base64: base64::engine::general_purpose::STANDARD.encode(&out.body),
                body_truncated: out.body_truncated,
                duration_ms,
            }
        });

        let authority = target.authority();
        let exchange_id = if should_capture {
            Some(
                self.db
                    .insert_exchange(NewExchange {
                        project_id,
                        source: context.source,
                        protocol: out.protocol.clone(),
                        method: mat.method.clone(),
                        scheme: target.scheme,
                        authority,
                        host: target.host,
                        port: target.port,
                        path: target.path,
                        query: target.query,
                        status_code: Some(out.status.as_u16()),
                        mime,
                        completion: if out.body_truncated {
                            CompletionState::TruncatedByPolicy
                        } else {
                            CompletionState::Complete
                        },
                        capture_quality: CaptureQuality::Semantic,
                        header_representation: HeaderRepresentation::Semantic,
                        body_representation: BodyRepresentation::SemanticEncoded,
                        cache_provenance: CacheProvenance::None,
                        transport_provenance: Some(out.transport_provenance),
                        transport_profile: Some(out.transport_profile.clone()),
                        request_headers: req_headers.clone(),
                        response_headers: resp_headers.clone(),
                        request_body: mat.body.clone(),
                        response_body: Some(out.body.to_vec()),
                        duration_ms: Some(duration_ms),
                        lineage: context.lineage.clone(),
                        page_title: None,
                        error_message: out
                            .body_truncated
                            .then(|| "response body truncated by project body limit".into()),
                    })
                    .await?,
            )
        } else {
            None
        };

        let _ = follow_redirects; // redirects: post-MVP partial — off by default in callers

        let mut diff = None;
        if let (Some(parent_id), Some(exchange_id)) = (base_exchange_id, exchange_id) {
            if let Ok(parent) = self
                .db
                .get_exchange_detail(project_id, parent_id, PresentationOptions::default())
                .await
            {
                let child = self
                    .db
                    .get_exchange_detail(project_id, exchange_id, PresentationOptions::default())
                    .await?;
                let ph: Vec<_> = parent
                    .response_headers
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect();
                let ch: Vec<_> = child
                    .response_headers
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect();
                diff = Some(diff_exchanges(
                    parent.summary.status_code,
                    child.summary.status_code,
                    parent.summary.response_length,
                    child.summary.response_length,
                    parent.summary.mime.as_deref(),
                    child.summary.mime.as_deref(),
                    parent.response_body_hash.as_deref(),
                    child.response_body_hash.as_deref(),
                    &ph,
                    &ch,
                    None,
                    None,
                ));
            }
        }

        if let Some(exchange_id) = exchange_id {
            let _ = self
                .db
                .audit(
                    Some(project_id),
                    if context.source == ExchangeSource::Fuzzer {
                        "fuzz_send"
                    } else {
                        "reply_send"
                    },
                    Some(if context.source == ExchangeSource::Fuzzer {
                        "fuzzer"
                    } else {
                        "reply"
                    }),
                    Some("exchange"),
                    Some(&exchange_id.to_string()),
                    serde_json::json!({ "parent": base_exchange_id.map(|i| i.get()) }),
                )
                .await;
        }

        Ok(ReplySendResult {
            exchange_id,
            diff,
            response: ephemeral_response,
            response_length,
            response_body_hash,
            duration_ms,
            status_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::transport::OutboundResponse;

    struct CannedTransport;

    #[async_trait::async_trait]
    impl SemanticTransport for CannedTransport {
        async fn send(
            &self,
            _dial: &ValidatedDial,
            _request: OutboundRequest,
        ) -> DomainResult<OutboundResponse> {
            Ok(OutboundResponse {
                status: http::StatusCode::OK,
                headers: vec![("content-type".into(), b"text/plain".to_vec())],
                body: bytes::Bytes::from_static(b"ephemeral"),
                body_truncated: false,
                protocol: "HTTP/1.1".into(),
                transport_provenance: TransportProvenance::GenericUnprofiled,
                transport_profile: "test".into(),
                duration: Duration::from_millis(2),
            })
        }

        fn profile_name(&self) -> &str {
            "test"
        }

        fn provenance(&self) -> TransportProvenance {
            TransportProvenance::GenericUnprofiled
        }
    }

    #[tokio::test]
    async fn out_of_scope_reply_is_sent_but_not_persisted() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config {
            data_dir: directory.path().to_path_buf(),
            spool_dir: directory.path().join("spool"),
            export_dir: directory.path().join("exports"),
            runtime_dir: directory.path().join("runtime"),
            ..Config::default()
        };
        config.ensure_layout().unwrap();
        let db = Arc::new(Db::open(&config).await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "capture filter".into(),
                target_url: "https://example.com".into(),
                advanced: Some(ScopePolicy {
                    schemes: vec!["https".into()],
                    host_patterns: vec!["example.com".into()],
                    ports: vec![],
                    path_prefixes: vec![],
                }),
            })
            .await
            .unwrap();
        let service = ReplyService {
            db: db.clone(),
            transport: Arc::new(CannedTransport),
            placeholder_key: PlaceholderKey::from_bytes(vec![1; 32]),
        };

        let result = service
            .send(
                project.id,
                None,
                None,
                &ReplyDraft {
                    method: Some("GET".into()),
                    url: Some("http://127.0.0.1:1234/outside".into()),
                    ..Default::default()
                },
                ProtocolPreference::H1,
                0,
            )
            .await
            .unwrap();

        assert!(result.exchange_id.is_none());
        assert_eq!(result.response.unwrap().status_code, 200);
        assert!(db
            .list_history(project.id, 10, None, None)
            .await
            .unwrap()
            .0
            .is_empty());
    }
}
