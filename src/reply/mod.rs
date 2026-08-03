//! Reply drafts, placeholder resolution, send orchestration.

mod raw;

pub use raw::*;

use crate::codec::{decode_content_encodings, MAX_DECODED_BODY_OUTPUT};
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
    let has_explicit_body = draft.body_override.is_some()
        || draft.body_text.is_some()
        || draft.body_json.is_some()
        || !draft.body_params.is_empty();
    let normalized = normalize_reply_draft(draft.clone())?;
    let draft = &normalized;
    let mut method = draft.method.clone().unwrap_or_else(|| "GET".into());
    let mut url = draft
        .url
        .clone()
        .unwrap_or_else(|| "http://localhost/".into());
    let mut headers: Vec<(String, Vec<u8>)> = Vec::new();
    let mut body = draft.body_override.clone();
    let mut inherited_url = None;
    let mut method_changed = false;

    if let Some(base_id) = base_exchange_id {
        let detail = db
            .get_exchange_detail(project_id, base_id, PresentationOptions::default())
            .await?;
        let query = detail
            .summary
            .query
            .as_ref()
            .map(|query| format!("?{query}"))
            .unwrap_or_default();
        let base_url = format!(
            "{}://{}{}{}",
            detail.summary.scheme, detail.summary.authority, detail.summary.path, query
        );
        inherited_url = Some(base_url.clone());
        method_changed = draft
            .method
            .as_deref()
            .is_some_and(|requested| !requested.eq_ignore_ascii_case(&detail.summary.method));
        if draft.method.is_none() {
            method = detail.summary.method;
        }
        if draft.url.is_none() {
            url = base_url;
        }

        let base_headers = db
            .load_raw_headers(project_id, base_id, MessageSide::Request)
            .await?;
        for h in &base_headers {
            if draft.inheritance == ReplyInheritance::CookiesAuthOnly
                && !is_auth_context_header(&h.name)
            {
                continue;
            }
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
        if body.is_none()
            && !draft.body_cleared
            && draft.inheritance == ReplyInheritance::FullRequest
            && !method_changed
        {
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

    if method_changed && !has_explicit_body {
        body = None;
        headers.retain(|(name, _)| {
            !is_entity_header(name)
                || draft
                    .header_overrides
                    .iter()
                    .any(|override_| override_.name.eq_ignore_ascii_case(name))
        });
    }

    // Semantic transports own message framing. Keeping inherited framing is
    // misleading in history and can make a changed body appear malformed.
    headers.retain(|(name, _)| {
        !name.eq_ignore_ascii_case("content-length")
            && !name.eq_ignore_ascii_case("transfer-encoding")
    });

    let host_was_overridden = draft
        .header_overrides
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("host"));
    if !host_was_overridden
        && inherited_url
            .as_deref()
            .is_some_and(|base| origins_differ(base, &url))
    {
        headers.retain(|(name, _)| !name.eq_ignore_ascii_case("host"));
    }

    Ok(MaterializedRequest {
        method,
        url,
        headers,
        body,
    })
}

pub fn normalize_reply_draft(mut draft: ReplyDraft) -> DomainResult<ReplyDraft> {
    let body_sources = usize::from(draft.body_override.is_some())
        + usize::from(draft.body_text.is_some())
        + usize::from(draft.body_json.is_some())
        + usize::from(!draft.body_params.is_empty());
    if body_sources > 1 {
        return Err(DomainError::invalid(
            "provide only one of body_override, body_text, body_json, or body_params",
        ));
    }
    if draft.body_cleared && (body_sources > 0 || draft.body_format.is_some()) {
        return Err(DomainError::invalid(
            "body_cleared cannot be combined with a body value or body_format",
        ));
    }
    let format = draft.body_format;
    match format {
        None => {
            if let Some(text) = draft.body_text.take() {
                draft.body_override = Some(text.into_bytes());
            }
            if let Some(value) = draft.body_json.take() {
                draft.body_override = Some(json_body(&value)?);
                set_content_type(&mut draft, "application/json", false);
            }
        }
        Some(ReplyBodyFormat::Raw) => {
            if draft.body_json.is_some() || !draft.body_params.is_empty() {
                return Err(DomainError::invalid(
                    "raw body format accepts body_override or body_text",
                ));
            }
            if let Some(text) = draft.body_text.take() {
                draft.body_override = Some(text.into_bytes());
            }
            require_body(&draft)?;
        }
        Some(ReplyBodyFormat::Json) => {
            if !draft.body_params.is_empty() {
                return Err(DomainError::invalid(
                    "json body format accepts body_json, body_text, or body_override",
                ));
            }
            if let Some(value) = draft.body_json.take() {
                draft.body_override = Some(json_body(&value)?);
            } else if let Some(text) = draft.body_text.take() {
                draft.body_override = Some(text.into_bytes());
            }
            require_body(&draft)?;
            serde_json::from_slice::<serde_json::Value>(
                draft.body_override.as_deref().unwrap_or_default(),
            )
            .map_err(|error| DomainError::invalid(format!("invalid JSON body: {error}")))?;
            set_content_type(&mut draft, "application/json", true);
        }
        Some(ReplyBodyFormat::Xml) => {
            if draft.body_json.is_some() || !draft.body_params.is_empty() {
                return Err(DomainError::invalid(
                    "xml body format accepts body_text or body_override",
                ));
            }
            if let Some(text) = draft.body_text.take() {
                draft.body_override = Some(text.into_bytes());
            }
            require_body(&draft)?;
            set_content_type(&mut draft, "application/xml", true);
        }
        Some(ReplyBodyFormat::FormUrlencoded) => {
            if draft.body_json.is_some() {
                return Err(DomainError::invalid(
                    "form_urlencoded accepts body_params, body_text, or body_override",
                ));
            }
            if !draft.body_params.is_empty() {
                let mut serializer = url::form_urlencoded::Serializer::new(String::new());
                for parameter in &draft.body_params {
                    serializer.append_pair(&parameter.name, &parameter.value);
                }
                draft.body_override = Some(serializer.finish().into_bytes());
                draft.body_params.clear();
            } else if let Some(text) = draft.body_text.take() {
                draft.body_override = Some(text.into_bytes());
            }
            require_body(&draft)?;
            set_content_type(&mut draft, "application/x-www-form-urlencoded", true);
        }
        Some(ReplyBodyFormat::Multipart) => {
            if draft.body_override.is_some()
                || draft.body_text.is_some()
                || draft.body_json.is_some()
                || draft.body_params.is_empty()
            {
                return Err(DomainError::invalid(
                    "multipart body format requires non-empty body_params only",
                ));
            }
            let boundary = format!("huntproxy-{}", uuid::Uuid::new_v4().simple());
            draft.body_override = Some(multipart_body(&draft.body_params, &boundary)?);
            draft.body_params.clear();
            set_content_type(
                &mut draft,
                &format!("multipart/form-data; boundary={boundary}"),
                true,
            );
        }
    }
    Ok(draft)
}

fn json_body(value: &serde_json::Value) -> DomainResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|error| DomainError::invalid(format!("body_json: {error}")))
}

fn require_body(draft: &ReplyDraft) -> DomainResult<()> {
    if draft.body_override.is_none() {
        Err(DomainError::invalid(
            "the selected body_format requires an explicit body",
        ))
    } else {
        Ok(())
    }
}

fn set_content_type(draft: &mut ReplyDraft, value: &str, replace: bool) {
    if !replace
        && draft
            .header_overrides
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("content-type"))
    {
        return;
    }
    draft
        .header_overrides
        .retain(|header| !header.name.eq_ignore_ascii_case("content-type"));
    draft.header_overrides.push(HeaderPatch {
        name: "Content-Type".into(),
        value: value.as_bytes().to_vec(),
    });
}

fn multipart_body(parameters: &[ReplyBodyParam], boundary: &str) -> DomainResult<Vec<u8>> {
    let mut body = Vec::new();
    for parameter in parameters {
        if parameter.name.is_empty()
            || parameter.name.contains('\r')
            || parameter.name.contains('\n')
            || parameter.name.len() > 1024
        {
            return Err(DomainError::invalid("invalid multipart field name"));
        }
        let name = parameter.name.replace('\\', "\\\\").replace('"', "\\\"");
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(parameter.value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(body)
}

fn is_entity_header(name: &str) -> bool {
    [
        "content-type",
        "content-encoding",
        "content-language",
        "content-location",
    ]
    .iter()
    .any(|header| name.eq_ignore_ascii_case(header))
}

fn is_auth_context_header(name: &str) -> bool {
    ["cookie", "authorization", "origin"]
        .iter()
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
}

fn origins_differ(left: &str, right: &str) -> bool {
    let Ok(left) = url::Url::parse(left) else {
        return true;
    };
    let Ok(right) = url::Url::parse(right) else {
        return true;
    };
    left.scheme() != right.scheme()
        || left.host_str() != right.host_str()
        || left.port_or_known_default() != right.port_or_known_default()
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
pub struct ReplyBodyPreview {
    pub text: String,
    pub truncated: bool,
    pub decoded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode_error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReplySendResult {
    pub exchange_id: Option<ExchangeId>,
    pub diff: Option<ResponseDiff>,
    /// Present only when capture scope excludes the exchange.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<EphemeralReplyResponse>,
    pub response_preview: ReplyBodyPreview,
    pub response_length: i64,
    pub response_body_hash: String,
    pub duration_ms: i64,
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
        let mut mat = materialize_request(
            &self.db,
            project_id,
            base_exchange_id,
            draft,
            &self.placeholder_key,
        )
        .await?;
        // URL rules run before managed cookie lookup so cookies are selected
        // for the effective destination, not the draft destination.
        let mut applied_rules =
            crate::request_rules::apply_url_rules(&self.db, project_id, &mut mat.url).await?;
        let cookie_overridden = draft
            .header_overrides
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("cookie"));
        let cookie_suppressed = draft
            .header_tombstones
            .iter()
            .any(|name| name.eq_ignore_ascii_case("cookie"));
        if !cookie_overridden && !cookie_suppressed {
            if let Some(profile) = self
                .db
                .get_cookie_profile_for_url(project_id, &mat.url)
                .await?
            {
                if let Some(cookie_header) = profile.cookie_header_for_url(&mat.url)? {
                    mat.headers
                        .retain(|(name, _)| !name.eq_ignore_ascii_case("cookie"));
                    mat.headers
                        .push(("Cookie".into(), cookie_header.into_bytes()));
                }
            }
        }
        applied_rules.extend(
            crate::request_rules::apply_message_rules(
                &self.db,
                project_id,
                &mat.url,
                &mut mat.headers,
                mat.body.as_mut(),
            )
            .await?,
        );

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
                match insert {
                    Ok(Some(exchange_id)) => {
                        let _ = self
                            .db
                            .record_exchange_request_rules(
                                project_id,
                                exchange_id,
                                applied_rules.clone(),
                            )
                            .await;
                    }
                    Ok(None) => {}
                    Err(storage_error) => {
                        tracing::warn!(%storage_error, "failed to preserve failed Reply exchange");
                    }
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

        let content_encoding = response_content_encoding(&resp_headers);
        let (preview_body, decoded, decode_error) = match content_encoding.as_deref() {
            Some(encoding) => {
                match decode_content_encodings(&out.body, encoding, MAX_DECODED_BODY_OUTPUT) {
                    Ok(decoded) => (decoded, true, None),
                    Err(error) => (out.body.to_vec(), false, Some(error.to_string())),
                }
            }
            None => (out.body.to_vec(), false, None),
        };
        let page_title = crate::page_title::is_html_mime(mime.as_deref())
            .then(|| crate::page_title::extract_html_title(&preview_body))
            .flatten();
        const REPLY_PREVIEW_BYTES: usize = 4096;
        let preview_end = preview_body.len().min(REPLY_PREVIEW_BYTES);
        let response_preview = ReplyBodyPreview {
            text: String::from_utf8_lossy(&preview_body[..preview_end]).into_owned(),
            truncated: preview_end < preview_body.len() || out.body_truncated,
            decoded,
            content_encoding,
            decode_error,
        };

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
                        page_title,
                        error_message: out
                            .body_truncated
                            .then(|| "response body truncated by project body limit".into()),
                    })
                    .await?,
            )
        } else {
            None
        };
        if let Some(exchange_id) = exchange_id {
            self.db
                .record_exchange_request_rules(project_id, exchange_id, applied_rules.clone())
                .await?;
        }

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
            response_preview,
            response_length,
            response_body_hash,
            duration_ms,
            status_code,
        })
    }
}

fn response_content_encoding(headers: &[HeaderEntry]) -> Option<String> {
    let values = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
        .map(|header| String::from_utf8_lossy(&header.value).trim().to_string())
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("identity"))
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::storage::NewExchange;
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

    struct GzipTransport;

    #[async_trait::async_trait]
    impl SemanticTransport for GzipTransport {
        async fn send(
            &self,
            _dial: &ValidatedDial,
            _request: OutboundRequest,
        ) -> DomainResult<OutboundResponse> {
            use std::io::Write;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(b"decoded preview").unwrap();
            Ok(OutboundResponse {
                status: http::StatusCode::CREATED,
                headers: vec![
                    ("content-type".into(), b"text/plain".to_vec()),
                    ("content-encoding".into(), b"gzip".to_vec()),
                ],
                body: bytes::Bytes::from(encoder.finish().unwrap()),
                body_truncated: false,
                protocol: "HTTP/2".into(),
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

    type RecordedHeaders = Vec<(String, Vec<u8>)>;

    struct RecordingTransport {
        headers: Arc<std::sync::Mutex<Vec<RecordedHeaders>>>,
    }

    #[async_trait::async_trait]
    impl SemanticTransport for RecordingTransport {
        async fn send(
            &self,
            _dial: &ValidatedDial,
            request: OutboundRequest,
        ) -> DomainResult<OutboundResponse> {
            self.headers.lock().unwrap().push(request.headers);
            Ok(OutboundResponse {
                status: http::StatusCode::OK,
                headers: vec![],
                body: bytes::Bytes::new(),
                body_truncated: false,
                protocol: "HTTP/1.1".into(),
                transport_provenance: TransportProvenance::GenericUnprofiled,
                transport_profile: "test".into(),
                duration: Duration::from_millis(1),
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
    async fn managed_cookie_replaces_inherited_but_not_explicit_cookie() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "cookies".into(),
                target_url: "http://127.0.0.1".into(),
                advanced: None,
            })
            .await
            .unwrap();
        db.upsert_cookie_profile(
            project.id,
            crate::cookies::validate_cookie_profile("http://127.0.0.1", "sid=managed".into())
                .unwrap(),
        )
        .await
        .unwrap();
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let service = ReplyService {
            db,
            transport: Arc::new(RecordingTransport {
                headers: recorded.clone(),
            }),
            placeholder_key: PlaceholderKey::from_bytes(vec![1; 32]),
        };

        service
            .send(
                project.id,
                None,
                None,
                &ReplyDraft {
                    method: Some("GET".into()),
                    url: Some("http://127.0.0.1/".into()),
                    ..Default::default()
                },
                ProtocolPreference::H1,
                0,
            )
            .await
            .unwrap();
        service
            .send(
                project.id,
                None,
                None,
                &ReplyDraft {
                    method: Some("GET".into()),
                    url: Some("http://127.0.0.1/".into()),
                    header_overrides: vec![HeaderPatch {
                        name: "Cookie".into(),
                        value: b"sid=explicit".to_vec(),
                    }],
                    ..Default::default()
                },
                ProtocolPreference::H1,
                0,
            )
            .await
            .unwrap();

        let requests = recorded.lock().unwrap();
        assert!(requests[0]
            .iter()
            .any(|(name, value)| name == "Cookie" && value == b"sid=managed"));
        assert!(requests[1]
            .iter()
            .any(|(name, value)| name == "Cookie" && value == b"sid=explicit"));
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
                    excluded_host_patterns: vec![],
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

    #[test]
    fn reply_body_conveniences_normalize_to_canonical_bytes() {
        let text = normalize_reply_draft(ReplyDraft {
            body_text: Some("hello".into()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(text.body_override.as_deref(), Some(b"hello".as_slice()));
        assert!(text.body_text.is_none());

        let json = normalize_reply_draft(ReplyDraft {
            body_json: Some(serde_json::json!({"ok": true})),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            json.body_override.as_deref(),
            Some(br#"{"ok":true}"#.as_slice())
        );
        assert!(json.header_overrides.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type") && header.value == b"application/json"
        }));

        assert!(normalize_reply_draft(ReplyDraft {
            body_override: Some(vec![1]),
            body_text: Some("conflict".into()),
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn semantic_body_formats_update_content_type_and_structure() {
        let json = normalize_reply_draft(ReplyDraft {
            body_format: Some(ReplyBodyFormat::Json),
            body_text: Some("{\"ok\":true}".into()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            json.body_override.as_deref(),
            Some(b"{\"ok\":true}".as_slice())
        );
        assert!(json.header_overrides.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type") && header.value == b"application/json"
        }));

        let form = normalize_reply_draft(ReplyDraft {
            body_format: Some(ReplyBodyFormat::FormUrlencoded),
            body_params: vec![
                ReplyBodyParam {
                    name: "a".into(),
                    value: "hello world".into(),
                },
                ReplyBodyParam {
                    name: "a".into(),
                    value: "two".into(),
                },
            ],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            form.body_override.as_deref(),
            Some(b"a=hello+world&a=two".as_slice())
        );

        let multipart = normalize_reply_draft(ReplyDraft {
            body_format: Some(ReplyBodyFormat::Multipart),
            body_params: vec![ReplyBodyParam {
                name: "name".into(),
                value: "value".into(),
            }],
            ..Default::default()
        })
        .unwrap();
        let content_type = multipart
            .header_overrides
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-type"))
            .unwrap();
        assert!(String::from_utf8_lossy(&content_type.value)
            .starts_with("multipart/form-data; boundary=huntproxy-"));
        assert!(
            String::from_utf8_lossy(multipart.body_override.as_deref().unwrap())
                .contains("name=\"name\"\r\n\r\nvalue")
        );

        assert!(normalize_reply_draft(ReplyDraft {
            body_format: Some(ReplyBodyFormat::Json),
            body_text: Some("not-json".into()),
            ..Default::default()
        })
        .is_err());
    }

    #[tokio::test]
    async fn auth_only_inheritance_drops_stale_request_shape() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "inheritance".into(),
                target_url: "https://base.test/rpc".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let base = db
            .insert_exchange(NewExchange {
                project_id: project.id,
                source: ExchangeSource::Proxy,
                protocol: "HTTP/2".into(),
                method: "POST".into(),
                scheme: "https".into(),
                authority: "base.test".into(),
                host: "base.test".into(),
                port: 443,
                path: "/rpc".into(),
                query: None,
                status_code: Some(200),
                mime: Some("application/json+protobuf".into()),
                completion: CompletionState::Complete,
                capture_quality: CaptureQuality::Semantic,
                header_representation: HeaderRepresentation::Semantic,
                body_representation: BodyRepresentation::SemanticEncoded,
                cache_provenance: CacheProvenance::None,
                transport_provenance: Some(TransportProvenance::ProtocolProfileOnly),
                transport_profile: Some("test".into()),
                request_headers: [
                    ("Host", "base.test"),
                    ("Cookie", "sid=secret"),
                    ("Authorization", "Bearer secret"),
                    ("Origin", "https://base.test"),
                    ("Content-Type", "application/json+protobuf"),
                    ("Content-Length", "44"),
                    ("X-Goog-Api-Key", "wrong-key"),
                ]
                .into_iter()
                .enumerate()
                .map(|(ordinal, (name, value))| HeaderEntry {
                    name: name.into(),
                    value: value.as_bytes().to_vec(),
                    ordinal: ordinal as u32,
                })
                .collect(),
                response_headers: vec![],
                request_body: Some(b"old protobuf body".to_vec()),
                response_body: None,
                duration_ms: Some(1),
                lineage: ExchangeLineage::default(),
                page_title: None,
                error_message: None,
            })
            .await
            .unwrap();

        let request = materialize_request(
            &db,
            project.id,
            Some(base),
            &ReplyDraft {
                method: Some("POST".into()),
                url: Some("https://other.test/rest".into()),
                inheritance: ReplyInheritance::CookiesAuthOnly,
                body_json: Some(serde_json::json!({"partner": 7})),
                ..Default::default()
            },
            &PlaceholderKey::from_bytes(vec![1; 32]),
        )
        .await
        .unwrap();

        assert_eq!(
            request.body.as_deref(),
            Some(br#"{"partner":7}"#.as_slice())
        );
        for expected in ["cookie", "authorization", "origin", "content-type"] {
            assert!(request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(expected)));
        }
        for removed in [
            "host",
            "content-length",
            "transfer-encoding",
            "x-goog-api-key",
        ] {
            assert!(!request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(removed)));
        }

        let changed_to_get = materialize_request(
            &db,
            project.id,
            Some(base),
            &ReplyDraft {
                method: Some("GET".into()),
                url: Some("https://base.test/rpc".into()),
                ..Default::default()
            },
            &PlaceholderKey::from_bytes(vec![1; 32]),
        )
        .await
        .unwrap();
        assert!(changed_to_get.body.is_none());
        assert!(!changed_to_get.headers.iter().any(|(name, _)| {
            name.eq_ignore_ascii_case("content-type") || name.eq_ignore_ascii_case("content-length")
        }));
    }

    #[tokio::test]
    async fn reply_result_includes_decoded_body_preview() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "preview".into(),
                target_url: "http://127.0.0.1/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let service = ReplyService {
            db,
            transport: Arc::new(GzipTransport),
            placeholder_key: PlaceholderKey::from_bytes(vec![1; 32]),
        };
        let result = service
            .send(
                project.id,
                None,
                None,
                &ReplyDraft {
                    method: Some("GET".into()),
                    url: Some("http://127.0.0.1/".into()),
                    ..Default::default()
                },
                ProtocolPreference::H2,
                0,
            )
            .await
            .unwrap();

        assert_eq!(result.status_code, 201);
        assert_eq!(result.response_preview.text, "decoded preview");
        assert!(result.response_preview.decoded);
        assert_eq!(
            result.response_preview.content_encoding.as_deref(),
            Some("gzip")
        );
    }
}
