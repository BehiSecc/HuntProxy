//! Projects, capture sessions, reply, fuzz, browser domain models.

use super::ids::*;
use serde::{Deserialize, Serialize};
use time::serde::rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: ProjectId,
    pub name: String,
    /// Starting target used for project context and quick browser actions.
    /// It is metadata, not an implicit capture scope.
    pub target_url: String,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub updated_at: OffsetDateTime,
    pub scope: ScopePolicy,
    pub limits: ProjectLimits,
    pub default_browser_profile: String,
    pub noise_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScopePolicy {
    pub schemes: Vec<String>,
    pub host_patterns: Vec<String>,
    /// Host patterns that must not be captured. Exclusions take precedence
    /// over `host_patterns`; an empty include list still means capture all
    /// otherwise-matching hosts.
    #[serde(
        default,
        alias = "out_of_scope_host_patterns",
        alias = "exclude_host_patterns"
    )]
    pub excluded_host_patterns: Vec<String>,
    pub ports: Vec<u16>,
    /// Empty means any path.
    pub path_prefixes: Vec<String>,
}

impl Default for ScopePolicy {
    fn default() -> Self {
        Self {
            schemes: vec!["http".into(), "https".into()],
            host_patterns: vec![],
            excluded_host_patterns: vec![],
            ports: vec![],
            path_prefixes: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectLimits {
    pub requests_per_second: f64,
    pub max_concurrent_requests: u32,
    pub max_concurrent_browsers: u32,
    pub max_body_bytes: u64,
    pub max_fuzz_cases: u64,
    pub max_disk_bytes: u64,
    pub capture_body_bytes: u64,
    pub fuzz_confirm_threshold: u64,
}

/// Default per-project logical capture allowance: exactly 2 GiB
/// (2 × 1024³ bytes), not 2 decimal GB.
pub const DEFAULT_PROJECT_DISK_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The most requests a project may have in flight at once. Transport pools
/// keep this many idle connections per host so a full budget reuses them.
pub const MAX_CONCURRENT_REQUESTS: u32 = 256;

impl Default for ProjectLimits {
    fn default() -> Self {
        Self {
            requests_per_second: 50.0,
            max_concurrent_requests: 32,
            max_concurrent_browsers: 2,
            max_body_bytes: 25 * 1024 * 1024,
            max_fuzz_cases: 100_000,
            max_disk_bytes: DEFAULT_PROJECT_DISK_BYTES,
            capture_body_bytes: 10 * 1024 * 1024,
            fuzz_confirm_threshold: 5_000,
        }
    }
}

#[cfg(test)]
mod project_limit_tests {
    use super::*;

    #[test]
    fn default_capture_quota_is_exactly_two_gibibytes() {
        assert_eq!(DEFAULT_PROJECT_DISK_BYTES, 2_147_483_648);
        assert_eq!(ProjectLimits::default().max_disk_bytes, 2_147_483_648);
    }
}

/// Result of target resolution. Addresses are pinned for the lifetime of one
/// send so the transport cannot silently perform a second DNS lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedDial {
    pub hostname: String,
    pub port: u16,
    pub approved_socket_addrs: Vec<std::net::SocketAddr>,
    pub policy_epoch: u64,
    #[serde(with = "rfc3339")]
    pub expires_at: OffsetDateTime,
    pub scheme: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSessionStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSession {
    pub id: CaptureSessionId,
    pub project_id: ProjectId,
    pub browser_session_id: Option<BrowserSessionId>,
    pub browser_action_id: Option<BrowserActionId>,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    pub status: CaptureSessionStatus,
    pub is_browser_bound: bool,
    /// Present only at creation/renewal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_once: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_presentation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_presentation: Option<String>,
}

/// Fixed Basic-auth username for Chromium/external clients.
pub const PROXY_BASIC_USER: &str = "huntproxy";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: AnnotationId,
    pub project_id: ProjectId,
    pub exchange_id: ExchangeId,
    pub display_title: Option<String>,
    pub note: Option<String>,
    pub labels: Vec<String>,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub updated_at: OffsetDateTime,
    pub revision: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationUpdate {
    pub display_title: Option<String>,
    pub note: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    pub expected_revision: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub project_id: ProjectId,
    pub exchange_id: ExchangeId,
    pub title: String,
    pub description: String,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SitemapHost {
    pub host: String,
    /// Backward-compatible, unique list of paths.
    pub paths: Vec<String>,
    /// Aggregated request/response observations for each path.
    #[serde(default)]
    pub routes: Vec<SitemapRoute>,
    /// Path segments arranged as a browsable tree.
    #[serde(default)]
    pub tree: Vec<SitemapNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SitemapHostSummary {
    pub host: String,
    pub route_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SitemapRoute {
    pub path: String,
    pub methods: Vec<String>,
    pub status_codes: Vec<u16>,
    pub parameters: Vec<String>,
    pub content_types: Vec<String>,
    pub exchange_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SitemapNode {
    pub segment: String,
    pub path: String,
    pub route: Option<SitemapRoute>,
    pub children: Vec<SitemapNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolPreference {
    #[default]
    Auto,
    H1,
    H2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyTab {
    pub id: ReplyTabId,
    pub project_id: ProjectId,
    pub name: String,
    pub base_exchange_id: Option<ExchangeId>,
    pub revision: i64,
    pub protocol: ProtocolPreference,
    pub draft: ReplyDraft,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Canonical draft: base inheritance + overrides/tombstones. Never sanitized text.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplyDraft {
    pub method: Option<String>,
    pub url: Option<String>,
    /// Omission preserves legacy credentials. Named and anonymous selections
    /// isolate the request from inherited and rule-supplied credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<ReplyIdentity>,
    /// Header overrides: name -> value bytes (base64 in JSON APIs as needed).
    pub header_overrides: Vec<HeaderPatch>,
    /// Header names tombstoned (removed from base).
    pub header_tombstones: Vec<String>,
    /// How much of the base request is inherited. Full request preserves the
    /// original behavior; cookies/auth-only is safer for a new endpoint.
    pub inheritance: ReplyInheritance,
    pub body_override: Option<Vec<u8>>,
    /// UTF-8 convenience input. Mutually exclusive with body_override/body_json.
    pub body_text: Option<String>,
    /// JSON convenience input. Serialized compactly and defaults Content-Type
    /// to application/json when no explicit Content-Type override exists.
    pub body_json: Option<serde_json::Value>,
    /// Optional semantic body format. When set, normalization updates
    /// Content-Type and validates/serializes the corresponding body input.
    pub body_format: Option<ReplyBodyFormat>,
    /// Ordered text fields for form-urlencoded and multipart bodies.
    pub body_params: Vec<ReplyBodyParam>,
    pub body_cleared: bool,
    /// Internal send policy used by bounded extensions. This is deliberately
    /// not part of the public Reply draft JSON contract.
    #[serde(skip)]
    pub credential_mode: ReplyCredentialMode,
}

/// Keys a request-supplied `draft` may carry. Stored drafts (reply revisions,
/// bundles) are deliberately not held to this list so old data keeps loading.
const REPLY_DRAFT_REQUEST_FIELDS: &[&str] = &[
    "method",
    "url",
    "identity",
    "header_overrides",
    "header_tombstones",
    "inheritance",
    "body_override",
    "body_text",
    "body_json",
    "body_format",
    "body_params",
    "body_cleared",
];

/// Rejects unknown keys in a request-supplied reply draft instead of letting
/// serde drop them and send a request without the caller's intent.
pub fn validate_reply_draft_request(value: &serde_json::Value) -> Result<(), String> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for key in object.keys() {
        if REPLY_DRAFT_REQUEST_FIELDS.contains(&key.as_str()) {
            continue;
        }
        let hint = match key.as_str() {
            "headers" | "header" => " (use `header_overrides`: [{\"name\", \"value\"}])",
            "body" => " (use `body_text`, `body_json`, or `body_params`)",
            _ => "",
        };
        return Err(format!(
            "unknown field `{key}` in draft{hint}; allowed fields: {}",
            REPLY_DRAFT_REQUEST_FIELDS.join(", ")
        ));
    }
    Ok(())
}

/// Deserializes a request-supplied draft and rejects unknown keys.
pub fn deserialize_reply_draft_request<'de, D>(deserializer: D) -> Result<ReplyDraft, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    validate_reply_draft_request(&value).map_err(serde::de::Error::custom)?;
    serde_json::from_value(value).map_err(serde::de::Error::custom)
}

/// Optional variant of [`deserialize_reply_draft_request`].
pub fn deserialize_optional_reply_draft_request<'de, D>(
    deserializer: D,
) -> Result<Option<ReplyDraft>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = Option::<serde_json::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    validate_reply_draft_request(&value).map_err(serde::de::Error::custom)?;
    serde_json::from_value(value)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReplyIdentity {
    Default {},
    Named { profile: String },
    Anonymous {},
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReplyCredentialMode {
    #[default]
    WithProjectCredentials,
    WithoutProjectCredentials,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyBodyFormat {
    Raw,
    Json,
    Xml,
    FormUrlencoded,
    Multipart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyBodyParam {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyInheritance {
    #[default]
    FullRequest,
    CookiesAuthOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderPatch {
    pub name: String,
    /// Raw value; never a presentation placeholder.
    #[serde(with = "serde_bytes_or_string")]
    pub value: Vec<u8>,
}

mod serde_bytes_or_string {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Ok(s) = std::str::from_utf8(bytes) {
            serializer.serialize_str(s)
        } else {
            serializer.serialize_str(&format!(
                "base64:{}",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            ))
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrBytes {
            String(String),
            Bytes(Vec<u8>),
        }

        match StringOrBytes::deserialize(deserializer)? {
            StringOrBytes::String(s) => {
                if let Some(rest) = s.strip_prefix("base64:") {
                    base64::engine::general_purpose::STANDARD
                        .decode(rest)
                        .map_err(serde::de::Error::custom)
                } else {
                    Ok(s.into_bytes())
                }
            }
            StringOrBytes::Bytes(bytes) => Ok(bytes),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzStrategy {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzJobState {
    Queued,
    Running,
    Cancelling,
    Completed,
    Failed,
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzCaseState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FuzzCasePayload {
    pub insertion_point: String,
    pub location: String,
    pub encoding: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzCaseResult {
    pub id: i64,
    pub job_id: FuzzJobId,
    pub project_id: ProjectId,
    pub case_index: u64,
    pub state: FuzzCaseState,
    pub payloads: Vec<FuzzCasePayload>,
    pub exchange_id: Option<ExchangeId>,
    pub status_code: Option<u16>,
    pub response_length: Option<i64>,
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
    pub body_hash: Option<String>,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "rfc3339::option")]
    pub started_at: Option<OffsetDateTime>,
    #[serde(with = "rfc3339::option")]
    pub finished_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzJob {
    pub id: FuzzJobId,
    pub project_id: ProjectId,
    pub base_exchange_id: Option<ExchangeId>,
    pub state: FuzzJobState,
    pub strategy: FuzzStrategy,
    pub estimated_cases: u64,
    pub completed_cases: u64,
    pub failed_cases: u64,
    pub error: Option<String>,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserEngine {
    Chromium,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserSessionState {
    Starting,
    Ready,
    Busy,
    Interrupted,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSession {
    pub id: BrowserSessionId,
    pub project_id: ProjectId,
    pub engine: BrowserEngine,
    /// Named persistent browser identity. Ephemeral internal sessions have no profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default)]
    pub requested_profile: Option<String>,
    /// Set only after the live worker confirms this identity and its directory.
    #[serde(default)]
    pub active_profile: Option<String>,
    pub current_url: Option<String>,
    /// Last title reported by the active page, retained for client reattachment.
    pub current_title: Option<String>,
    pub state: BrowserSessionState,
    pub checkpoint_status: Option<String>,
    pub checkpoint_hash: Option<String>,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    /// Target URL used as project metadata; it does not implicitly enable scope.
    pub target_url: String,
    #[serde(default)]
    pub advanced: Option<ScopePolicy>,
}

#[cfg(test)]
mod reply_draft_request_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_validation_rejects_unknown_keys_with_hints() {
        let error = validate_reply_draft_request(&json!({"headers": []})).unwrap_err();
        assert!(error.contains("header_overrides"), "{error}");
        let error = validate_reply_draft_request(&json!({"body": "x"})).unwrap_err();
        assert!(error.contains("body_text"), "{error}");
        let error = validate_reply_draft_request(&json!({"credential_mode": "x"})).unwrap_err();
        assert!(error.contains("credential_mode"), "{error}");
        validate_reply_draft_request(&json!({"url": "https://example.test/", "body_json": {}}))
            .unwrap();
    }

    #[test]
    fn deserializer_helpers_reject_unknown_keys_but_stored_drafts_still_load() {
        #[derive(Deserialize)]
        struct Request {
            #[serde(deserialize_with = "deserialize_reply_draft_request")]
            draft: ReplyDraft,
            #[serde(default, deserialize_with = "deserialize_optional_reply_draft_request")]
            maybe: Option<ReplyDraft>,
        }
        let error = serde_json::from_value::<Request>(json!({"draft": {"headers": []}}))
            .err()
            .unwrap();
        assert!(error.to_string().contains("header_overrides"));
        let error = serde_json::from_value::<Request>(json!({"draft": {}, "maybe": {"body": 1}}))
            .err()
            .unwrap();
        assert!(error.to_string().contains("body_text"));
        let ok = serde_json::from_value::<Request>(json!({"draft": {"method": "GET"}})).unwrap();
        assert_eq!(ok.draft.method.as_deref(), Some("GET"));
        assert!(ok.maybe.is_none());

        // Stored data written by older versions may carry keys this version does
        // not know; it must keep loading.
        let stored: ReplyDraft =
            serde_json::from_value(json!({"method": "GET", "legacy_field": true})).unwrap();
        assert_eq!(stored.method.as_deref(), Some("GET"));
    }
}
