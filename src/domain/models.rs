//! Projects, capture sessions, reply, fuzz, browser domain models.

use super::ids::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::serde::rfc3339;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: ProjectId,
    pub name: String,
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
pub struct ScopePolicy {
    pub schemes: Vec<String>,
    pub host_patterns: Vec<String>,
    pub ports: Vec<u16>,
    /// Empty means any path.
    pub path_prefixes: Vec<String>,
    pub allow_loopback: bool,
    pub allow_private_network: bool,
    pub allow_link_local: bool,
    pub allow_metadata: bool,
}

impl Default for ScopePolicy {
    fn default() -> Self {
        Self {
            schemes: vec!["http".into(), "https".into()],
            host_patterns: vec![],
            ports: vec![],
            path_prefixes: vec![],
            allow_loopback: false,
            allow_private_network: false,
            allow_link_local: false,
            allow_metadata: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for ProjectLimits {
    fn default() -> Self {
        Self {
            requests_per_second: 50.0,
            max_concurrent_requests: 32,
            max_concurrent_browsers: 2,
            max_body_bytes: 25 * 1024 * 1024,
            max_fuzz_cases: 100_000,
            max_disk_bytes: 2 * 1024 * 1024 * 1024,
            capture_body_bytes: 10 * 1024 * 1024,
            fuzz_confirm_threshold: 5_000,
        }
    }
}

/// Result of scope resolution — transports dial only approved addresses.
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
pub const PROXY_BASIC_USER: &str = "bb";

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
pub struct ReplyDraft {
    pub method: Option<String>,
    pub url: Option<String>,
    /// Header overrides: name -> value bytes (base64 in JSON APIs as needed).
    pub header_overrides: Vec<HeaderPatch>,
    /// Header names tombstoned (removed from base).
    pub header_tombstones: Vec<String>,
    pub body_override: Option<Vec<u8>>,
    pub body_cleared: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderPatch {
    pub name: String,
    /// Raw value; never a presentation placeholder.
    #[serde(with = "serde_bytes_or_string")]
    pub value: Vec<u8>,
}

mod serde_bytes_or_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use base64::Engine;

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
        let s = String::deserialize(deserializer)?;
        if let Some(rest) = s.strip_prefix("base64:") {
            base64::engine::general_purpose::STANDARD
                .decode(rest)
                .map_err(serde::de::Error::custom)
        } else {
            Ok(s.into_bytes())
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
    Paused,
    Cancelling,
    Completed,
    Failed,
    Interrupted,
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
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserEngine {
    Lightpanda,
    Chromium,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnginePolicy {
    Auto,
    Chromium,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserSessionState {
    Starting,
    Ready,
    Busy,
    Migrating,
    Interrupted,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSession {
    pub id: BrowserSessionId,
    pub project_id: ProjectId,
    pub engine: BrowserEngine,
    pub engine_policy: EnginePolicy,
    pub current_url: Option<String>,
    pub state: BrowserSessionState,
    pub fallback_used: bool,
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
    /// Target URL used to derive initial scope.
    pub target_url: String,
    #[serde(default)]
    pub advanced: Option<ScopePolicy>,
}
