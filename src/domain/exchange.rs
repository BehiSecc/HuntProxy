//! Immutable exchange and message evidence model.

use super::ids::*;
use serde::{Deserialize, Serialize};
use time::serde::rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeSource {
    Browser,
    Reply,
    Fuzzer,
    Plugin,
    Proxy,
    Imported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionState {
    InProgress,
    Complete,
    Timeout,
    Cancelled,
    ConnectionError,
    ProtocolError,
    TruncatedByPolicy,
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureQuality {
    /// Best-effort wire preservation through Hyper/Hudsucker.
    WirePreserved,
    /// Exact evidence on one message side and decoded/semantic evidence on the other.
    Mixed,
    /// Semantic proxy path (Hyper/Wreq serialization).
    Semantic,
    /// Playwright/CDP observation.
    BrowserObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderRepresentation {
    WirePreserved,
    Mixed,
    Semantic,
    BrowserObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyRepresentation {
    WireEncoded,
    Mixed,
    SemanticEncoded,
    BrowserDecoded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    ProtocolProfileOnly,
    IdentityInconsistent,
    GenericUnprofiled,
    ChromiumWireFidelity,
    SemanticProxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheProvenance {
    Unknown,
    RouteCacheDisabled,
    BrowserCache,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageSide {
    Request,
    Response,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderEntry {
    pub name: String,
    pub value: Vec<u8>,
    pub ordinal: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeSummary {
    pub project_id: ProjectId,
    pub exchange_id: ExchangeId,
    pub source: ExchangeSource,
    #[serde(with = "rfc3339")]
    pub started_at: OffsetDateTime,
    pub duration_ms: Option<i64>,
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
    pub status_code: Option<u16>,
    pub mime: Option<String>,
    pub request_length: Option<i64>,
    pub response_length: Option<i64>,
    pub completion: CompletionState,
    pub capture_quality: CaptureQuality,
    pub page_title: Option<String>,
    pub display_title: Option<String>,
    pub labels: Vec<String>,
    pub parent_exchange_id: Option<ExchangeId>,
    pub transport_provenance: Option<TransportProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeDetail {
    pub summary: ExchangeSummary,
    pub protocol: String,
    pub header_representation: HeaderRepresentation,
    pub body_representation: BodyRepresentation,
    pub cache_provenance: CacheProvenance,
    pub request_headers: Vec<PresentedHeader>,
    pub response_headers: Vec<PresentedHeader>,
    pub request_preview: Option<String>,
    pub response_preview: Option<String>,
    pub redacted_count: u32,
    pub noisy_hidden_count: u32,
    pub request_body_hash: Option<String>,
    pub response_body_hash: Option<String>,
    pub lineage: ExchangeLineage,
}

/// Header as presented to API/UI/MCP (sensitive values already redacted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentedHeader {
    pub name: String,
    pub value: String,
    pub redacted: bool,
    pub noisy: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExchangeLineage {
    pub parent_exchange_id: Option<ExchangeId>,
    pub redirect_parent_id: Option<ExchangeId>,
    pub reply_tab_id: Option<ReplyTabId>,
    pub fuzz_job_id: Option<FuzzJobId>,
    pub fuzz_case_id: Option<i64>,
    pub browser_session_id: Option<BrowserSessionId>,
    pub browser_action_id: Option<BrowserActionId>,
    pub capture_session_id: Option<CaptureSessionId>,
}
