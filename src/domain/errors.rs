//! Stable public error codes and domain errors.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Machine-readable error codes exposed via API/MCP/CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // generic
    Internal,
    InvalidArgument,
    NotFound,
    Conflict,
    Unauthorized,
    Forbidden,
    Unavailable,
    Cancelled,
    Timeout,
    // scope / network
    ScopeDenied,
    DnsBlocked,
    RateLimited,
    ConcurrencyLimited,
    BodyTooLarge,
    DiskQuotaExceeded,
    // proxy / capture
    ProxyAuthRequired,
    CaptureIncomplete,
    ProtocolError,
    // storage
    StorageError,
    MigrationError,
    // reply / fuzz
    RevisionConflict,
    PlaceholderInvalid,
    JobInterrupted,
    CombinationLimit,
    // browser
    BrowserDisabled,
    BrowserNotInstalled,
    ChromiumNotInstalled,
    LightpandaNotInstalled,
    EngineFallback,
    MigrationPartial,
    LoginRequired,
    // config / process
    ConfigInvalid,
    DaemonNotRunning,
    DaemonAlreadyRunning,
    ProtocolIncompatible,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::InvalidArgument => "invalid_argument",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::Unavailable => "unavailable",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::ScopeDenied => "scope_denied",
            Self::DnsBlocked => "dns_blocked",
            Self::RateLimited => "rate_limited",
            Self::ConcurrencyLimited => "concurrency_limited",
            Self::BodyTooLarge => "body_too_large",
            Self::DiskQuotaExceeded => "disk_quota_exceeded",
            Self::ProxyAuthRequired => "proxy_auth_required",
            Self::CaptureIncomplete => "capture_incomplete",
            Self::ProtocolError => "protocol_error",
            Self::StorageError => "storage_error",
            Self::MigrationError => "migration_error",
            Self::RevisionConflict => "revision_conflict",
            Self::PlaceholderInvalid => "placeholder_invalid",
            Self::JobInterrupted => "job_interrupted",
            Self::CombinationLimit => "combination_limit",
            Self::BrowserDisabled => "browser_disabled",
            Self::BrowserNotInstalled => "browser_not_installed",
            Self::ChromiumNotInstalled => "chromium_not_installed",
            Self::LightpandaNotInstalled => "lightpanda_not_installed",
            Self::EngineFallback => "engine_fallback",
            Self::MigrationPartial => "migration_partial",
            Self::LoginRequired => "login_required",
            Self::ConfigInvalid => "config_invalid",
            Self::DaemonNotRunning => "daemon_not_running",
            Self::DaemonAlreadyRunning => "daemon_already_running",
            Self::ProtocolIncompatible => "protocol_incompatible",
        }
    }
}

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("{message}")]
    App {
        code: ErrorCode,
        message: String,
        details: Option<serde_json::Value>,
    },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl DomainError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::App {
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(
        code: ErrorCode,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self::App {
            code,
            message: message.into(),
            details: Some(details),
        }
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            Self::App { code, .. } => *code,
            Self::Other(_) => ErrorCode::Internal,
        }
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, msg)
    }

    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, msg)
    }

    pub fn scope_denied(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::ScopeDenied, msg)
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, msg)
    }
}

pub type DomainResult<T> = Result<T, DomainError>;

/// Structured API/MCP error envelope (never contains secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl From<&DomainError> for ErrorEnvelope {
    fn from(err: &DomainError) -> Self {
        match err {
            DomainError::App {
                code,
                message,
                details,
            } => Self {
                code: code.as_str().to_string(),
                message: message.clone(),
                details: details.clone(),
                request_id: None,
            },
            DomainError::Other(e) => Self {
                code: ErrorCode::Internal.as_str().to_string(),
                message: e.to_string(),
                details: None,
                request_id: None,
            },
        }
    }
}
