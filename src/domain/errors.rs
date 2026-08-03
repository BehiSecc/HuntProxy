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
    ChromiumNotInstalled,
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
            Self::ChromiumNotInstalled => "chromium_not_installed",
            Self::LoginRequired => "login_required",
            Self::ConfigInvalid => "config_invalid",
            Self::DaemonNotRunning => "daemon_not_running",
            Self::DaemonAlreadyRunning => "daemon_already_running",
            Self::ProtocolIncompatible => "protocol_incompatible",
        }
    }

    pub fn from_code(value: &str) -> Option<Self> {
        Some(match value {
            "internal" => Self::Internal,
            "invalid_argument" => Self::InvalidArgument,
            "not_found" => Self::NotFound,
            "conflict" => Self::Conflict,
            "unauthorized" => Self::Unauthorized,
            "forbidden" => Self::Forbidden,
            "unavailable" => Self::Unavailable,
            "cancelled" => Self::Cancelled,
            "timeout" => Self::Timeout,
            "scope_denied" => Self::ScopeDenied,
            "dns_blocked" => Self::DnsBlocked,
            "rate_limited" => Self::RateLimited,
            "concurrency_limited" => Self::ConcurrencyLimited,
            "body_too_large" => Self::BodyTooLarge,
            "disk_quota_exceeded" => Self::DiskQuotaExceeded,
            "proxy_auth_required" => Self::ProxyAuthRequired,
            "capture_incomplete" => Self::CaptureIncomplete,
            "protocol_error" => Self::ProtocolError,
            "storage_error" => Self::StorageError,
            "migration_error" => Self::MigrationError,
            "revision_conflict" => Self::RevisionConflict,
            "placeholder_invalid" => Self::PlaceholderInvalid,
            "job_interrupted" => Self::JobInterrupted,
            "combination_limit" => Self::CombinationLimit,
            "browser_disabled" => Self::BrowserDisabled,
            "chromium_not_installed" => Self::ChromiumNotInstalled,
            "login_required" => Self::LoginRequired,
            "config_invalid" => Self::ConfigInvalid,
            "daemon_not_running" => Self::DaemonNotRunning,
            "daemon_already_running" => Self::DaemonAlreadyRunning,
            "protocol_incompatible" => Self::ProtocolIncompatible,
            _ => return None,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_error_codes_round_trip_from_daemon_envelopes() {
        for code in [
            ErrorCode::InvalidArgument,
            ErrorCode::NotFound,
            ErrorCode::Timeout,
            ErrorCode::BrowserDisabled,
            ErrorCode::ProtocolError,
        ] {
            assert_eq!(ErrorCode::from_code(code.as_str()), Some(code));
        }
        assert_eq!(ErrorCode::from_code("future_code"), None);
    }
}
