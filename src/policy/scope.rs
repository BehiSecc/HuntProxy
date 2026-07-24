//! Scope policy resolution and ValidatedDial.

use crate::domain::{
    DomainError, DomainResult, ErrorCode, ProjectLimits, ScopePolicy, ValidatedDial,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use time::OffsetDateTime;
use url::Url;

static POLICY_EPOCH: AtomicU64 = AtomicU64::new(1);

pub fn bump_policy_epoch() -> u64 {
    POLICY_EPOCH.fetch_add(1, Ordering::SeqCst) + 1
}

pub fn current_policy_epoch() -> u64 {
    POLICY_EPOCH.load(Ordering::SeqCst)
}

#[derive(Debug, Clone)]
pub struct TargetRef {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
}

impl TargetRef {
    pub fn from_url(raw: &str) -> DomainResult<Self> {
        let url = Url::parse(raw).map_err(|e| DomainError::invalid(format!("bad url: {e}")))?;
        let scheme = url.scheme().to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(DomainError::invalid("only http/https supported"));
        }
        let host = url
            .host_str()
            .ok_or_else(|| DomainError::invalid("url missing host"))?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        // IDNA: url crate already parses; store unicode/punycode as given normalized lower.
        let port = url
            .port()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() {
            "/".into()
        } else {
            url.path().to_string()
        };
        let query = url.query().map(|q| q.to_string());
        Ok(Self {
            scheme,
            host,
            port,
            path,
            query,
        })
    }

    pub fn authority(&self) -> String {
        if (self.scheme == "http" && self.port == 80)
            || (self.scheme == "https" && self.port == 443)
        {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Derive default scope from a target URL for project creation.
pub fn derive_scope_from_target(target_url: &str) -> DomainResult<ScopePolicy> {
    let t = TargetRef::from_url(target_url)?;
    Ok(ScopePolicy {
        schemes: vec![t.scheme],
        host_patterns: vec![t.host],
        ports: vec![t.port],
        path_prefixes: vec![],
    })
}

pub fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else if let Some(suffix) = pattern.strip_prefix('.') {
        host.ends_with(&format!(".{suffix}")) || host == suffix
    } else {
        host == pattern
    }
}

pub fn path_allowed(path: &str, prefixes: &[String]) -> bool {
    if prefixes.is_empty() {
        return true;
    }
    prefixes.iter().any(|p| {
        if p == "/" {
            true
        } else {
            let normalized = p.trim_end_matches('/');
            path == normalized || path.starts_with(&format!("{normalized}/"))
        }
    })
}

/// Check whether an exchange should be captured. An empty host list means
/// capture everything; scope never controls whether a request may be sent.
pub fn check_url_in_scope(url: &str, policy: &ScopePolicy) -> DomainResult<TargetRef> {
    let t = TargetRef::from_url(url)?;
    if policy.host_patterns.is_empty() {
        return Ok(t);
    }
    if !policy
        .schemes
        .iter()
        .any(|s| s.eq_ignore_ascii_case(&t.scheme))
    {
        return Err(DomainError::scope_denied(format!(
            "scheme {} not in scope",
            t.scheme
        )));
    }
    if !policy
        .host_patterns
        .iter()
        .any(|p| host_matches_pattern(&t.host, p))
    {
        return Err(DomainError::scope_denied(format!(
            "host {} not in scope",
            t.host
        )));
    }
    if !policy.ports.is_empty() && !policy.ports.contains(&t.port) {
        return Err(DomainError::scope_denied(format!(
            "port {} not in scope",
            t.port
        )));
    }
    if !path_allowed(&t.path, &policy.path_prefixes) {
        return Err(DomainError::scope_denied(format!(
            "path {} not in scope",
            t.path
        )));
    }
    Ok(t)
}

pub fn url_is_in_scope(url: &str, policy: &ScopePolicy) -> DomainResult<bool> {
    match check_url_in_scope(url, policy) {
        Ok(_) => Ok(true),
        Err(error) if error.code() == ErrorCode::ScopeDenied => Ok(false),
        Err(error) => Err(error),
    }
}

/// Resolve a target for egress. Project capture scope and address class do not
/// restrict destinations: HuntProxy is an explicitly user-directed workbench.
pub async fn resolve_validated_dial(
    url: &str,
    _policy: &ScopePolicy,
    dns_ttl: Duration,
) -> DomainResult<ValidatedDial> {
    let t = TargetRef::from_url(url)?;
    let host = t.host.clone();
    let port = t.port;

    // If host is already an IP literal, use it directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        return Ok(ValidatedDial {
            hostname: host,
            port,
            approved_socket_addrs: vec![addr],
            policy_epoch: current_policy_epoch(),
            expires_at: OffsetDateTime::now_utc() + dns_ttl,
            scheme: t.scheme,
            path: t.path,
        });
    }

    let lookup_host = format!("{host}:{port}");
    let addrs = tokio::net::lookup_host(&lookup_host)
        .await
        .map_err(|e| {
            DomainError::new(ErrorCode::DnsBlocked, format!("dns failed for {host}: {e}"))
        })?
        .collect::<Vec<_>>();

    if addrs.is_empty() {
        return Err(DomainError::new(
            ErrorCode::DnsBlocked,
            format!("no addresses for {host}"),
        ));
    }

    let approved = addrs
        .into_iter()
        .map(|addr| SocketAddr::new(addr.ip(), port))
        .collect();

    Ok(ValidatedDial {
        hostname: host,
        port,
        approved_socket_addrs: approved,
        policy_epoch: current_policy_epoch(),
        expires_at: OffsetDateTime::now_utc() + dns_ttl,
        scheme: t.scheme,
        path: t.path,
    })
}

/// Simple token-bucket / concurrency limiter state for a project.
#[derive(Debug)]
pub struct LimitTracker {
    pub concurrent: std::sync::atomic::AtomicU32,
    pub limits: ProjectLimits,
}

impl LimitTracker {
    pub fn new(limits: ProjectLimits) -> Self {
        Self {
            concurrent: std::sync::atomic::AtomicU32::new(0),
            limits,
        }
    }

    pub fn try_acquire(&self) -> DomainResult<Permit<'_>> {
        let cur = self.concurrent.load(Ordering::SeqCst);
        if cur >= self.limits.max_concurrent_requests {
            return Err(DomainError::new(
                ErrorCode::ConcurrencyLimited,
                "max concurrent requests reached",
            ));
        }
        self.concurrent.fetch_add(1, Ordering::SeqCst);
        Ok(Permit { tracker: self })
    }
}

pub struct Permit<'a> {
    tracker: &'a LimitTracker,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.tracker.concurrent.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(host: &str) -> ScopePolicy {
        ScopePolicy {
            schemes: vec!["http".into(), "https".into()],
            host_patterns: vec![host.into()],
            ports: vec![80, 443, 8080],
            path_prefixes: vec![],
        }
    }

    #[test]
    fn empty_scope_captures_every_supported_url() {
        let mut p = policy("example.com");
        p.host_patterns.clear();
        assert!(check_url_in_scope("https://example.com/", &p).is_ok());
        assert!(check_url_in_scope("http://127.0.0.1/admin", &p).is_ok());
    }

    #[test]
    fn allows_matching_host_and_blocks_other() {
        let p = policy("example.com");
        assert!(check_url_in_scope("https://example.com/a", &p).is_ok());
        assert!(check_url_in_scope("https://evil.com/", &p).is_err());
    }

    #[test]
    fn wildcard_and_path() {
        let mut p = policy("*.example.com");
        p.path_prefixes = vec!["/api".into()];
        assert!(check_url_in_scope("https://a.example.com/api/x", &p).is_ok());
        assert!(check_url_in_scope("https://a.example.com/api", &p).is_ok());
        assert!(check_url_in_scope("https://a.example.com/api2", &p).is_err());
        assert!(check_url_in_scope("https://a.example.com/other", &p).is_err());
    }

    #[test]
    fn path_prefix_with_trailing_slash_matches_same_boundary() {
        assert!(path_allowed("/api", &["/api/".into()]));
        assert!(path_allowed("/api/v1", &["/api/".into()]));
        assert!(!path_allowed("/api2", &["/api/".into()]));
    }

    #[tokio::test]
    async fn egress_resolution_ignores_capture_scope_and_address_class() {
        let p = policy("example.com");
        let dial = resolve_validated_dial("http://127.0.0.1:8080/", &p, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(dial.approved_socket_addrs[0].ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn derive_scope() {
        let s = derive_scope_from_target("https://app.example.com:8443/login").unwrap();
        assert_eq!(s.schemes, vec!["https"]);
        assert_eq!(s.host_patterns, vec!["app.example.com"]);
        assert_eq!(s.ports, vec![8443]);
    }

    #[test]
    fn trailing_dot_and_case() {
        let p = policy("Example.COM");
        let t = check_url_in_scope("https://EXAMPLE.com./path", &p).unwrap();
        assert_eq!(t.host, "example.com");
    }
}
