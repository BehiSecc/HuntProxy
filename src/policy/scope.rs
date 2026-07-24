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
    let allow_loopback = is_loopback_host(&t.host);
    Ok(ScopePolicy {
        schemes: vec![t.scheme],
        host_patterns: vec![t.host],
        ports: vec![t.port],
        path_prefixes: vec![],
        allow_loopback,
        allow_private_network: false,
        allow_link_local: false,
        allow_metadata: false,
    })
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host.ends_with(".localhost")
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
            path == p.as_str() || path.starts_with(&format!("{p}/")) || path.starts_with(p)
        }
    })
}

pub fn is_blocked_ip(ip: IpAddr, policy: &ScopePolicy) -> Option<ErrorCode> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // loopback 127.0.0.0/8
            if o[0] == 127 {
                return if policy.allow_loopback {
                    None
                } else {
                    Some(ErrorCode::PrivateNetworkBlocked)
                };
            }
            // link-local 169.254.0.0/16
            if o[0] == 169 && o[1] == 254 {
                // cloud metadata 169.254.169.254
                if o[2] == 169 && o[3] == 254 {
                    return if policy.allow_metadata {
                        None
                    } else {
                        Some(ErrorCode::PrivateNetworkBlocked)
                    };
                }
                return if policy.allow_link_local {
                    None
                } else {
                    Some(ErrorCode::PrivateNetworkBlocked)
                };
            }
            // private RFC1918
            if o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
            {
                return if policy.allow_private_network {
                    None
                } else {
                    Some(ErrorCode::PrivateNetworkBlocked)
                };
            }
            // CGNAT 100.64/10
            if o[0] == 100 && (64..=127).contains(&o[1]) {
                return if policy.allow_private_network {
                    None
                } else {
                    Some(ErrorCode::PrivateNetworkBlocked)
                };
            }
            // 0.0.0.0/8 multicast etc.
            if o[0] == 0 || o[0] >= 224 {
                return Some(ErrorCode::PrivateNetworkBlocked);
            }
            None
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return if policy.allow_loopback {
                    None
                } else {
                    Some(ErrorCode::PrivateNetworkBlocked)
                };
            }
            if v6.is_unicast_link_local() {
                return if policy.allow_link_local {
                    None
                } else {
                    Some(ErrorCode::PrivateNetworkBlocked)
                };
            }
            // unique local fc00::/7
            let s = v6.segments();
            if (s[0] & 0xfe00) == 0xfc00 {
                return if policy.allow_private_network {
                    None
                } else {
                    Some(ErrorCode::PrivateNetworkBlocked)
                };
            }
            // IPv4-mapped
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(v4), policy);
            }
            None
        }
    }
}

/// Check URL against scope (scheme/host/port/path) without DNS.
pub fn check_url_in_scope(url: &str, policy: &ScopePolicy) -> DomainResult<TargetRef> {
    let t = TargetRef::from_url(url)?;
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
    if policy.host_patterns.is_empty() {
        return Err(DomainError::scope_denied("project has empty host scope"));
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

/// Resolve DNS and produce ValidatedDial with only approved socket addresses.
pub async fn resolve_validated_dial(
    url: &str,
    policy: &ScopePolicy,
    dns_ttl: Duration,
) -> DomainResult<ValidatedDial> {
    let t = check_url_in_scope(url, policy)?;
    let host = t.host.clone();
    let port = t.port;

    // If host is already an IP literal, use it directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if let Some(code) = is_blocked_ip(ip, policy) {
            return Err(DomainError::new(
                code,
                format!("address {ip} blocked by policy"),
            ));
        }
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
        .map_err(|e| DomainError::new(ErrorCode::DnsBlocked, format!("dns failed for {host}: {e}")))?
        .collect::<Vec<_>>();

    if addrs.is_empty() {
        return Err(DomainError::new(
            ErrorCode::DnsBlocked,
            format!("no addresses for {host}"),
        ));
    }

    let mut approved = Vec::new();
    for addr in addrs {
        if let Some(code) = is_blocked_ip(addr.ip(), policy) {
            // skip blocked; if all blocked, fail
            tracing::debug!(%addr, ?code, "dns address blocked by policy");
            continue;
        }
        approved.push(SocketAddr::new(addr.ip(), port));
    }

    if approved.is_empty() {
        return Err(DomainError::new(
            ErrorCode::PrivateNetworkBlocked,
            format!("all resolved addresses for {host} are blocked by policy"),
        ));
    }

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
            allow_loopback: false,
            allow_private_network: false,
            allow_link_local: false,
            allow_metadata: false,
        }
    }

    #[test]
    fn default_deny_empty_hosts() {
        let mut p = policy("example.com");
        p.host_patterns.clear();
        assert!(check_url_in_scope("https://example.com/", &p).is_err());
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
        assert!(check_url_in_scope("https://a.example.com/other", &p).is_err());
    }

    #[test]
    fn blocks_metadata_and_private() {
        let p = policy("example.com");
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap(), &p).is_some());
        assert!(is_blocked_ip("192.168.1.1".parse().unwrap(), &p).is_some());
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap(), &p).is_some());
        assert!(is_blocked_ip("8.8.8.8".parse().unwrap(), &p).is_none());
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
