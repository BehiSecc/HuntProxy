//! Request-scoped approved-IP dial model (ValidatedDial).
//!
//! Policy produces an immutable dial plan. The transport must connect only to an
//! approved socket address while preserving the hostname for Host/SNI/cert verify.
//! A second DNS lookup that could return a different address is a policy bypass.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Immutable dial plan produced by scope resolution (spike-shaped).
#[derive(Debug, Clone)]
pub struct ValidatedDial {
    pub hostname: String,
    pub port: u16,
    pub approved_socket_addrs: Vec<SocketAddr>,
    pub policy_epoch: u64,
}

/// Global resolve-call counter used to prove the custom resolver is hit
/// and that system DNS is never consulted for the approved host.
static RESOLVE_CALLS: AtomicUsize = AtomicUsize::new(0);

pub fn resolve_call_counter() -> usize {
    RESOLVE_CALLS.load(Ordering::SeqCst)
}

pub fn reset_resolve_call_counter() {
    RESOLVE_CALLS.store(0, Ordering::SeqCst);
}

/// Resolver that returns only the approved address(es) for a known hostname
/// and refuses everything else. Never falls back to system DNS.
#[derive(Debug, Clone)]
pub struct FixedIpResolver {
    /// hostname (lowercase) -> approved addrs (ports are ignored by HTTP clients;
    /// URI port wins). We still store full SocketAddrs for audit.
    map: Arc<HashMap<String, Vec<SocketAddr>>>,
    /// Hostnames that would be dangerous if resolved via real DNS.
    /// If any of these appear, we fail hard rather than looking them up.
    denied_hosts: Arc<Vec<String>>,
    /// Audit log of every resolve invocation (name as seen by the client).
    log: Arc<Mutex<Vec<String>>>,
}

impl FixedIpResolver {
    pub fn for_dial(dial: &ValidatedDial) -> Self {
        let mut map = HashMap::new();
        map.insert(dial.hostname.to_ascii_lowercase(), dial.approved_socket_addrs.clone());
        Self {
            map: Arc::new(map),
            // Use a hostname that must never hit the public DNS path in this spike.
            denied_hosts: Arc::new(vec![
                "this-host-must-never-resolve.invalid".into(),
                "policy-bypass-check.invalid".into(),
            ]),
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn resolve_log(&self) -> Vec<String> {
        self.log.lock().expect("log lock").clone()
    }

    /// Core resolve used by both wreq and primp adapters.
    pub fn resolve_addrs(&self, host: &str) -> Result<Vec<SocketAddr>, String> {
        RESOLVE_CALLS.fetch_add(1, Ordering::SeqCst);
        let key = host.to_ascii_lowercase();
        self.log.lock().expect("log lock").push(key.clone());

        if self.denied_hosts.iter().any(|d| d == &key) {
            return Err(format!(
                "ValidatedDial policy: refusing to resolve denied host {host} (no system DNS fallback)"
            ));
        }

        match self.map.get(&key) {
            Some(addrs) if !addrs.is_empty() => Ok(addrs.clone()),
            Some(_) => Err(format!("ValidatedDial: empty approved list for {host}")),
            None => Err(format!(
                "ValidatedDial: host {host} not in approved map — no system DNS fallback"
            )),
        }
    }
}

// --- wreq Resolve adapter ----------------------------------------------------

#[cfg(feature = "wreq-backend")]
mod wreq_adapter {
    use super::*;
    use std::future;
    use wreq::dns::{Addrs, Name, Resolve, Resolving};

    impl Resolve for FixedIpResolver {
        fn resolve(&self, name: Name) -> Resolving {
            let host = name.as_str().to_string();
            let result = self.resolve_addrs(&host).map(|addrs| {
                let iter: Addrs = Box::new(addrs.into_iter());
                iter
            });
            Box::pin(future::ready(
                result.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() }),
            ))
        }
    }
}

// --- helpers for request-scoped clients --------------------------------------

impl ValidatedDial {
    pub fn url_http(&self, path: &str) -> String {
        format!("http://{}:{}{}", self.hostname, self.port, path)
    }

    pub fn url_https(&self, path: &str) -> String {
        format!("https://{}:{}{}", self.hostname, self.port, path)
    }

    /// Primary approved IP (for remote_addr assertions).
    pub fn primary_ip(&self) -> std::net::IpAddr {
        self.approved_socket_addrs[0].ip()
    }
}
