//! Configuration, data paths, and validation.

use crate::domain::{DomainError, DomainResult, ErrorCode};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const DEFAULT_API_ADDR: &str = "127.0.0.1:17890";
pub const DEFAULT_PROXY_ADDR: &str = "127.0.0.1:17891";
pub const DAEMON_SOCKET_NAME: &str = "daemon.sock";
pub const DAEMON_LOCK_NAME: &str = "daemon.lock";
pub const BOOTSTRAP_LOCK_NAME: &str = "bootstrap.lock";
pub const CONFIG_FILE_NAME: &str = "config.toml";
pub const DB_FILE_NAME: &str = "huntproxy.db";
const LEGACY_DB_FILE_NAME: &str = "bb.db";
pub const CA_CERT_NAME: &str = "ca.crt";
pub const CA_KEY_NAME: &str = "ca.key";
pub const PLACEHOLDER_KEY_NAME: &str = "placeholder.key";
pub const DAEMON_LOG_NAME: &str = "daemon.log";
pub const DAEMON_STARTUP_LOG_NAME: &str = "daemon-startup.log";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub data_dir: PathBuf,
    pub api_listen: SocketAddr,
    pub proxy_listen: SocketAddr,
    pub log_level: String,
    /// Require auth when binding non-loopback.
    pub remote_auth_token: Option<String>,
    pub mcp_listen: Option<SocketAddr>,
    pub sqlite_synchronous: String,
    pub busy_timeout_ms: u64,
    pub max_body_bytes: u64,
    pub spool_dir: PathBuf,
    pub export_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub node_path: Option<PathBuf>,
    pub browser_worker_path: Option<PathBuf>,
    /// Installed HuntProxy extensions. Each immediate child may contain one
    /// integrity-pinned `plugin.json` package.
    pub plugin_dir: PathBuf,
    pub auto_start_daemon: bool,
    /// Stop an inactive MCP bridge/daemon and its browsers. Zero disables it.
    pub idle_timeout_seconds: u64,
    /// Optional default and host-specific upstream proxies for outbound requests.
    pub upstream_proxies: UpstreamProxyConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamProxyConfig {
    /// Fallback proxy used when no host rule matches.
    pub default: Option<String>,
    /// Exact hosts and `*.example.com` suffix rules. Exact matches win.
    pub rules: Vec<UpstreamProxyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamProxyRule {
    pub host: String,
    pub proxy: String,
}

impl UpstreamProxyConfig {
    pub fn proxy_for(
        &self,
        host: &str,
        request_override: Option<&str>,
    ) -> DomainResult<Option<String>> {
        if let Some(proxy) = request_override {
            validate_upstream_proxy_url(proxy)?;
            return Ok(Some(proxy.to_string()));
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let exact = self.rules.iter().find(|rule| {
            !rule.host.starts_with("*.")
                && rule.host.trim_end_matches('.').eq_ignore_ascii_case(&host)
        });
        let wildcard = self
            .rules
            .iter()
            .filter(|rule| rule.host.starts_with("*."))
            .filter(|rule| host_matches(&host, &rule.host.to_ascii_lowercase()))
            .max_by_key(|rule| rule.host.len());
        Ok(exact
            .or(wildcard)
            .map(|rule| rule.proxy.clone())
            .or_else(|| self.default.clone()))
    }

    fn validate(&self) -> DomainResult<()> {
        if let Some(proxy) = &self.default {
            validate_upstream_proxy_url(proxy)?;
        }
        for rule in &self.rules {
            validate_host_pattern(&rule.host)?;
            validate_upstream_proxy_url(&rule.proxy)?;
        }
        Ok(())
    }
}

fn host_matches(host: &str, pattern: &str) -> bool {
    let suffix = pattern.strip_prefix("*.").unwrap_or(pattern);
    if pattern.starts_with("*.") {
        host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        host.eq_ignore_ascii_case(suffix)
    }
}

fn validate_host_pattern(pattern: &str) -> DomainResult<()> {
    let host = pattern.strip_prefix("*.").unwrap_or(pattern);
    if host.is_empty() || host.contains('*') || host.contains('/') || host.contains(':') {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "upstream proxy host must be an exact hostname or *.example.com",
        ));
    }
    Ok(())
}

pub fn validate_upstream_proxy_url(proxy: &str) -> DomainResult<()> {
    let parsed = url::Url::parse(proxy)
        .map_err(|_| DomainError::new(ErrorCode::ConfigInvalid, "invalid upstream proxy URL"))?;
    if !matches!(parsed.scheme(), "http" | "socks5" | "socks5h") {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "upstream proxy scheme must be http, socks5, or socks5h",
        ));
    }
    if parsed.host_str().is_none() || parsed.port_or_known_default().is_none() {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "upstream proxy URL requires a host and port",
        ));
    }
    if (!parsed.path().is_empty() && parsed.path() != "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(DomainError::new(
            ErrorCode::ConfigInvalid,
            "upstream proxy URL cannot contain a path, query, or fragment",
        ));
    }
    Ok(())
}

impl Default for Config {
    fn default() -> Self {
        let data_dir = default_data_dir();
        Self {
            data_dir: data_dir.clone(),
            api_listen: DEFAULT_API_ADDR.parse().unwrap(),
            proxy_listen: DEFAULT_PROXY_ADDR.parse().unwrap(),
            log_level: "info".into(),
            remote_auth_token: None,
            mcp_listen: None,
            sqlite_synchronous: "NORMAL".into(),
            busy_timeout_ms: 5_000,
            max_body_bytes: 25 * 1024 * 1024,
            spool_dir: data_dir.join("spool"),
            export_dir: data_dir.join("exports"),
            runtime_dir: data_dir.join("runtime"),
            node_path: which_path("node"),
            browser_worker_path: None,
            plugin_dir: data_dir.join("plugins"),
            auto_start_daemon: true,
            idle_timeout_seconds: 60 * 60,
            upstream_proxies: UpstreamProxyConfig::default(),
        }
    }
}

impl Config {
    pub fn load(data_dir: Option<PathBuf>) -> DomainResult<Self> {
        let mut cfg = Self::default();
        if let Some(dir) = data_dir {
            cfg.data_dir = dir;
            cfg.spool_dir = cfg.data_dir.join("spool");
            cfg.export_dir = cfg.data_dir.join("exports");
            cfg.runtime_dir = cfg.data_dir.join("runtime");
            cfg.plugin_dir = cfg.data_dir.join("plugins");
        }
        create_private_dir(&cfg.data_dir)?;
        let path = cfg.data_dir.join(CONFIG_FILE_NAME);
        if path.exists() {
            let text = fs::read_to_string(&path).map_err(|e| {
                DomainError::new(ErrorCode::ConfigInvalid, format!("read config: {e}"))
            })?;
            let file: ConfigFile = toml::from_str(&text).map_err(|e| {
                DomainError::new(ErrorCode::ConfigInvalid, format!("parse config: {e}"))
            })?;
            cfg.apply_file(file);
        }
        cfg.validate()?;
        cfg.ensure_layout()?;
        cfg.write_default_config()?;
        Ok(cfg)
    }

    fn apply_file(&mut self, f: ConfigFile) {
        if let Some(v) = f.api_listen {
            if let Ok(a) = v.parse() {
                self.api_listen = a;
            }
        }
        if let Some(v) = f.proxy_listen {
            if let Ok(a) = v.parse() {
                self.proxy_listen = a;
            }
        }
        if let Some(v) = f.log_level {
            self.log_level = v;
        }
        if let Some(v) = f.remote_auth_token {
            self.remote_auth_token = Some(v);
        }
        if let Some(v) = f.mcp_listen {
            self.mcp_listen = v.parse().ok();
        }
        if let Some(v) = f.sqlite_synchronous {
            self.sqlite_synchronous = v;
        }
        if let Some(v) = f.busy_timeout_ms {
            self.busy_timeout_ms = v;
        }
        if let Some(v) = f.max_body_bytes {
            self.max_body_bytes = v;
        }
        if let Some(v) = f.auto_start_daemon {
            self.auto_start_daemon = v;
        }
        if let Some(v) = f.idle_timeout_seconds {
            self.idle_timeout_seconds = v;
        }
        if let Some(v) = f.node_path {
            self.node_path = Some(PathBuf::from(v));
        }
        if let Some(v) = f.plugin_dir {
            self.plugin_dir = PathBuf::from(v);
        }
        if let Some(v) = f.upstream_proxies {
            self.upstream_proxies = v;
        }
    }

    pub fn validate(&self) -> DomainResult<()> {
        if !self.api_listen.ip().is_loopback() && self.remote_auth_token.is_none() {
            return Err(DomainError::new(
                ErrorCode::ConfigInvalid,
                "non-loopback API listen requires remote_auth_token",
            ));
        }
        if let Some(addr) = self.mcp_listen {
            if !addr.ip().is_loopback() && self.remote_auth_token.is_none() {
                return Err(DomainError::new(
                    ErrorCode::ConfigInvalid,
                    "non-loopback MCP listen requires remote_auth_token",
                ));
            }
        }
        let sync = self.sqlite_synchronous.to_uppercase();
        if sync != "NORMAL" && sync != "FULL" {
            return Err(DomainError::new(
                ErrorCode::ConfigInvalid,
                "sqlite_synchronous must be NORMAL or FULL",
            ));
        }
        self.upstream_proxies.validate()?;
        Ok(())
    }

    pub fn db_path(&self) -> PathBuf {
        let current = self.data_dir.join(DB_FILE_NAME);
        let legacy = self.data_dir.join(LEGACY_DB_FILE_NAME);
        if !current.exists() && legacy.exists() {
            legacy
        } else {
            current
        }
    }

    pub fn socket_path(&self) -> PathBuf {
        self.data_dir.join(DAEMON_SOCKET_NAME)
    }

    pub fn daemon_lock_path(&self) -> PathBuf {
        self.data_dir.join(DAEMON_LOCK_NAME)
    }

    pub fn bootstrap_lock_path(&self) -> PathBuf {
        self.data_dir.join(BOOTSTRAP_LOCK_NAME)
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.data_dir.join("ca").join(CA_CERT_NAME)
    }

    pub fn ca_key_path(&self) -> PathBuf {
        self.data_dir.join("ca").join(CA_KEY_NAME)
    }

    pub fn placeholder_key_path(&self) -> PathBuf {
        self.data_dir.join(PLACEHOLDER_KEY_NAME)
    }

    pub fn daemon_log_path(&self) -> PathBuf {
        self.runtime_dir.join(DAEMON_LOG_NAME)
    }

    pub fn daemon_startup_log_path(&self) -> PathBuf {
        self.runtime_dir.join(DAEMON_STARTUP_LOG_NAME)
    }

    pub fn browser_profiles_dir(&self) -> PathBuf {
        self.data_dir.join("browser-profiles")
    }

    pub fn ensure_layout(&self) -> DomainResult<()> {
        create_private_dir(&self.data_dir)?;
        create_private_dir(&self.data_dir.join("ca"))?;
        create_private_dir(&self.spool_dir)?;
        create_private_dir(&self.export_dir)?;
        create_private_dir(&self.runtime_dir)?;
        create_private_dir(&self.browser_profiles_dir())?;
        create_private_dir(&self.plugin_dir)?;
        Ok(())
    }

    pub fn write_default_config(&self) -> DomainResult<()> {
        let path = self.data_dir.join(CONFIG_FILE_NAME);
        if path.exists() {
            return Ok(());
        }
        let file = ConfigFile {
            api_listen: Some(self.api_listen.to_string()),
            proxy_listen: Some(self.proxy_listen.to_string()),
            log_level: Some(self.log_level.clone()),
            remote_auth_token: None,
            mcp_listen: None,
            sqlite_synchronous: Some(self.sqlite_synchronous.clone()),
            busy_timeout_ms: Some(self.busy_timeout_ms),
            max_body_bytes: Some(self.max_body_bytes),
            auto_start_daemon: Some(self.auto_start_daemon),
            idle_timeout_seconds: Some(self.idle_timeout_seconds),
            node_path: self.node_path.as_ref().map(|p| p.display().to_string()),
            plugin_dir: Some(self.plugin_dir.display().to_string()),
            upstream_proxies: Some(self.upstream_proxies.clone()),
        };
        let text = toml::to_string_pretty(&file).map_err(|e| {
            DomainError::new(ErrorCode::ConfigInvalid, format!("serialize config: {e}"))
        })?;
        write_private_file(&path, text.as_bytes())?;
        Ok(())
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ConfigFile {
    api_listen: Option<String>,
    proxy_listen: Option<String>,
    log_level: Option<String>,
    remote_auth_token: Option<String>,
    mcp_listen: Option<String>,
    sqlite_synchronous: Option<String>,
    busy_timeout_ms: Option<u64>,
    max_body_bytes: Option<u64>,
    auto_start_daemon: Option<bool>,
    idle_timeout_seconds: Option<u64>,
    node_path: Option<String>,
    plugin_dir: Option<String>,
    upstream_proxies: Option<UpstreamProxyConfig>,
}

pub fn default_data_dir() -> PathBuf {
    data_dir_from(
        std::env::var_os("HUNTPROXY_DATA_DIR"),
        std::env::var_os("HOME"),
    )
}

fn data_dir_from(
    override_dir: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> PathBuf {
    override_dir
        .filter(|directory| !directory.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            home.filter(|directory| !directory.is_empty())
                .map(PathBuf::from)
                .map(|directory| directory.join(".huntproxy"))
        })
        .unwrap_or_else(|| PathBuf::from(".huntproxy"))
}

pub fn create_private_dir(path: &Path) -> DomainResult<()> {
    fs::create_dir_all(path).map_err(|e| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("create dir {}: {e}", path.display()),
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

pub fn write_private_file(path: &Path, data: &[u8]) -> DomainResult<()> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    fs::write(path, data).map_err(|e| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("write {}: {e}", path.display()),
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn which_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let p = dir.join(name);
            if p.is_file() {
                Some(p)
            } else {
                None
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_directory_is_dot_huntproxy_under_home() {
        assert_eq!(
            data_dir_from(None, Some("/users/alice".into())),
            PathBuf::from("/users/alice/.huntproxy")
        );
        assert_eq!(
            data_dir_from(Some("/custom".into()), Some("/users/alice".into())),
            PathBuf::from("/custom")
        );
    }

    #[test]
    fn load_creates_a_complete_explicit_data_directory() {
        let parent = tempfile::tempdir().unwrap();
        let data_dir = parent.path().join("custom-data");
        let config = Config::load(Some(data_dir.clone())).unwrap();

        assert_eq!(config.data_dir, data_dir);
        for relative in ["ca", "spool", "exports", "runtime", "browser-profiles"] {
            assert!(config.data_dir.join(relative).is_dir());
        }
        assert!(config.data_dir.join(CONFIG_FILE_NAME).is_file());
        assert_eq!(config.idle_timeout_seconds, 60 * 60);
    }

    #[test]
    fn new_databases_use_huntproxy_name_and_existing_legacy_databases_still_open() {
        let parent = tempfile::tempdir().unwrap();
        let data_dir = parent.path().join("data");
        let config = Config::load(Some(data_dir.clone())).unwrap();

        assert_eq!(config.db_path(), data_dir.join("huntproxy.db"));

        std::fs::write(data_dir.join(LEGACY_DB_FILE_NAME), b"legacy").unwrap();
        assert_eq!(config.db_path(), data_dir.join(LEGACY_DB_FILE_NAME));

        std::fs::write(data_dir.join(DB_FILE_NAME), b"current").unwrap();
        assert_eq!(config.db_path(), data_dir.join(DB_FILE_NAME));
    }

    #[test]
    fn upstream_proxy_selection_prefers_exact_and_longest_wildcard() {
        let config = UpstreamProxyConfig {
            default: Some("http://default.test:8080".into()),
            rules: vec![
                UpstreamProxyRule {
                    host: "*.example.com".into(),
                    proxy: "socks5h://broad.test:1080".into(),
                },
                UpstreamProxyRule {
                    host: "*.api.example.com".into(),
                    proxy: "http://narrow.test:8080".into(),
                },
                UpstreamProxyRule {
                    host: "one.api.example.com".into(),
                    proxy: "socks5://exact.test:1080".into(),
                },
            ],
        };
        assert_eq!(
            config
                .proxy_for("one.api.example.com", None)
                .unwrap()
                .as_deref(),
            Some("socks5://exact.test:1080")
        );
        assert_eq!(
            config
                .proxy_for("two.api.example.com", None)
                .unwrap()
                .as_deref(),
            Some("http://narrow.test:8080")
        );
        assert_eq!(
            config.proxy_for("example.com", None).unwrap().as_deref(),
            Some("http://default.test:8080")
        );
        assert_eq!(
            config
                .proxy_for("elsewhere.test", Some("socks5h://override.test:1080"))
                .unwrap()
                .as_deref(),
            Some("socks5h://override.test:1080")
        );
    }

    #[test]
    fn upstream_proxy_validation_rejects_ambiguous_or_unsupported_values() {
        assert!(validate_upstream_proxy_url("https://proxy.test:443").is_err());
        assert!(validate_upstream_proxy_url("http://proxy.test:8080/path").is_err());
        assert!(validate_host_pattern("foo.*.example.com").is_err());
    }
}
