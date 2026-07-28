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
pub const DB_FILE_NAME: &str = "bb.db";
pub const CA_CERT_NAME: &str = "ca.crt";
pub const CA_KEY_NAME: &str = "ca.key";
pub const PLACEHOLDER_KEY_NAME: &str = "placeholder.key";

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
    pub lightpanda_path: Option<PathBuf>,
    pub node_path: Option<PathBuf>,
    pub browser_worker_path: Option<PathBuf>,
    pub auto_start_daemon: bool,
    /// Stop an inactive MCP bridge/daemon and its browsers. Zero disables it.
    pub idle_timeout_seconds: u64,
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
            lightpanda_path: which_path("lightpanda"),
            node_path: which_path("node"),
            browser_worker_path: None,
            auto_start_daemon: true,
            idle_timeout_seconds: 60 * 60,
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
        if let Some(v) = f.lightpanda_path {
            self.lightpanda_path = Some(PathBuf::from(v));
        }
        if let Some(v) = f.node_path {
            self.node_path = Some(PathBuf::from(v));
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
        Ok(())
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join(DB_FILE_NAME)
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
            lightpanda_path: self
                .lightpanda_path
                .as_ref()
                .map(|p| p.display().to_string()),
            node_path: self.node_path.as_ref().map(|p| p.display().to_string()),
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
    lightpanda_path: Option<String>,
    node_path: Option<String>,
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
}
