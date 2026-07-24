//! Browser worker supervision, sessions, checkpoints (memory-only secrets).

use crate::domain::*;
use crate::storage::Db;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserInstallStatus {
    pub node_available: bool,
    pub worker_available: bool,
    pub lightpanda_available: bool,
    pub chromium_available: bool,
    pub lightpanda_path: Option<String>,
    pub node_path: Option<String>,
    pub install_hint: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Checkpoint {
    pub url: Option<String>,
    pub cookies: Vec<serde_json::Value>,
    pub local_storage: HashMap<String, HashMap<String, String>>,
    pub session_storage: HashMap<String, String>,
    pub version: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrowserAction {
    Navigate { url: String },
    Snapshot { format: String, max_bytes: u64 },
    Click { locator: Locator },
    Fill { locator: Locator, value: String },
    Select { locator: Locator, value: String },
    Press { locator: Option<Locator>, key: String },
    Wait { for_what: String, value: String },
    Back,
    Forward,
    Close,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Locator {
    pub role: Option<String>,
    pub name: Option<String>,
    pub text: Option<String>,
    pub test_id: Option<String>,
    pub css: Option<String>,
    pub exact: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub ok: bool,
    pub untrusted: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

pub struct BrowserService {
    pub db: Arc<Db>,
    pub lightpanda_path: Option<PathBuf>,
    pub node_path: Option<PathBuf>,
    pub worker_path: Option<PathBuf>,
    checkpoints: Mutex<HashMap<i64, Checkpoint>>,
}

impl BrowserService {
    pub fn new(
        db: Arc<Db>,
        lightpanda_path: Option<PathBuf>,
        node_path: Option<PathBuf>,
        worker_path: Option<PathBuf>,
    ) -> Self {
        Self {
            db,
            lightpanda_path,
            node_path,
            worker_path,
            checkpoints: Mutex::new(HashMap::new()),
        }
    }

    pub fn status(&self) -> BrowserInstallStatus {
        let node_available = self
            .node_path
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or_else(|| which("node").is_some());
        let lightpanda_available = self
            .lightpanda_path
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or_else(|| which("lightpanda").is_some());
        let worker_available = self
            .worker_path
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false);
        let chromium_available = which("google-chrome").is_some()
            || which("google-chrome-stable").is_some()
            || which("chromium").is_some()
            || which("chromium-browser").is_some();

        let install_hint = if !node_available {
            Some("Install Node.js and run: bb browser install".into())
        } else if !worker_available {
            Some("Run: bb browser install".into())
        } else if !lightpanda_available && !chromium_available {
            Some("Install Lightpanda or Chromium: bb browser install".into())
        } else {
            None
        };

        BrowserInstallStatus {
            node_available,
            worker_available,
            lightpanda_available,
            chromium_available,
            lightpanda_path: self
                .lightpanda_path
                .as_ref()
                .map(|p| p.display().to_string())
                .or_else(|| which("lightpanda")),
            node_path: self
                .node_path
                .as_ref()
                .map(|p| p.display().to_string())
                .or_else(|| which("node")),
            install_hint,
        }
    }

    pub async fn start(
        &self,
        project_id: ProjectId,
        url: String,
        policy: EnginePolicy,
    ) -> DomainResult<BrowserSession> {
        let st = self.status();
        if !st.node_available || !st.worker_available {
            // Allow session record even when disabled so UI can show state
            if !st.chromium_available && !st.lightpanda_available {
                return Err(DomainError::new(
                    ErrorCode::BrowserDisabled,
                    st.install_hint
                        .unwrap_or_else(|| "Browser runtime not installed".into()),
                ));
            }
        }

        let engine = match policy {
            EnginePolicy::Chromium => {
                if !st.chromium_available {
                    return Err(DomainError::new(
                        ErrorCode::ChromiumNotInstalled,
                        "Chromium not installed; run bb browser install",
                    ));
                }
                BrowserEngine::Chromium
            }
            EnginePolicy::Auto => {
                if st.lightpanda_available {
                    BrowserEngine::Lightpanda
                } else if st.chromium_available {
                    BrowserEngine::Chromium
                } else {
                    return Err(DomainError::new(
                        ErrorCode::BrowserNotInstalled,
                        "No browser engine installed",
                    ));
                }
            }
        };

        let mut session = self
            .db
            .create_browser_session(project_id, engine, policy)
            .await?;
        session.current_url = Some(url.clone());
        session.state = BrowserSessionState::Ready;
        session.checkpoint_status = Some("empty".into());
        self.db.update_browser_session(&session).await?;
        self.checkpoints.lock().await.insert(
            session.id.get(),
            Checkpoint {
                url: Some(url),
                ..Default::default()
            },
        );
        Ok(session)
    }

    pub async fn action(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        action: BrowserAction,
    ) -> DomainResult<ActionResult> {
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        if matches!(
            session.state,
            BrowserSessionState::Interrupted | BrowserSessionState::Stopped
        ) {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "browser session is not active",
            ));
        }

        // Without a live worker, return structured capability responses for navigate/snapshot.
        let st = self.status();
        if !st.worker_available {
            return Ok(ActionResult {
                ok: false,
                untrusted: false,
                message: "Browser worker not installed".into(),
                data: None,
                error_code: Some(ErrorCode::BrowserDisabled.as_str().into()),
            });
        }

        match action {
            BrowserAction::Navigate { url } => {
                // Scope check
                let project = self.db.get_project(project_id).await?;
                crate::policy::scope::check_url_in_scope(&url, &project.scope)?;
                session.current_url = Some(url.clone());
                session.state = BrowserSessionState::Ready;
                // Update rolling checkpoint metadata only
                let mut cps = self.checkpoints.lock().await;
                let cp = cps.entry(session_id.get()).or_default();
                cp.url = Some(url.clone());
                cp.version += 1;
                cp.hash = format!("v{}", cp.version);
                session.checkpoint_hash = Some(cp.hash.clone());
                session.checkpoint_status = Some("ok".into());
                self.db.update_browser_session(&session).await?;
                Ok(ActionResult {
                    ok: true,
                    untrusted: true,
                    message: format!("navigated to {url} (worker path pending full CDP wire-up)"),
                    data: Some(serde_json::json!({"url": url})),
                    error_code: None,
                })
            }
            BrowserAction::Snapshot { format, max_bytes } => Ok(ActionResult {
                ok: true,
                untrusted: true,
                message: "snapshot placeholder — page content is untrusted".into(),
                data: Some(serde_json::json!({
                    "format": format,
                    "max_bytes": max_bytes,
                    "content": "",
                    "untrusted": true
                })),
                error_code: None,
            }),
            BrowserAction::Close => {
                session.state = BrowserSessionState::Stopped;
                self.db.update_browser_session(&session).await?;
                self.checkpoints.lock().await.remove(&session_id.get());
                Ok(ActionResult {
                    ok: true,
                    untrusted: false,
                    message: "session closed".into(),
                    data: None,
                    error_code: None,
                })
            }
            other => Ok(ActionResult {
                ok: true,
                untrusted: true,
                message: format!("action accepted (stub): {:?}", std::mem::discriminant(&other)),
                data: None,
                error_code: None,
            }),
        }
    }

    pub async fn stop(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<()> {
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        session.state = BrowserSessionState::Stopped;
        self.db.update_browser_session(&session).await?;
        self.checkpoints.lock().await.remove(&session_id.get());
        Ok(())
    }

    pub async fn switch_to_chromium(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<BrowserSession> {
        let st = self.status();
        if !st.chromium_available {
            return Err(DomainError::new(
                ErrorCode::ChromiumNotInstalled,
                "Chromium not installed; run bb browser install",
            ));
        }
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        if session.fallback_used {
            return Err(DomainError::new(
                ErrorCode::EngineFallback,
                "fallback already used for this session",
            ));
        }
        session.engine = BrowserEngine::Chromium;
        session.fallback_used = true;
        session.state = BrowserSessionState::Ready;
        session.checkpoint_status = Some("migrated_partial".into());
        self.db.update_browser_session(&session).await?;
        Ok(session)
    }
}

fn which(name: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let p = dir.join(name);
            if p.is_file() {
                Some(p.display().to_string())
            } else {
                None
            }
        })
    })
}
