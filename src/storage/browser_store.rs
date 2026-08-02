//! Browser session metadata (checkpoints are memory-only).

use crate::domain::*;
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::Db;
use rusqlite::params;

impl Db {
    pub async fn create_browser_session(
        &self,
        project_id: ProjectId,
        engine: BrowserEngine,
        engine_policy: EnginePolicy,
    ) -> DomainResult<BrowserSession> {
        let ts = now_rfc3339();
        let engine_s = engine_str(engine);
        let policy_s = policy_str(engine_policy);
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO browser_sessions (project_id, engine, engine_policy, state, fallback_used, checkpoint_version, created_at, updated_at)
                 VALUES (?1,?2,?3,'starting',0,0,?4,?5)",
                params![project_id.get(), engine_s, policy_s, ts, ts],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let id = conn.last_insert_rowid();
            Ok(BrowserSession {
                id: BrowserSessionId(id),
                project_id,
                engine,
                engine_policy,
                current_url: None,
                current_title: None,
                state: BrowserSessionState::Starting,
                fallback_used: false,
                checkpoint_status: None,
                checkpoint_hash: None,
                created_at: parse_time(&ts),
                updated_at: parse_time(&ts),
            })
        })
        .await
    }

    pub async fn update_browser_session(&self, session: &BrowserSession) -> DomainResult<()> {
        let ts = now_rfc3339();
        let id = session.id.get();
        let engine_s = engine_str(session.engine);
        let state_s = browser_state_str(session.state);
        let url = session.current_url.clone();
        let title = session.current_title.clone();
        let fallback = session.fallback_used as i64;
        let cp_status = session.checkpoint_status.clone();
        let cp_hash = session.checkpoint_hash.clone();
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE browser_sessions SET engine=?1, current_url=?2, current_title=?3,
                 state=?4, fallback_used=?5, checkpoint_status=?6, checkpoint_hash=?7,
                 updated_at=?8 WHERE id=?9",
                params![engine_s, url, title, state_s, fallback, cp_status, cp_hash, ts, id],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            Ok(())
        })
        .await
    }

    /// Persist only non-secret rolling-checkpoint metadata.
    #[allow(clippy::too_many_arguments)] // Mirrors the checkpoint columns without exposing private state.
    pub async fn update_browser_checkpoint_metadata(
        &self,
        project_id: ProjectId,
        id: BrowserSessionId,
        current_url: Option<String>,
        current_title: Option<String>,
        checkpoint_status: String,
        checkpoint_hash: String,
        checkpoint_version: u64,
    ) -> DomainResult<()> {
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let updated = conn
                .execute(
                    "UPDATE browser_sessions
                     SET current_url=?1, current_title=?2, checkpoint_status=?3,
                         checkpoint_hash=?4, checkpoint_version=?5, updated_at=?6
                     WHERE id=?7 AND project_id=?8",
                    params![
                        current_url,
                        current_title,
                        checkpoint_status,
                        checkpoint_hash,
                        checkpoint_version as i64,
                        ts,
                        id.get(),
                        project_id.get()
                    ],
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            if updated == 0 {
                return Err(DomainError::not_found("browser session"));
            }
            Ok(())
        })
        .await
    }

    pub async fn get_browser_session(
        &self,
        project_id: ProjectId,
        id: BrowserSessionId,
    ) -> DomainResult<BrowserSession> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT id, project_id, engine, engine_policy, current_url, current_title,
                        state, fallback_used, checkpoint_status, checkpoint_hash, created_at, updated_at
                 FROM browser_sessions WHERE id=?1 AND project_id=?2",
                params![id.get(), project_id.get()],
                |row| {
                    Ok(BrowserSession {
                        id: BrowserSessionId(row.get(0)?),
                        project_id: ProjectId(row.get(1)?),
                        engine: parse_engine(&row.get::<_, String>(2)?),
                        engine_policy: parse_policy(&row.get::<_, String>(3)?),
                        current_url: row.get(4)?,
                        current_title: row.get(5)?,
                        state: parse_browser_state(&row.get::<_, String>(6)?),
                        fallback_used: row.get::<_, i64>(7)? != 0,
                        checkpoint_status: row.get(8)?,
                        checkpoint_hash: row.get(9)?,
                        created_at: parse_time(&row.get::<_, String>(10)?),
                        updated_at: parse_time(&row.get::<_, String>(11)?),
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DomainError::not_found("browser session"),
                other => DomainError::new(ErrorCode::StorageError, other.to_string()),
            })
        })
        .await
    }

    pub async fn mark_browser_sessions_interrupted(&self) -> DomainResult<u64> {
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let n = conn
                .execute(
                    "UPDATE browser_sessions SET state='interrupted', updated_at=?1
                     WHERE state IN ('starting','ready','busy','migrating')",
                    params![ts],
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            Ok(n as u64)
        })
        .await
    }
}

fn engine_str(e: BrowserEngine) -> &'static str {
    match e {
        BrowserEngine::Lightpanda => "lightpanda",
        BrowserEngine::Chromium => "chromium",
    }
}
fn parse_engine(s: &str) -> BrowserEngine {
    match s {
        "chromium" => BrowserEngine::Chromium,
        _ => BrowserEngine::Lightpanda,
    }
}
fn policy_str(p: EnginePolicy) -> &'static str {
    match p {
        EnginePolicy::Auto => "auto",
        EnginePolicy::Chromium => "chromium",
    }
}
fn parse_policy(s: &str) -> EnginePolicy {
    match s {
        "chromium" => EnginePolicy::Chromium,
        _ => EnginePolicy::Auto,
    }
}
fn browser_state_str(s: BrowserSessionState) -> &'static str {
    match s {
        BrowserSessionState::Starting => "starting",
        BrowserSessionState::Ready => "ready",
        BrowserSessionState::Busy => "busy",
        BrowserSessionState::Migrating => "migrating",
        BrowserSessionState::Interrupted => "interrupted",
        BrowserSessionState::Stopped => "stopped",
        BrowserSessionState::Failed => "failed",
    }
}
fn parse_browser_state(s: &str) -> BrowserSessionState {
    match s {
        "ready" => BrowserSessionState::Ready,
        "busy" => BrowserSessionState::Busy,
        "migrating" => BrowserSessionState::Migrating,
        "interrupted" => BrowserSessionState::Interrupted,
        "stopped" => BrowserSessionState::Stopped,
        "failed" => BrowserSessionState::Failed,
        _ => BrowserSessionState::Starting,
    }
}
