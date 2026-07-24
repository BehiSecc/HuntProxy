//! Metadata-only audit events (never secret values).

use crate::domain::{DomainError, DomainResult, ErrorCode, ProjectId};
use crate::storage::projects::now_rfc3339;
use crate::storage::Db;
use rusqlite::params;
use serde_json::Value;

impl Db {
    pub async fn audit(
        &self,
        project_id: Option<ProjectId>,
        event_type: &str,
        actor: Option<&str>,
        target_type: Option<&str>,
        target_id: Option<&str>,
        metadata: Value,
    ) -> DomainResult<()> {
        let ts = now_rfc3339();
        let event_type = event_type.to_string();
        let actor = actor.map(|s| s.to_string());
        let target_type = target_type.map(|s| s.to_string());
        let target_id = target_id.map(|s| s.to_string());
        let meta = metadata.to_string();
        let pid = project_id.map(|p| p.get());
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO audit_events (project_id, event_type, actor, target_type, target_id, metadata_json, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![pid, event_type, actor, target_type, target_id, meta, ts],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            Ok(())
        })
        .await
    }
}
