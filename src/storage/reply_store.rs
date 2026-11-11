//! Reply workspace and tab persistence.

use crate::domain::*;
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::{write_transaction, Db};
use rusqlite::params;

impl Db {
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_reply_tab(
        &self,
        project_id: ProjectId,
        tab_id: Option<ReplyTabId>,
        name: String,
        base_exchange_id: Option<ExchangeId>,
        protocol: ProtocolPreference,
        draft: ReplyDraft,
        expected_revision: Option<i64>,
    ) -> DomainResult<ReplyTab> {
        let draft_json = serde_json::to_string(&draft)
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
        let protocol_s = match protocol {
            ProtocolPreference::Auto => "auto",
            ProtocolPreference::H1 => "h1",
            ProtocolPreference::H2 => "h2",
        };
        let ts = now_rfc3339();
        let base_id = base_exchange_id.map(|e| e.get());

        self.with_conn(move |conn| {
            let tx = write_transaction(conn).map_err(storage_error)?;
            let tab = if let Some(id) = tab_id {
                let current: i64 = tx
                    .query_row(
                        "SELECT revision FROM reply_tabs WHERE id=?1 AND project_id=?2",
                        params![id.get(), project_id.get()],
                        |r| r.get(0),
                    )
                    .map_err(|e| match e {
                        rusqlite::Error::QueryReturnedNoRows => DomainError::not_found("reply tab"),
                        other => DomainError::new(ErrorCode::StorageError, other.to_string()),
                    })?;
                if let Some(exp) = expected_revision {
                    if exp != current {
                        return Err(DomainError::new(
                            ErrorCode::RevisionConflict,
                            format!("reply tab revision conflict: expected {exp}, have {current}"),
                        ));
                    }
                }
                let new_rev = current + 1;
                tx.execute(
                    "UPDATE reply_tabs SET name=?1, base_exchange_id=?2, revision=?3, protocol=?4, draft_json=?5, updated_at=?6
                     WHERE id=?7 AND project_id=?8",
                    params![name, base_id, new_rev, protocol_s, draft_json, ts, id.get(), project_id.get()],
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                tx.execute(
                    "INSERT INTO reply_revisions (tab_id, revision, draft_json, created_at) VALUES (?1,?2,?3,?4)",
                    params![id.get(), new_rev, draft_json, ts],
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                ReplyTab {
                    id,
                    project_id,
                    name,
                    base_exchange_id,
                    revision: new_rev,
                    protocol,
                    draft,
                    created_at: parse_time(&ts),
                    updated_at: parse_time(&ts),
                }
            } else {
                tx.execute(
                    "INSERT INTO reply_tabs (project_id, name, base_exchange_id, revision, protocol, draft_json, created_at, updated_at)
                     VALUES (?1,?2,?3,1,?4,?5,?6,?7)",
                    params![project_id.get(), name, base_id, protocol_s, draft_json, ts, ts],
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                let id = tx.last_insert_rowid();
                tx.execute(
                    "INSERT INTO reply_revisions (tab_id, revision, draft_json, created_at) VALUES (?1,1,?2,?3)",
                    params![id, draft_json, ts],
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                ReplyTab {
                    id: ReplyTabId(id),
                    project_id,
                    name,
                    base_exchange_id,
                    revision: 1,
                    protocol,
                    draft,
                    created_at: parse_time(&ts),
                    updated_at: parse_time(&ts),
                }
            };
            tx.commit().map_err(storage_error)?;
            Ok(tab)
        })
        .await
    }

    pub async fn list_reply_tabs(&self, project_id: ProjectId) -> DomainResult<Vec<ReplyTab>> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, base_exchange_id, revision, protocol, draft_json, created_at, updated_at
                     FROM reply_tabs WHERE project_id=?1 ORDER BY id",
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let rows = stmt
                .query_map(params![project_id.get()], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                })
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let mut out = Vec::new();
            for r in rows {
                let (id, name, base_exchange_id, revision, protocol, draft_json, created, updated) =
                    r.map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                let protocol = match protocol.as_str() {
                    "h1" => ProtocolPreference::H1,
                    "h2" => ProtocolPreference::H2,
                    _ => ProtocolPreference::Auto,
                };
                let draft: ReplyDraft = serde_json::from_str(&draft_json).map_err(|error| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        format!("reply tab {id} has an invalid stored draft: {error}"),
                    )
                })?;
                out.push(ReplyTab {
                    id: ReplyTabId(id),
                    project_id,
                    name,
                    base_exchange_id: base_exchange_id.map(ExchangeId),
                    revision,
                    protocol,
                    draft,
                    created_at: parse_time(&created),
                    updated_at: parse_time(&updated),
                });
            }
            Ok(out)
        })
        .await
    }

    pub async fn get_reply_tab(
        &self,
        project_id: ProjectId,
        id: ReplyTabId,
    ) -> DomainResult<ReplyTab> {
        let tabs = self.list_reply_tabs(project_id).await?;
        tabs.into_iter()
            .find(|t| t.id == id)
            .ok_or_else(|| DomainError::not_found("reply tab"))
    }
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn corrupt_stored_reply_draft_is_reported_not_defaulted() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "reply".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let tab = db
            .upsert_reply_tab(
                project.id,
                None,
                "tab".into(),
                None,
                ProtocolPreference::Auto,
                ReplyDraft::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(db.list_reply_tabs(project.id).await.unwrap().len(), 1);
        db.with_conn(move |conn| {
            conn.execute(
                "UPDATE reply_tabs SET draft_json='not json' WHERE id=?1",
                params![tab.id.0],
            )
            .map_err(storage_error)?;
            Ok(())
        })
        .await
        .unwrap();
        let error = db.list_reply_tabs(project.id).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::StorageError);
        assert!(
            error.to_string().contains("invalid stored draft"),
            "{error}"
        );
    }
}
