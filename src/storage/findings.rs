//! Project findings linked to captured exchanges.

use crate::domain::*;
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::Db;
use rusqlite::params;

const MAX_FINDING_TITLE: usize = 256;
const MAX_FINDING_DESCRIPTION: usize = 64 * 1024;

impl Db {
    pub async fn create_finding(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        title: String,
        description: String,
    ) -> DomainResult<Finding> {
        let title = title.trim().to_string();
        let description = description.trim().to_string();
        if title.is_empty() {
            return Err(DomainError::invalid("finding title is required"));
        }
        if title.len() > MAX_FINDING_TITLE {
            return Err(DomainError::invalid("finding title exceeds 256 bytes"));
        }
        if description.is_empty() {
            return Err(DomainError::invalid("finding description is required"));
        }
        if description.len() > MAX_FINDING_DESCRIPTION {
            return Err(DomainError::invalid("finding description exceeds 64 KiB"));
        }
        let timestamp = now_rfc3339();
        self.with_conn(move |conn| {
            let exchange_exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM exchanges WHERE project_id=?1 AND exchange_id=?2)",
                    params![project_id.get(), exchange_id.get()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if !exchange_exists {
                return Err(DomainError::not_found("exchange"));
            }
            conn.execute(
                "INSERT INTO findings
                 (project_id, exchange_id, title, description, created_at, updated_at)
                 VALUES (?1,?2,?3,?4,?5,?5)",
                params![
                    project_id.get(),
                    exchange_id.get(),
                    title,
                    description,
                    timestamp
                ],
            )
            .map_err(storage_error)?;
            Ok(Finding {
                id: FindingId(conn.last_insert_rowid()),
                project_id,
                exchange_id,
                title,
                description,
                created_at: parse_time(&timestamp),
                updated_at: parse_time(&timestamp),
            })
        })
        .await
    }

    pub async fn list_findings(&self, project_id: ProjectId) -> DomainResult<Vec<Finding>> {
        self.get_project(project_id).await?;
        self.with_conn(move |conn| {
            let mut statement = conn
                .prepare(
                    "SELECT id, exchange_id, title, description, created_at, updated_at
                     FROM findings WHERE project_id=?1 ORDER BY id DESC",
                )
                .map_err(storage_error)?;
            let rows = statement
                .query_map(params![project_id.get()], |row| {
                    Ok(Finding {
                        id: FindingId(row.get(0)?),
                        project_id,
                        exchange_id: ExchangeId(row.get(1)?),
                        title: row.get(2)?,
                        description: row.get(3)?,
                        created_at: parse_time(&row.get::<_, String>(4)?),
                        updated_at: parse_time(&row.get::<_, String>(5)?),
                    })
                })
                .map_err(storage_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)
        })
        .await
    }

    pub async fn delete_finding(
        &self,
        project_id: ProjectId,
        finding_id: FindingId,
    ) -> DomainResult<()> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM findings WHERE project_id=?1 AND id=?2",
                    params![project_id.get(), finding_id.get()],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("finding"));
            }
            Ok(())
        })
        .await
    }
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}
