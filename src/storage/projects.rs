//! Project CRUD.

use crate::domain::*;
use crate::storage::{write_transaction, Db};
use rusqlite::params;
use serde::Serialize;
use std::collections::BTreeMap;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize)]
pub struct ProjectOverview {
    pub project_id: ProjectId,
    pub name: String,
    pub target_url: String,
    pub total_exchanges: u64,
    pub replies_sent: u64,
    pub findings: u64,
    pub unique_hosts: u64,
    pub exchanges_by_source: BTreeMap<String, u64>,
    pub last_activity_at: Option<String>,
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

pub fn parse_time(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

impl Db {
    pub async fn project_overview(&self, id: ProjectId) -> DomainResult<ProjectOverview> {
        self.with_conn(move |conn| {
            let (name, target_url): (String, String) = conn
                .query_row(
                    "SELECT name, target_url FROM projects WHERE id=?1",
                    params![id.get()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => {
                        DomainError::not_found(format!("project {}", id.get()))
                    }
                    other => DomainError::new(ErrorCode::StorageError, other.to_string()),
                })?;

            let mut exchanges_by_source = BTreeMap::from([
                ("browser".to_string(), 0),
                ("fuzzer".to_string(), 0),
                ("imported".to_string(), 0),
                ("plugin".to_string(), 0),
                ("proxy".to_string(), 0),
                ("reply".to_string(), 0),
            ]);
            let mut statement = conn
                .prepare(
                    "SELECT source, COUNT(*) FROM exchanges
                     WHERE project_id=?1 GROUP BY source",
                )
                .map_err(storage_error)?;
            let rows = statement
                .query_map(params![id.get()], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(storage_error)?;
            for row in rows {
                let (source, count) = row.map_err(storage_error)?;
                let count = u64::try_from(count).map_err(|_| {
                    DomainError::new(ErrorCode::StorageError, "negative exchange count")
                })?;
                *exchanges_by_source.entry(source).or_default() = count;
            }

            let total_exchanges = exchanges_by_source.values().sum();
            let replies_sent = exchanges_by_source
                .get("reply")
                .copied()
                .unwrap_or_default();
            let findings: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM findings WHERE project_id=?1",
                    params![id.get()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            let unique_hosts: i64 = conn
                .query_row(
                    "SELECT COUNT(DISTINCT lower(host)) FROM exchanges WHERE project_id=?1",
                    params![id.get()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            let last_activity_at: Option<String> = conn
                .query_row(
                    "SELECT MAX(started_at) FROM exchanges WHERE project_id=?1",
                    params![id.get()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            let findings = u64::try_from(findings)
                .map_err(|_| DomainError::new(ErrorCode::StorageError, "negative finding count"))?;
            let unique_hosts = u64::try_from(unique_hosts)
                .map_err(|_| DomainError::new(ErrorCode::StorageError, "negative host count"))?;

            Ok(ProjectOverview {
                project_id: id,
                name,
                target_url,
                total_exchanges,
                replies_sent,
                findings,
                unique_hosts,
                exchanges_by_source,
                last_activity_at,
            })
        })
        .await
    }

    pub async fn create_project(&self, req: CreateProjectRequest) -> DomainResult<Project> {
        // The initial target remains required, but does not silently become a
        // capture restriction. Scope is an explicit, optional capture filter.
        crate::policy::TargetRef::from_url(&req.target_url)?;
        let target_url = req.target_url.trim().to_string();
        let scope = req.advanced.unwrap_or_default();
        let limits = ProjectLimits::default();
        let name = req.name.trim().to_string();
        if name.is_empty() {
            return Err(DomainError::invalid("project name required"));
        }
        let scope_json = serde_json::to_string(&scope)
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
        let limits_json = serde_json::to_string(&limits)
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
        let ts = now_rfc3339();

        self.with_conn(move |conn| {
            let tx = write_transaction(conn).map_err(|e| {
                DomainError::new(ErrorCode::StorageError, e.to_string())
            })?;
            tx.execute(
                "INSERT INTO projects (name, target_url, created_at, updated_at, scope_json, limits_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![name, target_url, ts, ts, scope_json, limits_json],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let id = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO project_seq (project_id, next_exchange_id) VALUES (?1, 1)",
                params![id],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            tx.execute(
                "INSERT INTO project_usage (project_id, updated_at) VALUES (?1, ?2)",
                params![id, ts],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            tx.commit()
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            Ok(Project {
                id: ProjectId(id),
                name,
                target_url,
                created_at: parse_time(&ts),
                updated_at: parse_time(&ts),
                scope,
                limits,
                default_browser_profile: "default".into(),
                noise_policy: "default".into(),
            })
        })
        .await
    }

    pub async fn list_projects(&self) -> DomainResult<Vec<Project>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, target_url, created_at, updated_at, scope_json, limits_json,
                            default_browser_profile, noise_policy FROM projects ORDER BY id",
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                    ))
                })
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let mut out = Vec::new();
            for r in rows {
                let (id, name, target_url, ca, ua, sj, lj, prof, noise) =
                    r.map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                let scope: ScopePolicy = serde_json::from_str(&sj).unwrap_or_default();
                let limits: ProjectLimits = serde_json::from_str(&lj).unwrap_or_default();
                out.push(Project {
                    id: ProjectId(id),
                    name,
                    target_url,
                    created_at: parse_time(&ca),
                    updated_at: parse_time(&ua),
                    scope,
                    limits,
                    default_browser_profile: prof,
                    noise_policy: noise,
                });
            }
            Ok(out)
        })
        .await
    }

    pub async fn get_project(&self, id: ProjectId) -> DomainResult<Project> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT id, name, target_url, created_at, updated_at, scope_json, limits_json,
                        default_browser_profile, noise_policy FROM projects WHERE id=?1",
                params![id.get()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                    ))
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    DomainError::not_found(format!("project {}", id.get()))
                }
                other => DomainError::new(ErrorCode::StorageError, other.to_string()),
            })
            .map(|(id, name, target_url, ca, ua, sj, lj, prof, noise)| {
                let scope: ScopePolicy = serde_json::from_str(&sj).unwrap_or_default();
                let limits: ProjectLimits = serde_json::from_str(&lj).unwrap_or_default();
                Project {
                    id: ProjectId(id),
                    name,
                    target_url,
                    created_at: parse_time(&ca),
                    updated_at: parse_time(&ua),
                    scope,
                    limits,
                    default_browser_profile: prof,
                    noise_policy: noise,
                }
            })
        })
        .await
    }

    pub async fn update_project_scope(
        &self,
        id: ProjectId,
        scope: ScopePolicy,
        limits: Option<ProjectLimits>,
    ) -> DomainResult<Project> {
        let scope_json = serde_json::to_string(&scope)
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            if let Some(lim) = limits {
                let lj = serde_json::to_string(&lim)
                    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                conn.execute(
                    "UPDATE projects SET scope_json=?1, limits_json=?2, updated_at=?3 WHERE id=?4",
                    params![scope_json, lj, ts, id.get()],
                )
            } else {
                conn.execute(
                    "UPDATE projects SET scope_json=?1, updated_at=?2 WHERE id=?3",
                    params![scope_json, ts, id.get()],
                )
            }
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            Ok(())
        })
        .await?;
        crate::policy::bump_policy_epoch();
        self.get_project(id).await
    }

    pub async fn rename_project(&self, id: ProjectId, name: String) -> DomainResult<Project> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(DomainError::invalid("project name required"));
        }
        if name.len() > 256 {
            return Err(DomainError::invalid("project name exceeds 256 bytes"));
        }
        let timestamp = now_rfc3339();
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE projects SET name=?1, updated_at=?2 WHERE id=?3",
                    params![name, timestamp, id.get()],
                )
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            if changed == 0 {
                return Err(DomainError::not_found(format!("project {}", id.get())));
            }
            Ok(())
        })
        .await?;
        self.get_project(id).await
    }

    pub async fn delete_project(&self, id: ProjectId) -> DomainResult<()> {
        self.with_conn(move |conn| {
            let tx = write_transaction(conn)
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            let changed = tx
                .execute("DELETE FROM projects WHERE id=?1", params![id.get()])
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            if changed == 0 {
                return Err(DomainError::not_found(format!("project {}", id.get())));
            }
            // Bodies are content-addressed but currently project-private in
            // practice. Remove only objects no remaining exchange references.
            tx.execute(
                "DELETE FROM bodies WHERE id NOT IN (
                    SELECT request_body_id FROM exchanges WHERE request_body_id IS NOT NULL
                    UNION
                    SELECT response_body_id FROM exchanges WHERE response_body_id IS NOT NULL
                 )",
                [],
            )
            .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            tx.execute(
                "DELETE FROM search_fts WHERE project_id=?1",
                params![id.get()],
            )
            .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            tx.commit()
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            Ok(())
        })
        .await
    }
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}
