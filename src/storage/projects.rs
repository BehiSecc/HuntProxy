//! Project CRUD.

use crate::domain::*;
use crate::storage::Db;
use rusqlite::params;
use time::OffsetDateTime;

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
    pub async fn create_project(&self, req: CreateProjectRequest) -> DomainResult<Project> {
        // The initial target remains required, but does not silently become a
        // capture restriction. Scope is an explicit, optional capture filter.
        crate::policy::TargetRef::from_url(&req.target_url)?;
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
            conn.execute(
                "INSERT INTO projects (name, created_at, updated_at, scope_json, limits_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![name, ts, ts, scope_json, limits_json],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO project_seq (project_id, next_exchange_id) VALUES (?1, 1)",
                params![id],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            Ok(Project {
                id: ProjectId(id),
                name,
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
                    "SELECT id, name, created_at, updated_at, scope_json, limits_json,
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
                    ))
                })
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let mut out = Vec::new();
            for r in rows {
                let (id, name, ca, ua, sj, lj, prof, noise) =
                    r.map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                let scope: ScopePolicy = serde_json::from_str(&sj).unwrap_or_default();
                let limits: ProjectLimits = serde_json::from_str(&lj).unwrap_or_default();
                out.push(Project {
                    id: ProjectId(id),
                    name,
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
                "SELECT id, name, created_at, updated_at, scope_json, limits_json,
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
                    ))
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    DomainError::not_found(format!("project {}", id.get()))
                }
                other => DomainError::new(ErrorCode::StorageError, other.to_string()),
            })
            .map(|(id, name, ca, ua, sj, lj, prof, noise)| {
                let scope: ScopePolicy = serde_json::from_str(&sj).unwrap_or_default();
                let limits: ProjectLimits = serde_json::from_str(&lj).unwrap_or_default();
                Project {
                    id: ProjectId(id),
                    name,
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
}
