use crate::cookies::{CookieProfileStatus, StoredCookieProfile, ValidatedCookieProfile};
use crate::domain::{DomainError, DomainResult, ErrorCode, ProjectId};
use crate::storage::projects::now_rfc3339;
use crate::storage::Db;
use rusqlite::{params, OptionalExtension};

impl Db {
    pub async fn upsert_cookie_profile(
        &self,
        project_id: ProjectId,
        profile: ValidatedCookieProfile,
    ) -> DomainResult<CookieProfileStatus> {
        self.get_project(project_id).await?;
        let now = now_rfc3339();
        let names_json = serde_json::to_string(&profile.names)
            .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
        self.with_conn(move |connection| {
            connection
                .execute(
                    "INSERT INTO project_cookies
                     (project_id, host, target_url, cookie_header, names_json, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                     ON CONFLICT(project_id, host) DO UPDATE SET
                       target_url=excluded.target_url,
                       cookie_header=excluded.cookie_header,
                       names_json=excluded.names_json,
                       updated_at=excluded.updated_at",
                    params![
                        project_id.get(),
                        profile.host,
                        profile.target_url,
                        profile.cookie_header,
                        names_json,
                        now
                    ],
                )
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            load_profile(connection, project_id, &profile.host)?.map_or_else(
                || Err(DomainError::new(ErrorCode::StorageError, "cookie profile missing")),
                |profile| Ok(profile.status()),
            )
        })
        .await
    }

    pub async fn list_cookie_profiles(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Vec<CookieProfileStatus>> {
        self.get_project(project_id).await?;
        self.with_conn(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT host, target_url, cookie_header, names_json, created_at, updated_at
                     FROM project_cookies WHERE project_id=?1 ORDER BY host",
                )
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            let rows = statement
                .query_map(params![project_id.get()], |row| {
                    row_to_profile(project_id, row)
                })
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            rows.map(|row| {
                row.map(|profile| profile.status())
                    .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))
            })
            .collect()
        })
        .await
    }

    pub async fn list_stored_cookie_profiles(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Vec<StoredCookieProfile>> {
        self.get_project(project_id).await?;
        self.with_conn(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT host, target_url, cookie_header, names_json, created_at, updated_at
                     FROM project_cookies WHERE project_id=?1 ORDER BY host",
                )
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            let rows = statement
                .query_map(params![project_id.get()], |row| {
                    row_to_profile(project_id, row)
                })
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            rows.map(|row| {
                row.map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))
            })
            .collect()
        })
        .await
    }

    pub async fn get_cookie_profile_for_url(
        &self,
        project_id: ProjectId,
        target_url: &str,
    ) -> DomainResult<Option<StoredCookieProfile>> {
        let (host, _) = crate::cookies::normalize_target(target_url)?;
        self.with_conn(move |connection| load_profile(connection, project_id, &host))
            .await
    }

    pub async fn delete_cookie_profile(
        &self,
        project_id: ProjectId,
        target_url: &str,
    ) -> DomainResult<Option<StoredCookieProfile>> {
        let (host, _) = crate::cookies::normalize_target(target_url)?;
        self.with_conn(move |connection| {
            let profile = load_profile(connection, project_id, &host)?;
            if profile.is_some() {
                connection
                    .execute(
                        "DELETE FROM project_cookies WHERE project_id=?1 AND host=?2",
                        params![project_id.get(), host],
                    )
                    .map_err(|error| {
                        DomainError::new(ErrorCode::StorageError, error.to_string())
                    })?;
            }
            Ok(profile)
        })
        .await
    }
}

fn load_profile(
    connection: &rusqlite::Connection,
    project_id: ProjectId,
    host: &str,
) -> DomainResult<Option<StoredCookieProfile>> {
    connection
        .query_row(
            "SELECT host, target_url, cookie_header, names_json, created_at, updated_at
             FROM project_cookies WHERE project_id=?1 AND host=?2",
            params![project_id.get(), host],
            |row| row_to_profile(project_id, row),
        )
        .optional()
        .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))
}

fn row_to_profile(
    project_id: ProjectId,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredCookieProfile> {
    let names_json: String = row.get(3)?;
    let names = serde_json::from_str(&names_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(StoredCookieProfile {
        project_id,
        host: row.get(0)?,
        target_url: row.get(1)?,
        cookie_header: row.get(2)?,
        names,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cookies::validate_cookie_profile;
    use crate::domain::CreateProjectRequest;

    #[tokio::test]
    async fn profile_round_trip_is_project_and_host_scoped() {
        let db = Db::open_in_memory().await.unwrap();
        let first = db
            .create_project(CreateProjectRequest {
                name: "first".into(),
                target_url: "https://example.com".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let second = db
            .create_project(CreateProjectRequest {
                name: "second".into(),
                target_url: "https://example.com".into(),
                advanced: None,
            })
            .await
            .unwrap();
        db.upsert_cookie_profile(
            first.id,
            validate_cookie_profile("https://example.com/login", "sid=secret".into()).unwrap(),
        )
        .await
        .unwrap();

        assert!(db
            .get_cookie_profile_for_url(first.id, "http://example.com:8080/path")
            .await
            .unwrap()
            .is_some());
        assert!(db
            .get_cookie_profile_for_url(second.id, "https://example.com")
            .await
            .unwrap()
            .is_none());
        let status = db.list_cookie_profiles(first.id).await.unwrap();
        assert_eq!(status[0].names, vec!["sid"]);
        assert!(!serde_json::to_string(&status).unwrap().contains("secret"));
    }
}
