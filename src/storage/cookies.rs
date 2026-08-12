use crate::cookies::{
    CookieProfileStatus, ManagedCookie, StoredCookieProfile, ValidatedCookieProfile,
};
use crate::domain::{DomainError, DomainResult, ErrorCode, ProjectId};
use crate::storage::projects::now_rfc3339;
use crate::storage::Db;
use rusqlite::{params, OptionalExtension};

impl Db {
    pub async fn upsert_named_cookie_profile(
        &self,
        project_id: ProjectId,
        name: &str,
        profile: ValidatedCookieProfile,
    ) -> DomainResult<CookieProfileStatus> {
        validate_profile_name(name)?;
        self.get_project(project_id).await?;
        let name = name.to_string();
        let now = now_rfc3339();
        let names_json = cookie_metadata_json(&profile)?;
        self.with_conn(move |connection| {
            let created_at = connection
                .query_row(
                    "SELECT created_at FROM named_cookie_profiles WHERE project_id=?1 AND name=?2",
                    params![project_id.get(), name],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?
                .unwrap_or_else(|| now.clone());
            connection
                .execute(
                    "INSERT INTO named_cookie_profiles
                 (project_id, name, target_url, cookie_header, names_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                 ON CONFLICT(project_id, name) DO UPDATE SET
                   target_url=excluded.target_url, cookie_header=excluded.cookie_header,
                   names_json=excluded.names_json, updated_at=excluded.updated_at",
                    params![
                        project_id.get(),
                        name,
                        profile.target_url,
                        profile.cookie_header,
                        names_json,
                        now
                    ],
                )
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            Ok(CookieProfileStatus {
                project_id,
                host: profile.host,
                target_url: profile.target_url,
                names: profile.names.clone(),
                cookie_count: profile.names.len(),
                created_at,
                updated_at: now,
            })
        })
        .await
    }

    pub async fn list_named_cookie_profiles(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Vec<(String, CookieProfileStatus)>> {
        self.get_project(project_id).await?;
        self.with_conn(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT name, target_url, cookie_header, names_json, created_at, updated_at
                 FROM named_cookie_profiles WHERE project_id=?1 ORDER BY name",
                )
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            let rows = statement
                .query_map(params![project_id.get()], |row| {
                    let name: String = row.get(0)?;
                    let profile = row_to_named_profile(project_id, row)?;
                    Ok((name, profile.status()))
                })
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            rows.map(|row| {
                row.map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))
            })
            .collect()
        })
        .await
    }

    pub async fn get_named_cookie_profile(
        &self,
        project_id: ProjectId,
        name: &str,
    ) -> DomainResult<Option<StoredCookieProfile>> {
        validate_profile_name(name)?;
        let name = name.to_string();
        self.with_conn(move |connection| {
            connection
                .query_row(
                    "SELECT name, target_url, cookie_header, names_json, created_at, updated_at
                 FROM named_cookie_profiles WHERE project_id=?1 AND name=?2",
                    params![project_id.get(), name],
                    |row| row_to_named_profile(project_id, row),
                )
                .optional()
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))
        })
        .await
    }

    pub async fn delete_named_cookie_profile(
        &self,
        project_id: ProjectId,
        name: &str,
    ) -> DomainResult<bool> {
        validate_profile_name(name)?;
        let name = name.to_string();
        self.with_conn(move |connection| {
            connection
                .execute(
                    "DELETE FROM named_cookie_profiles WHERE project_id=?1 AND name=?2",
                    params![project_id.get(), name],
                )
                .map(|count| count > 0)
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))
        })
        .await
    }

    pub async fn upsert_cookie_profile(
        &self,
        project_id: ProjectId,
        profile: ValidatedCookieProfile,
    ) -> DomainResult<CookieProfileStatus> {
        self.get_project(project_id).await?;
        let now = now_rfc3339();
        let names_json = if let Some(managed_cookies) = &profile.managed_cookies {
            serde_json::to_string(&CookieMetadata::Structured {
                names: profile.names.clone(),
                managed_cookies: managed_cookies.clone(),
            })
        } else {
            serde_json::to_string(&CookieMetadata::Legacy(profile.names.clone()))
        }
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
                     FROM project_cookies WHERE project_id=?1
                     ORDER BY julianday(updated_at), updated_at, host",
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
        let (host, normalized_url) = crate::cookies::normalize_target(target_url)?;
        self.with_conn(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT host, target_url, cookie_header, names_json, created_at, updated_at
                     FROM project_cookies WHERE project_id=?1
                     ORDER BY julianday(updated_at), updated_at, host",
                )
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            let profiles = statement
                .query_map(params![project_id.get()], |row| {
                    row_to_profile(project_id, row)
                })
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            let mut by_identity = std::collections::BTreeMap::new();
            for profile in &profiles {
                if let Some(cookies) = &profile.managed_cookies {
                    for cookie in cookies
                        .iter()
                        .filter(|cookie| cookie.domain_matches_host(&host))
                    {
                        by_identity.insert(
                            (
                                cookie.name.clone(),
                                cookie.domain.clone(),
                                cookie.path.clone(),
                            ),
                            cookie.clone(),
                        );
                    }
                } else if profile.host == host {
                    // Raw cookies are exact-host root session cookies. Insert
                    // them in the same updated-at order as structured rows so
                    // Chromium and HTTP request selection choose the same
                    // winner for an identical name/domain/path identity.
                    for pair in profile.pairs()? {
                        let cookie = ManagedCookie {
                            name: pair.name,
                            value: pair.value,
                            domain: host.clone(),
                            host_only: true,
                            path: "/".into(),
                            http_only: false,
                            secure: false,
                            same_site: None,
                            expires: None,
                        };
                        by_identity.insert(
                            (
                                cookie.name.clone(),
                                cookie.domain.clone(),
                                cookie.path.clone(),
                            ),
                            cookie,
                        );
                    }
                }
            }
            let mut cookies = by_identity.into_values().collect::<Vec<_>>();
            if cookies.is_empty() {
                return Ok(None);
            }
            cookies.sort_by(|left, right| {
                right
                    .path
                    .len()
                    .cmp(&left.path.len())
                    .then_with(|| left.domain.cmp(&right.domain))
                    .then_with(|| left.name.cmp(&right.name))
            });
            let names = cookies
                .iter()
                .map(|cookie| cookie.name.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let cookie_header = cookies
                .iter()
                .map(|cookie| format!("{}={}", cookie.name, cookie.value))
                .collect::<Vec<_>>()
                .join("; ");
            let created_at = profiles
                .first()
                .map(|profile| profile.created_at.clone())
                .unwrap_or_default();
            let updated_at = profiles
                .last()
                .map(|profile| profile.updated_at.clone())
                .unwrap_or_default();
            Ok(Some(StoredCookieProfile {
                project_id,
                host,
                target_url: normalized_url,
                cookie_header,
                names,
                managed_cookies: Some(cookies),
                created_at,
                updated_at,
            }))
        })
        .await
    }

    pub async fn get_cookie_profile_for_target(
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

fn validate_profile_name(name: &str) -> DomainResult<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DomainError::invalid(
            "cookie profile name must use 1-64 letters, digits, hyphens, or underscores",
        ));
    }
    Ok(())
}

fn cookie_metadata_json(profile: &ValidatedCookieProfile) -> DomainResult<String> {
    let metadata = match &profile.managed_cookies {
        Some(managed_cookies) => CookieMetadata::Structured {
            names: profile.names.clone(),
            managed_cookies: managed_cookies.clone(),
        },
        None => CookieMetadata::Legacy(profile.names.clone()),
    };
    serde_json::to_string(&metadata)
        .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))
}

fn row_to_named_profile(
    project_id: ProjectId,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredCookieProfile> {
    let target_url: String = row.get(1)?;
    let host = url::Url::parse(&target_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_default();
    let names_json: String = row.get(3)?;
    let metadata: CookieMetadata = serde_json::from_str(&names_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let (names, managed_cookies) = match metadata {
        CookieMetadata::Legacy(names) => (names, None),
        CookieMetadata::Structured {
            names,
            managed_cookies,
        } => (names, Some(managed_cookies)),
    };
    Ok(StoredCookieProfile {
        project_id,
        host,
        target_url,
        cookie_header: row.get(2)?,
        names,
        managed_cookies,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
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
    let metadata: CookieMetadata = serde_json::from_str(&names_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let (names, managed_cookies) = match metadata {
        CookieMetadata::Legacy(names) => (names, None),
        CookieMetadata::Structured {
            names,
            managed_cookies,
        } => (names, Some(managed_cookies)),
    };
    Ok(StoredCookieProfile {
        project_id,
        host: row.get(0)?,
        target_url: row.get(1)?,
        cookie_header: row.get(2)?,
        names,
        managed_cookies,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum CookieMetadata {
    Legacy(Vec<String>),
    Structured {
        names: Vec<String>,
        managed_cookies: Vec<ManagedCookie>,
    },
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

        db.upsert_cookie_profile(
            first.id,
            validate_cookie_profile(
                "https://example.com/admin",
                r#"[{"domain":".example.com","name":"json_sid","path":"/admin","httpOnly":true,"secure":true,"sameSite":"strict","expirationDate":4102444800,"value":"json-secret"}]"#.into(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let stored = db
            .get_cookie_profile_for_url(first.id, "https://example.com/admin")
            .await
            .unwrap()
            .unwrap();
        let cookie = &stored.managed_cookies.as_ref().unwrap()[0];
        assert_eq!(cookie.path, "/admin");
        assert!(cookie.http_only);
        assert!(cookie.secure);
        assert_eq!(cookie.same_site.as_deref(), Some("Strict"));
        let sibling = db
            .get_cookie_profile_for_url(first.id, "https://api.example.com/admin/users")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            sibling
                .cookie_header_for_url("https://api.example.com/admin/users")
                .unwrap()
                .as_deref(),
            Some("json_sid=json-secret")
        );

        db.upsert_cookie_profile(
            first.id,
            validate_cookie_profile(
                "https://api.example.com/admin",
                r#"[{"domain":".example.com","name":"json_sid","path":"/admin","secure":true,"session":true,"value":"newer-secret"}]"#.into(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let merged = db
            .get_cookie_profile_for_url(first.id, "https://api.example.com/admin")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            merged
                .cookie_header_for_url("https://api.example.com/admin")
                .unwrap()
                .as_deref(),
            Some("json_sid=newer-secret")
        );

        db.upsert_cookie_profile(
            first.id,
            validate_cookie_profile("https://api.example.com", "raw=raw-secret".into()).unwrap(),
        )
        .await
        .unwrap();
        let merged = db
            .get_cookie_profile_for_url(first.id, "https://api.example.com/admin")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            merged
                .cookie_header_for_url("https://api.example.com/admin")
                .unwrap()
                .as_deref(),
            Some("json_sid=json-secret; raw=raw-secret")
        );

        db.upsert_cookie_profile(
            first.id,
            validate_cookie_profile("https://api.example.com", "identity=raw-older".into())
                .unwrap(),
        )
        .await
        .unwrap();
        db.upsert_cookie_profile(
            first.id,
            validate_cookie_profile(
                "https://sub.api.example.com",
                r#"[{"domain":".api.example.com","name":"identity","path":"/","secure":true,"session":true,"value":"structured-newer"}]"#.into(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let merged = db
            .get_cookie_profile_for_url(first.id, "https://api.example.com/")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            merged
                .managed_cookies
                .as_ref()
                .unwrap()
                .iter()
                .find(|cookie| cookie.name == "identity")
                .unwrap()
                .value,
            "structured-newer"
        );

        db.upsert_cookie_profile(
            first.id,
            validate_cookie_profile("https://api.example.com", "identity=raw-newer".into())
                .unwrap(),
        )
        .await
        .unwrap();
        let merged = db
            .get_cookie_profile_for_url(first.id, "https://api.example.com/")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            merged
                .managed_cookies
                .as_ref()
                .unwrap()
                .iter()
                .find(|cookie| cookie.name == "identity")
                .unwrap()
                .value,
            "raw-newer"
        );
    }

    #[tokio::test]
    async fn named_profiles_allow_two_isolated_identities_for_one_host() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "named".into(),
                target_url: "https://example.com".into(),
                advanced: None,
            })
            .await
            .unwrap();
        db.upsert_named_cookie_profile(
            project.id,
            "first",
            validate_cookie_profile("https://example.com", "sid=one".into()).unwrap(),
        )
        .await
        .unwrap();
        db.upsert_named_cookie_profile(
            project.id,
            "second",
            validate_cookie_profile("https://example.com", "sid=two".into()).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            db.list_named_cookie_profiles(project.id)
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            db.get_named_cookie_profile(project.id, "first")
                .await
                .unwrap()
                .unwrap()
                .cookie_header,
            "sid=one"
        );
        assert_eq!(
            db.get_named_cookie_profile(project.id, "second")
                .await
                .unwrap()
                .unwrap()
                .cookie_header,
            "sid=two"
        );
        assert_eq!(
            db.get_named_cookie_profile(project.id, "first")
                .await
                .unwrap()
                .unwrap()
                .cookie_header_for_url("https://other.example.com/")
                .unwrap(),
            None,
            "raw named identities are exact-host scoped"
        );
        assert!(
            db.get_cookie_profile_for_target(project.id, "https://example.com")
                .await
                .unwrap()
                .is_none(),
            "named profiles do not affect the active jar"
        );
        assert!(db
            .delete_named_cookie_profile(project.id, "first")
            .await
            .unwrap());
    }
}
