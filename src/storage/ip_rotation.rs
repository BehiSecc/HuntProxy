//! Persistent project-scoped API Gateway rotation profiles.

use crate::domain::{DomainError, DomainResult, ErrorCode, ProjectId};
use crate::storage::{now_rfc3339, write_transaction, Db};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

const MAX_GATEWAYS: usize = 30;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IpRotationGateway {
    pub region: String,
    pub rest_api_id: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IpRotationProfile {
    pub id: i64,
    pub project_id: ProjectId,
    pub target_origin: String,
    pub stage_name: String,
    pub enabled: bool,
    pub gateways: Vec<IpRotationGateway>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRotationRoute {
    pub profile_id: i64,
    pub target_origin: String,
    pub region: String,
    pub endpoint: String,
}

impl IpRotationRoute {
    pub fn wire_url(&self, original_url: &str) -> DomainResult<String> {
        let parsed = Url::parse(original_url)
            .map_err(|error| DomainError::invalid(format!("invalid request URL: {error}")))?;
        let suffix = parsed[url::Position::BeforePath..].to_string();
        Ok(format!("{}{}", self.endpoint.trim_end_matches('/'), suffix))
    }

    pub fn transport_profile(&self, base: &str) -> String {
        format!("{base}+ip_rotate:{}", self.region)
    }
}

pub fn canonical_rotation_origin(value: &str) -> DomainResult<String> {
    let parsed = Url::parse(value)
        .map_err(|error| DomainError::invalid(format!("invalid target origin: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(DomainError::invalid(
            "target must be an exact HTTP(S) origin without credentials, path, query, or fragment",
        ));
    }
    Ok(parsed.origin().ascii_serialization())
}

impl Db {
    pub async fn list_ip_rotation_profiles(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Vec<IpRotationProfile>> {
        self.get_project(project_id).await?;
        self.with_conn(move |conn| load_profiles(conn, project_id))
            .await
    }

    pub async fn activate_ip_rotation(
        &self,
        project_id: ProjectId,
        target_origin: String,
        stage_name: String,
        gateways: Vec<IpRotationGateway>,
    ) -> DomainResult<IpRotationProfile> {
        self.get_project(project_id).await?;
        let target_origin = canonical_rotation_origin(&target_origin)?;
        validate_gateways(&gateways)?;
        let timestamp = now_rfc3339();
        self.with_conn(move |conn| {
            let transaction = write_transaction(conn)
                .map_err(|error| storage_error(error.to_string()))?;
            let existing: Option<i64> = transaction
                .query_row(
                    "SELECT id FROM ip_rotation_profiles WHERE project_id=?1 AND target_origin=?2",
                    params![project_id.get(), target_origin],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage_error)?;
            if existing.is_some() {
                return Err(DomainError::new(
                    ErrorCode::Conflict,
                    "IP rotation is already configured for this target; disable it before enabling a replacement",
                ));
            }
            transaction
                .execute(
                    "INSERT INTO ip_rotation_profiles(project_id,target_origin,stage_name,enabled,created_at,updated_at) VALUES(?1,?2,?3,1,?4,?4)",
                    params![project_id.get(), target_origin, stage_name, timestamp],
                )
                .map_err(storage_error)?;
            let profile_id = transaction.last_insert_rowid();
            for gateway in gateways {
                transaction
                    .execute(
                        "INSERT INTO ip_rotation_gateways(profile_id,region,rest_api_id,endpoint) VALUES(?1,?2,?3,?4)",
                        params![profile_id, gateway.region, gateway.rest_api_id, gateway.endpoint],
                    )
                    .map_err(storage_error)?;
            }
            transaction.commit().map_err(storage_error)?;
            load_profile(conn, project_id, profile_id)
        })
        .await
    }

    /// Disable routing before any remote cleanup begins. Failed AWS deletions
    /// remain visible and can be retried without sending more target traffic.
    pub async fn deactivate_ip_rotation(
        &self,
        project_id: ProjectId,
        target_origin: String,
    ) -> DomainResult<IpRotationProfile> {
        let target_origin = canonical_rotation_origin(&target_origin)?;
        let timestamp = now_rfc3339();
        let profile = self
            .with_conn(move |conn| {
                let transaction =
                    write_transaction(conn).map_err(|error| storage_error(error.to_string()))?;
                let profile_id: i64 = transaction
                .query_row(
                    "SELECT id FROM ip_rotation_profiles WHERE project_id=?1 AND target_origin=?2",
                    params![project_id.get(), target_origin],
                    |row| row.get(0),
                )
                .map_err(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => {
                        DomainError::not_found("IP rotation profile")
                    }
                    other => storage_error(other),
                })?;
                transaction
                    .execute(
                        "UPDATE ip_rotation_profiles SET enabled=0,updated_at=?1 WHERE id=?2",
                        params![timestamp, profile_id],
                    )
                    .map_err(storage_error)?;
                transaction.commit().map_err(storage_error)?;
                load_profile(conn, project_id, profile_id)
            })
            .await?;
        self.ip_rotation_cursors.remove(&profile.id);
        Ok(profile)
    }

    pub async fn remove_ip_rotation_gateway(
        &self,
        project_id: ProjectId,
        profile_id: i64,
        region: String,
    ) -> DomainResult<()> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM ip_rotation_gateways WHERE profile_id=?1 AND region=?2 AND EXISTS(SELECT 1 FROM ip_rotation_profiles WHERE id=?1 AND project_id=?3)",
                    params![profile_id, region, project_id.get()],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("IP rotation gateway"));
            }
            Ok(())
        })
        .await
    }

    pub async fn remove_empty_ip_rotation_profile(
        &self,
        project_id: ProjectId,
        profile_id: i64,
    ) -> DomainResult<bool> {
        let removed = self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM ip_rotation_profiles WHERE id=?1 AND project_id=?2 AND NOT EXISTS(SELECT 1 FROM ip_rotation_gateways WHERE profile_id=?1)",
                    params![profile_id, project_id.get()],
                )
                .map_err(storage_error)?;
            Ok(changed != 0)
        })
        .await?;
        if removed {
            self.ip_rotation_cursors.remove(&profile_id);
        }
        Ok(removed)
    }

    pub async fn next_ip_rotation_route(
        &self,
        project_id: ProjectId,
        request_url: &str,
    ) -> DomainResult<Option<IpRotationRoute>> {
        let parsed = Url::parse(request_url)
            .map_err(|error| DomainError::invalid(format!("invalid request URL: {error}")))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Ok(None);
        }
        let origin = parsed.origin().ascii_serialization();
        let profile = self
            .with_conn(move |conn| {
                let profile_id: Option<i64> = conn
                    .query_row(
                        "SELECT id FROM ip_rotation_profiles WHERE project_id=?1 AND target_origin=?2 AND enabled=1",
                        params![project_id.get(), origin],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(storage_error)?;
                let Some(profile_id) = profile_id else {
                    return Ok(None);
                };
                let gateways = {
                    let mut statement = conn
                        .prepare("SELECT region,endpoint FROM ip_rotation_gateways WHERE profile_id=?1 ORDER BY id")
                        .map_err(storage_error)?;
                    let rows = statement
                        .query_map(params![profile_id], |row| Ok((row.get(0)?, row.get(1)?)))
                        .map_err(storage_error)?;
                    rows.collect::<Result<Vec<(String, String)>, _>>()
                        .map_err(storage_error)?
                };
                if gateways.is_empty() {
                    return Err(DomainError::new(
                        ErrorCode::StorageError,
                        "enabled IP rotation profile has no gateways",
                    ));
                }
                Ok(Some((profile_id, origin, gateways)))
            })
            .await?;
        let Some((profile_id, target_origin, gateways)) = profile else {
            return Ok(None);
        };
        let cursor = self
            .ip_rotation_cursors
            .entry(profile_id)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
        let index = usize::try_from(cursor).unwrap_or(0) % gateways.len();
        let (region, endpoint) = gateways[index].clone();
        Ok(Some(IpRotationRoute {
            profile_id,
            target_origin,
            region,
            endpoint,
        }))
    }
}

fn validate_gateways(gateways: &[IpRotationGateway]) -> DomainResult<()> {
    if gateways.is_empty() || gateways.len() > MAX_GATEWAYS {
        return Err(DomainError::invalid("IP rotation requires 1..=30 gateways"));
    }
    let mut regions = std::collections::BTreeSet::new();
    for gateway in gateways {
        if !regions.insert(gateway.region.as_str())
            || gateway.region.is_empty()
            || gateway.rest_api_id.is_empty()
            || gateway.endpoint.is_empty()
        {
            return Err(DomainError::invalid(
                "IP rotation gateways require unique regions and non-empty identifiers",
            ));
        }
    }
    Ok(())
}

fn load_profiles(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
) -> DomainResult<Vec<IpRotationProfile>> {
    let ids = {
        let mut statement = conn
            .prepare(
                "SELECT id FROM ip_rotation_profiles WHERE project_id=?1 ORDER BY target_origin",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map(params![project_id.get()], |row| row.get(0))
            .map_err(storage_error)?;
        rows.collect::<Result<Vec<i64>, _>>()
            .map_err(storage_error)?
    };
    ids.into_iter()
        .map(|id| load_profile(conn, project_id, id))
        .collect()
}

fn load_profile(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
    id: i64,
) -> DomainResult<IpRotationProfile> {
    let (target_origin, stage_name, enabled, created_at, updated_at) = conn
        .query_row(
            "SELECT target_origin,stage_name,enabled,created_at,updated_at FROM ip_rotation_profiles WHERE id=?1 AND project_id=?2",
            params![id, project_id.get()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? != 0, row.get(3)?, row.get(4)?)),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => DomainError::not_found("IP rotation profile"),
            other => storage_error(other),
        })?;
    let gateways = {
        let mut statement = conn
            .prepare("SELECT region,rest_api_id,endpoint FROM ip_rotation_gateways WHERE profile_id=?1 ORDER BY id")
            .map_err(storage_error)?;
        let rows = statement
            .query_map(params![id], |row| {
                Ok(IpRotationGateway {
                    region: row.get(0)?,
                    rest_api_id: row.get(1)?,
                    endpoint: row.get(2)?,
                })
            })
            .map_err(storage_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)?
    };
    Ok(IpRotationProfile {
        id,
        project_id,
        target_origin,
        stage_name,
        enabled,
        gateways,
        created_at,
        updated_at,
    })
}

fn storage_error(error: impl std::fmt::Display) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::CreateProjectRequest;

    fn gateway(region: &str, id: &str) -> IpRotationGateway {
        IpRotationGateway {
            region: region.into(),
            rest_api_id: id.into(),
            endpoint: format!("https://{id}.execute-api.{region}.amazonaws.com/huntproxy"),
        }
    }

    #[tokio::test]
    async fn rotation_is_exact_origin_round_robin_and_disable_is_immediate() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "rotation".into(),
                target_url: "https://api.example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let profile = db
            .activate_ip_rotation(
                project.id,
                "https://api.example.test".into(),
                "huntproxy".into(),
                vec![
                    gateway("us-east-1", "abcde12345"),
                    gateway("eu-west-1", "vwxyz12345"),
                ],
            )
            .await
            .unwrap();
        assert!(profile.enabled);

        let first = db
            .next_ip_rotation_route(project.id, "https://api.example.test/a?b=1")
            .await
            .unwrap()
            .unwrap();
        let second = db
            .next_ip_rotation_route(project.id, "https://api.example.test/b")
            .await
            .unwrap()
            .unwrap();
        let third = db
            .next_ip_rotation_route(project.id, "https://api.example.test/c")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.region, "us-east-1");
        assert_eq!(second.region, "eu-west-1");
        assert_eq!(third.region, "us-east-1");
        assert!(first
            .wire_url("https://api.example.test/a?b=1")
            .unwrap()
            .ends_with("/huntproxy/a?b=1"));
        assert!(db
            .next_ip_rotation_route(project.id, "http://api.example.test/a")
            .await
            .unwrap()
            .is_none());
        assert!(db
            .next_ip_rotation_route(project.id, "https://other.example.test/a")
            .await
            .unwrap()
            .is_none());

        let disabled = db
            .deactivate_ip_rotation(project.id, "https://api.example.test".into())
            .await
            .unwrap();
        assert!(!disabled.enabled);
        assert!(db
            .next_ip_rotation_route(project.id, "https://api.example.test/a")
            .await
            .unwrap()
            .is_none());
    }
}
