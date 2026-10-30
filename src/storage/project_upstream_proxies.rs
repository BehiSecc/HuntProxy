//! Persisted project routing overrides. Proxy URLs remain private.

use crate::config::{validate_upstream_proxy_url, UpstreamProxyConfig};
use crate::domain::{DomainError, DomainResult, ErrorCode, ProjectId};
use crate::storage::Db;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ProjectUpstreamProxyStatus {
    pub project_id: ProjectId,
    pub mode: &'static str,
}

impl Db {
    pub async fn set_project_upstream_proxy(
        &self,
        project_id: ProjectId,
        proxy: Option<String>,
    ) -> DomainResult<ProjectUpstreamProxyStatus> {
        if let Some(proxy) = &proxy {
            if proxy.len() > 4096 {
                return Err(DomainError::invalid(
                    "upstream proxy URL exceeds its size limit",
                ));
            }
            validate_upstream_proxy_url(proxy)?;
        }
        self.with_conn(move |conn| {
            let updated = conn
                .execute(
                    "INSERT INTO project_upstream_proxies (project_id, proxy)
                 SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM projects WHERE id=?1)
                 ON CONFLICT(project_id) DO UPDATE SET proxy=excluded.proxy",
                    params![project_id.get(), proxy],
                )
                .map_err(|_| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        "could not save project upstream proxy",
                    )
                })?;
            if updated == 0 {
                return Err(DomainError::not_found("project"));
            }
            Ok(ProjectUpstreamProxyStatus {
                project_id,
                mode: if proxy.is_some() { "proxy" } else { "direct" },
            })
        })
        .await
    }

    // Resolve on each new outbound request so clones and running browsers see
    // updates without restarting services or interrupting existing tunnels.
    pub async fn resolve_upstream_proxy(
        &self,
        project_id: ProjectId,
        configured: &UpstreamProxyConfig,
        host: &str,
        request_override: Option<&str>,
    ) -> DomainResult<Option<String>> {
        if let Some(proxy) = request_override {
            validate_upstream_proxy_url(proxy)?;
            return Ok(Some(proxy.to_owned()));
        }
        let live: Option<Option<String>> = self
            .with_conn(move |conn| {
                conn.query_row(
                    "SELECT proxy FROM project_upstream_proxies WHERE project_id=?1",
                    params![project_id.get()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        "could not read project upstream proxy",
                    )
                })
            })
            .await?;
        match live {
            Some(proxy) => Ok(proxy),
            None => configured.proxy_for_project(project_id.get(), host, None),
        }
    }
}
