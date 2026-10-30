//! Persisted project routing overrides. Proxy URLs remain private.

use crate::config::{validate_upstream_proxy_url, UpstreamProxyConfig};
use crate::domain::{DomainError, DomainResult, ErrorCode, Project, ProjectId};
use crate::storage::Db;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ProjectUpstreamProxyStatus {
    pub project_id: ProjectId,
    pub mode: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ProjectUpstreamProxySetting {
    pub mode: &'static str,
    pub proxy: Option<String>,
    pub effective: EffectiveUpstreamProxy,
}

#[derive(Debug, Serialize)]
pub struct EffectiveUpstreamProxy {
    pub host: String,
    pub mode: &'static str,
    pub proxy: Option<String>,
}

fn redact_proxy(proxy: &str) -> DomainResult<String> {
    let mut url =
        url::Url::parse(proxy).map_err(|_| DomainError::invalid("invalid upstream proxy URL"))?;
    url.set_password(None)
        .map_err(|_| DomainError::invalid("invalid upstream proxy URL"))?;
    url.set_username("")
        .map_err(|_| DomainError::invalid("invalid upstream proxy URL"))?;
    Ok(url.to_string())
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
            if proxy != "direct" {
                validate_upstream_proxy_url(proxy)?;
            }
        }
        self.with_conn(move |conn| {
            if proxy.is_none() {
                let exists: bool = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM projects WHERE id=?1)",
                        params![project_id.get()],
                        |row| row.get(0),
                    )
                    .map_err(|_| {
                        DomainError::new(ErrorCode::StorageError, "could not read project")
                    })?;
                if !exists {
                    return Err(DomainError::not_found("project"));
                }
                conn.execute(
                    "DELETE FROM project_upstream_proxies WHERE project_id=?1",
                    params![project_id.get()],
                )
                .map_err(|_| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        "could not clear project upstream proxy",
                    )
                })?;
                return Ok(ProjectUpstreamProxyStatus {
                    project_id,
                    mode: "inherit",
                });
            }
            let direct = proxy.as_deref() == Some("direct");
            let stored_proxy = if direct { None } else { proxy.as_deref() };
            let updated = conn
                .execute(
                    "INSERT INTO project_upstream_proxies (project_id, proxy)
                 SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM projects WHERE id=?1)
                 ON CONFLICT(project_id) DO UPDATE SET proxy=excluded.proxy",
                    params![project_id.get(), stored_proxy],
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
                mode: if direct { "direct" } else { "proxy" },
            })
        })
        .await
    }

    pub async fn project_upstream_proxy_setting(
        &self,
        project: &Project,
        configured: &UpstreamProxyConfig,
    ) -> DomainResult<ProjectUpstreamProxySetting> {
        let project_id = project.id;
        let live = self.project_upstream_proxy(project_id).await?;
        let host = url::Url::parse(&project.target_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .ok_or_else(|| DomainError::invalid("project target URL has no host"))?;
        let effective = match &live {
            Some(proxy) => proxy.clone(),
            None => configured.proxy_for_project(project_id.get(), &host, None)?,
        };
        Ok(ProjectUpstreamProxySetting {
            mode: match &live {
                None => "inherit",
                Some(None) => "direct",
                Some(Some(_)) => "proxy",
            },
            proxy: live.flatten().as_deref().map(redact_proxy).transpose()?,
            effective: EffectiveUpstreamProxy {
                host,
                mode: if effective.is_some() {
                    "proxy"
                } else {
                    "direct"
                },
                proxy: effective.as_deref().map(redact_proxy).transpose()?,
            },
        })
    }

    async fn project_upstream_proxy(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Option<Option<String>>> {
        self.with_conn(move |conn| {
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
        let live = self.project_upstream_proxy(project_id).await?;
        match live {
            Some(proxy) => Ok(proxy),
            None => configured.proxy_for_project(project_id.get(), host, None),
        }
    }
}
