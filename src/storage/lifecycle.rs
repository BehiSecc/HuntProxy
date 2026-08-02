//! Project lifecycle, usage, backup, and portable project archives.

use crate::domain::*;
use crate::storage::exchanges::{
    load_headers, parse_body_rep, parse_cache_prov, parse_capture_quality, parse_completion,
    parse_header_rep, parse_source, parse_transport_prov, NewExchange,
};
use crate::storage::projects::now_rfc3339;
use crate::storage::Db;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const ARCHIVE_FORMAT: &str = "huntproxy-project";
const ARCHIVE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct ProjectUsage {
    pub project_id: ProjectId,
    pub exchange_count: u64,
    pub request_body_bytes: u64,
    pub response_body_bytes: u64,
    pub header_bytes: u64,
    pub approximate_total_bytes: u64,
    pub database_file_bytes: u64,
    pub max_disk_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReconcileUsageResult {
    pub project_id: ProjectId,
    pub previous_accounted_bytes: u64,
    pub accounted_bytes: u64,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClearHistoryResult {
    pub project_id: ProjectId,
    pub deleted_exchanges: u64,
    pub before: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectArchive {
    pub format: String,
    pub version: u32,
    pub exported_at: String,
    pub project: ArchivedProject,
    #[serde(default)]
    pub request_rules: Vec<crate::request_rules::RequestRule>,
    pub exchanges: Vec<ArchivedExchange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedProject {
    pub name: String,
    pub target_url: String,
    pub scope: ScopePolicy,
    pub limits: ProjectLimits,
    pub default_browser_profile: String,
    pub noise_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedExchange {
    pub original_exchange_id: i64,
    pub started_at: String,
    pub display_title: Option<String>,
    pub exchange: NewExchange,
    pub annotation: Option<ArchivedAnnotation>,
    pub findings: Vec<ArchivedFinding>,
    #[serde(default)]
    pub applied_request_rules: Vec<crate::request_rules::AppliedRequestRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedAnnotation {
    pub display_title: Option<String>,
    pub note: Option<String>,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedFinding {
    pub title: String,
    pub description: String,
}

impl Db {
    pub async fn project_usage(&self, project_id: ProjectId) -> DomainResult<ProjectUsage> {
        let database_file_bytes = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        self.with_conn(move |conn| {
            let (limits_json, count, request, response, headers, accounted): (
                String,
                i64,
                i64,
                i64,
                i64,
                i64,
            ) = conn
                .query_row(
                    "SELECT p.limits_json, u.exchange_count, u.request_body_bytes,
                            u.response_body_bytes, u.header_bytes, u.accounted_bytes
                     FROM projects p JOIN project_usage u ON u.project_id=p.id
                     WHERE p.id=?1",
                    params![project_id.get()],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .map_err(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => {
                        missing_usage_or_project(conn, project_id)
                    }
                    other => storage_error(other.to_string()),
                })?;
            let limits: ProjectLimits = serde_json::from_str(&limits_json)
                .map_err(|error| storage_error(error.to_string()))?;
            let exchange_count = count.max(0) as u64;
            let request_body_bytes = request.max(0) as u64;
            let response_body_bytes = response.max(0) as u64;
            let header_bytes = headers.max(0) as u64;
            let approximate_total_bytes = accounted.max(0) as u64;
            Ok(ProjectUsage {
                project_id,
                exchange_count,
                request_body_bytes,
                response_body_bytes,
                header_bytes,
                approximate_total_bytes,
                database_file_bytes,
                max_disk_bytes: limits.max_disk_bytes,
            })
        })
        .await
    }

    pub async fn reconcile_project_usage(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<ReconcileUsageResult> {
        self.with_conn(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|error| storage_error(error.to_string()))?;
            let result = reconcile_project_usage_conn(&tx, project_id)?;
            tx.commit()
                .map_err(|error| storage_error(error.to_string()))?;
            Ok(result)
        })
        .await
    }

    pub async fn clear_history_before(
        &self,
        project_id: ProjectId,
        before: String,
    ) -> DomainResult<ClearHistoryResult> {
        let cutoff =
            time::OffsetDateTime::parse(&before, &time::format_description::well_known::Rfc3339)
                .map_err(|_| DomainError::invalid("before must be an RFC 3339 timestamp"))?
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| DomainError::invalid(error.to_string()))?;
        let cutoff_for_query = cutoff.clone();
        self.with_conn(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|error| storage_error(error.to_string()))?;
            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM projects WHERE id=?1)",
                    params![project_id.get()],
                    |row| row.get(0),
                )
                .map_err(|error| storage_error(error.to_string()))?;
            if !exists {
                return Err(DomainError::not_found(format!(
                    "project {}",
                    project_id.get()
                )));
            }
            tx.execute(
                "DELETE FROM search_fts WHERE project_id=?1 AND exchange_id IN
                 (SELECT exchange_id FROM exchanges WHERE project_id=?1
                  AND julianday(started_at) < julianday(?2))",
                params![project_id.get(), cutoff_for_query],
            )
            .map_err(|error| storage_error(error.to_string()))?;
            let deleted = tx
                .execute(
                    "DELETE FROM exchanges WHERE project_id=?1
                     AND julianday(started_at) < julianday(?2)",
                    params![project_id.get(), cutoff_for_query],
                )
                .map_err(|error| storage_error(error.to_string()))?;
            tx.execute(
                "DELETE FROM labels WHERE id NOT IN (SELECT label_id FROM exchange_labels)",
                [],
            )
            .map_err(|error| storage_error(error.to_string()))?;
            tx.execute(
                "DELETE FROM bodies WHERE id NOT IN (
                    SELECT request_body_id FROM exchanges WHERE request_body_id IS NOT NULL
                    UNION SELECT response_body_id FROM exchanges WHERE response_body_id IS NOT NULL
                 )",
                [],
            )
            .map_err(|error| storage_error(error.to_string()))?;
            reconcile_project_usage_conn(&tx, project_id)?;
            tx.commit()
                .map_err(|error| storage_error(error.to_string()))?;
            Ok(ClearHistoryResult {
                project_id,
                deleted_exchanges: deleted as u64,
                before: cutoff_for_query,
            })
        })
        .await
    }

    /// Create a consistent SQLite backup without stopping the daemon.
    pub async fn backup_to(&self, destination: PathBuf) -> DomainResult<PathBuf> {
        if self.path != Path::new(":memory:") && same_file_path(&self.path, &destination) {
            return Err(DomainError::invalid(
                "backup destination must differ from the database",
            ));
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| storage_error(format!("create backup directory: {error}")))?;
        }
        let source_path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let source = rusqlite::Connection::open(&source_path)
                .map_err(|error| storage_error(format!("open source database: {error}")))?;
            let mut target = rusqlite::Connection::open(&destination)
                .map_err(|error| storage_error(format!("open backup database: {error}")))?;
            let backup = rusqlite::backup::Backup::new(&source, &mut target)
                .map_err(|error| storage_error(format!("start database backup: {error}")))?;
            backup
                .run_to_completion(128, std::time::Duration::from_millis(10), None)
                .map_err(|error| storage_error(format!("database backup: {error}")))?;
            drop(backup);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600))
                    .map_err(|error| {
                        storage_error(format!("secure backup permissions: {error}"))
                    })?;
            }
            Ok(destination)
        })
        .await
        .map_err(|error| storage_error(format!("database backup task: {error}")))?
    }

    pub async fn export_project(&self, project_id: ProjectId) -> DomainResult<ProjectArchive> {
        let project = self.get_project(project_id).await?;
        let request_rules = self.list_request_rules(project_id).await?;
        self.with_conn(move |conn| {
            let mut statement = conn
                .prepare(
                    "SELECT exchange_id, started_at, display_title, source, protocol, method, scheme,
                            authority, host, port, path, query, status_code, mime, completion,
                            capture_quality, header_representation, body_representation, cache_provenance,
                            transport_provenance, transport_profile, duration_ms, page_title, error_message,
                            parent_exchange_id, redirect_parent_id, request_body_id, response_body_id
                     FROM exchanges WHERE project_id=?1 ORDER BY exchange_id",
                )
                .map_err(|error| storage_error(error.to_string()))?;
            let rows = statement
                .query_map(params![project_id.get()], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, Option<String>>(11)?,
                        row.get::<_, Option<i64>>(12)?,
                        row.get::<_, Option<String>>(13)?,
                        row.get::<_, String>(14)?,
                        row.get::<_, String>(15)?,
                        row.get::<_, String>(16)?,
                        row.get::<_, String>(17)?,
                        row.get::<_, String>(18)?,
                        row.get::<_, Option<String>>(19)?,
                        row.get::<_, Option<String>>(20)?,
                        row.get::<_, Option<i64>>(21)?,
                        row.get::<_, Option<String>>(22)?,
                        row.get::<_, Option<String>>(23)?,
                        row.get::<_, Option<i64>>(24)?,
                        row.get::<_, Option<i64>>(25)?,
                        row.get::<_, Option<i64>>(26)?,
                        row.get::<_, Option<i64>>(27)?,
                    ))
                })
                .map_err(|error| storage_error(error.to_string()))?;
            let mut exchanges = Vec::new();
            for row in rows {
                let (
                    id,
                    started_at,
                    display_title,
                    source,
                    protocol,
                    method,
                    scheme,
                    authority,
                    host,
                    port,
                    path,
                    query,
                    status,
                    mime,
                    completion,
                    quality,
                    header_rep,
                    body_rep,
                    cache,
                    transport,
                    transport_profile,
                    duration_ms,
                    page_title,
                    error_message,
                    parent,
                    redirect_parent,
                    request_body_id,
                    response_body_id,
                ) = row.map_err(|error| storage_error(error.to_string()))?;
                let body = |body_id: Option<i64>| -> DomainResult<Option<Vec<u8>>> {
                    let Some(body_id) = body_id else {
                        return Ok(None);
                    };
                    let (codec, content): (String, Vec<u8>) = conn
                        .query_row(
                            "SELECT codec, content FROM bodies WHERE id=?1",
                            params![body_id],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .map_err(|error| storage_error(error.to_string()))?;
                    crate::storage::bodies::decode_body(&codec, &content).map(Some)
                };
                exchanges.push(ArchivedExchange {
                    original_exchange_id: id,
                    started_at,
                    display_title,
                    annotation: load_archived_annotation(conn, project_id, ExchangeId(id))?,
                    findings: load_archived_findings(conn, project_id, ExchangeId(id))?,
                    applied_request_rules: load_applied_request_rules(
                        conn,
                        project_id,
                        ExchangeId(id),
                    )?,
                    exchange: NewExchange {
                        project_id,
                        source: parse_source(&source),
                        protocol,
                        method,
                        scheme,
                        authority,
                        host,
                        port: port as u16,
                        path,
                        query,
                        status_code: status.map(|value| value as u16),
                        mime,
                        completion: parse_completion(&completion),
                        capture_quality: parse_capture_quality(&quality),
                        header_representation: parse_header_rep(&header_rep),
                        body_representation: parse_body_rep(&body_rep),
                        cache_provenance: parse_cache_prov(&cache),
                        transport_provenance: transport.as_deref().map(parse_transport_prov),
                        transport_profile,
                        request_headers: load_headers(conn, project_id, ExchangeId(id), "request")?,
                        response_headers: load_headers(conn, project_id, ExchangeId(id), "response")?,
                        request_body: body(request_body_id)?,
                        response_body: body(response_body_id)?,
                        duration_ms,
                        lineage: ExchangeLineage {
                            parent_exchange_id: parent.map(ExchangeId),
                            redirect_parent_id: redirect_parent.map(ExchangeId),
                            ..Default::default()
                        },
                        page_title,
                        error_message,
                    },
                });
            }
            Ok(ProjectArchive {
                format: ARCHIVE_FORMAT.into(),
                version: ARCHIVE_VERSION,
                exported_at: now_rfc3339(),
                project: ArchivedProject {
                    name: project.name,
                    target_url: project.target_url,
                    scope: project.scope,
                    limits: project.limits,
                    default_browser_profile: project.default_browser_profile,
                    noise_policy: project.noise_policy,
                },
                request_rules,
                exchanges,
            })
        })
        .await
    }

    pub async fn import_project(&self, mut archive: ProjectArchive) -> DomainResult<Project> {
        if archive.format != ARCHIVE_FORMAT || archive.version != ARCHIVE_VERSION {
            return Err(DomainError::invalid(
                "unsupported HuntProxy project archive",
            ));
        }
        crate::policy::TargetRef::from_url(&archive.project.target_url)?;
        let project = self
            .create_project(CreateProjectRequest {
                name: archive.project.name.clone(),
                target_url: archive.project.target_url.clone(),
                advanced: Some(archive.project.scope.clone()),
            })
            .await?;
        self.update_project_scope(
            project.id,
            archive.project.scope.clone(),
            Some(archive.project.limits.clone()),
        )
        .await?;
        let mut rule_ids = HashMap::new();
        for rule in archive.request_rules {
            let old_id = rule.id;
            let created = self
                .create_request_rule(
                    project.id,
                    crate::request_rules::RequestRuleInput {
                        name: rule.name,
                        enabled: rule.enabled,
                        position: rule.position,
                        host_pattern: rule.host_pattern,
                        target: rule.target,
                        operation: rule.operation,
                        header_name: rule.header_name,
                        match_kind: rule.match_kind,
                        pattern: rule.pattern,
                        replacement: rule.replacement,
                        replace_all: rule.replace_all,
                    },
                )
                .await?;
            rule_ids.insert(old_id, created.id);
        }
        archive
            .exchanges
            .sort_by_key(|item| item.original_exchange_id);
        let mut ids = HashMap::new();
        for item in archive.exchanges {
            let old_parent = item
                .exchange
                .lineage
                .parent_exchange_id
                .map(ExchangeId::get);
            let old_redirect = item
                .exchange
                .lineage
                .redirect_parent_id
                .map(ExchangeId::get);
            let mut exchange = item.exchange;
            exchange.project_id = project.id;
            exchange.lineage.parent_exchange_id = old_parent
                .and_then(|id| ids.get(&id).copied())
                .map(ExchangeId);
            exchange.lineage.redirect_parent_id = old_redirect
                .and_then(|id| ids.get(&id).copied())
                .map(ExchangeId);
            exchange.lineage.reply_tab_id = None;
            exchange.lineage.fuzz_job_id = None;
            exchange.lineage.fuzz_case_id = None;
            exchange.lineage.browser_session_id = None;
            exchange.lineage.browser_action_id = None;
            exchange.lineage.capture_session_id = None;
            let new_id = self.insert_exchange(exchange).await?;
            self.record_exchange_request_rules(
                project.id,
                new_id,
                item.applied_request_rules
                    .into_iter()
                    .map(|applied| crate::request_rules::AppliedRequestRule {
                        id: rule_ids.get(&applied.id).copied().unwrap_or(applied.id),
                        name: applied.name,
                    })
                    .collect(),
            )
            .await?;
            ids.insert(item.original_exchange_id, new_id.get());
            let timestamp = item.started_at.clone();
            let title = item.display_title.clone();
            self.with_conn(move |conn| {
                conn.execute(
                    "UPDATE exchanges SET started_at=?1, display_title=?2 WHERE project_id=?3 AND exchange_id=?4",
                    params![timestamp, title, project.id.get(), new_id.get()],
                )
                .map_err(|error| storage_error(error.to_string()))?;
                Ok(())
            })
            .await?;
            if let Some(annotation) = item.annotation {
                self.upsert_annotation(
                    project.id,
                    new_id,
                    AnnotationUpdate {
                        display_title: annotation.display_title,
                        note: annotation.note,
                        labels: annotation.labels,
                        expected_revision: Some(0),
                    },
                )
                .await?;
            }
            for finding in item.findings {
                self.create_finding(project.id, new_id, finding.title, finding.description)
                    .await?;
            }
        }
        self.get_project(project.id).await
    }
}

pub(crate) fn reconcile_project_usage_conn(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
) -> DomainResult<ReconcileUsageResult> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE id=?1)",
            params![project_id.get()],
            |row| row.get(0),
        )
        .map_err(|error| storage_error(error.to_string()))?;
    if !exists {
        return Err(DomainError::not_found(format!(
            "project {}",
            project_id.get()
        )));
    }
    let previous: i64 = conn
        .query_row(
            "SELECT accounted_bytes FROM project_usage WHERE project_id=?1",
            params![project_id.get()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| storage_error(error.to_string()))?
        .unwrap_or(0);
    let (count, request, response, exchange_accounted): (i64, i64, i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(request_length),0),
                    COALESCE(SUM(response_length),0),
                    COALESCE(SUM(
                        ?2 + COALESCE(request_length,0) + COALESCE(response_length,0)
                        + length(CAST(protocol AS BLOB)) + length(CAST(method AS BLOB))
                        + length(CAST(scheme AS BLOB)) + length(CAST(authority AS BLOB))
                        + length(CAST(host AS BLOB)) + length(CAST(path AS BLOB))
                        + COALESCE(length(CAST(query AS BLOB)),0)
                        + COALESCE(length(CAST(mime AS BLOB)),0)
                        + COALESCE(length(CAST(transport_profile AS BLOB)),0)
                        + COALESCE(length(CAST(page_title AS BLOB)),0)
                        + COALESCE(length(CAST(error_message AS BLOB)),0)
                    ),0)
             FROM exchanges WHERE project_id=?1",
            params![
                project_id.get(),
                crate::storage::exchanges::EXCHANGE_ACCOUNTING_OVERHEAD as i64
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|error| storage_error(error.to_string()))?;
    let (header_bytes, header_accounted): (i64, i64) = conn
        .query_row(
            "SELECT COALESCE(SUM(length(CAST(name AS BLOB)) + length(value)),0),
                    COALESCE(SUM(?2 + length(CAST(name AS BLOB)) + length(value)),0)
             FROM message_headers WHERE project_id=?1",
            params![
                project_id.get(),
                crate::storage::exchanges::HEADER_ACCOUNTING_OVERHEAD as i64
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| storage_error(error.to_string()))?;
    let accounted = exchange_accounted.saturating_add(header_accounted).max(0);
    conn.execute(
        "INSERT INTO project_usage (
            project_id, exchange_count, request_body_bytes, response_body_bytes,
            header_bytes, accounted_bytes, updated_at
         ) VALUES (?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(project_id) DO UPDATE SET
            exchange_count=excluded.exchange_count,
            request_body_bytes=excluded.request_body_bytes,
            response_body_bytes=excluded.response_body_bytes,
            header_bytes=excluded.header_bytes,
            accounted_bytes=excluded.accounted_bytes,
            updated_at=excluded.updated_at",
        params![
            project_id.get(),
            count.max(0),
            request.max(0),
            response.max(0),
            header_bytes.max(0),
            accounted,
            now_rfc3339(),
        ],
    )
    .map_err(|error| storage_error(error.to_string()))?;
    Ok(ReconcileUsageResult {
        project_id,
        previous_accounted_bytes: previous.max(0) as u64,
        accounted_bytes: accounted as u64,
        changed: previous != accounted,
    })
}

fn load_archived_annotation(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
    exchange_id: ExchangeId,
) -> DomainResult<Option<ArchivedAnnotation>> {
    let row = conn
        .query_row(
            "SELECT display_title, note FROM annotations WHERE project_id=?1 AND exchange_id=?2",
            params![project_id.get(), exchange_id.get()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .optional()
        .map_err(|error| storage_error(error.to_string()))?;
    let Some((display_title, note)) = row else {
        return Ok(None);
    };
    let labels = crate::storage::annotations::load_labels_conn(conn, project_id, exchange_id)?;
    Ok(Some(ArchivedAnnotation {
        display_title,
        note,
        labels,
    }))
}

fn load_archived_findings(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
    exchange_id: ExchangeId,
) -> DomainResult<Vec<ArchivedFinding>> {
    let mut statement = conn
        .prepare(
            "SELECT title, description FROM findings WHERE project_id=?1 AND exchange_id=?2 ORDER BY id",
        )
        .map_err(|error| storage_error(error.to_string()))?;
    let rows = statement
        .query_map(params![project_id.get(), exchange_id.get()], |row| {
            Ok(ArchivedFinding {
                title: row.get(0)?,
                description: row.get(1)?,
            })
        })
        .map_err(|error| storage_error(error.to_string()))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| storage_error(error.to_string()))
}

fn load_applied_request_rules(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
    exchange_id: ExchangeId,
) -> DomainResult<Vec<crate::request_rules::AppliedRequestRule>> {
    let mut statement = conn
        .prepare(
            "SELECT rule_id, rule_name FROM exchange_request_rules
             WHERE project_id=?1 AND exchange_id=?2 ORDER BY rule_id",
        )
        .map_err(|error| storage_error(error.to_string()))?;
    let rows = statement
        .query_map(params![project_id.get(), exchange_id.get()], |row| {
            Ok(crate::request_rules::AppliedRequestRule {
                id: row.get(0)?,
                name: row.get(1)?,
            })
        })
        .map_err(|error| storage_error(error.to_string()))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| storage_error(error.to_string()))
}

fn same_file_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn storage_error(message: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::StorageError, message.into())
}

pub(crate) fn missing_usage_or_project(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
) -> DomainError {
    let exists = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE id=?1)",
            params![project_id.get()],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false);
    if exists {
        DomainError::new(
            ErrorCode::StorageError,
            "project usage counter missing; run `HuntProxy project reconcile`",
        )
    } else {
        DomainError::not_found(format!("project {}", project_id.get()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project_request(name: &str) -> CreateProjectRequest {
        CreateProjectRequest {
            name: name.into(),
            target_url: "https://example.test/".into(),
            advanced: None,
        }
    }

    fn exchange(project_id: ProjectId) -> NewExchange {
        NewExchange {
            project_id,
            source: ExchangeSource::Reply,
            protocol: "HTTP/1.1".into(),
            method: "GET".into(),
            scheme: "https".into(),
            authority: "example.test".into(),
            host: "example.test".into(),
            port: 443,
            path: "/one".into(),
            query: None,
            status_code: Some(200),
            mime: Some("text/plain".into()),
            completion: CompletionState::Complete,
            capture_quality: CaptureQuality::Semantic,
            header_representation: HeaderRepresentation::Semantic,
            body_representation: BodyRepresentation::SemanticEncoded,
            cache_provenance: CacheProvenance::None,
            transport_provenance: Some(TransportProvenance::SemanticProxy),
            transport_profile: None,
            request_headers: vec![HeaderEntry {
                name: "Cookie".into(),
                value: b"sid=secret".to_vec(),
                ordinal: 0,
            }],
            response_headers: vec![],
            request_body: None,
            response_body: Some(b"hello".to_vec()),
            duration_ms: Some(4),
            lineage: ExchangeLineage::default(),
            page_title: None,
            error_message: None,
        }
    }

    #[tokio::test]
    async fn lifecycle_round_trip_and_clear() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(project_request("Original"))
            .await
            .unwrap();
        assert_eq!(project.target_url, "https://example.test/");
        let id = db.insert_exchange(exchange(project.id)).await.unwrap();
        db.upsert_annotation(
            project.id,
            id,
            AnnotationUpdate {
                display_title: Some("Evidence".into()),
                note: Some("note".into()),
                labels: vec!["api".into()],
                expected_revision: Some(0),
            },
        )
        .await
        .unwrap();
        db.create_finding(project.id, id, "Finding".into(), "Description".into())
            .await
            .unwrap();
        assert_eq!(
            db.project_usage(project.id).await.unwrap().exchange_count,
            1
        );
        let original_accounted = db
            .project_usage(project.id)
            .await
            .unwrap()
            .approximate_total_bytes;
        db.with_conn(move |conn| {
            conn.execute(
                "UPDATE project_usage SET accounted_bytes=1 WHERE project_id=?1",
                params![project.id.get()],
            )
            .map_err(|error| storage_error(error.to_string()))?;
            Ok(())
        })
        .await
        .unwrap();
        let repaired = db.reconcile_project_usage(project.id).await.unwrap();
        assert!(repaired.changed);
        assert_eq!(repaired.previous_accounted_bytes, 1);
        assert_eq!(repaired.accounted_bytes, original_accounted);
        db.with_conn(move |conn| {
            conn.execute(
                "DELETE FROM project_usage WHERE project_id=?1",
                params![project.id.get()],
            )
            .map_err(|error| storage_error(error.to_string()))?;
            Ok(())
        })
        .await
        .unwrap();
        let missing = db.project_usage(project.id).await.unwrap_err();
        assert_eq!(missing.code(), ErrorCode::StorageError);
        assert!(missing.to_string().contains("project reconcile"));
        db.reconcile_project_usage(project.id).await.unwrap();
        let archive = db.export_project(project.id).await.unwrap();
        let imported = db.import_project(archive).await.unwrap();
        assert_eq!(
            db.project_usage(imported.id).await.unwrap().exchange_count,
            1
        );
        assert_eq!(db.list_findings(imported.id).await.unwrap().len(), 1);
        let headers = db
            .load_raw_headers(imported.id, ExchangeId(1), MessageSide::Request)
            .await
            .unwrap();
        assert!(headers.iter().any(|header| header.value == b"sid=secret"));
        let cleared = db
            .clear_history_before(imported.id, "9999-01-01T00:00:00Z".into())
            .await
            .unwrap();
        assert_eq!(cleared.deleted_exchanges, 1);
        db.delete_project(project.id).await.unwrap();
        assert!(db.get_project(project.id).await.is_err());
    }

    #[tokio::test]
    async fn history_cutoff_compares_rfc3339_offsets_chronologically() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db.create_project(project_request("Offsets")).await.unwrap();
        let older = db.insert_exchange(exchange(project.id)).await.unwrap();
        let newer = db.insert_exchange(exchange(project.id)).await.unwrap();
        db.with_conn(move |conn| {
            conn.execute(
                "UPDATE exchanges SET started_at=?1 WHERE exchange_id=?2",
                params!["2026-01-01T00:30:00+01:00", older.get()],
            )
            .map_err(|error| storage_error(error.to_string()))?;
            conn.execute(
                "UPDATE exchanges SET started_at=?1 WHERE exchange_id=?2",
                params!["2025-12-31T23:30:00-01:00", newer.get()],
            )
            .map_err(|error| storage_error(error.to_string()))?;
            Ok(())
        })
        .await
        .unwrap();

        let result = db
            .clear_history_before(project.id, "2026-01-01T00:00:00Z".into())
            .await
            .unwrap();

        assert_eq!(result.deleted_exchanges, 1);
        assert_eq!(
            db.project_usage(project.id).await.unwrap().exchange_count,
            1
        );
    }
}
