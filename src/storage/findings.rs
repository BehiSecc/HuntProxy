//! Project findings linked to captured exchanges.

use crate::domain::*;
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::Db;
use rusqlite::params;

const MAX_FINDING_TITLE: usize = 256;
const MAX_FINDING_DESCRIPTION: usize = 64 * 1024;

impl Db {
    pub async fn create_findings_atomic(
        &self,
        project_id: ProjectId,
        findings: Vec<(ExchangeId, String, String)>,
    ) -> DomainResult<Vec<Finding>> {
        let findings = findings
            .into_iter()
            .map(|(exchange_id, title, description)| {
                let title = title.trim().to_string();
                let description = description.trim().to_string();
                validate_finding_text(&title, &description)?;
                Ok((exchange_id, title, description))
            })
            .collect::<DomainResult<Vec<_>>>()?;
        if findings.is_empty() {
            return Ok(Vec::new());
        }
        let timestamp = now_rfc3339();
        self.with_conn(move |conn| {
            let transaction = crate::storage::db::write_transaction(conn).map_err(storage_error)?;
            let mut created = Vec::with_capacity(findings.len());
            for (exchange_id, title, description) in findings {
                let exchange_exists: bool = transaction
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM exchanges WHERE project_id=?1 AND exchange_id=?2)",
                        params![project_id.get(), exchange_id.get()],
                        |row| row.get(0),
                    )
                    .map_err(storage_error)?;
                if !exchange_exists {
                    return Err(DomainError::not_found("exchange"));
                }
                transaction
                    .execute(
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
                created.push(Finding {
                    id: FindingId(transaction.last_insert_rowid()),
                    project_id,
                    exchange_id,
                    title,
                    description,
                    created_at: parse_time(&timestamp),
                    updated_at: parse_time(&timestamp),
                });
            }
            transaction.commit().map_err(storage_error)?;
            Ok(created)
        })
        .await
    }

    pub async fn create_finding(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        title: String,
        description: String,
    ) -> DomainResult<Finding> {
        let title = title.trim().to_string();
        let description = description.trim().to_string();
        validate_finding_text(&title, &description)?;
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

fn validate_finding_text(title: &str, description: &str) -> DomainResult<()> {
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
    Ok(())
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::CreateProjectRequest;
    use crate::storage::NewExchange;

    #[tokio::test]
    async fn atomic_batch_rolls_back_when_any_evidence_exchange_is_missing() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "atomic findings".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let valid_exchange = db
            .insert_exchange(NewExchange {
                project_id: project.id,
                source: ExchangeSource::Reply,
                protocol: "HTTP/1.1".into(),
                method: "GET".into(),
                scheme: "https".into(),
                authority: "example.test".into(),
                host: "example.test".into(),
                port: 443,
                path: "/".into(),
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
                request_headers: Vec::new(),
                response_headers: Vec::new(),
                request_body: None,
                response_body: Some(b"ok".to_vec()),
                duration_ms: Some(1),
                lineage: ExchangeLineage::default(),
                page_title: None,
                error_message: None,
            })
            .await
            .unwrap();
        let result = db
            .create_findings_atomic(
                project.id,
                vec![
                    (valid_exchange, "first".into(), "first description".into()),
                    (
                        ExchangeId(i64::MAX),
                        "second".into(),
                        "second description".into(),
                    ),
                ],
            )
            .await;
        assert_eq!(result.unwrap_err().code(), ErrorCode::NotFound);
        assert!(db.list_findings(project.id).await.unwrap().is_empty());
    }
}
