//! Exchange annotations and project-scoped labels.

use crate::domain::*;
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::Db;
use rusqlite::{params, OptionalExtension};
use std::collections::BTreeSet;

const MAX_LABELS_PER_EXCHANGE: usize = 64;
const MAX_LABEL_LEN: usize = 128;

impl Db {
    pub async fn get_annotation(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
    ) -> DomainResult<Option<Annotation>> {
        self.with_conn(move |conn| load_annotation_conn(conn, project_id, exchange_id))
            .await
    }

    /// Create or fully replace an exchange annotation.
    ///
    /// `expected_revision=0` means the caller expects no existing annotation.
    pub async fn upsert_annotation(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        update: AnnotationUpdate,
    ) -> DomainResult<Annotation> {
        let labels = normalize_labels(update.labels)?;
        let title = normalize_optional_text(update.display_title);
        let note = normalize_optional_text(update.note);
        let expected_revision = update.expected_revision;
        let ts = now_rfc3339();

        self.with_conn(move |conn| {
            let tx = conn.unchecked_transaction().map_err(storage_error)?;
            let exchange_exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM exchanges WHERE project_id=?1 AND exchange_id=?2)",
                    params![project_id.get(), exchange_id.get()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if !exchange_exists {
                return Err(DomainError::not_found("exchange"));
            }

            let current: Option<(i64, i64, String)> = tx
                .query_row(
                    "SELECT id, revision, created_at FROM annotations WHERE project_id=?1 AND exchange_id=?2",
                    params![project_id.get(), exchange_id.get()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(storage_error)?;

            let (annotation_id, revision, created_at) = match current {
                Some((id, current_revision, created_at)) => {
                    if let Some(expected) = expected_revision {
                        if expected != current_revision {
                            return Err(DomainError::new(
                                ErrorCode::RevisionConflict,
                                format!(
                                    "annotation revision conflict: expected {expected}, have {current_revision}"
                                ),
                            ));
                        }
                    }
                    let next_revision = current_revision + 1;
                    tx.execute(
                        "UPDATE annotations SET display_title=?1, note=?2, updated_at=?3, revision=?4
                         WHERE id=?5 AND project_id=?6 AND exchange_id=?7",
                        params![
                            title,
                            note,
                            ts,
                            next_revision,
                            id,
                            project_id.get(),
                            exchange_id.get()
                        ],
                    )
                    .map_err(storage_error)?;
                    (id, next_revision, created_at)
                }
                None => {
                    if let Some(expected) = expected_revision {
                        if expected != 0 {
                            return Err(DomainError::new(
                                ErrorCode::RevisionConflict,
                                format!(
                                    "annotation revision conflict: expected {expected}, annotation does not exist"
                                ),
                            ));
                        }
                    }
                    tx.execute(
                        "INSERT INTO annotations
                         (project_id, exchange_id, display_title, note, created_at, updated_at, revision)
                         VALUES (?1,?2,?3,?4,?5,?6,1)",
                        params![project_id.get(), exchange_id.get(), title, note, ts, ts],
                    )
                    .map_err(storage_error)?;
                    (tx.last_insert_rowid(), 1, ts.clone())
                }
            };

            tx.execute(
                "UPDATE exchanges SET display_title=?1 WHERE project_id=?2 AND exchange_id=?3",
                params![title, project_id.get(), exchange_id.get()],
            )
            .map_err(storage_error)?;
            tx.execute(
                "DELETE FROM exchange_labels WHERE project_id=?1 AND exchange_id=?2",
                params![project_id.get(), exchange_id.get()],
            )
            .map_err(storage_error)?;

            for label in &labels {
                tx.execute(
                    "INSERT INTO labels (project_id, name) VALUES (?1,?2)
                     ON CONFLICT(project_id, name) DO NOTHING",
                    params![project_id.get(), label],
                )
                .map_err(storage_error)?;
                let label_id: i64 = tx
                    .query_row(
                        "SELECT id FROM labels WHERE project_id=?1 AND name=?2",
                        params![project_id.get(), label],
                        |row| row.get(0),
                    )
                    .map_err(storage_error)?;
                tx.execute(
                    "INSERT INTO exchange_labels (project_id, exchange_id, label_id)
                     VALUES (?1,?2,?3)",
                    params![project_id.get(), exchange_id.get(), label_id],
                )
                .map_err(storage_error)?;
            }

            tx.commit().map_err(storage_error)?;
            Ok(Annotation {
                id: AnnotationId(annotation_id),
                project_id,
                exchange_id,
                display_title: title,
                note,
                labels,
                created_at: parse_time(&created_at),
                updated_at: parse_time(&ts),
                revision,
            })
        })
        .await
    }
}

pub(crate) fn load_labels_conn(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
    exchange_id: ExchangeId,
) -> DomainResult<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT l.name FROM exchange_labels el
             JOIN labels l ON l.id=el.label_id AND l.project_id=el.project_id
             WHERE el.project_id=?1 AND el.exchange_id=?2
             ORDER BY l.name COLLATE NOCASE, l.id",
        )
        .map_err(storage_error)?;
    let rows = stmt
        .query_map(params![project_id.get(), exchange_id.get()], |row| {
            row.get(0)
        })
        .map_err(storage_error)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(storage_error)
}

fn load_annotation_conn(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
    exchange_id: ExchangeId,
) -> DomainResult<Option<Annotation>> {
    type AnnotationRow = (i64, Option<String>, Option<String>, String, String, i64);
    let row: Option<AnnotationRow> = conn
        .query_row(
            "SELECT id, display_title, note, created_at, updated_at, revision
             FROM annotations WHERE project_id=?1 AND exchange_id=?2",
            params![project_id.get(), exchange_id.get()],
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
        .optional()
        .map_err(storage_error)?;
    let Some((id, display_title, note, created_at, updated_at, revision)) = row else {
        return Ok(None);
    };
    Ok(Some(Annotation {
        id: AnnotationId(id),
        project_id,
        exchange_id,
        display_title,
        note,
        labels: load_labels_conn(conn, project_id, exchange_id)?,
        created_at: parse_time(&created_at),
        updated_at: parse_time(&updated_at),
        revision,
    }))
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn normalize_labels(labels: Vec<String>) -> DomainResult<Vec<String>> {
    if labels.len() > MAX_LABELS_PER_EXCHANGE {
        return Err(DomainError::invalid(format!(
            "at most {MAX_LABELS_PER_EXCHANGE} labels are allowed"
        )));
    }
    let mut normalized = BTreeSet::new();
    for label in labels {
        let label = label.trim();
        if label.is_empty() {
            continue;
        }
        if label.chars().count() > MAX_LABEL_LEN {
            return Err(DomainError::invalid(format!(
                "label exceeds {MAX_LABEL_LEN} characters"
            )));
        }
        normalized.insert(label.to_string());
    }
    Ok(normalized.into_iter().collect())
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::NewExchange;

    #[tokio::test]
    async fn annotation_round_trip_and_revision_conflict() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "annotations".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let exchange_id = db.insert_exchange(exchange(project.id)).await.unwrap();

        let annotation = db
            .upsert_annotation(
                project.id,
                exchange_id,
                AnnotationUpdate {
                    display_title: Some(" Login request ".into()),
                    note: Some(" csrf candidate ".into()),
                    labels: vec!["auth".into(), "csrf".into(), "auth".into()],
                    expected_revision: Some(0),
                },
            )
            .await
            .unwrap();
        assert_eq!(annotation.revision, 1);
        assert_eq!(annotation.display_title.as_deref(), Some("Login request"));
        assert_eq!(annotation.note.as_deref(), Some("csrf candidate"));
        assert_eq!(annotation.labels, vec!["auth", "csrf"]);

        let detail = db
            .get_exchange_detail(
                project.id,
                exchange_id,
                crate::policy::PresentationOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            detail.summary.display_title.as_deref(),
            Some("Login request")
        );
        assert_eq!(detail.summary.labels, vec!["auth", "csrf"]);

        let error = db
            .upsert_annotation(
                project.id,
                exchange_id,
                AnnotationUpdate {
                    display_title: None,
                    note: None,
                    labels: vec![],
                    expected_revision: Some(0),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::RevisionConflict);
        assert_eq!(
            db.get_annotation(project.id, exchange_id)
                .await
                .unwrap()
                .unwrap()
                .revision,
            1
        );
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
            path: "/login".into(),
            query: None,
            status_code: Some(200),
            mime: Some("text/html".into()),
            completion: CompletionState::Complete,
            capture_quality: CaptureQuality::Semantic,
            header_representation: HeaderRepresentation::Semantic,
            body_representation: BodyRepresentation::SemanticEncoded,
            cache_provenance: CacheProvenance::None,
            transport_provenance: Some(TransportProvenance::GenericUnprofiled),
            transport_profile: Some("test".into()),
            request_headers: vec![],
            response_headers: vec![],
            request_body: None,
            response_body: Some(b"ok".to_vec()),
            duration_ms: Some(5),
            lineage: ExchangeLineage::default(),
            page_title: None,
            error_message: None,
        }
    }
}
