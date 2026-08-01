//! Bounded access to the saved exchanges used by target word extraction.

use crate::domain::{DomainError, DomainResult, ErrorCode, ExchangeId, MessageSide, ProjectId};
use crate::storage::Db;
use rusqlite::params;
use rusqlite::types::Value;
use std::io::Read;

#[derive(Debug, Clone)]
pub struct WordSourceExchange {
    pub exchange_id: ExchangeId,
    pub host: String,
    pub path: String,
    pub query: Option<String>,
    pub mime: Option<String>,
    pub response_content_encoding: Option<String>,
}

impl Db {
    /// Return a bounded, stable list of exchanges for a host and its
    /// subdomains. A missing domain means every saved exchange in the project.
    pub async fn list_word_source_exchanges(
        &self,
        project_id: ProjectId,
        domain: Option<String>,
        limit: usize,
    ) -> DomainResult<(Vec<WordSourceExchange>, bool)> {
        let limit = limit.clamp(1, 5_000);
        self.with_conn(move |conn| {
            let mut statement = conn
                .prepare(
                    "SELECT e.exchange_id, e.host, e.path, e.query, e.mime,
                            (SELECT group_concat(CAST(value AS TEXT), ', ')
                               FROM message_headers h
                              WHERE h.project_id=e.project_id
                                AND h.exchange_id=e.exchange_id
                                AND h.side='response'
                                AND lower(h.name)='content-encoding')
                       FROM exchanges e
                      WHERE e.project_id=?1
                        AND (
                            ?2 IS NULL
                            OR lower(e.host)=?2
                            OR substr(lower(e.host), -(length(?2) + 1))='.' || ?2
                        )
                      ORDER BY e.exchange_id ASC
                      LIMIT ?3",
                )
                .map_err(storage_error)?;
            let rows = statement
                .query_map(
                    params![project_id.get(), domain, (limit + 1) as i64],
                    |row| {
                        Ok(WordSourceExchange {
                            exchange_id: ExchangeId(row.get(0)?),
                            host: row.get(1)?,
                            path: row.get(2)?,
                            query: row.get(3)?,
                            mime: row.get(4)?,
                            response_content_encoding: row.get(5)?,
                        })
                    },
                )
                .map_err(storage_error)?;
            let mut exchanges = rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)?;
            let truncated = exchanges.len() > limit;
            if truncated {
                exchanges.truncate(limit);
            }
            Ok((exchanges, truncated))
        })
        .await
    }

    /// Load metadata for a bounded set of related resources which may live on
    /// a different host than the page that included them.
    pub async fn list_word_source_exchanges_by_ids(
        &self,
        project_id: ProjectId,
        exchange_ids: Vec<ExchangeId>,
    ) -> DomainResult<Vec<WordSourceExchange>> {
        let mut exchange_ids = exchange_ids;
        exchange_ids.sort_unstable_by_key(|id| id.get());
        exchange_ids.dedup();
        exchange_ids.truncate(1_000);
        if exchange_ids.is_empty() {
            return Ok(Vec::new());
        }
        self.with_conn(move |conn| {
            let placeholders = (0..exchange_ids.len())
                .map(|index| format!("?{}", index + 2))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT e.exchange_id, e.host, e.path, e.query, e.mime,
                        (SELECT group_concat(CAST(value AS TEXT), ', ')
                           FROM message_headers h
                          WHERE h.project_id=e.project_id
                            AND h.exchange_id=e.exchange_id
                            AND h.side='response'
                            AND lower(h.name)='content-encoding')
                   FROM exchanges e
                  WHERE e.project_id=?1 AND e.exchange_id IN ({placeholders})
                  ORDER BY e.exchange_id ASC"
            );
            let mut values = Vec::with_capacity(exchange_ids.len() + 1);
            values.push(Value::Integer(project_id.get()));
            values.extend(exchange_ids.into_iter().map(|id| Value::Integer(id.get())));
            let mut statement = conn.prepare(&sql).map_err(storage_error)?;
            let rows = statement
                .query_map(rusqlite::params_from_iter(values), |row| {
                    Ok(WordSourceExchange {
                        exchange_id: ExchangeId(row.get(0)?),
                        host: row.get(1)?,
                        path: row.get(2)?,
                        query: row.get(3)?,
                        mime: row.get(4)?,
                        response_content_encoding: row.get(5)?,
                    })
                })
                .map_err(storage_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)
        })
        .await
    }

    /// Read at most `max_bytes` of a stored body. SQLite's incremental BLOB
    /// reader and a streaming zstd decoder keep large captures out of memory.
    pub async fn load_word_source_body_bounded(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        side: MessageSide,
        max_bytes: usize,
    ) -> DomainResult<Option<(Vec<u8>, bool)>> {
        let body_column = match side {
            MessageSide::Request => "request_body_id",
            MessageSide::Response => "response_body_id",
        };
        let sql =
            format!("SELECT {body_column} FROM exchanges WHERE project_id=?1 AND exchange_id=?2");
        self.with_conn(move |conn| {
            let body_id: Option<i64> = conn
                .query_row(&sql, params![project_id.get(), exchange_id.get()], |row| {
                    row.get(0)
                })
                .map_err(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => DomainError::not_found("exchange"),
                    other => storage_error(other),
                })?;
            let Some(body_id) = body_id else {
                return Ok(None);
            };
            let codec: String = conn
                .query_row(
                    "SELECT codec FROM bodies WHERE id=?1",
                    params![body_id],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            let blob = conn
                .blob_open(rusqlite::MAIN_DB, "bodies", "content", body_id, true)
                .map_err(storage_error)?;
            let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024) + 1);
            match codec.as_str() {
                "raw" => blob
                    .take((max_bytes + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(storage_io_error)?,
                "zstd" => zstd::stream::read::Decoder::new(blob)
                    .map_err(storage_io_error)?
                    .take((max_bytes + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(storage_io_error)?,
                other => {
                    return Err(DomainError::new(
                        ErrorCode::StorageError,
                        format!("unknown body codec {other}"),
                    ));
                }
            };
            let truncated = bytes.len() > max_bytes;
            if truncated {
                bytes.truncate(max_bytes);
            }
            Ok(Some((bytes, truncated)))
        })
        .await
    }
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

fn storage_io_error(error: std::io::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}
