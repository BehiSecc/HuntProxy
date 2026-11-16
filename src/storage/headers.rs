//! Message headers, with each distinct name and value stored once.
//!
//! `message_header_rows` keeps a message's headers as name and value ids. The
//! `message_headers` view (migration 018) joins them back for SQL readers and
//! copies; the capture path writes the tables directly.

use crate::domain::{DomainError, DomainResult, ErrorCode, HeaderEntry};
use rusqlite::{params, Connection, OptionalExtension};

/// The stored code of a message side.
pub(crate) fn side_code(side: &str) -> DomainResult<i64> {
    match side {
        "request" => Ok(0),
        "response" => Ok(1),
        other => Err(DomainError::new(
            ErrorCode::StorageError,
            format!("unknown header side {other}"),
        )),
    }
}

pub(crate) fn insert_headers_conn(
    conn: &Connection,
    project_id: i64,
    exchange_id: i64,
    side: &str,
    headers: &[HeaderEntry],
) -> DomainResult<()> {
    if headers.is_empty() {
        return Ok(());
    }
    let side = side_code(side)?;
    let mut insert = conn
        .prepare_cached(
            "INSERT INTO message_header_rows (project_id, exchange_id, side, ordinal, name_id, value_id)
             VALUES (?1,?2,?3,?4,?5,?6)",
        )
        .map_err(storage_error)?;
    for header in headers {
        let name_id = name_id(conn, &header.name).map_err(storage_error)?;
        let value_id = value_id(conn, &header.value).map_err(storage_error)?;
        insert
            .execute(params![
                project_id,
                exchange_id,
                side,
                header.ordinal as i64,
                name_id,
                value_id
            ])
            .map_err(storage_error)?;
    }
    Ok(())
}

fn name_id(conn: &Connection, name: &str) -> rusqlite::Result<i64> {
    let found = conn
        .prepare_cached("SELECT id FROM header_names WHERE name=?1")?
        .query_row(params![name], |row| row.get(0))
        .optional()?;
    if let Some(id) = found {
        return Ok(id);
    }
    conn.prepare_cached("INSERT INTO header_names (name) VALUES (?1)")?
        .execute(params![name])?;
    Ok(conn.last_insert_rowid())
}

fn value_id(conn: &Connection, value: &[u8]) -> rusqlite::Result<i64> {
    let found = conn
        .prepare_cached("SELECT id FROM header_values WHERE value=?1")?
        .query_row(params![value], |row| row.get(0))
        .optional()?;
    if let Some(id) = found {
        return Ok(id);
    }
    conn.prepare_cached("INSERT INTO header_values (value) VALUES (?1)")?
        .execute(params![value])?;
    Ok(conn.last_insert_rowid())
}

pub(crate) fn load_headers_conn(
    conn: &Connection,
    project_id: i64,
    exchange_id: i64,
    side: &str,
) -> DomainResult<Vec<HeaderEntry>> {
    let side = side_code(side)?;
    let mut statement = conn
        .prepare_cached(
            "SELECT r.ordinal, n.name, v.value
               FROM message_header_rows r
               JOIN header_names n ON n.id = r.name_id
               JOIN header_values v ON v.id = r.value_id
              WHERE r.project_id=?1 AND r.exchange_id=?2 AND r.side=?3
              ORDER BY r.ordinal",
        )
        .map_err(storage_error)?;
    let rows = statement
        .query_map(params![project_id, exchange_id, side], |row| {
            Ok(HeaderEntry {
                ordinal: row.get::<_, i64>(0)? as u32,
                name: row.get(1)?,
                value: row.get(2)?,
            })
        })
        .map_err(storage_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)
}

/// Removes names and values that no header row uses any more, so a deleted
/// exchange's cookies and tokens do not stay behind. One pass over the rows
/// marks the ids in use; there is no index from rows back to ids.
pub(crate) fn delete_unused_header_values(conn: &Connection) -> rusqlite::Result<()> {
    let max_id = |table: &str| -> rusqlite::Result<i64> {
        conn.query_row(
            &format!("SELECT COALESCE(MAX(id), 0) FROM {table}"),
            [],
            |row| row.get(0),
        )
    };
    let mut names = IdSet::new(max_id("header_names")?);
    let mut values = IdSet::new(max_id("header_values")?);
    {
        let mut statement = conn.prepare("SELECT name_id, value_id FROM message_header_rows")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            names.insert(row.get(0)?);
            values.insert(row.get(1)?);
        }
    }
    for (table, used) in [("header_names", &names), ("header_values", &values)] {
        let unused = {
            let mut statement = conn.prepare(&format!("SELECT id FROM {table}"))?;
            let ids = statement.query_map([], |row| row.get::<_, i64>(0))?;
            let mut unused = Vec::new();
            for id in ids {
                let id = id?;
                if !used.contains(id) {
                    unused.push(id);
                }
            }
            unused
        };
        let mut delete = conn.prepare(&format!("DELETE FROM {table} WHERE id=?1"))?;
        for id in unused {
            delete.execute(params![id])?;
        }
    }
    Ok(())
}

struct IdSet(Vec<u64>);

impl IdSet {
    fn new(max_id: i64) -> Self {
        Self(vec![0; (max_id.max(0) as usize) / 64 + 1])
    }

    fn insert(&mut self, id: i64) {
        // Rows only reference ids that exist, so every id is within range.
        if let Some(word) = usize::try_from(id)
            .ok()
            .and_then(|id| self.0.get_mut(id / 64))
        {
            *word |= 1 << (id % 64);
        }
    }

    fn contains(&self, id: i64) -> bool {
        usize::try_from(id)
            .ok()
            .and_then(|id| self.0.get(id / 64).map(|word| word & (1 << (id % 64)) != 0))
            .unwrap_or(false)
    }
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Db;

    fn header(ordinal: u32, name: &str, value: &[u8]) -> HeaderEntry {
        HeaderEntry {
            name: name.into(),
            value: value.to_vec(),
            ordinal,
        }
    }

    fn add_exchanges(conn: &Connection, count: i64) {
        conn.execute(
            "INSERT INTO projects (name,created_at,updated_at,scope_json,limits_json) VALUES ('p','t','t','{}','{}')",
            [],
        )
        .unwrap();
        for exchange in 1..=count {
            conn.execute(
                "INSERT INTO exchanges (project_id, exchange_id, source, started_at, method, scheme, authority,
                     host, port, path, completion, capture_quality, header_representation, body_representation)
                 VALUES (1, ?1, 'proxy', 't', 'GET', 'https', 'a.test', 'a.test', 443, '/', 'complete',
                     'semantic', 'semantic', 'semantic')",
                [exchange],
            )
            .unwrap();
        }
    }

    fn values(conn: &Connection) -> Vec<Vec<u8>> {
        let mut statement = conn
            .prepare("SELECT value FROM header_values ORDER BY value")
            .unwrap();
        let rows = statement.query_map([], |row| row.get(0)).unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    }

    fn names(headers: &[HeaderEntry]) -> Vec<(u32, String, Vec<u8>)> {
        headers
            .iter()
            .map(|h| (h.ordinal, h.name.clone(), h.value.clone()))
            .collect()
    }

    #[tokio::test]
    async fn headers_round_trip_in_order_and_share_repeated_values() {
        let db = Db::open_in_memory().await.unwrap();
        db.with_conn(|conn| {
            add_exchanges(conn, 2);
            let request = vec![
                header(0, "Cookie", b"sid=1"),
                header(1, "Accept", b"*/*"),
                header(2, "Cookie", b"theme=dark"),
            ];
            let response = vec![header(0, "Set-Cookie", b"sid=2; HttpOnly")];
            insert_headers_conn(conn, 1, 1, "request", &request)?;
            insert_headers_conn(conn, 1, 1, "response", &response)?;
            insert_headers_conn(conn, 1, 2, "request", &request)?;
            assert_eq!(
                names(&load_headers_conn(conn, 1, 1, "request")?),
                names(&request)
            );
            assert_eq!(
                names(&load_headers_conn(conn, 1, 1, "response")?),
                names(&response)
            );
            assert_eq!(
                names(&load_headers_conn(conn, 1, 2, "request")?),
                names(&request)
            );
            assert!(load_headers_conn(conn, 1, 2, "response")?.is_empty());
            assert_eq!(values(conn).len(), 4);
            assert!(insert_headers_conn(conn, 1, 2, "trailer", &response).is_err());

            // The view shows the same rows to SQL readers.
            let mut statement = conn
                .prepare(
                    "SELECT side, name, value FROM message_headers
                      WHERE exchange_id=1 ORDER BY side, ordinal",
                )
                .unwrap();
            let viewed = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(viewed.len(), 4);
            assert_eq!(
                viewed[3],
                (
                    "response".into(),
                    "Set-Cookie".into(),
                    b"sid=2; HttpOnly".to_vec()
                )
            );
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn values_only_deleted_exchanges_used_are_removed() {
        let db = Db::open_in_memory().await.unwrap();
        db.with_conn(|conn| {
            add_exchanges(conn, 2);
            insert_headers_conn(
                conn,
                1,
                1,
                "request",
                &[
                    header(0, "Cookie", b"shared"),
                    header(1, "Authorization", b"Bearer gone"),
                ],
            )?;
            insert_headers_conn(conn, 1, 2, "request", &[header(0, "Cookie", b"shared")])?;
            conn.execute("DELETE FROM exchanges WHERE exchange_id=1", [])
                .unwrap();
            delete_unused_header_values(conn).unwrap();
            assert_eq!(values(conn), vec![b"shared".to_vec()]);
            let name_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM header_names", [], |row| row.get(0))
                .unwrap();
            assert_eq!(name_count, 1);
            assert_eq!(
                names(&load_headers_conn(conn, 1, 2, "request")?),
                names(&[header(0, "Cookie", b"shared")])
            );

            conn.execute("DELETE FROM exchanges", []).unwrap();
            delete_unused_header_values(conn).unwrap();
            assert!(values(conn).is_empty());
            Ok(())
        })
        .await
        .unwrap();
    }
}
