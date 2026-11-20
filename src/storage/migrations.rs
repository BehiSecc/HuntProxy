//! Numbered embedded SQL migrations via PRAGMA user_version.

use crate::domain::{DomainError, DomainResult, ErrorCode};
use rusqlite::Connection;

const MIGRATIONS: &[(&str, &str)] = &[
    ("001_init", include_str!("../../migrations/001_init.sql")),
    (
        "002_backend_correctness",
        include_str!("../../migrations/002_backend_correctness.sql"),
    ),
    (
        "003_project_cookies",
        include_str!("../../migrations/003_project_cookies.sql"),
    ),
    (
        "004_findings",
        include_str!("../../migrations/004_findings.sql"),
    ),
    (
        "005_javascript_provenance",
        include_str!("../../migrations/005_javascript_provenance.sql"),
    ),
    (
        "006_project_target",
        include_str!("../../migrations/006_project_target.sql"),
    ),
    (
        "007_browser_session_title",
        include_str!("../../migrations/007_browser_session_title.sql"),
    ),
    (
        "008_project_usage",
        include_str!("../../migrations/008_project_usage.sql"),
    ),
    (
        "009_websockets",
        include_str!("../../migrations/009_websockets.sql"),
    ),
    (
        "010_request_rules",
        include_str!("../../migrations/010_request_rules.sql"),
    ),
    (
        "011_fuzz_response_groups",
        include_str!("../../migrations/011_fuzz_response_groups.sql"),
    ),
    (
        "012_chromium_only_browser",
        include_str!("../../migrations/012_chromium_only_browser.sql"),
    ),
    (
        "013_ip_rotation",
        include_str!("../../migrations/013_ip_rotation.sql"),
    ),
    (
        "014_named_cookie_profiles",
        include_str!("../../migrations/014_named_cookie_profiles.sql"),
    ),
    (
        "015_browser_profiles",
        include_str!("../../migrations/015_browser_profiles.sql"),
    ),
    (
        "016_project_upstream_proxies",
        include_str!("../../migrations/016_project_upstream_proxies.sql"),
    ),
    (
        "017_capture_token_lookup",
        include_str!("../../migrations/017_capture_token_lookup.sql"),
    ),
    (
        "018_compact_storage",
        include_str!("../../migrations/018_compact_storage.sql"),
    ),
    (
        "019_foreign_key_indexes",
        include_str!("../../migrations/019_foreign_key_indexes.sql"),
    ),
    (
        "020_request_rule_blocks",
        include_str!("../../migrations/020_request_rule_blocks.sql"),
    ),
];

/// Removes migration 020's request rule columns. Run it before UNDO_018 when a
/// test rebuilds an older schema from a current database.
#[cfg(test)]
pub(crate) const UNDO_020: &str = "
    ALTER TABLE request_rules DROP COLUMN method;
    ALTER TABLE request_rules DROP COLUMN response_status;
    ALTER TABLE request_rules DROP COLUMN response_content_type;
    ALTER TABLE request_rules DROP COLUMN response_body;
";

/// Turns a current database back into its schema-17 shape, keeping its header
/// rows, for tests that build databases from older releases.
#[cfg(test)]
pub(crate) const UNDO_018: &str = "
    CREATE TABLE message_headers_17 (
        project_id INTEGER NOT NULL,
        exchange_id INTEGER NOT NULL,
        side TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        name TEXT NOT NULL,
        value BLOB NOT NULL,
        PRIMARY KEY (project_id, exchange_id, side, ordinal),
        FOREIGN KEY (project_id, exchange_id) REFERENCES exchanges(project_id, exchange_id) ON DELETE CASCADE
    );
    INSERT INTO message_headers_17 SELECT * FROM message_headers;
    DROP VIEW message_headers;
    DROP TABLE message_header_rows;
    DROP TABLE header_names;
    DROP TABLE header_values;
    DROP TABLE storage_maintenance;
    ALTER TABLE message_headers_17 RENAME TO message_headers;
    PRAGMA user_version=17;
";

pub fn schema_version(conn: &Connection) -> DomainResult<i32> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| DomainError::new(ErrorCode::MigrationError, e.to_string()))
}

pub fn current_schema_version() -> i32 {
    MIGRATIONS.len() as i32
}

pub fn migrate(conn: &Connection) -> DomainResult<i32> {
    let mut version = schema_version(conn)?;
    let target = MIGRATIONS.len() as i32;
    if version > target {
        return Err(DomainError::new(
            ErrorCode::MigrationError,
            format!(
                "database schema version {version} is newer than this binary supports ({target}); run the same or a newer HuntProxy build, or reinstall/update HuntProxy"
            ),
        ));
    }
    while version < target {
        let idx = version as usize;
        let (name, sql) = MIGRATIONS[idx];
        tracing::info!(migration = name, from = version, "applying migration");
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(|e| DomainError::new(ErrorCode::MigrationError, e.to_string()))?;
        let migration = (|| {
            conn.execute_batch(sql)?;
            let next = version + 1;
            conn.pragma_update(None, "user_version", next)?;
            conn.execute_batch("COMMIT;")?;
            Ok::<_, rusqlite::Error>(next)
        })();
        match migration {
            Ok(next) => {
                version = next;
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(DomainError::new(
                    ErrorCode::MigrationError,
                    format!("migration {name} failed: {e}"),
                ));
            }
        }
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::configure_connection;

    #[test]
    fn fresh_db_migrates_to_current() {
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn, "NORMAL", 5000).unwrap();
        let v = migrate(&conn).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i32);
        assert_eq!(schema_version(&conn).unwrap(), v);
        // core tables exist
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='projects'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    /// Foreign keys left without an index on their referencing columns, each
    /// because deleting a project removes one parent row and so scans the
    /// small referencing table once.
    const UNINDEXED_FOREIGN_KEYS: &[(&str, &[&str])] = &[
        ("reply_workspaces", &["project_id"]),
        ("reply_tabs", &["project_id"]),
        ("reply_tabs", &["workspace_id"]),
        ("fuzz_jobs", &["project_id"]),
        ("browser_sessions", &["project_id"]),
    ];

    /// Deleting a row that foreign keys point at makes SQLite look for the
    /// rows that reference it: a scan of the whole referencing table unless an
    /// index starts with the referencing columns. Deleting many such rows at
    /// once (a project's bodies, WebSocket connections, browser sessions) then
    /// takes time proportional to their number times the table.
    #[test]
    fn every_foreign_key_has_an_index_on_its_referencing_columns() {
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn, "NORMAL", 5000).unwrap();
        migrate(&conn).unwrap();
        let column = |sql: &str, index: usize| -> Vec<String> {
            let mut statement = conn.prepare(sql).unwrap();
            let rows = statement.query_map([], |row| row.get(index)).unwrap();
            rows.collect::<Result<_, _>>().unwrap()
        };
        let tables = column(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            0,
        );
        let mut unindexed = Vec::new();
        for table in &tables {
            let mut foreign_keys = std::collections::BTreeMap::<i64, Vec<String>>::new();
            {
                let mut statement = conn
                    .prepare(&format!("PRAGMA foreign_key_list('{table}')"))
                    .unwrap();
                let mut rows = statement.query([]).unwrap();
                while let Some(row) = rows.next().unwrap() {
                    foreign_keys
                        .entry(row.get(0).unwrap())
                        .or_default()
                        .push(row.get(3).unwrap());
                }
            }
            // The primary key and every index, as their column lists.
            let mut indexed = vec![{
                let mut statement = conn
                    .prepare(&format!(
                        "SELECT name FROM pragma_table_info('{table}') WHERE pk > 0 ORDER BY pk"
                    ))
                    .unwrap();
                let rows = statement.query_map([], |row| row.get(0)).unwrap();
                rows.collect::<Result<Vec<String>, _>>().unwrap()
            }];
            for index in column(&format!("PRAGMA index_list('{table}')"), 1) {
                indexed.push(column(&format!("PRAGMA index_info('{index}')"), 2));
            }
            for columns in foreign_keys.into_values() {
                let covered = indexed.iter().any(|index| {
                    index.len() >= columns.len()
                        && columns
                            .iter()
                            .all(|name| index[..columns.len()].contains(name))
                });
                let known = UNINDEXED_FOREIGN_KEYS.iter().any(|(known_table, known)| {
                    known_table == table
                        && known
                            .iter()
                            .map(|name| name.to_string())
                            .collect::<Vec<_>>()
                            == columns
                });
                if !covered && !known {
                    unindexed.push(format!("{table}({})", columns.join(", ")));
                }
            }
        }
        assert!(
            unindexed.is_empty(),
            "foreign keys without an index on their referencing columns: {unindexed:?}"
        );
    }

    type HeaderRow = (i64, i64, String, i64, String, Vec<u8>, String);

    fn header_rows(conn: &Connection) -> Vec<HeaderRow> {
        let mut statement = conn
            .prepare(
                "SELECT project_id, exchange_id, side, ordinal, name, CAST(value AS BLOB), typeof(value)
                   FROM message_headers ORDER BY project_id, exchange_id, side, ordinal",
            )
            .unwrap();
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })
            .unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    #[test]
    fn headers_move_to_shared_names_and_values_without_changing_any_row() {
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn, "NORMAL", 5000).unwrap();
        for (index, (_, sql)) in MIGRATIONS.iter().take(17).enumerate() {
            conn.execute_batch(sql).unwrap();
            conn.pragma_update(None, "user_version", index as i32 + 1)
                .unwrap();
        }
        conn.execute(
            "INSERT INTO projects (name,created_at,updated_at,scope_json,limits_json) VALUES ('p','t','t','{}','{}')",
            [],
        )
        .unwrap();
        for exchange in 1..=3 {
            conn.execute(
                "INSERT INTO exchanges (project_id, exchange_id, source, started_at, method, scheme, authority,
                     host, port, path, completion, capture_quality, header_representation, body_representation)
                 VALUES (1, ?1, 'proxy', 't', 'GET', 'https', 'a.test', 'a.test', 443, '/', 'complete',
                     'semantic', 'semantic', 'semantic')",
                [exchange],
            )
            .unwrap();
        }
        // Repeated values, a name in two spellings, a value stored once as
        // text and once as a blob, and an empty value.
        conn.execute_batch(
            "INSERT INTO message_headers VALUES
                (1, 1, 'request', 0, 'Cookie', X'7369643D31'),
                (1, 1, 'request', 1, 'User-Agent', 'UA'),
                (1, 1, 'response', 0, 'Set-Cookie', X'78'),
                (1, 2, 'request', 0, 'Cookie', X'7369643D31'),
                (1, 2, 'request', 1, 'user-agent', X'5541'),
                (1, 3, 'response', 0, 'X-Empty', X'');",
        )
        .unwrap();
        let before = header_rows(&conn);

        migrate(&conn).unwrap();
        assert_eq!(header_rows(&conn), before);
        assert_eq!(count(&conn, "message_header_rows"), 6);
        assert_eq!(count(&conn, "header_names"), 5);
        assert_eq!(count(&conn, "header_values"), 5);

        // Writes through the view share the stored name and value.
        conn.execute(
            "INSERT INTO message_headers VALUES (1, 3, 'request', 0, 'Cookie', X'7369643D31')",
            [],
        )
        .unwrap();
        assert_eq!(count(&conn, "header_names"), 5);
        assert_eq!(count(&conn, "header_values"), 5);
        assert!(conn
            .execute(
                "INSERT INTO message_headers VALUES (1, 3, 'other', 0, 'A', X'00')",
                [],
            )
            .is_err());
        conn.execute(
            "DELETE FROM message_headers WHERE exchange_id=1 AND side='response'",
            [],
        )
        .unwrap();
        assert_eq!(count(&conn, "message_header_rows"), 6);
        // Deleting an exchange still removes its headers.
        conn.execute("DELETE FROM exchanges WHERE exchange_id=2", [])
            .unwrap();
        assert_eq!(count(&conn, "message_header_rows"), 4);
        let cleared: i64 = conn
            .query_row(
                "SELECT finished_at IS NULL FROM storage_maintenance WHERE task='compress_raw_bodies'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cleared, 1);
    }

    #[test]
    fn newer_database_error_explains_the_safe_recovery() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", MIGRATIONS.len() as i32 + 1)
            .unwrap();
        let error = migrate(&conn).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MigrationError);
        assert!(error.to_string().contains("newer HuntProxy build"));
    }

    #[test]
    fn failed_migration_rolls_back_and_preserves_version() {
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn, "NORMAL", 5000).unwrap();
        for (index, (_, sql)) in MIGRATIONS.iter().take(14).enumerate() {
            conn.execute_batch(sql).unwrap();
            conn.pragma_update(None, "user_version", index as i32 + 1)
                .unwrap();
        }
        conn.execute(
            "ALTER TABLE browser_sessions ADD COLUMN profile_name TEXT",
            [],
        )
        .unwrap();

        assert!(migrate(&conn).is_err());
        assert_eq!(schema_version(&conn).unwrap(), 14);
    }

    #[test]
    fn legacy_browser_sessions_are_normalized_without_inventing_profile_history() {
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn, "NORMAL", 5000).unwrap();
        conn.execute_batch(MIGRATIONS[0].1).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute(
            "INSERT INTO projects (name,created_at,updated_at,scope_json,limits_json) VALUES ('legacy','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','{}','{}')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO browser_sessions (project_id,engine,engine_policy,state,fallback_used,checkpoint_status,created_at,updated_at) VALUES (1,'lightpanda','auto','migrating',1,'fallback_chromium','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();

        migrate(&conn).unwrap();
        let values: (String, String, String, i64, String, Option<String>) = conn
            .query_row(
                "SELECT engine,engine_policy,state,fallback_used,checkpoint_status,profile_name FROM browser_sessions WHERE id=1",
                [],
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
            .unwrap();
        assert_eq!(
            values,
            (
                "chromium".into(),
                "chromium".into(),
                "interrupted".into(),
                0,
                "ok".into(),
                None,
            )
        );
    }
}
