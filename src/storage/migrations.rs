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
];

pub fn schema_version(conn: &Connection) -> DomainResult<i32> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| DomainError::new(ErrorCode::MigrationError, e.to_string()))
}

pub fn migrate(conn: &Connection) -> DomainResult<i32> {
    let mut version = schema_version(conn)?;
    let target = MIGRATIONS.len() as i32;
    if version > target {
        return Err(DomainError::new(
            ErrorCode::MigrationError,
            format!("database schema version {version} is newer than binary {target}"),
        ));
    }
    while version < target {
        let idx = version as usize;
        let (name, sql) = MIGRATIONS[idx];
        tracing::info!(migration = name, from = version, "applying migration");
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(|e| DomainError::new(ErrorCode::MigrationError, e.to_string()))?;
        match conn.execute_batch(sql) {
            Ok(()) => {
                let next = version + 1;
                conn.pragma_update(None, "user_version", next)
                    .map_err(|e| DomainError::new(ErrorCode::MigrationError, e.to_string()))?;
                conn.execute_batch("COMMIT;")
                    .map_err(|e| DomainError::new(ErrorCode::MigrationError, e.to_string()))?;
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
}
