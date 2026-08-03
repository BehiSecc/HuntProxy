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

    #[test]
    fn legacy_browser_sessions_are_normalized_to_chromium() {
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
        let values: (String, String, String, i64, String) = conn
            .query_row(
                "SELECT engine,engine_policy,state,fallback_used,checkpoint_status FROM browser_sessions WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
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
            )
        );
    }
}
