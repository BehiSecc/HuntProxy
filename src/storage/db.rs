//! Connection pool and SQLite configuration.

use crate::config::Config;
use crate::domain::{DomainError, DomainResult, ErrorCode};
use crate::storage::migrations;
use deadpool_sqlite::{Config as PoolConfig, Pool, Runtime};
use rusqlite::functions::FunctionFlags;
use rusqlite::Connection;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

#[derive(Clone)]
pub struct Db {
    pool: Pool,
    pub path: std::path::PathBuf,
    pub busy_timeout_ms: u64,
    pub synchronous: String,
    pub(crate) ip_rotation_cursors: Arc<dashmap::DashMap<i64, AtomicU64>>,
}

impl Db {
    pub async fn open(cfg: &Config) -> DomainResult<Self> {
        cfg.ensure_layout()?;
        let path = cfg.db_path();
        let pool_cfg = PoolConfig::new(path.display().to_string());
        let pool = pool_cfg
            .create_pool(Runtime::Tokio1)
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;

        let sync = cfg.sqlite_synchronous.clone();
        let busy = cfg.busy_timeout_ms;
        let migration_backup_dir = cfg.runtime_dir.join("migration-backups");
        // Configure and migrate on a connection
        {
            let conn = pool
                .get()
                .await
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let sync2 = sync.clone();
            conn.interact(move |c| {
                configure_connection(c, &sync2, busy)?;
                // WAL is database-wide
                c.pragma_update(None, "journal_mode", "WAL")
                    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                let version = migrations::schema_version(c)?;
                if version > 0 && version < migrations::current_schema_version() {
                    backup_before_migration(c, &migration_backup_dir, version)?;
                }
                migrations::migrate(c)
            })
            .await
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))??;
        }

        Ok(Self {
            pool,
            path,
            busy_timeout_ms: busy,
            synchronous: sync,
            ip_rotation_cursors: Arc::new(dashmap::DashMap::new()),
        })
    }

    pub async fn open_in_memory() -> DomainResult<Self> {
        let pool_cfg = PoolConfig::new(":memory:");
        let pool = pool_cfg
            .create_pool(Runtime::Tokio1)
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
        {
            let conn = pool
                .get()
                .await
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            conn.interact(|c| {
                configure_connection(c, "NORMAL", 5000)?;
                migrations::migrate(c)
            })
            .await
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))??;
        }
        Ok(Self {
            pool,
            path: Path::new(":memory:").to_path_buf(),
            busy_timeout_ms: 5000,
            synchronous: "NORMAL".into(),
            ip_rotation_cursors: Arc::new(dashmap::DashMap::new()),
        })
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    pub async fn with_conn<F, T>(&self, f: F) -> DomainResult<T>
    where
        F: FnOnce(&Connection) -> DomainResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
        let busy = self.busy_timeout_ms;
        let sync = self.synchronous.clone();
        conn.interact(move |c| {
            configure_connection(c, &sync, busy)?;
            f(c)
        })
        .await
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?
    }

    pub async fn schema_version(&self) -> DomainResult<i32> {
        self.with_conn(migrations::schema_version).await
    }
}

fn backup_before_migration(
    source: &Connection,
    directory: &Path,
    version: i32,
) -> DomainResult<()> {
    crate::config::create_private_dir(directory)?;
    let path = directory.join(format!("schema-{version}-{}.sqlite3", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut target = Connection::open(&path)?;
        let backup = rusqlite::backup::Backup::new(source, &mut target)?;
        backup.run_to_completion(128, std::time::Duration::from_millis(10), None)?;
        drop(backup);
        target.pragma_update(None, "journal_mode", "DELETE")?;
        drop(target);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::File::open(&path)?.sync_all()?;
        std::fs::File::open(directory)?.sync_all()?;
        Ok::<_, anyhow::Error>(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&path);
        return Err(DomainError::new(
            ErrorCode::MigrationError,
            format!("could not preserve the database before upgrading: {error}"),
        ));
    }
    tracing::info!(path = %path.display(), schema = version, "preserved database before schema upgrade");
    Ok(())
}

pub(crate) fn write_transaction(conn: &Connection) -> rusqlite::Result<rusqlite::Transaction<'_>> {
    rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
}

pub fn configure_connection(
    conn: &Connection,
    synchronous: &str,
    busy_timeout_ms: u64,
) -> DomainResult<()> {
    conn.pragma_update(None, "foreign_keys", true)
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    conn.busy_timeout(std::time::Duration::from_millis(busy_timeout_ms))
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    conn.pragma_update(None, "synchronous", synchronous)
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    conn.pragma_update(None, "trusted_schema", false)
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    conn.create_scalar_function(
        "huntproxy_body_contains",
        3,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |context| {
            let codec = context.get::<String>(0)?;
            let content = context.get::<Vec<u8>>(1)?;
            let needle = context.get::<String>(2)?.to_lowercase();
            let decoded =
                crate::storage::bodies::decode_body(&codec, &content).map_err(|error| {
                    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other(
                        error.to_string(),
                    )))
                })?;
            Ok(String::from_utf8_lossy(&decoded)
                .to_lowercase()
                .contains(&needle))
        },
    )
    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
    // DEFENSIVE mode
    unsafe {
        rusqlite::ffi::sqlite3_db_config(
            conn.handle(),
            rusqlite::ffi::SQLITE_DBCONFIG_DEFENSIVE,
            1,
            std::ptr::null_mut::<i32>(),
        );
    }
    Ok(())
}

/// Shared app state handle.
pub type DbHandle = Arc<Db>;

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_database(directory: &Path) -> Config {
        let config = Config {
            data_dir: directory.to_owned(),
            spool_dir: directory.join("spool"),
            export_dir: directory.join("exports"),
            runtime_dir: directory.join("runtime"),
            plugin_dir: directory.join("plugins"),
            ..Config::default()
        };
        config.ensure_layout().unwrap();
        let database = Connection::open(config.db_path()).unwrap();
        migrations::migrate(&database).unwrap();
        database.execute_batch("ALTER TABLE browser_sessions DROP COLUMN profile_name; PRAGMA user_version=14; CREATE TABLE saved_fixture(name TEXT); INSERT INTO saved_fixture VALUES ('Existing project');").unwrap();
        config
    }

    #[tokio::test]
    async fn schema_upgrade_keeps_a_private_usable_backup_and_does_not_repeat_it() {
        let directory = tempfile::tempdir().unwrap();
        let config = legacy_database(directory.path());
        let database = Db::open(&config).await.unwrap();
        assert_eq!(database.schema_version().await.unwrap(), 15);
        let backups = config.runtime_dir.join("migration-backups");
        let paths: Vec<_> = std::fs::read_dir(&backups)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(paths.len(), 1);
        let restored = Connection::open(&paths[0]).unwrap();
        assert_eq!(migrations::schema_version(&restored).unwrap(), 14);
        assert_eq!(
            restored
                .query_row("SELECT name FROM saved_fixture", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "Existing project"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&paths[0]).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(database);
        Db::open(&config).await.unwrap();
        assert_eq!(std::fs::read_dir(backups).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn backup_failure_prevents_schema_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let config = legacy_database(directory.path());
        std::fs::write(config.runtime_dir.join("migration-backups"), b"occupied").unwrap();
        assert!(Db::open(&config).await.is_err());
        let database = Connection::open(config.db_path()).unwrap();
        assert_eq!(migrations::schema_version(&database).unwrap(), 14);
        assert_eq!(
            database
                .query_row("SELECT name FROM saved_fixture", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "Existing project"
        );
    }
}
