//! Connection pool and SQLite configuration.

use crate::config::Config;
use crate::domain::{DomainError, DomainResult, ErrorCode};
use crate::storage::migrations;
use deadpool_sqlite::{Config as PoolConfig, Pool, Runtime};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct Db {
    pool: Pool,
    pub path: std::path::PathBuf,
    pub busy_timeout_ms: u64,
    pub synchronous: String,
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
