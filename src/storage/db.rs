//! Connection pool and SQLite configuration.

use crate::config::Config;
use crate::domain::{DomainError, DomainResult, ErrorCode};
use crate::storage::migrations;
use deadpool::managed::{self, Metrics, RecycleError, RecycleResult};
use deadpool::Runtime;
use deadpool_sync::SyncWrapper;
use rusqlite::functions::FunctionFlags;
use rusqlite::Connection;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

type Pool = managed::Pool<SqliteManager>;

/// Opens pooled SQLite connections, configured once when they are opened.
/// Each connection runs its queries on a blocking thread.
#[derive(Debug)]
struct SqliteManager {
    path: String,
    synchronous: String,
    busy_timeout_ms: u64,
}

impl managed::Manager for SqliteManager {
    type Type = SyncWrapper<Connection>;
    type Error = rusqlite::Error;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let path = self.path.clone();
        let synchronous = self.synchronous.clone();
        let busy_timeout_ms = self.busy_timeout_ms;
        SyncWrapper::new(Runtime::Tokio1, move || {
            let conn = Connection::open(path)?;
            configure(&conn, &synchronous, busy_timeout_ms)?;
            write_lock(&conn, Some(Duration::from_millis(busy_timeout_ms)));
            Ok(conn)
        })
        .await
    }

    async fn recycle(&self, conn: &mut Self::Type, _: &Metrics) -> RecycleResult<Self::Error> {
        // Settings live as long as the connection, so a checkout needs no
        // query. Only a connection whose query panicked is not reused.
        if conn.is_mutex_poisoned() {
            return Err(RecycleError::message(
                "a query panicked while holding this connection",
            ));
        }
        Ok(())
    }
}

fn open_pool(path: String, synchronous: String, busy_timeout_ms: u64) -> DomainResult<Pool> {
    Pool::builder(SqliteManager {
        path,
        synchronous,
        busy_timeout_ms,
    })
    .runtime(Runtime::Tokio1)
    .build()
    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))
}

/// The writers of one database file take turns here. SQLite's own busy
/// handler sleeps up to 100 ms between retries, so between short commits its
/// write lock sat idle while every waiter slept; a turn passes on at once.
struct WriteLock {
    held: parking_lot::Mutex<bool>,
    free: parking_lot::Condvar,
    /// How long a writer waits for its turn: the busy timeout it replaces.
    wait: Duration,
}

/// One lock per database file; in-memory databases share the `""` entry.
static WRITE_LOCKS: LazyLock<dashmap::DashMap<String, Arc<WriteLock>>> =
    LazyLock::new(Default::default);

/// Connections that are not pooled wait as long as the default busy timeout.
const DEFAULT_WRITE_WAIT: Duration = Duration::from_millis(5_000);

fn write_lock(conn: &Connection, wait: Option<Duration>) -> Arc<WriteLock> {
    let key = conn.path().unwrap_or_default().to_owned();
    WRITE_LOCKS
        .entry(key)
        .or_insert_with(|| {
            Arc::new(WriteLock {
                held: parking_lot::Mutex::new(false),
                free: parking_lot::Condvar::new(),
                wait: wait.unwrap_or(DEFAULT_WRITE_WAIT),
            })
        })
        .clone()
}

/// A writer's turn; the next writer goes when it is dropped.
struct WriteTurn(Arc<WriteLock>);

impl WriteTurn {
    fn take(lock: Arc<WriteLock>) -> Option<Self> {
        let deadline = Instant::now() + lock.wait;
        {
            let mut held = lock.held.lock();
            while *held {
                if lock.free.wait_until(&mut held, deadline).timed_out() && *held {
                    return None;
                }
            }
            *held = true;
        }
        Some(Self(lock))
    }
}

impl Drop for WriteTurn {
    fn drop(&mut self) {
        *self.0.held.lock() = false;
        self.0.free.notify_one();
    }
}

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
        let sync = cfg.sqlite_synchronous.clone();
        let busy = cfg.busy_timeout_ms;
        let pool = open_pool(path.display().to_string(), sync.clone(), busy)?;

        let migration_backup_dir = cfg.runtime_dir.join("migration-backups");
        // Migrate on a connection
        {
            let conn = pool
                .get()
                .await
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            conn.interact(move |c| {
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
        // Each SQLite :memory: connection is a separate database. Give this
        // pool a private shared-memory database so every connection sees the
        // migrated schema and the same data.
        let pool = open_pool(
            format!(
                "file:huntproxy-{}?mode=memory&cache=shared",
                uuid::Uuid::new_v4()
            ),
            "NORMAL".into(),
            5000,
        )?;
        {
            let conn = pool
                .get()
                .await
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            conn.interact(|c| migrations::migrate(c))
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
        conn.interact(move |c| f(c))
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

/// An `IMMEDIATE` transaction, begun once it is this writer's turn for the
/// database. The turn passes on after it commits, rolls back or is dropped.
pub(crate) struct WriteTransaction<'conn> {
    // Declared first so a dropped transaction rolls back before the turn ends.
    tx: rusqlite::Transaction<'conn>,
    _turn: WriteTurn,
}

impl WriteTransaction<'_> {
    pub fn commit(self) -> rusqlite::Result<()> {
        self.tx.commit()
    }
}

impl<'conn> Deref for WriteTransaction<'conn> {
    type Target = rusqlite::Transaction<'conn>;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl DerefMut for WriteTransaction<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

/// Begins a write transaction. Use it for every transaction that writes, so
/// the write lock is held from the first statement: a deferred transaction
/// that reads first fails when another writer commits before its first write.
pub(crate) fn write_transaction(conn: &Connection) -> rusqlite::Result<WriteTransaction<'_>> {
    let turn = WriteTurn::take(write_lock(conn, None)).ok_or_else(|| {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("timed out waiting for this database's write lock".into()),
        )
    })?;
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    Ok(WriteTransaction { tx, _turn: turn })
}

pub fn configure_connection(
    conn: &Connection,
    synchronous: &str,
    busy_timeout_ms: u64,
) -> DomainResult<()> {
    configure(conn, synchronous, busy_timeout_ms)
        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))
}

fn configure(conn: &Connection, synchronous: &str, busy_timeout_ms: u64) -> rusqlite::Result<()> {
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.busy_timeout(std::time::Duration::from_millis(busy_timeout_ms))?;
    conn.pragma_update(None, "synchronous", synchronous)?;
    conn.pragma_update(None, "trusted_schema", false)?;
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
    )?;
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

    #[test]
    fn sqlite_includes_unix_locking_and_wal_fixes() {
        // 3.51.3 fixes Unix locking and WAL; 3.54.0 fixes stale page-cache
        // reads when a WAL's page size differs from the database's
        // (RUSTSEC-2026-0459).
        assert!(
            rusqlite::version_number() >= 3_054_000,
            "SQLite {} predates the Unix locking and WAL fixes",
            rusqlite::version()
        );
    }

    /// Why every write transaction that reads before it writes must use
    /// `write_transaction`: a deferred one that read first fails at once when
    /// another connection commits meanwhile, and no busy timeout helps.
    #[test]
    fn write_transactions_hold_the_write_lock_from_their_first_read() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("locks.db");
        let open = || {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            conn.pragma_update(None, "busy_timeout", 200).unwrap();
            conn
        };
        let (first, second) = (open(), open());
        first.execute_batch("CREATE TABLE t(v INTEGER)").unwrap();

        let deferred = first.unchecked_transaction().unwrap();
        deferred
            .query_row("SELECT count(*) FROM t", [], |row| row.get::<_, i64>(0))
            .unwrap();
        second.execute("INSERT INTO t VALUES (1)", []).unwrap();
        let error = deferred
            .execute("INSERT INTO t VALUES (2)", [])
            .unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy)
        );
        drop(deferred);

        let immediate = write_transaction(&first).unwrap();
        immediate
            .query_row("SELECT count(*) FROM t", [], |row| row.get::<_, i64>(0))
            .unwrap();
        // The other writer waits for the lock instead of invalidating the read.
        assert!(second.execute("INSERT INTO t VALUES (3)", []).is_err());
        immediate.execute("INSERT INTO t VALUES (4)", []).unwrap();
        immediate.commit().unwrap();
        second.execute("INSERT INTO t VALUES (5)", []).unwrap();
    }

    #[tokio::test]
    async fn pooled_connections_keep_their_settings_between_calls() {
        let db = Db::open_in_memory().await.unwrap();
        for _ in 0..3 {
            let (foreign_keys, busy_timeout, trusted_schema, contains) = db
                .with_conn(|conn| {
                    let pragma = |name: &str| {
                        conn.query_row(&format!("PRAGMA {name}"), [], |row| row.get::<_, i64>(0))
                            .unwrap()
                    };
                    let contains = conn
                        .query_row(
                            "SELECT huntproxy_body_contains('raw', CAST('Hello' AS BLOB), 'hell')",
                            [],
                            |row| row.get::<_, bool>(0),
                        )
                        .unwrap();
                    Ok((
                        pragma("foreign_keys"),
                        pragma("busy_timeout"),
                        pragma("trusted_schema"),
                        contains,
                    ))
                })
                .await
                .unwrap();
            assert_eq!((foreign_keys, busy_timeout, trusted_schema), (1, 5000, 0));
            assert!(contains);
        }
    }

    #[test]
    fn concurrent_writers_take_turns_without_busy_errors_or_lost_updates() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("turns.db");
        let setup = Connection::open(&path).unwrap();
        setup.pragma_update(None, "journal_mode", "WAL").unwrap();
        setup
            .execute_batch("CREATE TABLE counter(v INTEGER); INSERT INTO counter VALUES (0);")
            .unwrap();
        let writers = (0..16)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let conn = Connection::open(&path).unwrap();
                    // SQLite alone would give up on the lock after 20 ms.
                    configure(&conn, "NORMAL", 20).unwrap();
                    for _ in 0..40 {
                        let tx = write_transaction(&conn).unwrap();
                        let value: i64 = tx
                            .query_row("SELECT v FROM counter", [], |row| row.get(0))
                            .unwrap();
                        std::thread::sleep(Duration::from_micros(200));
                        tx.execute("UPDATE counter SET v=?1", [value + 1]).unwrap();
                        tx.commit().unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().unwrap();
        }
        let total: i64 = setup
            .query_row("SELECT v FROM counter", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total, 16 * 40);
    }

    #[test]
    fn a_writer_gives_up_when_its_turn_does_not_come() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("timeout.db");
        let (first, second) = (
            Connection::open(&path).unwrap(),
            Connection::open(&path).unwrap(),
        );
        write_lock(&first, Some(Duration::from_millis(50)));
        let held = write_transaction(&first).unwrap();
        let started = Instant::now();
        let error = match write_transaction(&second) {
            Ok(_) => panic!("the second writer began while the first held its turn"),
            Err(error) => error,
        };
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy)
        );
        assert!(started.elapsed() >= Duration::from_millis(50));
        drop(held);
        write_transaction(&second).unwrap().commit().unwrap();
    }

    #[tokio::test]
    async fn in_memory_pool_shares_database_between_connections_but_not_pools() {
        let db = Db::open_in_memory().await.unwrap();
        let other = Db::open_in_memory().await.unwrap();
        let first = db.pool.get().await.unwrap();
        first.interact(|conn| {
            conn.execute_batch("CREATE TABLE shared_fixture (value TEXT); INSERT INTO shared_fixture VALUES ('shared');")
        }).await.unwrap().unwrap();
        let second = db.pool.get().await.unwrap();
        let value: String = second
            .interact(|conn| {
                conn.query_row("SELECT value FROM shared_fixture", [], |row| row.get(0))
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(value, "shared");
        assert!(other
            .with_conn(|conn| {
                conn.query_row("SELECT value FROM shared_fixture", [], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))
            })
            .await
            .is_err());
    }

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
        database.execute_batch("DROP TABLE project_upstream_proxies; DROP INDEX idx_capture_sessions_token_lookup; DROP INDEX idx_capture_sessions_legacy_active; ALTER TABLE capture_sessions DROP COLUMN token_lookup; ALTER TABLE browser_sessions DROP COLUMN profile_name; PRAGMA user_version=14; CREATE TABLE saved_fixture(name TEXT); INSERT INTO saved_fixture VALUES ('Existing project');").unwrap();
        config
    }

    #[tokio::test]
    async fn schema_upgrade_keeps_a_private_usable_backup_and_does_not_repeat_it() {
        let directory = tempfile::tempdir().unwrap();
        let config = legacy_database(directory.path());
        let database = Db::open(&config).await.unwrap();
        assert_eq!(
            database.schema_version().await.unwrap(),
            migrations::current_schema_version()
        );
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
