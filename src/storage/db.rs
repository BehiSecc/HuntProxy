//! Connection pool and SQLite configuration.

use crate::config::Config;
use crate::domain::{DomainError, DomainResult, ErrorCode};
use crate::storage::migrations;
use crate::storage::upgrade::{self, UpgradeOptions};
use deadpool::managed::{self, Metrics, RecycleError, RecycleResult};
use deadpool::Runtime;
use deadpool_sync::SyncWrapper;
use rusqlite::functions::FunctionFlags;
use rusqlite::Connection;
use std::collections::HashMap;
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
            let in_memory = path.contains("mode=memory");
            let conn = Connection::open(path)?;
            configure(&conn, &synchronous, busy_timeout_ms)?;
            if in_memory {
                // Test databases share one in-memory cache, where a reader's
                // table lock makes a concurrent write fail at once with
                // "database table is locked" instead of waiting. Readers of a
                // WAL database file never block writers; this keeps tests the same.
                conn.pragma_update(None, "read_uncommitted", true)?;
            }
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

/// One lock per database file.
static WRITE_LOCKS: LazyLock<dashmap::DashMap<String, Arc<WriteLock>>> =
    LazyLock::new(Default::default);

/// Connections that are not pooled wait as long as the default busy timeout.
const DEFAULT_WRITE_WAIT: Duration = Duration::from_millis(5_000);

/// The write lock of `conn`'s database file. In-memory databases, which only
/// tests use, report no file name and so no lock: one shared lock would make
/// unrelated databases wait for each other.
fn write_lock(conn: &Connection, wait: Option<Duration>) -> Option<Arc<WriteLock>> {
    let key = conn.path().filter(|path| !path.is_empty())?.to_owned();
    let lock = WRITE_LOCKS
        .entry(key)
        .or_insert_with(|| {
            Arc::new(WriteLock {
                held: parking_lot::Mutex::new(false),
                free: parking_lot::Condvar::new(),
                wait: wait.unwrap_or(DEFAULT_WRITE_WAIT),
            })
        })
        .clone();
    Some(lock)
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
        Self::open_with(cfg, UpgradeOptions::default()).await
    }

    /// Opens the database, upgrading an older one as `options` allow.
    pub async fn open_with(cfg: &Config, options: UpgradeOptions) -> DomainResult<Self> {
        cfg.ensure_layout()?;
        let path = cfg.db_path();
        let sync = cfg.sqlite_synchronous.clone();
        let busy = cfg.busy_timeout_ms;
        let pool = open_pool(path.display().to_string(), sync.clone(), busy)?;

        let paths = upgrade::UpgradePaths {
            database: path.clone(),
            backups: cfg.runtime_dir.join("migration-backups"),
            progress: upgrade::upgrade_progress_path(cfg),
        };
        // Migrate on one connection before the pool opens any other.
        {
            let conn = pool
                .get()
                .await
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            conn.interact(move |c| upgrade::run(c, &paths, &options))
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

/// An `IMMEDIATE` transaction, begun once it is this writer's turn for the
/// database. The turn passes on after it commits, rolls back or is dropped.
pub(crate) struct WriteTransaction<'conn> {
    // Declared first so a dropped transaction rolls back before the turn ends.
    tx: rusqlite::Transaction<'conn>,
    _turn: Option<WriteTurn>,
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
    let turn = write_lock(conn, None)
        .map(|lock| {
            WriteTurn::take(lock).ok_or_else(|| {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                    Some("timed out waiting for this database's write lock".into()),
                )
            })
        })
        .transpose()?;
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

/// A body as `huntproxy_body_contains` searches it: decoded from storage and
/// through its HTTP Content-Encoding, with ASCII letters lowercased. A body
/// that does not decode, such as a truncated capture, an unknown encoding or
/// one past the decoded size limit, is searched as stored, as it was before
/// encodings were decoded.
fn searchable_body(
    codec: &str,
    content: &[u8],
    content_encoding: Option<&str>,
) -> DomainResult<Vec<u8>> {
    let stored = crate::storage::bodies::decode_body(codec, content)?;
    let mut bytes = match content_encoding.filter(|encoding| !encoding.trim().is_empty()) {
        None => stored,
        Some(encoding) => match crate::codec::decode_content_encodings(
            &stored,
            encoding,
            crate::codec::MAX_DECODED_BODY_OUTPUT,
        ) {
            Ok(decoded) => decoded,
            Err(error) => {
                tracing::debug!(%error, encoding, "body search reads the body as stored");
                stored
            }
        },
    };
    bytes.make_ascii_lowercase();
    Ok(bytes)
}

/// Whether `body` (from [`searchable_body`]) contains `needle` (already
/// lowercase), ignoring case. An ASCII needle is matched byte for byte in the
/// valid UTF-8 runs of the body, without copying it: invalid bytes are never
/// ASCII, so no match can span them. Only a non-ASCII needle needs the
/// Unicode-lowercased copy that every search used to make; the one difference
/// is that an ASCII needle no longer matches the few non-ASCII letters whose
/// lowercase is ASCII, such as the Kelvin sign.
fn searchable_body_contains(body: &[u8], needle: &str) -> bool {
    if needle.is_ascii() {
        return needle.len() <= body.len()
            && body
                .utf8_chunks()
                .any(|chunk| chunk.valid().contains(needle));
    }
    String::from_utf8_lossy(body)
        .to_lowercase()
        .contains(needle)
}

/// Decoded bodies one history search keeps, newest last: one row's request
/// and response body, so the terms of `response:~a OR response:~b` decode
/// their body once.
const DECODED_BODIES: usize = 2;
/// Answers one history search keeps, so a body that many exchanges share is
/// searched once per needle.
const BODY_ANSWERS: usize = 65_536;

/// A stored body read through one Content-Encoding: `(bodies.id, encoding)`.
type BodyKey = (i64, Option<String>);

/// State of the history search running on this thread; see [`BodySearchScope`].
struct BodySearch {
    deadline: Option<Instant>,
    /// `started_at` of the first row `huntproxy_search_open` refused.
    stopped_at: Option<String>,
    /// `started_at` of the first row searched.
    first_started_at: Option<String>,
    decoded: Vec<(BodyKey, Vec<u8>)>,
    answers: HashMap<(BodyKey, String), bool>,
}

thread_local! {
    static BODY_SEARCH: std::cell::RefCell<Option<BodySearch>> =
        const { std::cell::RefCell::new(None) };
}

/// One history query on this thread: while it lives, `huntproxy_body_contains`
/// reuses decoded bodies, and `huntproxy_search_open(started_at)` turns false
/// once `budget` has passed. SQLite runs a statement's functions on the thread
/// that steps it, so the scope must live inside the `with_conn` closure.
pub(crate) struct BodySearchScope(());

impl BodySearchScope {
    pub(crate) fn begin(budget: Option<Duration>) -> Self {
        BODY_SEARCH.with(|search| {
            *search.borrow_mut() = Some(BodySearch {
                deadline: budget.map(|budget| Instant::now() + budget),
                stopped_at: None,
                first_started_at: None,
                decoded: Vec::new(),
                answers: HashMap::new(),
            });
        });
        Self(())
    }

    /// The `started_at` of the first row the budget kept out of the search:
    /// every row the query reached before it was searched in full.
    pub(crate) fn stopped_at(&self) -> Option<String> {
        BODY_SEARCH.with(|search| {
            search
                .borrow()
                .as_ref()
                .and_then(|search| search.stopped_at.clone())
        })
    }
}

impl Drop for BodySearchScope {
    fn drop(&mut self) {
        BODY_SEARCH.with(|search| search.borrow_mut().take());
    }
}

/// `huntproxy_search_open(started_at)`: true until the search budget has
/// passed, then false for every remaining row, so the query finishes at once
/// with the rows it already matched. Rows at the first row's time are always
/// searched, so a continuation from the stopped row's time gets further.
/// Outside a [`BodySearchScope`] it is true.
fn search_open(started_at: &str) -> bool {
    BODY_SEARCH.with(|search| {
        let mut search = search.borrow_mut();
        let Some(search) = search.as_mut() else {
            return true;
        };
        if search.stopped_at.is_some() {
            return false;
        }
        let Some(first) = &search.first_started_at else {
            search.first_started_at = Some(started_at.to_owned());
            return true;
        };
        if first != started_at
            && search
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            search.stopped_at = Some(started_at.to_owned());
            return false;
        }
        true
    })
}

/// `huntproxy_body_contains(codec, content, needle, content_encoding, body_id)`.
/// Inside a [`BodySearchScope`], `body_id` (the `bodies.id` of `content`, or
/// None) lets it reuse decoded bodies and answers.
fn body_contains(
    codec: &str,
    content: &[u8],
    needle: &str,
    content_encoding: Option<&str>,
    body_id: Option<i64>,
) -> DomainResult<bool> {
    if needle.is_empty() {
        return Ok(true);
    }
    let search_uncached = || {
        let body = searchable_body(codec, content, content_encoding)?;
        Ok(searchable_body_contains(&body, needle))
    };
    BODY_SEARCH.with(|search| {
        let mut search = search.borrow_mut();
        let Some(search) = search.as_mut() else {
            return search_uncached();
        };
        // The row is out of the search; its result is never used.
        if search.stopped_at.is_some() {
            return Ok(false);
        }
        let Some(body_id) = body_id else {
            return search_uncached();
        };
        let key: BodyKey = (body_id, content_encoding.map(str::to_owned));
        let answer_key = (key, needle.to_owned());
        if let Some(found) = search.answers.get(&answer_key) {
            return Ok(*found);
        }
        let (key, needle) = &answer_key;
        let found = match search.decoded.iter().find(|(cached, _)| cached == key) {
            Some((_, body)) => searchable_body_contains(body, needle),
            None => {
                let body = searchable_body(codec, content, content_encoding)?;
                let found = searchable_body_contains(&body, needle);
                if search.decoded.len() == DECODED_BODIES {
                    search.decoded.remove(0);
                }
                search.decoded.push((key.clone(), body));
                found
            }
        };
        if search.answers.len() < BODY_ANSWERS {
            search.answers.insert(answer_key, found);
        }
        Ok(found)
    })
}

/// Text or blob argument `index` as bytes, or None for NULL and numbers.
fn bytes_arg<'a>(context: &'a rusqlite::functions::Context<'_>, index: usize) -> Option<&'a [u8]> {
    match context.get_raw(index) {
        rusqlite::types::ValueRef::Text(value) | rusqlite::types::ValueRef::Blob(value) => {
            Some(value)
        }
        _ => None,
    }
}

fn function_error(error: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other(error.to_string())))
}

/// How many prepared statements a connection keeps for reuse. Storing one
/// captured exchange and the lookups before it use about twenty.
const STATEMENT_CACHE_CAPACITY: usize = 64;

/// Runs a query that returns one row through the connection's statement cache.
/// Use it on paths that run for every request: preparing a statement (parsing
/// and planning its SQL) costs more than running a small one.
pub(crate) fn cached_query_row<T, P, F>(
    conn: &Connection,
    sql: &str,
    params: P,
    row: F,
) -> rusqlite::Result<T>
where
    P: rusqlite::Params,
    F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    conn.prepare_cached(sql)?.query_row(params, row)
}

/// Runs a statement through the connection's statement cache; see
/// [`cached_query_row`]. Returns the number of rows it changed.
pub(crate) fn cached_execute<P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    params: P,
) -> rusqlite::Result<usize> {
    conn.prepare_cached(sql)?.execute(params)
}

fn configure(conn: &Connection, synchronous: &str, busy_timeout_ms: u64) -> rusqlite::Result<()> {
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.busy_timeout(std::time::Duration::from_millis(busy_timeout_ms))?;
    conn.pragma_update(None, "synchronous", synchronous)?;
    conn.pragma_update(None, "trusted_schema", false)?;
    // (codec, content, needle, content_encoding, body_id): content_encoding
    // is the message's Content-Encoding, or NULL; body_id is the bodies.id of
    // content, or NULL.
    conn.create_scalar_function(
        "huntproxy_body_contains",
        5,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |context| {
            let codec = context.get::<String>(0)?;
            // Borrowed: a stored body is not copied before it is decoded.
            let content = bytes_arg(context, 1)
                .ok_or_else(|| function_error("huntproxy_body_contains needs body content"))?;
            let needle = context.get::<String>(2)?.to_lowercase();
            // Captured header values are bytes; one that is not UTF-8 must not
            // fail every body search in its project.
            let content_encoding = bytes_arg(context, 3).map(String::from_utf8_lossy);
            let body_id = context.get::<Option<i64>>(4)?;
            body_contains(
                &codec,
                content,
                &needle,
                content_encoding.as_deref(),
                body_id,
            )
            .map_err(function_error)
        },
    )?;
    // (started_at): see `search_open`. Not deterministic: it reads the clock.
    conn.create_scalar_function(
        "huntproxy_search_open",
        1,
        FunctionFlags::SQLITE_UTF8,
        |context| {
            let started_at = bytes_arg(context, 0).unwrap_or_default();
            Ok(search_open(&String::from_utf8_lossy(started_at)))
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
                            "SELECT huntproxy_body_contains('raw', CAST('Hello' AS BLOB), 'hell', NULL, NULL)",
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

    #[tokio::test]
    async fn cached_statements_are_reused_and_survive_a_schema_change() {
        let db = Db::open_in_memory().await.unwrap();
        db.with_conn(|conn| {
            let count = |conn: &Connection| {
                cached_query_row(conn, "SELECT count(*) FROM cached_fixture", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap()
            };
            conn.execute_batch("CREATE TABLE cached_fixture(id INTEGER PRIMARY KEY, v TEXT)")
                .unwrap();
            for value in ["a", "b"] {
                let changed =
                    cached_execute(conn, "INSERT INTO cached_fixture(v) VALUES (?1)", [value]);
                assert_eq!(changed.unwrap(), 1);
            }
            assert_eq!(count(conn), 2);
            // A migration or an index added later must not break a statement
            // that a pooled connection prepared before it.
            conn.execute_batch(
                "ALTER TABLE cached_fixture ADD COLUMN extra TEXT;
                 CREATE INDEX cached_fixture_v ON cached_fixture(v);",
            )
            .unwrap();
            let changed = cached_execute(conn, "INSERT INTO cached_fixture(v) VALUES (?1)", ["c"]);
            assert_eq!(changed.unwrap(), 1);
            assert_eq!(count(conn), 3);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[test]
    fn body_search_survives_a_content_encoding_that_is_not_utf8() {
        // History search passes group_concat(CAST(value AS TEXT)), which keeps
        // a captured header's raw bytes; "g\xffzip" must not fail the query.
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn, "NORMAL", 5000).unwrap();
        let found: bool = conn
            .query_row(
                "SELECT huntproxy_body_contains('raw', CAST('a needle here' AS BLOB), 'needle',
                                                CAST(X'67FF7A6970' AS TEXT), NULL)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(found);
    }

    #[test]
    fn body_search_ignores_case_without_copying_and_keeps_unicode_needles() {
        for (body, needle, expected) in [
            (&b"Hello World"[..], "world", true),
            (b"HELLO", "hello", true),
            (b"hello", "help", false),
            (b"short", "longer than the body", false),
            (b"anything", "", true),
            // Invalid UTF-8 between ASCII runs: no match spans it.
            (b"tok\xffen", "token", false),
            (b"\xfftoken\xfe", "token", true),
            // Non-ASCII needles still match Unicode case-insensitively.
            ("CAFÉ au lait".as_bytes(), "café", true),
            ("Straße".as_bytes(), "straße", true),
            ("naïve".as_bytes(), "naive", false),
        ] {
            let found = body_contains("raw", body, &needle.to_lowercase(), None, None).unwrap();
            assert_eq!(found, expected, "{needle:?} in {body:?}");
        }
    }

    #[test]
    fn a_search_scope_reuses_decoded_bodies_and_stops_after_its_budget() {
        let first = zstd::encode_all(&b"First body with ALPHA"[..], 1).unwrap();
        let second = b"second body with beta".to_vec();
        let state = || {
            BODY_SEARCH.with(|search| {
                let search = search.borrow();
                let search = search.as_ref().unwrap();
                (search.decoded.len(), search.answers.len())
            })
        };
        {
            let scope = BodySearchScope::begin(None);
            for _ in 0..2 {
                assert!(body_contains("zstd", &first, "alpha", None, Some(1)).unwrap());
                assert!(!body_contains("zstd", &first, "beta", None, Some(1)).unwrap());
                assert!(body_contains("raw", &second, "beta", None, Some(2)).unwrap());
                // The same body under another encoding is searched on its own.
                assert!(body_contains("raw", &second, "beta", Some("gzip"), Some(2)).unwrap());
            }
            assert_eq!(state(), (DECODED_BODIES, 4));
            // Without an id nothing is kept.
            assert!(body_contains("raw", &second, "body", None, None).unwrap());
            assert_eq!(state(), (DECODED_BODIES, 4));
            // Without a deadline the search never stops.
            assert!(search_open("2026-01-02T00:00:00Z"));
            assert!(search_open("2026-01-01T00:00:00Z"));
            assert!(scope.stopped_at().is_none());
        }
        BODY_SEARCH.with(|search| assert!(search.borrow().is_none()));

        let scope = BodySearchScope::begin(Some(Duration::ZERO));
        // Rows at the first row's time are always searched.
        assert!(search_open("2026-01-03T00:00:00Z"));
        assert!(search_open("2026-01-03T00:00:00Z"));
        assert!(!search_open("2026-01-02T00:00:00Z"));
        assert!(!search_open("2026-01-01T00:00:00Z"));
        assert_eq!(scope.stopped_at().as_deref(), Some("2026-01-02T00:00:00Z"));
        // Rows past the stop are not decoded at all.
        assert!(!body_contains("zstd", b"not zstd", "x", None, Some(3)).unwrap());
        drop(scope);
        assert!(body_contains("zstd", b"not zstd", "x", None, Some(3)).is_err());
        assert!(search_open("2026-01-01T00:00:00Z"));
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
        database.execute_batch(migrations::UNDO_020).unwrap();
        database.execute_batch(migrations::UNDO_018).unwrap();
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
