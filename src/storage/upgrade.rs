//! Opening an older database: a free-space check, a backup, the migrations
//! and one compaction, reporting progress that the installer and auto-start
//! watch while they wait.

use crate::config::Config;
use crate::domain::{DomainError, DomainResult, ErrorCode};
use crate::storage::migrations;
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Migration 018 moves every header into new tables. The old table's pages
/// become free space inside the file, which only shrinks once it is compacted.
const COMPACTING_SCHEMA: i32 = 18;

/// Set by an installer that watches upgrade progress instead of stopping
/// release preparation after a fixed time.
pub const WATCHED_UPGRADE_ENV: &str = "HUNTPROXY_WATCHED_UPGRADE";

/// HuntProxy 0.4 and older kill release preparation after 900 seconds and
/// roll the update back. Preparation they start stops on its own before that.
const UNWATCHED_PREPARATION_BUDGET: Duration = Duration::from_secs(840);

/// Callers wait this long for a process that may be upgrading the database...
const BASE_WAIT: Duration = Duration::from_secs(900);
/// ...and longer while the upgrade reported progress this recently...
const STALL_LIMIT: Duration = Duration::from_secs(180);
/// ...but never longer than this.
const LONGEST_WAIT: Duration = Duration::from_secs(4 * 60 * 60);

/// Room kept free beyond each estimate.
const SPACE_MARGIN: u64 = 256 << 20;

/// Compaction runs only when at least this share of the file is free pages.
const COMPACT_FREE_SHARE: u64 = 4;
/// ...and they add up to at least this much.
const COMPACT_MIN_FREE_BYTES: u64 = if cfg!(test) { 64 << 10 } else { 64 << 20 };

const INSTALL_SCRIPT: &str =
    "curl -fsSL https://raw.githubusercontent.com/BehiSecc/HuntProxy/master/install.sh | bash";

/// How `Db::open` may upgrade an older database.
#[derive(Clone, Debug, Default)]
pub struct UpgradeOptions {
    /// An installer saved a restore point of the database moments ago, so the
    /// upgrade makes no backup of its own.
    pub restore_point_saved: bool,
    /// Upgrade work that has not finished by then is abandoned: a migration
    /// rolls back and fails, a compaction is skipped.
    pub deadline: Option<Instant>,
}

impl UpgradeOptions {
    /// For `prepare-update`, which installers run after they save a restore
    /// point. Call it when the process starts: an older installer's time limit
    /// runs from then.
    pub fn for_release_preparation() -> Self {
        let watched = std::env::var_os(WATCHED_UPGRADE_ENV).is_some();
        Self {
            restore_point_saved: true,
            deadline: (!watched).then(|| Instant::now() + UNWATCHED_PREPARATION_BUDGET),
        }
    }

    /// A watched release preparation also compacts a database that an earlier,
    /// time-limited upgrade could not.
    fn compacts_without_migrating(&self) -> bool {
        self.restore_point_saved && self.deadline.is_none()
    }
}

/// The file a database upgrade touches every few seconds while it works.
pub fn upgrade_progress_path(config: &Config) -> PathBuf {
    config.runtime_dir.join("database-upgrade.progress")
}

/// Decides when to stop waiting for a process that may be upgrading the
/// database: after 15 minutes, unless the upgrade keeps reporting progress.
pub struct UpgradeWait {
    started: Instant,
    progress: PathBuf,
}

impl UpgradeWait {
    pub fn new(config: &Config) -> Self {
        Self {
            started: Instant::now(),
            progress: upgrade_progress_path(config),
        }
    }

    pub fn expired(&self) -> bool {
        let waited = self.started.elapsed();
        if waited < BASE_WAIT {
            return false;
        }
        waited >= LONGEST_WAIT || !progressed_within(&self.progress, STALL_LIMIT)
    }
}

fn progressed_within(path: &Path, window: Duration) -> bool {
    let Ok(modified) = std::fs::metadata(path).and_then(|metadata| metadata.modified()) else {
        return false;
    };
    // A modification time ahead of the clock counts as recent.
    SystemTime::now()
        .duration_since(modified)
        .map_or(true, |age| age <= window)
}

pub(crate) struct UpgradePaths {
    pub database: PathBuf,
    pub backups: PathBuf,
    pub progress: PathBuf,
}

/// Migrates `conn`'s database to the current schema. An older database is
/// first checked for room and backed up, and compacted afterwards when the
/// upgrade left much of it free.
pub(crate) fn run(
    conn: &mut Connection,
    paths: &UpgradePaths,
    options: &UpgradeOptions,
) -> DomainResult<()> {
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(storage_error)?;
    let version = migrations::schema_version(conn)?;
    let upgrading = version > 0 && version < migrations::current_schema_version();
    if !upgrading && !options.compacts_without_migrating() {
        // A new database migrates in moments; a newer one is refused.
        migrations::migrate(conn)?;
        return Ok(());
    }
    let progress = Progress::start(conn, &paths.progress, options.deadline)?;
    let result = (|| {
        if upgrading {
            upgrade(conn, paths, options, version, &progress)?;
        } else {
            migrations::migrate(conn)?;
        }
        if version < COMPACTING_SCHEMA || options.compacts_without_migrating() {
            progress.stage("compacting the database");
            if let Err(error) = compact(conn, &paths.database, &progress) {
                tracing::warn!(%error, "did not compact the database");
            }
        }
        Ok(())
    })();
    progress.finish(conn);
    result
}

fn upgrade(
    conn: &mut Connection,
    paths: &UpgradePaths,
    options: &UpgradeOptions,
    version: i32,
    progress: &Progress,
) -> DomainResult<()> {
    let size = database_bytes(conn)?;
    let backup = !options.restore_point_saved;
    // Migration 018 writes the new header tables, about a quarter of a
    // header-heavy database, once into the WAL and once into the file.
    let growth = if version < COMPACTING_SCHEMA {
        size / 5 * 3
    } else {
        0
    };
    let needed = growth + if backup { size } else { 0 } + SPACE_MARGIN;
    let available = free_space(&paths.database)?;
    if available < needed {
        return Err(DomainError::new(
            ErrorCode::MigrationError,
            format!(
                "not enough free disk space to upgrade the {} database: it needs about {} free next to {}, and {} is available. Free some space and retry; nothing was changed",
                human_bytes(size),
                human_bytes(needed),
                paths.database.display(),
                human_bytes(available)
            ),
        ));
    }
    if backup {
        progress.stage("backing up the database");
        backup_before_migration(conn, &paths.backups, version, progress)?;
    }
    progress.stage("upgrading the database");
    tracing::info!(
        size = %human_bytes(size),
        "upgrading the database; a large one can take a while"
    );
    migrations::migrate(conn).map_err(|error| {
        if progress.out_of_time() {
            DomainError::new(
                ErrorCode::MigrationError,
                format!(
                    "upgrading the {} database takes longer than older HuntProxy releases wait during an update, so it was stopped and nothing was changed. Install this release with the install script, which waits for the upgrade: {INSTALL_SCRIPT}",
                    human_bytes(size)
                ),
            )
        } else {
            error
        }
    })?;
    checkpoint(conn);
    prune_backups(&paths.backups);
    Ok(())
}

fn backup_before_migration(
    source: &Connection,
    directory: &Path,
    version: i32,
    progress: &Progress,
) -> DomainResult<()> {
    crate::config::create_private_dir(directory)?;
    let path = directory.join(format!("schema-{version}-{}.sqlite3", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut target = Connection::open(&path)?;
        copy_pages(source, &mut target, progress)?;
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

/// Rewrites the database without its free pages: `VACUUM INTO` a file next
/// to it, then copies that back through the backup API, so a connection in
/// another process still sees one consistent database. On any failure the
/// database is left as it was.
fn compact(conn: &mut Connection, database: &Path, progress: &Progress) -> anyhow::Result<()> {
    let (pages, free, page_size) = page_counts(conn)?;
    if free * COMPACT_FREE_SHARE < pages || free * page_size < COMPACT_MIN_FREE_BYTES {
        return Ok(());
    }
    let live = (pages - free) * page_size;
    // The compacted copy, and the WAL that copying it back writes.
    let needed = 2 * live + SPACE_MARGIN;
    let available = free_space(database)?;
    if available < needed {
        anyhow::bail!(
            "compacting needs about {} free, and {} is available",
            human_bytes(needed),
            human_bytes(available)
        );
    }
    let Some(name) = database.file_name().and_then(|name| name.to_str()) else {
        anyhow::bail!("the database file name is not UTF-8");
    };
    let copy = database.with_file_name(format!("{name}.compacting"));
    let Some(copy_name) = copy.to_str() else {
        anyhow::bail!("the database path is not UTF-8");
    };
    let started = Instant::now();
    let before = pages * page_size;
    let remove_copy = || {
        for suffix in ["", "-journal", "-wal", "-shm"] {
            remove_if_present(Path::new(&format!("{copy_name}{suffix}")))?;
        }
        Ok::<_, std::io::Error>(())
    };
    let result = (|| {
        remove_copy()?;
        // VACUUM INTO accepts an empty file; creating it first keeps it private.
        crate::config::write_private_file(&copy, b"")?;
        conn.execute("VACUUM INTO ?1", [copy_name])?;
        let source = Connection::open_with_flags(&copy, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let schema = migrations::schema_version(&source)?;
        anyhow::ensure!(
            schema == migrations::schema_version(conn)?,
            "the compacted copy has schema {schema}"
        );
        copy_pages(&source, conn, progress)?;
        drop(source);
        checkpoint(conn);
        Ok(())
    })();
    if let Err(error) = remove_copy() {
        tracing::warn!(%error, path = %copy.display(), "could not remove the compacted copy");
    }
    if progress.out_of_time() {
        anyhow::bail!("out of time; a later update compacts it");
    }
    result?;
    let (pages, _, page_size) = page_counts(conn)?;
    tracing::info!(
        before = %human_bytes(before),
        after = %human_bytes(pages * page_size),
        seconds = started.elapsed().as_secs(),
        "compacted the database"
    );
    Ok(())
}

/// Copies every page of `source` into `target`, reporting progress between
/// steps. The copy commits only once it is complete.
fn copy_pages(
    source: &Connection,
    target: &mut Connection,
    progress: &Progress,
) -> anyhow::Result<()> {
    let backup = Backup::new(source, target)?;
    let mut busy_since = None;
    loop {
        match backup.step(4096)? {
            StepResult::Done => return Ok(()),
            StepResult::Busy | StepResult::Locked => {
                let since = *busy_since.get_or_insert_with(Instant::now);
                anyhow::ensure!(
                    since.elapsed() < Duration::from_secs(30),
                    "another connection kept the database busy"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => busy_since = None,
        }
        if progress.tick() {
            anyhow::bail!("interrupted");
        }
    }
}

/// Moves the WAL into the database and empties it, so a WAL as large as the
/// upgrade does not stay on disk.
fn checkpoint(conn: &Connection) {
    if let Err(error) = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())) {
        tracing::warn!(%error, "could not truncate the WAL after upgrading the database");
    }
}

/// Keeps only the newest pre-upgrade backup: each is a full copy.
fn prune_backups(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut backups: Vec<(SystemTime, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("schema-") && name.ends_with(".sqlite3")
        })
        .filter_map(|entry| {
            let metadata = entry
                .metadata()
                .ok()
                .filter(|metadata| metadata.is_file())?;
            Some((metadata.modified().ok()?, entry.path()))
        })
        .collect();
    backups.sort_by(|left, right| right.cmp(left));
    for (_, path) in backups.into_iter().skip(1) {
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::info!(path = %path.display(), "removed an older pre-upgrade backup"),
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "could not remove an older backup")
            }
        }
    }
}

/// Reports an upgrade's progress to whoever waits for it, and stops the work
/// at its deadline. SQLite calls it while statements run; long copies call it
/// between steps.
struct Progress {
    state: Arc<ProgressState>,
}

struct ProgressState {
    path: PathBuf,
    started: Instant,
    deadline: Option<Instant>,
    /// Milliseconds after `started` of the last write to `path`.
    written_at: AtomicU64,
    stage: parking_lot::Mutex<&'static str>,
    out_of_time: AtomicBool,
}

impl ProgressState {
    /// Returns true to stop the work.
    fn tick(&self) -> bool {
        if self.out_of_time.load(Ordering::Relaxed) {
            return true;
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.out_of_time.store(true, Ordering::Relaxed);
            return true;
        }
        let now = self.started.elapsed().as_millis() as u64;
        let last = self.written_at.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= 2_000
            && self
                .written_at
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.write();
        }
        false
    }

    fn write(&self) {
        let stage = *self.stage.lock();
        if let Err(error) = std::fs::write(&self.path, format!("{stage}\n")) {
            tracing::debug!(%error, "could not record database upgrade progress");
        }
    }
}

impl Progress {
    fn start(conn: &mut Connection, path: &Path, deadline: Option<Instant>) -> DomainResult<Self> {
        let state = Arc::new(ProgressState {
            path: path.to_path_buf(),
            started: Instant::now(),
            deadline,
            written_at: AtomicU64::new(0),
            stage: parking_lot::Mutex::new("opening the database"),
            out_of_time: AtomicBool::new(false),
        });
        state.write();
        let handler = Arc::clone(&state);
        conn.progress_handler(10_000, Some(move || handler.tick()))
            .map_err(storage_error)?;
        Ok(Self { state })
    }

    fn stage(&self, stage: &'static str) {
        *self.state.stage.lock() = stage;
        self.state.write();
    }

    fn tick(&self) -> bool {
        self.state.tick()
    }

    fn out_of_time(&self) -> bool {
        self.state.out_of_time.load(Ordering::Relaxed)
    }

    fn finish(self, conn: &mut Connection) {
        let _ = conn.progress_handler(0, None::<fn() -> bool>);
        let _ = remove_if_present(&self.state.path);
    }
}

fn page_counts(conn: &Connection) -> rusqlite::Result<(u64, u64, u64)> {
    let pragma = |name: &str| conn.pragma_query_value(None, name, |row| row.get::<_, i64>(0));
    Ok((
        pragma("page_count")? as u64,
        pragma("freelist_count")? as u64,
        pragma("page_size")? as u64,
    ))
}

fn database_bytes(conn: &Connection) -> DomainResult<u64> {
    let (pages, _, page_size) = page_counts(conn).map_err(storage_error)?;
    Ok(pages * page_size)
}

fn free_space(database: &Path) -> DomainResult<u64> {
    let directory = database
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let stat = nix::sys::statvfs::statvfs(directory).map_err(|error| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("check free disk space in {}: {error}", directory.display()),
        )
    })?;
    // The field types differ between Linux and macOS.
    #[allow(clippy::unnecessary_cast)]
    let bytes = stat.blocks_available() as u64 * stat.fragment_size() as u64;
    Ok(bytes)
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

fn human_bytes(bytes: u64) -> String {
    const GIB: f64 = (1u64 << 30) as f64;
    const MIB: f64 = (1u64 << 20) as f64;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.1} GB", bytes / GIB)
    } else {
        format!("{:.0} MB", (bytes / MIB).max(1.0))
    }
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::configure_connection;
    use crate::storage::Db;

    fn test_config(directory: &Path) -> Config {
        let config = Config {
            data_dir: directory.to_owned(),
            spool_dir: directory.join("spool"),
            export_dir: directory.join("exports"),
            runtime_dir: directory.join("runtime"),
            plugin_dir: directory.join("plugins"),
            ..Config::default()
        };
        config.ensure_layout().unwrap();
        config
    }

    type HeaderRow = (i64, i64, String, i64, String, Vec<u8>);

    fn header_rows(conn: &Connection) -> Vec<HeaderRow> {
        let mut statement = conn
            .prepare(
                "SELECT project_id, exchange_id, side, ordinal, name, value
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
                ))
            })
            .unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    }

    /// A schema-17 database whose old header table holds most of its pages:
    /// half the values repeat on every exchange, half are unique.
    fn header_heavy_database(config: &Config) -> Vec<HeaderRow> {
        let conn = Connection::open(config.db_path()).unwrap();
        configure_connection(&conn, "NORMAL", 5000).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        migrations::migrate(&conn).unwrap();
        conn.execute_batch(migrations::UNDO_020).unwrap();
        conn.execute_batch(migrations::UNDO_018).unwrap();
        conn.execute_batch(
            "INSERT INTO projects (name,created_at,updated_at,scope_json,limits_json)
                  VALUES ('p','t','t','{}','{}');
             WITH RECURSIVE e(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM e WHERE i < 2000)
             INSERT INTO exchanges (project_id, exchange_id, source, started_at, method, scheme,
                                    authority, host, port, path, completion, capture_quality,
                                    header_representation, body_representation)
             SELECT 1, i, 'proxy', 't', 'GET', 'https', 'a.test', 'a.test', 443, '/', 'complete',
                    'full', 'raw', 'raw' FROM e;
             WITH RECURSIVE e(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM e WHERE i < 2000),
                            h(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM h WHERE j < 19)
             INSERT INTO message_headers (project_id, exchange_id, side, ordinal, name, value)
             SELECT 1, i, CASE WHEN j < 10 THEN 'request' ELSE 'response' END, j, 'h' || j,
                    CASE WHEN j % 2 = 0 THEN CAST(hex(zeroblob(100)) || j AS BLOB)
                         ELSE randomblob(100) END
               FROM e, h;",
        )
        .unwrap();
        assert_eq!(migrations::schema_version(&conn).unwrap(), 17);
        header_rows(&conn)
    }

    fn file_len(path: &Path) -> u64 {
        std::fs::metadata(path).map_or(0, |metadata| metadata.len())
    }

    fn wal_path(config: &Config) -> PathBuf {
        PathBuf::from(format!("{}-wal", config.db_path().display()))
    }

    #[tokio::test]
    async fn an_upgrade_keeps_every_header_and_compacts_the_space_it_freed() {
        let directory = tempfile::tempdir().unwrap();
        let config = test_config(directory.path());
        let rows = header_heavy_database(&config);
        let before = file_len(&config.db_path());

        let db = Db::open(&config).await.unwrap();
        let (schema, after_rows, free, journal, check) = db
            .with_conn(|conn| {
                let pragma = |name: &str| {
                    conn.pragma_query_value(None, name, |row| row.get::<_, String>(0))
                        .unwrap()
                };
                Ok((
                    migrations::schema_version(conn)?,
                    header_rows(conn),
                    conn.pragma_query_value(None, "freelist_count", |row| row.get::<_, i64>(0))
                        .unwrap(),
                    pragma("journal_mode"),
                    pragma("quick_check"),
                ))
            })
            .await
            .unwrap();
        assert_eq!(schema, migrations::current_schema_version());
        assert_eq!(after_rows, rows);
        assert_eq!((journal.as_str(), check.as_str()), ("wal", "ok"));
        assert_eq!(free, 0, "the freed header pages were compacted away");
        let after = file_len(&config.db_path());
        assert!(after < before, "{after} bytes after, {before} before");
        assert_eq!(file_len(&wal_path(&config)), 0);

        // One backup of the old database, and nothing else left behind.
        let backups: Vec<_> = std::fs::read_dir(config.runtime_dir.join("migration-backups"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(backups.len(), 1);
        let backup = Connection::open(&backups[0]).unwrap();
        assert_eq!(migrations::schema_version(&backup).unwrap(), 17);
        assert_eq!(header_rows(&backup), rows);
        assert!(!upgrade_progress_path(&config).exists());
        let leftovers: Vec<_> = std::fs::read_dir(&config.data_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains("compacting"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[tokio::test]
    async fn a_preparation_out_of_time_stops_without_changing_the_database() {
        let directory = tempfile::tempdir().unwrap();
        let config = test_config(directory.path());
        let rows = header_heavy_database(&config);

        let error = Db::open_with(
            &config,
            UpgradeOptions {
                restore_point_saved: true,
                deadline: Some(Instant::now()),
            },
        )
        .await
        .err()
        .expect("the upgrade stops at its deadline");
        assert!(error.to_string().contains("install script"), "{error}");

        let conn = Connection::open(config.db_path()).unwrap();
        assert_eq!(migrations::schema_version(&conn).unwrap(), 17);
        assert_eq!(header_rows(&conn), rows);
        // The installer's restore point stands in for a backup.
        assert!(!config.runtime_dir.join("migration-backups").exists());
        assert!(!upgrade_progress_path(&config).exists());
    }

    #[tokio::test]
    async fn a_watched_preparation_compacts_a_current_database_that_is_mostly_free() {
        let directory = tempfile::tempdir().unwrap();
        let config = test_config(directory.path());
        let db = Db::open(&config).await.unwrap();
        db.with_conn(|conn| {
            conn.execute_batch(
                "CREATE TABLE filler (data BLOB);
                 WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 512)
                 INSERT INTO filler SELECT randomblob(4096) FROM n;
                 DROP TABLE filler;",
            )
            .and_then(|()| conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())))
            .map_err(storage_error)
        })
        .await
        .unwrap();
        drop(db);
        let before = file_len(&config.db_path());

        // An ordinary open leaves it alone; a watched release preparation compacts.
        drop(Db::open(&config).await.unwrap());
        assert_eq!(file_len(&config.db_path()), before);
        drop(
            Db::open_with(
                &config,
                UpgradeOptions {
                    restore_point_saved: true,
                    deadline: None,
                },
            )
            .await
            .unwrap(),
        );
        let after = file_len(&config.db_path());
        assert!(after * 4 < before, "{after} bytes after, {before} before");
    }

    #[test]
    fn only_the_newest_backup_is_kept() {
        let directory = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        for (name, age) in [
            ("schema-12-a.sqlite3", 300),
            ("schema-17-b.sqlite3", 10),
            ("schema-14-c.sqlite3", 100),
            ("notes.txt", 500),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, b"x").unwrap();
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(now - Duration::from_secs(age))
                .unwrap();
        }
        prune_backups(directory.path());
        let mut left: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["notes.txt", "schema-17-b.sqlite3"]);
    }

    #[test]
    fn only_recent_progress_extends_a_wait() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("progress");
        assert!(!progressed_within(&path, STALL_LIMIT));
        std::fs::write(&path, b"upgrading\n").unwrap();
        assert!(progressed_within(&path, STALL_LIMIT));
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(600))
            .unwrap();
        assert!(!progressed_within(&path, STALL_LIMIT));
    }
}
