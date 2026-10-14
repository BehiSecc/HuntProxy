//! Durable recovery for interruptions between release preparation and activation.

use crate::config::Config;
use crate::domain::{DomainError, DomainResult, ErrorCode};
use crate::update::DataSnapshot;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const JOURNAL_SCHEMA: u32 = 1;
const RESTORE_FORMAT: u32 = 1;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024;
const MAX_RESTORE_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SNAPSHOT_FILES: usize = 8;
const MAX_SNAPSHOT_PLUGINS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateJournal {
    schema_version: u32,
    source_version: String,
    target_version: String,
    installed_binary_path: PathBuf,
    snapshot_root: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreManifest {
    format: u32,
    version: String,
    data_dir: PathBuf,
    plugin_dir: PathBuf,
    database: PathBuf,
    plugins: Vec<(String, bool)>,
    snapshot: DataSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StableVersion(u64, u64, u64);

/// Record the restore point before the staged release mutates persisted data.
pub(crate) fn begin(
    config: &Config,
    source_version: &str,
    target_version: &str,
    installed_binary_path: &Path,
    snapshot_root: &Path,
) -> DomainResult<()> {
    let path = journal_path(config);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            return Err(recovery_error(
                "an unfinished update recovery journal already exists",
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(recovery_error(format!(
                "inspect update recovery journal: {error}"
            )))
        }
    }
    let source = StableVersion::parse(source_version)?;
    let target = StableVersion::parse(target_version)?;
    if source == target {
        return Err(recovery_error(
            "update recovery source and target versions must differ",
        ));
    }
    let binary = validate_binary_path(installed_binary_path)?;
    let snapshot_root = validate_restore_point(config, snapshot_root, Some(target))?.root;
    let journal = UpdateJournal {
        schema_version: JOURNAL_SCHEMA,
        source_version: source_version.to_string(),
        target_version: target_version.to_string(),
        installed_binary_path: binary,
        snapshot_root,
    };
    let encoded = serde_json::to_vec_pretty(&journal)
        .map_err(|error| recovery_error(format!("encode update recovery journal: {error}")))?;
    atomic_private_write(&path, &encoded)
}

/// Recover a prepared-but-not-activated update, or commit an activated update.
///
/// The caller owns the bootstrap maintenance lock. Ambiguous state is returned
/// as an error and leaves the journal and restore point untouched.
pub(crate) async fn recover(config: &Config) -> DomainResult<()> {
    let path = journal_path(config);
    let Some(journal) = read_journal(&path)? else {
        return Ok(());
    };
    let source = StableVersion::parse(&journal.source_version)?;
    let target = StableVersion::parse(&journal.target_version)?;
    if source == target {
        return Err(recovery_error(
            "update recovery source and target versions are identical",
        ));
    }
    let binary = validate_binary_path(&journal.installed_binary_path)?;
    let restore = validate_restore_point(config, &journal.snapshot_root, Some(target))?;
    let installed = inspect_binary_version(&binary).await?;

    if installed == target {
        if let Err(error) = prune_restore_points(config, Some(&restore.root)) {
            tracing::warn!(%error, "activated update restore point cleanup will be retried");
        } else if let Err(error) = finish(config) {
            tracing::warn!(%error, "activated update journal cleanup will be retried");
        }
        return Ok(());
    }
    if installed == source {
        restore.snapshot.restore(config)?;
        prune_restore_points(config, Some(&restore.root))?;
        return finish(config);
    }
    Err(recovery_error(format!(
        "installed HuntProxy version does not match update recovery source {} or target {}",
        journal.source_version, journal.target_version
    )))
}

/// Remove a completed journal durably. Missing journals are already finished.
pub(crate) fn finish(config: &Config) -> DomainResult<()> {
    let path = journal_path(config);
    match fs::remove_file(&path) {
        Ok(()) => sync_directory(&config.runtime_dir),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(recovery_error(format!(
            "remove update recovery journal {}: {error}",
            path.display()
        ))),
    }
}

/// Retain one validated restore point and remove only older, owned snapshots.
pub(crate) fn prune_restore_points(config: &Config, keep_root: Option<&Path>) -> DomainResult<()> {
    let updates = updates_root(config);
    let entries = match fs::read_dir(&updates) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(recovery_error(format!(
                "read update restore points {}: {error}",
                updates.display()
            )))
        }
    };

    let explicit_keep = keep_root
        .map(|path| validate_restore_point(config, path, None).map(|point| point.root))
        .transpose()?;
    let mut valid = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| recovery_error(format!("read update restore point entry: {error}")))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| recovery_error(format!("inspect update restore point: {error}")))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let point = match validate_restore_point(config, &entry.path(), None) {
            Ok(point) => point,
            Err(_) => continue,
        };
        let modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
        valid.push((point.root, modified));
    }
    valid.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let keep = explicit_keep.or_else(|| valid.first().map(|entry| entry.0.clone()));
    for (root, _) in valid {
        if keep.as_ref() == Some(&root) {
            continue;
        }
        fs::remove_dir_all(&root).map_err(|error| {
            recovery_error(format!("remove restore point {}: {error}", root.display()))
        })?;
    }
    sync_directory(&updates)
}

struct ValidatedRestorePoint {
    root: PathBuf,
    snapshot: DataSnapshot,
}

fn validate_restore_point(
    config: &Config,
    requested_root: &Path,
    expected_version: Option<StableVersion>,
) -> DomainResult<ValidatedRestorePoint> {
    let updates = canonical_directory(&updates_root(config), "update restore directory")?;
    let metadata = fs::symlink_metadata(requested_root)
        .map_err(|error| recovery_error(format!("inspect update restore point: {error}")))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(recovery_error(
            "update restore point must be a private regular directory",
        ));
    }
    require_private(&metadata, "update restore point")?;
    let root = requested_root
        .canonicalize()
        .map_err(|error| recovery_error(format!("resolve update restore point: {error}")))?;
    if root.parent() != Some(updates.as_path()) {
        return Err(recovery_error(
            "update restore point is outside the managed update directory",
        ));
    }

    let manifest_path = root.join("restore.json");
    let encoded = read_bounded_regular_file(
        &manifest_path,
        MAX_RESTORE_MANIFEST_BYTES,
        "update restore manifest",
    )?;
    let manifest: RestoreManifest = serde_json::from_slice(&encoded)
        .map_err(|error| recovery_error(format!("parse update restore manifest: {error}")))?;
    if manifest.format != RESTORE_FORMAT {
        return Err(recovery_error("unsupported update restore manifest format"));
    }
    let version = StableVersion::parse(&manifest.version)?;
    if expected_version.is_some_and(|expected| expected != version) {
        return Err(recovery_error(
            "update restore manifest version does not match the journal target",
        ));
    }
    validate_restore_root_name(&root, version)?;
    if clean_absolute(&manifest.data_dir)? != clean_absolute(&config.data_dir)?
        || clean_absolute(&manifest.plugin_dir)? != clean_absolute(&config.plugin_dir)?
        || clean_absolute(&manifest.database)? != clean_absolute(&config.db_path())?
    {
        return Err(recovery_error(
            "update restore manifest does not match the active data directory",
        ));
    }
    if manifest.plugins != manifest.snapshot.plugins {
        return Err(recovery_error(
            "update restore manifest plugin identity does not match its snapshot",
        ));
    }
    validate_snapshot(config, &root, &manifest.snapshot)?;
    Ok(ValidatedRestorePoint {
        root,
        snapshot: manifest.snapshot,
    })
}

fn validate_restore_root_name(root: &Path, version: StableVersion) -> DomainResult<()> {
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| recovery_error("update restore point has an invalid name"))?;
    let prefix = format!("v{}.{}.{}-", version.0, version.1, version.2);
    let identifier = name
        .strip_prefix(&prefix)
        .ok_or_else(|| recovery_error("update restore point name does not match its manifest"))?;
    let parsed = uuid::Uuid::parse_str(identifier)
        .map_err(|_| recovery_error("update restore point has an invalid identifier"))?;
    if parsed.hyphenated().to_string() != identifier {
        return Err(recovery_error(
            "update restore point has a non-canonical identifier",
        ));
    }
    Ok(())
}

fn validate_snapshot(config: &Config, root: &Path, snapshot: &DataSnapshot) -> DomainResult<()> {
    if clean_absolute(&snapshot.root)? != clean_absolute(root)? {
        return Err(recovery_error(
            "update restore snapshot root does not match its manifest",
        ));
    }
    if snapshot.files.len() > MAX_SNAPSHOT_FILES {
        return Err(recovery_error("update restore snapshot has too many files"));
    }
    let expected = [
        (
            clean_absolute(&config.db_path())?,
            root.join("database.sqlite3"),
        ),
        (
            clean_absolute(&config.data_dir.join("config.toml"))?,
            root.join("config.toml"),
        ),
        (
            clean_absolute(&config.plugin_dir.join(".huntproxy-first-party-source"))?,
            root.join("plugin-source"),
        ),
    ];
    let mut destinations = BTreeSet::new();
    for (destination, source) in &snapshot.files {
        let destination = clean_absolute(destination)?;
        if !destinations.insert(destination.clone()) {
            return Err(recovery_error(
                "update restore snapshot contains a duplicate destination",
            ));
        }
        let Some((_, expected_source)) = expected
            .iter()
            .find(|(expected_destination, _)| *expected_destination == destination)
        else {
            return Err(recovery_error(
                "update restore snapshot contains an unmanaged destination",
            ));
        };
        if let Some(source) = source {
            if clean_absolute(source)? != clean_absolute(expected_source)? {
                return Err(recovery_error(
                    "update restore snapshot contains an unmanaged source",
                ));
            }
            validate_regular_file(source, "update restore data file")?;
        }
    }
    if destinations.len() != expected.len() {
        return Err(recovery_error(
            "update restore snapshot does not describe every managed data file",
        ));
    }

    if snapshot.plugins.len() > MAX_SNAPSHOT_PLUGINS {
        return Err(recovery_error(
            "update restore snapshot has too many plugins",
        ));
    }
    let mut plugins = BTreeSet::new();
    for (name, existed) in &snapshot.plugins {
        if !valid_package_name(name) || !plugins.insert(name.as_str()) {
            return Err(recovery_error(
                "update restore snapshot contains an invalid plugin name",
            ));
        }
        if *existed {
            let backup = root.join("plugins").join(name);
            let metadata = fs::symlink_metadata(&backup).map_err(|error| {
                recovery_error(format!("inspect plugin restore data {name}: {error}"))
            })?;
            if !metadata.is_dir() && !metadata.file_type().is_symlink() {
                return Err(recovery_error(format!(
                    "plugin restore data {name} is not a directory"
                )));
            }
        }
    }
    Ok(())
}

fn read_journal(path: &Path) -> DomainResult<Option<UpdateJournal>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(recovery_error(format!(
                "inspect update recovery journal: {error}"
            )))
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(recovery_error(
            "update recovery journal must be a private regular file",
        ));
    }
    require_private(&metadata, "update recovery journal")?;
    let encoded = read_bounded_regular_file(path, MAX_JOURNAL_BYTES, "update recovery journal")?;
    let journal: UpdateJournal = serde_json::from_slice(&encoded)
        .map_err(|error| recovery_error(format!("parse update recovery journal: {error}")))?;
    if journal.schema_version != JOURNAL_SCHEMA {
        return Err(recovery_error(format!(
            "unsupported update recovery journal schema {}",
            journal.schema_version
        )));
    }
    Ok(Some(journal))
}

async fn inspect_binary_version(path: &Path) -> DomainResult<StableVersion> {
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        crate::update::binary_output(path, &["--version"]),
    )
    .await
    .map_err(|_| recovery_error("installed binary version check timed out"))?
    .map_err(|error| recovery_error(format!("run installed binary version check: {error}")))?;
    if !output.status.success() || output.stdout.len() > 256 {
        return Err(recovery_error(
            "installed binary failed its bounded version check",
        ));
    }
    let output = std::str::from_utf8(&output.stdout)
        .map_err(|_| recovery_error("installed binary returned an invalid version"))?;
    let mut fields = output.split_whitespace();
    if fields.next() != Some("HuntProxy") {
        return Err(recovery_error(
            "installed binary returned an invalid version",
        ));
    }
    let version = fields
        .next()
        .ok_or_else(|| recovery_error("installed binary returned an invalid version"))?;
    if fields.next().is_some() {
        return Err(recovery_error(
            "installed binary returned an invalid version",
        ));
    }
    StableVersion::parse(version)
}

impl StableVersion {
    fn parse(value: &str) -> DomainResult<Self> {
        let value = value.strip_prefix('v').unwrap_or(value);
        let mut parts = value.split('.');
        let mut parse = || {
            parts
                .next()
                .filter(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|part| part.parse::<u64>().ok())
                .ok_or_else(|| recovery_error("invalid stable version in update recovery metadata"))
        };
        let version = Self(parse()?, parse()?, parse()?);
        if parts.next().is_some() {
            return Err(recovery_error(
                "invalid stable version in update recovery metadata",
            ));
        }
        Ok(version)
    }
}

fn validate_binary_path(path: &Path) -> DomainResult<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| recovery_error(format!("inspect installed binary: {error}")))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(recovery_error(
            "installed binary path is not a regular file",
        ));
    }
    path.canonicalize()
        .map_err(|error| recovery_error(format!("resolve installed binary: {error}")))
}

fn canonical_directory(path: &Path, label: &str) -> DomainResult<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| recovery_error(format!("inspect {label}: {error}")))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(recovery_error(format!(
            "{label} is not a regular directory"
        )));
    }
    path.canonicalize()
        .map_err(|error| recovery_error(format!("resolve {label}: {error}")))
}

fn read_bounded_regular_file(path: &Path, limit: u64, label: &str) -> DomainResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| recovery_error(format!("inspect {label}: {error}")))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(recovery_error(format!(
            "{label} is not a bounded regular file"
        )));
    }
    let file =
        File::open(path).map_err(|error| recovery_error(format!("open {label}: {error}")))?;
    let capacity = usize::try_from(metadata.len().min(limit.min(4 * 1024 * 1024))).unwrap_or(0);
    let mut encoded = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut encoded)
        .map_err(|error| recovery_error(format!("read {label}: {error}")))?;
    if encoded.len() as u64 > limit {
        return Err(recovery_error(format!("{label} exceeds its size limit")));
    }
    Ok(encoded)
}

fn validate_regular_file(path: &Path, label: &str) -> DomainResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| recovery_error(format!("inspect {label}: {error}")))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(recovery_error(format!("{label} is not a regular file")));
    }
    Ok(())
}

fn atomic_private_write(path: &Path, data: &[u8]) -> DomainResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| recovery_error("update recovery journal has no parent directory"))?;
    crate::config::create_private_dir(parent)?;
    let temporary = parent.join(format!(".update-journal-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|error| recovery_error(format!("create update recovery journal: {error}")))?;
        file.write_all(data)
            .map_err(|error| recovery_error(format!("write update recovery journal: {error}")))?;
        file.sync_all()
            .map_err(|error| recovery_error(format!("sync update recovery journal: {error}")))?;
        fs::rename(&temporary, path)
            .map_err(|error| recovery_error(format!("commit update recovery journal: {error}")))?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn sync_directory(path: &Path) -> DomainResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| recovery_error(format!("sync {}: {error}", path.display())))
}

fn clean_absolute(path: &Path) -> DomainResult<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| recovery_error(format!("resolve current directory: {error}")))?
            .join(path)
    };
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => clean.push(prefix.as_os_str()),
            Component::RootDir => clean.push(Path::new("/")),
            Component::CurDir => {}
            Component::Normal(part) => clean.push(part),
            Component::ParentDir => {
                if !clean.pop() {
                    return Err(recovery_error("update recovery path escapes its root"));
                }
            }
        }
    }
    Ok(clean)
}

fn valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn require_private(metadata: &fs::Metadata, label: &str) -> DomainResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(recovery_error(format!(
                "{label} permissions are not private"
            )));
        }
    }
    Ok(())
}

fn journal_path(config: &Config) -> PathBuf {
    config.runtime_dir.join("update-journal.json")
}

fn updates_root(config: &Config) -> PathBuf {
    config.runtime_dir.join("updates")
}

fn recovery_error(message: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::Unavailable, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{create_private_dir, write_private_file};
    use serde_json::{json, Value};
    use std::sync::OnceLock;
    use tempfile::TempDir;

    fn test_root() -> &'static Path {
        static ROOT: OnceLock<PathBuf> = OnceLock::new();
        ROOT.get_or_init(|| {
            let root = PathBuf::from("/tmp/artis/huntproxy-update-journal-tests");
            fs::create_dir_all(&root).unwrap();
            root
        })
    }

    fn directory() -> TempDir {
        tempfile::Builder::new()
            .prefix("journal-")
            .tempdir_in(test_root())
            .unwrap()
    }

    fn config(directory: &TempDir) -> Config {
        let root = directory.path().join("data");
        let config = Config {
            data_dir: root.clone(),
            spool_dir: root.join("spool"),
            export_dir: root.join("exports"),
            runtime_dir: root.join("runtime"),
            plugin_dir: root.join("plugins"),
            ..Config::default()
        };
        config.ensure_layout().unwrap();
        config
    }

    fn binary(directory: &TempDir, version: &str) -> PathBuf {
        let path = directory.path().join("HuntProxy");
        fs::write(
            &path,
            format!("#!/bin/sh\nprintf 'HuntProxy {version}\\n'\n"),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn snapshot(config: &Config, version: &str) -> DataSnapshot {
        write_private_file(&config.db_path(), b"source database").unwrap();
        write_private_file(&config.data_dir.join("config.toml"), b"source config").unwrap();
        let plugin = config.plugin_dir.join("racer");
        create_private_dir(&plugin).unwrap();
        write_private_file(&plugin.join("index.js"), b"source plugin").unwrap();

        let root = updates_root(config).join(format!("v{version}-{}", uuid::Uuid::new_v4()));
        create_private_dir(&root).unwrap();
        write_private_file(&root.join("database.sqlite3"), b"source database").unwrap();
        write_private_file(&root.join("config.toml"), b"source config").unwrap();
        let plugin_backup = root.join("plugins/racer");
        create_private_dir(&plugin_backup).unwrap();
        write_private_file(&plugin_backup.join("index.js"), b"source plugin").unwrap();
        let snapshot = DataSnapshot {
            root: root.clone(),
            files: vec![
                (config.db_path(), Some(root.join("database.sqlite3"))),
                (
                    config.data_dir.join("config.toml"),
                    Some(root.join("config.toml")),
                ),
                (
                    config.plugin_dir.join(".huntproxy-first-party-source"),
                    None,
                ),
            ],
            plugins: vec![("racer".into(), true), ("new-package".into(), false)],
        };
        write_manifest(config, version, &snapshot);
        snapshot
    }

    fn write_manifest(config: &Config, version: &str, snapshot: &DataSnapshot) {
        write_private_file(
            &snapshot.root.join("restore.json"),
            &serde_json::to_vec_pretty(&json!({
                "format": RESTORE_FORMAT,
                "version": format!("v{version}"),
                "data_dir": config.data_dir,
                "plugin_dir": config.plugin_dir,
                "database": config.db_path(),
                "plugins": snapshot.plugins,
                "snapshot": snapshot,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn prepared_interruption_restores_source_state_idempotently() {
        let directory = directory();
        let config = config(&directory);
        let snapshot = snapshot(&config, "0.2.0");
        let binary = binary(&directory, "0.1.1");
        begin(&config, "0.1.1", "0.2.0", &binary, &snapshot.root).unwrap();
        fs::write(config.db_path(), b"migrated database").unwrap();
        fs::write(config.data_dir.join("config.toml"), b"new config").unwrap();
        fs::write(config.plugin_dir.join("racer/index.js"), b"new plugin").unwrap();
        let new_package = config.plugin_dir.join("new-package");
        create_private_dir(&new_package).unwrap();
        write_private_file(&new_package.join("index.js"), b"new package").unwrap();

        recover(&config).await.unwrap();
        assert_eq!(fs::read(config.db_path()).unwrap(), b"source database");
        assert_eq!(
            fs::read(config.data_dir.join("config.toml")).unwrap(),
            b"source config"
        );
        assert_eq!(
            fs::read(config.plugin_dir.join("racer/index.js")).unwrap(),
            b"source plugin"
        );
        assert!(!new_package.exists());
        assert!(!journal_path(&config).exists());
        recover(&config).await.unwrap();
    }

    #[tokio::test]
    async fn activated_interruption_commits_and_prunes_only_owned_points() {
        let directory = directory();
        let config = config(&directory);
        let old = snapshot(&config, "0.1.9");
        let latest = snapshot(&config, "0.2.0");
        let arbitrary = updates_root(&config).join("user-notes");
        create_private_dir(&arbitrary).unwrap();
        write_private_file(&arbitrary.join("keep.txt"), b"mine").unwrap();
        let binary = binary(&directory, "0.2.0");
        begin(&config, "0.1.1", "0.2.0", &binary, &latest.root).unwrap();
        fs::write(config.db_path(), b"target database").unwrap();

        recover(&config).await.unwrap();
        assert_eq!(fs::read(config.db_path()).unwrap(), b"target database");
        assert!(latest.root.exists());
        assert!(!old.root.exists());
        assert_eq!(fs::read(arbitrary.join("keep.txt")).unwrap(), b"mine");
        assert!(!journal_path(&config).exists());
    }

    #[tokio::test]
    async fn malformed_or_future_metadata_never_restores_or_escapes() {
        let directory = directory();
        let config = config(&directory);
        let snapshot = snapshot(&config, "0.2.0");
        let binary = binary(&directory, "0.1.1");
        begin(&config, "0.1.1", "0.2.0", &binary, &snapshot.root).unwrap();
        fs::write(config.db_path(), b"do not restore").unwrap();
        let outside = directory.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        let mut journal: Value =
            serde_json::from_slice(&fs::read(journal_path(&config)).unwrap()).unwrap();
        journal["schemaVersion"] = json!(2);
        write_private_file(
            &journal_path(&config),
            &serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        assert!(recover(&config).await.is_err());
        assert_eq!(fs::read(config.db_path()).unwrap(), b"do not restore");
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
        assert!(journal_path(&config).exists());

        journal["schemaVersion"] = json!(JOURNAL_SCHEMA);
        journal["snapshotRoot"] = json!(directory.path().join("outside-snapshot"));
        write_private_file(
            &journal_path(&config),
            &serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        assert!(recover(&config).await.is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
        assert!(journal_path(&config).exists());

        journal["snapshotRoot"] = json!(snapshot.root);
        write_private_file(
            &journal_path(&config),
            &serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        let manifest_path = snapshot.root.join("restore.json");
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["snapshot"]["files"][0][0] = json!(outside);
        write_private_file(&manifest_path, &serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(recover(&config).await.is_err());
        assert_eq!(fs::read(config.db_path()).unwrap(), b"do not restore");
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
        assert!(journal_path(&config).exists());
    }

    #[tokio::test]
    async fn unexpected_installed_version_keeps_recovery_metadata() {
        let directory = directory();
        let config = config(&directory);
        let snapshot = snapshot(&config, "0.2.0");
        let binary = binary(&directory, "0.3.0");
        begin(&config, "0.1.1", "0.2.0", &binary, &snapshot.root).unwrap();
        fs::write(config.db_path(), b"ambiguous").unwrap();

        assert!(recover(&config).await.is_err());
        assert_eq!(fs::read(config.db_path()).unwrap(), b"ambiguous");
        assert!(journal_path(&config).exists());
    }
}
