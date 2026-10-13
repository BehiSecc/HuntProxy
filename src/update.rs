//! Check and install verified HuntProxy GitHub Release binaries.

use crate::app;
use crate::config::Config;
use crate::domain::{DomainError, DomainResult, ErrorCode};
use flate2::read::GzDecoder;
use futures::StreamExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const REPOSITORY: &str = "BehiSecc/HuntProxy";
const GITHUB_API: &str = "https://api.github.com";
const GITHUB_DOWNLOADS: &str = "https://github.com";
const MAX_RELEASE_JSON_BYTES: u64 = 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 192 * 1024 * 1024;
const MAX_LICENSE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct UpdateRequest {
    pub check: bool,
    pub version: Option<String>,
    pub data_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    UpToDate {
        current: String,
    },
    Available {
        current: String,
        target: String,
    },
    CurrentNewer {
        current: String,
        target: String,
    },
    Installed {
        previous: String,
        installed: String,
        backup_path: PathBuf,
        data_backup_path: Option<PathBuf>,
        daemon_restarted: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct StableVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl StableVersion {
    fn parse(value: &str) -> DomainResult<Self> {
        let value = value.strip_prefix('v').unwrap_or(value);
        let mut parts = value.split('.');
        let major = parse_version_part(parts.next())?;
        let minor = parse_version_part(parts.next())?;
        let patch = parse_version_part(parts.next())?;
        if parts.next().is_some() {
            return Err(invalid_version());
        }
        Ok(Self {
            major,
            minor,
            patch,
        })
    }

    fn tag(self) -> String {
        format!("v{self}")
    }
}

impl fmt::Display for StableVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn parse_version_part(value: Option<&str>) -> DomainResult<u64> {
    let value =
        value.filter(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    value
        .and_then(|part| part.parse().ok())
        .ok_or_else(invalid_version)
}

fn invalid_version() -> DomainError {
    DomainError::invalid("version must be a stable semantic version such as v0.2.0")
}

#[derive(Debug, Clone)]
struct ReleaseSource {
    api_base: String,
    download_base: String,
    allow_http: bool,
}

impl ReleaseSource {
    fn production() -> DomainResult<Self> {
        Ok(Self {
            api_base: GITHUB_API.into(),
            download_base: GITHUB_DOWNLOADS.into(),
            allow_http: false,
        })
    }

    #[cfg(test)]
    fn test_source(base: &str) -> DomainResult<Self> {
        let parsed = url::Url::parse(base)
            .map_err(|_| DomainError::invalid("invalid updater test base URL"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(DomainError::invalid("invalid updater test base URL"));
        }
        let base = base.trim_end_matches('/').to_string();
        Ok(Self {
            api_base: base.clone(),
            download_base: base,
            allow_http: true,
        })
    }

    fn release_api_url(&self, requested_tag: Option<&str>) -> String {
        match requested_tag {
            Some(tag) => format!("{}/repos/{REPOSITORY}/releases/tags/{tag}", self.api_base),
            None => format!("{}/repos/{REPOSITORY}/releases/latest", self.api_base),
        }
    }

    fn release_asset_url(&self, tag: &str, name: &str) -> String {
        format!(
            "{}/{REPOSITORY}/releases/download/{tag}/{name}",
            self.download_base
        )
    }
}

#[derive(Debug)]
struct UpdateContext {
    source: ReleaseSource,
    executable: PathBuf,
    current_version: StableVersion,
    os: &'static str,
    arch: &'static str,
}

impl UpdateContext {
    fn production() -> DomainResult<Self> {
        let executable = std::env::current_exe()
            .and_then(fs::canonicalize)
            .map_err(|error| update_error(format!("resolve current executable: {error}")))?;
        Ok(Self {
            source: ReleaseSource::production()?,
            executable,
            current_version: StableVersion::parse(env!("CARGO_PKG_VERSION"))?,
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        })
    }
}

#[derive(Debug, Deserialize)]
struct ReleaseResponse {
    tag_name: String,
}

pub async fn run(request: UpdateRequest) -> DomainResult<UpdateOutcome> {
    run_with_context(request, UpdateContext::production()?).await
}

async fn run_with_context(
    request: UpdateRequest,
    context: UpdateContext,
) -> DomainResult<UpdateOutcome> {
    #[cfg(not(unix))]
    return Err(update_error(
        "self-update currently supports Linux and macOS only",
    ));

    let client = update_client(context.source.allow_http)?;
    let requested = request
        .version
        .as_deref()
        .map(StableVersion::parse)
        .transpose()?;
    let release = resolve_release(&client, &context.source, requested).await?;
    let target = StableVersion::parse(&release.tag_name)?;
    if Some(target) != requested && requested.is_some() {
        return Err(update_error(format!(
            "GitHub returned release {} for requested {}",
            release.tag_name,
            requested.unwrap()
        )));
    }
    let current_text = context.current_version.to_string();
    let target_text = target.to_string();

    if target == context.current_version {
        return Ok(UpdateOutcome::UpToDate {
            current: current_text,
        });
    }
    if request.check {
        return if target > context.current_version {
            Ok(UpdateOutcome::Available {
                current: current_text,
                target: target_text,
            })
        } else {
            Ok(UpdateOutcome::CurrentNewer {
                current: current_text,
                target: target_text,
            })
        };
    }
    if requested.is_none() && target < context.current_version {
        return Ok(UpdateOutcome::CurrentNewer {
            current: current_text,
            target: target_text,
        });
    }

    let coordinated = target
        >= StableVersion {
            major: 0,
            minor: 2,
            patch: 0,
        };
    let daemon_config = if coordinated {
        Config::load(request.data_dir.clone())?
    } else {
        daemon_config(request.data_dir)
    };
    if !coordinated {
        ensure_daemon_stopped(&daemon_config)?;
        if daemon_config.db_path().exists() {
            let database = rusqlite::Connection::open_with_flags(
                daemon_config.db_path(),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(|error| update_error(format!("inspect database compatibility: {error}")))?;
            let schema = crate::storage::schema_version(&database)?;
            if schema > 14 {
                return Err(update_error("this data directory requires HuntProxy 0.2 or newer; downgrading would make saved projects unavailable"));
            }
        }
    }
    let executable = &context.executable;
    let metadata = fs::metadata(executable)
        .map_err(|error| update_error(format!("inspect current executable: {error}")))?;
    if !metadata.is_file() {
        return Err(update_error("current executable is not a regular file"));
    }
    let parent = executable
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| update_error("current executable has no parent directory"))?;
    let _lock = UpdateLock::acquire(parent)?;
    let initial_hash = hash_file(executable)?;
    let asset_name = asset_name(context.os, context.arch)?;

    let checksums = download_bytes(
        &client,
        &context
            .source
            .release_asset_url(&target.tag(), "SHA256SUMS"),
        MAX_CHECKSUM_BYTES,
    )
    .await?;
    let expected_hash = parse_checksum(&checksums, asset_name)?;

    let (archive_path, archive_file) = create_temp_file(parent, "archive", 0o600)?;
    let mut archive_guard = TempPath::new(archive_path.clone());
    let actual_hash = download_file(
        &client,
        &context.source.release_asset_url(&target.tag(), asset_name),
        archive_file,
        MAX_ARCHIVE_BYTES,
    )
    .await?;
    if actual_hash != expected_hash {
        return Err(update_error(format!(
            "checksum verification failed for {asset_name}"
        )));
    }

    let staged = extract_staged_binary(&archive_path, parent)?;
    let staged_version = inspect_binary_version(staged.path()).await?;
    if staged_version != target {
        return Err(update_error(format!(
            "release {} contains HuntProxy {}",
            target.tag(),
            staged_version
        )));
    }
    archive_guard.remove_now()?;

    let plugin_names = if coordinated {
        inspect_release_plugins(staged.path(), target).await?
    } else {
        Vec::new()
    };
    activate_release(
        &daemon_config,
        ReleaseInstallation {
            executable: executable.to_owned(),
            staged,
            target,
            current: Some(context.current_version),
            coordinated,
            initial_hash: Some(initial_hash),
            plugin_names,
        },
    )
    .await
}

/// Install an already checksum-verified release from the upstream installer.
/// The executable and persisted state share the self-updater's transaction.
pub async fn install_local(
    data_dir: Option<PathBuf>,
    executable: PathBuf,
) -> DomainResult<UpdateOutcome> {
    let parent = executable
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| update_error("installation path has no parent directory"))?;
    fs::create_dir_all(parent)
        .map_err(|error| update_error(format!("create installation directory: {error}")))?;
    let parent = parent
        .canonicalize()
        .map_err(|error| update_error(format!("resolve installation directory: {error}")))?;
    let executable = parent.join(
        executable
            .file_name()
            .ok_or_else(|| update_error("installation path has no filename"))?,
    );
    let _lock = UpdateLock::acquire(&parent)?;
    if fs::symlink_metadata(&executable).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(update_error("refusing to replace a symlinked installation"));
    }
    let current = if executable.exists() {
        Some(inspect_binary_version(&executable).await?)
    } else {
        None
    };
    let initial_hash = executable
        .exists()
        .then(|| hash_file(&executable))
        .transpose()?;
    let config = Config::load(data_dir)?;
    let target = StableVersion::parse(env!("CARGO_PKG_VERSION"))?;
    let source = std::env::current_exe().map_err(|error| update_error(error.to_string()))?;
    let staged = copy_to_temp(&source, &parent, "release")?;
    let plugin_names = inspect_release_plugins(staged.path(), target).await?;
    activate_release(
        &config,
        ReleaseInstallation {
            executable,
            staged,
            target,
            current,
            coordinated: true,
            initial_hash,
            plugin_names,
        },
    )
    .await
}

struct ReleaseInstallation {
    executable: PathBuf,
    staged: TempPath,
    target: StableVersion,
    current: Option<StableVersion>,
    coordinated: bool,
    initial_hash: Option<[u8; 32]>,
    plugin_names: Vec<String>,
}

async fn activate_release(
    config: &Config,
    release: ReleaseInstallation,
) -> DomainResult<UpdateOutcome> {
    let ReleaseInstallation {
        executable,
        mut staged,
        target,
        current,
        coordinated,
        initial_hash,
        plugin_names,
    } = release;
    let parent = executable
        .parent()
        .ok_or_else(|| update_error("installation path has no parent directory"))?;
    let _maintenance = if coordinated {
        Some(app::acquire_bootstrap_lock(config).await?)
    } else {
        None
    };
    if coordinated {
        app::recover_installation(config, true).await?;
    }
    let was_running = app::daemon_is_active(config)?;
    if was_running && initial_hash.is_none() {
        return Err(update_error(
            "cannot replace a running installation without its original executable",
        ));
    }
    if was_running && coordinated {
        app::stop_daemon(config).await?;
    } else {
        ensure_daemon_stopped(config)?;
    }
    let snapshot = if coordinated {
        let snapshot_config = config.clone();
        let tag = target.tag();
        match tokio::task::spawn_blocking(move || {
            DataSnapshot::capture(&snapshot_config, &tag, &plugin_names)
        })
        .await
        {
            Ok(Ok(snapshot)) => Some(snapshot),
            result => {
                if was_running {
                    if let Err(restart) = app::start_daemon_binary(config, &executable).await {
                        return Err(update_error(format!("could not preserve update state and could not restart the previous daemon: {restart}")));
                    }
                }
                return Err(match result {
                    Ok(Err(error)) => error,
                    Err(error) => update_error(format!("update backup task: {error}")),
                    _ => unreachable!(),
                });
            }
        }
    } else {
        None
    };
    let backup_path = backup_path(&executable)?;
    let mut replaced = false;
    let mut journal_started = false;
    let mut binary_conflict = false;
    let installation = async {
        if let (Some(snapshot), Some(source)) = (&snapshot, current) {
            if source != target {
                journal_started = true;
                crate::update_journal::begin(
                    config,
                    &source.to_string(),
                    &target.to_string(),
                    &executable,
                    &snapshot.root,
                )?;
            }
        }
        if coordinated {
            prepare_downloaded_release(staged.path(), config, target).await?;
        }
        ensure_daemon_stopped(config)?;
        let actual_hash = executable
            .exists()
            .then(|| hash_file(&executable))
            .transpose()?;
        if actual_hash != initial_hash {
            binary_conflict = true;
            return Err(DomainError::new(
                ErrorCode::Conflict,
                "the installed HuntProxy binary changed during the update; retry",
            ));
        }
        if let Some(initial_hash) = initial_hash {
            let mut backup = copy_to_temp(&executable, parent, "previous")?;
            if hash_file(backup.path())? != initial_hash {
                return Err(update_error("could not verify the rollback binary"));
            }
            fs::rename(backup.path(), &backup_path)
                .map_err(|error| update_error(format!("install rollback binary: {error}")))?;
            backup.disarm();
            sync_directory(parent)?;
        }
        ensure_daemon_stopped(config)?;
        fs::rename(staged.path(), &executable)
            .map_err(|error| update_error(format!("replace HuntProxy binary: {error}")))?;
        staged.disarm();
        replaced = true;
        sync_directory(parent)?;
        if inspect_binary_version(&executable).await? != target {
            return Err(update_error(
                "the installed executable returned a different version",
            ));
        }
        if was_running {
            app::start_daemon_binary(config, &executable).await?;
        }
        Ok::<_, DomainError>(())
    }
    .await;
    if let Err(error) = installation {
        if binary_conflict {
            let recovery = snapshot
                .as_ref()
                .map(|snapshot| snapshot.root.display().to_string())
                .unwrap_or_else(|| backup_path.display().to_string());
            return Err(DomainError::new(
                ErrorCode::Conflict,
                format!(
                    "{error}; the executable was replaced by another process; recovery requires attention; restore point: {recovery}"
                ),
            ));
        }
        let mut failures = Vec::new();
        if app::daemon_is_active(config)? {
            if let Err(error) = app::stop_daemon(config).await {
                failures.push(format!("stop failed release: {error}"));
            }
        }
        if replaced && failures.is_empty() {
            if initial_hash.is_some() {
                let restore =
                    copy_to_temp(&backup_path, parent, "restore").and_then(|mut restore| {
                        fs::rename(restore.path(), &executable).map_err(|error| {
                            update_error(format!("restore executable: {error}"))
                        })?;
                        restore.disarm();
                        sync_directory(parent)
                    });
                if let Err(error) = restore {
                    failures.push(error.to_string());
                }
            } else if let Err(error) =
                fs::remove_file(&executable).and_then(|_| File::open(parent)?.sync_all())
            {
                failures.push(format!("remove failed new installation: {error}"));
            }
        }
        if failures.is_empty() {
            if let Some(snapshot) = &snapshot {
                if let Err(error) = snapshot.restore(config) {
                    failures.push(error.to_string());
                }
            }
        }
        if failures.is_empty() && journal_started {
            if let Err(error) = crate::update_journal::finish(config) {
                failures.push(error.to_string());
            }
        }
        if failures.is_empty() {
            if let Some(snapshot) = &snapshot {
                if let Err(error) =
                    crate::update_journal::prune_restore_points(config, Some(&snapshot.root))
                {
                    tracing::warn!(%error, "rollback completed; older restore point cleanup failed");
                }
            }
        }
        // Once old data has been restored, retire the rollback journal before
        // accepting new writes. Otherwise a cleanup failure could cause a
        // later recovery to discard records saved after the restart.
        if failures.is_empty() && was_running {
            if let Err(error) = app::start_daemon_binary(config, &executable).await {
                failures.push(format!("restart previous daemon: {error}"));
            }
        }
        let recovery = snapshot
            .as_ref()
            .map(|snapshot| snapshot.root.display().to_string())
            .unwrap_or_else(|| backup_path.display().to_string());
        return Err(update_error(if failures.is_empty() {
            format!("{error}; the previous installation was restored")
        } else {
            format!(
                "{error}; recovery requires attention: {}; restore point: {recovery}",
                failures.join("; ")
            )
        }));
    }
    if let Some(snapshot) = &snapshot {
        // Cleanup failures cannot turn a healthy, activated release into a
        // rollback. The durable journal lets the next startup retry cleanup.
        if let Err(error) =
            crate::update_journal::prune_restore_points(config, Some(&snapshot.root))
        {
            tracing::warn!(%error, "release installed; restore point cleanup will be retried");
        } else if journal_started {
            if let Err(error) = crate::update_journal::finish(config) {
                tracing::warn!(%error, "release installed; recovery journal cleanup will be retried");
            }
        }
    }
    Ok(UpdateOutcome::Installed {
        previous: current
            .map(|version| version.to_string())
            .unwrap_or_else(|| "none".into()),
        installed: target.to_string(),
        backup_path,
        data_backup_path: snapshot.map(|snapshot| snapshot.root),
        daemon_restarted: was_running,
    })
}

async fn inspect_release_plugins(path: &Path, version: StableVersion) -> DomainResult<Vec<String>> {
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        binary_output(path, &["release-info"]),
    )
    .await
    .map_err(|_| update_error("release metadata inspection timed out"))?
    .map_err(|error| update_error(format!("inspect release metadata: {error}")))?;
    if !output.status.success() || output.stdout.len() > MAX_RELEASE_JSON_BYTES as usize {
        return Err(update_error(
            "downloaded release has invalid installation metadata",
        ));
    }
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| update_error("downloaded release has invalid installation metadata"))?;
    if result.get("version").and_then(serde_json::Value::as_str)
        != Some(version.to_string().as_str())
    {
        return Err(update_error(
            "release metadata version does not match the requested release",
        ));
    }
    let names: Vec<String> =
        serde_json::from_value(result.get("plugins").cloned().unwrap_or_default())
            .map_err(|_| update_error("release plugin list is invalid"))?;
    if names.len() > 256
        || names.iter().any(|name| {
            name.is_empty()
                || name.len() > 80
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(update_error(
            "release plugin list contains an unsafe package name",
        ));
    }
    Ok(names)
}

async fn prepare_downloaded_release(
    path: &Path,
    config: &Config,
    version: StableVersion,
) -> DomainResult<()> {
    let arguments = [
        std::ffi::OsStr::new("prepare-update"),
        std::ffi::OsStr::new("--data-dir"),
        config.data_dir.as_os_str(),
    ];
    let output = tokio::time::timeout(Duration::from_secs(900), binary_output(path, &arguments))
        .await
        .map_err(|_| update_error("release preparation timed out"))?
        .map_err(|error| update_error(format!("prepare downloaded release: {error}")))?;
    if !output.status.success() {
        let tail = &output.stderr[output.stderr.len().saturating_sub(4096)..];
        return Err(update_error(format!(
            "release preparation failed: {}",
            String::from_utf8_lossy(tail).trim()
        )));
    }
    if output.stdout.len() > MAX_RELEASE_JSON_BYTES as usize {
        return Err(update_error(
            "release preparation result exceeded its size limit",
        ));
    }
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| update_error("release preparation returned an invalid result"))?;
    if result.get("ok").and_then(serde_json::Value::as_bool) != Some(true)
        || result.get("version").and_then(serde_json::Value::as_str)
            != Some(version.to_string().as_str())
    {
        return Err(update_error(
            "release preparation did not confirm the requested version",
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct DataSnapshot {
    pub(crate) root: PathBuf,
    pub(crate) files: Vec<(PathBuf, Option<PathBuf>)>,
    pub(crate) plugins: Vec<(String, bool)>,
}

impl DataSnapshot {
    fn capture(config: &Config, tag: &str, target_plugins: &[String]) -> DomainResult<Self> {
        let directory = config.runtime_dir.join("updates");
        crate::config::create_private_dir(&directory)?;
        let root = directory.join(format!("{tag}-{}", uuid::Uuid::new_v4()));
        crate::config::create_private_dir(&root)?;
        let mut snapshot = Self {
            root,
            files: Vec::new(),
            plugins: Vec::new(),
        };
        let result = (|| {
            for (name, source) in [
                ("database.sqlite3", config.db_path()),
                ("config.toml", config.data_dir.join("config.toml")),
                (
                    "plugin-source",
                    config.plugin_dir.join(".huntproxy-first-party-source"),
                ),
            ] {
                let destination = snapshot.root.join(name);
                if fs::symlink_metadata(&source)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
                {
                    return Err(update_error(format!(
                        "cannot preserve a symlinked update state file: {}",
                        source.display()
                    )));
                }
                if source.exists() {
                    if name == "database.sqlite3" {
                        let connection = rusqlite::Connection::open_with_flags(
                            &source,
                            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                        )
                        .map_err(|error| update_error(format!("open database backup: {error}")))?;
                        let mut target =
                            rusqlite::Connection::open(&destination).map_err(|error| {
                                update_error(format!("open restore point: {error}"))
                            })?;
                        let backup = rusqlite::backup::Backup::new(&connection, &mut target)
                            .map_err(|error| update_error(format!("preserve database: {error}")))?;
                        backup
                            .run_to_completion(128, Duration::from_millis(10), None)
                            .map_err(|error| update_error(format!("preserve database: {error}")))?;
                        drop(backup);
                        target
                            .pragma_update(None, "journal_mode", "DELETE")
                            .map_err(|error| {
                                update_error(format!("finalize database restore point: {error}"))
                            })?;
                    } else {
                        fs::copy(&source, &destination).map_err(|error| {
                            update_error(format!("preserve {}: {error}", source.display()))
                        })?;
                    }
                    secure_backup_file(&destination)?;
                    snapshot.files.push((source, Some(destination)));
                } else {
                    snapshot.files.push((source, None));
                }
            }
            let plugin_backup = snapshot.root.join("plugins");
            crate::config::create_private_dir(&plugin_backup)?;
            let mut names = crate::installation::bundled_plugin_names()?;
            names.extend_from_slice(target_plugins);
            names.sort();
            names.dedup();
            for name in names {
                let source = config.plugin_dir.join(&name);
                let existed = source.exists();
                if existed {
                    copy_backup_tree(&source, &plugin_backup.join(&name))?;
                }
                snapshot.plugins.push((name, existed));
            }
            let manifest = serde_json::json!({
                "format":1,"version":tag,"data_dir":config.data_dir,"plugin_dir":config.plugin_dir,
                "database":config.db_path(),"plugins":snapshot.plugins,
                "snapshot": &snapshot,
            });
            crate::config::write_private_file(
                &snapshot.root.join("restore.json"),
                &serde_json::to_vec_pretty(&manifest)
                    .map_err(|error| update_error(error.to_string()))?,
            )?;
            secure_backup_file(&snapshot.root.join("restore.json"))?;
            sync_directory(&plugin_backup)?;
            sync_directory(&snapshot.root)?;
            sync_directory(&directory)?;
            Ok::<_, DomainError>(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_dir_all(&snapshot.root);
            return Err(error);
        }
        Ok(snapshot)
    }

    pub(crate) fn restore(&self, config: &Config) -> DomainResult<()> {
        if app::daemon_is_active(config)? {
            return Err(update_error(
                "refusing to restore data while the daemon is running",
            ));
        }
        for (destination, source) in &self.files {
            if *destination == config.db_path() {
                for suffix in ["-wal", "-shm"] {
                    let sidecar = PathBuf::from(format!("{}{suffix}", destination.display()));
                    match fs::remove_file(sidecar) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(update_error(format!("restore database sidecar: {error}")))
                        }
                    }
                }
            }
            if let Some(source) = source {
                let parent = destination
                    .parent()
                    .ok_or_else(|| update_error("restore path has no parent"))?;
                crate::config::create_private_dir(parent)?;
                let (path, mut file) = create_temp_file(parent, "data-restore", 0o600)?;
                let mut guard = TempPath::new(path.clone());
                let mut input = File::open(source)
                    .map_err(|error| update_error(format!("read restore point: {error}")))?;
                std::io::copy(&mut input, &mut file)
                    .map_err(|error| update_error(format!("restore data: {error}")))?;
                file.sync_all()
                    .map_err(|error| update_error(format!("sync restored data: {error}")))?;
                fs::rename(&path, destination)
                    .map_err(|error| update_error(format!("replace restored data: {error}")))?;
                guard.disarm();
                sync_directory(parent)?;
            } else if destination.exists() {
                fs::remove_file(destination)
                    .map_err(|error| update_error(format!("remove new data file: {error}")))?;
                if let Some(parent) = destination.parent() {
                    sync_directory(parent)?;
                }
            }
        }
        for (name, existed) in &self.plugins {
            let destination = config.plugin_dir.join(name);
            if fs::symlink_metadata(&destination).is_ok() {
                fs::remove_dir_all(&destination)
                    .map_err(|error| update_error(format!("restore plugin {name}: {error}")))?;
            }
            if *existed {
                copy_backup_tree(&self.root.join("plugins").join(name), &destination)?;
            }
        }
        sync_directory(&config.plugin_dir)?;
        Ok(())
    }
}

fn secure_backup_file(path: &Path) -> DomainResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| update_error(error.to_string()))?;
    }
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| update_error(error.to_string()))
}

fn copy_backup_tree(source: &Path, destination: &Path) -> DomainResult<()> {
    let metadata = fs::symlink_metadata(source).map_err(|error| update_error(error.to_string()))?;
    if metadata.file_type().is_symlink() {
        #[cfg(unix)]
        {
            let link = fs::read_link(source).map_err(|error| update_error(error.to_string()))?;
            std::os::unix::fs::symlink(link, destination)
                .map_err(|error| update_error(error.to_string()))?;
            return Ok(());
        }
        #[cfg(not(unix))]
        return Err(update_error(
            "cannot preserve symlinked plugin data on this platform",
        ));
    }
    if metadata.is_dir() {
        crate::config::create_private_dir(destination)?;
        for entry in fs::read_dir(source).map_err(|error| update_error(error.to_string()))? {
            let entry = entry.map_err(|error| update_error(error.to_string()))?;
            copy_backup_tree(&entry.path(), &destination.join(entry.file_name()))?;
        }
        sync_directory(destination)?;
    } else if metadata.is_file() {
        fs::copy(source, destination).map_err(|error| update_error(error.to_string()))?;
        secure_backup_file(destination)?;
    } else {
        return Err(update_error(
            "cannot preserve a special file in a managed plugin package",
        ));
    }
    Ok(())
}

fn daemon_config(data_dir: Option<PathBuf>) -> Config {
    let mut config = Config::default();
    if let Some(data_dir) = data_dir {
        config.data_dir = data_dir;
    }
    config
}

fn ensure_daemon_stopped(config: &Config) -> DomainResult<()> {
    if app::daemon_is_active(config)? {
        return Err(DomainError::new(
            ErrorCode::Conflict,
            "HuntProxy is running; run HuntProxy stop, restart/reconnect AI clients, then retry",
        ));
    }
    Ok(())
}

fn update_client(allow_http: bool) -> DomainResult<wreq::Client> {
    let mut builder = wreq::Client::builder()
        .redirect(wreq::redirect::Policy::limited(10))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(180));
    if !allow_http {
        builder = builder.https_only(true);
    }
    builder
        .build()
        .map_err(|error| update_error(format!("build update client: {error}")))
}

async fn resolve_release(
    client: &wreq::Client,
    source: &ReleaseSource,
    requested: Option<StableVersion>,
) -> DomainResult<ReleaseResponse> {
    let requested_tag = requested.map(StableVersion::tag);
    let encoded = download_bytes(
        client,
        &source.release_api_url(requested_tag.as_deref()),
        MAX_RELEASE_JSON_BYTES,
    )
    .await?;
    let release: ReleaseResponse = serde_json::from_slice(&encoded)
        .map_err(|error| update_error(format!("invalid GitHub release response: {error}")))?;
    StableVersion::parse(&release.tag_name)?;
    Ok(release)
}

async fn send_get(client: &wreq::Client, url: &str) -> DomainResult<wreq::Response> {
    let mut last_error = None;
    for attempt in 0..3 {
        match client
            .get(url)
            .header(
                wreq::header::USER_AGENT,
                format!("HuntProxy/{} updater", env!("CARGO_PKG_VERSION")),
            )
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => return Ok(response),
            Ok(response) => {
                let status = response.status();
                last_error = Some(format!("download {url}: HTTP {status}"));
                if status.as_u16() != 429 && !status.is_server_error() {
                    break;
                }
            }
            Err(error) => last_error = Some(format!("download {url}: {error}")),
        }
        if attempt < 2 {
            tokio::time::sleep(Duration::from_millis(250 * (attempt + 1) as u64)).await;
        }
    }
    Err(update_error(
        last_error.unwrap_or_else(|| format!("download {url} failed")),
    ))
}

async fn download_bytes(client: &wreq::Client, url: &str, limit: u64) -> DomainResult<Vec<u8>> {
    let response = send_get(client, url).await?;
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(update_error(format!("download exceeded {limit} bytes")));
    }
    let mut stream = response.bytes_stream();
    let mut encoded = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| update_error(format!("download {url}: {error}")))?;
        if encoded.len() as u64 + chunk.len() as u64 > limit {
            return Err(update_error(format!("download exceeded {limit} bytes")));
        }
        encoded.extend_from_slice(&chunk);
    }
    Ok(encoded)
}

async fn download_file(
    client: &wreq::Client,
    url: &str,
    file: File,
    limit: u64,
) -> DomainResult<[u8; 32]> {
    let response = send_get(client, url).await?;
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(update_error(format!("download exceeded {limit} bytes")));
    }
    let mut stream = response.bytes_stream();
    let mut file = tokio::fs::File::from_std(file);
    let mut total = 0u64;
    let mut hasher = Sha256::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| update_error(format!("download {url}: {error}")))?;
        total = total.saturating_add(chunk.len() as u64);
        if total > limit {
            return Err(update_error(format!("download exceeded {limit} bytes")));
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|error| update_error(format!("write downloaded archive: {error}")))?;
    }
    file.sync_all()
        .await
        .map_err(|error| update_error(format!("sync downloaded archive: {error}")))?;
    Ok(hasher.finalize().into())
}

fn parse_checksum(encoded: &[u8], asset_name: &str) -> DomainResult<[u8; 32]> {
    let text =
        std::str::from_utf8(encoded).map_err(|_| update_error("SHA256SUMS is not valid UTF-8"))?;
    let mut matches = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(hash) = fields.next() else {
            continue;
        };
        let Some(name) = fields.next() else {
            continue;
        };
        if fields.next().is_none() && name.strip_prefix('*').unwrap_or(name) == asset_name {
            matches.push(hash);
        }
    }
    if matches.len() != 1 || matches[0].len() != 64 {
        return Err(update_error(format!(
            "SHA256SUMS must contain exactly one valid checksum for {asset_name}"
        )));
    }
    let decoded = hex::decode(matches[0]).map_err(|_| {
        update_error(format!(
            "SHA256SUMS must contain exactly one valid checksum for {asset_name}"
        ))
    })?;
    decoded.try_into().map_err(|_| {
        update_error(format!(
            "SHA256SUMS must contain exactly one valid checksum for {asset_name}"
        ))
    })
}

fn asset_name(os: &str, arch: &str) -> DomainResult<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Ok("huntproxy-linux-x86_64.tar.gz"),
        ("linux", "aarch64") => Ok("huntproxy-linux-aarch64.tar.gz"),
        ("macos", "x86_64") => Ok("huntproxy-mac-intel-chip.tar.gz"),
        ("macos", "aarch64") => Ok("huntproxy-mac-apple-chip.tar.gz"),
        ("linux" | "macos", _) => Err(update_error(format!(
            "unsupported CPU architecture: {arch}"
        ))),
        _ => Err(update_error(format!("unsupported operating system: {os}"))),
    }
}

fn extract_staged_binary(archive_path: &Path, parent: &Path) -> DomainResult<TempPath> {
    let file = File::open(archive_path)
        .map_err(|error| update_error(format!("open release archive: {error}")))?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|error| update_error(format!("read release archive: {error}")))?;
    let mut staged = None;
    let mut saw_license = false;
    for entry in entries {
        let mut entry =
            entry.map_err(|error| update_error(format!("read release archive: {error}")))?;
        let name = entry.path_bytes();
        let is_file = entry.header().entry_type().is_file();
        match name.as_ref() {
            b"HuntProxy" => {
                if staged.is_some() || !is_file || entry.size() > MAX_EXECUTABLE_BYTES {
                    return Err(update_error(
                        "the release archive must contain one bounded regular HuntProxy executable",
                    ));
                }
                let (path, mut output) = create_temp_file(parent, "new", 0o755)?;
                let temporary = TempPath::new(path.clone());
                std::io::copy(&mut entry, &mut output)
                    .map_err(|error| update_error(format!("extract HuntProxy: {error}")))?;
                output
                    .sync_all()
                    .map_err(|error| update_error(format!("sync HuntProxy: {error}")))?;
                set_executable(&path)?;
                output
                    .sync_all()
                    .map_err(|error| update_error(format!("sync HuntProxy: {error}")))?;
                staged = Some(temporary);
            }
            b"LICENSE" => {
                if saw_license || !is_file || entry.size() > MAX_LICENSE_BYTES {
                    return Err(update_error("invalid LICENSE in release archive"));
                }
                saw_license = true;
            }
            _ => {
                return Err(update_error(format!(
                    "unexpected release archive member: {}",
                    String::from_utf8_lossy(&name)
                )))
            }
        }
    }
    staged.ok_or_else(|| update_error("the release archive has no HuntProxy executable"))
}

async fn inspect_binary_version(path: &Path) -> DomainResult<StableVersion> {
    let output = tokio::time::timeout(Duration::from_secs(15), binary_output(path, &["--version"]))
        .await
        .map_err(|_| update_error("the downloaded binary version check timed out"))?
        .map_err(|error| update_error(format!("run downloaded binary: {error}")))?;
    if !output.status.success() {
        return Err(update_error(
            "the downloaded binary failed its version check",
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| update_error("the downloaded binary returned an invalid version"))?;
    let mut fields = stdout.split_whitespace();
    if fields.next() != Some("HuntProxy") {
        return Err(update_error(
            "the downloaded binary returned an invalid version",
        ));
    }
    let version = fields
        .next()
        .ok_or_else(|| update_error("the downloaded binary returned an invalid version"))?;
    if fields.next().is_some() {
        return Err(update_error(
            "the downloaded binary returned an invalid version",
        ));
    }
    StableVersion::parse(version)
}

/// A failed exec with ETXTBSY never started the program. A concurrent fork can
/// briefly inherit a closing write descriptor, so retry that exec error only.
pub(crate) async fn binary_output<S: AsRef<std::ffi::OsStr>>(
    path: &Path,
    args: &[S],
) -> std::io::Result<std::process::Output> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let result = tokio::process::Command::new(path)
            .args(args)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output()
            .await;
        match result {
            Err(error)
                if error.raw_os_error() == Some(libc::ETXTBSY)
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            result => return result,
        }
    }
}

fn hash_file(path: &Path) -> DomainResult<[u8; 32]> {
    let mut file = File::open(path)
        .map_err(|error| update_error(format!("open {}: {error}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| update_error(format!("read {}: {error}", path.display())))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

fn create_temp_file(parent: &Path, label: &str, mode: u32) -> DomainResult<(PathBuf, File)> {
    for _ in 0..32 {
        let mut random = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let path = parent.join(format!(".HuntProxy.{label}.{}", hex::encode(random)));
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(update_error(format!(
                    "create update staging file in {}: {error}",
                    parent.display()
                )))
            }
        }
    }
    Err(update_error(
        "could not create a unique update staging file",
    ))
}

fn copy_to_temp(source: &Path, parent: &Path, label: &str) -> DomainResult<TempPath> {
    let (path, mut output) = create_temp_file(parent, label, 0o700)?;
    let temporary = TempPath::new(path.clone());
    let mut input = File::open(source)
        .map_err(|error| update_error(format!("open rollback source: {error}")))?;
    std::io::copy(&mut input, &mut output)
        .map_err(|error| update_error(format!("copy rollback binary: {error}")))?;
    output
        .sync_all()
        .map_err(|error| update_error(format!("sync rollback binary: {error}")))?;
    let permissions = fs::metadata(source)
        .map_err(|error| update_error(format!("inspect rollback source: {error}")))?
        .permissions();
    fs::set_permissions(&path, permissions)
        .map_err(|error| update_error(format!("set rollback permissions: {error}")))?;
    output
        .sync_all()
        .map_err(|error| update_error(format!("sync rollback binary: {error}")))?;
    Ok(temporary)
}

fn backup_path(executable: &Path) -> DomainResult<PathBuf> {
    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| update_error("current executable has an invalid file name"))?;
    Ok(executable.with_file_name(format!("{name}.previous")))
}

fn set_executable(path: &Path) -> DomainResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|error| update_error(format!("set executable permissions: {error}")))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> DomainResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| update_error(format!("sync {}: {error}", path.display())))
}

struct TempPath {
    path: Option<PathBuf>,
}

impl TempPath {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("temporary path is active")
    }

    fn disarm(&mut self) {
        self.path = None;
    }

    fn remove_now(&mut self) -> DomainResult<()> {
        if let Some(path) = self.path.take() {
            fs::remove_file(&path)
                .map_err(|error| update_error(format!("remove {}: {error}", path.display())))?;
        }
        Ok(())
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

struct UpdateLock {
    #[cfg(unix)]
    _lock: nix::fcntl::Flock<File>,
    #[cfg(not(unix))]
    _file: File,
}

impl UpdateLock {
    fn acquire(parent: &Path) -> DomainResult<Self> {
        let path = parent.join(".HuntProxy.update.lock");
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|error| update_error(format!("open update lock: {error}")))?;
        #[cfg(unix)]
        {
            let lock = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
                .map_err(|_| {
                DomainError::new(ErrorCode::Conflict, "another update is running")
            })?;
            Ok(Self { _lock: lock })
        }
        #[cfg(not(unix))]
        {
            Ok(Self { _file: file })
        }
    }
}

fn update_error(message: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::Unavailable, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::os::unix::fs::PermissionsExt;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn script(version: &str) -> Vec<u8> {
        format!("#!/bin/sh\nprintf 'HuntProxy {version}\\n'\n").into_bytes()
    }

    fn write_script(path: &Path, version: &str) {
        fs::write(path, script(version)).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn archive(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (name, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder
                .append_data(&mut header, name, body.as_slice())
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    async fn mock_release(
        server: &MockServer,
        tag: &str,
        archive: &[u8],
        checksum: Option<String>,
    ) {
        Mock::given(method("GET"))
            .and(path(format!("/repos/{REPOSITORY}/releases/tags/{tag}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tag_name": tag
            })))
            .mount(server)
            .await;
        let asset = asset_name("linux", "x86_64").unwrap();
        let checksum = checksum.unwrap_or_else(|| {
            let hash = hex::encode(Sha256::digest(archive));
            format!("{hash}  {asset}\n")
        });
        Mock::given(method("GET"))
            .and(path(format!(
                "/{REPOSITORY}/releases/download/{tag}/SHA256SUMS"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_string(checksum))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/{REPOSITORY}/releases/download/{tag}/{asset}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(archive.to_vec()))
            .mount(server)
            .await;
    }

    fn context(server: &MockServer, executable: PathBuf, current: &str) -> UpdateContext {
        UpdateContext {
            source: ReleaseSource::test_source(&server.uri()).unwrap(),
            executable,
            current_version: StableVersion::parse(current).unwrap(),
            os: "linux",
            arch: "x86_64",
        }
    }

    fn request(data_dir: PathBuf, check: bool) -> UpdateRequest {
        UpdateRequest {
            check,
            version: Some("v0.1.1".into()),
            data_dir: Some(data_dir),
        }
    }

    fn staging_files(directory: &Path) -> Vec<PathBuf> {
        fs::read_dir(directory)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with(".HuntProxy.") && name != ".HuntProxy.update.lock"
                    })
            })
            .collect()
    }

    #[test]
    fn stable_versions_and_assets_are_strict() {
        assert_eq!(
            StableVersion::parse("v1.2.3").unwrap(),
            StableVersion {
                major: 1,
                minor: 2,
                patch: 3
            }
        );
        assert!(StableVersion::parse("1.2").is_err());
        assert!(StableVersion::parse("1.2.3-beta").is_err());
        assert!(StableVersion::parse("1.2.3.4").is_err());
        assert_eq!(
            asset_name("linux", "x86_64").unwrap(),
            "huntproxy-linux-x86_64.tar.gz"
        );
        assert_eq!(
            asset_name("linux", "aarch64").unwrap(),
            "huntproxy-linux-aarch64.tar.gz"
        );
        assert_eq!(
            asset_name("macos", "x86_64").unwrap(),
            "huntproxy-mac-intel-chip.tar.gz"
        );
        assert_eq!(
            asset_name("macos", "aarch64").unwrap(),
            "huntproxy-mac-apple-chip.tar.gz"
        );
        assert!(asset_name("linux", "riscv64").is_err());
        assert!(asset_name("windows", "x86_64").is_err());
    }

    #[test]
    fn checksums_require_one_exact_asset_entry() {
        let asset = "huntproxy-linux-x86_64.tar.gz";
        let hash = "a".repeat(64);
        assert_eq!(
            parse_checksum(format!("{hash}  {asset}\n").as_bytes(), asset).unwrap(),
            [0xaa; 32]
        );
        assert!(parse_checksum(format!("{hash}  other.tar.gz\n").as_bytes(), asset).is_err());
        assert!(parse_checksum(
            format!("{hash}  {asset}\n{hash}  {asset}\n").as_bytes(),
            asset
        )
        .is_err());
        assert!(parse_checksum(format!("xyz  {asset}\n").as_bytes(), asset).is_err());
    }

    #[tokio::test]
    async fn check_is_read_only_and_does_not_download_assets() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/{REPOSITORY}/releases/tags/v0.1.1")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tag_name": "v0.1.1"
            })))
            .mount(&server)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("HuntProxy");
        write_script(&executable, "0.1.0");
        let original = fs::read(&executable).unwrap();
        let data_dir = directory.path().join("missing-data");
        let outcome = run_with_context(
            request(data_dir.clone(), true),
            context(&server, executable.clone(), "0.1.0"),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            UpdateOutcome::Available {
                current: "0.1.0".into(),
                target: "0.1.1".into()
            }
        );
        assert_eq!(fs::read(executable).unwrap(), original);
        assert!(!data_dir.exists());
        assert!(staging_files(directory.path()).is_empty());
    }

    #[tokio::test]
    async fn same_version_and_older_latest_are_no_ops() {
        for (current, requested, expected) in [
            (
                "0.1.0",
                Some("v0.1.0"),
                UpdateOutcome::UpToDate {
                    current: "0.1.0".into(),
                },
            ),
            (
                "0.1.1",
                None,
                UpdateOutcome::CurrentNewer {
                    current: "0.1.1".into(),
                    target: "0.1.0".into(),
                },
            ),
        ] {
            let server = MockServer::start().await;
            let api_path = match requested {
                Some(tag) => format!("/repos/{REPOSITORY}/releases/tags/{tag}"),
                None => format!("/repos/{REPOSITORY}/releases/latest"),
            };
            Mock::given(method("GET"))
                .and(path(api_path))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "tag_name": "v0.1.0"
                })))
                .mount(&server)
                .await;
            let directory = tempfile::tempdir().unwrap();
            let executable = directory.path().join("HuntProxy");
            write_script(&executable, current);
            let original = fs::read(&executable).unwrap();
            let outcome = run_with_context(
                UpdateRequest {
                    check: false,
                    version: requested.map(str::to_string),
                    data_dir: Some(directory.path().join("data")),
                },
                context(&server, executable.clone(), current),
            )
            .await
            .unwrap();
            assert_eq!(outcome, expected);
            assert_eq!(fs::read(executable).unwrap(), original);
            assert!(staging_files(directory.path()).is_empty());
        }
    }

    #[tokio::test]
    async fn bounded_download_rejects_an_oversized_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oversized"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 33]))
            .mount(&server)
            .await;
        let client = update_client(true).unwrap();
        let error = download_bytes(&client, &format!("{}/oversized", server.uri()), 32)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeded 32 bytes"));
    }

    #[tokio::test]
    async fn verified_release_replaces_binary_and_preserves_state_and_rollback() {
        let server = MockServer::start().await;
        let release = archive(&[
            ("HuntProxy", script("0.1.1")),
            ("LICENSE", b"test license\n".to_vec()),
        ]);
        mock_release(&server, "v0.1.1", &release, None).await;
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("HuntProxy");
        write_script(&executable, "0.1.0");
        let old_binary = fs::read(&executable).unwrap();
        let data_dir = directory.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        let sentinel = data_dir.join("state-sentinel");
        fs::write(&sentinel, b"unchanged").unwrap();

        let outcome = run_with_context(
            request(data_dir, false),
            context(&server, executable.clone(), "0.1.0"),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            UpdateOutcome::Installed {
                previous: "0.1.0".into(),
                installed: "0.1.1".into(),
                backup_path: directory.path().join("HuntProxy.previous"),
                data_backup_path: None,
                daemon_restarted: false,
            }
        );
        assert_eq!(fs::read(&executable).unwrap(), script("0.1.1"));
        assert_eq!(
            fs::read(directory.path().join("HuntProxy.previous")).unwrap(),
            old_binary
        );
        assert_eq!(fs::read(sentinel).unwrap(), b"unchanged");
        assert_eq!(
            fs::metadata(executable).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(staging_files(directory.path()).is_empty());
    }

    #[tokio::test]
    async fn checksum_and_version_failures_leave_binary_untouched() {
        for (release_version, checksum) in [
            (
                "0.1.1",
                Some(format!(
                    "{}  huntproxy-linux-x86_64.tar.gz\n",
                    "0".repeat(64)
                )),
            ),
            ("9.9.9", None),
        ] {
            let server = MockServer::start().await;
            let release = archive(&[("HuntProxy", script(release_version))]);
            mock_release(&server, "v0.1.1", &release, checksum).await;
            let directory = tempfile::tempdir().unwrap();
            let executable = directory.path().join("HuntProxy");
            write_script(&executable, "0.1.0");
            let original = fs::read(&executable).unwrap();
            let result = run_with_context(
                request(directory.path().join("data"), false),
                context(&server, executable.clone(), "0.1.0"),
            )
            .await;
            assert!(result.is_err());
            assert_eq!(fs::read(&executable).unwrap(), original);
            assert!(!directory.path().join("HuntProxy.previous").exists());
            assert!(staging_files(directory.path()).is_empty());
        }
    }

    #[tokio::test]
    async fn running_daemon_is_rejected_before_any_update_files_are_created() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/{REPOSITORY}/releases/tags/v0.1.1")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tag_name": "v0.1.1"
            })))
            .mount(&server)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("HuntProxy");
        write_script(&executable, "0.1.0");
        let original = fs::read(&executable).unwrap();
        let data_dir = directory.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(data_dir.join(crate::config::DAEMON_LOCK_NAME))
            .unwrap();
        let _daemon_lock =
            nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusiveNonblock)
                .unwrap();

        let error = run_with_context(
            request(data_dir, false),
            context(&server, executable.clone(), "0.1.0"),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert!(error.to_string().contains("HuntProxy is running"));
        assert_eq!(fs::read(executable).unwrap(), original);
        assert!(staging_files(directory.path()).is_empty());
    }

    fn coordinated_script(fail_prepare: bool, bad_activation: bool) -> Vec<u8> {
        // Only the installed filename reports the intentionally bad version;
        // the verified staged binary passes both preflight inspections.
        format!(
            r#"#!/bin/sh
case "$1" in
  --version)
    if [ "{bad_activation}" = true ] && [ "$(basename "$0")" = HuntProxy ]; then
      printf 'HuntProxy 9.9.9\n'
    else printf 'HuntProxy 0.2.0\n'; fi ;;
  release-info) printf '%s\n' '{{"version":"0.2.0","schema":15,"plugins":["racer","new-target"]}}' ;;
  prepare-update)
    directory=$3
    mkdir -p "$directory/plugins/racer" "$directory/plugins/new-target"
    printf 'prepared package' > "$directory/plugins/racer/fixture.txt"
    printf 'new package' > "$directory/plugins/new-target/fixture.txt"
    if [ "{fail_prepare}" = true ]; then
      printf 'interrupted preparation' > "$directory/huntproxy.db"
      printf 'fixture preparation failed\n' >&2
      exit 1
    fi
    printf '%s\n' '{{"ok":true,"version":"0.2.0","schema":15}}' ;;
  *) exit 1 ;;
esac
"#
        )
        .into_bytes()
    }

    fn seed_update_state(directory: &Path) -> Config {
        let config = Config::load(Some(directory.join("data"))).unwrap();
        config.ensure_layout().unwrap();
        let database = rusqlite::Connection::open(config.db_path()).unwrap();
        database.execute_batch("CREATE TABLE saved_fixture (name TEXT); INSERT INTO saved_fixture VALUES ('Existing project'); PRAGMA user_version=14;").unwrap();
        fs::create_dir(config.plugin_dir.join("racer")).unwrap();
        fs::write(
            config.plugin_dir.join("racer/fixture.txt"),
            b"previous package",
        )
        .unwrap();
        fs::create_dir(config.plugin_dir.join("custom-tool")).unwrap();
        fs::write(
            config.plugin_dir.join("custom-tool/fixture.txt"),
            b"custom preserved",
        )
        .unwrap();
        config
    }

    #[tokio::test]
    async fn coordinated_update_preserves_projects_and_keeps_one_private_restore_point() {
        let directory = tempfile::tempdir().unwrap();
        let config = seed_update_state(directory.path());
        let executable = directory.path().join("HuntProxy");
        write_script(&executable, "0.1.1");
        let older = DataSnapshot::capture(&config, "v0.1.1", &[]).unwrap();
        let release = archive(&[
            ("HuntProxy", coordinated_script(false, false)),
            ("LICENSE", b"fixture license".to_vec()),
        ]);
        let server = MockServer::start().await;
        mock_release(&server, "v0.2.0", &release, None).await;
        let outcome = run_with_context(
            UpdateRequest {
                check: false,
                version: Some("v0.2.0".into()),
                data_dir: Some(config.data_dir.clone()),
            },
            context(&server, executable.clone(), "0.1.1"),
        )
        .await
        .unwrap();
        let UpdateOutcome::Installed {
            data_backup_path: Some(root),
            daemon_restarted,
            ..
        } = outcome
        else {
            panic!("expected installed release")
        };
        assert!(!daemon_restarted);
        assert!(root.join("restore.json").exists());
        assert!(!older.root.exists());
        assert!(!config.runtime_dir.join("update-journal.json").exists());
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join("database.sqlite3"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::read(config.plugin_dir.join("racer/fixture.txt")).unwrap(),
            b"prepared package"
        );
        assert_eq!(
            fs::read(config.plugin_dir.join("custom-tool/fixture.txt")).unwrap(),
            b"custom preserved"
        );
        let database = rusqlite::Connection::open(config.db_path()).unwrap();
        assert_eq!(
            database
                .query_row("SELECT name FROM saved_fixture", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "Existing project"
        );
        assert_eq!(
            fs::read(directory.path().join("HuntProxy.previous")).unwrap(),
            script("0.1.1")
        );
        assert!(staging_files(directory.path()).is_empty());
    }

    #[tokio::test]
    async fn coordinated_preparation_and_activation_failures_restore_binary_database_and_plugins() {
        for (fail_prepare, bad_activation) in [(true, false), (false, true)] {
            let directory = tempfile::tempdir().unwrap();
            let config = seed_update_state(directory.path());
            let executable = directory.path().join("HuntProxy");
            write_script(&executable, "0.1.1");
            let release = archive(&[(
                "HuntProxy",
                coordinated_script(fail_prepare, bad_activation),
            )]);
            let server = MockServer::start().await;
            mock_release(&server, "v0.2.0", &release, None).await;
            let error = run_with_context(
                UpdateRequest {
                    check: false,
                    version: Some("v0.2.0".into()),
                    data_dir: Some(config.data_dir.clone()),
                },
                context(&server, executable.clone(), "0.1.1"),
            )
            .await
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("previous installation was restored"),
                "{error}"
            );
            assert_eq!(fs::read(&executable).unwrap(), script("0.1.1"));
            assert!(!config.runtime_dir.join("update-journal.json").exists());
            assert_eq!(
                fs::read(config.plugin_dir.join("racer/fixture.txt")).unwrap(),
                b"previous package"
            );
            assert!(!config.plugin_dir.join("new-target").exists());
            assert_eq!(
                fs::read(config.plugin_dir.join("custom-tool/fixture.txt")).unwrap(),
                b"custom preserved"
            );
            let database = rusqlite::Connection::open(config.db_path()).unwrap();
            assert_eq!(
                database
                    .query_row("SELECT name FROM saved_fixture", [], |row| row
                        .get::<_, String>(0))
                    .unwrap(),
                "Existing project"
            );
            assert_eq!(
                database
                    .pragma_query_value(None, "user_version", |row| row.get::<_, i32>(0))
                    .unwrap(),
                14
            );
            assert!(staging_files(directory.path()).is_empty());
        }
    }

    #[tokio::test]
    async fn legacy_downgrade_rejects_current_schema_before_downloading_assets() {
        let directory = tempfile::tempdir().unwrap();
        let config = seed_update_state(directory.path());
        let database = rusqlite::Connection::open(config.db_path()).unwrap();
        database.pragma_update(None, "user_version", 15).unwrap();
        let executable = directory.path().join("HuntProxy");
        write_script(&executable, "0.2.0");
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/{REPOSITORY}/releases/tags/v0.1.1")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"tag_name":"v0.1.1"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let error = run_with_context(
            request(config.data_dir, false),
            context(&server, executable.clone(), "0.2.0"),
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("requires HuntProxy 0.2 or newer"));
        assert_eq!(fs::read(executable).unwrap(), script("0.2.0"));
        assert!(staging_files(directory.path()).is_empty());
    }

    #[tokio::test]
    async fn external_binary_replacement_preserves_recovery_and_does_not_claim_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let config = seed_update_state(directory.path());
        let executable = directory.path().join("HuntProxy");
        write_script(&executable, "0.1.1");
        let release_script = String::from_utf8(coordinated_script(false, false))
            .unwrap()
            .replace(
                "directory=$3",
                r#"directory=$3
    printf '%s\n' '#!/bin/sh' 'printf "HuntProxy 0.3.0\n"' > "$directory/../HuntProxy""#,
            );
        let release = archive(&[("HuntProxy", release_script.into_bytes())]);
        let server = MockServer::start().await;
        mock_release(&server, "v0.2.0", &release, None).await;
        let error = run_with_context(
            UpdateRequest {
                check: false,
                version: Some("v0.2.0".into()),
                data_dir: Some(config.data_dir.clone()),
            },
            context(&server, executable.clone(), "0.1.1"),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert!(
            error.to_string().contains("recovery requires attention"),
            "{error}"
        );
        assert!(!error
            .to_string()
            .contains("previous installation was restored"));
        assert_eq!(
            inspect_binary_version(&executable).await.unwrap(),
            StableVersion::parse("0.3.0").unwrap()
        );
        assert!(config.runtime_dir.join("update-journal.json").exists());
        assert_eq!(
            fs::read(config.plugin_dir.join("racer/fixture.txt")).unwrap(),
            b"prepared package"
        );
        assert!(!app::daemon_is_active(&config).unwrap());
        assert!(staging_files(directory.path()).is_empty());
    }

    #[test]
    fn update_lock_inode_is_reused_and_mutual_exclusion_survives_release() {
        use std::os::unix::fs::MetadataExt;
        let directory = tempfile::tempdir().unwrap();
        let first = UpdateLock::acquire(directory.path()).unwrap();
        assert!(UpdateLock::acquire(directory.path()).is_err());
        let path = directory.path().join(".HuntProxy.update.lock");
        let inode = fs::metadata(&path).unwrap().ino();
        drop(first);
        let _second = UpdateLock::acquire(directory.path()).unwrap();
        assert_eq!(fs::metadata(path).unwrap().ino(), inode);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn version_inspection_waits_for_a_transient_executable_write_handle() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("HuntProxy");
        write_script(&executable, "0.2.0");
        let writer = OpenOptions::new().write(true).open(&executable).unwrap();
        let inspect = tokio::spawn(async move { inspect_binary_version(&executable).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !inspect.is_finished(),
            "busy executable should still be awaiting its closing writer"
        );
        drop(writer);
        let version = tokio::time::timeout(Duration::from_secs(2), inspect)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(version, StableVersion::parse("0.2.0").unwrap());
    }

    #[test]
    fn archive_rejects_unexpected_members_without_leaving_staging_files() {
        let directory = tempfile::tempdir().unwrap();
        let archive_path = directory.path().join("release.tar.gz");
        fs::write(
            &archive_path,
            archive(&[
                ("HuntProxy", script("0.1.1")),
                ("unexpected", b"nope".to_vec()),
            ]),
        )
        .unwrap();
        assert!(extract_staged_binary(&archive_path, directory.path()).is_err());
        assert!(staging_files(directory.path()).is_empty());
    }

    #[test]
    fn archive_rejects_a_symlinked_executable() {
        let directory = tempfile::tempdir().unwrap();
        let archive_path = directory.path().join("release.tar.gz");
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("/tmp/not-huntproxy").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "HuntProxy", std::io::empty())
            .unwrap();
        let encoded = builder.into_inner().unwrap().finish().unwrap();
        fs::write(&archive_path, encoded).unwrap();
        assert!(extract_staged_binary(&archive_path, directory.path()).is_err());
        assert!(staging_files(directory.path()).is_empty());
    }
}
