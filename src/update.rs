//! Check and install verified HuntProxy GitHub Release binaries.

use crate::app;
use crate::config::Config;
use crate::domain::{DomainError, DomainResult, ErrorCode};
use flate2::read::GzDecoder;
use futures::StreamExt;
use rand::RngCore;
use serde::Deserialize;
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

    let daemon_config = daemon_config(request.data_dir);
    ensure_daemon_stopped(&daemon_config)?;
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

    let mut staged = extract_staged_binary(&archive_path, parent)?;
    let staged_version = inspect_binary_version(staged.path()).await?;
    if staged_version != target {
        return Err(update_error(format!(
            "release {} contains HuntProxy {}",
            target.tag(),
            staged_version
        )));
    }
    archive_guard.remove_now()?;

    ensure_daemon_stopped(&daemon_config)?;
    if hash_file(executable)? != initial_hash {
        return Err(DomainError::new(
            ErrorCode::Conflict,
            "the installed HuntProxy binary changed during the update; retry",
        ));
    }

    let backup_path = backup_path(executable)?;
    let mut backup = copy_to_temp(executable, parent, "previous")?;
    if hash_file(backup.path())? != initial_hash {
        return Err(update_error("could not verify the rollback binary"));
    }
    if hash_file(executable)? != initial_hash {
        return Err(DomainError::new(
            ErrorCode::Conflict,
            "the installed HuntProxy binary changed during the update; retry",
        ));
    }
    fs::rename(backup.path(), &backup_path)
        .map_err(|error| update_error(format!("install rollback binary: {error}")))?;
    backup.disarm();
    sync_directory(parent)?;
    ensure_daemon_stopped(&daemon_config)?;

    if let Err(error) = fs::rename(staged.path(), executable) {
        return Err(update_error(format!(
            "replace HuntProxy binary: {error}; rollback remains at {}",
            backup_path.display()
        )));
    }
    staged.disarm();
    if let Err(error) = sync_directory(parent) {
        return Err(restore_previous(
            &backup_path,
            executable,
            parent,
            format!("could not sync the installed binary: {error}"),
        ));
    }

    match inspect_binary_version(executable).await {
        Ok(version) if version == target => {}
        result => {
            let reason = match result {
                Ok(version) => format!("installed binary reported HuntProxy {version}"),
                Err(error) => error.to_string(),
            };
            return Err(restore_previous(&backup_path, executable, parent, reason));
        }
    }

    Ok(UpdateOutcome::Installed {
        previous: current_text,
        installed: target_text,
        backup_path,
    })
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
                std::io::copy(&mut entry, &mut output)
                    .map_err(|error| update_error(format!("extract HuntProxy: {error}")))?;
                output
                    .sync_all()
                    .map_err(|error| update_error(format!("sync HuntProxy: {error}")))?;
                set_executable(&path)?;
                output
                    .sync_all()
                    .map_err(|error| update_error(format!("sync HuntProxy: {error}")))?;
                staged = Some(TempPath::new(path));
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
    let mut command = tokio::process::Command::new(path);
    command.arg("--version").kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
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
    Ok(TempPath::new(path))
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

fn restore_previous(
    backup: &Path,
    executable: &Path,
    parent: &Path,
    reason: String,
) -> DomainError {
    if let Err(error) = fs::rename(backup, executable) {
        return update_error(format!(
            "{reason}; automatic rollback failed: {error}; rollback remains at {}",
            backup.display()
        ));
    }
    if let Err(error) = sync_directory(parent) {
        return update_error(format!(
            "{reason}; the previous binary was restored but directory sync failed: {error}"
        ));
    }
    update_error(format!("{reason}; the previous binary was restored"))
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
    path: PathBuf,
    #[cfg(unix)]
    lock: Option<nix::fcntl::Flock<File>>,
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
            Ok(Self {
                path,
                lock: Some(lock),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            Ok(Self { path })
        }
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        #[cfg(unix)]
        let _ = self.lock.take();
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
                    .is_some_and(|name| name.starts_with(".HuntProxy."))
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
                backup_path: directory.path().join("HuntProxy.previous")
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
