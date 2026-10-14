//! Release-owned runtime and first-party plugin provisioning.

use crate::config::{create_private_dir, write_private_file, Config};
use crate::domain::{DomainError, DomainResult, ErrorCode};
use flate2::read::GzDecoder;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

const PLAYWRIGHT_VERSION: &str = "1.64.0";
const NODE_VERSION: &str = "22.23.2";
const CHROMIUM_REVISION: &str = "1248";
const CHROMIUM_VERSION: &str = "156.0.8078.4";
const MAX_PLUGIN_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PLUGIN_ENTRIES: usize = 20_000;
const MAX_PLAYWRIGHT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PLAYWRIGHT_ENTRIES: usize = 10_000;
const MAX_NODE_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_NODE_EXPANDED_BYTES: u64 = 768 * 1024 * 1024;
const MAX_NODE_ENTRIES: usize = 150_000;
const MAX_PLUGIN_CATALOG_BYTES: u64 = 8 * 1024 * 1024;
const PLUGIN_SWAP_MARKER: &[u8] = b"HuntProxy plugin swap v1\n";
const PLUGIN_SOURCE_MARKER: &str = ".huntproxy-first-party-source";

const PLUGIN_CATALOG_ARCHIVE: &[u8] =
    include_bytes!("../resources/release/plugins-catalog.tar.zst");
const PLAYWRIGHT_ARCHIVE: &[u8] = include_bytes!("../resources/release/playwright-core-1.64.0.tgz");
const PLAYWRIGHT_MANIFEST: &[u8] = include_bytes!("../resources/release/playwright-core.json");
const NODE_MANIFEST: &[u8] = include_bytes!("../resources/release/node-runtimes.json");

#[derive(Debug, Clone)]
pub struct PreparedInstallation {
    pub node_path: PathBuf,
    pub worker_path: PathBuf,
    pub playwright_core_path: PathBuf,
    pub chromium_path: PathBuf,
    pub preserved_plugins: Vec<String>,
}

/// Inspect a previously validated release installation without changing disk or
/// launching a process. Explicit configuration and environment paths win.
pub fn inspect(config: &Config) -> Option<PreparedInstallation> {
    let marker: serde_json::Value =
        serde_json::from_slice(&fs::read(config.runtime_dir.join("browser-validation.json")).ok()?)
            .ok()?;
    if marker
        .get("schema_version")
        .and_then(|value| value.as_u64())
        != Some(1)
    {
        return None;
    }
    let marker_path = |key: &str| {
        marker
            .get(key)
            .and_then(|value| value.get("path"))
            .and_then(|value| value.as_str())
            .map(PathBuf::from)
    };
    let node_path = config
        .node_path
        .clone()
        .or_else(|| marker_path("node"))
        .or_else(|| {
            Some(
                config
                    .runtime_dir
                    .join(format!("node-{NODE_VERSION}/bin/node")),
            )
        })
        .filter(|path| path.is_file())?
        .canonicalize()
        .ok()?;
    let worker_path = config
        .browser_worker_path
        .clone()
        .or_else(|| {
            std::env::var_os("HUNTPROXY_BROWSER_WORKER_PATH")
                .or_else(|| std::env::var_os("BB_BROWSER_WORKER_PATH"))
                .map(PathBuf::from)
        })
        .or_else(|| marker_path("worker"))
        .filter(|path| path.is_file())?
        .canonicalize()
        .ok()?;
    let explicit_playwright = std::env::var_os("HUNTPROXY_PLAYWRIGHT_CORE_PATH")
        .or_else(|| std::env::var_os("BB_PLAYWRIGHT_CORE_PATH"))
        .map(PathBuf::from)
        .or_else(|| config.browser_playwright_core_path.clone());
    let playwright_core_path = explicit_playwright.clone().unwrap_or_else(|| {
        config
            .runtime_dir
            .join(format!("playwright-core-{PLAYWRIGHT_VERSION}"))
    });
    let expected_playwright = explicit_playwright.is_none().then_some(PLAYWRIGHT_VERSION);
    let playwright_runtime =
        validate_playwright_directory(&playwright_core_path, expected_playwright).ok()?;
    let playwright_core_path = playwright_core_path.canonicalize().ok()?;
    let explicit_chromium = [
        "HUNTPROXY_CHROME_EXECUTABLE",
        "BB_CHROME_EXECUTABLE",
        "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH",
    ]
    .into_iter()
    .find_map(|name| std::env::var_os(name).map(PathBuf::from))
    .or_else(|| config.browser_chromium_path.clone());
    let marker_matches_runtime = marker.get("playwright").and_then(|value| value.as_str())
        == Some(playwright_runtime.version.as_str())
        && marker
            .get("chromium_revision")
            .and_then(|value| value.as_str())
            == Some(playwright_runtime.chromium_revision.as_str())
        && marker
            .get("chromium_version")
            .and_then(|value| value.as_str())
            == Some(playwright_runtime.chromium_version.as_str());
    let chromium_path = explicit_chromium
        .or_else(|| {
            marker_matches_runtime
                .then(|| marker_path("chromium"))
                .flatten()
        })
        .filter(|path| path.is_file())?
        .canonicalize()
        .ok()?;
    Some(PreparedInstallation {
        node_path,
        worker_path,
        playwright_core_path,
        chromium_path,
        preserved_plugins: Vec::new(),
    })
}

/// Names of first-party packages owned by this release. This is derived from
/// the embedded catalog so update rollback code cannot drift from provisioning.
pub fn bundled_plugin_names() -> DomainResult<Vec<String>> {
    let catalog = embedded_plugin_catalog()?;
    let current = catalog
        .snapshots
        .iter()
        .find(|snapshot| snapshot.commit == catalog.current_commit)
        .ok_or_else(|| install_error("embedded plugin catalog has no current snapshot"))?;
    validate_package_names(current.packages.keys())?;
    Ok(current.packages.keys().cloned().collect())
}

fn embedded_plugin_catalog() -> DomainResult<PluginCatalog> {
    let decoder = zstd::stream::read::Decoder::new(PLUGIN_CATALOG_ARCHIVE)
        .map_err(|error| install_error(format!("decode embedded plugin catalog: {error}")))?;
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().map_err(storage_error)? {
        let mut entry = entry.map_err(storage_error)?;
        if entry.path().map_err(storage_error)?.as_ref() != Path::new("catalog.json") {
            continue;
        }
        if entry.size() > MAX_PLUGIN_CATALOG_BYTES {
            return Err(install_error("embedded plugin catalog is too large"));
        }
        let mut encoded = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut encoded).map_err(storage_error)?;
        return serde_json::from_slice(&encoded)
            .map_err(|error| install_error(format!("embedded plugin catalog: {error}")));
    }
    Err(install_error("embedded plugin catalog is missing"))
}

#[derive(Debug, Deserialize, Serialize)]
struct PluginCatalog {
    schema_version: u32,
    current_commit: String,
    snapshots: Vec<PluginSnapshot>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PluginSnapshot {
    commit: String,
    packages: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct PlaywrightManifest {
    schema_version: u32,
    version: String,
    sha512: String,
    chromium_revision: String,
    chromium_version: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PlaywrightRuntime {
    version: String,
    chromium_revision: String,
    chromium_version: String,
}

#[derive(Debug, Deserialize)]
struct NodeManifest {
    schema_version: u32,
    version: String,
    source: String,
    platforms: BTreeMap<String, NodeAsset>,
}

#[derive(Debug, Deserialize)]
struct NodeAsset {
    asset: String,
    sha256: String,
}

#[derive(Debug)]
struct InstallationLock {
    #[cfg(unix)]
    _file: nix::fcntl::Flock<File>,
    #[cfg(not(unix))]
    _file: File,
}

struct TemporaryDirectory(PathBuf);

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Prepare the exact release-owned runtime and reconcile official plugins.
/// Explicit configured/environment overrides remain authoritative.
pub async fn prepare(config: &Config) -> DomainResult<PreparedInstallation> {
    config.ensure_layout()?;
    let _lock = acquire_installation_lock(config).await?;

    let node_path = prepare_node(config).await?;
    let playwright_core_path = prepare_playwright(config)?;
    let worker_path = prepare_worker(config)?;
    let chromium_path = prepare_chromium(config, &node_path, &playwright_core_path).await?;
    let mut prepared = PreparedInstallation {
        node_path,
        worker_path,
        playwright_core_path,
        chromium_path,
        preserved_plugins: Vec::new(),
    };
    validate_browser_once(config, &prepared).await?;
    prepared.preserved_plugins = prepare_plugins(config)?;
    Ok(prepared)
}

async fn acquire_installation_lock(config: &Config) -> DomainResult<InstallationLock> {
    let path = config.runtime_dir.join("installation.lock");
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|error| install_error(format!("open installation lock: {error}")))?;
    #[cfg(unix)]
    let file = tokio::task::spawn_blocking(move || {
        nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_, error)| error)
    })
    .await
    .map_err(|error| install_error(format!("installation lock task: {error}")))?
    .map_err(|error| install_error(format!("installation lock: {error}")))?;
    Ok(InstallationLock { _file: file })
}

fn prepare_worker(config: &Config) -> DomainResult<PathBuf> {
    let explicit = config.browser_worker_path.clone().or_else(|| {
        std::env::var_os("HUNTPROXY_BROWSER_WORKER_PATH")
            .or_else(|| std::env::var_os("BB_BROWSER_WORKER_PATH"))
            .map(PathBuf::from)
    });
    if let Some(path) = explicit {
        return canonical_regular_file(&path, "configured browser worker");
    }
    let directory = crate::browser::prepare_browser_worker_installation(&config.data_dir)?;
    canonical_regular_file(&directory.join("index.js"), "embedded browser worker")
}

fn prepare_playwright(config: &Config) -> DomainResult<PathBuf> {
    if let Some(path) = std::env::var_os("HUNTPROXY_PLAYWRIGHT_CORE_PATH")
        .or_else(|| std::env::var_os("BB_PLAYWRIGHT_CORE_PATH"))
        .map(PathBuf::from)
        .or_else(|| config.browser_playwright_core_path.clone())
    {
        validate_playwright_directory(&path, None)?;
        return path.canonicalize().map_err(storage_error);
    }
    let manifest: PlaywrightManifest = serde_json::from_slice(PLAYWRIGHT_MANIFEST)
        .map_err(|error| install_error(format!("embedded Playwright manifest: {error}")))?;
    if manifest.schema_version != 1
        || manifest.version != PLAYWRIGHT_VERSION
        || manifest.sha512 != hex::encode(Sha512::digest(PLAYWRIGHT_ARCHIVE))
        || manifest.chromium_revision != CHROMIUM_REVISION
        || manifest.chromium_version != CHROMIUM_VERSION
    {
        return Err(install_error(
            "embedded Playwright archive integrity mismatch",
        ));
    }
    let destination = config
        .runtime_dir
        .join(format!("playwright-core-{PLAYWRIGHT_VERSION}"));
    recover_directory_replace(&destination)?;
    let marker = destination.join(".huntproxy-integrity.json");
    if fs::read(&marker).ok().as_deref() == Some(PLAYWRIGHT_MANIFEST)
        && validate_playwright_directory(&destination, Some(PLAYWRIGHT_VERSION)).is_ok()
    {
        return destination.canonicalize().map_err(storage_error);
    }

    let staging = sibling_directory(&destination, "incoming")?;
    let staging_guard = TemporaryDirectory(staging.clone());
    create_private_dir(&staging)?;
    extract_playwright_archive(PLAYWRIGHT_ARCHIVE, &staging)?;
    validate_playwright_directory(&staging, Some(PLAYWRIGHT_VERSION))?;
    write_private_file(
        &staging.join(".huntproxy-integrity.json"),
        PLAYWRIGHT_MANIFEST,
    )?;
    replace_directory(&staging, &destination)?;
    drop(staging_guard);
    destination.canonicalize().map_err(storage_error)
}

async fn prepare_node(config: &Config) -> DomainResult<PathBuf> {
    if let Some(path) = config.node_path.as_deref() {
        let path = canonical_regular_file(path, "configured Node.js")?;
        validate_node(&path, None).await?;
        return Ok(path);
    }

    let manifest: NodeManifest = serde_json::from_slice(NODE_MANIFEST)
        .map_err(|error| install_error(format!("embedded Node.js manifest: {error}")))?;
    if manifest.schema_version != 1 || manifest.version != NODE_VERSION {
        return Err(install_error("embedded Node.js manifest is invalid"));
    }
    let key = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let asset = manifest
        .platforms
        .get(&key)
        .ok_or_else(|| install_error(format!("Node.js runtime is unavailable for {key}")))?;
    let destination = config.runtime_dir.join(format!("node-{NODE_VERSION}"));
    recover_directory_replace(&destination)?;
    let node = destination.join("bin/node");
    if node.is_file() && validate_node(&node, Some(NODE_VERSION)).await.is_ok() {
        return node.canonicalize().map_err(storage_error);
    }

    let url = format!("{}/{}", manifest.source.trim_end_matches('/'), asset.asset);
    let client = wreq::Client::builder()
        .redirect(wreq::redirect::Policy::limited(5))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .https_only(true)
        .build()
        .map_err(|error| install_error(format!("build Node.js download client: {error}")))?;
    let response = client
        .get(&url)
        .header(
            wreq::header::USER_AGENT,
            format!("HuntProxy/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await
        .map_err(|error| install_error(format!("download Node.js: {error}")))?;
    if !response.status().is_success() {
        return Err(install_error(format!(
            "download Node.js: HTTP {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_NODE_ARCHIVE_BYTES)
    {
        return Err(install_error("Node.js archive exceeds the size limit"));
    }
    let archive_path = sibling_file(&destination, "download")?;
    let archive_guard = TemporaryFile(archive_path.clone());
    let mut file = tokio::fs::File::create(&archive_path)
        .await
        .map_err(storage_error)?;
    let mut stream = response.bytes_stream();
    let mut size = 0u64;
    let mut hasher = Sha256::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| install_error(format!("download Node.js: {error}")))?;
        size = size.saturating_add(chunk.len() as u64);
        if size > MAX_NODE_ARCHIVE_BYTES {
            return Err(install_error("Node.js archive exceeds the size limit"));
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(storage_error)?;
    }
    file.sync_all().await.map_err(storage_error)?;
    drop(file);
    if hex::encode(hasher.finalize()) != asset.sha256 {
        return Err(install_error(
            "downloaded Node.js archive checksum mismatch",
        ));
    }

    let staging = sibling_directory(&destination, "incoming")?;
    let staging_guard = TemporaryDirectory(staging.clone());
    create_private_dir(&staging)?;
    extract_node_archive(&archive_path, &staging)?;
    validate_node(&staging.join("bin/node"), Some(NODE_VERSION)).await?;
    replace_directory(&staging, &destination)?;
    drop(staging_guard);
    drop(archive_guard);
    destination
        .join("bin/node")
        .canonicalize()
        .map_err(storage_error)
}

struct TemporaryFile(PathBuf);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

async fn validate_node(path: &Path, exact: Option<&str>) -> DomainResult<()> {
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new(path).arg("--version").output(),
    )
    .await
    .map_err(|_| install_error("Node.js version check timed out"))?
    .map_err(|error| install_error(format!("start Node.js: {error}")))?;
    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !output.status.success() {
        return Err(install_error("Node.js version check failed"));
    }
    if let Some(exact) = exact {
        if version != format!("v{exact}") {
            return Err(install_error(format!("managed Node.js must be v{exact}")));
        }
    } else {
        let major = version
            .strip_prefix('v')
            .and_then(|value| value.split('.').next())
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        if major < 20 {
            return Err(install_error("Node.js 20 or newer is required"));
        }
    }
    Ok(())
}

fn extract_node_archive(archive_path: &Path, destination: &Path) -> DomainResult<()> {
    let file = File::open(archive_path).map_err(storage_error)?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    let mut entries = 0usize;
    let mut expanded = 0u64;
    for entry in archive.entries().map_err(storage_error)? {
        let mut entry = entry.map_err(storage_error)?;
        entries += 1;
        expanded = expanded.saturating_add(entry.size());
        if entries > MAX_NODE_ENTRIES || expanded > MAX_NODE_EXPANDED_BYTES {
            return Err(install_error("Node.js archive exceeds extraction limits"));
        }
        let source = entry.path().map_err(storage_error)?.into_owned();
        let relative = strip_first_component(&source)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let target = destination.join(&relative);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            create_private_dir(&target)?;
        } else if kind.is_file() {
            if let Some(parent) = target.parent() {
                create_private_dir(parent)?;
            }
            entry.unpack(&target).map_err(storage_error)?;
        } else if kind.is_symlink() {
            let link = entry
                .link_name()
                .map_err(storage_error)?
                .ok_or_else(|| install_error("Node.js archive symlink has no target"))?;
            validate_archive_symlink(&relative, &link)?;
            if let Some(parent) = target.parent() {
                create_private_dir(parent)?;
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(&link, &target).map_err(storage_error)?;
            #[cfg(not(unix))]
            return Err(install_error("Node.js archive symlinks are unsupported"));
        } else {
            return Err(install_error(
                "Node.js archive contains an unsupported entry",
            ));
        }
    }
    Ok(())
}

fn extract_playwright_archive(encoded: &[u8], destination: &Path) -> DomainResult<()> {
    if encoded.len() as u64 > MAX_PLAYWRIGHT_BYTES {
        return Err(install_error(
            "embedded Playwright archive exceeds the size limit",
        ));
    }
    let mut archive = tar::Archive::new(GzDecoder::new(encoded));
    let mut entries = 0usize;
    for entry in archive.entries().map_err(storage_error)? {
        let mut entry = entry.map_err(storage_error)?;
        entries += 1;
        if entries > MAX_PLAYWRIGHT_ENTRIES {
            return Err(install_error(
                "embedded Playwright archive has too many files",
            ));
        }
        let relative = strip_first_component(&entry.path().map_err(storage_error)?)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let target = destination.join(relative);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            create_private_dir(&target)?;
        } else if kind.is_file() {
            if let Some(parent) = target.parent() {
                create_private_dir(parent)?;
            }
            entry.unpack(&target).map_err(storage_error)?;
        } else {
            return Err(install_error(
                "embedded Playwright archive contains an unsupported entry",
            ));
        }
    }
    Ok(())
}

fn validate_playwright_directory(
    path: &Path,
    exact: Option<&str>,
) -> DomainResult<PlaywrightRuntime> {
    let package: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("package.json")).map_err(storage_error)?)
            .map_err(|error| install_error(format!("read Playwright package metadata: {error}")))?;
    let version = package
        .get("version")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if package.get("name").and_then(|v| v.as_str()) != Some("playwright-core")
        || version.is_empty()
        || exact.is_some_and(|expected| version != expected)
        || !path.join("cli.js").is_file()
    {
        return Err(install_error("Playwright SDK directory is invalid"));
    }
    let browsers_path = path.join("browsers.json");
    let metadata = fs::metadata(&browsers_path).map_err(storage_error)?;
    if metadata.len() > 64 * 1024 {
        return Err(install_error("Playwright browser metadata is too large"));
    }
    let browsers: serde_json::Value =
        serde_json::from_slice(&fs::read(browsers_path).map_err(storage_error)?)
            .map_err(|error| install_error(format!("read Playwright browser metadata: {error}")))?;
    let chromium = browsers
        .get("browsers")
        .and_then(|value| value.as_array())
        .and_then(|browsers| {
            let mut matching = browsers.iter().filter(|browser| {
                browser.get("name").and_then(|value| value.as_str()) == Some("chromium")
                    && browser
                        .get("installByDefault")
                        .and_then(|value| value.as_bool())
                        == Some(true)
            });
            let browser = matching.next()?;
            matching.next().is_none().then_some(browser)
        })
        .ok_or_else(|| install_error("Playwright browser metadata has no default Chromium"))?;
    let chromium_revision = chromium
        .get("revision")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let chromium_version = chromium
        .get("browserVersion")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if chromium_revision.is_empty()
        || chromium_revision.len() > 16
        || !chromium_revision.bytes().all(|byte| byte.is_ascii_digit())
        || chromium_version.is_empty()
        || chromium_version.len() > 64
    {
        return Err(install_error("Playwright Chromium metadata is invalid"));
    }
    Ok(PlaywrightRuntime {
        version: version.to_owned(),
        chromium_revision: chromium_revision.to_owned(),
        chromium_version: chromium_version.to_owned(),
    })
}

async fn prepare_chromium(
    config: &Config,
    node: &Path,
    playwright: &Path,
) -> DomainResult<PathBuf> {
    for name in [
        "HUNTPROXY_CHROME_EXECUTABLE",
        "BB_CHROME_EXECUTABLE",
        "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH",
    ] {
        if let Some(path) = std::env::var_os(name).map(PathBuf::from) {
            return canonical_regular_file(&path, "configured Chromium");
        }
    }
    if let Some(path) = config.browser_chromium_path.as_deref() {
        return canonical_regular_file(path, "configured Chromium");
    }
    let runtime = validate_playwright_directory(playwright, None)?;
    if runtime.version == PLAYWRIGHT_VERSION {
        require_supported_managed_browser_platform().await?;
    }
    let local_browsers = playwright.join(".local-browsers");
    if let Some(path) = managed_chromium_binary(playwright, &runtime.chromium_revision) {
        return path.canonicalize().map_err(storage_error);
    }

    create_private_dir(&local_browsers)?;
    let mut command = Command::new(node);
    command
        .arg(playwright.join("cli.js"))
        .args(["install", "chromium"])
        .env("PLAYWRIGHT_BROWSERS_PATH", "0")
        .env("PATH", private_path(node))
        .current_dir(playwright)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(600), command.output())
        .await
        .map_err(|_| install_error("Chromium installation timed out"))?
        .map_err(|error| install_error(format!("start Chromium installer: {error}")))?;
    if !output.status.success() {
        return Err(install_error(format!(
            "Chromium installation failed: {}",
            bounded_text(&output.stderr, 4096)
        )));
    }
    managed_chromium_binary(playwright, &runtime.chromium_revision)
        .ok_or_else(|| install_error("Chromium installer completed without a browser executable"))?
        .canonicalize()
        .map_err(storage_error)
}

#[cfg(target_os = "macos")]
async fn require_supported_managed_browser_platform() -> DomainResult<()> {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output(),
    )
    .await
    .map_err(|_| install_error("macOS version check timed out"))?
    .map_err(|error| install_error(format!("check macOS version: {error}")))?;
    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let major = version
        .split('.')
        .next()
        .and_then(|value| value.parse::<u32>().ok());
    if !output.status.success() || major.is_none() {
        return Err(install_error("could not determine the macOS version"));
    }
    if major.is_some_and(|value| value < 14) {
        return Err(install_error(format!(
            "managed Chromium requires macOS 14 or newer (found macOS {version}); upgrade macOS or configure browser_chromium_path to an explicitly supported browser"
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
async fn require_supported_managed_browser_platform() -> DomainResult<()> {
    Ok(())
}

fn managed_chromium_binary(playwright: &Path, revision: &str) -> Option<PathBuf> {
    find_chromium_binary(
        &playwright
            .join(".local-browsers")
            .join(format!("chromium-{revision}")),
        8,
    )
}

fn find_chromium_binary(directory: &Path, depth: usize) -> Option<PathBuf> {
    if depth == 0 {
        return None;
    }
    let mut entries = fs::read_dir(directory)
        .ok()?
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in &entries {
        let path = entry.path();
        if path.is_file()
            && matches!(
                entry.file_name().to_str(),
                Some(
                    "chrome" | "chromium" | "chrome.exe" | "Chromium" | "Google Chrome for Testing"
                )
            )
        {
            return Some(path);
        }
    }
    entries.into_iter().find_map(|entry| {
        let path = entry.path();
        path.is_dir()
            .then(|| find_chromium_binary(&path, depth - 1))
            .flatten()
    })
}

fn private_path(node: &Path) -> std::ffi::OsString {
    let mut paths = Vec::new();
    if let Some(parent) = node.parent() {
        paths.push(parent.to_path_buf());
    }
    if let Some(existing) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&existing));
    }
    std::env::join_paths(paths).unwrap_or_default()
}

/// Launch an isolated browser worker and verify hello/start/stop RPCs.
pub async fn validate_browser(prepared: &PreparedInstallation) -> DomainResult<()> {
    let mut command = Command::new(&prepared.node_path);
    command
        .arg(&prepared.worker_path)
        .env(
            "HUNTPROXY_PLAYWRIGHT_CORE_PATH",
            &prepared.playwright_core_path,
        )
        .env("HUNTPROXY_CHROME_EXECUTABLE", &prepared.chromium_path)
        .env("PLAYWRIGHT_BROWSERS_PATH", "0")
        .env("PATH", private_path(&prepared.node_path))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(parent) = prepared.worker_path.parent() {
        command.current_dir(parent);
    }
    let mut child = command
        .spawn()
        .map_err(|error| install_error(format!("start browser validation: {error}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| install_error("browser validation stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| install_error("browser validation stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| install_error("browser validation stderr unavailable"))?;
    let stderr_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut captured = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let Ok(size) = reader.read(&mut chunk).await else {
                break;
            };
            if size == 0 {
                break;
            }
            let remaining = 4096usize.saturating_sub(captured.len());
            captured.extend_from_slice(&chunk[..size.min(remaining)]);
        }
        captured
    });
    let mut stdout = BufReader::new(stdout);
    let validation = tokio::time::timeout(Duration::from_secs(45), async {
        rpc_call(&mut stdin, &mut stdout, 1, "hello", None).await?;
        rpc_call(
            &mut stdin,
            &mut stdout,
            2,
            "session.start",
            Some(serde_json::json!({
                "session_id": 1,
                "engine": "chromium",
                "url": "about:blank",
                "persistent": false
            })),
        )
        .await?;
        rpc_call(
            &mut stdin,
            &mut stdout,
            3,
            "session.stop",
            Some(serde_json::json!({"session_id": 1})),
        )
        .await
    })
    .await;
    drop(stdin);
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    let stderr = stderr_task.await.unwrap_or_default();
    match validation {
        Err(_) => Err(install_error(format!(
            "browser validation timed out: {}",
            bounded_text(&stderr, 4096)
        ))),
        Ok(Err(error)) => Err(install_error(format!(
            "{error}: {}",
            bounded_text(&stderr, 4096)
        ))),
        Ok(Ok(())) => Ok(()),
    }
}

async fn rpc_call(
    stdin: &mut tokio::process::ChildStdin,
    stdout: &mut BufReader<tokio::process::ChildStdout>,
    id: u64,
    method: &str,
    params: Option<serde_json::Value>,
) -> DomainResult<()> {
    let mut request = serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method});
    if let Some(params) = params {
        request["params"] = params;
    }
    let mut encoded = serde_json::to_vec(&request)
        .map_err(|error| install_error(format!("encode browser validation request: {error}")))?;
    encoded.push(b'\n');
    stdin.write_all(&encoded).await.map_err(storage_error)?;
    stdin.flush().await.map_err(storage_error)?;
    loop {
        let mut line = String::new();
        if stdout.read_line(&mut line).await.map_err(storage_error)? == 0 {
            return Err(install_error("browser worker exited during validation"));
        }
        if line.len() > 1024 * 1024 {
            return Err(install_error(
                "browser worker returned an oversized response",
            ));
        }
        let value: serde_json::Value = serde_json::from_str(&line)
            .map_err(|error| install_error(format!("invalid browser worker response: {error}")))?;
        if value.get("id").and_then(|value| value.as_u64()) != Some(id) {
            continue;
        }
        if let Some(error) = value.get("error") {
            let message = error
                .get("message")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown RPC error");
            return Err(install_error(format!(
                "browser worker {method} failed: {message}"
            )));
        }
        if value.get("result").is_none() {
            return Err(install_error(format!(
                "browser worker {method} omitted its result"
            )));
        }
        return Ok(());
    }
}

async fn validate_browser_once(
    config: &Config,
    prepared: &PreparedInstallation,
) -> DomainResult<()> {
    let marker = config.runtime_dir.join("browser-validation.json");
    let playwright = validate_playwright_directory(&prepared.playwright_core_path, None)?;
    let identity = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "node": file_identity(&prepared.node_path)?,
        "worker": file_identity(&prepared.worker_path)?,
        "playwright": playwright.version,
        "chromium_revision": playwright.chromium_revision,
        "chromium_version": playwright.chromium_version,
        "chromium": file_identity(&prepared.chromium_path)?,
    }))
    .map_err(|error| install_error(format!("encode browser validation marker: {error}")))?;
    if fs::read(&marker).ok().as_deref() == Some(identity.as_slice()) {
        return Ok(());
    }
    validate_browser(prepared).await?;
    write_durable_private_file(&marker, &identity)
}

fn file_identity(path: &Path) -> DomainResult<serde_json::Value> {
    let metadata = fs::metadata(path).map_err(storage_error)?;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|value| value.as_secs());
    Ok(serde_json::json!({
        "path": path,
        "size": metadata.len(),
        "modified": modified,
    }))
}

fn prepare_plugins(config: &Config) -> DomainResult<Vec<String>> {
    let extracted = sibling_directory(&config.plugin_dir, "release-catalog")?;
    let guard = TemporaryDirectory(extracted.clone());
    create_private_dir(&extracted)?;
    extract_plugin_archive(PLUGIN_CATALOG_ARCHIVE, &extracted)?;
    let catalog: PluginCatalog =
        serde_json::from_slice(&fs::read(extracted.join("catalog.json")).map_err(storage_error)?)
            .map_err(|error| install_error(format!("embedded plugin catalog: {error}")))?;
    if catalog.schema_version != 1 || catalog.snapshots.is_empty() {
        return Err(install_error("embedded plugin catalog is invalid"));
    }
    let current = catalog
        .snapshots
        .iter()
        .find(|snapshot| snapshot.commit == catalog.current_commit)
        .ok_or_else(|| install_error("embedded plugin catalog has no current snapshot"))?;
    validate_package_names(current.packages.keys())?;
    for (name, files) in &current.packages {
        if !directory_matches(&extracted.join("plugins").join(name), files)? {
            return Err(install_error(format!(
                "embedded plugin package {name} failed its integrity check"
            )));
        }
    }

    let preserved = reconcile_plugins(&catalog, &extracted.join("plugins"), &config.plugin_dir)?;
    drop(guard);
    Ok(preserved)
}

fn reconcile_plugins(
    catalog: &PluginCatalog,
    source: &Path,
    plugin_dir: &Path,
) -> DomainResult<Vec<String>> {
    let current = catalog
        .snapshots
        .iter()
        .find(|snapshot| snapshot.commit == catalog.current_commit)
        .ok_or_else(|| install_error("embedded plugin catalog has no current snapshot"))?;
    create_private_dir(plugin_dir)?;
    let mut preserved = Vec::new();
    for (name, current_files) in &current.packages {
        let destination = plugin_dir.join(name);
        let incoming = plugin_dir.join(format!(".huntproxy-{name}.incoming"));
        let backup = plugin_dir.join(format!(".huntproxy-{name}.backup"));
        let marker = plugin_dir.join(format!(".huntproxy-{name}.swap"));
        recover_package_swap(&destination, &incoming, &backup, &marker)?;

        if destination.exists() {
            if directory_matches(&destination, current_files)? {
                continue;
            }
            let trusted = catalog.snapshots.iter().any(|snapshot| {
                snapshot
                    .packages
                    .get(name)
                    .is_some_and(|files| directory_matches(&destination, files).unwrap_or(false))
            });
            if !trusted {
                preserved.push(name.clone());
                continue;
            }
        }
        write_durable_private_file(&marker, PLUGIN_SWAP_MARKER)?;
        if let Err(error) = copy_package(&source.join(name), &incoming) {
            if incoming.exists() {
                fs::remove_dir_all(&incoming).map_err(storage_error)?;
            }
            fs::remove_file(&marker).map_err(storage_error)?;
            sync_directory(plugin_dir)?;
            return Err(error);
        }
        install_package_swap(&destination, &incoming, &backup, &marker)?;
    }
    preserved.sort();
    write_durable_private_file(
        &plugin_dir.join(PLUGIN_SOURCE_MARKER),
        format!("{}\n", catalog.current_commit).as_bytes(),
    )?;
    Ok(preserved)
}

fn extract_plugin_archive(encoded: &[u8], destination: &Path) -> DomainResult<()> {
    if encoded.len() as u64 > MAX_PLUGIN_ARCHIVE_BYTES {
        return Err(install_error(
            "embedded plugin catalog exceeds the size limit",
        ));
    }
    let decoder = zstd::stream::read::Decoder::new(encoded)
        .map_err(|error| install_error(format!("decode embedded plugin catalog: {error}")))?;
    let mut archive = tar::Archive::new(decoder);
    let mut entries = 0usize;
    for entry in archive.entries().map_err(storage_error)? {
        let mut entry = entry.map_err(storage_error)?;
        entries += 1;
        if entries > MAX_PLUGIN_ENTRIES {
            return Err(install_error("embedded plugin catalog has too many files"));
        }
        let relative = entry.path().map_err(storage_error)?.into_owned();
        validate_relative_path(&relative)?;
        let target = destination.join(relative);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            create_private_dir(&target)?;
        } else if kind.is_file() {
            if let Some(parent) = target.parent() {
                create_private_dir(parent)?;
            }
            entry.unpack(&target).map_err(storage_error)?;
        } else {
            return Err(install_error(
                "embedded plugin catalog contains an unsupported entry",
            ));
        }
    }
    Ok(())
}

fn validate_package_names<'a>(names: impl Iterator<Item = &'a String>) -> DomainResult<()> {
    for name in names {
        if name.is_empty()
            || name.starts_with('.')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(install_error(
                "embedded plugin catalog has an unsafe package name",
            ));
        }
    }
    Ok(())
}

fn directory_matches(directory: &Path, expected: &BTreeMap<String, String>) -> DomainResult<bool> {
    if !directory.is_dir() {
        return Ok(false);
    }
    let mut actual = BTreeMap::new();
    collect_file_hashes(directory, directory, &mut actual)?;
    Ok(&actual == expected)
}

fn collect_file_hashes(
    root: &Path,
    directory: &Path,
    output: &mut BTreeMap<String, String>,
) -> DomainResult<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(storage_error)?;
        if metadata.file_type().is_symlink() {
            output.insert("<unsupported-entry>".into(), String::new());
            return Ok(());
        }
        if metadata.is_dir() {
            collect_file_hashes(root, &path, output)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| install_error("plugin path escaped its package"))?;
            let key = relative
                .components()
                .map(|part| part.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            output.insert(
                key,
                hex::encode(Sha256::digest(fs::read(&path).map_err(storage_error)?)),
            );
        } else {
            return Ok(());
        }
    }
    Ok(())
}

fn copy_package(source: &Path, destination: &Path) -> DomainResult<()> {
    if destination.exists() {
        fs::remove_dir_all(destination).map_err(storage_error)?;
    }
    create_private_dir(destination)?;
    copy_tree(source, source, destination)?;
    sync_tree(destination)
}

fn copy_tree(root: &Path, directory: &Path, destination: &Path) -> DomainResult<()> {
    let entries = fs::read_dir(directory)
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(storage_error)?;
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(install_error(
                "embedded plugin contains an unsupported file",
            ));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| install_error("plugin path escaped its package"))?;
        let target = destination.join(relative);
        if metadata.is_dir() {
            create_private_dir(&target)?;
            copy_tree(root, &path, destination)?;
        } else {
            if let Some(parent) = target.parent() {
                create_private_dir(parent)?;
            }
            fs::copy(&path, &target).map_err(storage_error)?;
        }
    }
    Ok(())
}

fn recover_package_swap(
    destination: &Path,
    incoming: &Path,
    backup: &Path,
    marker: &Path,
) -> DomainResult<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| install_error("plugin installation path has no parent"))?;
    if !marker.exists() {
        if incoming.exists() || backup.exists() {
            return Err(install_error(
                "plugin installation staging path exists without an ownership marker",
            ));
        }
        return Ok(());
    }
    if fs::read(marker).map_err(storage_error)? != PLUGIN_SWAP_MARKER {
        return Err(install_error(
            "plugin installation ownership marker is invalid",
        ));
    }
    if backup.exists() && !destination.exists() {
        fs::rename(backup, destination).map_err(storage_error)?;
        sync_directory(parent)?;
    } else if backup.exists() {
        fs::remove_dir_all(backup).map_err(storage_error)?;
        sync_directory(parent)?;
    }
    if incoming.exists() {
        fs::remove_dir_all(incoming).map_err(storage_error)?;
        sync_directory(parent)?;
    }
    fs::remove_file(marker).map_err(storage_error)?;
    sync_directory(parent)
}

fn install_package_swap(
    destination: &Path,
    incoming: &Path,
    backup: &Path,
    marker: &Path,
) -> DomainResult<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| install_error("plugin installation path has no parent"))?;
    if destination.exists() {
        fs::rename(destination, backup).map_err(storage_error)?;
        sync_directory(parent)?;
    }
    if let Err(error) = fs::rename(incoming, destination) {
        if backup.exists() && !destination.exists() {
            let _ = fs::rename(backup, destination);
            let _ = sync_directory(parent);
        }
        let _ = fs::remove_dir_all(incoming);
        let _ = fs::remove_file(marker);
        let _ = sync_directory(parent);
        return Err(storage_error(error));
    }
    sync_directory(parent)?;
    if backup.exists() {
        fs::remove_dir_all(backup).map_err(storage_error)?;
        sync_directory(parent)?;
    }
    fs::remove_file(marker).map_err(storage_error)?;
    sync_directory(parent)
}

fn replace_directory(staging: &Path, destination: &Path) -> DomainResult<()> {
    recover_directory_replace(destination)?;
    sync_tree(staging)?;
    let backup = directory_backup_path(destination)?;
    let parent = destination
        .parent()
        .ok_or_else(|| install_error("installation path has no parent"))?;
    if destination.exists() {
        fs::rename(destination, &backup).map_err(storage_error)?;
        sync_directory(parent)?;
    }
    if let Err(error) = fs::rename(staging, destination) {
        if backup.exists() && !destination.exists() {
            let _ = fs::rename(&backup, destination);
            let _ = sync_directory(parent);
        }
        return Err(storage_error(error));
    }
    sync_directory(parent)?;
    if backup.exists() {
        fs::remove_dir_all(backup).map_err(storage_error)?;
        sync_directory(parent)?;
    }
    Ok(())
}

fn recover_directory_replace(destination: &Path) -> DomainResult<()> {
    let backup = directory_backup_path(destination)?;
    let parent = destination
        .parent()
        .ok_or_else(|| install_error("installation path has no parent"))?;
    if backup.exists() && !destination.exists() {
        fs::rename(&backup, destination).map_err(storage_error)?;
        sync_directory(parent)?;
    } else if backup.exists() {
        fs::remove_dir_all(&backup).map_err(storage_error)?;
        sync_directory(parent)?;
    }
    Ok(())
}

fn write_durable_private_file(path: &Path, data: &[u8]) -> DomainResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| install_error("installation marker has no parent"))?;
    create_private_dir(parent)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| install_error("installation marker has an invalid name"))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(storage_error)?;
        file.write_all(data).map_err(storage_error)?;
        file.sync_all().map_err(storage_error)?;
        fs::rename(&temporary, path).map_err(storage_error)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_tree(path: &Path) -> DomainResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(storage_error)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        return File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(storage_error);
    }
    if !metadata.is_dir() {
        return Err(install_error("installation tree contains a special file"));
    }
    for entry in fs::read_dir(path).map_err(storage_error)? {
        sync_tree(&entry.map_err(storage_error)?.path())?;
    }
    sync_directory(path)
}

fn sync_directory(path: &Path) -> DomainResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(storage_error)
}

fn directory_backup_path(destination: &Path) -> DomainResult<PathBuf> {
    let parent = destination
        .parent()
        .ok_or_else(|| install_error("installation path has no parent"))?;
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| install_error("installation path has an invalid name"))?;
    Ok(parent.join(format!(".huntproxy-{name}.backup")))
}

fn sibling_directory(destination: &Path, label: &str) -> DomainResult<PathBuf> {
    let parent = destination
        .parent()
        .ok_or_else(|| install_error("installation path has no parent"))?;
    create_private_dir(parent)?;
    let path = parent.join(format!(
        ".huntproxy-{}-{label}-{}",
        destination
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("runtime"),
        std::process::id()
    ));
    if path.exists() {
        fs::remove_dir_all(&path).map_err(storage_error)?;
    }
    Ok(path)
}

fn sibling_file(destination: &Path, label: &str) -> DomainResult<PathBuf> {
    let parent = destination
        .parent()
        .ok_or_else(|| install_error("installation path has no parent"))?;
    create_private_dir(parent)?;
    let path = parent.join(format!(
        ".huntproxy-{}-{label}-{}",
        destination
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("runtime"),
        std::process::id()
    ));
    if path.exists() {
        fs::remove_file(&path).map_err(storage_error)?;
    }
    Ok(path)
}

fn strip_first_component(path: &Path) -> DomainResult<PathBuf> {
    validate_relative_path(path)?;
    Ok(path.components().skip(1).collect())
}

fn validate_relative_path(path: &Path) -> DomainResult<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(install_error("release archive contains an unsafe path"));
    }
    Ok(())
}

fn validate_archive_symlink(entry: &Path, link: &Path) -> DomainResult<()> {
    if link.is_absolute() || link.as_os_str().is_empty() {
        return Err(install_error("release archive contains an unsafe symlink"));
    }
    let mut depth = entry
        .parent()
        .map_or(0, |parent| parent.components().count());
    for component in link.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::CurDir => {}
            _ => return Err(install_error("release archive contains an unsafe symlink")),
        }
    }
    if depth == 0 {
        return Err(install_error("release archive symlink escapes its runtime"));
    }
    Ok(())
}

fn canonical_regular_file(path: &Path, label: &str) -> DomainResult<PathBuf> {
    if !path.is_file() {
        return Err(install_error(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    path.canonicalize().map_err(storage_error)
}

fn bounded_text(encoded: &[u8], limit: usize) -> String {
    String::from_utf8_lossy(&encoded[..encoded.len().min(limit)])
        .trim()
        .to_owned()
}

fn install_error(message: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::Unavailable, message)
}

fn storage_error(error: impl std::fmt::Display) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory() -> tempfile::TempDir {
        let root = Path::new("/tmp/artis");
        fs::create_dir_all(root).unwrap();
        tempfile::Builder::new()
            .prefix("huntproxy-installation-test-")
            .tempdir_in(root)
            .unwrap()
    }

    fn hashes(files: &[(&str, &[u8])]) -> BTreeMap<String, String> {
        files
            .iter()
            .map(|(name, content)| ((*name).to_owned(), hex::encode(Sha256::digest(content))))
            .collect()
    }

    fn write_package(root: &Path, name: &str, files: &[(&str, &[u8])]) {
        for (relative, content) in files {
            let path = root.join(name).join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
    }

    #[test]
    fn embedded_release_assets_pass_integrity_checks() {
        let manifest: PlaywrightManifest = serde_json::from_slice(PLAYWRIGHT_MANIFEST).unwrap();
        assert_eq!(manifest.version, PLAYWRIGHT_VERSION);
        assert_eq!(
            manifest.sha512,
            hex::encode(Sha512::digest(PLAYWRIGHT_ARCHIVE))
        );
        let mut tampered = PLAYWRIGHT_ARCHIVE.to_vec();
        tampered[0] ^= 1;
        assert_ne!(manifest.sha512, hex::encode(Sha512::digest(&tampered)));

        let temporary = temporary_directory();
        let sdk = temporary.path().join("sdk");
        fs::create_dir(&sdk).unwrap();
        extract_playwright_archive(PLAYWRIGHT_ARCHIVE, &sdk).unwrap();
        let runtime = validate_playwright_directory(&sdk, Some(PLAYWRIGHT_VERSION)).unwrap();
        assert_eq!(runtime.chromium_revision, CHROMIUM_REVISION);
        assert_eq!(runtime.chromium_version, CHROMIUM_VERSION);

        let plugins = temporary.path().join("plugins");
        fs::create_dir(&plugins).unwrap();
        extract_plugin_archive(PLUGIN_CATALOG_ARCHIVE, &plugins).unwrap();
        let catalog: PluginCatalog =
            serde_json::from_slice(&fs::read(plugins.join("catalog.json")).unwrap()).unwrap();
        let current = catalog
            .snapshots
            .iter()
            .find(|snapshot| snapshot.commit == catalog.current_commit)
            .unwrap();
        let published = catalog
            .snapshots
            .iter()
            .find(|snapshot| snapshot.commit == "95ad5b29cb02e8b1aa1c0ec0b6d7cb1e485f0c32")
            .unwrap();
        assert_eq!(
            published.packages["ip-rotate"]
                .get(".gitignore")
                .map(String::as_str),
            Some("cf2dc1d166ad2fc4c4d4bc26e62d0589fe3c4e0c553a847e3e95bfa743e7b565")
        );
        for snapshot in &catalog.snapshots {
            for files in snapshot.packages.values() {
                assert!(files.keys().all(|path| {
                    !matches!(
                        Path::new(path).file_name().and_then(|name| name.to_str()),
                        Some("aws-credentials.toml" | ".env")
                    )
                }));
            }
        }
        for (name, files) in &current.packages {
            assert!(directory_matches(&plugins.join("plugins").join(name), files).unwrap());
        }
    }

    #[test]
    fn playwright_sdk_materialization_is_versioned_and_repeatable() {
        let temporary = temporary_directory();
        let config = Config {
            runtime_dir: temporary.path().join("runtime"),
            browser_playwright_core_path: None,
            ..Config::default()
        };
        let first = prepare_playwright(&config).unwrap();
        let second = prepare_playwright(&config).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.file_name().and_then(|value| value.to_str()),
            Some("playwright-core-1.64.0")
        );
    }

    #[test]
    fn plugin_reconciliation_upgrades_only_trusted_packages() {
        let temporary = temporary_directory();
        let source = temporary.path().join("source");
        let installed = temporary.path().join("installed");
        let old = [
            ("plugin.json", b"old".as_slice()),
            ("index.js", b"old js".as_slice()),
        ];
        let new = [
            ("plugin.json", b"new".as_slice()),
            ("index.js", b"new js".as_slice()),
        ];
        write_package(&source, "official", &new);
        write_package(&source, "missing", &new);
        write_package(&installed, "official", &old);
        write_package(
            &installed,
            "modified",
            &[("plugin.json", b"mine"), ("index.js", b"mine")],
        );
        write_package(
            &installed,
            "custom",
            &[("plugin.json", b"custom"), ("index.js", b"custom")],
        );
        fs::write(installed.join(PLUGIN_SOURCE_MARKER), b"old\n").unwrap();
        write_package(&source, "modified", &new);
        let catalog = PluginCatalog {
            schema_version: 1,
            current_commit: "new".into(),
            snapshots: vec![
                PluginSnapshot {
                    commit: "new".into(),
                    packages: BTreeMap::from([
                        ("official".into(), hashes(&new)),
                        ("modified".into(), hashes(&new)),
                        ("missing".into(), hashes(&new)),
                    ]),
                },
                PluginSnapshot {
                    commit: "old".into(),
                    packages: BTreeMap::from([
                        ("official".into(), hashes(&old)),
                        ("modified".into(), hashes(&old)),
                    ]),
                },
            ],
        };

        assert_eq!(
            reconcile_plugins(&catalog, &source, &installed).unwrap(),
            vec!["modified"]
        );
        assert_eq!(
            fs::read(installed.join("official/index.js")).unwrap(),
            b"new js"
        );
        assert_eq!(
            fs::read(installed.join("missing/index.js")).unwrap(),
            b"new js"
        );
        assert_eq!(
            fs::read(installed.join("modified/index.js")).unwrap(),
            b"mine"
        );
        assert_eq!(
            fs::read(installed.join("custom/index.js")).unwrap(),
            b"custom"
        );
        assert_eq!(
            fs::read_to_string(installed.join(PLUGIN_SOURCE_MARKER)).unwrap(),
            "new\n"
        );
        assert_eq!(
            reconcile_plugins(&catalog, &source, &installed).unwrap(),
            vec!["modified"]
        );
    }

    #[test]
    fn archive_paths_cannot_escape_installation_root() {
        assert!(validate_relative_path(Path::new("../escape")).is_err());
        assert!(validate_relative_path(Path::new("/absolute")).is_err());
        assert!(validate_relative_path(Path::new("safe/path")).is_ok());
        assert!(strip_first_component(Path::new("package/../escape")).is_err());
        assert!(validate_archive_symlink(
            Path::new("bin/npm"),
            Path::new("../lib/node_modules/npm/bin/npm-cli.js")
        )
        .is_ok());
        assert!(validate_archive_symlink(Path::new("bin/npm"), Path::new("../../escape")).is_err());
    }

    #[test]
    fn interrupted_package_swap_is_restored_before_reconciliation() {
        let temporary = temporary_directory();
        let destination = temporary.path().join("plugin");
        let incoming = temporary.path().join("incoming");
        let backup = temporary.path().join("backup");
        let marker = temporary.path().join("swap");
        write_package(temporary.path(), "backup", &[("index.js", b"trusted")]);
        write_package(temporary.path(), "incoming", &[("index.js", b"partial")]);
        fs::write(&marker, PLUGIN_SWAP_MARKER).unwrap();
        recover_package_swap(&destination, &incoming, &backup, &marker).unwrap();
        assert_eq!(fs::read(destination.join("index.js")).unwrap(), b"trusted");
        assert!(!incoming.exists());
        assert!(!backup.exists());
        assert!(!marker.exists());
    }

    #[test]
    fn completed_package_swap_recovery_keeps_the_new_package() {
        let temporary = temporary_directory();
        let destination = temporary.path().join("plugin");
        let incoming = temporary.path().join("incoming");
        let backup = temporary.path().join("backup");
        let marker = temporary.path().join("swap");
        write_package(temporary.path(), "plugin", &[("index.js", b"current")]);
        write_package(temporary.path(), "backup", &[("index.js", b"previous")]);
        write_package(temporary.path(), "incoming", &[("index.js", b"unused")]);
        write_durable_private_file(&marker, PLUGIN_SWAP_MARKER).unwrap();

        recover_package_swap(&destination, &incoming, &backup, &marker).unwrap();

        assert_eq!(fs::read(destination.join("index.js")).unwrap(), b"current");
        assert!(!incoming.exists());
        assert!(!backup.exists());
        assert!(!marker.exists());
    }

    #[test]
    fn interrupted_runtime_swap_restores_the_previous_directory() {
        let temporary = temporary_directory();
        let destination = temporary.path().join("playwright-core-1.64.0");
        let backup = directory_backup_path(&destination).unwrap();
        fs::create_dir(&backup).unwrap();
        fs::write(backup.join("package.json"), b"previous").unwrap();
        recover_directory_replace(&destination).unwrap();
        assert_eq!(
            fs::read(destination.join("package.json")).unwrap(),
            b"previous"
        );
        assert!(!backup.exists());
    }

    #[test]
    fn unowned_plugin_staging_paths_are_never_removed() {
        let temporary = temporary_directory();
        let destination = temporary.path().join("plugin");
        let incoming = temporary.path().join("incoming");
        let backup = temporary.path().join("backup");
        let marker = temporary.path().join("swap");
        write_package(temporary.path(), "backup", &[("notes.txt", b"custom")]);
        assert!(recover_package_swap(&destination, &incoming, &backup, &marker).is_err());
        assert_eq!(fs::read(backup.join("notes.txt")).unwrap(), b"custom");
    }

    #[test]
    fn bundled_plugin_names_come_from_the_current_snapshot() {
        let names = bundled_plugin_names().unwrap();
        assert!(names.contains(&"racer".to_owned()));
        assert_eq!(names.len(), 10);
    }

    #[test]
    fn inspection_reads_only_a_complete_validated_installation() {
        let temporary = temporary_directory();
        let config = Config {
            data_dir: temporary.path().to_path_buf(),
            runtime_dir: temporary.path().join("runtime"),
            node_path: Some(temporary.path().join("node")),
            browser_worker_path: Some(temporary.path().join("worker.js")),
            ..Config::default()
        };
        fs::create_dir_all(&config.runtime_dir).unwrap();
        fs::write(config.node_path.as_ref().unwrap(), b"node").unwrap();
        fs::write(config.browser_worker_path.as_ref().unwrap(), b"worker").unwrap();
        let chromium = temporary.path().join("chromium");
        fs::write(&chromium, b"chromium").unwrap();
        let sdk = config
            .runtime_dir
            .join(format!("playwright-core-{PLAYWRIGHT_VERSION}"));
        fs::create_dir_all(&sdk).unwrap();
        fs::write(
            sdk.join("package.json"),
            format!(r#"{{"name":"playwright-core","version":"{PLAYWRIGHT_VERSION}"}}"#),
        )
        .unwrap();
        fs::write(sdk.join("cli.js"), b"cli").unwrap();
        fs::write(
            sdk.join("browsers.json"),
            serde_json::to_vec(&serde_json::json!({
                "browsers": [{
                    "name": "chromium",
                    "revision": CHROMIUM_REVISION,
                    "installByDefault": true,
                    "browserVersion": CHROMIUM_VERSION,
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            config.runtime_dir.join("browser-validation.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "node": {"path": config.node_path.clone()},
                "worker": {"path": config.browser_worker_path.clone()},
                "playwright": PLAYWRIGHT_VERSION,
                "chromium_revision": CHROMIUM_REVISION,
                "chromium_version": CHROMIUM_VERSION,
                "chromium": {"path": chromium},
            }))
            .unwrap(),
        )
        .unwrap();

        let found = inspect(&config).unwrap();
        assert_eq!(found.playwright_core_path, sdk.canonicalize().unwrap());
        fs::remove_file(found.chromium_path).unwrap();
        assert!(inspect(&config).is_none());
    }

    #[test]
    fn managed_chromium_lookup_requires_the_release_revision() {
        let temporary = temporary_directory();
        let playwright = temporary.path().join("playwright-core");
        let obsolete = playwright.join(".local-browsers/chromium-1148/chrome-linux/chrome");
        fs::create_dir_all(obsolete.parent().unwrap()).unwrap();
        fs::write(&obsolete, b"obsolete").unwrap();
        assert!(managed_chromium_binary(&playwright, CHROMIUM_REVISION).is_none());

        let current = playwright
            .join(format!(".local-browsers/chromium-{CHROMIUM_REVISION}"))
            .join("chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing");
        fs::create_dir_all(current.parent().unwrap()).unwrap();
        fs::write(&current, b"current").unwrap();
        assert_eq!(
            managed_chromium_binary(&playwright, CHROMIUM_REVISION),
            Some(current)
        );
    }

    #[tokio::test]
    async fn explicit_sdk_uses_its_declared_chromium_revision() {
        let temporary = temporary_directory();
        let sdk = temporary.path().join("playwright-core");
        fs::create_dir_all(&sdk).unwrap();
        fs::write(
            sdk.join("package.json"),
            br#"{"name":"playwright-core","version":"1.49.1"}"#,
        )
        .unwrap();
        fs::write(sdk.join("cli.js"), b"cli").unwrap();
        fs::write(
            sdk.join("browsers.json"),
            br#"{"browsers":[{"name":"chromium","revision":"1148","installByDefault":true,"browserVersion":"131.0.6778.33"}]}"#,
        )
        .unwrap();
        let executable = sdk.join(".local-browsers/chromium-1148/chrome-linux/chrome");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"browser").unwrap();

        let prepared = prepare_chromium(&Config::default(), Path::new("unused-node"), &sdk)
            .await
            .unwrap();
        assert_eq!(prepared, executable.canonicalize().unwrap());
    }
}
