//! Browser worker supervision, real actions, and private per-project browser state.

use crate::config::{create_private_dir, write_private_file, Config};
use crate::cookies::{CookiePair, StorageOrigin, StoredCookieProfile};
use crate::domain::*;
use crate::storage::{CreateCaptureSession, Db};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{Mutex, RwLock};

const WORKER_PROTOCOL_VERSION: u64 = 1;
const WORKER_RPC_TIMEOUT: Duration = Duration::from_secs(90);
/// How long a worker has to close one session whose call ran out of time
/// before the worker itself counts as stuck.
const WORKER_ABORT_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest a single worker request waits for browser events. The worker
/// runs one session's requests in order, so a longer wait would hold up that
/// session's other requests, such as status checks.
const EVENT_WAIT_SLICE: Duration = Duration::from_millis(100);
const DEFAULT_BROWSER_PROXY: &str = "http://127.0.0.1:17891";
const BROWSER_CDP_PORT: u16 = 9222;
const BROWSER_CDP_PORT_END: u16 = 9321;
/// A project's browsers are stopped once it has had no control activity for
/// this long. Their profiles are saved, so `browser_start` resumes them.
pub const BROWSER_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// How often the daemon looks for idle projects.
pub const BROWSER_IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(60);
/// The `checkpoint_status` of a session the idle rule stopped.
const IDLE_STOPPED_STATUS: &str = "idle_stopped";

/// A project worker's last reported sandbox state and reason.
type SandboxState = (Option<String>, Option<String>);
const DEFAULT_BROWSER_PROFILE: &str = "default";
const MAX_PERSISTENT_PROFILE_BYTES: usize = 25 * 1024 * 1024;
const MAX_BROWSER_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_BROWSER_REQUEST_RESPONSE_BYTES: u64 = 65_536;
const MAX_BROWSER_SCREENSHOT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_BROWSER_EVALUATE_BYTES: usize = 65_536;
const MAX_BROWSER_TYPE_BYTES: usize = 4096;
const MAX_POINTER_COORDINATE: f64 = 100_000.0;
/// Every action result is fitted to the MCP output budget by construction, so
/// MCP clients and the generic safety net never have to cut it.
const ACTION_OUTPUT_BYTES: usize = crate::mcp::budget::MAX_OUTPUT_BYTES;
/// A larger snapshot slice could never fit the result: JSON escaping only adds
/// bytes. The worker uses the same cap.
const MAX_SNAPSHOT_BYTES: u64 = ACTION_OUTPUT_BYTES as u64;
const EMBEDDED_WORKER: &str = include_str!("../../browser-worker/index.js");
const EMBEDDED_WORKER_HEADLESS: &str = include_str!("../../browser-worker/headless.js");
const EMBEDDED_WORKER_PACKAGE: &str = include_str!("../../browser-worker/package.json");
const EMBEDDED_WORKER_LOCK: &str = include_str!("../../browser-worker/package-lock.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserInstallStatus {
    pub node_available: bool,
    pub worker_available: bool,
    pub chromium_available: bool,
    pub chromium_path: Option<String>,
    #[serde(default)]
    pub chromium_version: Option<String>,
    #[serde(default)]
    pub headless: Option<bool>,
    #[serde(default)]
    pub headless_compatibility: Option<bool>,
    #[serde(default)]
    pub playwright_core_path: Option<String>,
    #[serde(default)]
    pub playwright_version: Option<String>,
    #[serde(default)]
    pub expected_chromium_version: Option<String>,
    pub node_path: Option<String>,
    pub install_hint: Option<String>,
    pub sandbox_state: Option<String>,
    pub sandbox_reason: Option<String>,
}

/// The worker owns browser discovery so diagnostics and launches use one policy.
#[derive(Debug, Clone, Default, Deserialize)]
struct BrowserRuntimeInspection {
    playwright_core_path: Option<PathBuf>,
    playwright_version: Option<String>,
    expected_chromium_version: Option<String>,
    chromium_path: Option<PathBuf>,
    chromium_version: Option<String>,
    headless: Option<bool>,
    headless_compatibility: Option<bool>,
    compatibility_error: Option<String>,
    #[serde(skip)]
    inspection_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserJavascriptFile {
    pub url: String,
    pub path: String,
    pub host: String,
    pub mime: Option<String>,
    pub status_code: Option<u16>,
    #[serde(default)]
    pub source_page_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserCdpInfo {
    pub port: u16,
    pub endpoint: String,
    pub devtools_url: String,
    pub hosted_devtools_url: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserProfileStatus {
    pub name: String,
    pub active: bool,
    pub session_id: Option<BrowserSessionId>,
    pub has_state: bool,
}

/// Compact resource observations for transition-time reuse. No page or private
/// browser state is included. The CDP flag indicates the entire port range is exhausted.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserResources {
    pub project_id: ProjectId,
    pub max_concurrent_browsers: u32,
    pub active_persistent: usize,
    pub active_ephemeral: usize,
    pub available_capacity: usize,
    pub cdp_port_in_use: bool,
    pub sessions: Vec<BrowserSessionResource>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserSessionResource {
    pub session_id: BrowserSessionId,
    pub profile: String,
    pub agent_control: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserStatus {
    pub sessions: Vec<BrowserSession>,
    pub resources: BrowserResources,
    pub sandbox_state: Option<String>,
    pub sandbox_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserCdpStatus {
    pub project_id: ProjectId,
    pub active: bool,
    pub agent_control: bool,
    pub session_id: Option<BrowserSessionId>,
    pub endpoint: Option<String>,
    pub cdp_port: Option<u16>,
    pub active_sessions: Vec<BrowserCdpActiveSession>,
    pub devtools_url: Option<String>,
    pub hosted_devtools_url: Option<String>,
    pub ssh_forward_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserCdpActiveSession {
    pub session_id: BrowserSessionId,
    pub port: u16,
    pub endpoint: String,
}

struct CdpReservation<'a> {
    reservations: &'a std::sync::Mutex<HashMap<i64, u16>>,
    session_id: i64,
    committed: bool,
}

impl Drop for CdpReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.reservations
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&self.session_id);
        }
    }
}

fn free_cdp_port(reservations: &HashMap<i64, u16>) -> Option<u16> {
    (BROWSER_CDP_PORT..=BROWSER_CDP_PORT_END).find(|port| {
        !reservations.values().any(|reserved| reserved == port)
            && std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, *port)).is_ok()
    })
}

/// Secret-bearing values live only in daemon memory. SQLite stores version/hash/status metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Checkpoint {
    pub url: Option<String>,
    pub title: Option<String>,
    pub cookies: Vec<Value>,
    pub local_storage: BTreeMap<String, BTreeMap<String, String>>,
    pub session_storage: BTreeMap<String, String>,
    pub version: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistentBrowserProfile {
    #[serde(default)]
    cookie_seed: Option<CookieSeed>,
    #[serde(default)]
    version: u64,
    #[serde(default)]
    checkpoint_hash: String,
    #[serde(default)]
    last_url: Option<String>,
    #[serde(default)]
    cookies: Vec<Value>,
    #[serde(default)]
    local_storage: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    session_storage: BTreeMap<String, BTreeMap<String, String>>,
}

/// What this process last wrote to a profile's `state.json`: the checkpoint it
/// holds and the file's size and modification time, so a file that was removed
/// or replaced behind our back is read again instead of being trusted.
struct PersistedProfileState {
    checkpoint_hash: String,
    len: u64,
    modified: Option<std::time::SystemTime>,
}

impl PersistedProfileState {
    /// `None` when the file cannot be inspected.
    fn of(path: &Path, checkpoint_hash: &str) -> Option<Self> {
        let metadata = std::fs::metadata(path).ok()?;
        Some(Self {
            checkpoint_hash: checkpoint_hash.to_string(),
            len: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }

    fn holds(&self, path: &Path, checkpoint_hash: &str) -> bool {
        self.checkpoint_hash == checkpoint_hash
            && std::fs::metadata(path).is_ok_and(|metadata| {
                metadata.len() == self.len && metadata.modified().ok() == self.modified
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CookieSeed {
    name: String,
    hash: String,
    #[serde(default)]
    identities: Vec<Value>,
    /// Origins whose storage this seed wrote, so a later seed that drops one
    /// can clear it. Absent in seeds saved before storage seeding existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    origins: Vec<String>,
}

struct CookieLaunchOverride {
    cookies: Vec<Value>,
    clear_cookies: Vec<Value>,
    seed: Option<CookieSeed>,
    /// localStorage/sessionStorage to write before the first real navigation.
    storage: Vec<StorageOrigin>,
    /// Origins a previous seed wrote that this one no longer lists.
    clear_origins: Vec<String>,
}

impl CookieLaunchOverride {
    fn from_profile(profile: &StoredCookieProfile) -> DomainResult<Self> {
        Ok(Self {
            cookies: browser_cookies(std::slice::from_ref(profile))?,
            clear_cookies: profile_cookie_identities(profile)?,
            seed: None,
            storage: profile.origins.clone(),
            clear_origins: Vec::new(),
        })
    }

    fn has_storage_work(&self) -> bool {
        !self.storage.is_empty() || !self.clear_origins.is_empty()
    }

    /// Worker `storage_seed` parameter; null when there is nothing to write.
    fn storage_params(&self) -> Value {
        if !self.has_storage_work() {
            return Value::Null;
        }
        json!({ "origins": self.storage, "clear_origins": self.clear_origins })
    }
}

/// Hash of everything a seed writes. Cookie-only seeds hash exactly as they
/// did before storage seeding existed, so saved seeds do not spuriously refresh.
fn cookie_seed_hash(cookies: &[Value], origins: &[StorageOrigin]) -> DomainResult<String> {
    let internal =
        |error: serde_json::Error| DomainError::new(ErrorCode::Internal, error.to_string());
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(cookies).map_err(internal)?);
    if !origins.is_empty() {
        hasher.update(b"\0origins\0");
        hasher.update(serde_json::to_vec(origins).map_err(internal)?);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Settings the page interactions share. Each is optional, and the worker
/// applies the action's own default when one is absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionOptions {
    /// How long to wait for the locator, navigation or condition: 1..30000
    /// ms, by default 10000 for an element and 30000 for a navigation or wait.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// A pause after the action, before the result and its snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    /// Bounds the `snapshot: true` result as the snapshot action's does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// When a navigation counts as done: load, domcontentloaded or networkidle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_until: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrowserAction {
    Navigate {
        url: String,
        /// Also return the resulting page's accessibility snapshot.
        #[serde(default)]
        snapshot: bool,
        #[serde(flatten)]
        options: InteractionOptions,
    },
    Snapshot {
        #[serde(default = "default_snapshot_format")]
        format: String,
        /// Clamped to what fits the action output budget.
        #[serde(default = "default_snapshot_max_bytes")]
        max_bytes: u64,
        /// UTF-8 byte offset into the full snapshot content.
        #[serde(default)]
        offset: u64,
        /// Captures only this element's subtree.
        locator: Option<Locator>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
    },
    Click {
        locator: Locator,
        #[serde(default)]
        snapshot: bool,
        #[serde(flatten)]
        options: InteractionOptions,
    },
    Fill {
        locator: Locator,
        value: String,
        #[serde(default)]
        snapshot: bool,
        #[serde(flatten)]
        options: InteractionOptions,
    },
    Select {
        locator: Locator,
        value: String,
        #[serde(default)]
        snapshot: bool,
        #[serde(flatten)]
        options: InteractionOptions,
    },
    Upload {
        locator: Locator,
        files: Vec<String>,
        #[serde(default)]
        via_chooser: bool,
        #[serde(default = "default_browser_action_timeout")]
        timeout_ms: u64,
    },
    Inspect {
        locator: Option<Locator>,
        #[serde(default = "default_inspection_max_bytes")]
        max_bytes: u64,
    },
    /// Runs JavaScript in the main world of the selected page.
    Evaluate {
        expression: String,
        /// Runs in the one frame whose name equals this or whose URL contains it.
        frame: Option<String>,
        #[serde(default = "default_browser_action_timeout")]
        timeout_ms: u64,
    },
    /// Mouse input aimed at an element or at a viewport point: `click`,
    /// `hover`, or `drag` to a second element or point. The locators are
    /// boxed so that two of them do not make every action this large.
    Pointer {
        op: String,
        locator: Option<Box<Locator>>,
        x: Option<f64>,
        y: Option<f64>,
        to_locator: Option<Box<Locator>>,
        to_x: Option<f64>,
        to_y: Option<f64>,
        #[serde(default = "default_pointer_button")]
        button: String,
        #[serde(default = "default_pointer_count")]
        count: u8,
        #[serde(default)]
        modifiers: Vec<String>,
        #[serde(default)]
        snapshot: bool,
        #[serde(flatten)]
        options: InteractionOptions,
    },
    /// Sends text as keystrokes to `locator`, or to whatever has focus.
    Type {
        text: String,
        locator: Option<Locator>,
        #[serde(default)]
        snapshot: bool,
        #[serde(flatten)]
        options: InteractionOptions,
    },
    Pages {
        /// `list` when omitted.
        #[serde(default = "default_pages_op")]
        op: String,
        page_id: Option<u64>,
        runtime_generation: Option<u64>,
        url: Option<String>,
    },
    Events {
        #[serde(default)]
        after_sequence: u64,
        runtime_generation: Option<u64>,
        #[serde(default = "default_browser_event_limit")]
        limit: u64,
        #[serde(default)]
        kinds: Vec<String>,
        #[serde(default)]
        wait_ms: u64,
    },
    Scroll {
        locator: Option<Locator>,
        #[serde(default)]
        delta_x: i64,
        #[serde(default)]
        delta_y: i64,
    },
    Screenshot {
        locator: Option<Locator>,
        #[serde(default)]
        full_page: bool,
        #[serde(default = "default_screenshot_max_bytes")]
        max_bytes: u64,
    },
    Request {
        method: String,
        url: String,
        #[serde(default)]
        headers: Vec<BrowserRequestHeader>,
        body_text: Option<String>,
        body_base64: Option<String>,
        #[serde(default = "default_browser_request_timeout")]
        timeout_ms: u64,
        #[serde(default = "default_browser_request_response_bytes")]
        max_response_bytes: u64,
        /// Follows a redirect instead of failing on it; sent once either way.
        #[serde(default)]
        follow_redirects: bool,
    },
    Press {
        locator: Option<Locator>,
        key: String,
        #[serde(default)]
        snapshot: bool,
        #[serde(flatten)]
        options: InteractionOptions,
    },
    Wait {
        for_what: String,
        value: String,
        #[serde(default)]
        snapshot: bool,
        #[serde(flatten)]
        options: InteractionOptions,
    },
    Back {
        #[serde(default)]
        snapshot: bool,
        #[serde(flatten)]
        options: InteractionOptions,
    },
    Forward {
        #[serde(default)]
        snapshot: bool,
        #[serde(flatten)]
        options: InteractionOptions,
    },
    Close,
}

impl BrowserAction {
    /// Whether the worker appends the resulting page's snapshot as `data.snapshot`.
    fn wants_snapshot(&self) -> bool {
        match self {
            Self::Navigate { snapshot, .. }
            | Self::Click { snapshot, .. }
            | Self::Fill { snapshot, .. }
            | Self::Select { snapshot, .. }
            | Self::Press { snapshot, .. }
            | Self::Wait { snapshot, .. }
            | Self::Pointer { snapshot, .. }
            | Self::Type { snapshot, .. }
            | Self::Back { snapshot, .. }
            | Self::Forward { snapshot, .. } => *snapshot,
            _ => false,
        }
    }

    /// The shared interaction settings, for the actions that take them.
    fn options(&self) -> Option<&InteractionOptions> {
        match self {
            Self::Navigate { options, .. }
            | Self::Click { options, .. }
            | Self::Fill { options, .. }
            | Self::Select { options, .. }
            | Self::Press { options, .. }
            | Self::Wait { options, .. }
            | Self::Pointer { options, .. }
            | Self::Type { options, .. }
            | Self::Back { options, .. }
            | Self::Forward { options, .. } => Some(options),
            _ => None,
        }
    }

    fn options_mut(&mut self) -> Option<&mut InteractionOptions> {
        match self {
            Self::Navigate { options, .. }
            | Self::Click { options, .. }
            | Self::Fill { options, .. }
            | Self::Select { options, .. }
            | Self::Press { options, .. }
            | Self::Wait { options, .. }
            | Self::Pointer { options, .. }
            | Self::Type { options, .. }
            | Self::Back { options, .. }
            | Self::Forward { options, .. } => Some(options),
            _ => None,
        }
    }

    /// Shared settings this action was given but does not use.
    fn unused_options(&self) -> Vec<&'static str> {
        // Nothing waits for a dom snapshot of the whole page.
        if let Self::Snapshot {
            format,
            locator: None,
            timeout_ms: Some(_),
            ..
        } = self
        {
            if format == "dom" {
                return vec!["timeout_ms"];
            }
        }
        let Some(options) = self.options() else {
            return Vec::new();
        };
        let navigation = matches!(
            self,
            Self::Navigate { .. } | Self::Back { .. } | Self::Forward { .. }
        );
        let waits_after = !matches!(self, Self::Wait { .. } | Self::Pointer { .. });
        // Keys sent to whatever has focus, a fixed pause and a point wait for nothing.
        let waits_for_nothing = match self {
            Self::Press { locator, .. } | Self::Type { locator, .. } => locator.is_none(),
            Self::Wait { for_what, .. } => for_what == "timeout",
            Self::Pointer {
                locator,
                to_locator,
                ..
            } => locator.is_none() && to_locator.is_none(),
            _ => false,
        };
        [
            (
                "timeout_ms",
                options.timeout_ms.is_some() && waits_for_nothing,
            ),
            ("wait_ms", options.wait_ms.is_some() && !waits_after),
            (
                "max_bytes",
                options.max_bytes.is_some() && !self.wants_snapshot(),
            ),
            ("wait_until", options.wait_until.is_some() && !navigation),
        ]
        .into_iter()
        .filter_map(|(name, unused)| unused.then_some(name))
        .collect()
    }

    /// Reads an action as agents send it. A null option is the same as an
    /// absent one, and an option this action does not take is named in the
    /// returned list instead of failing the call or vanishing: `op` naming the
    /// action's own type and `snapshot` on a snapshot action are accepted as
    /// they are. So is any option at its schema default, which some clients
    /// fill in for every property; each action's own default is the same.
    pub fn from_agent_input(value: Value) -> DomainResult<(Self, Vec<String>)> {
        let Value::Object(mut fields) = value else {
            return Err(DomainError::invalid("action must be an object"));
        };
        fields.retain(|name, value| !value.is_null() && !is_schema_default(name, value));
        let action: Self = serde_json::from_value(Value::Object(fields.clone()))
            .map_err(|error| DomainError::invalid(error.to_string()))?;
        // Every field the action read is serialized back, so what is missing
        // there was not read.
        let read = serde_json::to_value(&action)
            .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?;
        let kind = fields.get("type").cloned().unwrap_or(Value::Null);
        let mut ignored = fields
            .iter()
            .filter(|(name, value)| {
                read.get(name.as_str()).is_none()
                    && !(name.as_str() == "op" && **value == kind)
                    && !(name.as_str() == "snapshot" && kind == "snapshot")
            })
            .map(|(name, _)| name.chars().take(64).collect::<String>())
            .collect::<Vec<_>>();
        ignored.extend(action.unused_options().into_iter().map(String::from));
        ignored.sort();
        ignored.dedup();
        ignored.truncate(MAX_IGNORED_OPTIONS);
        Ok((action, ignored))
    }

    /// Every locator the action carries.
    fn locators(&self) -> Vec<&Locator> {
        match self {
            Self::Click { locator, .. }
            | Self::Fill { locator, .. }
            | Self::Select { locator, .. }
            | Self::Upload { locator, .. } => vec![locator],
            Self::Snapshot { locator, .. }
            | Self::Inspect { locator, .. }
            | Self::Scroll { locator, .. }
            | Self::Screenshot { locator, .. }
            | Self::Press { locator, .. }
            | Self::Type { locator, .. } => locator.iter().collect(),
            Self::Pointer {
                locator,
                to_locator,
                ..
            } => locator
                .as_deref()
                .into_iter()
                .chain(to_locator.as_deref())
                .collect(),
            _ => Vec::new(),
        }
    }
}

fn default_browser_action_timeout() -> u64 {
    10_000
}

fn default_pages_op() -> String {
    "list".into()
}

/// The most option names an action result lists as ignored.
const MAX_IGNORED_OPTIONS: usize = 16;

/// Whether `value` is the default the browser_action schema declares for the
/// `name` option. Every action that reads one of these options has the same
/// default, so leaving it out changes nothing.
fn is_schema_default(name: &str, value: &Value) -> bool {
    let default = match name {
        "offset" | "after_sequence" | "wait_ms" | "delta_x" | "delta_y" => json!(0),
        "limit" => json!(default_browser_event_limit()),
        "max_response_bytes" => json!(default_browser_request_response_bytes()),
        "snapshot" | "via_chooser" | "full_page" | "follow_redirects" => json!(false),
        _ => return false,
    };
    *value == default
}

fn default_pointer_button() -> String {
    "left".into()
}

fn default_pointer_count() -> u8 {
    1
}

fn default_inspection_max_bytes() -> u64 {
    4096
}

fn default_browser_event_limit() -> u64 {
    50
}

fn default_browser_request_timeout() -> u64 {
    15_000
}

fn default_browser_request_response_bytes() -> u64 {
    4096
}

fn default_screenshot_max_bytes() -> u64 {
    4 * 1024 * 1024
}

fn default_snapshot_format() -> String {
    "accessibility".into()
}

fn default_snapshot_max_bytes() -> u64 {
    MAX_SNAPSHOT_BYTES
}

/// A viewport point: both coordinates or neither, each within the range the
/// worker accepts.
fn pointer_point(x: Option<f64>, y: Option<f64>, label: &str) -> DomainResult<bool> {
    let valid = |value: f64| value.is_finite() && (0.0..=MAX_POINTER_COORDINATE).contains(&value);
    match (x, y) {
        (None, None) => Ok(false),
        (Some(x), Some(y)) if valid(x) && valid(y) => Ok(true),
        _ => Err(DomainError::invalid(format!(
            "{label} x and y must both be 0..100000"
        ))),
    }
}

fn validate_browser_action(action: &BrowserAction) -> DomainResult<()> {
    for locator in action.locators() {
        if locator
            .frame
            .as_ref()
            .is_some_and(|frame| frame.is_empty() || frame.len() > 2048)
        {
            return Err(DomainError::invalid(
                "locator frame must be 1..2048 bytes of a frame name or URL",
            ));
        }
        if locator
            .nth
            .is_some_and(|nth| !(-1_000_000..=1_000_000).contains(&nth))
        {
            return Err(DomainError::invalid(
                "locator nth must be -1000000..1000000",
            ));
        }
    }
    let timeout_ms = match action {
        BrowserAction::Snapshot { timeout_ms, .. } => *timeout_ms,
        _ => action.options().and_then(|options| options.timeout_ms),
    };
    if timeout_ms.is_some_and(|timeout| !(1..=30_000).contains(&timeout)) {
        return Err(DomainError::invalid("timeout_ms must be 1..30000"));
    }
    if let Some(options) = action.options() {
        if options.wait_ms.is_some_and(|wait| wait > 30_000) {
            return Err(DomainError::invalid("wait_ms must be 0..30000"));
        }
        if options.max_bytes == Some(0) {
            return Err(DomainError::invalid("max_bytes must be at least 1"));
        }
        if options
            .wait_until
            .as_deref()
            .is_some_and(|wait| !matches!(wait, "load" | "domcontentloaded" | "networkidle"))
        {
            return Err(DomainError::invalid(
                "wait_until must be load|domcontentloaded|networkidle",
            ));
        }
    }
    match action {
        BrowserAction::Pointer {
            op,
            locator,
            x,
            y,
            to_locator,
            to_x,
            to_y,
            button,
            count,
            modifiers,
            ..
        } => {
            if !matches!(op.as_str(), "click" | "hover" | "drag") {
                return Err(DomainError::invalid("pointer op must be click|hover|drag"));
            }
            const MODIFIERS: &[&str] = &["Alt", "Control", "Meta", "Shift"];
            let mut held = HashSet::new();
            if !matches!(button.as_str(), "left" | "right" | "middle")
                || !(1..=3).contains(count)
                || modifiers
                    .iter()
                    .any(|key| !MODIFIERS.contains(&key.as_str()) || !held.insert(key.as_str()))
            {
                return Err(DomainError::invalid(
                    "pointer button must be left|right|middle, count 1..3, and modifiers unique Alt|Control|Meta|Shift",
                ));
            }
            if locator.is_some() == pointer_point(*x, *y, "pointer")? {
                return Err(DomainError::invalid(format!(
                    "pointer {op} requires either a locator or x and y"
                )));
            }
            let destination = pointer_point(*to_x, *to_y, "pointer destination")?;
            if op == "drag" {
                if to_locator.is_some() == destination {
                    return Err(DomainError::invalid(
                        "pointer drag destination requires either to_locator or to_x and to_y",
                    ));
                }
            } else if to_locator.is_some() || destination {
                return Err(DomainError::invalid(
                    "pointer destination applies to drag only",
                ));
            }
        }
        BrowserAction::Type { text, .. }
            if text.is_empty() || text.len() > MAX_BROWSER_TYPE_BYTES =>
        {
            return Err(DomainError::invalid("type text must be 1..4096 bytes"));
        }
        BrowserAction::Upload {
            files,
            via_chooser,
            timeout_ms,
            ..
        } => {
            if files.len() > 16 || (*via_chooser && files.is_empty()) {
                return Err(DomainError::invalid(
                    "upload accepts at most 16 files; chooser uploads require at least one",
                ));
            }
            if !(1..=30_000).contains(timeout_ms) {
                return Err(DomainError::invalid("upload timeout_ms must be 1..30000"));
            }
            if files.iter().any(|file| {
                file.len() > 4096 || file.contains('\0') || !Path::new(file).is_absolute()
            }) {
                return Err(DomainError::invalid(
                    "upload files must be absolute paths of at most 4096 bytes",
                ));
            }
        }
        BrowserAction::Inspect { max_bytes, .. } if !(1..=65_536).contains(max_bytes) => {
            return Err(DomainError::invalid("inspect max_bytes must be 1..65536"));
        }
        BrowserAction::Snapshot { max_bytes: 0, .. } => {
            return Err(DomainError::invalid(
                "snapshot max_bytes must be at least 1",
            ));
        }
        BrowserAction::Evaluate {
            expression,
            frame,
            timeout_ms,
        } => {
            if expression.trim().is_empty() || expression.len() > MAX_BROWSER_EVALUATE_BYTES {
                return Err(DomainError::invalid(
                    "evaluate expression must be 1..65536 bytes of JavaScript",
                ));
            }
            if frame
                .as_ref()
                .is_some_and(|frame| frame.is_empty() || frame.len() > 2048)
            {
                return Err(DomainError::invalid(
                    "evaluate frame must be 1..2048 bytes of a frame name or URL",
                ));
            }
            if !(1..=30_000).contains(timeout_ms) {
                return Err(DomainError::invalid("evaluate timeout_ms must be 1..30000"));
            }
        }
        BrowserAction::Pages {
            op,
            page_id,
            runtime_generation,
            url,
        } => match op.as_str() {
            "list" if page_id.is_none() && runtime_generation.is_none() && url.is_none() => {}
            "new" if page_id.is_none() && runtime_generation.is_none() => {
                if let Some(url) = url {
                    validate_browser_page_url(url)?;
                }
            }
            "select" | "close"
                if page_id.is_some_and(|value| value > 0)
                    && runtime_generation.is_some_and(|value| value > 0)
                    && url.is_none() => {}
            "list" => {
                return Err(DomainError::invalid(
                    "pages list does not accept page_id, runtime_generation, or url",
                ));
            }
            "new" => {
                return Err(DomainError::invalid(
                    "pages new accepts only an optional url",
                ));
            }
            "select" | "close" => {
                return Err(DomainError::invalid(
                    "pages select/close require page_id and runtime_generation",
                ));
            }
            _ => {
                return Err(DomainError::invalid(
                    "pages op must be list|select|new|close",
                ));
            }
        },
        BrowserAction::Events {
            after_sequence,
            runtime_generation,
            limit,
            kinds,
            wait_ms,
        } => {
            if !(1..=100).contains(limit) {
                return Err(DomainError::invalid("events limit must be 1..100"));
            }
            if *wait_ms > 30_000 {
                return Err(DomainError::invalid("events wait_ms must be 0..30000"));
            }
            if *after_sequence > 0 && runtime_generation.is_none() {
                return Err(DomainError::invalid(
                    "events runtime_generation is required with after_sequence",
                ));
            }
            if runtime_generation.is_some_and(|value| value == 0) {
                return Err(DomainError::invalid(
                    "events runtime_generation must be a positive integer",
                ));
            }
            const KINDS: &[&str] = &[
                "page",
                "popup",
                "navigation",
                "dialog",
                "console",
                "page_error",
                "request",
                "response",
                "request_failed",
                "window_message",
                "observer_error",
            ];
            if kinds.len() > KINDS.len() || kinds.iter().any(|kind| !KINDS.contains(&kind.as_str()))
            {
                return Err(DomainError::invalid("events contains an unsupported kind"));
            }
        }
        BrowserAction::Scroll {
            locator,
            delta_x,
            delta_y,
        } => {
            if delta_x.unsigned_abs() > 100_000 || delta_y.unsigned_abs() > 100_000 {
                return Err(DomainError::invalid(
                    "scroll deltas must be between -100000 and 100000",
                ));
            }
            if locator.is_none() && *delta_x == 0 && *delta_y == 0 {
                return Err(DomainError::invalid(
                    "scroll requires a locator or a non-zero delta",
                ));
            }
        }
        BrowserAction::Screenshot {
            locator,
            full_page,
            max_bytes,
        } => {
            if !(1..=MAX_BROWSER_SCREENSHOT_BYTES).contains(max_bytes) {
                return Err(DomainError::invalid(
                    "screenshot max_bytes must be 1..8388608",
                ));
            }
            if *full_page && locator.is_some() {
                return Err(DomainError::invalid(
                    "screenshot full_page cannot be combined with a locator",
                ));
            }
        }
        BrowserAction::Request {
            method,
            url,
            headers,
            body_text,
            body_base64,
            timeout_ms,
            max_response_bytes,
            ..
        } => {
            let method = method.to_ascii_uppercase();
            if !matches!(
                method.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
            ) {
                return Err(DomainError::invalid(
                    "request method must be GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS",
                ));
            }
            let parsed = url::Url::parse(url)
                .map_err(|error| DomainError::invalid(format!("invalid request URL: {error}")))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(DomainError::invalid("request URL must use HTTP or HTTPS"));
            }
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err(DomainError::invalid(
                    "request URL must not contain credentials",
                ));
            }
            if !(1_000..=30_000).contains(timeout_ms) {
                return Err(DomainError::invalid(
                    "request timeout_ms must be 1000..30000",
                ));
            }
            if !(1..=MAX_BROWSER_REQUEST_RESPONSE_BYTES).contains(max_response_bytes) {
                return Err(DomainError::invalid(
                    "request max_response_bytes must be 1..65536",
                ));
            }
            if body_text.is_some() && body_base64.is_some() {
                return Err(DomainError::invalid(
                    "request accepts only one of body_text or body_base64",
                ));
            }
            let body_len = if let Some(body) = body_text {
                body.len()
            } else if let Some(body) = body_base64 {
                if body.len() > MAX_BROWSER_REQUEST_BODY_BYTES.div_ceil(3) * 4 {
                    return Err(DomainError::new(
                        ErrorCode::BodyTooLarge,
                        "request body exceeds 2 MiB",
                    ));
                }
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .map_err(|_| DomainError::invalid("request body_base64 is invalid base64"))?
                    .len()
            } else {
                0
            };
            if body_len > MAX_BROWSER_REQUEST_BODY_BYTES {
                return Err(DomainError::new(
                    ErrorCode::BodyTooLarge,
                    "request body exceeds 2 MiB",
                ));
            }
            if matches!(method.as_str(), "GET" | "HEAD")
                && (body_text.is_some() || body_base64.is_some())
            {
                return Err(DomainError::invalid(
                    "GET and HEAD browser requests cannot include a body",
                ));
            }
            if headers.len() > 64 {
                return Err(DomainError::invalid("request accepts at most 64 headers"));
            }
            let mut header_bytes = 0usize;
            let mut header_names = HashSet::new();
            for header in headers {
                let name = http::header::HeaderName::from_bytes(header.name.as_bytes())
                    .map_err(|_| DomainError::invalid("request contains an invalid header name"))?;
                http::header::HeaderValue::from_bytes(header.value.as_bytes()).map_err(|_| {
                    DomainError::invalid("request contains an invalid header value")
                })?;
                let name = name.as_str();
                if browser_managed_request_header(name, &header.value) {
                    return Err(DomainError::invalid(format!(
                        "request header {name} is browser-managed"
                    )));
                }
                if !header_names.insert(name.to_string()) {
                    return Err(DomainError::invalid(format!(
                        "request header {name} is duplicated; browser fetch would combine its values"
                    )));
                }
                header_bytes = header_bytes
                    .saturating_add(header.name.len())
                    .saturating_add(header.value.len());
            }
            if header_bytes > 65_536 {
                return Err(DomainError::invalid(
                    "request header names and values exceed 65536 bytes",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn browser_managed_request_header(name: &str, value: &str) -> bool {
    const EXACT: &[&str] = &[
        "accept-charset",
        "accept-encoding",
        "access-control-request-headers",
        "access-control-request-method",
        "connection",
        "content-length",
        "cookie",
        "cookie2",
        "date",
        "dnt",
        "expect",
        "host",
        "keep-alive",
        "origin",
        "permissions-policy",
        "referer",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "user-agent",
        "via",
        "x-huntproxy-browser-origin",
        "x-huntproxy-internal-crawler",
    ];
    if EXACT.contains(&name) || name.starts_with("proxy-") || name.starts_with("sec-") {
        return true;
    }
    matches!(
        name,
        "x-http-method" | "x-http-method-override" | "x-method-override"
    ) && value.split(',').any(|method| {
        matches!(
            method.trim().to_ascii_uppercase().as_str(),
            "CONNECT" | "TRACE" | "TRACK"
        )
    })
}

/// What holds a project's browser slots, from its active sessions' IDs and
/// the profiles of the persistent ones, so the caller can free one.
fn concurrency_limit_message(
    limit: u32,
    sessions: impl Iterator<Item = (i64, Option<impl std::fmt::Display>)>,
) -> String {
    let mut sessions = sessions.collect::<Vec<_>>();
    sessions.sort_by_key(|(id, _)| *id);
    let used = sessions.len();
    let mut holders = Vec::new();
    let mut ephemeral = 0;
    for (id, profile) in sessions {
        match profile {
            Some(profile) => holders.push(format!("session {id} (profile {profile})")),
            None => ephemeral += 1,
        }
    }
    match ephemeral {
        0 => {}
        1 => holders.push("1 ephemeral session".into()),
        count => holders.push(format!("{count} ephemeral sessions")),
    }
    let held = if holders.is_empty() {
        String::new()
    } else {
        format!(", held by {}", holders.join(", "))
    };
    // Ephemeral sessions belong to a running HuntProxy tool, which stops them.
    let ephemeral_note = if ephemeral > 0 {
        "; ephemeral sessions end on their own when the tool using them finishes"
    } else {
        ""
    };
    format!(
        "project browser concurrency limit reached: {used} of {limit} browser slots in use{held}; browser_manage op=stop with a persistent session's session_id frees one{ephemeral_note}"
    )
}

fn validate_browser_page_url(value: &str) -> DomainResult<()> {
    if value == "about:blank" {
        return Ok(());
    }
    let url = url::Url::parse(value)
        .map_err(|error| DomainError::invalid(format!("invalid page URL: {error}")))?;
    if matches!(url.scheme(), "http" | "https") {
        Ok(())
    } else {
        Err(DomainError::invalid(
            "page URL must be about:blank, HTTP, or HTTPS",
        ))
    }
}

/// Fits `result` to [`ACTION_OUTPUT_BYTES`] of compact JSON by construction.
/// Snapshot and inspection text is cut on a char boundary after accounting for
/// JSON escaping; snapshots then carry the exact `next_offset` to continue
/// from. Event rows end at a whole row whose sequence becomes `next_sequence`.
fn fit_action_result(action: &BrowserAction, result: &mut ActionResult) -> DomainResult<()> {
    match action {
        BrowserAction::Snapshot { .. } => fit_text_content(result, "", true),
        BrowserAction::Inspect { .. } => fit_text_content(result, "", false),
        BrowserAction::Evaluate { .. } => {
            value_to_content_if_oversized(result)?;
            fit_text_content(result, "", false)
        }
        BrowserAction::Events { .. } => fit_event_rows(result),
        _ if action.wants_snapshot() => fit_text_content(result, "/snapshot", true),
        _ => Ok(()),
    }
}

fn result_len(result: &ActionResult) -> DomainResult<usize> {
    let value = serde_json::to_value(result).map_err(|error| DomainError::Other(error.into()))?;
    Ok(crate::mcp::budget::json_len(&value))
}

/// An evaluation returns an object or array as JSON in `data.value` when it
/// fits; one that does not is turned into the JSON text `data.content`, which
/// can then be cut like any other.
fn value_to_content_if_oversized(result: &mut ActionResult) -> DomainResult<()> {
    let has_value = result
        .data
        .as_ref()
        .is_some_and(|data| data.get("value").is_some());
    if !has_value || result_len(result)? <= ACTION_OUTPUT_BYTES {
        return Ok(());
    }
    let Some(Value::Object(data)) = result.data.as_mut() else {
        return Ok(());
    };
    let value = data.remove("value").unwrap_or(Value::Null);
    let content =
        serde_json::to_string(&value).map_err(|error| DomainError::Other(error.into()))?;
    data.insert("total_bytes".into(), json!(content.len()));
    data.insert("content".into(), Value::String(content));
    Ok(())
}

/// Cuts the `content` of the object at `pointer` in `result.data`, which also
/// holds `total_bytes` and, past the start, the `offset` the content begins at.
fn fit_text_content(result: &mut ActionResult, pointer: &str, pageable: bool) -> DomainResult<()> {
    fn target<'a>(
        result: &'a mut ActionResult,
        pointer: &str,
    ) -> Option<&'a mut serde_json::Map<String, Value>> {
        result.data.as_mut()?.pointer_mut(pointer)?.as_object_mut()
    }
    let Some(object) = target(result, pointer) else {
        return Ok(());
    };
    let mut content = match object.get_mut("content") {
        Some(Value::String(content)) => std::mem::take(content),
        _ => return Ok(()),
    };
    let start = object.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let total = object
        .get("total_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(start + content.len() as u64);
    // Measure with the widest values the fields below can take.
    object.insert("truncated".into(), Value::Bool(false));
    if pageable {
        object.insert("next_offset".into(), json!(total));
    }
    let available = ACTION_OUTPUT_BYTES.saturating_sub(result_len(result)?);
    content.truncate(crate::mcp::budget::escaped_prefix_len(&content, available));
    let end = start + content.len() as u64;
    let object = target(result, pointer).expect("the content object was found above");
    object.insert("content".into(), Value::String(content));
    object.insert("truncated".into(), Value::Bool(end < total));
    if pageable && end < total {
        object.insert("next_offset".into(), json!(end));
    } else {
        object.remove("next_offset");
    }
    Ok(())
}

/// Keeps the leading event rows that fit; `truncated` marks a page the byte
/// budget ended, and `next_sequence` resumes right after the last row kept.
fn fit_event_rows(result: &mut ActionResult) -> DomainResult<()> {
    fn data(result: &mut ActionResult) -> Option<&mut serde_json::Map<String, Value>> {
        result.data.as_mut()?.as_object_mut()
    }
    let Some(object) = data(result) else {
        return Ok(());
    };
    let mut rows = match object.get_mut("events") {
        Some(Value::Array(rows)) => std::mem::take(rows),
        _ => return Ok(()),
    };
    object.insert("truncated".into(), Value::Bool(true));
    // The empty `[]` is already counted; rows_that_fit counts it as well.
    let available = ACTION_OUTPUT_BYTES.saturating_sub(result_len(result)?) + 2;
    let kept = crate::mcp::budget::rows_that_fit(&rows, available)?;
    let object = data(result).expect("the events object was found above");
    if kept < rows.len() {
        rows.truncate(kept);
        // The last kept row's sequence has no more digits than the original
        // cursor, so the result still fits.
        if let Some(sequence) = rows.last().and_then(|row| row.get("sequence")) {
            object.insert("next_sequence".into(), sequence.clone());
        }
    } else {
        object.remove("truncated");
    }
    object.insert("events".into(), Value::Array(rows));
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Locator {
    pub role: Option<String>,
    pub name: Option<String>,
    pub text: Option<String>,
    pub test_id: Option<String>,
    pub css: Option<String>,
    pub exact: Option<bool>,
    /// Picks one of several matches: 0 is the first, -1 the last.
    #[serde(default)]
    pub nth: Option<i64>,
    /// Looks inside the one frame whose name equals this or whose URL contains it.
    #[serde(default)]
    pub frame: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserRequestHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserActionContext {
    pub session_id: BrowserSessionId,
    pub profile: Option<String>,
    pub runtime_generation: u64,
    pub page_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub ok: bool,
    pub untrusted: bool,
    pub message: String,
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserActionContext>,
    /// Options the action was given but does not use.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored_options: Vec<String>,
}

/// Result of a bounded, host-owned cross-site navigation template. Secret
/// browser state is intentionally absent; network evidence is persisted by the
/// normal proxy capture path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserCsrfProbeResult {
    pub final_url: String,
    pub navigations: Vec<Value>,
}

#[derive(Debug, Clone)]
struct RuntimeSession {
    project_id: ProjectId,
    capture_session_id: CaptureSessionId,
    persistent: bool,
    profile: Option<String>,
    cdp: Option<BrowserCdpInfo>,
    /// Position in the worker's list of JavaScript files up to which they have
    /// been recorded; the next record asks only for what came after it.
    javascript_cursor: u64,
}

#[derive(Debug, Deserialize)]
struct WorkerResponse {
    id: Option<u64>,
    result: Option<Value>,
    error: Option<WorkerRpcError>,
}

#[derive(Debug, Deserialize)]
struct WorkerRpcError {
    code: i64,
    message: String,
}

enum WorkerCallFailure {
    /// The worker answered with an error.
    Rpc(DomainError),
    /// This call ran out of time. The worker may still be serving others.
    Timeout(DomainError),
    /// The worker cannot be used: it exited, closed its output, or wrote
    /// something that is not a response.
    Transport(DomainError),
}

impl WorkerCallFailure {
    fn into_domain(self) -> DomainError {
        match self {
            Self::Rpc(error) | Self::Timeout(error) | Self::Transport(error) => error,
        }
    }
}

/// Calls in flight to one worker. Each waits for the response carrying its
/// id, so a slow call holds up only its caller.
struct PendingCalls {
    next_id: u64,
    waiters: HashMap<u64, tokio::sync::oneshot::Sender<WorkerResponse>>,
    /// Why the worker can no longer be used, once it cannot.
    closed: Option<(ErrorCode, String)>,
}

/// The worker's request and response pipes, shared by every call to it.
struct WorkerIo {
    stdin: Mutex<ChildStdin>,
    pending: std::sync::Mutex<PendingCalls>,
}

impl WorkerIo {
    fn pending(&self) -> std::sync::MutexGuard<'_, PendingCalls> {
        self.pending
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    /// Fails every waiting call, and every later one, with `code` and `message`.
    fn close(&self, code: ErrorCode, message: impl Into<String>) {
        let mut pending = self.pending();
        if pending.closed.is_none() {
            pending.closed = Some((code, message.into()));
        }
        // A dropped sender wakes its caller, which then reports `closed`.
        pending.waiters.clear();
    }

    fn closed_error(&self) -> DomainError {
        let (code, message) = self
            .pending()
            .closed
            .clone()
            .unwrap_or((ErrorCode::Unavailable, "browser worker stopped".into()));
        DomainError::new(code, message)
    }

    async fn call(
        &self,
        timeout: Duration,
        method: &str,
        params: Value,
    ) -> Result<Value, WorkerCallFailure> {
        let (id, response) = {
            // Ids are taken while writing, so requests reach the worker in id order.
            let mut stdin = self.stdin.lock().await;
            let (id, response) = {
                let mut pending = self.pending();
                if pending.closed.is_some() {
                    drop(pending);
                    return Err(WorkerCallFailure::Transport(self.closed_error()));
                }
                let id = pending.next_id;
                pending.next_id = id.saturating_add(1);
                let (sender, receiver) = tokio::sync::oneshot::channel();
                pending.waiters.insert(id, sender);
                (id, receiver)
            };
            let request = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params,
            });
            let mut encoded = match serde_json::to_vec(&request) {
                Ok(encoded) => encoded,
                Err(error) => {
                    self.pending().waiters.remove(&id);
                    return Err(WorkerCallFailure::Transport(DomainError::new(
                        ErrorCode::ProtocolError,
                        format!("encode browser worker request: {error}"),
                    )));
                }
            };
            encoded.push(b'\n');
            let written = match stdin.write_all(&encoded).await {
                Ok(()) => stdin.flush().await,
                Err(error) => Err(error),
            };
            if let Err(error) = written {
                let message = format!("write browser worker request: {error}");
                self.close(ErrorCode::Unavailable, message.clone());
                return Err(WorkerCallFailure::Transport(DomainError::new(
                    ErrorCode::Unavailable,
                    message,
                )));
            }
            (id, response)
        };
        let response = match tokio::time::timeout(timeout, response).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => return Err(WorkerCallFailure::Transport(self.closed_error())),
            Err(_) => {
                self.pending().waiters.remove(&id);
                return Err(WorkerCallFailure::Timeout(DomainError::new(
                    ErrorCode::Timeout,
                    format!("browser worker {method} timed out"),
                )));
            }
        };
        if let Some(error) = response.error {
            let code = match error.code {
                -32602 => ErrorCode::InvalidArgument,
                -32001 => ErrorCode::NotFound,
                -32003 => ErrorCode::ChromiumNotInstalled,
                _ => ErrorCode::Unavailable,
            };
            return Err(WorkerCallFailure::Rpc(DomainError::new(
                code,
                error.message,
            )));
        }
        response.result.ok_or_else(|| {
            WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolError,
                "browser worker response missing result",
            ))
        })
    }
}

/// Hands each response line to the call waiting for its id, until the
/// worker's output ends or stops being responses.
async fn read_worker_responses(io: Arc<WorkerIo>, mut stdout: BufReader<ChildStdout>) {
    let mut line = String::new();
    loop {
        line.clear();
        match stdout.read_line(&mut line).await {
            Ok(0) => return io.close(ErrorCode::Unavailable, "browser worker closed stdout"),
            Ok(_) => {}
            Err(error) => {
                return io.close(
                    ErrorCode::Unavailable,
                    format!("read browser worker response: {error}"),
                )
            }
        }
        let response: WorkerResponse = match serde_json::from_str(line.trim()) {
            Ok(response) => response,
            Err(error) => {
                return io.close(
                    ErrorCode::ProtocolError,
                    format!("decode browser worker response: {error}"),
                )
            }
        };
        let Some(id) = response.id else {
            // An error about no request in particular: the two sides no
            // longer agree on the protocol.
            return io.close(
                ErrorCode::ProtocolError,
                "browser worker response without an id",
            );
        };
        // Nobody waits for the answer to a call that already timed out.
        let waiter = io.pending().waiters.remove(&id);
        if let Some(waiter) = waiter {
            let _ = waiter.send(response);
        }
    }
}

/// What a call needs of a worker. Cheap to clone, so callers wait for their
/// response without holding the project's worker lock.
#[derive(Clone)]
struct WorkerHandle {
    io: Arc<WorkerIo>,
    rpc_timeout: Duration,
}

impl WorkerHandle {
    async fn call(&self, method: &str, params: Value) -> Result<Value, WorkerCallFailure> {
        self.io.call(self.rpc_timeout, method, params).await
    }

    /// Whether `worker` is the process this handle calls.
    fn is(&self, worker: &WorkerProcess) -> bool {
        Arc::ptr_eq(&self.io, &worker.io)
    }
}

struct WorkerProcess {
    io: Arc<WorkerIo>,
    reader: tokio::task::JoinHandle<()>,
    child: Child,
    #[cfg(unix)]
    process_group: nix::unistd::Pid,
    terminated: bool,
    rpc_timeout: Duration,
}

impl WorkerProcess {
    async fn spawn(
        node_path: &Path,
        worker_path: &Path,
        playwright_core_path: Option<&Path>,
        chromium_path: Option<&Path>,
    ) -> Result<Self, WorkerCallFailure> {
        let mut command = Command::new(node_path);
        command
            .arg(worker_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(false);
        if let Some(parent) = worker_path.parent() {
            command.current_dir(parent);
        }
        if let Some(path) = playwright_core_path {
            command.env("HUNTPROXY_PLAYWRIGHT_CORE_PATH", path);
        }
        if let Some(path) = chromium_path {
            command.env("HUNTPROXY_CHROME_EXECUTABLE", path);
        }
        #[cfg(unix)]
        {
            // Native Chromium inherits this group, so a hung worker's browser can be
            // killed with it instead of keeping the project's profile locked.
            command.process_group(0);
            // Browser crashes should not leave large core files on a VPS.
            unsafe {
                command.pre_exec(|| {
                    let limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        let mut child = command.spawn().map_err(|error| {
            WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::BrowserDisabled,
                format!("start browser worker: {error}"),
            ))
        })?;
        #[cfg(unix)]
        let process_group = nix::unistd::Pid::from_raw(
            child.id().expect("newly spawned worker has a process ID") as i32,
        );
        let stdin = child.stdin.take().ok_or_else(|| {
            WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolError,
                "browser worker stdin unavailable",
            ))
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolError,
                "browser worker stdout unavailable",
            ))
        })?;
        let io = Arc::new(WorkerIo {
            stdin: Mutex::new(stdin),
            pending: std::sync::Mutex::new(PendingCalls {
                next_id: 1,
                waiters: HashMap::new(),
                closed: None,
            }),
        });
        let reader = tokio::spawn(read_worker_responses(io.clone(), BufReader::new(stdout)));
        let mut process = Self {
            io,
            reader,
            child,
            #[cfg(unix)]
            process_group,
            terminated: false,
            rpc_timeout: WORKER_RPC_TIMEOUT,
        };
        let hello = process.call("hello", json!({})).await?;
        let protocol = hello.get("protocol").and_then(Value::as_u64);
        if protocol != Some(WORKER_PROTOCOL_VERSION) {
            process.terminate().await;
            return Err(WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolIncompatible,
                format!("browser worker protocol {protocol:?}, expected {WORKER_PROTOCOL_VERSION}"),
            )));
        }
        if !hello
            .get("capabilities")
            .and_then(Value::as_array)
            .is_some_and(|capabilities| {
                capabilities
                    .iter()
                    .any(|value| value == "profile_isolation")
            })
        {
            process.terminate().await;
            return Err(WorkerCallFailure::Transport(DomainError::new(
                ErrorCode::ProtocolIncompatible,
                "browser worker cannot guarantee profile isolation; update the configured browser worker",
            )));
        }
        Ok(process)
    }

    fn handle(&self) -> WorkerHandle {
        WorkerHandle {
            io: self.io.clone(),
            rpc_timeout: self.rpc_timeout,
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, WorkerCallFailure> {
        self.handle().call(method, params).await
    }

    async fn terminate(&mut self) {
        if self.terminated {
            return;
        }
        // Calls still waiting fail now instead of at their deadlines.
        self.io
            .close(ErrorCode::Unavailable, "browser worker stopped");
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.start_kill();
        }
        match tokio::time::timeout(Duration::from_secs(6), self.child.wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => {
                let _ = self.child.kill().await;
            }
        }
        // A healthy worker has stopped its browsers by now. A hung or crashed one
        // cannot, and its surviving Chromium would keep the profile locked.
        #[cfg(unix)]
        let _ = nix::sys::signal::killpg(self.process_group, nix::sys::signal::Signal::SIGKILL);
        self.reader.abort();
        self.terminated = true;
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.reader.abort();
        if self.terminated {
            return;
        }
        self.io
            .close(ErrorCode::Unavailable, "browser worker stopped");
        #[cfg(unix)]
        let _ = nix::sys::signal::killpg(self.process_group, nix::sys::signal::Signal::SIGKILL);
        #[cfg(not(unix))]
        {
            let _ = self.child.start_kill();
        }
    }
}

pub struct BrowserService {
    pub db: Arc<Db>,
    pub node_path: Option<PathBuf>,
    pub worker_path: Option<PathBuf>,
    proxy_server: String,
    ca_cert_path: Option<PathBuf>,
    profiles_root: PathBuf,
    runtime: BrowserRuntimeInspection,
    /// Version of each session's latest checkpoint. Only the number is kept:
    /// the checkpoint itself holds secrets and is never read back.
    checkpoint_versions: Mutex<HashMap<i64, u64>>,
    runtime_sessions: Arc<Mutex<HashMap<i64, RuntimeSession>>>,
    cdp_reservations: Arc<std::sync::Mutex<HashMap<i64, u16>>>,
    profile_leases: Mutex<HashSet<(i64, String)>>,
    lifecycle: RwLock<()>,
    project_lifecycle: Mutex<HashMap<i64, Arc<Mutex<()>>>>,
    /// Serializes profile state file IO. It also remembers what this process
    /// last wrote to each profile's `state.json`, so an unchanged checkpoint is
    /// recognized without reading and parsing a file that can reach 25 MiB.
    profile_io: Mutex<HashMap<(i64, String), PersistedProfileState>>,
    session_ops: Mutex<HashMap<i64, Arc<Mutex<()>>>>,
    workers: Mutex<HashMap<i64, Arc<Mutex<Option<WorkerProcess>>>>>,
    sandbox: std::sync::Mutex<HashMap<i64, SandboxState>>,
    /// When each project last had control activity: an agent's tool call, a
    /// change made in the web UI, or a browser start. Proxy traffic and reads
    /// do not count, so an idle page cannot keep its own browser alive.
    project_activity: std::sync::Mutex<HashMap<i64, std::time::Instant>>,
    idle_timeout: Duration,
}

/// Inspect the installed browser runtime without starting the daemon, launching
/// Chromium, or materializing the embedded worker.
pub fn inspect_browser_installation(config: &Config) -> BrowserInstallStatus {
    if let Some(prepared) = crate::installation::inspect(config) {
        let runtime = inspect_browser_runtime_with_paths(
            Some(&prepared.node_path),
            Some(&prepared.worker_path),
            Some(&prepared.playwright_core_path),
            Some(&prepared.chromium_path),
        );
        return browser_install_status(
            Some(&prepared.node_path),
            Some(&prepared.worker_path),
            &runtime,
        );
    }
    let node_path = existing_path(config.node_path.clone(), "node");
    let worker_path = inspect_worker_path(config.browser_worker_path.clone(), &config.data_dir);
    let runtime = inspect_browser_runtime_with_paths(
        node_path.as_deref(),
        worker_path.as_deref(),
        config.browser_playwright_core_path.as_deref(),
        config.browser_chromium_path.as_deref(),
    );

    browser_install_status(node_path.as_deref(), worker_path.as_deref(), &runtime)
}

fn browser_install_status(
    node_path: Option<&Path>,
    worker_path: Option<&Path>,
    runtime: &BrowserRuntimeInspection,
) -> BrowserInstallStatus {
    let playwright_core_path = runtime.playwright_core_path.as_deref();
    let chromium_path = runtime.chromium_path.as_deref();
    let node_available = node_path.is_some_and(Path::is_file);
    let worker_script_available = worker_path.is_some_and(Path::is_file);
    let worker_available = node_available
        && worker_script_available
        && playwright_core_path.is_some_and(Path::is_dir)
        && runtime.compatibility_error.is_none();
    let chromium_available = chromium_path.is_some_and(Path::is_file);

    let install_hint = if !node_available {
        Some("Install Node.js, then run: HuntProxy browser install".into())
    } else if !worker_script_available {
        Some(
            "Browser worker missing; reinstall HuntProxy or set HUNTPROXY_BROWSER_WORKER_PATH"
                .into(),
        )
    } else if let Some(error) = &runtime.inspection_error {
        Some(error.clone())
    } else if let Some(error) = &runtime.compatibility_error {
        Some(error.clone())
    } else if !playwright_core_path.is_some_and(Path::is_dir) {
        let directory = worker_path
            .and_then(Path::parent)
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "browser-worker".into());
        Some(format!(
            "playwright-core missing; run `npm install` in {directory}"
        ))
    } else if !chromium_available {
        Some("Install Chromium: HuntProxy browser install".into())
    } else {
        None
    };

    BrowserInstallStatus {
        node_available,
        worker_available,
        chromium_available,
        chromium_path: chromium_path.map(|path| path.display().to_string()),
        chromium_version: runtime.chromium_version.clone(),
        headless: runtime.headless,
        headless_compatibility: runtime.headless_compatibility,
        playwright_core_path: playwright_core_path.map(|path| path.display().to_string()),
        playwright_version: runtime.playwright_version.clone(),
        expected_chromium_version: runtime.expected_chromium_version.clone(),
        node_path: node_path.map(|path| path.display().to_string()),
        install_hint,
        sandbox_state: None,
        sandbox_reason: None,
    }
}

impl BrowserService {
    pub fn new(db: Arc<Db>, node_path: Option<PathBuf>, worker_path: Option<PathBuf>) -> Self {
        let profiles_root = default_profiles_root(&db);
        let proxy_server = std::env::var("HUNTPROXY_BROWSER_PROXY_SERVER")
            .unwrap_or_else(|_| DEFAULT_BROWSER_PROXY.to_string());
        let ca_cert_path = std::env::var_os("HUNTPROXY_BROWSER_CA_CERT").map(PathBuf::from);
        Self::new_with_proxy_and_ca(
            db,
            node_path,
            worker_path,
            proxy_server,
            ca_cert_path,
            profiles_root,
        )
    }

    /// Proxy-aware constructor for daemon integration with non-default proxy binds.
    pub fn new_with_proxy(
        db: Arc<Db>,
        node_path: Option<PathBuf>,
        worker_path: Option<PathBuf>,
        proxy_server: String,
    ) -> Self {
        let profiles_root = default_profiles_root(&db);
        let ca_cert_path = std::env::var_os("HUNTPROXY_BROWSER_CA_CERT").map(PathBuf::from);
        Self::new_with_proxy_and_ca(
            db,
            node_path,
            worker_path,
            proxy_server,
            ca_cert_path,
            profiles_root,
        )
    }

    /// Proxy- and CA-aware constructor for the daemon's managed browser sessions.
    pub fn new_with_proxy_and_ca(
        db: Arc<Db>,
        node_path: Option<PathBuf>,
        worker_path: Option<PathBuf>,
        proxy_server: String,
        ca_cert_path: Option<PathBuf>,
        profiles_root: PathBuf,
    ) -> Self {
        let worker_path = resolve_worker_path(worker_path);
        let node_path = existing_path(node_path, "node");
        let runtime = inspect_browser_runtime(node_path.as_deref(), worker_path.as_deref());
        Self {
            db,
            node_path,
            worker_path,
            proxy_server,
            ca_cert_path: ca_cert_path.filter(|path| path.is_file()),
            profiles_root,
            runtime,
            checkpoint_versions: Mutex::new(HashMap::new()),
            runtime_sessions: Arc::new(Mutex::new(HashMap::new())),
            cdp_reservations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            profile_leases: Mutex::new(HashSet::new()),
            lifecycle: RwLock::new(()),
            project_lifecycle: Mutex::new(HashMap::new()),
            profile_io: Mutex::new(HashMap::new()),
            session_ops: Mutex::new(HashMap::new()),
            workers: Mutex::new(HashMap::new()),
            sandbox: std::sync::Mutex::new(HashMap::new()),
            project_activity: std::sync::Mutex::new(HashMap::new()),
            idle_timeout: BROWSER_IDLE_TIMEOUT,
        }
    }

    /// Records control activity for a project, which keeps its browsers open
    /// for another idle timeout.
    pub fn touch_project(&self, project_id: ProjectId) {
        self.project_activity
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(project_id.get(), std::time::Instant::now());
    }

    /// How long the project has gone without control activity; `Duration::MAX`
    /// when it has had none since the daemon started.
    pub fn project_idle_for(&self, project_id: ProjectId) -> Duration {
        self.project_activity
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&project_id.get())
            .map_or(Duration::MAX, std::time::Instant::elapsed)
    }

    /// Stops the browsers of every project idle for the timeout, unless the
    /// project is still in use: `has_running_job` says it has a job, or one of
    /// its browsers is busy, handed off through CDP, or ephemeral (ephemeral
    /// browsers belong to an operation that stops them). Only in-memory state
    /// is read until a project is due. Returns how many browsers were stopped.
    pub async fn stop_idle_projects(&self, has_running_job: impl Fn(ProjectId) -> bool) -> usize {
        let mut projects = self
            .runtime_sessions
            .lock()
            .await
            .values()
            .map(|runtime| runtime.project_id.get())
            .collect::<Vec<_>>();
        projects.sort_unstable();
        projects.dedup();
        let mut stopped = 0;
        for project_id in projects.into_iter().map(ProjectId) {
            if self.project_idle_for(project_id) < self.idle_timeout || has_running_job(project_id)
            {
                continue;
            }
            match self.stop_project_if_idle(project_id).await {
                Ok(0) => {}
                Ok(count) => {
                    tracing::info!(
                        project_id = project_id.get(),
                        browsers = count,
                        "stopped the browsers of an idle project"
                    );
                    stopped += count;
                }
                Err(error) => tracing::warn!(
                    %error,
                    project_id = project_id.get(),
                    "could not stop the browsers of an idle project"
                ),
            }
        }
        stopped
    }

    async fn stop_project_if_idle(&self, project_id: ProjectId) -> DomainResult<usize> {
        // A held lifecycle lock is a start, stop or shutdown in progress: the
        // project is not idle, or is already being dealt with.
        let Ok(_shutdown_guard) = self.lifecycle.try_read() else {
            return Ok(0);
        };
        let project_lock = self.project_lifecycle_lock(project_id).await;
        let Ok(_lifecycle) = project_lock.try_lock() else {
            return Ok(0);
        };
        let session_ids = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, runtime)| (runtime.project_id == project_id).then_some(*id))
            .collect::<Vec<_>>();
        // Holding every operation lock keeps new calls from starting while the
        // project is checked once more and stopped. One that is held is a call
        // in flight, so the project is in use; never wait for it.
        let mut operations = Vec::with_capacity(session_ids.len());
        for session_id in session_ids {
            let lock = self
                .session_operation_lock(BrowserSessionId(session_id))
                .await;
            let Ok(guard) = lock.try_lock_owned() else {
                return Ok(0);
            };
            operations.push((BrowserSessionId(session_id), guard));
        }
        let in_use = self.runtime_sessions.lock().await.values().any(|runtime| {
            runtime.project_id == project_id && (runtime.cdp.is_some() || !runtime.persistent)
        });
        // A call touches the project before it waits for an operation lock.
        if in_use || self.project_idle_for(project_id) < self.idle_timeout {
            return Ok(0);
        }
        let total = operations.len();
        let mut first_error = None;
        for (session_id, _operation) in operations {
            if let Err(error) = self
                .stop_locked(project_id, session_id, IDLE_STOPPED_STATUS)
                .await
            {
                first_error.get_or_insert(error);
            }
        }
        self.reap_worker(project_id).await;
        match first_error {
            Some(error) => Err(error),
            None => Ok(total),
        }
    }

    /// The error for a session the idle rule stopped, saying what happened and
    /// how to get the browser back.
    fn idle_stopped_error(&self, session: &BrowserSession) -> Option<DomainError> {
        if session.state != BrowserSessionState::Stopped
            || session.checkpoint_status.as_deref() != Some(IDLE_STOPPED_STATUS)
        {
            return None;
        }
        let resume = match session.profile.as_deref() {
            None | Some(DEFAULT_BROWSER_PROFILE) => "call browser_start".to_string(),
            Some(profile) => format!("call browser_start with profile \"{profile}\""),
        };
        Some(DomainError::new(
            ErrorCode::Unavailable,
            format!(
                "browser session {} was stopped after {} without project activity; {resume} to resume its profile",
                session.id.get(),
                describe_idle_timeout(self.idle_timeout),
            ),
        ))
    }

    /// The error for a session with no running browser.
    async fn inactive_session_error(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainError {
        self.db
            .get_browser_session(project_id, session_id)
            .await
            .ok()
            .and_then(|session| self.idle_stopped_error(&session))
            .unwrap_or_else(|| {
                DomainError::new(ErrorCode::Unavailable, "browser session is not active")
            })
    }

    /// Apply paths verified by the release installer without process-wide
    /// environment changes or changing an existing browser profile.
    pub(crate) fn with_runtime_paths(
        mut self,
        playwright_core_path: Option<PathBuf>,
        chromium_path: Option<PathBuf>,
    ) -> Self {
        let playwright_core_path = playwright_core_path.filter(|path| path.is_dir());
        let chromium_path = chromium_path.filter(|path| path.is_file());
        if playwright_core_path.is_some() || chromium_path.is_some() {
            self.runtime = inspect_browser_runtime_with_paths(
                self.node_path.as_deref(),
                self.worker_path.as_deref(),
                playwright_core_path.as_deref(),
                chromium_path.as_deref(),
            );
        }
        self
    }

    pub fn status(&self) -> BrowserInstallStatus {
        let mut status = browser_install_status(
            self.node_path.as_deref(),
            self.worker_path.as_deref(),
            &self.runtime,
        );
        let sandbox = self
            .sandbox
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some((state, reason)) = sandbox
            .iter()
            .min_by_key(|(id, value)| (value.0.as_deref() != Some("disabled_fallback"), **id))
            .map(|(_, value)| value)
        {
            status.sandbox_state = state.clone();
            status.sandbox_reason = reason.clone();
        }
        status
    }

    pub async fn start(&self, project_id: ProjectId, url: String) -> DomainResult<BrowserSession> {
        self.start_with_profile(project_id, url, DEFAULT_BROWSER_PROFILE)
            .await
    }

    pub async fn start_with_profile(
        &self,
        project_id: ProjectId,
        url: String,
        profile: &str,
    ) -> DomainResult<BrowserSession> {
        self.start_with_profile_and_cookie_profile(project_id, url, profile, None)
            .await
    }

    pub async fn start_with_profile_and_cookie_profile(
        &self,
        project_id: ProjectId,
        url: String,
        profile: &str,
        cookie_profile: Option<&str>,
    ) -> DomainResult<BrowserSession> {
        self.start_with_profile_options(project_id, url, profile, cookie_profile, false)
            .await
    }

    pub async fn start_with_profile_options(
        &self,
        project_id: ProjectId,
        url: String,
        profile: &str,
        cookie_profile: Option<&str>,
        refresh_cookies: bool,
    ) -> DomainResult<BrowserSession> {
        validate_browser_profile_name(profile)?;
        if cookie_profile.is_some_and(|name| name != profile) {
            return Err(DomainError::invalid(
                "cookie_profile must match the requested browser profile",
            ));
        }
        if refresh_cookies && cookie_profile.is_none() {
            return Err(DomainError::invalid(
                "refresh_cookies requires a matching cookie_profile",
            ));
        }
        self.start_with_persistence(
            project_id,
            url,
            true,
            Some(profile.to_string()),
            cookie_profile.map(str::to_string),
            refresh_cookies,
        )
        .await
    }

    pub async fn start_ephemeral(
        &self,
        project_id: ProjectId,
        url: String,
    ) -> DomainResult<BrowserSession> {
        self.start_with_persistence(project_id, url, false, None, None, false)
            .await
    }

    pub async fn start_ephemeral_with_profile(
        &self,
        project_id: ProjectId,
        profile: &StoredCookieProfile,
    ) -> DomainResult<BrowserSession> {
        let cookie_override = CookieLaunchOverride::from_profile(profile)?;
        let _shutdown_guard = self.lifecycle.read().await;
        let project_lock = self.project_lifecycle_lock(project_id).await;
        let _lifecycle = project_lock.lock().await;
        self.start_runtime_with_cookies(
            project_id,
            "about:blank".into(),
            false,
            None,
            Some(cookie_override),
        )
        .await
    }

    async fn start_with_persistence(
        &self,
        project_id: ProjectId,
        url: String,
        persistent: bool,
        profile: Option<String>,
        cookie_profile: Option<String>,
        refresh_cookies: bool,
    ) -> DomainResult<BrowserSession> {
        // Starting and stopping share one worker. Keep lifecycle transitions
        // atomic so a concurrent stop cannot terminate a worker between a new
        // session's launch and its registration, and concurrent starts cannot
        // race the per-project browser limit.
        self.touch_project(project_id);
        let _shutdown_guard = self.lifecycle.read().await;
        let project_lock = self.project_lifecycle_lock(project_id).await;
        let _lifecycle = project_lock.lock().await;
        let mut cookie_override = match cookie_profile.as_deref() {
            Some(name) => {
                let stored = self
                    .db
                    .get_named_cookie_profile(project_id, name)
                    .await?
                    .ok_or_else(|| {
                        DomainError::not_found(format!(
                            "cookie profile {name} not found in project {}; create it with cookies",
                            project_id.get()
                        ))
                    })?;
                let saved_seed = self
                    .load_persistent_profile(project_id, name)
                    .await?
                    .and_then(|state| state.cookie_seed);
                plan_cookie_seed(name, &stored, saved_seed, refresh_cookies)?
            }
            None => None,
        };
        if let Some(profile_name) = profile.as_deref().filter(|_| persistent) {
            let active_id = self
                .runtime_sessions
                .lock()
                .await
                .iter()
                .find_map(|(id, runtime)| {
                    (runtime.project_id == project_id
                        && runtime.persistent
                        && runtime.profile.as_deref() == Some(profile_name))
                    .then_some(BrowserSessionId(*id))
                });
            if let Some(session_id) = active_id {
                // Reuse only the exact verified identity, without relaunching or touching its cookies.
                let operation_lock = self.session_operation_lock(session_id).await;
                let _operation_guard = operation_lock.lock().await;
                let mut session = self.verified_session_status(project_id, session_id).await?;
                let mut navigated_by_seed = false;
                if let Some(cookie_override) = cookie_override.take() {
                    if self
                        .runtime_sessions
                        .lock()
                        .await
                        .get(&session_id.get())
                        .is_some_and(|runtime| runtime.cdp.is_some())
                    {
                        return Err(DomainError::new(
                            ErrorCode::Unavailable,
                            "return CDP control before refreshing profile cookies",
                        ));
                    }
                    // Storage must be written before the app's first load with
                    // the new tokens, so the worker also performs the requested
                    // navigation after seeding; it returns to the current page
                    // when no url was requested.
                    let seeds_storage = cookie_override.has_storage_work();
                    let result = self
                        .call_worker(
                            project_id,
                            "session.set_cookies",
                            json!({
                                "session_id": session_id.get(), "cookies": cookie_override.cookies,
                                "clear_cookies": cookie_override.clear_cookies,
                                "storage_seed": cookie_override.storage_params(),
                                "url": if seeds_storage { json!(url) } else { Value::Null },
                            }),
                        )
                        .await?;
                    let saved = self
                        .save_cookie_checkpoint(project_id, session_id, &result)
                        .await?;
                    self.record_cookie_seed(
                        project_id,
                        profile_name,
                        cookie_override.seed,
                        &cookie_override.storage,
                        &cookie_override.clear_origins,
                        saved.local_storage.keys().next().map(String::as_str),
                    )
                    .await?;
                    session = self.verified_session_status(project_id, session_id).await?;
                    if seeds_storage {
                        navigated_by_seed = true;
                    }
                }
                if url != "about:blank" && !navigated_by_seed {
                    if self
                        .runtime_sessions
                        .lock()
                        .await
                        .get(&session_id.get())
                        .is_some_and(|runtime| runtime.cdp.is_some())
                    {
                        return Err(DomainError::new(
                            ErrorCode::Unavailable,
                            "return CDP control before navigating the profile",
                        ));
                    }
                    let result = self.call_worker(project_id, "session.action", json!({
                        "session_id": session_id.get(), "action": {"type":"navigate", "url":url},
                    })).await?;
                    self.save_cookie_checkpoint(project_id, session_id, &result)
                        .await?;
                    session = self.verified_session_status(project_id, session_id).await?;
                }
                return Ok(session);
            }
        }
        let lease = if persistent {
            let profile = profile.as_deref().ok_or_else(|| {
                DomainError::new(ErrorCode::Internal, "persistent browser profile missing")
            })?;
            validate_browser_profile_name(profile)?;
            Some((project_id.get(), profile.to_string()))
        } else {
            None
        };
        if let Some(lease) = lease.as_ref() {
            let mut leases = self.profile_leases.lock().await;
            if !leases.insert(lease.clone()) {
                drop(leases);
                let active_session_id =
                    self.runtime_sessions
                        .lock()
                        .await
                        .iter()
                        .find_map(|(id, runtime)| {
                            (runtime.project_id == project_id
                                && runtime.persistent
                                && runtime.profile.as_deref() == Some(lease.1.as_str()))
                            .then_some(*id)
                        });
                let detail = active_session_id
                    .map(|id| format!(" as session {id}"))
                    .unwrap_or_default();
                return Err(DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    format!(
                        "browser profile '{}' is already active{detail}; stop it before starting it again",
                        lease.1
                    ),
                ));
            }
        }
        let result = async {
            self.start_runtime_with_cookies(project_id, url, persistent, profile, cookie_override)
                .await
        }
        .await;
        if result.is_err() {
            if let Some(lease) = lease {
                let still_owned = self.runtime_sessions.lock().await.values().any(|runtime| {
                    runtime.project_id.get() == lease.0
                        && runtime.persistent
                        && runtime.profile.as_deref() == Some(lease.1.as_str())
                });
                if !still_owned {
                    self.profile_leases.lock().await.remove(&lease);
                }
            }
        }
        result
    }

    async fn start_runtime_with_cookies(
        &self,
        project_id: ProjectId,
        mut url: String,
        persistent: bool,
        profile: Option<String>,
        cookie_override: Option<CookieLaunchOverride>,
    ) -> DomainResult<BrowserSession> {
        let status = self.status();
        if !status.worker_available {
            return Err(DomainError::new(
                ErrorCode::BrowserDisabled,
                status
                    .install_hint
                    .unwrap_or_else(|| "Browser runtime not installed".into()),
            ));
        }
        let project = self.db.get_project(project_id).await?;
        let profile_name = profile.as_deref();
        let runtimes = self.runtime_sessions.lock().await;
        let active_for_project = runtimes
            .values()
            .filter(|runtime| runtime.project_id == project_id)
            .count() as u32;
        if active_for_project >= project.limits.max_concurrent_browsers {
            return Err(DomainError::new(
                ErrorCode::ConcurrencyLimited,
                concurrency_limit_message(
                    project.limits.max_concurrent_browsers,
                    runtimes
                        .iter()
                        .filter(|(_, runtime)| runtime.project_id == project_id)
                        .map(|(id, runtime)| {
                            (
                                *id,
                                runtime.profile.as_deref().filter(|_| runtime.persistent),
                            )
                        }),
                ),
            ));
        }
        if persistent {
            let profile_name = profile_name.ok_or_else(|| {
                DomainError::new(ErrorCode::Internal, "persistent browser profile missing")
            })?;
            if let Some(active_session_id) = runtimes.iter().find_map(|(id, runtime)| {
                (runtime.project_id == project_id
                    && runtime.persistent
                    && runtime.profile.as_deref() == Some(profile_name))
                .then_some(*id)
            }) {
                return Err(DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    format!(
                        "browser profile '{profile_name}' is already active as session {active_session_id}; stop it before starting it again"
                    ),
                ));
            }
        }
        drop(runtimes);

        let restored_profile = if let Some(profile_name) = profile_name.filter(|_| persistent) {
            self.load_persistent_profile(project_id, profile_name)
                .await?
        } else {
            None
        };
        if url == "about:blank" {
            if let Some(last_url) = restored_profile
                .as_ref()
                .and_then(|profile| profile.last_url.as_ref())
            {
                url = last_url.clone();
            }
        }

        if !status.chromium_available {
            return Err(DomainError::new(
                ErrorCode::ChromiumNotInstalled,
                "Chromium not installed; run HuntProxy browser install",
            ));
        }

        // Persistent Chromium owns its jar. Only an explicitly selected seed
        // may import or clear cookies; project jars remain for ephemeral work.
        let clear_cookies = cookie_override
            .as_ref()
            .map(|cookies| cookies.clear_cookies.clone())
            .unwrap_or_default();
        let cookie_seed = cookie_override
            .as_ref()
            .and_then(|cookies| cookies.seed.clone());
        let storage_seed = cookie_override
            .as_ref()
            .map(CookieLaunchOverride::storage_params)
            .unwrap_or(Value::Null);
        let (seeded_storage, cleared_origins) = cookie_override
            .as_ref()
            .map(|cookies| (cookies.storage.clone(), cookies.clear_origins.clone()))
            .unwrap_or_default();
        let cookies = self
            .cookies_for_launch(project_id, persistent, cookie_override)
            .await?;
        let profile_dir = match profile_name.filter(|_| persistent) {
            Some(profile_name) => Some(self.chromium_profile_dir(project_id, profile_name)?),
            None => None,
        };
        let prefer_profile_state = profile_dir
            .as_deref()
            .is_some_and(chromium_profile_has_state);
        let mut session = self
            .db
            .create_browser_session(project_id, profile.clone())
            .await?;
        let capture = self
            .db
            .create_capture_session(CreateCaptureSession {
                project_id,
                browser_session_id: Some(session.id),
                browser_action_id: None,
                is_browser_bound: true,
                ttl: None,
            })
            .await?;
        let token = capture.token_once.clone().ok_or_else(|| {
            DomainError::new(
                ErrorCode::Internal,
                "browser capture credential missing one-time token",
            )
        })?;
        let start_params = json!({
            "session_id": session.id.get(),
            "engine": "chromium",
            "url": url,
            "proxy": {
                "server": self.proxy_server.clone(),
                "username": PROXY_BASIC_USER,
                "password": token,
            },
            "ca_cert_path": self.ca_cert_path.as_ref().map(|path| path.display().to_string()),
            "cookies": cookies,
            "clear_cookies": clear_cookies,
            "storage_seed": storage_seed,
            "restore_state": restored_profile,
            "persistent": persistent,
            "profile": profile_name,
            // An initialized Chromium profile is authoritative because it may
            // contain manual login and service-worker state. An empty profile
            // imports the portable checkpoint left by an older browser build.
            "prefer_profile_state": prefer_profile_state,
            "profile_dir": if persistent {
                profile_dir.as_ref().map(|path| path.display().to_string())
            } else {
                None
            },
        });
        let checkpoint_status = if persistent && restored_profile.is_some() {
            "restored"
        } else {
            "ok"
        };
        // Track ownership before launch so a failed startup whose cleanup
        // cannot stop Chromium remains visible and keeps its profile lease.
        self.runtime_sessions.lock().await.insert(
            session.id.get(),
            RuntimeSession {
                project_id,
                capture_session_id: capture.id,
                persistent,
                profile: profile.clone(),
                cdp: None,
                javascript_cursor: 0,
            },
        );
        let result = match self
            .call_worker(project_id, "session.start", start_params)
            .await
        {
            Ok(result) => result,
            Err(error) => {
                self.cleanup_failed_start(project_id, &mut session, capture.id)
                    .await?;
                return Err(error);
            }
        };
        // Interruption removes ownership before writing Interrupted. Keep the
        // runtime lock through finalization so Ready cannot overwrite it.
        let runtimes = self.runtime_sessions.lock().await;
        if !runtimes.get(&session.id.get()).is_some_and(|runtime| {
            runtime.project_id == project_id && runtime.capture_session_id == capture.id
        }) {
            drop(runtimes);
            return Err(self.startup_interrupted(project_id).await);
        }
        let prepared = async {
            verify_worker_identity(&result, session.id, profile_name, profile_dir.as_deref())?;
            let checkpoint = result.get("checkpoint").ok_or_else(|| {
                DomainError::new(ErrorCode::ProtocolError, "worker omitted checkpoint")
            })?;
            let saved = self
                .save_checkpoint(
                    project_id,
                    session.id,
                    checkpoint,
                    checkpoint_status,
                    profile_name,
                )
                .await?;
            let checkpoint_origin = saved.local_storage.keys().next().cloned();
            session.engine = BrowserEngine::Chromium;
            session.current_url = saved.url;
            session.current_title = saved.title;
            session.state = BrowserSessionState::Ready;
            session.active_profile = profile.clone();
            session.checkpoint_status = Some(checkpoint_status.into());
            session.checkpoint_hash = Some(saved.hash);
            self.db.update_browser_session(&session).await?;
            if let Some(profile_name) = profile_name {
                self.record_cookie_seed(
                    project_id,
                    profile_name,
                    cookie_seed,
                    &seeded_storage,
                    &cleared_origins,
                    checkpoint_origin.as_deref(),
                )
                .await?;
            }
            Ok::<(), DomainError>(())
        }
        .await;
        drop(runtimes);
        if let Err(error) = prepared {
            self.cleanup_failed_start(project_id, &mut session, capture.id)
                .await?;
            return Err(error);
        }
        if let Err(error) = self
            .persist_javascript_files(
                project_id,
                session.id,
                session.current_url.as_deref(),
                false,
            )
            .await
        {
            tracing::warn!(%error, session_id = session.id.get(), "could not persist JavaScript provenance");
        }
        let still_active = self
            .runtime_sessions
            .lock()
            .await
            .get(&session.id.get())
            .is_some_and(|runtime| runtime.project_id == project_id);
        if !still_active {
            return Err(self.startup_interrupted(project_id).await);
        }
        // However long the launch took, a new browser gets a full idle timeout.
        self.touch_project(project_id);
        schedule_page_title_association(self.db.clone(), &session);
        Ok(session)
    }

    pub async fn csrf_probe(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        target_url: &str,
        method: &str,
        params: &[(String, String)],
        timeout_ms: u64,
    ) -> DomainResult<BrowserCsrfProbeResult> {
        let parsed = url::Url::parse(target_url)
            .map_err(|error| DomainError::invalid(format!("invalid CSRF target URL: {error}")))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(DomainError::invalid(
                "CSRF target URL must use HTTP or HTTPS",
            ));
        }
        if !matches!(method, "GET" | "POST") {
            return Err(DomainError::invalid(
                "CSRF browser probe method must be GET or POST",
            ));
        }
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        let active = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .is_some_and(|runtime| runtime.project_id == project_id && !runtime.persistent);
        if !active {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "isolated browser session is not active",
            ));
        }
        let result = self
            .call_worker(project_id, "session.csrf_probe",
                json!({
                    "session_id": session_id.get(),
                    "target_url": target_url,
                    "method": method,
                    "params": params.iter().map(|(name, value)| json!({"name":name,"value":value})).collect::<Vec<_>>(),
                    "timeout_ms": timeout_ms.clamp(1_000, 30_000),
                }),
            )
            .await?;
        serde_json::from_value(result)
            .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))
    }

    async fn cleanup_failed_start(
        &self,
        project_id: ProjectId,
        session: &mut BrowserSession,
        capture_session_id: CaptureSessionId,
    ) -> DomainResult<()> {
        let cleanup_error = if self.worker_is_running(project_id).await {
            self.call_worker(
                project_id,
                "session.stop",
                json!({ "session_id": session.id.get() }),
            )
            .await
            .err()
        } else {
            None
        };
        let worker_running = cleanup_error.is_some() && self.worker_is_running(project_id).await;
        let mut runtimes = self.runtime_sessions.lock().await;
        if !runtimes.get(&session.id.get()).is_some_and(|runtime| {
            runtime.project_id == project_id && runtime.capture_session_id == capture_session_id
        }) {
            // A worker interruption already removed the session, revoked its
            // capture, and recorded Interrupted.
            return Ok(());
        }
        session.state = BrowserSessionState::Failed;
        if let Some(error) = cleanup_error {
            if worker_running {
                session.checkpoint_status = Some("start_cleanup_failed".into());
                let _ = self.db.update_browser_session(session).await;
                return Err(DomainError::new(
                    error.code(),
                    format!("browser startup failed and session {} could not stop: {error}; retry stopping this session before reusing its profile", session.id.get()),
                ));
            }
        }
        runtimes.remove(&session.id.get());
        drop(runtimes);
        self.reap_worker(project_id).await;
        session.checkpoint_status = Some("start_failed".into());
        let _ = self.db.update_browser_session(session).await;
        self.checkpoint_versions
            .lock()
            .await
            .remove(&session.id.get());
        let _ = self
            .db
            .revoke_capture_session(project_id, capture_session_id)
            .await;
        Ok(())
    }

    async fn cookies_for_launch(
        &self,
        project_id: ProjectId,
        persistent: bool,
        cookie_override: Option<CookieLaunchOverride>,
    ) -> DomainResult<Vec<Value>> {
        match cookie_override {
            Some(cookies) => Ok(cookies.cookies),
            None if persistent => Ok(Vec::new()),
            None => browser_cookies(&self.db.list_stored_cookie_profiles(project_id).await?),
        }
    }

    /// Apply managed project cookies only to ephemeral sessions. Persistent
    /// identities import cookies solely through an explicit cookie_profile.
    pub async fn apply_cookie_profile(
        &self,
        project_id: ProjectId,
        previous: Option<&StoredCookieProfile>,
        profile: &StoredCookieProfile,
    ) -> DomainResult<usize> {
        let cookies = browser_cookies(std::slice::from_ref(profile))?;
        let previous_names = previous
            .filter(|profile| profile.managed_cookies.is_none())
            .map(StoredCookieProfile::pairs)
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(|pair| pair.name)
            .collect::<Vec<_>>();
        let previous_cookies = previous
            .map(profile_cookie_identities)
            .transpose()?
            .unwrap_or_default();
        let session_ids = self.managed_cookie_session_ids(project_id).await;
        for session_id in &session_ids {
            let operation_lock = self.session_operation_lock(*session_id).await;
            let _operation_guard = operation_lock.lock().await;
            let result = self
                .call_worker(
                    project_id,
                    "session.set_cookies",
                    json!({
                        "session_id": session_id.get(),
                        "cookies": cookies.clone(),
                        "target_url": profile.target_url,
                        "clear_names": previous_names,
                        "clear_cookies": previous_cookies,
                    }),
                )
                .await?;
            self.save_cookie_checkpoint(project_id, *session_id, &result)
                .await?;
        }
        Ok(session_ids.len())
    }

    pub async fn clear_cookie_profile(
        &self,
        project_id: ProjectId,
        profile: &StoredCookieProfile,
    ) -> DomainResult<usize> {
        let session_ids = self.managed_cookie_session_ids(project_id).await;
        let pairs = if profile.managed_cookies.is_none() {
            profile.pairs()?
        } else {
            Vec::new()
        };
        let cookies = profile_cookie_identities(profile)?;
        for session_id in &session_ids {
            let operation_lock = self.session_operation_lock(*session_id).await;
            let _operation_guard = operation_lock.lock().await;
            let result = self
                .call_worker(
                    project_id,
                    "session.clear_cookies",
                    json!({
                        "session_id": session_id.get(),
                        "target_url": profile.target_url,
                        "names": pairs.iter().map(|pair| &pair.name).collect::<Vec<_>>(),
                        "cookies": cookies,
                    }),
                )
                .await?;
            self.save_cookie_checkpoint(project_id, *session_id, &result)
                .await?;
        }
        Ok(session_ids.len())
    }

    async fn managed_cookie_session_ids(&self, project_id: ProjectId) -> Vec<BrowserSessionId> {
        self.runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, runtime)| {
                (runtime.project_id == project_id && !runtime.persistent)
                    .then_some(BrowserSessionId(*id))
            })
            .collect()
    }

    pub async fn active_sessions(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Vec<BrowserSession>> {
        self.db.get_project(project_id).await?;
        let ids = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, runtime)| {
                (runtime.project_id == project_id && runtime.persistent)
                    .then_some(BrowserSessionId(*id))
            })
            .collect::<Vec<_>>();
        let mut sessions = Vec::with_capacity(ids.len());
        for session_id in ids {
            sessions.push(self.session_status(project_id, session_id).await?);
        }
        sessions.sort_by_key(|session| session.id.get());
        Ok(sessions)
    }

    pub async fn active_status(&self, project_id: ProjectId) -> DomainResult<BrowserStatus> {
        // Live identity checks may wait for browser actions. Do not hold the
        // global lifecycle or runtime map lock across them. The final sample
        // rejects persistent identities changed by an interleaved transition.
        let project = self.db.get_project(project_id).await?;
        let sessions = self.active_sessions(project_id).await?;
        let runtimes = self.runtime_sessions.lock().await;
        let resources = browser_resources(
            project_id,
            project.limits.max_concurrent_browsers,
            &sessions,
            &runtimes,
            free_cdp_port(
                &self
                    .cdp_reservations
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()),
            )
            .is_none(),
        )?;
        let sandbox = self
            .sandbox
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        Ok(BrowserStatus {
            sessions,
            resources,
            sandbox_state: sandbox.get(&project_id.get()).and_then(|v| v.0.clone()),
            sandbox_reason: sandbox.get(&project_id.get()).and_then(|v| v.1.clone()),
        })
    }

    pub async fn session_status(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<BrowserSession> {
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        self.verified_session_status(project_id, session_id).await
    }

    async fn verified_session_status(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<BrowserSession> {
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        let runtime = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .cloned();
        if let Some(runtime) = runtime {
            if runtime.project_id != project_id || runtime.profile != session.profile {
                return Err(DomainError::new(
                    ErrorCode::ProtocolError,
                    "requested browser profile does not match the active runtime",
                ));
            }
            let directory = runtime
                .profile
                .as_deref()
                .map(|name| self.chromium_profile_path(project_id, name));
            let directory = directory
                .map(std::fs::canonicalize)
                .transpose()
                .map_err(|error| {
                    DomainError::new(
                        ErrorCode::Unavailable,
                        format!("cannot verify browser profile directory: {error}"),
                    )
                })?;
            let result = self
                .call_worker(
                    project_id,
                    "session.status",
                    json!({"session_id":session_id.get()}),
                )
                .await?;
            verify_worker_identity(
                &result,
                session_id,
                runtime.profile.as_deref(),
                directory.as_deref(),
            )?;
            session.active_profile = runtime.profile;
        } else if matches!(
            session.state,
            BrowserSessionState::Ready | BrowserSessionState::Busy | BrowserSessionState::Starting
        ) {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "requested browser profile is not active",
            ));
        }
        Ok(session)
    }

    async fn record_cookie_seed(
        &self,
        project_id: ProjectId,
        profile: &str,
        seed: Option<CookieSeed>,
        storage: &[StorageOrigin],
        cleared_origins: &[String],
        checkpoint_origin: Option<&str>,
    ) -> DomainResult<()> {
        if let Some(seed) = seed {
            self.update_persistent_profile(project_id, profile, |state| {
                state.cookie_seed = Some(seed);
                apply_storage_seed(state, storage, cleared_origins, checkpoint_origin);
            })
            .await?;
        }
        Ok(())
    }

    pub async fn cdp_status(&self, project_id: ProjectId) -> DomainResult<BrowserCdpStatus> {
        self.db.get_project(project_id).await?;
        let ids = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, runtime)| {
                (runtime.project_id == project_id && runtime.cdp.is_some())
                    .then_some(BrowserSessionId(*id))
            })
            .collect::<Vec<_>>();
        for id in ids {
            let operation = self.session_operation_lock(id).await;
            let _guard = operation.lock().await;
            self.reconcile_cdp_state(project_id, id).await;
        }
        let runtimes = self.runtime_sessions.lock().await;
        let mut active = runtimes
            .iter()
            .filter_map(|(id, runtime)| {
                (runtime.project_id == project_id)
                    .then(|| runtime.cdp.clone().map(|cdp| (*id, cdp)))
                    .flatten()
            })
            .collect::<Vec<_>>();
        active.sort_by_key(|(id, cdp)| (cdp.port, *id));
        let mut status = cdp_status_view(project_id, active.first().cloned());
        status.active_sessions = active
            .into_iter()
            .map(|(id, cdp)| BrowserCdpActiveSession {
                session_id: BrowserSessionId(id),
                port: cdp.port,
                endpoint: cdp.endpoint,
            })
            .collect();
        Ok(status)
    }

    pub async fn cdp_status_for_session(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<BrowserCdpStatus> {
        self.db.get_browser_session(project_id, session_id).await?;
        let operation = self.session_operation_lock(session_id).await;
        let _guard = operation.lock().await;
        self.reconcile_cdp_state(project_id, session_id).await;
        let cdp = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .and_then(|runtime| runtime.cdp.clone());
        let mut status = cdp_status_view(project_id, cdp.map(|cdp| (session_id.get(), cdp)));
        status.session_id = Some(session_id);
        Ok(status)
    }

    pub async fn enable_cdp(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<BrowserCdpStatus> {
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        let runtime = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .cloned();
        let Some(runtime) = runtime else {
            return Err(self.inactive_session_error(project_id, session_id).await);
        };
        if runtime.project_id != project_id {
            return Err(crate::storage::browser_session_not_found(
                project_id, session_id,
            ));
        }
        if !runtime.persistent {
            return Err(DomainError::invalid(
                "CDP handoff requires a persistent project browser",
            ));
        }
        if let Some(cdp) = runtime.cdp {
            return Ok(cdp_status_view(project_id, Some((session_id.get(), cdp))));
        }
        let port = {
            let mut reservations = self
                .cdp_reservations
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let port = free_cdp_port(&reservations).ok_or_else(|| {
                DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    "No CDP port is free in the loopback range 9222-9321",
                )
            })?;
            reservations.insert(session_id.get(), port);
            port
        };
        let mut reservation = CdpReservation {
            reservations: &self.cdp_reservations,
            session_id: session_id.get(),
            committed: false,
        };
        let result = match self
            .call_worker(
                project_id,
                "session.cdp_enable",
                json!({
                    "session_id": session_id.get(),
                    "cdp_port": port,
                }),
            )
            .await
        {
            Ok(result) => result,
            Err(error) => {
                self.rollback_cdp_enable(project_id, session_id).await;
                return Err(error);
            }
        };
        let prepared = async {
            let cdp = parse_cdp_info(result.get("cdp"), port)?;
            self.save_cookie_checkpoint(project_id, session_id, &result)
                .await?;
            Ok::<_, DomainError>(cdp)
        }
        .await;
        let cdp = match prepared {
            Ok(cdp) => cdp,
            Err(error) => {
                self.rollback_cdp_enable(project_id, session_id).await;
                return Err(error);
            }
        };
        let recorded = {
            let mut runtimes = self.runtime_sessions.lock().await;
            if let Some(runtime) = runtimes.get_mut(&session_id.get()) {
                runtime.cdp = Some(cdp.clone());
                reservation.committed = true;
                true
            } else {
                false
            }
        };
        if !recorded {
            self.rollback_cdp_enable(project_id, session_id).await;
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "browser session stopped during CDP handoff",
            ));
        }
        self.monitor_cdp_port(session_id, port, operation_lock.clone());
        Ok(cdp_status_view(project_id, Some((session_id.get(), cdp))))
    }

    fn monitor_cdp_port(&self, session_id: BrowserSessionId, port: u16, operation: Arc<Mutex<()>>) {
        let runtimes = Arc::downgrade(&self.runtime_sessions);
        let reservations = Arc::downgrade(&self.cdp_reservations);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let (Some(runtimes), Some(reservations)) =
                    (runtimes.upgrade(), reservations.upgrade())
                else {
                    break;
                };
                let Ok(_operation) = operation.try_lock() else {
                    continue;
                };
                let mut active = runtimes.lock().await;
                let Some(runtime) = active.get_mut(&session_id.get()) else {
                    break;
                };
                if runtime.cdp.as_ref().map(|cdp| cdp.port) != Some(port) {
                    break;
                }
                // A live Chromium handoff holds the listening socket. Keeping the
                // probe bound until bookkeeping is updated prevents port reuse racing cleanup.
                if let Ok(_probe) =
                    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
                {
                    runtime.cdp = None;
                    let mut ports = reservations.lock().unwrap_or_else(|e| e.into_inner());
                    if ports.get(&session_id.get()) == Some(&port) {
                        ports.remove(&session_id.get());
                    }
                    break;
                }
            }
        });
    }

    pub async fn disable_cdp(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<BrowserCdpStatus> {
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        let runtime = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .cloned()
            .ok_or_else(|| {
                DomainError::new(ErrorCode::Unavailable, "browser session is not active")
            })?;
        if runtime.project_id != project_id {
            return Err(crate::storage::browser_session_not_found(
                project_id, session_id,
            ));
        }
        if runtime.cdp.is_none() {
            let mut status = cdp_status_view(project_id, None);
            status.session_id = Some(session_id);
            return Ok(status);
        }
        let result = match self
            .call_worker(
                project_id,
                "session.cdp_disable",
                json!({ "session_id": session_id.get() }),
            )
            .await
        {
            Ok(result) => result,
            Err(error) => {
                self.reconcile_cdp_state(project_id, session_id).await;
                return Err(error);
            }
        };
        if let Some(runtime) = self
            .runtime_sessions
            .lock()
            .await
            .get_mut(&session_id.get())
        {
            runtime.cdp = None;
        }
        self.release_cdp_reservation(session_id.get());
        self.save_cookie_checkpoint(project_id, session_id, &result)
            .await?;
        let mut status = cdp_status_view(project_id, None);
        status.session_id = Some(session_id);
        Ok(status)
    }

    async fn reconcile_cdp_state(&self, project_id: ProjectId, session_id: BrowserSessionId) {
        let entry = self.workers.lock().await.get(&project_id.get()).cloned();
        let Some(entry) = entry else {
            return;
        };
        let Some(handle) = self.session_worker_handle(&entry, session_id).await else {
            return;
        };
        match handle
            .call("session.cdp_state", json!({"session_id": session_id.get()}))
            .await
        {
            Ok(value) if value.get("cdp").is_some_and(Value::is_null) => {
                if let Some(runtime) = self
                    .runtime_sessions
                    .lock()
                    .await
                    .get_mut(&session_id.get())
                {
                    runtime.cdp = None;
                }
                self.release_cdp_reservation(session_id.get());
            }
            // A worker that broke has lost every session; a query that ran
            // out of time changes nothing.
            Err(WorkerCallFailure::Transport(_)) => {
                self.fail_worker(project_id, &entry, &handle).await;
            }
            _ => {}
        }
    }

    /// A handle to the project worker that runs `session_id`, if it still does.
    async fn session_worker_handle(
        &self,
        entry: &Mutex<Option<WorkerProcess>>,
        session_id: BrowserSessionId,
    ) -> Option<WorkerHandle> {
        let worker = entry.lock().await;
        if !self
            .runtime_sessions
            .lock()
            .await
            .contains_key(&session_id.get())
        {
            return None;
        }
        worker.as_ref().map(WorkerProcess::handle)
    }

    async fn rollback_cdp_enable(&self, project_id: ProjectId, session_id: BrowserSessionId) {
        let entry = self.workers.lock().await.get(&project_id.get()).cloned();
        let Some(entry) = entry else {
            return;
        };
        let Some(handle) = self.session_worker_handle(&entry, session_id).await else {
            return;
        };
        if handle
            .call(
                "session.cdp_disable",
                json!({"session_id": session_id.get()}),
            )
            .await
            .is_err()
        {
            // An unsuccessful rollback leaves ownership uncertain: terminate
            // this worker before releasing the reservation.
            self.fail_worker(project_id, &entry, &handle).await;
        }
    }

    fn release_cdp_reservation(&self, session_id: i64) {
        self.cdp_reservations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session_id);
    }

    async fn session_operation_lock(&self, session_id: BrowserSessionId) -> Arc<Mutex<()>> {
        self.session_ops
            .lock()
            .await
            .entry(session_id.get())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Fetch a crawler candidate through the browser's cookie-sharing request
    /// context. Returns false when the session is inactive or has no cookies
    /// for this URL, allowing the crawler to use its regular HTTP transport.
    pub async fn authenticated_background_fetch(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        url: &str,
    ) -> DomainResult<bool> {
        let parsed = url::Url::parse(url)
            .map_err(|error| DomainError::invalid(format!("invalid crawler URL: {error}")))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(DomainError::invalid("crawler URL must use HTTP or HTTPS"));
        }
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        let active = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .is_some_and(|runtime| runtime.project_id == project_id && runtime.cdp.is_none());
        if !active {
            return Ok(false);
        }
        let result = self
            .call_worker(
                project_id,
                "session.authenticated_fetch",
                json!({ "session_id": session_id.get(), "url": url }),
            )
            .await?;
        Ok(result.get("used").and_then(Value::as_bool).unwrap_or(false))
    }

    async fn save_cookie_checkpoint(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        result: &Value,
    ) -> DomainResult<Checkpoint> {
        let checkpoint = result.get("checkpoint").ok_or_else(|| {
            DomainError::new(ErrorCode::ProtocolError, "worker omitted checkpoint")
        })?;
        let runtimes = self.runtime_sessions.lock().await;
        let Some(runtime) = runtimes
            .get(&session_id.get())
            .filter(|runtime| runtime.project_id == project_id)
        else {
            drop(runtimes);
            self.wait_for_worker_interruption(project_id).await;
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "browser session is not active",
            ));
        };
        let profile = runtime.profile.as_deref().filter(|_| runtime.persistent);
        let saved = self
            .save_checkpoint(project_id, session_id, checkpoint, "ok", profile)
            .await?;
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        session.current_url = saved.url.clone();
        session.current_title = saved.title.clone();
        session.checkpoint_status = Some("ok".into());
        session.checkpoint_hash = Some(saved.hash.clone());
        self.db.update_browser_session(&session).await?;
        Ok(saved)
    }

    pub async fn action(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        action: BrowserAction,
    ) -> DomainResult<ActionResult> {
        self.action_with_ignored_options(project_id, session_id, action, Vec::new())
            .await
    }

    /// [`Self::action`] for an action read by [`BrowserAction::from_agent_input`]:
    /// the result lists the options it ignored.
    pub async fn action_with_ignored_options(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        action: BrowserAction,
        ignored_options: Vec<String>,
    ) -> DomainResult<ActionResult> {
        validate_browser_action(&action)?;
        let mut action = action;
        if let BrowserAction::Snapshot { max_bytes, .. } = &mut action {
            *max_bytes = (*max_bytes).min(MAX_SNAPSHOT_BYTES);
        }
        if let Some(options) = action.options_mut() {
            options.max_bytes = options.max_bytes.map(|bytes| bytes.min(MAX_SNAPSHOT_BYTES));
        }
        if matches!(&action, BrowserAction::Close) {
            self.stop(project_id, session_id).await?;
            return Ok(ActionResult {
                ok: true,
                untrusted: false,
                message: "session closed".into(),
                data: None,
                browser: None,
                ignored_options,
            });
        }
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        if matches!(
            session.state,
            BrowserSessionState::Interrupted
                | BrowserSessionState::Stopped
                | BrowserSessionState::Failed
        ) {
            return Err(self.idle_stopped_error(&session).unwrap_or_else(|| {
                DomainError::new(ErrorCode::Unavailable, "browser session is not active")
            }));
        }
        let runtimes = self.runtime_sessions.lock().await;
        let Some(runtime) = runtimes
            .get(&session_id.get())
            .filter(|runtime| runtime.project_id == project_id)
            .cloned()
        else {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "browser runtime is not attached; start a new browser session",
            ));
        };
        if runtime.cdp.is_some() {
            return Err(DomainError::new(
                ErrorCode::Conflict,
                "browser control is handed off through CDP; disable the CDP handoff before running agent browser actions",
            ));
        }
        session.state = BrowserSessionState::Busy;
        self.db.update_browser_session(&session).await?;
        drop(runtimes);
        let event_wait_ms = match &action {
            BrowserAction::Events { wait_ms, .. } => *wait_ms,
            _ => 0,
        };
        let worker_action = serde_json::to_value(&action)
            .map_err(|error| DomainError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let worker_result = async {
            if event_wait_ms > 0 {
                self.wait_for_browser_events(project_id, session_id, &worker_action, event_wait_ms)
                    .await?;
            }
            self.call_worker(
                project_id,
                "session.action",
                json!({
                    "session_id": session_id.get(),
                    "action": worker_action,
                }),
            )
            .await
        }
        .await;
        let result = match worker_result {
            Ok(result) => result,
            Err(error) => {
                let runtimes = self.runtime_sessions.lock().await;
                if runtimes
                    .get(&session_id.get())
                    .is_some_and(|runtime| runtime.project_id == project_id)
                {
                    session.state = BrowserSessionState::Ready;
                    let _ = self.db.update_browser_session(&session).await;
                } else {
                    drop(runtimes);
                    self.wait_for_worker_interruption(project_id).await;
                }
                return Err(error);
            }
        };
        let runtimes = self.runtime_sessions.lock().await;
        if !runtimes
            .get(&session_id.get())
            .is_some_and(|runtime| runtime.project_id == project_id)
        {
            drop(runtimes);
            self.wait_for_worker_interruption(project_id).await;
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "browser session is not active",
            ));
        }
        let checkpoint = result.get("checkpoint").ok_or_else(|| {
            DomainError::new(ErrorCode::ProtocolError, "worker omitted checkpoint")
        })?;
        let checkpoint_status = "ok";
        let saved = self
            .save_checkpoint(
                project_id,
                session_id,
                checkpoint,
                checkpoint_status,
                runtime.profile.as_deref().filter(|_| runtime.persistent),
            )
            .await?;
        session.current_url = saved.url;
        session.current_title = saved.title;
        session.state = BrowserSessionState::Ready;
        session.checkpoint_status = Some(checkpoint_status.into());
        session.checkpoint_hash = Some(saved.hash);
        self.db.update_browser_session(&session).await?;
        drop(runtimes);
        if let Err(error) = self
            .persist_javascript_files(
                project_id,
                session_id,
                session.current_url.as_deref(),
                false,
            )
            .await
        {
            tracing::warn!(%error, session_id = session_id.get(), "could not persist JavaScript provenance");
        }
        let still_active = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .is_some_and(|runtime| runtime.project_id == project_id);
        if !still_active {
            self.wait_for_worker_interruption(project_id).await;
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "browser session is not active",
            ));
        }
        schedule_page_title_association(self.db.clone(), &session);

        let mut action_result = ActionResult {
            ok: result.get("ok").and_then(Value::as_bool).unwrap_or(true),
            untrusted: result
                .get("untrusted")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            message: result
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("browser action completed")
                .to_string(),
            data: result.get("data").cloned().filter(|value| !value.is_null()),
            browser: result
                .get("browser")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    DomainError::new(
                        ErrorCode::ProtocolError,
                        format!("invalid browser action context: {error}"),
                    )
                })?,
            ignored_options,
        };
        fit_action_result(&action, &mut action_result)?;
        Ok(action_result)
    }

    /// Returns once the worker holds an event the `events` action would return,
    /// or `wait_ms` has passed. The worker does the waiting, in slices of at
    /// most `EVENT_WAIT_SLICE`, and the session's other requests are served
    /// between slices.
    async fn wait_for_browser_events(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        action: &Value,
        wait_ms: u64,
    ) -> DomainResult<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(wait_ms);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            let slice = remaining.min(EVENT_WAIT_SLICE);
            let result = self
                .call_worker(
                    project_id,
                    "session.events_wait",
                    json!({
                        "session_id": session_id.get(),
                        "action": action,
                        "wait_ms": slice.as_millis().max(1) as u64,
                    }),
                )
                .await?;
            let ready = result
                .get("ready")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    DomainError::new(ErrorCode::ProtocolError, "worker omitted event wait result")
                })?;
            if ready {
                return Ok(());
            }
        }
    }

    pub async fn javascript_files(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<Vec<BrowserJavascriptFile>> {
        let belongs_to_project = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .is_some_and(|runtime| runtime.project_id == project_id);
        if !belongs_to_project {
            return Err(DomainError::not_found(format!("active browser session {} not found in project {}; call browser_start or browser_manage status", session_id.get(), project_id.get())));
        }
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        self.persist_javascript_files(project_id, session_id, None, true)
            .await
    }

    /// Records the session's JavaScript files and returns the ones the worker
    /// reported: only those not recorded before, or every file with `all`.
    async fn persist_javascript_files(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        default_source_page_url: Option<&str>,
        all: bool,
    ) -> DomainResult<Vec<BrowserJavascriptFile>> {
        let mut params = json!({ "session_id": session_id.get() });
        if !all {
            if let Some(runtime) = self
                .runtime_sessions
                .lock()
                .await
                .get(&session_id.get())
                .filter(|runtime| runtime.project_id == project_id)
            {
                params["after"] = json!(runtime.javascript_cursor);
            }
        }
        let result = self
            .call_worker(project_id, "session.javascript_files", params)
            .await?;
        let cursor = result
            .get("cursor")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                DomainError::new(ErrorCode::ProtocolError, "worker omitted JavaScript cursor")
            })?;
        let files: Vec<BrowserJavascriptFile> =
            serde_json::from_value(result.get("files").cloned().unwrap_or_else(|| json!([])))
                .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
        let fallback = default_source_page_url
            .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
            .or_else(|| {
                files
                    .iter()
                    .find_map(|file| file.source_page_url.as_deref())
            });
        if !files.is_empty() {
            // Without a page to attribute them to, the files stay unrecorded
            // and the cursor stays put, so the next call offers them again.
            let Some(fallback) = fallback else {
                return Ok(files);
            };
            self.db
                .record_javascript_files(
                    project_id,
                    fallback,
                    files
                        .iter()
                        .map(|file| crate::storage::JavascriptProvenanceInput {
                            url: file.url.clone(),
                            source_page_url: file.source_page_url.clone(),
                        })
                        .collect(),
                    Some(session_id),
                    "browser",
                )
                .await?;
        }
        if let Some(runtime) = self
            .runtime_sessions
            .lock()
            .await
            .get_mut(&session_id.get())
            .filter(|runtime| runtime.project_id == project_id)
        {
            runtime.javascript_cursor = cursor;
        }
        Ok(files)
    }

    pub async fn stop(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<()> {
        let _shutdown_guard = self.lifecycle.read().await;
        let project_lock = self.project_lifecycle_lock(project_id).await;
        let _lifecycle = project_lock.lock().await;
        self.stop_inner(project_id, session_id).await
    }

    async fn stop_inner(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
    ) -> DomainResult<()> {
        let operation_lock = self.session_operation_lock(session_id).await;
        let _operation_guard = operation_lock.lock().await;
        self.stop_locked(project_id, session_id, "stopped").await
    }

    /// Stops a session whose operation lock the caller holds, recording
    /// `status` as the reason in its checkpoint status.
    async fn stop_locked(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        status: &str,
    ) -> DomainResult<()> {
        let mut session = self.db.get_browser_session(project_id, session_id).await?;
        let runtime = self
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .cloned();
        let mut persistence_error = None;
        if let Some(runtime) = &runtime {
            let result = self
                .call_worker(
                    project_id,
                    "session.stop",
                    json!({ "session_id": session_id.get() }),
                )
                .await;
            if result.is_err() && self.worker_is_running(project_id).await {
                // A live worker reports cleanup failure while retaining the
                // browser. Keep its runtime, profile lease and credentials so
                // callers can retry rather than opening the profile twice.
                return result.map(|_| ());
            }
            if let Ok(result) = result {
                if let Some(checkpoint) = result.get("checkpoint") {
                    match self
                        .save_checkpoint(
                            project_id,
                            session_id,
                            checkpoint,
                            status,
                            runtime.profile.as_deref().filter(|_| runtime.persistent),
                        )
                        .await
                    {
                        // The row is written once more below; keep what was saved.
                        Ok(saved) => {
                            session.current_url = saved.url;
                            session.current_title = saved.title;
                            session.checkpoint_hash = Some(saved.hash);
                        }
                        Err(error) => persistence_error = Some(error),
                    }
                }
            }
            session.checkpoint_status = Some(status.into());
        }
        self.runtime_sessions.lock().await.remove(&session_id.get());
        self.release_cdp_reservation(session_id.get());
        self.reap_worker(project_id).await;
        if let Some(profile) = runtime
            .as_ref()
            .filter(|runtime| runtime.persistent)
            .and_then(|runtime| runtime.profile.as_ref())
        {
            self.profile_leases
                .lock()
                .await
                .remove(&(project_id.get(), profile.clone()));
        }
        session.state = BrowserSessionState::Stopped;
        self.db.update_browser_session(&session).await?;
        self.checkpoint_versions
            .lock()
            .await
            .remove(&session_id.get());
        if let Some(runtime) = runtime {
            let _ = self
                .db
                .revoke_capture_session(project_id, runtime.capture_session_id)
                .await;
        }
        self.session_ops.lock().await.remove(&session_id.get());
        match persistence_error {
            Some(error) => Err(DomainError::new(
                ErrorCode::StorageError,
                format!("browser stopped but final state save failed: {error}"),
            )),
            None => Ok(()),
        }
    }

    /// Stop every active browser in one project.
    pub async fn stop_project(&self, project_id: ProjectId) -> DomainResult<usize> {
        let _shutdown_guard = self.lifecycle.read().await;
        let project_lock = self.project_lifecycle_lock(project_id).await;
        let _lifecycle = project_lock.lock().await;
        let sessions = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, runtime)| {
                (runtime.project_id == project_id).then_some((project_id, BrowserSessionId(*id)))
            })
            .collect::<Vec<_>>();
        let result = self.stop_sessions_inner(sessions).await;
        self.reap_worker(project_id).await;
        result
    }

    /// Stop all active browsers across projects during daemon shutdown.
    pub async fn stop_all(&self) -> DomainResult<usize> {
        let _lifecycle = self.lifecycle.write().await;
        let sessions = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .map(|(id, runtime)| (runtime.project_id, BrowserSessionId(*id)))
            .collect::<Vec<_>>();
        let result = self.stop_sessions_inner(sessions).await;
        self.terminate_all_workers().await;
        self.interrupt_runtime_sessions(None).await;
        result
    }

    /// Terminate all workers and mark every attached session interrupted.
    /// Used only when graceful shutdown exceeds its bound.
    pub async fn force_stop_all(&self) {
        let _lifecycle = self.lifecycle.write().await;
        self.terminate_all_workers().await;
        self.interrupt_runtime_sessions(None).await;
    }

    async fn stop_sessions_inner(
        &self,
        sessions: Vec<(ProjectId, BrowserSessionId)>,
    ) -> DomainResult<usize> {
        let total = sessions.len();
        let mut first_error = None;
        for (project_id, session_id) in sessions {
            if let Err(error) = self.stop_inner(project_id, session_id).await {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(total),
        }
    }

    async fn project_lifecycle_lock(&self, project_id: ProjectId) -> Arc<Mutex<()>> {
        self.project_lifecycle
            .lock()
            .await
            .entry(project_id.get())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn worker_entry(&self, project_id: ProjectId) -> Arc<Mutex<Option<WorkerProcess>>> {
        self.workers
            .lock()
            .await
            .entry(project_id.get())
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone()
    }

    async fn worker_is_running(&self, project_id: ProjectId) -> bool {
        let entry = self.workers.lock().await.get(&project_id.get()).cloned();
        match entry {
            Some(entry) => entry.lock().await.is_some(),
            None => false,
        }
    }

    async fn startup_interrupted(&self, project_id: ProjectId) -> DomainError {
        self.wait_for_worker_interruption(project_id).await;
        DomainError::new(
            ErrorCode::Unavailable,
            "browser worker failed during startup",
        )
    }

    async fn wait_for_worker_interruption(&self, project_id: ProjectId) {
        // Interruption removes the runtime before recording its final state and
        // revoking its capture. The worker lock is held until both complete.
        let entry = self.worker_entry(project_id).await;
        let _worker = entry.lock().await;
    }

    // Called while lifecycle is locked, so a new start cannot race the last stop.
    async fn reap_worker(&self, project_id: ProjectId) {
        let entry = self.workers.lock().await.get(&project_id.get()).cloned();
        if let Some(entry) = entry {
            // Starts register their session before locking the worker, so checking
            // under this lock means a concurrent start either keeps this worker alive
            // or waits here and then spawns a fresh one.
            let mut worker = entry.lock().await;
            if self
                .runtime_sessions
                .lock()
                .await
                .values()
                .any(|runtime| runtime.project_id == project_id)
            {
                return;
            }
            if let Some(mut worker) = worker.take() {
                worker.terminate().await;
            }
        }
        self.sandbox
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&project_id.get());
    }

    async fn terminate_all_workers(&self) {
        let entries = self
            .workers
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for entry in entries {
            if let Some(mut worker) = entry.lock().await.take() {
                worker.terminate().await;
            }
        }
        self.sandbox
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }

    async fn call_worker(
        &self,
        project_id: ProjectId,
        method: &str,
        params: Value,
    ) -> DomainResult<Value> {
        let node_path = self.node_path.as_deref().ok_or_else(|| {
            DomainError::new(ErrorCode::BrowserDisabled, "Node.js is not available")
        })?;
        let worker_path = self.worker_path.as_deref().ok_or_else(|| {
            DomainError::new(
                ErrorCode::BrowserDisabled,
                "browser worker is not available",
            )
        })?;
        let worker_entry = self.worker_entry(project_id).await;
        let session_id = params
            .get("session_id")
            .and_then(Value::as_i64)
            .filter(|_| method.starts_with("session."));
        // The worker lock is held only to find the worker, so a slow call
        // holds up its own session and no other.
        let handle = {
            let mut worker = worker_entry.lock().await;
            if let Some(session_id) = session_id {
                // A request may have waited here while a previous RPC failed and
                // interrupted this session. Never send it to a replacement worker.
                let active = self
                    .runtime_sessions
                    .lock()
                    .await
                    .get(&session_id)
                    .is_some_and(|runtime| runtime.project_id == project_id);
                if !active {
                    let message = if method == "session.start" {
                        "browser worker failed during startup"
                    } else {
                        "browser session is not active"
                    };
                    return Err(DomainError::new(ErrorCode::Unavailable, message));
                }
            }
            if worker.is_none() {
                self.sandbox
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .remove(&project_id.get());
                *worker = Some(
                    match WorkerProcess::spawn(
                        node_path,
                        worker_path,
                        self.runtime.playwright_core_path.as_deref(),
                        self.runtime.chromium_path.as_deref(),
                    )
                    .await
                    {
                        Ok(worker) => worker,
                        Err(error) => {
                            self.interrupt_runtime_sessions(Some(project_id)).await;
                            return Err(error.into_domain());
                        }
                    },
                );
            }
            worker.as_ref().expect("worker initialized").handle()
        };
        let result = handle.call(method, params).await;
        match result {
            Ok(value) => {
                if method == "session.start" {
                    if let Some(state) = value.get("sandbox_state").and_then(Value::as_str) {
                        let mut sandbox = self
                            .sandbox
                            .lock()
                            .unwrap_or_else(|error| error.into_inner());
                        sandbox.insert(
                            project_id.get(),
                            (
                                Some(state.to_owned()),
                                value
                                    .get("sandbox_reason")
                                    .and_then(Value::as_str)
                                    .map(str::to_owned),
                            ),
                        );
                    }
                }
                Ok(value)
            }
            Err(WorkerCallFailure::Rpc(error)) => Err(error),
            Err(WorkerCallFailure::Timeout(error)) => {
                // A session's call that ran out of time costs that session
                // alone while the worker still answers: the worker closes it.
                // A worker that cannot even do that is stuck and is replaced.
                let aborted = match session_id {
                    Some(session_id) => handle
                        .io
                        .call(
                            handle.rpc_timeout.min(WORKER_ABORT_TIMEOUT),
                            "session.abort",
                            json!({"session_id": session_id}),
                        )
                        .await
                        .is_ok(),
                    None => false,
                };
                match session_id.filter(|_| aborted) {
                    Some(session_id) => {
                        // Held while interrupting, as wait_for_worker_interruption expects.
                        let _worker = worker_entry.lock().await;
                        self.interrupt_runtimes(
                            |id, runtime| id == session_id && runtime.project_id == project_id,
                            "session_timed_out",
                        )
                        .await;
                    }
                    None => self.fail_worker(project_id, &worker_entry, &handle).await,
                }
                Err(error)
            }
            Err(WorkerCallFailure::Transport(error)) => {
                self.fail_worker(project_id, &worker_entry, &handle).await;
                Err(error)
            }
        }
    }

    /// Stops `handle`'s worker if it is still the project's, and interrupts the
    /// project's sessions: a worker that broke has lost them all.
    async fn fail_worker(
        &self,
        project_id: ProjectId,
        entry: &Mutex<Option<WorkerProcess>>,
        handle: &WorkerHandle,
    ) {
        let mut worker = entry.lock().await;
        // Whoever saw it fail first has already replaced or stopped it.
        if !worker.as_ref().is_some_and(|current| handle.is(current)) {
            return;
        }
        if let Some(mut failed) = worker.take() {
            failed.terminate().await;
        }
        self.sandbox
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&project_id.get());
        self.interrupt_runtime_sessions(Some(project_id)).await;
    }

    async fn interrupt_runtime_sessions(&self, project_id: Option<ProjectId>) {
        self.interrupt_runtimes(
            |_, runtime| project_id.is_none_or(|project_id| project_id == runtime.project_id),
            "worker_interrupted",
        )
        .await;
    }

    /// Ends the runtimes `pick` chooses: their sessions are marked interrupted
    /// with `status`, and their captures and reservations are released.
    async fn interrupt_runtimes(&self, pick: impl Fn(i64, &RuntimeSession) -> bool, status: &str) {
        let runtimes = {
            let mut active = self.runtime_sessions.lock().await;
            let ids = active
                .iter()
                .filter_map(|(id, runtime)| pick(*id, runtime).then_some(*id))
                .collect::<Vec<_>>();
            ids.into_iter()
                .filter_map(|id| active.remove(&id).map(|runtime| (id, runtime)))
                .collect::<Vec<_>>()
        };
        for (session_id, runtime) in runtimes {
            self.release_cdp_reservation(session_id);
            self.checkpoint_versions.lock().await.remove(&session_id);
            self.session_ops.lock().await.remove(&session_id);
            if let Some(profile) = runtime.profile.as_ref().filter(|_| runtime.persistent) {
                self.profile_leases
                    .lock()
                    .await
                    .remove(&(runtime.project_id.get(), profile.clone()));
            }
            if let Ok(mut session) = self
                .db
                .get_browser_session(runtime.project_id, BrowserSessionId(session_id))
                .await
            {
                session.state = BrowserSessionState::Interrupted;
                session.checkpoint_status = Some(status.into());
                let _ = self.db.update_browser_session(&session).await;
            }
            let _ = self
                .db
                .revoke_capture_session(runtime.project_id, runtime.capture_session_id)
                .await;
        }
    }

    fn project_profile_dir(&self, project_id: ProjectId) -> PathBuf {
        self.profiles_root
            .join("projects")
            .join(project_id.get().to_string())
    }

    fn profile_directory(&self, project_id: ProjectId, profile: &str) -> PathBuf {
        if profile == DEFAULT_BROWSER_PROFILE {
            self.project_profile_dir(project_id)
        } else {
            self.project_profile_dir(project_id)
                .join("profiles")
                .join(profile)
        }
    }

    fn profile_state_path(&self, project_id: ProjectId, profile: &str) -> PathBuf {
        self.profile_directory(project_id, profile)
            .join("state.json")
    }

    fn chromium_profile_path(&self, project_id: ProjectId, profile: &str) -> PathBuf {
        self.project_profile_dir(project_id)
            .join("chromium")
            .join(profile)
    }

    fn chromium_profile_dir(&self, project_id: ProjectId, profile: &str) -> DomainResult<PathBuf> {
        let directory = self.chromium_profile_path(project_id, profile);
        create_private_dir(&directory)?;
        let directory = std::fs::canonicalize(directory).map_err(|error| {
            DomainError::new(
                ErrorCode::Unavailable,
                format!("cannot verify browser profile directory: {error}"),
            )
        })?;
        // Detect case aliases and symlink aliases even across sequential launches.
        let identity_path = directory.join("huntproxy-identity.json");
        let identity = json!({"project_id":project_id.get(), "profile":profile});
        match std::fs::read(&identity_path) {
            Ok(bytes) if serde_json::from_slice::<Value>(&bytes).ok().as_ref() == Some(&identity) => {}
            Ok(_) => return Err(DomainError::new(ErrorCode::Unavailable,
                "browser profile directory belongs to a different identity; cannot guarantee isolation")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                write_private_file(&identity_path, &serde_json::to_vec(&identity)
                    .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?)?;
            }
            Err(error) => return Err(DomainError::new(ErrorCode::Unavailable,
                format!("cannot verify browser profile owner: {error}"))),
        }
        Ok(directory)
    }

    async fn load_persistent_profile(
        &self,
        project_id: ProjectId,
        profile: &str,
    ) -> DomainResult<Option<PersistentBrowserProfile>> {
        validate_browser_profile_name(profile)?;
        let _guard = self.profile_io.lock().await;
        let path = self.profile_state_path(project_id, profile);
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(DomainError::new(
                    ErrorCode::StorageError,
                    format!("read browser profile metadata: {error}"),
                ))
            }
        };
        if metadata.len() > MAX_PERSISTENT_PROFILE_BYTES as u64 {
            return Err(DomainError::new(
                ErrorCode::StorageError,
                "browser profile state exceeds the 25 MiB safety limit; reset the project browser profile",
            ));
        }
        let encoded = std::fs::read(&path).map_err(|error| {
            DomainError::new(
                ErrorCode::StorageError,
                format!("read browser profile state: {error}"),
            )
        })?;
        serde_json::from_slice(&encoded).map(Some).map_err(|_| {
            DomainError::new(
                ErrorCode::StorageError,
                "browser profile state is invalid; reset the project browser profile",
            )
        })
    }

    async fn update_persistent_profile(
        &self,
        project_id: ProjectId,
        profile_name: &str,
        update: impl FnOnce(&mut PersistentBrowserProfile),
    ) -> DomainResult<()> {
        validate_browser_profile_name(profile_name)?;
        let mut persisted = self.profile_io.lock().await;
        // The update may change what the file holds; the next checkpoint reads it.
        persisted.remove(&(project_id.get(), profile_name.to_string()));
        let path = self.profile_state_path(project_id, profile_name);
        let mut profile = match std::fs::read(&path) {
            Ok(encoded) if encoded.len() <= MAX_PERSISTENT_PROFILE_BYTES => {
                serde_json::from_slice(&encoded).map_err(|_| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        "browser profile state is invalid; reset the project browser profile",
                    )
                })?
            }
            Ok(_) => {
                return Err(DomainError::new(
                    ErrorCode::StorageError,
                    "browser profile state exceeds the 25 MiB safety limit; reset the project browser profile",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                PersistentBrowserProfile::default()
            }
            Err(error) => {
                return Err(DomainError::new(
                    ErrorCode::StorageError,
                    format!("read browser profile state: {error}"),
                ))
            }
        };
        update(&mut profile);
        let encoded = serde_json::to_vec(&profile)
            .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
        if encoded.len() > MAX_PERSISTENT_PROFILE_BYTES {
            return Err(DomainError::new(
                ErrorCode::StorageError,
                "browser profile state exceeds the 25 MiB safety limit",
            ));
        }
        let directory = path.parent().ok_or_else(|| {
            DomainError::new(
                ErrorCode::StorageError,
                "browser profile directory unavailable",
            )
        })?;
        create_private_dir(directory)?;
        let temporary = directory.join(format!(".state-{}.tmp", std::process::id()));
        write_private_file(&temporary, &encoded)?;
        std::fs::rename(&temporary, &path).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            DomainError::new(
                ErrorCode::StorageError,
                format!("commit browser profile state: {error}"),
            )
        })
    }

    async fn persist_checkpoint(
        &self,
        project_id: ProjectId,
        profile_name: &str,
        checkpoint: &Checkpoint,
    ) -> DomainResult<()> {
        validate_browser_profile_name(profile_name)?;
        let mut persisted = self.profile_io.lock().await;
        let key = (project_id.get(), profile_name.to_string());
        let path = self.profile_state_path(project_id, profile_name);
        // Most actions leave the checkpoint unchanged: skip reading the file.
        if !checkpoint.hash.is_empty()
            && persisted
                .get(&key)
                .is_some_and(|known| known.holds(&path, &checkpoint.hash))
        {
            return Ok(());
        }
        let mut profile = match std::fs::read(&path) {
            Ok(encoded) if encoded.len() <= MAX_PERSISTENT_PROFILE_BYTES => {
                serde_json::from_slice(&encoded).map_err(|_| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        "browser profile state is invalid; reset the project browser profile",
                    )
                })?
            }
            Ok(_) => {
                return Err(DomainError::new(
                    ErrorCode::StorageError,
                    "browser profile state exceeds the 25 MiB safety limit; reset the project browser profile",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                PersistentBrowserProfile::default()
            }
            Err(error) => {
                return Err(DomainError::new(
                    ErrorCode::StorageError,
                    format!("read browser profile state: {error}"),
                ))
            }
        };
        if !checkpoint.hash.is_empty() && profile.checkpoint_hash == checkpoint.hash {
            match PersistedProfileState::of(&path, &checkpoint.hash) {
                Some(state) => persisted.insert(key, state),
                None => persisted.remove(&key),
            };
            return Ok(());
        }
        merge_persistent_profile(&mut profile, checkpoint);
        let encoded = serde_json::to_vec(&profile)
            .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
        if encoded.len() > MAX_PERSISTENT_PROFILE_BYTES {
            return Err(DomainError::new(
                ErrorCode::StorageError,
                "browser profile state exceeds the 25 MiB safety limit",
            ));
        }
        let directory = path.parent().ok_or_else(|| {
            DomainError::new(
                ErrorCode::StorageError,
                "browser profile directory unavailable",
            )
        })?;
        create_private_dir(directory)?;
        let temporary = directory.join(format!(".state-{}.tmp", std::process::id()));
        write_private_file(&temporary, &encoded)?;
        if let Ok(file) = std::fs::File::open(&temporary) {
            let _ = file.sync_all();
        }
        std::fs::rename(&temporary, &path).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            DomainError::new(
                ErrorCode::StorageError,
                format!("commit browser profile state: {error}"),
            )
        })?;
        match PersistedProfileState::of(&path, &checkpoint.hash) {
            Some(state) => persisted.insert(key, state),
            None => persisted.remove(&key),
        };
        Ok(())
    }

    pub async fn browser_profiles(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Vec<BrowserProfileStatus>> {
        let _shutdown_guard = self.lifecycle.read().await;
        let project_lock = self.project_lifecycle_lock(project_id).await;
        let _lifecycle = project_lock.lock().await;
        self.db.get_project(project_id).await?;
        let mut names = std::collections::BTreeSet::from([DEFAULT_BROWSER_PROFILE.to_string()]);
        for root in [
            self.project_profile_dir(project_id).join("profiles"),
            self.project_profile_dir(project_id).join("chromium"),
        ] {
            let entries = match std::fs::read_dir(&root) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(DomainError::new(
                        ErrorCode::StorageError,
                        format!("list browser profiles: {error}"),
                    ))
                }
            };
            for entry in entries {
                let entry = entry.map_err(|error| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        format!("list browser profiles: {error}"),
                    )
                })?;
                let file_type = entry.file_type().map_err(|error| {
                    DomainError::new(
                        ErrorCode::StorageError,
                        format!("inspect browser profile: {error}"),
                    )
                })?;
                if !file_type.is_dir() {
                    continue;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if validate_browser_profile_name(&name).is_ok() {
                    names.insert(name);
                }
            }
        }
        let active = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(session_id, runtime)| {
                if runtime.project_id == project_id && runtime.persistent {
                    runtime
                        .profile
                        .as_ref()
                        .map(|profile| (profile.clone(), BrowserSessionId(*session_id)))
                } else {
                    None
                }
            })
            .collect::<HashMap<_, _>>();
        names.extend(active.keys().cloned());
        names.remove(DEFAULT_BROWSER_PROFILE);

        Ok(std::iter::once(DEFAULT_BROWSER_PROFILE.to_string())
            .chain(names)
            .map(|name| {
                let session_id = active.get(&name).copied();
                let has_state = self.profile_state_path(project_id, &name).is_file()
                    || chromium_profile_has_state(&self.chromium_profile_path(project_id, &name));
                BrowserProfileStatus {
                    name,
                    active: session_id.is_some(),
                    session_id,
                    has_state,
                }
            })
            .collect())
    }

    pub async fn create_browser_profile(
        &self,
        project_id: ProjectId,
        profile: &str,
    ) -> DomainResult<BrowserProfileStatus> {
        validate_browser_profile_name(profile)?;
        let _shutdown_guard = self.lifecycle.read().await;
        let project_lock = self.project_lifecycle_lock(project_id).await;
        let _lifecycle = project_lock.lock().await;
        self.db.get_project(project_id).await?;
        create_private_dir(&self.profile_directory(project_id, profile))?;
        let session_id =
            self.runtime_sessions
                .lock()
                .await
                .iter()
                .find_map(|(session_id, runtime)| {
                    (runtime.project_id == project_id
                        && runtime.persistent
                        && runtime.profile.as_deref() == Some(profile))
                    .then_some(BrowserSessionId(*session_id))
                });
        Ok(BrowserProfileStatus {
            name: profile.to_string(),
            active: session_id.is_some(),
            session_id,
            has_state: self.profile_state_path(project_id, profile).is_file()
                || chromium_profile_has_state(&self.chromium_profile_path(project_id, profile)),
        })
    }

    pub async fn delete_browser_profile(
        &self,
        project_id: ProjectId,
        profile: &str,
    ) -> DomainResult<bool> {
        validate_browser_profile_name(profile)?;
        if profile == DEFAULT_BROWSER_PROFILE {
            return Err(DomainError::invalid(
                "the default browser profile cannot be deleted; use browser_manage reset_profile",
            ));
        }
        let _shutdown_guard = self.lifecycle.read().await;
        let project_lock = self.project_lifecycle_lock(project_id).await;
        let _lifecycle = project_lock.lock().await;
        self.db.get_project(project_id).await?;
        let lease = (project_id.get(), profile.to_string());
        {
            let mut leases = self.profile_leases.lock().await;
            if !leases.insert(lease.clone()) {
                return Err(DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    format!("browser profile '{profile}' is active; stop it before deleting it"),
                ));
            }
        }
        let result = {
            let mut persisted = self.profile_io.lock().await;
            persisted.remove(&(project_id.get(), profile.to_string()));
            let removed_profile =
                remove_browser_profile_path(&self.profile_directory(project_id, profile));
            let removed_chromium =
                remove_browser_profile_path(&self.chromium_profile_path(project_id, profile));
            match (removed_profile, removed_chromium) {
                (Ok(profile), Ok(chromium)) => Ok(profile || chromium),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        };
        self.profile_leases.lock().await.remove(&lease);
        result
    }

    pub async fn reset_project_profile(&self, project_id: ProjectId) -> DomainResult<bool> {
        self.reset_browser_profile(project_id, DEFAULT_BROWSER_PROFILE)
            .await
    }

    pub async fn reset_browser_profile(
        &self,
        project_id: ProjectId,
        profile: &str,
    ) -> DomainResult<bool> {
        validate_browser_profile_name(profile)?;
        let _shutdown_guard = self.lifecycle.read().await;
        let project_lock = self.project_lifecycle_lock(project_id).await;
        let _lifecycle = project_lock.lock().await;
        self.db.get_project(project_id).await?;
        let active_session =
            self.runtime_sessions
                .lock()
                .await
                .iter()
                .find_map(|(session_id, runtime)| {
                    (runtime.project_id == project_id
                        && runtime.persistent
                        && runtime.profile.as_deref() == Some(profile))
                    .then_some(BrowserSessionId(*session_id))
                });
        if let Some(session_id) = active_session {
            self.stop_inner(project_id, session_id).await?;
        }

        let lease = (project_id.get(), profile.to_string());
        {
            let mut leases = self.profile_leases.lock().await;
            if !leases.insert(lease.clone()) {
                return Err(DomainError::new(
                    ErrorCode::ConcurrencyLimited,
                    format!(
                        "browser profile '{profile}' is starting or active; stop it before resetting it"
                    ),
                ));
            }
        }

        let result = {
            let mut persisted = self.profile_io.lock().await;
            persisted.remove(&(project_id.get(), profile.to_string()));
            let state_target = if profile == DEFAULT_BROWSER_PROFILE {
                self.profile_state_path(project_id, profile)
            } else {
                self.profile_directory(project_id, profile)
            };
            let removed_state = remove_browser_profile_path(&state_target);
            let removed_chromium =
                remove_browser_profile_path(&self.chromium_profile_path(project_id, profile));
            match (removed_state, removed_chromium) {
                (Ok(state), Ok(chromium)) => {
                    if profile != DEFAULT_BROWSER_PROFILE {
                        create_private_dir(&self.profile_directory(project_id, profile))
                            .map(|()| state || chromium)
                    } else {
                        Ok(state || chromium)
                    }
                }
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        };
        self.profile_leases.lock().await.remove(&lease);
        result
    }

    /// Atomically stop all browsers, remove every persistent identity, and
    /// delete the project while new browser starts remain blocked.
    pub async fn delete_project(&self, project_id: ProjectId) -> DomainResult<()> {
        let _shutdown_guard = self.lifecycle.read().await;
        let project_lock = self.project_lifecycle_lock(project_id).await;
        let _lifecycle = project_lock.lock().await;
        self.db.get_project(project_id).await?;
        let sessions = self
            .runtime_sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, runtime)| {
                (runtime.project_id == project_id).then_some((project_id, BrowserSessionId(*id)))
            })
            .collect::<Vec<_>>();
        self.stop_sessions_inner(sessions).await?;
        {
            let mut persisted = self.profile_io.lock().await;
            persisted.retain(|(project, _), _| *project != project_id.get());
            remove_browser_profile_path(&self.project_profile_dir(project_id))?;
        }
        self.profile_leases
            .lock()
            .await
            .retain(|(id, _)| *id != project_id.get());
        self.db.delete_project(project_id).await?;
        self.project_activity
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&project_id.get());
        Ok(())
    }

    async fn save_checkpoint(
        &self,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        value: &Value,
        status: &str,
        profile: Option<&str>,
    ) -> DomainResult<Checkpoint> {
        let mut checkpoint = decode_checkpoint(value)?;
        let mut versions = self.checkpoint_versions.lock().await;
        checkpoint.version = versions
            .get(&session_id.get())
            .map_or(1, |previous| previous.saturating_add(1));
        checkpoint.hash = checkpoint_hash(&checkpoint)?;
        versions.insert(session_id.get(), checkpoint.version);
        drop(versions);
        if let Some(profile) = profile {
            self.persist_checkpoint(project_id, profile, &checkpoint)
                .await?;
        }
        self.db
            .update_browser_checkpoint_metadata(
                project_id,
                session_id,
                checkpoint.url.clone(),
                checkpoint.title.clone(),
                status.to_string(),
                checkpoint.hash.clone(),
                checkpoint.version,
            )
            .await?;
        Ok(checkpoint)
    }
}

/// "30 minutes", or seconds for a timeout shorter than a minute.
fn describe_idle_timeout(timeout: Duration) -> String {
    let (count, unit) = match timeout.as_secs() {
        seconds if seconds >= 60 => (seconds / 60, "minute"),
        seconds => (seconds, "second"),
    };
    let plural = if count == 1 { "" } else { "s" };
    format!("{count} {unit}{plural}")
}

fn schedule_page_title_association(db: Arc<Db>, session: &BrowserSession) {
    let (Some(url), Some(title)) = (session.current_url.clone(), session.current_title.clone())
    else {
        return;
    };
    let project_id = session.project_id;
    let session_id = session.id;
    tokio::spawn(async move {
        // Browser navigation and proxy response persistence finish on separate
        // tasks. Retry briefly so either completion order produces a title.
        for delay in [0, 50, 150, 400, 1_000, 2_500] {
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            match db
                .associate_browser_page_title(project_id, session_id, &url, &title)
                .await
            {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => {
                    tracing::debug!(%error, session_id = session_id.get(), "could not associate browser page title");
                    break;
                }
            }
        }
    });
}

fn decode_checkpoint(value: &Value) -> DomainResult<Checkpoint> {
    let private = value.get("_private").ok_or_else(|| {
        DomainError::new(ErrorCode::ProtocolError, "checkpoint missing private state")
    })?;
    let cookies = private
        .get("cookies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let local_storage: BTreeMap<String, String> = serde_json::from_value(
        private
            .get("local_storage")
            .cloned()
            .unwrap_or_else(|| json!({})),
    )
    .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
    let session_storage: BTreeMap<String, String> = serde_json::from_value(
        private
            .get("session_storage")
            .cloned()
            .unwrap_or_else(|| json!({})),
    )
    .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
    let origin = private
        .get("origin")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut local_by_origin = BTreeMap::new();
    if let Some(origin) = origin {
        local_by_origin.insert(origin, local_storage);
    }
    Ok(Checkpoint {
        url: value.get("url").and_then(Value::as_str).map(str::to_string),
        title: value
            .get("title")
            .and_then(Value::as_str)
            .filter(|title| !title.is_empty())
            .map(str::to_string),
        cookies,
        local_storage: local_by_origin,
        session_storage,
        version: 0,
        hash: String::new(),
    })
}

fn checkpoint_hash(checkpoint: &Checkpoint) -> DomainResult<String> {
    let mut cookies = checkpoint.cookies.clone();
    cookies.sort_by_key(|cookie| serde_json::to_string(cookie).unwrap_or_default());
    let hashable = json!({
        "url": checkpoint.url.clone(),
        "title": checkpoint.title.clone(),
        "cookies": cookies,
        "local_storage": checkpoint.local_storage.clone(),
        "session_storage": checkpoint.session_storage.clone(),
    });
    let encoded = serde_json::to_vec(&hashable)
        .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn default_profiles_root(db: &Db) -> PathBuf {
    db.path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| path.join("browser-profiles"))
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("huntproxy-browser-profiles-{}", std::process::id()))
        })
}

fn validate_browser_profile_name(profile: &str) -> DomainResult<()> {
    if (1..=64).contains(&profile.len())
        && profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(());
    }
    Err(DomainError::invalid(
        "browser profile must be 1-64 ASCII letters, numbers, '_' or '-'",
    ))
}

fn remove_browser_profile_path(path: &Path) -> DomainResult<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(DomainError::new(
                ErrorCode::StorageError,
                format!("inspect browser profile: {error}"),
            ))
        }
    };
    let result = if metadata.file_type().is_symlink() || metadata.is_file() {
        std::fs::remove_file(path)
    } else {
        std::fs::remove_dir_all(path)
    };
    result.map_err(|error| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("remove browser profile: {error}"),
        )
    })?;
    Ok(true)
}

fn verify_worker_identity(
    result: &Value,
    session_id: BrowserSessionId,
    profile: Option<&str>,
    directory: Option<&Path>,
) -> DomainResult<()> {
    let directory = directory.map(|path| path.to_string_lossy());
    if result.get("session_id").and_then(Value::as_i64) != Some(session_id.get())
        || result.get("requested_profile").and_then(Value::as_str) != profile
        || result.get("active_profile").and_then(Value::as_str) != profile
        || result.get("profile_dir").and_then(Value::as_str) != directory.as_deref()
        || result.get("persistent").and_then(Value::as_bool) != Some(profile.is_some())
    {
        return Err(DomainError::new(ErrorCode::ProtocolError,
            "browser worker cannot guarantee the requested profile is active; session identity or profile directory mismatch"));
    }
    Ok(())
}

fn chromium_profile_has_state(profile_dir: &Path) -> bool {
    profile_dir.join("Local State").is_file()
        || profile_dir
            .join("Default")
            .read_dir()
            .is_ok_and(|mut entries| entries.next().is_some())
}

fn merge_persistent_profile(profile: &mut PersistentBrowserProfile, checkpoint: &Checkpoint) {
    profile.version = profile.version.saturating_add(1);
    profile.checkpoint_hash.clone_from(&checkpoint.hash);
    profile.last_url.clone_from(&checkpoint.url);
    profile.cookies.clone_from(&checkpoint.cookies);
    for (origin, values) in &checkpoint.local_storage {
        profile.local_storage.insert(origin.clone(), values.clone());
    }
    if let Some(origin) = checkpoint.local_storage.keys().next() {
        profile
            .session_storage
            .insert(origin.clone(), checkpoint.session_storage.clone());
    }
}

/// Decide whether a named cookie profile needs seeding. An unchanged seed is
/// left alone, so newer browser values survive unless `refresh` is set.
fn plan_cookie_seed(
    name: &str,
    stored: &StoredCookieProfile,
    saved_seed: Option<CookieSeed>,
    refresh: bool,
) -> DomainResult<Option<CookieLaunchOverride>> {
    let mut cookie_override = CookieLaunchOverride::from_profile(stored)?;
    let seed = CookieSeed {
        name: name.to_string(),
        identities: cookie_override.clear_cookies.clone(),
        hash: cookie_seed_hash(&cookie_override.cookies, &cookie_override.storage)?,
        origins: cookie_override
            .storage
            .iter()
            .map(|entry| entry.origin.clone())
            .collect(),
    };
    if !refresh && saved_seed.as_ref() == Some(&seed) {
        return Ok(None);
    }
    if let Some(previous) = saved_seed {
        for identity in previous.identities {
            if !cookie_override.clear_cookies.contains(&identity) {
                cookie_override.clear_cookies.push(identity);
            }
        }
        // Storage the previous seed wrote for an origin this one drops is
        // stale in the same way.
        cookie_override.clear_origins = previous
            .origins
            .into_iter()
            .filter(|origin| !seed.origins.contains(origin))
            .collect();
    }
    cookie_override.seed = Some(seed);
    Ok(Some(cookie_override))
}

/// Persist seeded storage into the profile state. Chromium keeps localStorage
/// natively but drops sessionStorage on exit, so a later launch restores it
/// from here. The origin the worker just checkpointed holds the browser's own
/// current values, so it is left to the checkpoint.
fn apply_storage_seed(
    state: &mut PersistentBrowserProfile,
    storage: &[StorageOrigin],
    cleared_origins: &[String],
    checkpoint_origin: Option<&str>,
) {
    let stale = |origin: &str| checkpoint_origin != Some(origin);
    for origin in cleared_origins.iter().filter(|origin| stale(origin)) {
        state.local_storage.remove(origin);
        state.session_storage.remove(origin);
    }
    for entry in storage.iter().filter(|entry| stale(&entry.origin)) {
        let pairs = |items: &[crate::cookies::StorageItem]| {
            items
                .iter()
                .map(|item| (item.name.clone(), item.value.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        state
            .local_storage
            .insert(entry.origin.clone(), pairs(&entry.local_storage));
        state
            .session_storage
            .insert(entry.origin.clone(), pairs(&entry.session_storage));
    }
}

fn browser_cookies(profiles: &[StoredCookieProfile]) -> DomainResult<Vec<Value>> {
    let mut output = BTreeMap::<(String, String, String), Value>::new();
    for profile in profiles {
        if let Some(cookies) = &profile.managed_cookies {
            for cookie in cookies {
                let mut value = serde_json::Map::from_iter([
                    ("name".into(), json!(cookie.name)),
                    ("value".into(), json!(cookie.value)),
                    (
                        "domain".into(),
                        json!(if cookie.host_only {
                            cookie.domain.clone()
                        } else {
                            format!(".{}", cookie.domain)
                        }),
                    ),
                    ("path".into(), json!(cookie.path)),
                    ("httpOnly".into(), json!(cookie.http_only)),
                    ("secure".into(), json!(cookie.secure)),
                ]);
                if let Some(same_site) = &cookie.same_site {
                    value.insert("sameSite".into(), json!(same_site));
                }
                if let Some(expires) = cookie.expires {
                    value.insert("expires".into(), json!(expires));
                }
                output.insert(
                    (
                        cookie.name.clone(),
                        if cookie.host_only {
                            cookie.domain.clone()
                        } else {
                            format!(".{}", cookie.domain)
                        },
                        cookie.path.clone(),
                    ),
                    Value::Object(value),
                );
            }
            continue;
        }
        // A Cookie header can contain duplicate names from different paths,
        // but it carries no path metadata. For browser import, the last value
        // wins and becomes a host-only, root-path session cookie.
        let mut pairs = BTreeMap::<String, CookiePair>::new();
        for pair in profile.pairs()? {
            pairs.insert(pair.name.clone(), pair);
        }
        for pair in pairs.into_values() {
            output.insert(
                (pair.name.clone(), profile.host.clone(), "/".into()),
                json!({
                    "name": pair.name,
                    "value": pair.value,
                    "url": profile.target_url,
                }),
            );
        }
    }
    Ok(output.into_values().collect())
}

fn cookie_identities(cookies: &[crate::cookies::ManagedCookie]) -> Vec<Value> {
    cookies
        .iter()
        .map(|cookie| {
            json!({
                "name": cookie.name,
                "domain": if cookie.host_only {
                    cookie.domain.clone()
                } else {
                    format!(".{}", cookie.domain)
                },
                "path": cookie.path,
            })
        })
        .collect()
}

fn profile_cookie_identities(profile: &StoredCookieProfile) -> DomainResult<Vec<Value>> {
    if let Some(cookies) = &profile.managed_cookies {
        return Ok(cookie_identities(cookies));
    }
    Ok(profile
        .pairs()?
        .into_iter()
        .map(|pair| {
            json!({
                "name": pair.name,
                "domain": profile.host,
                "path": "/",
            })
        })
        .collect())
}

fn parse_cdp_info(value: Option<&Value>, port: u16) -> DomainResult<BrowserCdpInfo> {
    let info: BrowserCdpInfo = serde_json::from_value(value.cloned().ok_or_else(|| {
        DomainError::new(
            ErrorCode::ProtocolError,
            "browser worker omitted CDP details",
        )
    })?)
    .map_err(|error| {
        DomainError::new(
            ErrorCode::ProtocolError,
            format!("browser worker returned invalid CDP details: {error}"),
        )
    })?;
    if info.port != port
        || info.endpoint != format!("http://127.0.0.1:{port}")
        || info.devtools_url.len() > 4_096
        || info.hosted_devtools_url.len() > 4_096
        || !info.devtools_url.starts_with(&format!(
            "http://127.0.0.1:{port}/devtools/inspector.html?ws=127.0.0.1:{port}/devtools/page/"
        ))
        || !info
            .hosted_devtools_url
            .starts_with("https://chrome-devtools-frontend.appspot.com/")
        || !info
            .hosted_devtools_url
            .contains(&format!("ws=127.0.0.1:{port}/devtools/page/"))
    {
        return Err(DomainError::new(
            ErrorCode::ProtocolError,
            "browser worker returned unexpected CDP details",
        ));
    }
    Ok(info)
}

fn browser_resources(
    project_id: ProjectId,
    max_concurrent_browsers: u32,
    sessions: &[BrowserSession],
    runtimes: &HashMap<i64, RuntimeSession>,
    cdp_port_in_use: bool,
) -> DomainResult<BrowserResources> {
    let mut active_persistent = 0;
    let mut active_ephemeral = 0;
    for runtime in runtimes
        .values()
        .filter(|runtime| runtime.project_id == project_id)
    {
        if runtime.persistent {
            active_persistent += 1;
        } else {
            active_ephemeral += 1;
        }
    }
    let mut resources = Vec::with_capacity(sessions.len());
    for session in sessions {
        let runtime = runtimes.get(&session.id.get()).ok_or_else(|| {
            DomainError::new(
                ErrorCode::Unavailable,
                "requested browser profile is not active",
            )
        })?;
        let profile = session.active_profile.as_ref().ok_or_else(|| {
            DomainError::new(
                ErrorCode::ProtocolError,
                "active browser profile was not verified",
            )
        })?;
        if session.project_id != project_id
            || runtime.project_id != project_id
            || !runtime.persistent
            || runtime.profile.as_ref() != Some(profile)
            || session.profile.as_ref() != Some(profile)
            || !matches!(
                session.state,
                BrowserSessionState::Ready
                    | BrowserSessionState::Busy
                    | BrowserSessionState::Starting
            )
        {
            return Err(DomainError::new(
                ErrorCode::ProtocolError,
                "requested browser profile does not match the active runtime",
            ));
        }
        resources.push(BrowserSessionResource {
            session_id: session.id,
            profile: profile.clone(),
            agent_control: runtime.cdp.is_none(),
        });
    }
    if resources.len() != active_persistent {
        return Err(DomainError::new(
            ErrorCode::Unavailable,
            "active browser sessions changed during status verification",
        ));
    }
    Ok(BrowserResources {
        project_id,
        max_concurrent_browsers,
        active_persistent,
        active_ephemeral,
        available_capacity: (max_concurrent_browsers as usize)
            .saturating_sub(active_persistent + active_ephemeral),
        cdp_port_in_use,
        sessions: resources,
    })
}

fn cdp_status_view(
    project_id: ProjectId,
    active: Option<(i64, BrowserCdpInfo)>,
) -> BrowserCdpStatus {
    match active {
        Some((session_id, cdp)) => BrowserCdpStatus {
            project_id,
            active: true,
            agent_control: false,
            session_id: Some(BrowserSessionId(session_id)),
            cdp_port: Some(cdp.port),
            active_sessions: Vec::new(),
            endpoint: Some(cdp.endpoint),
            devtools_url: Some(cdp.devtools_url),
            hosted_devtools_url: Some(cdp.hosted_devtools_url),
            ssh_forward_command: ssh_forward_command(cdp.port),
        },
        None => BrowserCdpStatus {
            project_id,
            active: false,
            agent_control: true,
            session_id: None,
            endpoint: None,
            cdp_port: None,
            active_sessions: Vec::new(),
            devtools_url: None,
            hosted_devtools_url: None,
            ssh_forward_command: None,
        },
    }
}

fn ssh_forward_command(port: u16) -> Option<String> {
    let user = runtime_username()?;
    let ip = runtime_host_ip()?;
    let host = match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    Some(format!("ssh -N -L {port}:127.0.0.1:{port} {user}@{host}"))
}

fn runtime_username() -> Option<String> {
    (|| {
        let output = StdCommand::new("id").arg("-un").output().ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    })()
    .filter(|value| valid_ssh_username(value))
    .or_else(|| {
        ["USER", "LOGNAME"]
            .into_iter()
            .filter_map(|name| std::env::var(name).ok())
            .map(|value| value.trim().to_owned())
            .find(|value| valid_ssh_username(value))
    })
    .filter(|value| valid_ssh_username(value))
}

fn valid_ssh_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn runtime_host_ip() -> Option<IpAddr> {
    if let Some(ip) = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|connection| ssh_server_ip(&connection))
    {
        return Some(ip);
    }
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
}

fn ssh_server_ip(connection: &str) -> Option<IpAddr> {
    connection.split_whitespace().nth(2)?.parse().ok()
}

fn existing_path(configured: Option<PathBuf>, executable_name: &str) -> Option<PathBuf> {
    configured
        .filter(|path| path.exists())
        .or_else(|| which(executable_name))
        .or_else(|| {
            let executable = std::env::current_exe().ok()?;
            let sibling = executable.parent()?.join(executable_name);
            sibling.is_file().then_some(sibling)
        })
        .map(|path| path.canonicalize().unwrap_or(path))
}

fn inspect_browser_runtime(
    node_path: Option<&Path>,
    worker_path: Option<&Path>,
) -> BrowserRuntimeInspection {
    inspect_browser_runtime_with_paths(node_path, worker_path, None, None)
}

fn inspect_browser_runtime_with_paths(
    node_path: Option<&Path>,
    worker_path: Option<&Path>,
    playwright_core_path: Option<&Path>,
    chromium_path: Option<&Path>,
) -> BrowserRuntimeInspection {
    let Some((node_path, worker_path)) = node_path.zip(worker_path) else {
        return BrowserRuntimeInspection::default();
    };
    let inspection_error = "Browser runtime inspection failed; run `HuntProxy browser install` or check HUNTPROXY_BROWSER_WORKER_PATH";
    let unavailable = || BrowserRuntimeInspection {
        inspection_error: Some(inspection_error.into()),
        ..BrowserRuntimeInspection::default()
    };
    let mut command = StdCommand::new(node_path);
    command
        .arg(worker_path)
        .arg("--inspect-runtime")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(parent) = worker_path.parent() {
        command.current_dir(parent);
    }
    if let Some(path) = playwright_core_path {
        command.env("HUNTPROXY_PLAYWRIGHT_CORE_PATH", path);
    }
    if let Some(path) = chromium_path {
        command.env("HUNTPROXY_CHROME_EXECUTABLE", path);
    }
    let Ok(mut child) = command.spawn() else {
        return unavailable();
    };
    // Inspection does no browser/profile work. Bound custom or broken workers
    // too, rather than letting doctor or daemon startup wait indefinitely.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                return child
                    .wait_with_output()
                    .ok()
                    .filter(|output| output.stdout.len() <= 16 * 1024)
                    .and_then(|output| serde_json::from_slice(&output.stdout).ok())
                    .unwrap_or_else(unavailable);
            }
            Ok(Some(_)) => return unavailable(),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return unavailable();
            }
        }
    }
}

fn resolve_worker_path(explicit: Option<PathBuf>) -> Option<PathBuf> {
    resolve_worker_path_in(explicit, &crate::config::default_data_dir())
}

fn resolve_worker_path_in(explicit: Option<PathBuf>, fallback_data_dir: &Path) -> Option<PathBuf> {
    let mut candidates = worker_path_candidates(explicit);
    // Explicit/installed workers already own their assets and dependencies.
    // Do not rewrite another data directory merely to discover that path.
    if let Some(worker) = first_existing_worker(candidates.clone()) {
        return Some(worker);
    }
    if let Ok(materialized) = materialize_embedded_worker(fallback_data_dir) {
        candidates.push(materialized);
    }
    append_source_worker_candidate(&mut candidates);
    first_existing_worker(candidates)
}

fn inspect_worker_path(explicit: Option<PathBuf>, data_dir: &Path) -> Option<PathBuf> {
    let managed = explicit.or_else(|| Some(browser_worker_path(data_dir)));
    let mut candidates = worker_path_candidates(managed);
    append_source_worker_candidate(&mut candidates);
    first_existing_worker(candidates)
}

fn worker_path_candidates(explicit: Option<PathBuf>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = explicit {
        candidates.push(path);
    }
    if let Some(path) = std::env::var_os("HUNTPROXY_BROWSER_WORKER_PATH") {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(bin_dir) = executable.parent() {
            candidates.push(bin_dir.join("browser-worker/index.js"));
            candidates.push(bin_dir.join("../libexec/huntproxy/browser-worker/index.js"));
            candidates.push(bin_dir.join("../share/huntproxy/browser-worker/index.js"));
        }
    }
    candidates
}

fn append_source_worker_candidate(candidates: &mut Vec<PathBuf>) {
    if let Ok(current) = std::env::current_dir() {
        candidates.push(current.join("browser-worker/index.js"));
    }
}

fn first_existing_worker(candidates: Vec<PathBuf>) -> Option<PathBuf> {
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .map(|path| path.canonicalize().unwrap_or(path))
}

const WORKER_DIRECTORY_PREFIX: &str = "browser-worker-";

fn browser_worker_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join(format!(
            "{WORKER_DIRECTORY_PREFIX}{}",
            env!("CARGO_PKG_VERSION")
        ))
        .join("index.js")
}

/// Materialize the version-matched worker and package manifest in a stable,
/// per-user location for release runtime preparation.
pub fn prepare_browser_worker_installation(data_dir: &Path) -> DomainResult<PathBuf> {
    let worker = materialize_embedded_worker(data_dir).map_err(|error| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("prepare browser worker: {error}"),
        )
    })?;
    worker
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| DomainError::new(ErrorCode::Internal, "worker directory unavailable"))
}

fn materialize_embedded_worker(data_dir: &Path) -> std::io::Result<PathBuf> {
    let worker_path = browser_worker_path(data_dir);
    let directory = worker_path
        .parent()
        .expect("browser worker path always has a parent");
    std::fs::create_dir_all(directory)?;
    let package_path = directory.join("package.json");
    let lock_path = directory.join("package-lock.json");
    write_if_changed(&worker_path, EMBEDDED_WORKER.as_bytes())?;
    write_if_changed(
        &directory.join("headless.js"),
        EMBEDDED_WORKER_HEADLESS.as_bytes(),
    )?;
    write_if_changed(&package_path, EMBEDDED_WORKER_PACKAGE.as_bytes())?;
    write_if_changed(&lock_path, EMBEDDED_WORKER_LOCK.as_bytes())?;
    prune_old_worker_directories(data_dir, env!("CARGO_PKG_VERSION"));
    Ok(worker_path)
}

/// A plain `MAJOR.MINOR.PATCH` release: decimal numbers without signs or
/// leading zeros.
fn parse_release(version: &str) -> Option<[u64; 3]> {
    let mut parts = version.split('.');
    let mut release = [0; 3];
    for number in &mut release {
        let part = parts.next()?;
        let plain = !part.is_empty()
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'));
        if !plain {
            return None;
        }
        *number = part.parse().ok()?;
    }
    parts.next().is_none().then_some(release)
}

/// Removes the worker directories of releases older than the previous one.
///
/// Only real directories named exactly `browser-worker-MAJOR.MINOR.PATCH` are
/// considered. The current release, newer ones and anything else stay. So does
/// the previous release: an installer can run the new binary before it commits
/// to it, and rolling back then needs the old worker. Failing to remove a
/// directory only costs disk space, so it is logged and never propagated.
fn prune_old_worker_directories(data_dir: &Path, current_version: &str) {
    let Some(current) = current_version
        .split(['-', '+'])
        .next()
        .and_then(parse_release)
    else {
        return;
    };
    let entries = match std::fs::read_dir(data_dir) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(%error, directory = %data_dir.display(), "could not list old browser worker directories");
            return;
        }
    };
    let mut older = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(%error, directory = %data_dir.display(), "could not read a data directory entry");
                continue;
            }
        };
        let Some(release) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_prefix(WORKER_DIRECTORY_PREFIX))
            .and_then(parse_release)
            .filter(|release| *release < current)
        else {
            continue;
        };
        // A symlink is not a directory here, so a link is never followed.
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => older.push((release, entry.path())),
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, path = %entry.path().display(), "could not inspect an old browser worker directory");
            }
        }
    }
    older.sort();
    older.pop();
    for (_, path) in older {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "could not remove an old browser worker directory");
            }
        }
    }
}

fn write_if_changed(path: &Path, content: &[u8]) -> std::io::Result<()> {
    if std::fs::read(path).ok().as_deref() == Some(content) {
        return Ok(());
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, content)?;
    std::fs::rename(temporary, path)
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|directory| {
            let path = directory.join(name);
            path.is_file().then_some(path)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_action_has_agent_friendly_defaults() {
        let action: BrowserAction = serde_json::from_value(json!({ "type": "snapshot" })).unwrap();
        match action {
            BrowserAction::Snapshot {
                format,
                max_bytes,
                offset,
                locator,
                timeout_ms,
            } => {
                assert!(timeout_ms.is_none());
                assert_eq!(format, "accessibility");
                assert_eq!(max_bytes, 24_000);
                assert_eq!(offset, 0);
                assert!(locator.is_none());
            }
            _ => panic!("wrong browser action"),
        }
        let zero: BrowserAction =
            serde_json::from_value(json!({"type": "snapshot", "max_bytes": 0})).unwrap();
        assert!(validate_browser_action(&zero).is_err());
    }

    #[test]
    fn post_action_snapshots_are_opt_in_for_interactions() {
        for action in [
            json!({"type": "navigate", "url": "https://app.test/"}),
            json!({"type": "click", "locator": {"css": "button"}}),
            json!({"type": "fill", "locator": {"css": "input"}, "value": "a"}),
            json!({"type": "select", "locator": {"css": "select"}, "value": "a"}),
            json!({"type": "press", "key": "Enter"}),
            json!({"type": "wait", "for_what": "timeout", "value": "0"}),
            json!({"type": "back"}),
            json!({"type": "forward"}),
        ] {
            let plain: BrowserAction = serde_json::from_value(action.clone()).unwrap();
            assert!(!plain.wants_snapshot(), "{action}");
            let mut requested = action.clone();
            requested["snapshot"] = json!(true);
            let requested: BrowserAction = serde_json::from_value(requested).unwrap();
            assert!(requested.wants_snapshot(), "{action}");
            // The worker receives the flag.
            assert_eq!(serde_json::to_value(&requested).unwrap()["snapshot"], true);
        }
        let back: BrowserAction = serde_json::from_value(json!({"type": "back"})).unwrap();
        assert_eq!(
            serde_json::to_value(back).unwrap(),
            json!({"type": "back", "snapshot": false})
        );
    }

    fn result_with(data: Value) -> ActionResult {
        ActionResult {
            ok: true,
            untrusted: true,
            message: "snapshot captured".into(),
            data: Some(data),
            browser: Some(BrowserActionContext {
                session_id: BrowserSessionId(7),
                profile: Some("default".into()),
                runtime_generation: 1,
                page_id: 1,
            }),
            ignored_options: Vec::new(),
        }
    }

    /// The worker's `snapshotSlice`: whole chars from `offset`, at most `max_bytes`.
    fn worker_slice(content: &str, offset: usize, max_bytes: usize) -> Value {
        let mut start = offset.min(content.len());
        while !content.is_char_boundary(start) {
            start += 1;
        }
        let mut end = (start + max_bytes).min(content.len());
        while !content.is_char_boundary(end) {
            end -= 1;
        }
        let mut data = json!({
            "format": "dom",
            "content": &content[start..end],
            "truncated": end < content.len(),
            "total_bytes": content.len(),
        });
        if start > 0 {
            data["offset"] = json!(start);
        }
        if end < content.len() {
            data["next_offset"] = json!(end);
        }
        data
    }

    /// Escapes, multi-byte chars and control chars, as large pages have them.
    fn hostile_page(bytes: usize) -> String {
        let unit = "<a href=\"/x?q=\\\"\">é🦀\t\u{1}</a>\n";
        unit.repeat(bytes / unit.len() + 1)
    }

    fn fitted_len(result: &ActionResult) -> usize {
        let text = serde_json::to_string(result).unwrap();
        assert!(
            text.len() <= ACTION_OUTPUT_BYTES,
            "{} > {ACTION_OUTPUT_BYTES}",
            text.len()
        );
        text.len()
    }

    #[test]
    fn snapshot_results_fit_the_output_budget_and_page_exactly() {
        let snapshot = BrowserAction::Snapshot {
            format: "dom".into(),
            max_bytes: MAX_SNAPSHOT_BYTES,
            offset: 0,
            locator: None,
            timeout_ms: None,
        };
        for page in [hostile_page(1_700_000), "plain ".repeat(40_000)] {
            let mut reassembled = String::new();
            let mut offset = 0;
            let mut calls = 0;
            loop {
                let mut result = result_with(worker_slice(&page, offset, 24_000));
                fit_action_result(&snapshot, &mut result).unwrap();
                let size = fitted_len(&result);
                let data = result.data.unwrap();
                let content = data["content"].as_str().unwrap();
                assert_eq!(data["total_bytes"], page.len());
                reassembled.push_str(content);
                calls += 1;
                match data.get("next_offset") {
                    Some(next) => {
                        assert_eq!(data["truncated"], true);
                        // Each page is nearly the whole budget.
                        assert!(size > ACTION_OUTPUT_BYTES - 64, "{size}");
                        let next = next.as_u64().unwrap() as usize;
                        assert_eq!(next, offset + content.len());
                        offset = next;
                    }
                    None => {
                        assert_eq!(data["truncated"], false);
                        break;
                    }
                }
            }
            assert_eq!(reassembled, page);
            assert!(calls > page.len() / ACTION_OUTPUT_BYTES);
        }
    }

    #[test]
    fn a_small_snapshot_is_returned_whole() {
        let snapshot: BrowserAction = serde_json::from_value(json!({"type": "snapshot"})).unwrap();
        let page = "- heading \"Sign in\" [level=1]\n- button \"Continue\"";
        let mut result = result_with(worker_slice(page, 0, 24_000));
        let before = result.data.clone();
        fit_action_result(&snapshot, &mut result).unwrap();
        assert_eq!(result.data, before);
    }

    #[test]
    fn post_action_snapshots_and_inspections_fit_the_output_budget() {
        let click: BrowserAction = serde_json::from_value(json!({
            "type": "click", "locator": {"css": "button"}, "snapshot": true
        }))
        .unwrap();
        let page = hostile_page(100_000);
        let mut snapshot = worker_slice(&page, 0, 24_000);
        snapshot.as_object_mut().unwrap().remove("format");
        let mut result = result_with(json!({"url": "https://app.test/next", "snapshot": snapshot}));
        fit_action_result(&click, &mut result).unwrap();
        fitted_len(&result);
        let data = result.data.unwrap();
        assert_eq!(data["url"], "https://app.test/next");
        let snapshot = &data["snapshot"];
        let content = snapshot["content"].as_str().unwrap();
        assert!(page.starts_with(content) && content.len() > 10_000);
        assert_eq!(snapshot["next_offset"], content.len());
        assert_eq!(snapshot["truncated"], true);
        assert_eq!(snapshot["total_bytes"], page.len());

        // A failed capture is reported as is.
        let failed = json!({"url": "https://app.test/", "snapshot": {"error": "Timeout"}});
        let mut result = result_with(failed.clone());
        fit_action_result(&click, &mut result).unwrap();
        assert_eq!(result.data.unwrap(), failed);

        let inspect: BrowserAction =
            serde_json::from_value(json!({"type": "inspect", "max_bytes": 65_536})).unwrap();
        let text = serde_json::to_string(&json!({"resources": [page]})).unwrap();
        let mut result = result_with(json!({
            "format": "runtime", "content": &text[..65_536], "truncated": true,
            "total_bytes": text.len(),
        }));
        fit_action_result(&inspect, &mut result).unwrap();
        fitted_len(&result);
        let data = result.data.unwrap();
        assert!(text.starts_with(data["content"].as_str().unwrap()));
        assert_eq!(data["truncated"], true);
        assert!(data.get("next_offset").is_none());

        // An evaluation result is cut the same way and keeps what describes it.
        let evaluate: BrowserAction =
            serde_json::from_value(json!({"type": "evaluate", "expression": "document.body"}))
                .unwrap();
        let mut slice = worker_slice(&page, 0, 24_000);
        let fields = slice.as_object_mut().unwrap();
        fields.remove("format");
        fields.remove("next_offset");
        fields.insert("type".into(), json!("node"));
        fields.insert("frame_url".into(), json!("https://app.test/embed"));
        let mut result = result_with(slice);
        fit_action_result(&evaluate, &mut result).unwrap();
        fitted_len(&result);
        let data = result.data.unwrap();
        let content = data["content"].as_str().unwrap();
        assert!(page.starts_with(content) && content.len() > 10_000);
        assert_eq!(data["truncated"], true);
        assert_eq!(data["total_bytes"], page.len());
        assert_eq!(data["type"], "node");
        assert_eq!(data["frame_url"], "https://app.test/embed");
        assert!(data.get("next_offset").is_none());
        // A result that fits is returned whole and says so.
        let whole =
            json!({"type": "string", "content": "Shop", "truncated": false, "total_bytes": 4});
        let mut result = result_with(whole.clone());
        fit_action_result(&evaluate, &mut result).unwrap();
        assert_eq!(result.data.unwrap(), whole);
    }

    #[test]
    fn an_event_page_ends_at_a_whole_row_and_resumes_without_loss() {
        let events: BrowserAction =
            serde_json::from_value(json!({"type": "events", "limit": 100})).unwrap();
        let all = (1..=100)
            .map(|sequence| {
                json!({
                    "sequence": sequence, "kind": "request", "page_id": 1,
                    "observed_at": "2026-11-15T07:47:53.123Z", "method": "GET",
                    "url": format!("https://app.test/assets/{}.js", "a".repeat(400)),
                    "resource_type": "script", "navigation": false,
                })
            })
            .collect::<Vec<_>>();
        let page = |after: u64| {
            let rows = all
                .iter()
                .filter(|row| row["sequence"].as_u64().unwrap() > after)
                .cloned()
                .collect::<Vec<_>>();
            json!({
                "runtime_generation": 1,
                "next_sequence": rows.last().map_or(json!(after), |row| row["sequence"].clone()),
                "events": rows, "latest_sequence": 100, "oldest_sequence": 1,
                "cursor_expired": false, "dropped_events": 0, "observer_errors": [],
            })
        };
        let mut seen = Vec::new();
        let mut after = 0;
        loop {
            let mut result = result_with(page(after));
            fit_action_result(&events, &mut result).unwrap();
            fitted_len(&result);
            let data = result.data.unwrap();
            let rows = data["events"].as_array().unwrap();
            assert!(!rows.is_empty());
            seen.extend(rows.iter().cloned());
            assert_eq!(data["next_sequence"], rows.last().unwrap()["sequence"]);
            after = data["next_sequence"].as_u64().unwrap();
            if data.get("truncated").is_none() {
                break;
            }
            assert_eq!(data["truncated"], true);
        }
        assert_eq!(seen, all);
    }

    #[test]
    fn structured_browser_actions_have_bounded_defaults() {
        let request: BrowserAction = serde_json::from_value(json!({
            "type": "request",
            "method": "POST",
            "url": "https://example.com/api/items"
        }))
        .unwrap();
        match &request {
            BrowserAction::Request {
                headers,
                timeout_ms,
                max_response_bytes,
                ..
            } => {
                assert!(headers.is_empty());
                assert_eq!(*timeout_ms, 15_000);
                assert_eq!(*max_response_bytes, 4096);
            }
            _ => panic!("wrong browser action"),
        }
        validate_browser_action(&request).unwrap();

        let events: BrowserAction = serde_json::from_value(json!({"type":"events"})).unwrap();
        match &events {
            BrowserAction::Events {
                after_sequence,
                limit,
                wait_ms,
                ..
            } => {
                assert_eq!(*after_sequence, 0);
                assert_eq!(*limit, 50);
                assert_eq!(*wait_ms, 0);
            }
            _ => panic!("wrong browser action"),
        }
        validate_browser_action(&events).unwrap();

        let observer_events: BrowserAction = serde_json::from_value(json!({
            "type": "events", "kinds": ["console", "page_error", "observer_error"]
        }))
        .unwrap();
        validate_browser_action(&observer_events).unwrap();

        let evaluate: BrowserAction =
            serde_json::from_value(json!({"type": "evaluate", "expression": "document.title"}))
                .unwrap();
        match &evaluate {
            BrowserAction::Evaluate {
                frame, timeout_ms, ..
            } => {
                assert!(frame.is_none());
                assert_eq!(*timeout_ms, 10_000);
            }
            _ => panic!("wrong browser action"),
        }
        validate_browser_action(&evaluate).unwrap();
        // The worker reads an absent frame as the selected page itself.
        assert_eq!(
            serde_json::to_value(&evaluate).unwrap()["frame"],
            Value::Null
        );
        let largest: BrowserAction = serde_json::from_value(json!({
            "type": "evaluate", "expression": "1".repeat(MAX_BROWSER_EVALUATE_BYTES),
            "frame": "checkout", "timeout_ms": 30_000,
        }))
        .unwrap();
        validate_browser_action(&largest).unwrap();

        let click: BrowserAction =
            serde_json::from_value(json!({"type": "pointer", "op": "click", "x": 12.5, "y": 0}))
                .unwrap();
        match &click {
            BrowserAction::Pointer {
                button,
                count,
                modifiers,
                snapshot,
                ..
            } => {
                assert_eq!(button, "left");
                assert_eq!(*count, 1);
                assert!(modifiers.is_empty() && !snapshot);
            }
            _ => panic!("wrong browser action"),
        }
        validate_browser_action(&click).unwrap();
        for value in [
            json!({"type":"pointer","op":"click","locator":{"css":"#pad"},"button":"right","count":3,"modifiers":["Alt","Control","Meta","Shift"],"snapshot":true}),
            json!({"type":"pointer","op":"hover","x":100000,"y":100000}),
            json!({"type":"pointer","op":"drag","locator":{"css":"#card"},"to_x":1,"to_y":2}),
            json!({"type":"pointer","op":"drag","x":1,"y":2,"to_locator":{"role":"listitem","nth":-1,"frame":"board"}}),
            json!({"type":"type","text":"x".repeat(MAX_BROWSER_TYPE_BYTES)}),
            json!({"type":"type","text":"a\nb","locator":{"css":"#editor","frame":"f".repeat(2048)},"snapshot":true}),
            // Clients that send every locator field send the absent ones as null.
            json!({"type":"click","locator":{"role":"button","name":"Delete","text":null,"test_id":null,"css":null,"exact":true,"nth":2,"frame":null}}),
            json!({"type":"snapshot","locator":{"css":"body","frame":"checkout","nth":null}}),
        ] {
            let action: BrowserAction = serde_json::from_value(value.clone()).unwrap();
            validate_browser_action(&action).unwrap_or_else(|error| panic!("{value}: {error}"));
            assert_eq!(
                action.wants_snapshot(),
                value["snapshot"] == true,
                "{value}"
            );
        }
        // A locator the worker can read back: absent fields are null, never missing.
        let locator = serde_json::to_value(css_only("#pay")).unwrap();
        assert_eq!(locator["nth"], Value::Null);
        assert_eq!(locator["frame"], Value::Null);
    }

    fn css_only(selector: &str) -> Locator {
        Locator {
            css: Some(selector.into()),
            ..Locator::default()
        }
    }

    #[test]
    fn structured_browser_actions_reject_ambiguous_or_unsafe_inputs() {
        for value in [
            json!({"type":"pages","op":"select","page_id":0,"runtime_generation":1}),
            json!({"type":"pages","op":"new","url":"file:///etc/passwd"}),
            json!({"type":"events","after_sequence":1}),
            json!({"type":"events","runtime_generation":0}),
            json!({"type":"scroll"}),
            json!({"type":"screenshot","full_page":true,"locator":{"css":"main"}}),
            json!({"type":"request","method":"GET","url":"https://example.com/","body_text":"data"}),
            json!({"type":"request","method":"GET","url":"https://example.com/","body_text":""}),
            json!({"type":"request","method":"POST","url":"https://user@example.com/"}),
            json!({"type":"request","method":"POST","url":"https://example.com/","body_text":"a","body_base64":"Yg=="}),
            json!({"type":"request","method":"POST","url":"https://example.com/","body_base64":"not base64"}),
            json!({"type":"request","method":"POST","url":"https://example.com/","headers":[{"name":"Cookie","value":"sid=1"}]}),
            json!({"type":"request","method":"POST","url":"https://example.com/","headers":[{"name":"Connection","value":"close"}]}),
            json!({"type":"request","method":"POST","url":"https://example.com/","headers":[{"name":"Sec-Fetch-Site","value":"same-origin"}]}),
            json!({"type":"request","method":"POST","url":"https://example.com/","headers":[{"name":"X-HTTP-Method-Override","value":"PATCH, TRACE"}]}),
            json!({"type":"request","method":"POST","url":"https://example.com/","headers":[{"name":"x-note","value":"one"},{"name":"X-Note","value":"two"}]}),
            json!({"type":"evaluate","expression":""}),
            json!({"type":"evaluate","expression":" \n\t"}),
            json!({"type":"evaluate","expression":"1".repeat(MAX_BROWSER_EVALUATE_BYTES + 1)}),
            json!({"type":"evaluate","expression":"1","frame":""}),
            json!({"type":"evaluate","expression":"1","frame":"f".repeat(2049)}),
            json!({"type":"evaluate","expression":"1","timeout_ms":0}),
            json!({"type":"evaluate","expression":"1","timeout_ms":30_001}),
            json!({"type":"pointer","op":"tap","x":1,"y":1}),
            json!({"type":"pointer","op":"click"}),
            json!({"type":"pointer","op":"click","x":1}),
            json!({"type":"pointer","op":"click","x":1,"y":-1}),
            json!({"type":"pointer","op":"click","x":1,"y":100_001}),
            json!({"type":"pointer","op":"click","x":1,"y":1,"locator":{"css":"#pad"}}),
            json!({"type":"pointer","op":"click","x":1,"y":1,"button":"back"}),
            json!({"type":"pointer","op":"click","x":1,"y":1,"count":0}),
            json!({"type":"pointer","op":"click","x":1,"y":1,"count":4}),
            json!({"type":"pointer","op":"click","x":1,"y":1,"modifiers":["Hyper"]}),
            json!({"type":"pointer","op":"click","x":1,"y":1,"modifiers":["Shift","Shift"]}),
            json!({"type":"pointer","op":"hover","x":1,"y":1,"to_x":2,"to_y":2}),
            json!({"type":"pointer","op":"click","x":1,"y":1,"to_locator":{"css":"#bin"}}),
            json!({"type":"pointer","op":"drag","x":1,"y":1}),
            json!({"type":"pointer","op":"drag","x":1,"y":1,"to_x":2}),
            json!({"type":"pointer","op":"drag","x":1,"y":1,"to_x":2,"to_y":2,"to_locator":{"css":"#bin"}}),
            json!({"type":"pointer","op":"drag","to_x":2,"to_y":2}),
            json!({"type":"type","text":""}),
            json!({"type":"type","text":"x".repeat(MAX_BROWSER_TYPE_BYTES + 1)}),
            json!({"type":"click","locator":{"css":"button","frame":""}}),
            json!({"type":"fill","locator":{"css":"input","frame":"f".repeat(2049)},"value":"x"}),
            json!({"type":"snapshot","locator":{"css":"li","nth":1_000_001}}),
            json!({"type":"pointer","op":"drag","x":1,"y":1,"to_locator":{"css":"#bin","frame":""}}),
        ] {
            let action: BrowserAction = serde_json::from_value(value).unwrap();
            assert!(validate_browser_action(&action).is_err());
        }
        assert!(serde_json::from_value::<BrowserAction>(json!({
            "type":"request",
            "method":"POST",
            "url":"https://example.com/",
            "headers":[{"name":"x-test","value":"ok","extra":true}]
        }))
        .is_err());
    }

    #[test]
    fn agent_actions_read_null_as_absent_and_name_the_options_they_ignore() {
        let read = |value: Value| BrowserAction::from_agent_input(value).unwrap();
        // A client that sends every schema property sends the unused ones as null.
        let (click, ignored) = read(json!({
            "type": "click", "locator": {"css": "#save", "nth": null}, "url": null,
            "snapshot": null, "timeout_ms": 5000, "wait_ms": null, "max_bytes": null,
            "for_what": null, "value": null, "op": "click", "exact": true,
        }));
        assert_eq!(ignored, ["exact"]);
        let BrowserAction::Click {
            snapshot, options, ..
        } = &click
        else {
            panic!("wrong browser action: {click:?}");
        };
        assert!(!snapshot);
        assert_eq!(
            options,
            &InteractionOptions {
                timeout_ms: Some(5000),
                ..InteractionOptions::default()
            }
        );
        // The worker receives what was set and nothing for what was not.
        let sent = serde_json::to_value(&click).unwrap();
        assert_eq!(sent["timeout_ms"], 5000);
        assert!(sent.get("wait_ms").is_none() && sent.get("wait_until").is_none());

        for (value, expected) in [
            // What the audit saw agents send, now honoured.
            (
                json!({"type":"navigate","url":"https://app.test/","timeout_ms":30000,"wait_ms":2500,"wait_until":"networkidle","snapshot":true,"max_bytes":3000}),
                vec![],
            ),
            (
                json!({"type":"click","locator":{"css":"a"},"wait_ms":500}),
                vec![],
            ),
            // A forced click lands on whatever covers the element, so there is none.
            (
                json!({"type":"click","locator":{"css":"a"},"force":true}),
                vec!["force"],
            ),
            (
                json!({"type":"wait","for_what":"selector","value":"#x","timeout_ms":15000}),
                vec![],
            ),
            (
                json!({"type":"snapshot","snapshot":true,"timeout_ms":1000}),
                vec![],
            ),
            (json!({"type":"pages"}), vec![]),
            // Settings an action takes only in other circumstances.
            (
                json!({"type":"click","locator":{"css":"a"},"max_bytes":12000}),
                vec!["max_bytes"],
            ),
            (
                json!({"type":"wait","for_what":"timeout","value":"1","wait_ms":1,"force":false}),
                vec!["force", "wait_ms"],
            ),
            (
                json!({"type":"fill","locator":{"css":"input"},"value":"a","wait_until":"load"}),
                vec!["wait_until"],
            ),
            // Unknown options, and an op that names another action.
            (
                json!({"type":"snapshot","selector":"main","op":"click"}),
                vec!["op", "selector"],
            ),
            (
                json!({"type":"request","method":"GET","url":"https://app.test/","redirect":"follow"}),
                vec!["redirect"],
            ),
        ] {
            let (action, ignored) = read(value.clone());
            validate_browser_action(&action).unwrap_or_else(|error| panic!("{value}: {error}"));
            assert_eq!(ignored, expected, "{value}");
        }
        let (pages, _) = read(json!({"type": "pages", "op": null}));
        assert!(matches!(pages, BrowserAction::Pages { op, .. } if op == "list"));
        let (request, _) = read(json!({"type":"request","method":"GET","url":"https://app.test/"}));
        assert_eq!(
            serde_json::to_value(request).unwrap()["follow_redirects"],
            false
        );

        assert!(BrowserAction::from_agent_input(json!("click")).is_err());
        assert!(BrowserAction::from_agent_input(json!({"type": "click"})).is_err());
        let many = (0..40)
            .map(|index| (format!("unknown_{index:02}"), json!(1)))
            .chain([("type".to_string(), json!("back"))])
            .collect::<serde_json::Map<_, _>>();
        let (_, ignored) = read(Value::Object(many));
        assert_eq!(ignored.len(), MAX_IGNORED_OPTIONS);
    }

    #[test]
    fn agent_actions_accept_schema_defaults_and_name_timeouts_nothing_waits_for() {
        let ignored = |value: Value| BrowserAction::from_agent_input(value).unwrap().1;
        // A client that fills in every schema default.
        let defaults = json!({
            "offset": 0, "limit": 50, "after_sequence": 0, "delta_x": 0, "delta_y": 0,
            "full_page": false, "via_chooser": false, "follow_redirects": false,
            "max_response_bytes": 4096, "wait_ms": 0, "snapshot": false,
        });
        let mut click = defaults.clone();
        click["type"] = json!("click");
        click["locator"] = json!({"css": "#save"});
        assert!(ignored(click).is_empty());
        let mut wait = defaults.clone();
        wait["type"] = json!("wait");
        wait["for_what"] = json!("selector");
        wait["value"] = json!("#x");
        assert!(ignored(wait).is_empty());
        // A value other than the default is still named.
        assert_eq!(
            ignored(json!({"type":"click","locator":{"css":"a"},"limit":10,"full_page":true})),
            ["full_page", "limit"]
        );
        // The defaults an action reads are the same with or without them.
        let (events, _) = BrowserAction::from_agent_input(
            json!({"type":"events","limit":50,"after_sequence":0,"wait_ms":0}),
        )
        .unwrap();
        assert!(matches!(
            events,
            BrowserAction::Events {
                limit: 50,
                after_sequence: 0,
                wait_ms: 0,
                ..
            }
        ));

        for (value, expected) in [
            (
                json!({"type":"press","key":"Enter","timeout_ms":5000}),
                vec!["timeout_ms"],
            ),
            (
                json!({"type":"type","text":"a","timeout_ms":5000}),
                vec!["timeout_ms"],
            ),
            (
                json!({"type":"wait","for_what":"timeout","value":"100","timeout_ms":5000}),
                vec!["timeout_ms"],
            ),
            (
                json!({"type":"pointer","op":"click","x":1,"y":2,"timeout_ms":5000}),
                vec!["timeout_ms"],
            ),
            (
                json!({"type":"snapshot","format":"dom","timeout_ms":5000}),
                vec!["timeout_ms"],
            ),
            // Where something is waited for, it applies.
            (
                json!({"type":"press","key":"Enter","locator":{"css":"input"},"timeout_ms":5000}),
                vec![],
            ),
            (
                json!({"type":"pointer","op":"drag","x":1,"y":2,"to_locator":{"css":"#bin"},"timeout_ms":5000}),
                vec![],
            ),
            (json!({"type":"snapshot","timeout_ms":5000}), vec![]),
            (
                json!({"type":"snapshot","format":"dom","locator":{"css":"main"},"timeout_ms":5000}),
                vec![],
            ),
        ] {
            assert_eq!(ignored(value.clone()), expected, "{value}");
        }
    }

    #[test]
    fn interaction_options_are_bounded() {
        for value in [
            json!({"type":"click","locator":{"css":"a"},"timeout_ms":0}),
            json!({"type":"navigate","url":"https://app.test/","timeout_ms":30_001}),
            json!({"type":"snapshot","timeout_ms":0}),
            json!({"type":"fill","locator":{"css":"a"},"value":"","wait_ms":30_001}),
            json!({"type":"press","key":"Enter","snapshot":true,"max_bytes":0}),
            json!({"type":"back","wait_until":"commit"}),
        ] {
            let action: BrowserAction = serde_json::from_value(value.clone()).unwrap();
            assert!(validate_browser_action(&action).is_err(), "{value}");
        }
        for value in [
            json!({"type":"click","locator":{"css":"a"},"timeout_ms":1,"wait_ms":30_000}),
            json!({"type":"forward","wait_until":"load","timeout_ms":30_000}),
            json!({"type":"type","text":"a","snapshot":true,"max_bytes":1}),
        ] {
            let action: BrowserAction = serde_json::from_value(value.clone()).unwrap();
            validate_browser_action(&action).unwrap_or_else(|error| panic!("{value}: {error}"));
        }
    }

    #[test]
    fn an_evaluated_object_is_returned_as_json_unless_it_must_be_cut() {
        let evaluate: BrowserAction =
            serde_json::from_value(json!({"type": "evaluate", "expression": "({a: 1})"})).unwrap();
        let small = json!({"type": "object", "value": {"items": [1, 2], "name": "Shop"}});
        let mut result = result_with(small.clone());
        fit_action_result(&evaluate, &mut result).unwrap();
        assert_eq!(result.data.unwrap(), small);

        // One that does not fit the result becomes JSON text, cut like any other.
        let rows = (0..2_000)
            .map(|index| json!({"id": index, "name": "é\"🦀"}))
            .collect::<Vec<_>>();
        let mut result = result_with(json!({"type": "object", "value": rows}));
        fit_action_result(&evaluate, &mut result).unwrap();
        fitted_len(&result);
        let data = result.data.unwrap();
        let whole = serde_json::to_string(&rows).unwrap();
        assert!(data.get("value").is_none());
        assert!(whole.starts_with(data["content"].as_str().unwrap()));
        assert_eq!(data["truncated"], true);
        assert_eq!(data["total_bytes"], whole.len());
        assert_eq!(data["type"], "object");
    }

    #[test]
    fn the_concurrency_limit_names_what_holds_the_slots() {
        let message = concurrency_limit_message(
            3,
            [(9, None), (4, Some("default")), (7, Some("admin"))].into_iter(),
        );
        assert_eq!(
            message,
            "project browser concurrency limit reached: 3 of 3 browser slots in use, held by session 4 (profile default), session 7 (profile admin), 1 ephemeral session; browser_manage op=stop with a persistent session's session_id frees one; ephemeral sessions end on their own when the tool using them finishes"
        );
        let message = concurrency_limit_message(2, [(1, None::<&str>), (2, None)].into_iter());
        assert!(message.contains("2 of 2 browser slots in use, held by 2 ephemeral sessions;"));
        // Without ephemeral sessions there is nothing to say about them.
        let message = concurrency_limit_message(1, [(5, Some("default"))].into_iter());
        assert!(message.ends_with("session_id frees one"), "{message}");
    }

    #[test]
    fn decodes_checkpoint_without_exposing_private_shape() {
        let value = json!({
            "url": "https://example.com/app",
            "title": "Example application",
            "_private": {
                "origin": "https://example.com",
                "cookies": [{"name":"sid","value":"secret"}],
                "local_storage": {"theme":"dark"},
                "session_storage": {"csrf":"secret"}
            }
        });
        let checkpoint = decode_checkpoint(&value).unwrap();
        assert_eq!(checkpoint.url.as_deref(), Some("https://example.com/app"));
        assert_eq!(checkpoint.title.as_deref(), Some("Example application"));
        assert_eq!(checkpoint.cookies.len(), 1);
        assert_eq!(
            checkpoint.local_storage["https://example.com"]["theme"],
            "dark"
        );
        assert_eq!(checkpoint.session_storage["csrf"], "secret");
    }

    #[tokio::test]
    async fn unknown_browser_action_session_has_actionable_error() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let browser = BrowserService::new(db, None, None);
        let action: BrowserAction = serde_json::from_value(json!({"type":"snapshot"})).unwrap();
        let error = browser
            .action(ProjectId(128), BrowserSessionId(0), action)
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(error.to_string(), "browser session 0 not found in project 128; call browser_start or browser_manage status");
    }

    #[tokio::test]
    async fn browser_session_title_round_trips_for_client_reattachment() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "reattach".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let mut session = db
            .create_browser_session(project.id, Some(DEFAULT_BROWSER_PROFILE.into()))
            .await
            .unwrap();
        session.current_url = Some("https://example.test/dashboard".into());
        session.current_title = Some("Dashboard".into());
        session.state = BrowserSessionState::Ready;
        db.update_browser_session(&session).await.unwrap();

        let restored = db
            .get_browser_session(project.id, session.id)
            .await
            .unwrap();
        assert_eq!(restored.profile.as_deref(), Some(DEFAULT_BROWSER_PROFILE));
        assert_eq!(restored.current_url, session.current_url);
        assert_eq!(restored.current_title.as_deref(), Some("Dashboard"));
        assert_eq!(restored.engine, BrowserEngine::Chromium);
        assert_eq!(restored.state, BrowserSessionState::Ready);
    }

    #[tokio::test]
    async fn browser_resources_count_ephemeral_capacity_and_hide_foreign_cdp_identity() {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "Resource observation".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let mut session = db
            .create_browser_session(project.id, Some("account1".into()))
            .await
            .unwrap();
        session.active_profile = Some("account1".into());
        session.state = BrowserSessionState::Ready;
        session.current_url = Some("https://example.test/private?value=hidden".into());
        session.current_title = Some("Private page".into());
        let cdp = BrowserCdpInfo {
            port: BROWSER_CDP_PORT,
            endpoint: "http://127.0.0.1:9222".into(),
            devtools_url: "foreign-devtools".into(),
            hosted_devtools_url: "foreign-hosted-devtools".into(),
        };
        let mut runtimes = HashMap::from([
            (
                session.id.get(),
                RuntimeSession {
                    project_id: project.id,
                    capture_session_id: CaptureSessionId(1),
                    persistent: true,
                    profile: Some("account1".into()),
                    cdp: None,
                    javascript_cursor: 0,
                },
            ),
            (
                session.id.get() + 1,
                RuntimeSession {
                    project_id: project.id,
                    capture_session_id: CaptureSessionId(2),
                    persistent: false,
                    profile: None,
                    cdp: None,
                    javascript_cursor: 0,
                },
            ),
            (
                999,
                RuntimeSession {
                    project_id: ProjectId(project.id.get() + 1),
                    capture_session_id: CaptureSessionId(3),
                    persistent: true,
                    profile: Some("foreign-account".into()),
                    cdp: Some(cdp.clone()),
                    javascript_cursor: 0,
                },
            ),
        ]);
        let observed =
            browser_resources(project.id, 2, &[session.clone()], &runtimes, false).unwrap();
        assert_eq!(
            serde_json::to_value(observed).unwrap(),
            json!({
                "project_id": project.id,
                "max_concurrent_browsers": 2,
                "active_persistent": 1,
                "active_ephemeral": 1,
                "available_capacity": 0,
                "cdp_port_in_use": false,
                "sessions": [{"session_id": session.id, "profile": "account1", "agent_control": true}],
            })
        );

        runtimes.remove(&(session.id.get() + 1));
        runtimes.remove(&999);
        let observed =
            browser_resources(project.id, 2, &[session.clone()], &runtimes, false).unwrap();
        assert_eq!(observed.available_capacity, 1);
        assert!(!observed.cdp_port_in_use);
        runtimes.get_mut(&session.id.get()).unwrap().cdp = Some(cdp);
        let observed =
            browser_resources(project.id, 0, &[session.clone()], &runtimes, false).unwrap();
        assert_eq!(observed.available_capacity, 0);
        assert!(!observed.sessions[0].agent_control);
        assert!(!observed.cdp_port_in_use);

        let mut unverified = session.clone();
        unverified.active_profile = None;
        assert!(browser_resources(project.id, 2, &[unverified], &runtimes, false).is_err());
        let mut mismatched = session.clone();
        mismatched.active_profile = Some("account2".into());
        assert!(browser_resources(project.id, 2, &[mismatched], &runtimes, false).is_err());
        assert!(browser_resources(project.id, 2, &[], &runtimes, false).is_err());
        runtimes.clear();
        let error = browser_resources(project.id, 2, &[session], &runtimes, false).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn browser_resource_status_wait_does_not_block_other_project_lifecycle() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "Busy local workspace".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let other_project = db
            .create_project(CreateProjectRequest {
                name: "Other local workspace".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let own = db
            .create_browser_session(project.id, Some("default".into()))
            .await
            .unwrap();
        let other = db
            .create_browser_session(other_project.id, Some("default".into()))
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            Some(directory.path().join("missing-worker.js")),
            DEFAULT_BROWSER_PROXY.into(),
            None,
            directory.path().join("profiles"),
        );
        service.runtime_sessions.lock().await.insert(
            own.id.get(),
            RuntimeSession {
                project_id: project.id,
                capture_session_id: CaptureSessionId(1),
                persistent: true,
                profile: Some("default".into()),
                cdp: None,
                javascript_cursor: 0,
            },
        );
        let operation = service.session_operation_lock(own.id).await;
        let operation_guard = operation.lock().await;
        let observation = service.active_status(project.id);
        tokio::pin!(observation);
        // The map and this test hold two references. A third means status has
        // reached the busy session's operation lock.
        tokio::time::timeout(Duration::from_secs(10), async {
            while Arc::strong_count(&operation) < 3 {
                tokio::select! {
                    result = &mut observation => panic!("status completed before waiting: {result:?}"),
                    _ = tokio::task::yield_now() => {}
                }
            }
        })
        .await
        .expect("status did not reach the busy session");
        tokio::time::timeout(
            Duration::from_secs(10),
            service.stop(other_project.id, other.id),
        )
        .await
        .expect("status blocked an unrelated project's lifecycle")
        .unwrap();
        drop(operation_guard);
        // This fixture has no live worker or directory, so normal identity
        // verification still returns its existing unavailable error.
        assert_eq!(
            observation.await.unwrap_err().code(),
            ErrorCode::Unavailable
        );
    }

    #[test]
    fn checkpoint_hash_excludes_version_and_hash_fields() {
        let mut checkpoint = Checkpoint {
            url: Some("https://example.com".into()),
            cookies: vec![json!({"name":"sid","value":"secret"})],
            ..Default::default()
        };
        let first = checkpoint_hash(&checkpoint).unwrap();
        checkpoint.version = 99;
        checkpoint.hash = "old".into();
        assert_eq!(first, checkpoint_hash(&checkpoint).unwrap());
    }

    #[tokio::test]
    async fn cdp_monitor_releases_port_when_browser_socket_closes() {
        let db = Db::open_in_memory().await.unwrap();
        let service = BrowserService::new(Arc::new(db), None, None);
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let session_id = BrowserSessionId(12345);
        service.runtime_sessions.lock().await.insert(
            session_id.get(),
            RuntimeSession {
                project_id: ProjectId(1),
                capture_session_id: CaptureSessionId(1),
                persistent: true,
                profile: Some("default".into()),
                cdp: Some(BrowserCdpInfo {
                    port,
                    endpoint: format!("http://127.0.0.1:{port}"),
                    devtools_url: String::new(),
                    hosted_devtools_url: String::new(),
                }),
                javascript_cursor: 0,
            },
        );
        service
            .cdp_reservations
            .lock()
            .unwrap()
            .insert(session_id.get(), port);
        service.monitor_cdp_port(
            session_id,
            port,
            service.session_operation_lock(session_id).await,
        );
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(service
            .cdp_reservations
            .lock()
            .unwrap()
            .contains_key(&session_id.get()));
        drop(listener);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if !service
                    .cdp_reservations
                    .lock()
                    .unwrap()
                    .contains_key(&session_id.get())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        assert!(service
            .runtime_sessions
            .lock()
            .await
            .get(&session_id.get())
            .unwrap()
            .cdp
            .is_none());
    }

    #[test]
    fn cdp_port_reservations_skip_busy_ports_and_release_on_failure() {
        let reservations = std::sync::Mutex::new(HashMap::new());
        let first = free_cdp_port(&reservations.lock().unwrap()).expect("a free port in CDP range");
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, first)).unwrap();
        let second = free_cdp_port(&reservations.lock().unwrap()).unwrap();
        assert!(second > first);
        drop(listener);
        reservations.lock().unwrap().insert(1, first);
        {
            let _reservation = CdpReservation {
                reservations: &reservations,
                session_id: 1,
                committed: false,
            };
            assert_ne!(free_cdp_port(&reservations.lock().unwrap()), Some(first));
        }
        assert_eq!(free_cdp_port(&reservations.lock().unwrap()), Some(first));
        let all: HashMap<i64, u16> = (BROWSER_CDP_PORT..=BROWSER_CDP_PORT_END)
            .map(|port| (i64::from(port), port))
            .collect();
        assert_eq!(free_cdp_port(&all), None);
    }

    #[test]
    fn cdp_details_are_bounded_and_status_makes_control_ownership_explicit() {
        let info = parse_cdp_info(Some(&json!({
            "port": 9222,
            "endpoint": "http://127.0.0.1:9222",
            "devtools_url": "http://127.0.0.1:9222/devtools/inspector.html?ws=127.0.0.1:9222/devtools/page/1",
            "hosted_devtools_url": "https://chrome-devtools-frontend.appspot.com/serve_rev/@abc/inspector.html?ws=127.0.0.1:9222/devtools/page/1"
        })), 9222)
        .unwrap();
        let handed_off = cdp_status_view(ProjectId(7), Some((9, info)));
        assert!(handed_off.active);
        assert!(!handed_off.agent_control);
        assert_eq!(handed_off.session_id, Some(BrowserSessionId(9)));
        let command = handed_off.ssh_forward_command.unwrap();
        assert!(command.starts_with("ssh -N -L 9222:127.0.0.1:9222 "));
        assert!(command.contains('@'));

        let available = cdp_status_view(ProjectId(7), None);
        assert!(!available.active);
        assert!(available.agent_control);
        assert!(parse_cdp_info(
            Some(&json!({
                "port": 9223,
                "endpoint": "http://127.0.0.1:9223",
                "devtools_url": "https://example.test/",
                "hosted_devtools_url": "https://example.test/"
            })),
            9223
        )
        .is_err());
    }

    #[test]
    fn ssh_connection_server_address_is_parsed_at_runtime() {
        assert_eq!(
            ssh_server_ip("192.0.2.10 54321 198.51.100.20 22"),
            Some("198.51.100.20".parse().unwrap())
        );
        assert_eq!(ssh_server_ip("invalid"), None);
    }

    #[test]
    fn persistent_profile_merges_origins_and_replaces_the_cookie_jar() {
        let mut profile = PersistentBrowserProfile::default();
        let first = Checkpoint {
            url: Some("https://one.test/app".into()),
            cookies: vec![json!({"name":"one","value":"1","domain":"one.test","path":"/"})],
            local_storage: BTreeMap::from([(
                "https://one.test".into(),
                BTreeMap::from([("theme".into(), "dark".into())]),
            )]),
            session_storage: BTreeMap::from([("nonce".into(), "first".into())]),
            ..Default::default()
        };
        merge_persistent_profile(&mut profile, &first);

        let second = Checkpoint {
            url: Some("https://two.test/".into()),
            cookies: vec![json!({"name":"two","value":"2","domain":"two.test","path":"/"})],
            local_storage: BTreeMap::from([(
                "https://two.test".into(),
                BTreeMap::from([("visit".into(), "2".into())]),
            )]),
            session_storage: BTreeMap::from([("nonce".into(), "second".into())]),
            ..Default::default()
        };
        merge_persistent_profile(&mut profile, &second);

        assert_eq!(profile.version, 2);
        assert_eq!(profile.last_url.as_deref(), Some("https://two.test/"));
        assert_eq!(profile.cookies.len(), 1);
        assert_eq!(profile.cookies[0]["name"], "two");
        assert_eq!(profile.local_storage["https://one.test"]["theme"], "dark");
        assert_eq!(profile.local_storage["https://two.test"]["visit"], "2");
        assert_eq!(
            profile.session_storage["https://one.test"]["nonce"],
            "first"
        );
        assert_eq!(
            profile.session_storage["https://two.test"]["nonce"],
            "second"
        );
    }

    #[tokio::test]
    async fn persistent_profile_file_round_trips_privately() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        let project_id = ProjectId(42);
        let checkpoint = Checkpoint {
            url: Some("https://example.test/".into()),
            cookies: vec![
                json!({"name":"sid","value":"secret","domain":"example.test","path":"/"}),
            ],
            local_storage: BTreeMap::from([(
                "https://example.test".into(),
                BTreeMap::from([("key".into(), "value".into())]),
            )]),
            ..Default::default()
        };

        service
            .persist_checkpoint(project_id, DEFAULT_BROWSER_PROFILE, &checkpoint)
            .await
            .unwrap();
        let loaded = service
            .load_persistent_profile(project_id, DEFAULT_BROWSER_PROFILE)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.last_url, checkpoint.url);
        assert_eq!(loaded.cookies, checkpoint.cookies);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                std::fs::metadata(service.profile_state_path(project_id, DEFAULT_BROWSER_PROFILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    fn hashed_checkpoint(value: &str) -> Checkpoint {
        let mut checkpoint = Checkpoint {
            url: Some("https://example.test/".into()),
            cookies: vec![json!({"name":"sid","value":value,"domain":"example.test","path":"/"})],
            ..Default::default()
        };
        checkpoint.hash = checkpoint_hash(&checkpoint).unwrap();
        checkpoint
    }

    #[tokio::test]
    async fn an_unchanged_checkpoint_does_not_read_the_profile_file_again() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        let project_id = ProjectId(42);
        let checkpoint = hashed_checkpoint("one");
        service
            .persist_checkpoint(project_id, DEFAULT_BROWSER_PROFILE, &checkpoint)
            .await
            .unwrap();

        // Replace the file with garbage of the same size and modification time:
        // reading it back would now fail, so success proves it was not read.
        let path = service.profile_state_path(project_id, DEFAULT_BROWSER_PROFILE);
        let written = std::fs::metadata(&path).unwrap();
        let garbage = vec![b'x'; written.len() as usize];
        std::fs::write(&path, &garbage).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(written.modified().unwrap())
            .unwrap();
        service
            .persist_checkpoint(project_id, DEFAULT_BROWSER_PROFILE, &checkpoint)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), garbage);

        // A different checkpoint is merged into what is on disk, which here is unreadable.
        let error = service
            .persist_checkpoint(
                project_id,
                DEFAULT_BROWSER_PROFILE,
                &hashed_checkpoint("two"),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::StorageError);
    }

    #[tokio::test]
    async fn a_removed_or_replaced_profile_file_is_written_again() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "profile file".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        let checkpoint = hashed_checkpoint("one");
        let path = service.profile_state_path(project.id, DEFAULT_BROWSER_PROFILE);
        service
            .persist_checkpoint(project.id, DEFAULT_BROWSER_PROFILE, &checkpoint)
            .await
            .unwrap();

        std::fs::remove_file(&path).unwrap();
        service
            .persist_checkpoint(project.id, DEFAULT_BROWSER_PROFILE, &checkpoint)
            .await
            .unwrap();
        let loaded = service
            .load_persistent_profile(project.id, DEFAULT_BROWSER_PROFILE)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.checkpoint_hash, checkpoint.hash);

        // Resetting the profile forgets what was written; the next checkpoint writes it all again.
        assert!(service.reset_project_profile(project.id).await.unwrap());
        assert!(service.profile_io.lock().await.is_empty());
        assert!(!path.exists());
        service
            .persist_checkpoint(project.id, DEFAULT_BROWSER_PROFILE, &checkpoint)
            .await
            .unwrap();
        assert!(path.is_file());
    }

    #[tokio::test]
    async fn checkpoint_versions_advance_per_session() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "versions".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db.clone(),
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        let first = db.create_browser_session(project.id, None).await.unwrap();
        let second = db.create_browser_session(project.id, None).await.unwrap();
        let value = json!({"url":"https://example.test/","_private":{}});
        for (session, expected) in [(&first, 1), (&first, 2), (&second, 1), (&first, 3)] {
            let saved = service
                .save_checkpoint(project.id, session.id, &value, "ok", None)
                .await
                .unwrap();
            assert_eq!(saved.version, expected);
        }
    }

    #[tokio::test]
    async fn named_browser_profiles_persist_independently() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "named profiles".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        service
            .create_browser_profile(project.id, "account1")
            .await
            .unwrap();
        service
            .create_browser_profile(project.id, "account2")
            .await
            .unwrap();

        let first = Checkpoint {
            url: Some("https://example.test/account1".into()),
            cookies: vec![json!({"name":"sid","value":"one"})],
            ..Default::default()
        };
        let second = Checkpoint {
            url: Some("https://example.test/account2".into()),
            cookies: vec![json!({"name":"sid","value":"two"})],
            ..Default::default()
        };
        service
            .persist_checkpoint(project.id, "account1", &first)
            .await
            .unwrap();
        service
            .persist_checkpoint(project.id, "account2", &second)
            .await
            .unwrap();

        let first_loaded = service
            .load_persistent_profile(project.id, "account1")
            .await
            .unwrap()
            .unwrap();
        let second_loaded = service
            .load_persistent_profile(project.id, "account2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_loaded.last_url, first.url);
        assert_eq!(second_loaded.last_url, second.url);
        assert_eq!(first_loaded.cookies[0]["value"], "one");
        assert_eq!(second_loaded.cookies[0]["value"], "two");
        assert_ne!(
            service.profile_state_path(project.id, "account1"),
            service.profile_state_path(project.id, "account2")
        );

        let profiles = service.browser_profiles(project.id).await.unwrap();
        assert_eq!(
            profiles
                .iter()
                .map(|profile| profile.name.as_str())
                .collect::<Vec<_>>(),
            vec!["default", "account1", "account2"]
        );
        assert!(profiles
            .iter()
            .filter(|profile| profile.name != DEFAULT_BROWSER_PROFILE)
            .all(|profile| profile.has_state));
    }

    #[tokio::test]
    async fn resetting_one_named_profile_preserves_other_identities() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "profile reset isolation".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        for (profile, url) in [
            (DEFAULT_BROWSER_PROFILE, "https://example.test/default"),
            ("account1", "https://example.test/one"),
            ("account2", "https://example.test/two"),
        ] {
            service
                .persist_checkpoint(
                    project.id,
                    profile,
                    &Checkpoint {
                        url: Some(url.into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        }

        assert!(service
            .reset_browser_profile(project.id, "account1")
            .await
            .unwrap());
        assert!(service
            .load_persistent_profile(project.id, "account1")
            .await
            .unwrap()
            .is_none());
        assert!(service
            .load_persistent_profile(project.id, "account2")
            .await
            .unwrap()
            .is_some());
        assert!(service
            .load_persistent_profile(project.id, DEFAULT_BROWSER_PROFILE)
            .await
            .unwrap()
            .is_some());
        let profiles = service.browser_profiles(project.id).await.unwrap();
        assert!(profiles.iter().any(|profile| profile.name == "account1"));
    }

    #[tokio::test]
    async fn failed_named_profile_reset_releases_its_lease() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "profile reset failure".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        let profiles_parent = service.project_profile_dir(project.id).join("profiles");
        write_private_file(&profiles_parent, b"not a directory").unwrap();

        assert!(service
            .reset_browser_profile(project.id, "account1")
            .await
            .is_err());
        assert!(!service
            .profile_leases
            .lock()
            .await
            .contains(&(project.id.get(), "account1".into())));

        std::fs::remove_file(profiles_parent).unwrap();
        service
            .create_browser_profile(project.id, "account1")
            .await
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sandbox_diagnostics_are_reported_and_worker_survives_idle() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("worker.sh");
        std::fs::write(&script, r#"
n=0
while IFS= read -r request; do
  n=$((n + 1))
  case "$n" in
    1) printf '%s\n' '{"id":1,"result":{"protocol":1,"capabilities":["profile_isolation"]}}' ;;
    *) printf '{"id":%s,"result":{"sandbox_state":"disabled_fallback","sandbox_reason":"sandbox failed at /chromium"}}\n' "$n" ;;
  esac
done
"#).unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "Sandbox status".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let mut service = BrowserService::new_with_proxy_and_ca(
            db.clone(),
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        service.node_path = Some(PathBuf::from("/bin/sh"));
        service.worker_path = Some(script);
        assert!(service.status().sandbox_state.is_none());
        service
            .call_worker(project.id, "session.start", json!({}))
            .await
            .unwrap();
        let status = service.active_status(project.id).await.unwrap();
        assert_eq!(status.sandbox_state.as_deref(), Some("disabled_fallback"));
        assert_eq!(
            status.sandbox_reason.as_deref(),
            Some("sandbox failed at /chromium")
        );
        assert_eq!(service.status().sandbox_state, status.sandbox_state);
        service.stop_project(project.id).await.unwrap();
        assert!(!service.worker_is_running(project.id).await);
        service.stop_all().await.unwrap();
        assert!(!service.worker_is_running(project.id).await);
        let restarted = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        assert!(restarted.status().sandbox_state.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_browser_cleanup_retains_ownership_until_stop_succeeds() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("worker.sh");
        std::fs::write(
            &script,
            r#"
n=0
while IFS= read -r request; do
  n=$((n + 1))
  case "$n" in
    1) printf '%s\n' '{"id":1,"result":{"protocol":1,"capabilities":["profile_isolation"]}}' ;;
    2) printf '%s\n' '{"id":2,"error":{"code":-32000,"message":"Owned browser remains in use"}}' ;;
    *) printf '{"id":%s,"result":{"stopped":true}}\n' "$n" ;;
  esac
done
"#,
        )
        .unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "Browser cleanup recovery".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        // Exercise both explicit stop and the failed-start cleanup caller.
        for failed_start in [false, true] {
            let mut service = BrowserService::new_with_proxy_and_ca(
                db.clone(),
                None,
                None,
                "http://127.0.0.1:17891".into(),
                None,
                directory.path().join("profiles"),
            );
            service.node_path = Some(PathBuf::from("/bin/sh"));
            service.worker_path = Some(script.clone());
            *service.worker_entry(project.id).await.lock().await = Some(
                WorkerProcess::spawn(Path::new("/bin/sh"), &script, None, None)
                    .await
                    .unwrap_or_else(|_| panic!("start cleanup fixture worker")),
            );
            let mut session = db
                .create_browser_session(project.id, Some("account1".into()))
                .await
                .unwrap();
            let capture = db
                .create_capture_session(CreateCaptureSession {
                    project_id: project.id,
                    browser_session_id: Some(session.id),
                    browser_action_id: None,
                    is_browser_bound: true,
                    ttl: None,
                })
                .await
                .unwrap();
            service.runtime_sessions.lock().await.insert(
                session.id.get(),
                RuntimeSession {
                    project_id: project.id,
                    capture_session_id: capture.id,
                    persistent: true,
                    profile: Some("account1".into()),
                    cdp: None,
                    javascript_cursor: 0,
                },
            );
            let lease = (project.id.get(), "account1".to_string());
            service.profile_leases.lock().await.insert(lease.clone());
            let error = if failed_start {
                service
                    .cleanup_failed_start(project.id, &mut session, capture.id)
                    .await
                    .unwrap_err()
            } else {
                service.stop(project.id, session.id).await.unwrap_err()
            };
            assert_eq!(error.code(), ErrorCode::Unavailable);
            assert!(service
                .runtime_sessions
                .lock()
                .await
                .contains_key(&session.id.get()));
            assert!(service.profile_leases.lock().await.contains(&lease));
            assert!(db
                .list_capture_sessions(project.id)
                .await
                .unwrap()
                .iter()
                .find(|candidate| candidate.id == capture.id)
                .unwrap()
                .revoked_at
                .is_none());
            assert!(service
                .delete_browser_profile(project.id, "account1")
                .await
                .is_err());
            service.stop(project.id, session.id).await.unwrap();
            assert!(!service
                .runtime_sessions
                .lock()
                .await
                .contains_key(&session.id.get()));
            assert!(!service.profile_leases.lock().await.contains(&lease));
            assert!(db
                .list_capture_sessions(project.id)
                .await
                .unwrap()
                .iter()
                .find(|candidate| candidate.id == capture.id)
                .unwrap()
                .revoked_at
                .is_some());
        }
    }

    #[test]
    fn browser_profile_names_are_path_safe() {
        for valid in ["default", "account1", "qa-user", "qa_user"] {
            validate_browser_profile_name(valid).unwrap();
        }
        for invalid in ["", "../escape", "a/b", "space name", "."] {
            assert!(validate_browser_profile_name(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn persistent_launch_requires_an_explicit_cookie_override() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "Google workspace".into(),
                target_url: "https://accounts.google.com".into(),
                advanced: None,
            })
            .await
            .unwrap();
        db.upsert_cookie_profile(
            project.id,
            crate::cookies::validate_cookie_profile(
                "https://accounts.google.com",
                "SID=project-account".into(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let stored = db
            .get_cookie_profile_for_url(project.id, "https://accounts.google.com")
            .await
            .unwrap()
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            PathBuf::from("unused-profiles"),
        );
        assert!(service
            .cookies_for_launch(project.id, true, None)
            .await
            .unwrap()
            .is_empty());
        let explicit = service
            .cookies_for_launch(
                project.id,
                true,
                Some(CookieLaunchOverride::from_profile(&stored).unwrap()),
            )
            .await
            .unwrap();
        assert_eq!(explicit[0]["value"], "project-account");
        // Raw project headers and named imports use equivalent host-only
        // identities even though their Playwright serialization differs.
        let ephemeral = service
            .cookies_for_launch(project.id, false, None)
            .await
            .unwrap();
        assert_eq!(ephemeral.len(), 1);
        assert_eq!(ephemeral[0]["name"], "SID");
        assert_eq!(ephemeral[0]["value"], "project-account");
        assert_eq!(ephemeral[0]["url"], "https://accounts.google.com/");
    }

    #[test]
    fn legacy_project_cookie_metadata_cannot_modify_persistent_state() {
        let state: PersistentBrowserProfile = serde_json::from_value(json!({
            "managed_cookie_hash":"old-seed",
            "pending_cookie_clears":[{"name":"SID", "domain":".google.com", "path":"/"}],
            "cookies":[{"name":"SID", "value":"native-account", "domain":".google.com", "path":"/"}]
        }))
        .unwrap();
        let saved = serde_json::to_value(state).unwrap();
        assert_eq!(saved["cookies"][0]["value"], "native-account");
        assert!(saved.get("managed_cookie_hash").is_none());
        assert!(saved.get("pending_cookie_clears").is_none());
    }

    #[tokio::test]
    async fn reset_profile_recovers_from_corrupt_state() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "reset profile".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            db,
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        let state_path = service.profile_state_path(project.id, DEFAULT_BROWSER_PROFILE);
        write_private_file(&state_path, b"not json").unwrap();

        assert!(service.reset_project_profile(project.id).await.unwrap());
        assert!(!service
            .profile_state_path(project.id, DEFAULT_BROWSER_PROFILE)
            .exists());
        assert!(service
            .load_persistent_profile(project.id, DEFAULT_BROWSER_PROFILE)
            .await
            .unwrap()
            .is_none());
    }

    fn named_profile(input: &str) -> StoredCookieProfile {
        let validated =
            crate::cookies::validate_named_cookie_profile("https://app.example/", input.into())
                .unwrap();
        StoredCookieProfile {
            project_id: ProjectId(1),
            host: validated.host,
            target_url: validated.target_url,
            cookie_header: validated.cookie_header,
            names: validated.names,
            managed_cookies: validated.managed_cookies,
            origins: validated.origins,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    const COOKIES_ONLY: &str = r#"[{"name":"sid","value":"v1","domain":"app.example"}]"#;

    fn with_storage(token: &str, origin: &str) -> String {
        format!(
            r#"{{"cookies":[{{"name":"sid","value":"v1","domain":"app.example"}}],
                "origins":[{{"origin":"{origin}","localStorage":[{{"name":"token","value":"{token}"}}]}}]}}"#
        )
    }

    fn saved_seed_of(plan: &CookieLaunchOverride) -> CookieSeed {
        plan.seed.clone().unwrap()
    }

    #[test]
    fn cookie_only_seed_hash_is_unchanged_by_storage_seeding() {
        let profile = named_profile(COOKIES_ONLY);
        let cookies = browser_cookies(std::slice::from_ref(&profile)).unwrap();
        let legacy = hex::encode(Sha256::digest(serde_json::to_vec(&cookies).unwrap()));
        assert_eq!(cookie_seed_hash(&cookies, &[]).unwrap(), legacy);
        // A seed saved by an older build (no `origins` key) must not look changed.
        let saved: CookieSeed = serde_json::from_value(json!({
            "name": "member", "hash": legacy, "identities": profile_cookie_identities(&profile).unwrap()
        }))
        .unwrap();
        assert!(plan_cookie_seed("member", &profile, Some(saved), false)
            .unwrap()
            .is_none());
    }

    #[test]
    fn storage_changes_reseed_and_unchanged_storage_does_not() {
        let first = named_profile(&with_storage("t1", "https://app.example"));
        let plan = plan_cookie_seed("member", &first, None, false)
            .unwrap()
            .unwrap();
        assert_eq!(plan.storage.len(), 1);
        assert!(plan.clear_origins.is_empty());
        let saved = saved_seed_of(&plan);
        assert_ne!(
            saved.hash,
            cookie_seed_hash(&plan.cookies, &[]).unwrap(),
            "storage is part of the hash"
        );
        assert_eq!(saved.origins, ["https://app.example"]);

        // Same file: nothing is written, so values the app changed survive.
        assert!(
            plan_cookie_seed("member", &first, Some(saved.clone()), false)
                .unwrap()
                .is_none()
        );
        // refresh_cookies re-applies it.
        assert!(
            plan_cookie_seed("member", &first, Some(saved.clone()), true)
                .unwrap()
                .is_some()
        );
        // Different value: reseeds.
        let changed = named_profile(&with_storage("t2", "https://app.example"));
        assert!(plan_cookie_seed("member", &changed, Some(saved), false)
            .unwrap()
            .is_some());
    }

    #[test]
    fn dropping_an_origin_clears_it_and_cookie_only_replacement_clears_all() {
        let both = named_profile(
            r#"{"origins":[{"origin":"https://app.example","localStorage":[{"name":"a","value":"1"}]},
                          {"origin":"https://idp.example","localStorage":[{"name":"b","value":"2"}]}]}"#,
        );
        let saved = saved_seed_of(
            &plan_cookie_seed("member", &both, None, false)
                .unwrap()
                .unwrap(),
        );
        assert_eq!(saved.origins.len(), 2);

        let only_app = named_profile(&with_storage("t", "https://app.example"));
        let plan = plan_cookie_seed("member", &only_app, Some(saved.clone()), false)
            .unwrap()
            .unwrap();
        assert_eq!(plan.clear_origins, ["https://idp.example"]);
        assert_eq!(
            plan.storage_params()["clear_origins"],
            json!(["https://idp.example"])
        );

        let cookie_only = named_profile(COOKIES_ONLY);
        let plan = plan_cookie_seed("member", &cookie_only, Some(saved), false)
            .unwrap()
            .unwrap();
        assert!(plan.storage.is_empty());
        assert_eq!(
            plan.clear_origins,
            ["https://app.example", "https://idp.example"]
        );
        // Nothing to write or clear: no storage_seed is sent to the worker.
        let plain = plan_cookie_seed("member", &cookie_only, None, false)
            .unwrap()
            .unwrap();
        assert!(plain.storage_params().is_null());
    }

    #[test]
    fn seeded_storage_is_persisted_and_the_checkpoint_origin_is_left_alone() {
        let mut state = PersistentBrowserProfile::default();
        state.local_storage.insert(
            "https://old.example".into(),
            BTreeMap::from([("stale".to_string(), "x".to_string())]),
        );
        state.session_storage.insert(
            "https://old.example".into(),
            BTreeMap::from([("stale".to_string(), "x".to_string())]),
        );
        state.local_storage.insert(
            "https://app.example".into(),
            BTreeMap::from([("token".to_string(), "from-app".to_string())]),
        );
        let profile = named_profile(
            r#"{"origins":[{"origin":"https://app.example","localStorage":[{"name":"token","value":"seed"}],"sessionStorage":[{"name":"csrf","value":"c"}]},
                          {"origin":"https://idp.example","sessionStorage":[{"name":"s","value":"1"}]}]}"#,
        );
        // app.example is the page the worker checkpointed: browser values win.
        apply_storage_seed(
            &mut state,
            &profile.origins,
            &["https://old.example".to_string()],
            Some("https://app.example"),
        );
        assert_eq!(
            state.local_storage["https://app.example"]["token"],
            "from-app"
        );
        assert!(!state.session_storage.contains_key("https://app.example"));
        assert_eq!(state.session_storage["https://idp.example"]["s"], "1");
        assert!(state.local_storage["https://idp.example"].is_empty());
        assert!(!state.local_storage.contains_key("https://old.example"));
        assert!(!state.session_storage.contains_key("https://old.example"));

        // Without a checkpointed origin every seeded origin is persisted.
        apply_storage_seed(&mut state, &profile.origins, &[], None);
        assert_eq!(state.local_storage["https://app.example"]["token"], "seed");
        assert_eq!(state.session_storage["https://app.example"]["csrf"], "c");

        // A later checkpoint for an origin replaces the seeded values.
        let checkpoint = Checkpoint {
            local_storage: BTreeMap::from([(
                "https://app.example".to_string(),
                BTreeMap::from([("token".to_string(), "rotated".to_string())]),
            )]),
            session_storage: BTreeMap::from([("csrf".to_string(), "c2".to_string())]),
            ..Checkpoint::default()
        };
        merge_persistent_profile(&mut state, &checkpoint);
        assert_eq!(
            state.local_storage["https://app.example"]["token"],
            "rotated"
        );
        assert_eq!(state.session_storage["https://app.example"]["csrf"], "c2");
        assert_eq!(state.session_storage["https://idp.example"]["s"], "1");
    }

    #[test]
    fn browser_cookie_import_is_host_only_and_last_duplicate_wins() {
        let profile = StoredCookieProfile {
            project_id: ProjectId(1),
            host: "example.com".into(),
            target_url: "https://example.com/".into(),
            cookie_header: "sid=old; theme=dark; sid=new".into(),
            names: vec!["sid".into(), "theme".into()],
            managed_cookies: None,
            created_at: String::new(),
            updated_at: String::new(),
            origins: Vec::new(),
        };
        let cookies = browser_cookies(&[profile]).unwrap();
        assert_eq!(cookies.len(), 2);
        assert!(cookies.iter().any(|cookie| {
            cookie["name"] == "sid"
                && cookie["value"] == "new"
                && cookie["url"] == "https://example.com/"
        }));
        let identities = profile_cookie_identities(&StoredCookieProfile {
            project_id: ProjectId(1),
            host: "example.com".into(),
            target_url: "https://example.com/".into(),
            cookie_header: "sid=value".into(),
            names: vec!["sid".into()],
            managed_cookies: None,
            created_at: String::new(),
            updated_at: String::new(),
            origins: Vec::new(),
        })
        .unwrap();
        assert_eq!(
            identities,
            vec![json!({"name":"sid","domain":"example.com","path":"/"})]
        );
    }

    #[test]
    fn browser_cookie_import_preserves_json_attributes_and_paths() {
        let validated = crate::cookies::validate_cookie_profile(
            "https://app.example.com/admin",
            r#"[{"domain":".example.com","name":"sid","path":"/","secure":true,"session":true,"value":"root"},{"domain":".example.com","expirationDate":4102444800.5,"httpOnly":true,"name":"sid","path":"/admin","sameSite":"lax","secure":true,"value":"admin"}]"#.into(),
        )
        .unwrap();
        let profile = StoredCookieProfile {
            project_id: ProjectId(1),
            host: validated.host,
            target_url: validated.target_url,
            cookie_header: validated.cookie_header,
            names: validated.names,
            managed_cookies: validated.managed_cookies,
            created_at: String::new(),
            updated_at: String::new(),
            origins: Vec::new(),
        };
        let launch_override = CookieLaunchOverride::from_profile(&profile).unwrap();
        let cookies = launch_override.cookies;
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0]["domain"], ".example.com");
        assert_eq!(cookies[0]["path"], "/");
        assert_eq!(cookies[0]["secure"], true);
        assert!(cookies[0].get("expires").is_none());
        assert_eq!(cookies[1]["path"], "/admin");
        assert_eq!(cookies[1]["httpOnly"], true);
        assert_eq!(cookies[1]["sameSite"], "Lax");
        assert_eq!(cookies[1]["expires"], 4102444800.5_f64);
        assert_eq!(launch_override.clear_cookies.len(), 2);
        assert!(launch_override
            .clear_cookies
            .iter()
            .all(|cookie| cookie.get("value").is_none()));
    }

    #[test]
    fn browser_cookie_import_deduplicates_identity_with_latest_profile_winning() {
        let make_profile = |value: &str| {
            let validated = crate::cookies::validate_cookie_profile(
                "https://app.example.com/",
                format!(
                    r#"[{{"domain":".example.com","name":"sid","path":"/","secure":true,"session":true,"value":"{value}"}}]"#
                ),
            )
            .unwrap();
            StoredCookieProfile {
                project_id: ProjectId(1),
                host: "app.example.com".into(),
                target_url: validated.target_url,
                cookie_header: validated.cookie_header,
                names: validated.names,
                managed_cookies: validated.managed_cookies,
                created_at: String::new(),
                updated_at: String::new(),
                origins: Vec::new(),
            }
        };
        let cookies = browser_cookies(&[make_profile("older"), make_profile("newer")]).unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0]["value"], "newer");
    }

    #[test]
    fn browser_cookie_import_keeps_host_and_domain_cookie_identities_distinct() {
        let validated = crate::cookies::validate_named_cookie_profile(
            "https://www.example.com",
            json!([
                {"name":"sid","value":"host","domain":"www.example.com","hostOnly":true},
                {"name":"sid","value":"domain","domain":".www.example.com","hostOnly":false},
            ])
            .to_string(),
        )
        .unwrap();
        let stored = StoredCookieProfile {
            project_id: ProjectId(1),
            host: validated.host,
            target_url: validated.target_url,
            cookie_header: validated.cookie_header,
            names: validated.names,
            managed_cookies: validated.managed_cookies,
            created_at: String::new(),
            updated_at: String::new(),
            origins: Vec::new(),
        };
        let cookies = browser_cookies(&[stored]).unwrap();
        assert_eq!(cookies.len(), 2);
        assert!(cookies
            .iter()
            .any(|cookie| cookie["domain"] == "www.example.com" && cookie["value"] == "host"));
        assert!(cookies
            .iter()
            .any(|cookie| cookie["domain"] == ".www.example.com" && cookie["value"] == "domain"));
    }

    #[test]
    fn explicit_worker_path_wins() {
        let directory = tempfile::tempdir().unwrap();
        let worker = directory.path().join("index.js");
        std::fs::write(&worker, "// worker").unwrap();
        let unused = directory.path().join("unused-data");
        assert_eq!(
            resolve_worker_path_in(Some(worker.clone()), &unused),
            Some(worker.clone())
        );
        assert!(
            !unused.exists(),
            "explicit worker discovery must not materialize default assets"
        );
        assert_eq!(resolve_worker_path(Some(worker.clone())), Some(worker));
    }

    #[test]
    fn browser_install_status_requires_the_complete_local_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let node = directory.path().join("node");
        let worker = directory.path().join("index.js");
        let playwright = directory.path().join("playwright-core");
        let chromium = directory.path().join("chromium");
        std::fs::write(&node, "node").unwrap();
        std::fs::write(&worker, "worker").unwrap();
        std::fs::create_dir(&playwright).unwrap();
        std::fs::write(&chromium, "chromium").unwrap();
        let runtime = BrowserRuntimeInspection {
            playwright_core_path: Some(playwright),
            playwright_version: Some("1.61.1".into()),
            expected_chromium_version: Some("149.0.7827.55".into()),
            chromium_path: Some(chromium),
            chromium_version: Some("153.0.8010.36".into()),
            headless: Some(false),
            ..BrowserRuntimeInspection::default()
        };

        let ready = browser_install_status(Some(&node), Some(&worker), &runtime);
        assert!(ready.node_available);
        assert!(ready.worker_available);
        assert!(ready.chromium_available);
        assert_eq!(ready.install_hint, None);
        assert_eq!(ready.playwright_version.as_deref(), Some("1.61.1"));
        assert_eq!(ready.chromium_version.as_deref(), Some("153.0.8010.36"));
        assert_eq!(ready.headless, Some(false));
        let mut compatibility = runtime.clone();
        compatibility.headless = Some(true);
        compatibility.headless_compatibility = Some(true);
        compatibility.compatibility_error =
            Some("Headless compatibility dependencies missing".into());
        let missing_dependency = browser_install_status(Some(&node), Some(&worker), &compatibility);
        assert!(!missing_dependency.worker_available);
        assert_eq!(missing_dependency.headless_compatibility, Some(true));
        assert!(missing_dependency
            .install_hint
            .unwrap()
            .contains("compatibility"));
        assert_eq!(
            ready.expected_chromium_version.as_deref(),
            Some("149.0.7827.55")
        );

        let missing_playwright = browser_install_status(
            Some(&node),
            Some(&worker),
            &BrowserRuntimeInspection::default(),
        );
        assert!(!missing_playwright.worker_available);
        assert!(missing_playwright
            .install_hint
            .as_deref()
            .is_some_and(|hint| hint.contains("playwright-core missing")));
    }

    #[test]
    fn browser_installation_inspection_does_not_materialize_the_worker() {
        let directory = tempfile::tempdir().unwrap();
        let expected_worker = browser_worker_path(directory.path());
        let config = Config {
            data_dir: directory.path().to_path_buf(),
            browser_worker_path: Some(directory.path().join("missing-worker.js")),
            ..Config::default()
        };

        assert!(!expected_worker.exists());
        let _ = inspect_browser_installation(&config);
        assert!(!expected_worker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn runtime_inspection_uses_worker_metadata_and_distinguishes_probe_failures() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::Builder::new()
            .prefix("huntproxy-runtime-contract-")
            .tempdir()
            .unwrap();
        let node = directory.path().join("node");
        let worker = directory.path().join("index.js");
        let arguments = directory.path().join("arguments");
        let selected = directory.path().join("selected");
        std::fs::write(&worker, "// worker").unwrap();
        let metadata = json!({
            "playwright_core_path": directory.path(),
            "playwright_version": "1.61.1",
            "expected_chromium_version": "149.0.7827.55",
            "chromium_path": &node,
            "chromium_version": "153.0.8010.36",
            "headless": false,
        });
        std::fs::write(
            &node,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s\\n' \"$HUNTPROXY_PLAYWRIGHT_CORE_PATH\" \"$HUNTPROXY_CHROME_EXECUTABLE\" > '{}'\nprintf '%s\\n' '{}'\n",
                arguments.display(),
                selected.display(),
                metadata,
            ),
        )
        .unwrap();
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o700)).unwrap();

        let runtime = inspect_browser_runtime(Some(&node), Some(&worker));
        assert_eq!(runtime.chromium_path.as_deref(), Some(node.as_path()));
        assert_eq!(runtime.playwright_version.as_deref(), Some("1.61.1"));
        assert_eq!(runtime.chromium_version.as_deref(), Some("153.0.8010.36"));
        assert_eq!(runtime.headless, Some(false));
        assert_eq!(
            std::fs::read_to_string(&arguments).unwrap(),
            format!("{}\n--inspect-runtime\n", worker.display())
        );

        let playwright = directory.path().join("selected-playwright");
        let chromium = directory.path().join("selected-chromium");
        inspect_browser_runtime_with_paths(
            Some(&node),
            Some(&worker),
            Some(&playwright),
            Some(&chromium),
        );
        assert_eq!(
            std::fs::read_to_string(&selected).unwrap(),
            format!("{}\n{}\n", playwright.display(), chromium.display())
        );

        std::fs::write(&node, "#!/bin/sh\nprintf 'invalid response'\n").unwrap();
        let failed = inspect_browser_runtime(Some(&node), Some(&worker));
        let status = browser_install_status(Some(&node), Some(&worker), &failed);
        assert!(!status.worker_available);
        assert!(status
            .install_hint
            .unwrap()
            .contains("runtime inspection failed"));
    }

    #[test]
    fn chromium_profile_requires_real_browser_state() {
        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("chromium");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        assert!(!chromium_profile_has_state(&profile));

        std::fs::write(profile.join("Default").join("Preferences"), "{}").unwrap();
        assert!(chromium_profile_has_state(&profile));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn aliased_profile_directories_cannot_claim_another_identity() {
        let directory = tempfile::Builder::new()
            .prefix("huntproxy-profile-owner-")
            .tempdir()
            .unwrap();
        let service = BrowserService::new_with_proxy_and_ca(
            Arc::new(Db::open_in_memory().await.unwrap()),
            None,
            None,
            DEFAULT_BROWSER_PROXY.into(),
            None,
            directory.path().join("profiles"),
        );
        let first = service.chromium_profile_dir(ProjectId(1), "acc1").unwrap();
        std::os::unix::fs::symlink(&first, service.chromium_profile_path(ProjectId(1), "acc2"))
            .unwrap();
        let error = service
            .chromium_profile_dir(ProjectId(1), "acc2")
            .unwrap_err();
        assert!(error.to_string().contains("different identity"));
        assert_eq!(
            first,
            service.chromium_profile_dir(ProjectId(1), "acc1").unwrap()
        );
    }

    #[test]
    fn worker_identity_requires_exact_session_profile_and_directory() {
        let identity = json!({
            "session_id": 8, "requested_profile": "acc2", "active_profile": "acc2",
            "profile_dir": "/profiles/acc2", "persistent": true,
        });
        verify_worker_identity(
            &identity,
            BrowserSessionId(8),
            Some("acc2"),
            Some(Path::new("/profiles/acc2")),
        )
        .unwrap();
        for field in [
            "session_id",
            "requested_profile",
            "active_profile",
            "profile_dir",
            "persistent",
        ] {
            let mut missing = identity.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(verify_worker_identity(
                &missing,
                BrowserSessionId(8),
                Some("acc2"),
                Some(Path::new("/profiles/acc2"))
            )
            .is_err());
        }
        assert!(verify_worker_identity(
            &identity,
            BrowserSessionId(7),
            Some("acc2"),
            Some(Path::new("/profiles/acc2"))
        )
        .is_err());
        assert!(verify_worker_identity(
            &identity,
            BrowserSessionId(8),
            Some("acc1"),
            Some(Path::new("/profiles/acc2"))
        )
        .is_err());
        assert!(verify_worker_identity(
            &identity,
            BrowserSessionId(8),
            Some("acc2"),
            Some(Path::new("/profiles/acc1"))
        )
        .is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn queued_start_does_not_launch_after_worker_interruption() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("worker.sh");
        let spawns = directory.path().join("spawns");
        let failing = directory.path().join("failing");
        let launches = directory.path().join("launches");
        std::fs::write(
            &script,
            format!(
                r#"
printf 'spawn\n' >> '{}'
n=0
while IFS= read -r request; do
  n=$((n + 1))
  case "$request" in
    *'"method":"hello"'*) printf '%s\n' '{{"id":1,"result":{{"protocol":1,"capabilities":["profile_isolation"]}}}}' ;;
    *'"method":"fail"'*) : > '{}'; sleep 10 ;;
    *'"method":"session.start"'*)
      : >> '{}'
      session=$(printf '%s\n' "$request" | sed -n 's/.*"session_id":\([0-9][0-9]*\).*/\1/p')
      printf '{{"id":%s,"result":{{"session_id":%s,"requested_profile":null,"active_profile":null,"profile_dir":null,"persistent":false,"checkpoint":{{"url":"about:blank","_private":{{}}}}}}}}\n' "$n" "$session" ;;
    *'"method":"session.action"'*) printf '{{"id":%s,"result":{{"ok":true,"checkpoint":{{"url":"about:blank","_private":{{}}}}}}}}\n' "$n" ;;
    *'"method":"session.javascript_files"'*) printf '{{"id":%s,"result":{{"files":[],"cursor":0}}}}\n' "$n" ;;
    *) printf '{{"id":%s,"result":{{"stopped":true}}}}\n' "$n" ;;
  esac
done
"#,
                spawns.display(),
                failing.display(),
                launches.display(),
            ),
        )
        .unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "Queued browser start".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let mut service = BrowserService::new_with_proxy_and_ca(
            db.clone(),
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        service.node_path = Some(PathBuf::from("/bin/sh"));
        service.worker_path = Some(script.clone());
        service.runtime.playwright_core_path = Some(directory.path().to_path_buf());
        service.runtime.chromium_path = Some(PathBuf::from("/bin/sh"));
        service.runtime.compatibility_error = None;
        let mut existing = db.create_browser_session(project.id, None).await.unwrap();
        existing.state = BrowserSessionState::Ready;
        db.update_browser_session(&existing).await.unwrap();
        let existing_capture = db
            .create_capture_session(CreateCaptureSession {
                project_id: project.id,
                browser_session_id: Some(existing.id),
                browser_action_id: None,
                is_browser_bound: true,
                ttl: None,
            })
            .await
            .unwrap();
        service.runtime_sessions.lock().await.insert(
            existing.id.get(),
            RuntimeSession {
                project_id: project.id,
                capture_session_id: existing_capture.id,
                persistent: false,
                profile: None,
                cdp: None,
                javascript_cursor: 0,
            },
        );
        let mut worker = WorkerProcess::spawn(Path::new("/bin/sh"), &script, None, None)
            .await
            .unwrap_or_else(|_| panic!("start fixture worker"));
        worker.rpc_timeout = Duration::from_secs(4);
        *service.worker_entry(project.id).await.lock().await = Some(worker);
        let service = Arc::new(service);
        let failing_call = {
            let service = service.clone();
            tokio::spawn(async move { service.call_worker(project.id, "fail", json!({})).await })
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            while !failing.is_file() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fixture did not receive the failing request");
        let queued_action = {
            let service = service.clone();
            tokio::spawn(async move {
                let action = serde_json::from_value(json!({"type":"snapshot"})).unwrap();
                service.action(project.id, existing.id, action).await
            })
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if db
                    .get_browser_session(project.id, existing.id)
                    .await
                    .unwrap()
                    .state
                    == BrowserSessionState::Busy
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("action did not reach the worker while it was busy");
        let queued_start = {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .start_ephemeral(project.id, "about:blank".into())
                    .await
            })
        };
        let session_id = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(id) = service
                    .runtime_sessions
                    .lock()
                    .await
                    .keys()
                    .copied()
                    .find(|id| *id != existing.id.get())
                {
                    break BrowserSessionId(id);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("start did not register while the worker was busy");
        assert_eq!(
            failing_call.await.unwrap().unwrap_err().code(),
            ErrorCode::Timeout
        );
        assert_eq!(
            queued_start.await.unwrap().unwrap_err().code(),
            ErrorCode::Unavailable
        );
        assert_eq!(
            queued_action.await.unwrap().unwrap_err().code(),
            ErrorCode::Unavailable
        );
        let interrupted = db
            .get_browser_session(project.id, session_id)
            .await
            .unwrap();
        assert_eq!(interrupted.state, BrowserSessionState::Interrupted);
        assert_eq!(
            interrupted.checkpoint_status.as_deref(),
            Some("worker_interrupted")
        );
        assert!(!service
            .runtime_sessions
            .lock()
            .await
            .contains_key(&session_id.get()));
        let existing_after = db
            .get_browser_session(project.id, existing.id)
            .await
            .unwrap();
        assert_eq!(existing_after.state, BrowserSessionState::Interrupted);
        assert_eq!(
            existing_after.checkpoint_status.as_deref(),
            Some("worker_interrupted")
        );
        let checkpoint = json!({"checkpoint":{"url":"about:blank","_private":{}}});
        assert_eq!(
            service
                .save_cookie_checkpoint(project.id, existing.id, &checkpoint)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::Unavailable
        );
        let existing_after = db
            .get_browser_session(project.id, existing.id)
            .await
            .unwrap();
        assert_eq!(existing_after.state, BrowserSessionState::Interrupted);
        assert_eq!(
            existing_after.checkpoint_status.as_deref(),
            Some("worker_interrupted")
        );
        let captures = db.list_capture_sessions(project.id).await.unwrap();
        assert_eq!(captures.len(), 2);
        assert!(captures.iter().all(|capture| capture.revoked_at.is_some()));
        assert_eq!(std::fs::read_to_string(&spawns).unwrap().lines().count(), 1);
        assert!(!launches.exists());

        // A fresh start is still allowed after the interrupted request completes.
        let active = service
            .start_ephemeral(project.id, "about:blank".into())
            .await
            .unwrap();
        assert_eq!(active.state, BrowserSessionState::Ready);
        assert!(service
            .runtime_sessions
            .lock()
            .await
            .contains_key(&active.id.get()));
        assert_eq!(std::fs::read_to_string(&spawns).unwrap().lines().count(), 2);
        assert!(launches.exists());
        let action = serde_json::from_value(json!({"type":"snapshot"})).unwrap();
        assert!(
            service
                .action(project.id, active.id, action)
                .await
                .unwrap()
                .ok
        );
        service.stop(project.id, active.id).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn worker_timeout_interrupts_only_its_project() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("worker.sh");
        std::fs::write(&script, r#"
while IFS= read -r request; do
  case "$request" in
    *'"method":"hello"'*) printf '%s\n' '{"id":1,"result":{"protocol":1,"capabilities":["profile_isolation"]}}' ;;
    *'"method":"fail"'*) sleep 2 ;;
    *) printf '%s\n' '{"id":2,"result":{"ok":true}}' ;;
  esac
done
"#).unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let mut projects = Vec::new();
        for name in ["First worker", "Second worker"] {
            projects.push(
                db.create_project(CreateProjectRequest {
                    name: name.into(),
                    target_url: "https://example.test".into(),
                    advanced: None,
                })
                .await
                .unwrap(),
            );
        }
        let mut service = BrowserService::new_with_proxy_and_ca(
            db.clone(),
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        service.node_path = Some(PathBuf::from("/bin/sh"));
        service.worker_path = Some(script);
        let mut ids = Vec::new();
        for project in &projects {
            let session = db.create_browser_session(project.id, None).await.unwrap();
            let capture = db
                .create_capture_session(CreateCaptureSession {
                    project_id: project.id,
                    browser_session_id: Some(session.id),
                    browser_action_id: None,
                    is_browser_bound: true,
                    ttl: None,
                })
                .await
                .unwrap();
            service.runtime_sessions.lock().await.insert(
                session.id.get(),
                RuntimeSession {
                    project_id: project.id,
                    capture_session_id: capture.id,
                    persistent: false,
                    profile: None,
                    cdp: None,
                    javascript_cursor: 0,
                },
            );
            ids.push(session.id);
        }
        service
            .cdp_reservations
            .lock()
            .unwrap()
            .insert(ids[0].get(), 9222);
        service
            .cdp_reservations
            .lock()
            .unwrap()
            .insert(ids[1].get(), 9223);
        service
            .call_worker(projects[1].id, "ok", json!({}))
            .await
            .unwrap();
        let entry = service.worker_entry(projects[0].id).await;
        let mut fixture = WorkerProcess::spawn(
            Path::new("/bin/sh"),
            service.worker_path.as_deref().unwrap(),
            None,
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("start timeout fixture"));
        fixture.rpc_timeout = Duration::from_millis(50);
        *entry.lock().await = Some(fixture);
        let error = service
            .call_worker(projects[0].id, "fail", json!({}))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Timeout);
        assert!(!service
            .runtime_sessions
            .lock()
            .await
            .contains_key(&ids[0].get()));
        assert!(service
            .runtime_sessions
            .lock()
            .await
            .contains_key(&ids[1].get()));
        assert!(service.worker_is_running(projects[1].id).await);
        assert!(!service
            .cdp_reservations
            .lock()
            .unwrap()
            .contains_key(&ids[0].get()));
        assert_eq!(
            service.cdp_reservations.lock().unwrap().get(&ids[1].get()),
            Some(&9223)
        );
        service.force_stop_all().await;
    }

    /// A fake worker that answers `session.slow` a second late and out of
    /// order, never answers `session.hang`, and answers `session.abort` only
    /// when `abort_answers`. It counts its starts in `<script>.spawns` and
    /// marks a slow request's arrival in `<script>.slow`.
    #[cfg(unix)]
    fn session_lane_worker(abort_answers: bool) -> String {
        let abort = if abort_answers {
            r#"printf '{"id":%s,"result":{"aborted":true}}\n' "$n""#
        } else {
            ":"
        };
        r#"
printf 'spawn\n' >> "$0.spawns"
n=0
while IFS= read -r request; do
  n=$((n + 1))
  case "$request" in
    *'"method":"hello"'*) printf '%s\n' '{"id":1,"result":{"protocol":1,"capabilities":["profile_isolation"]}}' ;;
    *'"method":"session.slow"'*) : > "$0.slow"; ( sleep 1; printf '{"id":%s,"result":{"slow":true}}\n' "$n" ) & ;;
    *'"method":"session.hang"'*) ;;
    *'"method":"session.abort"'*) @ABORT@ ;;
    *) printf '{"id":%s,"result":{"quick":true}}\n' "$n" ;;
  esac
done
"#
        .replace("@ABORT@", abort)
    }

    /// Two ready sessions of one project on one started fake worker.
    #[cfg(unix)]
    struct SessionLanes {
        service: Arc<BrowserService>,
        db: Arc<Db>,
        project_id: ProjectId,
        sessions: [BrowserSessionId; 2],
        script: PathBuf,
        _directory: tempfile::TempDir,
    }

    #[cfg(unix)]
    impl SessionLanes {
        async fn start(abort_answers: bool, rpc_timeout: Duration) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let script = directory.path().join("worker.sh");
            std::fs::write(&script, session_lane_worker(abort_answers)).unwrap();
            let db = Arc::new(Db::open_in_memory().await.unwrap());
            let project = db
                .create_project(CreateProjectRequest {
                    name: "Session lanes".into(),
                    target_url: "https://example.test".into(),
                    advanced: None,
                })
                .await
                .unwrap();
            let mut service = BrowserService::new_with_proxy_and_ca(
                db.clone(),
                None,
                None,
                "http://127.0.0.1:17891".into(),
                None,
                directory.path().join("profiles"),
            );
            service.node_path = Some(PathBuf::from("/bin/sh"));
            service.worker_path = Some(script.clone());
            let mut sessions = Vec::new();
            for _ in 0..2 {
                let mut session = db.create_browser_session(project.id, None).await.unwrap();
                session.state = BrowserSessionState::Ready;
                db.update_browser_session(&session).await.unwrap();
                let capture = db
                    .create_capture_session(CreateCaptureSession {
                        project_id: project.id,
                        browser_session_id: Some(session.id),
                        browser_action_id: None,
                        is_browser_bound: true,
                        ttl: None,
                    })
                    .await
                    .unwrap();
                service.runtime_sessions.lock().await.insert(
                    session.id.get(),
                    RuntimeSession {
                        project_id: project.id,
                        capture_session_id: capture.id,
                        persistent: false,
                        profile: None,
                        cdp: None,
                        javascript_cursor: 0,
                    },
                );
                sessions.push(session.id);
            }
            let mut worker = WorkerProcess::spawn(Path::new("/bin/sh"), &script, None, None)
                .await
                .unwrap_or_else(|_| panic!("start fixture worker"));
            worker.rpc_timeout = rpc_timeout;
            *service.worker_entry(project.id).await.lock().await = Some(worker);
            Self {
                service: Arc::new(service),
                db,
                project_id: project.id,
                sessions: [sessions[0], sessions[1]],
                script,
                _directory: directory,
            }
        }

        async fn call(&self, method: &str, session: BrowserSessionId) -> DomainResult<Value> {
            self.service
                .call_worker(
                    self.project_id,
                    method,
                    json!({"session_id": session.get()}),
                )
                .await
        }

        fn spawns(&self) -> usize {
            std::fs::read_to_string(self.script.with_extension("sh.spawns"))
                .unwrap_or_default()
                .lines()
                .count()
        }

        async fn is_attached(&self, session: BrowserSessionId) -> bool {
            self.service
                .runtime_sessions
                .lock()
                .await
                .contains_key(&session.get())
        }

        async fn session(&self, session: BrowserSessionId) -> BrowserSession {
            self.db
                .get_browser_session(self.project_id, session)
                .await
                .unwrap()
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_slow_session_call_holds_up_no_other_session() {
        let lanes = SessionLanes::start(true, Duration::from_secs(5)).await;
        let [slow, other] = lanes.sessions;
        let slow_call = {
            let service = lanes.service.clone();
            let project_id = lanes.project_id;
            tokio::spawn(async move {
                service
                    .call_worker(
                        project_id,
                        "session.slow",
                        json!({"session_id": slow.get()}),
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            while !lanes.script.with_extension("sh.slow").is_file() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fixture did not receive the slow request");
        // Answered while the slow call still waits, and each caller gets its
        // own answer although they arrive out of order.
        assert_eq!(
            lanes.call("session.quick", other).await.unwrap(),
            json!({"quick": true})
        );
        assert!(!slow_call.is_finished());
        assert_eq!(slow_call.await.unwrap().unwrap(), json!({"slow": true}));
        assert_eq!(lanes.spawns(), 1);
        lanes.service.force_stop_all().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_session_call_that_times_out_interrupts_only_its_session() {
        let lanes = SessionLanes::start(true, Duration::from_secs(1)).await;
        let [stuck, other] = lanes.sessions;
        let error = lanes.call("session.hang", stuck).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::Timeout);
        let interrupted = lanes.session(stuck).await;
        assert_eq!(interrupted.state, BrowserSessionState::Interrupted);
        assert_eq!(
            interrupted.checkpoint_status.as_deref(),
            Some("session_timed_out")
        );
        assert!(!lanes.is_attached(stuck).await);
        // The other session keeps its browser on the same worker.
        assert!(lanes.is_attached(other).await);
        assert_eq!(lanes.session(other).await.state, BrowserSessionState::Ready);
        assert_eq!(
            lanes.call("session.quick", other).await.unwrap(),
            json!({"quick": true})
        );
        assert_eq!(lanes.spawns(), 1);
        assert_eq!(
            lanes.call("session.quick", stuck).await.unwrap_err().code(),
            ErrorCode::Unavailable
        );
        lanes.service.force_stop_all().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_worker_that_cannot_abort_a_session_is_replaced() {
        let lanes = SessionLanes::start(false, Duration::from_secs(1)).await;
        let [stuck, other] = lanes.sessions;
        let error = lanes.call("session.hang", stuck).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::Timeout);
        for session in [stuck, other] {
            assert!(!lanes.is_attached(session).await);
            let interrupted = lanes.session(session).await;
            assert_eq!(interrupted.state, BrowserSessionState::Interrupted);
            assert_eq!(
                interrupted.checkpoint_status.as_deref(),
                Some("worker_interrupted")
            );
        }
        assert!(!lanes.service.worker_is_running(lanes.project_id).await);
        lanes.service.force_stop_all().await;
    }

    /// A service with one ready browser session whose worker is a shell
    /// script. The script appends every request to `requests.log` and answers
    /// with the given `case` arms, where `@DIR@` is the fixture directory.
    #[cfg(unix)]
    struct ScriptedSession {
        service: Arc<BrowserService>,
        db: Arc<Db>,
        project_id: ProjectId,
        session_id: BrowserSessionId,
        directory: tempfile::TempDir,
    }

    #[cfg(unix)]
    impl ScriptedSession {
        async fn start(arms: &str) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let script = directory.path().join("worker.sh");
            let body = r#"
n=0
while IFS= read -r request; do
  n=$((n + 1))
  printf '%s\n' "$request" >> '@DIR@/requests.log'
  case "$request" in
    *'"method":"hello"'*) printf '%s\n' '{"id":1,"result":{"protocol":1,"capabilities":["profile_isolation"]}}' ;;
@ARMS@
    *) printf '{"id":%s,"result":{}}\n' "$n" ;;
  esac
done
"#;
            std::fs::write(
                &script,
                body.replace("@ARMS@", arms)
                    .replace("@DIR@", &directory.path().display().to_string()),
            )
            .unwrap();
            let db = Arc::new(Db::open_in_memory().await.unwrap());
            let project = db
                .create_project(CreateProjectRequest {
                    name: "Scripted worker".into(),
                    target_url: "https://app.test".into(),
                    advanced: None,
                })
                .await
                .unwrap();
            let mut service = BrowserService::new_with_proxy_and_ca(
                db.clone(),
                None,
                None,
                "http://127.0.0.1:17891".into(),
                None,
                directory.path().join("profiles"),
            );
            service.node_path = Some(PathBuf::from("/bin/sh"));
            service.worker_path = Some(script.clone());
            let mut session = db.create_browser_session(project.id, None).await.unwrap();
            session.state = BrowserSessionState::Ready;
            db.update_browser_session(&session).await.unwrap();
            let capture = db
                .create_capture_session(CreateCaptureSession {
                    project_id: project.id,
                    browser_session_id: Some(session.id),
                    browser_action_id: None,
                    is_browser_bound: true,
                    ttl: None,
                })
                .await
                .unwrap();
            service.runtime_sessions.lock().await.insert(
                session.id.get(),
                RuntimeSession {
                    project_id: project.id,
                    capture_session_id: capture.id,
                    persistent: false,
                    profile: None,
                    cdp: None,
                    javascript_cursor: 0,
                },
            );
            let worker = WorkerProcess::spawn(Path::new("/bin/sh"), &script, None, None)
                .await
                .unwrap_or_else(|_| panic!("start scripted worker"));
            *service.worker_entry(project.id).await.lock().await = Some(worker);
            Self {
                service: Arc::new(service),
                db,
                project_id: project.id,
                session_id: session.id,
                directory,
            }
        }

        async fn run(&self, action: Value) -> DomainResult<ActionResult> {
            let action = serde_json::from_value(action).unwrap();
            self.service
                .action(self.project_id, self.session_id, action)
                .await
        }

        /// The requests the worker received for one method, in order.
        fn requests(&self, method: &str) -> Vec<Value> {
            std::fs::read_to_string(self.directory.path().join("requests.log"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .filter(|request| request["method"] == method)
                .collect()
        }

        /// The `after` cursor of every JavaScript file request so far.
        fn javascript_cursors_asked(&self) -> Vec<Option<u64>> {
            self.requests("session.javascript_files")
                .iter()
                .map(|request| request["params"]["after"].as_u64())
                .collect()
        }

        async fn recorded_javascript_urls(&self) -> Vec<String> {
            let (records, _) = self
                .db
                .list_javascript_files(self.project_id, None, Some("app.test".into()), 20)
                .await
                .unwrap();
            let mut urls: Vec<_> = records.into_iter().map(|record| record.url).collect();
            urls.sort();
            urls
        }
    }

    #[cfg(unix)]
    fn scripted_javascript_file(name: &str) -> String {
        format!(
            r#"{{"url":"https://app.test/{name}.js","path":"/{name}.js","host":"app.test","mime":"application/javascript","status_code":200,"source_page_url":"https://app.test/"}}"#
        )
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn javascript_files_are_recorded_once_and_asked_for_from_the_last_cursor() {
        let arms = r#"
    *'"method":"session.action"'*) printf '{"id":%s,"result":{"ok":true,"checkpoint":{"url":"https://app.test/","_private":{}}}}\n' "$n" ;;
    *'"method":"session.javascript_files"'*)
      after=$(printf '%s\n' "$request" | sed -n 's/.*"after":\([0-9][0-9]*\).*/\1/p')
      case "${after:-none}" in
        0) printf '{"id":%s,"result":{"files":[@A@,@B@],"cursor":2}}\n' "$n" ;;
        2) printf '{"id":%s,"result":{"files":[@C@],"cursor":3}}\n' "$n" ;;
        3) printf '{"id":%s,"result":{"files":[],"cursor":3}}\n' "$n" ;;
        *) printf '{"id":%s,"result":{"files":[@A@,@B@,@C@],"cursor":3}}\n' "$n" ;;
      esac ;;"#
            .replace("@A@", &scripted_javascript_file("a"))
            .replace("@B@", &scripted_javascript_file("b"))
            .replace("@C@", &scripted_javascript_file("c"));
        let fixture = ScriptedSession::start(&arms).await;
        for _ in 0..3 {
            fixture.run(json!({"type": "snapshot"})).await.unwrap();
        }
        // Asking for the session's files returns all of them, whatever was recorded.
        let all = fixture
            .service
            .javascript_files(fixture.project_id, fixture.session_id)
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(
            fixture.javascript_cursors_asked(),
            [Some(0), Some(2), Some(3), None]
        );
        assert_eq!(
            fixture.recorded_javascript_urls().await,
            ["a", "b", "c"].map(|name| format!("https://app.test/{name}.js"))
        );
        let runtimes = fixture.service.runtime_sessions.lock().await;
        assert_eq!(runtimes[&fixture.session_id.get()].javascript_cursor, 3);
        drop(runtimes);
        fixture.service.force_stop_all().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn javascript_files_without_a_page_are_offered_again_until_recorded() {
        let arms = r#"
    *'"method":"session.action"'*)
      if [ -e '@DIR@/online' ]; then url='https://app.test/'; else url='about:blank'; fi
      printf '{"id":%s,"result":{"ok":true,"checkpoint":{"url":"%s","_private":{}}}}\n' "$n" "$url" ;;
    *'"method":"session.javascript_files"'*)
      after=$(printf '%s\n' "$request" | sed -n 's/.*"after":\([0-9][0-9]*\).*/\1/p')
      if [ "${after:-0}" -lt 1 ]; then
        printf '{"id":%s,"result":{"files":[{"url":"https://app.test/a.js","path":"/a.js","host":"app.test","mime":null,"status_code":200,"source_page_url":null}],"cursor":1}}\n' "$n"
      else
        printf '{"id":%s,"result":{"files":[],"cursor":1}}\n' "$n"
      fi ;;"#;
        let fixture = ScriptedSession::start(arms).await;
        // On about:blank the file has no page to be attributed to.
        for _ in 0..2 {
            fixture.run(json!({"type": "snapshot"})).await.unwrap();
        }
        assert!(fixture.recorded_javascript_urls().await.is_empty());
        std::fs::write(fixture.directory.path().join("online"), "").unwrap();
        for _ in 0..2 {
            fixture.run(json!({"type": "snapshot"})).await.unwrap();
        }
        assert_eq!(
            fixture.javascript_cursors_asked(),
            [Some(0), Some(0), Some(0), Some(1)]
        );
        assert_eq!(
            fixture.recorded_javascript_urls().await,
            ["https://app.test/a.js"]
        );
        fixture.service.force_stop_all().await;
    }

    #[cfg(unix)]
    const SCRIPTED_EVENT_WAIT: &str = r#"
    *'"method":"session.events_wait"'*)
      printf 'x\n' >> '@DIR@/waits'
      sleep 0.05
      if [ "$(wc -l < '@DIR@/waits')" -ge @READY_AFTER@ ]; then ready=true; else ready=false; fi
      printf '{"id":%s,"result":{"ready":%s}}\n' "$n" "$ready" ;;
    *'"method":"session.action"'*) printf '{"id":%s,"result":{"ok":true,"message":"browser events read","data":{"events":[]},"checkpoint":{"url":"about:blank","_private":{}}}}\n' "$n" ;;
    *'"method":"session.javascript_files"'*) printf '{"id":%s,"result":{"files":[],"cursor":0}}\n' "$n" ;;"#;

    #[cfg(unix)]
    #[tokio::test]
    async fn event_waits_are_short_worker_requests_followed_by_one_action() {
        let fixture =
            ScriptedSession::start(&SCRIPTED_EVENT_WAIT.replace("@READY_AFTER@", "3")).await;
        let started = std::time::Instant::now();
        let result = fixture
            .run(json!({"type": "events", "wait_ms": 20_000, "kinds": ["page_error"]}))
            .await
            .unwrap();
        assert!(result.ok);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the wait ends with the first event, not at its deadline"
        );
        let waits = fixture.requests("session.events_wait");
        assert_eq!(waits.len(), 3);
        for wait in &waits {
            let params = &wait["params"];
            assert!(params["wait_ms"].as_u64().unwrap() <= 100);
            assert_eq!(params["session_id"], fixture.session_id.get());
            assert_eq!(params["action"]["type"], "events");
            assert_eq!(params["action"]["kinds"], json!(["page_error"]));
        }
        // However long the wait took, the action and its checkpoint happen once.
        assert_eq!(fixture.requests("session.action").len(), 1);

        fixture.run(json!({"type": "events"})).await.unwrap();
        assert_eq!(fixture.requests("session.events_wait").len(), 3);
        assert_eq!(fixture.requests("session.action").len(), 2);
        fixture.service.force_stop_all().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_event_wait_without_events_ends_at_its_deadline() {
        let fixture =
            ScriptedSession::start(&SCRIPTED_EVENT_WAIT.replace("@READY_AFTER@", "1000")).await;
        let started = std::time::Instant::now();
        fixture
            .run(json!({"type": "events", "wait_ms": 350}))
            .await
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(350));
        // Sliced, whatever each round trip costs on a busy machine: no
        // request asks for more than a slice, and together they cover the wait.
        let asked = fixture
            .requests("session.events_wait")
            .iter()
            .map(|request| request["params"]["wait_ms"].as_u64().unwrap())
            .collect::<Vec<_>>();
        assert!(
            asked
                .iter()
                .all(|&ms| (1..=EVENT_WAIT_SLICE.as_millis() as u64).contains(&ms)),
            "{asked:?}"
        );
        assert!(asked.len() <= 8, "{asked:?}");
        assert_eq!(fixture.requests("session.action").len(), 1);
        fixture.service.force_stop_all().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn other_requests_are_served_between_event_wait_slices() {
        let fixture =
            ScriptedSession::start(&SCRIPTED_EVENT_WAIT.replace("@READY_AFTER@", "1000")).await;
        let waiting = {
            let service = fixture.service.clone();
            let (project_id, session_id) = (fixture.project_id, fixture.session_id);
            tokio::spawn(async move {
                let action = serde_json::from_value(json!({"type": "events", "wait_ms": 3_000}));
                service
                    .action(project_id, session_id, action.unwrap())
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        let started = std::time::Instant::now();
        fixture
            .service
            .call_worker(
                fixture.project_id,
                "session.status",
                json!({"session_id": fixture.session_id.get()}),
            )
            .await
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(1_500),
            "a request made during a 3 s event wait waited {:?}",
            started.elapsed()
        );
        waiting.await.unwrap().unwrap();
        fixture.service.force_stop_all().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn snapshot_requests_are_clamped_and_whatever_the_worker_returns_fits() {
        let arms = r#"
    *'"method":"session.action"'*) printf '{"id":%s,"result":' "$n"; cat '@DIR@/result.json'; printf '}\n' ;;
    *'"method":"session.javascript_files"'*) printf '{"id":%s,"result":{"files":[],"cursor":0}}\n' "$n" ;;"#;
        let fixture = ScriptedSession::start(arms).await;
        // A worker that ignores max_bytes and sends a whole 300 KB page.
        let page = hostile_page(300_000);
        let result = json!({
            "ok": true, "untrusted": true, "message": "snapshot captured",
            "data": {"format": "dom", "content": page, "truncated": false, "total_bytes": page.len()},
            "browser": {"session_id": fixture.session_id.get(), "profile": null, "runtime_generation": 1, "page_id": 1},
            "checkpoint": {"url": "https://app.test/", "_private": {}},
        });
        std::fs::write(
            fixture.directory.path().join("result.json"),
            result.to_string(),
        )
        .unwrap();
        for action in [
            json!({"type": "snapshot", "format": "dom"}),
            json!({"type": "snapshot", "format": "dom", "max_bytes": 1_000_000}),
        ] {
            let result = fixture.run(action).await.unwrap();
            fitted_len(&result);
            let data = result.data.unwrap();
            let content = data["content"].as_str().unwrap();
            assert!(page.starts_with(content) && content.len() > 10_000);
            assert_eq!(data["next_offset"], content.len());
            assert_eq!(data["truncated"], true);
        }
        let asked = fixture
            .requests("session.action")
            .iter()
            .map(|request| request["params"]["action"]["max_bytes"].as_u64())
            .collect::<Vec<_>>();
        assert_eq!(asked, [Some(24_000), Some(24_000)]);
        fixture.service.force_stop_all().await;
    }

    #[test]
    fn browser_worker_installation_uses_selected_data_directory() {
        let directory = tempfile::tempdir().unwrap();
        let worker_dir = prepare_browser_worker_installation(directory.path()).unwrap();
        assert!(worker_dir.starts_with(directory.path()));
        assert!(worker_dir.join("index.js").is_file());
        assert!(worker_dir.join("package.json").is_file());
        assert!(worker_dir.join("package-lock.json").is_file());
        assert_eq!(
            std::fs::read_to_string(worker_dir.join("headless.js")).unwrap(),
            EMBEDDED_WORKER_HEADLESS
        );
    }

    #[test]
    fn worker_releases_are_plain_numeric_triples() {
        assert_eq!(parse_release("0.3.0"), Some([0, 3, 0]));
        assert_eq!(parse_release("12.0.104"), Some([12, 0, 104]));
        for rejected in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "1..3",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "+1.2.3",
            "-1.2.3",
            "1.2.3-rc.1",
            "1.2.3+build",
            " 1.2.3",
            "1.2.3 ",
            "99999999999999999999.0.0",
        ] {
            assert_eq!(parse_release(rejected), None, "{rejected:?}");
        }
    }

    #[test]
    fn only_worker_directories_older_than_the_previous_release_are_pruned() {
        let data = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let directory = |name: &str| {
            let path = data.path().join(name);
            std::fs::create_dir_all(path.join("node_modules")).unwrap();
            std::fs::write(path.join("index.js"), "worker").unwrap();
            path
        };
        let stale = [
            directory("browser-worker-0.1.0"),
            directory("browser-worker-0.1.5"),
            directory("browser-worker-0.0.9"),
        ];
        let kept = [
            // The previous release, the current one and newer ones.
            directory("browser-worker-0.2.0"),
            directory("browser-worker-0.3.0"),
            directory("browser-worker-0.4.0"),
            // 10 is newer than 3, which a text comparison would get wrong.
            directory("browser-worker-0.10.0"),
            // Not exactly browser-worker-MAJOR.MINOR.PATCH, whatever they hold.
            directory("browser-worker-0.1.0.bak"),
            directory("browser-worker-0.1.0-rc.1"),
            directory("browser-worker-01.0.0"),
            directory("browser-worker-1.0"),
            directory("browser-worker-old"),
            directory("browser-worker-"),
            directory("browser-workers-0.1.0"),
            directory(".browser-worker.old.k3j2h1"),
            directory("worker-0.1.0"),
            directory("runtime"),
        ];
        // Neither a file nor a link to a directory is a worker directory.
        let file = data.path().join("browser-worker-0.0.1");
        std::fs::write(&file, "not a directory").unwrap();
        std::fs::write(outside.path().join("keep"), "precious").unwrap();
        #[cfg(unix)]
        let link = {
            let link = data.path().join("browser-worker-0.0.2");
            std::os::unix::fs::symlink(outside.path(), &link).unwrap();
            link
        };

        prune_old_worker_directories(data.path(), "0.3.0");

        for path in &stale {
            assert!(!path.exists(), "{} should be pruned", path.display());
        }
        for path in &kept {
            assert!(
                path.join("index.js").is_file(),
                "{} should stay",
                path.display()
            );
        }
        assert!(file.is_file());
        assert_eq!(
            std::fs::read_to_string(outside.path().join("keep")).unwrap(),
            "precious"
        );
        #[cfg(unix)]
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());

        // Pruning again, or pruning from the oldest release, removes nothing more.
        prune_old_worker_directories(data.path(), "0.3.0");
        prune_old_worker_directories(data.path(), "0.0.1");
        for path in &kept {
            assert!(path.join("index.js").is_file(), "{}", path.display());
        }
        // An unusable current version prunes nothing.
        let before = std::fs::read_dir(data.path()).unwrap().count();
        for current in ["", "dev", "0.3", "0.3.0.1"] {
            prune_old_worker_directories(data.path(), current);
        }
        assert_eq!(std::fs::read_dir(data.path()).unwrap().count(), before);
    }

    #[test]
    fn a_pre_release_build_prunes_by_its_release_number() {
        let data = tempfile::tempdir().unwrap();
        for name in ["0.1.0", "0.2.0", "0.3.0"] {
            std::fs::create_dir(data.path().join(format!("browser-worker-{name}"))).unwrap();
        }
        prune_old_worker_directories(data.path(), "0.3.0-rc.1");
        assert!(!data.path().join("browser-worker-0.1.0").exists());
        assert!(data.path().join("browser-worker-0.2.0").exists());
        assert!(data.path().join("browser-worker-0.3.0").exists());
    }

    #[test]
    fn materializing_the_worker_prunes_the_old_ones_after_writing_it() {
        let data = tempfile::tempdir().unwrap();
        let old = |version: &str| {
            let path = data.path().join(format!("browser-worker-{version}"));
            std::fs::create_dir(&path).unwrap();
            path
        };
        let (oldest, previous) = (old("0.0.1"), old("0.0.2"));
        let worker = materialize_embedded_worker(data.path()).unwrap();
        assert!(worker.is_file());
        assert!(!oldest.exists());
        assert!(previous.is_dir());

        // Nothing is pruned when the current worker could not be written.
        let data = tempfile::tempdir().unwrap();
        let blocked = browser_worker_path(data.path());
        std::fs::write(blocked.parent().unwrap(), "in the way").unwrap();
        let stale = data.path().join("browser-worker-0.0.0");
        std::fs::create_dir(&stale).unwrap();
        assert!(materialize_embedded_worker(data.path()).is_err());
        assert!(stale.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_that_cannot_be_removed_does_not_stop_the_worker() {
        use std::os::unix::fs::PermissionsExt;
        let data = tempfile::tempdir().unwrap();
        let old = |version: &str| {
            let path = data.path().join(format!("browser-worker-{version}"));
            std::fs::create_dir(&path).unwrap();
            path
        };
        // The directory that cannot be removed comes first, so pruning must
        // carry on after the failure to reach the removable one.
        let (stuck, removable, previous) = (old("0.0.0"), old("0.0.1"), old("0.0.2"));
        // Entries of a read-only directory cannot be unlinked (except by root).
        let locked = stuck.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("file"), "x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = materialize_embedded_worker(data.path());

        if locked.exists() {
            // Removable again, so the temporary directory can be cleaned up.
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        } else {
            eprintln!("permissions do not block removal here (root); failure path not exercised");
        }
        let worker = result.expect("a failed cleanup must not fail the worker");
        assert!(worker.is_file());
        assert!(previous.is_dir());
        assert!(!removable.exists(), "pruning carries on after a failure");
    }

    /// A fake worker that starts persistent sessions, records each start
    /// request in `<script>.starts`, and saves `https://example.test/after-idle`
    /// as the last page when a session stops.
    #[cfg(unix)]
    const IDLE_WORKER: &str = r#"
n=0
while IFS= read -r request; do
  n=$((n + 1))
  case "$request" in
    *'"method":"hello"'*) printf '%s\n' '{"id":1,"result":{"protocol":1,"capabilities":["profile_isolation"]}}' ;;
    *'"method":"session.start"'*)
      printf '%s\n' "$request" >> "$0.starts"
      session=$(printf '%s\n' "$request" | sed -n 's/.*"session_id":\([0-9][0-9]*\).*/\1/p')
      directory=$(printf '%s\n' "$request" | sed -n 's/.*"profile_dir":"\([^"]*\)".*/\1/p')
      printf '{"id":%s,"result":{"session_id":%s,"requested_profile":"default","active_profile":"default","profile_dir":"%s","persistent":true,"checkpoint":{"url":"https://example.test/start","_private":{}}}}\n' "$n" "$session" "$directory" ;;
    *'"method":"session.stop"'*) printf '{"id":%s,"result":{"stopped":true,"checkpoint":{"url":"https://example.test/after-idle","_private":{}}}}\n' "$n" ;;
    *'"method":"session.javascript_files"'*) printf '{"id":%s,"result":{"files":[],"cursor":0}}\n' "$n" ;;
    *) printf '{"id":%s,"result":{"ok":true}}\n' "$n" ;;
  esac
done
"#;

    /// A browser service on `IDLE_WORKER` whose idle timeout is ten seconds,
    /// with two projects.
    #[cfg(unix)]
    async fn idle_fixture() -> (BrowserService, Arc<Db>, [ProjectId; 2], tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("worker.sh");
        std::fs::write(&script, IDLE_WORKER).unwrap();
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let mut projects = Vec::new();
        for name in ["Idle project", "Busy project"] {
            let project = db
                .create_project(CreateProjectRequest {
                    name: name.into(),
                    target_url: "https://example.test".into(),
                    advanced: None,
                })
                .await
                .unwrap();
            projects.push(project.id);
        }
        let mut service = BrowserService::new_with_proxy_and_ca(
            db.clone(),
            None,
            None,
            "http://127.0.0.1:17891".into(),
            None,
            directory.path().join("profiles"),
        );
        service.node_path = Some(PathBuf::from("/bin/sh"));
        service.worker_path = Some(script);
        service.runtime.playwright_core_path = Some(directory.path().to_path_buf());
        service.runtime.chromium_path = Some(PathBuf::from("/bin/sh"));
        service.runtime.compatibility_error = None;
        service.idle_timeout = Duration::from_secs(10);
        (service, db, [projects[0], projects[1]], directory)
    }

    /// Makes the project's last activity older than the idle timeout.
    #[cfg(unix)]
    fn make_idle(service: &BrowserService, project_id: ProjectId) {
        let past = std::time::Instant::now()
            .checked_sub(service.idle_timeout + Duration::from_secs(1))
            .expect("the monotonic clock reaches back past the idle timeout");
        service
            .project_activity
            .lock()
            .unwrap()
            .insert(project_id.get(), past);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_idle_project_browser_stops_and_browser_start_resumes_it() {
        let (mut service, db, [project_id, _], directory) = idle_fixture().await;
        let started = service
            .start(project_id, "about:blank".into())
            .await
            .unwrap();
        // Starting is activity: a new browser gets a full timeout.
        assert_eq!(service.stop_idle_projects(|_| false).await, 0);
        assert!(service.worker_is_running(project_id).await);

        make_idle(&service, project_id);
        assert_eq!(service.stop_idle_projects(|_| false).await, 1);
        assert!(service.runtime_sessions.lock().await.is_empty());
        assert!(!service.worker_is_running(project_id).await);
        let stopped = db
            .get_browser_session(project_id, started.id)
            .await
            .unwrap();
        assert_eq!(stopped.state, BrowserSessionState::Stopped);
        assert_eq!(stopped.checkpoint_status.as_deref(), Some("idle_stopped"));
        assert_eq!(
            stopped.current_url.as_deref(),
            Some("https://example.test/after-idle")
        );

        // An agent that comes back is told what happened and what to do.
        let snapshot: BrowserAction = serde_json::from_value(json!({"type":"snapshot"})).unwrap();
        let error = service
            .action(project_id, started.id, snapshot.clone())
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert_eq!(
            error.to_string(),
            format!(
                "browser session {} was stopped after 10 seconds without project activity; call browser_start to resume its profile",
                started.id.get()
            )
        );
        service.idle_timeout = BROWSER_IDLE_TIMEOUT;
        assert_eq!(
            service
                .action(project_id, started.id, snapshot)
                .await
                .unwrap_err()
                .to_string(),
            format!(
                "browser session {} was stopped after 30 minutes without project activity; call browser_start to resume its profile",
                started.id.get()
            )
        );
        let mut named = stopped.clone();
        named.profile = Some("account1".into());
        assert!(service
            .idle_stopped_error(&named)
            .unwrap()
            .to_string()
            .ends_with("call browser_start with profile \"account1\" to resume its profile"));
        assert!(service
            .enable_cdp(project_id, started.id)
            .await
            .unwrap_err()
            .to_string()
            .contains("without project activity"));
        // An explicit stop keeps its plain message.
        let mut explicit = stopped.clone();
        explicit.checkpoint_status = Some("stopped".into());
        assert!(service.idle_stopped_error(&explicit).is_none());

        // The saved profile resumes on the page it was stopped on.
        let resumed = service
            .start(project_id, "about:blank".into())
            .await
            .unwrap();
        assert_ne!(resumed.id, started.id);
        assert_eq!(resumed.checkpoint_status.as_deref(), Some("restored"));
        let starts = std::fs::read_to_string(directory.path().join("worker.sh.starts")).unwrap();
        let resume: Value = serde_json::from_str(starts.lines().nth(1).unwrap()).unwrap();
        assert_eq!(
            resume["params"]["url"],
            json!("https://example.test/after-idle")
        );
        service.stop(project_id, resumed.id).await.unwrap();
        let explicit = db
            .get_browser_session(project_id, resumed.id)
            .await
            .unwrap();
        assert_eq!(explicit.checkpoint_status.as_deref(), Some("stopped"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_project_in_use_keeps_its_browser_and_other_projects_do_not() {
        let (service, db, [idle, other], _directory) = idle_fixture().await;
        let first = service.start(idle, "about:blank".into()).await.unwrap();
        let second = service.start(other, "about:blank".into()).await.unwrap();
        make_idle(&service, idle);
        make_idle(&service, other);
        let attached = |id: BrowserSessionId| {
            let runtimes = &service.runtime_sessions;
            async move { runtimes.lock().await.contains_key(&id.get()) }
        };

        // Activity keeps a project's browsers open.
        service.touch_project(idle);
        service.touch_project(other);
        assert_eq!(service.stop_idle_projects(|_| false).await, 0);
        make_idle(&service, idle);

        // A call in flight on one of its browsers.
        let operation = service.session_operation_lock(first.id).await;
        let guard = operation.lock().await;
        assert_eq!(service.stop_idle_projects(|_| false).await, 0);
        drop(guard);

        // A browser handed off to Chrome DevTools.
        service
            .runtime_sessions
            .lock()
            .await
            .get_mut(&first.id.get())
            .unwrap()
            .cdp = Some(BrowserCdpInfo {
            port: BROWSER_CDP_PORT,
            endpoint: "http://127.0.0.1:9222".into(),
            devtools_url: "devtools".into(),
            hosted_devtools_url: "hosted-devtools".into(),
        });
        assert_eq!(service.stop_idle_projects(|_| false).await, 0);
        service
            .runtime_sessions
            .lock()
            .await
            .get_mut(&first.id.get())
            .unwrap()
            .cdp = None;

        // A running fuzz or plugin job.
        assert_eq!(
            service.stop_idle_projects(|project| project == idle).await,
            0
        );

        // An ephemeral browser, which its own operation stops.
        service.runtime_sessions.lock().await.insert(
            first.id.get() + 1_000,
            RuntimeSession {
                project_id: idle,
                capture_session_id: CaptureSessionId(1_000),
                persistent: false,
                profile: None,
                cdp: None,
                javascript_cursor: 0,
            },
        );
        assert_eq!(service.stop_idle_projects(|_| false).await, 0);
        service
            .runtime_sessions
            .lock()
            .await
            .remove(&(first.id.get() + 1_000));

        // A start or stop in progress.
        let lifecycle = service.project_lifecycle_lock(idle).await;
        let guard = lifecycle.lock().await;
        assert_eq!(service.stop_idle_projects(|_| false).await, 0);
        drop(guard);
        assert!(attached(first.id).await);

        // Another project's activity does not keep this one open, and this
        // one's idleness does not stop the other.
        service.touch_project(other);
        assert_eq!(service.stop_idle_projects(|_| false).await, 1);
        assert!(!attached(first.id).await);
        assert!(attached(second.id).await);
        assert_eq!(
            db.get_browser_session(other, second.id)
                .await
                .unwrap()
                .state,
            BrowserSessionState::Ready
        );
        service.stop(other, second.id).await.unwrap();
    }

    #[test]
    fn idle_timeouts_are_described_in_plain_units() {
        assert_eq!(describe_idle_timeout(BROWSER_IDLE_TIMEOUT), "30 minutes");
        assert_eq!(describe_idle_timeout(Duration::from_secs(60)), "1 minute");
        assert_eq!(describe_idle_timeout(Duration::from_secs(10)), "10 seconds");
        assert_eq!(describe_idle_timeout(Duration::from_secs(1)), "1 second");
    }

    #[cfg(unix)]
    async fn lifecycle_worker() -> (WorkerProcess, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("worker.sh");
        std::fs::write(
            &script,
            r#"
IFS= read -r request || exit 1
printf '%s\n' '{"id":1,"result":{"protocol":1,"capabilities":["profile_isolation"]}}'
IFS= read -r request
"#,
        )
        .unwrap();
        let worker = WorkerProcess::spawn(Path::new("/bin/sh"), &script, None, None)
            .await
            .unwrap_or_else(|_| panic!("start lifecycle fixture"));
        (worker, directory)
    }

    #[cfg(unix)]
    fn lifecycle_group_member(group: nix::unistd::Pid) -> Child {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "IFS= read -r request"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(group.as_raw())
            .kill_on_drop(true);
        let child = command.spawn().unwrap();
        assert_eq!(
            nix::unistd::getpgid(Some(nix::unistd::Pid::from_raw(child.id().unwrap() as i32)))
                .unwrap(),
            group
        );
        child
    }

    #[cfg(unix)]
    async fn assert_group_member_killed(member: &mut Child) {
        use std::os::unix::process::ExitStatusExt;

        let status = tokio::time::timeout(Duration::from_secs(5), member.wait())
            .await
            .expect("group member did not exit")
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn worker_lifecycle_terminate_kills_group_after_leader_is_reaped() {
        let (mut worker, _directory) = lifecycle_worker().await;
        let mut member = lifecycle_group_member(worker.process_group);
        {
            let mut stdin = worker.io.stdin.lock().await;
            stdin.write_all(b"exit\n").await.unwrap();
            stdin.flush().await.unwrap();
        }
        let status = tokio::time::timeout(Duration::from_secs(5), worker.child.wait())
            .await
            .expect("worker leader did not exit")
            .unwrap();
        assert!(status.success());
        assert!(worker.child.id().is_none());
        assert!(member.try_wait().unwrap().is_none());

        worker.terminate().await;

        assert_group_member_killed(&mut member).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn worker_lifecycle_dropping_unterminated_worker_kills_group() {
        let (worker, _directory) = lifecycle_worker().await;
        let mut member = lifecycle_group_member(worker.process_group);
        assert!(member.try_wait().unwrap().is_none());

        drop(worker);

        assert_group_member_killed(&mut member).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn worker_lifecycle_dropping_terminated_worker_does_not_kill_reassigned_group() {
        let (mut worker, _directory) = lifecycle_worker().await;
        worker.terminate().await;

        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "printf 'ready\\n'; IFS= read -r request; printf 'alive\\n'; IFS= read -r request",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true);
        let mut unrelated = command.spawn().unwrap();
        let mut unrelated_stdin = unrelated.stdin.take().unwrap();
        let mut unrelated_stdout = BufReader::new(unrelated.stdout.take().unwrap());
        let mut line = String::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            unrelated_stdout.read_line(&mut line),
        )
        .await
        .expect("unrelated group did not start")
        .unwrap();
        assert_eq!(line, "ready\n");
        worker.process_group = nix::unistd::Pid::from_raw(unrelated.id().unwrap() as i32);

        drop(worker);

        unrelated_stdin.write_all(b"ping\n").await.unwrap();
        unrelated_stdin.flush().await.unwrap();
        line.clear();
        tokio::time::timeout(
            Duration::from_secs(5),
            unrelated_stdout.read_line(&mut line),
        )
        .await
        .expect("unrelated group did not respond")
        .unwrap();
        assert_eq!(line, "alive\n");
        unrelated.kill().await.unwrap();
    }
}
