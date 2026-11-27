//! Minimal stdio JSON-RPC MCP server. Protocol on stdout; diagnostics on stderr.

mod arguments;
pub(crate) mod budget;
mod exchange_view;
mod fuzz_view;
mod history_view;
mod job_view;
mod view;
mod websocket_view;

use crate::app::AppState;
use crate::browser::BrowserAction;
use crate::codec::{apply_pipeline, Transform};
use crate::config::Config;
use crate::domain::*;
use crate::fuzzer::FuzzTemplate;
use crate::history::HISTORY_QUERY_SYNTAX;
use crate::policy::is_sensitive_header;
use crate::storage::CreateCaptureSession;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Arc;

#[async_trait::async_trait]
trait ToolBackend: Send + Sync {
    async fn call(&self, name: &str, args: Value) -> DomainResult<Value>;

    async fn definitions(&self) -> Value {
        tool_defs()
    }

    async fn definitions_changed(&self) -> bool {
        false
    }

    async fn reset_definitions_changed(&self) {}

    fn supports_list_changed(&self) -> bool {
        false
    }
}

/// In-process backend used by tests to compare against the daemon bridge.
#[cfg(test)]
struct LocalToolBackend {
    state: Arc<AppState>,
}

#[cfg(test)]
#[async_trait::async_trait]
impl ToolBackend for LocalToolBackend {
    async fn call(&self, name: &str, args: Value) -> DomainResult<Value> {
        call_tool(self.state.clone(), name, args).await
    }
}

struct DaemonToolBackend {
    config: Config,
    lifecycle_disabled: bool,
    catalog: tokio::sync::RwLock<Option<DaemonToolCatalog>>,
    catalog_change_pending: tokio::sync::Mutex<bool>,
}

#[derive(Clone, Debug, Deserialize)]
struct DaemonToolCatalog {
    version: String,
    protocol: u32,
    tools: Value,
}

impl DaemonToolBackend {
    fn new(config: Config) -> Self {
        Self {
            config,
            lifecycle_disabled: std::env::var("HUNTPROXY_MCP_DISABLE_LIFECYCLE")
                .is_ok_and(|value| value == "1"),
            catalog: tokio::sync::RwLock::new(Some(DaemonToolCatalog {
                version: SERVER_VERSION.to_string(),
                protocol: crate::INTERNAL_PROTOCOL_VERSION,
                tools: tool_defs(),
            })),
            catalog_change_pending: tokio::sync::Mutex::new(false),
        }
    }

    async fn refresh_catalog(&self) -> DomainResult<Option<Value>> {
        let Some(catalog) = fetch_daemon_tool_catalog(&self.config).await? else {
            return Ok(None);
        };
        if catalog.version.is_empty()
            || catalog.version.len() > 128
            || catalog.protocol == 0
            || !catalog.tools.is_array()
        {
            return Err(DomainError::new(
                ErrorCode::ProtocolError,
                "daemon returned an invalid MCP tool catalog",
            ));
        }

        let tools = catalog.tools.clone();
        let mut current = self.catalog.write().await;
        let changed = current.as_ref().is_some_and(|previous| {
            previous.version != catalog.version || previous.protocol != catalog.protocol
        });
        *current = Some(catalog);
        drop(current);
        if changed {
            *self.catalog_change_pending.lock().await = true;
        }
        Ok(Some(tools))
    }

    async fn cached_definitions(&self) -> Value {
        self.catalog
            .read()
            .await
            .as_ref()
            .map(|catalog| catalog.tools.clone())
            .unwrap_or_else(tool_defs)
    }
}

#[async_trait::async_trait]
impl ToolBackend for DaemonToolBackend {
    async fn call(&self, name: &str, args: Value) -> DomainResult<Value> {
        if self.lifecycle_disabled && is_lifecycle_tool(name) {
            return Err(DomainError::new(
                ErrorCode::Forbidden,
                "MCP lifecycle tools are disabled by HUNTPROXY_MCP_DISABLE_LIFECYCLE",
            ));
        }
        if name == "huntproxy_restart" {
            crate::app::restart_daemon(&self.config).await?;
            clear_stop_guard(&self.config);
            return Ok(json!({
                "ok": true,
                "message": "HuntProxy restarted; continue using this MCP connection. Saved projects and browser profiles are preserved. Resume browsers with browser_start; running jobs were interrupted.",
                "running_jobs_interrupted": true,
                "browser_resume_tool": "browser_start"
            }));
        }
        if stop_guard_blocks_start(&self.config) {
            return Err(DomainError::new(
                ErrorCode::DaemonNotRunning,
                "HuntProxy was explicitly stopped; call huntproxy_restart to continue in this session",
            ));
        }
        // Recover before sending a new operation. Never retry a tool after it
        // was dispatched: a lost response may still represent a completed send.
        crate::app::ensure_daemon(&self.config).await?;
        call_daemon_tool_guarded(&self.config, name, args).await
    }

    async fn definitions(&self) -> Value {
        let mut definitions = match self.refresh_catalog().await {
            Ok(Some(tools)) => tools,
            Ok(None) | Err(_) => self.cached_definitions().await,
        };
        if self.lifecycle_disabled {
            if let Some(tools) = definitions.as_array_mut() {
                tools.retain(|tool| {
                    !tool
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(is_lifecycle_tool)
                });
            }
        }
        definitions
    }

    async fn definitions_changed(&self) -> bool {
        if self.refresh_catalog().await.is_err() {
            return false;
        }
        let mut pending = self.catalog_change_pending.lock().await;
        std::mem::take(&mut *pending)
    }

    async fn reset_definitions_changed(&self) {
        *self.catalog_change_pending.lock().await = false;
    }

    fn supports_list_changed(&self) -> bool {
        true
    }
}

/// Arms the stop guard around `huntproxy_stop` and disarms it again when the
/// call fails, so a failed stop cannot leave this client blocked.
async fn call_daemon_tool_guarded(config: &Config, name: &str, args: Value) -> DomainResult<Value> {
    let armed_stop_guard = name == "huntproxy_stop";
    if armed_stop_guard {
        arm_stop_guard(config)?;
    }
    let result = call_daemon_tool(config, name, args).await;
    if armed_stop_guard && result.is_err() {
        clear_stop_guard(config);
    }
    result
}

fn is_lifecycle_tool(name: &str) -> bool {
    matches!(name, "huntproxy_stop" | "huntproxy_restart")
}

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "HuntProxy";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const EXPLICIT_STOP_GUARD: &str = ".mcp-stop-guard";

fn stop_guard_path(config: &Config) -> std::path::PathBuf {
    config.data_dir.join(EXPLICIT_STOP_GUARD)
}

#[cfg(unix)]
fn parent_process_id() -> u32 {
    unsafe { libc::getppid() as u32 }
}

#[cfg(not(unix))]
fn parent_process_id() -> u32 {
    0
}

fn arm_stop_guard(config: &Config) -> DomainResult<()> {
    crate::config::write_private_file(
        &stop_guard_path(config),
        parent_process_id().to_string().as_bytes(),
    )
}

pub fn stop_guard_blocks_start(config: &Config) -> bool {
    let path = stop_guard_path(config);
    let guarded_parent = std::fs::read_to_string(&path)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok());
    if guarded_parent == Some(parent_process_id()) {
        return true;
    }
    clear_stop_guard(config);
    false
}

pub fn clear_stop_guard(config: &Config) {
    let path = stop_guard_path(config);
    if path.is_file() {
        let _ = std::fs::remove_file(path);
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

#[derive(Debug, Serialize)]
struct DaemonToolRequest<'a> {
    name: &'a str,
    arguments: Value,
}

#[derive(Debug, Deserialize)]
struct DaemonToolResponse {
    result: Option<Value>,
    error: Option<ErrorEnvelope>,
}

fn reply_draft_schema() -> Value {
    json!({
        "type": "object",
        "description": "All fields are optional. Omitted fields inherit from base_exchange_id when supplied. Use inheritance=cookies_auth_only when adapting a captured request to a different endpoint.",
        "properties": {
            "method": {"type": ["string", "null"]},
            "url": {"type": ["string", "null"]},
            "identity": {
                "description": "Optional request-local cookie identity. Omit or use default for existing project-cookie behavior. named selects a saved cookie profile without changing the default jar or browser and removes inherited credentials; explicit non-Cookie credential overrides remain deliberate. A Cookie override conflicts with named selection; a Cookie tombstone suppresses its cookie. anonymous removes all credential headers, including overrides and rules. Named selections are pinned when a fuzz job starts. Selection metadata does not verify the logged-in actor.",
                "oneOf": [
                    {"type":"null"},
                    {"type":"object","properties":{"mode":{"type":"string","enum":["default","anonymous"]}},"required":["mode"],"additionalProperties":false},
                    {"type":"object","properties":{"mode":{"type":"string","const":"named"},"profile":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$"}},"required":["mode","profile"],"additionalProperties":false}
                ]
            },
            "header_overrides": {
                "type": "array",
                "default": [],
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "value": {"oneOf": [
                            {"type": "string"},
                            {"type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 255}}
                        ]}
                    },
                    "required": ["name", "value"],
                    "additionalProperties": false
                }
            },
            "header_tombstones": {"type": "array", "items": {"type": "string"}, "default": []},
            "inheritance": {"type": "string", "enum": ["full_request", "cookies_auth_only"], "default": "full_request", "description": "full_request preserves all base headers/body. cookies_auth_only keeps only Cookie, Authorization, and Origin; explicit overrides still apply."},
            "body_override": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 255}}
                ]
            },
            "body_text": {"type": ["string", "null"], "description": "UTF-8 request body convenience field. Mutually exclusive with body_override and body_json."},
            "body_json": {"description": "JSON request body convenience field. Mutually exclusive with body_override and body_text; adds application/json unless Content-Type is explicit.", "oneOf": [{"type":"object"},{"type":"array"},{"type":"string"},{"type":"number"},{"type":"boolean"},{"type":"null"}]},
            "body_format": {"type":["string","null"],"enum":["raw","json","xml","form_urlencoded","multipart",null],"description":"Validates/serializes the body and replaces Content-Type. JSON accepts body_json/body_text; XML accepts body_text; form formats accept body_params."},
            "body_params": {"type":"array","default":[],"description":"Ordered name/value fields for form_urlencoded or multipart.","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"}},"required":["name","value"],"additionalProperties":false}},
            "body_cleared": {"type": "boolean", "default": false}
        },
        "additionalProperties": false
    })
}

fn locator_schema() -> Value {
    json!({
        "type": "object",
        "description": "One strategy: role/name, text, test_id, css. nth picks one match (0 first, -1 last); frame: iframe name or URL part. Required for click/fill/select/upload; optional otherwise. snapshot: only its subtree.",
        "properties": {
            "role": {"type": ["string", "null"]},
            "name": {"type": ["string", "null"]},
            "text": {"type": ["string", "null"]},
            "test_id": {"type": ["string", "null"]},
            "css": {"type": ["string", "null"]},
            "exact": {"type": ["boolean", "null"]},
            "nth": {"type": ["integer", "null"]},
            "frame": {"type": ["string", "null"]}
        },
        "additionalProperties": false
    })
}

fn browser_action_schema() -> Value {
    // Keep descriptions compact: Codex removes them above its 5000-byte normalized budget.
    // https://github.com/openai/codex/blob/rust-v0.157.1/codex-rs/tools/src/json_schema/compaction.rs
    // Keep the action flat: Codex renders allOf as unknown and hides its properties.
    json!({
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["navigate", "snapshot", "click", "fill", "select", "upload", "inspect", "pages", "events", "scroll", "screenshot", "request", "press", "wait", "back", "forward", "close"]},
            "url": {"type": "string", "description":"Required for navigate/request; optional for pages new. request requires the active page origin."},
            "locator": locator_schema(),
            "value": {"type": "string","description":"Required for fill/select/wait. wait modes: selector=Playwright selector; text=visible text; url=URL pattern; timeout=string 0..60000 ms; load_state=load/domcontentloaded/networkidle (empty: domcontentloaded). Other waits: 30000 ms."},
            "files": {"type":"array","maxItems":16,"items":{"type":"string","minLength":1},"description":"Upload requires <=16 absolute readable regular-file paths, <=4096 bytes each. [] clears input; chooser needs a file."},
            "via_chooser": {"type":"boolean","default":false,"description":"Upload via trusted locator click/file chooser."},
            "timeout_ms": {"type":"integer","minimum":1,"maximum":30000,"description":"Upload ms: 1..30000 (default 10000); request: 1000..30000 (default 15000). wait uses for_what/value."},
            "key": {"type": "string","description":"Required for press: Playwright key (Enter, Control+A)."},
            "for_what": {"type": "string", "enum": ["selector", "text", "url", "timeout", "load_state"],"description":"Required with value for wait."},
            "format": {"type": "string", "enum": ["accessibility", "dom"],"description":"Snapshot; default accessibility."},
            "max_bytes": {"type": "integer", "minimum": 1, "maximum": 8388608, "description":"inspect 1..65536 (default 4096); screenshot 1..8388608 (default 4194304); snapshot default/cap 24000, cut to fit the result."},
            "offset": {"type":"integer","minimum":0,"default":0,"description":"Snapshot byte offset; continue with next_offset."},
            "snapshot": {"type":"boolean","default":false,"description":"navigate/click/fill/select/press/wait/back/forward: add data.snapshot of the resulting page."},
            "op": {"type":"string","enum":["list","select","new","close"],"description":"Required for pages: list omits IDs/url; new permits url only; select/close need page_id/runtime_generation, no url."},
            "page_id": {"type":"integer","minimum":1,"description":"Positive pages ID; required with runtime_generation for select/close, omitted for list/new."},
            "runtime_generation": {"type":"integer","minimum":1,"description":"Positive generation from pages/events/context. Required with its page ID for select/close or nonzero event cursor; omit for list/new."},
            "after_sequence": {"type":"integer","minimum":0,"default":0,"description":"Events cursor: integer >=0, default 0; pass next_sequence; nonzero requires matching runtime_generation."},
            "limit": {"type":"integer","minimum":1,"maximum":100,"default":50,"description":"Events limit: 1..100, default 50."},
            "kinds": {"type":"array","maxItems":11,"uniqueItems":true,"items":{"type":"string","enum":["page","popup","navigation","dialog","console","page_error","request","response","request_failed","window_message","observer_error"]},"description":"Event filter: <=11 unique kinds, default all. Filtered observer failures remain in observer_errors."},
            "wait_ms": {"type":"integer","minimum":0,"maximum":30000,"default":0,"description":"Events wait: 0..30000 ms, default 0."},
            "delta_x": {"type":"integer","minimum":-100000,"maximum":100000,"default":0,"description":"Horizontal scroll: -100000..100000, default 0; needs locator or nonzero delta."},
            "delta_y": {"type":"integer","minimum":-100000,"maximum":100000,"default":0,"description":"Vertical scroll: -100000..100000, default 0."},
            "full_page": {"type":"boolean","default":false,"description":"Full screenshot; excludes locator."},
            "method": {"type":"string","enum":["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"],"description":"Required for request."},
            "headers": {"type":"array","maxItems":64,"items":{"type":"object","properties":{"name":{"type":"string","minLength":1},"value":{"type":"string"}},"required":["name","value"],"additionalProperties":false},"description":"<=64, <=65536 bytes total; default []. Rejects duplicates, browser-managed/Fetch-forbidden transport, identity, origin, host, length, proxy, Sec-*, internal headers."},
            "body_text": {"type":"string","description":"UTF-8 body, at most 2 MiB; excludes body_base64. GET/HEAD cannot have a body."},
            "body_base64": {"type":"string","description":"Base64 body, at most 2 MiB decoded; excludes body_text."},
            "max_response_bytes": {"type":"integer","minimum":1,"maximum":65536,"default":4096,"description":"Response preview bytes: 1..65536, default 4096."}
        },
        "required": ["type"],
        "additionalProperties": false
    })
}

fn fuzz_template_schema() -> Value {
    // Integer generator fields omit minimum/maximum bounds that only restate i64/u64:
    // the OpenAI Codex backend answers HTTP 500 when a tool declares i64::MIN or u64::MAX.
    // Deserializing into PayloadGenerator still rejects out-of-range values.
    json!({
        "type": "object",
        "description": "Use marker §name§ in the selected draft field. Example: draft.url='https://example.test/?q=§q§' with insertion point {name:'q', location:'url'}. In body_json strings and body_params the payload is JSON-escaped or form-encoded with its field; use body_text for raw bytes. A body point without a marker replaces the whole body.",
        "properties": {
            "base_exchange_id": {"type": ["integer", "null"]},
            "draft": reply_draft_schema(),
            "insertion_points": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "minLength": 1, "description": "Marker name without section signs; name q maps to §q§."},
                        "location": {"type": "string", "pattern": "^(url|body|header:.+)$", "description": "Use url, body, or header:<header-name>."}
                    },
                    "required": ["name", "location"],
                    "additionalProperties": false
                }
            },
            "wordlists": {
                "type": "array",
                "default": [],
                "description": "Inline payloads: one array per insertion point; sniper may use one shared array.",
                "items": {"type": "array", "minItems": 1, "items": {"type": "string"}}
            },
            "wordlist_files": {
                "type": "array",
                "default": [],
                "description": "Local UTF-8 wordlist paths. Each file is one wordlist with one payload per line; files are appended after inline wordlists.",
                "items": {"type": "string", "minLength": 1}
            },
            "payload_generators": {
                "type": "array",
                "default": [],
                "description": "Native generators. Each generator is appended as one wordlist. Number ranges always include from and to. Regex bypass implements Recollapse-style byte mutations at the start, around separators, at the end, and in place of regex metacharacters.",
                "items": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "type": {"const": "numbers"},
                                "from": {"type": "integer"},
                                "to": {"type": "integer"},
                                "step": {"type": "integer", "description": "Non-zero; its sign must move from from toward to."}
                            },
                            "required": ["type", "from", "to", "step"],
                            "additionalProperties": false
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": {"const": "regex_bypass"},
                                "input": {"type": "string", "minLength": 1, "maxLength": 4096, "description": "Known value that the target's validation accepts or rejects (maximum 4096 UTF-8 bytes)."},
                                "encoding": {"type": "string", "enum": ["url", "unicode", "raw", "double_url"], "default": "url"},
                                "modes": {"type": "array", "minItems": 1, "uniqueItems": true, "default": ["start", "separator", "end", "regex_metachar"], "items": {"type": "string", "enum": ["start", "separator", "end", "regex_metachar"]}},
                                "byte_from": {"type": "integer", "minimum": 0, "maximum": 255, "default": 0},
                                "byte_to": {"type": "integer", "minimum": 0, "maximum": 255, "default": 255},
                                "include_alphanumeric": {"type": "boolean", "default": false},
                                "max_payloads": {"type": "integer", "minimum": 1, "default": 2000}
                            },
                            "required": ["type", "input"],
                            "additionalProperties": false
                        }
                    ]
                }
            },
            "transforms": {
                "type": "array",
                "default": [],
                "items": {"type": "string", "enum": ["raw", "hex_encode", "hex_decode", "base64_encode", "base64_decode", "base64_url_encode", "base64_url_decode", "url_encode", "url_decode", "html_encode", "html_decode", "gzip_decode", "gunzip", "brotli_decode", "br_decode"]}
            },
            "strategy": {"type": "string", "enum": ["sniper", "battering_ram", "pitchfork", "cluster_bomb"], "default": "sniper"},
            "request_timeout_ms": {"type": "integer", "minimum": 100, "maximum": 60000, "description": "Fail a case that takes longer than this instead of waiting the default 60 seconds."}
        },
        "required": ["insertion_points"],
        "anyOf": [{"required":["wordlists"]},{"required":["wordlist_files"]},{"required":["payload_generators"]}],
        "additionalProperties": false
    })
}

fn request_rules_tool_def() -> Value {
    serde_json::from_str(r#"{
      "name":"request_rules",
      "description":"Manage ordered request match/replace rules. Rules rewrite requests received through Proxy/Browser before forwarding and requests generated by semantic Reply, Fuzzer, plugins, and the crawler. Raw Reply remains byte-exact and is never modified. A url rule with operation block answers matching Proxy/Browser requests with its synthetic response (response_status, default 403; optional response_content_type and response_body) instead of contacting the origin; it is proxy-only, so Reply, Fuzzer, and plugin requests still reach the origin. Block rules need a host_pattern or a pattern, may set method, and stop evaluation of later url rules. Preview accepts method (default GET) and reports blocked and block.",
      "inputSchema":{"type":"object","properties":{
        "project_id":{"type":"integer"},
        "action":{"type":"string","enum":["list","add","update","remove","preview"]},
        "rule_id":{"type":"integer"},
        "rule":{"type":"object","properties":{
          "name":{"type":"string"},"enabled":{"type":"boolean","default":true},
          "position":{"type":"integer","default":0},"host_pattern":{"type":["string","null"]},
          "target":{"type":"string","enum":["url","header","body"]},
          "operation":{"type":"string","enum":["replace","set","remove","block"]},
          "header_name":{"type":["string","null"]},
          "match_kind":{"type":"string","enum":["literal","regex"],"default":"literal"},
          "pattern":{"type":"string","default":""},"replacement":{"type":["string","null"]},
          "replace_all":{"type":"boolean","default":true},
          "method":{"type":["string","null"],"description":"Block rules only: HTTP method to block; null blocks every method."},
          "response_status":{"type":["integer","null"],"minimum":200,"maximum":599,"description":"Block rules only: synthetic response status (default 403)."},
          "response_content_type":{"type":["string","null"],"description":"Block rules only: Content-Type of the synthetic response."},
          "response_body":{"type":["string","null"],"description":"Block rules only: synthetic response body; must be empty for 204 and 304."}},"required":["name","target","operation"],"additionalProperties":false},
        "url":{"type":"string"},"method":{"type":"string","description":"Preview only: request method used for block rules (default GET)."},"headers":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"}},"required":["name","value"]}},
        "body":{"type":"string"}},"required":["project_id","action"],"additionalProperties":false}
    }"#).expect("request rules tool schema is valid JSON")
}

/// browser_start's browser profile and cookie profile. A cookie profile seeds
/// the browser profile of the same name, so it also names the profile when
/// none is given.
fn browser_start_profiles(args: &Value) -> (&str, Option<&str>) {
    let cookie_profile = args.get("cookie_profile").and_then(Value::as_str);
    let profile = args
        .get("profile")
        .and_then(Value::as_str)
        .or(cookie_profile)
        .unwrap_or("default");
    (profile, cookie_profile)
}

fn browser_input_tool_def() -> Value {
    let mut element = locator_schema();
    element["description"] = json!("Element to click, hover, drag from, or type into. One strategy: role/name, text, test_id, css. nth picks one match (0 first, -1 last); frame: iframe name or URL part. Omit to use x and y, or to type into the focused element.");
    let mut destination = locator_schema();
    destination["description"] =
        json!("Drag destination element, with the same fields as locator; or give to_x and to_y.");
    // Flat and compact for the same Codex reasons as browser_action_schema.
    json!({
        "name": "browser_input",
        "description": "Mouse and keyboard input on the selected page that browser_action click, fill and press cannot express. click presses a mouse button (count 2 is a double-click, button right a context-menu click) with optional held modifiers; hover moves the pointer; drag presses at the start, moves in steps and releases at the destination, which mouse-driven and native HTML drag and drop both follow; a drag between elements scrolls them into view, but with x and y at either end nothing scrolls and an element end must already be in view; type sends text as real keystrokes after the text locator holds, or to whatever has focus when locator is omitted (fill replaces a value at once; type suits editors, autocomplete and one-character boxes). Aim click, hover and drag at a locator or at x and y: CSS pixels in the selected page's viewport, as getBoundingClientRect() reports in its top document, so a point reaches a canvas or anything a locator cannot name. An element is clicked with Playwright's checks; a point is clicked as it is, and the result names the element it hit, in whatever frame. For single keys and chords use browser_action press.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": {"type":"integer","description":"Required integer ID returned by projects; owns session."},
                "session_id": {"type":"integer","description":"Required integer ID returned by browser_start."},
                "op": {"type":"string","enum":["click","hover","drag","type"]},
                "locator": element,
                "x": {"type":"number","minimum":0,"maximum":100000,"description":"Viewport X in CSS pixels, 0..100000; give x and y instead of locator."},
                "y": {"type":"number","minimum":0,"maximum":100000,"description":"Viewport Y in CSS pixels, 0..100000."},
                "to_locator": destination,
                "to_x": {"type":"number","minimum":0,"maximum":100000,"description":"Drag destination X, 0..100000; give to_x and to_y instead of to_locator."},
                "to_y": {"type":"number","minimum":0,"maximum":100000,"description":"Drag destination Y, 0..100000."},
                "button": {"type":"string","enum":["left","right","middle"],"default":"left","description":"Button for click and drag; default left."},
                "count": {"type":"integer","minimum":1,"maximum":3,"default":1,"description":"Clicks, 1..3 (default 1); 2 is a double-click."},
                "modifiers": {"type":"array","maxItems":4,"uniqueItems":true,"items":{"type":"string","enum":["Alt","Control","Meta","Shift"]},"description":"Keys held during click, hover or drag; default none."},
                "text": {"type":"string","minLength":1,"maxLength":4096,"description":"Required for type: 1..4096 bytes; a newline presses Enter."},
                "snapshot": {"type":"boolean","default":false,"description":"Add data.snapshot of the resulting page."}
            },
            "required": ["project_id", "session_id", "op"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn tool_defs() -> Value {
    json!([
        {"name":"projects","description":"List project summaries or get full details with project_id, create a project, inspect its logical capture quota, or set capture scope. usage returns quota-enforced logical bytes separately from physical database size. Host patterns may be exact or wildcard suffixes such as *.example.com; exclusions take precedence. Scope controls persistence, never request destinations. set_upstream_proxy persists live routing; proxy null inherits config.toml, direct selects direct traffic, and a URL selects that proxy. Existing connections reconnect naturally. set_limits changes the request rate and concurrency that Reply, fuzz jobs, the crawler and extensions share; it applies at once, including to running fuzz jobs.","inputSchema":{"type":"object","properties":{"action":{"type":"string","enum":["list","create","usage","set_scope","set_upstream_proxy","set_limits"],"description":"list returns id, name, target_url and updated_at, or full details with project_id; create needs name and target_url; usage and set_scope need project_id; omitted scope resets to defaults; set_upstream_proxy needs project_id and an explicit proxy URL, direct, or null; set_limits needs project_id and requests_per_second, max_concurrent_requests, or both."},"project_id":{"type":"integer","description":"Optional for list; required for usage, set_scope, set_upstream_proxy and set_limits."},"name":{"type":"string","description":"Required for create."},"target_url":{"type":"string","description":"Required for create; absolute HTTP(S) URL."},"scope":{"type":"object","properties":{"schemes":{"type":"array","items":{"type":"string"}},"host_patterns":{"type":"array","description":"Hosts to capture. Supports exact names and wildcard suffixes such as *.example.com. Empty captures all hosts except exclusions.","items":{"type":"string"}},"excluded_host_patterns":{"type":"array","description":"Hosts not to capture. Supports exact names and wildcard suffixes; exclusions override inclusions.","default":[],"items":{"type":"string"}},"ports":{"type":"array","items":{"type":"integer"}},"path_prefixes":{"type":"array","items":{"type":"string"}}}},"requests_per_second":{"type":"number","minimum":0.1,"maximum":1000,"description":"For set_limits: the most requests started per second (default 50)."},"max_concurrent_requests":{"type":"integer","minimum":1,"maximum":256,"description":"For set_limits: the most requests in flight at once (default 32)."},"proxy":{"type":["string","null"],"description":"For set_upstream_proxy: http://, socks5:// or socks5h:// URL, direct to route directly, or null to inherit config.toml."}},"required":["action"],"additionalProperties":false}},
        {"name":"extension_list","description":"List compact installed-extension summaries and any rejected packages. Use extension_describe for schemas, capabilities, and limits.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"extension_describe","description":"Describe one extension, its actions, input schemas, capabilities, and requested/effective limits.","inputSchema":{"type":"object","properties":{"plugin_id":{"type":"string"}},"required":["plugin_id"],"additionalProperties":false}},
        {"name":"extension_preview","description":"Run the real extension planner without creating a job or sending requests. Returns stage-scoped request, candidate, runtime, and mode estimates plus a bounded planning_summary with selection/exclusion details when supplied by the plugin.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"plugin_id":{"type":"string"},"action":{"type":"string"},"base_exchange_id":{"type":"integer"},"input":{"type":"object","default":{}}},"required":["project_id","plugin_id","action"],"additionalProperties":false}},
        {"name":"extension_run","description":"Start an asynchronous extension job. Call extension_describe first and place action-specific fields inside input, not at the top level. project_id owns the job/evidence; optional base_exchange_id supplies a saved request while cookies and authorization remain host-side. Planning failures report the plugin's bounded validation message.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer","description":"HuntProxy project that owns the job and evidence."},"plugin_id":{"type":"string","description":"Installed id from extension_list."},"action":{"type":"string","description":"Action name from extension_describe."},"base_exchange_id":{"type":"integer","description":"Optional saved request inherited host-side without copying secrets into action input."},"input":{"type":"object","description":"Action arguments matching extension_describe.actions[].input_schema. Do not put these fields at the top level.","default":{}}},"required":["project_id","plugin_id","action"],"additionalProperties":false}},
        {"name":"job_status","description":"Read compact extension job state, phase, request-weighted progress, and recommended_poll_interval_ms. Progress is not requests actually sent; use job_results execution metadata for returned/skipped observations. Honor the returned interval before polling again, or pass wait_ms to wait for the job to end.","inputSchema":{"type":"object","properties":{"job_id":{"type":"string","format":"uuid"},"wait_ms":{"type":"integer","minimum":0,"maximum":30000,"default":0,"description":"Wait up to this long for the job to end instead of polling; returns as soon as it does."}},"required":["job_id"],"additionalProperties":false}},
        {"name":"job_cancel","description":"Cancel an active extension job.","inputSchema":{"type":"object","properties":{"job_id":{"type":"string","format":"uuid"}},"required":["job_id"],"additionalProperties":false}},
        {"name":"job_resume_analysis","description":"Retry only a failed resumable aggregation stage without replaying network probes, then resume normal status polling. The memory-only checkpoint must be retried before restart; timeout is bounded to 120000 ms.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"job_id":{"type":"string","format":"uuid"},"js_stage_timeout_ms":{"type":"integer","minimum":250,"maximum":120000}},"required":["project_id","job_id"],"additionalProperties":false}},
        {"name":"job_results","description":"Read available extension output, including partial results after failure or cancellation. summary (default) and full preserve host execution counts; returned observations do not establish clean coverage. findings returns a stable page; full returns complete non-finding data plus a paged findings array.","inputSchema":{"type":"object","properties":{"job_id":{"type":"string","format":"uuid"},"view":{"type":"string","enum":["summary","findings","full"],"default":"summary"},"offset":{"type":"integer","minimum":0,"default":0},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}},"required":["job_id"],"additionalProperties":false}},
        {"name":"capture_sessions","description":"List proxy capture credentials, create a one-time credential, revoke one, or renew one. create returns the secret once; copy it immediately. revoke and renew require session_id. This does not start Chromium; use browser_start for browser traffic.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","create","revoke","renew"]},"session_id":{"type":"integer","description":"Required for revoke and renew."}},"required":["project_id","action"],"additionalProperties":false}},
        {"name":"cookies","description":"Set, list, or clear project cookies without exposing their values. Set requires target_url and exactly one of cookie or file_path; with file_path, target_url may be omitted when the JSON cookies carry exactly one domain (https://<domain> is used); clear requires target_url unless profile_name is supplied. Set accepts a raw Cookie header, a browser-export JSON cookie array, or a session object {\"cookies\":[...],\"origins\":[{\"origin\":\"https://app.example\",\"localStorage\":[{\"name\",\"value\"}],\"sessionStorage\":[{\"name\",\"value\"}]}]} (Playwright storageState plus optional per-origin sessionStorage; cookies may be empty). Origins must be exact http(s) origins without a path, and storage requires profile_name (project cookies have no browser to seed). Input up to 4 MiB. list reports only an origin_count, never keys or values. Project cookies apply to HTTP tools and ephemeral sessions. Persistent browser jars change only with an explicit browser_start(cookie_profile=...). profile_name stores a reusable named cookie identity for extensions or browser_start(cookie_profile=...) without changing an already running browser.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["set","list","clear"]},"target_url":{"type":"string"},"profile_name":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$","description":"Optional reusable identity name. Pass the same name as browser_start.cookie_profile to seed a persistent Chromium profile."},"cookie":{"oneOf":[{"type":"string","description":"Raw Cookie header or a string containing a JSON cookie array or session object."},{"type":"object","description":"Session object: cookies plus per-origin localStorage/sessionStorage. Requires profile_name when origins are present.","properties":{"cookies":{"type":"array","items":{"type":"object"}},"origins":{"type":"array","items":{"type":"object","properties":{"origin":{"type":"string"},"localStorage":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"}},"required":["name","value"]}},"sessionStorage":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"}},"required":["name","value"]}}},"required":["origin"]}}}},{"type":"array","description":"Browser-export or Playwright cookie array.","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"},"domain":{"type":"string"},"hostOnly":{"type":"boolean"},"path":{"type":"string"},"httpOnly":{"type":"boolean"},"secure":{"type":"boolean"},"sameSite":{"type":"string"},"session":{"type":"boolean"},"expirationDate":{"type":"number"},"expires":{"type":"number"}},"required":["name","value"]}}]},"file_path":{"type":"string","description":"Local UTF-8 file (up to 4 MiB) containing a raw Cookie header, JSON cookie array, or session object with cookies and origins."}},"required":["project_id","action"]}},
        request_rules_tool_def(),
        {"name":"overview","description":"Summarize one project's saved activity: total exchanges and counts by source, captured replies sent, findings, distinct hosts, and last exchange time.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"}},"required":["project_id"],"additionalProperties":false}},
        {"name":"history_search","description":format!("Search saved project history, newest first, across all hosts and MIME types; active browser responses appear once captured. {} Pages fit the output budget; pass next as cursor to continue. When an AND query matches nothing, no_match_terms lists its terms that match nothing alone. Rows omit bodies; read exchanges with exchange_get.", view::EXCHANGE_ROW_NOTE),"inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"q":{"type":"string","description":format!("{HISTORY_QUERY_SYNTAX}. Comparisons: >, >=, <, <=, !=. time compares stored UTC RFC 3339 text, not Unix seconds. duration is milliseconds; request_size and response_size are body bytes. Fields: exchange_id, host, authority, path, query, url (scheme://authority/path?query), method, protocol, status, mime, source, label, request_size, response_size, duration, title, page_title, display_title, parent, browser_session, capture_session, reply_tab, fuzz_job, request_hash, response_hash, time, error, request, response. request:~text searches the request line, headers and decoded body; response:~text searches response headers and decoded body; both are slow on broad queries, so add host, method, time or size terms. Bare words search host, path, mime, title and error. Adjacent terms are AND; NOT binds before AND, then OR."),"examples":["host:example.com method:GET status>=400","time>2026-10-12T00:00:00Z","duration>=1000 response_size>1024","(request:~\"monthly report\" OR request:~summary) method:PUT"]},"limit":{"type":"integer","minimum":1,"maximum":500,"default":50},"cursor":{"description":"next from the previous page.","oneOf":[{"type":"array","items":{"type":["string","integer"]},"minItems":2,"maxItems":2},{"type":"string"},{"type":"null"}]}},"required":["project_id"],"additionalProperties":false}},
        {"name":"sitemap","description":"Discover saved routes. Omit host for a lightweight list of hosts and route counts. With one exact host, list its routes sorted by path, optionally under path_prefix; routes omit empty lists and exchange_count 1. Pass next_offset as offset to continue.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"host":{"type":"string","description":"Exact hostname, case-insensitive."},"path_prefix":{"type":"string","description":"Slash-boundary path subtree, such as /api. Requires host."},"offset":{"type":"integer","minimum":0}},"required":["project_id"],"additionalProperties":false}},
        {"name":"findings","description":"List findings, mark an exchange as a finding, or remove a finding.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","add","remove"]},"exchange_id":{"type":"integer","description":"Required for add."},"finding_id":{"type":"integer","description":"Required for remove."},"title":{"type":"string","description":"Required for add."},"description":{"type":"string","description":"Required for add."}},"required":["project_id","action"]}},
        {"name":"exchange_get","description":"Read exchanges in one call: summary, headers as \"name: value\" (secrets redacted, noisy hidden) and bodies inline up to body_bytes per side. A cut body has next_offset; continue, search or save it with exchange_body. exchange_ids reads up to 20; ids that do not fit are in not_returned; headers=compact (low-signal headers hidden, long values cut) or none fits more ids per call.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"exchange_ids":{"type":"array","items":{"type":"integer"},"minItems":1,"maxItems":exchange_view::MAX_BATCH_IDS,"description":"Instead of exchange_id."},"body_bytes":{"type":"integer","minimum":0,"maximum":exchange_view::MAX_INLINE_BODY_BYTES,"default":4096,"description":"0 omits bodies."},"headers":{"type":"string","enum":["full","compact","none"],"default":"full","description":"compact hides low-signal headers (hidden_headers names them) and cuts values over 256 characters; none omits headers."}},"required":["project_id"],"additionalProperties":false}},
        {"name":"exchange_compare","description":"Compare the saved request and response of two exchanges. Lists only differences; unchanged names matching parts. Sensitive values stay redacted but are still compared. Cuts are marked (text_diff_truncated, headers_omitted).","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"left_exchange_id":{"type":"integer"},"right_exchange_id":{"type":"integer"},"include_noisy_headers":{"type":"boolean","default":false}},"required":["project_id","left_exchange_id","right_exchange_id"],"additionalProperties":false}},
        {"name":"page_analyzer","description":"Extract sorted, unique endpoints, absolute URLs, emails, and request parameter names from JavaScript or HTML without executing it. Provide exactly one saved exchange_id or absolute URL. The tool analyzes that page and sequentially fetches bounded same-origin JavaScript bundles referenced by script tags or a Modern.js route manifest; URL mode first sends a semantic GET with project cookies. CSS and other non-JavaScript assets are skipped. Extracted values may contain secrets.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer","description":"Saved exchange whose decoded response body and same-origin JavaScript bundles should be analyzed."},"url":{"type":"string","description":"Absolute http/https URL to fetch and analyze, including its same-origin JavaScript bundles."}},"required":["project_id"],"oneOf":[{"required":["exchange_id"]},{"required":["url"]}],"additionalProperties":false}},
        {"name":"copy_as","description":"Convert a saved request to cURL or Python requests. The output includes the original sensitive headers by default so it is immediately runnable; set include_secrets=false to produce a redacted copy.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"format":{"type":"string","enum":["curl","python_requests"]},"include_secrets":{"type":"boolean","default":true}},"required":["project_id","exchange_id","format"],"additionalProperties":false}},
        {"name":"exchange_body","description":"Read a body beyond what exchange_get inlines. Pages fit the output budget; continue at next_offset while truncated. search finds a literal, ASCII case-insensitive string; match offsets work as offset. save writes the whole body to a private file and returns its path for local tools. Responses are decoded (gzip/br/deflate/zstd) unless raw=true, which also reads a body whose decoding fails; side=request redacts raw HTTP/1.1 request headers. available=false means no body. utf8 is lossy for non-UTF-8 bytes; encoding=base64 is exact.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"side":{"type":"string","enum":["request","response"],"default":"response"},"offset":{"type":"integer","minimum":0,"default":0},"max_bytes":{"type":"integer","minimum":1,"maximum":exchange_view::MAX_PAGE_BYTES,"default":16384},"raw":{"type":"boolean","default":false},"encoding":{"type":"string","enum":["utf8","base64"],"default":"utf8"},"search":{"type":"string"},"context_bytes":{"type":"integer","minimum":0,"maximum":exchange_view::MAX_CONTEXT_BYTES,"default":160,"description":"Context around each search match."},"save":{"type":"boolean","default":false}},"required":["project_id","exchange_id"],"additionalProperties":false}},
        {"name":"secret_reveal","description":"Reveal a sensitive header value (audited)","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"side":{"type":"string","enum":["request","response"],"default":"request"},"header":{"type":"string"}},"required":["project_id","exchange_id","header"]}},
        {"name":"reply_tabs","description":"List or create Reply tabs. Draft fields are optional.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","create"]},"name":{"type":"string"},"base_exchange_id":{"type":"integer"},"draft":reply_draft_schema()},"required":["project_id","action"]}},
        {"name":"reply_send","description":"Send a semantic HTTP request and return status, a decoded 4 KiB response preview and the saved exchange_id; read more of the response with exchange_body. With base_exchange_id, diff gives the base status, length and whether the body is identical. Put request fields under draft (for example draft.url and draft.method); omitted draft fields use safe defaults or inherit from base_exchange_id. upstream_proxy is a transient http://, socks5://, or socks5h:// override.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"tab_id":{"type":"integer"},"base_exchange_id":{"type":"integer"},"draft":reply_draft_schema(),"protocol":{"type":"string","enum":["auto","h1","h2"]},"upstream_proxy":{"type":"string"},"response_headers":{"type":"boolean","description":"Also return the response headers as \"name: value\" lines, secrets redacted."},"preview_bytes":{"type":"integer","minimum":0,"maximum":16384,"default":4096,"description":"Response preview size in bytes."}},"required":["project_id"],"additionalProperties":false}},
        {"name":"reply_send_raw","description":"Send exact raw HTTP/1.1 bytes, optionally through an upstream proxy, split-writing at one byte offset, reading an early response before same-socket continuation, half-closing the write side, and collecting multiple responses until idle. Use base64 whenever byte offsets or non-UTF-8 bytes matter. With use_project_cookies the project Cookie header replaces any in the request, and bare LF line endings in the header block are sent as CRLF. This does not provide malformed HTTP/2 framing.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"target_url":{"type":"string"},"request":{"type":"string"},"encoding":{"type":"string","enum":["utf8","base64"]},"tab_id":{"type":"integer"},"use_project_cookies":{"type":"boolean"},"upstream_proxy":{"type":"string","description":"Transient http://, socks5://, or socks5h:// proxy override."},"pause_at_byte":{"type":"integer","minimum":1,"description":"Split the exact decoded request at this byte offset."},"pause_ms":{"type":"integer","minimum":1,"maximum":120000},"await_response_before_continue":{"type":"boolean","default":false,"description":"Read one early response while the split request is incomplete, then continue on the same connection."},"half_close_write":{"type":"boolean","default":false},"response_mode":{"type":"string","enum":["auto","until_idle","until_close"],"default":"auto"},"read_timeout_ms":{"type":"integer","minimum":1,"maximum":120000,"default":60000},"idle_timeout_ms":{"type":"integer","minimum":1,"maximum":10000,"default":1000}},"required":["project_id","target_url","request"]}},
        {"name":"fuzz_start","description":"Start a bounded fuzz job. Put §name§ markers in draft.url, a header override, or the body (body_text, body_override, body_json strings or body_params); use the same name in insertion_points. Payloads may be inline wordlists, local UTF-8 wordlist_files, inclusive number ranges, or native Recollapse-style regex bypass generators. Returns the queued job at once; fuzz_manage get with wait_ms returns as soon as it ends.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"template":fuzz_template_schema(),"confirm_large":{"type":"boolean","default":false}},"required":["project_id","template"]}},
        {"name":"fuzz_manage","description":"List, inspect, cancel, group, diff, or page through fuzz jobs and cases. Case results include their saved exchange_id; exchange_get with exchange_ids reads several without replaying them. Pages fit the output budget: continue cases and group_cases with before_case_index=next_before_case_index, and groups (largest first) with offset=next_offset.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","get","cancel","cases","groups","group_cases","diff"]},"job_id":{"type":"integer"},"case_id":{"type":"integer"},"baseline_case_id":{"type":"integer"},"group_id":{"type":"string"},"include_text":{"type":"boolean","default":false},"limit":{"type":"integer","minimum":1,"maximum":500},"before_case_index":{"type":"integer","minimum":0},"offset":{"type":"integer","minimum":0,"description":"groups: next_offset from the previous page."},"wait_ms":{"type":"integer","minimum":0,"maximum":30000,"default":0,"description":"get: wait up to this long for the job to end instead of polling; returns as soon as it does."}},"required":["project_id","action"],"additionalProperties":false}},
        {"name":"websocket_manage","description":"List intercepted WebSocket connections and messages, read one message's whole payload, or inject a text/binary message into an active connection. messages lists the oldest first with the first 2 KB of each payload (payload_cut=true when there is more); pages fit the output budget, so continue with after_id=next_after_id while it is present. message reads one payload by message_id; continue at next_offset while truncated.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","messages","message","send"]},"connection_id":{"type":"integer","description":"Required for messages and send."},"after_id":{"type":"integer","description":"messages: list messages with a larger id; pass next_after_id."},"limit":{"type":"integer","minimum":1,"maximum":1000,"default":250,"description":"Most connections or messages to list; a messages page may hold fewer to fit the output budget."},"message_id":{"type":"integer","description":"Required for message."},"offset":{"type":"integer","minimum":0,"default":0,"description":"message: payload byte to start at; pass next_offset."},"max_bytes":{"type":"integer","minimum":1,"maximum":exchange_view::MAX_PAGE_BYTES,"default":16384,"description":"message: most payload bytes to read; a page may hold fewer to fit the output budget."},"direction":{"type":"string","enum":["to_server","to_client"]},"encoding":{"type":"string","enum":["text","base64"],"description":"send: how payload is written (default text). message: how the page is written; by default text for UTF-8 payloads, base64 otherwise."},"payload":{"type":"string"}},"required":["project_id","action"],"additionalProperties":false}},
        {"name":"browser_profiles","description":"List, create, or delete named persistent Chromium identities for a project. default always exists and cannot be deleted. Deleting a named profile requires it to be stopped first.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","create","delete"]},"profile":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$","description":"Required for create and delete."}},"required":["project_id","action"],"additionalProperties":false}},
        {"name":"browser_start","description":"Start or resume a persistent Chromium identity. profile defaults to default; different profiles can stay open simultaneously and each returns its own session_id. Omitting cookie_profile preserves the browser jar without injecting project or named cookies. Pass a matching cookie_profile created by cookies(profile_name=...) to seed its cookie jar. A seed also writes any localStorage/sessionStorage saved with the cookie profile, on the main tab before the first navigation and without contacting the target, so token-based apps load authenticated; sessionStorage exists only on that tab, not in tabs opened later. Repeated unchanged seeds preserve newer browser cookies and storage; use refresh_cookies=true to explicitly reimport. An active matching profile is resumed without relaunching. Omit url to resume the selected profile's last page.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"profile":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$","default":"default"},"cookie_profile":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$","description":"Must match profile, which defaults to it. Seeds new or changed cookies and storage; unchanged seeds are not reimported unless refresh_cookies=true."},"refresh_cookies":{"type":"boolean","default":false,"description":"Requires matching cookie_profile; explicitly reimports it into this browser profile."},"url":{"type":"string","default":"about:blank","description":"Optional page to open. Omitted or about:blank resumes the selected profile's last page."}},"required":["project_id"],"additionalProperties":false}},
        {"name":"browser_action","description":"Navigate, inspect, or interact with an active browser session. Required project_id and session_id are integer IDs returned by projects and browser_start. For pages, supply op; select/close also require page_id and runtime_generation. For wait, supply for_what and value. For events with after_sequence greater than 0, supply the matching runtime_generation. Structured Playwright action. Use pages to list/select/open/close tabs and events to observe popups, dialogs, navigation, requests, console errors, and window messages. console, page_error and dialog events carry the first 1000 characters of their text. Page IDs and event cursors are valid only for their runtime_generation. request sends one same-origin request with the live browser cookie jar, disables redirects/retries, and returns a bounded base64 body preview; use history_search for saved proxy evidence. screenshot returns an MCP image. Prefer accessibility snapshots: scope large pages with locator or page with offset, and add snapshot:true to an interaction instead of a separate snapshot call. A locator's nth picks one of several matches and its frame acts inside an iframe; pages list names each page's frames. Use browser_input for mouse input at a point, hover, drag and typed keystrokes, and browser_evaluate to run JavaScript in the page.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer","description":"Required integer ID returned by projects; owns session."},"session_id":{"type":"integer","description":"Required integer ID returned by browser_start."},"action":browser_action_schema()},"required":["project_id","session_id","action"],"additionalProperties":false}},
        {"name":"browser_evaluate","description":"Run JavaScript in the selected page of an active browser session and return its result. Use it to read page state and globals, call the application's own functions and APIs with the live session, or reach DOM that locators cannot; do not enable browser_cdp to script the page. expression runs in the page's main world as in the DevTools console: statements and top-level await work, declarations may be repeated between calls, a () => ... function source is called, and console helpers such as getEventListeners() and $$() are available. The page's CSP does not restrict it. frame runs it in one frame of the page instead, including cross-origin frames; browser_action pages lists them. data.content is the result: a string or DOM node (its outerHTML) as text, anything else as JSON; data.type names the JavaScript type, and a thrown exception is returned with type exception. content is cut to fit and then reports truncated with total_bytes, so return only what you need. Requests the page sends are captured in History like other browser traffic. Choose the tab with browser_action pages.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer","description":"Required integer ID returned by projects; owns session."},"session_id":{"type":"integer","description":"Required integer ID returned by browser_start."},"expression":{"type":"string","minLength":1,"maxLength":65536,"description":"JavaScript, at most 65536 bytes. The value of the last expression is returned, and a promise is awaited."},"frame":{"type":"string","minLength":1,"maxLength":2048,"description":"Frame name, or part of its URL, matching exactly one frame of the selected page. Omit for the page itself."},"timeout_ms":{"type":"integer","minimum":1,"maximum":30000,"default":10000,"description":"Stop waiting after 1..30000 ms, default 10000; a running loop is terminated."}},"required":["project_id","session_id","expression"],"additionalProperties":false}},
        browser_input_tool_def(),
        {"name":"browser_cdp","description":"Hand an active persistent Chromium session to a person through loopback Chrome DevTools on an available port from 9222 to 9321, inspect handoff status, or return control to the agent. This is a handoff to a person, not a scripting interface: to run JavaScript in the page yourself, call browser_evaluate, and for mouse or keyboard input browser_input. While enabled, browser_action, browser_evaluate and browser_input are paused for that session. Status accepts an optional session_id; without it, active_sessions lists the project’s handoffs. On a VPS, use ssh_forward_command when returned; otherwise forward the returned cdp_port to the same port on 127.0.0.1 over SSH. Try hosted_devtools_url first, then devtools_url if the browser restricts the hosted frontend’s local-network WebSocket.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"session_id":{"type":"integer","description":"Required for enable and disable; optional for status."},"op":{"type":"string","enum":["enable","status","disable"]}},"required":["project_id","op"],"additionalProperties":false}},
        {"name":"browser_manage","description":"Get status, suspend one browser, suspend all project browsers, or reset one persistent Chromium profile. Status without session_id lists active browser sessions and resources: per-project capacity including ephemeral sessions, verified profile ownership, and cdp_port_in_use, which is true when the CDP port range is exhausted. Reuse these observations until a lifecycle transition or browser error; capacity is not a reservation. Stop operations preserve browser state. reset_profile defaults to default, requires confirm=true, and clears only that profile's browser-derived state.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"session_id":{"type":"integer","description":"Required for stop; optional for status."},"profile":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$","default":"default","description":"Profile to reset when op=reset_profile."},"op":{"type":"string","enum":["status","stop","stop_all","reset_profile"]},"confirm":{"type":"boolean","default":false,"description":"Must be true for reset_profile because browser state is permanently deleted."}},"required":["project_id","op"],"additionalProperties":false}},
        {"name":"js_files","description":"List JavaScript files sorted by URL, with the pages that loaded them. Without url, search saved history and provenance; with url, load that page in Chromium first. domain matches the script host or its page host, including subdomains; saved history also includes scripts from browser sessions with matching evidence, and related_via_session marks files included only that way. Rows omit status_code 200, nulls and false; pages lists up to 3 page URLs, with page_count when there are more. Pass next_offset as offset to continue.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"url":{"type":"string","description":"When provided, perform a fresh browser load before collecting files."},"domain":{"type":"string","description":"Exact domain plus subdomains; accepts target.com, *.target.com, or a full URL."},"settle_ms":{"type":"integer","minimum":0,"maximum":30000,"default":2000},"limit":{"type":"integer","minimum":1,"maximum":10000,"default":2000},"offset":{"type":"integer","minimum":0}},"required":["project_id"]}},
        {"name":"get_words","description":"Build a sorted target-specific wordlist from saved request paths, parameter names, and textual responses. Related JavaScript files are included by default. Optionally filter by a domain and its subdomains.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"domain":{"type":"string","description":"Optional hostname, wildcard hostname, or HTTP URL."},"include_js":{"type":"boolean","default":true},"limit":{"type":"integer","minimum":1,"maximum":10000,"default":5000}},"required":["project_id"],"additionalProperties":false}},
        {"name":"huntproxy_stop","description":"Gracefully stop HuntProxy and all managed browsers. Keeps this MCP connection available; call huntproxy_restart to continue later. Use only when the user explicitly asks to stop HuntProxy.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"huntproxy_restart","description":"Restart or recover HuntProxy without reconnecting the agent's MCP session. Preserves saved projects, traffic, findings, Reply/Fuzzer state, and browser profiles. Active browsers close and can be resumed using browser_start. Running jobs are interrupted; memory-only plugin results/checkpoints are lost. Use when the user asks to restart or to continue after HuntProxy has stopped.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"codec_transform","description":"Apply byte transforms, including gzip_decode/gunzip and brotli_decode","inputSchema":{"type":"object","properties":{"input":{"type":"string"},"input_encoding":{"type":"string","enum":["utf8","base64","hex"],"default":"utf8"},"pipeline":{"type":"array","items":{"type":"string"}}},"required":["input","pipeline"]}},
        {"name":"evidence_export","description":"Write one exchange to a private JSON file: metadata, redacted headers and decoded bodies (text, or base64 when not UTF-8). Returns path and bytes.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"include_bodies":{"type":"boolean","default":true}},"required":["project_id","exchange_id"],"additionalProperties":false}},
        {"name":"project_transfer","description":"Import or export a project bundle or HAR through a local file. By default HAR omits sensitive headers including cookies but keeps URLs, queries, and bodies; project bundles omit credentials, bodies, replay and browser state. include_secrets includes credentials; browser state also requires include_chromium_profile=true. Returns a summary/path, never archive bytes.","inputSchema":{"type":"object","properties":{"action":{"type":"string","enum":["export","import"]},"format":{"type":"string","enum":["huntproxy","har"]},"project_id":{"type":"integer","description":"Required for export and HAR import."},"file_path":{"type":"string","description":"Required for import; optional export destination. Defaults to the configured exports directory."},"include_secrets":{"type":"boolean","default":false},"include_chromium_profile":{"type":"boolean","default":false}},"required":["action","format"],"additionalProperties":false}},
        {"name":"exchange_annotate","description":"Replace an exchange title, note, and labels; omitted fields are cleared","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"display_title":{"type":["string","null"]},"note":{"type":["string","null"]},"labels":{"type":"array","items":{"type":"string"}},"expected_revision":{"type":"integer"}},"required":["project_id","exchange_id"]}}
    ])
}

/// Run the stdio MCP adapter as a thin client of the single daemon owner.
pub async fn run_stdio_mcp_client(config: Config) -> DomainResult<()> {
    // The inexpensive bridge must outlive an idle/stopped daemon so restart
    // and the next tool call remain available on the same client connection.
    run_stdio_backend(
        Arc::new(DaemonToolBackend::new(config)),
        std::time::Duration::ZERO,
    )
    .await
}

async fn run_stdio_backend(
    backend: Arc<dyn ToolBackend>,
    idle_timeout: std::time::Duration,
) -> DomainResult<()> {
    eprintln!("HuntProxy mcp: starting stdio JSON-RPC server");
    // Tokio's stdin reader uses a blocking runtime thread which cannot be
    // cancelled while the MCP client keeps its pipe open. A detached reader
    // lets the process actually exit when the inactivity timeout fires.
    let (line_tx, mut lines) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in BufReader::new(stdin.lock()).lines() {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });

    let poll_period = std::time::Duration::from_secs(5);
    let mut catalog_poll =
        tokio::time::interval_at(tokio::time::Instant::now() + poll_period, poll_period);
    catalog_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut initialized = false;

    loop {
        let next_line = if backend.supports_list_changed() && initialized {
            tokio::select! {
                line = lines.recv() => line,
                _ = catalog_poll.tick() => {
                    if backend.definitions_changed().await {
                        write_notification("notifications/tools/list_changed");
                    }
                    continue;
                }
            }
        } else if idle_timeout.is_zero() {
            lines.recv().await
        } else {
            match tokio::time::timeout(idle_timeout, lines.recv()).await {
                Ok(result) => result,
                Err(_) => {
                    eprintln!(
                        "HuntProxy mcp: idle for {} seconds; exiting",
                        idle_timeout.as_secs()
                    );
                    break;
                }
            }
        };
        let Some(line) = next_line else {
            break;
        };
        let line = match line {
            Ok(line) => line,
            // A line that is not valid UTF-8 is a malformed message, not a
            // broken pipe: answer with a parse error and keep serving.
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                write_response(parse_error_response(&e));
                continue;
            }
            Err(e) => {
                return Err(DomainError::new(
                    ErrorCode::ProtocolError,
                    format!("stdin: {e}"),
                ))
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let req: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                write_response(parse_error_response(&e));
                continue;
            }
        };
        if req.method == "initialize" {
            // Establish a catalog baseline before notifications become legal.
            let _ = backend.definitions().await;
        }
        if let Some(response) = dispatch_rpc(backend.clone(), &req).await {
            write_response(response);
        }
        if matches!(
            req.method.as_str(),
            "notifications/initialized" | "initialized"
        ) {
            // Catalog differences observed before initialization are already
            // reflected in the client's first tools/list response.
            backend.reset_definitions_changed().await;
            initialized = true;
        }
    }
    Ok(())
}

fn rpc_error_response(id: Option<Value>, code: i32, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message,
            data: None,
        }),
    }
}

fn parse_error_response(error: &dyn std::fmt::Display) -> JsonRpcResponse {
    rpc_error_response(None, -32700, format!("parse error: {error}"))
}

fn is_known_method(method: &str) -> bool {
    matches!(method, "initialize" | "ping" | "tools/list" | "tools/call")
        || is_notification_method(method)
}

fn is_notification_method(method: &str) -> bool {
    method == "initialized" || method.starts_with("notifications/")
}

/// Runs one decoded message and returns the response to write, if any.
/// Messages without an id are notifications and never get a response; they
/// are not executed unless they are known notification methods.
async fn dispatch_rpc(
    backend: Arc<dyn ToolBackend>,
    req: &JsonRpcRequest,
) -> Option<JsonRpcResponse> {
    let Some(id) = req.id.clone() else {
        if is_notification_method(&req.method) {
            if let Err(error) = handle_rpc(backend, req).await {
                eprintln!("HuntProxy mcp: notification {} failed: {error}", req.method);
            }
        } else {
            eprintln!(
                "HuntProxy mcp: ignoring request {} without an id",
                req.method
            );
        }
        return None;
    };
    if !is_known_method(&req.method) {
        return Some(rpc_error_response(
            Some(id),
            -32601,
            format!("method not found: {}", req.method),
        ));
    }
    Some(match handle_rpc(backend, req).await {
        Ok(Some(value)) => JsonRpcResponse {
            jsonrpc: "2.0",
            id: Some(id),
            result: Some(value),
            error: None,
        },
        // A request with an id always gets exactly one response.
        Ok(None) => JsonRpcResponse {
            jsonrpc: "2.0",
            id: Some(id),
            result: Some(json!({})),
            error: None,
        },
        Err(e) => JsonRpcResponse {
            jsonrpc: "2.0",
            id: Some(id),
            result: None,
            error: Some(JsonRpcError {
                code: match e.code() {
                    ErrorCode::InvalidArgument => -32602,
                    ErrorCode::NotFound => -32001,
                    _ => -32000,
                },
                message: e.to_string(),
                data: Some(json!({ "code": e.code().as_str() })),
            }),
        },
    })
}

fn write_response(resp: JsonRpcResponse) {
    let mut out = std::io::stdout().lock();
    if let Ok(s) = serde_json::to_string(&resp) {
        let _ = writeln!(out, "{s}");
        let _ = out.flush();
    }
}

fn write_notification(method: &str) {
    let mut out = std::io::stdout().lock();
    let notification = json!({ "jsonrpc": "2.0", "method": method });
    if let Ok(serialized) = serde_json::to_string(&notification) {
        let _ = writeln!(out, "{serialized}");
        let _ = out.flush();
    }
}

#[cfg(unix)]
async fn call_daemon_tool(config: &Config, name: &str, args: Value) -> DomainResult<Value> {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::client::conn::http1;
    use hyper::Request;
    use hyper_util::rt::TokioIo;

    let stream = tokio::net::UnixStream::connect(config.socket_path())
        .await
        .map_err(|e| {
            DomainError::new(
                ErrorCode::DaemonNotRunning,
                format!("connect daemon socket: {e}"),
            )
        })?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "MCP daemon connection closed");
        }
    });

    let payload = serde_json::to_vec(&DaemonToolRequest {
        name,
        arguments: args,
    })
    .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?;
    let request = Request::post("/internal/mcp/call")
        .header(hyper::header::HOST, "localhost")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(payload)))
        .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| DomainError::new(ErrorCode::Unavailable, e.to_string()))?;
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?
        .to_bytes();
    let envelope: DaemonToolResponse = serde_json::from_slice(&bytes)
        .map_err(|e| DomainError::new(ErrorCode::ProtocolError, e.to_string()))?;
    if status.is_success() {
        return envelope
            .result
            .ok_or_else(|| DomainError::new(ErrorCode::ProtocolError, "daemon omitted result"));
    }
    let error = envelope.error.unwrap_or(ErrorEnvelope {
        code: ErrorCode::Unavailable.as_str().into(),
        message: format!("daemon returned HTTP {status}"),
        details: None,
        request_id: None,
    });
    Err(DomainError::with_details(
        ErrorCode::from_code(&error.code).unwrap_or(ErrorCode::Unavailable),
        error.message,
        json!({ "daemon_code": error.code, "details": error.details }),
    ))
}

#[cfg(unix)]
async fn fetch_daemon_tool_catalog(config: &Config) -> DomainResult<Option<DaemonToolCatalog>> {
    const MAX_CATALOG_BYTES: usize = 2 * 1024 * 1024;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::client::conn::http1;
    use hyper::{Request, StatusCode};
    use hyper_util::rt::TokioIo;

    let fetch = async {
        let stream = match tokio::net::UnixStream::connect(config.socket_path()).await {
            Ok(stream) => stream,
            Err(_) => return Ok(None),
        };
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "MCP catalog connection closed");
            }
        });
        let request = Request::get("/internal/mcp/tools")
            .header(hyper::header::HOST, "localhost")
            .body(Full::new(Bytes::new()))
            .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| DomainError::new(ErrorCode::Unavailable, error.to_string()))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                format!("daemon tool catalog returned HTTP {}", response.status()),
            ));
        }
        let bytes = Limited::new(response.into_body(), MAX_CATALOG_BYTES)
            .collect()
            .await
            .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))?
            .to_bytes();
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| DomainError::new(ErrorCode::ProtocolError, error.to_string()))
    };

    tokio::time::timeout(std::time::Duration::from_secs(2), fetch)
        .await
        .map_err(|_| DomainError::new(ErrorCode::Timeout, "daemon tool catalog timed out"))?
}

#[cfg(not(unix))]
async fn fetch_daemon_tool_catalog(_config: &Config) -> DomainResult<Option<DaemonToolCatalog>> {
    Ok(None)
}

#[cfg(not(unix))]
async fn call_daemon_tool(_config: &Config, _name: &str, _args: Value) -> DomainResult<Value> {
    Err(DomainError::new(
        ErrorCode::Unavailable,
        "the private daemon MCP bridge currently requires a Unix-domain socket",
    ))
}

async fn handle_rpc(
    backend: Arc<dyn ToolBackend>,
    req: &JsonRpcRequest,
) -> DomainResult<Option<Value>> {
    match req.method.as_str() {
        "initialize" => Ok(Some(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": { "listChanged": backend.supports_list_changed() } },
            "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION }
        }))),
        method if is_notification_method(method) => Ok(None),
        "ping" => Ok(Some(json!({}))),
        "tools/list" => Ok(Some(json!({ "tools": backend.definitions().await }))),
        "tools/call" => {
            let name = req
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| DomainError::invalid("tools/call requires name"))?;
            let args = req
                .params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let (result, is_error) = match backend.call(name, args).await {
                Ok(result) => (result, false),
                Err(error) if name == "history_search" && is_history_query_error(&error) => {
                    (json!(ErrorEnvelope::from(&error)), true)
                }
                Err(error) => return Err(error),
            };
            Ok(Some(tool_call_result(name, result, is_error)))
        }
        other => Err(DomainError::invalid(format!("unknown method {other}"))),
    }
}

/// Request fields an agent may put beside `draft` instead of inside it.
const LIFTED_DRAFT_FIELDS: [&str; 12] = [
    "method",
    "url",
    "identity",
    "header_overrides",
    "header_tombstones",
    "inheritance",
    "body_override",
    "body_text",
    "body_json",
    "body_format",
    "body_params",
    "body_cleared",
];

/// The request `draft` of a tool call: the `draft` argument plus any request
/// field given at the top level, which moves into it unless `draft` already
/// sets that field. A field set in both places must agree.
fn request_draft_value(args: &Value) -> DomainResult<Option<Value>> {
    for (field, hint) in [
        (
            "headers",
            "put `header_overrides`: [{\"name\", \"value\"}] under `draft`",
        ),
        (
            "body",
            "put `body_text`, `body_json`, or `body_params` under `draft`",
        ),
    ] {
        if arguments::present(args, field).is_some() {
            return Err(DomainError::invalid(format!(
                "`{field}` is not a request field; {hint}"
            )));
        }
    }
    let mut draft = arguments::present(args, "draft").cloned();
    if let Some(Value::Object(fields)) = &mut draft {
        // A client that sends every property sends null for the unused ones.
        fields.retain(|_, value| !value.is_null());
    }
    for field in LIFTED_DRAFT_FIELDS {
        let Some(value) = arguments::present(args, field) else {
            continue;
        };
        let Value::Object(fields) = draft.get_or_insert_with(|| json!({})) else {
            return Err(DomainError::invalid("draft must be an object"));
        };
        match fields.get(field) {
            None => {
                fields.insert(field.into(), value.clone());
            }
            Some(existing) if existing == value => {}
            Some(_) => {
                return Err(DomainError::invalid(format!(
                    "`{field}` is set both at the top level and in `draft` with different values; keep it under `draft`"
                )))
            }
        }
    }
    Ok(draft)
}

/// The protocol preference, accepting the usual spellings of HTTP/1.1 and HTTP/2.
fn parse_protocol(value: Option<&str>) -> DomainResult<ProtocolPreference> {
    match value
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        None | Some("auto") => Ok(ProtocolPreference::Auto),
        Some("h1" | "http1" | "http/1" | "http1.1" | "http/1.1") => Ok(ProtocolPreference::H1),
        Some("h2" | "http2" | "http/2") => Ok(ProtocolPreference::H2),
        Some(_) => Err(DomainError::invalid(
            "protocol must be auto, h1 or h2 (http/1.1 and http/2 also work)",
        )),
    }
}

/// The response headers as exchange_get shows them: `name: value` lines with
/// secrets redacted and noisy headers hidden.
fn response_header_lines(result: &crate::reply::ReplySendResult) -> Value {
    let presented = match (&result.saved_response, &result.response) {
        (Some(saved), _) => {
            let options = crate::policy::PresentationOptions::default();
            crate::policy::present_headers(&saved.headers, &options).headers
        }
        (None, Some(unsaved)) => unsaved.headers.clone(),
        (None, None) => Vec::new(),
    };
    exchange_view::header_lines(&presented)
}

/// The options of a raw send, read from the tool arguments. Null counts as
/// absent and the numbers may be quoted.
fn raw_http1_options(args: &Value) -> DomainResult<crate::reply::RawHttp1Options> {
    let mut options = args.as_object().cloned().unwrap_or_default();
    options.retain(|_, value| !value.is_null());
    for field in [
        "pause_at_byte",
        "pause_ms",
        "read_timeout_ms",
        "idle_timeout_ms",
    ] {
        match arguments::optional_u64(args, field)? {
            Some(number) => options.insert(field.into(), json!(number)),
            None => options.remove(field),
        };
    }
    serde_json::from_value(Value::Object(options))
        .map_err(|error| DomainError::invalid(format!("raw HTTP/1.1 options: {error}")))
}

/// Parses a request-supplied `draft`, rejecting unknown keys so fields such as
/// `headers` or `body` are never silently dropped from the sent request.
fn parse_request_draft(draft: Option<&Value>) -> DomainResult<ReplyDraft> {
    let Some(draft) = draft else {
        return Ok(ReplyDraft::default());
    };
    validate_reply_draft_request(draft).map_err(DomainError::invalid)?;
    serde_json::from_value(draft.clone()).map_err(|e| DomainError::invalid(e.to_string()))
}

/// Accepts the `next` value returned by history_search (`[started_at, id]`),
/// or the HTTP API's `started_at:id` string form.
fn parse_history_cursor(cursor: Option<&Value>) -> DomainResult<(Option<String>, Option<i64>)> {
    let invalid = || {
        DomainError::invalid(
            "history_search cursor must be the `next` value from the previous page",
        )
    };
    match cursor {
        None | Some(Value::Null) => Ok((None, None)),
        Some(Value::Array(parts)) => match parts.as_slice() {
            [Value::String(started_at), Value::Number(id)] => Ok((
                Some(started_at.clone()),
                Some(id.as_i64().ok_or_else(invalid)?),
            )),
            _ => Err(invalid()),
        },
        Some(Value::String(text)) => {
            let (started_at, id) = text.rsplit_once(':').ok_or_else(invalid)?;
            Ok((
                Some(started_at.to_string()),
                Some(id.parse::<i64>().map_err(|_| invalid())?),
            ))
        }
        Some(_) => Err(invalid()),
    }
}

fn is_history_query_error(error: &DomainError) -> bool {
    let DomainError::App {
        code: ErrorCode::InvalidArgument,
        details: Some(details),
        ..
    } = error
    else {
        return false;
    };
    // The private daemon bridge retains domain details inside its envelope.
    let is_query =
        |value: &Value| value.get("kind").and_then(Value::as_str) == Some("history_query");
    is_query(details) || details.get("details").is_some_and(is_query)
}

fn object_structured_content(result: Value) -> Value {
    if result.is_object() {
        result
    } else {
        json!({ "result": result })
    }
}

/// Builds the MCP `tools/call` result. The text content is the compact
/// serialization of `structuredContent`, and both carry the same value fitted
/// to [`budget::MAX_OUTPUT_BYTES`]. A browser screenshot moves to MCP image
/// content first, so its base64 is never counted or cut.
fn tool_call_result(name: &str, result: Value, is_error: bool) -> Value {
    let mut structured_content = object_structured_content(result);
    let image = if name == "browser_action" && !is_error {
        let encoded = structured_content
            .pointer("/data/image_base64")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mime_type = structured_content
            .pointer("/data/mime_type")
            .and_then(Value::as_str)
            .map(str::to_owned);
        encoded.zip(mime_type)
    } else {
        None
    };
    if image.is_some() {
        if let Some(data) = structured_content
            .get_mut("data")
            .and_then(Value::as_object_mut)
        {
            data.remove("image_base64");
            data.insert("image_in_content".into(), Value::Bool(true));
        }
    }
    let structured_content = budget::fit_to_budget(structured_content, budget::MAX_OUTPUT_BYTES);
    let mut content = vec![json!({
        "type": "text",
        "text": structured_content.to_string()
    })];
    if let Some((encoded, mime_type)) = image {
        content.push(json!({
            "type": "image",
            "data": encoded,
            "mimeType": mime_type
        }));
    }
    json!({
        "content": content,
        "structuredContent": structured_content,
        "isError": is_error
    })
}

fn require_project_id(args: &Value) -> DomainResult<ProjectId> {
    arguments::required_i64(args, "project_id").map(ProjectId)
}

async fn fetch_page_analyzer_bundle(
    state: &Arc<AppState>,
    project_id: ProjectId,
    source_url: &str,
    bundle_url: String,
) -> DomainResult<Option<crate::page_analyzer::ScriptBundleContent>> {
    if !crate::page_analyzer::same_origin_url(source_url, &bundle_url) {
        return Ok(None);
    }

    let parsed = url::Url::parse(&bundle_url)
        .map_err(|error| DomainError::invalid(format!("invalid bundle URL: {error}")))?;
    if !matches!(parsed.path().rsplit('/').next(), Some(name) if name.to_ascii_lowercase().ends_with(".js") || name.to_ascii_lowercase().ends_with(".mjs"))
    {
        return Ok(None);
    }

    let draft = ReplyDraft {
        method: Some("GET".into()),
        url: Some(bundle_url),
        ..Default::default()
    };
    let result = state
        .reply
        .send_same_origin(project_id, &draft, source_url)
        .await?;
    let effective_url = result.effective_url.clone();
    if !crate::page_analyzer::same_origin_url(source_url, &effective_url) {
        return Ok(None);
    }
    if let Some(exchange_id) = result.exchange_id {
        emit_event(
            state,
            project_id,
            "exchange",
            json!({ "exchange_id": exchange_id.get(), "source": "reply" }),
        );
        let content =
            crate::page_analyzer::load_exchange_content(&state.db, project_id, exchange_id).await?;
        return Ok(Some(crate::page_analyzer::ScriptBundleContent {
            source_url: content.source_url,
            body: content.body,
            status_code: content.status_code,
            content_type: content.content_type,
            completion: content.completion,
        }));
    }
    let Some(response) = result.response else {
        return Ok(None);
    };
    let (body, _, _) = crate::page_analyzer::decode_ephemeral_response(&response)?;
    Ok(Some(crate::page_analyzer::ScriptBundleContent {
        source_url: effective_url,
        body,
        status_code: Some(response.status_code),
        content_type: response
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-type"))
            .map(|header| header.value.clone()),
        completion: if response.body_truncated {
            crate::domain::CompletionState::TruncatedByPolicy
        } else {
            crate::domain::CompletionState::Complete
        },
    }))
}

async fn analyze_page_script_tree(
    state: &Arc<AppState>,
    project_id: ProjectId,
    source_url: String,
    body: Vec<u8>,
) -> crate::page_analyzer::ScriptTreeAnalysis {
    let fetch_state = state.clone();
    let fetch_source_url = source_url.clone();
    crate::page_analyzer::analyze_script_tree(&source_url, &body, |bundle_url| {
        let state = fetch_state.clone();
        let source_url = fetch_source_url.clone();
        async move { fetch_page_analyzer_bundle(&state, project_id, &source_url, bundle_url).await }
    })
    .await
}

fn page_analysis_tree_fields(
    tree: crate::page_analyzer::ScriptTreeAnalysis,
    root_incomplete: bool,
) -> Value {
    let analysis_incomplete =
        root_incomplete || tree.js_bundles_truncated || tree.js_bundle_failures > 0;
    let analysis = tree.analysis;
    json!({
        "endpoints": analysis.endpoints,
        "urls": analysis.urls,
        "emails": analysis.emails,
        "parameters": analysis.parameters,
        "stats": analysis.stats,
        "js_bundles": tree.js_bundles,
        "js_bundles_truncated": tree.js_bundles_truncated,
        "js_bundle_failures": tree.js_bundle_failures,
        "analysis_incomplete": analysis_incomplete,
    })
}

fn normalize_domain_filter(value: Option<&str>) -> DomainResult<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let value = value.trim_start_matches("*.");
    let parsed = if value.contains("://") {
        url::Url::parse(value)
    } else {
        url::Url::parse(&format!("http://{value}"))
    }
    .map_err(|error| DomainError::invalid(format!("invalid domain filter: {error}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| DomainError::invalid("domain filter requires a host"))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    Ok(Some(host))
}

fn host_matches_domain(host: &str, domain: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn emit_event(state: &AppState, project_id: ProjectId, kind: &str, payload: Value) {
    let _ = state.events.send(crate::app::AppEvent {
        project_id: project_id.get(),
        kind: kind.into(),
        payload,
    });
}

pub async fn call_tool(state: Arc<AppState>, name: &str, args: Value) -> DomainResult<Value> {
    // Any call about a project keeps that project's browsers open.
    // A malformed id is reported by the handler; here it only skips the touch.
    if let Ok(Some(project_id)) = arguments::optional_i64(&args, "project_id") {
        state.browser.touch_project(ProjectId(project_id));
    }
    match name {
        "extension_list" => Ok(json!({
            "plugin_directory": state.plugins.directory(),
            "plugins": state.plugins.list(),
            "load_issues": state.plugins.load_issues(),
        })),
        "extension_describe" => {
            let id = args
                .get("plugin_id")
                .and_then(Value::as_str)
                .ok_or_else(|| DomainError::invalid("plugin_id required"))?;
            Ok(json!(state.plugins.describe(id)?))
        }
        "extension_preview" => {
            let project_id = require_project_id(&args)?;
            let plugin_id = args
                .get("plugin_id")
                .and_then(Value::as_str)
                .ok_or_else(|| DomainError::invalid("plugin_id required"))?;
            let action = args
                .get("action")
                .and_then(Value::as_str)
                .ok_or_else(|| DomainError::invalid("action required"))?;
            let base_exchange_id =
                arguments::optional_i64(&args, "base_exchange_id")?.map(ExchangeId);
            let input = args.get("input").cloned().unwrap_or_else(|| json!({}));
            state
                .plugins
                .preview(project_id, plugin_id, action, base_exchange_id, input)
                .await
        }
        "extension_run" => {
            let project_id = require_project_id(&args)?;
            let plugin_id = args
                .get("plugin_id")
                .and_then(Value::as_str)
                .ok_or_else(|| DomainError::invalid("plugin_id required"))?;
            let action = args
                .get("action")
                .and_then(Value::as_str)
                .ok_or_else(|| DomainError::invalid("action required"))?;
            let base_exchange_id = if arguments::present(&args, "base_exchange_id").is_some() {
                arguments::optional_i64(&args, "base_exchange_id")?
            } else {
                arguments::optional_i64(&args, "exchange_id")?
            }
            .map(ExchangeId);
            let input = args.get("input").cloned().unwrap_or_else(|| json!({}));
            Ok(json!(
                state
                    .plugins
                    .run(project_id, plugin_id, action, base_exchange_id, input)
                    .await?
            ))
        }
        "job_status" | "job_cancel" | "job_results" | "job_resume_analysis" => {
            let id = args
                .get("job_id")
                .and_then(Value::as_str)
                .ok_or_else(|| DomainError::invalid("job_id required"))?
                .parse::<uuid::Uuid>()
                .map_err(|_| DomainError::invalid("job_id must be a UUID"))?;
            if name == "job_resume_analysis" {
                let project_id = require_project_id(&args)?;
                let status = state.plugins.status(id)?;
                if status.project_id != project_id {
                    return Err(DomainError::not_found("plugin job"));
                }
                return Ok(json!(
                    state
                        .plugins
                        .resume_analysis(
                            id,
                            arguments::optional_u64(&args, "js_stage_timeout_ms")?,
                        )
                        .await?
                ));
            }
            if name == "job_results" {
                let view = match args
                    .get("view")
                    .and_then(Value::as_str)
                    .unwrap_or("summary")
                {
                    "summary" => crate::plugins::PluginResultView::Summary,
                    "findings" => crate::plugins::PluginResultView::Findings,
                    "full" => crate::plugins::PluginResultView::Full,
                    _ => {
                        return Err(DomainError::invalid(
                            "view must be summary, findings, or full",
                        ))
                    }
                };
                let offset = arguments::optional_u64(&args, "offset")?.unwrap_or(0) as usize;
                let limit = arguments::optional_u64(&args, "limit")?.unwrap_or(25) as usize;
                job_view::findings_page(state.plugins.results(id, view, offset, limit)?)
            } else {
                let job = if name == "job_cancel" {
                    state.plugins.cancel(id)?
                } else {
                    let wait = arguments::optional_u64(&args, "wait_ms")?.unwrap_or(0);
                    state
                        .plugins
                        .wait_status(id, std::time::Duration::from_millis(wait))
                        .await?
                };
                Ok(json!(job))
            }
        }
        "projects" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list");
            match action {
                "list" => {
                    if arguments::present(&args, "project_id").is_some() {
                        Ok(json!(
                            state.project_detail(require_project_id(&args)?).await?
                        ))
                    } else {
                        let projects = state.db.list_projects().await?;
                        Ok(Value::Array(
                            projects
                                .into_iter()
                                .map(|project| {
                                    let mut value = json!(project);
                                    value.as_object_mut().unwrap().retain(|key, _| {
                                        matches!(
                                            key.as_str(),
                                            "id" | "name" | "target_url" | "updated_at"
                                        )
                                    });
                                    value
                                })
                                .collect(),
                        ))
                    }
                }
                "create" => {
                    let pname = args
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| DomainError::invalid("name required"))?;
                    let target_url = args
                        .get("target_url")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| DomainError::invalid("target_url required"))?;
                    let scope = args
                        .get("scope")
                        .cloned()
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|error| DomainError::invalid(format!("invalid scope: {error}")))?;
                    let project = state
                        .db
                        .create_project(CreateProjectRequest {
                            name: pname.into(),
                            target_url: target_url.into(),
                            advanced: scope,
                        })
                        .await?;
                    emit_event(
                        &state,
                        project.id,
                        "project",
                        json!({ "project_id": project.id.get() }),
                    );
                    Ok(json!(project))
                }
                "set_scope" => {
                    let project_id = require_project_id(&args)?;
                    let scope: ScopePolicy = args
                        .get("scope")
                        .cloned()
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|error| DomainError::invalid(format!("invalid scope: {error}")))?
                        .unwrap_or_default();
                    Ok(json!(
                        state
                            .db
                            .update_project_scope(project_id, scope, None)
                            .await?
                    ))
                }
                "set_limits" => {
                    let project_id = require_project_id(&args)?;
                    let update = RequestBudgetUpdate {
                        requests_per_second: arguments::present(&args, "requests_per_second")
                            .map(|value| {
                                value.as_f64().ok_or_else(|| {
                                    DomainError::invalid("requests_per_second must be a number")
                                })
                            })
                            .transpose()?,
                        max_concurrent_requests: arguments::present(
                            &args,
                            "max_concurrent_requests",
                        )
                        .map(|value| {
                            arguments::integer(value)
                                .and_then(|value| u32::try_from(value).ok())
                                .ok_or_else(|| {
                                    DomainError::invalid(
                                        "max_concurrent_requests must be a positive integer",
                                    )
                                })
                        })
                        .transpose()?,
                    };
                    let project = state
                        .db
                        .update_project_request_budget(project_id, update)
                        .await?;
                    // Running jobs hold the project's budget; apply the limits now.
                    state.reply.request_limiter.budget(&project);
                    Ok(json!({
                        "project_id": project.id.get(),
                        "requests_per_second": project.limits.requests_per_second,
                        "max_concurrent_requests": project.limits.max_concurrent_requests,
                    }))
                }
                "usage" => {
                    let project_id = require_project_id(&args)?;
                    Ok(json!(state.db.project_usage(project_id).await?))
                }
                "set_upstream_proxy" => {
                    let project_id = require_project_id(&args)?;
                    let proxy = match args.get("proxy") {
                        Some(Value::Null) => None,
                        Some(Value::String(proxy)) => Some(proxy.clone()),
                        _ => {
                            return Err(DomainError::invalid(
                                "proxy must be an explicit URL string, direct, or null",
                            ))
                        }
                    };
                    state
                        .db
                        .set_project_upstream_proxy(project_id, proxy)
                        .await?;
                    Ok(json!(state.upstream_proxy_setting(project_id).await?))
                }
                _ => Err(DomainError::invalid(
                    "action must be list|create|usage|set_scope|set_limits|set_upstream_proxy",
                )),
            }
        }
        "overview" => {
            let project_id = require_project_id(&args)?;
            Ok(json!(state.db.project_overview(project_id).await?))
        }
        "capture_sessions" => {
            let project_id = require_project_id(&args)?;
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list");
            match action {
                "list" => Ok(json!(state.db.list_capture_sessions(project_id).await?)),
                "create" => {
                    let session = state
                        .db
                        .create_capture_session(CreateCaptureSession {
                            project_id,
                            browser_session_id: None,
                            browser_action_id: None,
                            is_browser_bound: false,
                            ttl: None,
                        })
                        .await?;
                    emit_event(
                        &state,
                        project_id,
                        "capture",
                        json!({ "session_id": session.id.get(), "state": "created" }),
                    );
                    Ok(json!(session))
                }
                "revoke" => {
                    let sid = arguments::required_i64(&args, "session_id")?;
                    state
                        .db
                        .revoke_capture_session(project_id, CaptureSessionId(sid))
                        .await?;
                    emit_event(
                        &state,
                        project_id,
                        "capture",
                        json!({ "session_id": sid, "state": "revoked" }),
                    );
                    Ok(json!({ "ok": true }))
                }
                "renew" => {
                    let sid = arguments::required_i64(&args, "session_id")?;
                    let session = state
                        .db
                        .renew_capture_session(project_id, CaptureSessionId(sid))
                        .await?;
                    emit_event(
                        &state,
                        project_id,
                        "capture",
                        json!({ "session_id": session.id.get(), "state": "renewed" }),
                    );
                    Ok(json!(session))
                }
                _ => Err(DomainError::invalid(
                    "action must be list|create|revoke|renew",
                )),
            }
        }
        "cookies" => {
            let project_id = require_project_id(&args)?;
            let action = args.get("action").and_then(Value::as_str).unwrap_or("list");
            match action {
                "list" => Ok(json!({
                    "profiles": state.db.list_cookie_profiles(project_id).await?,
                    "named_profiles": state.db.list_named_cookie_profiles(project_id).await?.into_iter().map(|(name, profile)| json!({"name":name,"profile":profile})).collect::<Vec<_>>()
                })),
                "set" => {
                    let target_url = args.get("target_url").and_then(Value::as_str);
                    let inline = arguments::present(&args, "cookie");
                    let file_path = args.get("file_path").and_then(Value::as_str);
                    if target_url.is_none() && file_path.is_none() {
                        return Err(DomainError::invalid("target_url required"));
                    }
                    let cookie = match (inline, file_path) {
                        (Some(value), None) => crate::cookies::cookie_input_from_json_value(value)?,
                        (None, Some(path)) => {
                            crate::cookies::read_cookie_file(std::path::Path::new(path))?
                        }
                        _ => {
                            return Err(DomainError::invalid(
                                "provide exactly one of cookie or file_path",
                            ))
                        }
                    };
                    // A cookie file with one domain says which site it is for.
                    let target_url = match target_url {
                        Some(target_url) => target_url.to_string(),
                        None => crate::cookies::target_url_from_cookie_input(&cookie)?,
                    };
                    let target_url = target_url.as_str();
                    if let Some(name) = args.get("profile_name").and_then(Value::as_str) {
                        let profile =
                            crate::cookies::validate_named_cookie_profile(target_url, cookie)?;
                        Ok(
                            json!({"profile": state.db.upsert_named_cookie_profile(project_id, name, profile).await?, "name": name, "active": false}),
                        )
                    } else {
                        Ok(json!(
                            crate::cookies::set_project_cookie(
                                &state, project_id, target_url, cookie
                            )
                            .await?
                        ))
                    }
                }
                "clear" => {
                    if let Some(name) = args.get("profile_name").and_then(Value::as_str) {
                        Ok(
                            json!({"cleared": state.db.delete_named_cookie_profile(project_id, name).await?, "name": name}),
                        )
                    } else {
                        let target_url = args
                            .get("target_url")
                            .and_then(Value::as_str)
                            .ok_or_else(|| DomainError::invalid("target_url required"))?;
                        Ok(
                            json!({"cleared": crate::cookies::clear_project_cookie(&state, project_id, target_url).await?}),
                        )
                    }
                }
                _ => Err(DomainError::invalid("action must be set|list|clear")),
            }
        }
        "request_rules" => {
            let project_id = require_project_id(&args)?;
            match args.get("action").and_then(Value::as_str).unwrap_or("list") {
                "list" => Ok(json!({ "rules": state.db.list_request_rules(project_id).await? })),
                "add" | "update" => {
                    let input: crate::request_rules::RequestRuleInput = serde_json::from_value(
                        args.get("rule")
                            .cloned()
                            .ok_or_else(|| DomainError::invalid("rule required"))?,
                    )
                    .map_err(|error| DomainError::invalid(error.to_string()))?;
                    let rule = if args.get("action").and_then(Value::as_str) == Some("add") {
                        state.db.create_request_rule(project_id, input).await?
                    } else {
                        let id = arguments::required_i64(&args, "rule_id")?;
                        state.db.update_request_rule(project_id, id, input).await?
                    };
                    Ok(json!(rule))
                }
                "remove" => {
                    let id = arguments::required_i64(&args, "rule_id")?;
                    state.db.delete_request_rule(project_id, id).await?;
                    Ok(json!({ "ok": true }))
                }
                "preview" => {
                    let url = args
                        .get("url")
                        .and_then(Value::as_str)
                        .ok_or_else(|| DomainError::invalid("url required"))?
                        .to_string();
                    let headers = args
                        .get("headers")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|header| {
                            Some((
                                header.get("name")?.as_str()?.to_string(),
                                header.get("value")?.as_str()?.as_bytes().to_vec(),
                            ))
                        })
                        .collect();
                    Ok(json!(
                        crate::request_rules::preview(
                            &state.db,
                            project_id,
                            url,
                            args.get("method")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                            headers,
                            args.get("body")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .as_bytes()
                                .to_vec(),
                        )
                        .await?
                    ))
                }
                _ => Err(DomainError::invalid(
                    "action must be list|add|update|remove|preview",
                )),
            }
        }
        "history_search" => history_view::history_search(&state, &args).await,
        "sitemap" => history_view::sitemap(&state, &args).await,
        "findings" => {
            let project_id = require_project_id(&args)?;
            match args.get("action").and_then(Value::as_str).unwrap_or("list") {
                "list" => Ok(json!({
                    "findings": state.db.list_findings(project_id).await?
                })),
                "add" => {
                    let exchange_id = arguments::required_i64(&args, "exchange_id")?;
                    let title = args
                        .get("title")
                        .and_then(Value::as_str)
                        .ok_or_else(|| DomainError::invalid("title required"))?;
                    let description = args
                        .get("description")
                        .and_then(Value::as_str)
                        .ok_or_else(|| DomainError::invalid("description required"))?;
                    let finding = state
                        .db
                        .create_finding(
                            project_id,
                            ExchangeId(exchange_id),
                            title.to_string(),
                            description.to_string(),
                        )
                        .await?;
                    emit_event(
                        &state,
                        project_id,
                        "finding",
                        json!({ "finding_id": finding.id.get(), "action": "added" }),
                    );
                    let _ = state
                        .db
                        .audit(
                            Some(project_id),
                            "finding_add",
                            Some("mcp"),
                            Some("finding"),
                            Some(&finding.id.to_string()),
                            json!({ "exchange_id": exchange_id }),
                        )
                        .await;
                    Ok(json!(finding))
                }
                "remove" => {
                    let finding_id = arguments::required_i64(&args, "finding_id")?;
                    state
                        .db
                        .delete_finding(project_id, FindingId(finding_id))
                        .await?;
                    emit_event(
                        &state,
                        project_id,
                        "finding",
                        json!({ "finding_id": finding_id, "action": "removed" }),
                    );
                    let _ = state
                        .db
                        .audit(
                            Some(project_id),
                            "finding_remove",
                            Some("mcp"),
                            Some("finding"),
                            Some(&finding_id.to_string()),
                            json!({}),
                        )
                        .await;
                    Ok(json!({ "ok": true, "removed": finding_id }))
                }
                _ => Err(DomainError::invalid("action must be list|add|remove")),
            }
        }
        "exchange_get" => exchange_view::exchange_get(&state, &args).await,
        "exchange_compare" => {
            let project_id = require_project_id(&args)?;
            let left = arguments::required_i64(&args, "left_exchange_id")?;
            let right = arguments::required_i64(&args, "right_exchange_id")?;
            exchange_view::compare_view(
                &crate::compare::compare_saved_exchanges(
                    &state.db,
                    project_id,
                    ExchangeId(left),
                    ExchangeId(right),
                    crate::compare::CompareOptions {
                        include_noisy_headers: args
                            .get("include_noisy_headers")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    },
                )
                .await?,
            )
        }
        "page_analyzer" => {
            let project_id = require_project_id(&args)?;
            let exchange_id = arguments::optional_i64(&args, "exchange_id")?.map(ExchangeId);
            let url = args.get("url").and_then(Value::as_str);
            match (exchange_id, url) {
                (Some(exchange_id), None) => {
                    let content = crate::page_analyzer::load_exchange_content(
                        &state.db,
                        project_id,
                        exchange_id,
                    )
                    .await?;
                    let source_url = content.source_url.clone();
                    let tree = analyze_page_script_tree(
                        &state,
                        project_id,
                        source_url.clone(),
                        content.body,
                    )
                    .await;
                    let mut output = page_analysis_tree_fields(tree, content.body_truncated);
                    let object = output.as_object_mut().expect("page analysis object");
                    object.insert("project_id".into(), json!(project_id));
                    object.insert("exchange_id".into(), json!(exchange_id));
                    object.insert("source_url".into(), json!(source_url));
                    object.insert("decoded".into(), json!(content.decoded));
                    object.insert("content_encoding".into(), json!(content.content_encoding));
                    object.insert("body_truncated".into(), json!(content.body_truncated));
                    object.insert("completion".into(), json!(content.completion));
                    object.insert("status_code".into(), json!(content.status_code));
                    object.insert("content_type".into(), json!(content.content_type));
                    Ok(output)
                }
                (None, Some(url)) => {
                    let parsed = url::Url::parse(url).map_err(|error| {
                        DomainError::invalid(format!("invalid analysis URL: {error}"))
                    })?;
                    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                        return Err(DomainError::invalid(
                            "analysis URL must be an absolute http or https URL",
                        ));
                    }
                    let requested_url = parsed.to_string();
                    let draft = ReplyDraft {
                        method: Some("GET".into()),
                        url: Some(requested_url),
                        ..Default::default()
                    };
                    let result = state
                        .reply
                        .send(project_id, None, None, &draft, ProtocolPreference::Auto, 0)
                        .await?;
                    let effective_url = result.effective_url.clone();
                    let exchange_id = result.exchange_id;
                    let (
                        effective_source_url,
                        body,
                        decoded,
                        content_encoding,
                        body_truncated,
                        completion,
                        status_code,
                        content_type,
                    ) = if let Some(exchange_id) = exchange_id {
                        emit_event(
                            &state,
                            project_id,
                            "exchange",
                            json!({ "exchange_id": exchange_id.get(), "source": "reply" }),
                        );
                        let content = crate::page_analyzer::load_exchange_content(
                            &state.db,
                            project_id,
                            exchange_id,
                        )
                        .await?;
                        (
                            content.source_url,
                            content.body,
                            content.decoded,
                            content.content_encoding,
                            content.body_truncated,
                            content.completion,
                            content.status_code,
                            content.content_type,
                        )
                    } else {
                        let response = result.response.ok_or_else(|| {
                            DomainError::new(
                                ErrorCode::Internal,
                                "URL analysis response body was unavailable",
                            )
                        })?;
                        let (body, decoded, content_encoding) =
                            crate::page_analyzer::decode_ephemeral_response(&response)?;
                        (
                            effective_url,
                            body,
                            decoded,
                            content_encoding,
                            response.body_truncated,
                            if response.body_truncated {
                                crate::domain::CompletionState::TruncatedByPolicy
                            } else {
                                crate::domain::CompletionState::Complete
                            },
                            Some(response.status_code),
                            response
                                .headers
                                .iter()
                                .find(|header| header.name.eq_ignore_ascii_case("content-type"))
                                .map(|header| header.value.clone()),
                        )
                    };
                    let tree = analyze_page_script_tree(
                        &state,
                        project_id,
                        effective_source_url.clone(),
                        body,
                    )
                    .await;
                    let mut output = page_analysis_tree_fields(tree, body_truncated);
                    let object = output.as_object_mut().expect("page analysis object");
                    object.insert("project_id".into(), json!(project_id));
                    object.insert("exchange_id".into(), json!(exchange_id));
                    object.insert("source_url".into(), json!(effective_source_url));
                    object.insert("decoded".into(), json!(decoded));
                    object.insert("content_encoding".into(), json!(content_encoding));
                    object.insert("body_truncated".into(), json!(body_truncated));
                    object.insert("completion".into(), json!(completion));
                    object.insert("status_code".into(), json!(status_code));
                    object.insert("content_type".into(), json!(content_type));
                    Ok(output)
                }
                _ => Err(DomainError::invalid(
                    "provide exactly one of exchange_id or url",
                )),
            }
        }
        "copy_as" => {
            let project_id = require_project_id(&args)?;
            let exchange_id = ExchangeId(arguments::required_i64(&args, "exchange_id")?);
            let format: crate::copy_as::CopyAsFormat = serde_json::from_value(
                args.get("format")
                    .cloned()
                    .ok_or_else(|| DomainError::invalid("format required"))?,
            )
            .map_err(|_| DomainError::invalid("format must be curl|python_requests"))?;
            let include_secrets = args
                .get("include_secrets")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let result = crate::copy_as::copy_exchange_as(
                &state.db,
                project_id,
                exchange_id,
                format,
                include_secrets,
            )
            .await?;
            if include_secrets {
                // Fail closed: secrets are only returned once the reveal is audited.
                state
                    .db
                    .audit(
                        Some(project_id),
                        "copy_as_secret_reveal",
                        Some("mcp"),
                        Some("exchange"),
                        Some(&exchange_id.get().to_string()),
                        json!({ "format": format }),
                    )
                    .await?;
            }
            Ok(json!(result))
        }
        "exchange_body" => exchange_view::exchange_body(&state, &args).await,
        "secret_reveal" => {
            let project_id = require_project_id(&args)?;
            let eid = arguments::required_i64(&args, "exchange_id")?;
            let header = args
                .get("header")
                .and_then(|v| v.as_str())
                .ok_or_else(|| DomainError::invalid("header required"))?
                .to_string();
            if !is_sensitive_header(&header) {
                return Err(DomainError::invalid(
                    "header is not in the sensitive set; use exchange_get",
                ));
            }
            let side = match args
                .get("side")
                .and_then(|v| v.as_str())
                .unwrap_or("request")
            {
                "response" => MessageSide::Response,
                _ => MessageSide::Request,
            };
            let headers = state
                .db
                .load_raw_headers(project_id, ExchangeId(eid), side)
                .await?;
            let value = headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(&header))
                .map(|h| String::from_utf8_lossy(&h.value).into_owned())
                .ok_or_else(|| DomainError::not_found("header"))?;
            // Fail closed: the secret is only returned once the reveal is audited.
            state
                .db
                .audit(
                    Some(project_id),
                    "secret_reveal",
                    Some("mcp"),
                    Some("header"),
                    Some(&format!("{}/{}", eid, header.to_ascii_lowercase())),
                    json!({ "side": match side { MessageSide::Request => "request", MessageSide::Response => "response" } }),
                )
                .await?;
            Ok(json!({ "header": header, "value": value }))
        }
        "reply_tabs" => {
            let project_id = require_project_id(&args)?;
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list");
            match action {
                "list" => Ok(json!(state.db.list_reply_tabs(project_id).await?)),
                "create" | "upsert" => {
                    let name = args
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("tab")
                        .to_string();
                    let base = arguments::optional_i64(&args, "base_exchange_id")?.map(ExchangeId);
                    let draft = parse_request_draft(request_draft_value(&args)?.as_ref())?;
                    Ok(json!(
                        state
                            .db
                            .upsert_reply_tab(
                                project_id,
                                None,
                                name,
                                base,
                                ProtocolPreference::Auto,
                                draft,
                                None,
                            )
                            .await?
                    ))
                }
                _ => Err(DomainError::invalid("action must be list|create")),
            }
        }
        "reply_send" => {
            let project_id = require_project_id(&args)?;
            let draft = parse_request_draft(request_draft_value(&args)?.as_ref())?;
            let base_exchange_id =
                arguments::optional_i64(&args, "base_exchange_id")?.map(ExchangeId);
            let protocol = parse_protocol(args.get("protocol").and_then(Value::as_str))?;
            let preview_bytes = arguments::optional_u64(&args, "preview_bytes")?
                .map_or(crate::reply::DEFAULT_REPLY_PREVIEW_BYTES, |bytes| {
                    bytes.min(crate::reply::MAX_REPLY_PREVIEW_BYTES as u64) as usize
                });
            let with_response_headers =
                arguments::optional_bool(&args, "response_headers")?.unwrap_or(false);
            let result = state
                .reply
                .send_with_proxy_and_preview(
                    project_id,
                    arguments::optional_i64(&args, "tab_id")?.map(ReplyTabId),
                    base_exchange_id,
                    &draft,
                    protocol,
                    0,
                    args.get("upstream_proxy").and_then(Value::as_str),
                    preview_bytes,
                )
                .await?;
            if let Some(exchange_id) = result.exchange_id {
                emit_event(
                    &state,
                    project_id,
                    "exchange",
                    json!({ "exchange_id": exchange_id.get(), "source": "reply" }),
                );
            }
            let mut view =
                exchange_view::reply_send_view(&state, project_id, base_exchange_id, &result)
                    .await?;
            if with_response_headers {
                view["response_headers"] = response_header_lines(&result);
            }
            Ok(view)
        }
        "reply_send_raw" => {
            let project_id = require_project_id(&args)?;
            let target_url = args
                .get("target_url")
                .and_then(|value| value.as_str())
                .ok_or_else(|| DomainError::invalid("target_url required"))?;
            let request = args
                .get("request")
                .and_then(|value| value.as_str())
                .ok_or_else(|| DomainError::invalid("request required"))?;
            let request_bytes = match args
                .get("encoding")
                .and_then(|value| value.as_str())
                .unwrap_or("utf8")
            {
                "utf8" => request.as_bytes().to_vec(),
                "base64" => base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    request.as_bytes(),
                )
                .map_err(|error| {
                    DomainError::invalid(format!("invalid base64 request: {error}"))
                })?,
                _ => return Err(DomainError::invalid("encoding must be utf8 or base64")),
            };
            let result = state
                .reply
                .send_raw_http1(
                    project_id,
                    arguments::optional_i64(&args, "tab_id")?.map(ReplyTabId),
                    target_url,
                    request_bytes,
                    args.get("use_project_cookies")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    raw_http1_options(&args)?,
                )
                .await?;
            if let Some(exchange_id) = result.exchange_id {
                emit_event(
                    &state,
                    project_id,
                    "exchange",
                    json!({
                        "exchange_id": exchange_id.get(),
                        "source": "reply",
                        "mode": "raw_http1"
                    }),
                );
            }
            Ok(json!(result))
        }
        "fuzz_start" => {
            let project_id = require_project_id(&args)?;
            if args.get("identity").is_some()
                || args
                    .get("template")
                    .and_then(|template| template.get("identity"))
                    .is_some()
            {
                return Err(DomainError::invalid(
                    "put request field `identity` under `template.draft`",
                ));
            }
            let template = args
                .get("template")
                .cloned()
                .ok_or_else(|| DomainError::invalid("template required"))?;
            if let Some(draft) = template.get("draft") {
                validate_reply_draft_request(draft).map_err(DomainError::invalid)?;
            }
            let template: FuzzTemplate = serde_json::from_value(template)
                .map_err(|e| DomainError::invalid(e.to_string()))?;
            let confirm = args
                .get("confirm_large")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let job = state.fuzzer.start(project_id, template, confirm).await?;
            emit_event(
                &state,
                project_id,
                "fuzz",
                json!({ "job_id": job.id.get(), "state": job.state }),
            );
            Ok(json!(job))
        }
        "fuzz_manage" => {
            let project_id = require_project_id(&args)?;
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list");
            match action {
                "list" => Ok(json!(state.fuzzer.list(project_id).await?)),
                "cancel" => {
                    let jid = arguments::required_i64(&args, "job_id")?;
                    state
                        .fuzzer
                        .cancel_for_project(project_id, FuzzJobId(jid))
                        .await?;
                    emit_event(
                        &state,
                        project_id,
                        "fuzz",
                        json!({ "job_id": jid, "state": "cancelling" }),
                    );
                    Ok(json!({ "ok": true }))
                }
                "get" => {
                    let jid = arguments::required_i64(&args, "job_id")?;
                    let wait = arguments::optional_u64(&args, "wait_ms")?.unwrap_or(0);
                    Ok(json!(
                        state
                            .fuzzer
                            .wait(
                                project_id,
                                FuzzJobId(jid),
                                std::time::Duration::from_millis(wait),
                            )
                            .await?
                    ))
                }
                "cases" => {
                    let jid = arguments::required_i64(&args, "job_id")?;
                    let limit = arguments::optional_u64(&args, "limit")?
                        .unwrap_or(100)
                        .min(500) as u32;
                    let before = arguments::optional_u64(&args, "before_case_index")?;
                    let (cases, next) = state
                        .fuzzer
                        .list_cases(project_id, FuzzJobId(jid), limit, before)
                        .await?;
                    fuzz_view::case_page(cases, next.is_some())
                }
                "groups" => {
                    let jid = arguments::required_i64(&args, "job_id")?;
                    let groups = state
                        .fuzzer
                        .list_response_groups(project_id, FuzzJobId(jid))
                        .await?;
                    fuzz_view::group_page(groups, &args)
                }
                "group_cases" => {
                    let jid = arguments::required_i64(&args, "job_id")?;
                    let group_id = args
                        .get("group_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| DomainError::invalid("group_id required"))?;
                    let limit = arguments::optional_u64(&args, "limit")?
                        .unwrap_or(100)
                        .min(500) as u32;
                    let (cases, next) = state
                        .fuzzer
                        .list_group_cases(
                            project_id,
                            FuzzJobId(jid),
                            group_id.to_string(),
                            limit,
                            arguments::optional_u64(&args, "before_case_index")?,
                        )
                        .await?;
                    fuzz_view::case_page(cases, next.is_some())
                }
                "diff" => {
                    let jid = arguments::required_i64(&args, "job_id")?;
                    let case_id = arguments::required_i64(&args, "case_id")?;
                    Ok(json!(
                        state
                            .fuzzer
                            .response_diff(
                                project_id,
                                FuzzJobId(jid),
                                case_id,
                                arguments::optional_i64(&args, "baseline_case_id")?,
                                args.get("include_text")
                                    .and_then(Value::as_bool)
                                    .unwrap_or(false),
                            )
                            .await?
                    ))
                }
                _ => Err(DomainError::invalid(
                    "action must be list|cancel|get|cases|groups|group_cases|diff",
                )),
            }
        }
        "websocket_manage" => {
            let project_id = require_project_id(&args)?;
            let action = args.get("action").and_then(Value::as_str).unwrap_or("list");
            let limit = arguments::optional_u64(&args, "limit")?.unwrap_or(250) as u32;
            match action {
                "list" => Ok(json!({
                    "connections": state.db.list_websocket_connections(project_id, limit).await?
                })),
                "messages" => {
                    let connection_id = arguments::required_i64(&args, "connection_id")?;
                    let limit = limit.clamp(1, 1000);
                    let messages = state
                        .db
                        .list_websocket_messages(
                            project_id,
                            connection_id,
                            arguments::optional_i64(&args, "after_id")?,
                            limit,
                            websocket_view::PREVIEW_BYTES,
                        )
                        .await?;
                    websocket_view::messages_page(messages, limit as usize)
                }
                "message" => {
                    let message_id = arguments::required_i64(&args, "message_id")?;
                    let message = state
                        .db
                        .load_websocket_message(project_id, message_id)
                        .await?;
                    websocket_view::message_page(&message, &args)
                }
                "send" => {
                    let connection_id = arguments::required_i64(&args, "connection_id")?;
                    let direction = args
                        .get("direction")
                        .and_then(Value::as_str)
                        .ok_or_else(|| DomainError::invalid("direction required"))?;
                    let to_server = match direction {
                        "to_server" => true,
                        "to_client" => false,
                        _ => {
                            return Err(DomainError::invalid(
                                "direction must be to_server or to_client",
                            ))
                        }
                    };
                    let payload = args
                        .get("payload")
                        .and_then(Value::as_str)
                        .ok_or_else(|| DomainError::invalid("payload required"))?;
                    let encoding = args
                        .get("encoding")
                        .and_then(Value::as_str)
                        .unwrap_or("text");
                    state
                        .websocket
                        .send(project_id, connection_id, to_server, encoding, payload)
                        .await?;
                    Ok(json!({"ok": true}))
                }
                _ => Err(DomainError::invalid(
                    "action must be list, messages, message, or send",
                )),
            }
        }
        "browser_profiles" => {
            let project_id = require_project_id(&args)?;
            match args.get("action").and_then(Value::as_str).unwrap_or("list") {
                "list" => Ok(json!({
                    "profiles": state.browser.browser_profiles(project_id).await?
                })),
                "create" => {
                    let profile = args
                        .get("profile")
                        .and_then(Value::as_str)
                        .ok_or_else(|| DomainError::invalid("profile required"))?;
                    Ok(json!(
                        state
                            .browser
                            .create_browser_profile(project_id, profile)
                            .await?
                    ))
                }
                "delete" => {
                    let profile = args
                        .get("profile")
                        .and_then(Value::as_str)
                        .ok_or_else(|| DomainError::invalid("profile required"))?;
                    Ok(json!({
                        "removed": state
                            .browser
                            .delete_browser_profile(project_id, profile)
                            .await?,
                        "profile": profile,
                    }))
                }
                _ => Err(DomainError::invalid("action must be list|create|delete")),
            }
        }
        "browser_start" => {
            let project_id = require_project_id(&args)?;
            let (profile, cookie_profile) = browser_start_profiles(&args);
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("about:blank")
                .to_string();
            if args
                .get("engine_policy")
                .and_then(Value::as_str)
                .is_some_and(|policy| !matches!(policy, "auto" | "chromium"))
            {
                return Err(DomainError::invalid(
                    "engine_policy is obsolete; omit it to use Chromium",
                ));
            }
            let session = state
                .browser
                .start_with_profile_options(
                    project_id,
                    url,
                    profile,
                    cookie_profile,
                    args.get("refresh_cookies")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                )
                .await?;
            let mut response = json!(session);
            response["session_id"] = json!(session.id);
            if let Some(cookie_profile) = cookie_profile {
                response["cookie_profile"] = json!(cookie_profile);
            }
            Ok(response)
        }
        "browser_action" => {
            let project_id = require_project_id(&args)?;
            let sid = arguments::required_i64(&args, "session_id")?;
            let mut action = args
                .get("action")
                .cloned()
                .ok_or_else(|| DomainError::invalid("action required"))?;
            arguments::unquote_integers(
                &mut action,
                &["page_id", "runtime_generation", "after_sequence"],
            );
            let action: BrowserAction =
                serde_json::from_value(action).map_err(|e| DomainError::invalid(e.to_string()))?;
            Ok(json!(
                state
                    .browser
                    .action(project_id, BrowserSessionId(sid), action)
                    .await?
            ))
        }
        "browser_evaluate" => {
            let project_id = require_project_id(&args)?;
            let sid = arguments::required_i64(&args, "session_id")?;
            let mut action = serde_json::Map::new();
            action.insert("type".into(), json!("evaluate"));
            for field in ["expression", "frame", "timeout_ms"] {
                if let Some(value) = args.get(field).filter(|value| !value.is_null()) {
                    action.insert(field.into(), value.clone());
                }
            }
            let action: BrowserAction = serde_json::from_value(Value::Object(action))
                .map_err(|e| DomainError::invalid(e.to_string()))?;
            Ok(json!(
                state
                    .browser
                    .action(project_id, BrowserSessionId(sid), action)
                    .await?
            ))
        }
        "browser_input" => {
            let project_id = require_project_id(&args)?;
            let sid = arguments::required_i64(&args, "session_id")?;
            let op = args
                .get("op")
                .and_then(Value::as_str)
                .ok_or_else(|| DomainError::invalid("op required"))?;
            // Typing and pointer input are separate browser actions.
            const POINTER_ONLY: &[&str] = &[
                "x",
                "y",
                "to_locator",
                "to_x",
                "to_y",
                "button",
                "count",
                "modifiers",
            ];
            const SHARED: &[&str] = &["locator", "snapshot"];
            let typing = op == "type";
            let mut action = serde_json::Map::new();
            action.insert(
                "type".into(),
                json!(if typing { "type" } else { "pointer" }),
            );
            if !typing {
                action.insert("op".into(), json!(op));
            }
            for field in POINTER_ONLY.iter().chain(SHARED).chain(&["text"]) {
                let Some(value) = args.get(*field).filter(|value| !value.is_null()) else {
                    continue;
                };
                // A point with type, or text with a pointer op, is a
                // misunderstanding to report rather than input to drop.
                let misplaced = if typing {
                    POINTER_ONLY.contains(field)
                } else {
                    *field == "text"
                };
                if misplaced {
                    // A client may fill in the default of a field it does not use.
                    let default = match *field {
                        "button" => value == "left",
                        "count" => value == 1,
                        "modifiers" => value.as_array().is_some_and(Vec::is_empty),
                        _ => false,
                    };
                    if default {
                        continue;
                    }
                    return Err(DomainError::invalid(format!(
                        "{field} does not apply to op {op}"
                    )));
                }
                action.insert((*field).into(), value.clone());
            }
            let action: BrowserAction = serde_json::from_value(Value::Object(action))
                .map_err(|e| DomainError::invalid(e.to_string()))?;
            Ok(json!(
                state
                    .browser
                    .action(project_id, BrowserSessionId(sid), action)
                    .await?
            ))
        }
        "browser_cdp" => {
            let project_id = require_project_id(&args)?;
            let op = args
                .get("op")
                .and_then(Value::as_str)
                .ok_or_else(|| DomainError::invalid("op required"))?;
            let result = match op {
                "status" => match arguments::optional_i64(&args, "session_id")? {
                    Some(session_id) => {
                        state
                            .browser
                            .cdp_status_for_session(project_id, BrowserSessionId(session_id))
                            .await?
                    }
                    None => state.browser.cdp_status(project_id).await?,
                },
                "enable" | "disable" => {
                    let session_id = arguments::optional_i64(&args, "session_id")?
                        .map(BrowserSessionId)
                        .ok_or_else(|| {
                            DomainError::invalid(
                                "session_id is required for CDP enable and disable",
                            )
                        })?;
                    if op == "enable" {
                        state.browser.enable_cdp(project_id, session_id).await?
                    } else {
                        state.browser.disable_cdp(project_id, session_id).await?
                    }
                }
                _ => {
                    return Err(DomainError::invalid(
                        "op must be enable, status, or disable",
                    ))
                }
            };
            Ok(json!(result))
        }
        "browser_manage" => {
            let project_id = require_project_id(&args)?;
            let op = args.get("op").and_then(|v| v.as_str()).unwrap_or("stop");
            if op == "stop_all" {
                let stopped = state.browser.stop_project(project_id).await?;
                return Ok(json!({ "ok": true, "stopped": stopped }));
            }
            if op == "reset_profile" {
                if args.get("confirm").and_then(Value::as_bool) != Some(true) {
                    return Err(DomainError::invalid(
                        "reset_profile permanently deletes browser state and requires confirm=true",
                    ));
                }
                let profile = args
                    .get("profile")
                    .and_then(Value::as_str)
                    .unwrap_or("default");
                let removed = state
                    .browser
                    .reset_browser_profile(project_id, profile)
                    .await?;
                return Ok(json!({
                    "ok": true,
                    "removed": removed,
                    "profile": profile,
                    "managed_cookies_preserved": true,
                }));
            }
            let session_id = arguments::optional_i64(&args, "session_id")?;
            if op == "status" && session_id.is_none() {
                let status = state.browser.active_status(project_id).await?;
                return Ok(json!({
                    "runtime": state.browser.status(),
                    "transport": state.transport_status,
                    "sessions": status.sessions,
                    "resources": status.resources,
                }));
            }
            let sid = session_id.ok_or_else(|| DomainError::invalid("session_id required"))?;
            match op {
                "stop" | "close" => {
                    state
                        .browser
                        .stop(project_id, BrowserSessionId(sid))
                        .await?;
                    Ok(json!({ "ok": true }))
                }
                "status" => {
                    let s = state
                        .browser
                        .session_status(project_id, BrowserSessionId(sid))
                        .await?;
                    Ok(json!(s))
                }
                _ => Err(DomainError::invalid(
                    "op must be stop|stop_all|status|reset_profile",
                )),
            }
        }
        "js_files" => history_view::js_files(&state, &args).await,
        "get_words" => {
            let project_id = require_project_id(&args)?;
            let include_js = args
                .get("include_js")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let limit = arguments::optional_u64(&args, "limit")?
                .unwrap_or(crate::get_words::DEFAULT_WORD_LIMIT as u64)
                .clamp(1, crate::get_words::MAX_WORD_LIMIT as u64) as usize;
            Ok(json!(
                crate::get_words::get_words(
                    &state.db,
                    project_id,
                    crate::get_words::GetWordsOptions {
                        domain: args
                            .get("domain")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        include_js,
                        limit,
                    },
                )
                .await?
            ))
        }
        "huntproxy_stop" => {
            let (stopped_browsers, cleanup_warning) = match state.browser.stop_all().await {
                Ok(stopped) => (Some(stopped), None),
                Err(error) => (None, Some(error.to_string())),
            };
            let shutdown = state.shutdown.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                shutdown.cancel();
            });
            Ok(json!({
                "ok": true,
                "stopped_browsers": stopped_browsers,
                "cleanup_warning": cleanup_warning,
                "message": "HuntProxy is shutting down"
            }))
        }
        "codec_transform" => {
            let input = args
                .get("input")
                .and_then(|v| v.as_str())
                .ok_or_else(|| DomainError::invalid("input required"))?;
            let encoding = args
                .get("input_encoding")
                .and_then(|v| v.as_str())
                .unwrap_or("utf8");
            let bytes = match encoding {
                "base64" => {
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input)
                        .map_err(|e| DomainError::invalid(e.to_string()))?
                }
                "hex" => hex::decode(input).map_err(|e| DomainError::invalid(e.to_string()))?,
                _ => input.as_bytes().to_vec(),
            };
            let pipeline: Vec<Transform> = args
                .get("pipeline")
                .and_then(|v| v.as_array())
                .ok_or_else(|| DomainError::invalid("pipeline required"))?
                .iter()
                .map(|v| {
                    if let Ok(t) = serde_json::from_value::<Transform>(v.clone()) {
                        Ok(t)
                    } else if let Some(s) = v.as_str() {
                        serde_json::from_value(json!(s))
                            .map_err(|e| DomainError::invalid(e.to_string()))
                    } else {
                        Err(DomainError::invalid("bad transform"))
                    }
                })
                .collect::<DomainResult<Vec<_>>>()?;
            let out = apply_pipeline(&pipeline, &bytes)?;
            let text = String::from_utf8(out.clone()).unwrap_or_else(|_| {
                format!(
                    "base64:{}",
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &out)
                )
            });
            Ok(json!({ "output": text, "bytes": out.len() }))
        }
        "evidence_export" => exchange_view::evidence_export(&state, &args).await,
        "project_transfer" => {
            let action = args
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let format = args
                .get("format")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let include_secrets = args
                .get("include_secrets")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let include_chromium = args
                .get("include_chromium_profile")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let project_id = arguments::optional_i64(&args, "project_id")?.map(ProjectId);
            let supplied_path = args
                .get("file_path")
                .and_then(Value::as_str)
                .map(PathBuf::from);
            match (action, format) {
                ("export", "huntproxy") => {
                    let project_id = project_id
                        .ok_or_else(|| DomainError::invalid("project_id required for export"))?;
                    if include_chromium && !include_secrets {
                        return Err(DomainError::invalid(
                            "Chromium profile export requires include_secrets=true",
                        ));
                    }
                    crate::config::create_private_dir(&state.config.export_dir)?;
                    let path = supplied_path.unwrap_or_else(|| {
                        state
                            .config
                            .export_dir
                            .join(format!("huntproxy-project-{}.huntproxy", project_id.get()))
                    });
                    state
                        .db
                        .export_bundle(
                            &state.config,
                            project_id,
                            path.clone(),
                            crate::transfer::BundleExportOptions {
                                secrets: if include_secrets {
                                    crate::transfer::SecretMode::Full
                                } else {
                                    crate::transfer::SecretMode::Sanitized
                                },
                                include_chromium_profile: include_chromium,
                            },
                        )
                        .await?;
                    state.db.audit(Some(project_id), "project_export", Some("mcp"), Some("project"), Some(&project_id.get().to_string()), serde_json::json!({"format":"huntproxy","include_secrets":include_secrets})).await?;
                    Ok(json!({"path":path,"format":"huntproxy","include_secrets":include_secrets}))
                }
                ("import", "huntproxy") => {
                    let path = supplied_path
                        .ok_or_else(|| DomainError::invalid("file_path required for import"))?;
                    let result = state.db.import_bundle(&state.config, path, None).await?;
                    Ok(json!(result))
                }
                ("export", "har") => {
                    let project_id = project_id
                        .ok_or_else(|| DomainError::invalid("project_id required for export"))?;
                    crate::config::create_private_dir(&state.config.export_dir)?;
                    let path = supplied_path.unwrap_or_else(|| {
                        state
                            .config
                            .export_dir
                            .join(format!("huntproxy-project-{}.har", project_id.get()))
                    });
                    let har = state.db.export_har(project_id, include_secrets).await?;
                    crate::har::write_har_file(&path, &har)?;
                    state
                        .db
                        .audit(
                            Some(project_id),
                            "project_export",
                            Some("mcp"),
                            Some("project"),
                            Some(&project_id.get().to_string()),
                            serde_json::json!({"format":"har","include_secrets":include_secrets}),
                        )
                        .await?;
                    Ok(
                        json!({"path":path,"format":"har","include_secrets":include_secrets,"entries":har.log.entries.len()}),
                    )
                }
                ("import", "har") => {
                    let project_id = project_id.ok_or_else(|| {
                        DomainError::invalid("project_id required for HAR import")
                    })?;
                    let path = supplied_path
                        .ok_or_else(|| DomainError::invalid("file_path required for import"))?;
                    Ok(json!(state.db.import_har_file(project_id, &path).await?))
                }
                _ => Err(DomainError::invalid(
                    "unsupported project transfer action or format",
                )),
            }
        }
        "exchange_annotate" => {
            let project_id = require_project_id(&args)?;
            let eid = arguments::required_i64(&args, "exchange_id")?;
            let display_title = args
                .get("display_title")
                .and_then(|value| value.as_str())
                .map(str::to_string);
            let note = args
                .get("note")
                .and_then(|value| value.as_str())
                .map(str::to_string);
            let labels = args
                .get("labels")
                .and_then(|value| value.as_array())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let expected_revision = arguments::optional_i64(&args, "expected_revision")?;
            let annotation = state
                .db
                .upsert_annotation(
                    project_id,
                    ExchangeId(eid),
                    AnnotationUpdate {
                        display_title,
                        note,
                        labels,
                        expected_revision,
                    },
                )
                .await?;
            let _ = state.events.send(crate::app::AppEvent {
                project_id: project_id.get(),
                kind: "annotation".into(),
                payload: json!({ "exchange_id": eid }),
            });
            Ok(json!(annotation))
        }
        other => Err(DomainError::invalid(format!("unknown tool {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn projects_list_returns_summaries_and_optional_full_project() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config {
            data_dir: directory.path().to_path_buf(),
            spool_dir: directory.path().join("spool"),
            export_dir: directory.path().join("exports"),
            runtime_dir: directory.path().join("runtime"),
            plugin_dir: directory.path().join("plugins"),
            ..Config::default()
        };
        let state = crate::app::bootstrap_state(config).await.unwrap();
        let project = state
            .db
            .create_project(CreateProjectRequest {
                name: "Example".into(),
                target_url: "https://example.test/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let list = call_tool(state.clone(), "projects", json!({"action":"list"}))
            .await
            .unwrap();
        let item = &list.as_array().unwrap()[0];
        let keys = item
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["id", "name", "target_url", "updated_at"]);
        assert_eq!(item["id"], project.id.get());
        let full = call_tool(
            state.clone(),
            "projects",
            json!({"action":"list", "project_id":project.id.get()}),
        )
        .await
        .unwrap();
        let mut expected = json!(project);
        expected["upstream_proxy"] = json!({"mode":"inherit", "proxy":null, "effective":{"host":"example.test", "mode":"direct", "proxy":null}});
        assert_eq!(full, expected);
        assert!(
            call_tool(state, "projects", json!({"action":"list", "project_id":-1}))
                .await
                .is_err()
        );
    }

    #[test]
    fn projects_schema_advertises_live_upstream_proxy_and_explicit_direct() {
        let defs = tool_defs();
        let schema = &defs
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "projects")
            .unwrap()["inputSchema"];
        assert!(schema["properties"]["action"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("set_upstream_proxy")));
        assert_eq!(
            schema["properties"]["proxy"]["type"],
            json!(["string", "null"])
        );
    }

    fn history_call(arguments: Value) -> JsonRpcRequest {
        JsonRpcRequest {
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({"name": "history_search", "arguments": arguments}),
        }
    }

    #[test]
    fn browser_screenshot_uses_an_mcp_image_without_duplicating_base64() {
        let encoded = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB";
        let result = tool_call_result(
            "browser_action",
            json!({
                "ok": true,
                "untrusted": true,
                "message": "browser screenshot captured",
                "data": {
                    "mime_type": "image/png",
                    "byte_length": 24,
                    "image_base64": encoded
                }
            }),
            false,
        );
        assert_eq!(result["content"].as_array().unwrap().len(), 2);
        assert_eq!(result["content"][1]["type"], "image");
        assert_eq!(result["content"][1]["mimeType"], "image/png");
        assert_eq!(result["content"][1]["data"], encoded);
        assert_eq!(
            result["structuredContent"]["data"]["image_in_content"],
            true
        );
        assert!(result["structuredContent"]["data"]
            .get("image_base64")
            .is_none());
        assert!(!result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(encoded));
    }

    #[test]
    fn browser_action_schema_advertises_structured_playwright_capabilities() {
        let schema = browser_action_schema();
        let action_types = schema["properties"]["type"]["enum"].as_array().unwrap();
        for action in ["pages", "events", "scroll", "screenshot", "request"] {
            assert!(action_types.contains(&json!(action)));
        }
        let event_kinds = schema["properties"]["kinds"]["items"]["enum"]
            .as_array()
            .unwrap();
        assert!(event_kinds.contains(&json!("observer_error")));
        assert_eq!(schema["properties"]["kinds"]["maxItems"], event_kinds.len());
        assert_eq!(
            schema["properties"]["max_response_bytes"]["maximum"],
            65_536
        );
    }

    #[test]
    fn tool_schema_integer_bounds_stay_within_json_safe_range() {
        // The OpenAI Codex backend returns HTTP 500 for a tool declaring i64::MIN or u64::MAX
        // as a bound; ±(2^53 - 1) is accepted.
        const SAFE: i64 = (1 << 53) - 1;
        fn check(tool: &str, path: &str, value: &Value) {
            match value {
                Value::Object(fields) => {
                    for (key, field) in fields {
                        let path = format!("{path}/{key}");
                        if matches!(
                            key.as_str(),
                            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum"
                        ) && field.is_number()
                        {
                            let bound = field.as_i64();
                            assert!(
                                bound.is_some_and(|bound| (-SAFE..=SAFE).contains(&bound))
                                    || field
                                        .as_f64()
                                        .is_some_and(|bound| bound.abs() <= SAFE as f64),
                                "{tool}{path} = {field} exceeds the JSON-safe integer range"
                            );
                        }
                        check(tool, &path, field);
                    }
                }
                Value::Array(values) => {
                    for (index, value) in values.iter().enumerate() {
                        check(tool, &format!("{path}/{index}"), value);
                    }
                }
                _ => {}
            }
        }
        for tool in tool_defs().as_array().unwrap() {
            check(tool["name"].as_str().unwrap(), "", &tool["inputSchema"]);
        }
    }

    #[test]
    fn fuzz_start_schema_keeps_generator_shapes_without_64_bit_bounds() {
        let tools = tool_defs();
        let fuzz_start = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "fuzz_start")
            .unwrap();
        let generators = &fuzz_start["inputSchema"]["properties"]["template"]["properties"]
            ["payload_generators"]["items"]["oneOf"];
        let numbers = &generators[0];
        assert_eq!(numbers["properties"]["type"]["const"], "numbers");
        assert_eq!(numbers["required"], json!(["type", "from", "to", "step"]));
        for field in ["from", "to", "step"] {
            assert_eq!(numbers["properties"][field]["type"], "integer");
        }
        let regex = &generators[1];
        assert_eq!(regex["properties"]["type"]["const"], "regex_bypass");
        assert_eq!(regex["required"], json!(["type", "input"]));
        let max_payloads = &regex["properties"]["max_payloads"];
        assert_eq!(max_payloads["minimum"], 1);
        assert_eq!(max_payloads["default"], 2000);
        assert!(max_payloads.get("maximum").is_none());
        assert_eq!(regex["properties"]["byte_to"]["maximum"], 255);
    }

    #[test]
    fn browser_action_schema_stays_flat_for_codex() {
        fn remove_ignored_keywords(value: &mut Value) {
            match value {
                Value::Object(fields) => {
                    // Codex's JsonSchema type drops these keywords before measuring the schema.
                    for keyword in [
                        "default",
                        "minimum",
                        "maximum",
                        "minLength",
                        "maxItems",
                        "uniqueItems",
                    ] {
                        fields.remove(keyword);
                    }
                    for value in fields.values_mut() {
                        remove_ignored_keywords(value);
                    }
                }
                Value::Array(values) => values.iter_mut().for_each(remove_ignored_keywords),
                _ => {}
            }
        }

        let definitions = tool_defs();
        let named = |name: &str| {
            definitions
                .as_array()
                .unwrap()
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap()
                .clone()
        };
        // Past the budget Codex drops every description of a tool's schema.
        for name in ["browser_action", "browser_evaluate", "browser_input"] {
            let mut normalized = named(name)["inputSchema"].clone();
            remove_ignored_keywords(&mut normalized);
            let normalized_size = serde_json::to_vec(&normalized).unwrap().len();
            println!("{name} normalized schema: {normalized_size} bytes");
            assert!(
                normalized_size <= 5_000,
                "{name} normalized schema is {normalized_size} bytes"
            );
        }
        let pointer = named("browser_input");
        let pointer = &pointer["inputSchema"];
        assert_eq!(pointer["additionalProperties"], false);
        for keyword in ["allOf", "anyOf", "oneOf", "$ref", "if", "then", "else"] {
            assert!(pointer.get(keyword).is_none(), "unexpected {keyword}");
        }
        let tool = named("browser_action");
        let input = &tool["inputSchema"];
        let action = &input["properties"]["action"];
        // One locator shape everywhere, and clients that send every field may
        // send the unused ones as null.
        for locator in [
            &action["properties"]["locator"],
            &pointer["properties"]["locator"],
            &pointer["properties"]["to_locator"],
        ] {
            assert_eq!(locator["additionalProperties"], false);
            assert_eq!(
                locator["properties"]["nth"]["type"],
                json!(["integer", "null"])
            );
            assert_eq!(
                locator["properties"]["frame"]["type"],
                json!(["string", "null"])
            );
        }
        for locator in [
            &action["properties"]["locator"],
            &pointer["properties"]["locator"],
        ] {
            let description = locator["description"].as_str().unwrap();
            assert!(description.contains("nth picks one match (0 first, -1 last)"));
            assert!(description.contains("frame: iframe name or URL part"));
        }
        for schema in [input, action] {
            assert_eq!(schema["type"], "object");
            assert_eq!(schema["additionalProperties"], false);
            for keyword in ["allOf", "anyOf", "oneOf", "$ref", "if", "then", "else"] {
                assert!(schema.get(keyword).is_none(), "unexpected {keyword}");
            }
        }
        assert_eq!(action["required"], json!(["type"]));
        for field in [
            "type",
            "url",
            "locator",
            "value",
            "files",
            "via_chooser",
            "timeout_ms",
            "key",
            "for_what",
            "format",
            "max_bytes",
            "op",
            "page_id",
            "runtime_generation",
            "after_sequence",
            "limit",
            "kinds",
            "wait_ms",
            "delta_x",
            "delta_y",
            "full_page",
            "method",
            "headers",
            "body_text",
            "body_base64",
            "max_response_bytes",
            "offset",
            "snapshot",
        ] {
            assert!(
                action["properties"][field].is_object(),
                "missing action property {field}"
            );
        }
    }

    #[test]
    fn browser_action_deserialization_enforces_required_fields() {
        for action in [
            json!({"type":"navigate","url":"https://example.test/"}),
            json!({"type":"click","locator":{"css":"button"}}),
            json!({"type":"fill","locator":{"css":"input"},"value":"text"}),
            json!({"type":"select","locator":{"css":"select"},"value":"one"}),
            json!({"type":"upload","locator":{"css":"input"},"files":[]}),
            json!({"type":"press","key":"Enter"}),
            json!({"type":"request","method":"GET","url":"https://example.test/"}),
            json!({"type":"pages","op":"list"}),
            json!({"type":"pages","op":"new"}),
            json!({"type":"pages","op":"select","page_id":1,"runtime_generation":2}),
            json!({"type":"pages","op":"close","page_id":1,"runtime_generation":2}),
            json!({"type":"wait","for_what":"timeout","value":"0"}),
            json!({"type":"wait","for_what":"load_state","value":""}),
            json!({"type":"events"}),
            json!({"type":"events","after_sequence":1,"runtime_generation":2}),
        ] {
            assert!(
                serde_json::from_value::<BrowserAction>(action.clone()).is_ok(),
                "{action}"
            );
        }
        for action in [
            json!({"type":"navigate"}),
            json!({"type":"click"}),
            json!({"type":"pages"}),
            json!({"type":"wait","value":"0"}),
            json!({"type":"wait","for_what":"timeout"}),
            json!({"type":"fill","locator":{"css":"input"}}),
            json!({"type":"select","value":"one"}),
            json!({"type":"upload","locator":{"css":"input"}}),
            json!({"type":"press"}),
            json!({"type":"request","url":"https://example.test/"}),
            json!({"type":"request","method":"GET"}),
        ] {
            assert!(
                serde_json::from_value::<BrowserAction>(action.clone()).is_err(),
                "{action}"
            );
        }
    }

    #[test]
    fn browser_action_descriptions_preserve_bounds_and_required_inputs() {
        let definitions = tool_defs();
        let tool = definitions
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "browser_action")
            .unwrap();
        assert!(tool["description"]
            .as_str()
            .unwrap()
            .contains("Use browser_input for mouse input at a point, hover, drag and typed keystrokes, and browser_evaluate to run JavaScript in the page."));
        let inputs = &tool["inputSchema"];
        assert_eq!(
            inputs["required"],
            json!(["project_id", "session_id", "action"])
        );
        for field in ["project_id", "session_id"] {
            assert_eq!(inputs["properties"][field]["type"], "integer");
            assert!(inputs["properties"][field]["description"]
                .as_str()
                .unwrap()
                .contains("Required integer"));
        }
        let properties = &inputs["properties"]["action"]["properties"];
        for (field, fragments) in [
            ("url", vec!["Required for navigate/request"]),
            ("locator", vec!["Required for click/fill/select/upload"]),
            ("key", vec!["Required for press"]),
            ("method", vec!["Required for request"]),
            (
                "op",
                vec![
                    "Required for pages",
                    "select/close",
                    "page_id",
                    "runtime_generation",
                    "list",
                    "new",
                ],
            ),
            ("for_what", vec!["Required with value for wait"]),
            (
                "value",
                vec![
                    "Required for fill/select/wait",
                    "0..60000",
                    "30000 ms",
                    "domcontentloaded",
                    "selector",
                    "text",
                    "url",
                ],
            ),
            (
                "runtime_generation",
                vec![
                    "Positive",
                    "Required",
                    "page ID",
                    "select/close",
                    "nonzero event cursor",
                ],
            ),
            (
                "after_sequence",
                vec!["integer >=0", "default 0", "nonzero", "runtime_generation"],
            ),
            (
                "page_id",
                vec![
                    "Positive",
                    "required",
                    "runtime_generation",
                    "select/close",
                    "list/new",
                ],
            ),
            ("limit", vec!["1..100", "default 50"]),
            ("wait_ms", vec!["0..30000", "default 0"]),
            (
                "timeout_ms",
                vec!["1..30000", "1000..30000", "default 10000", "default 15000"],
            ),
            (
                "max_bytes",
                vec![
                    "1..65536",
                    "default 4096",
                    "1..8388608",
                    "default 4194304",
                    "24000",
                ],
            ),
            ("max_response_bytes", vec!["1..65536", "default 4096"]),
            (
                "delta_x",
                vec!["-100000..100000", "default 0", "locator", "nonzero"],
            ),
            ("delta_y", vec!["-100000..100000", "default 0"]),
            (
                "files",
                vec![
                    "Upload requires",
                    "<=16",
                    "absolute",
                    "readable",
                    "<=4096",
                    "chooser",
                ],
            ),
        ] {
            let description = properties[field]["description"].as_str().unwrap();
            for fragment in fragments {
                assert!(
                    description.contains(fragment),
                    "{field} must describe {fragment}"
                );
            }
        }
    }

    #[test]
    fn browser_evaluate_is_the_advertised_way_to_script_a_page() {
        let definitions = tool_defs();
        let tools = definitions.as_array().unwrap();
        let tool = |name: &str| tools.iter().find(|tool| tool["name"] == name).unwrap();
        let evaluate = tool("browser_evaluate");
        let inputs = &evaluate["inputSchema"];
        assert_eq!(
            inputs["required"],
            json!(["project_id", "session_id", "expression"])
        );
        assert_eq!(inputs["additionalProperties"], false);
        // Flat, so Codex shows every property (see browser_action_schema).
        for keyword in ["allOf", "anyOf", "oneOf", "$ref"] {
            assert!(inputs.get(keyword).is_none(), "unexpected {keyword}");
        }
        let properties = &inputs["properties"];
        assert_eq!(properties["expression"]["maxLength"], 65_536);
        assert_eq!(properties["frame"]["maxLength"], 2048);
        assert_eq!(properties["timeout_ms"]["maximum"], 30_000);
        assert_eq!(properties["timeout_ms"]["default"], 10_000);
        let description = evaluate["description"].as_str().unwrap();
        for fragment in [
            "selected page",
            "top-level await",
            "function source is called",
            "cross-origin frames",
            "outerHTML",
            "type exception",
            "truncated with total_bytes",
            "do not enable browser_cdp",
        ] {
            assert!(description.contains(fragment), "must describe {fragment}");
        }
        // The handoff tool sends agents here instead of to DevTools scripting.
        assert!(tool("browser_cdp")["description"]
            .as_str()
            .unwrap()
            .contains("not a scripting interface: to run JavaScript in the page yourself, call browser_evaluate"));
        // The schema's bounds are the ones the action enforces.
        let action = |arguments: Value| {
            serde_json::from_value::<BrowserAction>(arguments)
                .map_err(|error| DomainError::invalid(error.to_string()))
        };
        assert!(matches!(
            action(
                json!({"type": "evaluate", "expression": "document.title", "frame": "checkout"})
            ),
            Ok(BrowserAction::Evaluate {
                timeout_ms: 10_000,
                ..
            })
        ));
        assert!(action(json!({"type": "evaluate"})).is_err());
    }

    #[test]
    fn browser_start_uses_the_cookie_profile_as_the_profile_when_none_is_given() {
        for (args, expected) in [
            (json!({}), ("default", None)),
            (json!({"profile": "alice"}), ("alice", None)),
            (json!({"cookie_profile": "bob"}), ("bob", Some("bob"))),
            (
                json!({"profile": null, "cookie_profile": "bob"}),
                ("bob", Some("bob")),
            ),
            // A mismatch is still passed on, so browser_start reports it.
            (
                json!({"profile": "alice", "cookie_profile": "bob"}),
                ("alice", Some("bob")),
            ),
        ] {
            assert_eq!(browser_start_profiles(&args), expected, "{args}");
        }
    }

    #[test]
    fn browser_input_describes_pointer_and_keyboard_input() {
        let definitions = tool_defs();
        let tools = definitions.as_array().unwrap();
        let tool = |name: &str| tools.iter().find(|tool| tool["name"] == name).unwrap();
        let input = tool("browser_input");
        let schema = &input["inputSchema"];
        assert_eq!(
            schema["required"],
            json!(["project_id", "session_id", "op"])
        );
        let properties = &schema["properties"];
        assert_eq!(
            properties["op"]["enum"],
            json!(["click", "hover", "drag", "type"])
        );
        assert_eq!(
            properties["button"]["enum"],
            json!(["left", "right", "middle"])
        );
        assert_eq!(
            properties["modifiers"]["items"]["enum"],
            json!(["Alt", "Control", "Meta", "Shift"])
        );
        // Codex drops the numeric keywords, so the descriptions carry the bounds.
        for (field, fragments) in [
            ("x", vec!["0..100000", "instead of locator"]),
            ("y", vec!["0..100000"]),
            ("to_x", vec!["0..100000", "instead of to_locator"]),
            ("to_y", vec!["0..100000"]),
            ("button", vec!["default left"]),
            ("count", vec!["1..3", "default 1", "double-click"]),
            ("modifiers", vec!["default none"]),
            ("text", vec!["Required for type", "1..4096 bytes", "Enter"]),
            ("snapshot", vec!["data.snapshot"]),
            ("locator", vec!["Omit to use x and y", "focused element"]),
            ("to_locator", vec!["Drag destination"]),
        ] {
            let description = properties[field]["description"].as_str().unwrap();
            for fragment in fragments {
                assert!(
                    description.contains(fragment),
                    "{field} must describe {fragment}"
                );
            }
        }
        for field in ["x", "y", "to_x", "to_y"] {
            assert_eq!(properties[field]["maximum"], 100_000);
        }
        assert_eq!(properties["count"]["maximum"], 3);
        assert_eq!(properties["text"]["maxLength"], 4096);
        let description = input["description"].as_str().unwrap();
        for fragment in [
            "selected page",
            "double-click",
            "context-menu click",
            "hover moves the pointer",
            "native HTML drag and drop",
            "real keystrokes",
            "after the text locator holds",
            "nothing scrolls",
            "names the element it hit",
            "whatever has focus",
            "getBoundingClientRect()",
            "browser_action press",
        ] {
            assert!(description.contains(fragment), "must describe {fragment}");
        }
        for (name, fragment) in [
            ("browser_cdp", "for mouse or keyboard input browser_input"),
            ("browser_evaluate", "browser_action pages lists them"),
            ("browser_action", "pages list names each page's frames"),
            (
                "browser_action",
                "console, page_error and dialog events carry the first 1000 characters of their text",
            ),
        ] {
            assert!(
                tool(name)["description"]
                    .as_str()
                    .unwrap()
                    .contains(fragment),
                "{name} must mention {fragment}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn history_query_errors_are_actionable_through_the_daemon_bridge() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config {
            data_dir: directory.path().to_path_buf(),
            spool_dir: directory.path().join("spool"),
            export_dir: directory.path().join("exports"),
            runtime_dir: directory.path().join("runtime"),
            plugin_dir: directory.path().join("plugins"),
            ..Config::default()
        };
        let state = crate::app::bootstrap_state(config.clone()).await.unwrap();
        let project = state
            .db
            .create_project(CreateProjectRequest {
                name: "History query validation".into(),
                target_url: "https://example.com/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let listener = tokio::net::UnixListener::bind(config.socket_path()).unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let server = tokio::spawn(crate::api::serve_uds_listener(
            state.clone(),
            listener,
            cancel.clone(),
        ));
        for backend in [
            Arc::new(LocalToolBackend { state }) as Arc<dyn ToolBackend>,
            Arc::new(DaemonToolBackend::new(config)) as Arc<dyn ToolBackend>,
        ] {
            for query in [json!("time:>1970-01-01T00:00:00Z"), json!(100)] {
                let request = history_call(json!({"project_id": project.id.get(), "q": query}));
                let result = handle_rpc(backend.clone(), &request)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(result["isError"], true);
                let error = &result["structuredContent"];
                assert_eq!(error["code"], "invalid_argument");
                let message = error["message"].as_str().unwrap();
                if query.is_string() {
                    assert!(message.contains("time>VALUE"));
                } else {
                    assert!(message.contains("q must be a query string"));
                }
                assert!(error.get("items").is_none());
                assert_eq!(
                    serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap())
                        .unwrap(),
                    *error
                );
            }
            let corrected = history_call(json!({
                "project_id": project.id.get(),
                "q": "time>1970-01-01T00:00:00Z"
            }));
            let result = handle_rpc(backend, &corrected).await.unwrap().unwrap();
            assert_eq!(result["isError"], false);
            assert_eq!(result["structuredContent"], json!({"items": []}));
        }
        cancel.cancel();
        server.await.unwrap().unwrap();
    }

    struct ErrorBackend {
        code: ErrorCode,
        details: Option<Value>,
    }

    #[async_trait::async_trait]
    impl ToolBackend for ErrorBackend {
        async fn call(&self, _name: &str, _args: Value) -> DomainResult<Value> {
            Err(DomainError::App {
                code: self.code,
                message: "backend failure".into(),
                details: self.details.clone(),
            })
        }
    }

    #[tokio::test]
    async fn history_query_handling_preserves_other_rpc_errors() {
        for code in [
            ErrorCode::InvalidArgument,
            ErrorCode::NotFound,
            ErrorCode::Unavailable,
            ErrorCode::Internal,
        ] {
            let request = history_call(json!({"project_id": 1}));
            let error = handle_rpc(
                Arc::new(ErrorBackend {
                    code,
                    details: None,
                }),
                &request,
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), code);
        }
        // Even a marked validation error on another tool retains its RPC behavior.
        let request = JsonRpcRequest {
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({"name": "projects", "arguments": {}}),
        };
        let error = handle_rpc(
            Arc::new(ErrorBackend {
                code: ErrorCode::InvalidArgument,
                details: Some(json!({"kind": "history_query"})),
            }),
            &request,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn advertised_history_query_examples_compile() {
        let tools = tool_defs();
        let tool = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "history_search")
            .unwrap();
        let query = &tool["inputSchema"]["properties"]["q"];
        for example in query["examples"].as_array().unwrap() {
            let filter = crate::history::parse_text_query(example.as_str().unwrap()).unwrap();
            crate::history::filter_to_sql(&filter).unwrap();
        }
        let description = query["description"].as_str().unwrap();
        for guidance in [
            "no colon",
            "RFC 3339",
            "not Unix seconds",
            "milliseconds",
            "body bytes",
        ] {
            assert!(description.contains(guidance));
        }
    }

    #[test]
    fn reply_drafts_accept_the_minimal_shape_advertised_by_mcp() {
        let draft: ReplyDraft = serde_json::from_value(json!({
            "method": "GET",
            "url": "https://example.com",
            "header_overrides": [{"name":"X-Binary","value":[0,255]}],
            "body_text": "hello",
            "inheritance": "cookies_auth_only"
        }))
        .unwrap();
        assert_eq!(draft.header_overrides[0].value, vec![0, 255]);
        assert!(draft.header_tombstones.is_empty());
        assert_eq!(draft.body_text.as_deref(), Some("hello"));
        assert_eq!(draft.inheritance, ReplyInheritance::CookiesAuthOnly);
        assert!(!draft.body_cleared);
    }

    #[test]
    fn javascript_domain_filters_accept_hosts_wildcards_and_urls() {
        assert_eq!(
            normalize_domain_filter(Some("target.com")).unwrap(),
            Some("target.com".into())
        );
        assert_eq!(
            normalize_domain_filter(Some("*.Target.COM")).unwrap(),
            Some("target.com".into())
        );
        assert_eq!(
            normalize_domain_filter(Some("https://cdn.target.com/path")).unwrap(),
            Some("cdn.target.com".into())
        );
        assert!(host_matches_domain("cdn.target.com", "target.com"));
        assert!(!host_matches_domain("eviltarget.com", "target.com"));
    }

    #[test]
    fn lifecycle_tools_describe_continuing_on_the_same_connection() {
        let tools = tool_defs();
        let tools = tools.as_array().unwrap();
        for name in ["huntproxy_stop", "huntproxy_restart"] {
            let tool = tools.iter().find(|tool| tool["name"] == name).unwrap();
            let description = tool["description"].as_str().unwrap();
            assert!(description.contains("MCP"));
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        }
    }

    #[test]
    fn structured_content_is_always_an_object_for_mcp_clients() {
        let object = json!({"ok": true});
        assert_eq!(object_structured_content(object.clone()), object);
        assert_eq!(
            object_structured_content(json!([1, 2])),
            json!({"result": [1, 2]})
        );
        assert_eq!(
            object_structured_content(json!("value")),
            json!({"result": "value"})
        );
    }

    #[test]
    fn tool_results_are_compact_and_text_matches_structured_content() {
        for (result, structured) in [
            (
                json!({"items": [{"id": 1}], "next": null}),
                json!({"items": [{"id": 1}], "next": null}),
            ),
            (json!([1, 2]), json!({"result": [1, 2]})),
        ] {
            let output = tool_call_result("history_search", result, false);
            assert_eq!(output["structuredContent"], structured);
            assert_eq!(output["content"][0]["text"], structured.to_string());
            assert!(!output["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains(['\n', ' ']));
        }
    }

    #[test]
    fn oversized_tool_results_and_errors_are_fitted_to_the_output_budget() {
        let rows = (0..5_000)
            .map(|id| json!({"exchange_id": id, "url": format!("https://example.test/{id}")}))
            .collect::<Vec<_>>();
        for is_error in [false, true] {
            let output = tool_call_result("history_search", json!({"items": rows}), is_error);
            let text = output["content"][0]["text"].as_str().unwrap();
            assert!(text.len() <= budget::MAX_OUTPUT_BYTES);
            let structured = &output["structuredContent"];
            assert_eq!(serde_json::from_str::<Value>(text).unwrap(), *structured);
            assert_eq!(
                structured["output_truncated"]["omitted"][0]["path"],
                "/items"
            );
            assert_eq!(output["isError"], is_error);
        }
    }

    #[test]
    fn a_large_screenshot_is_not_counted_against_the_output_budget() {
        let encoded = "A".repeat(budget::MAX_OUTPUT_BYTES * 4);
        let output = tool_call_result(
            "browser_action",
            json!({
                "ok": true,
                "data": {"mime_type": "image/png", "image_base64": encoded}
            }),
            false,
        );
        assert_eq!(output["content"][1]["data"], encoded);
        let structured = &output["structuredContent"];
        assert!(structured.get("output_truncated").is_none());
        assert_eq!(structured["data"]["image_in_content"], true);
        assert_eq!(output["content"][0]["text"], structured.to_string());
    }

    #[test]
    fn explicit_stop_guard_blocks_only_the_same_parent_client() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config {
            data_dir: directory.path().to_path_buf(),
            plugin_dir: directory.path().join("plugins"),
            ..Config::default()
        };
        arm_stop_guard(&config).unwrap();
        assert!(stop_guard_blocks_start(&config));
        clear_stop_guard(&config);
        assert!(!stop_guard_path(&config).exists());
    }

    #[test]
    fn tool_schemas_describe_nested_reply_and_browser_inputs() {
        let tools = tool_defs();
        let tools = tools.as_array().unwrap();
        let projects = tools
            .iter()
            .find(|tool| tool["name"] == "projects")
            .unwrap();
        assert!(projects["inputSchema"]["properties"]["action"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action == "usage"));
        let reply = tools
            .iter()
            .find(|tool| tool["name"] == "reply_send")
            .unwrap();
        assert_eq!(reply["inputSchema"]["additionalProperties"], false);
        assert_eq!(
            reply["inputSchema"]["properties"]["draft"]["properties"]["header_overrides"]["type"],
            "array"
        );
        assert_eq!(
            reply["inputSchema"]["properties"]["draft"]["properties"]["inheritance"]["default"],
            "full_request"
        );
        assert!(reply["inputSchema"]["properties"]["draft"]["properties"]
            .get("body_text")
            .is_some());
        let identity = &reply["inputSchema"]["properties"]["draft"]["properties"]["identity"];
        assert_eq!(identity["oneOf"][2]["required"], json!(["mode", "profile"]));
        assert_eq!(identity["oneOf"][2]["additionalProperties"], false);
        let fuzz = tools
            .iter()
            .find(|tool| tool["name"] == "fuzz_start")
            .unwrap();
        assert_eq!(
            fuzz["inputSchema"]["properties"]["template"]["properties"]["draft"]["properties"]
                ["identity"],
            *identity
        );
        for selection in [
            json!({"mode":"default"}),
            json!({"mode":"anonymous"}),
            json!({"mode":"named","profile":"member"}),
        ] {
            let draft: ReplyDraft = serde_json::from_value(json!({"identity":selection})).unwrap();
            assert!(draft.identity.is_some());
        }
        assert!(serde_json::from_value::<ReplyDraft>(
            json!({"identity":{"mode":"anonymous","profile":"member"}})
        )
        .is_err());
        let cookies = tools.iter().find(|tool| tool["name"] == "cookies").unwrap();
        let cookie_inputs = cookies["inputSchema"]["properties"]["cookie"]["oneOf"]
            .as_array()
            .unwrap();
        assert_eq!(cookie_inputs[0]["type"], "string");
        assert_eq!(cookie_inputs[1]["type"], "object");
        assert_eq!(
            cookie_inputs[1]["properties"]["origins"]["items"]["properties"]["sessionStorage"]
                ["type"],
            "array"
        );
        assert_eq!(cookie_inputs[2]["type"], "array");
        assert_eq!(
            cookie_inputs[2]["items"]["required"],
            json!(["name", "value"])
        );
        assert_eq!(
            reply["inputSchema"]["properties"]["draft"]["properties"]["body_format"]["enum"],
            json!(["raw", "json", "xml", "form_urlencoded", "multipart", null])
        );
        let browser = tools
            .iter()
            .find(|tool| tool["name"] == "browser_action")
            .unwrap();
        let action = &browser["inputSchema"]["properties"]["action"]["properties"];
        for name in ["navigate", "upload", "inspect"] {
            assert!(action["type"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == name));
        }
        assert_eq!(action["files"]["maxItems"], 16);
        assert_eq!(action["timeout_ms"]["maximum"], 30000);
        let upload: crate::browser::BrowserAction = serde_json::from_value(
            json!({"type":"upload","locator":{"css":"input[type=file]"},"files":[]}),
        )
        .unwrap();
        assert!(matches!(
            upload,
            crate::browser::BrowserAction::Upload { .. }
        ));
        let inspect: crate::browser::BrowserAction =
            serde_json::from_value(json!({"type":"inspect"})).unwrap();
        assert!(matches!(
            inspect,
            crate::browser::BrowserAction::Inspect { .. }
        ));
        let browser_cdp = tools
            .iter()
            .find(|tool| tool["name"] == "browser_cdp")
            .unwrap();
        assert_eq!(
            browser_cdp["inputSchema"]["properties"]["op"]["enum"],
            json!(["enable", "status", "disable"])
        );
        assert!(!browser_cdp["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "session_id"));
        assert!(browser_cdp["description"]
            .as_str()
            .unwrap()
            .contains("ssh_forward_command when returned"));
        let browser_profiles = tools
            .iter()
            .find(|tool| tool["name"] == "browser_profiles")
            .unwrap();
        assert_eq!(
            browser_profiles["inputSchema"]["properties"]["action"]["enum"],
            json!(["list", "create", "delete"])
        );
        assert_eq!(
            browser_profiles["inputSchema"]["properties"]["profile"]["pattern"],
            "^[A-Za-z0-9_-]{1,64}$"
        );
        let browser_start = tools
            .iter()
            .find(|tool| tool["name"] == "browser_start")
            .unwrap();
        assert_eq!(
            browser_start["inputSchema"]["properties"]["cookie_profile"]["pattern"],
            "^[A-Za-z0-9_-]{1,64}$"
        );
        assert!(browser_start["description"]
            .as_str()
            .unwrap()
            .contains("cookies(profile_name=...)"));
        assert!(
            browser_start["inputSchema"]["properties"]["refresh_cookies"]["description"]
                .as_str()
                .unwrap()
                .contains("Requires matching cookie_profile")
        );
        assert!(
            browser_start["inputSchema"]["properties"]["url"]["description"]
                .as_str()
                .unwrap()
                .contains("Omitted or about:blank")
        );
        let browser_manage = tools
            .iter()
            .find(|tool| tool["name"] == "browser_manage")
            .unwrap();
        assert!(browser_manage["description"]
            .as_str()
            .unwrap()
            .contains("per-project capacity including ephemeral sessions"));
        assert!(browser_manage["inputSchema"]["properties"]["op"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "stop_all"));
        assert!(browser_manage["inputSchema"]["properties"]["op"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "reset_profile"));
        assert_eq!(
            browser_manage["inputSchema"]["properties"]["confirm"]["default"],
            false
        );
        assert_eq!(
            browser_manage["inputSchema"]["properties"]["profile"]["default"],
            "default"
        );
        assert!(!browser_manage["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "session_id"));
        assert!(!browser_manage["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "chromium_reason"));
        assert!(browser_manage["inputSchema"]["properties"]
            .get("chromium_reason")
            .is_none());
        assert!(!browser_manage["inputSchema"]["properties"]["op"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "switch_chromium"));
        let browser_start = tools
            .iter()
            .find(|tool| tool["name"] == "browser_start")
            .unwrap();
        assert_eq!(
            browser_start["inputSchema"]["properties"]["profile"]["default"],
            "default"
        );
        assert_eq!(
            browser_start["inputSchema"]["properties"]["profile"]["pattern"],
            "^[A-Za-z0-9_-]{1,64}$"
        );
        assert!(browser_start["inputSchema"]["properties"]
            .get("engine_policy")
            .is_none());
        assert!(!browser_start["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "chromium_reason"));
        assert!(browser_start["inputSchema"]["properties"]
            .get("chromium_reason")
            .is_none());
        let fuzz_start = tools
            .iter()
            .find(|tool| tool["name"] == "fuzz_start")
            .unwrap();
        let template = &fuzz_start["inputSchema"]["properties"]["template"];
        assert_eq!(template["properties"]["strategy"]["default"], "sniper");
        let generators = &template["properties"]["payload_generators"];
        assert_eq!(generators["default"], json!([]));
        let regex_generator = &generators["items"]["oneOf"][1];
        assert_eq!(regex_generator["properties"]["encoding"]["default"], "url");
        assert_eq!(
            regex_generator["properties"]["modes"]["default"],
            json!(["start", "separator", "end", "regex_metachar"])
        );
        assert_eq!(
            regex_generator["properties"]["max_payloads"]["default"],
            2000
        );
        assert_eq!(
            template["properties"]["insertion_points"]["items"]["properties"]["location"]
                ["pattern"],
            "^(url|body|header:.+)$"
        );
        let js_files = tools
            .iter()
            .find(|tool| tool["name"] == "js_files")
            .unwrap();
        assert_eq!(
            js_files["inputSchema"]["properties"]["settle_ms"]["default"],
            2000
        );
        let get_words = tools
            .iter()
            .find(|tool| tool["name"] == "get_words")
            .unwrap();
        assert_eq!(
            get_words["inputSchema"]["properties"]["include_js"]["default"],
            true
        );
        let copy_as = tools.iter().find(|tool| tool["name"] == "copy_as").unwrap();
        assert_eq!(
            copy_as["inputSchema"]["properties"]["include_secrets"]["default"],
            true
        );
        assert!(tools.iter().any(|tool| tool["name"] == "huntproxy_stop"));
        let sitemap = tools.iter().find(|tool| tool["name"] == "sitemap").unwrap();
        assert!(sitemap["description"]
            .as_str()
            .unwrap()
            .contains("lightweight list of hosts and route counts"));
        assert!(sitemap["inputSchema"]["properties"]
            .get("path_prefix")
            .is_some());
        assert_eq!(sitemap["inputSchema"]["additionalProperties"], false);
        assert!(tools.iter().any(|tool| tool["name"] == "findings"));
        let overview = tools
            .iter()
            .find(|tool| tool["name"] == "overview")
            .unwrap();
        assert_eq!(overview["inputSchema"]["required"], json!(["project_id"]));
        assert!(overview["description"]
            .as_str()
            .unwrap()
            .contains("captured replies sent"));
        let body = tools
            .iter()
            .find(|tool| tool["name"] == "exchange_body")
            .unwrap();
        assert_eq!(
            body["inputSchema"]["properties"]["encoding"]["enum"],
            json!(["utf8", "base64"])
        );
        assert_eq!(
            body["inputSchema"]["properties"]["max_bytes"]["maximum"],
            1048576
        );
        assert!(body["description"]
            .as_str()
            .unwrap()
            .contains("beyond what exchange_get inlines"));
        assert!(tools
            .iter()
            .find(|tool| tool["name"] == "reply_send")
            .unwrap()["description"]
            .as_str()
            .unwrap()
            .contains("read more of the response with exchange_body"));
    }

    fn rpc(id: Option<Value>, method: &str) -> JsonRpcRequest {
        JsonRpcRequest {
            id,
            method: method.into(),
            params: Value::Null,
        }
    }

    #[tokio::test]
    async fn notifications_never_get_a_response_and_unknown_methods_are_not_found() {
        let backend = || {
            Arc::new(ErrorBackend {
                code: ErrorCode::Internal,
                details: None,
            }) as Arc<dyn ToolBackend>
        };
        for method in [
            "notifications/initialized",
            "initialized",
            "notifications/cancelled",
            "notifications/anything/else",
            "does/not/exist",
            "tools/call",
            "ping",
        ] {
            assert!(
                dispatch_rpc(backend(), &rpc(None, method)).await.is_none(),
                "{method} without an id must not be answered"
            );
        }

        let unknown = dispatch_rpc(backend(), &rpc(Some(json!(7)), "does/not/exist"))
            .await
            .unwrap();
        assert_eq!(unknown.id, Some(json!(7)));
        assert_eq!(unknown.error.unwrap().code, -32601);

        let pong = dispatch_rpc(backend(), &rpc(Some(json!("a")), "ping"))
            .await
            .unwrap();
        assert_eq!(pong.result, Some(json!({})));
    }

    #[test]
    fn invalid_utf8_input_is_a_parse_error() {
        let error = std::io::Error::new(std::io::ErrorKind::InvalidData, "not utf-8");
        let response = parse_error_response(&error);
        assert_eq!(response.error.unwrap().code, -32700);
        assert!(response.id.is_none());
    }

    #[tokio::test]
    async fn failed_stop_does_not_leave_the_stop_guard_armed() {
        let directory = tempfile::tempdir().unwrap();
        // No daemon is listening, so the stop call fails after arming the guard.
        let config = Config {
            data_dir: directory.path().to_path_buf(),
            runtime_dir: directory.path().join("runtime"),
            plugin_dir: directory.path().join("plugins"),
            ..Config::default()
        };
        let error = call_daemon_tool_guarded(&config, "huntproxy_stop", json!({}))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::DaemonNotRunning);
        assert!(!stop_guard_path(&config).exists());
        assert!(!stop_guard_blocks_start(&config));
    }

    #[test]
    fn history_cursor_accepts_the_returned_next_value() {
        assert_eq!(parse_history_cursor(None).unwrap(), (None, None));
        assert_eq!(
            parse_history_cursor(Some(&Value::Null)).unwrap(),
            (None, None)
        );
        let started = "2026-01-02T03:04:05.123456Z";
        let expected = (Some(started.to_string()), Some(42));
        assert_eq!(
            parse_history_cursor(Some(&json!([started, 42]))).unwrap(),
            expected
        );
        assert_eq!(
            parse_history_cursor(Some(&json!(format!("{started}:42")))).unwrap(),
            expected
        );
        for bad in [json!([started]), json!([1, 2]), json!("no-id"), json!(5)] {
            assert_eq!(
                parse_history_cursor(Some(&bad)).unwrap_err().code(),
                ErrorCode::InvalidArgument,
                "{bad}"
            );
        }
    }

    #[test]
    fn request_drafts_reject_unknown_fields_with_a_hint() {
        let error = parse_request_draft(Some(&json!({"headers": []}))).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.to_string().contains("header_overrides"));
        let error = parse_request_draft(Some(&json!({"body": "x"}))).unwrap_err();
        assert!(error.to_string().contains("body_text"));
        let draft = parse_request_draft(Some(&json!({"url": "https://example.test/"}))).unwrap();
        assert_eq!(draft.url.as_deref(), Some("https://example.test/"));
        assert!(parse_request_draft(None).unwrap().url.is_none());
    }

    #[test]
    fn top_level_request_fields_move_into_the_draft() {
        let args = json!({
            "project_id": 1,
            "url": "https://a.test/",
            "identity": {"mode": "anonymous"},
            "body_text": null,
            "draft": {"method": "POST", "header_overrides": null}
        });
        assert_eq!(
            request_draft_value(&args).unwrap(),
            Some(json!({
                "method": "POST",
                "url": "https://a.test/",
                "identity": {"mode": "anonymous"}
            }))
        );
        // Without a draft the lifted fields make one; with nothing to lift there is none.
        assert_eq!(
            request_draft_value(&json!({"project_id": 1, "method": "HEAD"})).unwrap(),
            Some(json!({"method": "HEAD"}))
        );
        for args in [json!({"project_id": 1}), json!({"draft": null})] {
            assert_eq!(request_draft_value(&args).unwrap(), None);
        }
        // The same value in both places is fine; different values are a conflict.
        let same = json!({"url": "https://a.test/", "draft": {"url": "https://a.test/"}});
        assert_eq!(
            request_draft_value(&same).unwrap(),
            Some(json!({"url": "https://a.test/"}))
        );
        let conflict = json!({"url": "https://a.test/", "draft": {"url": "https://b.test/"}});
        let error = request_draft_value(&conflict).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.to_string().contains("`url`"), "{error}");
        assert!(error.to_string().contains("different values"), "{error}");
        // A draft that is not an object cannot take fields.
        assert!(request_draft_value(&json!({"url": "https://a.test/", "draft": "x"})).is_err());
        // headers and body are not request fields; the error says where they go.
        let error = request_draft_value(&json!({"headers": {"X": "1"}})).unwrap_err();
        assert!(error.to_string().contains("header_overrides"), "{error}");
        let error = request_draft_value(&json!({"body": "x"})).unwrap_err();
        assert!(error.to_string().contains("body_text"), "{error}");
        // Every lifted field is one a draft accepts.
        for field in LIFTED_DRAFT_FIELDS {
            validate_reply_draft_request(&json!({ field: null })).unwrap();
        }
    }

    #[test]
    fn input_schemas_stay_small_enough_for_codex_to_keep_descriptions() {
        // Codex drops every description of a tool whose input schema exceeds
        // 5,000 bytes; 4,700 leaves room for how it normalizes them.
        let definitions = tool_defs();
        for name in [
            "reply_send",
            "reply_tabs",
            "reply_send_raw",
            "cookies",
            "job_status",
            "job_results",
        ] {
            let tool = definitions
                .as_array()
                .unwrap()
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap();
            let size = serde_json::to_vec(&tool["inputSchema"]).unwrap().len();
            println!("{name} inputSchema: {size} bytes");
            assert!(size <= 4_700, "{name} inputSchema is {size} bytes");
        }
    }

    #[test]
    fn protocol_accepts_the_usual_spellings_of_http_versions() {
        for (value, expected) in [
            (None, ProtocolPreference::Auto),
            (Some("auto"), ProtocolPreference::Auto),
            (Some("h1"), ProtocolPreference::H1),
            (Some("HTTP/1.1"), ProtocolPreference::H1),
            (Some("http1.1"), ProtocolPreference::H1),
            (Some("http/1"), ProtocolPreference::H1),
            (Some("HTTP1"), ProtocolPreference::H1),
            (Some("h2"), ProtocolPreference::H2),
            (Some("http2"), ProtocolPreference::H2),
            (Some("HTTP/2"), ProtocolPreference::H2),
            (Some(" H2 "), ProtocolPreference::H2),
        ] {
            assert_eq!(parse_protocol(value).unwrap(), expected, "{value:?}");
        }
        let error = parse_protocol(Some("h3")).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.to_string().contains("auto, h1 or h2"), "{error}");
    }
}
