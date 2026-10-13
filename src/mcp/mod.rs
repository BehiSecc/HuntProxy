//! Minimal stdio JSON-RPC MCP server. Protocol on stdout; diagnostics on stderr.

use crate::app::AppState;
use crate::browser::BrowserAction;
use crate::codec::{apply_pipeline, Transform};
use crate::config::Config;
use crate::domain::*;
use crate::fuzzer::FuzzTemplate;
use crate::history::{parse_text_query, query_error, HISTORY_QUERY_SYNTAX};
use crate::policy::{is_sensitive_header, PresentationOptions};
use crate::storage::CreateCaptureSession;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Arc;

#[async_trait::async_trait]
trait ToolBackend: Send + Sync {
    async fn call(&self, name: &str, args: Value) -> DomainResult<Value>;

    fn definitions(&self) -> Value {
        tool_defs()
    }
}

struct LocalToolBackend {
    state: Arc<AppState>,
}

#[async_trait::async_trait]
impl ToolBackend for LocalToolBackend {
    async fn call(&self, name: &str, args: Value) -> DomainResult<Value> {
        call_tool(self.state.clone(), name, args).await
    }

    fn definitions(&self) -> Value {
        local_tool_defs()
    }
}

struct DaemonToolBackend {
    config: Config,
}

#[async_trait::async_trait]
impl ToolBackend for DaemonToolBackend {
    async fn call(&self, name: &str, args: Value) -> DomainResult<Value> {
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
        let armed_stop_guard = name == "huntproxy_stop";
        if armed_stop_guard {
            arm_stop_guard(&self.config)?;
        }
        let result = call_daemon_tool(&self.config, name, args).await;
        result
    }
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
        "description": "Use one locator strategy: role/name, text, test_id, or css.",
        "properties": {
            "role": {"type": ["string", "null"]},
            "name": {"type": ["string", "null"]},
            "text": {"type": ["string", "null"]},
            "test_id": {"type": ["string", "null"]},
            "css": {"type": ["string", "null"]},
            "exact": {"type": ["boolean", "null"]}
        },
        "additionalProperties": false
    })
}

fn browser_action_schema() -> Value {
    json!({
        "type": "object",
        "description": "Action object. navigate requires url; click requires locator; fill/select require locator and value; press requires key and optional locator; wait requires for_what and value; snapshot accepts format and max_bytes.",
        "properties": {
            "type": {"type": "string", "enum": ["navigate", "snapshot", "click", "fill", "select", "press", "wait", "back", "forward", "close"]},
            "url": {"type": "string"},
            "locator": locator_schema(),
            "value": {"type": "string"},
            "key": {"type": "string"},
            "for_what": {"type": "string", "enum": ["selector", "text", "url", "timeout", "load_state"]},
            "format": {"type": "string", "enum": ["accessibility", "dom"]},
            "max_bytes": {"type": "integer", "minimum": 1}
        },
        "required": ["type"],
        "additionalProperties": false
    })
}

fn fuzz_template_schema() -> Value {
    json!({
        "type": "object",
        "description": "Use marker §name§ in the selected draft field. Example: draft.url='https://example.test/?q=§q§' with insertion point {name:'q', location:'url'}.",
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
                                "from": {"type": "integer", "minimum": -9223372036854775808_i64, "maximum": 9223372036854775807_i64},
                                "to": {"type": "integer", "minimum": -9223372036854775808_i64, "maximum": 9223372036854775807_i64},
                                "step": {"type": "integer", "minimum": -9223372036854775808_i64, "maximum": 9223372036854775807_i64, "description": "Non-zero; its sign must move from from toward to."}
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
                                "max_payloads": {"type": "integer", "minimum": 1, "maximum": 18446744073709551615_u64, "default": 2000}
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
            "strategy": {"type": "string", "enum": ["sniper", "battering_ram", "pitchfork", "cluster_bomb"], "default": "sniper"}
        },
        "required": ["insertion_points"],
        "anyOf": [{"required":["wordlists"]},{"required":["wordlist_files"]},{"required":["payload_generators"]}],
        "additionalProperties": false
    })
}

fn request_rules_tool_def() -> Value {
    serde_json::from_str(r#"{
      "name":"request_rules",
      "description":"Manage ordered request match/replace rules. Rules rewrite requests received through Proxy/Browser before forwarding and requests generated by semantic Reply, Fuzzer, plugins, and the crawler. Raw Reply remains byte-exact and is never modified.",
      "inputSchema":{"type":"object","properties":{
        "project_id":{"type":"integer"},
        "action":{"type":"string","enum":["list","add","update","remove","preview"]},
        "rule_id":{"type":"integer"},
        "rule":{"type":"object","properties":{
          "name":{"type":"string"},"enabled":{"type":"boolean","default":true},
          "position":{"type":"integer","default":0},"host_pattern":{"type":["string","null"]},
          "target":{"type":"string","enum":["url","header","body"]},
          "operation":{"type":"string","enum":["replace","set","remove"]},
          "header_name":{"type":["string","null"]},
          "match_kind":{"type":"string","enum":["literal","regex"],"default":"literal"},
          "pattern":{"type":"string","default":""},"replacement":{"type":["string","null"]},
          "replace_all":{"type":"boolean","default":true}},"required":["name","target","operation"],"additionalProperties":false},
        "url":{"type":"string"},"headers":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"}},"required":["name","value"]}},
        "body":{"type":"string"}},"required":["project_id","action"],"additionalProperties":false}
    }"#).expect("request rules tool schema is valid JSON")
}

fn tool_defs() -> Value {
    json!([
        {"name":"projects","description":"List projects, create one, inspect its logical capture quota, or set capture scope. usage returns quota-enforced logical bytes separately from physical database size. Host patterns may be exact or wildcard suffixes such as *.example.com; exclusions take precedence. Scope controls persistence, never request destinations.","inputSchema":{"type":"object","properties":{"action":{"type":"string","enum":["list","create","usage","set_scope"],"description":"list needs no project_id; create needs name and target_url; usage needs project_id; set_scope needs project_id and scope."},"project_id":{"type":"integer","description":"Required for usage and set_scope."},"name":{"type":"string","description":"Required for create."},"target_url":{"type":"string","description":"Required for create; absolute HTTP(S) URL."},"scope":{"type":"object","properties":{"schemes":{"type":"array","items":{"type":"string"}},"host_patterns":{"type":"array","description":"Hosts to capture. Supports exact names and wildcard suffixes such as *.example.com. Empty captures all hosts except exclusions.","items":{"type":"string"}},"excluded_host_patterns":{"type":"array","description":"Hosts not to capture. Supports exact names and wildcard suffixes; exclusions override inclusions.","default":[],"items":{"type":"string"}},"ports":{"type":"array","items":{"type":"integer"}},"path_prefixes":{"type":"array","items":{"type":"string"}}}}},"required":["action"],"additionalProperties":false}},
        {"name":"extension_list","description":"List compact installed-extension summaries and any rejected packages. Use extension_describe for schemas, capabilities, and limits.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"extension_describe","description":"Describe one extension, its actions, input schemas, capabilities, and requested/effective limits.","inputSchema":{"type":"object","properties":{"plugin_id":{"type":"string"}},"required":["plugin_id"],"additionalProperties":false}},
        {"name":"extension_preview","description":"Run the real extension planner without creating a job or sending requests. Returns stage-scoped request, candidate, runtime, and mode estimates.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"plugin_id":{"type":"string"},"action":{"type":"string"},"base_exchange_id":{"type":"integer"},"input":{"type":"object","default":{}}},"required":["project_id","plugin_id","action"],"additionalProperties":false}},
        {"name":"extension_run","description":"Start an asynchronous extension job. Call extension_describe first and place action-specific fields inside input, not at the top level. project_id owns the job/evidence; optional base_exchange_id supplies a saved request while cookies and authorization remain host-side. Planning failures report the plugin's bounded validation message.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer","description":"HuntProxy project that owns the job and evidence."},"plugin_id":{"type":"string","description":"Installed id from extension_list."},"action":{"type":"string","description":"Action name from extension_describe."},"base_exchange_id":{"type":"integer","description":"Optional saved request inherited host-side without copying secrets into action input."},"input":{"type":"object","description":"Action arguments matching extension_describe.actions[].input_schema. Do not put these fields at the top level.","default":{}}},"required":["project_id","plugin_id","action"],"additionalProperties":false}},
        {"name":"job_status","description":"Read compact extension job state, phase, progress, and recommended_poll_interval_ms. Honor the returned interval before polling again.","inputSchema":{"type":"object","properties":{"job_id":{"type":"string","format":"uuid"}},"required":["job_id"],"additionalProperties":false}},
        {"name":"job_cancel","description":"Cancel an active extension job.","inputSchema":{"type":"object","properties":{"job_id":{"type":"string","format":"uuid"}},"required":["job_id"],"additionalProperties":false}},
        {"name":"job_resume_analysis","description":"Retry only a failed resumable aggregation stage without replaying network probes, then resume normal status polling. The memory-only checkpoint must be retried before restart; timeout is bounded to 120000 ms.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"job_id":{"type":"string","format":"uuid"},"js_stage_timeout_ms":{"type":"integer","minimum":250,"maximum":120000}},"required":["project_id","job_id"],"additionalProperties":false}},
        {"name":"job_results","description":"Read completed extension output. summary is compact (default); findings returns a stable page; full returns complete non-finding data plus a paged findings array.","inputSchema":{"type":"object","properties":{"job_id":{"type":"string","format":"uuid"},"view":{"type":"string","enum":["summary","findings","full"],"default":"summary"},"offset":{"type":"integer","minimum":0,"default":0},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}},"required":["job_id"],"additionalProperties":false}},
        {"name":"capture_sessions","description":"List proxy capture credentials, create a one-time credential, revoke one, or renew one. create returns the secret once; copy it immediately. revoke and renew require session_id. This does not start Chromium; use browser_start for browser traffic.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","create","revoke","renew"]},"session_id":{"type":"integer","description":"Required for revoke and renew."}},"required":["project_id","action"],"additionalProperties":false}},
        {"name":"cookies","description":"Set, list, or clear project cookies without exposing their values. Set accepts a raw Cookie header or browser-export JSON cookie array, inline or from a UTF-8 file. Project cookies apply to HTTP tools and ephemeral sessions. Persistent browser jars change only with an explicit browser_start(cookie_profile=...). profile_name stores a reusable named cookie identity for extensions or browser_start(cookie_profile=...) without changing an already running browser.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["set","list","clear"]},"target_url":{"type":"string"},"profile_name":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$","description":"Optional reusable identity name. Pass the same name as browser_start.cookie_profile to seed a persistent Chromium profile."},"cookie":{"oneOf":[{"type":"string","description":"Raw Cookie header or a string containing a JSON cookie array."},{"type":"array","description":"Browser-export or Playwright cookie array.","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"},"domain":{"type":"string"},"hostOnly":{"type":"boolean"},"path":{"type":"string"},"httpOnly":{"type":"boolean"},"secure":{"type":"boolean"},"sameSite":{"type":"string"},"session":{"type":"boolean"},"expirationDate":{"type":"number"},"expires":{"type":"number"}},"required":["name","value"]}}]},"file_path":{"type":"string","description":"Local UTF-8 file containing a raw Cookie header or JSON cookie array."}},"required":["project_id","action"]}},
        request_rules_tool_def(),
        {"name":"overview","description":"Summarize one project's saved activity: total exchanges and counts by source, captured replies sent, findings, distinct hosts, and last exchange time.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"}},"required":["project_id"],"additionalProperties":false}},
        {"name":"history_search","description":"Search saved project history without hiding hosts or MIME types. Active browser responses appear after capture completion. Comparisons attach directly to the field: status>=400 or time>2026-10-12T00:00:00Z. Supports AND/OR/NOT, parentheses, and quoted values. Query errors return repair guidance; correct q before retrying. Full request search can scan decoded bodies, so narrow large projects with host, method, source, size, or time terms. Search results identify exchanges but do not include full body content; use exchange_body with the matching exchange_id to read request or response bytes.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"q":{"type":"string","description":format!("{HISTORY_QUERY_SYNTAX}. Comparisons: >, >=, <, <=, !=. time compares stored UTC RFC 3339 timestamp text, not Unix seconds; copy the saved format for precise cutoffs. duration is milliseconds; request_size and response_size are body bytes. Fields: exchange_id, host, authority, path, method, protocol, status, mime, source, label, request_size, response_size, duration, title, page_title, display_title, parent, browser_session, capture_session, reply_tab, fuzz_job, request_hash, response_hash, time, error, request. request:~text searches the request target, headers, and decoded request body and can be expensive on broad queries. Bare words search summary fields. Adjacent terms are AND; NOT binds before AND, then OR."),"examples":["host:example.com method:GET status>=400","time>2026-10-12T00:00:00Z","duration>=1000 response_size>1024","(request:~\"monthly report\" OR request:~summary) method:PUT"]},"limit":{"type":"integer","minimum":1,"maximum":500}},"required":["project_id"],"additionalProperties":false}},
        {"name":"sitemap","description":"Discover saved routes without oversized responses. Omit host for a lightweight list of hosts and route counts. Provide one exact host for its detailed route tree, optionally limited to a path subtree.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"host":{"type":"string","description":"Optional exact hostname, case-insensitive. Omit for host summaries."},"path_prefix":{"type":"string","description":"Optional slash-boundary path subtree, such as /api. Requires host."}},"required":["project_id"],"additionalProperties":false}},
        {"name":"findings","description":"List findings, mark an exchange as a finding, or remove a finding.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","add","remove"]},"exchange_id":{"type":"integer","description":"Required for add."},"finding_id":{"type":"integer","description":"Required for remove."},"title":{"type":"string","description":"Required for add."},"description":{"type":"string","description":"Required for add."}},"required":["project_id","action"]}},
        {"name":"exchange_get","description":"Get exchange detail (secrets redacted)","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"}},"required":["project_id","exchange_id"]}},
        {"name":"exchange_compare","description":"Compare the saved request and response of two exchanges. Sensitive values stay redacted, while changes are still detected. Text body diffs are bounded.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"left_exchange_id":{"type":"integer"},"right_exchange_id":{"type":"integer"},"include_noisy_headers":{"type":"boolean","default":false}},"required":["project_id","left_exchange_id","right_exchange_id"],"additionalProperties":false}},
        {"name":"page_analyzer","description":"Extract sorted, unique endpoints, absolute URLs, emails, and request parameter names from JavaScript or HTML without executing it. Provide exactly one saved exchange_id or absolute URL. The tool analyzes that page and sequentially fetches bounded same-origin JavaScript bundles referenced by script tags or a Modern.js route manifest; URL mode first sends a semantic GET with project cookies. CSS and other non-JavaScript assets are skipped. Secrets are never scanned or returned.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer","description":"Saved exchange whose decoded response body and same-origin JavaScript bundles should be analyzed."},"url":{"type":"string","description":"Absolute http/https URL to fetch and analyze, including its same-origin JavaScript bundles."}},"required":["project_id"],"oneOf":[{"required":["exchange_id"]},{"required":["url"]}],"additionalProperties":false}},
        {"name":"copy_as","description":"Convert a saved request to cURL or Python requests. The output includes the original sensitive headers by default so it is immediately runnable; set include_secrets=false to produce a redacted copy.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"format":{"type":"string","enum":["curl","python_requests"]},"include_secrets":{"type":"boolean","default":true}},"required":["project_id","exchange_id","format"],"additionalProperties":false}},
        {"name":"exchange_body","description":"Read a captured request or response body in pages up to 1 MiB per call. reply_send returns exchange_id and only a 4 KiB preview; pass that exchange_id here to read the full captured response without re-fetching it or using HTTP Range. Use side=request for the captured request body. available=false means that side has no captured body. UTF-8 output is lossy for arbitrary bytes; set encoding=base64 for exact page bytes. gzip/br/deflate responses are decoded by default; set raw=true to read captured response bytes before decoding. Continue with next_offset while truncated is true.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"side":{"type":"string","enum":["request","response"],"default":"response"},"offset":{"type":"integer","minimum":0,"default":0},"max_bytes":{"type":"integer","minimum":1,"maximum":1048576,"default":4096},"raw":{"type":"boolean","default":false},"encoding":{"type":"string","enum":["utf8","base64"],"default":"utf8","description":"Representation of preview. utf8 is lossy for non-UTF-8 bytes; base64 preserves every byte in this page."}},"required":["project_id","exchange_id"],"additionalProperties":false}},
        {"name":"secret_reveal","description":"Reveal a sensitive header value (audited)","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"side":{"type":"string"},"header":{"type":"string"}},"required":["project_id","exchange_id","header"]}},
        {"name":"reply_tabs","description":"List or create Reply tabs. Draft fields are optional.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","create"]},"name":{"type":"string"},"base_exchange_id":{"type":"integer"},"draft":reply_draft_schema()},"required":["project_id","action"]}},
        {"name":"reply_send","description":"Send a semantic HTTP request and return status plus a decoded 4 KiB response preview. For the full captured response, pass the returned exchange_id to exchange_body with side=response; use its next_offset for further pages. Put request fields under draft (for example draft.url and draft.method); omitted draft fields use safe defaults or inherit from base_exchange_id. upstream_proxy is a transient http://, socks5://, or socks5h:// override.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"tab_id":{"type":"integer"},"base_exchange_id":{"type":"integer"},"draft":reply_draft_schema(),"protocol":{"type":"string","enum":["auto","h1","h2"]},"upstream_proxy":{"type":"string"}},"required":["project_id"],"additionalProperties":false}},
        {"name":"reply_send_raw","description":"Send exact raw HTTP/1.1 bytes, optionally through an upstream proxy, split-writing at one byte offset, reading an early response before same-socket continuation, half-closing the write side, and collecting multiple responses until idle. Use base64 whenever byte offsets or non-UTF-8 bytes matter. This does not provide malformed HTTP/2 framing.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"target_url":{"type":"string"},"request":{"type":"string"},"encoding":{"type":"string","enum":["utf8","base64"]},"tab_id":{"type":"integer"},"use_project_cookies":{"type":"boolean"},"upstream_proxy":{"type":"string","description":"Transient http://, socks5://, or socks5h:// proxy override."},"pause_at_byte":{"type":"integer","minimum":1,"description":"Split the exact decoded request at this byte offset."},"pause_ms":{"type":"integer","minimum":1,"maximum":120000},"await_response_before_continue":{"type":"boolean","default":false,"description":"Read one early response while the split request is incomplete, then continue on the same connection."},"half_close_write":{"type":"boolean","default":false},"response_mode":{"type":"string","enum":["auto","until_idle","until_close"],"default":"auto"},"read_timeout_ms":{"type":"integer","minimum":1,"maximum":120000,"default":60000},"idle_timeout_ms":{"type":"integer","minimum":1,"maximum":10000,"default":1000}},"required":["project_id","target_url","request"]}},
        {"name":"fuzz_start","description":"Start a bounded fuzz job. Put §name§ markers in draft.url, a header override, or body_override; use the same name in insertion_points. Payloads may be inline wordlists, local UTF-8 wordlist_files, inclusive number ranges, or native Recollapse-style regex bypass generators.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"template":fuzz_template_schema(),"confirm_large":{"type":"boolean","default":false}},"required":["project_id","template"]}},
        {"name":"fuzz_manage","description":"List, inspect, cancel, group, diff, or page through fuzz jobs and cases. Case results include their saved exchange_id; use exchange_body to read the full response without replaying it. Continue case pages with next_before_case_index.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","get","cancel","cases","groups","group_cases","diff"]},"job_id":{"type":"integer"},"case_id":{"type":"integer"},"baseline_case_id":{"type":"integer"},"group_id":{"type":"string"},"include_text":{"type":"boolean","default":false},"limit":{"type":"integer","minimum":1,"maximum":500},"before_case_index":{"type":"integer","minimum":0}},"required":["project_id","action"],"additionalProperties":false}},
        {"name":"websocket_manage","description":"List intercepted WebSocket connections and messages, or inject a text/binary message into an active connection.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","messages","send"]},"connection_id":{"type":"integer"},"after_id":{"type":"integer"},"limit":{"type":"integer","minimum":1,"maximum":1000},"direction":{"type":"string","enum":["to_server","to_client"]},"encoding":{"type":"string","enum":["text","base64"],"default":"text"},"payload":{"type":"string"}},"required":["project_id","action"],"additionalProperties":false}},
        {"name":"browser_profiles","description":"List, create, or delete named persistent Chromium identities for a project. default always exists and cannot be deleted. Deleting a named profile requires it to be stopped first.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","create","delete"]},"profile":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$","description":"Required for create and delete."}},"required":["project_id","action"],"additionalProperties":false}},
        {"name":"browser_start","description":"Start or resume a persistent Chromium identity. profile defaults to default; different profiles can stay open simultaneously and each returns its own session_id. Omitting cookie_profile preserves the browser jar without injecting project or named cookies. Pass a matching cookie_profile created by cookies(profile_name=...) to seed its cookie jar. Repeated unchanged seeds preserve newer browser cookies; use refresh_cookies=true to explicitly reimport. An active matching profile is resumed without relaunching. Omit url to resume the selected profile's last page.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"profile":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$","default":"default"},"cookie_profile":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$","description":"Must match profile. Seeds new or changed cookies; unchanged seeds are not reimported unless refresh_cookies=true."},"refresh_cookies":{"type":"boolean","default":false,"description":"Explicitly reimport the matching cookie_profile into this browser profile only."},"url":{"type":"string","default":"about:blank","description":"Optional page to open. Omit to resume the selected profile's last page."}},"required":["project_id"],"additionalProperties":false}},
        {"name":"browser_action","description":"Navigate, inspect, or interact with an active browser session.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"session_id":{"type":"integer"},"action":browser_action_schema()},"required":["project_id","session_id","action"]}},
        {"name":"browser_cdp","description":"Hand an active persistent Chromium session to a person through loopback Chrome DevTools on port 9222, inspect handoff status, or return control to the agent. While enabled, browser_action is paused. On a VPS, run the returned ssh_forward_command (ssh -N -L 9222:127.0.0.1:9222 <current-user>@<routed-host-ip>); its user and host are detected at runtime. Try hosted_devtools_url to avoid transferring the frontend through SSH; use devtools_url if the browser restricts the hosted frontend's local-network WebSocket.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"session_id":{"type":"integer","description":"Required for enable and disable; use the active browser session ID."},"op":{"type":"string","enum":["enable","status","disable"]}},"required":["project_id","op"],"additionalProperties":false}},
        {"name":"browser_manage","description":"Get status, suspend one browser, suspend all project browsers, or reset one persistent Chromium profile. Status without session_id lists active browser sessions and resources: per-project capacity including ephemeral sessions, verified profile ownership, and a global CDP busy flag. Reuse these observations until a lifecycle transition or browser error; capacity is not a reservation. Stop operations preserve browser state. reset_profile defaults to default, requires confirm=true, and clears only that profile's browser-derived state.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"session_id":{"type":"integer","description":"Required for stop; optional for status."},"profile":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$","default":"default","description":"Profile to reset when op=reset_profile."},"op":{"type":"string","enum":["status","stop","stop_all","reset_profile"]},"confirm":{"type":"boolean","default":false,"description":"Must be true for reset_profile because browser state is permanently deleted."}},"required":["project_id","op"],"additionalProperties":false}},
        {"name":"js_files","description":"Return JavaScript files with the page URLs and hosts that included or loaded them. Without url, search saved history and provenance; with url, load that page in Chromium. A domain filter matches either the JavaScript host or its related page host, including subdomains.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"url":{"type":"string","description":"When provided, perform a fresh browser load before collecting files."},"domain":{"type":"string","description":"Optional exact domain plus subdomains; accepts target.com, *.target.com, or a full URL."},"settle_ms":{"type":"integer","minimum":0,"maximum":30000,"default":2000},"limit":{"type":"integer","minimum":1,"maximum":10000,"default":2000}},"required":["project_id"]}},
        {"name":"get_words","description":"Build a sorted target-specific wordlist from saved request paths, parameter names, and textual responses. Related JavaScript files are included by default. Optionally filter by a domain and its subdomains.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"domain":{"type":"string","description":"Optional hostname, wildcard hostname, or HTTP URL."},"include_js":{"type":"boolean","default":true},"limit":{"type":"integer","minimum":1,"maximum":10000,"default":5000}},"required":["project_id"],"additionalProperties":false}},
        {"name":"huntproxy_stop","description":"Gracefully stop HuntProxy and all managed browsers. Keeps this MCP connection available; call huntproxy_restart to continue later. Use only when the user explicitly asks to stop HuntProxy.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"huntproxy_restart","description":"Restart or recover HuntProxy without reconnecting the agent's MCP session. Preserves saved projects, traffic, findings, Reply/Fuzzer state, and browser profiles. Active browsers close and can be resumed using browser_start. Running jobs are interrupted; memory-only plugin results/checkpoints are lost. Use when the user asks to restart or to continue after HuntProxy has stopped.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"codec_transform","description":"Apply byte transforms, including gzip_decode/gunzip and brotli_decode","inputSchema":{"type":"object","properties":{"input":{"type":"string"},"input_encoding":{"type":"string","enum":["utf8","base64","hex"]},"pipeline":{"type":"array","items":{"type":"string"}}},"required":["input","pipeline"]}},
        {"name":"evidence_export","description":"Export exchange evidence metadata","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"}},"required":["project_id","exchange_id"]}},
        {"name":"project_transfer","description":"Import or export a project bundle or HAR through a local file. Sanitized export is the default; include_secrets must be explicitly true for credentials and browser state. Returns a summary/path, never archive bytes.","inputSchema":{"type":"object","properties":{"action":{"type":"string","enum":["export","import"]},"format":{"type":"string","enum":["huntproxy","har"]},"project_id":{"type":"integer","description":"Required for export and HAR import."},"file_path":{"type":"string","description":"Required for import; optional export destination under the configured exports directory."},"include_secrets":{"type":"boolean","default":false},"include_chromium_profile":{"type":"boolean","default":false}},"required":["action","format"],"additionalProperties":false}},
        {"name":"exchange_annotate","description":"Set an exchange title, note, and labels","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"display_title":{"type":["string","null"]},"note":{"type":["string","null"]},"labels":{"type":"array","items":{"type":"string"}},"expected_revision":{"type":"integer"}},"required":["project_id","exchange_id"]}}
    ])
}

fn local_tool_defs() -> Value {
    let mut definitions = tool_defs();
    if let Some(tools) = definitions.as_array_mut() {
        tools.retain(|tool| tool.get("name").and_then(Value::as_str) != Some("huntproxy_restart"));
        if let Some(stop) = tools
            .iter_mut()
            .find(|tool| tool["name"] == "huntproxy_stop")
        {
            stop["description"] = json!("Gracefully stop HuntProxy and all managed browsers. The in-process MCP server cannot restart itself; reconnect to continue. Use only when the user explicitly asks to stop HuntProxy.");
        }
    }
    definitions
}

pub async fn run_stdio_mcp(state: Arc<AppState>) -> DomainResult<()> {
    let idle_timeout = std::time::Duration::from_secs(state.config.idle_timeout_seconds);
    run_stdio_backend(Arc::new(LocalToolBackend { state }), idle_timeout).await
}

/// Run the stdio MCP adapter as a thin client of the single daemon owner.
pub async fn run_stdio_mcp_client(config: Config) -> DomainResult<()> {
    // The inexpensive bridge must outlive an idle/stopped daemon so restart
    // and the next tool call remain available on the same client connection.
    run_stdio_backend(
        Arc::new(DaemonToolBackend { config }),
        std::time::Duration::ZERO,
    )
    .await
}

pub async fn run_stdio(state: Arc<AppState>) -> DomainResult<()> {
    run_stdio_mcp(state).await
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

    loop {
        let next_line = if idle_timeout.is_zero() {
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
        let line =
            line.map_err(|e| DomainError::new(ErrorCode::ProtocolError, format!("stdin: {e}")))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let req: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                write_response(JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: None,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("parse error: {e}"),
                        data: None,
                    }),
                });
                continue;
            }
        };
        let id = req.id.clone();
        match handle_rpc(backend.clone(), &req).await {
            Ok(Some(value)) => {
                write_response(JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(value),
                    error: None,
                });
            }
            Ok(None) => {}
            Err(e) => write_response(JsonRpcResponse {
                jsonrpc: "2.0",
                id,
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
            }),
        }
    }
    Ok(())
}

fn write_response(resp: JsonRpcResponse) {
    let mut out = std::io::stdout().lock();
    if let Ok(s) = serde_json::to_string(&resp) {
        let _ = writeln!(out, "{s}");
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
            "capabilities": { "tools": {} },
            "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION }
        }))),
        "notifications/initialized" | "initialized" => Ok(None),
        "ping" => Ok(Some(json!({}))),
        "tools/list" => Ok(Some(json!({ "tools": backend.definitions() }))),
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
            let structured_content = object_structured_content(&result);
            Ok(Some(json!({
                "content": [{ "type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_default() }],
                "structuredContent": structured_content,
                "isError": is_error
            })))
        }
        other => Err(DomainError::invalid(format!("unknown method {other}"))),
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

fn object_structured_content(result: &Value) -> Value {
    if result.is_object() {
        result.clone()
    } else {
        json!({ "result": result })
    }
}

fn require_project_id(args: &Value) -> DomainResult<ProjectId> {
    let id = args
        .get("project_id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| DomainError::invalid("project_id required"))?;
    Ok(ProjectId(id))
}

async fn fetch_page_analyzer_bundle(
    state: &Arc<AppState>,
    project_id: ProjectId,
    source_url: &str,
    bundle_url: String,
) -> DomainResult<Option<Vec<u8>>> {
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
    if let Some(exchange_id) = result.exchange_id {
        emit_event(
            state,
            project_id,
            "exchange",
            json!({ "exchange_id": exchange_id.get(), "source": "reply" }),
        );
        return Ok(Some(
            crate::page_analyzer::load_exchange_content(&state.db, project_id, exchange_id)
                .await?
                .body,
        ));
    }
    let Some(response) = result.response else {
        return Ok(None);
    };
    let (body, _, _) = crate::page_analyzer::decode_ephemeral_response(&response)?;
    Ok(Some(body))
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

fn page_analysis_tree_fields(tree: crate::page_analyzer::ScriptTreeAnalysis) -> Value {
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
    })
}

#[derive(Debug, Clone, Serialize)]
struct JavascriptFileOutput {
    exchange_id: Option<ExchangeId>,
    url: String,
    path: String,
    host: String,
    mime: Option<String>,
    status_code: Option<u16>,
    related_page_urls: Vec<String>,
    related_page_hosts: Vec<String>,
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

fn javascript_files_response(
    source: &str,
    files: Vec<JavascriptFileOutput>,
    truncated: bool,
    domain: Option<&str>,
    browser: Option<Value>,
) -> Value {
    let urls = files
        .iter()
        .map(|file| file.url.clone())
        .collect::<Vec<_>>();
    let paths = files
        .iter()
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    json!({
        "source": source,
        "domain": domain,
        "count": files.len(),
        "truncated": truncated,
        "files": files,
        "urls": urls,
        "paths": paths,
        "browser": browser,
    })
}

fn emit_event(state: &AppState, project_id: ProjectId, kind: &str, payload: Value) {
    let _ = state.events.send(crate::app::AppEvent {
        project_id: project_id.get(),
        kind: kind.into(),
        payload,
    });
}

pub async fn call_tool(state: Arc<AppState>, name: &str, args: Value) -> DomainResult<Value> {
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
            let base_exchange_id = args
                .get("base_exchange_id")
                .and_then(Value::as_i64)
                .map(ExchangeId);
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
            let base_exchange_id = args
                .get("base_exchange_id")
                .or_else(|| args.get("exchange_id"))
                .and_then(Value::as_i64)
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
                            args.get("js_stage_timeout_ms").and_then(Value::as_u64),
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
                let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(25) as usize;
                Ok(state.plugins.results(id, view, offset, limit)?)
            } else {
                let job = if name == "job_cancel" {
                    state.plugins.cancel(id)?
                } else {
                    state.plugins.status(id)?
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
                "list" => Ok(json!(state.db.list_projects().await?)),
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
                "usage" => {
                    let project_id = require_project_id(&args)?;
                    Ok(json!(state.db.project_usage(project_id).await?))
                }
                _ => Err(DomainError::invalid(
                    "action must be list|create|usage|set_scope",
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
                    let sid = args
                        .get("session_id")
                        .and_then(|v| v.as_i64())
                        .ok_or_else(|| DomainError::invalid("session_id required"))?;
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
                    let sid = args
                        .get("session_id")
                        .and_then(|v| v.as_i64())
                        .ok_or_else(|| DomainError::invalid("session_id required"))?;
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
                    let target_url = args
                        .get("target_url")
                        .and_then(Value::as_str)
                        .ok_or_else(|| DomainError::invalid("target_url required"))?;
                    let inline = args.get("cookie");
                    let file_path = args.get("file_path").and_then(Value::as_str);
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
                        let id = args
                            .get("rule_id")
                            .and_then(Value::as_i64)
                            .ok_or_else(|| DomainError::invalid("rule_id required"))?;
                        state.db.update_request_rule(project_id, id, input).await?
                    };
                    Ok(json!(rule))
                }
                "remove" => {
                    let id = args
                        .get("rule_id")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| DomainError::invalid("rule_id required"))?;
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
        "history_search" => {
            let project_id = require_project_id(&args)?;
            let query = match args.get("q") {
                None => None,
                Some(Value::String(query)) => Some(query.as_str()),
                Some(_) => {
                    return Err(query_error(format!(
                        "history_search q must be a query string; omit q to list history. {HISTORY_QUERY_SYNTAX}"
                    )))
                }
            };
            let filter = query
                .filter(|query| !query.trim().is_empty())
                .map(parse_text_query)
                .transpose()?;
            if let Some(filter) = &filter {
                crate::history::validate_filter(filter)?;
            }
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(50)
                .clamp(1, 500) as u32;
            let (items, next) = state
                .db
                .list_history_filtered(project_id, filter, limit, None, None)
                .await?;
            Ok(json!({
                "items": items,
                "next": next,
                "saved_only": true,
                "noise_filtered": false
            }))
        }
        "sitemap" => {
            let project_id = require_project_id(&args)?;
            let host = args
                .get("host")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            let path_prefix = args
                .get("path_prefix")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            match host {
                Some(host) => Ok(json!({
                    "hosts": state
                        .db
                        .list_sitemap_subtree(project_id, Some(host), path_prefix)
                        .await?
                })),
                None if path_prefix.is_some() => {
                    Err(DomainError::invalid("sitemap path_prefix requires host"))
                }
                None => Ok(json!({
                    "hosts": state.db.list_sitemap_hosts(project_id).await?
                })),
            }
        }
        "findings" => {
            let project_id = require_project_id(&args)?;
            match args.get("action").and_then(Value::as_str).unwrap_or("list") {
                "list" => Ok(json!({
                    "findings": state.db.list_findings(project_id).await?
                })),
                "add" => {
                    let exchange_id = args
                        .get("exchange_id")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| DomainError::invalid("exchange_id required"))?;
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
                    let finding_id = args
                        .get("finding_id")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| DomainError::invalid("finding_id required"))?;
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
        "exchange_get" => {
            let project_id = require_project_id(&args)?;
            let eid = args
                .get("exchange_id")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| DomainError::invalid("exchange_id required"))?;
            let detail = state
                .db
                .get_exchange_detail(project_id, ExchangeId(eid), PresentationOptions::default())
                .await?;
            let annotation = state.db.get_annotation(project_id, ExchangeId(eid)).await?;
            let applied_rules = state
                .db
                .list_exchange_request_rules(project_id, ExchangeId(eid))
                .await?;
            let mut value = serde_json::to_value(detail)
                .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?;
            if let Some(object) = value.as_object_mut() {
                object.insert("annotation".into(), json!(annotation));
                object.insert("applied_request_rules".into(), json!(applied_rules));
            }
            Ok(value)
        }
        "exchange_compare" => {
            let project_id = require_project_id(&args)?;
            let left = args
                .get("left_exchange_id")
                .and_then(Value::as_i64)
                .ok_or_else(|| DomainError::invalid("left_exchange_id required"))?;
            let right = args
                .get("right_exchange_id")
                .and_then(Value::as_i64)
                .ok_or_else(|| DomainError::invalid("right_exchange_id required"))?;
            Ok(json!(
                crate::compare::compare_saved_exchanges(
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
                .await?
            ))
        }
        "page_analyzer" => {
            let project_id = require_project_id(&args)?;
            let exchange_id = args
                .get("exchange_id")
                .and_then(Value::as_i64)
                .map(ExchangeId);
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
                    let mut output = page_analysis_tree_fields(tree);
                    let object = output.as_object_mut().expect("page analysis object");
                    object.insert("project_id".into(), json!(project_id));
                    object.insert("exchange_id".into(), json!(exchange_id));
                    object.insert("source_url".into(), json!(source_url));
                    object.insert("decoded".into(), json!(content.decoded));
                    object.insert("content_encoding".into(), json!(content.content_encoding));
                    object.insert("body_truncated".into(), json!(content.body_truncated));
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
                    let (effective_source_url, body, decoded, content_encoding, body_truncated) =
                        if let Some(exchange_id) = exchange_id {
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
                            )
                        };
                    let tree = analyze_page_script_tree(
                        &state,
                        project_id,
                        effective_source_url.clone(),
                        body,
                    )
                    .await;
                    let mut output = page_analysis_tree_fields(tree);
                    let object = output.as_object_mut().expect("page analysis object");
                    object.insert("project_id".into(), json!(project_id));
                    object.insert("exchange_id".into(), json!(exchange_id));
                    object.insert("source_url".into(), json!(effective_source_url));
                    object.insert("decoded".into(), json!(decoded));
                    object.insert("content_encoding".into(), json!(content_encoding));
                    object.insert("body_truncated".into(), json!(body_truncated));
                    Ok(output)
                }
                _ => Err(DomainError::invalid(
                    "provide exactly one of exchange_id or url",
                )),
            }
        }
        "copy_as" => {
            let project_id = require_project_id(&args)?;
            let exchange_id = args
                .get("exchange_id")
                .and_then(Value::as_i64)
                .map(ExchangeId)
                .ok_or_else(|| DomainError::invalid("exchange_id required"))?;
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
                let _ = state
                    .db
                    .audit(
                        Some(project_id),
                        "copy_as_secret_reveal",
                        Some("mcp"),
                        Some("exchange"),
                        Some(&exchange_id.get().to_string()),
                        json!({ "format": format }),
                    )
                    .await;
            }
            Ok(json!(result))
        }
        "exchange_body" => {
            let project_id = require_project_id(&args)?;
            let eid = args
                .get("exchange_id")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| DomainError::invalid("exchange_id required"))?;
            let encoding = args
                .get("encoding")
                .and_then(Value::as_str)
                .unwrap_or("utf8");
            if !matches!(encoding, "utf8" | "base64") {
                return Err(DomainError::invalid("encoding must be utf8|base64"));
            }
            let side = match args
                .get("side")
                .and_then(|v| v.as_str())
                .unwrap_or("response")
            {
                "request" => MessageSide::Request,
                "response" => MessageSide::Response,
                _ => return Err(DomainError::invalid("side must be request|response")),
            };
            let offset = args
                .get("offset")
                .and_then(|value| value.as_u64())
                .map(|value| usize::try_from(value).unwrap_or(usize::MAX))
                .unwrap_or(0);
            let max = args
                .get("max_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(4096)
                .clamp(1, 1024 * 1024) as usize;
            let stored_body = state
                .db
                .load_raw_body(project_id, ExchangeId(eid), side)
                .await?;
            let available = stored_body.is_some();
            let mut body = stored_body.unwrap_or_default();
            let raw_total = body.len();
            let mut content_encoding = None;
            let mut decoded = false;
            let detail = state
                .db
                .get_exchange_detail(project_id, ExchangeId(eid), PresentationOptions::default())
                .await?;
            if side == MessageSide::Request {
                if detail.protocol == "HTTP/1.1 raw" {
                    body = crate::reply::redact_raw_request_headers(&body);
                }
            } else if !args.get("raw").and_then(Value::as_bool).unwrap_or(false) {
                if detail.protocol == "HTTP/1.1 raw" {
                    body = crate::reply::presented_raw_response_body(&body);
                }
                let headers = state
                    .db
                    .load_raw_headers(project_id, ExchangeId(eid), MessageSide::Response)
                    .await?;
                let encodings = headers
                    .iter()
                    .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
                    .map(|header| String::from_utf8_lossy(&header.value).trim().to_string())
                    .filter(|encoding| {
                        !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity")
                    })
                    .collect::<Vec<_>>();
                if !encodings.is_empty() {
                    let encoding = encodings.join(", ");
                    body = crate::codec::decode_content_encodings(
                        &body,
                        &encoding,
                        crate::codec::MAX_DECODED_BODY_OUTPUT,
                    )?;
                    content_encoding = Some(encoding);
                    decoded = true;
                }
            }
            let end = offset.saturating_add(max).min(body.len());
            let slice = if offset >= body.len() {
                &body[..0]
            } else {
                &body[offset..end]
            };
            let preview = match encoding {
                "utf8" => String::from_utf8_lossy(slice).into_owned(),
                "base64" => base64::engine::general_purpose::STANDARD.encode(slice),
                _ => unreachable!("encoding validated above"),
            };
            Ok(json!({
                "available": available,
                "total": body.len(),
                "offset": offset,
                "length": slice.len(),
                "preview": preview,
                "encoding": encoding,
                "truncated": end < body.len(),
                "next_offset": (end < body.len()).then_some(end),
                "decoded": decoded,
                "content_encoding": content_encoding,
                "raw_total": raw_total,
            }))
        }
        "secret_reveal" => {
            let project_id = require_project_id(&args)?;
            let eid = args
                .get("exchange_id")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| DomainError::invalid("exchange_id required"))?;
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
            let _ = state
                .db
                .audit(
                    Some(project_id),
                    "secret_reveal",
                    Some("mcp"),
                    Some("header"),
                    Some(&format!("{}/{}", eid, header.to_ascii_lowercase())),
                    json!({ "side": match side { MessageSide::Request => "request", MessageSide::Response => "response" } }),
                )
                .await;
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
                    let base = args
                        .get("base_exchange_id")
                        .and_then(|v| v.as_i64())
                        .map(ExchangeId);
                    let draft: ReplyDraft = args
                        .get("draft")
                        .cloned()
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|e| DomainError::invalid(e.to_string()))?
                        .unwrap_or_default();
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
            for field in [
                "url",
                "method",
                "headers",
                "header_overrides",
                "body",
                "body_text",
                "body_json",
                "body_params",
                "body_format",
            ] {
                if args.get(field).is_some() {
                    return Err(DomainError::invalid(format!(
                        "put request field `{field}` under `draft`"
                    )));
                }
            }
            let draft: ReplyDraft = args
                .get("draft")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|e| DomainError::invalid(e.to_string()))?
                .unwrap_or_default();
            let protocol = match args.get("protocol").and_then(Value::as_str) {
                Some("h1") => ProtocolPreference::H1,
                Some("h2") => ProtocolPreference::H2,
                Some("auto") | None => ProtocolPreference::Auto,
                Some(_) => return Err(DomainError::invalid("protocol must be auto|h1|h2")),
            };
            let result = state
                .reply
                .send_with_proxy(
                    project_id,
                    args.get("tab_id").and_then(|v| v.as_i64()).map(ReplyTabId),
                    args.get("base_exchange_id")
                        .and_then(|v| v.as_i64())
                        .map(ExchangeId),
                    &draft,
                    protocol,
                    0,
                    args.get("upstream_proxy").and_then(Value::as_str),
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
            serde_json::to_value(result)
                .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))
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
                    args.get("tab_id")
                        .and_then(|value| value.as_i64())
                        .map(ReplyTabId),
                    target_url,
                    request_bytes,
                    args.get("use_project_cookies")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    serde_json::from_value(args.clone()).map_err(|error| {
                        DomainError::invalid(format!("raw HTTP/1.1 options: {error}"))
                    })?,
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
            let template: FuzzTemplate = serde_json::from_value(
                args.get("template")
                    .cloned()
                    .ok_or_else(|| DomainError::invalid("template required"))?,
            )
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
                    let jid = args
                        .get("job_id")
                        .and_then(|v| v.as_i64())
                        .ok_or_else(|| DomainError::invalid("job_id required"))?;
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
                    let jid = args
                        .get("job_id")
                        .and_then(|v| v.as_i64())
                        .ok_or_else(|| DomainError::invalid("job_id required"))?;
                    Ok(json!(state.fuzzer.get(project_id, FuzzJobId(jid)).await?))
                }
                "cases" => {
                    let jid = args
                        .get("job_id")
                        .and_then(|value| value.as_i64())
                        .ok_or_else(|| DomainError::invalid("job_id required"))?;
                    let limit = args
                        .get("limit")
                        .and_then(|value| value.as_u64())
                        .unwrap_or(100)
                        .min(500) as u32;
                    let before = args
                        .get("before_case_index")
                        .and_then(|value| value.as_u64());
                    let (cases, next) = state
                        .fuzzer
                        .list_cases(project_id, FuzzJobId(jid), limit, before)
                        .await?;
                    Ok(json!({ "cases": cases, "next_before_case_index": next }))
                }
                "groups" => {
                    let jid = args
                        .get("job_id")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| DomainError::invalid("job_id required"))?;
                    Ok(json!({
                        "groups": state.fuzzer
                            .list_response_groups(project_id, FuzzJobId(jid)).await?
                    }))
                }
                "group_cases" => {
                    let jid = args
                        .get("job_id")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| DomainError::invalid("job_id required"))?;
                    let group_id = args
                        .get("group_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| DomainError::invalid("group_id required"))?;
                    let limit = args
                        .get("limit")
                        .and_then(Value::as_u64)
                        .unwrap_or(100)
                        .min(500) as u32;
                    let (cases, next) = state
                        .fuzzer
                        .list_group_cases(
                            project_id,
                            FuzzJobId(jid),
                            group_id.to_string(),
                            limit,
                            args.get("before_case_index").and_then(Value::as_u64),
                        )
                        .await?;
                    Ok(json!({ "cases": cases, "next_before_case_index": next }))
                }
                "diff" => {
                    let jid = args
                        .get("job_id")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| DomainError::invalid("job_id required"))?;
                    let case_id = args
                        .get("case_id")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| DomainError::invalid("case_id required"))?;
                    Ok(json!(
                        state
                            .fuzzer
                            .response_diff(
                                project_id,
                                FuzzJobId(jid),
                                case_id,
                                args.get("baseline_case_id").and_then(Value::as_i64),
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
            let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(250) as u32;
            match action {
                "list" => Ok(json!({
                    "connections": state.db.list_websocket_connections(project_id, limit).await?
                })),
                "messages" => {
                    let connection_id = args
                        .get("connection_id")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| DomainError::invalid("connection_id required"))?;
                    Ok(json!({
                        "messages": state.db.list_websocket_messages(
                            project_id,
                            connection_id,
                            args.get("after_id").and_then(Value::as_i64),
                            limit,
                        ).await?
                    }))
                }
                "send" => {
                    let connection_id = args
                        .get("connection_id")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| DomainError::invalid("connection_id required"))?;
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
                    "action must be list, messages, or send",
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
            let profile = args
                .get("profile")
                .and_then(Value::as_str)
                .unwrap_or("default");
            let cookie_profile = args.get("cookie_profile").and_then(Value::as_str);
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
            let sid = args
                .get("session_id")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| DomainError::invalid("session_id required"))?;
            let action: BrowserAction = serde_json::from_value(
                args.get("action")
                    .cloned()
                    .ok_or_else(|| DomainError::invalid("action required"))?,
            )
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
                "status" => match args.get("session_id").and_then(Value::as_i64) {
                    Some(session_id) => {
                        state
                            .browser
                            .cdp_status_for_session(project_id, BrowserSessionId(session_id))
                            .await?
                    }
                    None => state.browser.cdp_status(project_id).await?,
                },
                "enable" | "disable" => {
                    let session_id = args
                        .get("session_id")
                        .and_then(Value::as_i64)
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
            if op == "status" && args.get("session_id").and_then(Value::as_i64).is_none() {
                return Ok(json!(state.browser.active_status(project_id).await?));
            }
            let sid = args
                .get("session_id")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| DomainError::invalid("session_id required"))?;
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
        "js_files" => {
            let project_id = require_project_id(&args)?;
            let domain = normalize_domain_filter(args.get("domain").and_then(Value::as_str))?;
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(2_000)
                .clamp(1, 10_000) as usize;
            if let Some(url) = args.get("url").and_then(Value::as_str) {
                let parsed = url::Url::parse(url)
                    .map_err(|error| DomainError::invalid(format!("invalid load URL: {error}")))?;
                if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                    return Err(DomainError::invalid(
                        "load URL must be an absolute http or https URL",
                    ));
                }
                let session = state
                    .browser
                    .start_ephemeral(project_id, url.to_string())
                    .await?;
                let settle_ms = args
                    .get("settle_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(2_000)
                    .min(30_000);
                tokio::time::sleep(std::time::Duration::from_millis(settle_ms)).await;
                let files_result = state.browser.javascript_files(project_id, session.id).await;
                let stop_result = state.browser.stop(project_id, session.id).await;
                let mut files = files_result?
                    .into_iter()
                    .filter(|file| {
                        domain.as_deref().is_none_or(|domain| {
                            host_matches_domain(&file.host, domain)
                                || file
                                    .source_page_url
                                    .as_deref()
                                    .and_then(|url| url::Url::parse(url).ok())
                                    .and_then(|url| url.host_str().map(str::to_string))
                                    .is_some_and(|host| host_matches_domain(&host, domain))
                        })
                    })
                    .map(|file| JavascriptFileOutput {
                        exchange_id: None,
                        url: file.url,
                        path: file.path,
                        host: file.host,
                        mime: file.mime,
                        status_code: file.status_code,
                        related_page_urls: file.source_page_url.clone().into_iter().collect(),
                        related_page_hosts: file
                            .source_page_url
                            .as_deref()
                            .and_then(|url| url::Url::parse(url).ok())
                            .and_then(|url| url.host_str().map(str::to_string))
                            .into_iter()
                            .collect(),
                    })
                    .collect::<Vec<_>>();
                stop_result?;
                let truncated = files.len() > limit;
                if truncated {
                    files.truncate(limit);
                }
                Ok(javascript_files_response(
                    "load",
                    files,
                    truncated,
                    domain.as_deref(),
                    Some(json!({
                        "session_id": session.id,
                        "engine": session.engine,
                        "stopped": true,
                    })),
                ))
            } else {
                let (files, truncated) = state
                    .db
                    .list_javascript_files(project_id, None, domain.clone(), limit as u32)
                    .await?;
                let files = files
                    .into_iter()
                    .map(|file| JavascriptFileOutput {
                        exchange_id: file.exchange_id,
                        url: file.url,
                        path: file.path,
                        host: file.host,
                        mime: file.mime,
                        status_code: file.status_code,
                        related_page_urls: file.related_page_urls,
                        related_page_hosts: file.related_page_hosts,
                    })
                    .collect();
                Ok(javascript_files_response(
                    "history",
                    files,
                    truncated,
                    domain.as_deref(),
                    None,
                ))
            }
        }
        "get_words" => {
            let project_id = require_project_id(&args)?;
            let include_js = args
                .get("include_js")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
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
        "evidence_export" => {
            let project_id = require_project_id(&args)?;
            let eid = args
                .get("exchange_id")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| DomainError::invalid("exchange_id required"))?;
            let detail = state
                .db
                .get_exchange_detail(project_id, ExchangeId(eid), PresentationOptions::default())
                .await?;
            let path =
                state
                    .config
                    .export_dir
                    .join(format!("exchange_{}_{}.json", project_id.get(), eid));
            crate::config::create_private_dir(&state.config.export_dir)?;
            let data = serde_json::to_vec_pretty(&detail)
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            crate::config::write_private_file(&path, &data)?;
            let _ = state
                .db
                .audit(
                    Some(project_id),
                    "evidence_export",
                    Some("mcp"),
                    Some("exchange"),
                    Some(&eid.to_string()),
                    json!({ "path": path.display().to_string() }),
                )
                .await;
            Ok(json!({ "path": path.display().to_string() }))
        }
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
            let project_id = args
                .get("project_id")
                .and_then(Value::as_i64)
                .map(ProjectId);
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
                    let file = std::fs::OpenOptions::new()
                        .create(true)
                        .truncate(true)
                        .write(true)
                        .open(&path)
                        .map_err(|error| {
                            DomainError::new(ErrorCode::StorageError, error.to_string())
                        })?;
                    serde_json::to_writer(file, &har).map_err(|error| {
                        DomainError::new(ErrorCode::StorageError, error.to_string())
                    })?;
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
            let eid = args
                .get("exchange_id")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| DomainError::invalid("exchange_id required"))?;
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
            let expected_revision = args
                .get("expected_revision")
                .and_then(|value| value.as_i64());
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

    fn history_call(arguments: Value) -> JsonRpcRequest {
        JsonRpcRequest {
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({"name": "history_search", "arguments": arguments}),
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
            Arc::new(DaemonToolBackend { config }) as Arc<dyn ToolBackend>,
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
            assert_eq!(result["structuredContent"]["items"], json!([]));
            assert_eq!(result["structuredContent"]["saved_only"], true);
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
            let filter = parse_text_query(example.as_str().unwrap()).unwrap();
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
    fn in_process_backend_does_not_advertise_daemon_restart() {
        let tools = local_tool_defs();
        assert!(!tools
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "huntproxy_restart"));
        let stop = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "huntproxy_stop")
            .unwrap();
        assert!(stop["description"]
            .as_str()
            .unwrap()
            .contains("cannot restart itself"));
    }

    #[test]
    fn structured_content_is_always_an_object_for_mcp_clients() {
        let object = json!({"ok": true});
        assert_eq!(object_structured_content(&object), object);
        assert_eq!(
            object_structured_content(&json!([1, 2])),
            json!({"result": [1, 2]})
        );
        assert_eq!(
            object_structured_content(&json!("value")),
            json!({"result": "value"})
        );
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
        let cookies = tools.iter().find(|tool| tool["name"] == "cookies").unwrap();
        let cookie_inputs = cookies["inputSchema"]["properties"]["cookie"]["oneOf"]
            .as_array()
            .unwrap();
        assert_eq!(cookie_inputs[0]["type"], "string");
        assert_eq!(cookie_inputs[1]["type"], "array");
        assert_eq!(
            cookie_inputs[1]["items"]["required"],
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
        assert!(
            browser["inputSchema"]["properties"]["action"]["properties"]["type"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "navigate")
        );
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
            .contains("ssh -N -L 9222"));
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
            .contains("without re-fetching it or using HTTP Range"));
        assert!(tools
            .iter()
            .find(|tool| tool["name"] == "reply_send")
            .unwrap()["description"]
            .as_str()
            .unwrap()
            .contains("pass the returned exchange_id to exchange_body"));
    }
}
