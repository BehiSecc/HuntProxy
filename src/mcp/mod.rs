//! Minimal stdio JSON-RPC MCP server. Protocol on stdout; diagnostics on stderr.

use crate::app::AppState;
use crate::browser::BrowserAction;
use crate::codec::{apply_pipeline, Transform};
use crate::config::Config;
use crate::domain::*;
use crate::fuzzer::FuzzTemplate;
use crate::history::parse_text_query;
use crate::policy::{is_sensitive_header, PresentationOptions};
use crate::storage::CreateCaptureSession;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Arc;

#[async_trait::async_trait]
trait ToolBackend: Send + Sync {
    async fn call(&self, name: &str, args: Value) -> DomainResult<Value>;
}

struct LocalToolBackend {
    state: Arc<AppState>,
}

#[async_trait::async_trait]
impl ToolBackend for LocalToolBackend {
    async fn call(&self, name: &str, args: Value) -> DomainResult<Value> {
        call_tool(self.state.clone(), name, args).await
    }
}

struct DaemonToolBackend {
    config: Config,
}

#[async_trait::async_trait]
impl ToolBackend for DaemonToolBackend {
    async fn call(&self, name: &str, args: Value) -> DomainResult<Value> {
        let armed_stop_guard = name == "huntproxy_stop";
        if armed_stop_guard {
            arm_stop_guard(&self.config)?;
        }
        let result = call_daemon_tool(&self.config, name, args).await;
        if armed_stop_guard && result.is_err() {
            clear_stop_guard(&self.config);
        }
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
      "description":"Manage ordered project request match/replace rules for semantic Proxy, Browser, Reply, Fuzzer, and crawler traffic. Raw Reply is never modified.",
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
          "replace_all":{"type":"boolean","default":true}},"required":["name","target","operation"]},
        "url":{"type":"string"},"headers":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"}},"required":["name","value"]}},
        "body":{"type":"string"}},"required":["project_id","action"]}
    }"#).expect("request rules tool schema is valid JSON")
}

fn tool_defs() -> Value {
    json!([
        {"name":"projects","description":"List, create, or set optional capture scope. Host patterns may be exact or wildcard suffixes such as *.example.com; excluded_host_patterns always take precedence. Empty host_patterns captures every host except exclusions. Scope only controls persistence, never request destinations.","inputSchema":{"type":"object","properties":{"action":{"type":"string","enum":["list","create","set_scope"]},"project_id":{"type":"integer"},"name":{"type":"string"},"target_url":{"type":"string"},"scope":{"type":"object","properties":{"schemes":{"type":"array","items":{"type":"string"}},"host_patterns":{"type":"array","description":"Hosts to capture. Supports exact names and wildcard suffixes such as *.example.com. Empty captures all hosts except exclusions.","items":{"type":"string"}},"excluded_host_patterns":{"type":"array","description":"Hosts not to capture. Supports exact names and wildcard suffixes; exclusions override inclusions.","default":[],"items":{"type":"string"}},"ports":{"type":"array","items":{"type":"integer"}},"path_prefixes":{"type":"array","items":{"type":"string"}}}}},"required":["action"]}},
        {"name":"capture_sessions","description":"Manage capture sessions","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string"},"session_id":{"type":"integer"}},"required":["project_id","action"]}},
        {"name":"cookies","description":"Set, list, or clear project cookies without exposing their values. Set accepts a raw Cookie header or browser-export JSON cookie array, inline or from a UTF-8 file.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["set","list","clear"]},"target_url":{"type":"string"},"cookie":{"oneOf":[{"type":"string","description":"Raw Cookie header or a string containing a JSON cookie array."},{"type":"array","description":"Browser-export JSON cookies.","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"},"domain":{"type":"string"},"hostOnly":{"type":"boolean"},"secure":{"type":"boolean"},"session":{"type":"boolean"},"expirationDate":{"type":"number"}},"required":["name","value"]}}]},"file_path":{"type":"string","description":"Local UTF-8 file containing a raw Cookie header or JSON cookie array."}},"required":["project_id","action"]}},
        request_rules_tool_def(),
        {"name":"history_search","description":"Search saved project history without hiding hosts or MIME types. Active browser responses appear after capture completion. Supports AND/OR/NOT, parentheses, and quoted values. Examples: method:PUT; (request:~this OR request:~that OR request:~\":smtg\") method:PUT.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"q":{"type":"string","description":"field:value is exact; field:~value contains. request:~text searches the request target, headers, and body. Adjacent terms are AND; explicit AND/OR/NOT and parentheses are supported."},"limit":{"type":"integer","minimum":1,"maximum":500}},"required":["project_id"]}},
        {"name":"sitemap","description":"Return an alphanumerically sorted host/path tree derived from saved project history, including methods, statuses, query parameters, content types, and exchange counts. Omit host for every host or provide one exact host.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"host":{"type":"string","description":"Optional exact hostname, case-insensitive."}},"required":["project_id"]}},
        {"name":"findings","description":"List findings, mark an exchange as a finding, or remove a finding.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","add","remove"]},"exchange_id":{"type":"integer","description":"Required for add."},"finding_id":{"type":"integer","description":"Required for remove."},"title":{"type":"string","description":"Required for add."},"description":{"type":"string","description":"Required for add."}},"required":["project_id","action"]}},
        {"name":"exchange_get","description":"Get exchange detail (secrets redacted)","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"}},"required":["project_id","exchange_id"]}},
        {"name":"exchange_compare","description":"Compare the saved request and response of two exchanges. Sensitive values stay redacted, while changes are still detected. Text body diffs are bounded.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"left_exchange_id":{"type":"integer"},"right_exchange_id":{"type":"integer"},"include_noisy_headers":{"type":"boolean","default":false}},"required":["project_id","left_exchange_id","right_exchange_id"],"additionalProperties":false}},
        {"name":"page_analyzer","description":"Extract sorted, unique endpoints, absolute URLs, and emails from JavaScript or HTML without executing it. Provide exactly one saved exchange_id or absolute URL. URL mode sends a semantic GET with project cookies and analyzes the complete response; secrets are never scanned or returned.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer","description":"Saved exchange whose decoded response body should be analyzed."},"url":{"type":"string","description":"Absolute http/https URL to fetch and analyze."}},"required":["project_id"],"oneOf":[{"required":["exchange_id"]},{"required":["url"]}],"additionalProperties":false}},
        {"name":"copy_as","description":"Convert a saved request to cURL or Python requests. The output includes the original sensitive headers by default so it is immediately runnable; set include_secrets=false to produce a redacted copy.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"format":{"type":"string","enum":["curl","python_requests"]},"include_secrets":{"type":"boolean","default":true}},"required":["project_id","exchange_id","format"],"additionalProperties":false}},
        {"name":"exchange_body","description":"Read a request or response body in pages. gzip/br/deflate responses are decoded by default; set raw=true for captured bytes. Continue with next_offset while truncated is true.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"side":{"type":"string","enum":["request","response"]},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":"integer","minimum":1,"maximum":1048576},"raw":{"type":"boolean","default":false}},"required":["project_id","exchange_id"]}},
        {"name":"secret_reveal","description":"Reveal a sensitive header value (audited)","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"side":{"type":"string"},"header":{"type":"string"}},"required":["project_id","exchange_id","header"]}},
        {"name":"reply_tabs","description":"List or create Reply tabs. Draft fields are optional.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","create"]},"name":{"type":"string"},"base_exchange_id":{"type":"integer"},"draft":reply_draft_schema()},"required":["project_id","action"]}},
        {"name":"reply_send","description":"Send a semantic HTTP request and return status plus a decoded 4 KiB response preview. Supply draft.url and optionally method/headers/body; omitted draft fields use safe defaults or inherit from base_exchange_id.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"tab_id":{"type":"integer"},"base_exchange_id":{"type":"integer"},"draft":reply_draft_schema(),"protocol":{"type":"string","enum":["auto","h1","h2"]}},"required":["project_id"]}},
        {"name":"reply_send_raw","description":"Send exact raw HTTP/1.1 bytes, optionally split-writing at one byte offset, half-closing the write side, and collecting multiple responses until idle. Use base64 whenever byte offsets or non-UTF-8 bytes matter. This does not provide malformed HTTP/2 framing.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"target_url":{"type":"string"},"request":{"type":"string"},"encoding":{"type":"string","enum":["utf8","base64"]},"tab_id":{"type":"integer"},"use_project_cookies":{"type":"boolean"},"pause_at_byte":{"type":"integer","minimum":1,"description":"Split the exact decoded request at this byte offset."},"pause_ms":{"type":"integer","minimum":1,"maximum":120000},"half_close_write":{"type":"boolean","default":false},"response_mode":{"type":"string","enum":["auto","until_idle","until_close"],"default":"auto"},"read_timeout_ms":{"type":"integer","minimum":1,"maximum":120000,"default":60000},"idle_timeout_ms":{"type":"integer","minimum":1,"maximum":10000,"default":1000}},"required":["project_id","target_url","request"]}},
        {"name":"fuzz_start","description":"Start a bounded fuzz job. Put §name§ markers in draft.url, a header override, or body_override; use the same name in insertion_points. Payloads may be inline wordlists, local UTF-8 wordlist_files, inclusive number ranges, or native Recollapse-style regex bypass generators.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"template":fuzz_template_schema(),"confirm_large":{"type":"boolean","default":false}},"required":["project_id","template"]}},
        {"name":"fuzz_manage","description":"List, inspect, cancel, group, diff, or page through fuzz jobs and cases","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","get","cancel","cases","groups","group_cases","diff"]},"job_id":{"type":"integer"},"case_id":{"type":"integer"},"baseline_case_id":{"type":"integer"},"group_id":{"type":"string"},"include_text":{"type":"boolean","default":false},"limit":{"type":"integer","minimum":1,"maximum":500},"before_case_index":{"type":"integer","minimum":0}},"required":["project_id","action"]}},
        {"name":"websocket_manage","description":"List intercepted WebSocket connections and messages, or inject a text/binary message into an active connection.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","messages","send"]},"connection_id":{"type":"integer"},"after_id":{"type":"integer"},"limit":{"type":"integer","minimum":1,"maximum":1000},"direction":{"type":"string","enum":["to_server","to_client"]},"encoding":{"type":"string","enum":["text","base64"],"default":"text"},"payload":{"type":"string"}},"required":["project_id","action"],"additionalProperties":false}},
        {"name":"browser_start","description":"Start or resume the project's persistent Chromium workspace. Omit url to resume the last page.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"url":{"type":"string","default":"about:blank","description":"Optional page to open. Omit to resume the persistent workspace's last page."}},"required":["project_id"]}},
        {"name":"browser_action","description":"Navigate, inspect, or interact with an active browser session.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"session_id":{"type":"integer"},"action":browser_action_schema()},"required":["project_id","session_id","action"]}},
        {"name":"browser_manage","description":"Get status, suspend one browser, suspend all project browsers, or reset the persistent Chromium workspace. Status without session_id lists active browser sessions. Stop operations preserve browser state. reset_profile requires confirm=true and clears browser-derived state but not cookies configured with the cookies tool.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"session_id":{"type":"integer","description":"Required for stop; optional for status."},"op":{"type":"string","enum":["status","stop","stop_all","reset_profile"]},"confirm":{"type":"boolean","default":false,"description":"Must be true for reset_profile because browser state is permanently deleted."}},"required":["project_id","op"]}},
        {"name":"js_files","description":"Return JavaScript files with the page URLs and hosts that included or loaded them. Without url, search saved history and provenance; with url, load that page in Chromium. A domain filter matches either the JavaScript host or its related page host, including subdomains.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"url":{"type":"string","description":"When provided, perform a fresh browser load before collecting files."},"domain":{"type":"string","description":"Optional exact domain plus subdomains; accepts target.com, *.target.com, or a full URL."},"settle_ms":{"type":"integer","minimum":0,"maximum":30000,"default":2000},"limit":{"type":"integer","minimum":1,"maximum":10000,"default":2000}},"required":["project_id"]}},
        {"name":"get_words","description":"Build a sorted target-specific wordlist from saved request paths, parameter names, and textual responses. Related JavaScript files are included by default. Optionally filter by a domain and its subdomains.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"domain":{"type":"string","description":"Optional hostname, wildcard hostname, or HTTP URL."},"include_js":{"type":"boolean","default":true},"limit":{"type":"integer","minimum":1,"maximum":10000,"default":5000}},"required":["project_id"],"additionalProperties":false}},
        {"name":"huntproxy_stop","description":"Gracefully stop HuntProxy and all managed browsers. Use only when the user explicitly asks to stop HuntProxy.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"codec_transform","description":"Apply byte transforms, including gzip_decode/gunzip and brotli_decode","inputSchema":{"type":"object","properties":{"input":{"type":"string"},"input_encoding":{"type":"string","enum":["utf8","base64","hex"]},"pipeline":{"type":"array","items":{"type":"string"}}},"required":["input","pipeline"]}},
        {"name":"evidence_export","description":"Export exchange evidence metadata","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"}},"required":["project_id","exchange_id"]}},
        {"name":"project_transfer","description":"Import or export a project bundle or HAR through a local file. Sanitized export is the default; include_secrets must be explicitly true for credentials and browser state. Returns a summary/path, never archive bytes.","inputSchema":{"type":"object","properties":{"action":{"type":"string","enum":["export","import"]},"format":{"type":"string","enum":["huntproxy","har"]},"project_id":{"type":"integer","description":"Required for export and HAR import."},"file_path":{"type":"string","description":"Required for import; optional export destination under the configured exports directory."},"include_secrets":{"type":"boolean","default":false},"include_chromium_profile":{"type":"boolean","default":false}},"required":["action","format"],"additionalProperties":false}},
        {"name":"exchange_annotate","description":"Set an exchange title, note, and labels","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"display_title":{"type":["string","null"]},"note":{"type":["string","null"]},"labels":{"type":"array","items":{"type":"string"}},"expected_revision":{"type":"integer"}},"required":["project_id","exchange_id"]}}
    ])
}

pub async fn run_stdio_mcp(state: Arc<AppState>) -> DomainResult<()> {
    let idle_timeout = std::time::Duration::from_secs(state.config.idle_timeout_seconds);
    run_stdio_backend(Arc::new(LocalToolBackend { state }), idle_timeout).await
}

/// Run the stdio MCP adapter as a thin client of the single daemon owner.
pub async fn run_stdio_mcp_client(config: Config) -> DomainResult<()> {
    let idle_timeout = std::time::Duration::from_secs(config.idle_timeout_seconds);
    run_stdio_backend(Arc::new(DaemonToolBackend { config }), idle_timeout).await
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
        let stop_after_response = is_stop_request(&req);
        match handle_rpc(backend.clone(), &req).await {
            Ok(Some(value)) => {
                write_response(JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(value),
                    error: None,
                });
                if stop_after_response {
                    break;
                }
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

fn is_stop_request(request: &JsonRpcRequest) -> bool {
    request.method == "tools/call"
        && request.params.get("name").and_then(Value::as_str) == Some("huntproxy_stop")
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
        "tools/list" => Ok(Some(json!({ "tools": tool_defs() }))),
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
            let result = backend.call(name, args).await?;
            let structured_content = object_structured_content(&result);
            Ok(Some(json!({
                "content": [{ "type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_default() }],
                "structuredContent": structured_content,
                "isError": false
            })))
        }
        other => Err(DomainError::invalid(format!("unknown method {other}"))),
    }
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
                _ => Err(DomainError::invalid("action must be list|create|set_scope")),
            }
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
                    "profiles": state.db.list_cookie_profiles(project_id).await?
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
                    Ok(json!(
                        crate::cookies::set_project_cookie(&state, project_id, target_url, cookie,)
                            .await?
                    ))
                }
                "clear" => {
                    let target_url = args
                        .get("target_url")
                        .and_then(Value::as_str)
                        .ok_or_else(|| DomainError::invalid("target_url required"))?;
                    Ok(json!({
                        "cleared": crate::cookies::clear_project_cookie(
                            &state,
                            project_id,
                            target_url,
                        )
                        .await?
                    }))
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
            let filter = args
                .get("q")
                .and_then(|value| value.as_str())
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
            let host = args.get("host").and_then(Value::as_str).map(str::to_string);
            Ok(json!({
                "hosts": state.db.list_sitemap(project_id, host).await?
            }))
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
            let mut value = serde_json::to_value(detail)
                .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?;
            if let Some(object) = value.as_object_mut() {
                object.insert("annotation".into(), json!(annotation));
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
                (Some(exchange_id), None) => Ok(json!(
                    crate::page_analyzer::analyze_exchange(&state.db, project_id, exchange_id,)
                        .await?
                )),
                (None, Some(url)) => {
                    let parsed = url::Url::parse(url).map_err(|error| {
                        DomainError::invalid(format!("invalid analysis URL: {error}"))
                    })?;
                    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                        return Err(DomainError::invalid(
                            "analysis URL must be an absolute http or https URL",
                        ));
                    }
                    let draft = ReplyDraft {
                        method: Some("GET".into()),
                        url: Some(parsed.to_string()),
                        ..Default::default()
                    };
                    let result = state
                        .reply
                        .send(project_id, None, None, &draft, ProtocolPreference::Auto, 0)
                        .await?;
                    if let Some(exchange_id) = result.exchange_id {
                        emit_event(
                            &state,
                            project_id,
                            "exchange",
                            json!({ "exchange_id": exchange_id.get(), "source": "reply" }),
                        );
                        return Ok(json!(
                            crate::page_analyzer::analyze_exchange(
                                &state.db,
                                project_id,
                                exchange_id,
                            )
                            .await?
                        ));
                    }

                    let response = result.response.ok_or_else(|| {
                        DomainError::new(
                            ErrorCode::Internal,
                            "URL analysis response body was unavailable",
                        )
                    })?;
                    let mut body = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        response.body_base64.as_bytes(),
                    )
                    .map_err(|error| {
                        DomainError::new(
                            ErrorCode::Internal,
                            format!("invalid internal response body: {error}"),
                        )
                    })?;
                    let encodings = response
                        .headers
                        .iter()
                        .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
                        .map(|header| header.value.trim().to_string())
                        .filter(|encoding| {
                            !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity")
                        })
                        .collect::<Vec<_>>();
                    let content_encoding = (!encodings.is_empty()).then(|| encodings.join(", "));
                    if let Some(encoding) = &content_encoding {
                        body = crate::codec::decode_content_encodings(
                            &body,
                            encoding,
                            crate::codec::MAX_DECODED_BODY_OUTPUT,
                        )?;
                    }
                    let analysis = crate::page_analyzer::analyze_page(&body);
                    Ok(json!({
                        "project_id": project_id,
                        "exchange_id": null,
                        "source_url": parsed.to_string(),
                        "decoded": content_encoding.is_some(),
                        "content_encoding": content_encoding,
                        "body_truncated": response.body_truncated,
                        "endpoints": analysis.endpoints,
                        "urls": analysis.urls,
                        "emails": analysis.emails,
                        "stats": analysis.stats,
                    }))
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
            let side = match args
                .get("side")
                .and_then(|v| v.as_str())
                .unwrap_or("response")
            {
                "request" => MessageSide::Request,
                _ => MessageSide::Response,
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
            let mut body = state
                .db
                .load_raw_body(project_id, ExchangeId(eid), side)
                .await?
                .unwrap_or_default();
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
            Ok(json!({
                "total": body.len(),
                "offset": offset,
                "length": slice.len(),
                "preview": String::from_utf8_lossy(slice),
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
                .send(
                    project_id,
                    args.get("tab_id").and_then(|v| v.as_i64()).map(ReplyTabId),
                    args.get("base_exchange_id")
                        .and_then(|v| v.as_i64())
                        .map(ExchangeId),
                    &draft,
                    protocol,
                    0,
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
        "browser_start" => {
            let project_id = require_project_id(&args)?;
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
            Ok(json!(state.browser.start(project_id, url).await?))
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
                let removed = state.browser.reset_project_profile(project_id).await?;
                return Ok(json!({
                    "ok": true,
                    "removed": removed,
                    "managed_cookies_preserved": true,
                }));
            }
            if op == "status" && args.get("session_id").and_then(Value::as_i64).is_none() {
                return Ok(json!({
                    "sessions": state.browser.active_sessions(project_id).await?
                }));
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
                        .db
                        .get_browser_session(project_id, BrowserSessionId(sid))
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
    fn successful_stop_calls_close_the_stdio_bridge_after_reply() {
        let request = JsonRpcRequest {
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({"name": "huntproxy_stop", "arguments": {}}),
        };
        assert!(is_stop_request(&request));
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
        let reply = tools
            .iter()
            .find(|tool| tool["name"] == "reply_send")
            .unwrap();
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
        let browser_manage = tools
            .iter()
            .find(|tool| tool["name"] == "browser_manage")
            .unwrap();
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
        assert!(tools.iter().any(|tool| tool["name"] == "sitemap"));
        assert!(tools.iter().any(|tool| tool["name"] == "findings"));
    }
}
