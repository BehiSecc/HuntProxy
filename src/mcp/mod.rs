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
use std::io::{BufRead, BufReader, Write};
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
        call_daemon_tool(&self.config, name, args).await
    }
}

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "HuntProxy";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

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
        "description": "All fields are optional. Omitted fields inherit from base_exchange_id when supplied.",
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
            "body_override": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 255}}
                ]
            },
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

fn tool_defs() -> Value {
    json!([
        {"name":"projects","description":"List, create, or set optional capture scope","inputSchema":{"type":"object","properties":{"action":{"type":"string","enum":["list","create","set_scope"]},"project_id":{"type":"integer"},"name":{"type":"string"},"target_url":{"type":"string"},"scope":{"type":"object","properties":{"schemes":{"type":"array","items":{"type":"string"}},"host_patterns":{"type":"array","items":{"type":"string"}},"ports":{"type":"array","items":{"type":"integer"}},"path_prefixes":{"type":"array","items":{"type":"string"}}}}},"required":["action"]}},
        {"name":"capture_sessions","description":"Manage capture sessions","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string"},"session_id":{"type":"integer"}},"required":["project_id","action"]}},
        {"name":"cookies","description":"Set, list, or clear project cookies without exposing their values","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["set","list","clear"]},"target_url":{"type":"string"},"cookie":{"type":"string"},"file_path":{"type":"string"}},"required":["project_id","action"]}},
        {"name":"history_search","description":"Search history. q accepts bare text or filters such as host:example.com path:~.js method:GET status>=400; separate terms with spaces.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"q":{"type":"string","description":"Bare text searches common fields. field:value is exact, field:~value contains, field:*suffix ends with, and comparisons use >= <= > < !=."},"limit":{"type":"integer","minimum":1,"maximum":500}},"required":["project_id"]}},
        {"name":"exchange_get","description":"Get exchange detail (secrets redacted)","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"}},"required":["project_id","exchange_id"]}},
        {"name":"exchange_body","description":"Read a request or response body in pages. Continue with next_offset while truncated is true.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"side":{"type":"string","enum":["request","response"]},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":"integer","minimum":1,"maximum":1048576}},"required":["project_id","exchange_id"]}},
        {"name":"secret_reveal","description":"Reveal a sensitive header value (audited)","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"side":{"type":"string"},"header":{"type":"string"}},"required":["project_id","exchange_id","header"]}},
        {"name":"reply_tabs","description":"List or create Reply tabs. Draft fields are optional.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string","enum":["list","create"]},"name":{"type":"string"},"base_exchange_id":{"type":"integer"},"draft":reply_draft_schema()},"required":["project_id","action"]}},
        {"name":"reply_send","description":"Send a semantic HTTP request. Supply draft.url and optionally method/headers/body; omitted draft fields use safe defaults or inherit from base_exchange_id.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"tab_id":{"type":"integer"},"base_exchange_id":{"type":"integer"},"draft":reply_draft_schema(),"protocol":{"type":"string","enum":["auto","h1","h2"]}},"required":["project_id"]}},
        {"name":"reply_send_raw","description":"Send exact raw HTTP/1.1 bytes for CRLF and protocol testing","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"target_url":{"type":"string"},"request":{"type":"string"},"encoding":{"type":"string","enum":["utf8","base64"]},"tab_id":{"type":"integer"},"use_project_cookies":{"type":"boolean"}},"required":["project_id","target_url","request"]}},
        {"name":"fuzz_start","description":"Start a fuzz job","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"template":{"type":"object"},"confirm_large":{"type":"boolean"}},"required":["project_id","template"]}},
        {"name":"fuzz_manage","description":"List, inspect, or cancel fuzz jobs and cases","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string"},"job_id":{"type":"integer"},"limit":{"type":"integer"},"before_case_index":{"type":"integer"}},"required":["project_id","action"]}},
        {"name":"browser_start","description":"Start a browser session. Auto prefers Lightpanda and falls back to Chromium when startup/navigation fails.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"url":{"type":"string","default":"about:blank"},"engine_policy":{"type":"string","enum":["auto","chromium"],"default":"auto"}},"required":["project_id"]}},
        {"name":"browser_action","description":"Navigate, inspect, or interact with an active browser session.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"session_id":{"type":"integer"},"action":browser_action_schema()},"required":["project_id","session_id","action"]}},
        {"name":"browser_manage","description":"Get status, stop a browser session, or migrate Lightpanda state to Chromium.","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"session_id":{"type":"integer"},"op":{"type":"string","enum":["status","stop","switch_chromium"]}},"required":["project_id","session_id","op"]}},
        {"name":"codec_transform","description":"Apply codec transforms","inputSchema":{"type":"object","properties":{"input":{"type":"string"},"input_encoding":{"type":"string"},"pipeline":{"type":"array","items":{"type":"string"}}},"required":["input","pipeline"]}},
        {"name":"evidence_export","description":"Export exchange evidence metadata","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"}},"required":["project_id","exchange_id"]}},
        {"name":"exchange_annotate","description":"Set an exchange title, note, and labels","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"display_title":{"type":["string","null"]},"note":{"type":["string","null"]},"labels":{"type":"array","items":{"type":"string"}},"expected_revision":{"type":"integer"}},"required":["project_id","exchange_id"]}}
    ])
}

pub async fn run_stdio_mcp(state: Arc<AppState>) -> DomainResult<()> {
    run_stdio_backend(Arc::new(LocalToolBackend { state })).await
}

/// Run the stdio MCP adapter as a thin client of the single daemon owner.
pub async fn run_stdio_mcp_client(config: Config) -> DomainResult<()> {
    run_stdio_backend(Arc::new(DaemonToolBackend { config })).await
}

pub async fn run_stdio(state: Arc<AppState>) -> DomainResult<()> {
    run_stdio_mcp(state).await
}

async fn run_stdio_backend(backend: Arc<dyn ToolBackend>) -> DomainResult<()> {
    eprintln!("HuntProxy mcp: starting stdio JSON-RPC server");
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| DomainError::new(ErrorCode::ProtocolError, format!("stdin: {e}")))?;
        if n == 0 {
            break;
        }
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
            Ok(Some(value)) => write_response(JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(value),
                error: None,
            }),
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
            Ok(Some(json!({
                "content": [{ "type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_default() }],
                "structuredContent": result,
                "isError": false
            })))
        }
        other => Err(DomainError::invalid(format!("unknown method {other}"))),
    }
}

fn require_project_id(args: &Value) -> DomainResult<ProjectId> {
    let id = args
        .get("project_id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| DomainError::invalid("project_id required"))?;
    Ok(ProjectId(id))
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
                    let inline = args.get("cookie").and_then(Value::as_str);
                    let file_path = args.get("file_path").and_then(Value::as_str);
                    let cookie = match (inline, file_path) {
                        (Some(value), None) => value.to_string(),
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
            Ok(json!({ "items": items, "next": next }))
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
            if side == MessageSide::Request {
                let detail = state
                    .db
                    .get_exchange_detail(
                        project_id,
                        ExchangeId(eid),
                        PresentationOptions::default(),
                    )
                    .await?;
                if detail.protocol == "HTTP/1.1 raw" {
                    body = crate::reply::redact_raw_request_headers(&body);
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
                "next_offset": (end < body.len()).then_some(end)
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
                _ => Err(DomainError::invalid("action must be list|cancel|get|cases")),
            }
        }
        "browser_start" => {
            let project_id = require_project_id(&args)?;
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("about:blank")
                .to_string();
            let policy = match args.get("engine_policy").and_then(Value::as_str) {
                Some("chromium") => EnginePolicy::Chromium,
                Some("auto") | None => EnginePolicy::Auto,
                Some(_) => return Err(DomainError::invalid("engine_policy must be auto|chromium")),
            };
            Ok(json!(state.browser.start(project_id, url, policy).await?))
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
            let sid = args
                .get("session_id")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| DomainError::invalid("session_id required"))?;
            let op = args.get("op").and_then(|v| v.as_str()).unwrap_or("stop");
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
                "switch_chromium" => Ok(json!(
                    state
                        .browser
                        .switch_to_chromium(project_id, BrowserSessionId(sid))
                        .await?
                )),
                _ => Err(DomainError::invalid(
                    "op must be stop|status|switch_chromium",
                )),
            }
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
            "url": "https://example.com"
        }))
        .unwrap();
        assert!(draft.header_overrides.is_empty());
        assert!(draft.header_tombstones.is_empty());
        assert!(!draft.body_cleared);
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
    }
}
