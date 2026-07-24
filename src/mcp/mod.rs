//! Minimal stdio JSON-RPC MCP server. Protocol on stdout; diagnostics on stderr.

use crate::app::AppState;
use crate::browser::BrowserAction;
use crate::codec::{apply_pipeline, Transform};
use crate::domain::*;
use crate::fuzzer::FuzzTemplate;
use crate::history::parse_text_query;
use crate::policy::{is_sensitive_header, PresentationOptions};
use crate::storage::CreateCaptureSession;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "bb";
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

fn tool_defs() -> Value {
    json!([
        {"name":"projects","description":"List or create projects","inputSchema":{"type":"object","properties":{"action":{"type":"string"},"name":{"type":"string"},"target_url":{"type":"string"}},"required":["action"]}},
        {"name":"capture_sessions","description":"Manage capture sessions","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string"},"session_id":{"type":"integer"}},"required":["project_id","action"]}},
        {"name":"history_search","description":"Search exchange history","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"q":{"type":"string"},"limit":{"type":"integer"}},"required":["project_id"]}},
        {"name":"exchange_get","description":"Get exchange detail (secrets redacted)","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"}},"required":["project_id","exchange_id"]}},
        {"name":"exchange_body","description":"Get exchange body preview","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"side":{"type":"string"},"max_bytes":{"type":"integer"}},"required":["project_id","exchange_id"]}},
        {"name":"secret_reveal","description":"Reveal a sensitive header value (audited)","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"side":{"type":"string"},"header":{"type":"string"}},"required":["project_id","exchange_id","header"]}},
        {"name":"reply_tabs","description":"List/create reply tabs","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string"},"name":{"type":"string"},"base_exchange_id":{"type":"integer"},"draft":{"type":"object"}},"required":["project_id","action"]}},
        {"name":"reply_send","description":"Send a reply draft","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"tab_id":{"type":"integer"},"base_exchange_id":{"type":"integer"},"draft":{"type":"object"}},"required":["project_id"]}},
        {"name":"fuzz_start","description":"Start a fuzz job","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"template":{"type":"object"},"confirm_large":{"type":"boolean"}},"required":["project_id","template"]}},
        {"name":"fuzz_manage","description":"List/cancel fuzz jobs","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"action":{"type":"string"},"job_id":{"type":"integer"}},"required":["project_id","action"]}},
        {"name":"browser_start","description":"Start browser session","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"url":{"type":"string"}},"required":["project_id"]}},
        {"name":"browser_action","description":"Run browser action","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"session_id":{"type":"integer"},"action":{"type":"object"}},"required":["project_id","session_id","action"]}},
        {"name":"browser_manage","description":"Stop browser session","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"session_id":{"type":"integer"},"op":{"type":"string"}},"required":["project_id","session_id","op"]}},
        {"name":"codec_transform","description":"Apply codec transforms","inputSchema":{"type":"object","properties":{"input":{"type":"string"},"input_encoding":{"type":"string"},"pipeline":{"type":"array","items":{"type":"string"}}},"required":["input","pipeline"]}},
        {"name":"evidence_export","description":"Export exchange evidence metadata","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"}},"required":["project_id","exchange_id"]}},
        {"name":"exchange_annotate","description":"Set display title","inputSchema":{"type":"object","properties":{"project_id":{"type":"integer"},"exchange_id":{"type":"integer"},"display_title":{"type":"string"}},"required":["project_id","exchange_id"]}}
    ])
}

pub async fn run_stdio_mcp(state: Arc<AppState>) -> DomainResult<()> {
    run_stdio(state).await
}

pub async fn run_stdio(state: Arc<AppState>) -> DomainResult<()> {
    eprintln!("bb mcp: starting stdio JSON-RPC server");
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
        match handle_rpc(state.clone(), &req).await {
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
                    code: -32000,
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

async fn handle_rpc(state: Arc<AppState>, req: &JsonRpcRequest) -> DomainResult<Option<Value>> {
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
            let result = call_tool(state, name, args).await?;
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

async fn call_tool(state: Arc<AppState>, name: &str, args: Value) -> DomainResult<Value> {
    match name {
        "projects" => {
            let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("list");
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
                    Ok(json!(
                        state
                            .db
                            .create_project(CreateProjectRequest {
                                name: pname.into(),
                                target_url: target_url.into(),
                                advanced: None,
                            })
                            .await?
                    ))
                }
                _ => Err(DomainError::invalid("action must be list|create")),
            }
        }
        "capture_sessions" => {
            let project_id = require_project_id(&args)?;
            let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("list");
            match action {
                "list" => Ok(json!(state.db.list_capture_sessions(project_id).await?)),
                "create" => Ok(json!(
                    state
                        .db
                        .create_capture_session(CreateCaptureSession {
                            project_id,
                            browser_session_id: None,
                            browser_action_id: None,
                            is_browser_bound: false,
                            ttl: None,
                        })
                        .await?
                )),
                "revoke" => {
                    let sid = args
                        .get("session_id")
                        .and_then(|v| v.as_i64())
                        .ok_or_else(|| DomainError::invalid("session_id required"))?;
                    state
                        .db
                        .revoke_capture_session(project_id, CaptureSessionId(sid))
                        .await?;
                    Ok(json!({ "ok": true }))
                }
                "renew" => {
                    let sid = args
                        .get("session_id")
                        .and_then(|v| v.as_i64())
                        .ok_or_else(|| DomainError::invalid("session_id required"))?;
                    Ok(json!(
                        state
                            .db
                            .renew_capture_session(project_id, CaptureSessionId(sid))
                            .await?
                    ))
                }
                _ => Err(DomainError::invalid("action must be list|create|revoke|renew")),
            }
        }
        "history_search" => {
            let project_id = require_project_id(&args)?;
            if let Some(q) = args.get("q").and_then(|v| v.as_str()) {
                let _ = parse_text_query(q)?;
            }
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as u32;
            let (items, next) = state.db.list_history(project_id, limit, None, None).await?;
            Ok(json!({ "items": items, "next": next }))
        }
        "exchange_get" => {
            let project_id = require_project_id(&args)?;
            let eid = args
                .get("exchange_id")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| DomainError::invalid("exchange_id required"))?;
            Ok(json!(
                state
                    .db
                    .get_exchange_detail(
                        project_id,
                        ExchangeId(eid),
                        PresentationOptions::default(),
                    )
                    .await?
            ))
        }
        "exchange_body" => {
            let project_id = require_project_id(&args)?;
            let eid = args
                .get("exchange_id")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| DomainError::invalid("exchange_id required"))?;
            let side = match args.get("side").and_then(|v| v.as_str()).unwrap_or("response") {
                "request" => MessageSide::Request,
                _ => MessageSide::Response,
            };
            let max = args.get("max_bytes").and_then(|v| v.as_u64()).unwrap_or(4096) as usize;
            let body = state
                .db
                .load_raw_body(project_id, ExchangeId(eid), side)
                .await?
                .unwrap_or_default();
            let slice = &body[..body.len().min(max)];
            Ok(json!({
                "total": body.len(),
                "preview": String::from_utf8_lossy(slice),
                "truncated": body.len() > max
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
            let side = match args.get("side").and_then(|v| v.as_str()).unwrap_or("request") {
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
            let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("list");
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
            let (eid, diff) = state
                .reply
                .send(
                    project_id,
                    args.get("tab_id").and_then(|v| v.as_i64()).map(ReplyTabId),
                    args.get("base_exchange_id")
                        .and_then(|v| v.as_i64())
                        .map(ExchangeId),
                    &draft,
                    ProtocolPreference::Auto,
                    0,
                )
                .await?;
            Ok(json!({ "exchange_id": eid.get(), "diff": diff }))
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
            Ok(json!(
                state.fuzzer.start(project_id, template, confirm).await?
            ))
        }
        "fuzz_manage" => {
            let project_id = require_project_id(&args)?;
            let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("list");
            match action {
                "list" => Ok(json!(state.fuzzer.list(project_id).await?)),
                "cancel" => {
                    let jid = args
                        .get("job_id")
                        .and_then(|v| v.as_i64())
                        .ok_or_else(|| DomainError::invalid("job_id required"))?;
                    state.fuzzer.cancel(FuzzJobId(jid)).await?;
                    Ok(json!({ "ok": true }))
                }
                "get" => {
                    let jid = args
                        .get("job_id")
                        .and_then(|v| v.as_i64())
                        .ok_or_else(|| DomainError::invalid("job_id required"))?;
                    Ok(json!(state.fuzzer.get(project_id, FuzzJobId(jid)).await?))
                }
                _ => Err(DomainError::invalid("action must be list|cancel|get")),
            }
        }
        "browser_start" => {
            let project_id = require_project_id(&args)?;
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("about:blank")
                .to_string();
            Ok(json!(
                state
                    .browser
                    .start(project_id, url, EnginePolicy::Auto)
                    .await?
            ))
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
            let op = args
                .get("op")
                .and_then(|v| v.as_str())
                .unwrap_or("stop");
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
                _ => Err(DomainError::invalid("op must be stop|status|switch_chromium")),
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
                "base64" => base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    input,
                )
                .map_err(|e| DomainError::invalid(e.to_string()))?,
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
                .get_exchange_detail(
                    project_id,
                    ExchangeId(eid),
                    PresentationOptions::default(),
                )
                .await?;
            let path = state.config.export_dir.join(format!(
                "exchange_{}_{}.json",
                project_id.get(),
                eid
            ));
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
            let _ = state
                .db
                .get_exchange_detail(
                    project_id,
                    ExchangeId(eid),
                    PresentationOptions::default(),
                )
                .await?;
            if let Some(t) = args.get("display_title").and_then(|v| v.as_str()) {
                let t = t.to_string();
                state
                    .db
                    .with_conn(move |conn| {
                        conn.execute(
                            "UPDATE exchanges SET display_title=?1 WHERE project_id=?2 AND exchange_id=?3",
                            rusqlite::params![t, project_id.get(), eid],
                        )
                        .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                        Ok(())
                    })
                    .await?;
            }
            Ok(json!({
                "ok": true,
                "project_id": project_id.get(),
                "exchange_id": eid,
            }))
        }
        other => Err(DomainError::invalid(format!("unknown tool {other}"))),
    }
}

