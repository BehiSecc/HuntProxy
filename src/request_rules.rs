//! Project-scoped semantic request match/replace rules.

use crate::domain::*;
use crate::storage::{now_rfc3339, Db};
use dashmap::DashMap;
use regex::Regex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};
use url::Url;

const MAX_RULES: usize = 100;
const MAX_PATTERN_BYTES: usize = 4096;
const MAX_REPLACEMENT_BYTES: usize = 64 * 1024;
const DEFAULT_BLOCK_STATUS: u16 = 403;
const DEFAULT_BLOCK_CONTENT_TYPE: &str = "text/plain; charset=utf-8";
pub const MAX_REWRITE_BODY_BYTES: usize = 2 * 1024 * 1024;

static CACHE: LazyLock<DashMap<String, Arc<Vec<CompiledRule>>>> = LazyLock::new(DashMap::new);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestRuleTarget {
    Url,
    Header,
    Body,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestRuleOperation {
    Replace,
    Set,
    Remove,
    /// Answers a matching proxied request with a synthetic response instead of sending it upstream.
    Block,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestRuleMatchKind {
    Literal,
    Regex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestRule {
    pub id: i64,
    pub project_id: ProjectId,
    pub name: String,
    pub enabled: bool,
    pub position: i64,
    pub host_pattern: Option<String>,
    pub target: RequestRuleTarget,
    pub operation: RequestRuleOperation,
    pub header_name: Option<String>,
    pub match_kind: RequestRuleMatchKind,
    pub pattern: String,
    pub replacement: Option<String>,
    pub replace_all: bool,
    /// Block rules only: limits the rule to one HTTP method; `None` matches any method.
    #[serde(default)]
    pub method: Option<String>,
    /// Block rules only: synthetic response status (default 403).
    #[serde(default)]
    pub response_status: Option<u16>,
    #[serde(default)]
    pub response_content_type: Option<String>,
    #[serde(default)]
    pub response_body: Option<String>,
    pub revision: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestRuleInput {
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub position: i64,
    pub host_pattern: Option<String>,
    pub target: RequestRuleTarget,
    pub operation: RequestRuleOperation,
    pub header_name: Option<String>,
    #[serde(default = "literal")]
    pub match_kind: RequestRuleMatchKind,
    #[serde(default)]
    pub pattern: String,
    pub replacement: Option<String>,
    #[serde(default = "yes")]
    pub replace_all: bool,
    /// Block rules only: limits the rule to one HTTP method; `None` matches any method.
    #[serde(default)]
    pub method: Option<String>,
    /// Block rules only: synthetic response status (default 403).
    #[serde(default)]
    pub response_status: Option<u16>,
    #[serde(default)]
    pub response_content_type: Option<String>,
    #[serde(default)]
    pub response_body: Option<String>,
}

fn yes() -> bool {
    true
}
fn literal() -> RequestRuleMatchKind {
    RequestRuleMatchKind::Literal
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppliedRequestRule {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestRulePreview {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub applied_rules: Vec<AppliedRequestRule>,
    /// Whether a block rule would answer this request in the proxy.
    pub blocked: bool,
    pub block: Option<RequestRuleBlock>,
}

/// The synthetic response a matching block rule sends instead of contacting the origin.
/// `content_type` and `body` are the effective values: none on 204 and 304.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RequestRuleBlock {
    pub rule: AppliedRequestRule,
    pub status: u16,
    pub content_type: Option<String>,
    pub body: String,
}

impl RequestRuleBlock {
    /// Headers and body for the client. A HEAD response keeps the headers but has no body.
    pub fn response_parts(&self, head: bool) -> (Vec<(&'static str, String)>, Vec<u8>) {
        let mut headers = vec![("cache-control", "no-store".to_string())];
        if let Some(content_type) = &self.content_type {
            headers.push(("content-type", content_type.clone()));
        }
        let body = if head {
            Vec::new()
        } else {
            self.body.clone().into_bytes()
        };
        (headers, body)
    }
}

/// Result of URL rules for proxied traffic: the rewrites that ran and, if one matched, the block.
#[derive(Debug, Default)]
pub struct UrlRuleOutcome {
    pub applied: Vec<AppliedRequestRule>,
    pub block: Option<RequestRuleBlock>,
}

#[derive(Clone)]
struct CompiledRule {
    rule: RequestRule,
    regex: Option<Regex>,
}

impl Db {
    pub async fn list_request_rules(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Vec<RequestRule>> {
        self.get_project(project_id).await?;
        self.with_conn(move |conn| {
            let mut stmt = conn.prepare("SELECT id,project_id,name,enabled,position,host_pattern,target,operation,header_name,match_kind,pattern,replacement,replace_all,revision,method,response_status,response_content_type,response_body FROM request_rules WHERE project_id=?1 ORDER BY position,id").map_err(storage)?;
            let rows = stmt
                .query_map(params![project_id.get()], map_rule)
                .map_err(storage)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage)
        }).await
    }

    pub async fn create_request_rule(
        &self,
        project_id: ProjectId,
        input: RequestRuleInput,
    ) -> DomainResult<RequestRule> {
        validate_input(&input)?;
        let input = normalized(input);
        self.get_project(project_id).await?;
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM request_rules WHERE project_id=?1", params![project_id.get()], |r| r.get(0)).map_err(storage)?;
            if count >= MAX_RULES as i64 { return Err(DomainError::invalid("a project may have at most 100 request rules")); }
            conn.execute("INSERT INTO request_rules(project_id,name,enabled,position,host_pattern,target,operation,header_name,match_kind,pattern,replacement,replace_all,revision,created_at,updated_at,method,response_status,response_content_type,response_body) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,1,?13,?13,?14,?15,?16,?17)", params![project_id.get(), input.name.trim(), input.enabled, input.position, normalize_host(input.host_pattern), target_str(input.target), operation_str(input.operation), input.header_name, match_str(input.match_kind), input.pattern, input.replacement, input.replace_all, ts, input.method, input.response_status, input.response_content_type, input.response_body]).map_err(storage)?;
            load_rule(conn, project_id, conn.last_insert_rowid())
        }).await.inspect(|_| invalidate_cache(self, project_id))
    }

    pub async fn update_request_rule(
        &self,
        project_id: ProjectId,
        id: i64,
        input: RequestRuleInput,
    ) -> DomainResult<RequestRule> {
        validate_input(&input)?;
        let input = normalized(input);
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let changed=conn.execute("UPDATE request_rules SET name=?1,enabled=?2,position=?3,host_pattern=?4,target=?5,operation=?6,header_name=?7,match_kind=?8,pattern=?9,replacement=?10,replace_all=?11,revision=revision+1,updated_at=?12,method=?15,response_status=?16,response_content_type=?17,response_body=?18 WHERE id=?13 AND project_id=?14", params![input.name.trim(),input.enabled,input.position,normalize_host(input.host_pattern),target_str(input.target),operation_str(input.operation),input.header_name,match_str(input.match_kind),input.pattern,input.replacement,input.replace_all,ts,id,project_id.get(),input.method,input.response_status,input.response_content_type,input.response_body]).map_err(storage)?;
            if changed==0 { return Err(DomainError::not_found("request rule")); }
            load_rule(conn,project_id,id)
        }).await.inspect(|_| invalidate_cache(self, project_id))
    }

    pub async fn delete_request_rule(&self, project_id: ProjectId, id: i64) -> DomainResult<()> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM request_rules WHERE id=?1 AND project_id=?2",
                    params![id, project_id.get()],
                )
                .map_err(storage)?;
            if changed == 0 {
                return Err(DomainError::not_found("request rule"));
            }
            Ok(())
        })
        .await?;
        invalidate_cache(self, project_id);
        Ok(())
    }

    pub async fn record_exchange_request_rules(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        rules: Vec<AppliedRequestRule>,
    ) -> DomainResult<()> {
        if rules.is_empty() {
            return Ok(());
        }
        self.with_conn(move |conn| { let tx=crate::storage::write_transaction(conn).map_err(storage)?; for rule in rules { tx.execute("INSERT OR IGNORE INTO exchange_request_rules(project_id,exchange_id,rule_id,rule_name) VALUES(?1,?2,?3,?4)",params![project_id.get(),exchange_id.get(),rule.id,rule.name]).map_err(storage)?; } tx.commit().map_err(storage) }).await
    }

    pub async fn list_exchange_request_rules(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
    ) -> DomainResult<Vec<AppliedRequestRule>> {
        self.with_conn(move |conn| {
            let mut statement = conn
                .prepare("SELECT rule_id,rule_name FROM exchange_request_rules WHERE project_id=?1 AND exchange_id=?2 ORDER BY rule_id")
                .map_err(storage)?;
            let rows = statement
                .query_map(params![project_id.get(), exchange_id.get()], |row| {
                    Ok(AppliedRequestRule { id: row.get(0)?, name: row.get(1)? })
                })
                .map_err(storage)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage)
        })
        .await
    }
}

/// URL rewrites for requests HuntProxy sends on the user's behalf (Repeater, Fuzzer,
/// plugins). Block rules never apply here, so an explicitly tested request reaches the origin.
pub async fn apply_url_rules(
    db: &Db,
    project_id: ProjectId,
    url: &mut String,
) -> DomainResult<Vec<AppliedRequestRule>> {
    let rules = compiled_rules(db, project_id).await?;
    let mut applied = Vec::new();
    for rule in rules.iter().filter(|r| {
        r.rule.enabled
            && r.rule.target == RequestRuleTarget::Url
            && r.rule.operation != RequestRuleOperation::Block
    }) {
        if host_matches(&rule.rule.host_pattern, url) {
            rewrite_url(rule, url, &mut applied)?;
        }
    }
    Ok(applied)
}

/// URL rules for proxied traffic, in position order. Rewrites run as usual; the first block
/// rule matching the current URL and `method` ends evaluation. `exempt` lets the caller keep
/// a URL (such as HuntProxy's own API) from ever being blocked.
pub async fn apply_url_rules_with_blocks(
    db: &Db,
    project_id: ProjectId,
    url: &mut String,
    method: &str,
    exempt: &(dyn Fn(&str) -> bool + Send + Sync),
) -> DomainResult<UrlRuleOutcome> {
    let rules = compiled_rules(db, project_id).await?;
    let mut outcome = UrlRuleOutcome::default();
    for rule in rules
        .iter()
        .filter(|r| r.rule.enabled && r.rule.target == RequestRuleTarget::Url)
    {
        if !host_matches(&rule.rule.host_pattern, url) {
            continue;
        }
        if rule.rule.operation != RequestRuleOperation::Block {
            rewrite_url(rule, url, &mut outcome.applied)?;
        } else if block_matches(rule, url, method) && !exempt(url) {
            outcome.applied.push(applied_rule(rule));
            outcome.block = Some(block_response(rule));
            return Ok(outcome);
        }
    }
    Ok(outcome)
}

fn rewrite_url(
    rule: &CompiledRule,
    url: &mut String,
    applied: &mut Vec<AppliedRequestRule>,
) -> DomainResult<()> {
    let before = url.clone();
    *url = replace_text(rule, &before)?;
    if *url != before {
        validate_url(url)?;
        applied.push(applied_rule(rule));
    }
    Ok(())
}

fn block_matches(rule: &CompiledRule, url: &str, method: &str) -> bool {
    rule.rule
        .method
        .as_deref()
        .is_none_or(|expected| expected.eq_ignore_ascii_case(method))
        && matches_bytes(rule, url.as_bytes())
}

fn block_response(rule: &CompiledRule) -> RequestRuleBlock {
    let status = rule.rule.response_status.unwrap_or(DEFAULT_BLOCK_STATUS);
    let bodiless = matches!(status, 204 | 304);
    let body = if bodiless {
        String::new()
    } else {
        rule.rule.response_body.clone().unwrap_or_default()
    };
    let content_type = if bodiless {
        None
    } else {
        rule.rule
            .response_content_type
            .clone()
            .or_else(|| (!body.is_empty()).then(|| DEFAULT_BLOCK_CONTENT_TYPE.to_string()))
    };
    RequestRuleBlock {
        rule: applied_rule(rule),
        status,
        content_type,
        body,
    }
}

pub async fn apply_message_rules(
    db: &Db,
    project_id: ProjectId,
    url: &str,
    headers: &mut Vec<(String, Vec<u8>)>,
    mut body: Option<&mut Vec<u8>>,
) -> DomainResult<Vec<AppliedRequestRule>> {
    let rules = compiled_rules(db, project_id).await?;
    let mut applied = Vec::new();
    for rule in rules
        .iter()
        .filter(|r| r.rule.enabled && r.rule.target != RequestRuleTarget::Url)
    {
        if !host_matches(&rule.rule.host_pattern, url) {
            continue;
        }
        let changed = match rule.rule.target {
            RequestRuleTarget::Header => apply_header(rule, headers)?,
            RequestRuleTarget::Body => {
                if let Some(value) = body.as_deref_mut() {
                    apply_body(rule, value)?
                } else {
                    false
                }
            }
            RequestRuleTarget::Url => false,
        };
        if changed {
            applied.push(applied_rule(rule));
        }
    }
    Ok(applied)
}

pub async fn has_applicable_body_rules(
    db: &Db,
    project_id: ProjectId,
    url: &str,
) -> DomainResult<bool> {
    Ok(compiled_rules(db, project_id).await?.iter().any(|rule| {
        rule.rule.enabled
            && rule.rule.target == RequestRuleTarget::Body
            && host_matches(&rule.rule.host_pattern, url)
    }))
}

/// Shows what the proxy would do with a request. `method` defaults to GET.
pub async fn preview(
    db: &Db,
    project_id: ProjectId,
    mut url: String,
    method: Option<String>,
    mut headers: Vec<(String, Vec<u8>)>,
    mut body: Vec<u8>,
) -> DomainResult<RequestRulePreview> {
    let method = method
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "GET".into());
    let outcome =
        apply_url_rules_with_blocks(db, project_id, &mut url, &method, &|_| false).await?;
    let mut applied = outcome.applied;
    if outcome.block.is_none() {
        applied.extend(
            apply_message_rules(db, project_id, &url, &mut headers, Some(&mut body)).await?,
        );
    }
    Ok(RequestRulePreview {
        url,
        headers: headers
            .into_iter()
            .map(|(n, v)| (n, String::from_utf8_lossy(&v).into_owned()))
            .collect(),
        body: String::from_utf8_lossy(&body).into_owned(),
        applied_rules: applied,
        blocked: outcome.block.is_some(),
        block: outcome.block,
    })
}

async fn compiled_rules(db: &Db, project_id: ProjectId) -> DomainResult<Arc<Vec<CompiledRule>>> {
    let key = cache_key(db, project_id);
    if db.path != std::path::Path::new(":memory:") {
        if let Some(v) = CACHE.get(&key) {
            return Ok(v.clone());
        }
    }
    let rules = db.list_request_rules(project_id).await?;
    let compiled = Arc::new(
        rules
            .into_iter()
            .map(|rule| {
                let regex = (rule.match_kind == RequestRuleMatchKind::Regex)
                    .then(|| Regex::new(&rule.pattern))
                    .transpose()
                    .map_err(|e| DomainError::invalid(e.to_string()))?;
                Ok(CompiledRule { rule, regex })
            })
            .collect::<DomainResult<Vec<_>>>()?,
    );
    if db.path != std::path::Path::new(":memory:") {
        CACHE.insert(key, compiled.clone());
    }
    Ok(compiled)
}

fn cache_key(db: &Db, project_id: ProjectId) -> String {
    format!("{}:{}", db.path.display(), project_id.get())
}

fn invalidate_cache(db: &Db, project_id: ProjectId) {
    CACHE.remove(&cache_key(db, project_id));
}

fn apply_header(rule: &CompiledRule, headers: &mut Vec<(String, Vec<u8>)>) -> DomainResult<bool> {
    let name = rule.rule.header_name.as_deref().unwrap_or_default();
    match rule.rule.operation {
        RequestRuleOperation::Set => {
            let replacement = rule
                .rule
                .replacement
                .clone()
                .unwrap_or_default()
                .into_bytes();
            http::HeaderValue::from_bytes(&replacement)
                .map_err(|error| DomainError::invalid(format!("invalid header value: {error}")))?;
            let mut matching = 0usize;
            let mut changed = false;
            headers.retain(|(n, v)| {
                if n.eq_ignore_ascii_case(name) {
                    matching += 1;
                    changed |= *v != replacement;
                    false
                } else {
                    true
                }
            });
            headers.push((name.into(), replacement));
            Ok(changed || matching != 1)
        }
        RequestRuleOperation::Remove => {
            let before = headers.len();
            headers.retain(|(n, v)| !(n.eq_ignore_ascii_case(name) && matches_bytes(rule, v)));
            Ok(headers.len() != before)
        }
        RequestRuleOperation::Replace => {
            let mut changed = false;
            for (_, v) in headers
                .iter_mut()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            {
                let next = replace_bytes(rule, v)?;
                http::HeaderValue::from_bytes(&next).map_err(|error| {
                    DomainError::invalid(format!("rewritten header value is invalid: {error}"))
                })?;
                changed |= next != *v;
                *v = next;
            }
            Ok(changed)
        }
        RequestRuleOperation::Block => Ok(false),
    }
}
fn apply_body(rule: &CompiledRule, body: &mut Vec<u8>) -> DomainResult<bool> {
    if body.len() > MAX_REWRITE_BODY_BYTES {
        return Err(DomainError::new(
            ErrorCode::BodyTooLarge,
            "request body exceeds 2 MiB rewrite limit",
        ));
    }
    let next = replace_bytes(rule, body)?;
    if next.len() > MAX_REWRITE_BODY_BYTES {
        return Err(DomainError::new(
            ErrorCode::BodyTooLarge,
            "rewritten request body exceeds 2 MiB rewrite limit",
        ));
    }
    let changed = next != *body;
    *body = next;
    Ok(changed)
}
fn replace_bytes(rule: &CompiledRule, value: &[u8]) -> DomainResult<Vec<u8>> {
    let text = std::str::from_utf8(value)
        .map_err(|_| DomainError::invalid("regex/text request rule requires UTF-8 input"))?;
    Ok(replace_text(rule, text)?.into_bytes())
}
fn replace_text(rule: &CompiledRule, value: &str) -> DomainResult<String> {
    let replacement = rule.rule.replacement.as_deref().unwrap_or_default();
    Ok(match rule.rule.match_kind {
        RequestRuleMatchKind::Literal => {
            if rule.rule.pattern.is_empty() {
                replacement.into()
            } else if rule.rule.replace_all {
                value.replace(&rule.rule.pattern, replacement)
            } else {
                value.replacen(&rule.rule.pattern, replacement, 1)
            }
        }
        RequestRuleMatchKind::Regex => {
            let regex = rule.regex.as_ref().expect("compiled regex");
            if rule.rule.replace_all {
                regex.replace_all(value, replacement).into_owned()
            } else {
                regex.replace(value, replacement).into_owned()
            }
        }
    })
}
fn matches_bytes(rule: &CompiledRule, value: &[u8]) -> bool {
    std::str::from_utf8(value).ok().is_some_and(|v| {
        if rule.rule.pattern.is_empty() {
            true
        } else if let Some(r) = &rule.regex {
            r.is_match(v)
        } else {
            v.contains(&rule.rule.pattern)
        }
    })
}
fn host_matches(pattern: &Option<String>, url: &str) -> bool {
    let Some(pattern) = pattern else {
        return true;
    };
    let Ok(url) = Url::parse(url) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    pattern
        .strip_prefix("*.")
        .map_or(host == pattern.as_str(), |suffix| {
            host.ends_with(&format!(".{suffix}"))
        })
}
fn validate_url(value: &str) -> DomainResult<()> {
    if value.len() > 16 * 1024 {
        return Err(DomainError::invalid("rewritten URL exceeds 16 KiB"));
    }
    let url = Url::parse(value)
        .map_err(|e| DomainError::invalid(format!("rewritten URL invalid: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(DomainError::invalid(
            "rewritten URL must be absolute HTTP(S)",
        ));
    }
    Ok(())
}
fn validate_input(i: &RequestRuleInput) -> DomainResult<()> {
    if i.name.trim().is_empty() {
        return Err(DomainError::invalid("rule name required"));
    }
    if i.pattern.len() > MAX_PATTERN_BYTES
        || i.replacement
            .as_ref()
            .is_some_and(|v| v.len() > MAX_REPLACEMENT_BYTES)
    {
        return Err(DomainError::invalid(
            "request rule pattern or replacement is too large",
        ));
    }
    let block = i.operation == RequestRuleOperation::Block;
    if block {
        validate_block(i)?;
    } else if i.method.is_some()
        || i.response_status.is_some()
        || i.response_content_type.is_some()
        || i.response_body.is_some()
    {
        return Err(DomainError::invalid(
            "method and response fields are only valid for block rules",
        ));
    }
    if i.target == RequestRuleTarget::Header && i.header_name.as_deref().is_none_or(str::is_empty) {
        return Err(DomainError::invalid("header_name required for header rule"));
    }
    if i.target == RequestRuleTarget::Header {
        i.header_name
            .as_deref()
            .unwrap_or_default()
            .parse::<http::HeaderName>()
            .map_err(|error| DomainError::invalid(format!("invalid header name: {error}")))?;
        if let Some(replacement) = &i.replacement {
            http::HeaderValue::from_str(replacement).map_err(|error| {
                DomainError::invalid(format!("invalid header replacement: {error}"))
            })?;
        }
    }
    if i.target != RequestRuleTarget::Header
        && i.operation != RequestRuleOperation::Replace
        && !block
    {
        return Err(DomainError::invalid(
            "URL and body rules only support replace (URL rules also support block)",
        ));
    }
    if !block && i.operation != RequestRuleOperation::Remove && i.replacement.is_none() {
        return Err(DomainError::invalid("replacement required"));
    }
    if i.match_kind == RequestRuleMatchKind::Regex {
        Regex::new(&i.pattern).map_err(|e| DomainError::invalid(format!("invalid regex: {e}")))?;
    }
    Ok(())
}
fn validate_block(i: &RequestRuleInput) -> DomainResult<()> {
    if i.target != RequestRuleTarget::Url {
        return Err(DomainError::invalid("block rules require target url"));
    }
    if i.replacement.is_some() {
        return Err(DomainError::invalid("block rules do not use replacement"));
    }
    if normalize_host(i.host_pattern.clone()).is_none() && i.pattern.is_empty() {
        return Err(DomainError::invalid(
            "block rules need a host_pattern or a pattern, so one rule cannot block all traffic",
        ));
    }
    let status = i.response_status.unwrap_or(DEFAULT_BLOCK_STATUS);
    if !(200..=599).contains(&status) {
        return Err(DomainError::invalid(
            "response_status must be between 200 and 599",
        ));
    }
    let body = i.response_body.as_deref().unwrap_or_default();
    if matches!(status, 204 | 304) && !body.is_empty() {
        return Err(DomainError::invalid(
            "204 and 304 block responses cannot have a response_body",
        ));
    }
    if body.len() > MAX_REPLACEMENT_BYTES {
        return Err(DomainError::invalid("response_body is too large"));
    }
    if let Some(content_type) = trimmed(i.response_content_type.as_deref()) {
        http::HeaderValue::from_str(content_type).map_err(|error| {
            DomainError::invalid(format!("invalid response_content_type: {error}"))
        })?;
    }
    if let Some(method) = trimmed(i.method.as_deref()) {
        http::Method::from_bytes(method.to_ascii_uppercase().as_bytes())
            .map_err(|error| DomainError::invalid(format!("invalid method: {error}")))?;
    }
    Ok(())
}
fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}
/// Stores block fields in canonical form and clears them on every other operation.
fn normalized(mut input: RequestRuleInput) -> RequestRuleInput {
    if input.operation == RequestRuleOperation::Block {
        input.method = trimmed(input.method.as_deref()).map(str::to_ascii_uppercase);
        input.response_status = Some(input.response_status.unwrap_or(DEFAULT_BLOCK_STATUS));
        input.response_content_type =
            trimmed(input.response_content_type.as_deref()).map(str::to_string);
    } else {
        input.method = None;
        input.response_status = None;
        input.response_content_type = None;
        input.response_body = None;
    }
    input
}
fn normalize_host(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
}
fn applied_rule(r: &CompiledRule) -> AppliedRequestRule {
    AppliedRequestRule {
        id: r.rule.id,
        name: r.rule.name.clone(),
    }
}
fn map_rule(row: &rusqlite::Row<'_>) -> rusqlite::Result<RequestRule> {
    Ok(RequestRule {
        id: row.get(0)?,
        project_id: ProjectId(row.get(1)?),
        name: row.get(2)?,
        enabled: row.get(3)?,
        position: row.get(4)?,
        host_pattern: row.get(5)?,
        target: parse_target(&row.get::<_, String>(6)?),
        operation: parse_operation(&row.get::<_, String>(7)?),
        header_name: row.get(8)?,
        match_kind: parse_match(&row.get::<_, String>(9)?),
        pattern: row.get(10)?,
        replacement: row.get(11)?,
        replace_all: row.get(12)?,
        revision: row.get(13)?,
        method: row.get(14)?,
        response_status: row
            .get::<_, Option<i64>>(15)?
            .and_then(|status| u16::try_from(status).ok()),
        response_content_type: row.get(16)?,
        response_body: row.get(17)?,
    })
}
fn load_rule(c: &rusqlite::Connection, p: ProjectId, id: i64) -> DomainResult<RequestRule> {
    c.query_row("SELECT id,project_id,name,enabled,position,host_pattern,target,operation,header_name,match_kind,pattern,replacement,replace_all,revision,method,response_status,response_content_type,response_body FROM request_rules WHERE id=?1 AND project_id=?2",params![id,p.get()],map_rule).map_err(storage)
}
fn target_str(v: RequestRuleTarget) -> &'static str {
    match v {
        RequestRuleTarget::Url => "url",
        RequestRuleTarget::Header => "header",
        RequestRuleTarget::Body => "body",
    }
}
fn parse_target(v: &str) -> RequestRuleTarget {
    match v {
        "header" => RequestRuleTarget::Header,
        "body" => RequestRuleTarget::Body,
        _ => RequestRuleTarget::Url,
    }
}
fn operation_str(v: RequestRuleOperation) -> &'static str {
    match v {
        RequestRuleOperation::Replace => "replace",
        RequestRuleOperation::Set => "set",
        RequestRuleOperation::Remove => "remove",
        RequestRuleOperation::Block => "block",
    }
}
fn parse_operation(v: &str) -> RequestRuleOperation {
    match v {
        "set" => RequestRuleOperation::Set,
        "remove" => RequestRuleOperation::Remove,
        "block" => RequestRuleOperation::Block,
        _ => RequestRuleOperation::Replace,
    }
}
fn match_str(v: RequestRuleMatchKind) -> &'static str {
    match v {
        RequestRuleMatchKind::Literal => "literal",
        RequestRuleMatchKind::Regex => "regex",
    }
}
fn parse_match(v: &str) -> RequestRuleMatchKind {
    if v == "regex" {
        RequestRuleMatchKind::Regex
    } else {
        RequestRuleMatchKind::Literal
    }
}
fn storage(e: impl std::fmt::Display) -> DomainError {
    DomainError::new(ErrorCode::StorageError, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fixture() -> (Db, ProjectId) {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "rules".into(),
                target_url: "https://example.test/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        (db, project.id)
    }

    fn input(
        name: &str,
        target: RequestRuleTarget,
        operation: RequestRuleOperation,
        pattern: &str,
        replacement: Option<&str>,
    ) -> RequestRuleInput {
        RequestRuleInput {
            name: name.into(),
            enabled: true,
            position: 0,
            host_pattern: Some("*.example.test".into()),
            target,
            operation,
            header_name: None,
            match_kind: RequestRuleMatchKind::Literal,
            pattern: pattern.into(),
            replacement: replacement.map(str::to_string),
            replace_all: true,
            method: None,
            response_status: None,
            response_content_type: None,
            response_body: None,
        }
    }

    #[tokio::test]
    async fn url_header_and_body_rules_apply_in_order() {
        let (db, project_id) = fixture().await;
        db.create_request_rule(
            project_id,
            input(
                "URL",
                RequestRuleTarget::Url,
                RequestRuleOperation::Replace,
                "/v1/",
                Some("/v2/"),
            ),
        )
        .await
        .unwrap();
        let mut header = input(
            "Header",
            RequestRuleTarget::Header,
            RequestRuleOperation::Set,
            "",
            Some("agent"),
        );
        header.position = 1;
        header.header_name = Some("X-Client".into());
        db.create_request_rule(project_id, header).await.unwrap();
        let mut body = input(
            "Body",
            RequestRuleTarget::Body,
            RequestRuleOperation::Replace,
            "old",
            Some("new"),
        );
        body.position = 2;
        db.create_request_rule(project_id, body).await.unwrap();

        let mut url = "https://api.example.test/v1/items".to_string();
        let mut headers = vec![("Accept".into(), b"application/json".to_vec())];
        let mut bytes = b"old old".to_vec();
        let first = apply_url_rules(&db, project_id, &mut url).await.unwrap();
        let second = apply_message_rules(&db, project_id, &url, &mut headers, Some(&mut bytes))
            .await
            .unwrap();

        assert_eq!(url, "https://api.example.test/v2/items");
        assert!(headers
            .iter()
            .any(|(name, value)| name == "X-Client" && value == b"agent"));
        assert_eq!(bytes, b"new new");
        assert_eq!(first.len() + second.len(), 3);
    }

    #[tokio::test]
    async fn host_gate_and_disabled_rules_do_not_apply() {
        let (db, project_id) = fixture().await;
        let mut rule = input(
            "Gated",
            RequestRuleTarget::Url,
            RequestRuleOperation::Replace,
            "old",
            Some("new"),
        );
        rule.host_pattern = Some("api.example.test".into());
        db.create_request_rule(project_id, rule).await.unwrap();
        let mut url = "https://other.example.test/old".to_string();
        assert!(apply_url_rules(&db, project_id, &mut url)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(url, "https://other.example.test/old");
    }

    fn block(name: &str, pattern: &str) -> RequestRuleInput {
        let mut rule = input(
            name,
            RequestRuleTarget::Url,
            RequestRuleOperation::Block,
            pattern,
            None,
        );
        rule.match_kind = RequestRuleMatchKind::Regex;
        rule
    }

    fn names(applied: &[AppliedRequestRule]) -> Vec<&str> {
        applied.iter().map(|rule| rule.name.as_str()).collect()
    }

    #[tokio::test]
    async fn block_rules_are_validated_strictly_and_stored_canonically() {
        let (db, project_id) = fixture().await;
        let rejected = |rule: RequestRuleInput, message: &'static str| {
            let db = db.clone();
            async move {
                let error = db.create_request_rule(project_id, rule).await.unwrap_err();
                assert!(
                    error.to_string().contains(message),
                    "{error} should mention {message}"
                );
            }
        };
        let mut everything = block("Everything", "");
        everything.host_pattern = None;
        rejected(everything, "cannot block all traffic").await;
        let mut header = block("Header", "x");
        header.target = RequestRuleTarget::Header;
        header.header_name = Some("X-Test".into());
        rejected(header, "require target url").await;
        let mut body = block("Body", "x");
        body.target = RequestRuleTarget::Body;
        rejected(body, "require target url").await;
        for status in [199, 600] {
            let mut rule = block("Status", "x");
            rule.response_status = Some(status);
            rejected(rule, "between 200 and 599").await;
        }
        for status in [204, 304] {
            let mut rule = block("Bodiless", "x");
            rule.response_status = Some(status);
            rule.response_body = Some("text".into());
            rejected(rule, "cannot have a response_body").await;
        }
        let mut content_type = block("Content type", "x");
        content_type.response_content_type = Some("text/html\r\nSet-Cookie: a=b".into());
        rejected(content_type, "invalid response_content_type").await;
        let mut method = block("Method", "x");
        method.method = Some("NOT A METHOD".into());
        rejected(method, "invalid method").await;
        let mut replacement = block("Replacement", "x");
        replacement.replacement = Some("y".into());
        rejected(replacement, "do not use replacement").await;
        let mut large = block("Large", "x");
        large.response_body = Some("a".repeat(MAX_REPLACEMENT_BYTES + 1));
        rejected(large, "too large").await;
        let mut rewrite = input(
            "Rewrite",
            RequestRuleTarget::Url,
            RequestRuleOperation::Replace,
            "a",
            Some("b"),
        );
        rewrite.method = Some("GET".into());
        rejected(rewrite, "only valid for block rules").await;

        let mut empty_no_content = block("No content", "x");
        empty_no_content.response_status = Some(204);
        empty_no_content.response_body = Some(String::new());
        db.create_request_rule(project_id, empty_no_content)
            .await
            .unwrap();
        let mut rule = block("Canonical", "^https://");
        rule.method = Some(" get ".into());
        rule.response_content_type = Some(" text/html ".into());
        let created = db.create_request_rule(project_id, rule).await.unwrap();
        assert_eq!(created.operation, RequestRuleOperation::Block);
        assert_eq!(created.method.as_deref(), Some("GET"));
        assert_eq!(created.response_status, Some(403), "status defaults to 403");
        assert_eq!(created.response_content_type.as_deref(), Some("text/html"));
        let listed = db.list_request_rules(project_id).await.unwrap();
        let stored = listed.iter().find(|item| item.id == created.id).unwrap();
        assert_eq!(stored.method, created.method);
        assert_eq!(stored.response_status, created.response_status);
        let mut changed = block("Canonical", "^https://");
        changed.response_status = Some(200);
        changed.response_body = Some("ok".into());
        let updated = db
            .update_request_rule(project_id, created.id, changed)
            .await
            .unwrap();
        assert_eq!(
            (
                updated.response_status,
                updated.response_body.as_deref(),
                updated.method
            ),
            (Some(200), Some("ok"), None)
        );
    }

    #[tokio::test]
    async fn block_rules_follow_rule_order_method_and_exemptions() {
        let (db, project_id) = fixture().await;
        let mut rewrite = input(
            "Rewrite",
            RequestRuleTarget::Url,
            RequestRuleOperation::Replace,
            "/old?",
            Some("/logout?"),
        );
        rewrite.position = 0;
        db.create_request_rule(project_id, rewrite).await.unwrap();
        let mut stop = block(
            "Block",
            r"(?i)^https://accounts\.example\.test(?::443)?/logout\?(?:.*&)?source=ChromiumAccountReconcilor",
        );
        stop.position = 1;
        stop.host_pattern = Some("accounts.example.test".into());
        stop.method = Some("GET".into());
        stop.response_status = Some(200);
        stop.response_content_type = Some("text/html; charset=utf-8".into());
        stop.response_body = Some(String::new());
        db.create_request_rule(project_id, stop).await.unwrap();
        let mut later = input(
            "Later",
            RequestRuleTarget::Url,
            RequestRuleOperation::Replace,
            "/logout?",
            Some("/after?"),
        );
        later.position = 2;
        db.create_request_rule(project_id, later).await.unwrap();
        let never = |_: &str| false;
        let source =
            "https://accounts.example.test/old?continue=x&source=ChromiumAccountReconcilor";

        let mut url = source.to_string();
        let outcome = apply_url_rules_with_blocks(&db, project_id, &mut url, "GET", &never)
            .await
            .unwrap();
        let blocked = outcome.block.expect("the reconciler logout is blocked");
        assert_eq!(
            (
                blocked.status,
                blocked.content_type.as_deref(),
                blocked.body.as_str()
            ),
            (200, Some("text/html; charset=utf-8"), "")
        );
        assert_eq!(blocked.rule.name, "Block");
        assert_eq!(
            url, "https://accounts.example.test/logout?continue=x&source=ChromiumAccountReconcilor",
            "earlier rewrites run, later ones do not"
        );
        assert_eq!(names(&outcome.applied), ["Rewrite", "Block"]);

        let mut post = source.to_string();
        let outcome = apply_url_rules_with_blocks(&db, project_id, &mut post, "POST", &never)
            .await
            .unwrap();
        assert!(outcome.block.is_none(), "the rule only blocks GET");
        assert_eq!(names(&outcome.applied), ["Rewrite", "Later"]);

        let mut user_logout = "https://accounts.example.test/old?continue=x".to_string();
        assert!(
            apply_url_rules_with_blocks(&db, project_id, &mut user_logout, "GET", &never)
                .await
                .unwrap()
                .block
                .is_none(),
            "a user's own logout still goes through"
        );

        let mut exempt = source.to_string();
        assert!(
            apply_url_rules_with_blocks(&db, project_id, &mut exempt, "GET", &|_| true)
                .await
                .unwrap()
                .block
                .is_none(),
            "an exempt URL is never blocked"
        );

        let mut replay = source.to_string();
        let applied = apply_url_rules(&db, project_id, &mut replay).await.unwrap();
        assert_eq!(
            names(&applied),
            ["Rewrite", "Later"],
            "Repeater and plugin requests ignore block rules"
        );
    }

    #[tokio::test]
    async fn literal_block_responses_use_safe_defaults() {
        let (db, project_id) = fixture().await;
        let mut literal = block("Tracker", "/collect");
        literal.match_kind = RequestRuleMatchKind::Literal;
        literal.response_body = Some("blocked".into());
        db.create_request_rule(project_id, literal).await.unwrap();
        let mut disabled = block("Disabled", "/beacon");
        disabled.enabled = false;
        db.create_request_rule(project_id, disabled).await.unwrap();
        let mut no_content = block("No content", "/ping");
        no_content.match_kind = RequestRuleMatchKind::Literal;
        no_content.response_status = Some(204);
        no_content.response_content_type = Some("text/html".into());
        db.create_request_rule(project_id, no_content)
            .await
            .unwrap();
        let never = |_: &str| false;

        let mut url = "https://api.example.test/v1/collect?x=1".to_string();
        let blocked = apply_url_rules_with_blocks(&db, project_id, &mut url, "PUT", &never)
            .await
            .unwrap()
            .block
            .unwrap();
        assert_eq!(
            (blocked.status, blocked.content_type.as_deref()),
            (403, Some(DEFAULT_BLOCK_CONTENT_TYPE))
        );
        let (headers, body) = blocked.response_parts(false);
        assert_eq!(
            headers,
            [
                ("cache-control", "no-store".to_string()),
                ("content-type", DEFAULT_BLOCK_CONTENT_TYPE.to_string())
            ]
        );
        assert_eq!(body, b"blocked");
        assert!(
            blocked.response_parts(true).1.is_empty(),
            "HEAD has no body"
        );

        let mut beacon = "https://api.example.test/beacon".to_string();
        assert!(
            apply_url_rules_with_blocks(&db, project_id, &mut beacon, "GET", &never)
                .await
                .unwrap()
                .block
                .is_none(),
            "disabled rules never block"
        );

        let mut ping = "https://api.example.test/ping".to_string();
        let bodiless = apply_url_rules_with_blocks(&db, project_id, &mut ping, "GET", &never)
            .await
            .unwrap()
            .block
            .unwrap();
        assert_eq!(
            (
                bodiless.status,
                bodiless.content_type.clone(),
                bodiless.body.as_str()
            ),
            (204, None, "")
        );
        assert_eq!(
            bodiless.response_parts(false),
            (vec![("cache-control", "no-store".to_string())], Vec::new())
        );
    }

    #[tokio::test]
    async fn preview_reports_blocks_and_assumes_get() {
        let (db, project_id) = fixture().await;
        let mut stop = block("Block", "/logout");
        stop.method = Some("GET".into());
        stop.response_status = Some(200);
        db.create_request_rule(project_id, stop).await.unwrap();
        let mut header = input(
            "Header",
            RequestRuleTarget::Header,
            RequestRuleOperation::Set,
            "",
            Some("1"),
        );
        header.header_name = Some("X-Rule".into());
        db.create_request_rule(project_id, header).await.unwrap();
        let url = "https://accounts.example.test/logout".to_string();

        let blocked = preview(&db, project_id, url.clone(), None, Vec::new(), Vec::new())
            .await
            .unwrap();
        assert!(blocked.blocked);
        assert_eq!(blocked.block.as_ref().unwrap().status, 200);
        assert!(
            blocked.headers.is_empty(),
            "a blocked request never reaches message rules"
        );
        assert_eq!(names(&blocked.applied_rules), ["Block"]);

        let allowed = preview(
            &db,
            project_id,
            url,
            Some("post".into()),
            Vec::new(),
            Vec::new(),
        )
        .await
        .unwrap();
        assert!(!allowed.blocked && allowed.block.is_none());
        assert_eq!(names(&allowed.applied_rules), ["Header"]);
    }

    #[tokio::test]
    async fn invalid_rule_combinations_are_rejected() {
        let (db, project_id) = fixture().await;
        let invalid = input(
            "Bad",
            RequestRuleTarget::Body,
            RequestRuleOperation::Remove,
            "x",
            None,
        );
        assert!(db.create_request_rule(project_id, invalid).await.is_err());
    }
}
