//! Project-scoped semantic request match/replace rules.

use crate::domain::*;
use crate::storage::{now_rfc3339, Db};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;

const MAX_RULES: usize = 100;
const MAX_PATTERN_BYTES: usize = 4096;
const MAX_REPLACEMENT_BYTES: usize = 64 * 1024;
pub const MAX_REWRITE_BODY_BYTES: usize = 2 * 1024 * 1024;

static CACHE: Lazy<DashMap<String, Arc<Vec<CompiledRule>>>> = Lazy::new(DashMap::new);

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
            let mut stmt = conn.prepare("SELECT id,project_id,name,enabled,position,host_pattern,target,operation,header_name,match_kind,pattern,replacement,replace_all,revision FROM request_rules WHERE project_id=?1 ORDER BY position,id").map_err(storage)?;
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
        self.get_project(project_id).await?;
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM request_rules WHERE project_id=?1", params![project_id.get()], |r| r.get(0)).map_err(storage)?;
            if count >= MAX_RULES as i64 { return Err(DomainError::invalid("a project may have at most 100 request rules")); }
            conn.execute("INSERT INTO request_rules(project_id,name,enabled,position,host_pattern,target,operation,header_name,match_kind,pattern,replacement,replace_all,revision,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,1,?13,?13)", params![project_id.get(), input.name.trim(), input.enabled, input.position, normalize_host(input.host_pattern), target_str(input.target), operation_str(input.operation), input.header_name, match_str(input.match_kind), input.pattern, input.replacement, input.replace_all, ts]).map_err(storage)?;
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
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let changed=conn.execute("UPDATE request_rules SET name=?1,enabled=?2,position=?3,host_pattern=?4,target=?5,operation=?6,header_name=?7,match_kind=?8,pattern=?9,replacement=?10,replace_all=?11,revision=revision+1,updated_at=?12 WHERE id=?13 AND project_id=?14", params![input.name.trim(),input.enabled,input.position,normalize_host(input.host_pattern),target_str(input.target),operation_str(input.operation),input.header_name,match_str(input.match_kind),input.pattern,input.replacement,input.replace_all,ts,id,project_id.get()]).map_err(storage)?;
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
        self.with_conn(move |conn| { let tx=conn.unchecked_transaction().map_err(storage)?; for rule in rules { tx.execute("INSERT OR IGNORE INTO exchange_request_rules(project_id,exchange_id,rule_id,rule_name) VALUES(?1,?2,?3,?4)",params![project_id.get(),exchange_id.get(),rule.id,rule.name]).map_err(storage)?; } tx.commit().map_err(storage) }).await
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

pub async fn apply_url_rules(
    db: &Db,
    project_id: ProjectId,
    url: &mut String,
) -> DomainResult<Vec<AppliedRequestRule>> {
    let rules = compiled_rules(db, project_id).await?;
    let mut applied = Vec::new();
    for rule in rules
        .iter()
        .filter(|r| r.rule.enabled && r.rule.target == RequestRuleTarget::Url)
    {
        if !host_matches(&rule.rule.host_pattern, url) {
            continue;
        }
        let before = url.clone();
        *url = replace_text(rule, &before)?;
        if *url != before {
            validate_url(url)?;
            applied.push(applied_rule(rule));
        }
    }
    Ok(applied)
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

pub async fn preview(
    db: &Db,
    project_id: ProjectId,
    mut url: String,
    mut headers: Vec<(String, Vec<u8>)>,
    mut body: Vec<u8>,
) -> DomainResult<RequestRulePreview> {
    let mut applied = apply_url_rules(db, project_id, &mut url).await?;
    applied.extend(apply_message_rules(db, project_id, &url, &mut headers, Some(&mut body)).await?);
    Ok(RequestRulePreview {
        url,
        headers: headers
            .into_iter()
            .map(|(n, v)| (n, String::from_utf8_lossy(&v).into_owned()))
            .collect(),
        body: String::from_utf8_lossy(&body).into_owned(),
        applied_rules: applied,
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
    if i.target != RequestRuleTarget::Header && i.operation != RequestRuleOperation::Replace {
        return Err(DomainError::invalid(
            "URL and body rules only support replace",
        ));
    }
    if i.operation != RequestRuleOperation::Remove && i.replacement.is_none() {
        return Err(DomainError::invalid("replacement required"));
    }
    if i.match_kind == RequestRuleMatchKind::Regex {
        Regex::new(&i.pattern).map_err(|e| DomainError::invalid(format!("invalid regex: {e}")))?;
    }
    Ok(())
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
    })
}
fn load_rule(c: &rusqlite::Connection, p: ProjectId, id: i64) -> DomainResult<RequestRule> {
    c.query_row("SELECT id,project_id,name,enabled,position,host_pattern,target,operation,header_name,match_kind,pattern,replacement,replace_all,revision FROM request_rules WHERE id=?1 AND project_id=?2",params![id,p.get()],map_rule).map_err(storage)
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
    }
}
fn parse_operation(v: &str) -> RequestRuleOperation {
    match v {
        "set" => RequestRuleOperation::Set,
        "remove" => RequestRuleOperation::Remove,
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
