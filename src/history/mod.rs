//! History filtering, pagination, summaries, diffs.

use crate::domain::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterNode {
    And {
        and: Vec<FilterNode>,
    },
    Or {
        or: Vec<FilterNode>,
    },
    Not {
        not: Box<FilterNode>,
    },
    Term {
        field: String,
        op: String,
        value: serde_json::Value,
    },
}

const ALLOWED_FIELDS: &[&str] = &[
    "exchange_id",
    "host",
    "authority",
    "path",
    "method",
    "protocol",
    "status",
    "mime",
    "source",
    "label",
    "request_size",
    "response_size",
    "duration",
    "title",
    "page_title",
    "display_title",
    "parent",
    "browser_session",
    "capture_session",
    "reply_tab",
    "fuzz_job",
    "request_hash",
    "response_hash",
    "time",
    "error",
    "request",
];

const ALLOWED_OPS: &[&str] = &[
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "contains",
    "starts_with",
    "ends_with",
    "exists",
];

const MAX_TERMS: usize = 32;
const MAX_DEPTH: usize = 6;
const MAX_INPUT_LEN: usize = 2048;

pub fn validate_filter(node: &FilterNode) -> DomainResult<()> {
    validate_filter_depth(node, 0, &mut 0)
}

fn validate_filter_depth(node: &FilterNode, depth: usize, terms: &mut usize) -> DomainResult<()> {
    if depth > MAX_DEPTH {
        return Err(DomainError::invalid("filter nesting too deep"));
    }
    match node {
        FilterNode::And { and } | FilterNode::Or { or: and } => {
            for c in and {
                validate_filter_depth(c, depth + 1, terms)?;
            }
        }
        FilterNode::Not { not } => validate_filter_depth(not, depth + 1, terms)?,
        FilterNode::Term { field, op, .. } => {
            *terms += 1;
            if *terms > MAX_TERMS {
                return Err(DomainError::invalid("too many filter terms"));
            }
            if !ALLOWED_FIELDS.contains(&field.as_str()) {
                return Err(DomainError::invalid(format!(
                    "unknown filter field: {field}"
                )));
            }
            if !ALLOWED_OPS.contains(&op.as_str()) {
                return Err(DomainError::invalid(format!(
                    "unknown filter operator: {op}"
                )));
            }
        }
    }
    Ok(())
}

/// Compile filter AST to parameterized SQL WHERE clause (without leading WHERE).
pub fn filter_to_sql(node: &FilterNode) -> DomainResult<(String, Vec<String>)> {
    validate_filter(node)?;
    let mut binds = Vec::new();
    let sql = compile_node(node, &mut binds)?;
    Ok((sql, binds))
}

fn compile_node(node: &FilterNode, binds: &mut Vec<String>) -> DomainResult<String> {
    match node {
        FilterNode::And { and } => {
            if and.is_empty() {
                return Ok("1=1".into());
            }
            let parts: DomainResult<Vec<_>> = and.iter().map(|n| compile_node(n, binds)).collect();
            Ok(format!("({})", parts?.join(" AND ")))
        }
        FilterNode::Or { or } => {
            if or.is_empty() {
                return Ok("1=0".into());
            }
            let parts: DomainResult<Vec<_>> = or.iter().map(|n| compile_node(n, binds)).collect();
            Ok(format!("({})", parts?.join(" OR ")))
        }
        FilterNode::Not { not } => Ok(format!("NOT ({})", compile_node(not, binds)?)),
        FilterNode::Term { field, op, value } => compile_term(field, op, value, binds),
    }
}

fn col(field: &str) -> DomainResult<&'static str> {
    Ok(match field {
        "exchange_id" => "exchange_id",
        "host" => "host",
        "authority" => "authority",
        "path" => "path",
        "method" => "method",
        "protocol" => "protocol",
        "status" => "status_code",
        "mime" => "mime",
        "source" => "source",
        "request_size" => "request_length",
        "response_size" => "response_length",
        "duration" => "duration_ms",
        "title" => "COALESCE(display_title, page_title)",
        "page_title" => "page_title",
        "display_title" => "display_title",
        "parent" => "parent_exchange_id",
        "browser_session" => "browser_session_id",
        "capture_session" => "capture_session_id",
        "reply_tab" => "reply_tab_id",
        "fuzz_job" => "fuzz_job_id",
        "request_hash" => "request_body_hash",
        "response_hash" => "response_body_hash",
        "time" => "started_at",
        "error" => "error_message",
        "label" => "exchange_id", // special-cased
        other => {
            return Err(DomainError::invalid(format!("unsupported field {other}")));
        }
    })
}

fn compile_term(
    field: &str,
    op: &str,
    value: &serde_json::Value,
    binds: &mut Vec<String>,
) -> DomainResult<String> {
    if field == "label" {
        return compile_label_term(op, value, binds);
    }
    if field == "request" {
        return compile_request_term(op, value, binds);
    }
    let c = col(field)?;
    match op {
        "eq" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c}=?{}", binds.len()))
        }
        "ne" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c}!=?{}", binds.len()))
        }
        "gt" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c}>?{}", binds.len()))
        }
        "gte" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c}>=?{}", binds.len()))
        }
        "lt" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c}<?{}", binds.len()))
        }
        "lte" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c}<=?{}", binds.len()))
        }
        "contains" => {
            binds.push(format!("%{}%", escape_like(&value_as_string(value)?)));
            Ok(format!("{c} LIKE ?{} ESCAPE '\\'", binds.len()))
        }
        "starts_with" => {
            binds.push(format!("{}%", escape_like(&value_as_string(value)?)));
            Ok(format!("{c} LIKE ?{} ESCAPE '\\'", binds.len()))
        }
        "ends_with" => {
            binds.push(format!("%{}", escape_like(&value_as_string(value)?)));
            Ok(format!("{c} LIKE ?{} ESCAPE '\\'", binds.len()))
        }
        "in" => {
            let arr = value
                .as_array()
                .ok_or_else(|| DomainError::invalid("in operator requires array"))?;
            if arr.is_empty() {
                return Ok("1=0".into());
            }
            let mut placeholders = Vec::new();
            for v in arr {
                binds.push(value_as_string(v)?);
                placeholders.push(format!("?{}", binds.len()));
            }
            Ok(format!("{c} IN ({})", placeholders.join(",")))
        }
        "exists" => {
            let exists = value.as_bool().unwrap_or(true);
            if exists {
                Ok(format!("{c} IS NOT NULL"))
            } else {
                Ok(format!("{c} IS NULL"))
            }
        }
        other => Err(DomainError::invalid(format!("unsupported op {other}"))),
    }
}

fn compile_request_term(
    op: &str,
    value: &serde_json::Value,
    binds: &mut Vec<String>,
) -> DomainResult<String> {
    if op != "contains" {
        return Err(DomainError::invalid(
            "request supports only the contains operator; use request:~text",
        ));
    }
    let value = value_as_string(value)?;
    binds.push(format!("%{}%", escape_like(&value)));
    let like_index = binds.len();
    binds.push(value);
    let body_index = binds.len();
    Ok(format!(
        "(method LIKE ?{like_index} ESCAPE '\\' \
          OR scheme LIKE ?{like_index} ESCAPE '\\' \
          OR authority LIKE ?{like_index} ESCAPE '\\' \
          OR path LIKE ?{like_index} ESCAPE '\\' \
          OR COALESCE(query, '') LIKE ?{like_index} ESCAPE '\\' \
          OR EXISTS (SELECT 1 FROM message_headers mh \
                     WHERE mh.project_id=exchanges.project_id \
                       AND mh.exchange_id=exchanges.exchange_id \
                       AND mh.side='request' \
                       AND (mh.name LIKE ?{like_index} ESCAPE '\\' \
                            OR CAST(mh.value AS TEXT) LIKE ?{like_index} ESCAPE '\\')) \
          OR EXISTS (SELECT 1 FROM bodies b \
                     WHERE b.id=exchanges.request_body_id \
                       AND huntproxy_body_contains(b.codec, b.content, ?{body_index})))"
    ))
}

fn compile_label_term(
    op: &str,
    value: &serde_json::Value,
    binds: &mut Vec<String>,
) -> DomainResult<String> {
    let prefix = "EXISTS (SELECT 1 FROM exchange_labels el JOIN labels l ON l.id=el.label_id AND l.project_id=el.project_id WHERE el.project_id=exchanges.project_id AND el.exchange_id=exchanges.exchange_id";
    match op {
        "eq" | "ne" => {
            binds.push(value_as_string(value)?);
            let exists = format!("{prefix} AND l.name=?{})", binds.len());
            Ok(if op == "ne" {
                format!("NOT ({exists})")
            } else {
                exists
            })
        }
        "contains" | "starts_with" | "ends_with" => {
            let value = escape_like(&value_as_string(value)?);
            let pattern = match op {
                "contains" => format!("%{value}%"),
                "starts_with" => format!("{value}%"),
                _ => format!("%{value}"),
            };
            binds.push(pattern);
            Ok(format!(
                "{prefix} AND l.name LIKE ?{} ESCAPE '\\')",
                binds.len()
            ))
        }
        "in" => {
            let values = value
                .as_array()
                .ok_or_else(|| DomainError::invalid("in operator requires array"))?;
            if values.is_empty() {
                return Ok("1=0".into());
            }
            let mut placeholders = Vec::with_capacity(values.len());
            for value in values {
                binds.push(value_as_string(value)?);
                placeholders.push(format!("?{}", binds.len()));
            }
            Ok(format!(
                "{prefix} AND l.name IN ({}))",
                placeholders.join(",")
            ))
        }
        "exists" => {
            let clause = format!("{prefix})");
            Ok(if value.as_bool().unwrap_or(true) {
                clause
            } else {
                format!("NOT ({clause})")
            })
        }
        _ => Err(DomainError::invalid(format!(
            "operator {op} is not supported for label"
        ))),
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn value_as_string(v: &serde_json::Value) -> DomainResult<String> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Null => Ok(String::new()),
        _ => Err(DomainError::invalid("unsupported filter value type")),
    }
}

/// Small text syntax: `host:example.com method:GET status>=400`.
/// Bare words search common summary fields; `field:~value` means contains.
/// `AND`, `OR`, `NOT`, parentheses, and quoted values are supported.
pub fn parse_text_query(input: &str) -> DomainResult<FilterNode> {
    if input.len() > MAX_INPUT_LEN {
        return Err(DomainError::invalid("filter text too long"));
    }
    let input = input.trim();
    if input.is_empty() {
        return Ok(FilterNode::And { and: vec![] });
    }
    QueryParser::new(tokenize_query(input)?).parse()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum QueryToken {
    Text(String),
    LeftParen,
    RightParen,
}

fn tokenize_query(input: &str) -> DomainResult<Vec<QueryToken>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let flush = |current: &mut String, tokens: &mut Vec<QueryToken>| {
        if !current.is_empty() {
            tokens.push(QueryToken::Text(std::mem::take(current)));
        }
    };
    for character in input.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            continue;
        }
        if !quoted {
            match character {
                '(' => {
                    flush(&mut current, &mut tokens);
                    tokens.push(QueryToken::LeftParen);
                    continue;
                }
                ')' => {
                    flush(&mut current, &mut tokens);
                    tokens.push(QueryToken::RightParen);
                    continue;
                }
                character if character.is_whitespace() => {
                    flush(&mut current, &mut tokens);
                    continue;
                }
                _ => {}
            }
        }
        current.push(character);
    }
    if quoted {
        return Err(DomainError::invalid("unterminated quote in history filter"));
    }
    if escaped {
        current.push('\\');
    }
    flush(&mut current, &mut tokens);
    Ok(tokens)
}

struct QueryParser {
    tokens: Vec<QueryToken>,
    position: usize,
}

impl QueryParser {
    fn new(tokens: Vec<QueryToken>) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }

    fn parse(mut self) -> DomainResult<FilterNode> {
        let node = self.parse_or()?;
        if self.position != self.tokens.len() {
            return Err(DomainError::invalid("unexpected token in history filter"));
        }
        Ok(node)
    }

    fn parse_or(&mut self) -> DomainResult<FilterNode> {
        let mut nodes = vec![self.parse_and()?];
        while self.consume_keyword("OR") {
            nodes.push(self.parse_and()?);
        }
        Ok(if nodes.len() == 1 {
            nodes.remove(0)
        } else {
            FilterNode::Or { or: nodes }
        })
    }

    fn parse_and(&mut self) -> DomainResult<FilterNode> {
        let mut nodes = vec![self.parse_not()?];
        loop {
            if self.peek_keyword("OR") || matches!(self.peek(), None | Some(QueryToken::RightParen))
            {
                break;
            }
            let _ = self.consume_keyword("AND");
            nodes.push(self.parse_not()?);
        }
        Ok(if nodes.len() == 1 {
            nodes.remove(0)
        } else {
            FilterNode::And { and: nodes }
        })
    }

    fn parse_not(&mut self) -> DomainResult<FilterNode> {
        if self.consume_keyword("NOT") {
            return Ok(FilterNode::Not {
                not: Box::new(self.parse_not()?),
            });
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> DomainResult<FilterNode> {
        match self.next() {
            Some(QueryToken::Text(text)) => parse_one_term(&text).map_err(|error| {
                DomainError::invalid(format!("filter parse error at `{text}`: {error}"))
            }),
            Some(QueryToken::LeftParen) => {
                let node = self.parse_or()?;
                match self.next() {
                    Some(QueryToken::RightParen) => Ok(node),
                    _ => Err(DomainError::invalid(
                        "missing closing parenthesis in history filter",
                    )),
                }
            }
            Some(QueryToken::RightParen) => {
                Err(DomainError::invalid("unexpected closing parenthesis"))
            }
            None => Err(DomainError::invalid("missing term in history filter")),
        }
    }

    fn peek(&self) -> Option<&QueryToken> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<QueryToken> {
        let token = self.tokens.get(self.position).cloned();
        self.position += usize::from(token.is_some());
        token
    }

    fn peek_keyword(&self, expected: &str) -> bool {
        matches!(self.peek(), Some(QueryToken::Text(text)) if text.eq_ignore_ascii_case(expected))
    }

    fn consume_keyword(&mut self, expected: &str) -> bool {
        if self.peek_keyword(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }
}

fn parse_one_term(part: &str) -> Result<FilterNode, String> {
    if let Some((field, rest)) = part.split_once(">=") {
        return Ok(term(field, "gte", rest));
    }
    if let Some((field, rest)) = part.split_once("<=") {
        return Ok(term(field, "lte", rest));
    }
    if let Some((field, rest)) = part.split_once("!=") {
        return Ok(term(field, "ne", rest));
    }
    if let Some((field, rest)) = part.split_once('>') {
        return Ok(term(field, "gt", rest));
    }
    if let Some((field, rest)) = part.split_once('<') {
        return Ok(term(field, "lt", rest));
    }
    if let Some((field, rest)) = part.split_once(':') {
        if let Some(value) = rest.strip_prefix('~') {
            return Ok(term(field, "contains", value));
        }
        if let Some(v) = rest.strip_prefix('*') {
            if let Some(v) = v.strip_suffix('*') {
                return Ok(term(field, "contains", v));
            }
            return Ok(term(field, "ends_with", v));
        }
        if let Some(v) = rest.strip_suffix('*') {
            return Ok(term(field, "starts_with", v));
        }
        return Ok(term(field, "eq", rest));
    }
    Ok(FilterNode::Or {
        or: ["host", "authority", "path", "mime", "title", "error"]
            .into_iter()
            .map(|field| term(field, "contains", part))
            .collect(),
    })
}

fn term(field: &str, op: &str, value: &str) -> FilterNode {
    let value = if let Ok(n) = value.parse::<i64>() {
        serde_json::json!(n)
    } else {
        serde_json::json!(value)
    };
    FilterNode::Term {
        field: field.to_string(),
        op: op.to_string(),
        value,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDiff {
    pub status_changed: bool,
    pub parent_status: Option<u16>,
    pub child_status: Option<u16>,
    pub length_delta: Option<i64>,
    pub mime_changed: bool,
    pub body_hash_equal: Option<bool>,
    pub header_added: Vec<String>,
    pub header_removed: Vec<String>,
    pub header_changed: Vec<String>,
    pub text_diff: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub fn diff_exchanges(
    parent_status: Option<u16>,
    child_status: Option<u16>,
    parent_len: Option<i64>,
    child_len: Option<i64>,
    parent_mime: Option<&str>,
    child_mime: Option<&str>,
    parent_hash: Option<&str>,
    child_hash: Option<&str>,
    parent_headers: &[(String, String)],
    child_headers: &[(String, String)],
    parent_body_text: Option<&str>,
    child_body_text: Option<&str>,
) -> ResponseDiff {
    let mut parent_map: std::collections::BTreeMap<String, String> = parent_headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    let child_map: std::collections::BTreeMap<String, String> = child_headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();

    let mut header_added = Vec::new();
    let mut header_removed = Vec::new();
    let mut header_changed = Vec::new();
    for (k, v) in &child_map {
        match parent_map.remove(k) {
            None => header_added.push(k.clone()),
            Some(pv) if pv != *v => header_changed.push(k.clone()),
            _ => {}
        }
    }
    for k in parent_map.keys() {
        header_removed.push(k.clone());
    }

    let text_diff = match (parent_body_text, child_body_text) {
        (Some(a), Some(b)) if a.len() < 64 * 1024 && b.len() < 64 * 1024 => {
            Some(bounded_line_diff(a, b, 50))
        }
        _ => None,
    };

    ResponseDiff {
        status_changed: parent_status != child_status,
        parent_status,
        child_status,
        length_delta: match (parent_len, child_len) {
            (Some(a), Some(b)) => Some(b - a),
            _ => None,
        },
        mime_changed: parent_mime != child_mime,
        body_hash_equal: match (parent_hash, child_hash) {
            (Some(a), Some(b)) => Some(a == b),
            _ => None,
        },
        header_added,
        header_removed,
        header_changed,
        text_diff,
    }
}

fn bounded_line_diff(a: &str, b: &str, max_lines: usize) -> String {
    let al: Vec<&str> = a.lines().collect();
    let bl: Vec<&str> = b.lines().collect();
    let mut out = String::new();
    let max = al.len().max(bl.len()).min(max_lines);
    for i in 0..max {
        let left = al.get(i).copied().unwrap_or("");
        let right = bl.get(i).copied().unwrap_or("");
        if left != right {
            out.push_str(&format!("- {left}\n+ {right}\n"));
        }
    }
    if al.len().max(bl.len()) > max_lines {
        out.push_str(&format!("... truncated after {max_lines} lines\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_query_and_sql() {
        let n = parse_text_query("host:example.com method:GET status>=400").unwrap();
        validate_filter(&n).unwrap();
        let (sql, binds) = filter_to_sql(&n).unwrap();
        assert!(sql.contains("host"));
        assert!(sql.contains("method"));
        assert_eq!(binds.len(), 3);
    }

    #[test]
    fn lineage_ids_and_body_hashes_are_filterable() {
        let filter = parse_text_query(
            "exchange_id:3011 capture_session:42 request_hash:abc response_hash:~def",
        )
        .unwrap();
        let (sql, binds) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("exchange_id="));
        assert!(sql.contains("capture_session_id="));
        assert!(sql.contains("request_body_hash="));
        assert!(sql.contains("response_body_hash LIKE"));
        assert_eq!(binds, vec!["3011", "42", "abc", "%def%"]);
    }

    #[test]
    fn bare_text_and_tilde_are_contains_searches() {
        let bare = parse_text_query("javascript").unwrap();
        let (sql, binds) = filter_to_sql(&bare).unwrap();
        assert!(sql.contains(" OR "));
        assert!(binds.iter().all(|value| value == "%javascript%"));

        let path = parse_text_query("path:~.js").unwrap();
        let (_, binds) = filter_to_sql(&path).unwrap();
        assert_eq!(binds, vec!["%.js%"]);
    }

    #[test]
    fn request_contains_supports_boolean_or_quotes_and_method() {
        let filter = parse_text_query(
            r#"(request:~"this" OR request:~"that" OR request:~":smtg") method:PUT"#,
        )
        .unwrap();
        let (sql, binds) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("huntproxy_body_contains"));
        assert!(sql.contains(" OR "));
        assert!(sql.contains(" AND "));
        assert!(sql.contains("method="));
        assert!(binds.iter().any(|value| value == ":smtg"));
        assert!(binds.iter().any(|value| value == "PUT"));
    }

    #[test]
    fn malformed_boolean_queries_are_rejected() {
        assert!(parse_text_query("method:PUT OR").is_err());
        assert!(parse_text_query("(method:PUT").is_err());
        assert!(parse_text_query(r#"request:~"unfinished"#).is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        let n = FilterNode::Term {
            field: "drop_table".into(),
            op: "eq".into(),
            value: serde_json::json!("x"),
        };
        assert!(validate_filter(&n).is_err());
    }

    #[test]
    fn sql_injection_stays_bound() {
        // Text query splits on whitespace; injection payload is a single token.
        let n = parse_text_query("host:a';DROP_TABLE_projects;--").unwrap();
        let (sql, binds) = filter_to_sql(&n).unwrap();
        assert!(!sql.to_lowercase().contains("drop"));
        assert!(binds[0].contains("DROP"));
    }
}
