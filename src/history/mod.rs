//! History filtering, pagination, summaries, diffs.

use crate::compare::bounded_line_diff;
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
    "response",
    "query",
    "url",
    "project_id",
    "project",
];

/// Fields a bare word searches; the group counts as one term.
const BARE_WORD_FIELDS: [&str; 6] = ["host", "authority", "path", "mime", "title", "error"];

/// Full URL as `scheme://authority/path?query`, matching the MCP row `url`.
const URL_SQL: &str = "(scheme || '://' || authority || path || CASE WHEN query IS NULL OR query='' THEN '' ELSE '?' || query END)";

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

/// Shared guidance for adapters that surface history-query errors.
pub const HISTORY_QUERY_SYNTAX: &str = "Use field:value, field:~text, or field>=value (no colon before comparisons); combine terms with AND, OR, NOT and parentheses. Quote values containing spaces. URL parameters: query:~\"id=5\". Example: host:example.com status>=400";

pub(crate) fn query_error(message: impl Into<String>) -> DomainError {
    DomainError::with_details(
        crate::domain::ErrorCode::InvalidArgument,
        message,
        serde_json::json!({"kind": "history_query", "syntax": HISTORY_QUERY_SYNTAX}),
    )
}

pub fn validate_filter(node: &FilterNode) -> DomainResult<()> {
    validate_filter_depth(node, 0, &mut 0)
}

/// `request` and `response` searches include decoded body bytes and are
/// intentionally treated as expensive by callers (for example, they skip an
/// exact second-pass count). Keep this structural check next to the filter
/// model so every adapter can make the same decision without inspecting
/// generated SQL.
pub fn uses_body_search(node: &FilterNode) -> bool {
    match node {
        FilterNode::And { and } => and.iter().any(uses_body_search),
        FilterNode::Or { or } => or.iter().any(uses_body_search),
        FilterNode::Not { not } => uses_body_search(not),
        FilterNode::Term { field, .. } => is_body_field(field),
    }
}

fn is_body_field(field: &str) -> bool {
    matches!(field, "request" | "response")
}

/// The word when `node` is the OR group a bare word expands to.
fn bare_word(node: &FilterNode) -> Option<&serde_json::Value> {
    let FilterNode::Or { or } = node else {
        return None;
    };
    if or.len() != BARE_WORD_FIELDS.len() {
        return None;
    }
    let mut word = None;
    for (child, expected) in or.iter().zip(BARE_WORD_FIELDS) {
        let FilterNode::Term { field, op, value } = child else {
            return None;
        };
        if field != expected || op != "contains" || word.is_some_and(|word| word != value) {
            return None;
        }
        word = Some(value);
    }
    word.filter(|value| value.is_string() || value.is_number())
}

fn validate_filter_depth(node: &FilterNode, depth: usize, terms: &mut usize) -> DomainResult<()> {
    if depth > MAX_DEPTH {
        return Err(query_error(format!(
            "filter nesting too deep; use at most {MAX_DEPTH} nested Boolean levels"
        )));
    }
    match node {
        node if bare_word(node).is_some() => count_term(terms)?,
        FilterNode::And { and } | FilterNode::Or { or: and } => {
            for c in and {
                validate_filter_depth(c, depth + 1, terms)?;
            }
        }
        FilterNode::Not { not } => validate_filter_depth(not, depth + 1, terms)?,
        FilterNode::Term { field, op, value } => {
            count_term(terms)?;
            if !ALLOWED_FIELDS.contains(&field.as_str()) {
                return Err(unknown_field_error(field, op, value));
            }
            if !ALLOWED_OPS.contains(&op.as_str()) {
                return Err(query_error(format!(
                    "unknown filter operator: {op} for {field}; use {}. Text example: {}",
                    ALLOWED_OPS.join(", "),
                    field_example(field),
                )));
            }
        }
    }
    Ok(())
}

fn count_term(terms: &mut usize) -> DomainResult<()> {
    *terms += 1;
    if *terms > MAX_TERMS {
        return Err(query_error(format!(
            "too many filter terms; use at most {MAX_TERMS} terms"
        )));
    }
    Ok(())
}

fn field_example(field: &str) -> String {
    match field {
        "time" => "time>2026-10-12T00:00:00Z".into(),
        "status" => "status>=400".into(),
        "duration" => "duration>=1000".into(),
        "request_size" | "response_size" => format!("{field}>1024"),
        "request" | "response" => format!("{field}:~text"),
        "query" => "query:~\"id=5\"".into(),
        "url" => "url:~/api/".into(),
        _ => format!("{field}:value"),
    }
}

/// Field names agents borrow from other tools, with the field to use.
const FIELD_ALIASES: &[(&str, &str)] = &[
    ("status_code", "status"),
    ("code", "status"),
    ("started_at", "time"),
    ("timestamp", "time"),
    ("duration_ms", "duration"),
    ("request_length", "request_size"),
    ("response_length", "response_size"),
    ("request_body", "request"),
    ("response_body", "response"),
    ("body", "request or response"),
    ("header", "request or response"),
    ("headers", "request or response"),
    ("params", "query"),
    ("param", "query"),
    ("query_string", "query"),
    ("uri", "url"),
    ("href", "url"),
    ("domain", "host"),
    ("hostname", "host"),
    ("content_type", "mime"),
    ("content-type", "mime"),
    ("labels", "label"),
    ("tag", "label"),
];

fn unknown_field_error(field: &str, op: &str, value: &serde_json::Value) -> DomainError {
    if let Some(correct) = field.strip_suffix(':').filter(|field| {
        ALLOWED_FIELDS.contains(field) && matches!(op, "gt" | "gte" | "lt" | "lte" | "ne")
    }) {
        if is_body_field(correct) {
            return query_error(format!(
                "unknown filter field: {correct}:; {correct} supports only text searches. Use {correct}:~text"
            ));
        }
        if correct == "label" && !matches!(op, "eq" | "ne") {
            return query_error(
                "unknown filter field: label:; label does not support ordering comparisons. Use label:reviewed or label:~review",
            );
        }
        let operator = match op {
            "gt" => ">",
            "gte" => ">=",
            "lt" => "<",
            "lte" => "<=",
            "ne" => "!=",
            _ => ":",
        };
        return query_error(format!(
            "unknown filter field: {field}; remove the colon before `{operator}`: use `{correct}{operator}VALUE`. Example: {}",
            field_example(correct),
        ));
    }
    let lower = field.to_ascii_lowercase();
    if let Some((_, correct)) = FIELD_ALIASES.iter().find(|(alias, _)| *alias == lower) {
        let example = if correct.contains(' ') {
            "request:~text or response:~text".into()
        } else {
            field_example(correct)
        };
        return query_error(format!(
            "unknown filter field: {field}; use {correct}. Example: {example}"
        ));
    }
    let closest = closest_field(&lower)
        .map(|correct| format!("did you mean {correct}? "))
        .unwrap_or_default();
    let value = match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    };
    let parameter = format!("{field}={value}")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    query_error(format!(
        "unknown filter field: {field}; {closest}For a URL parameter use query:~\"{parameter}\". Supported fields: {}",
        ALLOWED_FIELDS.join(", "),
    ))
}

/// The supported field within two edits of `field`, for typos such as `stauts`.
fn closest_field(field: &str) -> Option<&'static str> {
    if field.len() < 4 {
        return None;
    }
    ALLOWED_FIELDS
        .iter()
        .map(|candidate| (edit_distance(field, candidate), *candidate))
        .filter(|(distance, _)| *distance <= 2)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| candidate)
}

fn edit_distance(left: &str, right: &str) -> usize {
    let right = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    for (row, left_char) in left.chars().enumerate() {
        let mut current = vec![row + 1];
        for (column, right_char) in right.iter().enumerate() {
            let substitution = previous[column] + usize::from(left_char != *right_char);
            current.push(
                substitution
                    .min(previous[column + 1] + 1)
                    .min(current[column] + 1),
            );
        }
        previous = current;
    }
    previous[right.len()]
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
        "query" => "query",
        "url" => URL_SQL,
        "project_id" | "project" => "project_id",
        "label" => "exchange_id", // special-cased
        other => {
            return Err(query_error(format!("unsupported field {other}")));
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
    if is_body_field(field) {
        return compile_body_term(field, op, value, binds);
    }
    let c = col(field)?;
    match op {
        "eq" => {
            binds.push(value_as_string(field, value)?);
            Ok(format!("{c}=?{}", binds.len()))
        }
        "ne" => {
            binds.push(value_as_string(field, value)?);
            Ok(format!("{c}!=?{}", binds.len()))
        }
        "gt" => {
            binds.push(value_as_string(field, value)?);
            Ok(format!("{c}>?{}", binds.len()))
        }
        "gte" => {
            binds.push(value_as_string(field, value)?);
            Ok(format!("{c}>=?{}", binds.len()))
        }
        "lt" => {
            binds.push(value_as_string(field, value)?);
            Ok(format!("{c}<?{}", binds.len()))
        }
        "lte" => {
            binds.push(value_as_string(field, value)?);
            Ok(format!("{c}<=?{}", binds.len()))
        }
        "contains" => {
            binds.push(format!(
                "%{}%",
                escape_like(&value_as_string(field, value)?)
            ));
            Ok(format!("{c} LIKE ?{} ESCAPE '\\'", binds.len()))
        }
        "starts_with" => {
            binds.push(format!("{}%", escape_like(&value_as_string(field, value)?)));
            Ok(format!("{c} LIKE ?{} ESCAPE '\\'", binds.len()))
        }
        "ends_with" => {
            binds.push(format!("%{}", escape_like(&value_as_string(field, value)?)));
            Ok(format!("{c} LIKE ?{} ESCAPE '\\'", binds.len()))
        }
        "in" => {
            let arr = value.as_array().ok_or_else(|| in_value_error(field))?;
            if arr.is_empty() {
                return Ok("1=0".into());
            }
            let mut placeholders = Vec::new();
            for v in arr {
                binds.push(value_as_string(field, v)?);
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
        other => Err(query_error(format!("unsupported op {other}"))),
    }
}

/// `request` searches the request target, headers and decoded body; `response`
/// searches response headers and the decoded body. Both are contains searches,
/// so `request:text` and `request:text*` search the same way as `request:~text`.
fn compile_body_term(
    side: &str,
    op: &str,
    value: &serde_json::Value,
    binds: &mut Vec<String>,
) -> DomainResult<String> {
    if !matches!(op, "contains" | "eq" | "starts_with" | "ends_with") {
        return Err(query_error(format!(
            "{side} supports only text searches; use {side}:~text"
        )));
    }
    let value = value_as_string(side, value)?;
    binds.push(format!("%{}%", escape_like(&value)));
    let like_index = binds.len();
    binds.push(value);
    let body_index = binds.len();
    let (target, body_column, side_code) = if side == "request" {
        (
            format!(
                "method LIKE ?{like_index} ESCAPE '\\' \
                 OR scheme LIKE ?{like_index} ESCAPE '\\' \
                 OR authority LIKE ?{like_index} ESCAPE '\\' \
                 OR path LIKE ?{like_index} ESCAPE '\\' \
                 OR COALESCE(query, '') LIKE ?{like_index} ESCAPE '\\' \
                 OR "
            ),
            "request_body_id",
            0,
        )
    } else {
        (String::new(), "response_body_id", 1)
    };
    // Each distinct name and value is matched once, then rows are checked by id.
    // Bodies are searched through the same side's Content-Encoding, in header order.
    let content_encoding = format!(
        "(SELECT group_concat(CAST(ev.value AS TEXT), ', ' ORDER BY ce.ordinal) \
            FROM message_header_rows ce \
            JOIN header_values ev ON ev.id=ce.value_id \
           WHERE ce.project_id=exchanges.project_id \
             AND ce.exchange_id=exchanges.exchange_id \
             AND ce.side={side_code} \
             AND ce.name_id IN (SELECT id FROM header_names \
                                WHERE lower(name)='content-encoding'))"
    );
    Ok(format!(
        "({target}EXISTS (SELECT 1 FROM message_header_rows mh \
                     WHERE mh.project_id=exchanges.project_id \
                       AND mh.exchange_id=exchanges.exchange_id \
                       AND mh.side={side_code} \
                       AND (mh.name_id IN (SELECT id FROM header_names \
                                           WHERE name LIKE ?{like_index} ESCAPE '\\') \
                            OR mh.value_id IN (SELECT id FROM header_values \
                                               WHERE CAST(value AS TEXT) LIKE ?{like_index} ESCAPE '\\'))) \
          OR EXISTS (SELECT 1 FROM bodies b \
                     WHERE b.id=exchanges.{body_column} \
                       AND huntproxy_body_contains(b.codec, b.content, ?{body_index}, \
                                                   {content_encoding})))"
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
            binds.push(value_as_string("label", value)?);
            let exists = format!("{prefix} AND l.name=?{})", binds.len());
            Ok(if op == "ne" {
                format!("NOT ({exists})")
            } else {
                exists
            })
        }
        "contains" | "starts_with" | "ends_with" => {
            let value = escape_like(&value_as_string("label", value)?);
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
                .ok_or_else(|| in_value_error("label"))?;
            if values.is_empty() {
                return Ok("1=0".into());
            }
            let mut placeholders = Vec::with_capacity(values.len());
            for value in values {
                binds.push(value_as_string("label", value)?);
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
        _ => Err(query_error(format!(
            "operator {op} is not supported for label; use eq, ne, contains, starts_with, ends_with, in, or exists. Text example: label:reviewed"
        ))),
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn value_as_string(field: &str, v: &serde_json::Value) -> DomainResult<String> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Null => Ok(String::new()),
        _ => Err(query_error(format!(
            "unsupported filter value type for {field}; use a string, number, boolean, or null (in requires an array of these values). Text example: {}",
            field_example(field),
        ))),
    }
}

fn in_value_error(field: &str) -> DomainError {
    query_error(format!(
        "in operator requires an array for {field}; JSON example: {{\"field\":\"{field}\",\"op\":\"in\",\"value\":[\"first\",\"second\"]}}. Text queries use OR: {field}:first OR {field}:second"
    ))
}

/// Small text syntax: `host:example.com method:GET status>=400`.
/// Bare words search common summary fields; `field:~value` means contains.
/// `AND`, `OR`, `NOT`, parentheses, and quoted values are supported.
pub fn parse_text_query(input: &str) -> DomainResult<FilterNode> {
    if input.len() > MAX_INPUT_LEN {
        return Err(query_error(format!(
            "filter text too long; use at most {MAX_INPUT_LEN} bytes"
        )));
    }
    let input = input.trim();
    if input.is_empty() {
        return Ok(FilterNode::And { and: vec![] });
    }
    let tokens = match tokenize_query(input) {
        // Agents often send JSON-escaped quotes (`path:~\"value\"`); read
        // `\"` as `"` before reporting the unterminated quote.
        Err(error) if input.contains("\\\"") => {
            tokenize_query(&input.replace("\\\"", "\"")).map_err(|_| error)?
        }
        tokens => tokens?,
    };
    QueryParser::new(tokens).parse()
}

/// Renders `node` in the text syntax accepted by [`parse_text_query`], for
/// messages that point at one term of a query.
pub fn filter_to_text(node: &FilterNode) -> String {
    let join = |nodes: &[FilterNode], separator: &str| {
        nodes
            .iter()
            .map(filter_to_text)
            .collect::<Vec<_>>()
            .join(separator)
    };
    if let Some(word) = bare_word(node) {
        return quote_value(&text_value(word));
    }
    match node {
        FilterNode::And { and } => format!("({})", join(and, " ")),
        FilterNode::Or { or } => format!("({})", join(or, " OR ")),
        FilterNode::Not { not } => format!("NOT {}", filter_to_text(not)),
        FilterNode::Term { field, op, value } => {
            if let serde_json::Value::Array(values) = value {
                let alternatives = values
                    .iter()
                    .map(|value| format!("{field}:{}", quote_value(&text_value(value))))
                    .collect::<Vec<_>>();
                return format!("({})", alternatives.join(" OR "));
            }
            let text = quote_value(&text_value(value));
            match op.as_str() {
                "ne" => format!("{field}!={text}"),
                "gt" => format!("{field}>{text}"),
                "gte" => format!("{field}>={text}"),
                "lt" => format!("{field}<{text}"),
                "lte" => format!("{field}<={text}"),
                "contains" => format!("{field}:~{text}"),
                "starts_with" => format!("{field}:{text}*"),
                "ends_with" => format!("{field}:*{text}"),
                "exists" if value.as_bool() == Some(false) => format!("NOT {field}:*"),
                "exists" => format!("{field}:*"),
                _ => format!("{field}:{text}"),
            }
        }
    }
}

fn text_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// `value` as one token: quoted when it holds spaces, parentheses or quotes.
fn quote_value(value: &str) -> String {
    if !value.is_empty()
        && !value
            .chars()
            .any(|character| character.is_whitespace() || "()\"\\".contains(character))
    {
        return value.to_owned();
    }
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
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
    // Opened by an over-escaped `\"` (agents JSON-escape quotes twice); in such
    // a value `\"` closes the quote too.
    let mut opened_escaped = false;
    let mut escaped = false;
    let flush = |current: &mut String, tokens: &mut Vec<QueryToken>| {
        if !current.is_empty() {
            tokens.push(QueryToken::Text(std::mem::take(current)));
        }
    };
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && characters.peek() == Some(&'"') {
            if !quoted && (current.is_empty() || current.ends_with([':', '~', '=', '>', '<'])) {
                characters.next();
                quoted = true;
                opened_escaped = true;
                continue;
            }
            if quoted && opened_escaped {
                characters.next();
                quoted = false;
                opened_escaped = false;
                continue;
            }
        }
        if quoted && character == '\\' {
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            opened_escaped = false;
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
        return Err(query_error(
            "unterminated quote in history filter; close the double quote. Example: path:~\"monthly report\"; escape a literal quote as \\\"",
        ));
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
            return Err(query_error(
                "unexpected token in history filter; check matching parentheses. Example: (method:GET OR method:POST) status>=400",
            ));
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
                query_error(format!("filter parse error at `{text}`: {error}"))
            }),
            Some(QueryToken::LeftParen) => {
                let node = self.parse_or()?;
                match self.next() {
                    Some(QueryToken::RightParen) => Ok(node),
                    _ => Err(query_error(
                        "missing closing parenthesis in history filter; close each group with `)`. Example: (method:GET OR method:POST) status>=400",
                    )),
                }
            }
            Some(QueryToken::RightParen) => {
                Err(query_error(
                    "unexpected closing parenthesis; groups must contain a term and match `(` with `)`. Example: (method:GET OR method:POST)",
                ))
            }
            None => Err(query_error(
                "missing term in history filter; AND, OR and NOT require a following term. Example: method:GET OR method:POST",
            )),
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
    // `field=value` for a known field; any other `a=b` stays a bare word.
    if let Some((field, rest)) = part
        .split_once('=')
        .filter(|(field, _)| ALLOWED_FIELDS.contains(field))
    {
        return parse_one_term(&format!("{field}:{rest}"));
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
        or: BARE_WORD_FIELDS
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
        assert!(uses_body_search(&filter));
    }

    #[test]
    fn only_request_and_response_terms_are_classified_as_full_body_searches() {
        let ordinary = parse_text_query("host:example.com method:POST query:~a url:~b").unwrap();
        assert!(!uses_body_search(&ordinary));

        let nested = parse_text_query("NOT (status:404 OR request:~needle)").unwrap();
        assert!(uses_body_search(&nested));
        assert!(uses_body_search(
            &parse_text_query("response:~needle").unwrap()
        ));
    }

    #[test]
    fn json_escaped_quotes_are_read_as_quotes_when_the_query_would_not_tokenize() {
        for (input, expected) in [
            (r#"path:~\"monthly report\""#, vec!["%monthly report%"]),
            (r#"path:~\"a\" method:GET"#, vec!["%a%", "GET"]),
            // Escaped opening quote with a plain closing quote.
            (r#"path:~\"api/v2" method:POST"#, vec!["%api/v2%", "POST"]),
            (r#"path:~\"api/v2\" method:POST"#, vec!["%api/v2%", "POST"]),
            (r#"host:\"a.test" status>\"400""#, vec!["a.test", "400"]),
            (
                r#"request:~\"monthly report""#,
                vec!["%monthly report%", "monthly report"],
            ),
            // An escaped quote inside a plainly quoted value keeps its meaning.
            (r#"path:~"say \"hi\"""#, vec![r#"%say "hi"%"#]),
            (r#"path:~"a \"quoted\" word""#, vec![r#"%a "quoted" word%"#]),
            (r#"path:~"a\""#, vec!["%a%"]),
        ] {
            let (_, binds) = filter_to_sql(&parse_text_query(input).unwrap()).unwrap();
            assert_eq!(binds, expected, "{input}");
        }
        let error = parse_text_query(r#"path:~\"open"#).unwrap_err();
        assert!(error.to_string().contains("unterminated quote"), "{error}");
    }

    #[test]
    fn request_and_response_accept_any_text_operator_as_contains() {
        for input in [
            "request:token",
            "request=token",
            "request:token*",
            "request:*token",
            "request:~token",
        ] {
            let (sql, binds) = filter_to_sql(&parse_text_query(input).unwrap()).unwrap();
            assert!(sql.contains("request_body_id"), "{input}");
            assert_eq!(binds, ["%token%", "token"], "{input}");
        }
        let (sql, binds) = filter_to_sql(&parse_text_query("response:~secret").unwrap()).unwrap();
        assert!(sql.contains("mh.side=1"));
        assert!(sql.contains("exchanges.response_body_id"));
        assert!(!sql.contains("method LIKE"));
        assert_eq!(binds, ["%secret%", "secret"]);
        for input in ["request>1", "response!=x"] {
            let error = filter_to_sql(&parse_text_query(input).unwrap()).unwrap_err();
            assert!(error.to_string().contains("only text searches"), "{error}");
        }
    }

    #[test]
    fn query_url_and_project_fields_compile_to_columns() {
        for (input, sql_part, bind) in [
            (r#"query:~"id=5""#, "query LIKE", "%id=5%"),
            ("url:~/api/items?x", "'://'", "%/api/items?x%"),
            ("project_id:7", "project_id=", "7"),
            ("project:7", "project_id=", "7"),
            ("host=example.com", "host=", "example.com"),
        ] {
            let (sql, binds) = filter_to_sql(&parse_text_query(input).unwrap()).unwrap();
            assert!(sql.contains(sql_part), "{input}: {sql}");
            assert_eq!(binds, [bind], "{input}");
        }
        // `a=b` with an unknown left side is still a bare word.
        let bare = parse_text_query("token=abc").unwrap();
        assert_eq!(bare_word(&bare), Some(&serde_json::json!("token=abc")));
    }

    #[test]
    fn bare_words_count_as_one_term_each() {
        let words = (0..MAX_TERMS)
            .map(|index| format!("word{index}"))
            .collect::<Vec<_>>();
        let filter = parse_text_query(&words.join(" OR ")).unwrap();
        filter_to_sql(&filter).unwrap();
        let filter = parse_text_query(&format!("{} OR 404", words.join(" OR "))).unwrap();
        let error = filter_to_sql(&filter).unwrap_err();
        assert!(error.to_string().contains("too many filter terms"));
    }

    #[test]
    fn unknown_fields_name_the_fix() {
        let error = |input: &str| {
            filter_to_sql(&parse_text_query(input).unwrap())
                .unwrap_err()
                .to_string()
        };
        let message = error("redirect_uri:https://x.test");
        assert!(
            message.contains(r#"query:~"redirect_uri=https://x.test""#),
            "{message}"
        );
        assert!(message.contains("Supported fields: exchange_id"));
        assert!(error("stauts:200").contains("did you mean status?"));
        assert!(error("response_body:~x").contains("use response."));
        let message = error("content_type:json");
        assert!(message.contains("use mime"), "{message}");
        assert!(!message.contains("Supported fields"), "{message}");
        assert!(error("body:~x").contains("request:~text or response:~text"));
    }

    #[test]
    fn filter_text_round_trips_through_the_parser() {
        for input in [
            "path:/foo",
            "path:~\"monthly report\"",
            "status>=400",
            "status!=404",
            "time<2026-10-12T00:00:00Z",
            "path:/api/*",
            "path:*.js",
            "javascript",
            "NOT host:a.test",
            "(method:GET OR method:POST)",
            r#"query:~"q=\"x\"""#,
        ] {
            let node = parse_text_query(input).unwrap();
            let text = filter_to_text(&node);
            assert_eq!(text, input);
            let reparsed = parse_text_query(&text).unwrap();
            assert_eq!(
                filter_to_sql(&reparsed).unwrap(),
                filter_to_sql(&node).unwrap(),
                "{input}"
            );
        }
    }

    #[test]
    fn malformed_boolean_queries_are_rejected() {
        assert!(parse_text_query("method:PUT OR").is_err());
        assert!(parse_text_query("(method:PUT").is_err());
        assert!(parse_text_query(r#"request:~"unfinished"#).is_err());
    }

    #[test]
    fn colon_comparison_errors_give_a_valid_field_specific_correction() {
        for (field, value) in [
            ("time", "2026-10-12T00:00:00Z"),
            ("status", "400"),
            ("duration", "1000"),
            ("request_size", "1024"),
            ("response_size", "1024"),
        ] {
            for op in [">", ">=", "<", "<=", "!="] {
                let invalid = parse_text_query(&format!("{field}:{op}{value}")).unwrap();
                let error = filter_to_sql(&invalid).unwrap_err();
                assert_eq!(error.code(), crate::domain::ErrorCode::InvalidArgument);
                let envelope = crate::domain::ErrorEnvelope::from(&error);
                assert_eq!(envelope.details.as_ref().unwrap()["kind"], "history_query");
                assert_eq!(
                    envelope.details.as_ref().unwrap()["syntax"],
                    HISTORY_QUERY_SYNTAX
                );
                let message = error.to_string();
                assert!(message.contains("remove the colon"), "{message}");
                assert!(message.contains(&format!("{field}{op}VALUE")), "{message}");
                let corrected = parse_text_query(&format!("{field}{op}{value}")).unwrap();
                let (_, binds) = filter_to_sql(&corrected).unwrap();
                assert_eq!(binds, [value]);
            }
        }
    }

    #[test]
    fn unsupported_fields_operators_and_value_shapes_explain_accepted_forms() {
        for (field, expected) in [
            ("status_code", "status>=400"),
            ("started_at", "time>2026-10-12T00:00:00Z"),
            ("not_a_field", "Supported fields: exchange_id, host"),
        ] {
            let node = term(field, "eq", "value");
            assert!(filter_to_sql(&node)
                .unwrap_err()
                .to_string()
                .contains(expected));
        }
        assert!(filter_to_sql(&term("status", "between", "400"))
            .unwrap_err()
            .to_string()
            .contains("Text example: status>=400"));
        assert!(filter_to_sql(&term("request", "gt", "text"))
            .unwrap_err()
            .to_string()
            .contains("request:~text"));
        assert!(filter_to_sql(&term("label", "gt", "reviewed"))
            .unwrap_err()
            .to_string()
            .contains("label:reviewed"));
        for field in ["host", "label"] {
            assert!(filter_to_sql(&term(field, "in", "first"))
                .unwrap_err()
                .to_string()
                .contains(&format!("{field}:first OR {field}:second")));
        }
        let bad_value = FilterNode::Term {
            field: "status".into(),
            op: "eq".into(),
            value: serde_json::json!({"value": 400}),
        };
        assert!(filter_to_sql(&bad_value)
            .unwrap_err()
            .to_string()
            .contains("for status"));
    }

    #[test]
    fn syntax_failures_explain_quotes_groups_and_missing_operands() {
        for (input, expected) in [
            (r#"path:~"monthly report"#, "close the double quote"),
            ("(method:GET", "close each group"),
            ("method:GET)", "matching parentheses"),
            ("()", "groups must contain a term"),
            ("method:GET OR", "require a following term"),
            ("NOT", "require a following term"),
        ] {
            let error = parse_text_query(input).unwrap_err();
            assert_eq!(error.code(), crate::domain::ErrorCode::InvalidArgument);
            assert!(error.to_string().contains(expected), "{input}: {error}");
            assert!(error.to_string().contains("Example:"));
        }
    }

    #[test]
    fn documented_queries_keep_exact_bind_values_and_boolean_precedence() {
        for (input, expected) in [
            (
                "host:example.com method:GET status>=400",
                vec!["example.com", "GET", "400"],
            ),
            (r#"path:~"monthly report""#, vec!["%monthly report%"]),
            (
                r#"request:~"monthly report""#,
                vec!["%monthly report%", "monthly report"],
            ),
            (
                "time>2026-10-12T00:00:00Z time<=2026-10-13T00:00:00Z",
                vec!["2026-10-12T00:00:00Z", "2026-10-13T00:00:00Z"],
            ),
            ("duration>=1000 response_size>1024", vec!["1000", "1024"]),
            (
                "(status:200 OR status:304) NOT path:~.js",
                vec!["200", "304", "%.js%"],
            ),
            ("path:/api/*", vec!["/api/%"]),
            ("path:*.js", vec!["%.js"]),
            ("path:*report*", vec!["%report%"]),
            // These permissive forms already compile; diagnostic changes must not narrow them.
            ("status>=many", vec!["many"]),
            (r#"path:"001""#, vec!["1"]),
            (r#"path:"*monthly*""#, vec!["%monthly%"]),
            (
                "host:example.com and method:GET",
                vec!["example.com", "GET"],
            ),
        ] {
            let filter = parse_text_query(input).unwrap();
            let (_, binds) = filter_to_sql(&filter).unwrap();
            assert_eq!(binds, expected, "{input}");
        }
        let filter = parse_text_query("host:example.com OR method:GET NOT status:404").unwrap();
        let (sql, binds) = filter_to_sql(&filter).unwrap();
        assert_eq!(sql, "(host=?1 OR (method=?2 AND NOT (status_code=?3)))");
        assert_eq!(binds, ["example.com", "GET", "404"]);
        let (sql, binds) = filter_to_sql(&parse_text_query("").unwrap()).unwrap();
        assert_eq!(sql, "1=1");
        assert!(binds.is_empty());
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
