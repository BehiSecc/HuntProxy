//! MCP-only reads of saved exchanges. Every result is built to fit
//! [`MAX_OUTPUT_BYTES`] with an exact continuation, so the generic safety net
//! in `tool_call_result` should never have to cut it. The REST API and web UI
//! keep the full serde shapes from `crate::domain`.

use super::budget::{escaped_len, json_len, rows_that_fit, water_level, MAX_OUTPUT_BYTES};
use super::require_project_id;
use super::view::exchange_row;
use crate::app::{AppState, PreparedBody};
use crate::compare::{BodyComparison, ExchangeComparison, HeaderComparison, ValueChange};
use crate::domain::*;
use crate::history::ResponseDiff;
use crate::policy::PresentationOptions;
use crate::reply::ReplySendResult;
use base64::Engine as _;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::path::Path;

const DEFAULT_INLINE_BODY_BYTES: u64 = 4096;
pub(crate) const MAX_INLINE_BODY_BYTES: u64 = 16_384;
pub(crate) const MAX_BATCH_IDS: usize = 20;
/// Share a batch body keeps before trailing exchanges move to `not_returned`.
const MIN_SHARED_BODY_BYTES: usize = 256;
pub(super) const DEFAULT_PAGE_BYTES: u64 = 16_384;
pub(crate) const MAX_PAGE_BYTES: u64 = 1024 * 1024;
const DEFAULT_CONTEXT_BYTES: u64 = 160;
pub(crate) const MAX_CONTEXT_BYTES: u64 = 2_000;
/// `match_count` stops here and reports `match_count_capped`.
const MAX_COUNTED_MATCHES: usize = 10_000;
/// Matches rendered before fitting to the budget.
const MAX_LISTED_MATCHES: usize = 200;
/// Header values in an oversized comparison are cut to this many bytes.
const COMPARE_VALUE_BYTES: usize = 256;
/// Retries when a rendered result still overshoots the budget.
const MAX_FIT_ATTEMPTS: usize = 4;

/// Representation and provenance values that most captures share.
const DEFAULT_PROVENANCE: [(&str, &str); 4] = [
    ("header_representation", "semantic"),
    ("body_representation", "semantic_encoded"),
    ("cache_provenance", "none"),
    ("transport_provenance", "protocol_profile_only"),
];

fn present<'a>(args: &'a Value, key: &str) -> Option<&'a Value> {
    args.get(key).filter(|value| !value.is_null())
}

pub(super) fn optional_u64(args: &Value, key: &str) -> DomainResult<Option<u64>> {
    present(args, key)
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                DomainError::invalid(format!("{key} must be a non-negative integer"))
            })
        })
        .transpose()
}

fn optional_bool(args: &Value, key: &str) -> DomainResult<Option<bool>> {
    present(args, key)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| DomainError::invalid(format!("{key} must be a boolean")))
        })
        .transpose()
}

pub(super) fn to_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn required_exchange_id(args: &Value) -> DomainResult<ExchangeId> {
    present(args, "exchange_id")
        .and_then(Value::as_i64)
        .map(ExchangeId)
        .ok_or_else(|| DomainError::invalid("exchange_id required"))
}

fn to_json<T: Serialize>(value: &T) -> DomainResult<Value> {
    serde_json::to_value(value)
        .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))
}

fn side_name(side: MessageSide) -> &'static str {
    match side {
        MessageSide::Request => "request",
        MessageSide::Response => "response",
    }
}

/// Escaped JSON length of `text` without its quotes.
fn escaped_str_len(text: &str) -> usize {
    text.chars().map(escaped_len).sum()
}

/// Byte length of the longest char-aligned prefix of `text` whose escaped
/// JSON length is at most `max_escaped`.
fn escaped_prefix(text: &str, max_escaped: usize) -> usize {
    let mut used = 0;
    for (index, ch) in text.char_indices() {
        used += escaped_len(ch);
        if used > max_escaped {
            return index;
        }
    }
    text.len()
}

/// Byte length of the longest prefix of `bytes` whose lossy UTF-8 rendering
/// fits in `max_escaped` escaped JSON bytes, cut only between characters or
/// invalid sequences so the prefix renders exactly as the whole does.
fn lossy_prefix(bytes: &[u8], max_escaped: usize) -> usize {
    let mut used = 0;
    let mut kept = 0;
    for chunk in bytes.utf8_chunks() {
        for ch in chunk.valid().chars() {
            used += escaped_len(ch);
            if used > max_escaped {
                return kept;
            }
            kept += ch.len_utf8();
        }
        if !chunk.invalid().is_empty() {
            used += escaped_len(char::REPLACEMENT_CHARACTER);
            if used > max_escaped {
                return kept;
            }
            kept += chunk.invalid().len();
        }
    }
    kept
}

fn is_continuation(byte: u8) -> bool {
    byte & 0xC0 == 0x80
}

/// Moves a page end inside `data` back to the start of a UTF-8 character it
/// would split, unless that would empty the page.
fn utf8_floor(data: &[u8], start: usize, end: usize) -> usize {
    if end >= data.len() || !is_continuation(data[end]) {
        return end;
    }
    let mut lead = end;
    while lead > start && end - lead < 3 && is_continuation(data[lead]) {
        lead -= 1;
    }
    if lead > start && data[lead] >= 0xC0 {
        lead
    } else {
        end
    }
}

// ---------------------------------------------------------------------------
// exchange_get
// ---------------------------------------------------------------------------

/// A body as exchange_get inlines it.
enum InlineBody {
    /// Valid UTF-8; `prefix` is at most the requested inline bytes.
    Text {
        prefix: String,
        total: usize,
        hash: String,
    },
    /// Rendered as is: binary bodies and bodies that could not be prepared.
    Fixed(Value),
}

struct LoadedExchange {
    head: Map<String, Value>,
    bodies: Vec<(&'static str, InlineBody)>,
}

enum Entry {
    Loaded(LoadedExchange),
    Failed(Value),
}

pub(crate) async fn exchange_get(state: &AppState, args: &Value) -> DomainResult<Value> {
    let project_id = require_project_id(args)?;
    let body_bytes = to_usize(
        optional_u64(args, "body_bytes")?
            .unwrap_or(DEFAULT_INLINE_BODY_BYTES)
            .min(MAX_INLINE_BODY_BYTES),
    );
    match (present(args, "exchange_id"), present(args, "exchange_ids")) {
        (Some(_), None) => {
            let id = required_exchange_id(args)?;
            let loaded = load_exchange(state, project_id, id, body_bytes).await?;
            Ok(fit_exchanges(
                vec![Entry::Loaded(loaded)],
                Vec::new(),
                false,
            ))
        }
        (None, Some(ids)) => {
            let ids = ids
                .as_array()
                .filter(|ids| (1..=MAX_BATCH_IDS).contains(&ids.len()))
                .and_then(|ids| ids.iter().map(Value::as_i64).collect::<Option<Vec<_>>>())
                .ok_or_else(|| {
                    DomainError::invalid(format!(
                        "exchange_ids must be 1 to {MAX_BATCH_IDS} integer exchange ids"
                    ))
                })?;
            let mut entries = Vec::with_capacity(ids.len());
            for &id in &ids {
                entries.push(
                    match load_exchange(state, project_id, ExchangeId(id), body_bytes).await {
                        Ok(loaded) => Entry::Loaded(loaded),
                        Err(error) => {
                            Entry::Failed(json!({ "exchange_id": id, "error": error.to_string() }))
                        }
                    },
                );
            }
            Ok(fit_exchanges(entries, ids, true))
        }
        _ => Err(DomainError::invalid(
            "pass exactly one of exchange_id or exchange_ids",
        )),
    }
}

fn header_lines(headers: &[PresentedHeader]) -> Value {
    headers
        .iter()
        .map(|header| Value::String(format!("{}: {}", header.name, header.value)))
        .collect()
}

async fn load_exchange(
    state: &AppState,
    project_id: ProjectId,
    exchange_id: ExchangeId,
    body_bytes: usize,
) -> DomainResult<LoadedExchange> {
    let detail = state
        .db
        .get_exchange_detail(project_id, exchange_id, PresentationOptions::default())
        .await?;
    let annotation = state.db.get_annotation(project_id, exchange_id).await?;
    let applied_rules = state
        .db
        .list_exchange_request_rules(project_id, exchange_id)
        .await?;

    let Value::Object(mut head) = exchange_row(&detail.summary) else {
        unreachable!("exchange rows are JSON objects");
    };
    head.insert("protocol".into(), json!(detail.protocol));
    let provenance = [
        to_json(&detail.header_representation)?,
        to_json(&detail.body_representation)?,
        to_json(&detail.cache_provenance)?,
        to_json(&detail.summary.transport_provenance)?,
    ];
    for ((key, default), value) in DEFAULT_PROVENANCE.into_iter().zip(provenance) {
        if !value.is_null() && value != default {
            head.insert(key.into(), value);
        }
    }
    for (key, headers) in [
        ("request_headers", &detail.request_headers),
        ("response_headers", &detail.response_headers),
    ] {
        if !headers.is_empty() {
            head.insert(key.into(), header_lines(headers));
        }
    }
    for (key, count) in [
        ("redacted_count", detail.redacted_count),
        ("noisy_hidden_count", detail.noisy_hidden_count),
    ] {
        if count > 0 {
            head.insert(key.into(), json!(count));
        }
    }
    if let Some(annotation) = annotation {
        // display_title and labels are already in the row.
        let mut compact = Map::new();
        if let Some(note) = annotation.note.filter(|note| !note.is_empty()) {
            compact.insert("note".into(), json!(note));
        }
        compact.insert("revision".into(), json!(annotation.revision));
        head.insert("annotation".into(), Value::Object(compact));
    }
    if !applied_rules.is_empty() {
        head.insert("applied_request_rules".into(), to_json(&applied_rules)?);
    }
    // parent_exchange_id is already in the row.
    let mut lineage = to_json(&detail.lineage)?;
    if let Some(members) = lineage.as_object_mut() {
        members.retain(|key, value| key != "parent_exchange_id" && !value.is_null());
        if !members.is_empty() {
            head.insert("lineage".into(), lineage);
        }
    }

    let mut bodies = Vec::new();
    if body_bytes > 0 {
        for (key, side, stored_hash) in [
            (
                "request_body",
                MessageSide::Request,
                &detail.request_body_hash,
            ),
            (
                "response_body",
                MessageSide::Response,
                &detail.response_body_hash,
            ),
        ] {
            let body = match state
                .prepared_body(project_id, exchange_id, side, false)
                .await
            {
                Ok(None) => continue,
                Ok(Some(body)) if body.data.is_empty() => continue,
                Ok(Some(body)) => {
                    let hash = stored_hash.clone().unwrap_or_else(|| body.sha256.clone());
                    inline_body(&body, body_bytes, hash)
                }
                Err(error) => InlineBody::Fixed(json!({ "error": error.to_string() })),
            };
            bodies.push((key, body));
        }
    }
    Ok(LoadedExchange { head, bodies })
}

fn inline_body(body: &PreparedBody, body_bytes: usize, hash: String) -> InlineBody {
    let total = body.data.len();
    match std::str::from_utf8(&body.data) {
        Ok(text) => {
            let mut end = body_bytes.min(total);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            InlineBody::Text {
                prefix: text[..end].to_owned(),
                total,
                hash,
            }
        }
        Err(_) => InlineBody::Fixed(json!({ "binary": true, "total": total, "hash": hash })),
    }
}

/// Renders a text body cut to `cap` escaped bytes; `None` renders the worst
/// case (empty text with every continuation field) for budgeting.
fn render_text_body(prefix: &str, total: usize, hash: &str, cap: Option<usize>) -> Value {
    let end = cap.map_or(0, |cap| escaped_prefix(prefix, cap));
    if cap.is_some() && end == total {
        return json!({ "text": prefix, "total": total });
    }
    json!({
        "text": &prefix[..end],
        "total": total,
        "truncated": true,
        "next_offset": if cap.is_some() { end } else { total },
        "hash": hash,
    })
}

/// Renders one exchange. `caps` holds one escaped allowance per text body in
/// order; `None` renders worst-case body stubs.
fn render_exchange(loaded: &LoadedExchange, caps: Option<&[usize]>) -> Value {
    let mut object = loaded.head.clone();
    let mut text_index = 0;
    for (key, body) in &loaded.bodies {
        let value = match body {
            InlineBody::Text {
                prefix,
                total,
                hash,
            } => {
                let cap = caps.map(|caps| caps[text_index]);
                text_index += 1;
                render_text_body(prefix, *total, hash, cap)
            }
            InlineBody::Fixed(value) => value.clone(),
        };
        object.insert((*key).into(), value);
    }
    Value::Object(object)
}

fn text_wants(entry: &Entry) -> Vec<usize> {
    match entry {
        Entry::Loaded(loaded) => loaded
            .bodies
            .iter()
            .filter_map(|(_, body)| match body {
                InlineBody::Text { prefix, .. } => Some(escaped_str_len(prefix)),
                InlineBody::Fixed(_) => None,
            })
            .collect(),
        Entry::Failed(_) => Vec::new(),
    }
}

fn render_entry(entry: &Entry, caps: Option<&[usize]>) -> Value {
    match entry {
        Entry::Loaded(loaded) => render_exchange(loaded, caps),
        Entry::Failed(value) => value.clone(),
    }
}

fn assemble(
    entries: &[Entry],
    ids: &[i64],
    returned: usize,
    caps: Option<&[Vec<usize>]>,
    batch: bool,
) -> Value {
    let rendered = entries[..returned]
        .iter()
        .enumerate()
        .map(|(index, entry)| render_entry(entry, caps.map(|caps| caps[index].as_slice())))
        .collect::<Vec<_>>();
    if !batch {
        return rendered.into_iter().next().unwrap_or(Value::Null);
    }
    let mut result = json!({ "exchanges": rendered });
    if returned < ids.len() {
        result["not_returned"] = json!(ids[returned..]);
    }
    result
}

/// Shares the output budget across the inline bodies of `entries`: every text
/// body gets the same escaped allowance (smaller bodies keep their full size),
/// and trailing exchanges are listed in `not_returned` when even a small share
/// per body does not fit.
fn fit_exchanges(entries: Vec<Entry>, ids: Vec<i64>, batch: bool) -> Value {
    let wants = entries.iter().map(text_wants).collect::<Vec<_>>();
    let floor = |returned: usize| -> usize {
        wants[..returned]
            .iter()
            .flatten()
            .map(|want| (*want).min(MIN_SHARED_BODY_BYTES))
            .sum()
    };
    let mut returned = entries.len();
    while returned > 1
        && json_len(&assemble(&entries, &ids, returned, None, batch)) + floor(returned)
            > MAX_OUTPUT_BYTES
    {
        returned -= 1;
    }
    let fixed = json_len(&assemble(&entries, &ids, returned, None, batch));
    let all_wants = wants[..returned]
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    let mut available = MAX_OUTPUT_BYTES.saturating_sub(fixed);
    let mut result = Value::Null;
    for _ in 0..MAX_FIT_ATTEMPTS {
        let cap = water_level(&all_wants, available);
        let caps = wants[..returned]
            .iter()
            .map(|wants| wants.iter().map(|want| (*want).min(cap)).collect())
            .collect::<Vec<Vec<usize>>>();
        result = assemble(&entries, &ids, returned, Some(&caps), batch);
        let len = json_len(&result);
        if len <= MAX_OUTPUT_BYTES || available == 0 {
            break;
        }
        available = available.saturating_sub(len - MAX_OUTPUT_BYTES);
    }
    result
}

// ---------------------------------------------------------------------------
// exchange_body
// ---------------------------------------------------------------------------

pub(crate) async fn exchange_body(state: &AppState, args: &Value) -> DomainResult<Value> {
    let project_id = require_project_id(args)?;
    let exchange_id = required_exchange_id(args)?;
    let base64 = match present(args, "encoding").map(Value::as_str) {
        None | Some(Some("utf8")) => false,
        Some(Some("base64")) => true,
        Some(_) => return Err(DomainError::invalid("encoding must be utf8|base64")),
    };
    let side = match present(args, "side").map(Value::as_str) {
        None | Some(Some("response")) => MessageSide::Response,
        Some(Some("request")) => MessageSide::Request,
        Some(_) => return Err(DomainError::invalid("side must be request|response")),
    };
    let raw = optional_bool(args, "raw")?.unwrap_or(false);
    let offset = to_usize(optional_u64(args, "offset")?.unwrap_or(0));
    let max_bytes = to_usize(
        optional_u64(args, "max_bytes")?
            .unwrap_or(DEFAULT_PAGE_BYTES)
            .clamp(1, MAX_PAGE_BYTES),
    );
    let search = present(args, "search")
        .map(|value| {
            value
                .as_str()
                .filter(|needle| !needle.is_empty())
                .ok_or_else(|| DomainError::invalid("search must be a non-empty string"))
        })
        .transpose()?;
    let context_bytes = to_usize(
        optional_u64(args, "context_bytes")?
            .unwrap_or(DEFAULT_CONTEXT_BYTES)
            .min(MAX_CONTEXT_BYTES),
    );
    let save = optional_bool(args, "save")?.unwrap_or(false);
    if save && (search.is_some() || offset > 0) {
        return Err(DomainError::invalid(
            "save writes the whole body; omit search and offset",
        ));
    }
    if search.is_some() && base64 {
        return Err(DomainError::invalid(
            "search returns text context; omit encoding=base64",
        ));
    }

    let Some(body) = state
        .prepared_body(project_id, exchange_id, side, raw)
        .await?
    else {
        return Ok(json!({ "available": false, "total": 0 }));
    };
    if save {
        save_body(state, project_id, exchange_id, side, raw, &body).await
    } else if let Some(needle) = search {
        search_body(&body.data, offset, needle, context_bytes)
    } else {
        Ok(read_page(&body, offset, max_bytes, base64))
    }
}

/// The largest page of `body[offset..offset + max_bytes]` whose result fits
/// the output budget, with an exact `next_offset`.
fn read_page(body: &PreparedBody, offset: usize, max_bytes: usize, base64: bool) -> Value {
    read_bytes_page(&body.data, offset, max_bytes, base64, |page| {
        if body.decoded {
            page["decoded"] = json!(true);
            page["content_encoding"] = json!(body.content_encoding);
        }
        if body.raw_total != body.data.len() {
            page["raw_total"] = json!(body.raw_total);
        }
    })
}

/// The largest page of `data[offset..offset + max_bytes]` whose result,
/// including the fields `annotate` adds, fits the output budget, with an
/// exact `next_offset`.
pub(super) fn read_bytes_page(
    data: &[u8],
    offset: usize,
    max_bytes: usize,
    base64: bool,
    annotate: impl Fn(&mut Value),
) -> Value {
    let total = data.len();
    let start = offset.min(total);
    let mut end = start.saturating_add(max_bytes).min(total);
    if !base64 {
        end = utf8_floor(data, start, end);
    }
    let render = |end: usize, preview: String, worst_case: bool| -> Value {
        let truncated = worst_case || end < total;
        let mut page = json!({
            "total": total,
            "offset": offset,
            "length": end - start,
            "preview": preview,
            "truncated": truncated,
        });
        if truncated {
            page["next_offset"] = json!(if worst_case { total } else { end });
        }
        if base64 {
            page["encoding"] = json!("base64");
        }
        annotate(&mut page);
        page
    };
    let encode = |end: usize| -> String {
        let slice = &data[start..end];
        if base64 {
            base64::engine::general_purpose::STANDARD.encode(slice)
        } else {
            String::from_utf8_lossy(slice).into_owned()
        }
    };
    let mut room = MAX_OUTPUT_BYTES.saturating_sub(json_len(&render(end, String::new(), true)));
    let mut page = Value::Null;
    for _ in 0..MAX_FIT_ATTEMPTS {
        let fitted = if base64 {
            (room / 4 * 3).min(end - start)
        } else {
            lossy_prefix(&data[start..end], room)
        };
        let page_end = start + fitted;
        page = render(page_end, encode(page_end), false);
        let len = json_len(&page);
        if len <= MAX_OUTPUT_BYTES || room == 0 {
            break;
        }
        room = room.saturating_sub(len - MAX_OUTPUT_BYTES);
    }
    page
}

/// First ASCII case-insensitive occurrence of `needle` in `haystack` at or
/// after `from`.
fn find_ignore_ascii_case(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let last_start = haystack.len().checked_sub(needle.len())?;
    let (lower, upper) = (
        needle[0].to_ascii_lowercase(),
        needle[0].to_ascii_uppercase(),
    );
    let mut position = from;
    while position <= last_start {
        position += haystack[position..=last_start]
            .iter()
            .position(|&byte| byte == lower || byte == upper)?;
        if haystack[position..position + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(position);
        }
        position += 1;
    }
    None
}

fn match_context(data: &[u8], hit: usize, needle_len: usize, context_bytes: usize) -> String {
    let half = context_bytes / 2;
    let mut start = hit.saturating_sub(half);
    let mut end = hit
        .saturating_add(needle_len)
        .saturating_add(half)
        .min(data.len());
    while start < hit && is_continuation(data[start]) {
        start += 1;
    }
    while end > hit + needle_len && end < data.len() && is_continuation(data[end]) {
        end -= 1;
    }
    String::from_utf8_lossy(&data[start..end]).into_owned()
}

fn search_body(
    data: &[u8],
    offset: usize,
    needle: &str,
    context_bytes: usize,
) -> DomainResult<Value> {
    let needle = needle.as_bytes();
    let start = offset.min(data.len());
    let mut hits = Vec::new();
    let mut count = 0;
    let mut capped = false;
    let mut position = start;
    while let Some(hit) = find_ignore_ascii_case(data, needle, position) {
        if count == MAX_COUNTED_MATCHES {
            capped = true;
            break;
        }
        count += 1;
        if hits.len() < MAX_LISTED_MATCHES {
            hits.push(hit);
        }
        position = hit + needle.len();
    }
    let mut matches = hits
        .iter()
        .map(|&hit| {
            json!({
                "offset": hit,
                "context": match_context(data, hit, needle.len(), context_bytes),
            })
        })
        .collect::<Vec<_>>();
    let mut result = json!({
        "total": data.len(),
        "offset": start,
        "match_count": count,
        "matches": [],
        "next_offset": data.len(),
    });
    if capped {
        result["match_count_capped"] = json!(true);
    }
    // `rows_that_fit` counts the brackets that `"matches":[]` already holds.
    let room = MAX_OUTPUT_BYTES.saturating_sub(json_len(&result)) + 2;
    let kept = rows_that_fit(&matches, room)?;
    matches.truncate(kept);
    let object = result.as_object_mut().expect("search result is an object");
    if kept < count {
        object.insert("next_offset".into(), json!(hits[kept - 1] + needle.len()));
    } else {
        object.remove("next_offset");
    }
    object.insert("matches".into(), Value::Array(matches));
    Ok(result)
}

/// File extension for a saved body, from its MIME type.
fn body_extension(mime: Option<&str>) -> &'static str {
    let essence = mime
        .and_then(|mime| mime.split(';').next())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if essence.contains("json") {
        "json"
    } else if essence == "text/html" || essence.contains("xhtml") {
        "html"
    } else if essence.contains("javascript") || essence.contains("ecmascript") {
        "js"
    } else if essence == "text/css" {
        "css"
    } else if essence.contains("xml") {
        "xml"
    } else if essence.starts_with("text/") || essence == "application/x-www-form-urlencoded" {
        "txt"
    } else {
        "bin"
    }
}

async fn save_body(
    state: &AppState,
    project_id: ProjectId,
    exchange_id: ExchangeId,
    side: MessageSide,
    raw: bool,
    body: &PreparedBody,
) -> DomainResult<Value> {
    let raw = raw && side == MessageSide::Response;
    let extension = if raw {
        "bin"
    } else {
        let detail = state
            .db
            .get_exchange_detail(project_id, exchange_id, PresentationOptions::default())
            .await?;
        let mime = match side {
            MessageSide::Response => detail.summary.mime,
            MessageSide::Request => detail
                .request_headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-type"))
                .map(|header| header.value.clone()),
        };
        body_extension(mime.as_deref())
    };
    let path = state.config.export_dir.join(format!(
        "exchange_{}_{}_{}{}.{extension}",
        project_id.get(),
        exchange_id.get(),
        side_name(side),
        if raw { "_raw" } else { "" },
    ));
    // Fail closed: captured content is only written once the export is audited.
    state
        .db
        .audit(
            Some(project_id),
            "exchange_body_save",
            Some("mcp"),
            Some("exchange"),
            Some(&exchange_id.get().to_string()),
            json!({
                "side": side_name(side),
                "raw": raw,
                "path": path.display().to_string(),
                "bytes": body.data.len(),
            }),
        )
        .await?;
    write_export(&state.config.export_dir, &path, &body.data)?;
    Ok(json!({ "path": path.display().to_string(), "bytes": body.data.len() }))
}

fn write_export(export_dir: &Path, path: &Path, data: &[u8]) -> DomainResult<()> {
    crate::config::create_private_dir(export_dir)?;
    crate::config::write_private_file(path, data)
}

// ---------------------------------------------------------------------------
// evidence_export
// ---------------------------------------------------------------------------

pub(crate) async fn evidence_export(state: &AppState, args: &Value) -> DomainResult<Value> {
    let project_id = require_project_id(args)?;
    let exchange_id = required_exchange_id(args)?;
    let include_bodies = optional_bool(args, "include_bodies")?.unwrap_or(true);
    let detail = state
        .db
        .get_exchange_detail(project_id, exchange_id, PresentationOptions::default())
        .await?;
    let mut evidence = to_json(&detail)?;
    if include_bodies {
        for (key, side) in [
            ("request_body", MessageSide::Request),
            ("response_body", MessageSide::Response),
        ] {
            if let Some(body) = exported_body(state, project_id, exchange_id, side).await? {
                evidence[key] = body;
            }
        }
    }
    let data = serde_json::to_vec_pretty(&evidence)
        .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
    let path = state.config.export_dir.join(format!(
        "exchange_{}_{}.json",
        project_id.get(),
        exchange_id.get()
    ));
    // Fail closed: evidence is only written once the export is audited.
    state
        .db
        .audit(
            Some(project_id),
            "evidence_export",
            Some("mcp"),
            Some("exchange"),
            Some(&exchange_id.get().to_string()),
            json!({ "path": path.display().to_string(), "include_bodies": include_bodies }),
        )
        .await?;
    write_export(&state.config.export_dir, &path, &data)?;
    Ok(json!({ "path": path.display().to_string(), "bytes": data.len() }))
}

/// The presented body as exported: decoded like exchange_body, as `text` when
/// valid UTF-8 and `base64` otherwise. A response that cannot be decoded is
/// exported as captured with the `decode_error`.
async fn exported_body(
    state: &AppState,
    project_id: ProjectId,
    exchange_id: ExchangeId,
    side: MessageSide,
) -> DomainResult<Option<Value>> {
    let (body, decode_error) = match state
        .prepared_body(project_id, exchange_id, side, false)
        .await
    {
        Ok(body) => (body, None),
        Err(error) if side == MessageSide::Response => (
            state
                .prepared_body(project_id, exchange_id, side, true)
                .await?,
            Some(error.to_string()),
        ),
        Err(error) => return Err(error),
    };
    let Some(body) = body else {
        return Ok(None);
    };
    let mut exported = match std::str::from_utf8(&body.data) {
        Ok(text) => json!({ "bytes": body.data.len(), "text": text }),
        Err(_) => json!({
            "bytes": body.data.len(),
            "base64": base64::engine::general_purpose::STANDARD.encode(&body.data),
        }),
    };
    if body.decoded {
        exported["content_encoding"] = json!(body.content_encoding);
    }
    if let Some(error) = decode_error {
        exported["decode_error"] = json!(error);
    }
    Ok(Some(exported))
}

// ---------------------------------------------------------------------------
// exchange_compare
// ---------------------------------------------------------------------------

/// How much of an oversized comparison is kept.
#[derive(Clone, Copy, Default)]
struct CompareLimits {
    /// Escaped bytes of `text_diff` kept per side (request, response).
    diff_caps: [Option<usize>; 2],
    /// Bytes kept of each header value.
    value_cap: Option<usize>,
    /// Header change rows kept per side.
    header_rows: [Option<usize>; 2],
}

/// Compact comparison: only differences are listed and unchanged parts are
/// named in `unchanged`. Cut parts carry `text_diff_truncated`,
/// `values_truncated` or `headers_omitted`.
pub(crate) fn compare_view(comparison: &ExchangeComparison) -> DomainResult<Value> {
    let build = |limits: &CompareLimits| compare_value(comparison, limits);
    let full = build(&CompareLimits::default());
    if json_len(&full) <= MAX_OUTPUT_BYTES {
        return Ok(full);
    }
    let diffs = [
        &comparison.request.body.text_diff,
        &comparison.response.body.text_diff,
    ];
    let diff_wants = diffs.map(|diff| diff.as_deref().map_or(0, escaped_str_len));

    // Long text diffs are the usual cause; share the room between them.
    let mut limits = CompareLimits {
        diff_caps: [Some(0), Some(0)],
        ..CompareLimits::default()
    };
    let fixed = json_len(&build(&limits));
    if fixed <= MAX_OUTPUT_BYTES {
        let mut available = MAX_OUTPUT_BYTES - fixed;
        let mut result = full;
        for _ in 0..MAX_FIT_ATTEMPTS {
            let cap = water_level(&diff_wants, available);
            limits.diff_caps = diff_wants.map(|want| Some(want.min(cap)));
            result = build(&limits);
            let len = json_len(&result);
            if len <= MAX_OUTPUT_BYTES || available == 0 {
                break;
            }
            available = available.saturating_sub(len - MAX_OUTPUT_BYTES);
        }
        return Ok(result);
    }

    // Header changes dominate: drop the diffs, cut long values and keep a
    // prefix of each side's changed headers.
    limits.value_cap = Some(COMPARE_VALUE_BYTES);
    limits.header_rows = [Some(0), Some(0)];
    let fixed = json_len(&build(&limits));
    let sides = [&comparison.request.headers, &comparison.response.headers];
    let rows = sides.map(|headers| header_rows(headers, Some(COMPARE_VALUE_BYTES)));
    let row_wants = rows.each_ref().map(|rows| json_len(&json!(rows)));
    let cap = water_level(&row_wants, MAX_OUTPUT_BYTES.saturating_sub(fixed));
    for side in 0..2 {
        limits.header_rows[side] = Some(rows_that_fit(&rows[side], cap.min(row_wants[side]))?);
    }
    Ok(build(&limits))
}

fn compare_value(comparison: &ExchangeComparison, limits: &CompareLimits) -> Value {
    let request = &comparison.request;
    let response = &comparison.response;
    let mut request_view = Map::new();
    let mut unchanged = Vec::new();
    value_change(&mut request_view, &mut unchanged, "method", &request.method);
    value_change(&mut request_view, &mut unchanged, "url", &request.url);
    headers_change(
        &mut request_view,
        &mut unchanged,
        &request.headers,
        limits.value_cap,
        limits.header_rows[0],
    );
    body_change(
        &mut request_view,
        &mut unchanged,
        &request.body,
        limits.diff_caps[0],
    );
    finish_side(&mut request_view, unchanged);

    let mut response_view = Map::new();
    let mut unchanged = Vec::new();
    value_change(
        &mut response_view,
        &mut unchanged,
        "status",
        &response.status,
    );
    value_change(&mut response_view, &mut unchanged, "mime", &response.mime);
    value_change(
        &mut response_view,
        &mut unchanged,
        "duration_ms",
        &response.duration_ms,
    );
    headers_change(
        &mut response_view,
        &mut unchanged,
        &response.headers,
        limits.value_cap,
        limits.header_rows[1],
    );
    body_change(
        &mut response_view,
        &mut unchanged,
        &response.body,
        limits.diff_caps[1],
    );
    finish_side(&mut response_view, unchanged);

    json!({
        "left_exchange_id": comparison.left_exchange_id,
        "right_exchange_id": comparison.right_exchange_id,
        "request": request_view,
        "response": response_view,
    })
}

fn finish_side(view: &mut Map<String, Value>, unchanged: Vec<&'static str>) {
    if !unchanged.is_empty() {
        view.insert("unchanged".into(), json!(unchanged));
    }
}

fn value_change<T: Serialize + PartialEq>(
    view: &mut Map<String, Value>,
    unchanged: &mut Vec<&'static str>,
    key: &'static str,
    change: &ValueChange<T>,
) {
    if change.changed {
        view.insert(
            key.into(),
            json!({ "left": change.left, "right": change.right }),
        );
    } else {
        unchanged.push(key);
    }
}

fn cut_values(values: &[String], value_cap: Option<usize>) -> (Vec<String>, bool) {
    let mut cut = false;
    let values = values
        .iter()
        .map(|value| match value_cap {
            Some(cap) if value.len() > cap => {
                cut = true;
                let mut end = cap;
                while !value.is_char_boundary(end) {
                    end -= 1;
                }
                value[..end].to_owned()
            }
            _ => value.clone(),
        })
        .collect();
    (values, cut)
}

fn header_rows(headers: &HeaderComparison, value_cap: Option<usize>) -> Vec<Value> {
    headers
        .changes
        .iter()
        .map(|change| {
            let mut row = json!({ "name": change.name, "kind": change.kind });
            if change.sensitive {
                // Every value is the same placeholder, so only counts are useful.
                row["redacted"] = json!(true);
                for (key, count) in [
                    ("left_count", change.left_count),
                    ("right_count", change.right_count),
                ] {
                    if count > 0 {
                        row[key] = json!(count);
                    }
                }
                return row;
            }
            let mut any_cut = false;
            for (key, values) in [
                ("left", &change.left_values),
                ("right", &change.right_values),
            ] {
                if !values.is_empty() {
                    let (values, cut) = cut_values(values, value_cap);
                    any_cut |= cut;
                    row[key] = json!(values);
                }
            }
            if any_cut {
                row["values_truncated"] = json!(true);
            }
            row
        })
        .collect()
}

fn headers_change(
    view: &mut Map<String, Value>,
    unchanged: &mut Vec<&'static str>,
    headers: &HeaderComparison,
    value_cap: Option<usize>,
    rows_kept: Option<usize>,
) {
    if headers.noisy_hidden > 0 {
        view.insert("noisy_headers_hidden".into(), json!(headers.noisy_hidden));
    }
    if headers.changes.is_empty() {
        unchanged.push("headers");
        return;
    }
    let mut rows = header_rows(headers, value_cap);
    if let Some(kept) = rows_kept.filter(|kept| *kept < rows.len()) {
        view.insert("headers_omitted".into(), json!(rows.len() - kept));
        rows.truncate(kept);
    }
    view.insert("headers".into(), Value::Array(rows));
}

fn body_change(
    view: &mut Map<String, Value>,
    unchanged: &mut Vec<&'static str>,
    body: &BodyComparison,
    diff_cap: Option<usize>,
) {
    if body.equal == Some(true) && body.warnings.is_empty() {
        unchanged.push("body");
        return;
    }
    let mut out = Map::new();
    if let Some(equal) = body.equal {
        out.insert("equal".into(), json!(equal));
    }
    for (key, evidence) in [("left_length", &body.left), ("right_length", &body.right)] {
        if let Some(length) = evidence.length.filter(|_| evidence.present) {
            out.insert(key.into(), json!(length));
        }
    }
    if let Some(diff) = body.text_diff.as_deref().filter(|diff| !diff.is_empty()) {
        let end = match diff_cap {
            Some(cap) if cap < escaped_str_len(diff) => {
                let end = escaped_prefix(diff, cap);
                // Prefer whole diff lines.
                let line_end = diff[..end].rfind('\n').map_or(end, |newline| newline + 1);
                out.insert("text_diff_truncated".into(), json!(true));
                out.insert("text_diff_bytes".into(), json!(diff.len()));
                line_end
            }
            _ => diff.len(),
        };
        out.insert("text_diff".into(), json!(&diff[..end]));
    }
    if !body.warnings.is_empty() {
        out.insert("warnings".into(), json!(body.warnings));
    }
    view.insert("body".into(), Value::Object(out));
}

// ---------------------------------------------------------------------------
// reply_send
// ---------------------------------------------------------------------------

/// reply_send result with `diff` reduced to what tells whether the change
/// altered the outcome: base status, base response length and whether the
/// response body is byte-identical. The core diff exists only when the reply
/// was saved, so an uncaptured (out-of-scope) reply is compared with the base
/// here. `diff` is omitted without a base.
pub(crate) async fn reply_send_view(
    state: &AppState,
    project_id: ProjectId,
    base_exchange_id: Option<ExchangeId>,
    result: &ReplySendResult,
) -> DomainResult<Value> {
    let diff = match (&result.diff, base_exchange_id) {
        (Some(diff), _) => Some(compact_diff(diff, result.response_length)),
        (None, Some(base_id)) => Some(
            match state
                .db
                .get_exchange_detail(project_id, base_id, PresentationOptions::default())
                .await
            {
                Ok(base) => base_comparison(&base, result),
                // The request was already sent, so report rather than fail.
                Err(error) => json!({ "error": error.to_string() }),
            },
        ),
        (None, None) => None,
    };
    let mut value = to_json(result)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| DomainError::new(ErrorCode::Internal, "reply result is not an object"))?;
    match diff {
        Some(diff) => object.insert("diff".into(), diff),
        None => object.remove("diff"),
    };
    Ok(value)
}

fn compact_diff(diff: &ResponseDiff, response_length: i64) -> Value {
    let mut out = Map::new();
    if let Some(status) = diff.parent_status {
        out.insert("base_status".into(), json!(status));
    }
    if let Some(delta) = diff.length_delta {
        out.insert("base_length".into(), json!(response_length - delta));
    }
    if let Some(same) = diff.body_hash_equal {
        out.insert("same_body".into(), json!(same));
    }
    Value::Object(out)
}

fn base_comparison(base: &ExchangeDetail, result: &ReplySendResult) -> Value {
    let mut out = Map::new();
    if let Some(status) = base.summary.status_code {
        out.insert("base_status".into(), json!(status));
    }
    if let Some(length) = base.summary.response_length {
        out.insert("base_length".into(), json!(length));
    }
    if let Some(hash) = &base.response_body_hash {
        out.insert(
            "same_body".into(),
            json!(*hash == result.response_body_hash),
        );
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lossy_prefix_cuts_between_characters_and_invalid_sequences() {
        let bytes = "aé\"".as_bytes();
        assert_eq!(lossy_prefix(bytes, 1), 1);
        assert_eq!(lossy_prefix(bytes, 2), 1);
        assert_eq!(lossy_prefix(bytes, 3), 3);
        assert_eq!(lossy_prefix(bytes, 4), 3);
        assert_eq!(lossy_prefix(bytes, 5), 4);
        let invalid = [b'a', 0xff, 0xfe, b'b'];
        assert_eq!(lossy_prefix(&invalid, 3), 1);
        assert_eq!(lossy_prefix(&invalid, 4), 2);
        assert_eq!(lossy_prefix(&invalid, 7), 3);
        assert_eq!(lossy_prefix(&invalid, 8), 4);
    }

    #[test]
    fn utf8_floor_never_splits_a_character_or_empties_a_page() {
        let data = "aé€".as_bytes(); // a, é (2 bytes), € (3 bytes)
        assert_eq!(utf8_floor(data, 0, 2), 1);
        assert_eq!(utf8_floor(data, 0, 3), 3);
        assert_eq!(utf8_floor(data, 0, 5), 3);
        assert_eq!(utf8_floor(data, 1, 2), 2, "page keeps at least one byte");
        assert_eq!(utf8_floor(data, 0, 6), 6);
    }

    #[test]
    fn case_insensitive_search_finds_every_occurrence() {
        let haystack = b"Token=1;TOKEN=2;tok;token";
        let found = (0..)
            .scan(0, |from, _| {
                let hit = find_ignore_ascii_case(haystack, b"token", *from)?;
                *from = hit + 1;
                Some(hit)
            })
            .collect::<Vec<_>>();
        assert_eq!(found, [0, 8, 20]);
        assert_eq!(find_ignore_ascii_case(b"ab", b"abc", 0), None);
    }

    #[test]
    fn body_extensions_follow_common_mime_types() {
        assert_eq!(
            body_extension(Some("application/json; charset=utf-8")),
            "json"
        );
        assert_eq!(body_extension(Some("application/problem+json")), "json");
        assert_eq!(body_extension(Some("text/html")), "html");
        assert_eq!(body_extension(Some("application/javascript")), "js");
        assert_eq!(body_extension(Some("text/css")), "css");
        assert_eq!(body_extension(Some("application/xml")), "xml");
        assert_eq!(body_extension(Some("text/plain")), "txt");
        assert_eq!(body_extension(Some("image/png")), "bin");
        assert_eq!(body_extension(None), "bin");
    }
}
