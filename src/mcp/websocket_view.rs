//! MCP presentation of captured WebSocket messages: list pages that fit
//! [`MAX_OUTPUT_BYTES`] by construction, so `next_after_id` never skips a
//! message, and one message's whole payload read in slices.

use super::arguments::optional_u64;
use super::budget::{json_len, rows_that_fit, MAX_OUTPUT_BYTES};
use super::exchange_view::{read_bytes_page, to_usize, DEFAULT_PAGE_BYTES, MAX_PAGE_BYTES};
use crate::domain::*;
use crate::websocket::{StoredWebSocketMessage, WebSocketMessageRecord};
use serde_json::{json, Value};

/// Payload bytes listed per message; the `message` action reads the rest.
pub(super) const PREVIEW_BYTES: usize = 2_048;

/// The leading `messages` that fit the output budget. `next_after_id` is set
/// when the page was cut or `limit` messages came back, so more may follow.
pub(super) fn messages_page(
    mut messages: Vec<WebSocketMessageRecord>,
    limit: usize,
) -> DomainResult<Value> {
    let envelope = json!({"messages": [], "next_after_id": i64::MAX});
    let kept = rows_that_fit(
        &messages,
        MAX_OUTPUT_BYTES.saturating_sub(json_len(&envelope)),
    )?;
    let more = kept < messages.len() || messages.len() >= limit;
    messages.truncate(kept);
    let next_after_id = messages.last().filter(|_| more).map(|message| message.id);
    let mut page = json!({ "messages": messages });
    if let Some(id) = next_after_id {
        page["next_after_id"] = json!(id);
    }
    Ok(page)
}

/// One page of `message`'s stored payload with the message's details.
/// Without `encoding`, UTF-8 payloads are read as text and others as base64.
pub(super) fn message_page(message: &StoredWebSocketMessage, args: &Value) -> DomainResult<Value> {
    let offset = to_usize(optional_u64(args, "offset")?.unwrap_or(0));
    let max_bytes = to_usize(
        optional_u64(args, "max_bytes")?
            .unwrap_or(DEFAULT_PAGE_BYTES)
            .clamp(1, MAX_PAGE_BYTES),
    );
    let base64 = match args.get("encoding").and_then(Value::as_str) {
        Some("base64") => true,
        Some("text") => false,
        None => std::str::from_utf8(&message.payload).is_err(),
        Some(_) => return Err(DomainError::invalid("encoding must be text or base64")),
    };
    Ok(read_bytes_page(
        &message.payload,
        offset,
        max_bytes,
        base64,
        |page| {
            page["message_id"] = json!(message.id);
            page["connection_id"] = json!(message.connection_id);
            page["direction"] = json!(message.direction);
            page["opcode"] = json!(message.opcode);
            page["created_at"] = json!(message.created_at);
            if message.truncated {
                page["capture_truncated"] = json!(true);
                page["payload_length"] = json!(message.payload_length);
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: i64, payload: String) -> WebSocketMessageRecord {
        WebSocketMessageRecord {
            id,
            project_id: ProjectId(1),
            connection_id: 7,
            direction: "to_client".into(),
            opcode: "text".into(),
            payload_length: payload.len() as u64,
            truncated: false,
            created_at: "2026-11-16T00:00:00Z".into(),
            encoding: "text".into(),
            payload,
            payload_cut: false,
        }
    }

    #[test]
    fn message_pages_fit_and_cover_every_message_once() {
        let all = (1..=300)
            .map(|id| record(id, "x".repeat(PREVIEW_BYTES)))
            .collect::<Vec<_>>();
        let limit = 250;
        let mut after_id = 0;
        let mut seen: Vec<i64> = Vec::new();
        loop {
            let rows = all
                .iter()
                .filter(|message| message.id > after_id)
                .take(limit)
                .cloned()
                .collect::<Vec<_>>();
            let page = messages_page(rows, limit).unwrap();
            assert!(json_len(&page) <= MAX_OUTPUT_BYTES);
            let ids = page["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|message| message["id"].as_i64().unwrap())
                .collect::<Vec<_>>();
            seen.extend(&ids);
            match page.get("next_after_id") {
                Some(next) => {
                    assert_eq!(next.as_i64(), ids.last().copied());
                    after_id = next.as_i64().unwrap();
                }
                None => break,
            }
        }
        assert_eq!(seen, (1..=300).collect::<Vec<i64>>());

        let short = messages_page(vec![record(1, "a".into())], limit).unwrap();
        assert!(short.get("next_after_id").is_none());
        let full = messages_page(vec![record(1, "a".into())], 1).unwrap();
        assert_eq!(full["next_after_id"], 1);
    }

    #[test]
    fn a_long_message_is_read_whole_in_slices() {
        let payload = "é".repeat(40_000).into_bytes();
        let message = StoredWebSocketMessage {
            id: 9,
            connection_id: 7,
            direction: "to_client".into(),
            opcode: "text".into(),
            payload_length: payload.len() as u64 + 10,
            truncated: true,
            created_at: "2026-11-16T00:00:00Z".into(),
            payload: payload.clone(),
        };
        let mut read = Vec::new();
        let mut offset = 0;
        loop {
            let page = message_page(
                &message,
                &json!({"offset": offset, "max_bytes": MAX_PAGE_BYTES}),
            )
            .unwrap();
            assert!(json_len(&page) <= MAX_OUTPUT_BYTES);
            assert_eq!(page["message_id"], 9);
            assert_eq!(page["capture_truncated"], true);
            assert!(page.get("encoding").is_none());
            read.extend_from_slice(page["preview"].as_str().unwrap().as_bytes());
            match page.get("next_offset") {
                Some(next) => offset = next.as_u64().unwrap(),
                None => break,
            }
        }
        assert_eq!(read, payload);

        let binary = StoredWebSocketMessage {
            payload: vec![0xff, 0x00, 0x01],
            truncated: false,
            ..message
        };
        let page = message_page(&binary, &json!({})).unwrap();
        assert_eq!(page["encoding"], "base64");
        assert_eq!(page["preview"], "/wAB");
        assert!(page.get("capture_truncated").is_none());
        assert!(message_page(&binary, &json!({"encoding": "hex"})).is_err());
    }
}
