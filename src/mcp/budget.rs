//! Output budget for MCP tool results.
//!
//! `tool_call_result` passes every tool result through [`fit_to_budget`] as a
//! safety net, so a client never receives JSON it has to clip. List-shaped
//! tools should page with [`rows_that_fit`] so the safety net rarely cuts.

use crate::domain::{DomainError, DomainResult};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::io;

/// Stays under the smallest observed MCP client cap (32,768 chars) with margin so results are never clipped mid-JSON.
pub(crate) const MAX_OUTPUT_BYTES: usize = 24_000;

const TRUNCATION_HINT: &str =
    "Narrow the request with filters, limit, max_bytes or paging arguments.";
/// Omission entries listed in the note; the rest are only counted.
const MAX_NOTED_OMISSIONS: usize = 20;
/// Each retry lowers the inner budget by the previous overshoot.
const MAX_FIT_ATTEMPTS: usize = 8;

struct ByteCounter(usize);

impl io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_len<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<usize> {
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}

/// Byte length of `value` serialized as compact JSON (`value.to_string()`),
/// computed without allocating the string.
pub(crate) fn json_len(value: &Value) -> usize {
    // A `Value` has only string keys and finite numbers, and the counter never
    // fails, so serialization cannot fail.
    serialized_len(value).expect("serializing a serde_json::Value cannot fail")
}

/// Number of leading `rows` whose compact JSON array (`[row,row,...]`) fits in
/// `max_bytes`. Fewer than `rows.len()` means rows were dropped: emit a
/// continuation cursor for `rows[n]`, then `rows.truncate(n)`.
///
/// Pass the bytes left for the array after the rest of the response, for
/// example `MAX_OUTPUT_BYTES.saturating_sub(json_len(&envelope_without_rows))`.
/// At least one row is kept when `rows` is not empty so paging always advances;
/// an oversized single row is left to the [`fit_to_budget`] safety net.
pub(crate) fn rows_that_fit<T: Serialize>(rows: &[T], max_bytes: usize) -> DomainResult<usize> {
    let mut used = 2; // `[` and `]`
    for (index, row) in rows.iter().enumerate() {
        let row_len = serialized_len(row).map_err(|error| DomainError::Other(error.into()))?;
        let separator = usize::from(index > 0);
        if index > 0 && used + separator + row_len > max_bytes {
            return Ok(index);
        }
        used += separator + row_len;
    }
    Ok(rows.len())
}

/// Returns `value` unchanged when its compact JSON fits in `max_bytes`.
///
/// Otherwise returns a valid JSON object of at most `max_bytes` (a non-object
/// is first wrapped as `{"result": value}`): the largest nodes are cut first,
/// arrays to a prefix of whole elements and strings on a char boundary, and a
/// top-level `output_truncated` note lists each cut by JSON pointer. If no
/// structural cut is enough, only the note remains. `max_bytes` must leave room
/// for the note (a few hundred bytes).
pub(crate) fn fit_to_budget(value: Value, max_bytes: usize) -> Value {
    let original_len = json_len(&value);
    if original_len <= max_bytes {
        return value;
    }
    let value = super::object_structured_content(value);
    let value_len = json_len(&value);
    let mut budget = max_bytes;
    for _ in 0..MAX_FIT_ATTEMPTS {
        let mut omitted = Vec::new();
        let fitted = shrink(&value, value_len, budget, &mut String::new(), &mut omitted);
        let noted = with_note(fitted, omitted, max_bytes);
        let noted_len = json_len(&noted);
        if noted_len <= max_bytes {
            return noted;
        }
        budget = budget.saturating_sub(noted_len - max_bytes);
        if budget == 0 {
            break;
        }
    }
    with_note(
        Value::Object(Map::new()),
        vec![json!({ "path": "", "kept_bytes": 0, "of_bytes": original_len })],
        max_bytes,
    )
}

fn with_note(mut fitted: Value, mut omitted: Vec<Value>, max_bytes: usize) -> Value {
    let total = omitted.len();
    omitted.truncate(MAX_NOTED_OMISSIONS);
    let mut note = json!({
        "max_bytes": max_bytes,
        "omitted": omitted,
        "hint": TRUNCATION_HINT,
    });
    if total > MAX_NOTED_OMISSIONS {
        note["more_omitted"] = json!(total - MAX_NOTED_OMISSIONS);
    }
    if let Some(object) = fitted.as_object_mut() {
        object.insert("output_truncated".into(), note);
    }
    fitted
}

/// Shrinks `value` (whose compact length is `len`) towards `budget` bytes,
/// recording every cut in `omitted`. `path` is the JSON pointer of `value`.
fn shrink(
    value: &Value,
    len: usize,
    budget: usize,
    path: &mut String,
    omitted: &mut Vec<Value>,
) -> Value {
    if len <= budget {
        return value.clone();
    }
    match value {
        Value::Object(map) => {
            let sizes = map.values().map(json_len).collect::<Vec<_>>();
            // Braces, keys, colons and commas cannot be cut.
            let overhead = len - sizes.iter().sum::<usize>();
            let cap = water_level(&sizes, budget.saturating_sub(overhead));
            let mut out = Map::new();
            for ((key, child), &size) in map.iter().zip(&sizes) {
                let child = if size <= cap {
                    child.clone()
                } else {
                    let parent = path.len();
                    path.push('/');
                    path.push_str(&key.replace('~', "~0").replace('/', "~1"));
                    let child = shrink(child, size, cap, path, omitted);
                    path.truncate(parent);
                    child
                };
                out.insert(key.clone(), child);
            }
            Value::Object(out)
        }
        Value::Array(items) if !items.is_empty() => {
            let mut used = 2; // `[` and `]`
            let mut kept = 0;
            let mut first_len = 0;
            for (index, item) in items.iter().enumerate() {
                let item_len = json_len(item);
                let separator = usize::from(index > 0);
                if index == 0 {
                    first_len = item_len;
                }
                if used + separator + item_len > budget {
                    break;
                }
                used += separator + item_len;
                kept += 1;
            }
            if kept == 0 {
                // Keep a shrunk first element so the agent still sees the row shape.
                if items.len() > 1 {
                    omitted.push(json!({ "path": path.clone(), "kept": 1, "of": items.len() }));
                }
                let parent = path.len();
                path.push_str("/0");
                let first = shrink(
                    &items[0],
                    first_len,
                    budget.saturating_sub(2),
                    path,
                    omitted,
                );
                path.truncate(parent);
                return Value::Array(vec![first]);
            }
            omitted.push(json!({ "path": path.clone(), "kept": kept, "of": items.len() }));
            Value::Array(items[..kept].to_vec())
        }
        Value::String(text) => {
            let end = escaped_prefix_len(text, budget.saturating_sub(2)); // the quotes
            omitted.push(json!({
                "path": path.clone(),
                "kept_bytes": end,
                "of_bytes": text.len(),
            }));
            Value::String(text[..end].to_owned())
        }
        // Numbers, booleans, null and empty arrays cannot shrink.
        _ => value.clone(),
    }
}

/// Largest cap such that cutting every size above it down to the cap makes the
/// sizes sum to at most `available` (water filling). Small children keep their
/// full size and the largest ones share what is left equally.
pub(crate) fn water_level(sizes: &[usize], available: usize) -> usize {
    let mut sorted = sizes.to_vec();
    sorted.sort_unstable();
    let mut remaining = available;
    for (index, &size) in sorted.iter().enumerate() {
        let rest = sorted.len() - index;
        if size > remaining / rest {
            return remaining / rest;
        }
        remaining -= size;
    }
    usize::MAX
}

/// Byte length of the longest prefix of `text`, cut on a char boundary, whose
/// JSON string escaping (without the quotes) takes at most `max_bytes`.
pub(crate) fn escaped_prefix_len(text: &str, max_bytes: usize) -> usize {
    let mut used = 0;
    for (index, ch) in text.char_indices() {
        used += escaped_len(ch);
        if used > max_bytes {
            return index;
        }
    }
    text.len()
}

/// Bytes `ch` takes inside a serde_json string literal.
pub(crate) fn escaped_len(ch: char) -> usize {
    match ch {
        '"' | '\\' | '\u{08}' | '\u{0c}' | '\n' | '\r' | '\t' => 2,
        '\u{00}'..='\u{1f}' => 6,
        _ => ch.len_utf8(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fitted(value: Value, max_bytes: usize) -> Value {
        let result = fit_to_budget(value, max_bytes);
        let text = result.to_string();
        assert!(text.len() <= max_bytes, "{} > {max_bytes}", text.len());
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), result);
        assert_eq!(json_len(&result), text.len());
        result
    }

    fn omitted(result: &Value) -> &Vec<Value> {
        result["output_truncated"]["omitted"].as_array().unwrap()
    }

    #[test]
    fn small_values_are_returned_unchanged_without_a_note() {
        for value in [
            json!({"items": [1, 2, 3], "next": null}),
            json!([1, 2]),
            json!("text"),
            json!(null),
        ] {
            assert_eq!(fitted(value.clone(), 1_000), value);
        }
    }

    #[test]
    fn a_top_level_array_field_keeps_a_prefix_of_whole_rows() {
        let rows = (0..1_000)
            .map(|id| json!({"id": id, "url": format!("https://example.test/{id}")}))
            .collect::<Vec<_>>();
        let result = fitted(json!({"items": rows, "next": "cursor"}), 4_000);
        let items = result["items"].as_array().unwrap();
        assert!(items.len() > 10);
        assert_eq!(items[..], rows[..items.len()]);
        assert_eq!(result["next"], "cursor");
        assert_eq!(
            *omitted(&result),
            vec![json!({"path": "/items", "kept": items.len(), "of": 1_000})]
        );
        assert_eq!(result["output_truncated"]["max_bytes"], 4_000);
        assert_eq!(result["output_truncated"]["hint"], TRUNCATION_HINT);
    }

    #[test]
    fn nested_arrays_are_cut_where_the_bytes_are() {
        let value = json!({
            "groups": [{"name": "a", "rows": (0..5_000).collect::<Vec<_>>()}],
            "small": [1, 2, 3]
        });
        let result = fitted(value, 2_000);
        assert_eq!(result["small"], json!([1, 2, 3]));
        assert_eq!(result["groups"][0]["name"], "a");
        let rows = result["groups"][0]["rows"].as_array().unwrap();
        assert!(!rows.is_empty() && rows.len() < 5_000);
        assert_eq!(
            *omitted(&result),
            vec![json!({"path": "/groups/0/rows", "kept": rows.len(), "of": 5_000})]
        );
    }

    #[test]
    fn a_huge_multibyte_string_is_cut_on_a_char_boundary() {
        let text = "é\"🦀\n".repeat(200_000);
        let result = fitted(
            json!({"data": {"content": text, "mime": "text/plain"}}),
            3_001,
        );
        let kept = result["data"]["content"].as_str().unwrap();
        assert!(text.starts_with(kept));
        assert!(kept.len() > 1_500);
        assert_eq!(result["data"]["mime"], "text/plain");
        assert_eq!(
            *omitted(&result),
            vec![
                json!({"path": "/data/content", "kept_bytes": kept.len(), "of_bytes": text.len()})
            ]
        );
    }

    #[test]
    fn several_large_nodes_are_all_trimmed() {
        let value = json!({
            "a/b": "x".repeat(50_000),
            "list": (0..10_000).map(|n| format!("item-{n}")).collect::<Vec<_>>(),
            "nested": {"body": "y".repeat(30_000), "status": 200},
            "id": 7
        });
        let result = fitted(value, MAX_OUTPUT_BYTES);
        assert_eq!(result["id"], 7);
        assert_eq!(result["nested"]["status"], 200);
        let paths = omitted(&result)
            .iter()
            .map(|entry| entry["path"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(paths, ["/a~1b", "/list", "/nested/body"]);
        // The budget is shared, not spent on the first large node.
        assert!(result["a/b"].as_str().unwrap().len() > 4_000);
        assert!(result["list"].as_array().unwrap().len() > 400);
    }

    #[test]
    fn a_giant_scalar_is_wrapped_and_cut() {
        let result = fitted(json!("z".repeat(5_000_000)), MAX_OUTPUT_BYTES);
        assert!(result["result"].as_str().unwrap().len() > 20_000);
        assert_eq!(omitted(&result)[0]["path"], "/result");
        let result = fitted(json!((0..1_000_000).collect::<Vec<_>>()), MAX_OUTPUT_BYTES);
        assert_eq!(omitted(&result)[0]["path"], "/result");
    }

    #[test]
    fn many_small_cuts_are_counted_and_unshrinkable_values_fall_back_to_the_note() {
        let many = (0..100)
            .map(|n| (format!("k{n}"), json!("v".repeat(1_000))))
            .collect::<Map<_, _>>();
        let result = fitted(Value::Object(many), 10_000);
        assert_eq!(omitted(&result).len(), MAX_NOTED_OMISSIONS);
        assert_eq!(result["output_truncated"]["more_omitted"], 80);

        let numbers = (0..10_000)
            .map(|n| (format!("key-{n}"), json!(n)))
            .collect::<Map<_, _>>();
        let original_len = json_len(&Value::Object(numbers.clone()));
        let result = fitted(Value::Object(numbers), 2_000);
        assert_eq!(result.as_object().unwrap().len(), 1);
        assert_eq!(
            *omitted(&result),
            vec![json!({"path": "", "kept_bytes": 0, "of_bytes": original_len})]
        );
    }

    #[test]
    fn escaped_prefix_len_counts_json_escaping_and_keeps_whole_chars() {
        let text = "a\"é\n🦀\u{1}";
        for max_bytes in 0..=text.len() * 6 {
            let end = escaped_prefix_len(text, max_bytes);
            assert!(text.is_char_boundary(end));
            let escaped = json_len(&json!(&text[..end])) - 2;
            assert!(escaped <= max_bytes, "{escaped} > {max_bytes}");
            if end < text.len() {
                let next = end + text[end..].chars().next().unwrap().len_utf8();
                assert!(json_len(&json!(&text[..next])) - 2 > max_bytes);
            }
        }
        assert_eq!(escaped_prefix_len(text, usize::MAX), text.len());
    }

    #[test]
    fn rows_that_fit_returns_the_longest_fitting_prefix() {
        let rows = ["aaaa", "bbbb", "cccc"];
        // `["aaaa","bbbb"]` is 15 bytes.
        assert_eq!(rows_that_fit(&rows, 15).unwrap(), 2);
        assert_eq!(rows_that_fit(&rows, 14).unwrap(), 1);
        assert_eq!(rows_that_fit(&rows, 22).unwrap(), 3);
        assert_eq!(rows_that_fit(&rows, 1).unwrap(), 1);
        assert_eq!(rows_that_fit::<&str>(&[], 0).unwrap(), 0);
        let prefix = &rows[..rows_that_fit(&rows, 15).unwrap()];
        assert_eq!(serde_json::to_string(prefix).unwrap().len(), 15);
    }
}
