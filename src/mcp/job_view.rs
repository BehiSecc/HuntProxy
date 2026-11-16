//! MCP presentation of extension job results: a findings page that fits
//! [`MAX_OUTPUT_BYTES`] by construction, so `next_offset` never points past a
//! finding the page did not return.

use super::budget::{json_len, rows_that_fit, MAX_OUTPUT_BYTES};
use crate::domain::*;
use serde_json::{json, Value};

/// Cuts the findings page of a `findings` or `full` result to the output
/// budget and corrects its pagination. Other results pass through unchanged.
pub(super) fn findings_page(mut result: Value) -> DomainResult<Value> {
    let pointer = if result.get("findings").is_some_and(Value::is_array) {
        "/findings"
    } else if result
        .pointer("/result/analysis/findings")
        .is_some_and(Value::is_array)
    {
        "/result/analysis/findings"
    } else {
        return Ok(result);
    };
    let Some(pagination) = result.get("pagination").cloned() else {
        return Ok(result);
    };
    let mut page = std::mem::take(
        result
            .pointer_mut(pointer)
            .and_then(Value::as_array_mut)
            .expect("checked above"),
    );
    // Measure the rest of the result with the widest pagination it can carry.
    result["pagination"]["returned"] = json!(u64::MAX);
    result["pagination"]["next_offset"] = json!(u64::MAX);
    let kept = rows_that_fit(&page, MAX_OUTPUT_BYTES.saturating_sub(json_len(&result)))?;
    let offset = pagination["offset"].as_u64().unwrap_or(0);
    let next_offset = if kept < page.len() {
        json!(offset + kept as u64)
    } else {
        pagination["next_offset"].clone()
    };
    result["pagination"]["returned"] = json!(kept);
    result["pagination"]["next_offset"] = next_offset;
    page.truncate(kept);
    *result.pointer_mut(pointer).expect("checked above") = Value::Array(page);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `PluginService::results` returns for one page of `findings`.
    fn service_page(findings: &[Value], offset: usize, limit: usize, full: bool) -> Value {
        let end = (offset + limit).min(findings.len());
        let page = findings[offset..end].to_vec();
        let pagination = json!({
            "offset": offset,
            "limit": limit,
            "returned": page.len(),
            "total": findings.len(),
            "next_offset": (end < findings.len()).then_some(end),
        });
        if full {
            json!({
                "job": {"state": "completed"},
                "result_available": true,
                "pagination": pagination,
                "result": {"analysis": {"findings": page, "notes": "x".repeat(2_000)}},
            })
        } else {
            json!({
                "job": {"state": "completed"},
                "result_available": true,
                "pagination": pagination,
                "findings": page,
            })
        }
    }

    #[test]
    fn findings_pages_cover_every_finding_once_within_the_budget() {
        let findings = (0..60)
            .map(|index| json!({"id": index, "evidence": "e".repeat(900 + index * 37)}))
            .collect::<Vec<_>>();
        for full in [false, true] {
            let mut seen = Vec::new();
            let mut offset = 0;
            loop {
                let page = findings_page(service_page(&findings, offset, 25, full)).unwrap();
                assert!(json_len(&page) <= MAX_OUTPUT_BYTES, "{}", json_len(&page));
                let rows = if full {
                    page.pointer("/result/analysis/findings").unwrap()
                } else {
                    &page["findings"]
                };
                let rows = rows.as_array().unwrap();
                assert!(!rows.is_empty());
                assert_eq!(page["pagination"]["returned"], rows.len());
                seen.extend(rows.iter().map(|row| row["id"].as_u64().unwrap()));
                match page["pagination"]["next_offset"].as_u64() {
                    Some(next) => {
                        assert_eq!(next, offset as u64 + rows.len() as u64);
                        offset = next as usize;
                    }
                    None => break,
                }
            }
            assert_eq!(seen, (0..60).collect::<Vec<_>>(), "full={full}");
        }
    }

    #[test]
    fn pages_that_fit_and_summaries_are_unchanged() {
        let findings = (0..3).map(|id| json!({"id": id})).collect::<Vec<_>>();
        let page = service_page(&findings, 0, 2, false);
        assert_eq!(findings_page(page.clone()).unwrap(), page);
        let summary = json!({"job": {}, "result_available": true, "findings": {"total": 3}});
        assert_eq!(findings_page(summary.clone()).unwrap(), summary);
        let unavailable = json!({"job": {}, "result_available": false});
        assert_eq!(findings_page(unavailable.clone()).unwrap(), unavailable);
    }

    #[test]
    fn one_oversized_finding_still_advances() {
        let findings = vec![
            json!({"id": 0, "evidence": "e".repeat(40_000)}),
            json!({"id": 1}),
        ];
        let page = findings_page(service_page(&findings, 0, 25, false)).unwrap();
        assert_eq!(page["pagination"]["returned"], 1);
        assert_eq!(page["pagination"]["next_offset"], 1);
    }
}
