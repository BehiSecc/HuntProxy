//! MCP presentation of fuzz_manage result lists: pages that fit
//! [`MAX_OUTPUT_BYTES`] by construction, with a continuation that never skips
//! a row the page did not return.

use super::budget::{json_len, rows_that_fit, MAX_OUTPUT_BYTES};
use super::history_view::{offset_arg, offset_page};
use crate::domain::*;
use crate::fuzzer::FuzzResponseGroup;
use serde_json::{json, Map, Value};

/// A page of cases, newest case index first, cut to the output budget.
/// `next_before_case_index` is the index of the last case returned, so the
/// next page starts right after it whether this page ended at `limit`, at the
/// byte budget, or (`more`) at the storage page size.
pub(super) fn case_page(mut cases: Vec<FuzzCaseResult>, more: bool) -> DomainResult<Value> {
    let envelope = json!({"cases": [], "next_before_case_index": u64::MAX});
    let kept = rows_that_fit(&cases, MAX_OUTPUT_BYTES.saturating_sub(json_len(&envelope)))?;
    let next = (kept < cases.len() || more).then(|| cases[kept - 1].case_index);
    cases.truncate(kept);
    Ok(json!({"cases": cases, "next_before_case_index": next}))
}

/// Response groups from `offset`, largest first, cut to `limit` and to the
/// output budget. `total` and `next_offset` appear while groups remain.
pub(super) fn group_page(groups: Vec<FuzzResponseGroup>, args: &Value) -> DomainResult<Value> {
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(usize::MAX, |limit| {
            usize::try_from(limit.max(1)).unwrap_or(usize::MAX)
        });
    let rows = groups.iter().map(|group| json!(group)).collect();
    offset_page(Map::new(), "groups", rows, offset_arg(args), limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(index: u64) -> FuzzCaseResult {
        FuzzCaseResult {
            id: index as i64 + 1,
            job_id: FuzzJobId(1),
            project_id: ProjectId(1),
            case_index: index,
            state: FuzzCaseState::Completed,
            payloads: vec![FuzzCasePayload {
                insertion_point: "q".into(),
                location: "url".into(),
                encoding: "text".into(),
                value: format!("{index}-{}", "x".repeat(200)),
            }],
            exchange_id: Some(ExchangeId(index as i64 + 1)),
            status_code: Some(200),
            response_length: Some(455),
            duration_ms: Some(3),
            error: None,
            body_hash: Some("a".repeat(64)),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            started_at: None,
            finished_at: None,
        }
    }

    /// Storage pages newest first and reports the last row of a full page.
    fn storage_page(
        all: &[FuzzCaseResult],
        limit: usize,
        before: Option<u64>,
    ) -> (Vec<FuzzCaseResult>, bool) {
        let mut rows = all
            .iter()
            .rev()
            .filter(|case| before.is_none_or(|before| case.case_index < before))
            .take(limit + 1)
            .cloned()
            .collect::<Vec<_>>();
        let more = rows.len() > limit;
        rows.truncate(limit);
        (rows, more)
    }

    #[test]
    fn case_pages_cover_every_case_once_within_the_budget() {
        let all = (0..1_200).map(case).collect::<Vec<_>>();
        for limit in [1, 100, 500] {
            let mut before = None;
            let mut seen = Vec::new();
            loop {
                let (rows, more) = storage_page(&all, limit, before);
                let page = case_page(rows, more).unwrap();
                assert!(json_len(&page) <= MAX_OUTPUT_BYTES);
                let cases = page["cases"].as_array().unwrap();
                assert!(!cases.is_empty());
                seen.extend(
                    cases
                        .iter()
                        .map(|case| case["case_index"].as_u64().unwrap()),
                );
                match page["next_before_case_index"].as_u64() {
                    Some(next) => {
                        assert_eq!(next, *seen.last().unwrap());
                        before = Some(next);
                    }
                    None => break,
                }
            }
            assert_eq!(seen, (0..1_200).rev().collect::<Vec<_>>(), "limit {limit}");
        }
        let empty = case_page(Vec::new(), false).unwrap();
        assert_eq!(empty, json!({"cases": [], "next_before_case_index": null}));
    }

    fn group(index: u64) -> FuzzResponseGroup {
        FuzzResponseGroup {
            group_id: format!("{index:016x}"),
            state: FuzzCaseState::Completed,
            case_count: 1,
            representative_case_id: index as i64,
            representative_case_index: index,
            representative_exchange_id: Some(ExchangeId(index as i64)),
            status_code: Some(200),
            mime: Some("text/html".into()),
            body_hash: Some("b".repeat(64)),
            body_hash_matches_baseline: Some(false),
            different_from_baseline: Some(true),
            response_length_min: Some(455),
            response_length_max: Some(455),
            duration_ms_min: Some(1),
            duration_ms_avg: Some(1.0),
            duration_ms_max: Some(1),
        }
    }

    #[test]
    fn group_pages_reach_every_group() {
        let groups = (0..2_000).map(group).collect::<Vec<_>>();
        let mut offset = 0;
        let mut seen = Vec::new();
        loop {
            let page = group_page(groups.clone(), &json!({"offset": offset})).unwrap();
            assert!(json_len(&page) <= MAX_OUTPUT_BYTES);
            seen.extend(
                page["groups"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|group| group["representative_case_index"].as_u64().unwrap()),
            );
            match page.get("next_offset") {
                Some(next) => {
                    assert_eq!(page["total"], 2_000);
                    offset = next.as_u64().unwrap();
                }
                None => break,
            }
        }
        assert_eq!(seen, (0..2_000).collect::<Vec<_>>());
        let limited = group_page(groups, &json!({"limit": 3, "offset": 10})).unwrap();
        assert_eq!(limited["groups"].as_array().unwrap().len(), 3);
        assert_eq!(limited["next_offset"], 13);
    }
}
