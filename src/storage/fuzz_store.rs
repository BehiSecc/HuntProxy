//! Project-scoped fuzz job and case persistence.

use crate::domain::*;
use crate::fuzzer::FuzzResponseGroup;
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::{write_transaction, Db};
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

impl Db {
    pub async fn create_fuzz_job(
        &self,
        project_id: ProjectId,
        base_exchange_id: Option<ExchangeId>,
        strategy: FuzzStrategy,
        template_json: String,
        estimated_cases: u64,
        limits_json: String,
    ) -> DomainResult<FuzzJob> {
        let ts = now_rfc3339();
        let strategy_s = strategy_str(strategy);
        self.with_conn(move |conn| {
            let tx = write_transaction(conn).map_err(storage_error)?;
            let project_exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM projects WHERE id=?1)",
                    params![project_id.get()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if !project_exists {
                return Err(DomainError::not_found("project"));
            }
            if let Some(base_exchange_id) = base_exchange_id {
                let base_exists: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM exchanges WHERE project_id=?1 AND exchange_id=?2)",
                        params![project_id.get(), base_exchange_id.get()],
                        |row| row.get(0),
                    )
                    .map_err(storage_error)?;
                if !base_exists {
                    return Err(DomainError::not_found("base exchange"));
                }
            }
            tx.execute(
                "INSERT INTO fuzz_jobs
                 (project_id, base_exchange_id, state, strategy, template_json, estimated_cases,
                  completed_cases, failed_cases, limits_json, error, created_at, updated_at)
                 VALUES (?1,?2,'queued',?3,?4,?5,0,0,?6,NULL,?7,?8)",
                params![
                    project_id.get(),
                    base_exchange_id.map(|exchange_id| exchange_id.get()),
                    strategy_s,
                    template_json,
                    estimated_cases as i64,
                    limits_json,
                    ts,
                    ts
                ],
            )
            .map_err(storage_error)?;
            let id = FuzzJobId(tx.last_insert_rowid());
            tx.commit().map_err(storage_error)?;
            Ok(FuzzJob {
                id,
                project_id,
                base_exchange_id,
                state: FuzzJobState::Queued,
                strategy,
                estimated_cases,
                completed_cases: 0,
                failed_cases: 0,
                error: None,
                created_at: parse_time(&ts),
                updated_at: parse_time(&ts),
            })
        })
        .await
    }

    pub async fn set_fuzz_job_state(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
        state: FuzzJobState,
        error: Option<String>,
    ) -> DomainResult<()> {
        let ts = now_rfc3339();
        let state_s = fuzz_state_str(state);
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE fuzz_jobs SET state=?1, error=?2, updated_at=?3
                     WHERE id=?4 AND project_id=?5",
                    params![state_s, error, ts, job_id.get(), project_id.get()],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("fuzz job"));
            }
            Ok(())
        })
        .await
    }

    pub async fn get_fuzz_job(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
    ) -> DomainResult<FuzzJob> {
        self.with_conn(move |conn| load_fuzz_job(conn, Some(project_id), job_id))
            .await
    }

    pub async fn get_fuzz_job_by_id(&self, job_id: FuzzJobId) -> DomainResult<FuzzJob> {
        self.with_conn(move |conn| load_fuzz_job(conn, None, job_id))
            .await
    }

    pub async fn list_fuzz_jobs(&self, project_id: ProjectId) -> DomainResult<Vec<FuzzJob>> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, project_id, base_exchange_id, state, strategy, estimated_cases,
                            completed_cases, failed_cases, error, created_at, updated_at
                     FROM fuzz_jobs WHERE project_id=?1 ORDER BY id DESC LIMIT 100",
                )
                .map_err(storage_error)?;
            let rows = stmt
                .query_map(params![project_id.get()], map_fuzz_job)
                .map_err(storage_error)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_error)
        })
        .await
    }

    pub async fn load_fuzz_template_for_project(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
    ) -> DomainResult<String> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT template_json FROM fuzz_jobs WHERE id=?1 AND project_id=?2",
                params![job_id.get(), project_id.get()],
                |row| row.get(0),
            )
            .map_err(not_found_fuzz_job)
        })
        .await
    }

    pub async fn load_fuzz_template(&self, job_id: FuzzJobId) -> DomainResult<String> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT template_json FROM fuzz_jobs WHERE id=?1",
                params![job_id.get()],
                |row| row.get(0),
            )
            .map_err(not_found_fuzz_job)
        })
        .await
    }

    pub async fn create_fuzz_case(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
        case_index: u64,
        payloads: Vec<FuzzCasePayload>,
    ) -> DomainResult<FuzzCaseResult> {
        let payloads_json = serde_json::to_string(&payloads)
            .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
        let payload_summary = payloads
            .iter()
            .map(|payload| format!("{}={}", payload.insertion_point, payload.value))
            .collect::<Vec<_>>()
            .join(", ")
            .chars()
            .take(512)
            .collect::<String>();
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let job_exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM fuzz_jobs WHERE id=?1 AND project_id=?2)",
                    params![job_id.get(), project_id.get()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if !job_exists {
                return Err(DomainError::not_found("fuzz job"));
            }
            conn.execute(
                "INSERT INTO fuzz_cases
                 (job_id, case_index, state, payloads_json, payload_summary, created_at)
                 VALUES (?1,?2,'queued',?3,?4,?5)",
                params![
                    job_id.get(),
                    case_index as i64,
                    payloads_json,
                    payload_summary,
                    ts
                ],
            )
            .map_err(storage_error)?;
            Ok(FuzzCaseResult {
                id: conn.last_insert_rowid(),
                job_id,
                project_id,
                case_index,
                state: FuzzCaseState::Queued,
                payloads,
                exchange_id: None,
                status_code: None,
                response_length: None,
                duration_ms: None,
                error: None,
                body_hash: None,
                created_at: parse_time(&ts),
                started_at: None,
                finished_at: None,
            })
        })
        .await
    }

    pub async fn mark_fuzz_case_running(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
        case_id: i64,
    ) -> DomainResult<()> {
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE fuzz_cases SET state='running', started_at=?1
                     WHERE id=?2 AND job_id=?3
                       AND EXISTS(SELECT 1 FROM fuzz_jobs WHERE id=?3 AND project_id=?4)",
                    params![ts, case_id, job_id.get(), project_id.get()],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("fuzz case"));
            }
            Ok(())
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn finish_fuzz_case(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
        case_id: i64,
        state: FuzzCaseState,
        exchange_id: Option<ExchangeId>,
        status_code: Option<u16>,
        response_length: Option<i64>,
        duration_ms: Option<i64>,
        error: Option<String>,
        body_hash: Option<String>,
    ) -> DomainResult<()> {
        if !matches!(
            state,
            FuzzCaseState::Completed | FuzzCaseState::Failed | FuzzCaseState::Cancelled
        ) {
            return Err(DomainError::invalid(
                "fuzz case must finish in a terminal state",
            ));
        }
        let ts = now_rfc3339();
        let state_s = fuzz_case_state_str(state);
        self.with_conn(move |conn| {
            let tx = write_transaction(conn).map_err(storage_error)?;
            if let Some(exchange_id) = exchange_id {
                let changed = tx
                    .execute(
                        "UPDATE exchanges SET source='fuzzer', fuzz_job_id=?1, fuzz_case_id=?2
                         WHERE project_id=?3 AND exchange_id=?4",
                        params![job_id.get(), case_id, project_id.get(), exchange_id.get()],
                    )
                    .map_err(storage_error)?;
                if changed == 0 {
                    return Err(DomainError::not_found("fuzz exchange"));
                }
            }
            let changed = tx
                .execute(
                    "UPDATE fuzz_cases
                     SET state=?1, exchange_id=?2, status_code=?3, response_length=?4,
                         duration_ms=?5, error=?6, body_hash=?7, finished_at=?8
                     WHERE id=?9 AND job_id=?10
                       AND EXISTS(SELECT 1 FROM fuzz_jobs WHERE id=?10 AND project_id=?11)",
                    params![
                        state_s,
                        exchange_id.map(|exchange_id| exchange_id.get()),
                        status_code.map(i64::from),
                        response_length,
                        duration_ms,
                        error,
                        body_hash,
                        ts,
                        case_id,
                        job_id.get(),
                        project_id.get()
                    ],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("fuzz case"));
            }
            refresh_fuzz_counts(&tx, project_id, job_id, &ts)?;
            tx.commit().map_err(storage_error)?;
            Ok(())
        })
        .await
    }

    pub async fn find_fuzz_case_exchange(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
        case_id: i64,
    ) -> DomainResult<Option<ExchangeId>> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT exchange_id FROM exchanges
                 WHERE project_id=?1 AND fuzz_job_id=?2 AND fuzz_case_id=?3
                 ORDER BY exchange_id DESC LIMIT 1",
                params![project_id.get(), job_id.get(), case_id],
                |row| row.get::<_, i64>(0).map(ExchangeId),
            )
            .optional()
            .map_err(storage_error)
        })
        .await
    }

    pub async fn list_fuzz_cases(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
        limit: u32,
        before_case_index: Option<u64>,
    ) -> DomainResult<(Vec<FuzzCaseResult>, Option<u64>)> {
        let limit = limit.clamp(1, 500) as usize;
        self.with_conn(move |conn| {
            let mut sql = String::from(
                "SELECT fc.id, fc.job_id, fj.project_id, fc.case_index, fc.state, fc.payloads_json,
                        fc.exchange_id, fc.status_code, fc.response_length, fc.duration_ms, fc.error,
                        fc.body_hash, fc.created_at, fc.started_at, fc.finished_at
                 FROM fuzz_cases fc JOIN fuzz_jobs fj ON fj.id=fc.job_id
                 WHERE fc.job_id=?1 AND fj.project_id=?2",
            );
            if before_case_index.is_some() {
                sql.push_str(" AND fc.case_index < ?3 ORDER BY fc.case_index DESC LIMIT ?4");
            } else {
                sql.push_str(" ORDER BY fc.case_index DESC LIMIT ?3");
            }
            let mut stmt = conn.prepare(&sql).map_err(storage_error)?;
            let fetch = (limit + 1) as i64;
            let rows = if let Some(before) = before_case_index {
                stmt.query_map(
                    params![job_id.get(), project_id.get(), before as i64, fetch],
                    map_fuzz_case,
                )
                .map_err(storage_error)?
            } else {
                stmt.query_map(
                    params![job_id.get(), project_id.get(), fetch],
                    map_fuzz_case,
                )
                .map_err(storage_error)?
            };
            let mut cases = rows
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_error)?;
            let has_more = cases.len() > limit;
            if has_more {
                cases.truncate(limit);
            }
            let next = has_more.then(|| {
                cases
                    .last()
                    .expect("fuzz case overflow must contain an item")
                    .case_index
            });
            Ok((cases, next))
        })
        .await
    }

    pub async fn get_fuzz_case(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
        case_id: i64,
    ) -> DomainResult<FuzzCaseResult> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT fc.id, fc.job_id, fj.project_id, fc.case_index, fc.state, fc.payloads_json,
                        fc.exchange_id, fc.status_code, fc.response_length, fc.duration_ms, fc.error,
                        fc.body_hash, fc.created_at, fc.started_at, fc.finished_at
                 FROM fuzz_cases fc JOIN fuzz_jobs fj ON fj.id=fc.job_id
                 WHERE fc.id=?1 AND fc.job_id=?2 AND fj.project_id=?3",
                params![case_id, job_id.get(), project_id.get()],
                map_fuzz_case,
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => DomainError::not_found("fuzz case"),
                other => storage_error(other),
            })
        })
        .await
    }

    pub async fn first_completed_fuzz_case_exchange(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
    ) -> DomainResult<Option<(i64, ExchangeId)>> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT fc.id, fc.exchange_id
                 FROM fuzz_cases fc JOIN fuzz_jobs fj ON fj.id=fc.job_id
                 WHERE fc.job_id=?1 AND fj.project_id=?2 AND fc.state='completed'
                   AND fc.exchange_id IS NOT NULL
                 ORDER BY fc.case_index ASC LIMIT 1",
                params![job_id.get(), project_id.get()],
                |row| Ok((row.get(0)?, ExchangeId(row.get(1)?))),
            )
            .optional()
            .map_err(storage_error)
        })
        .await
    }

    pub async fn list_fuzz_response_groups(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
    ) -> DomainResult<Vec<FuzzResponseGroup>> {
        self.with_conn(move |conn| {
            let rows = load_grouping_cases(conn, project_id, job_id)?;
            let mut groups = BTreeMap::<String, GroupAccumulator>::new();
            for row in rows {
                let signature = grouping_signature(&row);
                groups
                    .entry(signature)
                    .and_modify(|group| group.add(&row))
                    .or_insert_with(|| GroupAccumulator::new(&row));
            }
            let mut result = groups
                .into_iter()
                .map(|(signature, group)| group.finish(group_id(&signature)))
                .collect::<Vec<_>>();
            result.sort_by(|left, right| {
                right.case_count.cmp(&left.case_count).then_with(|| {
                    left.representative_case_index
                        .cmp(&right.representative_case_index)
                })
            });
            Ok(result)
        })
        .await
    }

    pub async fn list_fuzz_cases_in_group(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
        wanted_group_id: String,
        limit: u32,
        before_case_index: Option<u64>,
    ) -> DomainResult<(Vec<FuzzCaseResult>, Option<u64>)> {
        let limit = limit.clamp(1, 500) as usize;
        self.with_conn(move |conn| {
            let grouping = load_grouping_cases(conn, project_id, job_id)?;
            let all_matching_indexes = grouping
                .into_iter()
                .filter(|row| group_id(&grouping_signature(row)) == wanted_group_id)
                .map(|row| row.case_index)
                .collect::<std::collections::BTreeSet<_>>();
            if all_matching_indexes.is_empty() {
                return Err(DomainError::not_found("fuzz response group"));
            }
            let matching_indexes = all_matching_indexes
                .into_iter()
                .filter(|index| before_case_index.is_none_or(|before| *index < before))
                .collect::<std::collections::BTreeSet<_>>();
            let mut stmt = conn
                .prepare(
                    "SELECT fc.id, fc.job_id, fj.project_id, fc.case_index, fc.state, fc.payloads_json,
                            fc.exchange_id, fc.status_code, fc.response_length, fc.duration_ms, fc.error,
                            fc.body_hash, fc.created_at, fc.started_at, fc.finished_at
                     FROM fuzz_cases fc JOIN fuzz_jobs fj ON fj.id=fc.job_id
                     WHERE fc.job_id=?1 AND fj.project_id=?2 ORDER BY fc.case_index DESC",
                )
                .map_err(storage_error)?;
            let all = stmt
                .query_map(params![job_id.get(), project_id.get()], map_fuzz_case)
                .map_err(storage_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_error)?;
            let mut cases = all
                .into_iter()
                .filter(|case| matching_indexes.contains(&case.case_index))
                .collect::<Vec<_>>();
            let has_more = cases.len() > limit;
            cases.truncate(limit);
            let next = has_more.then(|| cases.last().expect("group page is non-empty").case_index);
            Ok((cases, next))
        })
        .await
    }

    pub async fn mark_fuzz_jobs_interrupted(&self) -> DomainResult<u64> {
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let tx = write_transaction(conn).map_err(storage_error)?;
            tx.execute(
                "UPDATE fuzz_cases SET state='cancelled', finished_at=?1
                 WHERE state IN ('queued','running')
                   AND job_id IN (SELECT id FROM fuzz_jobs WHERE state IN ('queued','running','cancelling'))",
                params![ts],
            )
            .map_err(storage_error)?;
            let changed = tx
                .execute(
                    "UPDATE fuzz_jobs SET state='interrupted', error='daemon restarted', updated_at=?1
                     WHERE state IN ('queued','running','cancelling')",
                    params![ts],
                )
                .map_err(storage_error)?;
            tx.commit().map_err(storage_error)?;
            Ok(changed as u64)
        })
        .await
    }
}

#[derive(Debug)]
struct GroupingCase {
    id: i64,
    case_index: u64,
    state: FuzzCaseState,
    exchange_id: Option<ExchangeId>,
    status_code: Option<u16>,
    mime: Option<String>,
    body_hash: Option<String>,
    response_length: Option<i64>,
    duration_ms: Option<i64>,
    error: Option<String>,
}

fn load_grouping_cases(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
    job_id: FuzzJobId,
) -> DomainResult<Vec<GroupingCase>> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM fuzz_jobs WHERE id=?1 AND project_id=?2)",
            params![job_id.get(), project_id.get()],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if !exists {
        return Err(DomainError::not_found("fuzz job"));
    }
    let mut stmt = conn
        .prepare(
            "SELECT fc.id, fc.case_index, fc.state, fc.exchange_id, fc.status_code,
                    e.mime, fc.body_hash, fc.response_length, fc.duration_ms, fc.error
             FROM fuzz_cases fc
             JOIN fuzz_jobs fj ON fj.id=fc.job_id
             LEFT JOIN exchanges e ON e.project_id=fj.project_id AND e.exchange_id=fc.exchange_id
             WHERE fc.job_id=?1 AND fj.project_id=?2
             ORDER BY fc.case_index ASC",
        )
        .map_err(storage_error)?;
    let rows = stmt
        .query_map(params![job_id.get(), project_id.get()], |row| {
            Ok(GroupingCase {
                id: row.get(0)?,
                case_index: row.get::<_, i64>(1)? as u64,
                state: parse_fuzz_case_state(&row.get::<_, String>(2)?),
                exchange_id: row.get::<_, Option<i64>>(3)?.map(ExchangeId),
                status_code: row.get::<_, Option<i64>>(4)?.map(|value| value as u16),
                mime: row.get::<_, Option<String>>(5)?.and_then(normalize_mime),
                body_hash: row.get(6)?,
                response_length: row.get(7)?,
                duration_ms: row.get(8)?,
                error: row.get(9)?,
            })
        })
        .map_err(storage_error)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(storage_error)
}

fn normalize_mime(value: String) -> Option<String> {
    let value = value
        .split(';')
        .next()
        .unwrap_or(&value)
        .trim()
        .to_ascii_lowercase();
    (!value.is_empty()).then_some(value)
}

fn canonical_error(error: Option<&str>) -> String {
    let value = error.unwrap_or("unknown").trim().to_ascii_lowercase();
    value
        .split_once(':')
        .map(|(category, _)| category.trim().to_string())
        .or_else(|| value.split_whitespace().next().map(str::to_string))
        .filter(|category| !category.is_empty())
        .unwrap_or(value)
}

fn grouping_signature(row: &GroupingCase) -> String {
    let state = fuzz_case_state_str(row.state);
    if row.state == FuzzCaseState::Failed {
        return format!("{state}|error:{}", canonical_error(row.error.as_deref()));
    }
    let identity = row
        .body_hash
        .as_deref()
        .filter(|hash| !hash.is_empty())
        .map(|hash| format!("hash:{hash}"))
        .unwrap_or_else(|| format!("length:{:?}", row.response_length));
    format!(
        "{state}|status:{:?}|mime:{}|{identity}",
        row.status_code,
        row.mime.as_deref().unwrap_or("")
    )
}

fn group_id(signature: &str) -> String {
    hex::encode(Sha256::digest(signature.as_bytes()))[..16].to_string()
}

struct GroupAccumulator {
    representative: GroupingCase,
    count: u64,
    response_length_min: Option<i64>,
    response_length_max: Option<i64>,
    duration_ms_min: Option<i64>,
    duration_ms_max: Option<i64>,
    duration_ms_total: i128,
    duration_count: u64,
}

impl GroupAccumulator {
    fn new(row: &GroupingCase) -> Self {
        Self {
            representative: GroupingCase {
                id: row.id,
                case_index: row.case_index,
                state: row.state,
                exchange_id: row.exchange_id,
                status_code: row.status_code,
                mime: row.mime.clone(),
                body_hash: row.body_hash.clone(),
                response_length: row.response_length,
                duration_ms: row.duration_ms,
                error: row.error.clone(),
            },
            count: 1,
            response_length_min: row.response_length,
            response_length_max: row.response_length,
            duration_ms_min: row.duration_ms,
            duration_ms_max: row.duration_ms,
            duration_ms_total: i128::from(row.duration_ms.unwrap_or_default()),
            duration_count: u64::from(row.duration_ms.is_some()),
        }
    }

    fn add(&mut self, row: &GroupingCase) {
        self.count += 1;
        if row.case_index < self.representative.case_index {
            self.representative.id = row.id;
            self.representative.case_index = row.case_index;
            self.representative.exchange_id = row.exchange_id;
        }
        update_min_max(
            row.response_length,
            &mut self.response_length_min,
            &mut self.response_length_max,
        );
        update_min_max(
            row.duration_ms,
            &mut self.duration_ms_min,
            &mut self.duration_ms_max,
        );
        if let Some(duration) = row.duration_ms {
            self.duration_ms_total += i128::from(duration);
            self.duration_count += 1;
        }
    }

    fn finish(self, group_id: String) -> FuzzResponseGroup {
        FuzzResponseGroup {
            group_id,
            state: self.representative.state,
            case_count: self.count,
            representative_case_id: self.representative.id,
            representative_case_index: self.representative.case_index,
            representative_exchange_id: self.representative.exchange_id,
            status_code: self.representative.status_code,
            mime: self.representative.mime,
            body_hash: self.representative.body_hash,
            response_length_min: self.response_length_min,
            response_length_max: self.response_length_max,
            duration_ms_min: self.duration_ms_min,
            duration_ms_avg: (self.duration_count > 0)
                .then(|| self.duration_ms_total as f64 / self.duration_count as f64),
            duration_ms_max: self.duration_ms_max,
        }
    }
}

fn update_min_max(value: Option<i64>, min: &mut Option<i64>, max: &mut Option<i64>) {
    if let Some(value) = value {
        *min = Some(min.map_or(value, |current| current.min(value)));
        *max = Some(max.map_or(value, |current| current.max(value)));
    }
}

fn load_fuzz_job(
    conn: &rusqlite::Connection,
    project_id: Option<ProjectId>,
    job_id: FuzzJobId,
) -> DomainResult<FuzzJob> {
    let result = if let Some(project_id) = project_id {
        conn.query_row(
            "SELECT id, project_id, base_exchange_id, state, strategy, estimated_cases,
                    completed_cases, failed_cases, error, created_at, updated_at
             FROM fuzz_jobs WHERE id=?1 AND project_id=?2",
            params![job_id.get(), project_id.get()],
            map_fuzz_job,
        )
    } else {
        conn.query_row(
            "SELECT id, project_id, base_exchange_id, state, strategy, estimated_cases,
                    completed_cases, failed_cases, error, created_at, updated_at
             FROM fuzz_jobs WHERE id=?1",
            params![job_id.get()],
            map_fuzz_job,
        )
    };
    result.map_err(not_found_fuzz_job)
}

fn map_fuzz_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<FuzzJob> {
    Ok(FuzzJob {
        id: FuzzJobId(row.get(0)?),
        project_id: ProjectId(row.get(1)?),
        base_exchange_id: row.get::<_, Option<i64>>(2)?.map(ExchangeId),
        state: parse_fuzz_state(&row.get::<_, String>(3)?),
        strategy: parse_strategy(&row.get::<_, String>(4)?),
        estimated_cases: row.get::<_, i64>(5)? as u64,
        completed_cases: row.get::<_, i64>(6)? as u64,
        failed_cases: row.get::<_, i64>(7)? as u64,
        error: row.get(8)?,
        created_at: parse_time(&row.get::<_, String>(9)?),
        updated_at: parse_time(&row.get::<_, String>(10)?),
    })
}

fn map_fuzz_case(row: &rusqlite::Row<'_>) -> rusqlite::Result<FuzzCaseResult> {
    let payloads_json: String = row.get(5)?;
    let payloads = serde_json::from_str(&payloads_json).unwrap_or_default();
    let created_at: Option<String> = row.get(12)?;
    let started_at: Option<String> = row.get(13)?;
    let finished_at: Option<String> = row.get(14)?;
    Ok(FuzzCaseResult {
        id: row.get(0)?,
        job_id: FuzzJobId(row.get(1)?),
        project_id: ProjectId(row.get(2)?),
        case_index: row.get::<_, i64>(3)? as u64,
        state: parse_fuzz_case_state(&row.get::<_, String>(4)?),
        payloads,
        exchange_id: row.get::<_, Option<i64>>(6)?.map(ExchangeId),
        status_code: row.get::<_, Option<i64>>(7)?.map(|status| status as u16),
        response_length: row.get(8)?,
        duration_ms: row.get(9)?,
        error: row.get(10)?,
        body_hash: row.get(11)?,
        created_at: created_at
            .as_deref()
            .map(parse_time)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH),
        started_at: started_at.as_deref().map(parse_time),
        finished_at: finished_at.as_deref().map(parse_time),
    })
}

fn refresh_fuzz_counts(
    conn: &rusqlite::Connection,
    project_id: ProjectId,
    job_id: FuzzJobId,
    timestamp: &str,
) -> DomainResult<()> {
    conn.execute(
        "UPDATE fuzz_jobs
         SET completed_cases=(SELECT COUNT(*) FROM fuzz_cases WHERE job_id=?1 AND state='completed'),
             failed_cases=(SELECT COUNT(*) FROM fuzz_cases WHERE job_id=?1 AND state='failed'),
             updated_at=?2
         WHERE id=?1 AND project_id=?3",
        params![job_id.get(), timestamp, project_id.get()],
    )
    .map_err(storage_error)?;
    Ok(())
}

fn strategy_str(strategy: FuzzStrategy) -> &'static str {
    match strategy {
        FuzzStrategy::Sniper => "sniper",
        FuzzStrategy::BatteringRam => "battering_ram",
        FuzzStrategy::Pitchfork => "pitchfork",
        FuzzStrategy::ClusterBomb => "cluster_bomb",
    }
}

fn parse_strategy(strategy: &str) -> FuzzStrategy {
    match strategy {
        "battering_ram" => FuzzStrategy::BatteringRam,
        "pitchfork" => FuzzStrategy::Pitchfork,
        "cluster_bomb" => FuzzStrategy::ClusterBomb,
        _ => FuzzStrategy::Sniper,
    }
}

fn fuzz_state_str(state: FuzzJobState) -> &'static str {
    match state {
        FuzzJobState::Queued => "queued",
        FuzzJobState::Running => "running",
        FuzzJobState::Paused => "paused",
        FuzzJobState::Cancelling => "cancelling",
        FuzzJobState::Completed => "completed",
        FuzzJobState::Failed => "failed",
        FuzzJobState::Interrupted => "interrupted",
    }
}

fn parse_fuzz_state(state: &str) -> FuzzJobState {
    match state {
        "running" => FuzzJobState::Running,
        "paused" => FuzzJobState::Paused,
        "cancelling" => FuzzJobState::Cancelling,
        "completed" => FuzzJobState::Completed,
        "failed" => FuzzJobState::Failed,
        "interrupted" => FuzzJobState::Interrupted,
        _ => FuzzJobState::Queued,
    }
}

fn fuzz_case_state_str(state: FuzzCaseState) -> &'static str {
    match state {
        FuzzCaseState::Queued => "queued",
        FuzzCaseState::Running => "running",
        FuzzCaseState::Completed => "completed",
        FuzzCaseState::Failed => "failed",
        FuzzCaseState::Cancelled => "cancelled",
    }
}

fn parse_fuzz_case_state(state: &str) -> FuzzCaseState {
    match state {
        "running" => FuzzCaseState::Running,
        "completed" => FuzzCaseState::Completed,
        "failed" => FuzzCaseState::Failed,
        "cancelled" => FuzzCaseState::Cancelled,
        _ => FuzzCaseState::Queued,
    }
}

fn not_found_fuzz_job(error: rusqlite::Error) -> DomainError {
    match error {
        rusqlite::Error::QueryReturnedNoRows => DomainError::not_found("fuzz job"),
        other => storage_error(other),
    }
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

#[cfg(test)]
mod grouping_tests {
    use super::*;

    fn row(hash: Option<&str>, status: u16, mime: &str, length: i64) -> GroupingCase {
        GroupingCase {
            id: 1,
            case_index: 0,
            state: FuzzCaseState::Completed,
            exchange_id: Some(ExchangeId(1)),
            status_code: Some(status),
            mime: normalize_mime(mime.into()),
            body_hash: hash.map(str::to_string),
            response_length: Some(length),
            duration_ms: Some(5),
            error: None,
        }
    }

    #[test]
    fn exact_group_signature_uses_status_mime_and_hash() {
        let base = row(Some("same"), 200, "Text/Plain; charset=utf-8", 10);
        let same = row(Some("same"), 200, "text/plain", 999);
        assert_eq!(grouping_signature(&base), grouping_signature(&same));
        assert_ne!(
            grouping_signature(&base),
            grouping_signature(&row(Some("different"), 200, "text/plain", 10))
        );
        assert_ne!(
            grouping_signature(&base),
            grouping_signature(&row(Some("same"), 404, "text/plain", 10))
        );
        assert_ne!(
            grouping_signature(&base),
            grouping_signature(&row(Some("same"), 200, "application/json", 10))
        );
    }

    #[test]
    fn missing_hash_falls_back_to_length_and_failed_errors_are_canonical() {
        assert_ne!(
            grouping_signature(&row(None, 200, "text/plain", 10)),
            grouping_signature(&row(None, 200, "text/plain", 11))
        );
        let mut left = row(None, 0, "", 0);
        left.state = FuzzCaseState::Failed;
        left.error = Some("timeout: host one".into());
        let mut right = row(None, 0, "", 999);
        right.state = FuzzCaseState::Failed;
        right.error = Some("TIMEOUT: host two".into());
        assert_eq!(grouping_signature(&left), grouping_signature(&right));
    }
}
