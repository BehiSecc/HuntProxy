//! Fuzz job persistence.

use crate::domain::*;
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::Db;
use rusqlite::params;

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
            conn.execute(
                "INSERT INTO fuzz_jobs (project_id, base_exchange_id, state, strategy, template_json, estimated_cases, completed_cases, failed_cases, limits_json, created_at, updated_at)
                 VALUES (?1,?2,'queued',?3,?4,?5,0,0,?6,?7,?8)",
                params![
                    project_id.get(),
                    base_exchange_id.map(|e| e.get()),
                    strategy_s,
                    template_json,
                    estimated_cases as i64,
                    limits_json,
                    ts,
                    ts
                ],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let id = conn.last_insert_rowid();
            Ok(FuzzJob {
                id: FuzzJobId(id),
                project_id,
                base_exchange_id,
                state: FuzzJobState::Queued,
                strategy,
                estimated_cases,
                completed_cases: 0,
                failed_cases: 0,
                created_at: parse_time(&ts),
                updated_at: parse_time(&ts),
            })
        })
        .await
    }

    pub async fn update_fuzz_job_state(
        &self,
        job_id: FuzzJobId,
        state: FuzzJobState,
        completed: Option<u64>,
        failed: Option<u64>,
    ) -> DomainResult<()> {
        let ts = now_rfc3339();
        let state_s = fuzz_state_str(state);
        self.with_conn(move |conn| {
            if let (Some(c), Some(f)) = (completed, failed) {
                conn.execute(
                    "UPDATE fuzz_jobs SET state=?1, completed_cases=?2, failed_cases=?3, updated_at=?4 WHERE id=?5",
                    params![state_s, c as i64, f as i64, ts, job_id.get()],
                )
            } else {
                conn.execute(
                    "UPDATE fuzz_jobs SET state=?1, updated_at=?2 WHERE id=?3",
                    params![state_s, ts, job_id.get()],
                )
            }
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            Ok(())
        })
        .await
    }

    pub async fn get_fuzz_job(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
    ) -> DomainResult<FuzzJob> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT id, project_id, base_exchange_id, state, strategy, estimated_cases, completed_cases, failed_cases, created_at, updated_at
                 FROM fuzz_jobs WHERE id=?1 AND project_id=?2",
                params![job_id.get(), project_id.get()],
                |row| {
                    Ok(FuzzJob {
                        id: FuzzJobId(row.get(0)?),
                        project_id: ProjectId(row.get(1)?),
                        base_exchange_id: row.get::<_, Option<i64>>(2)?.map(ExchangeId),
                        state: parse_fuzz_state(&row.get::<_, String>(3)?),
                        strategy: parse_strategy(&row.get::<_, String>(4)?),
                        estimated_cases: row.get::<_, i64>(5)? as u64,
                        completed_cases: row.get::<_, i64>(6)? as u64,
                        failed_cases: row.get::<_, i64>(7)? as u64,
                        created_at: parse_time(&row.get::<_, String>(8)?),
                        updated_at: parse_time(&row.get::<_, String>(9)?),
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DomainError::not_found("fuzz job"),
                other => DomainError::new(ErrorCode::StorageError, other.to_string()),
            })
        })
        .await
    }

    pub async fn list_fuzz_jobs(&self, project_id: ProjectId) -> DomainResult<Vec<FuzzJob>> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, project_id, base_exchange_id, state, strategy, estimated_cases, completed_cases, failed_cases, created_at, updated_at
                     FROM fuzz_jobs WHERE project_id=?1 ORDER BY id DESC LIMIT 100",
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let rows = stmt
                .query_map(params![project_id.get()], |row| {
                    Ok(FuzzJob {
                        id: FuzzJobId(row.get(0)?),
                        project_id: ProjectId(row.get(1)?),
                        base_exchange_id: row.get::<_, Option<i64>>(2)?.map(ExchangeId),
                        state: parse_fuzz_state(&row.get::<_, String>(3)?),
                        strategy: parse_strategy(&row.get::<_, String>(4)?),
                        estimated_cases: row.get::<_, i64>(5)? as u64,
                        completed_cases: row.get::<_, i64>(6)? as u64,
                        failed_cases: row.get::<_, i64>(7)? as u64,
                        created_at: parse_time(&row.get::<_, String>(8)?),
                        updated_at: parse_time(&row.get::<_, String>(9)?),
                    })
                })
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?);
            }
            Ok(out)
        })
        .await
    }

    pub async fn load_fuzz_template(&self, job_id: FuzzJobId) -> DomainResult<String> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT template_json FROM fuzz_jobs WHERE id=?1",
                params![job_id.get()],
                |r| r.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DomainError::not_found("fuzz job"),
                other => DomainError::new(ErrorCode::StorageError, other.to_string()),
            })
        })
        .await
    }
}

fn strategy_str(s: FuzzStrategy) -> &'static str {
    match s {
        FuzzStrategy::Sniper => "sniper",
        FuzzStrategy::BatteringRam => "battering_ram",
        FuzzStrategy::Pitchfork => "pitchfork",
        FuzzStrategy::ClusterBomb => "cluster_bomb",
    }
}
fn parse_strategy(s: &str) -> FuzzStrategy {
    match s {
        "battering_ram" => FuzzStrategy::BatteringRam,
        "pitchfork" => FuzzStrategy::Pitchfork,
        "cluster_bomb" => FuzzStrategy::ClusterBomb,
        _ => FuzzStrategy::Sniper,
    }
}
fn fuzz_state_str(s: FuzzJobState) -> &'static str {
    match s {
        FuzzJobState::Queued => "queued",
        FuzzJobState::Running => "running",
        FuzzJobState::Paused => "paused",
        FuzzJobState::Cancelling => "cancelling",
        FuzzJobState::Completed => "completed",
        FuzzJobState::Failed => "failed",
        FuzzJobState::Interrupted => "interrupted",
    }
}
fn parse_fuzz_state(s: &str) -> FuzzJobState {
    match s {
        "running" => FuzzJobState::Running,
        "paused" => FuzzJobState::Paused,
        "cancelling" => FuzzJobState::Cancelling,
        "completed" => FuzzJobState::Completed,
        "failed" => FuzzJobState::Failed,
        "interrupted" => FuzzJobState::Interrupted,
        _ => FuzzJobState::Queued,
    }
}
