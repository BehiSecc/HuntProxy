//! Bounded fuzzer: insertion points, strategies, cancel, limits.

use crate::domain::*;
use crate::reply::{PlaceholderKey, ReplyService};
use crate::storage::Db;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertionPoint {
    pub name: String,
    /// Where to insert: "url", "header:<name>", "body", or placeholder name in template.
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzTemplate {
    pub base_exchange_id: Option<ExchangeId>,
    pub draft: ReplyDraft,
    pub insertion_points: Vec<InsertionPoint>,
    pub wordlists: Vec<Vec<String>>,
    pub transforms: Vec<crate::codec::Transform>,
    pub strategy: FuzzStrategy,
}

pub fn estimate_cases(strategy: FuzzStrategy, points: usize, list_lens: &[usize]) -> u64 {
    if points == 0 || list_lens.is_empty() {
        return 0;
    }
    match strategy {
        FuzzStrategy::Sniper => list_lens.iter().map(|l| *l as u64).sum::<u64>() * points as u64
            / points.max(1) as u64
            * points as u64
            / points as u64
            + list_lens.iter().take(points).map(|l| *l as u64).sum::<u64>(),
        FuzzStrategy::BatteringRam => list_lens.first().copied().unwrap_or(0) as u64,
        FuzzStrategy::Pitchfork => list_lens.iter().copied().map(|l| l as u64).min().unwrap_or(0),
        FuzzStrategy::ClusterBomb => list_lens
            .iter()
            .take(points)
            .map(|l| (*l as u64).max(1))
            .product(),
    }
}

/// Correct estimate helpers
pub fn estimate_combinations(
    strategy: FuzzStrategy,
    n_points: usize,
    list_lens: &[usize],
) -> u64 {
    if n_points == 0 {
        return 0;
    }
    match strategy {
        FuzzStrategy::Sniper => {
            // one point at a time: sum of wordlist sizes (use list i for point i, or first list)
            (0..n_points)
                .map(|i| list_lens.get(i).or_else(|| list_lens.first()).copied().unwrap_or(0) as u64)
                .sum()
        }
        FuzzStrategy::BatteringRam => {
            // one payload applied to every point: length of first list
            list_lens.first().copied().unwrap_or(0) as u64
        }
        FuzzStrategy::Pitchfork => {
            // zip by row
            list_lens
                .iter()
                .take(n_points)
                .map(|l| *l as u64)
                .min()
                .unwrap_or(0)
        }
        FuzzStrategy::ClusterBomb => {
            let mut acc = 1u64;
            for i in 0..n_points {
                let len = list_lens.get(i).copied().unwrap_or(0) as u64;
                acc = acc.saturating_mul(len.max(1));
                if len == 0 {
                    return 0;
                }
            }
            acc
        }
    }
}

#[derive(Debug, Clone)]
pub struct FuzzCasePayloads {
    pub index: u64,
    /// Parallel to insertion points.
    pub values: Vec<String>,
}

pub struct CaseIterator {
    strategy: FuzzStrategy,
    points: usize,
    lists: Vec<Vec<String>>,
    index: u64,
    total: u64,
}

impl CaseIterator {
    pub fn new(strategy: FuzzStrategy, points: usize, lists: Vec<Vec<String>>) -> Self {
        let lens: Vec<_> = lists.iter().map(|l| l.len()).collect();
        let total = estimate_combinations(strategy, points, &lens);
        Self {
            strategy,
            points,
            lists,
            index: 0,
            total,
        }
    }

    pub fn total(&self) -> u64 {
        self.total
    }
}

impl Iterator for CaseIterator {
    type Item = FuzzCasePayloads;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.total {
            return None;
        }
        let i = self.index;
        self.index += 1;
        let values = match self.strategy {
            FuzzStrategy::Sniper => {
                // Walk points sequentially
                let mut offset = 0u64;
                for p in 0..self.points {
                    let list = self.lists.get(p).or_else(|| self.lists.first())?;
                    let len = list.len() as u64;
                    if i < offset + len {
                        let mut vals = vec![String::new(); self.points];
                        vals[p] = list[(i - offset) as usize].clone();
                        return Some(FuzzCasePayloads {
                            index: i,
                            values: vals,
                        });
                    }
                    offset += len;
                }
                return None;
            }
            FuzzStrategy::BatteringRam => {
                let list = self.lists.first()?;
                let v = list.get(i as usize)?.clone();
                vec![v; self.points]
            }
            FuzzStrategy::Pitchfork => {
                let mut vals = Vec::new();
                for p in 0..self.points {
                    let list = self.lists.get(p)?;
                    vals.push(list.get(i as usize)?.clone());
                }
                vals
            }
            FuzzStrategy::ClusterBomb => {
                let mut vals = Vec::new();
                let rem = i;
                let mut strides = vec![1u64; self.points];
                for p in (0..self.points).rev() {
                    if p + 1 < self.points {
                        let next_len = self.lists.get(p + 1).map(|l| l.len() as u64).unwrap_or(1);
                        strides[p] = strides[p + 1].saturating_mul(next_len.max(1));
                    }
                }
                // simpler odometer
                let mut idxs = vec![0usize; self.points];
                let mut x = i;
                for p in (0..self.points).rev() {
                    let len = self.lists.get(p).map(|l| l.len()).unwrap_or(1).max(1);
                    idxs[p] = (x % len as u64) as usize;
                    x /= len as u64;
                }
                for p in 0..self.points {
                    let list = self.lists.get(p)?;
                    vals.push(list.get(idxs[p])?.clone());
                }
                let _ = rem;
                vals
            }
        };
        Some(FuzzCasePayloads { index: i, values })
    }
}

pub struct FuzzerService {
    pub db: Arc<Db>,
    pub reply: Arc<ReplyService>,
    pub placeholder_key: PlaceholderKey,
    pub cancel_flags: dashmap::DashMap<i64, CancellationToken>,
}

impl FuzzerService {
    pub fn new(db: Arc<Db>, reply: Arc<ReplyService>, placeholder_key: PlaceholderKey) -> Self {
        Self {
            db,
            reply,
            placeholder_key,
            cancel_flags: dashmap::DashMap::new(),
        }
    }

    pub async fn start(
        &self,
        project_id: ProjectId,
        template: FuzzTemplate,
        confirm_large: bool,
    ) -> DomainResult<FuzzJob> {
        let project = self.db.get_project(project_id).await?;
        let lens: Vec<_> = template.wordlists.iter().map(|w| w.len()).collect();
        let estimated = estimate_combinations(
            template.strategy,
            template.insertion_points.len(),
            &lens,
        );
        if estimated > project.limits.fuzz_confirm_threshold && !confirm_large {
            return Err(DomainError::new(
                ErrorCode::CombinationLimit,
                format!(
                    "estimated {estimated} cases exceeds threshold {}; pass confirm",
                    project.limits.fuzz_confirm_threshold
                ),
            ));
        }
        if estimated > project.limits.max_fuzz_cases {
            return Err(DomainError::new(
                ErrorCode::CombinationLimit,
                format!("estimated {estimated} exceeds max_fuzz_cases"),
            ));
        }
        let template_json = serde_json::to_string(&template)
            .map_err(|e| DomainError::new(ErrorCode::InvalidArgument, e.to_string()))?;
        let job = self
            .db
            .create_fuzz_job(
                project_id,
                template.base_exchange_id,
                template.strategy,
                template_json,
                estimated,
                "{}".into(),
            )
            .await?;

        let cancel = CancellationToken::new();
        self.cancel_flags.insert(job.id.get(), cancel.clone());
        let db = self.db.clone();
        let reply = self.reply.clone();
        let key = PlaceholderKey::from_bytes(self.placeholder_key_bytes());
        let job_id = job.id;
        let strategy = template.strategy;
        let points = template.insertion_points.clone();
        let lists = template.wordlists.clone();
        let base = template.base_exchange_id;
        let draft = template.draft.clone();
        let max_conc = project.limits.max_concurrent_requests.max(1);

        tokio::spawn(async move {
            let _ = db
                .update_fuzz_job_state(job_id, FuzzJobState::Running, None, None)
                .await;
            let iter = CaseIterator::new(strategy, points.len(), lists);
            let completed = Arc::new(AtomicU64::new(0));
            let failed = Arc::new(AtomicU64::new(0));
            let stopped = AtomicBool::new(false);
            let sem = Arc::new(tokio::sync::Semaphore::new(max_conc as usize));
            let mut handles = Vec::new();

            for case in iter {
                if cancel.is_cancelled() {
                    stopped.store(true, Ordering::SeqCst);
                    break;
                }
                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                if cancel.is_cancelled() {
                    break;
                }
                let db = db.clone();
                let reply = reply.clone();
                let points = points.clone();
                let mut draft = draft.clone();
                let key_bytes = key.as_bytes().to_vec();
                let cancel2 = cancel.clone();
                let completed = completed.clone();
                let failed = failed.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    if cancel2.is_cancelled() {
                        return;
                    }
                    // Apply payloads into draft
                    for (idx, point) in points.iter().enumerate() {
                        let val = case.values.get(idx).cloned().unwrap_or_default();
                        if point.location == "body" {
                            draft.body_override = Some(val.into_bytes());
                        } else if let Some(name) = point.location.strip_prefix("header:") {
                            draft.header_overrides.push(HeaderPatch {
                                name: name.to_string(),
                                value: val.into_bytes(),
                            });
                        } else if point.location == "url" {
                            draft.url = Some(val);
                        } else if let Some(url) = draft.url.as_mut() {
                            let ph = format!("§{}§", point.name);
                            *url = url.replace(&ph, &val);
                        }
                    }
                    let _key = PlaceholderKey::from_bytes(key_bytes);
                    let result = reply
                        .send(
                            project_id,
                            None,
                            base,
                            &draft,
                            ProtocolPreference::Auto,
                            0,
                        )
                        .await;
                    match result {
                        Ok(_) => {
                            completed.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(_) => {
                            failed.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    let _ = db
                        .update_fuzz_job_state(
                            job_id,
                            FuzzJobState::Running,
                            Some(completed.load(Ordering::SeqCst)),
                            Some(failed.load(Ordering::SeqCst)),
                        )
                        .await;
                }));
            }

            for h in handles {
                let _ = h.await;
            }
            let final_state = if cancel.is_cancelled() || stopped.load(Ordering::SeqCst) {
                FuzzJobState::Interrupted
            } else {
                FuzzJobState::Completed
            };
            let _ = db
                .update_fuzz_job_state(
                    job_id,
                    final_state,
                    Some(completed.load(Ordering::SeqCst)),
                    Some(failed.load(Ordering::SeqCst)),
                )
                .await;
        });

        Ok(job)
    }

    pub async fn cancel(&self, job_id: FuzzJobId) -> DomainResult<()> {
        if let Some(c) = self.cancel_flags.get(&job_id.get()) {
            c.cancel();
        }
        self.db
            .update_fuzz_job_state(job_id, FuzzJobState::Cancelling, None, None)
            .await
    }

    pub async fn list(&self, project_id: ProjectId) -> DomainResult<Vec<FuzzJob>> {
        self.db.list_fuzz_jobs(project_id).await
    }

    pub async fn get(&self, project_id: ProjectId, job_id: FuzzJobId) -> DomainResult<FuzzJob> {
        self.db.get_fuzz_job(project_id, job_id).await
    }

    fn placeholder_key_bytes(&self) -> Vec<u8> {
        self.placeholder_key.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniper_count() {
        let n = estimate_combinations(FuzzStrategy::Sniper, 2, &[3, 4]);
        assert_eq!(n, 7);
    }

    #[test]
    fn cluster_bomb_count() {
        let n = estimate_combinations(FuzzStrategy::ClusterBomb, 2, &[2, 3]);
        assert_eq!(n, 6);
    }

    #[test]
    fn pitchfork_and_ram() {
        assert_eq!(
            estimate_combinations(FuzzStrategy::Pitchfork, 2, &[5, 3]),
            3
        );
        assert_eq!(
            estimate_combinations(FuzzStrategy::BatteringRam, 2, &[10, 99]),
            10
        );
    }

    #[test]
    fn iterator_cluster() {
        let it = CaseIterator::new(
            FuzzStrategy::ClusterBomb,
            2,
            vec![vec!["a".into(), "b".into()], vec!["1".into(), "2".into()]],
        );
        assert_eq!(it.total(), 4);
        let all: Vec<_> = it.collect();
        assert_eq!(all.len(), 4);
    }
}
