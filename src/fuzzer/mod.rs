//! Bounded fuzzer execution, payload transforms, cancellation, and persisted results.

use crate::codec::apply_pipeline;
use crate::domain::*;
use crate::reply::{PlaceholderKey, ReplySendContext, ReplyService};
use crate::storage::Db;
use base64::Engine;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

mod generators;

pub use generators::PayloadGenerator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertionPoint {
    pub name: String,
    /// Supported locations: `url`, `header:<name>`, and `body`.
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzTemplate {
    #[serde(default)]
    pub base_exchange_id: Option<ExchangeId>,
    #[serde(default)]
    pub draft: ReplyDraft,
    pub insertion_points: Vec<InsertionPoint>,
    #[serde(default)]
    pub wordlists: Vec<Vec<String>>,
    /// Local UTF-8 files, one payload per line. Each file becomes one
    /// wordlist and is appended after inline wordlists.
    #[serde(default)]
    pub wordlist_files: Vec<String>,
    /// Native payload generators. Each generator becomes one wordlist and is
    /// appended after inline and file-backed wordlists.
    #[serde(default)]
    pub payload_generators: Vec<PayloadGenerator>,
    #[serde(default)]
    pub transforms: Vec<crate::codec::Transform>,
    #[serde(default = "default_fuzz_strategy")]
    pub strategy: FuzzStrategy,
}

fn default_fuzz_strategy() -> FuzzStrategy {
    FuzzStrategy::Sniper
}

pub fn estimate_cases(strategy: FuzzStrategy, points: usize, list_lens: &[usize]) -> u64 {
    estimate_combinations(strategy, points, list_lens)
}

pub fn estimate_combinations(
    strategy: FuzzStrategy,
    point_count: usize,
    list_lens: &[usize],
) -> u64 {
    if point_count == 0 {
        return 0;
    }
    match strategy {
        FuzzStrategy::Sniper => (0..point_count)
            .map(|index| {
                list_lens
                    .get(index)
                    .or_else(|| list_lens.first())
                    .copied()
                    .unwrap_or(0) as u64
            })
            .sum(),
        FuzzStrategy::BatteringRam => list_lens.first().copied().unwrap_or(0) as u64,
        FuzzStrategy::Pitchfork => (0..point_count)
            .map(|index| list_lens.get(index).copied().unwrap_or(0) as u64)
            .min()
            .unwrap_or(0),
        FuzzStrategy::ClusterBomb => {
            let mut total = 1u64;
            for index in 0..point_count {
                let len = list_lens.get(index).copied().unwrap_or(0) as u64;
                if len == 0 {
                    return 0;
                }
                total = total.saturating_mul(len);
            }
            total
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzCasePayloads {
    pub index: u64,
    /// Parallel to insertion points. `None` means this point is untouched (Sniper).
    pub values: Vec<Option<String>>,
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
        let lens = lists.iter().map(Vec::len).collect::<Vec<_>>();
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
        let case_index = self.index;
        self.index += 1;
        let values = match self.strategy {
            FuzzStrategy::Sniper => {
                let mut offset = 0u64;
                let mut values = vec![None; self.points];
                for point_index in 0..self.points {
                    let list = self.lists.get(point_index).or_else(|| self.lists.first())?;
                    let list_len = list.len() as u64;
                    if case_index < offset + list_len {
                        values[point_index] = list.get((case_index - offset) as usize).cloned();
                        return Some(FuzzCasePayloads {
                            index: case_index,
                            values,
                        });
                    }
                    offset += list_len;
                }
                return None;
            }
            FuzzStrategy::BatteringRam => {
                let value = self.lists.first()?.get(case_index as usize)?.clone();
                vec![Some(value); self.points]
            }
            FuzzStrategy::Pitchfork => (0..self.points)
                .map(|point_index| {
                    self.lists
                        .get(point_index)?
                        .get(case_index as usize)
                        .cloned()
                        .map(Some)
                })
                .collect::<Option<Vec<_>>>()?,
            FuzzStrategy::ClusterBomb => {
                let mut remaining = case_index;
                let mut indexes = vec![0usize; self.points];
                for point_index in (0..self.points).rev() {
                    let len = self.lists.get(point_index)?.len();
                    indexes[point_index] = (remaining % len as u64) as usize;
                    remaining /= len as u64;
                }
                (0..self.points)
                    .map(|point_index| {
                        self.lists
                            .get(point_index)?
                            .get(indexes[point_index])
                            .cloned()
                            .map(Some)
                    })
                    .collect::<Option<Vec<_>>>()?
            }
        };
        Some(FuzzCasePayloads {
            index: case_index,
            values,
        })
    }
}

pub struct FuzzerService {
    pub db: Arc<Db>,
    pub reply: Arc<ReplyService>,
    pub placeholder_key: PlaceholderKey,
    pub cancel_flags: Arc<dashmap::DashMap<i64, CancellationToken>>,
    project_limiters: Arc<dashmap::DashMap<i64, Arc<ProjectFuzzLimiter>>>,
}

#[derive(Debug)]
struct ProjectFuzzLimiter {
    concurrency: Arc<Semaphore>,
    next_dispatch: Mutex<Instant>,
    dispatch_interval: Duration,
}

impl ProjectFuzzLimiter {
    fn new(limits: &ProjectLimits) -> DomainResult<Self> {
        if limits.max_concurrent_requests == 0 {
            return Err(DomainError::invalid(
                "max_concurrent_requests must be greater than zero",
            ));
        }
        if !limits.requests_per_second.is_finite() || limits.requests_per_second <= 0.0 {
            return Err(DomainError::invalid(
                "requests_per_second must be a finite positive number",
            ));
        }
        Ok(Self {
            concurrency: Arc::new(Semaphore::new(limits.max_concurrent_requests as usize)),
            next_dispatch: Mutex::new(Instant::now()),
            dispatch_interval: Duration::from_secs_f64(1.0 / limits.requests_per_second),
        })
    }

    async fn acquire(
        &self,
        cancel: &CancellationToken,
    ) -> DomainResult<Option<OwnedSemaphorePermit>> {
        let permit = tokio::select! {
            _ = cancel.cancelled() => return Ok(None),
            permit = self.concurrency.clone().acquire_owned() => permit
                .map_err(|_| DomainError::new(ErrorCode::Unavailable, "fuzzer limiter closed"))?,
        };
        let wait = {
            let mut next_dispatch = self.next_dispatch.lock().await;
            let now = Instant::now();
            let scheduled = (*next_dispatch).max(now);
            *next_dispatch = scheduled + self.dispatch_interval;
            scheduled.saturating_duration_since(now)
        };
        if !wait.is_zero() {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(None),
                _ = tokio::time::sleep(wait) => {}
            }
        }
        Ok(Some(permit))
    }
}

impl FuzzerService {
    pub fn new(db: Arc<Db>, reply: Arc<ReplyService>, placeholder_key: PlaceholderKey) -> Self {
        Self {
            db,
            reply,
            placeholder_key,
            cancel_flags: Arc::new(dashmap::DashMap::new()),
            project_limiters: Arc::new(dashmap::DashMap::new()),
        }
    }

    pub fn has_active_jobs(&self) -> bool {
        !self.cancel_flags.is_empty()
    }

    fn project_limiter(&self, project: &Project) -> DomainResult<Arc<ProjectFuzzLimiter>> {
        if let Some(existing) = self.project_limiters.get(&project.id.get()) {
            return Ok(existing.clone());
        }
        let limiter = Arc::new(ProjectFuzzLimiter::new(&project.limits)?);
        let entry = self
            .project_limiters
            .entry(project.id.get())
            .or_insert_with(|| limiter.clone());
        Ok(entry.clone())
    }

    pub async fn start(
        &self,
        project_id: ProjectId,
        mut template: FuzzTemplate,
        confirm_large: bool,
    ) -> DomainResult<FuzzJob> {
        let project = self.db.get_project(project_id).await?;
        load_wordlist_files(&mut template).await?;
        generators::expand_generators(&mut template, project.limits.max_fuzz_cases)?;
        validate_template(&template)?;
        if let Some(base_exchange_id) = template.base_exchange_id {
            self.db
                .get_exchange_detail(
                    project_id,
                    base_exchange_id,
                    crate::policy::PresentationOptions::default(),
                )
                .await?;
        }
        let list_lens = template.wordlists.iter().map(Vec::len).collect::<Vec<_>>();
        let estimated = estimate_combinations(
            template.strategy,
            template.insertion_points.len(),
            &list_lens,
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
        let limiter = self.project_limiter(&project)?;

        let template_json = serde_json::to_string(&template)
            .map_err(|error| DomainError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let job = self
            .db
            .create_fuzz_job(
                project_id,
                template.base_exchange_id,
                template.strategy,
                template_json,
                estimated,
                serde_json::json!({
                    "max_concurrent_requests": project.limits.max_concurrent_requests,
                    "max_fuzz_cases": project.limits.max_fuzz_cases,
                })
                .to_string(),
            )
            .await?;

        let cancel = CancellationToken::new();
        self.cancel_flags.insert(job.id.get(), cancel.clone());
        let db = self.db.clone();
        let reply = self.reply.clone();
        let cancel_flags = self.cancel_flags.clone();
        let job_id = job.id;
        let max_concurrency = project.limits.max_concurrent_requests.max(1) as usize;
        tokio::spawn(async move {
            let result = run_job(
                db.clone(),
                reply,
                project_id,
                job_id,
                template,
                max_concurrency,
                limiter,
                cancel.clone(),
            )
            .await;
            if let Err(error) = result {
                let _ = db
                    .set_fuzz_job_state(
                        project_id,
                        job_id,
                        FuzzJobState::Failed,
                        Some(error.to_string()),
                    )
                    .await;
            }
            cancel_flags.remove(&job_id.get());
        });

        Ok(job)
    }

    pub async fn cancel_for_project(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
    ) -> DomainResult<()> {
        let job = self.db.get_fuzz_job(project_id, job_id).await?;
        if matches!(
            job.state,
            FuzzJobState::Completed | FuzzJobState::Failed | FuzzJobState::Interrupted
        ) {
            return Err(DomainError::conflict("fuzz job is already terminal"));
        }
        let token = self
            .cancel_flags
            .get(&job_id.get())
            .map(|entry| entry.value().clone());
        if let Some(token) = token {
            self.db
                .set_fuzz_job_state(project_id, job_id, FuzzJobState::Cancelling, None)
                .await?;
            token.cancel();
        } else {
            self.db
                .set_fuzz_job_state(
                    project_id,
                    job_id,
                    FuzzJobState::Interrupted,
                    Some("fuzz worker is not active".into()),
                )
                .await?;
        }
        Ok(())
    }

    /// Compatibility wrapper for callers that do not yet pass the route project id.
    pub async fn cancel(&self, job_id: FuzzJobId) -> DomainResult<()> {
        let job = self.db.get_fuzz_job_by_id(job_id).await?;
        self.cancel_for_project(job.project_id, job_id).await
    }

    pub async fn list(&self, project_id: ProjectId) -> DomainResult<Vec<FuzzJob>> {
        self.db.list_fuzz_jobs(project_id).await
    }

    pub async fn get(&self, project_id: ProjectId, job_id: FuzzJobId) -> DomainResult<FuzzJob> {
        self.db.get_fuzz_job(project_id, job_id).await
    }

    pub async fn list_cases(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
        limit: u32,
        before_case_index: Option<u64>,
    ) -> DomainResult<(Vec<FuzzCaseResult>, Option<u64>)> {
        self.db
            .list_fuzz_cases(project_id, job_id, limit, before_case_index)
            .await
    }
}

const MAX_WORDLIST_FILE_BYTES: u64 = 10 * 1024 * 1024;

async fn load_wordlist_files(template: &mut FuzzTemplate) -> DomainResult<()> {
    for file_path in std::mem::take(&mut template.wordlist_files) {
        let path = std::path::PathBuf::from(&file_path);
        let metadata = tokio::fs::metadata(&path).await.map_err(|error| {
            DomainError::invalid(format!("read wordlist file {file_path}: {error}"))
        })?;
        if !metadata.is_file() {
            return Err(DomainError::invalid(format!(
                "wordlist path is not a file: {file_path}"
            )));
        }
        if metadata.len() > MAX_WORDLIST_FILE_BYTES {
            return Err(DomainError::new(
                ErrorCode::BodyTooLarge,
                format!("wordlist file exceeds 10 MiB: {file_path}"),
            ));
        }
        let contents = tokio::fs::read_to_string(&path).await.map_err(|error| {
            DomainError::invalid(format!(
                "wordlist file must be UTF-8 ({file_path}): {error}"
            ))
        })?;
        let payloads = contents.lines().map(str::to_string).collect::<Vec<_>>();
        if payloads.is_empty() {
            return Err(DomainError::invalid(format!(
                "wordlist file is empty: {file_path}"
            )));
        }
        template.wordlists.push(payloads);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_job(
    db: Arc<Db>,
    reply: Arc<ReplyService>,
    project_id: ProjectId,
    job_id: FuzzJobId,
    template: FuzzTemplate,
    max_concurrency: usize,
    limiter: Arc<ProjectFuzzLimiter>,
    cancel: CancellationToken,
) -> DomainResult<()> {
    db.set_fuzz_job_state(project_id, job_id, FuzzJobState::Running, None)
        .await?;
    let mut cases = CaseIterator::new(
        template.strategy,
        template.insertion_points.len(),
        template.wordlists.clone(),
    );
    let mut running = FuturesUnordered::new();
    let mut exhausted = false;

    loop {
        while !exhausted && !cancel.is_cancelled() && running.len() < max_concurrency {
            let Some(case) = cases.next() else {
                exhausted = true;
                break;
            };
            let db = db.clone();
            let reply = reply.clone();
            let template = template.clone();
            let limiter = limiter.clone();
            let cancel = cancel.clone();
            running.push(tokio::spawn(async move {
                execute_case(
                    db, reply, project_id, job_id, template, case, limiter, cancel,
                )
                .await
            }));
        }

        if running.is_empty() {
            break;
        }
        match running.next().await {
            Some(Ok(result)) => result?,
            Some(Err(error)) => {
                return Err(DomainError::new(
                    ErrorCode::Internal,
                    format!("fuzz case task failed: {error}"),
                ));
            }
            None => break,
        }
    }

    if cancel.is_cancelled() {
        return db
            .set_fuzz_job_state(project_id, job_id, FuzzJobState::Interrupted, None)
            .await;
    }

    let job = db.get_fuzz_job(project_id, job_id).await?;
    if job.completed_cases == 0 && job.failed_cases > 0 {
        db.set_fuzz_job_state(
            project_id,
            job_id,
            FuzzJobState::Failed,
            Some(format!("all {} fuzz cases failed", job.failed_cases)),
        )
        .await
    } else {
        db.set_fuzz_job_state(project_id, job_id, FuzzJobState::Completed, None)
            .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_case(
    db: Arc<Db>,
    reply: Arc<ReplyService>,
    project_id: ProjectId,
    job_id: FuzzJobId,
    template: FuzzTemplate,
    case: FuzzCasePayloads,
    limiter: Arc<ProjectFuzzLimiter>,
    cancel: CancellationToken,
) -> DomainResult<()> {
    let prepared = prepare_case(&template, &case);
    let payloads = match &prepared {
        Ok(prepared) => prepared.payloads.clone(),
        Err(error) => error.payloads.clone(),
    };
    let persisted = db
        .create_fuzz_case(project_id, job_id, case.index, payloads)
        .await?;
    if cancel.is_cancelled() {
        return db
            .finish_fuzz_case(
                project_id,
                job_id,
                persisted.id,
                FuzzCaseState::Cancelled,
                None,
                None,
                None,
                None,
                Some("cancelled before dispatch".into()),
                None,
            )
            .await;
    }
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return db
                .finish_fuzz_case(
                    project_id,
                    job_id,
                    persisted.id,
                    FuzzCaseState::Failed,
                    None,
                    None,
                    None,
                    None,
                    Some(error.message),
                    None,
                )
                .await;
        }
    };
    db.mark_fuzz_case_running(project_id, job_id, persisted.id)
        .await?;
    let Some(_permit) = limiter.acquire(&cancel).await? else {
        return db
            .finish_fuzz_case(
                project_id,
                job_id,
                persisted.id,
                FuzzCaseState::Cancelled,
                None,
                None,
                None,
                None,
                Some("cancelled before dispatch".into()),
                None,
            )
            .await;
    };
    if cancel.is_cancelled() {
        return db
            .finish_fuzz_case(
                project_id,
                job_id,
                persisted.id,
                FuzzCaseState::Cancelled,
                None,
                None,
                None,
                None,
                Some("cancelled before dispatch".into()),
                None,
            )
            .await;
    }
    let result = reply
        .send_with_context(
            project_id,
            template.base_exchange_id,
            &prepared.draft,
            ProtocolPreference::Auto,
            0,
            ReplySendContext::fuzzer(template.base_exchange_id, job_id, persisted.id),
        )
        .await;
    match result {
        Ok(result) => {
            let Some(exchange_id) = result.exchange_id else {
                return db
                    .finish_fuzz_case(
                        project_id,
                        job_id,
                        persisted.id,
                        FuzzCaseState::Completed,
                        None,
                        Some(result.status_code),
                        Some(result.response_length),
                        Some(result.duration_ms),
                        None,
                        Some(result.response_body_hash),
                    )
                    .await;
            };
            let detail = db
                .get_exchange_detail(
                    project_id,
                    exchange_id,
                    crate::policy::PresentationOptions::default(),
                )
                .await;
            match detail {
                Ok(detail) => {
                    db.finish_fuzz_case(
                        project_id,
                        job_id,
                        persisted.id,
                        FuzzCaseState::Completed,
                        Some(exchange_id),
                        detail.summary.status_code,
                        detail.summary.response_length,
                        detail.summary.duration_ms,
                        None,
                        detail.response_body_hash,
                    )
                    .await
                }
                Err(error) => {
                    db.finish_fuzz_case(
                        project_id,
                        job_id,
                        persisted.id,
                        FuzzCaseState::Failed,
                        Some(exchange_id),
                        None,
                        None,
                        None,
                        Some(format!("request sent but result loading failed: {error}")),
                        None,
                    )
                    .await
                }
            }
        }
        Err(error) => {
            let exchange_id = db
                .find_fuzz_case_exchange(project_id, job_id, persisted.id)
                .await?;
            db.finish_fuzz_case(
                project_id,
                job_id,
                persisted.id,
                FuzzCaseState::Failed,
                exchange_id,
                None,
                None,
                None,
                Some(error.to_string()),
                None,
            )
            .await
        }
    }
}

#[derive(Debug)]
struct PreparedCase {
    draft: ReplyDraft,
    payloads: Vec<FuzzCasePayload>,
}

#[derive(Debug)]
struct PrepareError {
    message: String,
    payloads: Vec<FuzzCasePayload>,
}

fn prepare_case(
    template: &FuzzTemplate,
    case: &FuzzCasePayloads,
) -> Result<PreparedCase, PrepareError> {
    let mut draft = template.draft.clone();
    let mut payloads = Vec::new();
    for (index, point) in template.insertion_points.iter().enumerate() {
        let Some(raw_value) = case.values.get(index).and_then(Option::as_ref) else {
            continue;
        };
        let transformed = match apply_pipeline(&template.transforms, raw_value.as_bytes()) {
            Ok(value) => value,
            Err(error) => {
                payloads.push(display_payload(point, raw_value.as_bytes()));
                return Err(PrepareError {
                    message: error.to_string(),
                    payloads,
                });
            }
        };
        payloads.push(display_payload(point, &transformed));
        if let Err(error) = apply_insertion(&mut draft, point, &transformed) {
            return Err(PrepareError {
                message: error.to_string(),
                payloads,
            });
        }
    }
    Ok(PreparedCase { draft, payloads })
}

fn apply_insertion(
    draft: &mut ReplyDraft,
    point: &InsertionPoint,
    payload: &[u8],
) -> DomainResult<()> {
    let marker = format!("§{}§", point.name);
    match point.location.as_str() {
        "body" => {
            draft.body_cleared = false;
            draft.body_override = Some(match draft.body_override.take() {
                Some(body) if contains_bytes(&body, marker.as_bytes()) => {
                    replace_bytes(&body, marker.as_bytes(), payload)
                }
                _ => payload.to_vec(),
            });
        }
        "url" => {
            let payload = std::str::from_utf8(payload)
                .map_err(|_| DomainError::invalid("URL payload must be UTF-8 after transforms"))?;
            draft.url = Some(match draft.url.take() {
                Some(url) if url.contains(&marker) => url.replace(&marker, payload),
                _ if url::Url::parse(payload)
                    .is_ok_and(|url| matches!(url.scheme(), "http" | "https")) =>
                {
                    payload.to_string()
                }
                _ => {
                    return Err(DomainError::invalid(format!(
                        "URL insertion point '{}' requires marker '{}' in draft.url; without a marker each payload must be an absolute URL",
                        point.name, marker
                    )))
                }
            });
        }
        location if location.starts_with("header:") => {
            let header_name = location.trim_start_matches("header:");
            let existing = draft
                .header_overrides
                .iter_mut()
                .find(|header| header.name.eq_ignore_ascii_case(header_name));
            if let Some(existing) = existing {
                existing.value = if contains_bytes(&existing.value, marker.as_bytes()) {
                    replace_bytes(&existing.value, marker.as_bytes(), payload)
                } else {
                    payload.to_vec()
                };
            } else {
                draft.header_overrides.push(HeaderPatch {
                    name: header_name.to_string(),
                    value: payload.to_vec(),
                });
            }
        }
        _ => return Err(DomainError::invalid("unsupported insertion point location")),
    }
    Ok(())
}

fn display_payload(point: &InsertionPoint, payload: &[u8]) -> FuzzCasePayload {
    match std::str::from_utf8(payload) {
        Ok(value) => FuzzCasePayload {
            insertion_point: point.name.clone(),
            location: point.location.clone(),
            encoding: "text".into(),
            value: value.to_string(),
        },
        Err(_) => FuzzCasePayload {
            insertion_point: point.name.clone(),
            location: point.location.clone(),
            encoding: "base64".into(),
            value: base64::engine::general_purpose::STANDARD.encode(payload),
        },
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut output = Vec::with_capacity(haystack.len());
    let mut offset = 0;
    while let Some(relative) = haystack[offset..]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        let position = offset + relative;
        output.extend_from_slice(&haystack[offset..position]);
        output.extend_from_slice(replacement);
        offset = position + needle.len();
    }
    output.extend_from_slice(&haystack[offset..]);
    output
}

fn validate_template(template: &FuzzTemplate) -> DomainResult<()> {
    let point_count = template.insertion_points.len();
    if point_count == 0 {
        return Err(DomainError::invalid(
            "at least one insertion point is required",
        ));
    }
    let mut names = HashSet::new();
    for point in &template.insertion_points {
        if point.name.trim().is_empty() {
            return Err(DomainError::invalid("insertion point name is required"));
        }
        if !names.insert(point.name.clone()) {
            return Err(DomainError::invalid(format!(
                "duplicate insertion point name: {}",
                point.name
            )));
        }
        let valid_location = point.location == "url"
            || point.location == "body"
            || point
                .location
                .strip_prefix("header:")
                .is_some_and(|name| !name.trim().is_empty());
        if !valid_location {
            return Err(DomainError::invalid(format!(
                "unsupported insertion point location: {}",
                point.location
            )));
        }
    }
    let expected_wordlists = match template.strategy {
        FuzzStrategy::BatteringRam => 1,
        FuzzStrategy::Sniper if template.wordlists.len() == 1 => 1,
        _ => point_count,
    };
    if template.wordlists.len() != expected_wordlists {
        return Err(DomainError::invalid(format!(
            "strategy {:?} requires {expected_wordlists} wordlist(s)",
            template.strategy
        )));
    }
    if template.wordlists.iter().any(Vec::is_empty) {
        return Err(DomainError::invalid("wordlists must not be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Transform;
    use crate::transport::{OutboundRequest, OutboundResponse, SemanticTransport};
    use bytes::Bytes;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct FailingTransport;

    struct MixedTransport {
        calls: AtomicUsize,
    }

    fn test_limiter(
        max_concurrent_requests: u32,
        requests_per_second: f64,
    ) -> Arc<ProjectFuzzLimiter> {
        let limits = ProjectLimits {
            max_concurrent_requests,
            requests_per_second,
            ..Default::default()
        };
        Arc::new(ProjectFuzzLimiter::new(&limits).unwrap())
    }

    #[async_trait::async_trait]
    impl SemanticTransport for FailingTransport {
        async fn send(
            &self,
            _dial: &ValidatedDial,
            _request: OutboundRequest,
        ) -> DomainResult<OutboundResponse> {
            Err(DomainError::new(
                ErrorCode::Unavailable,
                "synthetic transport failure",
            ))
        }

        fn profile_name(&self) -> &str {
            "test_failure"
        }

        fn provenance(&self) -> TransportProvenance {
            TransportProvenance::GenericUnprofiled
        }
    }

    #[async_trait::async_trait]
    impl SemanticTransport for MixedTransport {
        async fn send(
            &self,
            _dial: &ValidatedDial,
            _request: OutboundRequest,
        ) -> DomainResult<OutboundResponse> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(OutboundResponse {
                    status: http::StatusCode::OK,
                    headers: vec![("content-type".into(), b"text/plain".to_vec())],
                    body: Bytes::from_static(b"ok"),
                    body_truncated: false,
                    protocol: "HTTP/1.1".into(),
                    transport_provenance: TransportProvenance::GenericUnprofiled,
                    transport_profile: "test_mixed".into(),
                    duration: Duration::from_millis(1),
                })
            } else {
                Err(DomainError::new(
                    ErrorCode::Unavailable,
                    "synthetic transport failure",
                ))
            }
        }

        fn profile_name(&self) -> &str {
            "test_mixed"
        }

        fn provenance(&self) -> TransportProvenance {
            TransportProvenance::GenericUnprofiled
        }
    }

    #[test]
    fn strategy_counts_are_correct() {
        assert_eq!(estimate_combinations(FuzzStrategy::Sniper, 2, &[3, 4]), 7);
        assert_eq!(
            estimate_combinations(FuzzStrategy::BatteringRam, 2, &[3]),
            3
        );
        assert_eq!(
            estimate_combinations(FuzzStrategy::Pitchfork, 2, &[5, 3]),
            3
        );
        assert_eq!(
            estimate_combinations(FuzzStrategy::ClusterBomb, 2, &[2, 3]),
            6
        );
    }

    #[test]
    fn sniper_mutates_only_one_point_per_case() {
        let cases = CaseIterator::new(
            FuzzStrategy::Sniper,
            2,
            vec![vec!["a".into(), "b".into()], vec!["1".into()]],
        )
        .collect::<Vec<_>>();
        assert_eq!(cases.len(), 3);
        assert_eq!(cases[0].values, vec![Some("a".into()), None]);
        assert_eq!(cases[2].values, vec![None, Some("1".into())]);
    }

    #[test]
    fn cluster_bomb_is_a_cartesian_product() {
        let cases = CaseIterator::new(
            FuzzStrategy::ClusterBomb,
            2,
            vec![vec!["a".into(), "b".into()], vec!["1".into(), "2".into()]],
        )
        .collect::<Vec<_>>();
        assert_eq!(cases.len(), 4);
        assert_eq!(cases[0].values, vec![Some("a".into()), Some("1".into())]);
        assert_eq!(cases[3].values, vec![Some("b".into()), Some("2".into())]);
    }

    #[test]
    fn transforms_and_markers_are_applied() {
        let template = FuzzTemplate {
            base_exchange_id: None,
            draft: ReplyDraft {
                url: Some("https://example.test/§path§".into()),
                body_override: Some("before=§body§".as_bytes().to_vec()),
                ..Default::default()
            },
            insertion_points: vec![
                InsertionPoint {
                    name: "path".into(),
                    location: "url".into(),
                },
                InsertionPoint {
                    name: "body".into(),
                    location: "body".into(),
                },
            ],
            wordlists: vec![vec!["admin".into()], vec!["x".into()]],
            wordlist_files: vec![],
            payload_generators: vec![],
            transforms: vec![Transform::HexEncode],
            strategy: FuzzStrategy::Pitchfork,
        };
        let case = CaseIterator::new(
            template.strategy,
            template.insertion_points.len(),
            template.wordlists.clone(),
        )
        .next()
        .unwrap();
        let prepared = prepare_case(&template, &case).unwrap();
        assert_eq!(
            prepared.draft.url.as_deref(),
            Some("https://example.test/61646d696e")
        );
        assert_eq!(
            prepared.draft.body_override.as_deref(),
            Some(b"before=78".as_slice())
        );
    }

    #[test]
    fn minimal_template_defaults_to_sniper_without_transforms() {
        let template: FuzzTemplate = serde_json::from_value(serde_json::json!({
            "draft": {"url": "https://example.test/?q=§q§"},
            "insertion_points": [{"name": "q", "location": "url"}],
            "wordlists": [["alpha"]]
        }))
        .unwrap();

        assert_eq!(template.strategy, FuzzStrategy::Sniper);
        assert!(template.transforms.is_empty());
        assert_eq!(template.base_exchange_id, None);
        assert!(template.wordlist_files.is_empty());
        assert!(template.payload_generators.is_empty());
    }

    #[tokio::test]
    async fn wordlist_files_load_one_payload_per_line() {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "alpha\r\n\r\n:smtg\r\n").unwrap();
        let mut template = FuzzTemplate {
            base_exchange_id: None,
            draft: ReplyDraft::default(),
            insertion_points: vec![InsertionPoint {
                name: "value".into(),
                location: "url".into(),
            }],
            wordlists: vec![],
            wordlist_files: vec![file.path().display().to_string()],
            payload_generators: vec![],
            transforms: vec![],
            strategy: FuzzStrategy::Sniper,
        };

        load_wordlist_files(&mut template).await.unwrap();
        assert_eq!(template.wordlists, vec![vec!["alpha", "", ":smtg"]]);
        assert!(template.wordlist_files.is_empty());
        validate_template(&template).unwrap();
    }

    #[test]
    fn url_payload_without_matching_marker_has_actionable_error() {
        let template = FuzzTemplate {
            base_exchange_id: None,
            draft: ReplyDraft {
                url: Some("https://example.test/?q=§other§".into()),
                ..Default::default()
            },
            insertion_points: vec![InsertionPoint {
                name: "q".into(),
                location: "url".into(),
            }],
            wordlists: vec![vec!["alpha".into()]],
            wordlist_files: vec![],
            payload_generators: vec![],
            transforms: vec![],
            strategy: FuzzStrategy::Sniper,
        };
        let case = CaseIterator::new(
            template.strategy,
            template.insertion_points.len(),
            template.wordlists.clone(),
        )
        .next()
        .unwrap();
        let error = prepare_case(&template, &case).unwrap_err();

        assert!(error.message.contains("requires marker '§q§'"));
    }

    #[tokio::test]
    async fn project_limiter_enforces_concurrency_and_rate() {
        let limiter = test_limiter(1, 20.0);
        let cancel = CancellationToken::new();
        let first = limiter.acquire(&cancel).await.unwrap().unwrap();
        let blocked =
            tokio::time::timeout(Duration::from_millis(20), limiter.acquire(&cancel)).await;
        assert!(
            blocked.is_err(),
            "second request bypassed concurrency limit"
        );
        drop(first);
        let second = tokio::time::timeout(Duration::from_millis(100), limiter.acquire(&cancel))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(second);

        let limiter = test_limiter(4, 20.0);
        let started = Instant::now();
        for _ in 0..3 {
            drop(limiter.acquire(&cancel).await.unwrap().unwrap());
        }
        assert!(
            started.elapsed() >= Duration::from_millis(90),
            "three dispatches exceeded the shared 20 requests/second limit"
        );
    }

    #[tokio::test]
    async fn queued_requests_remain_rate_limited_after_concurrency_frees() {
        let limiter = test_limiter(2, 10.0);
        let cancel = CancellationToken::new();
        let first = limiter.acquire(&cancel).await.unwrap().unwrap();
        let second = limiter.acquire(&cancel).await.unwrap().unwrap();

        let acquire_at = |limiter: Arc<ProjectFuzzLimiter>, cancel: CancellationToken| async move {
            let permit = limiter.acquire(&cancel).await.unwrap().unwrap();
            let acquired_at = Instant::now();
            (permit, acquired_at)
        };
        let third = tokio::spawn(acquire_at(limiter.clone(), cancel.clone()));
        let fourth = tokio::spawn(acquire_at(limiter.clone(), cancel.clone()));
        tokio::time::sleep(Duration::from_millis(220)).await;
        drop(first);
        drop(second);

        let (_, third_at) = third.await.unwrap();
        let (_, fourth_at) = fourth.await.unwrap();
        let gap = if third_at >= fourth_at {
            third_at.duration_since(fourth_at)
        } else {
            fourth_at.duration_since(third_at)
        };
        assert!(
            gap >= Duration::from_millis(80),
            "queued requests burst after permits became available: gap was {gap:?}"
        );
    }

    #[tokio::test]
    async fn concurrent_jobs_in_one_project_share_the_same_limiter() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "shared limiter".into(),
                target_url: "http://127.0.0.1:9/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: Arc::new(FailingTransport),
            placeholder_key: PlaceholderKey::from_bytes(vec![5; 32]),
        });
        let service = FuzzerService::new(db, reply, PlaceholderKey::from_bytes(vec![6; 32]));
        let first = service.project_limiter(&project).unwrap();
        let second = service.project_limiter(&project).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn all_failed_cases_keep_fuzzer_provenance_and_fail_the_job() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "fuzz failure".into(),
                target_url: "http://127.0.0.1:9/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let template = FuzzTemplate {
            base_exchange_id: None,
            draft: ReplyDraft {
                url: Some("http://127.0.0.1:9/?q=§value§".into()),
                ..Default::default()
            },
            insertion_points: vec![InsertionPoint {
                name: "value".into(),
                location: "url".into(),
            }],
            wordlists: vec![vec!["payload".into()]],
            wordlist_files: vec![],
            payload_generators: vec![],
            transforms: vec![],
            strategy: FuzzStrategy::Sniper,
        };
        let job = db
            .create_fuzz_job(
                project.id,
                None,
                template.strategy,
                serde_json::to_string(&template).unwrap(),
                1,
                "{}".into(),
            )
            .await
            .unwrap();
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: Arc::new(FailingTransport),
            placeholder_key: PlaceholderKey::from_bytes(vec![7; 32]),
        });

        run_job(
            db.clone(),
            reply,
            project.id,
            job.id,
            template,
            1,
            test_limiter(1, 1_000.0),
            CancellationToken::new(),
        )
        .await
        .unwrap();

        let job = db.get_fuzz_job(project.id, job.id).await.unwrap();
        assert_eq!(job.state, FuzzJobState::Failed);
        assert_eq!(job.completed_cases, 0);
        assert_eq!(job.failed_cases, 1);
        assert_eq!(job.error.as_deref(), Some("all 1 fuzz cases failed"));

        let (cases, _) = db
            .list_fuzz_cases(project.id, job.id, 10, None)
            .await
            .unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].state, FuzzCaseState::Failed);
        let exchange_id = cases[0]
            .exchange_id
            .expect("failed transport exchange should remain linked");
        let detail = db
            .get_exchange_detail(
                project.id,
                exchange_id,
                crate::policy::PresentationOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(detail.summary.source, ExchangeSource::Fuzzer);
        assert_eq!(detail.lineage.fuzz_job_id, Some(job.id));
        assert_eq!(detail.lineage.fuzz_case_id, Some(cases[0].id));
    }

    #[tokio::test]
    async fn mixed_case_outcomes_complete_with_failure_count_visible() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "mixed fuzz".into(),
                target_url: "http://127.0.0.1:9/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let template = FuzzTemplate {
            base_exchange_id: None,
            draft: ReplyDraft {
                url: Some("http://127.0.0.1:9/?q=§value§".into()),
                ..Default::default()
            },
            insertion_points: vec![InsertionPoint {
                name: "value".into(),
                location: "url".into(),
            }],
            wordlists: vec![vec!["first".into(), "second".into()]],
            wordlist_files: vec![],
            payload_generators: vec![],
            transforms: vec![],
            strategy: FuzzStrategy::Sniper,
        };
        let job = db
            .create_fuzz_job(
                project.id,
                None,
                template.strategy,
                serde_json::to_string(&template).unwrap(),
                2,
                "{}".into(),
            )
            .await
            .unwrap();
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: Arc::new(MixedTransport {
                calls: AtomicUsize::new(0),
            }),
            placeholder_key: PlaceholderKey::from_bytes(vec![9; 32]),
        });

        run_job(
            db.clone(),
            reply,
            project.id,
            job.id,
            template,
            1,
            test_limiter(1, 1_000.0),
            CancellationToken::new(),
        )
        .await
        .unwrap();

        let job = db.get_fuzz_job(project.id, job.id).await.unwrap();
        assert_eq!(job.state, FuzzJobState::Completed);
        assert_eq!(job.completed_cases, 1);
        assert_eq!(job.failed_cases, 1);
        assert_eq!(job.error, None);
        let (cases, _) = db
            .list_fuzz_cases(project.id, job.id, 10, None)
            .await
            .unwrap();
        assert_eq!(cases.len(), 2);
        assert!(cases.iter().all(|case| case.exchange_id.is_some()));
        for case in cases {
            let detail = db
                .get_exchange_detail(
                    project.id,
                    case.exchange_id.unwrap(),
                    crate::policy::PresentationOptions::default(),
                )
                .await
                .unwrap();
            assert_eq!(detail.summary.source, ExchangeSource::Fuzzer);
            assert_eq!(detail.lineage.fuzz_job_id, Some(job.id));
            assert_eq!(detail.lineage.fuzz_case_id, Some(case.id));
        }
    }
}
