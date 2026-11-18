//! Bounded fuzzer execution, payload transforms, cancellation, and persisted results.

use crate::codec::{apply_pipeline, decode_content_encodings};
use crate::domain::*;
use crate::policy::PresentationOptions;
use crate::reply::{PlaceholderKey, ReplySendContext, ReplyService};
use crate::storage::Db;
use base64::Engine;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

mod generators;

pub use generators::PayloadGenerator;

pub const MAX_FUZZ_DIFF_TEXT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResponseGroup {
    pub group_id: String,
    pub state: FuzzCaseState,
    pub case_count: u64,
    pub representative_case_id: i64,
    pub representative_case_index: u64,
    pub representative_exchange_id: Option<ExchangeId>,
    pub status_code: Option<u16>,
    pub mime: Option<String>,
    pub body_hash: Option<String>,
    pub body_hash_matches_baseline: Option<bool>,
    pub different_from_baseline: Option<bool>,
    pub response_length_min: Option<i64>,
    pub response_length_max: Option<i64>,
    pub duration_ms_min: Option<i64>,
    pub duration_ms_avg: Option<f64>,
    pub duration_ms_max: Option<i64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FuzzBaselineKind {
    BaseExchange,
    FirstCompleted,
    ExplicitCase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzHeaderChange {
    pub name: String,
    pub kind: String,
    pub baseline_values: Vec<String>,
    pub case_values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResponseDiff {
    pub case_id: i64,
    pub case_exchange_id: ExchangeId,
    pub baseline_kind: FuzzBaselineKind,
    pub baseline_case_id: Option<i64>,
    pub baseline_exchange_id: ExchangeId,
    pub status_baseline: Option<u16>,
    pub status_case: Option<u16>,
    pub status_changed: bool,
    pub mime_baseline: Option<String>,
    pub mime_case: Option<String>,
    pub mime_changed: bool,
    pub body_hash_equal: Option<bool>,
    pub response_length_delta: Option<i64>,
    pub response_length_delta_percent: Option<f64>,
    pub duration_ms_delta: Option<i64>,
    pub duration_ratio: Option<f64>,
    pub header_changes: Vec<FuzzHeaderChange>,
    pub text_diff: Option<String>,
    pub text_diff_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertionPoint {
    pub name: String,
    /// Supported locations: `url`, `header:<name>`, and `body`.
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// How long each case may take, so a slow endpoint fails its case instead
    /// of holding a request slot for Reply's full 60 seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_ms: Option<u64>,
}

/// Bounds of a fuzz job's per-case timeout. The ceiling is Reply's own timeout.
pub const MIN_FUZZ_REQUEST_TIMEOUT_MS: u64 = 100;
pub const MAX_FUZZ_REQUEST_TIMEOUT_MS: u64 = 60_000;

fn default_fuzz_strategy() -> FuzzStrategy {
    FuzzStrategy::Sniper
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

/// The longest `wait` accepts, so one call never outlasts an MCP client's patience.
pub const MAX_FUZZ_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct FuzzerService {
    pub db: Arc<Db>,
    pub reply: Arc<ReplyService>,
    pub placeholder_key: PlaceholderKey,
    pub cancel_flags: Arc<dashmap::DashMap<i64, CancellationToken>>,
    /// One receiver per running job. Its sender is dropped once the worker has
    /// saved the job's final state, which wakes every `wait`.
    finished: Arc<dashmap::DashMap<i64, tokio::sync::watch::Receiver<()>>>,
}

impl FuzzerService {
    pub fn new(db: Arc<Db>, reply: Arc<ReplyService>, placeholder_key: PlaceholderKey) -> Self {
        Self {
            db,
            reply,
            placeholder_key,
            cancel_flags: Arc::new(dashmap::DashMap::new()),
            finished: Arc::new(dashmap::DashMap::new()),
        }
    }

    pub fn has_active_jobs(&self) -> bool {
        !self.cancel_flags.is_empty()
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
        // Keep explicitly selected credentials stable for all cases; never
        // serialize the snapshot into the saved template or job state.
        let identity = self
            .reply
            .resolve_named_identity(project_id, &template.draft)
            .await?
            .map(Arc::new);
        // Cases share the project's request budget with Reply and plugins.
        let limiter = self.reply.request_limiter.budget(&project);

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
        // One audit event per job; cases are not audited one by one.
        let mut audit = serde_json::json!({
            "parent": template.base_exchange_id.map(ExchangeId::get),
            "strategy": template.strategy,
            "estimated_cases": estimated,
        });
        if let Some(identity) = &template.draft.identity {
            audit["identity"] = serde_json::to_value(identity)
                .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))?;
        }
        let _ = self
            .db
            .audit(
                Some(project_id),
                "fuzz_start",
                Some("fuzzer"),
                Some("fuzz_job"),
                Some(&job.id.get().to_string()),
                audit,
            )
            .await;

        let cancel = CancellationToken::new();
        self.cancel_flags.insert(job.id.get(), cancel.clone());
        let (finished_sender, finished_receiver) = tokio::sync::watch::channel(());
        self.finished.insert(job.id.get(), finished_receiver);
        let db = self.db.clone();
        let reply = self.reply.clone();
        let cancel_flags = self.cancel_flags.clone();
        let finished = self.finished.clone();
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
                identity,
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
            finished.remove(&job_id.get());
            drop(finished_sender);
        });

        Ok(job)
    }

    /// The job, once it has ended or `wait` has passed, whichever is first.
    pub async fn wait(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
        wait: std::time::Duration,
    ) -> DomainResult<FuzzJob> {
        let job = self.db.get_fuzz_job(project_id, job_id).await?;
        if wait.is_zero() || fuzz_job_has_ended(job.state) {
            return Ok(job);
        }
        let finished = self
            .finished
            .get(&job_id.get())
            .map(|entry| entry.value().clone());
        if let Some(mut finished) = finished {
            // `changed` fails as soon as the worker drops the sender.
            let _ = tokio::time::timeout(wait.min(MAX_FUZZ_WAIT), finished.changed()).await;
        }
        self.db.get_fuzz_job(project_id, job_id).await
    }

    pub async fn cancel_for_project(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
    ) -> DomainResult<()> {
        let job = self.db.get_fuzz_job(project_id, job_id).await?;
        if fuzz_job_has_ended(job.state) {
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

    pub async fn list_response_groups(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
    ) -> DomainResult<Vec<FuzzResponseGroup>> {
        let mut groups = self
            .db
            .list_fuzz_response_groups(project_id, job_id)
            .await?;
        let job = self.db.get_fuzz_job(project_id, job_id).await?;
        let baseline_exchange_id = if let Some(exchange_id) = job.base_exchange_id {
            match self
                .db
                .get_exchange_detail(project_id, exchange_id, PresentationOptions::default())
                .await
            {
                Ok(detail) if detail.summary.status_code.is_some() => Some(exchange_id),
                Ok(_) | Err(_) => self
                    .db
                    .first_completed_fuzz_case_exchange(project_id, job_id)
                    .await?
                    .map(|(_, exchange_id)| exchange_id),
            }
        } else {
            self.db
                .first_completed_fuzz_case_exchange(project_id, job_id)
                .await?
                .map(|(_, exchange_id)| exchange_id)
        };
        if let Some(exchange_id) = baseline_exchange_id {
            if let Ok(baseline) = self
                .db
                .get_exchange_detail(project_id, exchange_id, PresentationOptions::default())
                .await
            {
                for group in &mut groups {
                    annotate_group_with_baseline(
                        group,
                        baseline.summary.status_code,
                        baseline.summary.mime.as_deref(),
                        baseline.response_body_hash.as_deref(),
                        baseline.summary.response_length,
                    );
                }
            }
        }
        Ok(groups)
    }

    pub async fn list_group_cases(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
        group_id: String,
        limit: u32,
        before_case_index: Option<u64>,
    ) -> DomainResult<(Vec<FuzzCaseResult>, Option<u64>)> {
        self.db
            .list_fuzz_cases_in_group(project_id, job_id, group_id, limit, before_case_index)
            .await
    }

    pub async fn response_diff(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
        case_id: i64,
        baseline_case_id: Option<i64>,
        include_text: bool,
    ) -> DomainResult<FuzzResponseDiff> {
        let job = self.db.get_fuzz_job(project_id, job_id).await?;
        let case = self.db.get_fuzz_case(project_id, job_id, case_id).await?;
        let case_exchange_id = case
            .exchange_id
            .ok_or_else(|| DomainError::invalid("fuzz case has no saved response"))?;

        let (baseline_kind, resolved_baseline_case_id, baseline_exchange_id) =
            if let Some(explicit_case_id) = baseline_case_id {
                let baseline = self
                    .db
                    .get_fuzz_case(project_id, job_id, explicit_case_id)
                    .await?;
                let exchange_id = baseline.exchange_id.ok_or_else(|| {
                    DomainError::invalid("explicit baseline case has no saved response")
                })?;
                (
                    FuzzBaselineKind::ExplicitCase,
                    Some(explicit_case_id),
                    exchange_id,
                )
            } else if let Some(exchange_id) = job.base_exchange_id {
                match self
                    .db
                    .get_exchange_detail(project_id, exchange_id, PresentationOptions::default())
                    .await
                {
                    Ok(detail) if detail.summary.status_code.is_some() => {
                        (FuzzBaselineKind::BaseExchange, None, exchange_id)
                    }
                    Ok(_) | Err(_) => self.first_completed_baseline(project_id, job_id).await?,
                }
            } else {
                self.first_completed_baseline(project_id, job_id).await?
            };

        let baseline = self
            .db
            .get_exchange_detail(
                project_id,
                baseline_exchange_id,
                PresentationOptions::default(),
            )
            .await?;
        let current = self
            .db
            .get_exchange_detail(project_id, case_exchange_id, PresentationOptions::default())
            .await?;
        let baseline_mime = normalize_response_mime(baseline.summary.mime.as_deref());
        let current_mime = normalize_response_mime(current.summary.mime.as_deref());
        let length_delta = option_delta(
            current.summary.response_length,
            baseline.summary.response_length,
        );
        let duration_delta =
            option_delta(current.summary.duration_ms, baseline.summary.duration_ms);
        let header_changes =
            compare_response_headers(&baseline.response_headers, &current.response_headers);

        let (text_diff, text_diff_warning) = if include_text {
            self.load_text_diff(
                project_id,
                baseline_exchange_id,
                case_exchange_id,
                baseline.summary.mime.as_deref(),
                current.summary.mime.as_deref(),
                &baseline.response_headers,
                &current.response_headers,
            )
            .await
        } else {
            (None, None)
        };

        Ok(FuzzResponseDiff {
            case_id,
            case_exchange_id,
            baseline_kind,
            baseline_case_id: resolved_baseline_case_id,
            baseline_exchange_id,
            status_baseline: baseline.summary.status_code,
            status_case: current.summary.status_code,
            status_changed: baseline.summary.status_code != current.summary.status_code,
            mime_changed: baseline_mime != current_mime,
            mime_baseline: baseline_mime,
            mime_case: current_mime,
            body_hash_equal: match (
                baseline.response_body_hash.as_ref(),
                current.response_body_hash.as_ref(),
            ) {
                (Some(left), Some(right)) => Some(left == right),
                _ => None,
            },
            response_length_delta: length_delta,
            response_length_delta_percent: match (length_delta, baseline.summary.response_length) {
                (Some(0), Some(0)) => Some(0.0),
                (Some(_), Some(0)) => None,
                (Some(delta), Some(base)) => Some(delta as f64 * 100.0 / base as f64),
                _ => None,
            },
            duration_ms_delta: duration_delta,
            duration_ratio: match (current.summary.duration_ms, baseline.summary.duration_ms) {
                (Some(current), Some(base)) if base != 0 => Some(current as f64 / base as f64),
                _ => None,
            },
            header_changes,
            text_diff,
            text_diff_warning,
        })
    }

    async fn first_completed_baseline(
        &self,
        project_id: ProjectId,
        job_id: FuzzJobId,
    ) -> DomainResult<(FuzzBaselineKind, Option<i64>, ExchangeId)> {
        let (case_id, exchange_id) = self
            .db
            .first_completed_fuzz_case_exchange(project_id, job_id)
            .await?
            .ok_or_else(|| DomainError::invalid("fuzz job has no completed response baseline"))?;
        Ok((FuzzBaselineKind::FirstCompleted, Some(case_id), exchange_id))
    }

    #[allow(clippy::too_many_arguments)]
    async fn load_text_diff(
        &self,
        project_id: ProjectId,
        baseline_exchange_id: ExchangeId,
        case_exchange_id: ExchangeId,
        baseline_mime: Option<&str>,
        case_mime: Option<&str>,
        baseline_headers: &[PresentedHeader],
        case_headers: &[PresentedHeader],
    ) -> (Option<String>, Option<String>) {
        if !is_textual_mime(baseline_mime) || !is_textual_mime(case_mime) {
            return (
                None,
                Some("text diff is available only for textual responses".into()),
            );
        }
        let baseline_body = match self
            .db
            .load_raw_body(project_id, baseline_exchange_id, MessageSide::Response)
            .await
        {
            Ok(Some(body)) => body,
            Ok(None) => return (None, Some("baseline response body is unavailable".into())),
            Err(error) => return (None, Some(error.to_string())),
        };
        let case_body = match self
            .db
            .load_raw_body(project_id, case_exchange_id, MessageSide::Response)
            .await
        {
            Ok(Some(body)) => body,
            Ok(None) => return (None, Some("case response body is unavailable".into())),
            Err(error) => return (None, Some(error.to_string())),
        };
        let decode = |body: Vec<u8>, headers: &[PresentedHeader]| -> DomainResult<String> {
            let encoding = headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-encoding"))
                .map(|header| header.value.as_str())
                .filter(|value| !value.trim().is_empty());
            let mut bytes = if let Some(encoding) = encoding {
                decode_content_encodings(&body, encoding, MAX_FUZZ_DIFF_TEXT_BYTES)?
            } else {
                body.into_iter()
                    .take(MAX_FUZZ_DIFF_TEXT_BYTES)
                    .collect::<Vec<_>>()
            };
            match std::str::from_utf8(&bytes) {
                Ok(_) => String::from_utf8(bytes)
                    .map_err(|_| DomainError::invalid("response body is not valid UTF-8")),
                Err(error)
                    if error.error_len().is_none() && error.valid_up_to() + 4 >= bytes.len() =>
                {
                    bytes.truncate(error.valid_up_to());
                    String::from_utf8(bytes)
                        .map_err(|_| DomainError::invalid("response body is not valid UTF-8"))
                }
                Err(_) => Err(DomainError::invalid("response body is not valid UTF-8")),
            }
        };
        match (
            decode(baseline_body, baseline_headers),
            decode(case_body, case_headers),
        ) {
            (Ok(left), Ok(right)) => (Some(bounded_text_diff(&left, &right)), None),
            (Err(error), _) | (_, Err(error)) => (None, Some(error.to_string())),
        }
    }
}

fn fuzz_job_has_ended(state: FuzzJobState) -> bool {
    matches!(
        state,
        FuzzJobState::Completed | FuzzJobState::Failed | FuzzJobState::Interrupted
    )
}

fn annotate_group_with_baseline(
    group: &mut FuzzResponseGroup,
    status_code: Option<u16>,
    mime: Option<&str>,
    body_hash: Option<&str>,
    response_length: Option<i64>,
) {
    if group.representative_exchange_id.is_none() {
        return;
    }
    group.body_hash_matches_baseline = match (group.body_hash.as_deref(), body_hash) {
        (Some(group), Some(baseline)) => Some(group == baseline),
        _ => None,
    };
    let length_matches = group.response_length_min == response_length
        && group.response_length_max == response_length;
    group.different_from_baseline = Some(
        group.status_code != status_code
            || normalize_response_mime(group.mime.as_deref()) != normalize_response_mime(mime)
            || group.body_hash_matches_baseline == Some(false)
            || !length_matches,
    );
}

fn option_delta(current: Option<i64>, baseline: Option<i64>) -> Option<i64> {
    current
        .zip(baseline)
        .map(|(current, baseline)| current - baseline)
}

fn normalize_response_mime(mime: Option<&str>) -> Option<String> {
    mime.map(|value| {
        value
            .split(';')
            .next()
            .unwrap_or(value)
            .trim()
            .to_ascii_lowercase()
    })
    .filter(|value| !value.is_empty())
}

fn is_textual_mime(mime: Option<&str>) -> bool {
    let Some(mime) = normalize_response_mime(mime) else {
        return true;
    };
    mime.starts_with("text/")
        || mime.contains("json")
        || mime.contains("xml")
        || mime.contains("javascript")
        || mime == "application/x-www-form-urlencoded"
        || mime == "application/graphql"
}

fn compare_response_headers(
    baseline: &[PresentedHeader],
    current: &[PresentedHeader],
) -> Vec<FuzzHeaderChange> {
    const VOLATILE: &[&str] = &[
        "date",
        "set-cookie",
        "expires",
        "age",
        "server-timing",
        "x-request-id",
        "x-correlation-id",
        "traceparent",
        "tracestate",
        "cf-ray",
        "x-amzn-trace-id",
        "content-length",
    ];
    let group = |headers: &[PresentedHeader]| {
        let mut grouped = BTreeMap::<String, Vec<String>>::new();
        for header in headers {
            let name = header.name.to_ascii_lowercase();
            if !VOLATILE.contains(&name.as_str()) {
                grouped.entry(name).or_default().push(header.value.clone());
            }
        }
        grouped
    };
    let baseline = group(baseline);
    let current = group(current);
    let names = baseline
        .keys()
        .chain(current.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    names
        .into_iter()
        .filter_map(|name| {
            let left = baseline.get(&name).cloned().unwrap_or_default();
            let right = current.get(&name).cloned().unwrap_or_default();
            (left != right).then(|| FuzzHeaderChange {
                kind: if left.is_empty() {
                    "added"
                } else if right.is_empty() {
                    "removed"
                } else {
                    "changed"
                }
                .into(),
                name,
                baseline_values: left,
                case_values: right,
            })
        })
        .collect()
}

fn bounded_text_diff(left: &str, right: &str) -> String {
    let mut output = String::new();
    let left_lines = left.lines().collect::<Vec<_>>();
    let right_lines = right.lines().collect::<Vec<_>>();
    for index in 0..left_lines.len().max(right_lines.len()).min(400) {
        let left_line = left_lines.get(index).copied().unwrap_or("");
        let right_line = right_lines.get(index).copied().unwrap_or("");
        if left_line == right_line {
            continue;
        }
        let change = format!("- {left_line}\n+ {right_line}\n");
        let remaining = MAX_FUZZ_DIFF_TEXT_BYTES.saturating_sub(output.len());
        if remaining == 0 {
            break;
        }
        if change.len() <= remaining {
            output.push_str(&change);
        } else {
            let boundary = change
                .char_indices()
                .map(|(index, _)| index)
                .take_while(|index| *index <= remaining)
                .last()
                .unwrap_or(0);
            output.push_str(&change[..boundary]);
        }
    }
    output
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
    limiter: Arc<crate::reply::ProjectBudget>,
    cancel: CancellationToken,
    identity: Option<Arc<crate::cookies::StoredCookieProfile>>,
) -> DomainResult<()> {
    db.set_fuzz_job_state(project_id, job_id, FuzzJobState::Running, None)
        .await?;
    // Wordlists are only needed by the case iterator. Move them out before
    // sharing the remaining request template so neither this setup nor each
    // concurrent case duplicates potentially multi-megabyte payload lists.
    let (template, wordlists) = share_execution_template(template);
    let mut cases = CaseIterator::new(
        template.strategy,
        template.insertion_points.len(),
        wordlists,
    );
    let mut running = FuturesUnordered::new();
    let mut exhausted = false;
    let mut fatal_error = None;

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
            let identity = identity.clone();
            running.push(tokio::spawn(async move {
                execute_case(
                    db, reply, project_id, job_id, template, case, limiter, cancel, identity,
                )
                .await
            }));
        }

        if running.is_empty() {
            break;
        }
        match running.next().await {
            Some(Ok(Ok(()))) => {}
            Some(Ok(Err(error))) => {
                cancel.cancel();
                exhausted = true;
                if fatal_error.is_none() {
                    fatal_error = Some(error);
                }
            }
            Some(Err(error)) => {
                cancel.cancel();
                exhausted = true;
                if fatal_error.is_none() {
                    fatal_error = Some(DomainError::new(
                        ErrorCode::Internal,
                        format!("fuzz case task failed: {error}"),
                    ));
                }
            }
            None => break,
        }
    }

    if let Some(error) = fatal_error {
        return Err(error);
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

fn share_execution_template(mut template: FuzzTemplate) -> (Arc<FuzzTemplate>, Vec<Vec<String>>) {
    let wordlists = std::mem::take(&mut template.wordlists);
    (Arc::new(template), wordlists)
}

#[allow(clippy::too_many_arguments)]
async fn execute_case(
    db: Arc<Db>,
    reply: Arc<ReplyService>,
    project_id: ProjectId,
    job_id: FuzzJobId,
    template: Arc<FuzzTemplate>,
    case: FuzzCasePayloads,
    limiter: Arc<crate::reply::ProjectBudget>,
    cancel: CancellationToken,
    identity: Option<Arc<crate::cookies::StoredCookieProfile>>,
) -> DomainResult<()> {
    let mut prepared = prepare_case(&template, &case);
    let payloads = match &mut prepared {
        Ok(prepared) => std::mem::take(&mut prepared.payloads),
        Err(error) => std::mem::take(&mut error.payloads),
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
    let slots = tokio::select! {
        _ = cancel.cancelled() => None,
        slots = limiter.acquire(1) => Some(slots?),
    };
    let Some(slots) = slots else {
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
        .send_with_context_and_pinned_identity(
            project_id,
            template.base_exchange_id,
            &prepared.draft,
            ProtocolPreference::Auto,
            ReplySendContext::fuzzer(template.base_exchange_id, job_id, persisted.id)
                .with_request_timeout(
                    template
                        .request_timeout_ms
                        .map(std::time::Duration::from_millis),
                ),
            identity.as_deref(),
            slots,
        )
        .await;
    match result {
        // The send result carries what the saved exchange holds, so the case
        // is finished without reading the exchange back.
        Ok(result) => {
            db.finish_fuzz_case(
                project_id,
                job_id,
                persisted.id,
                FuzzCaseState::Completed,
                result.exchange_id,
                Some(result.status_code),
                Some(result.response_length),
                Some(result.duration_ms),
                None,
                Some(result.response_body_hash),
            )
            .await
        }
        Err(failed) => {
            let fatal = failed.error.code() == ErrorCode::DiskQuotaExceeded;
            db.finish_fuzz_case(
                project_id,
                job_id,
                persisted.id,
                FuzzCaseState::Failed,
                failed.exchange_id,
                None,
                None,
                None,
                Some(failed.error.to_string()),
                None,
            )
            .await?;
            if fatal {
                Err(failed.error)
            } else {
                Ok(())
            }
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
            // An insertion point this case leaves untouched (Sniper) must not
            // reach the target as a literal `§name§` marker.
            if let Err(error) = clear_marker(&mut draft, point) {
                return Err(PrepareError {
                    message: error.to_string(),
                    payloads,
                });
            }
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

/// Replaces the point's marker with an empty string wherever the point's
/// location holds it. Insertion points carry no default value, so empty is the
/// neutral fill for a point a case does not mutate.
fn clear_marker(draft: &mut ReplyDraft, point: &InsertionPoint) -> DomainResult<()> {
    let marker = format!("§{}§", point.name);
    match point.location.as_str() {
        "body" => {
            replace_body_marker(draft, &marker, b"")?;
        }
        "url" => {
            if let Some(url) = draft.url.as_mut() {
                if url.contains(&marker) {
                    *url = url.replace(&marker, "");
                }
            }
        }
        location if location.starts_with("header:") => {
            let header_name = location.trim_start_matches("header:");
            if let Some(header) = draft
                .header_overrides
                .iter_mut()
                .find(|header| header.name.eq_ignore_ascii_case(header_name))
            {
                if contains_bytes(&header.value, marker.as_bytes()) {
                    header.value = replace_bytes(&header.value, marker.as_bytes(), b"");
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Replaces `marker` with `payload` in whichever draft field holds the body
/// and returns whether it was there. Raw bytes and text are replaced as
/// written. In body_json strings and body_params fields the payload becomes
/// part of that string, so it is escaped or form-encoded with it when the
/// request is built.
fn replace_body_marker(draft: &mut ReplyDraft, marker: &str, payload: &[u8]) -> DomainResult<bool> {
    if let Some(body) = draft.body_override.as_mut() {
        if !contains_bytes(body, marker.as_bytes()) {
            return Ok(false);
        }
        *body = replace_bytes(body, marker.as_bytes(), payload);
        return Ok(true);
    }
    if let Some(text) = draft.body_text.as_mut() {
        if !text.contains(marker) {
            return Ok(false);
        }
        match std::str::from_utf8(payload) {
            Ok(payload) => *text = text.replace(marker, payload),
            // Text cannot hold the payload: send the body as bytes instead.
            Err(_) => {
                draft.body_override =
                    Some(replace_bytes(text.as_bytes(), marker.as_bytes(), payload));
                draft.body_text = None;
            }
        }
        return Ok(true);
    }
    let in_json = draft
        .body_json
        .as_ref()
        .is_some_and(|value| json_contains(value, marker));
    let in_params = draft
        .body_params
        .iter()
        .any(|param| param.name.contains(marker) || param.value.contains(marker));
    if !in_json && !in_params {
        return Ok(false);
    }
    let payload = std::str::from_utf8(payload).map_err(|_| {
        DomainError::invalid(
            "a payload for a marker in body_json or body_params must be UTF-8 after transforms; use body_text or body_override for bytes",
        )
    })?;
    if let Some(value) = draft.body_json.as_mut() {
        json_replace(value, marker, payload);
    }
    for param in &mut draft.body_params {
        param.name = param.name.replace(marker, payload);
        param.value = param.value.replace(marker, payload);
    }
    Ok(true)
}

fn json_contains(value: &serde_json::Value, marker: &str) -> bool {
    match value {
        serde_json::Value::String(text) => text.contains(marker),
        serde_json::Value::Array(items) => items.iter().any(|item| json_contains(item, marker)),
        serde_json::Value::Object(fields) => fields
            .iter()
            .any(|(key, field)| key.contains(marker) || json_contains(field, marker)),
        _ => false,
    }
}

/// Replaces `marker` in every string and object key of `value`.
fn json_replace(value: &mut serde_json::Value, marker: &str, payload: &str) {
    match value {
        serde_json::Value::String(text) => *text = text.replace(marker, payload),
        serde_json::Value::Array(items) => {
            for item in items {
                json_replace(item, marker, payload);
            }
        }
        serde_json::Value::Object(fields) => {
            *fields = std::mem::take(fields)
                .into_iter()
                .map(|(key, mut field)| {
                    json_replace(&mut field, marker, payload);
                    (key.replace(marker, payload), field)
                })
                .collect();
        }
        _ => {}
    }
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
            if !replace_body_marker(draft, &marker, payload)? {
                // Without a marker the payload is the whole body.
                draft.body_text = None;
                draft.body_json = None;
                draft.body_params.clear();
                draft.body_override = Some(payload.to_vec());
            }
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
        let guidance = if template.strategy == FuzzStrategy::Sniper {
            format!(
                "sniper requires either 1 shared wordlist or exactly {point_count} per-point wordlists"
            )
        } else {
            format!(
                "strategy {:?} requires exactly {expected_wordlists} wordlist(s)",
                template.strategy
            )
        };
        return Err(DomainError::invalid(guidance));
    }
    if template.wordlists.iter().any(Vec::is_empty) {
        return Err(DomainError::invalid("wordlists must not be empty"));
    }
    if template.request_timeout_ms.is_some_and(|timeout| {
        !(MIN_FUZZ_REQUEST_TIMEOUT_MS..=MAX_FUZZ_REQUEST_TIMEOUT_MS).contains(&timeout)
    }) {
        return Err(DomainError::invalid(format!(
            "request_timeout_ms must be between {MIN_FUZZ_REQUEST_TIMEOUT_MS} and {MAX_FUZZ_REQUEST_TIMEOUT_MS}"
        )));
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

    struct SizedTransport {
        calls: AtomicUsize,
    }

    fn test_limiter(
        max_concurrent_requests: u32,
        requests_per_second: f64,
    ) -> Arc<crate::reply::ProjectBudget> {
        let limits = ProjectLimits {
            max_concurrent_requests,
            requests_per_second,
            ..Default::default()
        };
        Arc::new(crate::reply::ProjectBudget::new(&limits))
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

    #[async_trait::async_trait]
    impl SemanticTransport for SizedTransport {
        async fn send(
            &self,
            _dial: &ValidatedDial,
            _request: OutboundRequest,
        ) -> DomainResult<OutboundResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(OutboundResponse {
                status: http::StatusCode::OK,
                headers: vec![("content-type".into(), b"text/plain".to_vec())],
                body: Bytes::from(vec![b'x'; 4096]),
                body_truncated: false,
                protocol: "HTTP/1.1".into(),
                transport_provenance: TransportProvenance::GenericUnprofiled,
                transport_profile: "test_sized".into(),
                duration: Duration::from_millis(1),
            })
        }

        fn profile_name(&self) -> &str {
            "test_sized"
        }

        fn provenance(&self) -> TransportProvenance {
            TransportProvenance::GenericUnprofiled
        }
    }

    /// Records the transport identity and timeouts of every request.
    #[derive(Default)]
    struct RecordingTransport {
        identities: parking_lot::Mutex<Vec<crate::transport::TransportIdentity>>,
        timeouts: parking_lot::Mutex<Vec<(Duration, Duration)>>,
    }

    #[async_trait::async_trait]
    impl SemanticTransport for RecordingTransport {
        async fn send(
            &self,
            _dial: &ValidatedDial,
            request: OutboundRequest,
        ) -> DomainResult<OutboundResponse> {
            self.timeouts
                .lock()
                .push((request.connect_timeout, request.total_timeout));
            self.identities.lock().push(request.identity);
            Ok(OutboundResponse {
                status: http::StatusCode::OK,
                headers: vec![("content-type".into(), b"text/plain".to_vec())],
                body: Bytes::from_static(b"ok"),
                body_truncated: false,
                protocol: "HTTP/1.1".into(),
                transport_provenance: TransportProvenance::GenericUnprofiled,
                transport_profile: "test_recording".into(),
                duration: Duration::from_millis(1),
            })
        }

        fn profile_name(&self) -> &str {
            "test_recording"
        }

        fn provenance(&self) -> TransportProvenance {
            TransportProvenance::GenericUnprofiled
        }
    }

    #[tokio::test]
    async fn cases_varying_credentials_share_one_transport_identity() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "fuzz identity".into(),
                target_url: "http://127.0.0.1:9/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        let template = FuzzTemplate {
            base_exchange_id: None,
            draft: ReplyDraft {
                url: Some("http://127.0.0.1:9/".into()),
                header_overrides: vec![HeaderPatch {
                    name: "Authorization".into(),
                    value: b"Bearer \xc2\xa7token\xc2\xa7".to_vec(),
                }],
                ..Default::default()
            },
            insertion_points: vec![InsertionPoint {
                name: "token".into(),
                location: "header:Authorization".into(),
            }],
            wordlists: vec![vec!["one".into(), "two".into(), "three".into()]],
            wordlist_files: vec![],
            payload_generators: vec![],
            transforms: vec![],
            strategy: FuzzStrategy::Sniper,
            request_timeout_ms: None,
        };
        let job = db
            .create_fuzz_job(
                project.id,
                None,
                template.strategy,
                serde_json::to_string(&template).unwrap(),
                3,
                "{}".into(),
            )
            .await
            .unwrap();
        let transport = Arc::new(RecordingTransport::default());
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: transport.clone(),
            placeholder_key: PlaceholderKey::from_bytes(vec![8; 32]),
            upstream_proxies: Default::default(),
            verify_upstream_tls: true,
            request_limiter: Default::default(),
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
            None,
        )
        .await
        .unwrap();

        let identities = transport.identities.lock().clone();
        assert_eq!(identities.len(), 3);
        assert!(identities.iter().all(|identity| *identity
            == crate::transport::TransportIdentity::for_fuzz_job(project.id, job.id)));
    }

    #[tokio::test]
    async fn a_job_is_audited_once_and_cases_keep_their_send_results() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let mut project = db
            .create_project(CreateProjectRequest {
                name: "fuzz audit".into(),
                target_url: "http://127.0.0.1:9/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        // The in-memory test database is shared-cache, where concurrent
        // writers fail instead of waiting.
        project.limits.max_concurrent_requests = 1;
        project.limits.requests_per_second = 1_000.0;
        db.update_project_scope(project.id, project.scope.clone(), Some(project.limits))
            .await
            .unwrap();
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: Arc::new(RecordingTransport::default()),
            placeholder_key: PlaceholderKey::from_bytes(vec![9; 32]),
            upstream_proxies: Default::default(),
            verify_upstream_tls: true,
            request_limiter: Default::default(),
        });
        let service =
            FuzzerService::new(db.clone(), reply, PlaceholderKey::from_bytes(vec![10; 32]));
        let template = FuzzTemplate {
            base_exchange_id: None,
            draft: ReplyDraft {
                url: Some("http://127.0.0.1:9/?q=§q§".into()),
                ..Default::default()
            },
            insertion_points: vec![InsertionPoint {
                name: "q".into(),
                location: "url".into(),
            }],
            wordlists: vec![vec!["a".into(), "b".into(), "c".into()]],
            wordlist_files: vec![],
            payload_generators: vec![],
            transforms: vec![],
            strategy: FuzzStrategy::Sniper,
            request_timeout_ms: None,
        };
        let job = service.start(project.id, template, false).await.unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while service.has_active_jobs() {
            assert!(
                std::time::Instant::now() < deadline,
                "fuzz job did not finish"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let finished = db.get_fuzz_job(project.id, job.id).await.unwrap();
        assert_eq!(finished.state, FuzzJobState::Completed);
        assert_eq!(finished.completed_cases, 3);

        let audits = db
            .with_conn(|conn| {
                let mut statement = conn
                    .prepare("SELECT event_type, target_id FROM audit_events ORDER BY id")
                    .unwrap();
                let rows = statement
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                Ok(rows)
            })
            .await
            .unwrap();
        assert_eq!(
            audits,
            vec![("fuzz_start".into(), job.id.get().to_string())]
        );

        let (cases, _) = db
            .list_fuzz_cases(project.id, job.id, 10, None)
            .await
            .unwrap();
        assert_eq!(cases.len(), 3);
        for case in cases {
            assert_eq!(case.state, FuzzCaseState::Completed);
            assert_eq!(case.status_code, Some(200));
            assert_eq!(case.response_length, Some(2));
            assert_eq!(
                case.body_hash.as_deref(),
                Some(crate::storage::sha256_hex(b"ok").as_str())
            );
            assert!(case.started_at.is_some() && case.finished_at.is_some());
            let detail = db
                .get_exchange_detail(
                    project.id,
                    case.exchange_id.unwrap(),
                    PresentationOptions::default(),
                )
                .await
                .unwrap();
            assert_eq!(detail.summary.source, ExchangeSource::Fuzzer);
            assert_eq!(detail.lineage.fuzz_job_id, Some(job.id));
            assert_eq!(detail.lineage.fuzz_case_id, Some(case.id));
            assert_eq!(detail.response_body_hash, case.body_hash);
        }
    }

    #[tokio::test]
    async fn a_job_timeout_bounds_each_case_and_is_validated() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let mut project = db
            .create_project(CreateProjectRequest {
                name: "fuzz timeout".into(),
                target_url: "http://127.0.0.1:9/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        project.limits.max_concurrent_requests = 1;
        project.limits.requests_per_second = 1_000.0;
        db.update_project_scope(project.id, project.scope.clone(), Some(project.limits))
            .await
            .unwrap();
        let transport = Arc::new(RecordingTransport::default());
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: transport.clone(),
            placeholder_key: PlaceholderKey::from_bytes(vec![13; 32]),
            upstream_proxies: Default::default(),
            verify_upstream_tls: true,
            request_limiter: Default::default(),
        });
        let service =
            FuzzerService::new(db.clone(), reply, PlaceholderKey::from_bytes(vec![14; 32]));
        let template = |timeout| FuzzTemplate {
            base_exchange_id: None,
            draft: ReplyDraft {
                url: Some("http://127.0.0.1:9/?q=§q§".into()),
                ..Default::default()
            },
            insertion_points: vec![InsertionPoint {
                name: "q".into(),
                location: "url".into(),
            }],
            wordlists: vec![vec!["a".into()]],
            wordlist_files: vec![],
            payload_generators: vec![],
            transforms: vec![],
            strategy: FuzzStrategy::Sniper,
            request_timeout_ms: timeout,
        };
        for timeout in [Some(99), Some(60_001)] {
            let error = service
                .start(project.id, template(timeout), false)
                .await
                .unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
        }
        for timeout in [Some(250), Some(60_000), None] {
            let job = service
                .start(project.id, template(timeout), false)
                .await
                .unwrap();
            let ended = service
                .wait(project.id, job.id, Duration::from_secs(10))
                .await
                .unwrap();
            assert_eq!(ended.state, FuzzJobState::Completed);
        }
        assert_eq!(
            *transport.timeouts.lock(),
            vec![
                (Duration::from_millis(250), Duration::from_millis(250)),
                (Duration::from_secs(10), Duration::from_secs(60)),
                (Duration::from_secs(10), Duration::from_secs(60)),
            ]
        );
    }

    /// Answers every request after a delay.
    struct SlowTransport(Duration);

    #[async_trait::async_trait]
    impl SemanticTransport for SlowTransport {
        async fn send(
            &self,
            _dial: &ValidatedDial,
            _request: OutboundRequest,
        ) -> DomainResult<OutboundResponse> {
            tokio::time::sleep(self.0).await;
            Ok(OutboundResponse {
                status: http::StatusCode::OK,
                headers: vec![("content-type".into(), b"text/plain".to_vec())],
                body: Bytes::from_static(b"ok"),
                body_truncated: false,
                protocol: "HTTP/1.1".into(),
                transport_provenance: TransportProvenance::GenericUnprofiled,
                transport_profile: "test_slow".into(),
                duration: self.0,
            })
        }

        fn profile_name(&self) -> &str {
            "test_slow"
        }

        fn provenance(&self) -> TransportProvenance {
            TransportProvenance::GenericUnprofiled
        }
    }

    #[tokio::test]
    async fn wait_returns_when_the_job_ends_not_when_the_wait_does() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let mut project = db
            .create_project(CreateProjectRequest {
                name: "fuzz wait".into(),
                target_url: "http://127.0.0.1:9/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        project.limits.max_concurrent_requests = 1;
        project.limits.requests_per_second = 1_000.0;
        db.update_project_scope(project.id, project.scope.clone(), Some(project.limits))
            .await
            .unwrap();
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: Arc::new(SlowTransport(Duration::from_millis(150))),
            placeholder_key: PlaceholderKey::from_bytes(vec![11; 32]),
            upstream_proxies: Default::default(),
            verify_upstream_tls: true,
            request_limiter: Default::default(),
        });
        let service =
            FuzzerService::new(db.clone(), reply, PlaceholderKey::from_bytes(vec![12; 32]));
        let template = FuzzTemplate {
            base_exchange_id: None,
            draft: ReplyDraft {
                url: Some("http://127.0.0.1:9/?q=§q§".into()),
                ..Default::default()
            },
            insertion_points: vec![InsertionPoint {
                name: "q".into(),
                location: "url".into(),
            }],
            wordlists: vec![vec!["a".into(), "b".into()]],
            wordlist_files: vec![],
            payload_generators: vec![],
            transforms: vec![],
            strategy: FuzzStrategy::Sniper,
            request_timeout_ms: None,
        };
        let job = service.start(project.id, template, false).await.unwrap();

        let immediate = service
            .wait(project.id, job.id, Duration::ZERO)
            .await
            .unwrap();
        assert!(!fuzz_job_has_ended(immediate.state));

        let started = std::time::Instant::now();
        let ended = service
            .wait(project.id, job.id, Duration::from_secs(20))
            .await
            .unwrap();
        assert_eq!(ended.state, FuzzJobState::Completed);
        assert_eq!(ended.completed_cases, 2);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );

        // An ended job returns at once, and another project's job is not found.
        let again = std::time::Instant::now();
        service
            .wait(project.id, job.id, Duration::from_secs(20))
            .await
            .unwrap();
        assert!(again.elapsed() < Duration::from_secs(1));
        let other = service
            .wait(
                ProjectId(project.id.get() + 1),
                job.id,
                Duration::from_secs(20),
            )
            .await
            .unwrap_err();
        assert_eq!(other.code(), ErrorCode::NotFound);
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
    fn sniper_clears_markers_of_untouched_points_in_built_request() {
        let template = FuzzTemplate {
            base_exchange_id: None,
            draft: ReplyDraft {
                url: Some("https://example.test/?a=§a§&b=§b§".into()),
                body_override: Some("x=§c§".as_bytes().to_vec()),
                header_overrides: vec![HeaderPatch {
                    name: "X-D".into(),
                    value: "v-§d§".as_bytes().to_vec(),
                }],
                ..Default::default()
            },
            insertion_points: ["a", "b", "c", "d"]
                .iter()
                .zip(["url", "url", "body", "header:X-D"])
                .map(|(name, location)| InsertionPoint {
                    name: (*name).into(),
                    location: location.into(),
                })
                .collect(),
            wordlists: vec![vec!["P".into()]],
            wordlist_files: vec![],
            payload_generators: vec![],
            transforms: vec![],
            strategy: FuzzStrategy::Sniper,
            request_timeout_ms: None,
        };
        let cases = CaseIterator::new(
            template.strategy,
            template.insertion_points.len(),
            vec![vec!["P".into()]; 4],
        )
        .collect::<Vec<_>>();
        assert_eq!(cases.len(), 4);
        let built = cases
            .iter()
            .map(|case| prepare_case(&template, case).unwrap().draft)
            .collect::<Vec<_>>();
        assert_eq!(
            built[0].url.as_deref(),
            Some("https://example.test/?a=P&b=")
        );
        assert_eq!(
            built[1].url.as_deref(),
            Some("https://example.test/?a=&b=P")
        );
        assert_eq!(built[2].body_override.as_deref(), Some(b"x=P".as_slice()));
        assert_eq!(built[2].url.as_deref(), Some("https://example.test/?a=&b="));
        assert_eq!(built[3].header_overrides[0].value, "v-P".as_bytes());
        assert_eq!(built[3].body_override.as_deref(), Some(b"x=".as_slice()));
        for draft in &built {
            let all = format!(
                "{} {:?} {:?}",
                draft.url.as_deref().unwrap_or(""),
                draft.body_override,
                draft.header_overrides
            );
            assert!(!all.contains('§'), "literal marker left in {all}");
        }
    }

    #[test]
    fn body_markers_are_replaced_in_every_body_field() {
        let template =
            |draft: ReplyDraft, names: &[&str], transforms: Vec<Transform>| FuzzTemplate {
                base_exchange_id: None,
                draft: ReplyDraft {
                    method: Some("POST".into()),
                    url: Some("https://example.test/".into()),
                    ..draft
                },
                insertion_points: names
                    .iter()
                    .map(|name| InsertionPoint {
                        name: (*name).into(),
                        location: "body".into(),
                    })
                    .collect(),
                wordlists: vec![vec!["c&d=\"<x>\"".into()]],
                wordlist_files: vec![],
                payload_generators: vec![],
                transforms,
                strategy: FuzzStrategy::Sniper,
                request_timeout_ms: None,
            };
        // The body each case sends, after the draft is normalized for sending.
        let bodies = |template: &FuzzTemplate| {
            CaseIterator::new(
                template.strategy,
                template.insertion_points.len(),
                template.wordlists.clone(),
            )
            .map(|case| {
                let prepared = prepare_case(template, &case).map_err(|error| error.message)?;
                let draft = crate::reply::normalize_reply_draft(prepared.draft)
                    .map_err(|error| error.to_string())?;
                Ok(draft.body_override.unwrap_or_default())
            })
            .collect::<Result<Vec<_>, String>>()
        };
        let text = |value: &str| ReplyDraft {
            body_text: Some(value.into()),
            ..Default::default()
        };
        let payload = "c&d=\"<x>\"";

        assert_eq!(
            bodies(&template(text("user=§p§&x=1"), &["p"], vec![])).unwrap(),
            [format!("user={payload}&x=1").into_bytes()]
        );
        let json = ReplyDraft {
            body_json: Some(serde_json::json!({"user": "§p§", "§p§": [1, "id-§p§"]})),
            ..Default::default()
        };
        let sent = bodies(&template(json, &["p"], vec![])).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&sent[0]).unwrap(),
            serde_json::json!({"user": payload, payload: [1, format!("id-{payload}")]})
        );
        let form = ReplyDraft {
            body_format: Some(ReplyBodyFormat::FormUrlencoded),
            body_params: vec![
                ReplyBodyParam {
                    name: "user".into(),
                    value: "§p§".into(),
                },
                ReplyBodyParam {
                    name: "x".into(),
                    value: "1".into(),
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            bodies(&template(form, &["p"], vec![])).unwrap(),
            [b"user=c%26d%3D%22%3Cx%3E%22&x=1".to_vec()]
        );
        let xml = ReplyDraft {
            body_format: Some(ReplyBodyFormat::Xml),
            body_text: Some("<a>§p§</a>".into()),
            ..Default::default()
        };
        assert_eq!(
            bodies(&template(xml, &["p"], vec![])).unwrap(),
            [format!("<a>{payload}</a>").into_bytes()]
        );

        // Sniper fills one point per case and empties the other's marker.
        assert_eq!(
            bodies(&template(text("a=§a§&b=§b§"), &["a", "b"], vec![])).unwrap(),
            [
                format!("a={payload}&b=").into_bytes(),
                format!("a=&b={payload}").into_bytes()
            ]
        );

        // A payload that is not UTF-8 after transforms still reaches a text
        // body as bytes; JSON and form fields cannot hold it.
        let mut bytes = template(text("v=§p§"), &["p"], vec![Transform::HexDecode]);
        bytes.wordlists = vec![vec!["ff00".into()]];
        assert_eq!(bodies(&bytes).unwrap(), [b"v=\xff\x00".to_vec()]);
        let mut json_bytes = template(
            ReplyDraft {
                body_json: Some(serde_json::json!({"v": "§p§"})),
                ..Default::default()
            },
            &["p"],
            vec![Transform::HexDecode],
        );
        json_bytes.wordlists = vec![vec!["ff".into()]];
        assert!(bodies(&json_bytes).unwrap_err().contains("must be UTF-8"));

        // Without a marker the payload is the whole body, whatever field held it.
        assert_eq!(
            bodies(&template(text("no marker"), &["p"], vec![])).unwrap(),
            [payload.as_bytes().to_vec()]
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
    fn sniper_wordlist_error_explains_shared_and_per_point_shapes() {
        let template: FuzzTemplate = serde_json::from_value(serde_json::json!({
            "draft": {"url": "https://example.test/?a=§a§&b=§b§"},
            "insertion_points": [
                {"name": "a", "location": "url"},
                {"name": "b", "location": "url"}
            ],
            "wordlists": [["one"], ["two"], ["three"]],
            "strategy": "sniper"
        }))
        .unwrap();

        let error = validate_template(&template).unwrap_err();
        assert!(error
            .to_string()
            .contains("either 1 shared wordlist or exactly 2 per-point wordlists"));
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
    fn execution_template_moves_wordlists_instead_of_cloning_them() {
        let payload = "x".repeat(1024 * 1024);
        let template = FuzzTemplate {
            wordlists: vec![vec![payload]],
            ..serde_json::from_value(serde_json::json!({
                "draft": {"url": "https://example.test/?q=§q§"},
                "insertion_points": [{"name": "q", "location": "url"}]
            }))
            .unwrap()
        };
        let payload_ptr = template.wordlists[0][0].as_ptr();

        let (shared, wordlists) = share_execution_template(template);

        assert!(shared.wordlists.is_empty());
        assert_eq!(wordlists[0][0].as_ptr(), payload_ptr);
        assert_eq!(Arc::strong_count(&shared), 1);
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
            request_timeout_ms: None,
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
            request_timeout_ms: None,
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
            request_timeout_ms: None,
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
    async fn fuzz_jobs_and_reply_share_the_project_budget() {
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
            upstream_proxies: Default::default(),
            verify_upstream_tls: true,
            request_limiter: Default::default(),
        });
        let budget = reply.request_limiter.budget(&project);
        let service = FuzzerService::new(db, reply, PlaceholderKey::from_bytes(vec![6; 32]));
        assert!(Arc::ptr_eq(
            &budget,
            &service.reply.request_limiter.budget(&project)
        ));
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
            request_timeout_ms: None,
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
            upstream_proxies: Default::default(),
            verify_upstream_tls: true,
            request_limiter: Default::default(),
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
            None,
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
    async fn disk_quota_failure_stops_dispatch_after_bounded_in_flight_cases() {
        let directory = tempfile::tempdir().unwrap();
        let config = crate::config::Config::load(Some(directory.path().to_path_buf())).unwrap();
        let db = Arc::new(Db::open(&config).await.unwrap());
        let mut project = db
            .create_project(CreateProjectRequest {
                name: "fuzz quota".into(),
                target_url: "http://127.0.0.1:9/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        project.limits.max_disk_bytes = 1;
        project = db
            .update_project_scope(
                project.id,
                project.scope.clone(),
                Some(project.limits.clone()),
            )
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
            wordlists: vec![(0..20).map(|value| value.to_string()).collect()],
            wordlist_files: vec![],
            payload_generators: vec![],
            transforms: vec![],
            strategy: FuzzStrategy::Sniper,
            request_timeout_ms: None,
        };
        let job = db
            .create_fuzz_job(
                project.id,
                None,
                template.strategy,
                serde_json::to_string(&template).unwrap(),
                20,
                "{}".into(),
            )
            .await
            .unwrap();
        let transport = Arc::new(SizedTransport {
            calls: AtomicUsize::new(0),
        });
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: transport.clone(),
            placeholder_key: PlaceholderKey::from_bytes(vec![11; 32]),
            upstream_proxies: Default::default(),
            verify_upstream_tls: true,
            request_limiter: Default::default(),
        });

        let error = run_job(
            db.clone(),
            reply,
            project.id,
            job.id,
            template,
            3,
            test_limiter(3, 1_000.0),
            CancellationToken::new(),
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(
            error.code(),
            ErrorCode::DiskQuotaExceeded,
            "unexpected terminal error: {error}"
        );
        assert!(transport.calls.load(Ordering::SeqCst) <= 3);
        let (cases, _) = db
            .list_fuzz_cases(project.id, job.id, 100, None)
            .await
            .unwrap();
        assert!(cases.len() <= 3);
        assert!(cases
            .iter()
            .all(|case| case.state != FuzzCaseState::Running));
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
            request_timeout_ms: None,
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
            upstream_proxies: Default::default(),
            verify_upstream_tls: true,
            request_limiter: Default::default(),
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
            None,
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
        let groups = db
            .list_fuzz_response_groups(project.id, job.id)
            .await
            .unwrap();
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|group| group.case_count == 1));
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

    #[test]
    fn response_groups_expose_baseline_hash_and_semantic_outliers() {
        let mut group = FuzzResponseGroup {
            group_id: "group".into(),
            state: FuzzCaseState::Completed,
            case_count: 2,
            representative_case_id: 1,
            representative_case_index: 0,
            representative_exchange_id: Some(ExchangeId(1)),
            status_code: Some(200),
            mime: Some("text/plain; charset=utf-8".into()),
            body_hash: Some("same-hash".into()),
            body_hash_matches_baseline: None,
            different_from_baseline: None,
            response_length_min: Some(10),
            response_length_max: Some(10),
            duration_ms_min: Some(1),
            duration_ms_avg: Some(1.0),
            duration_ms_max: Some(1),
        };

        annotate_group_with_baseline(
            &mut group,
            Some(200),
            Some("text/plain"),
            Some("same-hash"),
            Some(10),
        );
        assert_eq!(group.body_hash_matches_baseline, Some(true));
        assert_eq!(group.different_from_baseline, Some(false));

        annotate_group_with_baseline(
            &mut group,
            Some(200),
            Some("text/plain"),
            Some("different-hash"),
            Some(10),
        );
        assert_eq!(group.body_hash_matches_baseline, Some(false));
        assert_eq!(group.different_from_baseline, Some(true));
    }

    #[test]
    fn response_header_diff_ignores_volatile_headers() {
        let header = |name: &str, value: &str| PresentedHeader {
            name: name.into(),
            value: value.into(),
            redacted: false,
            noisy: false,
        };
        let baseline = vec![
            header("Date", "yesterday"),
            header("X-Request-Id", "one"),
            header("X-Feature", "off"),
        ];
        let current = vec![
            header("Date", "today"),
            header("X-Request-Id", "two"),
            header("X-Feature", "on"),
        ];
        let changes = compare_response_headers(&baseline, &current);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].name, "x-feature");
        assert_eq!(changes[0].kind, "changed");
    }

    #[test]
    fn bounded_diff_and_mime_normalization_are_predictable() {
        assert_eq!(
            normalize_response_mime(Some("Application/JSON; charset=utf-8")),
            Some("application/json".into())
        );
        assert!(is_textual_mime(Some("application/json")));
        assert!(!is_textual_mime(Some("application/octet-stream")));
        assert_eq!(
            bounded_text_diff("same\nold", "same\nnew"),
            "- old\n+ new\n"
        );
        assert!(
            bounded_text_diff(&"a".repeat(70_000), &"b".repeat(70_000)).len()
                <= MAX_FUZZ_DIFF_TEXT_BYTES
        );
    }
}
