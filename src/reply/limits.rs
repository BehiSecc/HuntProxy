//! One request budget per project, shared by every request HuntProxy sends
//! itself: Reply, raw requests, the Fuzzer, plugins, the crawler and page
//! discovery. Proxied browser traffic is not limited.
//!
//! A budget holds `max_concurrent_requests` slots and starts requests
//! `1 / requests_per_second` apart. A group that must start together, such as
//! a race, reserves all of its slots in one step and then counts as that many
//! requests against the rate, so the average still holds.

use crate::domain::{DomainError, DomainResult, ErrorCode, Project, ProjectLimits};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// The longest gap between two request starts. It only bounds absurdly small
/// rates, so that schedule arithmetic cannot overflow.
const MAX_START_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// The rate a project gets when its stored rate is not a positive number. It
/// is the floor plugin jobs already apply.
const FALLBACK_REQUESTS_PER_SECOND: f64 = 0.1;

#[derive(Debug, Default)]
pub struct RequestLimiter {
    projects: dashmap::DashMap<i64, Arc<ProjectBudget>>,
}

/// A project's budget. It lives as long as the daemon and follows changes to
/// the project's limits, so a running fuzz job, which holds it, slows down as
/// soon as the project's rate is lowered.
#[derive(Debug)]
pub struct ProjectBudget {
    /// The project's limits as stored, to notice when they change.
    configured: parking_lot::Mutex<(u32, u64)>,
    concurrency: parking_lot::Mutex<Concurrency>,
    schedule: parking_lot::Mutex<Schedule>,
}

#[derive(Debug)]
struct Concurrency {
    max_concurrent_requests: u32,
    /// Replaced when the limit changes: requests in flight finish on the old
    /// one, and new requests take slots from the new one.
    slots: Arc<Semaphore>,
}

#[derive(Debug)]
struct Schedule {
    next_start: Instant,
    interval: Duration,
}

/// Slots held while requests are in flight. Members of one group share them;
/// they return to the budget when the last copy is dropped.
#[derive(Debug, Clone)]
pub struct RequestSlots {
    _permit: Arc<OwnedSemaphorePermit>,
}

impl RequestLimiter {
    /// The project's budget, updated to the project's current limits.
    pub fn budget(&self, project: &Project) -> Arc<ProjectBudget> {
        let budget = self
            .projects
            .entry(project.id.get())
            .or_insert_with(|| ProjectBudget::for_project(project))
            .clone();
        budget.apply(project);
        budget
    }

    /// Wait until `requests` requests may start for the project.
    pub async fn acquire(&self, project: &Project, requests: usize) -> DomainResult<RequestSlots> {
        self.budget(project).acquire(requests).await
    }
}

/// The concurrency and start interval a project's limits allow. Limits are
/// not validated when a project is stored, so an unusable value falls back to
/// the slowest budget plugin jobs already use: one request at a time, at most
/// one every ten seconds.
fn settings(limits: &ProjectLimits) -> (u32, Duration) {
    let rate = if usable_rate(limits.requests_per_second) {
        limits.requests_per_second
    } else {
        FALLBACK_REQUESTS_PER_SECOND
    };
    let interval = (1.0 / rate).min(MAX_START_INTERVAL.as_secs_f64());
    (
        limits.max_concurrent_requests.max(1),
        Duration::from_secs_f64(interval),
    )
}

fn configured(limits: &ProjectLimits) -> (u32, u64) {
    (
        limits.max_concurrent_requests,
        limits.requests_per_second.to_bits(),
    )
}

fn warn_if_unusable(project: &Project) {
    let limits = &project.limits;
    if limits.max_concurrent_requests == 0 || !usable_rate(limits.requests_per_second) {
        tracing::warn!(
            project_id = project.id.get(),
            max_concurrent_requests = limits.max_concurrent_requests,
            requests_per_second = limits.requests_per_second,
            "project request limits are not usable; sending one request at a time, at most {FALLBACK_REQUESTS_PER_SECOND} per second"
        );
    }
}

impl ProjectBudget {
    pub(crate) fn new(limits: &ProjectLimits) -> Self {
        let (max_concurrent_requests, interval) = settings(limits);
        Self {
            configured: parking_lot::Mutex::new(configured(limits)),
            concurrency: parking_lot::Mutex::new(Concurrency {
                max_concurrent_requests,
                slots: Arc::new(Semaphore::new(max_concurrent_requests as usize)),
            }),
            schedule: parking_lot::Mutex::new(Schedule {
                next_start: Instant::now(),
                interval,
            }),
        }
    }

    fn for_project(project: &Project) -> Arc<Self> {
        warn_if_unusable(project);
        Arc::new(Self::new(&project.limits))
    }

    /// Switches to the project's limits if they changed. A new rate applies
    /// to the next start; a new concurrency to requests that have not taken
    /// a slot yet.
    fn apply(&self, project: &Project) {
        let mut current = self.configured.lock();
        if *current == configured(&project.limits) {
            return;
        }
        *current = configured(&project.limits);
        warn_if_unusable(project);
        let (max_concurrent_requests, interval) = settings(&project.limits);
        {
            let mut schedule = self.schedule.lock();
            schedule.interval = interval;
            // A faster rate does not wait out the slower one's gap.
            schedule.next_start = schedule.next_start.min(Instant::now() + interval);
        }
        let mut concurrency = self.concurrency.lock();
        if concurrency.max_concurrent_requests != max_concurrent_requests {
            *concurrency = Concurrency {
                max_concurrent_requests,
                slots: Arc::new(Semaphore::new(max_concurrent_requests as usize)),
            };
        }
    }

    /// Take slots for `requests` requests that start together, then wait for
    /// their start time. Slots come first, so a request waiting for one does
    /// not hold a place in the schedule, and the start is claimed only once it
    /// has come, so a request cancelled while waiting leaves the schedule as
    /// it was. A group larger than the project's concurrency takes every slot
    /// rather than waiting forever.
    pub async fn acquire(&self, requests: usize) -> DomainResult<RequestSlots> {
        let requests = u32::try_from(requests.max(1)).unwrap_or(u32::MAX);
        let (slots, max_concurrent_requests) = {
            let concurrency = self.concurrency.lock();
            (
                concurrency.slots.clone(),
                concurrency.max_concurrent_requests,
            )
        };
        let permit = slots
            .acquire_many_owned(requests.min(max_concurrent_requests))
            .await
            .map_err(|_| DomainError::new(ErrorCode::Unavailable, "request limiter closed"))?;
        loop {
            let wait = {
                let mut schedule = self.schedule.lock();
                let now = Instant::now();
                if schedule.next_start <= now {
                    schedule.next_start = now + schedule.interval.saturating_mul(requests);
                    break;
                }
                schedule.next_start - now
            };
            tokio::time::sleep(wait).await;
        }
        Ok(RequestSlots {
            _permit: Arc::new(permit),
        })
    }

    #[cfg(test)]
    fn current(&self) -> (u32, Duration) {
        (
            self.concurrency.lock().max_concurrent_requests,
            self.schedule.lock().interval,
        )
    }
}

fn usable_rate(requests_per_second: f64) -> bool {
    requests_per_second.is_finite() && requests_per_second > 0.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ProjectId, ScopePolicy};

    fn project(id: i64, max_concurrent_requests: u32, requests_per_second: f64) -> Project {
        Project {
            id: ProjectId(id),
            name: "limits".into(),
            target_url: "http://127.0.0.1/".into(),
            scope: ScopePolicy::default(),
            limits: ProjectLimits {
                max_concurrent_requests,
                requests_per_second,
                ..Default::default()
            },
            default_browser_profile: "default".into(),
            noise_policy: "default".into(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn sequential_requests_start_one_interval_apart() {
        let limiter = RequestLimiter::default();
        let project = project(1, 4, 20.0);
        let started = Instant::now();
        for _ in 0..3 {
            drop(limiter.acquire(&project, 1).await.unwrap());
        }
        assert!(
            started.elapsed() >= Duration::from_millis(90),
            "three requests exceeded 20 requests/second"
        );
    }

    #[tokio::test]
    async fn a_request_waits_for_a_free_slot() {
        let limiter = RequestLimiter::default();
        let project = project(1, 1, 1_000.0);
        let first = limiter.acquire(&project, 1).await.unwrap();
        let blocked =
            tokio::time::timeout(Duration::from_millis(30), limiter.acquire(&project, 1)).await;
        assert!(
            blocked.is_err(),
            "second request bypassed the concurrency limit"
        );
        drop(first);
        tokio::time::timeout(Duration::from_secs(2), limiter.acquire(&project, 1))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn queued_requests_stay_rate_limited_after_slots_free() {
        let limiter = Arc::new(RequestLimiter::default());
        let project = project(1, 2, 10.0);
        let first = limiter.acquire(&project, 1).await.unwrap();
        let second = limiter.acquire(&project, 1).await.unwrap();
        let start_at = |limiter: Arc<RequestLimiter>, project: Project| async move {
            let slots = limiter.acquire(&project, 1).await.unwrap();
            (slots, Instant::now())
        };
        let third = tokio::spawn(start_at(limiter.clone(), project.clone()));
        let fourth = tokio::spawn(start_at(limiter.clone(), project.clone()));
        tokio::time::sleep(Duration::from_millis(220)).await;
        drop((first, second));
        let (_, third_at) = third.await.unwrap();
        let (_, fourth_at) = fourth.await.unwrap();
        let gap = third_at.max(fourth_at) - third_at.min(fourth_at);
        assert!(
            gap >= Duration::from_millis(50),
            "queued requests burst once slots freed: gap was {gap:?}"
        );
    }

    #[tokio::test]
    async fn a_group_starts_together_and_counts_against_the_rate() {
        let limiter = RequestLimiter::default();
        let project = project(1, 3, 4.0);
        let started = Instant::now();
        let group = limiter.acquire(&project, 3).await.unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "a group on a fresh budget waited for its start"
        );
        let blocked =
            tokio::time::timeout(Duration::from_millis(30), limiter.acquire(&project, 1)).await;
        assert!(blocked.is_err(), "a request took a slot the group holds");
        let members = [group.clone(), group.clone(), group];
        drop(members);
        drop(limiter.acquire(&project, 1).await.unwrap());
        assert!(
            started.elapsed() >= Duration::from_millis(745),
            "the request after a group of three did not wait three intervals"
        );
    }

    #[tokio::test]
    async fn a_group_larger_than_the_concurrency_takes_every_slot() {
        let limiter = RequestLimiter::default();
        let project = project(1, 2, 1_000.0);
        let group = tokio::time::timeout(Duration::from_secs(2), limiter.acquire(&project, 5))
            .await
            .expect("an oversized group waited forever")
            .unwrap();
        let blocked =
            tokio::time::timeout(Duration::from_millis(30), limiter.acquire(&project, 1)).await;
        assert!(blocked.is_err());
        drop(group);
    }

    #[tokio::test]
    async fn a_cancelled_wait_does_not_delay_the_next_request() {
        let limiter = RequestLimiter::default();
        let project = project(1, 4, 2.0);
        let started = Instant::now();
        drop(limiter.acquire(&project, 1).await.unwrap());
        let cancelled =
            tokio::time::timeout(Duration::from_millis(50), limiter.acquire(&project, 1)).await;
        assert!(cancelled.is_err());
        drop(limiter.acquire(&project, 1).await.unwrap());
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(495) && elapsed < Duration::from_millis(900),
            "the next request started {elapsed:?} after the first, not one interval"
        );
    }

    #[test]
    fn a_project_keeps_one_budget_through_limit_changes_and_projects_do_not_share() {
        let limiter = RequestLimiter::default();
        let first = limiter.budget(&project(1, 4, 20.0));
        assert!(!Arc::ptr_eq(&first, &limiter.budget(&project(2, 4, 20.0))));
        let changed = limiter.budget(&project(1, 2, 5.0));
        assert!(Arc::ptr_eq(&first, &changed));
        assert_eq!(first.current(), (2, Duration::from_millis(200)));
    }

    #[tokio::test]
    async fn a_held_budget_slows_down_when_the_rate_is_lowered() {
        // A fuzz job takes the budget once and keeps it for every case.
        let limiter = RequestLimiter::default();
        let held = limiter.budget(&project(1, 4, 1_000.0));
        drop(held.acquire(1).await.unwrap());
        limiter.budget(&project(1, 4, 10.0));
        let started = Instant::now();
        for _ in 0..3 {
            drop(held.acquire(1).await.unwrap());
        }
        assert!(
            started.elapsed() >= Duration::from_millis(190),
            "the held budget kept the old rate: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_held_budget_takes_new_concurrency_for_requests_not_yet_started() {
        let limiter = RequestLimiter::default();
        let held = limiter.budget(&project(1, 1, 1_000.0));
        let in_flight = held.acquire(1).await.unwrap();
        limiter.budget(&project(1, 2, 1_000.0));
        let second = tokio::time::timeout(Duration::from_secs(2), held.acquire(1))
            .await
            .expect("the raised concurrency did not apply")
            .unwrap();
        // The request in flight finishes on the old slots; then two at a time.
        drop(in_flight);
        let third = held.acquire(1).await.unwrap();
        let fourth = tokio::time::timeout(Duration::from_millis(50), held.acquire(1)).await;
        assert!(fourth.is_err(), "more requests started than the new limit");
        drop((second, third));
    }

    #[test]
    fn unusable_limits_fall_back_to_a_slow_budget() {
        let limiter = RequestLimiter::default();
        let budget = limiter.budget(&project(1, 0, 1.0));
        assert_eq!(budget.current(), (1, Duration::from_secs(1)));
        for rate in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let budget = limiter.budget(&project(1, 2, rate));
            assert_eq!(budget.current(), (2, Duration::from_secs(10)), "{rate}");
        }
        assert_eq!(
            limiter.budget(&project(1, 2, 1e-12)).current().1,
            MAX_START_INTERVAL
        );
    }
}
