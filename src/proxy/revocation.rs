//! Closes CONNECT tunnels whose capture session was revoked or has expired.
//!
//! A tunnel authenticates once, when it opens, and then carries any number of
//! requests. Each open tunnel used to ask SQLite twice a second whether its
//! session was still valid; a browser keeps dozens of tunnels open, so idle
//! browsers alone kept the database busy. One check per tick now covers every
//! open tunnel, and nothing runs while no tunnel is open.

use crate::app::AppState;
use crate::domain::{CaptureSession, DomainError, DomainResult, ErrorCode};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// How long a tunnel may outlive its session.
const CHECK_PERIOD: Duration = Duration::from_millis(500);

/// A failed check is retried once before the tunnels it could not vouch for
/// are closed: one slow query must not disconnect every browser at once, and
/// a database that stays unreadable must not keep revoked sessions connected.
const FAILED_CHECKS_BEFORE_CLOSING: u32 = 2;

struct WatchedSession {
    project_id: i64,
    tunnels: usize,
    revoked: CancellationToken,
    /// Tells this watch from an earlier one of the same session that was
    /// closed. Tunnels closed after failed checks belong to a session that is
    /// still valid, and it can reconnect while they wind down.
    generation: u64,
}

#[derive(Default)]
struct Watched {
    sessions: HashMap<i64, WatchedSession>,
    generations: u64,
}

#[derive(Default)]
pub(super) struct TunnelRevocations {
    watched: Mutex<Watched>,
    opened: Notify,
}

/// One open tunnel's place in [`TunnelRevocations`], given up when dropped.
pub(super) struct TunnelWatch {
    revocations: Arc<TunnelRevocations>,
    session_id: i64,
    generation: u64,
    revoked: CancellationToken,
}

impl TunnelWatch {
    /// Completes once the tunnel's session is no longer valid.
    pub(super) async fn revoked(&self) {
        self.revoked.cancelled().await
    }
}

impl Drop for TunnelWatch {
    fn drop(&mut self) {
        let mut watched = self.revocations.watched();
        let Some(session) = watched.sessions.get_mut(&self.session_id) else {
            return;
        };
        if session.generation != self.generation {
            return;
        }
        session.tunnels = session.tunnels.saturating_sub(1);
        if session.tunnels == 0 {
            watched.sessions.remove(&self.session_id);
        }
    }
}

impl TunnelRevocations {
    fn watched(&self) -> MutexGuard<'_, Watched> {
        self.watched
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    /// Watches `session` for as long as the returned value lives. The caller
    /// has just authenticated the session, so a watch that was already closed
    /// belongs to an earlier life of it and is replaced.
    pub(super) fn watch(self: &Arc<Self>, session: &CaptureSession) -> TunnelWatch {
        let session_id = session.id.get();
        let (generation, revoked) = {
            let mut watched = self.watched();
            if watched
                .sessions
                .get(&session_id)
                .is_none_or(|current| current.revoked.is_cancelled())
            {
                watched.generations += 1;
                let generation = watched.generations;
                watched.sessions.insert(
                    session_id,
                    WatchedSession {
                        project_id: session.project_id.get(),
                        tunnels: 0,
                        revoked: CancellationToken::new(),
                        generation,
                    },
                );
            }
            let current = watched
                .sessions
                .get_mut(&session_id)
                .expect("the session was just inserted");
            current.tunnels += 1;
            (current.generation, current.revoked.clone())
        };
        self.opened.notify_one();
        TunnelWatch {
            revocations: self.clone(),
            session_id,
            generation,
            revoked,
        }
    }

    /// The sessions, as (session, project) pairs, whose tunnels are still open.
    fn open_sessions(&self) -> Vec<(i64, i64)> {
        self.watched()
            .sessions
            .iter()
            .filter(|(_, session)| !session.revoked.is_cancelled())
            .map(|(session_id, session)| (*session_id, session.project_id))
            .collect()
    }

    fn close(&self, session_ids: impl IntoIterator<Item = i64>) {
        let watched = self.watched();
        for session_id in session_ids {
            if let Some(session) = watched.sessions.get(&session_id) {
                tracing::debug!(session_id, "closing revoked CONNECT tunnels");
                session.revoked.cancel();
            }
        }
    }

    /// Checks the watched sessions every [`CHECK_PERIOD`] until `cancel`.
    pub(super) async fn run(self: Arc<Self>, state: Arc<AppState>, cancel: CancellationToken) {
        let mut failed_checks = 0;
        loop {
            // Sleep until a tunnel is open. A permit stored by `watch` between
            // the check and the wait is consumed by the wait.
            while self.watched().sessions.is_empty() {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = self.opened.notified() => {}
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(CHECK_PERIOD) => {}
            }
            let open = self.open_sessions();
            if open.is_empty() {
                continue;
            }
            match active_sessions(&state, &open).await {
                Ok(active) => {
                    failed_checks = 0;
                    self.close(
                        open.into_iter()
                            .filter(|session| !active.contains(session))
                            .map(|(session_id, _)| session_id),
                    );
                }
                Err(error) => {
                    failed_checks += 1;
                    tracing::warn!(%error, failed_checks, "could not check the capture sessions of open tunnels");
                    if failed_checks >= FAILED_CHECKS_BEFORE_CLOSING {
                        self.close(open.into_iter().map(|(session_id, _)| session_id));
                    }
                }
            }
        }
    }
}

/// Which of `sessions`, as (session, project) pairs, are still valid.
async fn active_sessions(
    state: &AppState,
    sessions: &[(i64, i64)],
) -> DomainResult<HashSet<(i64, i64)>> {
    // The ids are integers from this process, so they can be written into the
    // statement; SQLite has no array parameters.
    let ids = sessions
        .iter()
        .map(|(session_id, _)| session_id.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT id, project_id FROM capture_sessions
         WHERE id IN ({ids}) AND status='active'
           AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?1)"
    );
    let now = crate::storage::now_rfc3339();
    state
        .db
        .with_conn(move |connection| {
            let storage_error = |error: rusqlite::Error| {
                DomainError::new(ErrorCode::StorageError, error.to_string())
            };
            let mut statement = connection.prepare(&sql).map_err(storage_error)?;
            let rows = statement
                .query_map([now], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(storage_error)?;
            rows.collect::<Result<HashSet<(i64, i64)>, _>>()
                .map_err(storage_error)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::super::tests::proxy_test_fixture;
    use super::*;
    use crate::storage::CreateCaptureSession;

    async fn closes_within(watch: &TunnelWatch, wait: Duration) -> bool {
        tokio::time::timeout(wait, watch.revoked()).await.is_ok()
    }

    #[tokio::test]
    async fn every_tunnel_of_a_revoked_session_closes_and_other_sessions_stay_open() {
        let directory = tempfile::tempdir().unwrap();
        let (state, project, revoked) = proxy_test_fixture(&directory).await;
        let kept = state
            .db
            .create_capture_session(CreateCaptureSession {
                project_id: project.id,
                browser_session_id: None,
                browser_action_id: None,
                is_browser_bound: false,
                ttl: None,
            })
            .await
            .unwrap();
        let revocations = Arc::new(TunnelRevocations::default());
        let cancel = CancellationToken::new();
        let checker = tokio::spawn(revocations.clone().run(state.clone(), cancel.clone()));

        let first = revocations.watch(&revoked);
        let second = revocations.watch(&revoked);
        let other = revocations.watch(&kept);
        // Valid sessions survive a few checks.
        assert!(!closes_within(&first, CHECK_PERIOD * 3).await);

        state
            .db
            .revoke_capture_session(project.id, revoked.id)
            .await
            .unwrap();
        assert!(closes_within(&first, CHECK_PERIOD * 6).await);
        assert!(closes_within(&second, CHECK_PERIOD * 6).await);
        assert!(!closes_within(&other, CHECK_PERIOD * 3).await);

        drop((first, second, other));
        assert!(revocations.watched().sessions.is_empty());
        cancel.cancel();
        checker.await.unwrap();
    }

    #[tokio::test]
    async fn an_expired_session_closes_its_tunnels() {
        let directory = tempfile::tempdir().unwrap();
        let (state, project, _) = proxy_test_fixture(&directory).await;
        let expiring = state
            .db
            .create_capture_session(CreateCaptureSession {
                project_id: project.id,
                browser_session_id: None,
                browser_action_id: None,
                is_browser_bound: false,
                ttl: Some(time::Duration::seconds(1)),
            })
            .await
            .unwrap();
        let revocations = Arc::new(TunnelRevocations::default());
        let cancel = CancellationToken::new();
        tokio::spawn(revocations.clone().run(state.clone(), cancel.clone()));
        let tunnel = revocations.watch(&expiring);
        assert!(closes_within(&tunnel, Duration::from_secs(4)).await);
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_session_that_reconnects_after_its_tunnels_were_closed_is_watched_afresh() {
        let directory = tempfile::tempdir().unwrap();
        let (_state, _, session) = proxy_test_fixture(&directory).await;
        let revocations = Arc::new(TunnelRevocations::default());
        let closed = revocations.watch(&session);
        revocations.close([session.id.get()]);
        assert!(closes_within(&closed, Duration::from_millis(50)).await);

        // The old tunnel has not wound down yet when the session reconnects.
        let reconnected = revocations.watch(&session);
        assert!(!closes_within(&reconnected, Duration::from_millis(50)).await);
        drop(closed);
        assert_eq!(
            revocations.open_sessions(),
            vec![(session.id.get(), session.project_id.get())],
            "dropping the closed tunnel must not end the new watch"
        );
        drop(reconnected);
        assert!(revocations.watched().sessions.is_empty());
    }
}
