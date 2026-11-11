//! Capture session credentials (hashed storage).

use crate::domain::*;
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::Db;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::params;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_EXTERNAL_TTL_SECS: i64 = 8 * 3600;
const BASIC_USER: &str = PROXY_BASIC_USER;

fn hash_token(salt: &[u8], token: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(salt).expect("hmac key");
    mac.update(token.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Unsalted index key for finding a session by token. Tokens carry 256 bits of
/// randomness, so the digest is not a guessing aid; the salted HMAC remains the
/// authenticating comparison.
fn lookup_key(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

pub struct CreateCaptureSession {
    pub project_id: ProjectId,
    pub browser_session_id: Option<BrowserSessionId>,
    pub browser_action_id: Option<BrowserActionId>,
    pub is_browser_bound: bool,
    pub ttl: Option<Duration>,
}

impl Db {
    pub async fn create_capture_session(
        &self,
        req: CreateCaptureSession,
    ) -> DomainResult<CaptureSession> {
        let token = generate_token();
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let token_hash = hash_token(&salt, &token);
        let token_lookup = lookup_key(&token);
        let created = OffsetDateTime::now_utc();
        let expires = if req.is_browser_bound {
            None
        } else {
            Some(
                created
                    + req
                        .ttl
                        .unwrap_or(Duration::seconds(DEFAULT_EXTERNAL_TTL_SECS)),
            )
        };
        let created_s = now_rfc3339();
        let expires_s = expires.map(|e| {
            e.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        });
        let project_id = req.project_id;
        let browser_session_id = req.browser_session_id.map(|i| i.get());
        let browser_action_id = req.browser_action_id.map(|i| i.get());
        let is_browser_bound = req.is_browser_bound;

        let id = self
            .with_conn(move |conn| {
                conn.execute(
                    "INSERT INTO capture_sessions
                     (project_id, browser_session_id, browser_action_id, created_at, expires_at, status, is_browser_bound, token_hash, token_salt, token_lookup)
                     VALUES (?1,?2,?3,?4,?5,'active',?6,?7,?8,?9)",
                    params![
                        project_id.get(),
                        browser_session_id,
                        browser_action_id,
                        created_s,
                        expires_s,
                        is_browser_bound as i64,
                        token_hash,
                        salt.as_slice(),
                        token_lookup
                    ],
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                Ok(conn.last_insert_rowid())
            })
            .await?;

        Ok(CaptureSession {
            id: CaptureSessionId(id),
            project_id: req.project_id,
            browser_session_id: req.browser_session_id,
            browser_action_id: req.browser_action_id,
            created_at: created,
            expires_at: expires,
            revoked_at: None,
            status: CaptureSessionStatus::Active,
            is_browser_bound: req.is_browser_bound,
            token_once: Some(token.clone()),
            bearer_presentation: Some(format!("Bearer {token}")),
            basic_presentation: Some(format!("{BASIC_USER}:{token}")),
        })
    }

    /// Authenticate proxy credential. Returns session if valid.
    ///
    /// Sessions created since migration 017 are found through the indexed
    /// token digest. Older sessions have no digest, so only the (shrinking)
    /// set of still-active, unexpired legacy rows is hashed and compared.
    pub async fn auth_capture_token(&self, token: &str) -> DomainResult<CaptureSession> {
        let token = token.to_string();
        self.with_conn(move |conn| {
            let now = OffsetDateTime::now_utc();
            let indexed = load_candidates(conn, "token_lookup=?1", params![lookup_key(&token)])?;
            if let Some(session) = verify_candidates(conn, indexed, &token, now)? {
                return Ok(session);
            }

            let now_s = now
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            expire_sessions(conn, &now_s, "token_lookup IS NULL AND ")?;
            let legacy = load_candidates(
                conn,
                "token_lookup IS NULL AND status='active'
                 AND (expires_at IS NULL OR julianday(expires_at) > julianday(?1))",
                params![now_s],
            )?;
            if let Some(session) = verify_candidates(conn, legacy, &token, now)? {
                return Ok(session);
            }
            Err(DomainError::new(
                ErrorCode::ProxyAuthRequired,
                "invalid capture credentials",
            ))
        })
        .await
    }

    pub async fn revoke_capture_session(
        &self,
        project_id: ProjectId,
        id: CaptureSessionId,
    ) -> DomainResult<()> {
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let n = conn
                .execute(
                    "UPDATE capture_sessions SET status='revoked', revoked_at=?1
                     WHERE id=?2 AND project_id=?3 AND status='active'",
                    params![ts, id.get(), project_id.get()],
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            if n == 0 {
                return Err(DomainError::not_found("capture session"));
            }
            Ok(())
        })
        .await
    }

    pub async fn renew_capture_session(
        &self,
        project_id: ProjectId,
        id: CaptureSessionId,
    ) -> DomainResult<CaptureSession> {
        // Revoke old, create new external session for same project.
        self.revoke_capture_session(project_id, id).await?;
        self.create_capture_session(CreateCaptureSession {
            project_id,
            browser_session_id: None,
            browser_action_id: None,
            is_browser_bound: false,
            ttl: None,
        })
        .await
    }

    pub async fn list_capture_sessions(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Vec<CaptureSession>> {
        self.with_conn(move |conn| {
            let now_s = now_rfc3339();
            expire_sessions(conn, &now_s, "")?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, project_id, browser_session_id, browser_action_id, created_at, expires_at, revoked_at, status, is_browser_bound
                     FROM capture_sessions WHERE project_id=?1 ORDER BY id DESC LIMIT 100",
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let rows = stmt
                .query_map(params![project_id.get()], |row| {
                    Ok(CaptureSession {
                        id: CaptureSessionId(row.get(0)?),
                        project_id: ProjectId(row.get(1)?),
                        browser_session_id: row.get::<_, Option<i64>>(2)?.map(BrowserSessionId),
                        browser_action_id: row.get::<_, Option<i64>>(3)?.map(BrowserActionId),
                        created_at: parse_time(&row.get::<_, String>(4)?),
                        expires_at: row.get::<_, Option<String>>(5)?.as_deref().map(parse_time),
                        revoked_at: row.get::<_, Option<String>>(6)?.as_deref().map(parse_time),
                        status: match row.get::<_, String>(7)?.as_str() {
                            "revoked" => CaptureSessionStatus::Revoked,
                            "expired" => CaptureSessionStatus::Expired,
                            _ => CaptureSessionStatus::Active,
                        },
                        is_browser_bound: row.get::<_, i64>(8)? != 0,
                        token_once: None,
                        bearer_presentation: None,
                        basic_presentation: None,
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
}

struct SessionCandidate {
    session: CaptureSession,
    status: String,
    token_hash: Vec<u8>,
    salt: Vec<u8>,
}

fn load_candidates(
    conn: &rusqlite::Connection,
    condition: &str,
    values: impl rusqlite::Params,
) -> DomainResult<Vec<SessionCandidate>> {
    let storage = |e: rusqlite::Error| DomainError::new(ErrorCode::StorageError, e.to_string());
    let mut stmt = conn
        .prepare(&format!(
            "SELECT id, project_id, browser_session_id, browser_action_id, created_at, expires_at,
                    revoked_at, status, is_browser_bound, token_hash, token_salt
             FROM capture_sessions WHERE {condition}"
        ))
        .map_err(storage)?;
    let rows = stmt
        .query_map(values, |row| {
            Ok(SessionCandidate {
                session: CaptureSession {
                    id: CaptureSessionId(row.get(0)?),
                    project_id: ProjectId(row.get(1)?),
                    browser_session_id: row.get::<_, Option<i64>>(2)?.map(BrowserSessionId),
                    browser_action_id: row.get::<_, Option<i64>>(3)?.map(BrowserActionId),
                    created_at: parse_time(&row.get::<_, String>(4)?),
                    expires_at: row.get::<_, Option<String>>(5)?.as_deref().map(parse_time),
                    revoked_at: row.get::<_, Option<String>>(6)?.as_deref().map(parse_time),
                    status: CaptureSessionStatus::Active,
                    is_browser_bound: row.get::<_, i64>(8)? != 0,
                    token_once: None,
                    bearer_presentation: None,
                    basic_presentation: None,
                },
                status: row.get(7)?,
                token_hash: row.get(9)?,
                salt: row.get(10)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Compare the presented token with each candidate in constant time and apply
/// the matching session's revoked/expired state.
fn verify_candidates(
    conn: &rusqlite::Connection,
    candidates: Vec<SessionCandidate>,
    token: &str,
    now: OffsetDateTime,
) -> DomainResult<Option<CaptureSession>> {
    for candidate in candidates {
        let expected = hash_token(&candidate.salt, token);
        if !bool::from(expected.as_slice().ct_eq(candidate.token_hash.as_slice())) {
            continue;
        }
        let session = candidate.session;
        if candidate.status == "revoked" || session.revoked_at.is_some() {
            return Err(DomainError::new(
                ErrorCode::ProxyAuthRequired,
                "capture session revoked",
            ));
        }
        if candidate.status == "expired" || session.expires_at.is_some_and(|exp| exp < now) {
            conn.execute(
                "UPDATE capture_sessions SET status='expired' WHERE id=?1 AND status='active'",
                params![session.id.get()],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            return Err(DomainError::new(
                ErrorCode::ProxyAuthRequired,
                "capture session expired",
            ));
        }
        return Ok(Some(session));
    }
    Ok(None)
}

/// Mark active sessions whose expiry has passed. `extra_condition` narrows the
/// sweep (it must end with `AND ` or be empty).
fn expire_sessions(
    conn: &rusqlite::Connection,
    now: &str,
    extra_condition: &str,
) -> DomainResult<()> {
    let storage = |e: rusqlite::Error| DomainError::new(ErrorCode::StorageError, e.to_string());
    let condition = format!(
        "{extra_condition}status='active' AND revoked_at IS NULL
         AND expires_at IS NOT NULL AND julianday(expires_at) <= julianday(?1)"
    );
    // Check first so the common case takes no write lock.
    let any: bool = conn
        .query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM capture_sessions WHERE {condition})"),
            params![now],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if any {
        conn.execute(
            &format!("UPDATE capture_sessions SET status='expired' WHERE {condition}"),
            params![now],
        )
        .map_err(storage)?;
    }
    Ok(())
}

/// Parse Proxy-Authorization header into token.
pub fn extract_proxy_token(header_value: &str) -> Option<String> {
    let v = header_value.trim();
    if let Some(rest) = v
        .strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))
    {
        return Some(rest.trim().to_string());
    }
    if let Some(rest) = v
        .strip_prefix("Basic ")
        .or_else(|| v.strip_prefix("basic "))
    {
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, rest.trim()).ok()?;
        let s = String::from_utf8(decoded).ok()?;
        // username:password — password is the token
        if let Some((user, pass)) = s.split_once(':') {
            if user == BASIC_USER {
                return Some(pass.to_string());
            }
            // also accept password-only style if username empty
            if !pass.is_empty() {
                return Some(pass.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(value: &str) -> String {
        format!(
            "Basic {}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, value.as_bytes())
        )
    }

    async fn session_db() -> (Db, ProjectId) {
        let db = Db::open_in_memory().await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "sessions".into(),
                target_url: "https://example.test".into(),
                advanced: None,
            })
            .await
            .unwrap();
        (db, project.id)
    }

    fn external(project_id: ProjectId, ttl: Duration) -> CreateCaptureSession {
        CreateCaptureSession {
            project_id,
            browser_session_id: None,
            browser_action_id: None,
            is_browser_bound: false,
            ttl: Some(ttl),
        }
    }

    async fn status_of(db: &Db, project_id: ProjectId, id: CaptureSessionId) -> String {
        db.with_conn(move |conn| {
            conn.query_row(
                "SELECT status FROM capture_sessions WHERE id=?1 AND project_id=?2",
                params![id.get(), project_id.get()],
                |row| row.get(0),
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn token_auth_accepts_valid_and_rejects_unknown_revoked_and_expired() {
        let (db, project) = session_db().await;
        let live = db
            .create_capture_session(external(project, Duration::hours(1)))
            .await
            .unwrap();
        let token = live.token_once.clone().unwrap();
        assert_eq!(db.auth_capture_token(&token).await.unwrap().id, live.id);
        assert!(db.auth_capture_token("not-a-token").await.is_err());

        db.revoke_capture_session(project, live.id).await.unwrap();
        let error = db.auth_capture_token(&token).await.unwrap_err();
        assert!(error.to_string().contains("revoked"), "{error}");

        let stale = db
            .create_capture_session(external(project, Duration::seconds(-5)))
            .await
            .unwrap();
        let stale_token = stale.token_once.clone().unwrap();
        // Still marked active until something notices the expiry.
        assert_eq!(status_of(&db, project, stale.id).await, "active");
        let error = db.auth_capture_token(&stale_token).await.unwrap_err();
        assert!(error.to_string().contains("expired"), "{error}");
        assert_eq!(status_of(&db, project, stale.id).await, "expired");
    }

    #[tokio::test]
    async fn legacy_sessions_without_a_lookup_still_authenticate_until_they_expire() {
        let (db, project) = session_db().await;
        let legacy = db
            .create_capture_session(external(project, Duration::hours(1)))
            .await
            .unwrap();
        let expiring = db
            .create_capture_session(external(project, Duration::hours(1)))
            .await
            .unwrap();
        let legacy_token = legacy.token_once.clone().unwrap();
        let expiring_token = expiring.token_once.clone().unwrap();
        // Simulate rows created before migration 017.
        let ids = (legacy.id.get(), expiring.id.get());
        db.with_conn(move |conn| {
            conn.execute(
                "UPDATE capture_sessions SET token_lookup=NULL WHERE id IN (?1,?2)",
                params![ids.0, ids.1],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            conn.execute(
                "UPDATE capture_sessions SET expires_at='2000-01-01T00:00:00Z' WHERE id=?1",
                params![ids.1],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            Ok(())
        })
        .await
        .unwrap();

        assert_eq!(
            db.auth_capture_token(&legacy_token).await.unwrap().id,
            legacy.id
        );
        assert!(db.auth_capture_token(&expiring_token).await.is_err());
        assert_eq!(status_of(&db, project, expiring.id).await, "expired");
        assert_eq!(status_of(&db, project, legacy.id).await, "active");
    }

    #[tokio::test]
    async fn listing_marks_expired_sessions() {
        let (db, project) = session_db().await;
        let stale = db
            .create_capture_session(external(project, Duration::seconds(-5)))
            .await
            .unwrap();
        let sessions = db.list_capture_sessions(project).await.unwrap();
        assert_eq!(sessions[0].status, CaptureSessionStatus::Expired);
        assert_eq!(status_of(&db, project, stale.id).await, "expired");
    }

    #[test]
    fn proxy_basic_auth_takes_the_token_from_the_password() {
        assert_eq!(
            extract_proxy_token(&basic("huntproxy:token")),
            Some("token".into())
        );
        assert_eq!(
            extract_proxy_token(&basic("any-user:token")),
            Some("token".into())
        );
        assert_eq!(extract_proxy_token(&basic("any-user:")), None);
    }
}
