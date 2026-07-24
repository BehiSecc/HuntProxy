//! Capture session credentials (hashed storage).

use crate::domain::*;
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::Db;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::params;
use sha2::Sha256;
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
                     (project_id, browser_session_id, browser_action_id, created_at, expires_at, status, is_browser_bound, token_hash, token_salt)
                     VALUES (?1,?2,?3,?4,?5,'active',?6,?7,?8)",
                    params![
                        project_id.get(),
                        browser_session_id,
                        browser_action_id,
                        created_s,
                        expires_s,
                        is_browser_bound as i64,
                        token_hash,
                        salt.as_slice()
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
    pub async fn auth_capture_token(&self, token: &str) -> DomainResult<CaptureSession> {
        let token = token.to_string();
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, project_id, browser_session_id, browser_action_id, created_at, expires_at, revoked_at, status, is_browser_bound, token_hash, token_salt
                     FROM capture_sessions WHERE status='active'",
                )
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                    ))
                })
                .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;

            let now = OffsetDateTime::now_utc();
            for r in rows {
                let (
                    id,
                    project_id,
                    browser_session_id,
                    browser_action_id,
                    created_at,
                    expires_at,
                    revoked_at,
                    status,
                    is_browser_bound,
                    token_hash,
                    salt,
                ) = r.map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
                let expected = hash_token(&salt, &token);
                if bool::from(expected.as_slice().ct_eq(token_hash.as_slice())) {
                    if let Some(exp) = &expires_at {
                        let exp_t = parse_time(exp);
                        if exp_t < now {
                            return Err(DomainError::new(
                                ErrorCode::ProxyAuthRequired,
                                "capture session expired",
                            ));
                        }
                    }
                    if status != "active" || revoked_at.is_some() {
                        return Err(DomainError::new(
                            ErrorCode::ProxyAuthRequired,
                            "capture session revoked",
                        ));
                    }
                    return Ok(CaptureSession {
                        id: CaptureSessionId(id),
                        project_id: ProjectId(project_id),
                        browser_session_id: browser_session_id.map(BrowserSessionId),
                        browser_action_id: browser_action_id.map(BrowserActionId),
                        created_at: parse_time(&created_at),
                        expires_at: expires_at.as_deref().map(parse_time),
                        revoked_at: revoked_at.as_deref().map(parse_time),
                        status: CaptureSessionStatus::Active,
                        is_browser_bound: is_browser_bound != 0,
                        token_once: None,
                        bearer_presentation: None,
                        basic_presentation: None,
                    });
                }
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
            if user == BASIC_USER || user == "bb" {
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
