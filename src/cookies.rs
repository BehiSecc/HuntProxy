//! Project-scoped managed Cookie header values.

use crate::domain::{DomainError, DomainResult, ErrorCode, ProjectId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

pub const MAX_COOKIE_HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CookiePair {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedCookieProfile {
    pub host: String,
    pub target_url: String,
    pub cookie_header: String,
    pub pairs: Vec<CookiePair>,
    pub names: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct StoredCookieProfile {
    pub project_id: ProjectId,
    pub host: String,
    pub target_url: String,
    pub cookie_header: String,
    pub names: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieProfileStatus {
    pub project_id: ProjectId,
    pub host: String,
    pub target_url: String,
    pub names: Vec<String>,
    pub cookie_count: usize,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieMutationResult {
    pub profile: CookieProfileStatus,
    pub active_browser_sessions_updated: usize,
}

impl StoredCookieProfile {
    pub fn status(&self) -> CookieProfileStatus {
        CookieProfileStatus {
            project_id: self.project_id,
            host: self.host.clone(),
            target_url: self.target_url.clone(),
            names: self.names.clone(),
            cookie_count: self.names.len(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
        }
    }

    pub fn pairs(&self) -> DomainResult<Vec<CookiePair>> {
        parse_cookie_header(&self.cookie_header)
    }
}

pub fn validate_cookie_profile(
    target_url: &str,
    cookie_header: String,
) -> DomainResult<ValidatedCookieProfile> {
    let (host, target_url) = normalize_target(target_url)?;
    let pairs = parse_cookie_header(&cookie_header)?;
    let names = pairs
        .iter()
        .map(|pair| pair.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(ValidatedCookieProfile {
        host,
        target_url,
        cookie_header,
        pairs,
        names,
    })
}

pub fn normalize_target(target_url: &str) -> DomainResult<(String, String)> {
    let mut url = url::Url::parse(target_url)
        .map_err(|error| DomainError::invalid(format!("invalid cookie target URL: {error}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(DomainError::invalid(
            "cookie target URL scheme must be http or https",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(DomainError::invalid(
            "cookie target URL cannot contain credentials",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| DomainError::invalid("cookie target URL requires a host"))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Ok((host, url.to_string()))
}

pub fn parse_cookie_header(value: &str) -> DomainResult<Vec<CookiePair>> {
    if value.is_empty() {
        return Err(DomainError::invalid("Cookie header value cannot be empty"));
    }
    if value.len() > MAX_COOKIE_HEADER_BYTES {
        return Err(DomainError::new(
            ErrorCode::BodyTooLarge,
            format!("Cookie header exceeds {MAX_COOKIE_HEADER_BYTES} bytes"),
        ));
    }
    if value
        .as_bytes()
        .iter()
        .any(|byte| *byte < 0x20 || *byte == 0x7f)
    {
        return Err(DomainError::invalid(
            "Cookie header cannot contain control characters or line breaks",
        ));
    }

    let mut pairs = Vec::new();
    for segment in value.split(';') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let (name, pair_value) = segment
            .split_once('=')
            .ok_or_else(|| DomainError::invalid("each cookie must use name=value"))?;
        let name = name.trim();
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
        {
            return Err(DomainError::invalid("invalid cookie name"));
        }
        pairs.push(CookiePair {
            name: name.to_string(),
            value: pair_value.trim().to_string(),
        });
    }
    if pairs.is_empty() {
        return Err(DomainError::invalid(
            "Cookie header must contain at least one name=value pair",
        ));
    }
    Ok(pairs)
}

pub fn read_cookie_file(path: &Path) -> DomainResult<String> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        DomainError::new(ErrorCode::Unavailable, format!("read cookie file: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(DomainError::invalid("cookie file must be a regular file"));
    }
    if metadata.len() > (MAX_COOKIE_HEADER_BYTES + 2) as u64 {
        return Err(DomainError::new(
            ErrorCode::BodyTooLarge,
            "cookie file is too large",
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        DomainError::new(ErrorCode::Unavailable, format!("read cookie file: {error}"))
    })?;
    let mut value = String::from_utf8(bytes)
        .map_err(|_| DomainError::invalid("cookie file must contain UTF-8 text"))?;
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') {
        value.truncate(value.len() - 1);
    }
    parse_cookie_header(&value)?;
    Ok(value)
}

pub async fn set_project_cookie(
    state: &crate::app::AppState,
    project_id: ProjectId,
    target_url: &str,
    cookie_header: String,
) -> DomainResult<CookieMutationResult> {
    let validated = validate_cookie_profile(target_url, cookie_header)?;
    let previous = state
        .db
        .get_cookie_profile_for_url(project_id, target_url)
        .await?;
    let status = state
        .db
        .upsert_cookie_profile(project_id, validated)
        .await?;
    let stored = state
        .db
        .get_cookie_profile_for_url(project_id, target_url)
        .await?
        .ok_or_else(|| DomainError::new(ErrorCode::StorageError, "cookie profile missing"))?;
    let active_browser_sessions_updated = state
        .browser
        .apply_cookie_profile(project_id, previous.as_ref(), &stored)
        .await?;
    let _ = state
        .db
        .audit(
            Some(project_id),
            "cookie_set",
            Some("user"),
            Some("host"),
            Some(&status.host),
            serde_json::json!({ "cookie_count": status.cookie_count }),
        )
        .await;
    Ok(CookieMutationResult {
        profile: status,
        active_browser_sessions_updated,
    })
}

pub async fn clear_project_cookie(
    state: &crate::app::AppState,
    project_id: ProjectId,
    target_url: &str,
) -> DomainResult<Option<CookieMutationResult>> {
    let Some(stored) = state
        .db
        .delete_cookie_profile(project_id, target_url)
        .await?
    else {
        return Ok(None);
    };
    let status = stored.status();
    let active_browser_sessions_updated = state
        .browser
        .clear_cookie_profile(project_id, &stored)
        .await?;
    let _ = state
        .db
        .audit(
            Some(project_id),
            "cookie_clear",
            Some("user"),
            Some("host"),
            Some(&status.host),
            serde_json::json!({ "cookie_count": status.cookie_count }),
        )
        .await;
    Ok(Some(CookieMutationResult {
        profile: status,
        active_browser_sessions_updated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_values_with_equals_and_ows() {
        let pairs = parse_cookie_header(" sid=a== ; theme=dark; empty=").unwrap();
        assert_eq!(pairs[0].value, "a==");
        assert_eq!(pairs[2].value, "");
    }

    #[test]
    fn rejects_unsafe_or_malformed_values() {
        for value in ["sid", "=value", "sid=x\r\nX-Test: yes", "sid=x\0"] {
            assert!(parse_cookie_header(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn normalizes_to_host_and_root_url() {
        let (host, url) = normalize_target("https://Example.COM:8443/login?q=1").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(url, "https://example.com:8443/");
        assert!(normalize_target("https://user:secret@example.com").is_err());
    }

    #[test]
    fn reads_one_line_cookie_files_without_changing_the_value() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cookies.txt");
        std::fs::write(&path, "sid=a==; theme=dark\r\n").unwrap();
        assert_eq!(read_cookie_file(&path).unwrap(), "sid=a==; theme=dark");

        std::fs::write(&path, "sid=a\nother=b\n").unwrap();
        assert!(read_cookie_file(&path).is_err());
        assert!(read_cookie_file(directory.path()).is_err());
    }
}
