//! Project-scoped managed Cookie header values.

use crate::domain::{DomainError, DomainResult, ErrorCode, ProjectId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_COOKIE_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_COOKIE_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportedCookie {
    name: String,
    value: String,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    host_only: bool,
    #[serde(default = "default_cookie_path")]
    path: String,
    #[serde(default)]
    http_only: bool,
    #[serde(default)]
    same_site: Option<String>,
    #[serde(default)]
    secure: bool,
    #[serde(default)]
    session: bool,
    #[serde(default)]
    expiration_date: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManagedCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub host_only: bool,
    pub path: String,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<String>,
    pub expires: Option<f64>,
}

#[derive(Debug)]
struct NormalizedCookieInput {
    cookie_header: String,
    managed_cookies: Option<Vec<ManagedCookie>>,
}

fn default_cookie_path() -> String {
    "/".into()
}

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
    pub managed_cookies: Option<Vec<ManagedCookie>>,
}

#[derive(Debug, Clone)]
pub struct StoredCookieProfile {
    pub project_id: ProjectId,
    pub host: String,
    pub target_url: String,
    pub cookie_header: String,
    pub names: Vec<String>,
    pub managed_cookies: Option<Vec<ManagedCookie>>,
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

    pub fn cookie_header_for_url(&self, target_url: &str) -> DomainResult<Option<String>> {
        let Some(cookies) = &self.managed_cookies else {
            return Ok(Some(self.cookie_header.clone()));
        };
        let target = parse_cookie_target(target_url)?;
        let now = unix_time_seconds();
        let mut applicable = cookies
            .iter()
            .filter(|cookie| managed_cookie_applies(cookie, &target, now))
            .collect::<Vec<_>>();
        applicable.sort_by(|left, right| right.path.len().cmp(&left.path.len()));
        let pairs = applicable
            .into_iter()
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect::<Vec<_>>();
        Ok((!pairs.is_empty()).then(|| pairs.join("; ")))
    }
}

impl ManagedCookie {
    pub fn domain_matches_host(&self, host: &str) -> bool {
        managed_cookie_domain_matches(self, &host.to_ascii_lowercase())
    }
}

pub fn validate_cookie_profile(
    target_url: &str,
    cookie_input: String,
) -> DomainResult<ValidatedCookieProfile> {
    let normalized = parse_cookie_input(target_url, &cookie_input)?;
    let (host, target_url) = normalize_target(target_url)?;
    let cookie_header = normalized.cookie_header;
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
        managed_cookies: normalized.managed_cookies,
    })
}

/// Accept an ordinary Cookie header or a browser-export JSON cookie array and
/// return the canonical header representation used by managed-cookie consumers.
pub fn normalize_cookie_input(target_url: &str, input: &str) -> DomainResult<String> {
    Ok(parse_cookie_input(target_url, input)?.cookie_header)
}

fn parse_cookie_input(target_url: &str, input: &str) -> DomainResult<NormalizedCookieInput> {
    if input.len() > MAX_COOKIE_INPUT_BYTES {
        return Err(DomainError::new(
            ErrorCode::BodyTooLarge,
            format!("cookie input exceeds {MAX_COOKIE_INPUT_BYTES} bytes"),
        ));
    }

    let detection_value = input.strip_prefix('\u{feff}').unwrap_or(input).trim();
    if !detection_value.starts_with('[') && !detection_value.starts_with('{') {
        parse_cookie_header(input)?;
        return Ok(NormalizedCookieInput {
            cookie_header: input.to_string(),
            managed_cookies: None,
        });
    }
    if detection_value.starts_with('{') {
        return Err(DomainError::invalid(
            "JSON cookie input must be an array of cookie objects",
        ));
    }

    let cookies: Vec<ExportedCookie> = serde_json::from_str(detection_value)
        .map_err(|_| DomainError::invalid("invalid JSON cookie array"))?;
    if cookies.is_empty() {
        return Err(DomainError::invalid("JSON cookie array cannot be empty"));
    }

    let target = parse_cookie_target(target_url)?;
    let target_host = target
        .host_str()
        .ok_or_else(|| DomainError::invalid("cookie target URL requires a host"))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let now = unix_time_seconds();

    let mut managed_cookies = Vec::new();
    for cookie in cookies {
        if cookie.value.contains(';')
            || cookie
                .value
                .as_bytes()
                .iter()
                .any(|byte| *byte < 0x20 || *byte == 0x7f)
        {
            return Err(DomainError::invalid(
                "JSON cookie contains an invalid value",
            ));
        }
        // Validate each name independently so a value cannot manufacture an
        // extra header pair during canonicalization.
        let parsed_name = parse_cookie_header(&format!("{}=", cookie.name))?;
        if parsed_name.len() != 1 || parsed_name[0].name != cookie.name {
            return Err(DomainError::invalid("invalid cookie name"));
        }
        if !cookie.path.starts_with('/')
            || cookie
                .path
                .as_bytes()
                .iter()
                .any(|byte| *byte < 0x20 || *byte == 0x7f || *byte == b';')
        {
            return Err(DomainError::invalid("JSON cookie contains an invalid path"));
        }
        let domain = match cookie.domain.as_deref() {
            Some(domain) => normalize_exported_domain(domain)?,
            None => target_host.clone(),
        };
        let effective_host_only = cookie.host_only || cookie.domain.is_none();
        let domain_is_ip = domain.parse::<std::net::IpAddr>().is_ok();
        if !effective_host_only && domain_is_ip {
            return Err(DomainError::invalid(
                "JSON cookie IP domains must be hostOnly",
            ));
        }
        if !effective_host_only && !domain_is_ip && psl::domain_str(&domain).is_none() {
            return Err(DomainError::invalid(
                "JSON cookie domain cannot be a public suffix",
            ));
        }
        let same_site = normalize_same_site(cookie.same_site.as_deref())?;
        let managed = ManagedCookie {
            name: cookie.name,
            value: cookie.value,
            domain,
            host_only: effective_host_only,
            path: cookie.path,
            http_only: cookie.http_only,
            secure: cookie.secure,
            same_site,
            expires: (!cookie.session)
                .then_some(cookie.expiration_date)
                .flatten(),
        };
        if managed_cookie_domain_matches(&managed, &target_host)
            && managed.expires.is_none_or(|expires| expires > now)
        {
            managed_cookies.push(managed);
        }
    }

    if managed_cookies.is_empty() {
        return Err(DomainError::invalid(
            "JSON cookie array has no live cookies for the target domain",
        ));
    }
    let header = managed_cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ");
    parse_cookie_header(&header)?;
    Ok(NormalizedCookieInput {
        cookie_header: header,
        managed_cookies: Some(managed_cookies),
    })
}

/// Convert the public API/MCP cookie argument into the text form shared with
/// file and UI input. Arrays are serialized without exposing their values.
pub fn cookie_input_from_json_value(value: &serde_json::Value) -> DomainResult<String> {
    match value {
        serde_json::Value::String(value) => Ok(value.clone()),
        serde_json::Value::Array(_) => serde_json::to_string(value)
            .map_err(|_| DomainError::invalid("invalid JSON cookie array")),
        _ => Err(DomainError::invalid(
            "cookie must be a raw Cookie header string or a JSON cookie array",
        )),
    }
}

fn normalize_exported_domain(domain: &str) -> DomainResult<String> {
    let domain = domain.trim().trim_start_matches('.').trim_end_matches('.');
    if domain.is_empty() || domain.contains(['/', '\\', ':', '@']) {
        return Err(DomainError::invalid(
            "JSON cookie contains an invalid domain",
        ));
    }
    let parsed = url::Host::parse(domain)
        .map_err(|_| DomainError::invalid("JSON cookie contains an invalid domain"))?;
    Ok(parsed.to_string().to_ascii_lowercase())
}

fn normalize_same_site(value: Option<&str>) -> DomainResult<Option<String>> {
    let Some(value) = value else { return Ok(None) };
    match value.to_ascii_lowercase().as_str() {
        "strict" => Ok(Some("Strict".into())),
        "lax" => Ok(Some("Lax".into())),
        "none" | "no_restriction" => Ok(Some("None".into())),
        "unspecified" => Ok(None),
        _ => Err(DomainError::invalid(
            "JSON cookie contains an invalid sameSite value",
        )),
    }
}

fn parse_cookie_target(target_url: &str) -> DomainResult<url::Url> {
    let target = url::Url::parse(target_url)
        .map_err(|error| DomainError::invalid(format!("invalid cookie target URL: {error}")))?;
    if !matches!(target.scheme(), "http" | "https") || target.host_str().is_none() {
        return Err(DomainError::invalid(
            "cookie target URL must use http or https and include a host",
        ));
    }
    Ok(target)
}

fn unix_time_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn managed_cookie_domain_matches(cookie: &ManagedCookie, host: &str) -> bool {
    if cookie.host_only {
        host == cookie.domain
    } else {
        host == cookie.domain
            || host
                .strip_suffix(&cookie.domain)
                .is_some_and(|prefix| prefix.ends_with('.'))
    }
}

fn managed_cookie_applies(cookie: &ManagedCookie, target: &url::Url, now: f64) -> bool {
    let Some(host) = target.host_str() else {
        return false;
    };
    managed_cookie_domain_matches(cookie, &host.to_ascii_lowercase())
        && (!cookie.secure || target.scheme() == "https")
        && cookie.expires.is_none_or(|expires| expires > now)
        && cookie_path_matches(&cookie.path, target.path())
}

fn cookie_path_matches(cookie_path: &str, request_path: &str) -> bool {
    request_path == cookie_path
        || request_path
            .strip_prefix(cookie_path)
            .is_some_and(|suffix| cookie_path.ends_with('/') || suffix.starts_with('/'))
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
    if metadata.len() > (MAX_COOKIE_INPUT_BYTES + 3) as u64 {
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
        .get_cookie_profile_for_target(project_id, target_url)
        .await?;
    let status = state
        .db
        .upsert_cookie_profile(project_id, validated)
        .await?;
    let stored = state
        .db
        .get_cookie_profile_for_target(project_id, target_url)
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
    fn raw_cookie_input_is_preserved() {
        let input = " sid=a== ; theme=dark";
        assert_eq!(
            normalize_cookie_input("https://example.com", input).unwrap(),
            input
        );
    }

    #[test]
    fn browser_export_json_is_filtered_and_normalized() {
        let input = serde_json::json!([
            {
                "domain": ".tydal.co",
                "expirationDate": 4102444800.25_f64,
                "hostOnly": false,
                "httpOnly": false,
                "name": "visitor",
                "path": "/",
                "sameSite": null,
                "secure": true,
                "session": false,
                "storeId": null,
                "value": "a1a9d31e-ede1-40e4-aaa2-eca35dcb6c9c"
            },
            {
                "domain": "app.tydal.co",
                "hostOnly": true,
                "name": "token",
                "session": true,
                "value": "a=="
            },
            {
                "domain": "other.example",
                "name": "unrelated",
                "value": "secret"
            },
            {
                "domain": ".tydal.co",
                "expirationDate": 1,
                "name": "expired",
                "value": "secret"
            }
        ])
        .to_string();
        assert_eq!(
            normalize_cookie_input("https://app.tydal.co/login", &input).unwrap(),
            "visitor=a1a9d31e-ede1-40e4-aaa2-eca35dcb6c9c; token=a=="
        );
        assert_eq!(
            normalize_cookie_input("http://app.tydal.co/login", &input).unwrap(),
            "visitor=a1a9d31e-ede1-40e4-aaa2-eca35dcb6c9c; token=a=="
        );
    }

    #[test]
    fn json_cookie_domains_use_exact_boundaries_and_host_only_rules() {
        let parent = r#"[{"domain":".tydal.co","hostOnly":false,"name":"sid","value":"ok"}]"#;
        assert!(normalize_cookie_input("https://app.tydal.co", parent).is_ok());
        assert!(normalize_cookie_input("https://eviltydal.co", parent).is_err());

        let host_only = r#"[{"domain":"tydal.co","hostOnly":true,"name":"sid","value":"ok"}]"#;
        assert!(normalize_cookie_input("https://tydal.co", host_only).is_ok());
        assert!(normalize_cookie_input("https://app.tydal.co", host_only).is_err());
    }

    #[test]
    fn malformed_or_unsafe_json_cookie_input_is_rejected() {
        for input in [
            "[",
            "{}",
            "[]",
            r#"[{"name":"sid"}]"#,
            r#"[{"name":"sid","value":"safe; injected=yes"}]"#,
            r#"[{"name":"bad name","value":"value"}]"#,
            r#"[{"name":"sid=other","value":"value"}]"#,
            r#"[{"domain":"example.com?other","name":"sid","value":"value"}]"#,
            r#"[{"domain":".com","hostOnly":false,"name":"sid","value":"value"}]"#,
            r#"[{"domain":".co.uk","hostOnly":false,"name":"sid","value":"value"}]"#,
        ] {
            assert!(
                normalize_cookie_input("https://example.com", input).is_err(),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn structured_cookie_rules_are_enforced_for_every_request_url() {
        let input = serde_json::json!([
            {
                "domain": ".example.com",
                "name": "root",
                "path": "/",
                "secure": true,
                "session": true,
                "value": "root-value"
            },
            {
                "domain": ".example.com",
                "expirationDate": 4102444800.5_f64,
                "httpOnly": true,
                "name": "scoped",
                "path": "/admin",
                "sameSite": "lax",
                "secure": true,
                "value": "scoped-value"
            }
        ])
        .to_string();
        let validated =
            validate_cookie_profile("https://app.example.com/admin/start", input).unwrap();
        let mut profile = StoredCookieProfile {
            project_id: ProjectId(1),
            host: validated.host,
            target_url: validated.target_url,
            cookie_header: validated.cookie_header,
            names: validated.names,
            managed_cookies: validated.managed_cookies,
            created_at: String::new(),
            updated_at: String::new(),
        };
        assert_eq!(
            profile
                .cookie_header_for_url("https://app.example.com/admin/users")
                .unwrap()
                .as_deref(),
            Some("scoped=scoped-value; root=root-value")
        );
        assert_eq!(
            profile
                .cookie_header_for_url("https://app.example.com/administrator")
                .unwrap()
                .as_deref(),
            Some("root=root-value")
        );
        assert!(profile
            .cookie_header_for_url("http://app.example.com/admin/users")
            .unwrap()
            .is_none());
        profile.managed_cookies.as_mut().unwrap()[1].expires = Some(1.0);
        assert_eq!(
            profile
                .cookie_header_for_url("https://app.example.com/admin/users")
                .unwrap()
                .as_deref(),
            Some("root=root-value")
        );
    }

    #[test]
    fn public_cookie_argument_accepts_strings_and_arrays_only() {
        assert_eq!(
            cookie_input_from_json_value(&serde_json::json!("sid=value")).unwrap(),
            "sid=value"
        );
        let array = cookie_input_from_json_value(&serde_json::json!([
            {"name": "sid", "value": "value"}
        ]))
        .unwrap();
        assert_eq!(
            normalize_cookie_input("https://example.com", &array).unwrap(),
            "sid=value"
        );
        assert!(cookie_input_from_json_value(&serde_json::json!({})).is_err());
        assert!(cookie_input_from_json_value(&serde_json::Value::Null).is_err());
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
    fn reads_raw_and_json_cookie_files_as_bounded_utf8() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cookies.txt");
        std::fs::write(&path, "sid=a==; theme=dark\r\n").unwrap();
        assert_eq!(read_cookie_file(&path).unwrap(), "sid=a==; theme=dark");

        std::fs::write(&path, "sid=a\nother=b\n").unwrap();
        let input = read_cookie_file(&path).unwrap();
        assert!(normalize_cookie_input("https://example.com", &input).is_err());

        std::fs::write(&path, "\u{feff}[{\"name\":\"sid\",\"value\":\"value\"}]\n").unwrap();
        let input = read_cookie_file(&path).unwrap();
        assert_eq!(
            normalize_cookie_input("https://example.com", &input).unwrap(),
            "sid=value"
        );
        assert!(read_cookie_file(directory.path()).is_err());
    }
}
