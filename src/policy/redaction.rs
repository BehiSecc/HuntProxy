//! Header redaction and noisy-header presentation policy.
//!
//! Redaction never mutates stored evidence. Presentation only.

use crate::domain::{HeaderEntry, PresentedHeader};

/// Normalized lowercase sensitive header names (exact set from PRODUCT_SPEC).
pub const SENSITIVE_HEADERS: &[&str] = &[
    "cookie",
    "set-cookie",
    "authorization",
    "csrf-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-csrftoken",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
    "x-amz-security-token",
    "x-amz-signature",
    "x-amz-credential",
    "x-goog-api-key",
    "cf-access-jwt-assertion",
    "cf-access-client-secret",
    "x-hub-signature",
    "x-hub-signature-256",
    "x-signature",
    "x-client-secret",
];

/// Noisy headers hidden from normal presentation.
pub const NOISY_HEADERS: &[&str] = &[
    "accept-language",
    "if-modified-since",
    "if-none-match",
    "priority",
    "sec-ch-ua",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-full-version",
    "sec-ch-ua-mobile",
    "sec-ch-ua-model",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-wow64",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "upgrade-insecure-requests",
    "x-requested-with",
];

pub const REDACTED_PLACEHOLDER: &str = "<redacted>";

#[derive(Debug, Clone, Default)]
pub struct PresentationOptions {
    pub include_noisy_headers: bool,
    /// When true, return noisy header names without values in a side channel (not implemented as values).
    pub include_noisy_names: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PresentationResult {
    pub headers: Vec<PresentedHeader>,
    pub redacted_count: u32,
    pub noisy_hidden_count: u32,
    pub noisy_names: Vec<String>,
}

pub fn normalize_header_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

pub fn is_sensitive_header(name: &str) -> bool {
    let n = normalize_header_name(name);
    SENSITIVE_HEADERS.iter().any(|s| *s == n)
}

pub fn is_noisy_header(name: &str) -> bool {
    let n = normalize_header_name(name);
    NOISY_HEADERS.iter().any(|s| *s == n)
}

/// Present headers for safe API/UI/MCP/CLI views.
pub fn present_headers(entries: &[HeaderEntry], opts: &PresentationOptions) -> PresentationResult {
    let mut out = PresentationResult::default();
    for h in entries {
        let sensitive = is_sensitive_header(&h.name);
        let noisy = is_noisy_header(&h.name);

        if noisy && !opts.include_noisy_headers {
            out.noisy_hidden_count += 1;
            if opts.include_noisy_names {
                out.noisy_names.push(h.name.clone());
            }
            continue;
        }

        let (value, redacted) = if sensitive {
            out.redacted_count += 1;
            (REDACTED_PLACEHOLDER.to_string(), true)
        } else {
            (String::from_utf8_lossy(&h.value).into_owned(), false)
        };

        out.headers.push(PresentedHeader {
            name: h.name.clone(),
            value,
            redacted,
            noisy,
        });
    }
    out
}

/// Value bytes for a header if not sensitive presentation path (raw storage access).
pub fn header_value_utf8_lossy(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, value: &str, ordinal: u32) -> HeaderEntry {
        HeaderEntry {
            name: name.into(),
            value: value.as_bytes().to_vec(),
            ordinal,
        }
    }

    #[test]
    fn redacts_all_sensitive_spellings_case_insensitive() {
        let headers = vec![
            entry("Cookie", "secret1", 0),
            entry("AUTHORIZATION", "Bearer secret2", 1),
            entry("X-Api-Key", "k", 2),
            entry("Set-Cookie", "a=1", 3),
            entry("set-cookie", "b=2", 4),
            entry("Host", "example.com", 5),
        ];
        let r = present_headers(&headers, &PresentationOptions::default());
        assert_eq!(r.redacted_count, 5);
        for h in &r.headers {
            if is_sensitive_header(&h.name) {
                assert_eq!(h.value, REDACTED_PLACEHOLDER);
                assert!(h.redacted);
            }
        }
        let host = r.headers.iter().find(|h| h.name == "Host").unwrap();
        assert_eq!(host.value, "example.com");
        assert!(!host.redacted);
    }

    #[test]
    fn hides_noisy_by_default() {
        let headers = vec![
            entry("Accept-Language", "en", 0),
            entry("sec-ch-ua", "x", 1),
            entry("Content-Type", "text/plain", 2),
        ];
        let r = present_headers(&headers, &PresentationOptions::default());
        assert_eq!(r.noisy_hidden_count, 2);
        assert_eq!(r.headers.len(), 1);
        assert_eq!(r.headers[0].name, "Content-Type");
    }

    #[test]
    fn include_noisy_still_redacts_sensitive() {
        let headers = vec![
            entry("Cookie", "secret", 0),
            entry("sec-fetch-mode", "cors", 1),
        ];
        let opts = PresentationOptions {
            include_noisy_headers: true,
            ..Default::default()
        };
        let r = present_headers(&headers, &opts);
        assert_eq!(r.headers.len(), 2);
        let cookie = r.headers.iter().find(|h| h.name == "Cookie").unwrap();
        assert_eq!(cookie.value, REDACTED_PLACEHOLDER);
    }

    #[test]
    fn empty_and_long_sensitive_values() {
        let long = "x".repeat(100_000);
        let headers = vec![entry("Cookie", "", 0), entry("Authorization", &long, 1)];
        let r = present_headers(&headers, &PresentationOptions::default());
        assert!(r.headers.iter().all(|h| h.value == REDACTED_PLACEHOLDER));
    }
}
