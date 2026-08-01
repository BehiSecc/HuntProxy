//! Convert a saved request into a reproducible command without exposing secrets by default.

use crate::domain::{
    DomainError, DomainResult, ExchangeDetail, ExchangeId, HeaderEntry, MessageSide, ProjectId,
};
use crate::policy::{is_sensitive_header, REDACTED_PLACEHOLDER};
use crate::storage::Db;
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyAsFormat {
    Curl,
    PythonRequests,
}

#[derive(Debug, Clone, Serialize)]
pub struct CopyAsOutput {
    pub format: CopyAsFormat,
    pub content: String,
    pub secrets_included: bool,
    pub redacted_headers: u32,
}

/// Format a saved request. Sensitive header values remain redacted unless the caller
/// has made an explicit, audited decision to include them.
pub async fn copy_exchange_as(
    db: &Db,
    project_id: ProjectId,
    exchange_id: ExchangeId,
    format: CopyAsFormat,
    include_secrets: bool,
) -> DomainResult<CopyAsOutput> {
    let detail = db
        .get_exchange_detail(project_id, exchange_id, Default::default())
        .await?;
    let stored_headers = db
        .load_raw_headers(project_id, exchange_id, MessageSide::Request)
        .await?;
    let stored_body = db
        .load_raw_body(project_id, exchange_id, MessageSide::Request)
        .await?
        .unwrap_or_default();

    let (headers, body) = if detail.protocol == "HTTP/1.1 raw" {
        parse_raw_request(&stored_body)?
    } else {
        (stored_headers, stored_body)
    };
    let (headers, redacted_headers) = present_copy_headers(headers, include_secrets);
    let url = exchange_url(&detail);
    let content = match format {
        CopyAsFormat::Curl => format_curl(&detail.summary.method, &url, &headers, &body),
        CopyAsFormat::PythonRequests => {
            format_python_requests(&detail.summary.method, &url, &headers, &body)
        }
    };
    Ok(CopyAsOutput {
        format,
        content,
        secrets_included: include_secrets,
        redacted_headers,
    })
}

fn exchange_url(detail: &ExchangeDetail) -> String {
    let summary = &detail.summary;
    let mut url = format!("{}://{}{}", summary.scheme, summary.authority, summary.path);
    if let Some(query) = summary.query.as_deref().filter(|query| !query.is_empty()) {
        url.push('?');
        url.push_str(query);
    }
    url
}

fn present_copy_headers(
    mut headers: Vec<HeaderEntry>,
    include_secrets: bool,
) -> (Vec<(String, String)>, u32) {
    headers.sort_by_key(|header| header.ordinal);
    let mut redacted = 0;
    let headers = headers
        .into_iter()
        .filter(|header| {
            !header.name.starts_with(':')
                && !header.name.eq_ignore_ascii_case("content-length")
                && !header.name.eq_ignore_ascii_case("transfer-encoding")
        })
        .map(|header| {
            let sensitive = is_sensitive_header(&header.name);
            if sensitive && !include_secrets {
                redacted += 1;
                (header.name, REDACTED_PLACEHOLDER.to_string())
            } else {
                (
                    header.name,
                    String::from_utf8_lossy(&header.value).into_owned(),
                )
            }
        })
        .collect();
    (headers, redacted)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn format_curl(method: &str, url: &str, headers: &[(String, String)], body: &[u8]) -> String {
    let mut curl = format!(
        "curl --request {} --url {}",
        shell_quote(method),
        shell_quote(url)
    );
    for (name, value) in headers {
        curl.push_str(" \\\n  --header ");
        curl.push_str(&shell_quote(&format!("{name}: {value}")));
    }
    if !body.is_empty() {
        if let Ok(text) = std::str::from_utf8(body) {
            if !text.contains('\0') {
                curl.push_str(" \\\n  --data-binary ");
                curl.push_str(&shell_quote(text));
                return curl;
            }
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(body);
        curl = format!(
            "printf '%s' {} | base64 --decode | {curl} \\\n  --data-binary @-",
            shell_quote(&encoded)
        );
    }
    curl
}

fn python_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

fn format_python_requests(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> String {
    // requests' public API stores headers in a case-insensitive mapping, so combine
    // duplicate values deterministically instead of silently discarding one.
    let mut combined: Vec<(String, String)> = Vec::new();
    for (name, value) in headers {
        if let Some((_, current)) = combined
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
        {
            current.push_str(if name.eq_ignore_ascii_case("cookie") {
                "; "
            } else {
                ", "
            });
            current.push_str(value);
        } else {
            combined.push((name.clone(), value.clone()));
        }
    }

    let mut output = String::from("import base64\n\nimport requests\n\n");
    output.push_str(&format!("url = {}\n", python_string(url)));
    output.push_str("headers = {\n");
    for (name, value) in combined {
        output.push_str(&format!(
            "    {}: {},\n",
            python_string(&name),
            python_string(&value)
        ));
    }
    output.push_str("}\n");
    if !body.is_empty() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(body);
        output.push_str(&format!(
            "body = base64.b64decode({})\n",
            python_string(&encoded)
        ));
    }
    output.push_str("\nresponse = requests.request(\n");
    output.push_str(&format!("    {},\n", python_string(method)));
    output.push_str("    url,\n    headers=headers,");
    if !body.is_empty() {
        output.push_str("\n    data=body,");
    }
    output.push_str("\n)\n\nprint(response.status_code)\nprint(response.text)\n");
    output
}

fn parse_raw_request(raw: &[u8]) -> DomainResult<(Vec<HeaderEntry>, Vec<u8>)> {
    let boundary = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| (position, 4))
        .or_else(|| {
            raw.windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| (position, 2))
        })
        .ok_or_else(|| DomainError::invalid("raw request has no header/body separator"))?;
    let head = String::from_utf8_lossy(&raw[..boundary.0]);
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    if request_line.split_whitespace().count() < 2 {
        return Err(DomainError::invalid(
            "raw request has an invalid request line",
        ));
    }
    let mut headers = Vec::new();
    for (ordinal, line) in lines.enumerate() {
        let Some((name, value)) = line.trim_end_matches('\r').split_once(':') else {
            continue;
        };
        headers.push(HeaderEntry {
            name: name.to_string(),
            value: value.trim_start().as_bytes().to_vec(),
            ordinal: ordinal as u32,
        });
    }
    Ok((headers, raw[boundary.0 + boundary.1..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &[u8], ordinal: u32) -> HeaderEntry {
        HeaderEntry {
            name: name.into(),
            value: value.to_vec(),
            ordinal,
        }
    }

    #[test]
    fn curl_quotes_shell_metacharacters_and_preserves_duplicate_headers() {
        let output = format_curl(
            "POST",
            "https://example.com/a?x=';touch /tmp/nope",
            &[
                ("X-Test".into(), "one'$(id)".into()),
                ("X-Test".into(), "two".into()),
            ],
            b"a='$(id)",
        );
        assert!(output.contains("--header 'X-Test: one'\"'\"'$(id)'"));
        assert_eq!(output.matches("--header 'X-Test:").count(), 2);
        assert!(output.contains("--data-binary 'a='\"'\"'$(id)'"));
    }

    #[test]
    fn binary_curl_body_uses_base64_stdin() {
        let output = format_curl("POST", "https://example.com/", &[], &[0, 255]);
        assert!(output.starts_with("printf '%s' 'AP8=' | base64 --decode | curl"));
        assert!(output.ends_with("--data-binary @-"));
    }

    #[test]
    fn python_output_is_valid_and_combines_repeated_headers() {
        let output = format_python_requests(
            "PATCH",
            "https://example.com/\"quoted",
            &[
                ("X-Test".into(), "one".into()),
                ("x-test".into(), "two".into()),
            ],
            &[0, 255],
        );
        assert!(output.contains("\"X-Test\": \"one, two\""));
        assert!(output.contains("body = base64.b64decode(\"AP8=\")"));
        assert!(output.contains("requests.request(\n    \"PATCH\""));
    }

    #[test]
    fn copy_headers_redact_secrets_and_drop_framing_headers() {
        let (headers, redacted) = present_copy_headers(
            vec![
                header("Content-Length", b"999", 0),
                header("Authorization", b"Bearer secret", 1),
                header("X-Test", b"ok", 2),
            ],
            false,
        );
        assert_eq!(redacted, 1);
        assert_eq!(
            headers,
            vec![
                ("Authorization".into(), REDACTED_PLACEHOLDER.into()),
                ("X-Test".into(), "ok".into())
            ]
        );
    }

    #[test]
    fn raw_requests_are_split_into_headers_and_body() {
        let (headers, body) = parse_raw_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nX-A: one\r\nX-A: two\r\n\r\nbody",
        )
        .unwrap();
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[2].value, b"two");
        assert_eq!(body, b"body");
    }
}
