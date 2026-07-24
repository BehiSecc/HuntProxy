//! Shared byte/string transforms used by CLI, MCP, Reply, and Fuzzer.

use crate::domain::{DomainError, DomainResult, ErrorCode};
use base64::Engine;
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};

const MAX_TRANSFORM_OUTPUT: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    Raw,
    HexEncode,
    HexDecode,
    Base64Encode,
    Base64Decode,
    Base64UrlEncode,
    Base64UrlDecode,
    UrlEncode,
    UrlDecode,
    HtmlEncode,
    HtmlDecode,
}

pub fn apply_transform(t: Transform, input: &[u8]) -> DomainResult<Vec<u8>> {
    let out = match t {
        Transform::Raw => input.to_vec(),
        Transform::HexEncode => hex::encode(input).into_bytes(),
        Transform::HexDecode => {
            let s = std::str::from_utf8(input)
                .map_err(|_| DomainError::invalid("hex decode requires utf-8 input"))?;
            let s = s.trim();
            hex::decode(s).map_err(|e| DomainError::invalid(format!("hex decode: {e}")))?
        }
        Transform::Base64Encode => base64::engine::general_purpose::STANDARD
            .encode(input)
            .into_bytes(),
        Transform::Base64Decode => {
            let s = std::str::from_utf8(input)
                .map_err(|_| DomainError::invalid("base64 decode requires utf-8 input"))?;
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .map_err(|e| DomainError::invalid(format!("base64 decode: {e}")))?
        }
        Transform::Base64UrlEncode => base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(input)
            .into_bytes(),
        Transform::Base64UrlDecode => {
            let s = std::str::from_utf8(input)
                .map_err(|_| DomainError::invalid("base64url decode requires utf-8 input"))?;
            let s = s.trim();
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
                .map_err(|e| DomainError::invalid(format!("base64url decode: {e}")))?
        }
        Transform::UrlEncode => {
            let s = std::str::from_utf8(input)
                .map_err(|_| DomainError::invalid("url encode requires utf-8 input"))?;
            utf8_percent_encode(s, NON_ALPHANUMERIC)
                .to_string()
                .into_bytes()
        }
        Transform::UrlDecode => {
            let s = std::str::from_utf8(input)
                .map_err(|_| DomainError::invalid("url decode requires utf-8 input"))?;
            percent_decode_str(s)
                .decode_utf8()
                .map_err(|e| DomainError::invalid(format!("url decode: {e}")))?
                .into_owned()
                .into_bytes()
        }
        Transform::HtmlEncode => {
            let s = std::str::from_utf8(input)
                .map_err(|_| DomainError::invalid("html encode requires utf-8 input"))?;
            html_escape::encode_safe(s).into_owned().into_bytes()
        }
        Transform::HtmlDecode => {
            let s = std::str::from_utf8(input)
                .map_err(|_| DomainError::invalid("html decode requires utf-8 input"))?;
            html_escape::decode_html_entities(s)
                .into_owned()
                .into_bytes()
        }
    };
    if out.len() > MAX_TRANSFORM_OUTPUT {
        return Err(DomainError::new(
            ErrorCode::BodyTooLarge,
            format!(
                "transform output {} exceeds limit {}",
                out.len(),
                MAX_TRANSFORM_OUTPUT
            ),
        ));
    }
    Ok(out)
}

pub fn apply_pipeline(steps: &[Transform], input: &[u8]) -> DomainResult<Vec<u8>> {
    let mut cur = input.to_vec();
    for t in steps {
        cur = apply_transform(*t, &cur)?;
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let v = b"hello";
        let e = apply_transform(Transform::HexEncode, v).unwrap();
        let d = apply_transform(Transform::HexDecode, &e).unwrap();
        assert_eq!(d, v);
    }

    #[test]
    fn b64_roundtrip() {
        let v = b"\x00\xff data";
        let e = apply_transform(Transform::Base64Encode, v).unwrap();
        let d = apply_transform(Transform::Base64Decode, &e).unwrap();
        assert_eq!(d, v);
    }

    #[test]
    fn b64url_roundtrip() {
        let v = b"\xfb\xff";
        let e = apply_transform(Transform::Base64UrlEncode, v).unwrap();
        let d = apply_transform(Transform::Base64UrlDecode, &e).unwrap();
        assert_eq!(d, v);
    }

    #[test]
    fn url_and_html() {
        let v = b"a b&c";
        let e = apply_transform(Transform::UrlEncode, v).unwrap();
        let d = apply_transform(Transform::UrlDecode, &e).unwrap();
        assert_eq!(d, v);
        let h = apply_transform(Transform::HtmlEncode, b"<x>").unwrap();
        assert!(String::from_utf8_lossy(&h).contains("&lt;"));
    }

    #[test]
    fn invalid_hex() {
        assert!(apply_transform(Transform::HexDecode, b"zz").is_err());
    }
}
