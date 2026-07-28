//! Shared byte/string transforms used by CLI, MCP, Reply, and Fuzzer.

use crate::domain::{DomainError, DomainResult, ErrorCode};
use base64::Engine;
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};
use std::io::Read;

const MAX_TRANSFORM_OUTPUT: usize = 10 * 1024 * 1024;
pub const MAX_DECODED_BODY_OUTPUT: usize = 32 * 1024 * 1024;

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
    #[serde(alias = "gunzip")]
    GzipDecode,
    #[serde(alias = "br_decode")]
    BrotliDecode,
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
        Transform::GzipDecode => decode_reader(
            flate2::read::GzDecoder::new(input),
            MAX_TRANSFORM_OUTPUT,
            "gzip",
        )?,
        Transform::BrotliDecode => decode_reader(
            brotli::Decompressor::new(input, 4096),
            MAX_TRANSFORM_OUTPUT,
            "brotli",
        )?,
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

/// Decode an HTTP Content-Encoding chain. Encodings are applied by servers in
/// header order and therefore decoded in reverse order.
pub fn decode_content_encodings(
    input: &[u8],
    content_encoding: &str,
    max_output: usize,
) -> DomainResult<Vec<u8>> {
    let encodings = content_encoding
        .split(',')
        .map(str::trim)
        .filter(|encoding| !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity"))
        .collect::<Vec<_>>();
    let mut output = input.to_vec();
    for encoding in encodings.into_iter().rev() {
        output = if encoding.eq_ignore_ascii_case("gzip") || encoding.eq_ignore_ascii_case("x-gzip")
        {
            decode_reader(
                flate2::read::GzDecoder::new(output.as_slice()),
                max_output,
                "gzip",
            )?
        } else if encoding.eq_ignore_ascii_case("br") {
            decode_reader(
                brotli::Decompressor::new(output.as_slice(), 4096),
                max_output,
                "brotli",
            )?
        } else if encoding.eq_ignore_ascii_case("deflate") {
            decode_reader(
                flate2::read::ZlibDecoder::new(output.as_slice()),
                max_output,
                "deflate",
            )?
        } else {
            return Err(DomainError::invalid(format!(
                "unsupported content encoding `{encoding}`; request the raw body instead"
            )));
        };
    }
    Ok(output)
}

fn decode_reader(reader: impl Read, max_output: usize, encoding: &str) -> DomainResult<Vec<u8>> {
    let limit = u64::try_from(max_output)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut output = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut output)
        .map_err(|error| DomainError::invalid(format!("{encoding} decode: {error}")))?;
    if output.len() > max_output {
        return Err(DomainError::new(
            ErrorCode::BodyTooLarge,
            format!("decoded {encoding} body exceeds {max_output} bytes"),
        ));
    }
    Ok(output)
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

    #[test]
    fn gzip_and_brotli_decode() {
        use std::io::Write;

        let expected = b"compressed response body";
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(expected).unwrap();
        let gzip = gzip.finish().unwrap();
        assert_eq!(
            apply_transform(Transform::GzipDecode, &gzip).unwrap(),
            expected
        );

        let mut brotli = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut brotli, 4096, 3, 22);
            writer.write_all(expected).unwrap();
        }
        assert_eq!(
            apply_transform(Transform::BrotliDecode, &brotli).unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_unsupported_or_oversized_content_encoding() {
        assert!(decode_content_encodings(b"body", "compress", 1024).is_err());

        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        use std::io::Write;
        gzip.write_all(&[b'a'; 64]).unwrap();
        let gzip = gzip.finish().unwrap();
        assert!(decode_content_encodings(&gzip, "gzip", 8).is_err());
    }
}
