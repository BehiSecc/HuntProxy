//! Target-specific wordlist extraction from saved HTTP traffic.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io::Read;

use crate::domain::{DomainError, DomainResult, MessageSide, ProjectId};
use crate::storage::{Db, WordSourceExchange};

const MAX_EXCHANGES: usize = 2_000;
const MAX_JS_EXCHANGES: u32 = 1_000;
const MAX_BODY_READ: usize = 2 * 1024 * 1024;
const MAX_BODY_SCAN: usize = 512 * 1024;
const MAX_TOTAL_SCAN: usize = 32 * 1024 * 1024;
pub const DEFAULT_WORD_LIMIT: usize = 5_000;
pub const MAX_WORD_LIMIT: usize = 10_000;

static WORD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?u)[A-Za-z][A-Za-z_'-]{2,63}").expect("word regex"));
static JSON_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"[\"']([A-Za-z][A-Za-z0-9_.:-]{2,63})[\"']\s*:"#).expect("JSON key regex")
});
static XML_NAME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)</?([a-z][a-z0-9_.:-]{2,63})|\s([a-z][a-z0-9_.:-]{2,63})\s*=")
        .expect("XML name regex")
});
static FORM_NAME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:^|[&;])([a-z][a-z0-9_.-]{2,63})=|\bname=[\"']([^\"']{3,64})[\"']"#)
        .expect("form name regex")
});
static SCRIPT_STYLE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)\s*>")
        .expect("script/style regex")
});
static HTML_TAG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)<[^>]{0,4096}>").expect("HTML tag regex"));
static CAMEL_BOUNDARY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([a-z])([A-Z])").expect("camel-case regex"));

static STOP_WORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "about",
        "after",
        "again",
        "against",
        "also",
        "and",
        "any",
        "are",
        "around",
        "because",
        "been",
        "before",
        "being",
        "between",
        "both",
        "but",
        "can",
        "const",
        "could",
        "default",
        "does",
        "done",
        "each",
        "else",
        "every",
        "false",
        "for",
        "from",
        "function",
        "get",
        "had",
        "has",
        "have",
        "here",
        "how",
        "html",
        "http",
        "https",
        "into",
        "its",
        "javascript",
        "json",
        "let",
        "more",
        "most",
        "new",
        "not",
        "null",
        "object",
        "only",
        "other",
        "our",
        "out",
        "return",
        "same",
        "should",
        "some",
        "string",
        "style",
        "such",
        "than",
        "that",
        "the",
        "their",
        "them",
        "then",
        "there",
        "these",
        "they",
        "this",
        "those",
        "through",
        "true",
        "undefined",
        "use",
        "used",
        "var",
        "very",
        "was",
        "were",
        "what",
        "when",
        "where",
        "which",
        "while",
        "who",
        "will",
        "with",
        "would",
        "www",
        "you",
        "your",
    ]
    .into_iter()
    .collect()
});

#[derive(Debug, Clone)]
pub struct GetWordsOptions {
    pub domain: Option<String>,
    pub include_js: bool,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GetWordsStats {
    pub exchanges_examined: usize,
    pub javascript_exchanges_examined: usize,
    pub bytes_examined: usize,
    pub words: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GetWordsResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub include_js: bool,
    pub words: Vec<String>,
    pub stats: GetWordsStats,
    pub truncated: bool,
}

pub async fn get_words(
    db: &Db,
    project_id: ProjectId,
    options: GetWordsOptions,
) -> DomainResult<GetWordsResult> {
    let domain = normalize_target_domain(options.domain.as_deref())?;
    let limit = options.limit.clamp(1, MAX_WORD_LIMIT);
    let (base, mut truncated) = db
        .list_word_source_exchanges(project_id, domain.clone(), MAX_EXCHANGES)
        .await?;

    let mut sources = base
        .into_iter()
        .map(|source| (source.exchange_id, (source, false)))
        .collect::<HashMap<_, _>>();
    if options.include_js {
        let (javascript, js_truncated) = db
            .list_javascript_files(project_id, None, domain.clone(), MAX_JS_EXCHANGES)
            .await?;
        truncated |= js_truncated;
        let missing_ids = javascript
            .iter()
            .filter_map(|file| file.exchange_id)
            .filter(|exchange_id| !sources.contains_key(exchange_id))
            .collect::<Vec<_>>();
        let related_sources = db
            .list_word_source_exchanges_by_ids(project_id, missing_ids)
            .await?
            .into_iter()
            .map(|source| (source.exchange_id, source))
            .collect::<HashMap<_, _>>();
        for file in javascript {
            let Some(exchange_id) = file.exchange_id else {
                continue;
            };
            if let Some((_, is_related_js)) = sources.get_mut(&exchange_id) {
                *is_related_js = true;
            } else if let Some(source) = related_sources.get(&exchange_id).cloned() {
                sources.insert(exchange_id, (source, true));
            }
        }
    }

    let mut sources = sources.into_values().collect::<Vec<_>>();
    sources.sort_by_key(|(source, _)| source.exchange_id.get());
    let mut collector = WordCollector::new(limit);
    let mut exchanges_examined = 0;
    let mut javascript_exchanges_examined = 0;
    let mut bytes_examined = 0;

    for (source, related_js) in sources {
        if bytes_examined >= MAX_TOTAL_SCAN || collector.full() {
            truncated = true;
            break;
        }
        let is_javascript = is_javascript(&source);
        collect_path_and_query(&mut collector, &source.path, source.query.as_deref());
        if is_javascript && !options.include_js {
            continue;
        }
        exchanges_examined += 1;
        if is_javascript || related_js {
            javascript_exchanges_examined += 1;
        }

        if let Some((body, body_truncated)) = db
            .load_word_source_body_bounded(
                project_id,
                source.exchange_id,
                MessageSide::Request,
                MAX_BODY_SCAN,
            )
            .await?
        {
            truncated |= body_truncated;
            bytes_examined += body.len();
            collect_structural_names(&mut collector, &body);
        }

        if bytes_examined >= MAX_TOTAL_SCAN || collector.full() {
            truncated = true;
            break;
        }
        let Some((raw_response, response_truncated)) = db
            .load_word_source_body_bounded(
                project_id,
                source.exchange_id,
                MessageSide::Response,
                MAX_BODY_READ,
            )
            .await?
        else {
            continue;
        };
        truncated |= response_truncated;
        let (response, scan_truncated) = match source.response_content_encoding.as_deref() {
            Some(encoding) if !encoding.trim().is_empty() => {
                match decode_response_prefix(&raw_response, encoding, MAX_BODY_SCAN) {
                    Ok(decoded) => decoded,
                    Err(_) => {
                        truncated = true;
                        continue;
                    }
                }
            }
            _ => {
                let body_truncated = raw_response.len() > MAX_BODY_SCAN;
                (
                    raw_response.into_iter().take(MAX_BODY_SCAN).collect(),
                    body_truncated,
                )
            }
        };
        truncated |= scan_truncated;
        bytes_examined += response.len();
        collect_response_words(&mut collector, &response, source.mime.as_deref());
    }

    let words = collector.finish();
    truncated |= words.len() >= limit;
    Ok(GetWordsResult {
        domain,
        include_js: options.include_js,
        stats: GetWordsStats {
            exchanges_examined,
            javascript_exchanges_examined,
            bytes_examined,
            words: words.len(),
        },
        words,
        truncated,
    })
}

fn decode_response_prefix(
    input: &[u8],
    content_encoding: &str,
    max_output: usize,
) -> DomainResult<(Vec<u8>, bool)> {
    let encodings = content_encoding
        .split(',')
        .map(str::trim)
        .filter(|encoding| !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity"))
        .collect::<Vec<_>>();
    if encodings.len() != 1 {
        let decoded = crate::codec::decode_content_encodings(
            input,
            content_encoding,
            crate::codec::MAX_DECODED_BODY_OUTPUT,
        )?;
        let truncated = decoded.len() > max_output;
        return Ok((decoded.into_iter().take(max_output).collect(), truncated));
    }
    let encoding = encodings[0];
    if encoding.eq_ignore_ascii_case("gzip") || encoding.eq_ignore_ascii_case("x-gzip") {
        read_decoded_prefix(flate2::read::GzDecoder::new(input), max_output, "gzip")
    } else if encoding.eq_ignore_ascii_case("br") {
        read_decoded_prefix(brotli::Decompressor::new(input, 4096), max_output, "brotli")
    } else if encoding.eq_ignore_ascii_case("deflate") {
        read_decoded_prefix(flate2::read::ZlibDecoder::new(input), max_output, "deflate")
    } else {
        Err(DomainError::invalid(format!(
            "unsupported content encoding `{encoding}`"
        )))
    }
}

fn read_decoded_prefix(
    reader: impl Read,
    max_output: usize,
    encoding: &str,
) -> DomainResult<(Vec<u8>, bool)> {
    let limit = u64::try_from(max_output)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut output = Vec::with_capacity(max_output.min(64 * 1024) + 1);
    reader
        .take(limit)
        .read_to_end(&mut output)
        .map_err(|error| DomainError::invalid(format!("{encoding} decode: {error}")))?;
    let truncated = output.len() > max_output;
    if truncated {
        output.truncate(max_output);
    }
    Ok((output, truncated))
}

pub fn normalize_target_domain(value: Option<&str>) -> DomainResult<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let without_wildcard = value.strip_prefix("*.").unwrap_or(value);
    let host = if without_wildcard.contains("://") {
        url::Url::parse(without_wildcard)
            .map_err(|error| DomainError::invalid(format!("invalid domain URL: {error}")))?
            .host_str()
            .ok_or_else(|| DomainError::invalid("domain URL has no host"))?
            .to_string()
    } else {
        without_wildcard
            .split(['/', ':'])
            .next()
            .unwrap_or_default()
            .to_string()
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || !host
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-'))
    {
        return Err(DomainError::invalid(
            "domain must be a hostname or HTTP URL",
        ));
    }
    Ok(Some(host))
}

fn is_javascript(source: &WordSourceExchange) -> bool {
    let path = source.path.to_ascii_lowercase();
    path.ends_with(".js")
        || path.ends_with(".mjs")
        || path.ends_with(".cjs")
        || source.mime.as_deref().is_some_and(|mime| {
            let mime = mime.to_ascii_lowercase();
            mime.contains("javascript") || mime.contains("ecmascript")
        })
}

fn collect_path_and_query(collector: &mut WordCollector, path: &str, query: Option<&str>) {
    let decoded = percent_encoding::percent_decode_str(path).decode_utf8_lossy();
    for segment in decoded.split('/') {
        if !segment.contains('.') {
            collector.add_compound(segment);
        }
    }
    if let Some(query) = query {
        for (name, _) in url::form_urlencoded::parse(query.as_bytes()) {
            collector.add_compound(&name);
        }
    }
}

fn collect_structural_names(collector: &mut WordCollector, content: &[u8]) {
    let text = String::from_utf8_lossy(content);
    for captures in JSON_KEY.captures_iter(&text) {
        collector.add_compound(&captures[1]);
    }
    for captures in XML_NAME.captures_iter(&text) {
        if let Some(name) = captures.get(1).or_else(|| captures.get(2)) {
            collector.add_compound(name.as_str());
        }
    }
    for captures in FORM_NAME.captures_iter(&text) {
        if let Some(name) = captures.get(1).or_else(|| captures.get(2)) {
            collector.add_compound(name.as_str());
        }
    }
}

fn collect_response_words(collector: &mut WordCollector, content: &[u8], mime: Option<&str>) {
    let text = String::from_utf8_lossy(content);
    collect_structural_names(collector, content);
    let is_html = mime.is_some_and(|mime| mime.to_ascii_lowercase().contains("html"))
        || text.trim_start().starts_with("<!DOCTYPE html")
        || text.trim_start().starts_with("<html");
    if is_html {
        let without_scripts = SCRIPT_STYLE.replace_all(&text, " ");
        let visible = HTML_TAG.replace_all(&without_scripts, " ");
        let decoded = html_escape::decode_html_entities(&visible);
        collector.add_text(&decoded);
    } else {
        collector.add_text(&text);
    }
}

struct WordCollector {
    words: HashSet<String>,
    limit: usize,
}

impl WordCollector {
    fn new(limit: usize) -> Self {
        Self {
            words: HashSet::new(),
            limit,
        }
    }

    fn full(&self) -> bool {
        self.words.len() >= self.limit
    }

    fn add_text(&mut self, text: &str) {
        for matched in WORD.find_iter(text) {
            self.add(matched.as_str());
            if self.full() {
                break;
            }
        }
    }

    fn add_compound(&mut self, value: &str) {
        let value = value.trim_matches(|character: char| !character.is_ascii_alphanumeric());
        self.add(value);
        let camel_split = CAMEL_BOUNDARY.replace_all(value, "$1 $2");
        for part in camel_split.split(|character: char| !character.is_ascii_alphabetic()) {
            self.add(part);
        }
    }

    fn add(&mut self, value: &str) {
        if self.full() {
            return;
        }
        let value = value.trim_matches(|character: char| {
            !character.is_ascii_alphabetic() && !matches!(character, '_' | '-' | '\'')
        });
        let lower = value.to_ascii_lowercase();
        if !(3..=48).contains(&value.len())
            || value.chars().any(|character| character.is_ascii_digit())
            || !value
                .chars()
                .any(|character| character.is_ascii_alphabetic())
            || STOP_WORDS.contains(lower.as_str())
            || looks_secret(value)
        {
            return;
        }
        self.words.insert(value.to_string());
    }

    fn finish(self) -> Vec<String> {
        let mut words = self.words.into_iter().collect::<Vec<_>>();
        words.sort_by(|left, right| {
            left.to_ascii_lowercase()
                .cmp(&right.to_ascii_lowercase())
                .then_with(|| left.cmp(right))
        });
        words
    }
}

fn looks_secret(value: &str) -> bool {
    if value.len() < 20 {
        return false;
    }
    let unique = value.bytes().collect::<HashSet<_>>().len();
    unique * 100 / value.len() >= 65 && !value.contains(['-', '_'].as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_target_words_and_structural_names_without_values() {
        let mut collector = WordCollector::new(100);
        collect_path_and_query(
            &mut collector,
            "/partner-dashboard/userProfile",
            Some("account_name=privatevalue&csrf_token=hidden"),
        );
        collect_structural_names(
            &mut collector,
            br#"{"workspaceName":"DoNotIncludeThisValue","password":"SecretValue"}"#,
        );
        let words = collector.finish();
        assert!(words.contains(&"partner-dashboard".to_string()));
        assert!(words.contains(&"dashboard".to_string()));
        assert!(words.contains(&"account_name".to_string()));
        assert!(words.contains(&"workspaceName".to_string()));
        assert!(!words.contains(&"privatevalue".to_string()));
        assert!(!words.contains(&"SecretValue".to_string()));
    }

    #[test]
    fn strips_non_visible_html_and_filters_entropy() {
        let mut collector = WordCollector::new(100);
        collect_response_words(
            &mut collector,
            b"<html><script>internalBundleWord</script><h1>Partner Portal</h1></html>",
            Some("text/html"),
        );
        collector.add("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP");
        let words = collector.finish();
        assert!(words.contains(&"Partner".to_string()));
        assert!(words.contains(&"Portal".to_string()));
        assert!(!words.contains(&"internalBundleWord".to_string()));
        assert!(!words.contains(&"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP".to_string()));
    }

    #[test]
    fn normalizes_domain_filters() {
        assert_eq!(
            normalize_target_domain(Some("*.Example.COM")).unwrap(),
            Some("example.com".into())
        );
        assert_eq!(
            normalize_target_domain(Some("https://app.example.com/path")).unwrap(),
            Some("app.example.com".into())
        );
        assert!(normalize_target_domain(Some("not a host")).is_err());
    }

    #[test]
    fn compressed_bodies_are_scanned_as_a_bounded_prefix() {
        use std::io::Write;

        let content = format!("TargetVocabulary {}", "x".repeat(1024 * 1024));
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(content.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let (decoded, truncated) = decode_response_prefix(&compressed, "gzip", 256).unwrap();
        assert!(truncated);
        assert!(String::from_utf8_lossy(&decoded).contains("TargetVocabulary"));
    }
}
