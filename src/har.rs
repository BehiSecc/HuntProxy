//! Bounded HAR 1.2 import/export for exchange interoperability.

use crate::domain::*;
use crate::policy::is_sensitive_header;
use crate::storage::{Db, NewExchange};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const MAX_HAR_FILE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_HAR_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Har {
    pub log: HarLog,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarLog {
    pub version: String,
    pub creator: HarCreator,
    #[serde(default)]
    pub entries: Vec<HarEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarCreator {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarEntry {
    pub started_date_time: String,
    pub time: f64,
    pub request: HarRequest,
    pub response: HarResponse,
    #[serde(default)]
    pub cache: serde_json::Value,
    pub timings: HarTimings,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "_huntproxy"
    )]
    pub huntproxy: Option<HarExtension>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    pub http_version: String,
    #[serde(default)]
    pub headers: Vec<HarNameValue>,
    #[serde(default)]
    pub query_string: Vec<HarNameValue>,
    #[serde(default)]
    pub cookies: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_data: Option<HarPostData>,
    pub headers_size: i64,
    pub body_size: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarResponse {
    pub status: u16,
    #[serde(default)]
    pub status_text: String,
    pub http_version: String,
    #[serde(default)]
    pub headers: Vec<HarNameValue>,
    #[serde(default)]
    pub cookies: Vec<serde_json::Value>,
    pub content: HarContent,
    #[serde(default)]
    pub redirect_url: String,
    pub headers_size: i64,
    pub body_size: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarContent {
    pub size: i64,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarPostData {
    #[serde(default)]
    pub mime_type: String,
    #[serde(default)]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "_encoding")]
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarNameValue {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarTimings {
    pub blocked: f64,
    pub dns: f64,
    pub connect: f64,
    pub send: f64,
    pub wait: f64,
    pub receive: f64,
    pub ssl: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarExtension {
    #[serde(default)]
    pub request_headers_raw: Vec<HarRawHeader>,
    #[serde(default)]
    pub response_headers_raw: Vec<HarRawHeader>,
    #[serde(default)]
    pub omitted_sensitive_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarRawHeader {
    pub name: String,
    pub value_base64: String,
    pub ordinal: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct HarImportResult {
    pub project_id: ProjectId,
    pub imported_entries: usize,
}

impl Db {
    pub async fn export_har(
        &self,
        project_id: ProjectId,
        include_secrets: bool,
    ) -> DomainResult<Har> {
        let archive = self.export_project(project_id).await?;
        let mut entries = Vec::with_capacity(archive.exchanges.len());
        for archived in archive.exchanges {
            let ex = archived.exchange;
            let url = exchange_url(&ex);
            let parsed =
                url::Url::parse(&url).map_err(|error| DomainError::invalid(error.to_string()))?;
            let query_string = parsed
                .query_pairs()
                .map(|(name, value)| HarNameValue {
                    name: name.into_owned(),
                    value: value.into_owned(),
                })
                .collect();
            let (request_headers, request_raw, mut omitted) =
                har_headers(&ex.request_headers, include_secrets);
            let (response_headers, response_raw, response_omitted) =
                har_headers(&ex.response_headers, include_secrets);
            omitted.extend(response_omitted);
            let request_body = ex.request_body.as_deref().unwrap_or_default();
            let response_body = ex.response_body.as_deref().unwrap_or_default();
            let request_mime =
                header_value(&ex.request_headers, "content-type").unwrap_or_default();
            let redirect = header_value(&ex.response_headers, "location").unwrap_or_default();
            let duration = ex.duration_ms.unwrap_or(0).max(0) as f64;
            entries.push(HarEntry {
                started_date_time: archived.started_at,
                time: duration,
                request: HarRequest {
                    method: ex.method,
                    url,
                    http_version: ex.protocol.clone(),
                    headers: request_headers,
                    query_string,
                    cookies: vec![],
                    post_data: (!request_body.is_empty()).then(|| HarPostData {
                        mime_type: request_mime,
                        text: base64::engine::general_purpose::STANDARD.encode(request_body),
                        encoding: Some("base64".into()),
                    }),
                    headers_size: -1,
                    body_size: request_body.len() as i64,
                },
                response: HarResponse {
                    status: ex.status_code.unwrap_or(0),
                    status_text: String::new(),
                    http_version: ex.protocol,
                    headers: response_headers,
                    cookies: vec![],
                    content: HarContent {
                        size: response_body.len() as i64,
                        mime_type: ex.mime.unwrap_or_default(),
                        text: (!response_body.is_empty()).then(|| {
                            base64::engine::general_purpose::STANDARD.encode(response_body)
                        }),
                        encoding: (!response_body.is_empty()).then(|| "base64".into()),
                    },
                    redirect_url: redirect,
                    headers_size: -1,
                    body_size: response_body.len() as i64,
                },
                cache: serde_json::json!({}),
                timings: HarTimings {
                    blocked: -1.0,
                    dns: -1.0,
                    connect: -1.0,
                    send: 0.0,
                    wait: duration,
                    receive: 0.0,
                    ssl: -1.0,
                },
                huntproxy: Some(HarExtension {
                    request_headers_raw: request_raw,
                    response_headers_raw: response_raw,
                    omitted_sensitive_headers: omitted,
                }),
            });
        }
        Ok(Har {
            log: HarLog {
                version: "1.2".into(),
                creator: HarCreator {
                    name: crate::DISPLAY_NAME.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                },
                entries,
            },
        })
    }

    pub async fn import_har_file(
        &self,
        project_id: ProjectId,
        path: &Path,
    ) -> DomainResult<HarImportResult> {
        self.get_project(project_id).await?;
        let metadata = std::fs::metadata(path)
            .map_err(|error| DomainError::invalid(format!("read HAR: {error}")))?;
        if metadata.len() > MAX_HAR_FILE_BYTES {
            return Err(DomainError::invalid("HAR exceeds 512 MiB limit"));
        }
        let file = std::fs::File::open(path)
            .map_err(|error| DomainError::invalid(format!("open HAR: {error}")))?;
        let har: Har = serde_json::from_reader(file)
            .map_err(|error| DomainError::invalid(format!("invalid HAR: {error}")))?;
        if har.log.version != "1.2" && har.log.version != "1.1" {
            return Err(DomainError::invalid("unsupported HAR version"));
        }
        if har.log.entries.len() > MAX_HAR_ENTRIES {
            return Err(DomainError::invalid("HAR contains too many entries"));
        }
        let project = self.get_project(project_id).await?;
        let mut total_body_bytes = 0_u64;
        for entry in &har.log.entries {
            total_body_bytes = total_body_bytes
                .saturating_add(decoded_request_body(&entry.request)?.len() as u64)
                .saturating_add(decoded_response_body(&entry.response)?.len() as u64);
            if total_body_bytes > project.limits.max_disk_bytes {
                return Err(DomainError::invalid(
                    "HAR decoded bodies exceed project disk quota",
                ));
            }
        }
        let count = har.log.entries.len();
        let mut prepared = Vec::with_capacity(count);
        for entry in har.log.entries {
            let parsed = url::Url::parse(&entry.request.url)
                .map_err(|error| DomainError::invalid(format!("HAR request URL: {error}")))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(DomainError::invalid(
                    "HAR request URL must use HTTP or HTTPS",
                ));
            }
            let request_headers = import_headers(
                &entry.request.headers,
                entry
                    .huntproxy
                    .as_ref()
                    .map(|extension| extension.request_headers_raw.as_slice()),
            )?;
            let response_headers = import_headers(
                &entry.response.headers,
                entry
                    .huntproxy
                    .as_ref()
                    .map(|extension| extension.response_headers_raw.as_slice()),
            )?;
            let request_body = decoded_request_body(&entry.request)?;
            let response_body = decoded_response_body(&entry.response)?;
            let authority = parsed_authority(&parsed);
            prepared.push((
                NewExchange {
                    project_id,
                    source: ExchangeSource::Imported,
                    protocol: entry.request.http_version,
                    method: entry.request.method,
                    scheme: parsed.scheme().into(),
                    authority,
                    host: parsed.host_str().unwrap_or_default().to_ascii_lowercase(),
                    port: parsed.port_or_known_default().unwrap_or(80),
                    path: parsed.path().into(),
                    query: parsed.query().map(str::to_string),
                    status_code: (entry.response.status != 0).then_some(entry.response.status),
                    mime: (!entry.response.content.mime_type.is_empty())
                        .then_some(entry.response.content.mime_type),
                    completion: CompletionState::Complete,
                    capture_quality: CaptureQuality::Semantic,
                    header_representation: HeaderRepresentation::Semantic,
                    body_representation: BodyRepresentation::SemanticEncoded,
                    cache_provenance: CacheProvenance::Unknown,
                    transport_provenance: Some(TransportProvenance::GenericUnprofiled),
                    transport_profile: Some("har-import".into()),
                    request_headers,
                    response_headers,
                    request_body: (!request_body.is_empty()).then_some(request_body),
                    response_body: (!response_body.is_empty()).then_some(response_body),
                    duration_ms: Some(entry.time.max(0.0) as i64),
                    lineage: ExchangeLineage::default(),
                    page_title: None,
                    error_message: None,
                },
                entry.started_date_time,
            ));
        }
        self.with_conn(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            for (exchange, started) in prepared {
                let id = crate::storage::insert_exchange_conn(&tx, exchange)?;
                tx.execute(
                    "UPDATE exchanges SET started_at=?1 WHERE project_id=?2 AND exchange_id=?3",
                    rusqlite::params![started, project_id.get(), id.get()],
                )
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            }
            tx.commit()
                .map_err(|error| DomainError::new(ErrorCode::StorageError, error.to_string()))?;
            Ok(())
        })
        .await?;
        Ok(HarImportResult {
            project_id,
            imported_entries: count,
        })
    }
}

fn har_headers(
    headers: &[HeaderEntry],
    include_secrets: bool,
) -> (Vec<HarNameValue>, Vec<HarRawHeader>, Vec<String>) {
    let mut standard = Vec::new();
    let mut raw = Vec::new();
    let mut omitted = Vec::new();
    for header in headers {
        if is_sensitive_header(&header.name) && !include_secrets {
            omitted.push(header.name.clone());
            continue;
        }
        standard.push(HarNameValue {
            name: header.name.clone(),
            value: String::from_utf8_lossy(&header.value).into_owned(),
        });
        raw.push(HarRawHeader {
            name: header.name.clone(),
            value_base64: base64::engine::general_purpose::STANDARD.encode(&header.value),
            ordinal: header.ordinal,
        });
    }
    (standard, raw, omitted)
}

fn import_headers(
    standard: &[HarNameValue],
    raw: Option<&[HarRawHeader]>,
) -> DomainResult<Vec<HeaderEntry>> {
    if let Some(raw) = raw.filter(|headers| !headers.is_empty()) {
        let mut out = raw
            .iter()
            .map(|header| {
                let value = base64::engine::general_purpose::STANDARD
                    .decode(&header.value_base64)
                    .map_err(|error| DomainError::invalid(format!("HAR raw header: {error}")))?;
                Ok(HeaderEntry {
                    name: header.name.clone(),
                    value,
                    ordinal: header.ordinal,
                })
            })
            .collect::<DomainResult<Vec<_>>>()?;
        out.sort_by_key(|header| header.ordinal);
        return Ok(out);
    }
    Ok(standard
        .iter()
        .enumerate()
        .map(|(ordinal, header)| HeaderEntry {
            name: header.name.clone(),
            value: header.value.as_bytes().to_vec(),
            ordinal: ordinal as u32,
        })
        .collect())
}

fn decoded_request_body(request: &HarRequest) -> DomainResult<Vec<u8>> {
    let Some(post) = &request.post_data else {
        return Ok(vec![]);
    };
    if post.encoding.as_deref() == Some("base64") {
        base64::engine::general_purpose::STANDARD
            .decode(&post.text)
            .map_err(|error| DomainError::invalid(format!("HAR request body: {error}")))
    } else {
        Ok(post.text.as_bytes().to_vec())
    }
}

fn decoded_response_body(response: &HarResponse) -> DomainResult<Vec<u8>> {
    let Some(text) = &response.content.text else {
        return Ok(vec![]);
    };
    if response.content.encoding.as_deref() == Some("base64") {
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(|error| DomainError::invalid(format!("HAR response body: {error}")))
    } else {
        Ok(text.as_bytes().to_vec())
    }
}

fn exchange_url(exchange: &NewExchange) -> String {
    let mut url = format!(
        "{}://{}{}",
        exchange.scheme, exchange.authority, exchange.path
    );
    if let Some(query) = &exchange.query {
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }
    }
    url
}

fn parsed_authority(url: &url::Url) -> String {
    let host = match url.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        Some(host) => host.to_string(),
        None => String::new(),
    };
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

fn header_value(headers: &[HeaderEntry], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| String::from_utf8_lossy(&header.value).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_duplicate_headers_round_trip() {
        let input = vec![
            HeaderEntry {
                name: "X-Test".into(),
                value: vec![0, 255],
                ordinal: 0,
            },
            HeaderEntry {
                name: "X-Test".into(),
                value: b"two".to_vec(),
                ordinal: 1,
            },
        ];
        let (_, raw, _) = har_headers(&input, true);
        let restored = import_headers(&[], Some(&raw)).unwrap();
        assert_eq!(restored[0].value, vec![0, 255]);
        assert_eq!(restored[1].value, b"two");
    }

    #[test]
    fn sanitized_headers_omit_credentials() {
        let input = vec![
            HeaderEntry {
                name: "Authorization".into(),
                value: b"secret".to_vec(),
                ordinal: 0,
            },
            HeaderEntry {
                name: "Accept".into(),
                value: b"*/*".to_vec(),
                ordinal: 1,
            },
        ];
        let (headers, raw, omitted) = har_headers(&input, false);
        assert_eq!(headers.len(), 1);
        assert_eq!(raw.len(), 1);
        assert!(!raw.iter().any(|header| header.name == "Authorization"));
        assert_eq!(omitted, vec!["Authorization"]);
    }

    #[tokio::test]
    async fn har_file_round_trip_preserves_binary_and_duplicate_query() {
        let db = Db::open_in_memory().await.unwrap();
        let source = db
            .create_project(CreateProjectRequest {
                name: "source".into(),
                target_url: "https://example.test/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        db.insert_exchange(NewExchange {
            project_id: source.id,
            source: ExchangeSource::Reply,
            protocol: "HTTP/2".into(),
            method: "POST".into(),
            scheme: "https".into(),
            authority: "example.test".into(),
            host: "example.test".into(),
            port: 443,
            path: "/api".into(),
            query: Some("a=1&a=2".into()),
            status_code: Some(201),
            mime: Some("application/octet-stream".into()),
            completion: CompletionState::Complete,
            capture_quality: CaptureQuality::Semantic,
            header_representation: HeaderRepresentation::Semantic,
            body_representation: BodyRepresentation::SemanticEncoded,
            cache_provenance: CacheProvenance::None,
            transport_provenance: None,
            transport_profile: None,
            request_headers: vec![HeaderEntry {
                name: "X-Test".into(),
                value: vec![0, 255],
                ordinal: 0,
            }],
            response_headers: vec![],
            request_body: Some(vec![0, 1, 255]),
            response_body: Some(vec![9, 8, 7]),
            duration_ms: Some(3),
            lineage: ExchangeLineage::default(),
            page_title: None,
            error_message: None,
        })
        .await
        .unwrap();
        let har = db.export_har(source.id, true).await.unwrap();
        assert_eq!(har.log.entries[0].request.query_string.len(), 2);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.har");
        serde_json::to_writer(std::fs::File::create(&path).unwrap(), &har).unwrap();
        let target = db
            .create_project(CreateProjectRequest {
                name: "target".into(),
                target_url: "https://example.test/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        db.import_har_file(target.id, &path).await.unwrap();
        let body = db
            .load_raw_body(target.id, ExchangeId(1), MessageSide::Response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, vec![9, 8, 7]);
        let detail = db
            .get_exchange_detail(
                target.id,
                ExchangeId(1),
                crate::policy::PresentationOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(detail.summary.source, ExchangeSource::Imported);
        assert_eq!(detail.summary.query.as_deref(), Some("a=1&a=2"));
    }
}
