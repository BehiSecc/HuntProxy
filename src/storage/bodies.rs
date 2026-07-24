//! Body storage with hashing and optional zstd compression.

use crate::domain::{BodyId, DomainError, DomainResult, ErrorCode};
use crate::storage::Db;
use rusqlite::params;
use sha2::{Digest, Sha256};

const COMPRESS_THRESHOLD: usize = 1024;

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub struct StoredBody {
    pub id: BodyId,
    pub sha256: String,
    pub original_length: i64,
    pub stored_length: i64,
    pub codec: String,
}

impl Db {
    pub async fn store_body(&self, data: Vec<u8>, mime_class: Option<String>) -> DomainResult<StoredBody> {
        self.with_conn(move |conn| store_body_conn(conn, &data, mime_class.as_deref()))
            .await
    }

    pub async fn read_body_range(
        &self,
        id: BodyId,
        offset: usize,
        max_bytes: usize,
    ) -> DomainResult<(Vec<u8>, i64, String)> {
        self.with_conn(move |conn| {
            let (codec, content, original_length): (String, Vec<u8>, i64) = conn
                .query_row(
                    "SELECT codec, content, original_length FROM bodies WHERE id=?1",
                    params![id.get()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => {
                        DomainError::not_found(format!("body {}", id.get()))
                    }
                    other => DomainError::new(ErrorCode::StorageError, other.to_string()),
                })?;
            let raw = decode_body(&codec, &content)?;
            let total = original_length;
            let end = (offset + max_bytes).min(raw.len());
            let slice = if offset >= raw.len() {
                Vec::new()
            } else {
                raw[offset..end].to_vec()
            };
            Ok((slice, total, sha256_hex(&raw)))
        })
        .await
    }
}

pub fn store_body_conn(
    conn: &rusqlite::Connection,
    data: &[u8],
    mime_class: Option<&str>,
) -> DomainResult<StoredBody> {
    let hash = sha256_hex(data);
    // dedup by hash
    if let Ok((id, stored_length, codec)) = conn.query_row(
        "SELECT id, stored_length, codec FROM bodies WHERE sha256=?1 LIMIT 1",
        params![hash],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, String>(2)?)),
    ) {
        return Ok(StoredBody {
            id: BodyId(id),
            sha256: hash,
            original_length: data.len() as i64,
            stored_length,
            codec,
        });
    }

    let (codec, stored) = if data.len() >= COMPRESS_THRESHOLD {
        match zstd::encode_all(data, 3) {
            Ok(c) if c.len() < data.len() => ("zstd".to_string(), c),
            _ => ("raw".to_string(), data.to_vec()),
        }
    } else {
        ("raw".to_string(), data.to_vec())
    };

    conn.execute(
        "INSERT INTO bodies (sha256, original_length, stored_length, codec, mime_class, content)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            hash,
            data.len() as i64,
            stored.len() as i64,
            codec,
            mime_class,
            stored
        ],
    )
    .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;

    Ok(StoredBody {
        id: BodyId(conn.last_insert_rowid()),
        sha256: hash,
        original_length: data.len() as i64,
        stored_length: stored.len() as i64,
        codec,
    })
}

fn decode_body(codec: &str, content: &[u8]) -> DomainResult<Vec<u8>> {
    match codec {
        "raw" => Ok(content.to_vec()),
        "zstd" => zstd::decode_all(content)
            .map_err(|e| DomainError::new(ErrorCode::StorageError, format!("zstd decode: {e}"))),
        other => Err(DomainError::new(
            ErrorCode::StorageError,
            format!("unknown body codec {other}"),
        )),
    }
}
