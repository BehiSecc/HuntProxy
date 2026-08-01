//! Body storage with hashing and optional zstd compression.

use crate::domain::{BodyId, DomainError, DomainResult, ErrorCode};
use crate::storage::Db;
use rusqlite::blob::ZeroBlob;
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

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
    pub async fn store_body(
        &self,
        data: Vec<u8>,
        mime_class: Option<String>,
    ) -> DomainResult<StoredBody> {
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
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
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

pub fn store_body_file_conn(
    conn: &rusqlite::Connection,
    path: &Path,
    mime_class: Option<&str>,
) -> DomainResult<StoredBody> {
    let mut file = std::fs::File::open(path).map_err(|error| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("open body spool {}: {error}", path.display()),
        )
    })?;
    let length = file.metadata().map_err(storage_io_error)?.len();
    let original_length = i64::try_from(length).map_err(|_| {
        DomainError::new(
            ErrorCode::BodyTooLarge,
            "body spool length exceeds SQLite limits",
        )
    })?;
    let blob_length = i32::try_from(length).map_err(|_| {
        DomainError::new(
            ErrorCode::BodyTooLarge,
            "body spool exceeds SQLite incremental BLOB limit",
        )
    })?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(storage_io_error)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let hash = hex::encode(hasher.finalize());

    if let Ok((id, stored_length, codec)) = conn.query_row(
        "SELECT id, stored_length, codec FROM bodies WHERE sha256=?1 LIMIT 1",
        params![hash],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    ) {
        return Ok(StoredBody {
            id: BodyId(id),
            sha256: hash,
            original_length,
            stored_length,
            codec,
        });
    }

    file.seek(SeekFrom::Start(0)).map_err(storage_io_error)?;
    conn.execute(
        "INSERT INTO bodies (sha256, original_length, stored_length, codec, mime_class, content)
         VALUES (?1, ?2, ?3, 'raw', ?4, ?5)",
        params![
            hash,
            original_length,
            original_length,
            mime_class,
            ZeroBlob(blob_length)
        ],
    )
    .map_err(storage_error)?;
    let id = conn.last_insert_rowid();
    let mut blob = conn
        .blob_open(rusqlite::MAIN_DB, "bodies", "content", id, false)
        .map_err(storage_error)?;
    let copied = std::io::copy(&mut file, &mut blob).map_err(storage_io_error)?;
    if copied != length {
        return Err(DomainError::new(
            ErrorCode::StorageError,
            format!("short body spool copy: expected {length}, copied {copied}"),
        ));
    }

    Ok(StoredBody {
        id: BodyId(id),
        sha256: hash,
        original_length,
        stored_length: original_length,
        codec: "raw".into(),
    })
}

pub(crate) fn decode_body(codec: &str, content: &[u8]) -> DomainResult<Vec<u8>> {
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

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

fn storage_io_error(error: std::io::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}
