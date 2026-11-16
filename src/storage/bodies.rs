//! Body storage with hashing and optional zstd compression.

use crate::domain::{BodyId, DomainError, DomainResult, ErrorCode};
use crate::storage::Db;
use rusqlite::blob::ZeroBlob;
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

const COMPRESS_THRESHOLD: usize = 1024;

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[derive(Debug)]
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

/// A body's hash, and its encoding unless it was already stored, worked out
/// before the write transaction that stores it, so the write lock is not held
/// while a large body is hashed and compressed.
pub struct PreparedBody {
    hash: String,
    encoded: Option<(String, Vec<u8>)>,
}

pub fn prepare_body(conn: &rusqlite::Connection, data: &[u8]) -> PreparedBody {
    let hash = sha256_hex(data);
    // A body that is already stored is not compressed again. The check is
    // repeated in the write transaction, which may still have to encode it.
    let known = stored_body_by_hash(conn, &hash).is_some();
    PreparedBody {
        encoded: (!known).then(|| encode_body(data)),
        hash,
    }
}

fn encode_body(data: &[u8]) -> (String, Vec<u8>) {
    if data.len() >= COMPRESS_THRESHOLD {
        match zstd::encode_all(data, 3) {
            Ok(c) if c.len() < data.len() => ("zstd".to_string(), c),
            _ => ("raw".to_string(), data.to_vec()),
        }
    } else {
        ("raw".to_string(), data.to_vec())
    }
}

/// `(id, stored_length, codec)` of the body stored with this hash.
fn stored_body_by_hash(conn: &rusqlite::Connection, hash: &str) -> Option<(i64, i64, String)> {
    conn.query_row(
        "SELECT id, stored_length, codec FROM bodies WHERE sha256=?1 LIMIT 1",
        params![hash],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .ok()
}

pub fn store_body_conn(
    conn: &rusqlite::Connection,
    data: &[u8],
    mime_class: Option<&str>,
) -> DomainResult<StoredBody> {
    let prepared = prepare_body(conn, data);
    store_prepared_body_conn(conn, data, prepared, mime_class)
}

/// Stores `data`, prepared by [`prepare_body`], or finds it already stored.
pub fn store_prepared_body_conn(
    conn: &rusqlite::Connection,
    data: &[u8],
    prepared: PreparedBody,
    mime_class: Option<&str>,
) -> DomainResult<StoredBody> {
    let PreparedBody { hash, encoded } = prepared;
    if let Some((id, stored_length, codec)) = stored_body_by_hash(conn, &hash) {
        return Ok(StoredBody {
            id: BodyId(id),
            sha256: hash,
            original_length: data.len() as i64,
            stored_length,
            codec,
        });
    }
    let (codec, stored) = encoded.unwrap_or_else(|| encode_body(data));

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

/// A spooled body's hash and length, read before the write transaction that
/// stores it.
pub struct HashedBodyFile {
    hash: String,
    length: u64,
}

pub fn hash_body_file(path: &Path) -> DomainResult<HashedBodyFile> {
    let mut file = open_body_spool(path)?;
    let length = file.metadata().map_err(storage_io_error)?.len();
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(storage_io_error)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(HashedBodyFile {
        hash: hex::encode(hasher.finalize()),
        length,
    })
}

fn open_body_spool(path: &Path) -> DomainResult<std::fs::File> {
    std::fs::File::open(path).map_err(|error| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("open body spool {}: {error}", path.display()),
        )
    })
}

/// Stores a spooled body hashed by [`hash_body_file`], or finds it already
/// stored.
pub fn store_body_file_conn(
    conn: &rusqlite::Connection,
    path: &Path,
    hashed: HashedBodyFile,
    mime_class: Option<&str>,
) -> DomainResult<StoredBody> {
    let HashedBodyFile { hash, length } = hashed;
    let original_length = i64::try_from(length).map_err(|_| {
        DomainError::new(
            ErrorCode::BodyTooLarge,
            "body spool length exceeds SQLite limits",
        )
    })?;
    // Incremental BLOB writes take `int` offsets.
    if i32::try_from(length).is_err() {
        return Err(DomainError::new(
            ErrorCode::BodyTooLarge,
            "body spool exceeds SQLite incremental BLOB limit",
        ));
    }

    if let Some((id, stored_length, codec)) = stored_body_by_hash(conn, &hash) {
        return Ok(StoredBody {
            id: BodyId(id),
            sha256: hash,
            original_length,
            stored_length,
            codec,
        });
    }

    let mut file = open_body_spool(path)?;
    if file.metadata().map_err(storage_io_error)?.len() != length {
        return Err(DomainError::new(
            ErrorCode::StorageError,
            format!("body spool {} changed after it was hashed", path.display()),
        ));
    }
    conn.execute(
        "INSERT INTO bodies (sha256, original_length, stored_length, codec, mime_class, content)
         VALUES (?1, ?2, ?3, 'raw', ?4, ?5)",
        params![
            hash,
            original_length,
            original_length,
            mime_class,
            ZeroBlob(length)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn count(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT count(*) FROM bodies", [], |row| row.get(0))
            .unwrap()
    }

    #[tokio::test]
    async fn prepared_bodies_are_compressed_once_and_deduplicated() {
        let db = Db::open_in_memory().await.unwrap();
        db.with_conn(|conn| {
            let body = "fuzz response ".repeat(400).into_bytes();
            let prepared = prepare_body(conn, &body);
            assert_eq!(prepared.encoded.as_ref().unwrap().0, "zstd");
            let first = store_prepared_body_conn(conn, &body, prepared, Some("html")).unwrap();
            assert_eq!(first.codec, "zstd");
            assert!(first.stored_length < first.original_length);

            // A stored body is not compressed again, and is found again.
            let again = prepare_body(conn, &body);
            assert!(again.encoded.is_none());
            let second = store_prepared_body_conn(conn, &body, again, None).unwrap();
            assert_eq!(second.id, first.id);
            assert_eq!(count(conn), 1);

            // Removed after it was prepared: it is encoded in the transaction.
            let stale = prepare_body(conn, &body);
            conn.execute("DELETE FROM bodies", []).unwrap();
            let restored = store_prepared_body_conn(conn, &body, stale, None).unwrap();
            assert_eq!(restored.codec, "zstd");
            let (codec, content): (String, Vec<u8>) = conn
                .query_row(
                    "SELECT codec, content FROM bodies WHERE id=?1",
                    [restored.id.get()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(decode_body(&codec, &content).unwrap(), body);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn spooled_bodies_are_hashed_before_storing_and_checked_for_changes() {
        let db = Db::open_in_memory().await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("spool");
        std::fs::write(&path, b"spooled body").unwrap();
        db.with_conn(move |conn| {
            let hashed = hash_body_file(&path).unwrap();
            let stored = store_body_file_conn(conn, &path, hashed, None).unwrap();
            assert_eq!(stored.sha256, sha256_hex(b"spooled body"));
            assert_eq!(stored.original_length, 12);
            let again =
                store_body_file_conn(conn, &path, hash_body_file(&path).unwrap(), None).unwrap();
            assert_eq!(again.id, stored.id);

            std::fs::write(&path, b"first").unwrap();
            let hashed = hash_body_file(&path).unwrap();
            std::fs::write(&path, b"first, then longer").unwrap();
            let error = store_body_file_conn(conn, &path, hashed, None).unwrap_err();
            assert!(
                error.to_string().contains("changed after it was hashed"),
                "{error}"
            );
            assert_eq!(count(conn), 1);
            Ok(())
        })
        .await
        .unwrap();
    }
}
