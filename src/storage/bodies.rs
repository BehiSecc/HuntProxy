//! Body storage with hashing and optional zstd compression.

use crate::domain::{BodyId, DomainError, DomainResult, ErrorCode};
use crate::storage::Db;
use rusqlite::blob::ZeroBlob;
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const COMPRESS_THRESHOLD: usize = 1024;
const ZSTD_LEVEL: i32 = 3;
/// A larger body is compressed only if its first bytes shrink, so an image or
/// a gzip or brotli stream is stored as it is without compressing all of it.
const SAMPLE_BYTES: usize = 64 * 1024;

/// Whether `sample` shrinks by at least 2% at zstd's fastest level.
fn sample_compresses(sample: &[u8]) -> bool {
    zstd::bulk::compress(sample, 1)
        .is_ok_and(|compressed| compressed.len() + sample.len() / 50 < sample.len())
}

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
    let worth_trying = data.len() >= COMPRESS_THRESHOLD
        && (data.len() <= SAMPLE_BYTES || sample_compresses(&data[..SAMPLE_BYTES]));
    if worth_trying {
        match zstd::encode_all(data, ZSTD_LEVEL) {
            Ok(c) if c.len() < data.len() => return ("zstd".to_string(), c),
            _ => {}
        }
    }
    ("raw".to_string(), data.to_vec())
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

/// A spooled body's hash and length, and its encoding unless it was already
/// stored, worked out before the write transaction that stores it.
pub struct PreparedBodyFile {
    hash: String,
    length: u64,
    encoding: SpoolEncoding,
}

enum SpoolEncoding {
    /// Already stored when prepared; encoded in the transaction if it is gone.
    Unprepared,
    Raw,
    Zstd(CompressedSpool),
}

/// A zstd copy of a spooled body, removed when dropped.
struct CompressedSpool {
    path: PathBuf,
    length: u64,
}

impl Drop for CompressedSpool {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %self.path.display(), %error, "failed to remove compressed body spool");
            }
        }
    }
}

pub fn prepare_body_file(
    conn: &rusqlite::Connection,
    path: &Path,
) -> DomainResult<PreparedBodyFile> {
    let mut file = open_body_spool(path)?;
    let length = file.metadata().map_err(storage_io_error)?.len();
    let hash = hash_reader(&mut file, |_| Ok(()))?;
    let encoding = if stored_body_by_hash(conn, &hash).is_some() {
        SpoolEncoding::Unprepared
    } else {
        encode_spool(path, &hash, length)?
    };
    Ok(PreparedBodyFile {
        hash,
        length,
        encoding,
    })
}

/// Hashes everything `reader` yields, handing each chunk to `sink` as well.
fn hash_reader(
    reader: &mut impl Read,
    mut sink: impl FnMut(&[u8]) -> std::io::Result<()>,
) -> DomainResult<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(storage_io_error)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        sink(&buffer[..read]).map_err(storage_io_error)?;
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Compresses a spool into a private file beside it when that saves space,
/// streaming so a large body is never held in memory. The copy is hashed as it
/// is written, so a spool that changed after it was hashed is refused.
fn encode_spool(path: &Path, hash: &str, length: u64) -> DomainResult<SpoolEncoding> {
    if length < COMPRESS_THRESHOLD as u64 {
        return Ok(SpoolEncoding::Raw);
    }
    let mut file = open_body_spool(path)?;
    if length > SAMPLE_BYTES as u64 {
        let mut sample = vec![0u8; SAMPLE_BYTES];
        file.read_exact(&mut sample).map_err(storage_io_error)?;
        if !sample_compresses(&sample) {
            return Ok(SpoolEncoding::Raw);
        }
        file.seek(SeekFrom::Start(0)).map_err(storage_io_error)?;
    }
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".zst");
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let target = path.with_file_name(name);
    let output = options.open(&target).map_err(|error| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("create compressed body spool {}: {error}", target.display()),
        )
    })?;
    let mut compressed = CompressedSpool {
        path: target,
        length: 0,
    };
    let mut encoder = zstd::stream::Encoder::new(std::io::BufWriter::new(output), ZSTD_LEVEL)
        .map_err(storage_io_error)?;
    encoder
        .include_contentsize(true)
        .map_err(storage_io_error)?;
    encoder
        .set_pledged_src_size(Some(length))
        .map_err(storage_io_error)?;
    let mut copied = 0u64;
    let copy_hash = hash_reader(&mut file, |chunk| {
        copied += chunk.len() as u64;
        encoder.write_all(chunk)
    })?;
    if copied != length || copy_hash != hash {
        return Err(spool_changed(path));
    }
    let output = encoder
        .finish()
        .map_err(storage_io_error)?
        .into_inner()
        .map_err(|error| storage_io_error(error.into_error()))?;
    compressed.length = output.metadata().map_err(storage_io_error)?.len();
    if compressed.length >= length {
        return Ok(SpoolEncoding::Raw);
    }
    Ok(SpoolEncoding::Zstd(compressed))
}

fn spool_changed(path: &Path) -> DomainError {
    DomainError::new(
        ErrorCode::StorageError,
        format!("body spool {} changed after it was hashed", path.display()),
    )
}

fn open_body_spool(path: &Path) -> DomainResult<std::fs::File> {
    std::fs::File::open(path).map_err(|error| {
        DomainError::new(
            ErrorCode::StorageError,
            format!("open body spool {}: {error}", path.display()),
        )
    })
}

/// Stores a spooled body prepared by [`prepare_body_file`], or finds it
/// already stored.
pub fn store_body_file_conn(
    conn: &rusqlite::Connection,
    path: &Path,
    prepared: PreparedBodyFile,
    mime_class: Option<&str>,
) -> DomainResult<StoredBody> {
    let PreparedBodyFile {
        hash,
        length,
        encoding,
    } = prepared;
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

    let encoding = match encoding {
        SpoolEncoding::Unprepared => encode_spool(path, &hash, length)?,
        prepared => prepared,
    };
    // The compressed copy was checked against the hash as it was written.
    let (codec, mut source, stored_length) = match &encoding {
        SpoolEncoding::Zstd(compressed) => (
            "zstd",
            open_body_spool(&compressed.path)?,
            compressed.length,
        ),
        _ => {
            let file = open_body_spool(path)?;
            if file.metadata().map_err(storage_io_error)?.len() != length {
                return Err(spool_changed(path));
            }
            ("raw", file, length)
        }
    };
    conn.execute(
        "INSERT INTO bodies (sha256, original_length, stored_length, codec, mime_class, content)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            hash,
            original_length,
            stored_length as i64,
            codec,
            mime_class,
            ZeroBlob(stored_length)
        ],
    )
    .map_err(storage_error)?;
    let id = conn.last_insert_rowid();
    let mut blob = conn
        .blob_open(rusqlite::MAIN_DB, "bodies", "content", id, false)
        .map_err(storage_error)?;
    let copied = std::io::copy(&mut source, &mut blob).map_err(storage_io_error)?;
    if copied != stored_length {
        return Err(DomainError::new(
            ErrorCode::StorageError,
            format!("short body spool copy: expected {stored_length}, copied {copied}"),
        ));
    }

    Ok(StoredBody {
        id: BodyId(id),
        sha256: hash,
        original_length,
        stored_length: stored_length as i64,
        codec: codec.into(),
    })
}

/// What one pass over stored bodies compressed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BodyCompaction {
    pub compressed: u64,
    pub saved_bytes: u64,
}

const COMPRESS_TASK: &str = "compress_raw_bodies";
/// Bodies read and compressed between two short write transactions.
const COMPACTION_BATCH_BYTES: i64 = 32 << 20;
const COMPACTION_BATCH_ROWS: i64 = 256;

impl Db {
    /// Compresses bodies that earlier versions stored uncompressed, in small
    /// batches so captures keep their turn to write. It resumes where it
    /// stopped and returns `None` once a pass has finished.
    pub async fn compress_stored_bodies(
        &self,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> DomainResult<Option<BodyCompaction>> {
        let mut total = BodyCompaction::default();
        loop {
            if cancel.is_cancelled() {
                return Ok(Some(total));
            }
            match self.with_conn(compress_body_batch).await? {
                BatchOutcome::AlreadyFinished => return Ok(None),
                BatchOutcome::Finished => return Ok(Some(total)),
                BatchOutcome::Compressed(batch) => {
                    total.compressed += batch.compressed;
                    total.saved_bytes += batch.saved_bytes;
                }
            }
            tokio::task::yield_now().await;
        }
    }
}

enum BatchOutcome {
    AlreadyFinished,
    Finished,
    Compressed(BodyCompaction),
}

fn compress_body_batch(conn: &rusqlite::Connection) -> DomainResult<BatchOutcome> {
    use rusqlite::OptionalExtension;
    let state: Option<(i64, Option<String>)> = conn
        .query_row(
            "SELECT cursor, finished_at FROM storage_maintenance WHERE task=?1",
            params![COMPRESS_TASK],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(storage_error)?;
    let cursor = match state {
        Some((cursor, None)) => cursor,
        _ => return Ok(BatchOutcome::AlreadyFinished),
    };
    let candidates: Vec<(i64, i64, String)> = {
        let mut statement = conn
            .prepare(
                "SELECT id, original_length, sha256 FROM bodies
                  WHERE id > ?1 AND codec = 'raw' ORDER BY id LIMIT ?2",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map(params![cursor, COMPACTION_BATCH_ROWS], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(storage_error)?;
        rows.collect::<Result<_, _>>().map_err(storage_error)?
    };
    if candidates.is_empty() {
        conn.execute(
            "UPDATE storage_maintenance SET finished_at=?2 WHERE task=?1",
            params![COMPRESS_TASK, crate::storage::now_rfc3339()],
        )
        .map_err(storage_error)?;
        return Ok(BatchOutcome::Finished);
    }

    // Compress outside the write transaction.
    let mut last_id = cursor;
    let mut read = 0i64;
    let mut encoded = Vec::new();
    for (id, length, sha256) in candidates {
        if read >= COMPACTION_BATCH_BYTES {
            break;
        }
        last_id = id;
        if length < COMPRESS_THRESHOLD as i64 {
            continue;
        }
        let Some(content) = compressible_body_content(conn, id, length)? else {
            continue;
        };
        read += length;
        if sha256_hex(&content) != sha256 {
            tracing::warn!(
                body = id,
                "stored body does not match its hash; left as it is"
            );
            continue;
        }
        let Ok(compressed) = zstd::encode_all(content.as_slice(), ZSTD_LEVEL) else {
            continue;
        };
        if compressed.len() >= content.len() {
            continue;
        }
        if decode_body("zstd", &compressed)? != content {
            return Err(DomainError::new(
                ErrorCode::StorageError,
                format!("compressed body {id} did not decode to the original"),
            ));
        }
        encoded.push((id, content.len() as u64, compressed));
    }

    let tx = crate::storage::write_transaction(conn).map_err(storage_error)?;
    let mut batch = BodyCompaction::default();
    for (id, length, compressed) in encoded {
        let changed = tx
            .execute(
                "UPDATE bodies SET codec='zstd', stored_length=?2, content=?3
                  WHERE id=?1 AND codec='raw'",
                params![id, compressed.len() as i64, compressed],
            )
            .map_err(storage_error)?;
        if changed == 1 {
            batch.compressed += 1;
            batch.saved_bytes += length - compressed.len() as u64;
        }
    }
    tx.execute(
        "UPDATE storage_maintenance SET cursor=?2 WHERE task=?1",
        params![COMPRESS_TASK, last_id],
    )
    .map_err(storage_error)?;
    tx.commit().map_err(storage_error)?;
    Ok(BatchOutcome::Compressed(batch))
}

/// A raw body's content if it is worth compressing. Only the first bytes of a
/// large body are read to decide, so images and gzip or brotli streams are not
/// read whole.
fn compressible_body_content(
    conn: &rusqlite::Connection,
    id: i64,
    length: i64,
) -> DomainResult<Option<Vec<u8>>> {
    let mut blob = match conn.blob_open(rusqlite::MAIN_DB, "bodies", "content", id, true) {
        Ok(blob) => blob,
        Err(error) => {
            // Removed since it was listed: nothing to compress.
            let exists = conn
                .query_row("SELECT 1 FROM bodies WHERE id=?1", params![id], |_| Ok(()))
                .is_ok();
            return if exists {
                Err(storage_error(error))
            } else {
                Ok(None)
            };
        }
    };
    let mut content = Vec::with_capacity(usize::try_from(length).unwrap_or(0));
    if length > SAMPLE_BYTES as i64 {
        (&mut blob)
            .take(SAMPLE_BYTES as u64)
            .read_to_end(&mut content)
            .map_err(storage_io_error)?;
        if !sample_compresses(&content) {
            return Ok(None);
        }
    }
    blob.read_to_end(&mut content).map_err(storage_io_error)?;
    Ok(Some(content))
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
            let prepared = prepare_body_file(conn, &path).unwrap();
            let stored = store_body_file_conn(conn, &path, prepared, None).unwrap();
            assert_eq!(stored.sha256, sha256_hex(b"spooled body"));
            assert_eq!(stored.original_length, 12);
            let again =
                store_body_file_conn(conn, &path, prepare_body_file(conn, &path).unwrap(), None)
                    .unwrap();
            assert_eq!(again.id, stored.id);

            std::fs::write(&path, b"first").unwrap();
            let prepared = prepare_body_file(conn, &path).unwrap();
            std::fs::write(&path, b"first, then longer").unwrap();
            let error = store_body_file_conn(conn, &path, prepared, None).unwrap_err();
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

    fn stored(conn: &rusqlite::Connection, id: BodyId) -> (String, i64, Vec<u8>) {
        conn.query_row(
            "SELECT codec, stored_length, content FROM bodies WHERE id=?1",
            [id.get()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
    }

    fn files_in(directory: &Path) -> usize {
        std::fs::read_dir(directory).unwrap().count()
    }

    /// Bytes that do not compress, as an image or a gzip stream would not.
    fn incompressible(length: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect()
    }

    #[tokio::test]
    async fn spooled_bodies_are_compressed_before_the_transaction_and_read_back_exactly() {
        let db = Db::open_in_memory().await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".response-1.spool");
        // Larger than the sample, so the streaming path is used.
        let body = "<div class=\"row\">captured page</div>\n"
            .repeat(8_000)
            .into_bytes();
        std::fs::write(&path, &body).unwrap();
        let spool_dir = directory.path().to_path_buf();
        db.with_conn(move |conn| {
            let prepared = prepare_body_file(conn, &path).unwrap();
            assert!(matches!(prepared.encoding, SpoolEncoding::Zstd(_)));
            // The compressed copy sits beside the spool until it is stored.
            assert_eq!(files_in(&spool_dir), 2);
            let first = store_body_file_conn(conn, &path, prepared, Some("text/html")).unwrap();
            assert_eq!(files_in(&spool_dir), 1);
            assert_eq!(first.codec, "zstd");
            assert_eq!(first.original_length, body.len() as i64);
            assert!(first.stored_length * 20 < first.original_length);
            let (codec, stored_length, content) = stored(conn, first.id);
            assert_eq!(
                (codec.as_str(), stored_length),
                ("zstd", first.stored_length)
            );
            assert_eq!(decode_body(&codec, &content).unwrap(), body);
            assert_eq!(first.sha256, sha256_hex(&body));

            // A stored body is found by its hash and not compressed again.
            let again = prepare_body_file(conn, &path).unwrap();
            assert!(matches!(again.encoding, SpoolEncoding::Unprepared));
            assert_eq!(files_in(&spool_dir), 1);
            let second = store_body_file_conn(conn, &path, again, None).unwrap();
            assert_eq!(second.id, first.id);

            // Removed after it was prepared: it is compressed in the transaction.
            let stale = prepare_body_file(conn, &path).unwrap();
            conn.execute("DELETE FROM bodies", []).unwrap();
            let restored = store_body_file_conn(conn, &path, stale, None).unwrap();
            assert_eq!(restored.codec, "zstd");
            let (codec, _, content) = stored(conn, restored.id);
            assert_eq!(decode_body(&codec, &content).unwrap(), body);
            assert_eq!(files_in(&spool_dir), 1);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn spooled_bodies_that_do_not_compress_stay_raw_without_leftovers() {
        let db = Db::open_in_memory().await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let spool_dir = directory.path().to_path_buf();
        db.with_conn(move |conn| {
            for (name, body) in [
                ("small", b"tiny".to_vec()),
                ("noise", incompressible(200_000)),
                ("short-noise", incompressible(4_000)),
            ] {
                let path = spool_dir.join(name);
                std::fs::write(&path, &body).unwrap();
                let prepared = prepare_body_file(conn, &path).unwrap();
                assert!(matches!(prepared.encoding, SpoolEncoding::Raw), "{name}");
                let stored_body = store_body_file_conn(conn, &path, prepared, None).unwrap();
                assert_eq!(stored_body.codec, "raw", "{name}");
                let (codec, stored_length, content) = stored(conn, stored_body.id);
                assert_eq!((codec.as_str(), stored_length), ("raw", body.len() as i64));
                assert_eq!(content, body, "{name}");
                std::fs::remove_file(&path).unwrap();
                assert_eq!(files_in(&spool_dir), 0, "{name}");
            }
            Ok(())
        })
        .await
        .unwrap();
    }

    #[test]
    fn a_spool_changed_while_it_is_compressed_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("spool");
        let original = "compressible ".repeat(10_000).into_bytes();
        std::fs::write(&path, &original).unwrap();
        let mut file = open_body_spool(&path).unwrap();
        let hash = hash_reader(&mut file, |_| Ok(())).unwrap();
        // Same length, different bytes: only the hash can tell.
        std::fs::write(&path, "COMPRESSIBLE ".repeat(10_000)).unwrap();
        let error = match encode_spool(&path, &hash, original.len() as u64) {
            Err(error) => error,
            Ok(_) => panic!("a changed spool was accepted"),
        };
        assert!(
            error.to_string().contains("changed after it was hashed"),
            "{error}"
        );
        assert_eq!(files_in(directory.path()), 1);
    }

    #[test]
    fn in_memory_bodies_skip_compression_when_their_start_does_not_shrink() {
        let noise = incompressible(SAMPLE_BYTES * 3);
        assert_eq!(encode_body(&noise), ("raw".to_string(), noise.clone()));
        let text = "{\"items\":[1,2,3]}".repeat(10_000).into_bytes();
        let (codec, encoded) = encode_body(&text);
        assert_eq!(codec, "zstd");
        assert_eq!(decode_body(&codec, &encoded).unwrap(), text);
    }

    fn insert_raw(conn: &rusqlite::Connection, content: &[u8], sha256: &str) -> BodyId {
        conn.execute(
            "INSERT INTO bodies (sha256, original_length, stored_length, codec, content)
             VALUES (?1, ?2, ?2, 'raw', ?3)",
            params![sha256, content.len() as i64, content],
        )
        .unwrap();
        BodyId(conn.last_insert_rowid())
    }

    #[tokio::test]
    async fn bodies_stored_raw_by_earlier_versions_are_compressed_once() {
        let db = Db::open_in_memory().await.unwrap();
        let page = "<li class=\"result\">captured before</li>\n"
            .repeat(10_000)
            .into_bytes();
        let json = "{\"id\":1,\"ok\":true}".repeat(200).into_bytes();
        let noise = incompressible(150_000);
        let tampered = "same length, other bytes ".repeat(100).into_bytes();
        let bodies = [page.clone(), json.clone(), noise.clone(), b"tiny".to_vec()];
        let (ids, tampered_id) = db
            .with_conn(move |conn| {
                let ids: Vec<BodyId> = bodies
                    .iter()
                    .map(|body| insert_raw(conn, body, &sha256_hex(body)))
                    .collect();
                // Content that no longer matches its hash is left untouched.
                let tampered_id = insert_raw(conn, &tampered, &sha256_hex(b"other"));
                Ok((ids, tampered_id))
            })
            .await
            .unwrap();

        // A stopped pass does nothing and resumes later.
        let stopped = tokio_util::sync::CancellationToken::new();
        stopped.cancel();
        assert_eq!(
            db.compress_stored_bodies(&stopped).await.unwrap(),
            Some(BodyCompaction::default())
        );

        let token = tokio_util::sync::CancellationToken::new();
        let done = db.compress_stored_bodies(&token).await.unwrap().unwrap();
        assert_eq!(done.compressed, 2);
        assert!(done.saved_bytes > page.len() as u64 / 2);
        db.with_conn(move |conn| {
            for (id, original, codec) in [
                (ids[0], page, "zstd"),
                (ids[1], json, "zstd"),
                (ids[2], noise, "raw"),
                (ids[3], b"tiny".to_vec(), "raw"),
            ] {
                let (stored_codec, stored_length, content) = stored(conn, id);
                assert_eq!(stored_codec, codec);
                assert_eq!(stored_length, content.len() as i64);
                assert_eq!(decode_body(&stored_codec, &content).unwrap(), original);
            }
            assert_eq!(stored(conn, tampered_id).0, "raw");
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(db.compress_stored_bodies(&token).await.unwrap(), None);
    }
}
