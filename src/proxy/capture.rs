//! Bodies captured for History while they are forwarded.
//!
//! A body is held in memory while it is small. Once it outgrows
//! [`MEMORY_BODY_BYTES`] it moves to a private spool file, so a capture never
//! holds more than that much of one body. A spool is scratch space: the
//! evidence becomes durable when its exchange is committed to the database,
//! and a spool left behind by a crash is never read back, so it is not synced
//! to disk.

use super::{create_private_spool, SpoolGuard};
use crate::storage::CapturedBody;
use crate::transport::OutboundBody;
use bytes::Bytes;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncWriteExt, BufWriter};

/// The most of one body a capture holds in memory.
pub(super) const MEMORY_BODY_BYTES: usize = 256 * 1024;

/// Each write to a spool is a hop to a blocking thread, so chunks are
/// gathered into writes of this size.
const SPOOL_WRITE_BYTES: usize = 256 * 1024;

/// A body being captured, chunk by chunk.
pub(super) struct BodyCapture {
    spool_dir: PathBuf,
    kind: &'static str,
    memory: Vec<u8>,
    spool: Option<(SpoolGuard, BufWriter<tokio::fs::File>)>,
    len: u64,
}

impl BodyCapture {
    pub(super) fn new(spool_dir: &Path, kind: &'static str) -> Self {
        Self {
            spool_dir: spool_dir.to_path_buf(),
            kind,
            memory: Vec::new(),
            spool: None,
            len: 0,
        }
    }

    pub(super) fn len(&self) -> u64 {
        self.len
    }

    pub(super) async fn write(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        if let Some((_, file)) = &mut self.spool {
            file.write_all(chunk).await?;
        } else if self.memory.len() + chunk.len() <= MEMORY_BODY_BYTES {
            self.memory.extend_from_slice(chunk);
        } else {
            let (guard, file) = create_private_spool(&self.spool_dir, self.kind)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let mut file = BufWriter::with_capacity(SPOOL_WRITE_BYTES, file);
            file.write_all(&self.memory).await?;
            file.write_all(chunk).await?;
            self.memory = Vec::new();
            self.spool = Some((guard, file));
        }
        self.len += chunk.len() as u64;
        Ok(())
    }

    /// The whole body, once every chunk was written.
    pub(super) async fn finish(self) -> std::io::Result<CompleteBody> {
        match self.spool {
            Some((guard, mut file)) => {
                // Hands the last buffered bytes to the file and waits for them
                // to be written, so the reader that stores the body sees them.
                file.flush().await?;
                Ok(CompleteBody::Spool(guard, self.len))
            }
            None => Ok(CompleteBody::Memory(Bytes::from(self.memory))),
        }
    }
}

/// A captured body, complete. A spooled one is deleted when this is dropped.
pub(super) enum CompleteBody {
    Memory(Bytes),
    Spool(SpoolGuard, u64),
}

impl CompleteBody {
    pub(super) fn len(&self) -> u64 {
        match self {
            Self::Memory(bytes) => bytes.len() as u64,
            Self::Spool(_, len) => *len,
        }
    }

    /// The body as the transport sends it upstream.
    pub(super) fn outbound(&self) -> OutboundBody {
        match self {
            Self::Memory(bytes) if bytes.is_empty() => OutboundBody::Empty,
            Self::Memory(bytes) => OutboundBody::Bytes(bytes.clone()),
            Self::Spool(guard, len) => OutboundBody::Spool {
                path: guard.path().to_path_buf(),
                len: *len,
            },
        }
    }

    /// The body as storage reads it. A spool must outlive that read.
    pub(super) fn stored(&self) -> CapturedBody {
        match self {
            Self::Memory(bytes) => CapturedBody::Memory(bytes.clone()),
            Self::Spool(guard, _) => CapturedBody::Spool(guard.path().to_path_buf()),
        }
    }

    pub(super) async fn read(&self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Memory(bytes) => Ok(bytes.to_vec()),
            Self::Spool(guard, _) => tokio::fs::read(guard.path()).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spools_in(directory: &Path) -> usize {
        std::fs::read_dir(directory).unwrap().count()
    }

    #[tokio::test]
    async fn a_small_body_never_touches_the_spool_directory() {
        let directory = tempfile::tempdir().unwrap();
        let mut capture = BodyCapture::new(directory.path(), "response");
        capture.write(b"hello ").await.unwrap();
        capture.write(b"world").await.unwrap();
        assert_eq!(capture.len(), 11);
        let body = capture.finish().await.unwrap();
        assert!(matches!(&body, CompleteBody::Memory(bytes) if &bytes[..] == b"hello world"));
        assert_eq!(body.len(), 11);
        assert!(
            matches!(body.outbound(), OutboundBody::Bytes(bytes) if &bytes[..] == b"hello world")
        );
        assert!(matches!(body.stored(), CapturedBody::Memory(_)));
        assert_eq!(body.read().await.unwrap(), b"hello world");
        assert_eq!(spools_in(directory.path()), 0);
    }

    #[tokio::test]
    async fn an_empty_body_is_sent_as_no_body() {
        let directory = tempfile::tempdir().unwrap();
        let body = BodyCapture::new(directory.path(), "request")
            .finish()
            .await
            .unwrap();
        assert_eq!(body.len(), 0);
        assert!(matches!(body.outbound(), OutboundBody::Empty));
    }

    #[tokio::test]
    async fn a_body_past_the_memory_limit_moves_to_a_spool_and_reads_back_exactly() {
        let directory = tempfile::tempdir().unwrap();
        let mut capture = BodyCapture::new(directory.path(), "response");
        let mut expected = Vec::new();
        // Chunks that straddle the limit, then more than one write buffer.
        for index in 0..40u32 {
            let chunk = vec![(index % 251) as u8; 30_000 + index as usize];
            capture.write(&chunk).await.unwrap();
            expected.extend_from_slice(&chunk);
        }
        assert!(expected.len() > MEMORY_BODY_BYTES + SPOOL_WRITE_BYTES);
        assert_eq!(capture.len(), expected.len() as u64);
        let body = capture.finish().await.unwrap();
        let CompleteBody::Spool(guard, len) = &body else {
            panic!("a large body stays in memory");
        };
        assert_eq!(*len, expected.len() as u64);
        assert_eq!(std::fs::read(guard.path()).unwrap(), expected);
        assert_eq!(body.read().await.unwrap(), expected);
        assert!(
            matches!(body.outbound(), OutboundBody::Spool { len, .. } if len == expected.len() as u64)
        );
        assert_eq!(spools_in(directory.path()), 1);
        drop(body);
        assert_eq!(spools_in(directory.path()), 0);
    }

    #[tokio::test]
    async fn a_body_exactly_at_the_memory_limit_stays_in_memory() {
        let directory = tempfile::tempdir().unwrap();
        let mut capture = BodyCapture::new(directory.path(), "response");
        capture.write(&vec![7u8; MEMORY_BODY_BYTES]).await.unwrap();
        assert!(matches!(
            capture.finish().await.unwrap(),
            CompleteBody::Memory(bytes) if bytes.len() == MEMORY_BODY_BYTES
        ));
        assert_eq!(spools_in(directory.path()), 0);
    }
}
