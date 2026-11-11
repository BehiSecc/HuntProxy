//! Small in-memory cache of prepared (redacted/decoded) exchange bodies.
//!
//! Paging a large body through the API or MCP asks for the same body many
//! times. Without a cache every page reloads, decompresses, decodes and hashes
//! the whole body, which makes paging quadratic.

use super::AppState;
use crate::domain::*;
use crate::policy::PresentationOptions;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Total bytes held across all cached bodies.
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
/// Bodies above this size are served uncached so one body cannot flush the rest.
const MAX_ENTRY_BYTES: usize = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 16;
/// Bounds how long a body that changes after the first read can stay stale.
const TTL: Duration = Duration::from_secs(60);

/// A body after header redaction and `Content-Encoding` decoding.
#[derive(Debug)]
pub struct PreparedBody {
    pub data: Vec<u8>,
    /// Stored size before any decoding.
    pub raw_total: usize,
    pub content_encoding: Option<String>,
    pub decoded: bool,
    pub sha256: String,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    project_id: ProjectId,
    exchange_id: ExchangeId,
    request_side: bool,
    raw: bool,
}

struct Entry {
    body: Arc<PreparedBody>,
    stored_at: Instant,
    last_used: u64,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<Key, Entry>,
    bytes: usize,
    clock: u64,
}

#[derive(Default)]
pub struct BodyCache {
    inner: Mutex<Inner>,
}

impl BodyCache {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panicked holder can only have left `bytes` out of step with the
        // entries, so recompute it.
        self.inner.lock().unwrap_or_else(|poisoned| {
            let mut inner = poisoned.into_inner();
            inner.bytes = inner.entries.values().map(|e| e.body.data.len()).sum();
            inner
        })
    }

    fn get(&self, key: &Key) -> Option<Arc<PreparedBody>> {
        let mut inner = self.lock();
        inner.clock += 1;
        let clock = inner.clock;
        let expired = inner
            .entries
            .get(key)
            .is_some_and(|entry| entry.stored_at.elapsed() > TTL);
        if expired {
            if let Some(entry) = inner.entries.remove(key) {
                inner.bytes -= entry.body.data.len();
            }
            return None;
        }
        let entry = inner.entries.get_mut(key)?;
        entry.last_used = clock;
        Some(entry.body.clone())
    }

    fn insert(&self, key: Key, body: Arc<PreparedBody>) {
        let size = body.data.len();
        if size > MAX_ENTRY_BYTES {
            return;
        }
        let mut inner = self.lock();
        if let Some(old) = inner.entries.remove(&key) {
            inner.bytes -= old.body.data.len();
        }
        while !inner.entries.is_empty()
            && (inner.bytes + size > MAX_TOTAL_BYTES || inner.entries.len() >= MAX_ENTRIES)
        {
            let Some(oldest) = inner
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(entry) = inner.entries.remove(&oldest) {
                inner.bytes -= entry.body.data.len();
            }
        }
        inner.clock += 1;
        let last_used = inner.clock;
        inner.bytes += size;
        inner.entries.insert(
            key,
            Entry {
                body,
                stored_at: Instant::now(),
                last_used,
            },
        );
    }

    #[cfg(test)]
    fn total_bytes(&self) -> usize {
        self.lock().bytes
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().entries.len()
    }
}

impl AppState {
    /// Loads the presented body of one exchange side, from cache when possible.
    ///
    /// `raw` skips response decoding and raw-response presentation; it has no
    /// effect on the request side. Returns `None` when the side has no body
    /// (never cached, since a response can be stored after the first read).
    pub async fn prepared_body(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        side: MessageSide,
        raw: bool,
    ) -> DomainResult<Option<Arc<PreparedBody>>> {
        let key = Key {
            project_id,
            exchange_id,
            request_side: side == MessageSide::Request,
            raw: raw && side == MessageSide::Response,
        };
        if let Some(body) = self.body_cache.get(&key) {
            return Ok(Some(body));
        }
        let Some(mut data) = self.db.load_raw_body(project_id, exchange_id, side).await? else {
            return Ok(None);
        };
        let raw_total = data.len();
        let mut content_encoding = None;
        let mut decoded = false;
        if side == MessageSide::Request {
            let detail = self
                .db
                .get_exchange_detail(project_id, exchange_id, PresentationOptions::default())
                .await?;
            if detail.protocol == "HTTP/1.1 raw" {
                data = crate::reply::redact_raw_request_headers(&data);
            }
        } else if !raw {
            let detail = self
                .db
                .get_exchange_detail(project_id, exchange_id, PresentationOptions::default())
                .await?;
            if detail.protocol == "HTTP/1.1 raw" {
                data = crate::reply::presented_raw_response_body(&data);
            }
            let headers = self
                .db
                .load_raw_headers(project_id, exchange_id, MessageSide::Response)
                .await?;
            let encodings = headers
                .iter()
                .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
                .map(|header| String::from_utf8_lossy(&header.value).trim().to_string())
                .filter(|encoding| {
                    !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity")
                })
                .collect::<Vec<_>>();
            if !encodings.is_empty() {
                let encoding = encodings.join(", ");
                data = crate::codec::decode_content_encodings(
                    &data,
                    &encoding,
                    crate::codec::MAX_DECODED_BODY_OUTPUT,
                )?;
                content_encoding = Some(encoding);
                decoded = true;
            }
        }
        let body = Arc::new(PreparedBody {
            sha256: crate::storage::sha256_hex(&data),
            data,
            raw_total,
            content_encoding,
            decoded,
        });
        self.body_cache.insert(key, body.clone());
        Ok(Some(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(exchange: i64) -> Key {
        Key {
            project_id: ProjectId(1),
            exchange_id: ExchangeId(exchange),
            request_side: false,
            raw: false,
        }
    }

    fn body(size: usize) -> Arc<PreparedBody> {
        Arc::new(PreparedBody {
            data: vec![0; size],
            raw_total: size,
            content_encoding: None,
            decoded: false,
            sha256: String::new(),
        })
    }

    #[test]
    fn evicts_least_recently_used_to_respect_the_byte_cap() {
        let cache = BodyCache::default();
        let each = MAX_TOTAL_BYTES / 2 - 1;
        cache.insert(key(1), body(each));
        cache.insert(key(2), body(each));
        assert!(cache.get(&key(1)).is_some(), "touch 1 so 2 is the oldest");
        cache.insert(key(3), body(each));
        assert!(cache.get(&key(1)).is_some());
        assert!(cache.get(&key(2)).is_none());
        assert!(cache.get(&key(3)).is_some());
        assert!(cache.total_bytes() <= MAX_TOTAL_BYTES);
    }

    #[test]
    fn oversized_bodies_and_entry_count_are_bounded() {
        let cache = BodyCache::default();
        cache.insert(key(1), body(MAX_ENTRY_BYTES + 1));
        assert_eq!(cache.len(), 0);
        for id in 0..(MAX_ENTRIES as i64 + 5) {
            cache.insert(key(id), body(1));
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
        assert_eq!(cache.total_bytes(), MAX_ENTRIES);
    }
}
