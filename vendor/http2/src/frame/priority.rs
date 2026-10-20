use std::hash::Hash;

use crate::frame::*;
use crate::tracing;
use bytes::BufMut;
use smallvec::SmallVec;

/// The PRIORITY frame (type=0x2) specifies the sender-advised priority
/// of a stream [Section 5.3].  It can be sent in any stream state,
/// including idle or closed streams.
/// [Section 5.3]: <https://tools.ietf.org/html/rfc7540#section-5.3>
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Priority {
    /// The stream ID of the stream that this priority frame is for
    stream_id: StreamId,

    /// The stream dependency target
    dependency: StreamDependency,
}

/// Represents a stream dependency in HTTP/2 priority frames.
///
/// A stream dependency consists of three components:
/// * A stream identifier that the stream depends on
/// * A weight value between 0 and 255 (representing 1-256 in the protocol)
/// * An exclusive flag indicating whether this is an exclusive dependency
///
/// # Stream Dependencies
///
/// In HTTP/2, stream dependencies form a dependency tree where each stream
/// can depend on another stream. This creates a priority hierarchy that helps
/// determine the relative order in which streams should be processed.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct StreamDependency {
    /// The ID of the stream dependency target
    dependency_id: StreamId,

    /// The weight for the stream. The value exposed (and set) here is always in
    /// the range [0, 255], instead of [1, 256] (as defined in section 5.3.2.)
    /// so that the value fits into a `u8`.
    weight: u8,

    /// True if the stream dependency is exclusive.
    is_exclusive: bool,
}

// ===== impl Priority =====

impl Priority {
    /// Create a new [`Priority`].
    pub fn new(stream_id: StreamId, dependency: StreamDependency) -> Self {
        Priority {
            stream_id,
            dependency,
        }
    }

    /// Loads the priority frame but doesn't actually do HPACK decoding.
    pub fn load(head: Head, payload: &[u8]) -> Result<Self, Error> {
        tracing::trace!("loading priority frame; stream_id={:?}", head.stream_id());

        let dependency = StreamDependency::load(payload)?;

        if dependency.dependency_id() == head.stream_id() {
            return Err(Error::InvalidDependencyId);
        }

        Ok(Priority {
            stream_id: head.stream_id(),
            dependency,
        })
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        let head = Head::new(Kind::Priority, 0, self.stream_id);
        head.encode(5, dst);

        // Priority frame payload is exactly 5 bytes
        // Format:
        // +---------------+
        // |E|  Dep ID (31)|
        // +---------------+
        // |   Weight (8)  |
        // +---------------+
        self.dependency.encode(dst);
    }
}

impl<B> From<Priority> for Frame<B> {
    fn from(src: Priority) -> Self {
        Frame::Priority(src)
    }
}

// ===== impl StreamDependency =====

impl StreamDependency {
    /// Create a new [`StreamDependency`]
    pub fn new(dependency_id: StreamId, weight: u8, is_exclusive: bool) -> Self {
        StreamDependency {
            dependency_id,
            weight,
            is_exclusive,
        }
    }

    /// Loads the stream dependency from a buffer
    pub fn load(src: &[u8]) -> Result<Self, Error> {
        tracing::trace!("loading priority stream dependency; src={:?}", src);

        if src.len() != 5 {
            return Err(Error::InvalidPayloadLength);
        }

        // Parse the stream ID and exclusive flag
        let (dependency_id, is_exclusive) = StreamId::parse(&src[..4]);

        // Read the weight
        let weight = src[4];

        Ok(StreamDependency::new(dependency_id, weight, is_exclusive))
    }

    #[inline]
    pub fn dependency_id(&self) -> StreamId {
        self.dependency_id
    }

    pub fn encode<T: BufMut>(&self, dst: &mut T) {
        const STREAM_ID_MASK: u32 = 1 << 31;
        let mut dependency_id = self.dependency_id.into();
        if self.is_exclusive {
            dependency_id |= STREAM_ID_MASK;
        }
        dst.put_u32(dependency_id);
        dst.put_u8(self.weight);
    }
}

const DEFAULT_STACK_SIZE: usize = 8;

/// A collection of HTTP/2 PRIORITY frames.
///
/// The `Priorities` struct maintains an ordered list of `Priority` frames,
/// which can be used to represent and manage the stream dependency tree
/// in HTTP/2. This is useful for pre-configuring stream priorities or
/// sending multiple PRIORITY frames at once during connection setup or
/// stream reprioritization.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Priorities {
    priorities: SmallVec<[Priority; DEFAULT_STACK_SIZE]>,
    max_stream_id: StreamId,
}

/// A builder for constructing a `Priorities` collection.
///
/// `PrioritiesBuilder` provides a convenient way to incrementally add
/// `Priority` frames to a collection, ensuring that invalid priorities
/// (such as those with a stream ID of zero) are ignored. Once all desired
/// priorities have been added, call `.build()` to obtain a `Priorities`
/// instance for use in the HTTP/2 connection or frame layer.
#[derive(Debug)]
pub struct PrioritiesBuilder {
    priorities: SmallVec<[Priority; DEFAULT_STACK_SIZE]>,
    max_stream_id: StreamId,
    inserted_bitmap: u32,
}

// ===== impl Priorities =====

impl Priorities {
    pub fn builder() -> PrioritiesBuilder {
        PrioritiesBuilder {
            priorities: SmallVec::new(),
            max_stream_id: StreamId::zero(),
            inserted_bitmap: 0,
        }
    }

    #[inline]
    pub(crate) fn max_stream_id(&self) -> StreamId {
        self.max_stream_id
    }
}

impl IntoIterator for Priorities {
    type Item = Priority;
    type IntoIter = std::vec::IntoIter<Priority>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.priorities.into_vec().into_iter()
    }
}

// ===== impl PrioritiesBuilder =====

impl PrioritiesBuilder {
    pub fn push(mut self, priority: Priority) -> Self {
        if priority.stream_id.is_zero() {
            tracing::warn!("ignoring priority frame with stream ID 0");
            return self;
        }

        const MAX_BITMAP_STREAMS: u32 = 32;

        let id: u32 = priority.stream_id.into();
        // Check for duplicate priorities based on stream ID.
        // For stream IDs less than MAX_BITMAP_STREAMS, we use a bitmap to track inserted priorities.
        if id < MAX_BITMAP_STREAMS {
            let mask = 1u32 << id;
            if self.inserted_bitmap & mask != 0 {
                tracing::debug!(
                    "duplicate priority for stream_id={:?} ignored",
                    priority.stream_id
                );
                return self;
            }
            self.inserted_bitmap |= mask;
        } else {
            // For stream_id greater than or equal to MAX_BITMAP_STREAMS, duplicate checking is still performed using iterators.
            if self
                .priorities
                .iter()
                .any(|p| p.stream_id == priority.stream_id)
            {
                tracing::debug!(
                    "duplicate priority for stream_id={:?} ignored",
                    priority.stream_id
                );
                return self;
            }
        }

        if priority.stream_id > self.max_stream_id {
            self.max_stream_id = priority.stream_id;
        }

        self.priorities.push(priority);
        self
    }

    pub fn extend(mut self, priorities: impl IntoIterator<Item = Priority>) -> Self {
        for priority in priorities {
            self = self.push(priority);
        }
        self
    }

    pub fn build(self) -> Priorities {
        Priorities {
            priorities: self.priorities,
            max_stream_id: self.max_stream_id,
        }
    }
}

mod tests {

    #[test]
    fn test_priority_frame() {
        use crate::frame::{self, Priority, StreamDependency, StreamId};

        let mut dependency_buf = Vec::new();
        let dependency = StreamDependency::new(StreamId::zero(), 201, false);
        dependency.encode(&mut dependency_buf);
        let dependency = StreamDependency::load(&dependency_buf).unwrap();
        assert_eq!(dependency.dependency_id, StreamId::zero());
        assert_eq!(dependency.weight, 201);
        assert!(!dependency.is_exclusive);

        let priority = Priority::new(StreamId::from(3), dependency);
        let mut priority_buf = Vec::new();
        priority.encode(&mut priority_buf);
        let priority = Priority::load(
            frame::Head::new(frame::Kind::Priority, 0, priority.stream_id),
            &priority_buf[frame::HEADER_LEN..],
        )
        .unwrap();
        assert_eq!(priority.stream_id, StreamId::from(3));
        assert_eq!(priority.dependency.dependency_id, StreamId::zero());
        assert_eq!(priority.dependency.weight, 201);
        assert!(!priority.dependency.is_exclusive);
    }

    #[test]
    fn test_priorities_builder_ignores_stream_id_zero() {
        use crate::frame::{Priorities, Priority, StreamDependency, StreamId};

        let dependency = StreamDependency::new(StreamId::from(1), 50, false);
        let priority_zero = Priority::new(StreamId::zero(), dependency);

        let dependency2 = StreamDependency::new(StreamId::from(2), 100, false);
        let priority_valid = Priority::new(StreamId::from(3), dependency2);

        let priorities = Priorities::builder()
            .extend([priority_zero, priority_valid])
            .build();

        assert_eq!(priorities.priorities.len(), 1);
        assert_eq!(priorities.priorities[0].stream_id, StreamId::from(3));
    }

    #[test]
    fn test_priorities_builder_ignores_duplicate_priorities() {
        use crate::frame::{Priorities, Priority, StreamDependency, StreamId};

        let dependency = StreamDependency::new(StreamId::from(1), 50, false);
        let priority1 = Priority::new(StreamId::from(4), dependency);

        let dependency2 = StreamDependency::new(StreamId::from(2), 100, false);
        let priority2 = Priority::new(StreamId::from(4), dependency2); // Duplicate stream ID

        let priorities = Priorities::builder().extend([priority1, priority2]).build();
        assert_eq!(priorities.priorities.len(), 1);
        assert_eq!(priorities.priorities[0].stream_id, StreamId::from(4));

        // stream id > 31
        let dependency3 = StreamDependency::new(StreamId::from(32), 150, false);
        let priority3 = Priority::new(StreamId::from(32), dependency3);

        let dependency4 = StreamDependency::new(StreamId::from(32), 200, false); // Duplicate stream ID
        let priority4 = Priority::new(StreamId::from(32), dependency4);

        let priorities = Priorities::builder().extend([priority3, priority4]).build();
        assert_eq!(priorities.priorities.len(), 1);
        assert_eq!(priorities.priorities[0].stream_id, StreamId::from(32));
    }
}
