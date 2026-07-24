//! Shared local origin + ValidatedDial helpers for the transport spike.

pub mod origin;
pub mod validated_dial;

pub use origin::{OriginHandles, start_http_origin, start_https_origin};
pub use validated_dial::{FixedIpResolver, ValidatedDial, resolve_call_counter};
