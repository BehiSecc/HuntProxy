//! bb — local-first agent-safe HTTP workbench for authorized testing.
//!
//! Display name is centralized so renaming stays cheap.

pub const DISPLAY_NAME: &str = "bb";
pub const INTERNAL_PROTOCOL_VERSION: u32 = 1;
pub const API_VERSION: &str = "v1";

pub mod app;
pub mod browser;
pub mod codec;
pub mod config;
pub mod domain;
pub mod fuzzer;
pub mod history;
pub mod policy;
pub mod proxy;
pub mod reply;
pub mod storage;
pub mod transport;
pub mod api;
pub mod mcp;
