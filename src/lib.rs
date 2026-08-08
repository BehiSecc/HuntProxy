//! HuntProxy — local-first agent-safe HTTP workbench for authorized testing.
//!
//! Display name is centralized so renaming stays cheap.

#![recursion_limit = "256"]

pub const DISPLAY_NAME: &str = "HuntProxy";
pub const INTERNAL_PROTOCOL_VERSION: u32 = 1;
pub const API_VERSION: &str = "v1";

pub mod api;
pub mod app;
pub mod browser;
pub mod codec;
pub mod compare;
pub mod config;
pub mod cookies;
pub mod copy_as;
pub mod crawler;
pub mod domain;
pub mod fuzzer;
pub mod get_words;
pub mod har;
pub mod history;
pub mod mcp;
pub mod page_analyzer;
pub mod page_title;
pub mod plugins;
pub mod policy;
pub mod proxy;
pub mod reply;
pub mod request_rules;
pub mod storage;
pub mod transfer;
pub mod transport;
pub mod websocket;
