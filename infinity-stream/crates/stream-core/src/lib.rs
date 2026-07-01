//! stream-core — durable streaming and search primitives for Infinity Stream.

pub mod bm25;
pub mod commit_log;
pub mod error;
pub mod model;
pub mod password;
pub mod rbac;
pub mod security;

pub use error::{CoreError, Result};
