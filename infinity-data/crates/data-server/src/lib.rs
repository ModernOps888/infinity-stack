//! Infinity Data — single-node Rust-native analytics + vector database.
//!
//! Exposed as a library (in addition to the `infinity-data` binary) so that
//! integration tests can drive the real axum `Router` end-to-end (see
//! `tests/security.rs`) instead of re-implementing or mocking route logic.

pub mod assets;
pub mod auth;
pub mod config;
pub mod error;
pub mod ratelimit;
pub mod routes;
pub mod state;
pub mod store;
pub mod throttle;
pub mod util;
