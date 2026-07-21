//! Infinity Observe — production-grade observability in a single Rust binary.
//!
//! Exposed as a library (in addition to the `infinity-observe` binary) so the
//! HTTP surface can be exercised directly from integration tests in `tests/`.

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
