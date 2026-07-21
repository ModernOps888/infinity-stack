//! Infinity ID — secure-by-design identity provider (OIDC/OAuth2 + MFA + RBAC).
//!
//! Exposed as a library (in addition to the `infinity-id` binary in
//! `main.rs`) so integration tests in `tests/` can drive the real axum
//! `Router` and `AppState` in-process via `tower::ServiceExt::oneshot`
//! instead of a mocked stand-in.

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
