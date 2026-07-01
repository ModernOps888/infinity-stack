//! infinity-core — security primitives and domain model for Infinity ID.
//!
//! Everything security-critical lives here: password hashing (Argon2id),
//! asymmetric JWT signing (RS256 + JWKS), TOTP MFA, and the RBAC model.

pub mod error;
pub mod password;
pub mod keys;
pub mod token;
pub mod mfa;
pub mod rbac;
pub mod model;

pub use error::CoreError;
