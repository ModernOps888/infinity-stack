//! data-core — algorithms and security primitives for Infinity Data.
//!
//! Contains a pure-Rust HNSW approximate nearest-neighbor index, a small JSON
//! aggregation engine, domain models, Argon2id password hashing, and RBAC helpers.

pub mod aggregation;
pub mod error;
pub mod hnsw;
pub mod model;
pub mod password;
pub mod rbac;
pub mod security;

pub use error::{CoreError, Result};
