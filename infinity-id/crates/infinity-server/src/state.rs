use std::sync::{Arc, RwLock};

use infinity_core::keys::KeyRing;
use sqlx::SqlitePool;

use crate::config::Config;
use crate::ratelimit::IpRateLimiter;
use crate::throttle::LoginThrottle;

/// Shared, cheaply-clonable application state passed to every handler.
pub struct AppState {
    pub db: SqlitePool,
    /// The signing key ring, behind a lock so it can be rotated at runtime
    /// without invalidating tokens signed under a just-retired key.
    pub key: RwLock<KeyRing>,
    pub key_path: std::path::PathBuf,
    pub config: Config,
    pub login_throttle: LoginThrottle,
    pub ip_limiter: IpRateLimiter,
}

impl AppState {
    /// How long a retired key must keep validating: the longest-lived token
    /// type this server issues, so no live token can outlive its signing key.
    pub fn key_retention_secs(&self) -> i64 {
        self.config.refresh_token_ttl_secs.max(self.config.access_token_ttl_secs)
    }
}

pub type SharedState = Arc<AppState>;
