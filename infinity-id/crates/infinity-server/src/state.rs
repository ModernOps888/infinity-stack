use std::sync::Arc;

use infinity_core::keys::SigningKey;
use sqlx::SqlitePool;

use crate::config::Config;
use crate::ratelimit::IpRateLimiter;
use crate::throttle::LoginThrottle;

/// Shared, cheaply-clonable application state passed to every handler.
pub struct AppState {
    pub db: SqlitePool,
    pub key: SigningKey,
    pub config: Config,
    pub login_throttle: LoginThrottle,
    pub ip_limiter: IpRateLimiter,
}

pub type SharedState = Arc<AppState>;
