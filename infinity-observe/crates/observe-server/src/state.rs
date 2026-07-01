use std::sync::Arc;

use sqlx::SqlitePool;

use crate::config::Config;
use crate::ratelimit::IpRateLimiter;
use crate::throttle::LoginThrottle;

pub struct AppState {
    pub db: SqlitePool,
    pub config: Config,
    pub login_throttle: LoginThrottle,
    pub ip_limiter: IpRateLimiter,
}

pub type SharedState = Arc<AppState>;
