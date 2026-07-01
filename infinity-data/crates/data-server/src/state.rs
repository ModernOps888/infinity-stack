use std::collections::HashMap;
use std::sync::Arc;

use data_core::hnsw::HnswIndex;
use sqlx::SqlitePool;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::ratelimit::IpRateLimiter;
use crate::throttle::LoginThrottle;

pub struct AppState {
    pub db: SqlitePool,
    pub config: Config,
    pub indexes: RwLock<HashMap<String, HnswIndex>>,
    pub login_throttle: LoginThrottle,
    pub ip_limiter: IpRateLimiter,
}

pub type SharedState = Arc<AppState>;
