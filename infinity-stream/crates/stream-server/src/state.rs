use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use sqlx::SqlitePool;
use stream_core::bm25::Bm25Index;
use stream_core::commit_log::CommitLog;
use stream_core::model::LogRecord;
use tokio::sync::{broadcast, Mutex, RwLock};

use crate::config::Config;
use crate::ratelimit::IpRateLimiter;
use crate::throttle::LoginThrottle;

pub struct AppState {
    pub db: SqlitePool,
    pub config: Config,
    pub log: Mutex<CommitLog>,
    pub indexes: RwLock<HashMap<String, Bm25Index>>,
    pub broadcasts: RwLock<HashMap<String, broadcast::Sender<LogRecord>>>,
    pub produced_times: Mutex<VecDeque<Instant>>,
    pub login_throttle: LoginThrottle,
    pub ip_limiter: IpRateLimiter,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub async fn topic_sender(&self, topic: &str) -> broadcast::Sender<LogRecord> {
        let mut map = self.broadcasts.write().await;
        map.entry(topic.to_string())
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(1024);
                tx
            })
            .clone()
    }
}
