use std::sync::Arc;

use sqlx::SqlitePool;

use crate::config::Config;

pub struct AppState {
    pub db: SqlitePool,
    pub config: Config,
}

pub type SharedState = Arc<AppState>;
