use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use data_core::hnsw::HnswIndex;
use sqlx::SqlitePool;
use tokio::sync::RwLock;

use crate::config::Config;

pub struct AppState {
    pub db: SqlitePool,
    pub config: Config,
    pub indexes: RwLock<HashMap<String, HnswIndex>>,
    pub collections_dir: PathBuf,
}

pub type SharedState = Arc<AppState>;
