use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};

/// Runtime configuration, loaded from defaults -> `Config.toml` -> `INFINITY_*` -> `STREAM_*` env.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub bind: String,
    pub public_url: String,
    pub database_url: String,
    pub data_dir: String,
    pub session_ttl_secs: i64,
    pub global_rate_limit_per_min: u32,
    pub max_json_body_bytes: usize,
    pub max_batch_records: usize,
    pub max_search_docs_per_batch: usize,
    pub admin_email: String,
    pub admin_password: String,
    pub cors_origins: Vec<String>,
    pub segment_max_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8092".into(),
            public_url: "http://localhost:8092".into(),
            database_url: "sqlite://data/stream.db".into(),
            data_dir: "data".into(),
            session_ttl_secs: 60 * 60 * 2,
            global_rate_limit_per_min: 600,
            max_json_body_bytes: 1024 * 1024,
            max_batch_records: 1_000,
            max_search_docs_per_batch: 1_000,
            admin_email: "admin@infinity.local".into(),
            admin_password: "ChangeMe_Infinity#2025".into(),
            cors_origins: vec![
                "http://localhost:8092".into(),
                "http://127.0.0.1:8092".into(),
            ],
            segment_max_bytes: 1 << 20,
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        Ok(Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file("Config.toml"))
            .merge(Env::prefixed("INFINITY_").split("__"))
            .merge(Env::prefixed("STREAM_").split("__"))
            .extract()?)
    }
}
