use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};

/// Runtime configuration, loaded from defaults -> `Config.toml` -> `OBSERVE_*` env.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Socket address to bind, e.g. `0.0.0.0:8090`.
    pub bind: String,
    /// Public URL used to decide whether dashboard cookies may omit `Secure` for local development.
    pub public_url: String,
    pub database_url: String,
    pub data_dir: String,
    pub session_ttl_secs: i64,
    /// Global per-IP request cap per 60s window (0 = unlimited).
    pub global_rate_limit_per_min: u32,
    /// Maximum accepted request body size in bytes.
    pub max_request_body_bytes: usize,
    pub admin_email: String,
    pub admin_password: String,
    pub cors_origins: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8090".into(),
            public_url: "http://localhost:8090".into(),
            database_url: "sqlite://data/observe.db".into(),
            data_dir: "data".into(),
            session_ttl_secs: 60 * 60 * 2,
            global_rate_limit_per_min: 600,
            max_request_body_bytes: 1024 * 1024,
            admin_email: "admin@infinity.local".into(),
            admin_password: "ChangeMe_InfinityObserve#2026".into(),
            cors_origins: vec![
                "http://localhost:8090".into(),
                "http://127.0.0.1:8090".into(),
            ],
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        Ok(Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file("Config.toml"))
            .merge(Env::prefixed("OBSERVE_").split("__"))
            .extract()?)
    }
}
