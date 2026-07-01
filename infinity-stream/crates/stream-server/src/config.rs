use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub bind: String,
    pub database_url: String,
    pub data_dir: String,
    pub session_ttl_secs: i64,
    pub admin_email: String,
    pub admin_password: String,
    pub cors_origins: Vec<String>,
    pub segment_max_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:9300".into(),
            database_url: "sqlite://data/stream.db".into(),
            data_dir: "data".into(),
            session_ttl_secs: 60 * 60 * 8,
            admin_email: "admin@infinity.local".into(),
            admin_password: "ChangeMe_Infinity#2025".into(),
            cors_origins: vec!["http://localhost:9300".into(), "http://127.0.0.1:9300".into()],
            segment_max_bytes: 1 << 20,
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        Ok(Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file("Config.toml"))
            .merge(Env::prefixed("INFINITY_").split("__"))
            .extract()?)
    }
}
