use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};

/// Runtime configuration, loaded from defaults -> `Config.toml` -> `INFINITY_*` env.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Socket address to bind, e.g. `0.0.0.0:8080`.
    pub bind: String,
    /// Public issuer URL used in tokens and discovery, e.g. `http://localhost:8080`.
    pub issuer: String,
    /// SQLite/Postgres connection string.
    pub database_url: String,
    /// Directory for persisted signing keys and data.
    pub data_dir: String,
    /// Access-token lifetime in seconds.
    pub access_token_ttl_secs: i64,
    /// Refresh-token lifetime in seconds.
    pub refresh_token_ttl_secs: i64,
    /// Authorization-code lifetime in seconds.
    pub code_ttl_secs: i64,
    /// Dashboard session lifetime in seconds.
    pub session_ttl_secs: i64,
    /// Global per-IP request cap per 60s window (0 = unlimited).
    pub global_rate_limit_per_min: u32,
    /// Display name shown in authenticator apps (must not contain a colon).
    pub mfa_issuer: String,
    /// Seed admin email (created on first run if no users exist).
    pub admin_email: String,
    /// Seed admin password (change immediately in production).
    pub admin_password: String,
    /// Allowed CORS origins for the dashboard / SPA clients.
    pub cors_origins: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".into(),
            issuer: "http://localhost:8080".into(),
            database_url: "sqlite://data/infinity.db".into(),
            data_dir: "data".into(),
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 60 * 60 * 24 * 30,
            code_ttl_secs: 300,
            session_ttl_secs: 60 * 60 * 8,
            global_rate_limit_per_min: 600,
            mfa_issuer: "Infinity ID".into(),
            admin_email: "admin@infinity.local".into(),
            admin_password: "ChangeMe_Infinity#2025".into(),
            cors_origins: vec!["http://localhost:8080".into()],
        }
    }
}

impl Config {
    /// Load configuration, layering optional `Config.toml` and `INFINITY_` env vars.
    pub fn load() -> anyhow::Result<Self> {
        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file("Config.toml"))
            .merge(Env::prefixed("INFINITY_").split("__"))
            .extract()?;
        Ok(cfg)
    }
}
