use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub bind: String,
    pub public_url: String,
    pub database_url: String,
    pub data_dir: String,
    pub session_ttl_secs: i64,
    pub global_rate_limit_per_min: u32,
    pub admin_email: String,
    pub admin_password: String,
    pub cors_origins: Vec<String>,
    #[serde(default, skip_serializing)]
    pub generated_admin_password: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8094".into(),
            public_url: "http://localhost:8094".into(),
            database_url: "sqlite://data/infinity_data.db".into(),
            data_dir: "data".into(),
            session_ttl_secs: 60 * 60 * 2,
            global_rate_limit_per_min: 600,
            admin_email: "admin@infinity.local".into(),
            admin_password: String::new(),
            cors_origins: vec![
                "http://localhost:8094".into(),
                "http://127.0.0.1:8094".into(),
            ],
            generated_admin_password: false,
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let mut cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file("Config.toml"))
            .merge(Env::prefixed("INFINITY_").split("__"))
            .merge(Env::prefixed("DATA_").split("__"))
            .extract()?;
        if cfg.admin_password.trim().is_empty() {
            cfg.admin_password = strong_password();
            cfg.generated_admin_password = true;
            tracing::warn!(email = %cfg.admin_email, password = %cfg.admin_password, "generated initial Infinity Data admin password; shown once");
        }
        Ok(cfg)
    }

    pub fn secure_cookies(&self) -> bool {
        !(self.public_url.starts_with("http://localhost")
            || self.public_url.starts_with("http://127."))
    }
}

fn strong_password() -> String {
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%*-_=+";
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    let body: String = bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect();
    format!("Idat-{body}")
}
