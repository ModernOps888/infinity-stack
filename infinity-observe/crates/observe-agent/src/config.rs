use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server_url: String,
    pub ingest_key: String,
    pub service: String,
    pub file: Option<String>,
    pub interval_secs: u64,
    pub once: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:9100".into(),
            ingest_key: "".into(),
            service: "sample-service".into(),
            file: None,
            interval_secs: 5,
            once: false,
        }
    }
}

impl AgentConfig {
    pub fn load() -> anyhow::Result<Self> {
        let mut cfg: AgentConfig = Figment::from(Serialized::defaults(AgentConfig::default()))
            .merge(Toml::file("Agent.toml"))
            .merge(Env::prefixed("INFINITY_AGENT_").split("__"))
            .extract()?;
        let args: Vec<String> = std::env::args().collect();
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--server" => {
                    i += 1;
                    if i < args.len() {
                        cfg.server_url = args[i].clone();
                    }
                }
                "--key" => {
                    i += 1;
                    if i < args.len() {
                        cfg.ingest_key = args[i].clone();
                    }
                }
                "--service" => {
                    i += 1;
                    if i < args.len() {
                        cfg.service = args[i].clone();
                    }
                }
                "--file" => {
                    i += 1;
                    if i < args.len() {
                        cfg.file = Some(args[i].clone());
                    }
                }
                "--interval" => {
                    i += 1;
                    if i < args.len() {
                        cfg.interval_secs = args[i].parse().unwrap_or(cfg.interval_secs);
                    }
                }
                "--once" => cfg.once = true,
                "--help" | "-h" => {
                    println!("infinity-observe-agent --key <ingest-key> [--server http://127.0.0.1:9100] [--service name] [--file path] [--once]");
                    std::process::exit(0);
                }
                _ => {}
            }
            i += 1;
        }
        Ok(cfg)
    }
}
