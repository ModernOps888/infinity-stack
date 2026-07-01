use serde::{Deserialize, Serialize};

/// Edge gateway configuration, loaded from `Edge.toml` + `EDGE_*` env vars.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeConfig {
    /// Address to bind, e.g. `0.0.0.0:9000`.
    pub bind: String,
    /// Issuer expected in JWTs (must match Infinity ID's issuer).
    pub issuer: String,
    /// URL of Infinity ID's JWKS document.
    pub jwks_url: String,
    /// Max requests per client IP per 60s window (0 = unlimited).
    #[serde(default)]
    pub rate_limit_per_min: u32,
    /// Reverse-proxy routes, matched by longest path prefix.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Path prefix to match, e.g. `/api`.
    pub prefix: String,
    /// Upstream base URL, e.g. `http://127.0.0.1:8081`.
    pub upstream: String,
    /// Require a valid Infinity ID access token.
    #[serde(default)]
    pub require_auth: bool,
    /// Optional scope/permission the token must carry (e.g. `orders:read`).
    #[serde(default)]
    pub required_scope: Option<String>,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:9000".into(),
            issuer: "http://localhost:8080".into(),
            jwks_url: "http://localhost:8080/.well-known/jwks.json".into(),
            rate_limit_per_min: 600,
            routes: vec![],
        }
    }
}

impl EdgeConfig {
    pub fn load() -> anyhow::Result<Self> {
        use figment::providers::{Env, Format, Serialized, Toml};
        use figment::Figment;
        let cfg = Figment::from(Serialized::defaults(EdgeConfig::default()))
            .merge(Toml::file("Edge.toml"))
            .merge(Env::prefixed("EDGE_").split("__"))
            .extract()?;
        Ok(cfg)
    }
}
