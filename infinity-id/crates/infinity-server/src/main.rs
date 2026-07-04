//! Infinity ID — secure-by-design identity provider (OIDC/OAuth2 + MFA + RBAC).

mod assets;
mod auth;
mod config;
mod error;
mod ratelimit;
mod routes;
mod state;
mod store;
mod throttle;
mod util;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderName, HeaderValue, Method};
use infinity_core::keys::SigningKey;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::Config;
use crate::state::AppState;
use crate::throttle::LoginThrottle;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::load().context("loading configuration")?;
    std::fs::create_dir_all(&config.data_dir).ok();

    // Database (SQLite by default; create file if missing) + migrations.
    let opts = SqliteConnectOptions::from_str(&config.database_url)
        .context("parsing database_url")?
        .create_if_missing(true);
    let db = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(opts)
        .await
        .context("connecting to database")?;
    sqlx::migrate!("./migrations").run(&db).await.context("running migrations")?;

    // Signing key (persisted so live tokens survive restarts).
    let key_path = std::path::Path::new(&config.data_dir).join("signing_key.pem");
    let key = SigningKey::load_or_generate(&key_path).context("loading signing key")?;
    tracing::info!(kid = %key.kid, "loaded RS256 signing key");

    store::seed(&db, &config).await.context("seeding database")?;

    let bind = config.bind.clone();
    let cors = build_cors(&config);
    let ip_limiter = ratelimit::IpRateLimiter::new(config.global_rate_limit_per_min);
    let state = Arc::new(AppState {
        db,
        key,
        config,
        login_throttle: LoginThrottle::default(),
        ip_limiter,
    });

    let app = routes::router(state)
        // Cap request bodies (forms/JSON) to prevent memory-exhaustion DoS.
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; \
                 base-uri 'self'; form-action 'self'",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, "Infinity ID listening — dashboard at the bind address");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server error")?;
    Ok(())
}

fn build_cors(config: &Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = config
        .cors_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::PUT, Method::DELETE])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION])
        .allow_credentials(true)
}
