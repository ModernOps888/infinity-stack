//! Infinity Observe ? production-grade observability in a single Rust binary.

mod assets;
mod auth;
mod config;
mod error;
mod routes;
mod state;
mod store;
mod util;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use axum::http::{header, HeaderName, HeaderValue, Method};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::Config;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::load().context("loading configuration")?;
    std::fs::create_dir_all(&config.data_dir).ok();

    let opts = SqliteConnectOptions::from_str(&config.database_url)
        .context("parsing database_url")?
        .create_if_missing(true);
    let db = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(opts)
        .await
        .context("connecting to database")?;
    sqlx::migrate!("./migrations").run(&db).await.context("running migrations")?;

    store::seed(&db, &config).await.context("seeding database")?;

    let bind = config.bind.clone();
    let cors = build_cors(&config);
    let state = Arc::new(AppState { db, config });

    let app = routes::router(state)
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
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, "Infinity Observe listening ? dashboard at the bind address");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
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
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true)
}
