//! Infinity Data — single-node Rust-native analytics + vector database.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use axum::http::{header, HeaderName, HeaderValue, Method};
use data_core::hnsw::HnswIndex;
use data_server::config::Config;
use data_server::ratelimit::IpRateLimiter;
use data_server::state::AppState;
use data_server::throttle::LoginThrottle;
use data_server::{routes, store};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::load().context("loading configuration")?;
    std::fs::create_dir_all(&config.data_dir).context("creating data directory")?;
    let collections_dir = std::path::Path::new(&config.data_dir).join("collections");
    std::fs::create_dir_all(&collections_dir).context("creating collections directory")?;
    tracing::debug!(path = %collections_dir.display(), "collection data directory ready");

    let opts = SqliteConnectOptions::from_str(&config.database_url)
        .context("parsing database_url")?
        .create_if_missing(true)
        .foreign_keys(true);
    let db = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(opts)
        .await
        .context("connecting to database")?;
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .context("running migrations")?;
    store::seed(&db, &config)
        .await
        .context("seeding database")?;

    let indexes = rebuild_indexes(&db)
        .await
        .context("rebuilding vector indexes")?;
    tracing::info!(collections = indexes.len(), "loaded vector indexes");

    let bind = config.bind.clone();
    let cors = build_cors(&config);
    let global_limit = config.global_rate_limit_per_min;
    let state = Arc::new(AppState {
        db,
        config,
        indexes: tokio::sync::RwLock::new(indexes),
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(global_limit),
    });
    tracing::info!(
        limit_per_min = global_limit,
        "global rate limiter configured"
    );

    let app = routes::router(state.clone())
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::overriding(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")))
        .layer(SetResponseHeaderLayer::overriding(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")))
        .layer(SetResponseHeaderLayer::overriding(HeaderName::from_static("permissions-policy"), HeaderValue::from_static("geolocation=(), microphone=(), camera=()")))
        .layer(SetResponseHeaderLayer::overriding(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=63072000; includeSubDomains")))
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, dashboard = %state.config.public_url, "Infinity Data listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server error")?;
    Ok(())
}

async fn rebuild_indexes(db: &sqlx::SqlitePool) -> anyhow::Result<HashMap<String, HnswIndex>> {
    let mut indexes = HashMap::new();
    for c in store::list_collections(db).await? {
        let mut index = HnswIndex::new(c.dim, c.metric, 16, 128)?;
        for point in store::load_points(db, &c.name).await? {
            index.insert(point)?;
        }
        indexes.insert(c.name, index);
    }
    Ok(indexes)
}

fn build_cors(config: &Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = config
        .cors_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::PUT,
            Method::DELETE,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true)
}
