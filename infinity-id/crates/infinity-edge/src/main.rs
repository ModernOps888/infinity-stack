//! Infinity Edge — an auth-aware reverse proxy / API gateway.
//!
//! Validates Infinity ID access tokens (via JWKS), enforces per-route scopes,
//! applies per-IP rate limiting, then forwards to configured upstreams.

mod config;
mod jwks;
mod ratelimit;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::{EdgeConfig, RouteConfig};
use crate::jwks::JwksCache;
use crate::ratelimit::RateLimiter;

struct EdgeState {
    config: EdgeConfig,
    jwks: JwksCache,
    limiter: RateLimiter,
    http: reqwest::Client,
}

type Shared = Arc<EdgeState>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = EdgeConfig::load().context("loading edge config")?;
    tracing::info!(jwks = %config.jwks_url, "fetching signing keys");
    let jwks = JwksCache::fetch(&config.jwks_url, &config.issuer)
        .await
        .context("fetching JWKS — is Infinity ID running?")?;

    let limiter = RateLimiter::new(config.rate_limit_per_min);
    let bind = config.bind.clone();
    let state = Arc::new(EdgeState {
        config,
        jwks,
        limiter,
        http: reqwest::Client::new(),
    });

    let app = Router::new().fallback(proxy).with_state(state);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, "Infinity Edge listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn match_route<'a>(cfg: &'a EdgeConfig, path: &str) -> Option<&'a RouteConfig> {
    cfg.routes
        .iter()
        .filter(|r| path.starts_with(&r.prefix))
        .max_by_key(|r| r.prefix.len())
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
}

async fn proxy(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let ip = addr.ip().to_string();
    if !st.limiter.allow(&ip) {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }

    let path = req.uri().path().to_string();
    let route = match match_route(&st.config, &path) {
        Some(r) => r.clone(),
        None => return err(StatusCode::NOT_FOUND, "no route configured for this path"),
    };

    // Authentication / authorization.
    let mut subject: Option<String> = None;
    if route.require_auth {
        let token = bearer(req.headers());
        let claims = match token.and_then(|t| st.jwks.validate(&t, route.audience.as_deref())) {
            Some(c) => c,
            None => return err(StatusCode::UNAUTHORIZED, "missing or invalid access token"),
        };
        // Scopes and roles are checked against separate requirements so a
        // user's roles can never satisfy a scope-gated route.
        if let Some(required) = &route.required_scope {
            if !claims.scope.split_whitespace().any(|s| s == required) {
                return err(StatusCode::FORBIDDEN, "token lacks required scope");
            }
        }
        if let Some(required) = &route.required_role {
            if !claims.roles.iter().any(|r| r == required) {
                return err(StatusCode::FORBIDDEN, "token lacks required role");
            }
        }
        subject = Some(claims.sub);
    }

    match forward(&st, &route, req, subject).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(error = %e, "upstream error");
            err(StatusCode::BAD_GATEWAY, "upstream request failed")
        }
    }
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}

async fn forward(
    st: &Shared,
    route: &RouteConfig,
    req: Request,
    subject: Option<String>,
) -> anyhow::Result<Response> {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let mut headers = req.headers().clone();
    headers.remove(header::HOST);
    // Prevent identity spoofing: never trust a client-supplied identity header.
    headers.remove("x-infinity-sub");
    if let Some(sub) = subject {
        if let Ok(v) = axum::http::HeaderValue::from_str(&sub) {
            headers.insert("x-infinity-sub", v);
        }
    }

    let body_bytes = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await?;
    let url = format!("{}{}", route.upstream.trim_end_matches('/'), path_and_query);

    let mut builder = st.http.request(method, &url).headers(headers);
    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes);
    }
    let upstream = builder.send().await?;

    let status = upstream.status();
    let mut resp_headers = upstream.headers().clone();
    resp_headers.remove(header::TRANSFER_ENCODING);
    resp_headers.remove(header::CONTENT_LENGTH);
    let bytes = upstream.bytes().await?;

    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    Ok(response)
}
