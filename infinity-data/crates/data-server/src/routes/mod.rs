pub mod admin;
pub mod audit;
pub mod auth_routes;
pub mod collections;
pub mod tables;

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde_json::json;

use crate::error::ApiError;
use crate::state::SharedState;

async fn rate_limit(
    State(st): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    if !st.ip_limiter.allow(&addr.ip().to_string()) {
        return ApiError::TooManyRequests("global rate limit exceeded".into()).into_response();
    }
    next.run(req).await
}

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/logout", post(auth_routes::logout))
        .route("/auth/me", get(auth_routes::me))
        .route("/api/stats", get(collections::stats))
        .route(
            "/api/collections",
            get(collections::list).post(collections::create),
        )
        .route(
            "/api/collections/:name",
            get(collections::get_one).delete(collections::delete_one),
        )
        .route(
            "/api/collections/:name/vectors",
            post(collections::upsert_vectors),
        )
        .route("/api/collections/:name/search", post(collections::search))
        .route("/api/tables", get(tables::list).post(tables::create))
        .route(
            "/api/tables/:name",
            get(tables::get_one).delete(tables::delete_one),
        )
        .route("/api/tables/:name/rows", post(tables::insert_rows))
        .route("/api/tables/:name/query", post(tables::query))
        .route(
            "/admin/users",
            get(admin::list_users).post(admin::create_user),
        )
        .route(
            "/admin/users/:id",
            patch(admin::update_user).delete(admin::delete_user),
        )
        .route(
            "/admin/roles",
            get(admin::list_roles).put(admin::upsert_role),
        )
        .route(
            "/admin/api-keys",
            get(admin::list_api_keys).post(admin::create_api_key),
        )
        .route("/admin/api-keys/:id", delete(admin::delete_api_key))
        .route("/admin/audit", get(audit::list))
        .fallback(crate::assets::handler)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "service": "infinity-data" }))
}

pub fn valid_name(name: &str) -> bool {
    let len = name.len();
    (1..=64).contains(&len)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
