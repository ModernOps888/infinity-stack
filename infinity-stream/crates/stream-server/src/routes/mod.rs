pub mod auth_routes;
pub mod keys;
pub mod search;
pub mod stats;
pub mod topics;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::state::SharedState;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/logout", post(auth_routes::logout))
        .route("/auth/me", get(auth_routes::me))
        .route("/v1/topics", get(topics::list).post(topics::create))
        .route("/v1/topics/:name", delete(topics::delete_topic))
        .route("/v1/topics/:name/produce", post(topics::produce))
        .route("/v1/topics/:name/consume", get(topics::consume))
        .route("/v1/topics/:name/commit", post(topics::commit))
        .route("/v1/topics/:name/offset", get(topics::offset))
        .route("/v1/topics/:name/subscribe", get(topics::subscribe))
        .route("/v1/consumers", get(topics::consumers))
        .route("/v1/indexes", get(search::list).post(search::create))
        .route("/v1/indexes/:name", delete(search::delete_index))
        .route("/v1/indexes/:name/docs", post(search::upsert_docs))
        .route("/v1/indexes/:name/search", get(search::query))
        .route("/v1/keys", get(keys::list).post(keys::create))
        .route("/v1/keys/:id", delete(keys::delete_key))
        .route("/v1/stats", get(stats::stats))
        .fallback(crate::assets::handler)
        .with_state(state)
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"status":"ok","service":"infinity-stream"}))
}
