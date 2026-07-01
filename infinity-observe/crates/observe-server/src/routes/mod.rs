pub mod alerts;
pub mod auth_routes;
pub mod ingest;
pub mod keys;
pub mod query;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::state::SharedState;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/logout", post(auth_routes::logout))
        .route("/auth/me", get(auth_routes::me))
        .route("/v1/logs", post(ingest::logs).get(query::logs))
        .route("/v1/metrics", post(ingest::metrics))
        .route("/v1/metrics/names", get(query::metric_names))
        .route("/v1/metrics/series", get(query::metric_series))
        .route("/v1/metrics/summary", get(query::metric_summary))
        .route("/v1/traces", post(ingest::traces).get(query::traces))
        .route("/v1/traces/:trace_id", get(query::trace_by_id))
        .route("/v1/alerts/rules", get(alerts::rules).post(alerts::create_rule))
        .route("/v1/alerts/rules/:id", delete(alerts::delete_rule))
        .route("/v1/alerts", get(alerts::list_alerts))
        .route("/v1/keys", get(keys::list).post(keys::create))
        .route("/v1/keys/:id", delete(keys::revoke))
        .route("/v1/stats", get(query::stats))
        .fallback(crate::assets::handler)
        .with_state(state)
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "status": "ok", "service": "infinity-observe" }))
}
