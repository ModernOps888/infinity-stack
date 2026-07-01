use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct CreateRule {
    pub name: String,
    pub kind: String,
    pub target: String,
    pub threshold: f64,
    pub window_secs: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AlertParams {
    pub limit: Option<i64>,
}

pub async fn rules(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("alerts:read")?;
    let rules = store::list_alert_rules(&st.db).await?;
    Ok(Json(json!({ "rules": rules })))
}

pub async fn create_rule(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<CreateRule>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("alerts:create")?;
    if !matches!(req.kind.as_str(), "error_log_count" | "metric_p99") {
        return Err(ApiError::BadRequest(
            "kind must be error_log_count or metric_p99".into(),
        ));
    }
    let name = req.name.trim();
    let target = req.target.trim();
    if name.is_empty() || name.len() > 120 || target.len() > 160 || !req.threshold.is_finite() {
        return Err(ApiError::BadRequest(
            "valid name, target and finite threshold are required".into(),
        ));
    }
    let rule = store::create_alert_rule(
        &st.db,
        name,
        &req.kind,
        target,
        req.threshold,
        req.window_secs.unwrap_or(300),
    )
    .await?;
    Ok(Json(json!({ "rule": rule })))
}

pub async fn delete_rule(
    State(st): State<SharedState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("alerts:delete")?;
    store::delete_alert_rule(&st.db, &id).await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn list_alerts(
    State(st): State<SharedState>,
    principal: Principal,
    Query(params): Query<AlertParams>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("alerts:read")?;
    let alerts = store::list_alerts(&st.db, params.limit.unwrap_or(100)).await?;
    Ok(Json(json!({ "alerts": alerts })))
}
