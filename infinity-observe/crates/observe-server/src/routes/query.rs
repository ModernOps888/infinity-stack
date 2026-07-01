use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store::{self, LogFilter};

#[derive(Debug, Deserialize)]
pub struct LogParams {
    pub service: Option<String>,
    pub level: Option<String>,
    pub q: Option<String>,
    pub since: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct NameSince {
    pub name: Option<String>,
    pub since: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TraceParams {
    pub service: Option<String>,
    pub limit: Option<i64>,
}

pub async fn logs(
    State(st): State<SharedState>,
    principal: Principal,
    Query(params): Query<LogParams>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("logs:read")?;
    let rows = store::list_logs(&st.db, LogFilter {
        service: params.service.as_deref().filter(|s| !s.is_empty()),
        level: params.level.as_deref().filter(|s| !s.is_empty()),
        q: params.q.as_deref().filter(|s| !s.is_empty()),
        since: params.since.as_deref().filter(|s| !s.is_empty()),
        limit: params.limit.unwrap_or(100),
    }).await?;
    Ok(Json(json!({ "logs": rows })))
}

pub async fn metric_names(State(st): State<SharedState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require("metrics:read")?;
    let names = store::metric_names(&st.db).await?;
    Ok(Json(json!({ "names": names })))
}

pub async fn metric_series(
    State(st): State<SharedState>,
    principal: Principal,
    Query(params): Query<NameSince>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("metrics:read")?;
    let name = params.name.as_deref().ok_or_else(|| ApiError::BadRequest("name is required".into()))?;
    let rows = store::metric_series(&st.db, name, params.since.as_deref()).await?;
    Ok(Json(json!({ "series": rows })))
}

pub async fn metric_summary(
    State(st): State<SharedState>,
    principal: Principal,
    Query(params): Query<NameSince>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("metrics:read")?;
    let name = params.name.as_deref().ok_or_else(|| ApiError::BadRequest("name is required".into()))?;
    let summary = store::metric_summary(&st.db, name).await?;
    Ok(Json(json!({ "name": name, "summary": summary })))
}

pub async fn trace_by_id(
    State(st): State<SharedState>,
    principal: Principal,
    Path(trace_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("traces:read")?;
    let spans = store::get_trace(&st.db, &trace_id).await?;
    if spans.is_empty() {
        return Err(ApiError::NotFound("trace not found".into()));
    }
    Ok(Json(json!({ "trace_id": trace_id, "spans": spans })))
}

pub async fn traces(
    State(st): State<SharedState>,
    principal: Principal,
    Query(params): Query<TraceParams>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("traces:read")?;
    let traces = store::list_traces(&st.db, params.service.as_deref().filter(|s| !s.is_empty()), params.limit.unwrap_or(50)).await?;
    Ok(Json(json!({ "traces": traces })))
}

pub async fn stats(State(st): State<SharedState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require("stats:read")?;
    let stats = store::stats(&st.db).await?;
    Ok(Json(json!({ "stats": stats })))
}
