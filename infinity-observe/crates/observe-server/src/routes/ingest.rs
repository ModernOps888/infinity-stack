use axum::extract::State;
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::IngestAuth;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store::{self, NewLog, NewMetric, NewSpan};

#[derive(Debug, Deserialize)]
pub struct LogIn {
    pub timestamp: Option<String>,
    pub level: String,
    pub service: String,
    pub message: String,
    pub attributes: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct MetricIn {
    pub timestamp: Option<String>,
    pub name: String,
    pub value: f64,
    pub tags: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct SpanIn {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub service: String,
    pub start: String,
    pub end: Option<String>,
    pub duration_ms: Option<f64>,
    pub status: Option<String>,
    pub attributes: Option<Value>,
}

pub async fn logs(
    State(st): State<SharedState>,
    auth: IngestAuth,
    Json(items): Json<Vec<LogIn>>,
) -> ApiResult<Json<serde_json::Value>> {
    let _ = &auth.key_id;
    if items.len() > 5_000 {
        return Err(ApiError::BadRequest("too many log records".into()));
    }
    let mut inserted = 0;
    for l in items {
        if l.level.trim().is_empty() || l.service.trim().is_empty() || l.message.trim().is_empty() {
            return Err(ApiError::BadRequest("level, service and message are required".into()));
        }
        let ts = l.timestamp.unwrap_or_else(store::now);
        store::insert_log(&st.db, NewLog {
            timestamp: &ts,
            level: &l.level,
            service: &l.service,
            message: &l.message,
            attributes: l.attributes,
        }).await?;
        inserted += 1;
    }
    store::evaluate_alerts(&st.db).await?;
    Ok(Json(json!({ "accepted": inserted })))
}

pub async fn metrics(
    State(st): State<SharedState>,
    auth: IngestAuth,
    Json(items): Json<Vec<MetricIn>>,
) -> ApiResult<Json<serde_json::Value>> {
    let _ = &auth.key_id;
    if items.len() > 10_000 {
        return Err(ApiError::BadRequest("too many metric records".into()));
    }
    let mut inserted = 0;
    for m in items {
        if m.name.trim().is_empty() || !m.value.is_finite() {
            return Err(ApiError::BadRequest("metric name and finite value are required".into()));
        }
        let ts = m.timestamp.unwrap_or_else(store::now);
        store::insert_metric(&st.db, NewMetric { timestamp: &ts, name: &m.name, value: m.value, tags: m.tags }).await?;
        inserted += 1;
    }
    store::evaluate_alerts(&st.db).await?;
    Ok(Json(json!({ "accepted": inserted })))
}

pub async fn traces(
    State(st): State<SharedState>,
    auth: IngestAuth,
    Json(items): Json<Vec<SpanIn>>,
) -> ApiResult<Json<serde_json::Value>> {
    let _ = &auth.key_id;
    if items.len() > 5_000 {
        return Err(ApiError::BadRequest("too many spans".into()));
    }
    let mut inserted = 0;
    for s in items {
        if s.trace_id.trim().is_empty() || s.span_id.trim().is_empty() || s.name.trim().is_empty() || s.service.trim().is_empty() {
            return Err(ApiError::BadRequest("trace_id, span_id, name and service are required".into()));
        }
        let (end, duration) = normalize_span_time(&s.start, s.end.as_deref(), s.duration_ms)?;
        store::insert_span(&st.db, NewSpan {
            trace_id: &s.trace_id,
            span_id: &s.span_id,
            parent_span_id: s.parent_span_id.as_deref(),
            name: &s.name,
            service: &s.service,
            start_time: &s.start,
            end_time: &end,
            duration_ms: duration,
            status: s.status.as_deref(),
            attributes: s.attributes,
        }).await?;
        inserted += 1;
    }
    Ok(Json(json!({ "accepted": inserted })))
}

fn normalize_span_time(start: &str, end: Option<&str>, duration_ms: Option<f64>) -> ApiResult<(String, f64)> {
    if let Some(d) = duration_ms {
        if !d.is_finite() || d < 0.0 { return Err(ApiError::BadRequest("duration_ms must be non-negative".into())); }
        if let Some(e) = end { return Ok((e.to_string(), d)); }
        let start_dt = chrono::DateTime::parse_from_rfc3339(start).map_err(|_| ApiError::BadRequest("start must be RFC3339".into()))?;
        let end_dt = start_dt.with_timezone(&Utc) + Duration::milliseconds(d.round() as i64);
        return Ok((end_dt.to_rfc3339(), d));
    }
    let e = end.ok_or_else(|| ApiError::BadRequest("end or duration_ms is required".into()))?;
    let sdt = chrono::DateTime::parse_from_rfc3339(start).map_err(|_| ApiError::BadRequest("start must be RFC3339".into()))?;
    let edt = chrono::DateTime::parse_from_rfc3339(e).map_err(|_| ApiError::BadRequest("end must be RFC3339".into()))?;
    let d = (edt - sdt).num_milliseconds().max(0) as f64;
    Ok((e.to_string(), d))
}
