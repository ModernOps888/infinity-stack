//! Audit-log read endpoint.

use axum::extract::State;
use axum::Json;
use serde_json::json;

use crate::auth::Principal;
use crate::error::ApiResult;
use crate::state::SharedState;
use crate::store;

/// GET /admin/audit
pub async fn list(State(st): State<SharedState>, p: Principal) -> ApiResult<Json<serde_json::Value>> {
    p.require("audit:read")?;
    let events = store::list_audit(&st.db, 200).await?;
    Ok(Json(json!({ "events": events })))
}
