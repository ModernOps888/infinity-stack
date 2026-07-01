use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::ApiResult;
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    100
}

pub async fn list(
    State(st): State<SharedState>,
    principal: Principal,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("audit:read")?;
    Ok(Json(
        json!({"events": store::list_audit(&st.db, q.limit).await?}),
    ))
}
