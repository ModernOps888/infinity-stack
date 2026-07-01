//! Role & permission management endpoints.

use axum::extract::State;
use axum::Json;
use infinity_core::model::Role;
use serde_json::json;

use crate::auth::Principal;
use crate::error::ApiResult;
use crate::state::SharedState;
use crate::store;

/// GET /admin/roles
pub async fn list(State(st): State<SharedState>, p: Principal) -> ApiResult<Json<serde_json::Value>> {
    p.require("roles:read")?;
    let roles = store::list_roles(&st.db).await?;
    Ok(Json(json!({ "roles": roles })))
}

/// PUT /admin/roles — create or update a role.
pub async fn upsert(
    State(st): State<SharedState>,
    p: Principal,
    Json(role): Json<Role>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("roles:write")?;
    store::upsert_role(&st.db, &role).await?;
    store::audit(&st.db, &p.user_id, "role.upsert", Some(&role.name), None, None).await;
    Ok(Json(json!({ "ok": true })))
}
