use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::ApiResult;
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct CreateKey { pub name: String }

pub async fn list(State(st): State<SharedState>, p: Principal) -> ApiResult<Json<serde_json::Value>> {
    p.require("keys:read")?;
    Ok(Json(json!({"keys": store::list_api_keys(&st.db).await?})))
}

pub async fn create(State(st): State<SharedState>, p: Principal, Json(req): Json<CreateKey>) -> ApiResult<Json<serde_json::Value>> {
    p.require("keys:create")?;
    let (id, token) = store::create_api_key(&st.db, &req.name).await?;
    Ok(Json(json!({"id": id, "key": token, "note": "store this key now; only its SHA-256 hash is persisted"})))
}

pub async fn delete_key(State(st): State<SharedState>, p: Principal, Path(id): Path<String>) -> ApiResult<Json<serde_json::Value>> {
    p.require("keys:delete")?;
    store::revoke_api_key(&st.db, &id).await?;
    Ok(Json(json!({"ok": true})))
}
