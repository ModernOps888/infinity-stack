use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct CreateKey {
    pub name: Option<String>,
}

pub async fn list(State(st): State<SharedState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require("keys:read")?;
    let keys = store::list_ingest_keys(&st.db).await?;
    Ok(Json(json!({ "keys": keys })))
}

pub async fn create(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<CreateKey>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("keys:create")?;
    let name = req.name.unwrap_or_else(|| "dashboard".into());
    if name.trim().is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    let (key, token) = store::create_ingest_key(&st.db, &name).await.map_err(|e| match e {
        sqlx::Error::Database(db) if db.message().contains("UNIQUE") => ApiError::Conflict("key collision".into()),
        other => other.into(),
    })?;
    Ok(Json(json!({ "key": key, "token": token, "note": "copy now; only the SHA-256 hash is stored" })))
}

pub async fn revoke(
    State(st): State<SharedState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("keys:delete")?;
    store::revoke_ingest_key(&st.db, &id).await?;
    Ok(Json(json!({ "ok": true })))
}
