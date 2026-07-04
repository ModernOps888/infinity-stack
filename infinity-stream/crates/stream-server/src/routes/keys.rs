use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{Principal, PrincipalKind};
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct CreateKey {
    pub name: String,
}

/// Defense in depth: even if API-key scopes are ever widened, keys must never
/// be able to list, mint, or revoke other keys.
fn deny_api_keys(p: &Principal) -> Result<(), ApiError> {
    if matches!(p.kind, PrincipalKind::ApiKey) {
        return Err(ApiError::Forbidden(
            "API keys cannot manage API keys".into(),
        ));
    }
    Ok(())
}

pub async fn list(
    State(st): State<SharedState>,
    p: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    deny_api_keys(&p)?;
    p.require("keys:read")?;
    Ok(Json(json!({"keys": store::list_api_keys(&st.db).await?})))
}

pub async fn create(
    State(st): State<SharedState>,
    p: Principal,
    Json(req): Json<CreateKey>,
) -> ApiResult<Json<serde_json::Value>> {
    deny_api_keys(&p)?;
    p.require("keys:create")?;
    if req.name.trim().is_empty() || req.name.len() > 128 {
        return Err(ApiError::BadRequest("key name must be 1-128 chars".into()));
    }
    let (id, token) = store::create_api_key(&st.db, &req.name).await?;
    Ok(Json(
        json!({"id": id, "key": token, "note": "store this key now; only its SHA-256 hash is persisted"}),
    ))
}

pub async fn delete_key(
    State(st): State<SharedState>,
    p: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    deny_api_keys(&p)?;
    p.require("keys:delete")?;
    store::revoke_api_key(&st.db, &id).await?;
    Ok(Json(json!({"ok": true})))
}
