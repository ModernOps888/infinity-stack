//! Signing-key rotation (superadmin only).

use axum::extract::State;
use axum::Json;
use serde_json::json;

use crate::auth::Principal;
use crate::error::ApiResult;
use crate::state::SharedState;
use crate::store;

/// POST /admin/keys/rotate — retire the active signing key and generate a
/// fresh one. The retired key stays published in the JWKS (and accepted for
/// local verification) until every token it signed would have expired, so
/// rotating never invalidates a live session or access token.
pub async fn rotate(State(st): State<SharedState>, p: Principal) -> ApiResult<Json<serde_json::Value>> {
    p.require("keys:rotate")?;
    let retention_secs = st.key_retention_secs();
    let new_kid = {
        let mut ring = st.key.write().unwrap();
        ring.rotate(&st.key_path, retention_secs)?;
        ring.active.kid.clone()
    };
    store::audit(&st.db, &p.user_id, "keys.rotate", Some(&new_kid), None, None).await;
    Ok(Json(json!({ "ok": true, "active_kid": new_kid })))
}
