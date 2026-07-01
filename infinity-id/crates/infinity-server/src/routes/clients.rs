//! OAuth client (application) management endpoints.

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::ApiResult;
use crate::state::SharedState;
use crate::store::{self, NewClient};
use crate::util::{random_token, sha256_hex};

#[derive(Deserialize)]
pub struct CreateClient {
    pub name: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default = "default_grants")]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Public clients (SPA/native) use PKCE and receive no secret.
    #[serde(default)]
    pub public: bool,
}

fn default_grants() -> Vec<String> {
    vec!["authorization_code".into(), "refresh_token".into()]
}

/// GET /admin/clients
pub async fn list(State(st): State<SharedState>, p: Principal) -> ApiResult<Json<serde_json::Value>> {
    p.require("clients:read")?;
    let clients = store::list_clients(&st.db).await?;
    Ok(Json(json!({ "clients": clients })))
}

/// POST /admin/clients — returns the plaintext secret exactly once.
pub async fn create(
    State(st): State<SharedState>,
    p: Principal,
    Json(req): Json<CreateClient>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("clients:create")?;
    let (secret, secret_hash) = if req.public {
        (None, None)
    } else {
        let s = random_token();
        let h = sha256_hex(&s);
        (Some(s), Some(h))
    };
    let client_id = store::create_client(
        &st.db,
        NewClient {
            name: &req.name,
            secret_hash: secret_hash.as_deref(),
            redirect_uris: &req.redirect_uris,
            grant_types: &req.grant_types,
            scopes: &req.scopes,
            public: req.public,
        },
    )
    .await?;
    store::audit(&st.db, &p.user_id, "client.create", Some(&client_id), None, None).await;
    Ok(Json(json!({
        "client_id": client_id,
        "client_secret": secret,
        "note": "Store the client_secret now; it will not be shown again.",
    })))
}

/// DELETE /admin/clients/:client_id
pub async fn delete(
    State(st): State<SharedState>,
    p: Principal,
    Path(client_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("clients:delete")?;
    store::delete_client(&st.db, &client_id).await?;
    store::audit(&st.db, &p.user_id, "client.delete", Some(&client_id), None, None).await;
    Ok(Json(json!({ "ok": true })))
}
