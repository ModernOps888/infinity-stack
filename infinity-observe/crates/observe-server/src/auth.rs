use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::ApiError;
use crate::state::SharedState;
use crate::store;
use crate::util::sha256_hex;

pub const SESSION_COOKIE: &str = "infinity_observe_session";

#[derive(Debug, Clone)]
pub struct Principal {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub permissions: Vec<String>,
}

impl Principal {
    pub fn require(&self, required: &str) -> Result<(), ApiError> {
        if observe_core::rbac::any_permission(&self.permissions, required) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!(
                "missing permission: {required}"
            )))
        }
    }
}

#[derive(Debug, Clone)]
pub struct IngestAuth {
    pub key_id: String,
}

fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
    let header = parts
        .headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?;
    header.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

fn bearer(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}

#[axum::async_trait]
impl FromRequestParts<SharedState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(tok) = bearer(parts).or_else(|| cookie_value(parts, SESSION_COOKIE)) {
            let hash = sha256_hex(&tok);
            if let Some(uid) = store::get_session_user(&state.db, &hash).await? {
                return resolve(state, &uid).await;
            }
        }
        Err(ApiError::Unauthorized("authentication required".into()))
    }
}

#[axum::async_trait]
impl FromRequestParts<SharedState> for IngestAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let Some(tok) = bearer(parts) else {
            return Err(ApiError::Unauthorized("missing bearer ingest key".into()));
        };
        let hash = sha256_hex(&tok);
        match store::validate_ingest_key(&state.db, &hash).await? {
            Some(id) => Ok(IngestAuth { key_id: id }),
            None => Err(ApiError::Unauthorized("invalid ingest key".into())),
        }
    }
}

async fn resolve(state: &SharedState, user_id: &str) -> Result<Principal, ApiError> {
    let user = store::get_user(&state.db, user_id)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("unknown subject".into()))?;
    if user.disabled != 0 {
        return Err(ApiError::Forbidden("account disabled".into()));
    }
    let permissions = observe_core::rbac::permissions_for_role(&user.role);
    Ok(Principal {
        user_id: user.id,
        email: user.email,
        role: user.role,
        permissions,
    })
}
