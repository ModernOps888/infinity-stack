use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::ApiError;
use crate::state::SharedState;
use crate::store;
use crate::util::sha256_hex;

pub const SESSION_COOKIE: &str = "infinity_session";

#[derive(Debug, Clone)]
pub enum PrincipalKind { User, ApiKey }

#[derive(Debug, Clone)]
pub struct Principal {
    pub subject: String,
    pub kind: PrincipalKind,
    pub permissions: Vec<String>,
}

impl Principal {
    pub fn require(&self, required: &str) -> Result<(), ApiError> {
        if stream_core::rbac::any_permission(&self.permissions, required) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!("missing permission: {required}")))
        }
    }
}

fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
    let header = parts.headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    header.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

#[axum::async_trait]
impl FromRequestParts<SharedState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &SharedState) -> Result<Self, Self::Rejection> {
        if let Some(auth) = parts.headers.get(axum::http::header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
            if let Some(token) = auth.strip_prefix("Bearer ") {
                if let Some(id) = store::api_key_subject(&state.db, &sha256_hex(token)).await? {
                    return Ok(Principal { subject: id, kind: PrincipalKind::ApiKey, permissions: vec!["*:*".into()] });
                }
            }
        }
        if let Some(raw) = cookie_value(parts, SESSION_COOKIE) {
            if let Some(uid) = store::session_user(&state.db, &sha256_hex(&raw)).await? {
                return Ok(Principal { subject: uid, kind: PrincipalKind::User, permissions: vec!["*:*".into()] });
            }
        }
        Err(ApiError::Unauthorized("authentication required".into()))
    }
}
