use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use data_core::rbac;

use crate::error::ApiError;
use crate::state::SharedState;
use crate::store;
use crate::util::sha256_hex;

pub const SESSION_COOKIE: &str = "infinity_data_session";

#[derive(Debug, Clone)]
pub struct Principal {
    pub user_id: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub first_party: bool,
}

impl Principal {
    pub fn require(&self, required: &str) -> Result<(), ApiError> {
        self.require_first_party()?;
        if rbac::any_permission(&self.permissions, required) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!(
                "missing permission: {required}"
            )))
        }
    }

    pub fn require_first_party(&self) -> Result<(), ApiError> {
        if self.first_party {
            Ok(())
        } else {
            Err(ApiError::Forbidden(
                "first-party credentials required".into(),
            ))
        }
    }
}

pub fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
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

#[axum::async_trait]
impl FromRequestParts<SharedState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(auth) = parts.headers.get(axum::http::header::AUTHORIZATION) {
            if let Ok(value) = auth.to_str() {
                if let Some(raw) = value.strip_prefix("Bearer ") {
                    if let Some(key) = store::verify_api_key(&state.db, raw).await? {
                        return Ok(Principal {
                            user_id: format!("api_key:{}", key.id),
                            roles: vec!["api_key".into()],
                            permissions: vec![
                                "data:*".into(),
                                "collections:*".into(),
                                "tables:*".into(),
                            ],
                            first_party: true,
                        });
                    }
                }
            }
        }

        if let Some(raw) = cookie_value(parts, SESSION_COOKIE) {
            let hash = sha256_hex(&raw);
            if let Some(uid) = store::get_session_user(&state.db, &hash).await? {
                let user = store::get_user(&state.db, &uid)
                    .await?
                    .ok_or_else(|| ApiError::Unauthorized("unknown session".into()))?;
                if user.disabled != 0 {
                    return Err(ApiError::Forbidden("account disabled".into()));
                }
                let roles = store::user_roles(&state.db, &uid).await?;
                let permissions = store::user_permissions(&state.db, &uid).await?;
                return Ok(Principal {
                    user_id: uid,
                    roles,
                    permissions,
                    first_party: true,
                });
            }
        }

        Err(ApiError::Unauthorized("authentication required".into()))
    }
}
