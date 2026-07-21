//! Request authentication: resolves a [`Principal`] from either a Bearer JWT
//! (machine/API clients) or the dashboard session cookie, then enforces RBAC.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use infinity_core::{rbac, token};

use crate::error::ApiError;
use crate::state::SharedState;
use crate::store;
use crate::util::sha256_hex;

pub const SESSION_COOKIE: &str = "infinity_session";

/// An authenticated caller with resolved roles and effective permissions.
#[derive(Debug, Clone)]
pub struct Principal {
    pub user_id: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    /// True for the dashboard session cookie or a first-party access token
    /// (audience == issuer). Third-party access tokens (audience == some client
    /// id) are NOT first-party and must not reach privileged/self-service APIs.
    pub first_party: bool,
}

impl Principal {
    /// Enforce that the principal holds a permission satisfying `required`.
    ///
    /// Also requires a first-party context — this prevents a token minted for
    /// an unrelated relying party from being replayed against the management
    /// API (confused-deputy / audience-confusion).
    pub fn require(&self, required: &str) -> Result<(), ApiError> {
        self.require_first_party()?;
        if rbac::any_permission(&self.permissions, required) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!("missing permission: {required}")))
        }
    }

    /// Require that the caller is first-party (dashboard session or issuer-
    /// audience token). Used to gate self-service account mutations too.
    pub fn require_first_party(&self) -> Result<(), ApiError> {
        if self.first_party {
            Ok(())
        } else {
            Err(ApiError::Forbidden(
                "this endpoint requires a first-party token (audience must be the issuer)".into(),
            ))
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

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        // 1) Bearer JWT (validated with our own public key components).
        if let Some(auth) = parts.headers.get(axum::http::header::AUTHORIZATION) {
            if let Ok(val) = auth.to_str() {
                if let Some(tok) = val.strip_prefix("Bearer ") {
                    // Try every still-valid key (active, then recently
                    // retired) so a token signed just before a rotation still
                    // authenticates until it naturally expires.
                    let jwks: Vec<_> = {
                        let ring = state.key.read().unwrap();
                        ring.verification_keys().cloned().collect()
                    };
                    let claims = jwks
                        .iter()
                        .find_map(|jwk| {
                            token::validate_with_components(
                                tok,
                                &jwk.n,
                                &jwk.e,
                                &state.config.issuer,
                                None,
                            )
                            .ok()
                        })
                        .ok_or_else(|| ApiError::Unauthorized("invalid or expired token".into()))?;
                    // Only access tokens may authorize API calls.
                    if claims.typ != "access" {
                        return Err(ApiError::Unauthorized(
                            "only access tokens are accepted here".into(),
                        ));
                    }
                    // First-party iff the token audience is the issuer itself.
                    let first_party = claims.aud == state.config.issuer;
                    return resolve(state, &claims.sub, first_party).await;
                }
            }
        }

        // 2) Dashboard session cookie (opaque, stored hashed) — always first-party.
        if let Some(raw) = cookie_value(parts, SESSION_COOKIE) {
            let hash = sha256_hex(&raw);
            if let Some(uid) = store::get_session_user(&state.db, &hash).await? {
                return resolve(state, &uid, true).await;
            }
        }

        Err(ApiError::Unauthorized("authentication required".into()))
    }
}

async fn resolve(state: &SharedState, user_id: &str, first_party: bool) -> Result<Principal, ApiError> {
    let row = store::get_user_row(&state.db, user_id)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("unknown subject".into()))?;
    if row.disabled != 0 {
        return Err(ApiError::Forbidden("account disabled".into()));
    }
    let roles = store::user_roles(&state.db, user_id).await?;
    let permissions = store::user_permissions(&state.db, user_id).await?;
    Ok(Principal { user_id: user_id.to_string(), roles, permissions, first_party })
}
