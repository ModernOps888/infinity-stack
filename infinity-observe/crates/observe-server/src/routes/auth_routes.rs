use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{Principal, SESSION_COOKIE};
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;
use crate::util::{random_token, sha256_hex};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

fn session_cookie(token: &str, ttl: i64) -> String {
    format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}")
}

fn cookie_from_headers(headers: &HeaderMap) -> Option<String> {
    headers.get(axum::http::header::COOKIE)?.to_str().ok()?.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == SESSION_COOKIE).then(|| v.to_string())
    })
}

pub async fn login(State(st): State<SharedState>, Json(req): Json<LoginRequest>) -> ApiResult<Response> {
    let user = match store::get_user_by_email(&st.db, &req.email).await? {
        Some(u) => u,
        None => {
            observe_core::password::dummy_verify(&req.password);
            return Err(ApiError::Unauthorized("invalid credentials".into()));
        }
    };
    if user.disabled != 0 {
        return Err(ApiError::Forbidden("account disabled".into()));
    }
    if !observe_core::password::verify_password(&req.password, &user.password_hash)? {
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }

    let session = random_token();
    store::create_session(&st.db, &sha256_hex(&session), &user.id, st.config.session_ttl_secs).await?;
    let permissions = observe_core::rbac::permissions_for_role(&user.role);
    let mut resp = Json(json!({
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "display_name": user.display_name,
            "role": user.role,
            "permissions": permissions
        }
    })).into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie(&session, st.config.session_ttl_secs))
            .map_err(|e| ApiError::Internal(e.to_string()))?,
    );
    Ok(resp)
}

pub async fn logout(
    State(st): State<SharedState>,
    headers: HeaderMap,
    principal: Principal,
) -> ApiResult<Response> {
    if let Some(raw) = cookie_from_headers(&headers) {
        store::delete_session(&st.db, &sha256_hex(&raw)).await?;
    }
    let mut resp = Json(json!({ "ok": true, "user_id": principal.user_id })).into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static("infinity_observe_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    Ok(resp)
}

pub async fn me(principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({
        "id": principal.user_id,
        "email": principal.email,
        "role": principal.role,
        "permissions": principal.permissions,
    })))
}
