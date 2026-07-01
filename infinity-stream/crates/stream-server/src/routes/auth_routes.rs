use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::HeaderValue;
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
pub struct LoginRequest { pub email: String, pub password: String }

fn session_cookie(token: &str, ttl: i64) -> String {
    format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}")
}

pub async fn login(State(st): State<SharedState>, Json(req): Json<LoginRequest>) -> ApiResult<Response> {
    let Some((id, email, hash)) = store::get_user_by_email(&st.db, &req.email).await? else {
        stream_core::password::dummy_verify(&req.password);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    };
    if !stream_core::password::verify_password(&req.password, &hash)? {
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    let session = random_token();
    store::create_session(&st.db, &sha256_hex(&session), &id, st.config.session_ttl_secs).await?;
    let mut resp = Json(json!({"user":{"id":id,"email":email,"username":"admin","roles":["superadmin"],"permissions":["*:*"]}})).into_response();
    resp.headers_mut().insert(SET_COOKIE, HeaderValue::from_str(&session_cookie(&session, st.config.session_ttl_secs)).map_err(|e| ApiError::Internal(e.to_string()))?);
    Ok(resp)
}

pub async fn logout(State(st): State<SharedState>, headers: axum::http::HeaderMap, principal: Principal) -> ApiResult<Response> {
    if let Some(raw) = headers.get(axum::http::header::COOKIE).and_then(|c| c.to_str().ok()).and_then(|c| c.split(';').find_map(|kv| { let (k, v) = kv.trim().split_once('=')?; (k == SESSION_COOKIE).then(|| v.to_string()) })) {
        store::delete_session(&st.db, &sha256_hex(&raw)).await?;
    }
    let mut resp = Json(json!({"ok":true,"subject":principal.subject})).into_response();
    resp.headers_mut().insert(SET_COOKIE, HeaderValue::from_static("infinity_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"));
    Ok(resp)
}

pub async fn me(principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({"id":principal.subject,"kind":format!("{:?}", principal.kind),"username":"admin","email":"admin@infinity.local","roles":["superadmin"],"permissions":principal.permissions})))
}
