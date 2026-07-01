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

fn session_cookie(token: &str, ttl: i64, secure: bool) -> String {
    let base =
        format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}");
    if secure {
        format!("{base}; Secure")
    } else {
        base
    }
}

fn clear_session_cookie(secure: bool) -> &'static str {
    if secure {
        "infinity_observe_session=; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=0"
    } else {
        "infinity_observe_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
    }
}

fn is_https(st: &SharedState) -> bool {
    st.config.public_url.starts_with("https://")
}

fn cookie_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == SESSION_COOKIE).then(|| v.to_string())
        })
}

pub async fn login(
    State(st): State<SharedState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Response> {
    let email = req.email.trim().to_lowercase();
    if email.is_empty() || email.len() > 254 || req.password.len() > 1024 {
        observe_core::password::dummy_verify(&req.password);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }

    if let Err(retry) = st.login_throttle.check(&email) {
        return Err(ApiError::TooManyRequests(format!(
            "too many attempts; retry in {retry}s"
        )));
    }

    let user = match store::get_user_by_email(&st.db, &email).await? {
        Some(u) => u,
        None => {
            observe_core::password::dummy_verify(&req.password);
            st.login_throttle.record_failure(&email);
            return Err(ApiError::Unauthorized("invalid credentials".into()));
        }
    };
    if user.disabled != 0 {
        return Err(ApiError::Forbidden("account disabled".into()));
    }
    if !observe_core::password::verify_password(&req.password, &user.password_hash)? {
        st.login_throttle.record_failure(&email);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    st.login_throttle.record_success(&email);

    let session = random_token();
    store::create_session(
        &st.db,
        &sha256_hex(&session),
        &user.id,
        st.config.session_ttl_secs,
    )
    .await?;
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
    }))
    .into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie(
            &session,
            st.config.session_ttl_secs,
            is_https(&st),
        ))
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
        HeaderValue::from_static(clear_session_cookie(is_https(&st))),
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
