//! Dashboard session authentication: username/password (+ MFA) login that sets
//! an HttpOnly session cookie, plus logout and the `/auth/me` profile endpoint.

use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{Principal, SESSION_COOKIE};
use crate::error::{ApiError, ApiResult};
use crate::routes::oidc;
use crate::state::SharedState;
use crate::store;
use crate::util::{random_token, sha256_hex};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub otp: Option<String>,
}

fn session_cookie(token: &str, ttl: i64, secure: bool) -> String {
    let base = format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}");
    if secure {
        format!("{base}; Secure")
    } else {
        base
    }
}

fn is_https(st: &SharedState) -> bool {
    st.config.issuer.starts_with("https://")
}

/// POST /auth/login
pub async fn login(
    State(st): State<SharedState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Response> {
    let throttle_key = req.email.to_lowercase();
    if let Err(retry) = st.login_throttle.check(&throttle_key) {
        return Err(ApiError::TooManyRequests(format!("too many attempts; retry in {retry}s")));
    }

    let user = match store::get_user_row_by_email(&st.db, &req.email).await? {
        Some(u) => u,
        None => {
            infinity_core::password::dummy_verify(&req.password);
            st.login_throttle.record_failure(&throttle_key);
            return Err(ApiError::Unauthorized("invalid credentials".into()));
        }
    };
    if !infinity_core::password::verify_password(&req.password, &user.password_hash)? {
        st.login_throttle.record_failure(&throttle_key);
        store::audit(&st.db, &user.id, "login.fail", None, None, None).await;
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    // Disabled check only after successful password verification, and returns
    // the same generic error — avoids a pre-auth account-status enumeration oracle.
    if user.disabled != 0 {
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    if user.mfa_enabled != 0 {
        if let Err(e) = oidc::verify_second_factor(&st, &user, req.otp.as_deref()).await {
            st.login_throttle.record_failure(&throttle_key);
            return Err(e);
        }
    }
    st.login_throttle.record_success(&throttle_key);

    let session = random_token();
    store::create_session(&st.db, &sha256_hex(&session), &user.id, st.config.session_ttl_secs).await?;
    store::audit(&st.db, &user.id, "login.success", None, None, None).await;

    let permissions = store::user_permissions(&st.db, &user.id).await?;
    let roles = store::user_roles(&st.db, &user.id).await?;
    let body = json!({
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "display_name": user.display_name,
            "roles": roles,
            "permissions": permissions,
            "mfa_enabled": user.mfa_enabled != 0,
        }
    });

    let mut resp = Json(body).into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie(&session, st.config.session_ttl_secs, is_https(&st)))
            .map_err(|e| ApiError::Internal(e.to_string()))?,
    );
    Ok(resp)
}

/// POST /auth/logout — revokes the server-side session, not just the cookie.
pub async fn logout(
    State(st): State<SharedState>,
    headers: axum::http::HeaderMap,
    principal: Principal,
) -> ApiResult<Response> {
    if let Some(raw) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .and_then(|c| {
            c.split(';').find_map(|kv| {
                let (k, v) = kv.trim().split_once('=')?;
                (k == SESSION_COOKIE).then(|| v.to_string())
            })
        })
    {
        store::delete_session(&st.db, &sha256_hex(&raw)).await?;
    }
    store::audit(&st.db, &principal.user_id, "logout", None, None, None).await;
    let mut resp = Json(json!({ "ok": true })).into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static("infinity_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    Ok(resp)
}

/// GET /auth/me
pub async fn me(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    let user = store::get_user_row(&st.db, &principal.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    Ok(Json(json!({
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "display_name": user.display_name,
        "roles": principal.roles,
        "permissions": principal.permissions,
        "mfa_enabled": user.mfa_enabled != 0,
    })))
}
