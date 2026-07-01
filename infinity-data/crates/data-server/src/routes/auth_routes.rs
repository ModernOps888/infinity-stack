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

fn clear_cookie(secure: bool) -> String {
    let base = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    if secure {
        format!("{base}; Secure")
    } else {
        base
    }
}

pub async fn login(
    State(st): State<SharedState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Response> {
    let email = req.email.trim().to_ascii_lowercase();
    if email.len() > 254 || req.password.len() > 1024 {
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    if let Err(retry) = st.login_throttle.check(&email) {
        return Err(ApiError::TooManyRequests(format!(
            "too many attempts; retry in {retry}s"
        )));
    }

    let Some(user) = store::get_user_by_email(&st.db, &email).await? else {
        data_core::password::dummy_verify(&req.password);
        st.login_throttle.record_failure(&email);
        store::audit(
            &st.db,
            None,
            "login.fail",
            Some("unknown"),
            None,
            None,
            None,
        )
        .await;
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    };
    if !data_core::password::verify_password(&req.password, &user.password_hash)? {
        st.login_throttle.record_failure(&email);
        store::audit(
            &st.db,
            Some(&user.id),
            "login.fail",
            Some("user"),
            None,
            None,
            None,
        )
        .await;
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    if user.disabled != 0 {
        st.login_throttle.record_failure(&email);
        store::audit(
            &st.db,
            Some(&user.id),
            "login.fail",
            Some("user"),
            None,
            None,
            None,
        )
        .await;
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
    store::audit(
        &st.db,
        Some(&user.id),
        "login.success",
        Some("user"),
        None,
        None,
        None,
    )
    .await;
    let roles = store::user_roles(&st.db, &user.id).await?;
    let permissions = store::user_permissions(&st.db, &user.id).await?;
    let body = json!({"user":{"id":user.id,"email":user.email,"username":user.username,"display_name":user.display_name,"roles":roles,"permissions":permissions}});
    let mut resp = Json(body).into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie(
            &session,
            st.config.session_ttl_secs,
            st.config.secure_cookies(),
        ))
        .map_err(|e| ApiError::Internal(e.to_string()))?,
    );
    Ok(resp)
}

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
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "logout",
        Some("session"),
        None,
        None,
        None,
    )
    .await;
    let mut resp = Json(json!({"ok": true})).into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&clear_cookie(st.config.secure_cookies()))
            .map_err(|e| ApiError::Internal(e.to_string()))?,
    );
    Ok(resp)
}

pub async fn me(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    let user = store::get_user(&st.db, &principal.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    Ok(Json(json!({
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "display_name": user.display_name,
        "roles": principal.roles,
        "permissions": principal.permissions
    })))
}
