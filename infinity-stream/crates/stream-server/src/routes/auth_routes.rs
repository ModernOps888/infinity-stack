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

/// Cookies get the `Secure` flag by default. It is only omitted for local
/// development over plain HTTP on loopback, so a TLS-terminating proxy
/// deployment never accidentally ships a cleartext-capable session cookie.
fn cookie_secure(public_url: &str) -> bool {
    !(public_url.starts_with("http://localhost") || public_url.starts_with("http://127."))
}

pub async fn login(
    State(st): State<SharedState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Response> {
    let throttle_key = req.email.trim().to_lowercase();
    if throttle_key.len() > 320 || req.password.len() > 1024 {
        stream_core::password::dummy_verify(&req.password);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    if let Err(retry) = st.login_throttle.check(&throttle_key) {
        return Err(ApiError::TooManyRequests(format!(
            "too many attempts; retry in {retry}s"
        )));
    }

    let Some((id, email, username, hash)) = store::get_user_by_email(&st.db, &throttle_key).await?
    else {
        stream_core::password::dummy_verify(&req.password);
        st.login_throttle.record_failure(&throttle_key);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    };
    if !stream_core::password::verify_password(&req.password, &hash)? {
        st.login_throttle.record_failure(&throttle_key);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    st.login_throttle.record_success(&throttle_key);
    let session = random_token();
    store::create_session(
        &st.db,
        &sha256_hex(&session),
        &id,
        st.config.session_ttl_secs,
    )
    .await?;
    let mut resp = Json(json!({"user":{"id":id,"email":email,"username":username,"roles":["superadmin"],"permissions":["*:*"]}})).into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie(
            &session,
            st.config.session_ttl_secs,
            cookie_secure(&st.config.public_url),
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
    let mut resp = Json(json!({"ok":true,"subject":principal.subject})).into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static("infinity_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    Ok(resp)
}

pub async fn me(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    let (email, username) = match principal.kind {
        crate::auth::PrincipalKind::User => store::get_user_by_id(&st.db, &principal.subject)
            .await?
            .unwrap_or_else(|| ("unknown".into(), "unknown".into())),
        crate::auth::PrincipalKind::ApiKey => ("api-key".into(), "api-key".into()),
    };
    Ok(Json(json!({
        "id": principal.subject,
        "kind": format!("{:?}", principal.kind),
        "username": username,
        "email": email,
        "roles": ["superadmin"],
        "permissions": principal.permissions
    })))
}
