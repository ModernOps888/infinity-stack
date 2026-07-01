//! MFA enrolment and lifecycle for the currently authenticated user.

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;

#[derive(Deserialize)]
pub struct ActivateRequest {
    pub code: String,
}

/// POST /mfa/enroll — generate a TOTP secret + recovery codes (not yet active).
pub async fn enroll(
    State(st): State<SharedState>,
    p: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    p.require_first_party()?;
    let user = store::get_user_row(&st.db, &p.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    if user.mfa_enabled != 0 {
        return Err(ApiError::Conflict(
            "MFA is already enabled; disable it before re-enrolling".into(),
        ));
    }

    let secret = infinity_core::mfa::generate_secret();
    let uri = infinity_core::mfa::provisioning_uri(&secret, &st.config.mfa_issuer, &user.email)?;
    store::set_mfa_secret(&st.db, &p.user_id, &secret).await?;

    let codes = infinity_core::mfa::generate_recovery_codes(10);
    let hashes: Vec<String> = codes.iter().map(|c| c.hash.clone()).collect();
    let plaintext: Vec<String> = codes.iter().map(|c| c.plaintext.clone()).collect();
    store::store_recovery_codes(&st.db, &p.user_id, &hashes).await?;

    Ok(Json(json!({
        "secret": secret,
        "otpauth_uri": uri,
        "recovery_codes": plaintext,
        "next": "Scan the QR / enter the secret in your authenticator, then POST the current code to /mfa/activate",
    })))
}

/// POST /mfa/activate — confirm enrolment by verifying the first TOTP code.
pub async fn activate(
    State(st): State<SharedState>,
    p: Principal,
    Json(req): Json<ActivateRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require_first_party()?;
    let user = store::get_user_row(&st.db, &p.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    let secret = user
        .mfa_secret
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("no pending MFA enrolment; call /mfa/enroll first".into()))?;
    let ok = infinity_core::mfa::verify_totp(secret, &req.code, &st.config.mfa_issuer, &user.email)
        .unwrap_or(false);
    if !ok {
        return Err(ApiError::BadRequest("invalid code".into()));
    }
    store::enable_mfa(&st.db, &p.user_id).await?;
    store::audit(&st.db, &p.user_id, "mfa.enabled", None, None, None).await;
    Ok(Json(json!({ "mfa_enabled": true })))
}

/// POST /mfa/disable — turn MFA off for the current user.
pub async fn disable(
    State(st): State<SharedState>,
    p: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    p.require_first_party()?;
    store::disable_mfa(&st.db, &p.user_id).await?;
    store::audit(&st.db, &p.user_id, "mfa.disabled", None, None, None).await;
    Ok(Json(json!({ "mfa_enabled": false })))
}
