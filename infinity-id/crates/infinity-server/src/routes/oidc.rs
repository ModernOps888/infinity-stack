//! OAuth2 / OpenID Connect endpoints: discovery, JWKS, authorize, token, userinfo.

use axum::extract::{Form, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use chrono::Utc;
use infinity_core::token::{issue, Claims};
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;
use crate::util::{random_token, sha256_hex, verify_pkce};

/// OIDC discovery document at `/.well-known/openid-configuration`.
pub async fn discovery(State(st): State<SharedState>) -> Json<serde_json::Value> {
    let iss = &st.config.issuer;
    Json(json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/oauth/authorize"),
        "token_endpoint": format!("{iss}/oauth/token"),
        "userinfo_endpoint": format!("{iss}/userinfo"),
        "jwks_uri": format!("{iss}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials", "password"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"]
    }))
}

/// Public JWKS document used by resource servers to validate tokens.
pub async fn jwks(State(st): State<SharedState>) -> Json<serde_json::Value> {
    Json(serde_json::to_value(st.key.jwks()).unwrap())
}

// ---------------------------------------------------------------------------
// Token minting helpers (shared across grants and the dashboard login).
// ---------------------------------------------------------------------------

pub async fn mint_access_token(
    st: &SharedState,
    user_id: &str,
    username: Option<&str>,
    aud: &str,
    scope: &str,
    typ: &str,
) -> ApiResult<String> {
    let roles = store::user_roles(&st.db, user_id).await?;
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user_id.to_string(),
        iss: st.config.issuer.clone(),
        aud: aud.to_string(),
        exp: now + st.config.access_token_ttl_secs,
        iat: now,
        nbf: now,
        scope: scope.to_string(),
        roles,
        preferred_username: username.map(|s| s.to_string()),
        typ: typ.to_string(),
    };
    Ok(issue(&st.key, &claims)?)
}

pub async fn issue_refresh(
    st: &SharedState,
    user_id: &str,
    client_id: &str,
    scope: &str,
) -> ApiResult<String> {
    let token = random_token();
    store::insert_refresh(
        &st.db,
        &sha256_hex(&token),
        user_id,
        client_id,
        scope,
        st.config.refresh_token_ttl_secs,
    )
    .await?;
    Ok(token)
}

/// Standard OIDC scopes that any client may always receive.
const STANDARD_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

/// Narrow a requested scope string to what the client is actually allowed:
/// standard OIDC scopes plus the client's registered resource scopes. This
/// prevents callers from self-asserting arbitrary (e.g. privileged) scopes.
pub fn narrow_scope(requested: &str, allowed: &[String]) -> String {
    requested
        .split_whitespace()
        .filter(|s| STANDARD_SCOPES.contains(s) || allowed.iter().any(|a| a == s))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Build a full token response (access + optional refresh + optional id_token).
///
/// `aud` is the access-token audience (resource server / issuer for first-party
/// tokens); `client_id` identifies the client for the id_token audience and for
/// refresh-token bookkeeping.
pub async fn token_response(
    st: &SharedState,
    user_id: &str,
    username: Option<&str>,
    aud: &str,
    client_id: &str,
    scope: &str,
    with_refresh: bool,
) -> ApiResult<serde_json::Value> {
    let access = mint_access_token(st, user_id, username, aud, scope, "access").await?;
    let mut body = json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": st.config.access_token_ttl_secs,
        "scope": scope,
    });
    if scope.split_whitespace().any(|s| s == "openid") {
        // The id_token's audience is always the client it was issued to.
        let id_token = mint_access_token(st, user_id, username, client_id, scope, "id").await?;
        body["id_token"] = json!(id_token);
    }
    if with_refresh {
        let refresh = issue_refresh(st, user_id, client_id, scope).await?;
        body["refresh_token"] = json!(refresh);
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// Authorization endpoint (code flow + PKCE)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// GET /oauth/authorize — requires an active dashboard session (cookie).
pub async fn authorize(
    State(st): State<SharedState>,
    principal: Principal,
    Query(p): Query<AuthorizeParams>,
) -> ApiResult<Response> {
    if p.response_type != "code" {
        return Err(ApiError::BadRequest("only response_type=code is supported".into()));
    }
    let (client, _) = store::get_client_raw(&st.db, &p.client_id)
        .await?
        .ok_or_else(|| ApiError::BadRequest("unknown client_id".into()))?;
    if !client.redirect_uris.iter().any(|u| u == &p.redirect_uri) {
        return Err(ApiError::BadRequest("redirect_uri not registered".into()));
    }
    if client.public && p.code_challenge.is_none() {
        return Err(ApiError::BadRequest("PKCE code_challenge required for public clients".into()));
    }
    // Enforce PKCE S256 only — `plain` exposes the verifier and is refused.
    if p.code_challenge.is_some() {
        match p.code_challenge_method.as_deref() {
            Some("S256") => {}
            _ => return Err(ApiError::BadRequest("code_challenge_method must be S256".into())),
        }
    }

    // Never grant more scope than the client is registered for.
    let scope = narrow_scope(&p.scope, &client.scopes);

    let code = random_token();
    store::insert_auth_code(
        &st.db,
        &code,
        &p.client_id,
        &principal.user_id,
        &p.redirect_uri,
        &scope,
        p.code_challenge.as_deref(),
        p.code_challenge_method.as_deref(),
        st.config.code_ttl_secs,
    )
    .await?;
    store::audit(&st.db, &principal.user_id, "oauth.authorize", Some(&p.client_id), None, None).await;

    let sep = if p.redirect_uri.contains('?') { '&' } else { '?' };
    let location = format!("{}{}code={}&state={}", p.redirect_uri, sep, code, p.state);
    Ok(Redirect::to(&location).into_response())
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TokenParams {
    pub grant_type: String,
    // authorization_code
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    // client auth
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    // password grant
    pub username: Option<String>,
    pub password: Option<String>,
    pub otp: Option<String>,
    // refresh
    pub refresh_token: Option<String>,
    // scope
    pub scope: Option<String>,
}

/// POST /oauth/token — supports authorization_code, refresh_token,
/// client_credentials and password grants.
pub async fn token(
    State(st): State<SharedState>,
    Form(p): Form<TokenParams>,
) -> ApiResult<Json<serde_json::Value>> {
    match p.grant_type.as_str() {
        "authorization_code" => grant_auth_code(&st, p).await,
        "refresh_token" => grant_refresh(&st, p).await,
        "client_credentials" => grant_client_credentials(&st, p).await,
        "password" => grant_password(&st, p).await,
        other => Err(ApiError::BadRequest(format!("unsupported grant_type: {other}"))),
    }
}

async fn grant_auth_code(st: &SharedState, p: TokenParams) -> ApiResult<Json<serde_json::Value>> {
    let code = p.code.ok_or_else(|| ApiError::BadRequest("code required".into()))?;
    let row = store::take_auth_code(&st.db, &code)
        .await?
        .ok_or_else(|| ApiError::BadRequest("invalid or used code".into()))?;

    if chrono::DateTime::parse_from_rfc3339(&row.expires_at).map(|t| t < Utc::now()).unwrap_or(true) {
        return Err(ApiError::BadRequest("authorization code expired".into()));
    }
    if let Some(ru) = &p.redirect_uri {
        if ru != &row.redirect_uri {
            return Err(ApiError::BadRequest("redirect_uri mismatch".into()));
        }
    }

    // Authenticate the client. The client_id must match the one the code was
    // issued to; confidential clients must present their secret.
    let client_id = p
        .client_id
        .clone()
        .ok_or_else(|| ApiError::BadRequest("client_id required".into()))?;
    if client_id != row.client_id {
        return Err(ApiError::BadRequest("client_id does not match authorization code".into()));
    }
    let (client, secret_hash) = store::get_client_raw(&st.db, &client_id)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("unknown client".into()))?;
    if client.public {
        // Public clients cannot keep a secret and MUST use PKCE.
        if row.code_challenge.is_none() {
            return Err(ApiError::BadRequest("PKCE required for public clients".into()));
        }
    } else {
        let secret = p
            .client_secret
            .clone()
            .ok_or_else(|| ApiError::Unauthorized("client authentication required".into()))?;
        let stored = secret_hash
            .ok_or_else(|| ApiError::Internal("confidential client missing secret".into()))?;
        if !infinity_core::password::constant_time_eq(sha256_hex(&secret).as_bytes(), stored.as_bytes()) {
            return Err(ApiError::Unauthorized("invalid client credentials".into()));
        }
    }

    if let Some(challenge) = &row.code_challenge {
        let verifier = p
            .code_verifier
            .ok_or_else(|| ApiError::BadRequest("code_verifier required".into()))?;
        if !verify_pkce(&verifier, challenge, row.code_challenge_method.as_deref()) {
            return Err(ApiError::BadRequest("PKCE verification failed".into()));
        }
    }

    let user = store::get_user_row(&st.db, &row.user_id)
        .await?
        .ok_or_else(|| ApiError::BadRequest("user no longer exists".into()))?;
    if user.disabled != 0 {
        return Err(ApiError::Forbidden("account disabled".into()));
    }
    let body = token_response(st, &row.user_id, Some(&user.username), &row.client_id, &row.client_id, &row.scope, true).await?;
    store::audit(&st.db, &row.user_id, "token.issue", Some(&row.client_id), None, Some("authorization_code")).await;
    Ok(Json(body))
}

async fn grant_refresh(st: &SharedState, p: TokenParams) -> ApiResult<Json<serde_json::Value>> {
    let token = p.refresh_token.ok_or_else(|| ApiError::BadRequest("refresh_token required".into()))?;
    let hash = sha256_hex(&token);
    let row = store::get_refresh(&st.db, &hash)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("invalid refresh token".into()))?;
    if row.revoked != 0 {
        // Reuse of a rotated/revoked token is a strong compromise signal:
        // revoke the whole family for this user+client.
        store::revoke_refresh_family(&st.db, &row.user_id, &row.client_id).await?;
        store::audit(&st.db, &row.user_id, "token.refresh_reuse", Some(&row.client_id), None, None).await;
        return Err(ApiError::Unauthorized("refresh token revoked".into()));
    }
    if chrono::DateTime::parse_from_rfc3339(&row.expires_at).map(|t| t < Utc::now()).unwrap_or(true) {
        return Err(ApiError::Unauthorized("refresh token expired".into()));
    }
    // Authenticate the client the token was issued to (RFC 6749 §6). A presented
    // client_id must match the token's client; registered confidential clients
    // must also present a valid secret so a stolen refresh token alone cannot be
    // redeemed. Public / first-party (unregistered) clients keep no secret.
    if let Some(cid) = &p.client_id {
        if cid != &row.client_id {
            return Err(ApiError::Unauthorized(
                "client_id does not match refresh token".into(),
            ));
        }
    }
    if let Some((client, secret_hash)) = store::get_client_raw(&st.db, &row.client_id).await? {
        if !client.public {
            let secret = p
                .client_secret
                .clone()
                .ok_or_else(|| ApiError::Unauthorized("client authentication required".into()))?;
            let stored = secret_hash
                .ok_or_else(|| ApiError::Internal("confidential client missing secret".into()))?;
            if !infinity_core::password::constant_time_eq(
                sha256_hex(&secret).as_bytes(),
                stored.as_bytes(),
            ) {
                return Err(ApiError::Unauthorized("invalid client credentials".into()));
            }
        }
    }
    // Rotate: revoke the presented token and mint a fresh pair.
    store::revoke_refresh(&st.db, &hash).await?;
    let user = store::get_user_row(&st.db, &row.user_id)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("user no longer exists".into()))?;
    if user.disabled != 0 {
        return Err(ApiError::Forbidden("account disabled".into()));
    }
    let body = token_response(st, &row.user_id, Some(&user.username), &row.client_id, &row.client_id, &row.scope, true).await?;
    Ok(Json(body))
}

async fn grant_client_credentials(st: &SharedState, p: TokenParams) -> ApiResult<Json<serde_json::Value>> {
    let client_id = p.client_id.ok_or_else(|| ApiError::BadRequest("client_id required".into()))?;
    let secret = p.client_secret.ok_or_else(|| ApiError::Unauthorized("client_secret required".into()))?;
    let (client, stored) = store::get_client_raw(&st.db, &client_id)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("invalid client".into()))?;
    let stored = stored.ok_or_else(|| ApiError::Unauthorized("client is public".into()))?;
    if !infinity_core::password::constant_time_eq(sha256_hex(&secret).as_bytes(), stored.as_bytes()) {
        return Err(ApiError::Unauthorized("invalid client credentials".into()));
    }
    // Bound the granted scope to what the client is registered for.
    let requested = p.scope.unwrap_or_else(|| client.scopes.join(" "));
    let scope = narrow_scope(&requested, &client.scopes);
    // Subject is the client itself (machine-to-machine).
    let access = mint_access_token(st, &client_id, Some(&client.name), &client_id, &scope, "access").await?;
    store::audit(&st.db, &client_id, "token.issue", Some(&client_id), None, Some("client_credentials")).await;
    Ok(Json(json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": st.config.access_token_ttl_secs,
        "scope": scope,
    })))
}

async fn grant_password(st: &SharedState, p: TokenParams) -> ApiResult<Json<serde_json::Value>> {
    let username = p.username.ok_or_else(|| ApiError::BadRequest("username required".into()))?;
    let password = p.password.ok_or_else(|| ApiError::BadRequest("password required".into()))?;
    let client_id = p.client_id.unwrap_or_else(|| "infinity-cli".into());

    let throttle_key = username.to_lowercase();
    if let Err(retry) = st.login_throttle.check(&throttle_key) {
        return Err(ApiError::TooManyRequests(format!("too many attempts; retry in {retry}s")));
    }

    let user = match store::get_user_row_by_email(&st.db, &username).await? {
        Some(u) => u,
        None => {
            // Equalize timing so absent accounts are indistinguishable.
            infinity_core::password::dummy_verify(&password);
            st.login_throttle.record_failure(&throttle_key);
            return Err(ApiError::Unauthorized("invalid credentials".into()));
        }
    };
    if !infinity_core::password::verify_password(&password, &user.password_hash)? {
        st.login_throttle.record_failure(&throttle_key);
        store::audit(&st.db, &user.id, "login.fail", None, None, Some("password")).await;
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    // Disabled check only after successful password verification (avoids
    // pre-auth account-status enumeration).
    if user.disabled != 0 {
        return Err(ApiError::Forbidden("account disabled".into()));
    }
    if user.mfa_enabled != 0 {
        if let Err(e) = verify_second_factor(st, &user, p.otp.as_deref()).await {
            st.login_throttle.record_failure(&throttle_key);
            return Err(e);
        }
    }
    st.login_throttle.record_success(&throttle_key);
    // Password grant is a trusted first-party flow: audience is the issuer, and
    // only standard OIDC scopes (or the named client's registered scopes) are
    // granted — callers cannot self-assert arbitrary resource scopes.
    let allowed = match store::get_client_raw(&st.db, &client_id).await? {
        Some((c, _)) => c.scopes,
        None => Vec::new(),
    };
    let requested = p.scope.unwrap_or_else(|| "openid profile email offline_access".into());
    let scope = narrow_scope(&requested, &allowed);
    let body = token_response(st, &user.id, Some(&user.username), &st.config.issuer, &client_id, &scope, true).await?;
    store::audit(&st.db, &user.id, "token.issue", Some(&client_id), None, Some("password")).await;
    Ok(Json(body))
}

/// Verify a TOTP code or a single-use recovery code for an MFA-enabled user.
pub async fn verify_second_factor(
    st: &SharedState,
    user: &store::UserRow,
    otp: Option<&str>,
) -> ApiResult<()> {
    let otp = otp.ok_or(ApiError::Unauthorized("mfa_required".into()))?;
    let secret = user
        .mfa_secret
        .as_deref()
        .ok_or_else(|| ApiError::Internal("mfa enabled without secret".into()))?;
    // Enforce one-time use: only accept a TOTP step newer than the last one
    // consumed, then advance the high-water mark so the code cannot be replayed.
    let min_step = user.mfa_last_step.map(|s| s.saturating_add(1) as u64).unwrap_or(0);
    if let Some(step) =
        infinity_core::mfa::verify_totp_step(secret, otp, &st.config.mfa_issuer, &user.email, min_step)
            .unwrap_or(None)
    {
        store::set_mfa_last_step(&st.db, &user.id, step as i64).await?;
        return Ok(());
    }
    // Fall back to recovery code.
    let hash = infinity_core::mfa::hash_recovery_code(otp);
    if store::consume_recovery_code(&st.db, &user.id, &hash).await? {
        store::audit(&st.db, &user.id, "mfa.recovery_used", None, None, None).await;
        return Ok(());
    }
    Err(ApiError::Unauthorized("invalid mfa code".into()))
}

/// GET /userinfo — OIDC userinfo endpoint (Bearer access token).
pub async fn userinfo(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    let user = store::get_user_row(&st.db, &principal.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    Ok(Json(json!({
        "sub": user.id,
        "email": user.email,
        "email_verified": true,
        "preferred_username": user.username,
        "name": user.display_name,
        "roles": principal.roles,
    })))
}
