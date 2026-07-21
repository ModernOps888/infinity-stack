//! Integration tests for security-critical HTTP surface that had never been
//! exercised by an automated test: the OAuth2 authorization-code + PKCE
//! flow, refresh-token rotation/reuse detection, and TOTP MFA replay
//! protection.
//!
//! Each test drives the *real* axum `Router` (`infinity_server::routes::router`)
//! in-process via `tower::ServiceExt::oneshot` against a fresh temp-file
//! SQLite database with the same migrations `main.rs` applies at startup —
//! no mocks, no live TCP port.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http_body_util::BodyExt;
use rand::Rng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tower::ServiceExt;
use totp_rs::{Algorithm, Secret, TOTP};

use infinity_core::keys::KeyRing;
use infinity_server::config::Config;
use infinity_server::ratelimit::IpRateLimiter;
use infinity_server::state::{AppState, SharedState};
use infinity_server::store::{self, NewClient, NewUser};
use infinity_server::throttle::LoginThrottle;
use infinity_server::routes;

// ---------------------------------------------------------------------------
// Test fixtures / helpers
// ---------------------------------------------------------------------------

/// Build a fresh `AppState` backed by a unique temp-file SQLite database with
/// migrations applied, mirroring exactly what `main.rs` does at startup.
async fn test_state() -> SharedState {
    let db_path =
        std::env::temp_dir().join(format!("infinity-id-security-test-{}.sqlite", uuid::Uuid::new_v4()));
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))
        .expect("parse sqlite url")
        .create_if_missing(true);
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .expect("connect sqlite");
    sqlx::migrate!("./migrations").run(&db).await.expect("run migrations");

    let key_dir =
        std::env::temp_dir().join(format!("infinity-id-security-test-key-{}", uuid::Uuid::new_v4()));
    let key_path = key_dir.join("signing_key.pem");
    let key = KeyRing::load_or_generate(&key_path, 3600).expect("generate signing key");

    // Disable the global per-IP limiter so it can't interfere with tests that
    // fire several requests back-to-back.
    let config = Config { global_rate_limit_per_min: 0, ..Config::default() };

    Arc::new(AppState {
        db,
        key: RwLock::new(key),
        key_path,
        config,
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(0),
    })
}

/// Send a request through the real router. Manually inserts a `ConnectInfo`
/// extension (normally supplied by `into_make_service_with_connect_info` in
/// `main.rs`) because the per-IP rate-limit middleware extracts it.
async fn send(app: &Router, mut req: Request<Body>) -> Response {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    app.clone().oneshot(req).await.expect("router call")
}

async fn json_body(resp: Response) -> Value {
    let bytes = resp.into_body().collect().await.expect("collect body").to_bytes();
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("invalid json body: {e}: {bytes:?}"))
    }
}

async fn create_user(db: &sqlx::SqlitePool, email: &str, username: &str, password: &str) -> String {
    let hash = infinity_core::password::hash_password(password).expect("hash password");
    store::create_user(
        db,
        NewUser {
            email,
            username,
            display_name: None,
            password_hash: &hash,
            roles: &[],
        },
    )
    .await
    .expect("create user")
}

/// Register a public (PKCE-only, no client secret) OAuth client.
async fn create_public_client(db: &sqlx::SqlitePool, redirect_uri: &str) -> String {
    store::create_client(
        db,
        NewClient {
            name: "test-client",
            secret_hash: None,
            redirect_uris: &[redirect_uri.to_string()],
            grant_types: &["authorization_code".into(), "refresh_token".into()],
            scopes: &["openid".into(), "profile".into(), "offline_access".into()],
            public: true,
        },
    )
    .await
    .expect("create client")
}

/// POST /auth/login. Returns (status, session cookie value if any, json body).
async fn login(app: &Router, email: &str, password: &str, otp: Option<&str>) -> (StatusCode, Option<String>, Value) {
    let mut body = json!({ "email": email, "password": password });
    if let Some(otp) = otp {
        body["otp"] = json!(otp);
    }
    let req = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = send(app, req).await;
    let status = resp.status();
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap().to_string());
    let json = json_body(resp).await;
    (status, cookie, json)
}

/// A PKCE `code_verifier` / S256 `code_challenge` pair.
struct Pkce {
    verifier: String,
    challenge: String,
}

fn random_pkce() -> Pkce {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();
    let verifier: String = (0..64).map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char).collect();
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
    Pkce { verifier, challenge }
}

/// Drive GET /oauth/authorize with a valid session cookie and PKCE challenge;
/// returns the `code` extracted from the redirect's `Location` header.
async fn authorize(app: &Router, cookie: &str, client_id: &str, redirect_uri: &str, pkce: &Pkce) -> String {
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope=openid&state=xyz123&code_challenge={}&code_challenge_method=S256",
        pkce.challenge
    );
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    let resp = send(app, req).await;
    assert!(
        resp.status().is_redirection(),
        "expected a redirect from /oauth/authorize, got {}: {:?}",
        resp.status(),
        json_body(resp).await
    );
    let location = resp
        .headers()
        .get(header::LOCATION)
        .expect("Location header on authorize redirect")
        .to_str()
        .unwrap()
        .to_string();
    let query = location.split_once('?').expect("redirect has query string").1;
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix("code=").map(|c| c.to_string()))
        .expect("redirect contains code=")
}

/// POST /oauth/token with an arbitrary form body, returning (status, json).
async fn token_request(app: &Router, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let body = form
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let resp = send(app, req).await;
    let status = resp.status();
    (status, json_body(resp).await)
}

const REDIRECT_URI: &str = "https://client.example/callback";

/// Full setup used by both the PKCE and refresh-rotation tests: a user, a
/// public PKCE client, a logged-in session cookie, and the router.
async fn setup_authorize_flow() -> (Router, SharedState, String, String, String) {
    let state = test_state().await;
    create_user(&state.db, "alice@example.com", "alice", "correct horse battery staple").await;
    let client_id = create_public_client(&state.db, REDIRECT_URI).await;
    let app = routes::router(state.clone());
    let (status, cookie, _) = login(&app, "alice@example.com", "correct horse battery staple", None).await;
    assert_eq!(status, StatusCode::OK, "setup login must succeed");
    let cookie = cookie.expect("login must set a session cookie");
    (app, state, client_id, cookie, REDIRECT_URI.to_string())
}

// ---------------------------------------------------------------------------
// 1. OAuth2 authorization-code + PKCE flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oauth_authorize_and_token_pkce_success() {
    let (app, _state, client_id, cookie, redirect_uri) = setup_authorize_flow().await;
    let pkce = random_pkce();

    let code = authorize(&app, &cookie, &client_id, &redirect_uri, &pkce).await;

    let (status, body) = token_request(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
            ("code_verifier", &pkce.verifier),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "valid PKCE exchange must succeed: {body:?}");
    assert!(body["access_token"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(body["refresh_token"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(
        body["id_token"].as_str().is_some_and(|s| !s.is_empty()),
        "openid scope must yield an id_token"
    );
}

#[tokio::test]
async fn oauth_token_rejects_wrong_code_verifier() {
    let (app, _state, client_id, cookie, redirect_uri) = setup_authorize_flow().await;
    let pkce = random_pkce();
    let code = authorize(&app, &cookie, &client_id, &redirect_uri, &pkce).await;

    let (status, body) = token_request(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
            ("code_verifier", "totally-wrong-verifier-value-xyz"),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "wrong code_verifier must be rejected: {body:?}"
    );
    assert!(body["access_token"].is_null());
}

#[tokio::test]
async fn oauth_token_rejects_missing_code_verifier() {
    let (app, _state, client_id, cookie, redirect_uri) = setup_authorize_flow().await;
    let pkce = random_pkce();
    let code = authorize(&app, &cookie, &client_id, &redirect_uri, &pkce).await;

    // No code_verifier at all — must be rejected the same as a wrong one.
    let (status, body) = token_request(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "missing code_verifier must be rejected: {body:?}");
}

// ---------------------------------------------------------------------------
// 2. Refresh-token rotation + reuse detection
// ---------------------------------------------------------------------------

/// Real behavior confirmed by reading `crates/infinity-server/src/routes/oidc.rs`
/// (`grant_refresh`) and `crates/infinity-server/src/store/mod.rs`
/// (`revoke_refresh_family`): replaying an already-rotated refresh token does
/// **not** just invalidate that one token — it revokes every refresh token for
/// that user+client pair (the whole "family"/session for that client), per the
/// `oauth.refresh_reuse` audit event and the explicit
/// `revoke_refresh_family(user_id, client_id)` call. This test asserts that
/// full-family revocation, not single-token revocation.
#[tokio::test]
async fn refresh_token_reuse_revokes_whole_family() {
    let (app, _state, client_id, cookie, redirect_uri) = setup_authorize_flow().await;
    let pkce = random_pkce();
    let code = authorize(&app, &cookie, &client_id, &redirect_uri, &pkce).await;
    let (status, body) = token_request(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
            ("code_verifier", &pkce.verifier),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initial code exchange must succeed: {body:?}");
    let refresh1 = body["refresh_token"].as_str().unwrap().to_string();

    // Rotate: exchanging refresh1 must succeed and mint a *different* refresh2,
    // and must invalidate refresh1.
    let (status, body) =
        token_request(&app, &[("grant_type", "refresh_token"), ("refresh_token", &refresh1), ("client_id", &client_id)])
            .await;
    assert_eq!(status, StatusCode::OK, "first refresh must succeed: {body:?}");
    let refresh2 = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(refresh1, refresh2, "rotation must issue a brand new refresh token");

    // Replay the rotated-away refresh1 — must be rejected.
    let (status, body) =
        token_request(&app, &[("grant_type", "refresh_token"), ("refresh_token", &refresh1), ("client_id", &client_id)])
            .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "replaying an already-rotated refresh token must be rejected: {body:?}"
    );

    // The just-issued refresh2 must ALSO now be dead: reuse of refresh1 is a
    // compromise signal that revokes the whole user+client refresh-token
    // family, not just the replayed token.
    let (status, body) =
        token_request(&app, &[("grant_type", "refresh_token"), ("refresh_token", &refresh2), ("client_id", &client_id)])
            .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "reuse detection must revoke the WHOLE refresh-token family, so the \
         still-fresh refresh2 must also be rejected afterwards: {body:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. TOTP MFA replay-window rejection
// ---------------------------------------------------------------------------

fn current_totp_code(secret_b32: &str, issuer: &str, account: &str) -> String {
    let bytes = Secret::Encoded(secret_b32.to_string()).to_bytes().expect("decode base32 secret");
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, Some(issuer.to_string()), account.to_string())
        .expect("build TOTP");
    totp.generate_current().expect("generate current TOTP code")
}

#[tokio::test]
async fn totp_code_cannot_be_replayed_within_its_validity_window() {
    let state = test_state().await;
    let email = "bob@example.com";
    let password = "correct horse battery staple";
    create_user(&state.db, email, "bob", password).await;
    let app = routes::router(state.clone());

    // Log in once (no MFA yet) to get a session for the self-service MFA API.
    let (status, cookie, _) = login(&app, email, password, None).await;
    assert_eq!(status, StatusCode::OK);
    let cookie = cookie.unwrap();

    // Enroll: get the TOTP secret.
    let req = Request::builder()
        .method("POST")
        .uri("/mfa/enroll")
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let secret = body["secret"].as_str().expect("enroll returns a secret").to_string();

    let code = current_totp_code(&secret, &state.config.mfa_issuer, email);

    // Activate using the current code.
    let req = Request::builder()
        .method("POST")
        .uri("/mfa/activate")
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "code": code }).to_string()))
        .unwrap();
    let resp = send(&app, req).await;
    let status = resp.status();
    let activate_body = json_body(resp).await;
    assert_eq!(status, StatusCode::OK, "activation with a fresh code must succeed: {activate_body:?}");

    // First login with this TOTP code as the second factor: must succeed, and
    // it should record this step as consumed (one-time-use high-water mark).
    let (status, _cookie2, body) = login(&app, email, password, Some(&code)).await;
    assert_eq!(status, StatusCode::OK, "first use of the TOTP code at login must succeed: {body:?}");

    // Replay: logging in again with the exact same TOTP code (still within its
    // ±1 step / 30s validity window) must now be rejected.
    let (status, _cookie3, body) = login(&app, email, password, Some(&code)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "reusing the same TOTP code a second time must be rejected as a replay: {body:?}"
    );
}
