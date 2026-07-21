//! Integration tests for the security-critical HTTP surface of `observe-server`:
//! login lockout/throttling, the ingest-key vs session auth boundary, and
//! alert-rule RBAC. These exercise the real axum `Router` (via
//! `tower::ServiceExt::oneshot`) against a real temp-file SQLite database with
//! migrations actually applied — no mocks.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::connect_info::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tower::ServiceExt;

use observe_server::config::Config;
use observe_server::ratelimit::IpRateLimiter;
use observe_server::routes;
use observe_server::state::AppState;
use observe_server::throttle::LoginThrottle;

const ADMIN_PASSWORD: &str = "Sup3r-Secret-Admin-Pass!";
const VIEWER_PASSWORD: &str = "Sup3r-Secret-Viewer-Pass!";

/// A running test instance: the router plus the raw credentials/tokens seeded
/// into its database, so tests can exercise auth without knowing internals.
struct TestApp {
    router: Router,
    db_path: PathBuf,
    admin_email: String,
    viewer_email: String,
    ingest_token: String,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.db_path);
    }
}

async fn spawn_app() -> TestApp {
    spawn_app_with_throttle(LoginThrottle::new(3, 60, 60)).await
}

async fn spawn_app_with_throttle(login_throttle: LoginThrottle) -> TestApp {
    let mut db_path = std::env::temp_dir();
    db_path.push(format!("observe-test-{}.sqlite", uuid::Uuid::new_v4()));

    let opts = SqliteConnectOptions::from_str(&format!(
        "sqlite://{}",
        db_path.to_str().expect("utf8 temp path")
    ))
    .expect("valid sqlite url")
    .create_if_missing(true);
    let db: SqlitePool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .expect("connect to temp sqlite db");
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("run migrations");

    let admin_email = "admin@example.test".to_string();
    let config = Config {
        admin_email: admin_email.clone(),
        admin_password: ADMIN_PASSWORD.to_string(),
        session_ttl_secs: 3600,
        // High enough that the global per-IP limiter never interferes with
        // the (small, deliberate) burst of requests these tests send.
        global_rate_limit_per_min: 1_000_000,
        ..Config::default()
    };

    // Seeds the admin user (using config.admin_password above) and an
    // initial ingest key (raw token only logged, not returned) — create our
    // own ingest key afterwards so the test knows the raw token.
    observe_server::store::seed(&db, &config)
        .await
        .expect("seed database");

    let viewer_email = "viewer@example.test".to_string();
    let viewer_hash =
        observe_core::password::hash_password(VIEWER_PASSWORD).expect("hash viewer password");
    sqlx::query(
        "INSERT INTO users (id, email, username, display_name, password_hash, role, created_at)
         VALUES (?, ?, 'viewer', 'Viewer', ?, 'viewer', ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&viewer_email)
    .bind(&viewer_hash)
    .bind(observe_server::store::now())
    .execute(&db)
    .await
    .expect("insert viewer user");

    let (_, ingest_token) = observe_server::store::create_ingest_key(&db, "test-key")
        .await
        .expect("create ingest key");

    let state = Arc::new(AppState {
        db,
        config,
        login_throttle,
        ip_limiter: IpRateLimiter::new(1_000_000),
    });

    TestApp {
        router: routes::router(state),
        db_path,
        admin_email,
        viewer_email,
        ingest_token,
    }
}

/// Builds a request with a fake connect-info extension inserted (required by
/// the router's per-IP rate-limit middleware, which normally gets this from
/// `into_make_service_with_connect_info` — not present under `oneshot`).
fn req_builder(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder().method(method).uri(uri)
}

fn with_connect_info(builder: axum::http::request::Builder, body: Body) -> Request<Body> {
    let mut req = builder.body(body).expect("build request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    req
}

async fn send(router: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("router call");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

async fn login(router: &Router, email: &str, password: &str) -> (StatusCode, Option<String>, Value) {
    let payload = json!({ "email": email, "password": password }).to_string();
    let req = with_connect_info(
        req_builder("POST", "/auth/login").header(header::CONTENT_TYPE, "application/json"),
        Body::from(payload),
    );
    let resp = router.clone().oneshot(req).await.expect("router call");
    let status = resp.status();
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| raw.split(';').next())
        .map(|s| s.to_string());
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, cookie, body)
}

// ---------------------------------------------------------------------
// 1. Login lockout / throttling
// ---------------------------------------------------------------------

/// After `max_fails` wrong-password attempts against the same account, the
/// account is locked out — and critically, a *subsequent attempt with the
/// correct password* is still rejected (429, not 200) while locked. This is
/// what distinguishes a real lockout from mere password verification.
#[tokio::test]
async fn login_lockout_blocks_even_correct_password_while_locked() {
    let app = spawn_app().await; // LoginThrottle::new(3, 60, 60): locks after 3 fails.

    for attempt in 1..=3 {
        let (status, _, body) = login(&app.router, &app.admin_email, "totally-wrong-password").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt} should be a plain auth failure, got body {body:?}"
        );
    }

    // Now retry with the CORRECT password: must still be rejected because
    // the account is locked out, not because the password is wrong.
    let (status, cookie, body) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "correct password during lockout window must still be rejected, got body {body:?}"
    );
    assert!(cookie.is_none(), "no session should be issued while locked out");
}

/// Sanity check that the correct password *does* work absent any lockout —
/// proves the lockout test above isn't just permanently rejecting logins.
#[tokio::test]
async fn login_succeeds_with_correct_password_when_not_locked_out() {
    let app = spawn_app().await;
    let (status, cookie, body) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert!(cookie.is_some(), "a session cookie must be issued on success");
}

/// A failed attempt against one account must not lock out an unrelated
/// account — the throttle key is per-identity, not global.
#[tokio::test]
async fn login_lockout_is_scoped_per_account() {
    let app = spawn_app().await;

    for _ in 1..=3 {
        let (status, _, _) = login(&app.router, &app.admin_email, "wrong-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // Admin account is now locked; viewer account must be unaffected.
    let (status, cookie, body) = login(&app.router, &app.viewer_email, VIEWER_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert!(cookie.is_some());
}

// ---------------------------------------------------------------------
// 2. Ingest-key auth boundary
// ---------------------------------------------------------------------

/// An ingest key can reach ingest endpoints (POST /v1/logs).
#[tokio::test]
async fn ingest_key_can_reach_ingest_endpoint() {
    let app = spawn_app().await;
    let payload = json!([{
        "level": "info",
        "service": "test-svc",
        "message": "hello from ingest key",
    }])
    .to_string();
    let req = with_connect_info(
        req_builder("POST", "/v1/logs")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {}", app.ingest_token)),
        Body::from(payload),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert_eq!(body["accepted"], json!(1));
}

/// The same ingest key must be rejected from an admin/session-only endpoint
/// (GET /v1/alerts/rules requires a `Principal`, i.e. a real session).
#[tokio::test]
async fn ingest_key_is_rejected_from_session_only_endpoint() {
    let app = spawn_app().await;
    let req = with_connect_info(
        req_builder("GET", "/v1/alerts/rules")
            .header(header::AUTHORIZATION, format!("Bearer {}", app.ingest_token)),
        Body::empty(),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an ingest key must not authenticate a session-only endpoint, got body {body:?}"
    );
}

/// A request with no credentials at all is rejected from both endpoint
/// classes.
#[tokio::test]
async fn no_credentials_are_rejected_from_both_ingest_and_admin_endpoints() {
    let app = spawn_app().await;

    let ingest_req = with_connect_info(
        req_builder("POST", "/v1/logs").header(header::CONTENT_TYPE, "application/json"),
        Body::from(json!([]).to_string()),
    );
    let (status, body) = send(&app.router, ingest_req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body:?}");

    let admin_req = with_connect_info(req_builder("GET", "/v1/alerts/rules"), Body::empty());
    let (status, body) = send(&app.router, admin_req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body:?}");
}

/// A valid session (not an ingest key) must not be usable against an
/// ingest-only endpoint — the boundary holds in both directions.
#[tokio::test]
async fn session_cookie_is_rejected_from_ingest_only_endpoint() {
    let app = spawn_app().await;
    let (_, cookie, _) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    let cookie = cookie.expect("admin login should succeed");

    let req = with_connect_info(
        req_builder("POST", "/v1/logs")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie),
        Body::from(json!([]).to_string()),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a dashboard session must not authenticate the ingest key surface, got body {body:?}"
    );
}

// ---------------------------------------------------------------------
// 3. Alert-rule RBAC
// ---------------------------------------------------------------------

fn create_rule_payload() -> String {
    json!({
        "name": "too many errors",
        "kind": "error_log_count",
        "target": "",
        "threshold": 5.0,
        "window_secs": 300
    })
    .to_string()
}

/// A viewer (non-admin, lacking `alerts:create`) must not be able to create
/// an alert rule.
#[tokio::test]
async fn viewer_cannot_create_alert_rule() {
    let app = spawn_app().await;
    let (_, cookie, _) = login(&app.router, &app.viewer_email, VIEWER_PASSWORD).await;
    let cookie = cookie.expect("viewer login should succeed");

    let req = with_connect_info(
        req_builder("POST", "/v1/alerts/rules")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie),
        Body::from(create_rule_payload()),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer must be forbidden from creating alert rules, got body {body:?}"
    );
}

/// An admin (or any principal with `alerts:create`) can create an alert
/// rule.
#[tokio::test]
async fn admin_can_create_alert_rule() {
    let app = spawn_app().await;
    let (_, cookie, _) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    let cookie = cookie.expect("admin login should succeed");

    let req = with_connect_info(
        req_builder("POST", "/v1/alerts/rules")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie),
        Body::from(create_rule_payload()),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert_eq!(body["rule"]["name"], json!("too many errors"));
}

/// A viewer also must not be able to delete an alert rule created by an
/// admin (covers the `alerts:delete` permission, not just `alerts:create`).
#[tokio::test]
async fn viewer_cannot_delete_alert_rule() {
    let app = spawn_app().await;
    let (_, admin_cookie, _) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    let admin_cookie = admin_cookie.expect("admin login should succeed");

    let create_req = with_connect_info(
        req_builder("POST", "/v1/alerts/rules")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, admin_cookie),
        Body::from(create_rule_payload()),
    );
    let (status, body) = send(&app.router, create_req).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    let rule_id = body["rule"]["id"].as_str().expect("rule id").to_string();

    let (_, viewer_cookie, _) = login(&app.router, &app.viewer_email, VIEWER_PASSWORD).await;
    let viewer_cookie = viewer_cookie.expect("viewer login should succeed");
    let delete_req = with_connect_info(
        req_builder("DELETE", &format!("/v1/alerts/rules/{rule_id}"))
            .header(header::COOKIE, viewer_cookie),
        Body::empty(),
    );
    let (status, body) = send(&app.router, delete_req).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer must be forbidden from deleting alert rules, got body {body:?}"
    );
}
