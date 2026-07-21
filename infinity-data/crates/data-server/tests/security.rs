//! Integration tests for the privilege-escalation guard documented in the
//! top-level README's Security table:
//!
//! > Privilege escalation | Callers may only assign roles / grant permissions
//! > they already hold; the built-in `superadmin` role is protected from
//! > non-superadmins.
//!
//! These tests drive the real axum `Router` returned by `data_server::routes::router`
//! (via `tower::ServiceExt::oneshot`) against a real, freshly-migrated SQLite
//! database. Nothing about the RBAC logic or the admin route handlers is mocked.
//!
//! ## The real protection boundary (read from source, not assumed)
//!
//! `crates/data-server/src/routes/admin.rs` defines the guard as:
//!
//! - `caller_is_superadmin(p)`: true if the caller holds the `superadmin`
//!   *role*, OR the caller holds the literal wildcard permission `*:*`
//!   (see `rbac::any_permission(&p.permissions, "*:*")`). These two are
//!   treated as fully equivalent privilege levels *by design* — a caller
//!   with `*:*` already has every permission, so letting them also assign
//!   the `superadmin` role is not an escalation.
//! - `permission_grant_allowed(p, perms)`: a non-superadmin-equivalent caller
//!   may only grant a permission set that is a subset of permissions they
//!   already hold (checked with the same `granted:action` wildcard matching
//!   used everywhere else in RBAC, `data_core::rbac::any_permission`).
//! - `role_change_allowed` / `assigned_roles_allowed`: a non-superadmin-equivalent
//!   caller may not assign a role literally named `superadmin`, and may not
//!   assign any role whose *expanded* permission set they don't already
//!   fully hold.
//!
//! Critically, holding broad-but-partial wildcards short of `*:*` (e.g.
//! `users:*` + `roles:*`) does **not** make a caller superadmin-equivalent —
//! `any_permission(["users:*", "roles:*"], "*:*")` is `false`, because the
//! resource segment `users`/`roles` does not match the required resource
//! segment `*`. Only the literal `*:*` permission (or the `superadmin` role)
//! crosses the line. Test `wildcard_permission_holder_is_superadmin_equivalent`
//! below confirms that nuance explicitly, since it is easy to assume (as a
//! first guess) that the boundary is purely role-based.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use data_server::config::Config;
use data_server::ratelimit::IpRateLimiter;
use data_server::routes;
use data_server::state::AppState;
use data_server::store;
use data_server::throttle::LoginThrottle;
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tower::ServiceExt;

/// Spins up a fresh in-memory SQLite database, runs the real migrations, and
/// seeds the built-in roles (`superadmin` / `admin` / `user`) plus the
/// bootstrap admin account exactly as the production binary does at startup.
async fn test_state() -> Arc<AppState> {
    let opts: SqliteConnectOptions = "sqlite::memory:".parse().expect("parse sqlite url");
    let db = SqlitePoolOptions::new()
        .max_connections(1) // single connection so the in-memory DB persists across calls
        .connect_with(opts)
        .await
        .expect("connect in-memory sqlite");
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("run migrations");

    let config = Config {
        admin_email: "admin@infinity.local".into(),
        admin_password: "Sup3rStrongAdminPass!1".into(),
        ..Config::default()
    };
    store::seed(&db, &config).await.expect("seed database");

    Arc::new(AppState {
        db,
        config,
        indexes: tokio::sync::RwLock::new(HashMap::new()),
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(0), // unlimited, so it never interferes with these tests
    })
}

/// Creates a role directly via the store (test fixture setup only — this does
/// NOT exercise the HTTP guard; it just seeds data the guard will later be
/// checked against).
async fn seed_role(state: &Arc<AppState>, name: &str, perms: &[&str]) {
    let perms: Vec<String> = perms.iter().map(|p| p.to_string()).collect();
    store::upsert_role(&state.db, name, "fixture role", &perms)
        .await
        .expect("seed role");
}

/// Creates a real user, assigns real roles to them, and opens a real session
/// row in the database, returning a `Cookie` header value. This goes through
/// the exact same `Principal::from_request_parts` session-lookup path that
/// production requests use — nothing about authentication is mocked.
async fn login_as(state: &Arc<AppState>, email: &str, username: &str, roles: &[&str]) -> String {
    let user = store::create_user(&state.db, email, username, None, "irrelevant-password-1")
        .await
        .expect("create fixture user");
    let roles: Vec<String> = roles.iter().map(|r| r.to_string()).collect();
    store::set_user_roles(&state.db, &user.id, &roles)
        .await
        .expect("assign fixture roles");

    let raw_token = format!("test-session-{}", user.id);
    let hash = data_server::util::sha256_hex(&raw_token);
    store::create_session(&state.db, &hash, &user.id, 3600)
        .await
        .expect("create fixture session");
    format!("{}={}", data_server::auth::SESSION_COOKIE, raw_token)
}

/// Issues a request against the real router and returns (status, json body).
async fn call(state: &Arc<AppState>, method: &str, path: &str, cookie: &str, body: Value) -> (StatusCode, Value) {
    let app = routes::router(state.clone());
    // The real binary serves via `into_make_service_with_connect_info`, which
    // populates a `ConnectInfo<SocketAddr>` extension consumed by the global
    // IP rate-limit middleware. `oneshot` bypasses that layer, so the fixture
    // inserts the same extension a real TCP connection would provide.
    let peer: std::net::SocketAddr = ([127, 0, 0, 1], 12345).into();
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("cookie", cookie)
        .extension(axum::extract::ConnectInfo(peer))
        .body(Body::from(body.to_string()))
        .expect("build request");
    let response = app.oneshot(request).await.expect("router call");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

fn new_user_payload(email: &str, username: &str, roles: &[&str]) -> Value {
    json!({
        "email": email,
        "username": username,
        "password": "TargetUserPassword1!",
        "roles": roles,
    })
}

/// 1. Baseline: a non-superadmin caller who holds permission `widgets:write`
///    (via a custom role) CAN grant a role that carries only that permission
///    to another user. Proves legitimate, non-escalating grants still work.
#[tokio::test]
async fn non_superadmin_can_grant_permission_they_hold() {
    let state = test_state().await;
    seed_role(&state, "widget_editor", &["widgets:write"]).await;
    seed_role(&state, "user_admin", &["users:write"]).await;
    let cookie = login_as(
        &state,
        "granter1@infinity.local",
        "granter1",
        &["widget_editor", "user_admin"],
    )
    .await;

    let (status, body) = call(
        &state,
        "POST",
        "/admin/users",
        &cookie,
        new_user_payload("target1@infinity.local", "target1", &["widget_editor"]),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "granting a held permission should succeed, got body: {body}"
    );
    let roles = body["user"]["roles"]
        .as_array()
        .expect("roles array in response");
    assert!(
        roles.iter().any(|r| r == "widget_editor"),
        "target user should have received the widget_editor role: {body}"
    );
}

/// 2. A non-superadmin caller who holds `widgets:write` and `users:write`
///    CANNOT grant a role that carries `secrets:read`, a permission they do
///    not hold themselves. This is the core self-escalation guard.
#[tokio::test]
async fn non_superadmin_cannot_grant_permission_they_do_not_hold() {
    let state = test_state().await;
    seed_role(&state, "widget_editor", &["widgets:write"]).await;
    seed_role(&state, "user_admin", &["users:write"]).await;
    seed_role(&state, "secret_reader", &["secrets:read"]).await;
    let cookie = login_as(
        &state,
        "granter2@infinity.local",
        "granter2",
        &["widget_editor", "user_admin"],
    )
    .await;

    let (status, body) = call(
        &state,
        "POST",
        "/admin/users",
        &cookie,
        new_user_payload("target2@infinity.local", "target2", &["secret_reader"]),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "granting a permission the caller lacks must be rejected, got body: {body}"
    );
    assert_eq!(body["error"], "access_denied");
}

/// 3. A non-superadmin caller who holds broad-but-partial wildcards
///    (`users:*` and `roles:*`, short of the full `*:*`) CANNOT assign the
///    built-in `superadmin` role to anyone. Confirms the real boundary is not
///    "any wildcard permission" but specifically full (`*:*`) or the
///    `superadmin` role itself.
#[tokio::test]
async fn non_superadmin_with_broad_wildcards_cannot_assign_superadmin() {
    let state = test_state().await;
    seed_role(&state, "power_user", &["users:*", "roles:*"]).await;
    let cookie = login_as(
        &state,
        "poweruser@infinity.local",
        "poweruser",
        &["power_user"],
    )
    .await;

    let (status, body) = call(
        &state,
        "POST",
        "/admin/users",
        &cookie,
        new_user_payload("target3@infinity.local", "target3", &["superadmin"]),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a broad-but-partial wildcard holder must not be able to assign superadmin, got body: {body}"
    );
    assert_eq!(body["error"], "access_denied");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or_default()
            .contains("superadmin"),
        "error should explain the superadmin restriction: {body}"
    );
}

/// 4. Positive control: the actual seeded `superadmin` user CAN grant a
///    permission it did not previously hold as an explicit string (via its
///    `*:*` wildcard) and CAN assign the `superadmin` role to another user.
///    Proves the guard is a real allow/deny check, not a blanket rejection.
#[tokio::test]
async fn superadmin_can_grant_permissions_and_assign_superadmin() {
    let state = test_state().await;
    let cookie = login_as(
        &state,
        "sa@infinity.local",
        "sa_user",
        &[data_core::rbac::ROLE_SUPERADMIN],
    )
    .await;

    // Can create a brand new role carrying an arbitrary permission.
    let (status, body) = call(
        &state,
        "PUT",
        "/admin/roles",
        &cookie,
        json!({
            "name": "arbitrary_role",
            "description": "granted by superadmin",
            "permissions": ["anything:goes", "totally:unheld-elsewhere"],
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "superadmin should be able to grant any permission, got body: {body}"
    );

    // Can assign the superadmin role to another user.
    let (status, body) = call(
        &state,
        "POST",
        "/admin/users",
        &cookie,
        new_user_payload(
            "target4@infinity.local",
            "target4",
            &[data_core::rbac::ROLE_SUPERADMIN],
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "superadmin should be able to assign superadmin, got body: {body}"
    );
    let roles = body["user"]["roles"].as_array().expect("roles array");
    assert!(roles.iter().any(|r| r == "superadmin"));
}

/// 5. Boundary confirmation: a caller who does NOT hold the `superadmin`
///    *role* but does hold the literal wildcard permission `*:*` (via a
///    differently-named custom role) IS treated as superadmin-equivalent by
///    `caller_is_superadmin` and CAN assign the `superadmin` role. This is
///    the precise, code-confirmed boundary — not "any broad permission",
///    but "role == superadmin OR permission == *:*" exactly.
#[tokio::test]
async fn wildcard_permission_holder_is_superadmin_equivalent() {
    let state = test_state().await;
    seed_role(&state, "godmode", &["*:*"]).await;
    let cookie = login_as(&state, "godmode@infinity.local", "godmode_user", &["godmode"]).await;

    let (status, body) = call(
        &state,
        "POST",
        "/admin/users",
        &cookie,
        new_user_payload(
            "target5@infinity.local",
            "target5",
            &[data_core::rbac::ROLE_SUPERADMIN],
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a literal *:* permission holder is superadmin-equivalent by design, got body: {body}"
    );
}
