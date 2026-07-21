//! HTTP route table assembly.

pub mod audit;
pub mod auth_routes;
pub mod clients;
pub mod keys;
pub mod mfa;
pub mod oidc;
pub mod roles;
pub mod users;

use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post, put};
use axum::Router;

use crate::state::SharedState;

/// Per-IP rate-limiting middleware applied to all routes.
async fn rate_limit(
    axum::extract::State(st): axum::extract::State<SharedState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !st.ip_limiter.allow(&addr.ip().to_string()) {
        return crate::error::ApiError::TooManyRequests("global rate limit exceeded".into())
            .into_response();
    }
    next.run(req).await
}

/// Build the full application router.
pub fn router(state: SharedState) -> Router {
    let api = Router::new()
        // Health
        .route("/health", get(health))
        // OIDC / OAuth2
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route("/.well-known/jwks.json", get(oidc::jwks))
        .route("/oauth/authorize", get(oidc::authorize))
        .route("/oauth/token", post(oidc::token))
        .route("/userinfo", get(oidc::userinfo))
        // Dashboard session auth
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/logout", post(auth_routes::logout))
        .route("/auth/me", get(auth_routes::me))
        // MFA (self-service)
        .route("/mfa/enroll", post(mfa::enroll))
        .route("/mfa/activate", post(mfa::activate))
        .route("/mfa/disable", post(mfa::disable))
        // Admin: users
        .route("/admin/users", get(users::list).post(users::create))
        .route("/admin/users/:id", patch(users::update).delete(users::delete))
        // Admin: clients
        .route("/admin/clients", get(clients::list).post(clients::create))
        .route("/admin/clients/:client_id", delete(clients::delete))
        // Admin: roles
        .route("/admin/roles", get(roles::list))
        .route("/admin/roles", put(roles::upsert))
        // Admin: signing-key rotation
        .route("/admin/keys/rotate", post(keys::rotate))
        // Admin: audit
        .route("/admin/audit", get(audit::list));

    Router::new()
        .merge(api)
        .fallback(crate::assets::handler)
        .layer(axum::middleware::from_fn_with_state(state.clone(), rate_limit))
        .with_state(state)
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "status": "ok", "service": "infinity-id" }))
}
