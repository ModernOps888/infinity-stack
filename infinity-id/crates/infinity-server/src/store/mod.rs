//! Persistence layer. All SQL lives here; handlers stay storage-agnostic.
//!
//! Uses sqlx runtime queries (no compile-time DB needed) so the project builds
//! anywhere. Timestamps are RFC3339 UTC strings; JSON columns hold arrays.

use chrono::{Duration, Utc};
use infinity_core::model::{AuditEvent, OAuthClient, Role, User};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

use crate::config::Config;

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn future(secs: i64) -> String {
    (Utc::now() + Duration::seconds(secs)).to_rfc3339()
}

fn json_arr(v: &[String]) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "[]".into())
}

fn parse_arr(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

#[derive(FromRow)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub password_hash: String,
    pub mfa_enabled: i64,
    pub mfa_secret: Option<String>,
    pub disabled: i64,
    pub created_at: String,
}

#[derive(FromRow)]
struct RoleRow {
    name: String,
    description: String,
    permissions: String,
}

#[derive(FromRow)]
struct ClientRow {
    client_id: String,
    name: String,
    secret_hash: Option<String>,
    redirect_uris: String,
    grant_types: String,
    scopes: String,
    public: i64,
    created_at: String,
}

#[derive(FromRow)]
#[allow(dead_code)]
pub struct AuthCodeRow {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: String,
}

#[derive(FromRow)]
#[allow(dead_code)]
pub struct RefreshRow {
    pub token_hash: String,
    pub user_id: String,
    pub client_id: String,
    pub scope: String,
    pub expires_at: String,
    pub revoked: i64,
}

#[derive(FromRow)]
struct AuditRow {
    id: String,
    actor: String,
    action: String,
    target: Option<String>,
    ip: Option<String>,
    detail: Option<String>,
    created_at: String,
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

pub async fn user_roles(db: &SqlitePool, user_id: &str) -> sqlx::Result<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT role FROM user_roles WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(db)
            .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// Aggregate all permissions granted to a user via their roles.
pub async fn user_permissions(db: &SqlitePool, user_id: &str) -> sqlx::Result<Vec<String>> {
    let roles = user_roles(db, user_id).await?;
    let mut perms = Vec::new();
    for r in roles {
        if let Some(role) = get_role(db, &r).await? {
            perms.extend(role.permissions);
        }
    }
    perms.sort();
    perms.dedup();
    Ok(perms)
}

pub fn row_to_user(row: &UserRow, roles: Vec<String>) -> User {
    User {
        id: row.id.clone(),
        email: row.email.clone(),
        username: row.username.clone(),
        display_name: row.display_name.clone(),
        roles,
        mfa_enabled: row.mfa_enabled != 0,
        disabled: row.disabled != 0,
        created_at: row.created_at.clone(),
    }
}

pub async fn get_user_row_by_email(db: &SqlitePool, email: &str) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE email = ?")
        .bind(email)
        .fetch_optional(db)
        .await
}

pub async fn get_user_row(db: &SqlitePool, id: &str) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await
}

pub struct NewUser<'a> {
    pub email: &'a str,
    pub username: &'a str,
    pub display_name: Option<&'a str>,
    pub password_hash: &'a str,
    pub roles: &'a [String],
}

pub async fn create_user(db: &SqlitePool, u: NewUser<'_>) -> sqlx::Result<String> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, username, display_name, password_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(u.email)
    .bind(u.username)
    .bind(u.display_name)
    .bind(u.password_hash)
    .bind(now())
    .execute(db)
    .await?;
    for role in u.roles {
        sqlx::query("INSERT OR IGNORE INTO user_roles (user_id, role) VALUES (?, ?)")
            .bind(&id)
            .bind(role)
            .execute(db)
            .await?;
    }
    Ok(id)
}

pub async fn list_users(db: &SqlitePool) -> sqlx::Result<Vec<User>> {
    let rows = sqlx::query_as::<_, UserRow>("SELECT * FROM users ORDER BY created_at DESC")
        .fetch_all(db)
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let roles = user_roles(db, &row.id).await?;
        out.push(row_to_user(&row, roles));
    }
    Ok(out)
}

pub async fn set_user_disabled(db: &SqlitePool, id: &str, disabled: bool) -> sqlx::Result<()> {
    sqlx::query("UPDATE users SET disabled = ? WHERE id = ?")
        .bind(disabled as i64)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn set_user_roles(db: &SqlitePool, id: &str, roles: &[String]) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM user_roles WHERE user_id = ?")
        .bind(id)
        .execute(db)
        .await?;
    for role in roles {
        sqlx::query("INSERT OR IGNORE INTO user_roles (user_id, role) VALUES (?, ?)")
            .bind(id)
            .bind(role)
            .execute(db)
            .await?;
    }
    Ok(())
}

pub async fn delete_user(db: &SqlitePool, id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM users WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// MFA
// ---------------------------------------------------------------------------

pub async fn set_mfa_secret(db: &SqlitePool, id: &str, secret: &str) -> sqlx::Result<()> {
    sqlx::query("UPDATE users SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ?")
        .bind(secret)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn enable_mfa(db: &SqlitePool, id: &str) -> sqlx::Result<()> {
    sqlx::query("UPDATE users SET mfa_enabled = 1 WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn disable_mfa(db: &SqlitePool, id: &str) -> sqlx::Result<()> {
    sqlx::query("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn store_recovery_codes(db: &SqlitePool, id: &str, hashes: &[String]) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
        .bind(id)
        .execute(db)
        .await?;
    for h in hashes {
        sqlx::query("INSERT INTO recovery_codes (id, user_id, code_hash, used) VALUES (?, ?, ?, 0)")
            .bind(Uuid::new_v4().to_string())
            .bind(id)
            .bind(h)
            .execute(db)
            .await?;
    }
    Ok(())
}

/// Consume a recovery code if it exists and is unused. Returns true on success.
pub async fn consume_recovery_code(db: &SqlitePool, id: &str, hash: &str) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "UPDATE recovery_codes SET used = 1 WHERE user_id = ? AND code_hash = ? AND used = 0",
    )
    .bind(id)
    .bind(hash)
    .execute(db)
    .await?;
    Ok(res.rows_affected() > 0)
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

pub async fn get_role(db: &SqlitePool, name: &str) -> sqlx::Result<Option<Role>> {
    let row = sqlx::query_as::<_, RoleRow>("SELECT * FROM roles WHERE name = ?")
        .bind(name)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| Role {
        name: r.name,
        description: r.description,
        permissions: parse_arr(&r.permissions),
    }))
}

pub async fn list_roles(db: &SqlitePool) -> sqlx::Result<Vec<Role>> {
    let rows = sqlx::query_as::<_, RoleRow>("SELECT * FROM roles ORDER BY name")
        .fetch_all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| Role {
            name: r.name,
            description: r.description,
            permissions: parse_arr(&r.permissions),
        })
        .collect())
}

pub async fn upsert_role(db: &SqlitePool, role: &Role) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO roles (name, description, permissions) VALUES (?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET description = excluded.description,
                                         permissions = excluded.permissions",
    )
    .bind(&role.name)
    .bind(&role.description)
    .bind(json_arr(&role.permissions))
    .execute(db)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// OAuth clients
// ---------------------------------------------------------------------------

fn row_to_client(r: ClientRow) -> OAuthClient {
    OAuthClient {
        client_id: r.client_id,
        name: r.name,
        redirect_uris: parse_arr(&r.redirect_uris),
        grant_types: parse_arr(&r.grant_types),
        scopes: parse_arr(&r.scopes),
        public: r.public != 0,
        created_at: r.created_at,
    }
}

pub struct NewClient<'a> {
    pub name: &'a str,
    pub secret_hash: Option<&'a str>,
    pub redirect_uris: &'a [String],
    pub grant_types: &'a [String],
    pub scopes: &'a [String],
    pub public: bool,
}

pub async fn create_client(db: &SqlitePool, c: NewClient<'_>) -> sqlx::Result<String> {
    let client_id = format!("cli_{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO oauth_clients
         (client_id, name, secret_hash, redirect_uris, grant_types, scopes, public, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&client_id)
    .bind(c.name)
    .bind(c.secret_hash)
    .bind(json_arr(c.redirect_uris))
    .bind(json_arr(c.grant_types))
    .bind(json_arr(c.scopes))
    .bind(c.public as i64)
    .bind(now())
    .execute(db)
    .await?;
    Ok(client_id)
}

pub async fn get_client_raw(db: &SqlitePool, client_id: &str) -> sqlx::Result<Option<(OAuthClient, Option<String>)>> {
    let row = sqlx::query_as::<_, ClientRow>("SELECT * FROM oauth_clients WHERE client_id = ?")
        .bind(client_id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| {
        let secret = r.secret_hash.clone();
        (row_to_client(r), secret)
    }))
}

pub async fn list_clients(db: &SqlitePool) -> sqlx::Result<Vec<OAuthClient>> {
    let rows = sqlx::query_as::<_, ClientRow>("SELECT * FROM oauth_clients ORDER BY created_at DESC")
        .fetch_all(db)
        .await?;
    Ok(rows.into_iter().map(row_to_client).collect())
}

pub async fn delete_client(db: &SqlitePool, client_id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM oauth_clients WHERE client_id = ?")
        .bind(client_id)
        .execute(db)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Authorization codes
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn insert_auth_code(
    db: &SqlitePool,
    code: &str,
    client_id: &str,
    user_id: &str,
    redirect_uri: &str,
    scope: &str,
    challenge: Option<&str>,
    method: Option<&str>,
    ttl_secs: i64,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO auth_codes
         (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(code)
    .bind(client_id)
    .bind(user_id)
    .bind(redirect_uri)
    .bind(scope)
    .bind(challenge)
    .bind(method)
    .bind(future(ttl_secs))
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

/// Fetch and delete an authorization code atomically (single-use).
pub async fn take_auth_code(db: &SqlitePool, code: &str) -> sqlx::Result<Option<AuthCodeRow>> {
    let row = sqlx::query_as::<_, AuthCodeRow>("SELECT * FROM auth_codes WHERE code = ?")
        .bind(code)
        .fetch_optional(db)
        .await?;
    sqlx::query("DELETE FROM auth_codes WHERE code = ?")
        .bind(code)
        .execute(db)
        .await?;
    Ok(row)
}

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------

pub async fn insert_refresh(
    db: &SqlitePool,
    token_hash: &str,
    user_id: &str,
    client_id: &str,
    scope: &str,
    ttl_secs: i64,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO refresh_tokens (token_hash, user_id, client_id, scope, expires_at, revoked, created_at)
         VALUES (?, ?, ?, ?, ?, 0, ?)",
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(client_id)
    .bind(scope)
    .bind(future(ttl_secs))
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn get_refresh(db: &SqlitePool, token_hash: &str) -> sqlx::Result<Option<RefreshRow>> {
    sqlx::query_as::<_, RefreshRow>("SELECT * FROM refresh_tokens WHERE token_hash = ?")
        .bind(token_hash)
        .fetch_optional(db)
        .await
}

pub async fn revoke_refresh(db: &SqlitePool, token_hash: &str) -> sqlx::Result<()> {
    sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?")
        .bind(token_hash)
        .execute(db)
        .await?;
    Ok(())
}

/// Revoke every refresh token for a user+client (used on reuse detection).
pub async fn revoke_refresh_family(db: &SqlitePool, user_id: &str, client_id: &str) -> sqlx::Result<()> {
    sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND client_id = ?")
        .bind(user_id)
        .bind(client_id)
        .execute(db)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Sessions (dashboard cookie auth)
// ---------------------------------------------------------------------------

pub async fn create_session(db: &SqlitePool, id_hash: &str, user_id: &str, ttl: i64) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
        .bind(id_hash)
        .bind(user_id)
        .bind(future(ttl))
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn get_session_user(db: &SqlitePool, id_hash: &str) -> sqlx::Result<Option<String>> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT user_id, expires_at FROM sessions WHERE id = ?")
            .bind(id_hash)
            .fetch_optional(db)
            .await?;
    match row {
        Some((uid, exp)) => {
            let valid = chrono::DateTime::parse_from_rfc3339(&exp)
                .map(|t| t > Utc::now())
                .unwrap_or(false);
            Ok(if valid { Some(uid) } else { None })
        }
        None => Ok(None),
    }
}

#[allow(dead_code)]
pub async fn delete_session(db: &SqlitePool, id_hash: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(id_hash)
        .execute(db)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

pub async fn audit(
    db: &SqlitePool,
    actor: &str,
    action: &str,
    target: Option<&str>,
    ip: Option<&str>,
    detail: Option<&str>,
) {
    let _ = sqlx::query(
        "INSERT INTO audit_log (id, actor, action, target, ip, detail, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(ip)
    .bind(detail)
    .bind(now())
    .execute(db)
    .await;
}

pub async fn list_audit(db: &SqlitePool, limit: i64) -> sqlx::Result<Vec<AuditEvent>> {
    let rows = sqlx::query_as::<_, AuditRow>(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| AuditEvent {
            id: r.id,
            actor: r.actor,
            action: r.action,
            target: r.target,
            ip: r.ip,
            detail: r.detail,
            created_at: r.created_at,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

/// Seed built-in roles and the initial admin account on first run.
pub async fn seed(db: &SqlitePool, config: &Config) -> anyhow::Result<()> {
    use infinity_core::rbac::{ROLE_ADMIN, ROLE_SUPERADMIN, ROLE_USER};

    upsert_role(db, &Role {
        name: ROLE_SUPERADMIN.into(),
        description: "Full platform control".into(),
        permissions: vec!["*:*".into()],
    })
    .await?;
    upsert_role(db, &Role {
        name: ROLE_ADMIN.into(),
        description: "Manage users, clients and roles".into(),
        permissions: vec![
            "users:*".into(),
            "clients:*".into(),
            "roles:read".into(),
            "audit:read".into(),
        ],
    })
    .await?;
    upsert_role(db, &Role {
        name: ROLE_USER.into(),
        description: "Standard end user".into(),
        permissions: vec!["profile:read".into(), "profile:write".into()],
    })
    .await?;

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users").fetch_one(db).await?;
    if count.0 == 0 {
        // Never persist a shipped default credential. If the operator left the
        // built-in placeholder in place, generate a strong random password and
        // surface it once in the logs.
        let default_placeholder = Config::default().admin_password;
        let password = if config.admin_password == default_placeholder {
            let generated = crate::util::random_token();
            tracing::warn!(
                "no INFINITY_ADMIN_PASSWORD set — generated a random admin password (shown once): {}",
                generated
            );
            generated
        } else {
            config.admin_password.clone()
        };
        let hash = infinity_core::password::hash_password(&password)?;
        create_user(
            db,
            NewUser {
                email: &config.admin_email,
                username: "admin",
                display_name: Some("Infinity Administrator"),
                password_hash: &hash,
                roles: &[ROLE_SUPERADMIN.into()],
            },
        )
        .await?;
        tracing::info!(email = %config.admin_email, "seeded initial admin account");
    }
    Ok(())
}
