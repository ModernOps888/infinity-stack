//! Admin user-management endpoints (RBAC-guarded).

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store::{self, NewUser};

/// Privileged roles that only a superadmin (`*:*`) may assign — prevents an
/// admin (which holds `users:*` but not `roles:write`) from escalating itself
/// or others to a higher tier.
const PRIVILEGED_ROLES: &[&str] = &["superadmin", "admin"];

fn assert_can_assign(p: &Principal, roles: &[String]) -> ApiResult<()> {
    let is_superadmin = p.permissions.iter().any(|perm| perm == "*:*");
    for role in roles {
        if PRIVILEGED_ROLES.contains(&role.as_str()) && !is_superadmin {
            return Err(ApiError::Forbidden(format!(
                "only a superadmin may assign the '{role}' role"
            )));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub username: String,
    pub password: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Deserialize)]
pub struct UpdateUser {
    pub disabled: Option<bool>,
    pub roles: Option<Vec<String>>,
}

/// GET /admin/users
pub async fn list(State(st): State<SharedState>, p: Principal) -> ApiResult<Json<serde_json::Value>> {
    p.require("users:read")?;
    let users = store::list_users(&st.db).await?;
    Ok(Json(json!({ "users": users })))
}

/// POST /admin/users
pub async fn create(
    State(st): State<SharedState>,
    p: Principal,
    Json(req): Json<CreateUser>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("users:create")?;
    let hash = infinity_core::password::hash_password(&req.password)?;
    let roles = if req.roles.is_empty() {
        vec![infinity_core::rbac::ROLE_USER.to_string()]
    } else {
        req.roles
    };
    assert_can_assign(&p, &roles)?;
    let id = store::create_user(
        &st.db,
        NewUser {
            email: &req.email,
            username: &req.username,
            display_name: req.display_name.as_deref(),
            password_hash: &hash,
            roles: &roles,
        },
    )
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.message().contains("UNIQUE") => {
            ApiError::Conflict("email or username already exists".into())
        }
        other => other.into(),
    })?;
    store::audit(&st.db, &p.user_id, "user.create", Some(&id), None, None).await;
    Ok(Json(json!({ "id": id })))
}

/// PATCH /admin/users/:id
pub async fn update(
    State(st): State<SharedState>,
    p: Principal,
    Path(id): Path<String>,
    Json(req): Json<UpdateUser>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("users:update")?;
    if let Some(disabled) = req.disabled {
        store::set_user_disabled(&st.db, &id, disabled).await?;
    }
    if let Some(roles) = req.roles {
        assert_can_assign(&p, &roles)?;
        store::set_user_roles(&st.db, &id, &roles).await?;
    }
    store::audit(&st.db, &p.user_id, "user.update", Some(&id), None, None).await;
    Ok(Json(json!({ "ok": true })))
}

/// DELETE /admin/users/:id
pub async fn delete(
    State(st): State<SharedState>,
    p: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("users:delete")?;
    if id == p.user_id {
        return Err(ApiError::BadRequest("cannot delete your own account".into()));
    }
    store::delete_user(&st.db, &id).await?;
    store::audit(&st.db, &p.user_id, "user.delete", Some(&id), None, None).await;
    Ok(Json(json!({ "ok": true })))
}
