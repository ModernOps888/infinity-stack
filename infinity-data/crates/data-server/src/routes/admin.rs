use axum::extract::{Path, State};
use axum::Json;
use data_core::rbac::ROLE_SUPERADMIN;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::routes::valid_name;
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub username: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub password: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUser {
    #[serde(default)]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub roles: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpsertRole {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKey {
    pub name: String,
}

fn user_json(u: &store::UserRow, roles: Vec<String>) -> serde_json::Value {
    json!({"id": u.id, "email": u.email, "username": u.username, "display_name": u.display_name, "disabled": u.disabled != 0, "created_at": u.created_at, "roles": roles})
}

fn caller_is_superadmin(p: &Principal) -> bool {
    p.roles.iter().any(|r| r == ROLE_SUPERADMIN)
}

fn role_change_allowed(p: &Principal, roles: &[String]) -> bool {
    !roles.iter().any(|r| r == ROLE_SUPERADMIN) || caller_is_superadmin(p)
}

pub async fn list_users(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("users:read")?;
    let mut out = Vec::new();
    for u in store::list_users(&st.db).await? {
        let roles = store::user_roles(&st.db, &u.id).await?;
        out.push(user_json(&u, roles));
    }
    Ok(Json(json!({"users": out})))
}

pub async fn create_user(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<CreateUser>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("users:write")?;
    let email = req.email.trim().to_ascii_lowercase();
    let username = req.username.trim();
    if !email.contains('@') || email.len() > 254 {
        return Err(ApiError::BadRequest("valid email required".into()));
    }
    if !valid_name(username) {
        return Err(ApiError::BadRequest(
            "username must be 1-64 characters: letters, numbers, '_' or '-'".into(),
        ));
    }
    if !role_change_allowed(&principal, &req.roles) {
        return Err(ApiError::Forbidden(
            "only superadmin may grant superadmin".into(),
        ));
    }
    let user = store::create_user(
        &st.db,
        &email,
        username,
        req.display_name.as_deref(),
        &req.password,
    )
    .await?;
    let roles = if req.roles.is_empty() {
        vec![data_core::rbac::ROLE_USER.to_string()]
    } else {
        req.roles
    };
    store::set_user_roles(&st.db, &user.id, &roles).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "user.create",
        Some(&user.id),
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({"user": user_json(&user, roles)})))
}

pub async fn update_user(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    principal: Principal,
    Json(req): Json<UpdateUser>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("users:write")?;
    if id == principal.user_id && req.disabled == Some(true) {
        return Err(ApiError::BadRequest(
            "cannot disable your own account".into(),
        ));
    }
    let user = store::get_user(&st.db, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    if let Some(disabled) = req.disabled {
        store::set_user_disabled(&st.db, &id, disabled).await?;
    }
    if let Some(roles) = req.roles {
        if !role_change_allowed(&principal, &roles) {
            return Err(ApiError::Forbidden(
                "only superadmin may grant superadmin".into(),
            ));
        }
        store::set_user_roles(&st.db, &id, &roles).await?;
    }
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "user.update",
        Some(&id),
        None,
        None,
        None,
    )
    .await;
    let roles = store::user_roles(&st.db, &id).await?;
    Ok(Json(json!({"user": user_json(&user, roles)})))
}

pub async fn delete_user(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("users:write")?;
    if id == principal.user_id {
        return Err(ApiError::BadRequest(
            "cannot delete your own account".into(),
        ));
    }
    if store::get_user(&st.db, &id).await?.is_none() {
        return Err(ApiError::NotFound("user not found".into()));
    }
    store::delete_user(&st.db, &id).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "user.delete",
        Some(&id),
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn list_roles(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("roles:read")?;
    let mut out = Vec::new();
    for role in store::list_roles(&st.db).await? {
        out.push(json!({"name": role.name, "description": role.description, "permissions": store::role_permissions(&st.db, &role.name).await?}));
    }
    Ok(Json(json!({"roles": out})))
}

pub async fn upsert_role(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<UpsertRole>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("roles:write")?;
    if !valid_name(&req.name) {
        return Err(ApiError::BadRequest(
            "role name must be 1-64 characters: letters, numbers, '_' or '-'".into(),
        ));
    }
    if req.permissions.iter().any(|p| p == "*:*") && !caller_is_superadmin(&principal) {
        return Err(ApiError::Forbidden(
            "only superadmin may grant wildcard permissions".into(),
        ));
    }
    if req.permissions.len() > 256 {
        return Err(ApiError::BadRequest("too many permissions".into()));
    }
    store::upsert_role(&st.db, &req.name, &req.description, &req.permissions).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "role.upsert",
        Some(&req.name),
        Some(json!({"permissions": req.permissions.len()})),
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn list_api_keys(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("api_keys:read")?;
    Ok(Json(
        json!({"api_keys": store::list_api_keys(&st.db).await?}),
    ))
}

pub async fn create_api_key(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<CreateApiKey>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("api_keys:write")?;
    if req.name.trim().is_empty() || req.name.len() > 64 {
        return Err(ApiError::BadRequest(
            "API key name must be 1-64 characters".into(),
        ));
    }
    let (raw, info) = store::create_api_key(&st.db, req.name.trim()).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "api_key.create",
        Some(&info.id),
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({"api_key": info, "token": raw})))
}

pub async fn delete_api_key(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("api_keys:write")?;
    store::delete_api_key(&st.db, &id).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "api_key.delete",
        Some(&id),
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true})))
}
