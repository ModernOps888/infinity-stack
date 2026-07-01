use axum::extract::{Path, State};
use axum::Json;
use data_core::aggregation::{run_query, Query};
use data_core::model::{TableColumn, TableInfo};
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::routes::valid_name;
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct CreateTable {
    pub name: String,
    #[serde(default)]
    pub columns: Vec<TableColumn>,
}

#[derive(Debug, Deserialize)]
pub struct InsertRows {
    pub rows: Vec<serde_json::Value>,
}

pub async fn list(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("tables:read")?;
    let mut out = Vec::new();
    for t in store::list_tables(&st.db).await? {
        out.push(TableInfo {
            name: t.name.clone(),
            columns: t.columns,
            row_count: store::table_count(&st.db, &t.name).await?,
            created_at: t.created_at,
        });
    }
    Ok(Json(json!({"tables": out})))
}

pub async fn get_one(
    State(st): State<SharedState>,
    Path(name): Path<String>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("tables:read")?;
    let t = store::get_table(&st.db, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound("table not found".into()))?;
    Ok(Json(
        json!({"name": t.name, "columns": t.columns, "row_count": store::table_count(&st.db, &name).await?, "created_at": t.created_at}),
    ))
}

pub async fn create(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<CreateTable>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("tables:write")?;
    let name = req.name.trim();
    if !valid_name(name) {
        return Err(ApiError::BadRequest(
            "table name must be 1-64 characters: letters, numbers, '_' or '-'".into(),
        ));
    }
    if req.columns.len() > 256 {
        return Err(ApiError::BadRequest("too many columns".into()));
    }
    if store::get_table(&st.db, name).await?.is_some() {
        return Err(ApiError::Conflict("table already exists".into()));
    }
    store::insert_table(&st.db, name, &req.columns).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "table.create",
        Some(name),
        Some(json!({"columns": req.columns.len()})),
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true, "name": name})))
}

pub async fn delete_one(
    State(st): State<SharedState>,
    Path(name): Path<String>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("tables:write")?;
    if store::get_table(&st.db, &name).await?.is_none() {
        return Err(ApiError::NotFound("table not found".into()));
    }
    store::delete_table(&st.db, &name).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "table.delete",
        Some(&name),
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn insert_rows(
    State(st): State<SharedState>,
    Path(name): Path<String>,
    principal: Principal,
    Json(req): Json<InsertRows>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("data:write")?;
    if store::get_table(&st.db, &name).await?.is_none() {
        return Err(ApiError::NotFound("table not found".into()));
    }
    if req.rows.is_empty() || req.rows.len() > 1000 {
        return Err(ApiError::BadRequest("rows length must be 1..=1000".into()));
    }
    if req.rows.iter().any(|r| !r.is_object()) {
        return Err(ApiError::BadRequest(
            "each row must be a JSON object".into(),
        ));
    }
    store::insert_rows(&st.db, &name, &req.rows).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "rows.insert",
        Some(&name),
        Some(json!({"count": req.rows.len()})),
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true, "inserted": req.rows.len()})))
}

pub async fn query(
    State(st): State<SharedState>,
    Path(name): Path<String>,
    principal: Principal,
    Json(req): Json<Query>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("data:read")?;
    if store::get_table(&st.db, &name).await?.is_none() {
        return Err(ApiError::NotFound("table not found".into()));
    }
    let rows = store::load_rows(&st.db, &name).await?;
    let result = run_query(&rows, &req)?;
    Ok(Json(json!({"table": name, "rows": result})))
}
