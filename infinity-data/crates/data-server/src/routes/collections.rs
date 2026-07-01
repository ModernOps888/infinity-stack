use axum::extract::{Path, State};
use axum::Json;
use data_core::hnsw::{HnswIndex, Point};
use data_core::model::{CollectionInfo, Metric};
use serde::Deserialize;
use serde_json::json;
use std::str::FromStr;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::routes::valid_name;
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct CreateCollection {
    pub name: String,
    pub dim: usize,
    #[serde(default = "default_metric")]
    pub metric: String,
}

fn default_metric() -> String {
    "cosine".into()
}

#[derive(Debug, Deserialize)]
pub struct VectorInput {
    #[serde(default)]
    pub id: Option<String>,
    pub vector: Vec<f32>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpsertVectors {
    pub points: Vec<VectorInput>,
}

#[derive(Debug, Deserialize)]
pub struct SearchRequest {
    pub vector: Vec<f32>,
    #[serde(default = "default_k")]
    pub k: usize,
    #[serde(default)]
    pub ef: Option<usize>,
}

fn default_k() -> usize {
    10
}

pub async fn stats(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("data:read")?;
    let (collections, vectors, tables, rows, users) = store::stats_counts(&st.db).await?;
    Ok(Json(
        json!({"collections": collections, "vectors": vectors, "tables": tables, "rows": rows, "users": users}),
    ))
}

pub async fn list(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("collections:read")?;
    let mut out = Vec::new();
    for c in store::list_collections(&st.db).await? {
        out.push(CollectionInfo {
            name: c.name.clone(),
            dim: c.dim,
            metric: c.metric,
            count: store::vector_count(&st.db, Some(&c.name)).await?,
            created_at: c.created_at,
        });
    }
    Ok(Json(json!({"collections": out})))
}

pub async fn get_one(
    State(st): State<SharedState>,
    Path(name): Path<String>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("collections:read")?;
    let c = store::get_collection(&st.db, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound("collection not found".into()))?;
    let count = store::vector_count(&st.db, Some(&c.name)).await?;
    Ok(Json(
        json!({"name": c.name, "dim": c.dim, "metric": c.metric, "count": count, "created_at": c.created_at}),
    ))
}

pub async fn create(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<CreateCollection>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("collections:write")?;
    let name = req.name.trim();
    if !valid_name(name) {
        return Err(ApiError::BadRequest(
            "collection name must be 1-64 characters: letters, numbers, '_' or '-'".into(),
        ));
    }
    if req.dim == 0 || req.dim > 4096 {
        return Err(ApiError::BadRequest(
            "dimension must be between 1 and 4096".into(),
        ));
    }
    if store::get_collection(&st.db, name).await?.is_some() {
        return Err(ApiError::Conflict("collection already exists".into()));
    }
    let metric = Metric::from_str(&req.metric).map_err(ApiError::BadRequest)?;
    store::insert_collection(&st.db, name, req.dim, metric).await?;
    st.indexes
        .write()
        .await
        .insert(name.to_string(), HnswIndex::new(req.dim, metric, 16, 128)?);
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "collection.create",
        Some(name),
        Some(json!({"dim": req.dim, "metric": metric})),
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
    principal.require("collections:write")?;
    if store::get_collection(&st.db, &name).await?.is_none() {
        return Err(ApiError::NotFound("collection not found".into()));
    }
    store::delete_collection(&st.db, &name).await?;
    st.indexes.write().await.remove(&name);
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "collection.delete",
        Some(&name),
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn upsert_vectors(
    State(st): State<SharedState>,
    Path(name): Path<String>,
    principal: Principal,
    Json(req): Json<UpsertVectors>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("data:write")?;
    let c = store::get_collection(&st.db, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound("collection not found".into()))?;
    if req.points.is_empty() || req.points.len() > 1000 {
        return Err(ApiError::BadRequest(
            "points length must be 1..=1000".into(),
        ));
    }
    let mut points = Vec::with_capacity(req.points.len());
    for p in req.points {
        if p.vector.len() != c.dim {
            return Err(ApiError::BadRequest(format!(
                "vector dimension {} does not match collection dimension {}",
                p.vector.len(),
                c.dim
            )));
        }
        if p.vector.iter().any(|v| !v.is_finite()) {
            return Err(ApiError::BadRequest(
                "vectors must contain only finite numbers".into(),
            ));
        }
        let id = p.id.unwrap_or_else(|| Uuid::new_v4().to_string());
        if id.len() > 128 || id.is_empty() {
            return Err(ApiError::BadRequest(
                "point id must be 1-128 characters".into(),
            ));
        }
        points.push(Point {
            id,
            vector: p.vector,
            metadata: p.metadata,
        });
    }
    {
        let mut indexes = st.indexes.write().await;
        let index = indexes
            .entry(name.clone())
            .or_insert(HnswIndex::new(c.dim, c.metric, 16, 128)?);
        for p in points.clone() {
            index.insert(p)?;
        }
    }
    store::upsert_points(&st.db, &name, &points).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "vectors.upsert",
        Some(&name),
        Some(json!({"count": points.len()})),
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true, "upserted": points.len()})))
}

pub async fn search(
    State(st): State<SharedState>,
    Path(name): Path<String>,
    principal: Principal,
    Json(req): Json<SearchRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("data:read")?;
    let c = store::get_collection(&st.db, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound("collection not found".into()))?;
    if req.vector.len() != c.dim {
        return Err(ApiError::BadRequest(format!(
            "query dimension {} does not match collection dimension {}",
            req.vector.len(),
            c.dim
        )));
    }
    if req.vector.iter().any(|v| !v.is_finite()) {
        return Err(ApiError::BadRequest(
            "query vector must contain only finite numbers".into(),
        ));
    }
    let k = req.k.clamp(1, 100);
    let ef = req.ef.unwrap_or(k * 8).clamp(k, 10_000);
    let hits = {
        let indexes = st.indexes.read().await;
        let idx = indexes
            .get(&name)
            .ok_or_else(|| ApiError::NotFound("index not loaded".into()))?;
        idx.search(&req.vector, k, ef)?
    };
    Ok(Json(json!({"collection": name, "k": k, "hits": hits})))
}
