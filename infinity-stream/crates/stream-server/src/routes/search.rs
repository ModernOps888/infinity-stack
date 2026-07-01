use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use stream_core::bm25::Bm25Index;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct CreateIndex {
    pub name: String,
}
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
    #[serde(default = "default_k")]
    pub k: usize,
}
fn default_k() -> usize {
    10
}

pub async fn create(
    State(st): State<SharedState>,
    p: Principal,
    Json(req): Json<CreateIndex>,
) -> ApiResult<Json<Value>> {
    p.require("search:create")?;
    validate_name(&req.name)?;
    store::create_index(&st.db, &req.name)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db) if db.message().contains("UNIQUE") => {
                ApiError::Conflict("index already exists".into())
            }
            other => other.into(),
        })?;
    st.indexes
        .write()
        .await
        .insert(req.name.clone(), Bm25Index::new());
    Ok(Json(json!({"name": req.name})))
}

pub async fn list(State(st): State<SharedState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("search:read")?;
    let indexes: Vec<Value> = store::list_indexes(&st.db)
        .await?
        .into_iter()
        .map(|(name, created_at)| json!({"name":name,"created_at":created_at}))
        .collect();
    Ok(Json(json!({"indexes": indexes})))
}

pub async fn delete_index(
    State(st): State<SharedState>,
    p: Principal,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    p.require("search:delete")?;
    validate_name(&name)?;
    store::delete_index(&st.db, &name).await?;
    st.indexes.write().await.remove(&name);
    Ok(Json(json!({"ok": true})))
}

pub async fn upsert_docs(
    State(st): State<SharedState>,
    p: Principal,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    p.require("search:write")?;
    validate_name(&name)?;
    let docs = if let Some(arr) = body.as_array() {
        arr.clone()
    } else if let Some(arr) = body.get("docs").and_then(|v| v.as_array()) {
        arr.clone()
    } else {
        return Err(ApiError::BadRequest(
            "expected array or {docs:[...]}".into(),
        ));
    };
    if docs.is_empty() || docs.len() > st.config.max_search_docs_per_batch {
        return Err(ApiError::BadRequest(format!(
            "docs must contain 1..={} entries",
            st.config.max_search_docs_per_batch
        )));
    }
    if !st.indexes.read().await.contains_key(&name) {
        return Err(ApiError::NotFound("index not found".into()));
    }
    let mut indexed = 0usize;
    let mut idxs = st.indexes.write().await;
    let idx = idxs
        .get_mut(&name)
        .ok_or_else(|| ApiError::NotFound("index not found".into()))?;
    for doc in docs {
        let obj = doc
            .as_object()
            .ok_or_else(|| ApiError::BadRequest("doc must be object".into()))?;
        let id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::BadRequest("doc.id string required".into()))?
            .to_string();
        validate_doc_id(&id)?;
        let mut fields = HashMap::new();
        for (k, v) in obj {
            if k != "id" {
                fields.insert(k.clone(), v.clone());
            }
        }
        let json_fields =
            serde_json::to_string(&fields).map_err(|e| ApiError::BadRequest(e.to_string()))?;
        store::upsert_doc(&st.db, &name, &id, &json_fields).await?;
        idx.index(id, fields);
        indexed += 1;
    }
    Ok(Json(json!({"indexed": indexed})))
}

pub async fn query(
    State(st): State<SharedState>,
    p: Principal,
    Path(name): Path<String>,
    Query(q): Query<SearchQuery>,
) -> ApiResult<Json<Value>> {
    p.require("search:query")?;
    validate_name(&name)?;
    if q.q.len() > 512 {
        return Err(ApiError::BadRequest("query too long".into()));
    }
    let hits = {
        let idxs = st.indexes.read().await;
        let idx = idxs
            .get(&name)
            .ok_or_else(|| ApiError::NotFound("index not found".into()))?;
        idx.search(&q.q, q.k.min(100))
    };
    let mut out = Vec::new();
    for hit in hits {
        if let Some(fields_json) = store::doc_fields(&st.db, &name, &hit.doc_id).await? {
            let fields: Value = serde_json::from_str(&fields_json).unwrap_or_else(|_| json!({}));
            out.push(json!({"id": hit.doc_id, "score": hit.score, "fields": fields}));
        }
    }
    Ok(Json(json!({"query": q.q, "hits": out})))
}

fn validate_name(name: &str) -> ApiResult<()> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "name must be 1-128 chars of [A-Za-z0-9_-]".into(),
        ))
    }
}

fn validate_doc_id(id: &str) -> ApiResult<()> {
    let ok = !id.is_empty()
        && id.len() <= 256
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':');
    if ok {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "doc.id must be 1-256 chars of [A-Za-z0-9_.:-]".into(),
        ))
    }
}
