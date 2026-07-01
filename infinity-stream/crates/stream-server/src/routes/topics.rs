use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::Json;
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use stream_core::model::NewRecord;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct CreateTopic { pub name: String, pub partitions: u32 }

#[derive(Debug, Deserialize)]
pub struct ProduceInput { #[serde(default)] pub key: Option<String>, pub value: serde_json::Value, #[serde(default)] pub partition: Option<u32> }

#[derive(Debug, Deserialize)]
pub struct ProduceRequest { #[serde(default)] pub key: Option<String>, #[serde(default)] pub value: Option<serde_json::Value>, #[serde(default)] pub partition: Option<u32>, #[serde(default)] pub records: Option<Vec<ProduceInput>> }

#[derive(Debug, Deserialize)]
pub struct ConsumeQuery { pub partition: u32, pub offset: u64, #[serde(default = "default_max")] pub max: usize }
fn default_max() -> usize { 100 }

#[derive(Debug, Deserialize)]
pub struct CommitRequest { pub group: String, pub partition: u32, pub offset: u64 }
#[derive(Debug, Deserialize)]
pub struct OffsetQuery { pub group: String, pub partition: u32 }

pub async fn create(State(st): State<SharedState>, _p: Principal, Json(req): Json<CreateTopic>) -> ApiResult<Json<serde_json::Value>> {
    validate_name(&req.name)?;
    if req.partitions == 0 || req.partitions > 1024 { return Err(ApiError::BadRequest("partitions must be 1..=1024".into())); }
    store::create_topic(&st.db, &req.name, req.partitions as i64).await.map_err(|e| match e { sqlx::Error::Database(db) if db.message().contains("UNIQUE") => ApiError::Conflict("topic already exists".into()), other => other.into() })?;
    let mut log = st.log.lock().await;
    for p in 0..req.partitions { log.create_partition(&req.name, p)?; }
    st.topic_sender(&req.name).await;
    Ok(Json(json!({"name":req.name,"partitions":req.partitions})))
}

pub async fn list(State(st): State<SharedState>, _p: Principal) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({"topics": store::list_topics(&st.db).await?})))
}

pub async fn delete_topic(State(st): State<SharedState>, _p: Principal, Path(name): Path<String>) -> ApiResult<Json<serde_json::Value>> {
    store::delete_topic(&st.db, &name).await?;
    st.log.lock().await.delete_topic(&name)?;
    st.broadcasts.write().await.remove(&name);
    Ok(Json(json!({"ok":true})))
}

pub async fn produce(State(st): State<SharedState>, _p: Principal, Path(name): Path<String>, Json(req): Json<ProduceRequest>) -> ApiResult<Json<serde_json::Value>> {
    let topic = store::get_topic(&st.db, &name).await?.ok_or_else(|| ApiError::NotFound("topic not found".into()))?;
    let inputs = if let Some(records) = req.records { records } else { vec![ProduceInput { key: req.key, value: req.value.ok_or_else(|| ApiError::BadRequest("value required".into()))?, partition: req.partition }] };
    let sender = st.topic_sender(&name).await;
    let mut assigned = Vec::new();
    {
        let mut log = st.log.lock().await;
        for input in inputs {
            let part = input.partition.unwrap_or_else(|| rand::thread_rng().gen_range(0..topic.partitions as u32));
            if part >= topic.partitions as u32 { return Err(ApiError::BadRequest("partition out of range".into())); }
            let recs = log.append(&name, part, vec![NewRecord { key: input.key, value: input.value }])?;
            for rec in recs {
                let _ = sender.send(rec.clone());
                assigned.push(rec);
            }
        }
    }
    let mut times = st.produced_times.lock().await;
    let now = Instant::now();
    for _ in 0..assigned.len() { times.push_back(now); }
    while times.front().is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60)) { times.pop_front(); }
    let first = assigned.first().cloned();
    Ok(Json(json!({"partition": first.as_ref().map(|r| r.partition), "offset": first.as_ref().map(|r| r.offset), "records": assigned})))
}

pub async fn consume(State(st): State<SharedState>, _p: Principal, Path(name): Path<String>, Query(q): Query<ConsumeQuery>) -> ApiResult<Json<serde_json::Value>> {
    let records = st.log.lock().await.read_from(&name, q.partition, q.offset, q.max)?;
    let next = records.last().map(|r| r.offset + 1).unwrap_or(q.offset);
    Ok(Json(json!({"records": records, "nextOffset": next})))
}

pub async fn commit(State(st): State<SharedState>, _p: Principal, Path(name): Path<String>, Json(req): Json<CommitRequest>) -> ApiResult<Json<serde_json::Value>> {
    store::commit_offset(&st.db, &name, &req.group, req.partition as i64, req.offset as i64).await?;
    Ok(Json(json!({"ok":true})))
}

pub async fn offset(State(st): State<SharedState>, _p: Principal, Path(name): Path<String>, Query(q): Query<OffsetQuery>) -> ApiResult<Json<serde_json::Value>> {
    let offset = store::get_offset(&st.db, &name, &q.group, q.partition as i64).await?.unwrap_or(0);
    Ok(Json(json!({"topic":name,"group":q.group,"partition":q.partition,"offset":offset})))
}

pub async fn consumers(State(st): State<SharedState>, _p: Principal) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({"offsets": store::list_offsets(&st.db).await?})))
}

pub async fn subscribe(State(st): State<SharedState>, _p: Principal, Path(name): Path<String>, ws: WebSocketUpgrade) -> ApiResult<impl axum::response::IntoResponse> {
    let rx = st.topic_sender(&name).await.subscribe();
    Ok(ws.on_upgrade(move |socket| ws_loop(socket, rx)))
}

async fn ws_loop(mut socket: WebSocket, mut rx: tokio::sync::broadcast::Receiver<stream_core::model::LogRecord>) {
    while let Ok(record) = rx.recv().await {
        match serde_json::to_string(&record) {
            Ok(text) => if socket.send(Message::Text(text)).await.is_err() { break; },
            Err(_) => break,
        }
    }
}

fn validate_name(name: &str) -> ApiResult<()> {
    let ok = !name.is_empty() && name.len() <= 128 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok { Ok(()) } else { Err(ApiError::BadRequest("name must be 1-128 chars of [A-Za-z0-9_-]".into())) }
}
