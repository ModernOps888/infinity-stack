use std::time::{Duration, Instant};

use axum::extract::State;
use axum::Json;
use serde_json::json;

use crate::auth::Principal;
use crate::error::ApiResult;
use crate::state::SharedState;
use crate::store;

pub async fn stats(
    State(st): State<SharedState>,
    p: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("stats:read")?;
    let (topic_count, index_count, total_docs) = store::counts(&st.db).await?;
    let total_messages = st.log.lock().await.total_records();
    let mut times = st.produced_times.lock().await;
    let now = Instant::now();
    while times
        .front()
        .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
    {
        times.pop_front();
    }
    let messages_per_min = times.len();
    Ok(Json(json!({
        "topicCount": topic_count,
        "totalMessages": total_messages,
        "indexCount": index_count,
        "totalDocs": total_docs,
        "messagesPerMin": messages_per_min
    })))
}
