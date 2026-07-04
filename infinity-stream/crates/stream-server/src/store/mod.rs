use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

use crate::config::Config;
use crate::util::{random_token, sha256_hex};

fn now() -> String {
    Utc::now().to_rfc3339()
}
fn future(secs: i64) -> String {
    (Utc::now() + Duration::seconds(secs)).to_rfc3339()
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Topic {
    pub name: String,
    pub partitions: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OffsetRow {
    pub topic: String,
    pub consumer_group: String,
    pub partition: i64,
    pub offset: i64,
    pub updated_at: String,
}

pub async fn seed(db: &SqlitePool, config: &Config) -> anyhow::Result<Option<String>> {
    // Purge expired sessions so the table cannot grow without bound.
    sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(now())
        .execute(db)
        .await?;
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await?;
    if count.0 == 0 {
        let default_placeholder = Config::default().admin_password;
        let password = if config.admin_password == default_placeholder {
            let generated = random_token();
            tracing::warn!(
                "no STREAM_ADMIN_PASSWORD set — generated a random admin password (shown once): {}",
                generated
            );
            generated
        } else {
            config.admin_password.clone()
        };
        let hash = stream_core::password::hash_password(&password)?;
        sqlx::query(
            "INSERT INTO users (id,email,username,password_hash,created_at) VALUES (?,?,?,?,?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&config.admin_email)
        .bind("admin")
        .bind(hash)
        .bind(now())
        .execute(db)
        .await?;
        tracing::info!(email = %config.admin_email, "seeded initial admin account");
    }
    let keys: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL")
        .fetch_one(db)
        .await?;
    if keys.0 == 0 {
        let token = format!("isk_{}", random_token());
        create_api_key_with_token(db, "seed", &token).await?;
        Ok(Some(token))
    } else {
        Ok(None)
    }
}

pub async fn get_user_by_email(
    db: &SqlitePool,
    email: &str,
) -> sqlx::Result<Option<(String, String, String, String)>> {
    sqlx::query_as(
        "SELECT id, email, username, password_hash FROM users WHERE lower(email) = lower(?)",
    )
    .bind(email)
    .fetch_optional(db)
    .await
}

pub async fn get_user_by_id(db: &SqlitePool, id: &str) -> sqlx::Result<Option<(String, String)>> {
    sqlx::query_as("SELECT email, username FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await
}

pub async fn create_session(
    db: &SqlitePool,
    id_hash: &str,
    user_id: &str,
    ttl: i64,
) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO sessions (id,user_id,expires_at,created_at) VALUES (?,?,?,?)")
        .bind(id_hash)
        .bind(user_id)
        .bind(future(ttl))
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn session_user(db: &SqlitePool, id_hash: &str) -> sqlx::Result<Option<String>> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT user_id, expires_at FROM sessions WHERE id = ?")
            .bind(id_hash)
            .fetch_optional(db)
            .await?;
    Ok(row.and_then(|(uid, exp)| {
        chrono::DateTime::parse_from_rfc3339(&exp)
            .ok()
            .filter(|t| *t > Utc::now())
            .map(|_| uid)
    }))
}

pub async fn delete_session(db: &SqlitePool, id_hash: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(id_hash)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn api_key_subject(db: &SqlitePool, hash: &str) -> sqlx::Result<Option<String>> {
    // Indexed lookup by hash instead of scanning every key: keeps auth O(1)
    // (no DoS as the key count grows) and avoids the timing difference between
    // "no match" and "match found" that a full scan with early exit leaks.
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT id, key_hash FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL",
    )
    .bind(hash)
    .fetch_optional(db)
    .await?;
    if let Some((id, stored_hash)) = row {
        if stream_core::security::constant_time_eq(hash.as_bytes(), stored_hash.as_bytes()) {
            sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
                .bind(now())
                .bind(&id)
                .execute(db)
                .await?;
            return Ok(Some(id));
        }
    }
    Ok(None)
}

async fn create_api_key_with_token(
    db: &SqlitePool,
    name: &str,
    token: &str,
) -> sqlx::Result<String> {
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO api_keys (id,name,key_hash,created_at) VALUES (?,?,?,?)")
        .bind(&id)
        .bind(name)
        .bind(sha256_hex(token))
        .bind(now())
        .execute(db)
        .await?;
    Ok(id)
}

pub async fn create_api_key(db: &SqlitePool, name: &str) -> sqlx::Result<(String, String)> {
    let token = format!("isk_{}", random_token());
    let id = create_api_key_with_token(db, name, &token).await?;
    Ok((id, token))
}

pub async fn list_api_keys(db: &SqlitePool) -> sqlx::Result<Vec<ApiKeyInfo>> {
    sqlx::query_as::<_, ApiKeyInfo>("SELECT id, name, created_at, last_used_at, revoked_at FROM api_keys ORDER BY created_at DESC").fetch_all(db).await
}

pub async fn revoke_api_key(db: &SqlitePool, id: &str) -> sqlx::Result<()> {
    sqlx::query("UPDATE api_keys SET revoked_at = ? WHERE id = ?")
        .bind(now())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn create_topic(db: &SqlitePool, name: &str, partitions: i64) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO topics (name, partitions, created_at) VALUES (?,?,?)")
        .bind(name)
        .bind(partitions)
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}
pub async fn list_topics(db: &SqlitePool) -> sqlx::Result<Vec<Topic>> {
    sqlx::query_as::<_, Topic>("SELECT name, partitions, created_at FROM topics ORDER BY name")
        .fetch_all(db)
        .await
}
pub async fn get_topic(db: &SqlitePool, name: &str) -> sqlx::Result<Option<Topic>> {
    sqlx::query_as::<_, Topic>("SELECT name, partitions, created_at FROM topics WHERE name = ?")
        .bind(name)
        .fetch_optional(db)
        .await
}
pub async fn delete_topic(db: &SqlitePool, name: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM topics WHERE name = ?")
        .bind(name)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM consumer_offsets WHERE topic = ?")
        .bind(name)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn commit_offset(
    db: &SqlitePool,
    topic: &str,
    group: &str,
    partition: i64,
    offset: i64,
) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO consumer_offsets (topic, consumer_group, partition, offset, updated_at) VALUES (?,?,?,?,?) ON CONFLICT(topic, consumer_group, partition) DO UPDATE SET offset=excluded.offset, updated_at=excluded.updated_at")
        .bind(topic).bind(group).bind(partition).bind(offset).bind(now()).execute(db).await?;
    Ok(())
}
pub async fn get_offset(
    db: &SqlitePool,
    topic: &str,
    group: &str,
    partition: i64,
) -> sqlx::Result<Option<i64>> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT offset FROM consumer_offsets WHERE topic = ? AND consumer_group = ? AND partition = ?").bind(topic).bind(group).bind(partition).fetch_optional(db).await?;
    Ok(row.map(|r| r.0))
}
pub async fn list_offsets(db: &SqlitePool) -> sqlx::Result<Vec<OffsetRow>> {
    sqlx::query_as::<_, OffsetRow>("SELECT topic, consumer_group, partition, offset, updated_at FROM consumer_offsets ORDER BY updated_at DESC").fetch_all(db).await
}

pub async fn create_index(db: &SqlitePool, name: &str) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO search_indexes (name, created_at) VALUES (?,?)")
        .bind(name)
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}
pub async fn list_indexes(db: &SqlitePool) -> sqlx::Result<Vec<(String, String)>> {
    sqlx::query_as("SELECT name, created_at FROM search_indexes ORDER BY name")
        .fetch_all(db)
        .await
}
pub async fn delete_index(db: &SqlitePool, name: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM search_indexes WHERE name = ?")
        .bind(name)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM search_docs WHERE index_name = ?")
        .bind(name)
        .execute(db)
        .await?;
    Ok(())
}
pub async fn upsert_doc(
    db: &SqlitePool,
    index: &str,
    id: &str,
    fields_json: &str,
) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO search_docs (index_name, doc_id, fields_json, created_at, updated_at) VALUES (?,?,?,?,?) ON CONFLICT(index_name, doc_id) DO UPDATE SET fields_json=excluded.fields_json, updated_at=excluded.updated_at")
        .bind(index).bind(id).bind(fields_json).bind(now()).bind(now()).execute(db).await?;
    Ok(())
}
pub async fn docs_for_index(db: &SqlitePool, index: &str) -> sqlx::Result<Vec<(String, String)>> {
    sqlx::query_as("SELECT doc_id, fields_json FROM search_docs WHERE index_name = ?")
        .bind(index)
        .fetch_all(db)
        .await
}
pub async fn doc_fields(db: &SqlitePool, index: &str, id: &str) -> sqlx::Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT fields_json FROM search_docs WHERE index_name = ? AND doc_id = ?")
            .bind(index)
            .bind(id)
            .fetch_optional(db)
            .await?;
    Ok(row.map(|r| r.0))
}
pub async fn counts(db: &SqlitePool) -> sqlx::Result<(i64, i64, i64)> {
    let topics: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM topics")
        .fetch_one(db)
        .await?;
    let indexes: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM search_indexes")
        .fetch_one(db)
        .await?;
    let docs: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM search_docs")
        .fetch_one(db)
        .await?;
    Ok((topics.0, indexes.0, docs.0))
}
