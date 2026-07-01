use chrono::{Duration, Utc};
use data_core::model::{Metric, TableColumn};
use data_core::security::{random_token, sha256_hex};
use serde::Serialize;
use sqlx::{FromRow, SqlitePool};
use std::str::FromStr;
use uuid::Uuid;

use crate::config::Config;

fn now() -> String { Utc::now().to_rfc3339() }
fn future(secs: i64) -> String { (Utc::now() + Duration::seconds(secs)).to_rfc3339() }

#[derive(Debug, FromRow)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub password_hash: String,
    pub disabled: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CollectionRow {
    pub name: String,
    pub dim: usize,
    pub metric: Metric,
    pub created_at: String,
}

#[derive(Debug, FromRow)]
struct CollectionDbRow {
    name: String,
    dim: i64,
    metric: String,
    created_at: String,
}

#[derive(Debug, Clone)]
pub struct TableRowInfo {
    pub name: String,
    pub columns: Vec<TableColumn>,
    pub created_at: String,
}

#[derive(Debug, FromRow)]
struct TableDbRow {
    name: String,
    columns: String,
    created_at: String,
}

impl TryFrom<CollectionDbRow> for CollectionRow {
    type Error = anyhow::Error;
    fn try_from(r: CollectionDbRow) -> Result<Self, Self::Error> {
        Ok(Self { name: r.name, dim: r.dim as usize, metric: Metric::from_str(&r.metric).map_err(anyhow::Error::msg)?, created_at: r.created_at })
    }
}

impl TryFrom<TableDbRow> for TableRowInfo {
    type Error = anyhow::Error;
    fn try_from(r: TableDbRow) -> Result<Self, Self::Error> {
        Ok(Self { name: r.name, columns: serde_json::from_str(&r.columns)?, created_at: r.created_at })
    }
}

pub async fn seed(db: &SqlitePool, config: &Config) -> anyhow::Result<()> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users").fetch_one(db).await?;
    if count.0 == 0 {
        let hash = data_core::password::hash_password(&config.admin_password)?;
        let id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, email, username, display_name, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(&id)
            .bind(&config.admin_email)
            .bind("admin")
            .bind("Infinity Data Administrator")
            .bind(hash)
            .bind(now())
            .execute(db)
            .await?;
        tracing::info!(email=%config.admin_email, "seeded initial admin account");
    }
    let key_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM api_keys").fetch_one(db).await?;
    if key_count.0 == 0 {
        let raw = format!("idat_{}", random_token());
        create_api_key_with_raw(db, "seed", &raw).await?;
        tracing::warn!("seeded initial Infinity Data API key (shown once): {}", raw);
    }
    Ok(())
}

pub async fn get_user_by_email(db: &SqlitePool, email: &str) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE email = ?")
        .bind(email)
        .fetch_optional(db)
        .await
}

pub async fn get_user(db: &SqlitePool, id: &str) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await
}

pub async fn create_session(db: &SqlitePool, id_hash: &str, user_id: &str, ttl: i64) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
        .bind(id_hash).bind(user_id).bind(future(ttl)).bind(now()).execute(db).await?;
    Ok(())
}

pub async fn get_session_user(db: &SqlitePool, id_hash: &str) -> sqlx::Result<Option<String>> {
    let row: Option<(String, String)> = sqlx::query_as("SELECT user_id, expires_at FROM sessions WHERE id = ?")
        .bind(id_hash).fetch_optional(db).await?;
    Ok(match row {
        Some((uid, exp)) if chrono::DateTime::parse_from_rfc3339(&exp).map(|t| t > Utc::now()).unwrap_or(false) => Some(uid),
        _ => None,
    })
}

pub async fn delete_session(db: &SqlitePool, id_hash: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?").bind(id_hash).execute(db).await?;
    Ok(())
}

async fn create_api_key_with_raw(db: &SqlitePool, name: &str, raw: &str) -> sqlx::Result<String> {
    let id = Uuid::new_v4().to_string();
    let prefix = raw.chars().take(12).collect::<String>();
    let hash = sha256_hex(raw);
    sqlx::query("INSERT INTO api_keys (id, name, prefix, key_hash, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&id).bind(name).bind(prefix).bind(hash).bind(now()).execute(db).await?;
    Ok(id)
}

pub async fn create_api_key(db: &SqlitePool, name: &str) -> sqlx::Result<(String, ApiKeyInfo)> {
    let raw = format!("idat_{}", random_token());
    let id = create_api_key_with_raw(db, name, &raw).await?;
    let info = get_api_key(db, &id).await?.expect("created key exists");
    Ok((raw, info))
}

pub async fn get_api_key(db: &SqlitePool, id: &str) -> sqlx::Result<Option<ApiKeyInfo>> {
    sqlx::query_as::<_, ApiKeyInfo>("SELECT id, name, prefix, created_at, last_used_at FROM api_keys WHERE id = ?")
        .bind(id).fetch_optional(db).await
}

pub async fn list_api_keys(db: &SqlitePool) -> sqlx::Result<Vec<ApiKeyInfo>> {
    sqlx::query_as::<_, ApiKeyInfo>("SELECT id, name, prefix, created_at, last_used_at FROM api_keys ORDER BY created_at DESC")
        .fetch_all(db).await
}

pub async fn delete_api_key(db: &SqlitePool, id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM api_keys WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}

pub async fn verify_api_key(db: &SqlitePool, raw: &str) -> sqlx::Result<Option<ApiKeyInfo>> {
    let hash = sha256_hex(raw);
    let row = sqlx::query_as::<_, ApiKeyInfo>("SELECT id, name, prefix, created_at, last_used_at FROM api_keys WHERE key_hash = ?")
        .bind(hash).fetch_optional(db).await?;
    if let Some(info) = &row {
        sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
            .bind(now()).bind(&info.id).execute(db).await?;
    }
    Ok(row)
}

pub async fn insert_collection(db: &SqlitePool, name: &str, dim: usize, metric: Metric) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO collections (name, dim, metric, created_at) VALUES (?, ?, ?, ?)")
        .bind(name).bind(dim as i64).bind(metric.to_string()).bind(now()).execute(db).await?;
    Ok(())
}

pub async fn list_collections(db: &SqlitePool) -> anyhow::Result<Vec<CollectionRow>> {
    let rows = sqlx::query_as::<_, CollectionDbRow>("SELECT * FROM collections ORDER BY name").fetch_all(db).await?;
    rows.into_iter().map(CollectionRow::try_from).collect()
}

pub async fn get_collection(db: &SqlitePool, name: &str) -> anyhow::Result<Option<CollectionRow>> {
    let row = sqlx::query_as::<_, CollectionDbRow>("SELECT * FROM collections WHERE name = ?").bind(name).fetch_optional(db).await?;
    row.map(CollectionRow::try_from).transpose()
}

pub async fn delete_collection(db: &SqlitePool, name: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM collections WHERE name = ?").bind(name).execute(db).await?;
    Ok(())
}

pub async fn insert_table(db: &SqlitePool, name: &str, columns: &[TableColumn]) -> sqlx::Result<()> {
    let cols = serde_json::to_string(columns).unwrap_or_else(|_| "[]".into());
    sqlx::query("INSERT INTO analytics_tables (name, columns, created_at) VALUES (?, ?, ?)")
        .bind(name).bind(cols).bind(now()).execute(db).await?;
    Ok(())
}

pub async fn list_tables(db: &SqlitePool) -> anyhow::Result<Vec<TableRowInfo>> {
    let rows = sqlx::query_as::<_, TableDbRow>("SELECT * FROM analytics_tables ORDER BY name").fetch_all(db).await?;
    rows.into_iter().map(TableRowInfo::try_from).collect()
}

pub async fn get_table(db: &SqlitePool, name: &str) -> anyhow::Result<Option<TableRowInfo>> {
    let row = sqlx::query_as::<_, TableDbRow>("SELECT * FROM analytics_tables WHERE name = ?").bind(name).fetch_optional(db).await?;
    row.map(TableRowInfo::try_from).transpose()
}

pub async fn delete_table(db: &SqlitePool, name: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM analytics_tables WHERE name = ?").bind(name).execute(db).await?;
    Ok(())
}

pub async fn insert_rows(db: &SqlitePool, table: &str, rows: &[serde_json::Value]) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    for row in rows {
        sqlx::query("INSERT INTO table_rows (id, table_name, row_json, created_at) VALUES (?, ?, ?, ?)")
            .bind(Uuid::new_v4().to_string())
            .bind(table)
            .bind(row.to_string())
            .bind(now())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn load_rows(db: &SqlitePool, table: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT row_json FROM table_rows WHERE table_name = ? ORDER BY created_at")
        .bind(table).fetch_all(db).await?;
    Ok(rows.into_iter().filter_map(|(s,)| serde_json::from_str(&s).ok()).collect())
}

pub async fn table_count(db: &SqlitePool, table: &str) -> sqlx::Result<usize> {
    let c: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM table_rows WHERE table_name = ?").bind(table).fetch_one(db).await?;
    Ok(c.0 as usize)
}

pub async fn stats_counts(db: &SqlitePool) -> sqlx::Result<(usize, usize)> {
    let tables: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM analytics_tables").fetch_one(db).await?;
    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM table_rows").fetch_one(db).await?;
    Ok((tables.0 as usize, rows.0 as usize))
}
