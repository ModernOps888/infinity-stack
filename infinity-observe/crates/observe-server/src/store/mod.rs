//! Persistence layer. All SQL lives here and uses runtime sqlx queries.

use chrono::{Duration, Utc};
use observe_core::digest::TDigest;
use observe_core::model::QuantileSummary;
use serde::Serialize;
use serde_json::Value;
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

use crate::config::Config;
use crate::util::{random_token, sha256_hex};

pub fn now() -> String {
    Utc::now().to_rfc3339()
}

fn future(secs: i64) -> String {
    (Utc::now() + Duration::seconds(secs)).to_rfc3339()
}

fn json_value(v: &Option<Value>) -> String {
    v.as_ref().map(Value::to_string).unwrap_or_else(|| "{}".into())
}

fn json_map_string(v: &Option<Value>) -> String {
    v.as_ref().map(Value::to_string).unwrap_or_else(|| "{}".into())
}

#[derive(Debug, FromRow, Serialize)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub disabled: i64,
    pub created_at: String,
}

#[derive(Debug, FromRow, Serialize)]
pub struct LogRow {
    pub id: String,
    pub timestamp: String,
    pub level: String,
    pub service: String,
    pub message: String,
    pub attributes: String,
}

#[derive(Debug, FromRow, Serialize)]
pub struct MetricRow {
    pub id: String,
    pub timestamp: String,
    pub name: String,
    pub value: f64,
    pub tags: String,
}

#[derive(Debug, FromRow, Serialize)]
pub struct SpanRow {
    pub id: String,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub service: String,
    pub start_time: String,
    pub end_time: String,
    pub duration_ms: f64,
    pub status: Option<String>,
    pub attributes: String,
}

#[derive(Debug, FromRow, Serialize)]
pub struct TraceListRow {
    pub trace_id: String,
    pub service: String,
    pub start_time: String,
    pub end_time: String,
    pub duration_ms: f64,
    pub span_count: i64,
    pub status: Option<String>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct IngestKeyRow {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub last_used_at: Option<String>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct AlertRuleRow {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub target: String,
    pub threshold: f64,
    pub window_secs: i64,
    pub enabled: i64,
    pub created_at: String,
}

#[derive(Debug, FromRow, Serialize)]
pub struct AlertRow {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub message: String,
    pub fired_at: String,
    pub resolved_at: Option<String>,
}

pub async fn seed(db: &SqlitePool, config: &Config) -> anyhow::Result<()> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users").fetch_one(db).await?;
    if count.0 == 0 {
        let hash = observe_core::password::hash_password(&config.admin_password)?;
        sqlx::query(
            "INSERT INTO users (id, email, username, display_name, password_hash, role, created_at)
             VALUES (?, ?, 'admin', 'Infinity Observe Administrator', ?, 'admin', ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&config.admin_email)
        .bind(hash)
        .bind(now())
        .execute(db)
        .await?;
        tracing::info!(email = %config.admin_email, "seeded initial admin account");
    }

    let key_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ingest_keys WHERE revoked_at IS NULL")
        .fetch_one(db)
        .await?;
    if key_count.0 == 0 {
        let raw = format!("io_{}", random_token());
        create_ingest_key_with_raw(db, "default", &raw).await?;
        tracing::warn!("seeded initial ingest API key (shown once): {}", raw);
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
        .bind(id_hash)
        .bind(user_id)
        .bind(future(ttl))
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn get_session_user(db: &SqlitePool, id_hash: &str) -> sqlx::Result<Option<String>> {
    let row: Option<(String, String)> = sqlx::query_as("SELECT user_id, expires_at FROM sessions WHERE id = ?")
        .bind(id_hash)
        .fetch_optional(db)
        .await?;
    Ok(match row {
        Some((uid, exp)) if chrono::DateTime::parse_from_rfc3339(&exp).map(|t| t > Utc::now()).unwrap_or(false) => Some(uid),
        _ => None,
    })
}

pub async fn delete_session(db: &SqlitePool, id_hash: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?").bind(id_hash).execute(db).await?;
    Ok(())
}

async fn create_ingest_key_with_raw(db: &SqlitePool, name: &str, raw: &str) -> sqlx::Result<String> {
    let id = Uuid::new_v4().to_string();
    let prefix: String = raw.chars().take(12).collect();
    sqlx::query(
        "INSERT INTO ingest_keys (id, name, key_hash, prefix, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(sha256_hex(raw))
    .bind(prefix)
    .bind(now())
    .execute(db)
    .await?;
    Ok(id)
}

pub async fn create_ingest_key(db: &SqlitePool, name: &str) -> sqlx::Result<(IngestKeyRow, String)> {
    let raw = format!("io_{}", random_token());
    let id = create_ingest_key_with_raw(db, name, &raw).await?;
    let row = sqlx::query_as::<_, IngestKeyRow>(
        "SELECT id, name, prefix, created_at, revoked_at, last_used_at FROM ingest_keys WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(db)
    .await?;
    Ok((row, raw))
}

pub async fn list_ingest_keys(db: &SqlitePool) -> sqlx::Result<Vec<IngestKeyRow>> {
    sqlx::query_as::<_, IngestKeyRow>(
        "SELECT id, name, prefix, created_at, revoked_at, last_used_at FROM ingest_keys ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await
}

pub async fn revoke_ingest_key(db: &SqlitePool, id: &str) -> sqlx::Result<()> {
    sqlx::query("UPDATE ingest_keys SET revoked_at = ? WHERE id = ?")
        .bind(now())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn validate_ingest_key(db: &SqlitePool, key_hash: &str) -> sqlx::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM ingest_keys WHERE key_hash = ? AND revoked_at IS NULL",
    )
    .bind(key_hash)
    .fetch_optional(db)
    .await?;
    if let Some((id,)) = row {
        sqlx::query("UPDATE ingest_keys SET last_used_at = ? WHERE id = ?")
            .bind(now())
            .bind(&id)
            .execute(db)
            .await?;
        Ok(Some(id))
    } else {
        Ok(None)
    }
}

pub struct NewLog<'a> {
    pub timestamp: &'a str,
    pub level: &'a str,
    pub service: &'a str,
    pub message: &'a str,
    pub attributes: Option<Value>,
}

pub async fn insert_log(db: &SqlitePool, l: NewLog<'_>) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO logs (id, timestamp, level, service, message, attributes) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(Uuid::new_v4().to_string())
        .bind(l.timestamp)
        .bind(l.level.to_uppercase())
        .bind(l.service)
        .bind(l.message)
        .bind(json_value(&l.attributes))
        .execute(db)
        .await?;
    Ok(())
}

pub struct LogFilter<'a> {
    pub service: Option<&'a str>,
    pub level: Option<&'a str>,
    pub q: Option<&'a str>,
    pub since: Option<&'a str>,
    pub limit: i64,
}

pub async fn list_logs(db: &SqlitePool, f: LogFilter<'_>) -> sqlx::Result<Vec<LogRow>> {
    let mut sql = String::from("SELECT * FROM logs WHERE 1=1");
    if f.service.is_some() { sql.push_str(" AND service = ?"); }
    if f.level.is_some() { sql.push_str(" AND level = ?"); }
    if f.since.is_some() { sql.push_str(" AND timestamp >= ?"); }
    let tokens: Vec<String> = f.q.unwrap_or("").split_whitespace().map(|s| format!("%{}%", s)).collect();
    for _ in &tokens { sql.push_str(" AND message LIKE ?"); }
    sql.push_str(" ORDER BY timestamp DESC LIMIT ?");
    let mut q = sqlx::query_as::<_, LogRow>(&sql);
    if let Some(v) = f.service { q = q.bind(v); }
    if let Some(v) = f.level { q = q.bind(v.to_uppercase()); }
    if let Some(v) = f.since { q = q.bind(v); }
    for tok in tokens { q = q.bind(tok); }
    q.bind(f.limit.clamp(1, 500)).fetch_all(db).await
}

pub struct NewMetric<'a> {
    pub timestamp: &'a str,
    pub name: &'a str,
    pub value: f64,
    pub tags: Option<Value>,
}

pub async fn insert_metric(db: &SqlitePool, m: NewMetric<'_>) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO metrics (id, timestamp, name, value, tags) VALUES (?, ?, ?, ?, ?)")
        .bind(Uuid::new_v4().to_string())
        .bind(m.timestamp)
        .bind(m.name)
        .bind(m.value)
        .bind(json_map_string(&m.tags))
        .execute(db)
        .await?;
    Ok(())
}

pub async fn metric_series(db: &SqlitePool, name: &str, since: Option<&str>) -> sqlx::Result<Vec<MetricRow>> {
    if let Some(since) = since {
        sqlx::query_as::<_, MetricRow>("SELECT * FROM metrics WHERE name = ? AND timestamp >= ? ORDER BY timestamp ASC LIMIT 2000")
            .bind(name)
            .bind(since)
            .fetch_all(db)
            .await
    } else {
        sqlx::query_as::<_, MetricRow>("SELECT * FROM metrics WHERE name = ? ORDER BY timestamp ASC LIMIT 2000")
            .bind(name)
            .fetch_all(db)
            .await
    }
}

pub async fn metric_names(db: &SqlitePool) -> sqlx::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT DISTINCT name FROM metrics ORDER BY name LIMIT 200")
        .fetch_all(db)
        .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn metric_summary(db: &SqlitePool, name: &str) -> sqlx::Result<Option<QuantileSummary>> {
    let rows: Vec<(f64,)> = sqlx::query_as("SELECT value FROM metrics WHERE name = ? ORDER BY timestamp DESC LIMIT 10000")
        .bind(name)
        .fetch_all(db)
        .await?;
    if rows.is_empty() { return Ok(None); }
    let mut digest = TDigest::new(120.0);
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;
    let mut sum = 0.0;
    for (v,) in rows {
        digest.add(v);
        min = min.min(v);
        max = max.max(v);
        sum += v;
    }
    digest.compress();
    let count = digest.count();
    Ok(Some(QuantileSummary {
        count,
        min,
        max,
        avg: sum / count as f64,
        p50: digest.quantile(0.50).unwrap_or(0.0),
        p90: digest.quantile(0.90).unwrap_or(0.0),
        p95: digest.quantile(0.95).unwrap_or(0.0),
        p99: digest.quantile(0.99).unwrap_or(0.0),
    }))
}

pub struct NewSpan<'a> {
    pub trace_id: &'a str,
    pub span_id: &'a str,
    pub parent_span_id: Option<&'a str>,
    pub name: &'a str,
    pub service: &'a str,
    pub start_time: &'a str,
    pub end_time: &'a str,
    pub duration_ms: f64,
    pub status: Option<&'a str>,
    pub attributes: Option<Value>,
}

pub async fn insert_span(db: &SqlitePool, s: NewSpan<'_>) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO spans (id, trace_id, span_id, parent_span_id, name, service, start_time, end_time, duration_ms, status, attributes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(s.trace_id)
    .bind(s.span_id)
    .bind(s.parent_span_id)
    .bind(s.name)
    .bind(s.service)
    .bind(s.start_time)
    .bind(s.end_time)
    .bind(s.duration_ms)
    .bind(s.status)
    .bind(json_value(&s.attributes))
    .execute(db)
    .await?;
    Ok(())
}

pub async fn get_trace(db: &SqlitePool, trace_id: &str) -> sqlx::Result<Vec<SpanRow>> {
    sqlx::query_as::<_, SpanRow>("SELECT * FROM spans WHERE trace_id = ? ORDER BY start_time ASC")
        .bind(trace_id)
        .fetch_all(db)
        .await
}

pub async fn list_traces(db: &SqlitePool, service: Option<&str>, limit: i64) -> sqlx::Result<Vec<TraceListRow>> {
    if let Some(service) = service {
        sqlx::query_as::<_, TraceListRow>(
            "SELECT trace_id, service, MIN(start_time) AS start_time, MAX(end_time) AS end_time,
                    SUM(duration_ms) AS duration_ms, COUNT(*) AS span_count, MAX(status) AS status
             FROM spans WHERE service = ? GROUP BY trace_id, service ORDER BY start_time DESC LIMIT ?",
        )
        .bind(service)
        .bind(limit.clamp(1, 200))
        .fetch_all(db)
        .await
    } else {
        sqlx::query_as::<_, TraceListRow>(
            "SELECT trace_id, MIN(service) AS service, MIN(start_time) AS start_time, MAX(end_time) AS end_time,
                    SUM(duration_ms) AS duration_ms, COUNT(*) AS span_count, MAX(status) AS status
             FROM spans GROUP BY trace_id ORDER BY start_time DESC LIMIT ?",
        )
        .bind(limit.clamp(1, 200))
        .fetch_all(db)
        .await
    }
}

pub async fn list_alert_rules(db: &SqlitePool) -> sqlx::Result<Vec<AlertRuleRow>> {
    sqlx::query_as::<_, AlertRuleRow>("SELECT * FROM alert_rules ORDER BY created_at DESC")
        .fetch_all(db)
        .await
}

pub async fn create_alert_rule(db: &SqlitePool, name: &str, kind: &str, target: &str, threshold: f64, window_secs: i64) -> sqlx::Result<AlertRuleRow> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO alert_rules (id, name, kind, target, threshold, window_secs, enabled, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(kind)
    .bind(target)
    .bind(threshold)
    .bind(window_secs.max(60))
    .bind(now())
    .execute(db)
    .await?;
    sqlx::query_as::<_, AlertRuleRow>("SELECT * FROM alert_rules WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await
}

pub async fn delete_alert_rule(db: &SqlitePool, id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM alert_rules WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}

pub async fn list_alerts(db: &SqlitePool, limit: i64) -> sqlx::Result<Vec<AlertRow>> {
    sqlx::query_as::<_, AlertRow>("SELECT * FROM alerts ORDER BY fired_at DESC LIMIT ?")
        .bind(limit.clamp(1, 500))
        .fetch_all(db)
        .await
}

pub async fn evaluate_alerts(db: &SqlitePool) -> sqlx::Result<()> {
    let rules = list_alert_rules(db).await?;
    for r in rules.into_iter().filter(|r| r.enabled != 0) {
        let since = (Utc::now() - Duration::seconds(r.window_secs)).to_rfc3339();
        match r.kind.as_str() {
            "error_log_count" => {
                let count: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM logs WHERE timestamp >= ? AND level IN ('ERROR', 'FATAL') AND (? = '' OR service = ?)",
                )
                .bind(&since)
                .bind(&r.target)
                .bind(&r.target)
                .fetch_one(db)
                .await?;
                if (count.0 as f64) > r.threshold {
                    fire_alert(db, &r, "critical", &format!("{} error logs in last {}s", count.0, r.window_secs)).await?;
                }
            }
            "metric_p99" => {
                let vals: Vec<(f64,)> = sqlx::query_as("SELECT value FROM metrics WHERE name = ? AND timestamp >= ?")
                    .bind(&r.target)
                    .bind(&since)
                    .fetch_all(db)
                    .await?;
                let mut d = TDigest::new(120.0);
                for (v,) in vals { d.add(v); }
                d.compress();
                if let Some(p99) = d.quantile(0.99) {
                    if p99 > r.threshold {
                        fire_alert(db, &r, "warning", &format!("metric {} p99 {:.2} > {:.2}", r.target, p99, r.threshold)).await?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

async fn fire_alert(db: &SqlitePool, r: &AlertRuleRow, severity: &str, message: &str) -> sqlx::Result<()> {
    let recent: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM alerts WHERE rule_id = ? AND fired_at >= ?")
        .bind(&r.id)
        .bind((Utc::now() - Duration::seconds(60)).to_rfc3339())
        .fetch_one(db)
        .await?;
    if recent.0 > 0 { return Ok(()); }
    sqlx::query("INSERT INTO alerts (id, rule_id, rule_name, severity, message, fired_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(Uuid::new_v4().to_string())
        .bind(&r.id)
        .bind(&r.name)
        .bind(severity)
        .bind(message)
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Stats {
    pub logs: i64,
    pub metrics: i64,
    pub spans: i64,
    pub ingest_events_last_hour: i64,
    pub active_alerts: i64,
    pub services: i64,
}

pub async fn stats(db: &SqlitePool) -> sqlx::Result<Stats> {
    let since = (Utc::now() - Duration::hours(1)).to_rfc3339();
    let logs: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM logs").fetch_one(db).await?;
    let metrics: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM metrics").fetch_one(db).await?;
    let spans: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM spans").fetch_one(db).await?;
    let recent_logs: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM logs WHERE timestamp >= ?").bind(&since).fetch_one(db).await?;
    let recent_metrics: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM metrics WHERE timestamp >= ?").bind(&since).fetch_one(db).await?;
    let recent_spans: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM spans WHERE start_time >= ?").bind(&since).fetch_one(db).await?;
    let active_alerts: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL").fetch_one(db).await?;
    let services: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM (SELECT service FROM logs UNION SELECT service FROM spans)",
    ).fetch_one(db).await?;
    Ok(Stats {
        logs: logs.0,
        metrics: metrics.0,
        spans: spans.0,
        ingest_events_last_hour: recent_logs.0 + recent_metrics.0 + recent_spans.0,
        active_alerts: active_alerts.0,
        services: services.0,
    })
}
