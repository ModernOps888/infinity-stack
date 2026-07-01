//! Infinity Observe Agent ? tails a file or emits sample telemetry to the server.

mod config;

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::time::Duration;

use anyhow::{bail, Context};
use chrono::Utc;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::json;
use tokio::time::sleep;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;

use crate::config::AgentConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = AgentConfig::load().context("loading agent config")?;
    if cfg.ingest_key.trim().is_empty() {
        bail!("ingest key required: pass --key or set INFINITY_AGENT_INGEST_KEY");
    }
    let client = client(&cfg.ingest_key)?;
    if let Some(path) = &cfg.file {
        tail_file(&client, &cfg, path).await?;
    } else {
        generate_samples(&client, &cfg).await?;
    }
    Ok(())
}

fn client(key: &str) -> anyhow::Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {key}"))?,
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(reqwest::Client::builder()
        .default_headers(headers)
        .build()?)
}

async fn tail_file(client: &reqwest::Client, cfg: &AgentConfig, path: &str) -> anyhow::Result<()> {
    let mut pos = 0;
    loop {
        let mut file = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
        file.seek(SeekFrom::Start(pos))?;
        let mut reader = BufReader::new(file);
        let mut lines = Vec::new();
        let mut buf = String::new();
        while reader.read_line(&mut buf)? > 0 {
            let line = buf.trim_end().to_string();
            if !line.is_empty() {
                lines.push(json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "level": infer_level(&line),
                    "service": cfg.service,
                    "message": line,
                    "attributes": { "source": path }
                }));
            }
            buf.clear();
        }
        pos = reader.stream_position()?;
        if !lines.is_empty() {
            post(client, &cfg.server_url, "/v1/logs", lines).await?;
        }
        if cfg.once {
            break;
        }
        sleep(Duration::from_secs(cfg.interval_secs.max(1))).await;
    }
    Ok(())
}

async fn generate_samples(client: &reqwest::Client, cfg: &AgentConfig) -> anyhow::Result<()> {
    loop {
        let (latency, error) = {
            let mut rng = rand::thread_rng();
            (rng.gen_range(20.0..450.0), rng.gen_bool(0.08))
        };
        let now = Utc::now().to_rfc3339();
        post(client, &cfg.server_url, "/v1/logs", vec![json!({
            "timestamp": now,
            "level": if error { "ERROR" } else { "INFO" },
            "service": cfg.service,
            "message": if error { "request failed with upstream timeout" } else { "request completed" },
            "attributes": { "agent": "infinity-observe-agent" }
        })]).await?;
        post(
            client,
            &cfg.server_url,
            "/v1/metrics",
            vec![json!({
                "timestamp": Utc::now().to_rfc3339(),
                "name": "http.server.duration_ms",
                "value": latency,
                "tags": { "service": cfg.service }
            })],
        )
        .await?;
        let trace_id = Uuid::new_v4().simple().to_string();
        let root_span = Uuid::new_v4().simple().to_string();
        post(
            client,
            &cfg.server_url,
            "/v1/traces",
            vec![json!({
                "trace_id": trace_id,
                "span_id": root_span,
                "name": "GET /api/demo",
                "service": cfg.service,
                "start": Utc::now().to_rfc3339(),
                "duration_ms": latency,
                "status": if error { "ERROR" } else { "OK" }
            })],
        )
        .await?;
        tracing::info!(latency_ms = latency, error, "shipped sample telemetry");
        if cfg.once {
            break;
        }
        sleep(Duration::from_secs(cfg.interval_secs.max(1))).await;
    }
    Ok(())
}

async fn post(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    body: Vec<serde_json::Value>,
) -> anyhow::Result<()> {
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let res = client.post(&url).json(&body).send().await?;
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        bail!("server rejected {path}: {status} {text}");
    }
    Ok(())
}

fn infer_level(line: &str) -> &'static str {
    let upper = line.to_ascii_uppercase();
    if upper.contains("ERROR") || upper.contains("FATAL") {
        "ERROR"
    } else if upper.contains("WARN") {
        "WARN"
    } else if upper.contains("DEBUG") {
        "DEBUG"
    } else {
        "INFO"
    }
}
