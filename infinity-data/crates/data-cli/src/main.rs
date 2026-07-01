use anyhow::{bail, Context};
use reqwest::header::AUTHORIZATION;
use serde_json::{json, Value};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "help" || args[0] == "--help" {
        print_help();
        return Ok(());
    }
    let server = take_opt(&mut args, "--server")
        .or_else(|| std::env::var("DATA_SERVER_URL").ok())
        .unwrap_or_else(|| "http://localhost:8094".into());
    let token = take_opt(&mut args, "--token").or_else(|| std::env::var("DATA_API_TOKEN").ok());
    let cmd = args.remove(0);
    let client = reqwest::Client::new();

    match cmd.as_str() {
        "health" => {
            let v: Value = client
                .get(format!("{server}/health"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        "login" => {
            if args.len() != 2 {
                bail!("usage: infinity-data-cli login <email> <password> [--server URL]");
            }
            let resp = client
                .post(format!("{server}/auth/login"))
                .json(&json!({"email": args[0], "password": args[1]}))
                .send()
                .await?
                .error_for_status()?;
            let cookie = resp
                .headers()
                .get("set-cookie")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body: Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            if !cookie.is_empty() {
                println!("Set-Cookie: {cookie}");
            }
        }
        "create-collection" => {
            if args.len() < 2 || args.len() > 3 {
                bail!("usage: infinity-data-cli create-collection <name> <dim> [metric] --token TOKEN");
            }
            let dim: usize = args[1].parse().context("dim must be a positive integer")?;
            let metric = args.get(2).cloned().unwrap_or_else(|| "cosine".into());
            let v = authed(
                client.post(format!("{server}/api/collections")),
                token.as_deref(),
            )
            .json(&json!({"name": args[0], "dim": dim, "metric": metric}))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        "insert" => {
            if args.len() < 3 || args.len() > 4 {
                bail!("usage: infinity-data-cli insert <collection> <id> <vector-json> [metadata-json] --token TOKEN");
            }
            let vector: Vec<f32> =
                serde_json::from_str(&args[2]).context("vector must be a JSON number array")?;
            let metadata: Option<Value> = if args.len() == 4 {
                Some(serde_json::from_str(&args[3]).context("metadata must be JSON")?)
            } else {
                None
            };
            let point = json!({"id": args[1], "vector": vector, "metadata": metadata});
            let v = authed(
                client.post(format!("{server}/api/collections/{}/vectors", args[0])),
                token.as_deref(),
            )
            .json(&json!({"points": [point]}))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        "search" => {
            if args.len() < 2 || args.len() > 3 {
                bail!(
                    "usage: infinity-data-cli search <collection> <vector-json> [k] --token TOKEN"
                );
            }
            let vector: Vec<f32> =
                serde_json::from_str(&args[1]).context("vector must be a JSON number array")?;
            let k: usize = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(10);
            let v = authed(
                client.post(format!("{server}/api/collections/{}/search", args[0])),
                token.as_deref(),
            )
            .json(&json!({"vector": vector, "k": k}))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        _ => {
            print_help();
            bail!("unknown command: {cmd}");
        }
    }
    Ok(())
}

fn authed(req: reqwest::RequestBuilder, token: Option<&str>) -> reqwest::RequestBuilder {
    match token {
        Some(t) => req.header(AUTHORIZATION, format!("Bearer {t}")),
        None => req,
    }
}

fn take_opt(args: &mut Vec<String>, name: &str) -> Option<String> {
    if let Some(pos) = args.iter().position(|a| a == name) {
        args.remove(pos);
        if pos < args.len() {
            Some(args.remove(pos))
        } else {
            None
        }
    } else {
        None
    }
}

fn print_help() {
    eprintln!("Infinity Data CLI");
    eprintln!("  health [--server URL]");
    eprintln!("  login <email> <password> [--server URL]");
    eprintln!("  create-collection <name> <dim> [metric] --token TOKEN");
    eprintln!("  insert <collection> <id> <vector-json> [metadata-json] --token TOKEN");
    eprintln!("  search <collection> <vector-json> [k] --token TOKEN");
    eprintln!("Env: DATA_SERVER_URL, DATA_API_TOKEN");
}
