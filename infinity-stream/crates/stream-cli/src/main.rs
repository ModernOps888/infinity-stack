use anyhow::{bail, Context};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") { usage(); return Ok(()); }
    let server = take_opt(&mut args, "--server").unwrap_or_else(|| "http://127.0.0.1:9300".into());
    let key = take_opt(&mut args, "--key").or_else(|| std::env::var("INFINITY_STREAM_KEY").ok()).context("--key or INFINITY_STREAM_KEY required")?;
    let cmd = args.get(0).cloned().context("command required")?;
    args.remove(0);
    let http = reqwest::Client::new();
    match cmd.as_str() {
        "produce" => {
            let topic = pop(&mut args, "topic")?;
            let count: usize = take_opt(&mut args, "--count").unwrap_or_else(|| "1".into()).parse()?;
            let partition = take_opt(&mut args, "--partition").map(|v| v.parse::<u32>()).transpose()?;
            let value = take_opt(&mut args, "--value").unwrap_or_else(|| "hello from infinity-stream-cli".into());
            for i in 0..count {
                let body = json!({"partition": partition, "key": format!("cli-{i}"), "value": {"message": value, "n": i}});
                let res = http.post(format!("{server}/v1/topics/{topic}/produce")).bearer_auth(&key).json(&body).send().await?;
                print_response(res).await?;
            }
        }
        "consume" => {
            let topic = pop(&mut args, "topic")?;
            let partition: u32 = take_opt(&mut args, "--partition").unwrap_or_else(|| "0".into()).parse()?;
            let offset: u64 = take_opt(&mut args, "--offset").unwrap_or_else(|| "0".into()).parse()?;
            let max: usize = take_opt(&mut args, "--max").unwrap_or_else(|| "10".into()).parse()?;
            let res = http.get(format!("{server}/v1/topics/{topic}/consume?partition={partition}&offset={offset}&max={max}")).bearer_auth(&key).send().await?;
            print_response(res).await?;
        }
        "search" => {
            let index = pop(&mut args, "index")?;
            let query = take_opt(&mut args, "--query").or_else(|| take_opt(&mut args, "-q")).context("--query required")?;
            let k: usize = take_opt(&mut args, "--k").unwrap_or_else(|| "10".into()).parse()?;
            let res = http.get(format!("{server}/v1/indexes/{index}/search")).bearer_auth(&key).query(&[("q", query), ("k", k.to_string())]).send().await?;
            print_response(res).await?;
        }
        _ => bail!("unknown command: {cmd}"),
    }
    Ok(())
}

fn take_opt(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.remove(i);
    if i < args.len() { Some(args.remove(i)) } else { None }
}
fn pop(args: &mut Vec<String>, what: &str) -> anyhow::Result<String> {
    if args.is_empty() { bail!("{what} required") } else { Ok(args.remove(0)) }
}
async fn print_response(res: reqwest::Response) -> anyhow::Result<()> {
    let status = res.status();
    let text = res.text().await?;
    if !status.is_success() { bail!("HTTP {status}: {text}"); }
    let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text}));
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
fn usage() {
    eprintln!("Usage:\n  infinity-stream-cli --key KEY [--server URL] produce TOPIC [--count N] [--partition P] [--value TEXT]\n  infinity-stream-cli --key KEY [--server URL] consume TOPIC [--partition P] [--offset O] [--max M]\n  infinity-stream-cli --key KEY [--server URL] search INDEX --query TEXT [--k N]");
}
