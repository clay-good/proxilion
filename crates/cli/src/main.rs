//! `proxilion-cli` — operator CLI for log queries, chain verification,
//! end-to-end selftest, killswitch.
//!
//! Talks to the proxy's HTTP API (`/healthz`, `/api/v1/pca/...`) and, for
//! `selftest`, directly to the Trust Plane (`/v1/federation/info`,
//! `/v1/pca/issue`). For deeper SQL audit (action stream, blocked actions,
//! quarantine), connect to postgres — see `docs/specs/spec.md` §5.4.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde_json::{Value, json};

/// Proxilion CLI.
#[derive(Parser, Debug)]
#[command(version, about = "operator CLI for Proxilion", long_about = None)]
struct Cli {
    /// Proxy base URL (overrides PROXILION_URL env var).
    #[arg(long, env = "PROXILION_URL", default_value = "https://localhost:8443")]
    url: String,

    /// Trust Plane base URL (only used by `selftest`).
    #[arg(
        long,
        env = "TRUST_PLANE_URL",
        default_value = "http://localhost:8080"
    )]
    trust_plane: String,

    /// Accept self-signed certs (development only).
    #[arg(long)]
    insecure: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Probe the proxy's /healthz.
    Health,
    /// Fetch a single PCA by id.
    Pca {
        /// PCA UUID.
        id: String,
    },
    /// Walk a PCA chain from this leaf to PCA_0 and report verification.
    Verify {
        /// Leaf PCA UUID.
        id: String,
    },
    /// Run a synthetic end-to-end transaction (no real OAuth, no real SaaS).
    ///
    /// Steps:
    ///   1. /healthz must report ready
    ///   2. /v1/federation/info reachable on the Trust Plane
    ///   3. Mock IdP JWT → Trust Plane POST /v1/pca/issue → PCA_0
    ///
    /// Reports ✓/✗ per step with timings. Non-zero exit on any failure.
    Selftest,
    /// Live tail / list / show / export of the action log.
    #[command(subcommand)]
    Actions(ActionsCmd),
}

#[derive(Subcommand, Debug)]
enum ActionsCmd {
    /// Stream live action events (SSE) until interrupted.
    Tail {
        /// Filter: decision (allow|block|require_confirmation|rate_limit).
        #[arg(long)]
        decision: Option<String>,
        /// Filter: vendor.
        #[arg(long)]
        vendor: Option<String>,
        /// Filter: action verb (e.g. drive.files.get).
        #[arg(long)]
        action: Option<String>,
        /// Output format. Defaults to ndjson.
        #[arg(long, default_value = "ndjson")]
        format: String,
    },
    /// List paginated history.
    List {
        #[arg(long)]
        decision: Option<String>,
        #[arg(long)]
        vendor: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long, value_name = "EMAIL_OR_ID")]
        p_0: Option<String>,
        #[arg(long)]
        session_id: Option<String>,
        /// Window like "24h", "5m", "7d".
        #[arg(long)]
        since: Option<String>,
        /// Per-page limit (1..=500). Default 50.
        #[arg(long, default_value_t = 50)]
        limit: u32,
        /// Follow `next_before` cursors until exhausted.
        #[arg(long)]
        all: bool,
        /// Output: pretty | json | ndjson.
        #[arg(long, default_value = "pretty")]
        format: String,
    },
    /// Show a full action record with its PCA chain (ASCII inspector).
    Show {
        id: String,
        /// Output: pretty | json.
        #[arg(long, default_value = "pretty")]
        format: String,
    },
    /// Bulk audit export. Streams from the proxy to stdout or a file.
    Export {
        /// `ndjson` (default) | `csv`.
        #[arg(long, default_value = "ndjson")]
        format: String,
        /// Window like "30d", "7d", "24h", or an RFC3339 date.
        #[arg(long)]
        since: Option<String>,
        /// Upper bound, RFC3339. Defaults to now.
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        decision: Option<String>,
        #[arg(long)]
        vendor: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        p_0: Option<String>,
        /// Write to file (default: stdout).
        #[arg(long, short = 'o')]
        output: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(cli.insecure)
        .build()
        .context("building reqwest client")?;

    match cli.cmd {
        Cmd::Health => cmd_health(&http, &cli.url).await,
        Cmd::Pca { id } => cmd_pca(&http, &cli.url, &id).await,
        Cmd::Verify { id } => cmd_verify(&http, &cli.url, &id).await,
        Cmd::Selftest => cmd_selftest(&http, &cli.url, &cli.trust_plane).await,
        Cmd::Actions(sub) => cmd_actions(&http, &cli.url, sub).await,
    }
}

async fn cmd_actions(http: &reqwest::Client, url: &str, sub: ActionsCmd) -> Result<()> {
    match sub {
        ActionsCmd::Tail { decision, vendor, action, format } => {
            actions_tail(http, url, decision, vendor, action, &format).await
        }
        ActionsCmd::List {
            decision, vendor, action, p_0, session_id, since, limit, all, format,
        } => {
            actions_list(
                http, url, decision, vendor, action, p_0, session_id, since,
                limit, all, &format,
            )
            .await
        }
        ActionsCmd::Show { id, format } => actions_show(http, url, &id, &format).await,
        ActionsCmd::Export {
            format, since, until, decision, vendor, action, p_0, output,
        } => {
            actions_export(http, url, &format, since, until, decision, vendor, action, p_0, output)
                .await
        }
    }
}

/// Parse "5m" / "24h" / "7d" / RFC3339 into a UTC timestamp.
fn parse_since(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }
    let dur = humantime::parse_duration(s)
        .with_context(|| format!("--since {s:?} is not a duration or RFC3339 date"))?;
    let chrono_dur = chrono::Duration::from_std(dur)
        .map_err(|_| anyhow!("--since duration overflows"))?;
    Ok(chrono::Utc::now() - chrono_dur)
}

async fn actions_tail(
    http: &reqwest::Client,
    url: &str,
    decision: Option<String>,
    vendor: Option<String>,
    action: Option<String>,
    format: &str,
) -> Result<()> {
    let resp = http
        .get(format!("{url}/api/v1/actions/stream"))
        .send()
        .await
        .context("opening SSE stream")?
        .error_for_status()?;
    let mut stream = resp.bytes_stream();
    use futures_util::StreamExt;
    let mut buf = String::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("SSE chunk")?;
        let text = std::str::from_utf8(&chunk).unwrap_or("");
        buf.push_str(text);
        while let Some(idx) = buf.find("\n\n") {
            let frame: String = buf.drain(..idx + 2).collect();
            let mut data = String::new();
            let mut event = "action".to_string();
            for line in frame.lines() {
                if let Some(d) = line.strip_prefix("data:") {
                    data.push_str(d.trim_start());
                } else if let Some(e) = line.strip_prefix("event:") {
                    event = e.trim().to_string();
                }
            }
            if event != "action" || data.is_empty() { continue; }
            // Client-side filter — the SSE endpoint does not take query
            // params, so this is the place to apply tail-time filters.
            if !matches_tail_filter(&data, decision.as_deref(), vendor.as_deref(), action.as_deref()) {
                continue;
            }
            match format {
                "json" | "ndjson" => println!("{data}"),
                _ => print_pretty_event(&data),
            }
            use std::io::Write;
            std::io::stdout().flush().ok();
        }
    }
    Ok(())
}

fn matches_tail_filter(
    data: &str,
    decision: Option<&str>,
    vendor: Option<&str>,
    action: Option<&str>,
) -> bool {
    if decision.is_none() && vendor.is_none() && action.is_none() {
        return true;
    }
    let v: Value = match serde_json::from_str(data) {
        Ok(v) => v,
        Err(_) => return true,
    };
    let field = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("");
    if let Some(d) = decision { if field("decision") != d { return false; } }
    if let Some(d) = vendor   { if field("vendor")   != d { return false; } }
    if let Some(d) = action   { if field("action")   != d { return false; } }
    true
}

fn print_pretty_event(json: &str) {
    let v: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    let at = v.get("at").and_then(|x| x.as_str()).unwrap_or("");
    let vendor = v.get("vendor").and_then(|x| x.as_str()).unwrap_or("?");
    let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("?");
    let decision = v.get("decision").and_then(|x| x.as_str()).unwrap_or("?");
    let status = v.get("status").and_then(|x| x.as_u64()).unwrap_or(0);
    let p0 = v.get("p_0").and_then(|x| x.as_str()).unwrap_or("?");
    let dec_color = match decision {
        "allow" => GREEN,
        "block" => RED,
        _ => DIM,
    };
    println!(
        "{DIM}{at}{RESET}  {dec_color}{decision:>22}{RESET}  {status:>3}  {vendor}.{action}  {DIM}{p0}{RESET}"
    );
}

#[allow(clippy::too_many_arguments)]
async fn actions_list(
    http: &reqwest::Client,
    url: &str,
    decision: Option<String>,
    vendor: Option<String>,
    action: Option<String>,
    p_0: Option<String>,
    session_id: Option<String>,
    since: Option<String>,
    limit: u32,
    all: bool,
    format: &str,
) -> Result<()> {
    let since_dt = since.as_deref().map(parse_since).transpose()?;
    let mut before: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut total = 0usize;
    let limit = limit.clamp(1, 500);
    if matches!(format, "pretty") {
        println!(
            "{DIM}{:<25}  {:>22}  {:>3}  {:<32}  {}{RESET}",
            "at", "decision", "st", "action", "p_0"
        );
    }
    loop {
        let mut q = vec![format!("limit={limit}")];
        if let Some(v) = &decision { q.push(format!("decision={}", urlencode(v))); }
        if let Some(v) = &vendor { q.push(format!("vendor={}", urlencode(v))); }
        if let Some(v) = &action { q.push(format!("action={}", urlencode(v))); }
        if let Some(v) = &p_0 { q.push(format!("p_0={}", urlencode(v))); }
        if let Some(v) = &session_id { q.push(format!("session_id={}", urlencode(v))); }
        if let Some(b) = before { q.push(format!("before={}", urlencode(&b.to_rfc3339()))); }
        let endpoint = format!("{url}/api/v1/actions?{}", q.join("&"));
        let env: Value = http.get(&endpoint).send().await?.error_for_status()?.json().await?;
        let rows = env.get("rows").and_then(|x| x.as_array()).cloned().unwrap_or_default();
        for r in &rows {
            // Honor --since by stopping once we've crossed the boundary.
            if let Some(s) = since_dt {
                let at = r.get("at").and_then(|x| x.as_str()).and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&chrono::Utc))
                });
                if let Some(t) = at { if t < s { return Ok(()); } }
            }
            match format {
                "json" => println!("{}", serde_json::to_string(r)?),
                "ndjson" => println!("{}", serde_json::to_string(r)?),
                _ => print_pretty_event(&r.to_string()),
            }
            total += 1;
        }
        let next = env.get("next_before").and_then(|x| x.as_str()).map(|s| s.to_string());
        if !all || rows.is_empty() {
            if format == "pretty" {
                println!("{DIM}-- {total} rows --{RESET}");
            }
            return Ok(());
        }
        match next {
            Some(s) => {
                before = Some(chrono::DateTime::parse_from_rfc3339(&s)?.with_timezone(&chrono::Utc));
            }
            None => {
                if format == "pretty" {
                    println!("{DIM}-- {total} rows (end) --{RESET}");
                }
                return Ok(());
            }
        }
    }
}

async fn actions_show(http: &reqwest::Client, url: &str, id: &str, format: &str) -> Result<()> {
    let v: Value = http
        .get(format!("{url}/api/v1/actions/{}", urlencode(id)))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    println!("{}", "─".repeat(70));
    println!("action {}", v.get("id").and_then(|x| x.as_str()).unwrap_or("?"));
    println!("  at:       {}", v.get("at").and_then(|x| x.as_str()).unwrap_or("?"));
    println!("  vendor:   {}", v.get("vendor").and_then(|x| x.as_str()).unwrap_or("?"));
    println!("  action:   {}", v.get("action").and_then(|x| x.as_str()).unwrap_or("?"));
    println!("  method:   {}  {}", v.get("method").and_then(|x| x.as_str()).unwrap_or(""), v.get("path").and_then(|x| x.as_str()).unwrap_or(""));
    println!("  status:   {}", v.get("status").and_then(|x| x.as_u64()).unwrap_or(0));
    println!("  decision: {}", v.get("decision").and_then(|x| x.as_str()).unwrap_or("?"));
    println!("  p_0:      {}", v.get("p_0").and_then(|x| x.as_str()).unwrap_or("?"));
    if let Some(s) = v.get("session_id").and_then(|x| x.as_str()) {
        println!("  session:  {s}");
    }
    if let Some(r) = v.get("block_reason").and_then(|x| x.as_str()) {
        println!("  block:    {r}");
    }
    if let Some(p) = v.get("policy_id").and_then(|x| x.as_str()) {
        println!("  policy:   {p}");
    }
    println!();
    println!("PCA chain (root → leaf)");
    let chain = v.get("chain").and_then(|x| x.as_array()).cloned().unwrap_or_default();
    if chain.is_empty() {
        println!("  (none)");
    } else {
        let mut prev_ops: Option<std::collections::HashSet<String>> = None;
        for (i, link) in chain.iter().enumerate() {
            let hop = link.get("hop").and_then(|x| x.as_i64()).unwrap_or(-1);
            let icon = if hop == 0 { "🌱" } else { "🔗" };
            let pca_id = link.get("pca_id").and_then(|x| x.as_str()).unwrap_or("?");
            let p_0 = link.get("p_0").and_then(|x| x.as_str()).unwrap_or("?");
            let ops: Vec<String> = link
                .get("ops")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            println!(
                "  {icon} hop {hop:<2}  {DIM}pca={pca_id}{RESET}",
            );
            println!("       p_0={p_0}");
            if let Some(prev) = &prev_ops {
                let cur: std::collections::HashSet<String> = ops.iter().cloned().collect();
                let removed: Vec<&String> = prev.difference(&cur).collect();
                if removed.is_empty() {
                    println!("       ops [{}] — {DIM}(no narrowing){RESET}", ops.len());
                } else {
                    println!(
                        "       ops [{}] — {RED}narrowed: removed {}{RESET}",
                        ops.len(), removed.len()
                    );
                    for r in removed.iter().take(3) {
                        println!("          - {r}");
                    }
                }
            } else {
                println!("       ops [{}]", ops.len());
            }
            prev_ops = Some(ops.iter().cloned().collect());
            if i + 1 < chain.len() { println!("       │"); }
        }
    }
    if let Some(b) = v.get("chain_broken_at").and_then(|x| x.as_str()) {
        println!("  {RED}✗ chain broken at {b}{RESET}");
    } else if !chain.is_empty() {
        println!("  {GREEN}✓ chain intact ({} link{}){RESET}", chain.len(), if chain.len() == 1 { "" } else { "s" });
    }
    println!("{}", "─".repeat(70));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn actions_export(
    http: &reqwest::Client,
    url: &str,
    format: &str,
    since: Option<String>,
    until: Option<String>,
    decision: Option<String>,
    vendor: Option<String>,
    action: Option<String>,
    p_0: Option<String>,
    output: Option<String>,
) -> Result<()> {
    let mut q = vec![format!("format={}", urlencode(format))];
    if let Some(s) = since {
        let dt = parse_since(&s)?;
        q.push(format!("since={}", urlencode(&dt.to_rfc3339())));
    }
    if let Some(u) = until {
        q.push(format!("until={}", urlencode(&u)));
    }
    if let Some(v) = &decision { q.push(format!("decision={}", urlencode(v))); }
    if let Some(v) = &vendor { q.push(format!("vendor={}", urlencode(v))); }
    if let Some(v) = &action { q.push(format!("action={}", urlencode(v))); }
    if let Some(v) = &p_0 { q.push(format!("p_0={}", urlencode(v))); }
    let endpoint = format!("{url}/api/v1/actions/export?{}", q.join("&"));
    let resp = http.get(&endpoint).send().await?.error_for_status()?;
    let mut stream = resp.bytes_stream();
    use futures_util::StreamExt;
    use std::io::Write;
    let mut sink: Box<dyn Write> = match output {
        Some(p) => Box::new(std::io::BufWriter::new(std::fs::File::create(&p)
            .with_context(|| format!("creating {p}"))?)),
        None => Box::new(std::io::BufWriter::new(std::io::stdout().lock())),
    };
    let mut bytes_written: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read export chunk")?;
        sink.write_all(&chunk)?;
        bytes_written += chunk.len() as u64;
    }
    sink.flush()?;
    eprintln!("{DIM}exported {bytes_written} bytes ({format}){RESET}");
    Ok(())
}

async fn cmd_health(http: &reqwest::Client, url: &str) -> Result<()> {
    let v: Value = http
        .get(format!("{url}/healthz"))
        .send()
        .await?
        .json()
        .await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

async fn cmd_pca(http: &reqwest::Client, url: &str, id: &str) -> Result<()> {
    let v: Value = http
        .get(format!("{url}/api/v1/pca/{}", urlencode(id)))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

async fn cmd_verify(http: &reqwest::Client, url: &str, id: &str) -> Result<()> {
    let v: Value = http
        .get(format!("{url}/api/v1/pca/{}/verify", urlencode(id)))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    let intact = v.get("intact").and_then(|x| x.as_bool()).unwrap_or(false);
    if !intact {
        std::process::exit(1);
    }
    Ok(())
}

// ============ selftest ============

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

fn ok(name: &str, latency_ms: u128, detail: &str) {
    println!(
        "  {GREEN}✓{RESET} {name:<28}{DIM}{:>6}ms{RESET}   {detail}",
        latency_ms
    );
}
fn fail(name: &str, latency_ms: u128, detail: &str) {
    println!(
        "  {RED}✗{RESET} {name:<28}{DIM}{:>6}ms{RESET}   {RED}{detail}{RESET}"
    , latency_ms);
}

async fn cmd_selftest(
    http: &reqwest::Client,
    proxy_url: &str,
    trust_plane_url: &str,
) -> Result<()> {
    println!("proxilion selftest");
    println!("  proxy:       {proxy_url}");
    println!("  trust-plane: {trust_plane_url}\n");

    let mut all_ok = true;

    // 1. /healthz ready
    let t = Instant::now();
    let health_res = http.get(format!("{proxy_url}/healthz")).send().await;
    let dt = t.elapsed().as_millis();
    match health_res {
        Ok(r) => {
            let status = r.status();
            match r.json::<Value>().await {
                Ok(body) => {
                    let ready = body.get("ready").and_then(|x| x.as_bool()).unwrap_or(false);
                    if ready {
                        ok("proxy /healthz", dt, "ready=true");
                    } else {
                        fail("proxy /healthz", dt, &format!("status={status}, ready=false — see `proxilion-cli health`"));
                        all_ok = false;
                    }
                }
                Err(e) => {
                    fail("proxy /healthz", dt, &format!("non-JSON body: {e}"));
                    all_ok = false;
                }
            }
        }
        Err(e) => {
            fail("proxy /healthz", dt, &format!("unreachable: {e}"));
            all_ok = false;
        }
    }

    // 2. Trust Plane /v1/federation/info reachable + valid response
    let t = Instant::now();
    let info_res = http
        .get(format!("{trust_plane_url}/v1/federation/info"))
        .send()
        .await;
    let dt = t.elapsed().as_millis();
    let cat_kid: Option<String> = match info_res {
        Ok(r) if r.status().is_success() => match r.json::<FederationInfo>().await {
            Ok(info) => {
                ok(
                    "trust-plane /federation/info",
                    dt,
                    &format!("kid={} pubkey={} bytes (b64)", info.kid, info.public_key.len()),
                );
                Some(info.kid)
            }
            Err(e) => {
                fail("trust-plane /federation/info", dt, &format!("bad JSON: {e}"));
                all_ok = false;
                None
            }
        },
        Ok(r) => {
            fail("trust-plane /federation/info", dt, &format!("status {}", r.status()));
            all_ok = false;
            None
        }
        Err(e) => {
            fail("trust-plane /federation/info", dt, &format!("unreachable: {e}"));
            all_ok = false;
            None
        }
    };

    // 3. Mock IdP JWT → POST /v1/pca/issue → PCA_0
    if cat_kid.is_some() {
        let t = Instant::now();
        let now = chrono::Utc::now().timestamp();
        let jwt = make_mock_jwt(&json!({
            "iss": "https://demo.proxilion.local/idp",
            "sub": "alice@selftest.local",
            "preferred_username": "alice@selftest.local",
            "iat": now,
            "exp": now + 300,
            "groups": ["engineering"],
            // Trust Plane (see provenance-plane/.../api/handlers/issue.rs)
            // requires the `pic_ops` claim. In a real deployment the
            // federation bridge synthesizes this from the IdP group → ops
            // mapping; for selftest we hand-write a minimal set.
            "pic_ops": ["read:claims:alice", "drive:read:engineering/*"],
        }));
        let issue_body = json!({
            "credential": jwt,
            "credential_type": "jwt",
            "ops": ["read:claims:alice", "drive:read:engineering/*"],
            "executor_binding": { "service": "proxilion-selftest" },
        });
        let issue_res = http
            .post(format!("{trust_plane_url}/v1/pca/issue"))
            .json(&issue_body)
            .send()
            .await;
        let dt = t.elapsed().as_millis();
        match issue_res {
            Ok(r) if r.status().is_success() => match r.json::<IssuePcaResponse>().await {
                Ok(resp) => {
                    if resp.hop == 0 && !resp.ops.is_empty() {
                        ok(
                            "PCA_0 issuance",
                            dt,
                            &format!(
                                "hop=0 p_0={} ops={} pca_bytes={}",
                                resp.p_0,
                                resp.ops.len(),
                                resp.pca.len()
                            ),
                        );
                    } else {
                        fail(
                            "PCA_0 issuance",
                            dt,
                            &format!("malformed: hop={} ops={}", resp.hop, resp.ops.len()),
                        );
                        all_ok = false;
                    }
                }
                Err(e) => {
                    fail("PCA_0 issuance", dt, &format!("bad JSON: {e}"));
                    all_ok = false;
                }
            },
            Ok(r) => {
                let s = r.status();
                let body = r.text().await.unwrap_or_default();
                fail(
                    "PCA_0 issuance",
                    dt,
                    &format!("status {s}: {}", body.chars().take(140).collect::<String>()),
                );
                all_ok = false;
            }
            Err(e) => {
                fail("PCA_0 issuance", dt, &format!("unreachable: {e}"));
                all_ok = false;
            }
        }
    } else {
        fail("PCA_0 issuance", 0, "skipped (trust-plane unreachable)");
        all_ok = false;
    }

    println!();
    if all_ok {
        println!("{GREEN}selftest: PASS{RESET}");
        Ok(())
    } else {
        println!("{RED}selftest: FAIL{RESET}");
        Err(anyhow!("one or more selftest steps failed"))
    }
}

fn make_mock_jwt(payload: &Value) -> String {
    // "alg": "none" — Trust Plane's stub validator only decodes the payload
    // (verified against `provenance-plane/.../api/handlers/issue.rs`). When
    // the bridge service lands we'll switch to a real JWKS-signed token.
    let header = B64URL.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let body = B64URL.encode(payload.to_string().as_bytes());
    format!("{header}.{body}.signature")
}

#[derive(Deserialize)]
struct FederationInfo {
    kid: String,
    public_key: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct IssuePcaResponse {
    pca: String,
    hop: u32,
    p_0: String,
    ops: Vec<String>,
    #[serde(default)]
    exp: Option<String>,
}

fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}
