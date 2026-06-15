//! `proxilion-cli` — operator CLI for log queries, chain verification,
//! end-to-end selftest, killswitch.
//!
//! Talks to the proxy's HTTP API (`/healthz`, `/api/v1/pca/...`) and, for
//! `selftest`, directly to the Trust Plane (`/v1/federation/info`,
//! `/v1/pca/issue`). For deeper SQL audit (action stream, blocked actions,
//! quarantine), connect to postgres — see `docs/specs/spec.md` §5.4.

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
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
    #[arg(long, env = "TRUST_PLANE_URL", default_value = "http://localhost:8080")]
    trust_plane: String,

    /// Accept self-signed certs (development only).
    #[arg(long)]
    insecure: bool,

    /// Operator token (sent as `Authorization: Bearer <token>` on
    /// `/api/v1/*` requests). When the proxy runs with
    /// `PROXILION_DISABLE_OPERATOR_AUTH=1` this can be empty.
    #[arg(long, env = "PROXILION_OPERATOR_TOKEN", default_value = "")]
    token: String,

    /// When to colorize output: auto (color iff stdout is a TTY and
    /// `NO_COLOR` is unset), always, or never.
    /// surface-delight-and-correctness.md §3.2.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,

    #[command(subcommand)]
    cmd: Cmd,
}

/// `--color` policy. `auto` honors `NO_COLOR` and the TTY-ness of stdout.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Emit a shell completion script for `proxilion-cli`.
    ///
    /// surface-delight-and-correctness.md §3.4. Offline — talks to no proxy.
    /// Install (bash): `proxilion-cli completion bash > /etc/bash_completion.d/proxilion-cli`.
    /// zsh: write to a dir on `$fpath`; fish: `~/.config/fish/completions/`.
    Completion {
        /// Target shell: bash | zsh | fish | powershell | elvish.
        shell: Shell,
    },
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
    /// Operator-token management (ui-less-surfaces.md §4.4). Writes
    /// directly to postgres via `DATABASE_URL` — no token required (this
    /// is how the bootstrap token is minted).
    #[command(subcommand)]
    Tokens(TokensCmd),
    /// Policy hot-reload + mode flips (ui-less-surfaces.md §2 + §4).
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Blocked-action queue: list / show / approve / reject.
    #[command(subcommand)]
    Blocked(BlockedCmd),
    /// Notifier diagnostics (ui-less-surfaces.md §4.1).
    #[command(subcommand)]
    Notifier(NotifierCmd),
    /// System + setup snapshot. Combines /healthz reachability + the
    /// /api/v1/setup/status checklist into a single one-screen report.
    /// Exits non-zero when /healthz is `ready:false` so a CI runner /
    /// shell pipeline can gate on `proxilion-cli status` without parsing
    /// JSON. ui-less-surfaces.md §4.1.
    Status {
        /// Output: pretty (default) | json.
        #[arg(long, default_value = "pretty")]
        format: String,
    },
    /// PCA inspection (ui-less-surfaces.md §4.1 — `pic` command tree).
    /// Subset of the upstream §4.1 sketch: `show` and `verify` (the live
    /// invariants-mode flip is wired through `policy set-mode` per
    /// ui-less-surfaces.md §2 deviation 1; this subcommand is purely
    /// the chain inspector).
    #[command(subcommand)]
    Pic(PicCmd),
    /// Killswitch — revoke an agent's right to take further actions.
    /// Spec.md §3.2. All three forms write to `kill_records`, mark
    /// matching `agent_bearers.revoked_at`, and the auth middleware
    /// rejects on the next request.
    #[command(subcommand)]
    Killswitch(KillswitchCmd),
    /// Prometheus `/metrics` helpers (ui-less-surfaces.md §4.1).
    #[command(subcommand)]
    Metrics(MetricsCmd),
    /// Trust Plane diagnostics (ui-less-surfaces.md §4.1).
    #[command(subcommand)]
    TrustPlane(TrustPlaneCmd),
    /// OAuth client registry (ui-less-surfaces.md §4.1). Writes directly
    /// to postgres via `DATABASE_URL` — no token required (same bootstrap
    /// pattern as `tokens`). Replaces hand-editing `oauth_clients` via
    /// psql / a migration.
    #[command(subcommand)]
    Clients(ClientsCmd),
}

#[derive(Subcommand, Debug)]
enum ClientsCmd {
    /// List every OAuth client. By default skips revoked rows; `--all`
    /// shows them.
    List {
        #[arg(long)]
        all: bool,
        /// Output: pretty (default) | json.
        #[arg(long, default_value = "pretty")]
        format: String,
    },
    /// Register a new OAuth client.
    Add {
        /// Stable client id the agent will send in `?client_id=...`.
        id: String,
        #[arg(long)]
        name: String,
        /// One or more allowed redirect URIs. Pass `--redirect-uri` once
        /// per URI; the agent's redirect_uri must match one exactly.
        #[arg(long = "redirect-uri", required = true)]
        redirect_uri: Vec<String>,
    },
    /// Soft-revoke a client. The row stays in the table (historical
    /// sessions still resolve) but the authorize handler refuses new
    /// flows. ui-less-surfaces.md §4.1.
    Revoke {
        id: String,
        #[arg(long, default_value = "operator-initiated")]
        reason: String,
        /// Preview whether the client would be revoked (and that it exists and
        /// is not already revoked) without writing. §3.3.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand, Debug)]
enum MetricsCmd {
    /// Curl /metrics and pretty-print the top N series by sample count.
    /// Mounted outside operator-auth — same trust boundary as the
    /// Prometheus scrape target (assume operator network is private).
    Sample {
        /// Show only series whose name contains this substring.
        #[arg(long)]
        filter: Option<String>,
        /// Print every metric line in raw exposition format instead of
        /// the grouped summary.
        #[arg(long)]
        raw: bool,
    },
}

#[derive(Subcommand, Debug)]
enum TrustPlaneCmd {
    /// Fetch the Trust Plane's federation/info endpoint — confirms the
    /// upstream is reachable and surfaces the CAT key id the proxy will
    /// verify chain signatures against.
    Info,
}

#[derive(Subcommand, Debug)]
enum PicCmd {
    /// Fetch a PCA by id (same payload as `proxilion-cli pca`, kept here
    /// so `pic show <id>` reads naturally alongside `pic verify <id>`).
    Show {
        /// PCA UUID.
        id: String,
    },
    /// Walk a chain from this leaf to PCA_0 and report the result.
    /// Non-zero exit when `intact:false`.
    Verify {
        /// Leaf PCA UUID.
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum KillswitchCmd {
    /// Revoke a single session (`pxl_live_*` bearer chain rooted in this
    /// OAuth session). All bearers under the session and all PCA-issuance
    /// rights tied to it are revoked atomically.
    Session {
        /// Session UUID (the `id` column on `oauth_sessions`).
        id: String,
        /// Operator-visible reason; stored on `kill_records.reason`.
        #[arg(long, default_value = "operator-initiated")]
        reason: String,
        /// Preview the blast radius (count of bearers that WOULD be revoked)
        /// without revoking anything. surface-delight-and-correctness.md §3.3.
        #[arg(long)]
        dry_run: bool,
    },
    /// Revoke every active session for a user (`p_0`). Use for full-user
    /// kill — e.g., suspended account, compromised credentials.
    User {
        /// `p_0` value (typically `user:alice@org.com`, but accepts any
        /// PrincipalIdentifier-shaped string).
        p_0: String,
        #[arg(long, default_value = "operator-initiated")]
        reason: String,
        /// Preview without revoking. §3.3.
        #[arg(long)]
        dry_run: bool,
    },
    /// Revoke EVERY active session globally. Requires explicit confirmation
    /// to guard against fat-fingered fleet-wide kills.
    All {
        /// Must be `yes` (case-sensitive) for the kill to fire. Not required
        /// with `--dry-run` (a preview revokes nothing).
        #[arg(long, default_value = "")]
        confirm: String,
        #[arg(long, default_value = "operator-initiated")]
        reason: String,
        /// Preview the fleet-wide blast radius without revoking. §3.3.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand, Debug)]
enum NotifierCmd {
    /// Display the current webhook + burst-suppressor config.
    Show {
        #[arg(long, default_value = "pretty")]
        format: String,
    },
    /// Send a synthetic test notification. Default fans out to every
    /// configured driver; `--driver <name>` targets one and 412s if
    /// that driver isn't configured. ui-less-surfaces.md §4.1.
    Test {
        /// One of `all` (default) | `webhook` | `slack` | `email`.
        #[arg(long, default_value = "all")]
        driver: String,
    },
    /// Read the persisted notifier_config row.
    Config,
    /// Set / update the webhook driver config (DB-stored, hot-swapped on
    /// the proxy without restart). ui-less-surfaces.md §8.4.
    SetWebhook {
        /// Webhook URL the proxy POSTs to.
        #[arg(long)]
        url: String,
        /// HMAC secret (hex, ≥32 chars).
        #[arg(long)]
        hmac_hex: String,
        /// Disable the webhook without removing the row.
        #[arg(long)]
        disabled: bool,
    },
    /// Set / update the Slack driver config (ui-less-surfaces.md §5.3).
    /// Outbound: posts Block Kit message to the incoming-webhook URL.
    /// Inbound: verifies button-click POSTs via the signing-secret.
    SetSlack {
        /// Slack incoming-webhook URL (Slack workspace admin > Apps > your app).
        #[arg(long)]
        incoming_webhook_url: String,
        /// Slack signing secret (32-char hex from "Basic Information").
        #[arg(long)]
        signing_secret: String,
        /// Disable without removing the row.
        #[arg(long)]
        disabled: bool,
    },
    /// Set / update the Email driver config (ui-less-surfaces.md §5.4).
    /// Sends plain-text + HTML email with single-use signed approve/reject
    /// URLs on every blocked action.
    SetEmail {
        /// SMTP relay URL: smtps://user:pass@host:465 or smtp://host:25.
        #[arg(long)]
        smtp_url: String,
        /// RFC 5322 from address (e.g. "Proxilion <secops@org.com>").
        #[arg(long)]
        from: String,
        /// Recipient(s). Repeat for multiple addresses.
        #[arg(long = "to", required = true)]
        to: Vec<String>,
        /// Disable without removing the row.
        #[arg(long)]
        disabled: bool,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCmd {
    /// List current policies + modes.
    List {
        /// Optional mode filter: enforce | observe | disabled.
        #[arg(long)]
        mode: Option<String>,
        /// Output: pretty | json.
        #[arg(long, default_value = "pretty")]
        format: String,
    },
    /// Show a single policy by id. Pulls the current loaded policy set
    /// from the proxy (`GET /api/v1/policy`) and filters locally — no
    /// new endpoint needed.
    Show {
        /// Policy id.
        id: String,
        #[arg(long, default_value = "pretty")]
        format: String,
    },
    /// Parse a candidate YAML file and report whether it's loadable.
    /// Exit 0 on success, 1 on parse failure. ui-less-surfaces.md §4.1.
    /// Local-only — does not touch the proxy or DB; safe to run in CI.
    Validate {
        /// YAML file to validate.
        file: String,
    },
    /// Diff two policy YAML files. Reports added / removed / modified
    /// policy ids and per-policy field deltas (mode, decision shape,
    /// match-expression text, required_ops). Local-only, no proxy hit.
    Diff {
        /// Baseline YAML file.
        before: String,
        /// Candidate YAML file.
        after: String,
        #[arg(long, default_value = "pretty")]
        format: String,
    },
    /// Force a re-read from disk.
    Reload,
    /// Flip a single policy between observe / enforce / disabled.
    SetMode {
        /// Policy id.
        id: String,
        /// Target mode: `enforce`, `observe`, or `disabled`.
        mode: String,
    },
    /// Open the live policy YAML in `$EDITOR`, validate on save, and
    /// hot-reload the proxy. ui-less-surfaces.md §4.1 `policy edit`.
    ///
    /// File-path resolution: `--file <path>` wins; otherwise the path
    /// is pulled from `GET /api/v1/policy` (`source` field). When the
    /// proxy's source path isn't reachable from this machine (remote
    /// deployment), pass `--file` explicitly to edit a local copy.
    ///
    /// Pre-flight: a backup copy is dropped at `<path>.bak` before the
    /// editor opens. On a validation failure the new file is reverted
    /// from the backup; the backup is removed on a successful reload.
    Edit {
        /// Path to the policy YAML. If unset, queried from the proxy.
        #[arg(long)]
        file: Option<String>,
        /// Editor command. Defaults to `$EDITOR`, then `$VISUAL`, then
        /// `vi`. Passed verbatim to the shell, so you can use e.g.
        /// `--editor "code --wait"`.
        #[arg(long)]
        editor: Option<String>,
        /// Skip the `POST /api/v1/policy/reload` after the save.
        /// Local-only validation; the operator can hot-reload manually
        /// later via `proxilion-cli policy reload`.
        #[arg(long)]
        no_reload: bool,
    },
    /// Replay historical action_events against a candidate YAML and
    /// report would-have-block deltas per policy. ui-less-surfaces.md §2.4.
    Simulate {
        /// Candidate YAML file.
        file: String,
        /// Window: `last-7d`, `last-24h`, `last-1h`, or an explicit
        /// `--since` / `--until` pair via the standard CLI flags above.
        #[arg(long, default_value = "last-7d")]
        against: String,
        /// Customer domain for `${customer_domain}` substitution. If
        /// unset, falls back to `PROXILION_CUSTOMER_DOMAIN` then a
        /// reasonable default.
        #[arg(long)]
        customer_domain: Option<String>,
        /// Per-page fetch limit. Default 500 (the proxy max).
        #[arg(long, default_value_t = 500)]
        page_limit: u32,
        /// Output format. `pretty` (default) | `json`.
        #[arg(long, default_value = "pretty")]
        format: String,
        /// Exit non-zero (code 1) when any policy's delta exceeds this
        /// percentage of replayed events. Useful in CI gates.
        #[arg(long)]
        fail_if_delta_exceeds: Option<f64>,
    },
}

#[derive(Subcommand, Debug)]
enum BlockedCmd {
    /// List blocked actions, default filter pending.
    List {
        /// `pending` (default) | `approved` | `overridden` | `rejected` | `expired` | `all`.
        #[arg(long, default_value = "pending")]
        status: String,
        /// Filter by p_0.
        #[arg(long)]
        p_0: Option<String>,
        /// Filter by policy_id.
        #[arg(long)]
        policy_id: Option<String>,
        /// Per-page limit (1..=200, default 50).
        #[arg(long, default_value_t = 50)]
        limit: u32,
        /// Output: pretty | json.
        #[arg(long, default_value = "pretty")]
        format: String,
    },
    /// Show one blocked-action record (full envelope).
    Show {
        id: String,
        /// Output: pretty | json.
        #[arg(long, default_value = "pretty")]
        format: String,
    },
    /// Approve a blocked action with a justification.
    Approve {
        id: String,
        #[arg(long)]
        justification: String,
        /// Approver subject (defaults to $USER@cli).
        #[arg(long)]
        approver: Option<String>,
        /// TTL in minutes for the override (1..=1440).
        #[arg(long)]
        ttl: Option<u32>,
    },
    /// Reject a blocked action.
    Reject {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum TokensCmd {
    /// Mint a new operator token. Prints once to stdout; only the SHA-256
    /// hash is persisted.
    Issue {
        /// Human-readable name (e.g. "alice (on-call)" or "ci-bot").
        #[arg(long)]
        name: String,
        /// Comma-separated scopes. Use `*` for an admin/bootstrap token.
        /// See `--help-scopes` for the full catalogue.
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,
    },
    /// List active (non-revoked) tokens.
    List {
        /// Include revoked tokens.
        #[arg(long)]
        all: bool,
    },
    /// Revoke a token by id.
    Revoke {
        /// Token id (UUID).
        id: String,
        /// Reason (optional, recorded for audit).
        #[arg(long)]
        reason: Option<String>,
    },
    /// Print the operator-token scope catalogue (what each scope grants,
    /// which endpoints require it). ui-less-surfaces.md §4.4.
    Scopes {
        /// Output format. `pretty` (default) | `json`.
        #[arg(long, default_value = "pretty")]
        format: String,
    },
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
    /// Show the ordered PCA chain for a given session (every leaf the
    /// agent's bearers minted, walked back to PCA_0). Wraps
    /// `GET /api/v1/sessions/{id}/chain` (ui-less-surfaces.md §4.1).
    Chain {
        /// Session UUID (`oauth_sessions.id`).
        session_id: String,
        /// Output: pretty (default) | json.
        #[arg(long, default_value = "pretty")]
        format: String,
    },
    /// Delete audit rows older than a window. Cron-friendly retention.
    Purge {
        /// Window like "90d", "30d", "7d", "24h", or an RFC3339 date. Rows
        /// with `at < (now - window)` are deleted.
        #[arg(long)]
        older_than: String,
        /// Count what would be deleted without deleting. Defaults to false.
        #[arg(long)]
        dry_run: bool,
        /// Output: pretty (default) | json.
        #[arg(long, default_value = "pretty")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    set_color_mode(cli.color);

    // Offline, network-free commands handled before the HTTP client is built.
    if let Cmd::Completion { shell } = &cli.cmd {
        let shell = *shell;
        let mut cmd = Cli::command();
        let bin = cmd.get_name().to_string();
        clap_complete::generate(shell, &mut cmd, bin, &mut std::io::stdout());
        return Ok(());
    }

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(cli.insecure)
        .build()
        .context("building reqwest client")?;

    match cli.cmd {
        Cmd::Completion { .. } => unreachable!("handled before the HTTP client is built"),
        Cmd::Health => cmd_health(&http, &cli.url).await,
        Cmd::Pca { id } => cmd_pca(&http, &cli.url, &cli.token, &id).await,
        Cmd::Verify { id } => cmd_verify(&http, &cli.url, &cli.token, &id).await,
        Cmd::Selftest => cmd_selftest(&http, &cli.url, &cli.trust_plane).await,
        Cmd::Actions(sub) => cmd_actions(&http, &cli.url, &cli.token, sub).await,
        Cmd::Tokens(sub) => cmd_tokens(sub).await,
        Cmd::Policy(sub) => cmd_policy(&http, &cli.url, &cli.token, sub).await,
        Cmd::Blocked(sub) => cmd_blocked(&http, &cli.url, &cli.token, sub).await,
        Cmd::Notifier(sub) => cmd_notifier(&http, &cli.url, &cli.token, sub).await,
        Cmd::Status { format } => cmd_status(&http, &cli.url, &cli.token, &format).await,
        Cmd::Pic(sub) => cmd_pic(&http, &cli.url, &cli.token, sub).await,
        Cmd::Killswitch(sub) => cmd_killswitch(&http, &cli.url, &cli.token, sub).await,
        Cmd::Metrics(sub) => cmd_metrics(&http, &cli.url, sub).await,
        Cmd::TrustPlane(sub) => cmd_trust_plane(&http, &cli.trust_plane, sub).await,
        Cmd::Clients(sub) => cmd_clients(sub).await,
    }
}

async fn cmd_clients(sub: ClientsCmd) -> Result<()> {
    let db_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL must be set (proxilion-cli clients writes directly to postgres)")?;
    let pool = sqlx::PgPool::connect(&db_url)
        .await
        .context("connecting to postgres")?;
    match sub {
        ClientsCmd::List { all, format } => {
            let rows: Vec<(
                String,
                String,
                Vec<String>,
                chrono::DateTime<chrono::Utc>,
                Option<chrono::DateTime<chrono::Utc>>,
                Option<String>,
            )> = sqlx::query_as(
                "SELECT id, name, redirect_uris, created_at, revoked_at, revoked_reason
                   FROM oauth_clients
                  WHERE ($1 OR revoked_at IS NULL)
               ORDER BY created_at",
            )
            .bind(all)
            .fetch_all(&pool)
            .await
            .context("selecting oauth_clients")?;
            let arr: Vec<_> = rows
                .iter()
                .map(|(id, name, redirects, created, revoked, reason)| {
                    json!({
                        "id": id,
                        "name": name,
                        "redirect_uris": redirects,
                        "created_at": created.to_rfc3339(),
                        "revoked_at": revoked.map(|t| t.to_rfc3339()),
                        "revoked_reason": reason,
                    })
                })
                .collect();
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&arr)?);
            } else {
                // §3.1 — aligned table: client_id · name · created_at · revoked.
                println!(
                    "{:<28} {:<24} {:<22} revoked",
                    "client_id", "name", "created_at"
                );
                println!("{}", "─".repeat(86));
                for (id, name, _redirects, created, revoked, reason) in &rows {
                    let revoked_cell = match (revoked, reason) {
                        (Some(t), Some(r)) => format!("yes ({}) — {}", t.format("%Y-%m-%d"), r),
                        (Some(t), None) => format!("yes ({})", t.format("%Y-%m-%d")),
                        (None, _) => "no".to_string(),
                    };
                    println!(
                        "{:<28} {:<24} {:<22} {}",
                        truncate(id, 28),
                        truncate(name, 24),
                        created.format("%Y-%m-%d %H:%M UTC"),
                        revoked_cell,
                    );
                }
                println!("\n{} client(s)", rows.len());
            }
            Ok(())
        }
        ClientsCmd::Add {
            id,
            name,
            redirect_uri,
        } => {
            // Defensive URL validation — every redirect_uri must parse as
            // a real URL so we don't accept obvious typos that would
            // 404 the OAuth handshake at exchange-time.
            for u in &redirect_uri {
                let parsed = reqwest::Url::parse(u)
                    .map_err(|e| anyhow!("redirect_uri `{u}` is not a valid URL: {e}"))?;
                if parsed.scheme() != "https" && parsed.scheme() != "http" {
                    return Err(anyhow!(
                        "redirect_uri `{u}` must use http(s); got scheme `{}`",
                        parsed.scheme()
                    ));
                }
            }
            let res = sqlx::query(
                "INSERT INTO oauth_clients (id, name, redirect_uris)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(&id)
            .bind(&name)
            .bind(&redirect_uri)
            .execute(&pool)
            .await
            .context("inserting oauth_clients")?;
            if res.rows_affected() == 0 {
                return Err(anyhow!("client id `{id}` already exists"));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "id": id,
                    "name": name,
                    "redirect_uris": redirect_uri,
                }))?
            );
            Ok(())
        }
        ClientsCmd::Revoke {
            id,
            reason,
            dry_run,
        } => {
            if dry_run {
                // §3.3 — resolve the target (would it be revoked?) without
                // writing. Counts the rows the real UPDATE's WHERE matches.
                let active: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM oauth_clients WHERE id = $1 AND revoked_at IS NULL",
                )
                .bind(&id)
                .fetch_one(&pool)
                .await
                .context("previewing oauth_clients revoke")?;
                if active == 0 {
                    return Err(anyhow!(
                        "no active client with id `{id}` (already revoked, or never existed)"
                    ));
                }
                #[allow(non_snake_case)]
                let (GREEN, _, DIM, RESET, _) = colors();
                println!(
                    "{GREEN}dry-run{RESET}: would revoke client {DIM}{id}{RESET} (reason: {reason}) — nothing was changed."
                );
                return Ok(());
            }
            let res = sqlx::query(
                "UPDATE oauth_clients
                    SET revoked_at = now(), revoked_reason = $2
                  WHERE id = $1 AND revoked_at IS NULL",
            )
            .bind(&id)
            .bind(&reason)
            .execute(&pool)
            .await
            .context("revoking oauth_clients row")?;
            if res.rows_affected() == 0 {
                return Err(anyhow!(
                    "no active client with id `{id}` (already revoked, or never existed)"
                ));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "id": id,
                    "revoked_reason": reason,
                }))?
            );
            Ok(())
        }
    }
}

async fn cmd_metrics(http: &reqwest::Client, url: &str, sub: MetricsCmd) -> Result<()> {
    match sub {
        MetricsCmd::Sample { filter, raw } => {
            let body = http
                .get(format!("{url}/metrics"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            if raw {
                if let Some(f) = filter.as_deref() {
                    for line in body.lines() {
                        if line.contains(f) {
                            println!("{line}");
                        }
                    }
                } else {
                    print!("{body}");
                }
                return Ok(());
            }
            // Group by metric family (the name before `{`). One row per
            // family with: sample count, smallest value, largest value.
            // HELP / TYPE lines are dropped — the operator wants the data,
            // not the schema, in this view.
            use std::collections::BTreeMap;
            let mut by_family: BTreeMap<String, (usize, f64, f64)> = BTreeMap::new();
            for line in body.lines() {
                let line = line.trim_start();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // `name{labels…} value` OR `name value`.
                let (name_part, value_part) = match line.rsplit_once(' ') {
                    Some(t) => t,
                    None => continue,
                };
                let family = match name_part.find('{') {
                    Some(b) => &name_part[..b],
                    None => name_part,
                };
                if let Some(f) = filter.as_deref() {
                    if !family.contains(f) {
                        continue;
                    }
                }
                let v: f64 = value_part.parse().unwrap_or(f64::NAN);
                let entry = by_family.entry(family.to_string()).or_insert((
                    0usize,
                    f64::INFINITY,
                    f64::NEG_INFINITY,
                ));
                entry.0 += 1;
                if !v.is_nan() {
                    if v < entry.1 {
                        entry.1 = v;
                    }
                    if v > entry.2 {
                        entry.2 = v;
                    }
                }
            }
            if by_family.is_empty() {
                println!("(no metric families matched)");
                return Ok(());
            }
            println!(
                "{:<60} {:>8} {:>14} {:>14}",
                "FAMILY", "SERIES", "MIN", "MAX"
            );
            for (fam, (count, min, max)) in by_family {
                let min_s = if min.is_infinite() {
                    "—".to_string()
                } else {
                    format_metric_value(min)
                };
                let max_s = if max.is_infinite() {
                    "—".to_string()
                } else {
                    format_metric_value(max)
                };
                println!("{fam:<60} {count:>8} {min_s:>14} {max_s:>14}");
            }
            Ok(())
        }
    }
}

/// Render a metric value compactly. Integers (no fractional part within
/// 1e-9 tolerance) drop the decimal; floats keep up to 6 significant digits.
fn format_metric_value(v: f64) -> String {
    if (v.fract().abs() < 1e-9) && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v:.6}")
    }
}

async fn cmd_trust_plane(
    http: &reqwest::Client,
    trust_plane_url: &str,
    sub: TrustPlaneCmd,
) -> Result<()> {
    match sub {
        TrustPlaneCmd::Info => {
            let v: Value = http
                .get(format!("{trust_plane_url}/v1/federation/info"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
    }
}

async fn cmd_status(http: &reqwest::Client, url: &str, token: &str, format: &str) -> Result<()> {
    #[allow(non_snake_case)]
    let (GREEN, RED, _, RESET, _) = colors();
    let healthz: Value = http
        .get(format!("{url}/healthz"))
        .send()
        .await?
        .json()
        .await
        .unwrap_or_else(|_| serde_json::json!({}));
    let setup: Value = match auth_header(http.get(format!("{url}/api/v1/setup/status")), token)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or(Value::Null),
        _ => Value::Null,
    };
    let ready = healthz
        .get("ready")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let combined = serde_json::json!({
        "ready": ready,
        "healthz": healthz,
        "setup": setup,
    });
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&combined)?);
    } else {
        let symbol = if ready { GREEN } else { RED };
        let label = if ready { "ready" } else { "NOT ready" };
        println!("proxilion status — {symbol}{label}{RESET}");
        println!("  endpoint: {url}");
        if let Some(version) = healthz.get("version").and_then(|v| v.as_str()) {
            println!("  version:  {version}");
        }
        if let Some(checks) = healthz.get("checks") {
            println!(
                "  checks:   {}",
                serde_json::to_string(checks).unwrap_or_default()
            );
        }
        if !setup.is_null() {
            println!("\nsetup checklist:");
            println!(
                "{}",
                serde_json::to_string_pretty(&setup).unwrap_or_default()
            );
        } else {
            println!("\nsetup checklist: (unavailable — token missing or insufficient scope)");
        }
    }
    if !ready {
        std::process::exit(1);
    }
    Ok(())
}

async fn cmd_pic(http: &reqwest::Client, url: &str, token: &str, sub: PicCmd) -> Result<()> {
    match sub {
        PicCmd::Show { id } => {
            let v: Value = auth_header(
                http.get(format!("{url}/api/v1/pca/{}", urlencode(&id))),
                token,
            )
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
        PicCmd::Verify { id } => {
            // Same shape as `cmd_verify` but token-aware so the operator's
            // scope check fires (pca:read).
            let v: Value = auth_header(
                http.get(format!("{url}/api/v1/pca/{}/verify", urlencode(&id))),
                token,
            )
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
    }
}

async fn cmd_killswitch(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    sub: KillswitchCmd,
) -> Result<()> {
    #[allow(non_snake_case)]
    let (GREEN, RED, DIM, RESET, _) = colors();
    // (path, reason, dry_run, confirm) — `confirm` is forwarded only for the
    // `all` scope (the server gates a real fleet-wide kill on it).
    let (path, reason, dry_run, confirm) = match sub {
        KillswitchCmd::Session {
            id,
            reason,
            dry_run,
        } => (
            format!("/api/v1/killswitch/session/{}", urlencode(&id)),
            reason,
            dry_run,
            None,
        ),
        KillswitchCmd::User {
            p_0,
            reason,
            dry_run,
        } => (
            format!("/api/v1/killswitch/user/{}", urlencode(&p_0)),
            reason,
            dry_run,
            None,
        ),
        KillswitchCmd::All {
            confirm,
            reason,
            dry_run,
        } => {
            // A real (non-dry-run) fleet kill requires the explicit gate.
            if !dry_run && confirm != "yes" {
                eprintln!(
                    "{RED}refused{RESET}: `killswitch all` requires --confirm yes (case-sensitive). Got: {confirm:?}"
                );
                std::process::exit(2);
            }
            (
                "/api/v1/killswitch/all".to_string(),
                reason,
                dry_run,
                Some(confirm),
            )
        }
    };
    // Build the request body: reason always, dry_run when previewing, and
    // confirm forwarded for the `all` scope's server-side gate.
    let mut payload = serde_json::json!({ "reason": reason });
    if dry_run {
        payload["dry_run"] = serde_json::json!(true);
    }
    if let Some(c) = &confirm {
        payload["confirm"] = serde_json::json!(c);
    }
    let resp = auth_header(http.post(format!("{url}{path}")), token)
        .json(&payload)
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        eprintln!(
            "{RED}killswitch failed{RESET}: HTTP {} — {body}",
            status.as_u16()
        );
        std::process::exit(1);
    }
    if dry_run {
        let n = body
            .get("bearers_revoked")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let target = body.get("target").and_then(|v| v.as_str()).unwrap_or("?");
        let scope = body.get("scope").and_then(|v| v.as_str()).unwrap_or("?");
        println!(
            "{GREEN}dry-run{RESET}: would revoke {n} bearer(s) for {scope} {DIM}{target}{RESET} — nothing was changed."
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&body)?);
    }
    Ok(())
}

fn auth_header(builder: reqwest::RequestBuilder, token: &str) -> reqwest::RequestBuilder {
    if token.is_empty() {
        builder
    } else {
        builder.bearer_auth(token)
    }
}

async fn cmd_actions(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    sub: ActionsCmd,
) -> Result<()> {
    match sub {
        ActionsCmd::Tail {
            decision,
            vendor,
            action,
            format,
        } => actions_tail(http, url, token, decision, vendor, action, &format).await,
        ActionsCmd::List {
            decision,
            vendor,
            action,
            p_0,
            session_id,
            since,
            limit,
            all,
            format,
        } => {
            actions_list(
                http, url, token, decision, vendor, action, p_0, session_id, since, limit, all,
                &format,
            )
            .await
        }
        ActionsCmd::Show { id, format } => actions_show(http, url, token, &id, &format).await,
        ActionsCmd::Export {
            format,
            since,
            until,
            decision,
            vendor,
            action,
            p_0,
            output,
        } => {
            actions_export(
                http, url, token, &format, since, until, decision, vendor, action, p_0, output,
            )
            .await
        }
        ActionsCmd::Chain { session_id, format } => {
            actions_chain(http, url, token, &session_id, &format).await
        }
        ActionsCmd::Purge {
            older_than,
            dry_run,
            format,
        } => actions_purge(http, url, token, &older_than, dry_run, &format).await,
    }
}

async fn actions_purge(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    older_than: &str,
    dry_run: bool,
    format: &str,
) -> Result<()> {
    let cutoff = parse_since(older_than).with_context(|| {
        format!(
            "invalid --older-than {older_than:?} — expected an RFC3339 timestamp \
             or a duration like \"24h\", \"7d\""
        )
    })?;
    let body = serde_json::json!({
        "older_than": cutoff.to_rfc3339(),
        "dry_run": dry_run,
    });
    let req = http.post(format!("{url}/api/v1/actions/purge")).json(&body);
    let resp = auth_header(req, token).send().await?;
    let status = resp.status();
    let payload: serde_json::Value = resp.json().await?;
    if !status.is_success() {
        anyhow::bail!("purge failed ({status}): {payload}");
    }
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&payload)?),
        _ => {
            let deleted = payload.get("deleted").and_then(|v| v.as_u64()).unwrap_or(0);
            let cutoff_str = payload
                .get("older_than")
                .and_then(|v| v.as_str())
                .unwrap_or(older_than);
            let verb = if dry_run { "would delete" } else { "deleted" };
            println!("{verb} {deleted} action_event row(s) older than {cutoff_str}");
        }
    }
    Ok(())
}

/// Parse "5m" / "24h" / "7d" / RFC3339 into a UTC timestamp.
fn parse_since(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }
    let dur = humantime::parse_duration(s).with_context(|| {
        format!(
            "--since {s:?} is not a valid value — expected an RFC3339 timestamp \
             (e.g. 2026-06-11T14:00:00Z) or a duration like \"30m\", \"24h\", \"7d\""
        )
    })?;
    let chrono_dur =
        chrono::Duration::from_std(dur).map_err(|_| anyhow!("--since duration overflows"))?;
    Ok(chrono::Utc::now() - chrono_dur)
}

async fn actions_tail(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    decision: Option<String>,
    vendor: Option<String>,
    action: Option<String>,
    format: &str,
) -> Result<()> {
    let resp = auth_header(http.get(format!("{url}/api/v1/actions/stream")), token)
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
            if event != "action" || data.is_empty() {
                continue;
            }
            // Client-side filter — the SSE endpoint does not take query
            // params, so this is the place to apply tail-time filters.
            if !matches_tail_filter(
                &data,
                decision.as_deref(),
                vendor.as_deref(),
                action.as_deref(),
            ) {
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
    if let Some(d) = decision {
        if field("decision") != d {
            return false;
        }
    }
    if let Some(d) = vendor {
        if field("vendor") != d {
            return false;
        }
    }
    if let Some(d) = action {
        if field("action") != d {
            return false;
        }
    }
    true
}

fn print_pretty_event(json: &str) {
    #[allow(non_snake_case)]
    let (GREEN, RED, DIM, RESET, _) = colors();
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
    token: &str,
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
    #[allow(non_snake_case)]
    let (_, _, DIM, RESET, _) = colors();
    let since_dt = since.as_deref().map(parse_since).transpose()?;
    let mut before: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut total = 0usize;
    let limit = limit.clamp(1, 500);
    if matches!(format, "pretty") {
        println!(
            "{DIM}{:<25}  {:>22}  {:>3}  {:<32}  p_0{RESET}",
            "at", "decision", "st", "action"
        );
    }
    loop {
        let mut q = vec![format!("limit={limit}")];
        if let Some(v) = &decision {
            q.push(format!("decision={}", urlencode(v)));
        }
        if let Some(v) = &vendor {
            q.push(format!("vendor={}", urlencode(v)));
        }
        if let Some(v) = &action {
            q.push(format!("action={}", urlencode(v)));
        }
        if let Some(v) = &p_0 {
            q.push(format!("p_0={}", urlencode(v)));
        }
        if let Some(v) = &session_id {
            q.push(format!("session_id={}", urlencode(v)));
        }
        if let Some(b) = before {
            q.push(format!("before={}", urlencode(&b.to_rfc3339())));
        }
        let endpoint = format!("{url}/api/v1/actions?{}", q.join("&"));
        let env: Value = auth_header(http.get(&endpoint), token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let rows = env
            .get("rows")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        for r in &rows {
            // Honor --since by stopping once we've crossed the boundary.
            if let Some(s) = since_dt {
                let at = r.get("at").and_then(|x| x.as_str()).and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(s)
                        .ok()
                        .map(|d| d.with_timezone(&chrono::Utc))
                });
                if let Some(t) = at {
                    if t < s {
                        return Ok(());
                    }
                }
            }
            match format {
                "json" => println!("{}", serde_json::to_string(r)?),
                "ndjson" => println!("{}", serde_json::to_string(r)?),
                _ => print_pretty_event(&r.to_string()),
            }
            total += 1;
        }
        let next = env
            .get("next_before")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        if !all || rows.is_empty() {
            if format == "pretty" {
                println!("{DIM}-- {total} rows --{RESET}");
            }
            return Ok(());
        }
        match next {
            Some(s) => {
                before =
                    Some(chrono::DateTime::parse_from_rfc3339(&s)?.with_timezone(&chrono::Utc));
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

async fn actions_chain(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    session_id: &str,
    format: &str,
) -> Result<()> {
    let v: Value = auth_header(
        http.get(format!(
            "{url}/api/v1/sessions/{}/chain",
            urlencode(session_id)
        )),
        token,
    )
    .send()
    .await?
    .error_for_status()?
    .json()
    .await?;
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    println!("session {session_id}");
    let chain = v
        .get("chain")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    if chain.is_empty() {
        println!("  (no PCA hops recorded for this session)");
        return Ok(());
    }
    for (i, link) in chain.iter().enumerate() {
        let hop = link.get("hop").and_then(|x| x.as_u64()).unwrap_or(0);
        let id = link.get("pca_id").and_then(|x| x.as_str()).unwrap_or("?");
        let p_0 = link.get("p_0").and_then(|x| x.as_str()).unwrap_or("?");
        let ops_count = link
            .get("ops")
            .and_then(|x| x.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let prefix = if i == 0 { "└─" } else { "├─" };
        println!("  {prefix} hop={hop} pca={id} p_0={p_0} ops={ops_count}");
    }
    Ok(())
}

async fn actions_show(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    id: &str,
    format: &str,
) -> Result<()> {
    #[allow(non_snake_case)]
    let (GREEN, RED, DIM, RESET, _) = colors();
    let v: Value = auth_header(
        http.get(format!("{url}/api/v1/actions/{}", urlencode(id))),
        token,
    )
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
    println!(
        "action {}",
        v.get("id").and_then(|x| x.as_str()).unwrap_or("?")
    );
    println!(
        "  at:       {}",
        v.get("at").and_then(|x| x.as_str()).unwrap_or("?")
    );
    println!(
        "  vendor:   {}",
        v.get("vendor").and_then(|x| x.as_str()).unwrap_or("?")
    );
    println!(
        "  action:   {}",
        v.get("action").and_then(|x| x.as_str()).unwrap_or("?")
    );
    println!(
        "  method:   {}  {}",
        v.get("method").and_then(|x| x.as_str()).unwrap_or(""),
        v.get("path").and_then(|x| x.as_str()).unwrap_or("")
    );
    println!(
        "  status:   {}",
        v.get("status").and_then(|x| x.as_u64()).unwrap_or(0)
    );
    println!(
        "  decision: {}",
        v.get("decision").and_then(|x| x.as_str()).unwrap_or("?")
    );
    println!(
        "  p_0:      {}",
        v.get("p_0").and_then(|x| x.as_str()).unwrap_or("?")
    );
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
    let chain = v
        .get("chain")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
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
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            println!("  {icon} hop {hop:<2}  {DIM}pca={pca_id}{RESET}",);
            println!("       p_0={p_0}");
            if let Some(prev) = &prev_ops {
                let cur: std::collections::HashSet<String> = ops.iter().cloned().collect();
                let removed: Vec<&String> = prev.difference(&cur).collect();
                if removed.is_empty() {
                    println!("       ops [{}] — {DIM}(no narrowing){RESET}", ops.len());
                } else {
                    println!(
                        "       ops [{}] — {RED}narrowed: removed {}{RESET}",
                        ops.len(),
                        removed.len()
                    );
                    for r in removed.iter().take(3) {
                        println!("          - {r}");
                    }
                }
            } else {
                println!("       ops [{}]", ops.len());
            }
            prev_ops = Some(ops.iter().cloned().collect());
            if i + 1 < chain.len() {
                println!("       │");
            }
        }
    }
    if let Some(b) = v.get("chain_broken_at").and_then(|x| x.as_str()) {
        println!("  {RED}✗ chain broken at {b}{RESET}");
    } else if !chain.is_empty() {
        println!(
            "  {GREEN}✓ chain intact ({} link{}){RESET}",
            chain.len(),
            if chain.len() == 1 { "" } else { "s" }
        );
    }
    println!("{}", "─".repeat(70));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn actions_export(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    format: &str,
    since: Option<String>,
    until: Option<String>,
    decision: Option<String>,
    vendor: Option<String>,
    action: Option<String>,
    p_0: Option<String>,
    output: Option<String>,
) -> Result<()> {
    #[allow(non_snake_case)]
    let (_, _, DIM, RESET, _) = colors();
    let mut q = vec![format!("format={}", urlencode(format))];
    if let Some(s) = since {
        let dt = parse_since(&s)?;
        q.push(format!("since={}", urlencode(&dt.to_rfc3339())));
    }
    if let Some(u) = until {
        q.push(format!("until={}", urlencode(&u)));
    }
    if let Some(v) = &decision {
        q.push(format!("decision={}", urlencode(v)));
    }
    if let Some(v) = &vendor {
        q.push(format!("vendor={}", urlencode(v)));
    }
    if let Some(v) = &action {
        q.push(format!("action={}", urlencode(v)));
    }
    if let Some(v) = &p_0 {
        q.push(format!("p_0={}", urlencode(v)));
    }
    let endpoint = format!("{url}/api/v1/actions/export?{}", q.join("&"));
    let resp = auth_header(http.get(&endpoint), token)
        .send()
        .await?
        .error_for_status()?;
    let mut stream = resp.bytes_stream();
    use futures_util::StreamExt;
    use std::io::Write;
    let mut sink: Box<dyn Write> = match output {
        Some(p) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(&p).with_context(|| format!("creating {p}"))?,
        )),
        None => Box::new(std::io::BufWriter::new(std::io::stdout().lock())),
    };
    let mut bytes_written: u64 = 0;
    let mut progress = Progress::new("exporting", "bytes", format);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read export chunk")?;
        sink.write_all(&chunk)?;
        bytes_written += chunk.len() as u64;
        progress.tick(bytes_written);
    }
    sink.flush()?;
    progress.finish(bytes_written);
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

async fn cmd_pca(http: &reqwest::Client, url: &str, token: &str, id: &str) -> Result<()> {
    let v: Value = auth_header(
        http.get(format!("{url}/api/v1/pca/{}", urlencode(id))),
        token,
    )
    .send()
    .await?
    .error_for_status()?
    .json()
    .await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

async fn cmd_verify(http: &reqwest::Client, url: &str, token: &str, id: &str) -> Result<()> {
    let v: Value = auth_header(
        http.get(format!("{url}/api/v1/pca/{}/verify", urlencode(id))),
        token,
    )
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

// ============ color (§3.2) ============

/// Global ANSI-color gate, set once in `main` from `--color` + `NO_COLOR` +
/// TTY-ness. Default `false` so any code path that runs before `main` sets it
/// (and tests) emits no escape codes.
static COLOR: AtomicBool = AtomicBool::new(false);

/// Whether `--color never` was passed. Tracked separately from [`COLOR`]
/// because the §3.5 stderr progress indicator keys on stderr TTY-ness (not
/// stdout's), so it must stay independent of the stdout-driven color gate —
/// but it should still honor an explicit `--color never`.
static COLOR_NEVER: AtomicBool = AtomicBool::new(false);

/// Whether ANSI color should be emitted. One predicate, consulted by every
/// styled write-site via [`colors`].
fn should_color() -> bool {
    COLOR.load(Ordering::Relaxed)
}

/// Resolve `--color` (+ `NO_COLOR` + stdout TTY-ness) into the on/off decision
/// and store it. `auto` → color iff stdout is a terminal and `NO_COLOR` is
/// unset (or empty, per no-color.org). Called once at startup.
fn set_color_mode(choice: ColorChoice) {
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    let enabled = resolve_color(choice, no_color, std::io::stdout().is_terminal());
    COLOR.store(enabled, Ordering::Relaxed);
    COLOR_NEVER.store(choice == ColorChoice::Never, Ordering::Relaxed);
}

/// Pure color decision (extracted for testing): `always`/`never` are absolute;
/// `auto` enables color iff `NO_COLOR` is unset/empty **and** stdout is a TTY.
fn resolve_color(choice: ColorChoice, no_color: bool, stdout_is_tty: bool) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => !no_color && stdout_is_tty,
    }
}

/// The `(GREEN, RED, DIM, RESET, YELLOW)` SGR tuple — the actual escape codes
/// when color is enabled, or empty strings when it isn't. Every styled site
/// binds the subset it needs from this, so a single `should_color()` decision
/// gates all output.
fn colors() -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    if should_color() {
        ("\x1b[32m", "\x1b[31m", "\x1b[2m", "\x1b[0m", "\x1b[33m")
    } else {
        ("", "", "", "", "")
    }
}

/// `\x1b[1m…\x1b[0m` bold wrapper, gated by `should_color()`.
fn bold(s: &str) -> String {
    if should_color() {
        format!("\x1b[1m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// A throttled single-line stderr progress indicator for long streaming
/// operations (surface-delight-and-correctness.md §3.5). Active only when
/// stderr is a TTY, `--color never` was not passed, and the output format
/// isn't `json` (so machine-readable stdout pipelines stay clean and a piped
/// stderr emits nothing). Renders `\r<label>: <n> <unit> · <elapsed>s` at most
/// ~8×/second; `finish` clears the line with a final count. A no-op otherwise.
struct Progress {
    active: bool,
    started: Instant,
    last: Instant,
    label: &'static str,
    unit: &'static str,
}

impl Progress {
    fn new(label: &'static str, unit: &'static str, format: &str) -> Self {
        let active = format != "json"
            && !COLOR_NEVER.load(Ordering::Relaxed)
            && std::io::stderr().is_terminal();
        let now = Instant::now();
        Progress {
            active,
            started: now,
            last: now,
            label,
            unit,
        }
    }

    fn tick(&mut self, n: u64) {
        if !self.active {
            return;
        }
        let now = Instant::now();
        if now.duration_since(self.last) < Duration::from_millis(120) {
            return;
        }
        self.last = now;
        let secs = self.started.elapsed().as_secs_f64();
        eprint!("\r{}: {n} {} · {secs:.1}s   ", self.label, self.unit);
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }

    fn finish(&self, n: u64) {
        if !self.active {
            return;
        }
        let secs = self.started.elapsed().as_secs_f64();
        eprintln!("\r{}: {n} {} · {secs:.1}s        ", self.label, self.unit);
    }
}

// ============ selftest ============

fn ok(name: &str, latency_ms: u128, detail: &str) {
    #[allow(non_snake_case)]
    let (GREEN, _, DIM, RESET, _) = colors();
    println!(
        "  {GREEN}✓{RESET} {name:<28}{DIM}{:>6}ms{RESET}   {detail}",
        latency_ms
    );
}
fn fail(name: &str, latency_ms: u128, detail: &str) {
    #[allow(non_snake_case)]
    let (_, RED, DIM, RESET, _) = colors();
    println!(
        "  {RED}✗{RESET} {name:<28}{DIM}{:>6}ms{RESET}   {RED}{detail}{RESET}",
        latency_ms
    );
}

async fn cmd_selftest(
    http: &reqwest::Client,
    proxy_url: &str,
    trust_plane_url: &str,
) -> Result<()> {
    #[allow(non_snake_case)]
    let (GREEN, RED, _, RESET, _) = colors();
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
                        fail(
                            "proxy /healthz",
                            dt,
                            &format!("status={status}, ready=false — see `proxilion-cli health`"),
                        );
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
                    &format!(
                        "kid={} pubkey={} bytes (b64)",
                        info.kid,
                        info.public_key.len()
                    ),
                );
                Some(info.kid)
            }
            Err(e) => {
                fail(
                    "trust-plane /federation/info",
                    dt,
                    &format!("bad JSON: {e}"),
                );
                all_ok = false;
                None
            }
        },
        Ok(r) => {
            fail(
                "trust-plane /federation/info",
                dt,
                &format!("status {}", r.status()),
            );
            all_ok = false;
            None
        }
        Err(e) => {
            fail(
                "trust-plane /federation/info",
                dt,
                &format!("unreachable: {e}"),
            );
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

/// Compute a human-readable diff between two `PolicyDoc`s. Returns a
/// list of `"field: before → after"` snippets for fields that changed.
/// Comparison is shallow — `match` / `decision` / `read_filter` are
/// compared via their YAML-serialized form so any structural change
/// shows up as a single delta line rather than a recursive walk.
fn field_diff(
    before: &policy_engine::yaml::PolicyDoc,
    after: &policy_engine::yaml::PolicyDoc,
) -> Vec<String> {
    let mut out = Vec::new();
    if before.vendor != after.vendor {
        out.push(format!("vendor: {} → {}", before.vendor, after.vendor));
    }
    if before.action != after.action {
        out.push(format!("action: {} → {}", before.action, after.action));
    }
    if before.mode != after.mode {
        out.push(format!("mode: {:?} → {:?}", before.mode, after.mode));
    }
    if before.pic_mode != after.pic_mode {
        out.push(format!(
            "pic_mode: {:?} → {:?}",
            before.pic_mode, after.pic_mode
        ));
    }
    if before.required_ops != after.required_ops {
        out.push("required_ops changed".to_string());
    }
    let dump = |v: &serde_yaml::Value| serde_yaml::to_string(v).unwrap_or_default();
    if dump(&before.match_) != dump(&after.match_) {
        out.push("match changed".to_string());
    }
    if dump(&before.decision) != dump(&after.decision) {
        out.push("decision changed".to_string());
    }
    out
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

// ─────────────────────────────────────────────────────────────────────────
// Operator-token management (ui-less-surfaces.md §4.4)
// ─────────────────────────────────────────────────────────────────────────

const TOKEN_PREFIX: &str = "pxl_operator_";
const TOKEN_BODY_LEN: usize = 52;

fn generate_token() -> String {
    use rand::RngCore;
    const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bytes = [0u8; TOKEN_BODY_LEN];
    rand::thread_rng().fill_bytes(&mut bytes);
    let body: String = bytes
        .iter()
        .map(|b| ALPH[(*b as usize) % ALPH.len()] as char)
        .collect();
    format!("{TOKEN_PREFIX}{body}")
}

fn token_hash(token: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(token.as_bytes()).to_vec()
}

async fn cmd_tokens(sub: TokensCmd) -> Result<()> {
    // `Scopes` is a pure read of the catalogue — no DB connection needed,
    // so handle it before opening the pool. That way the command works
    // in environments without a DATABASE_URL (CI, container builds, etc).
    if let TokensCmd::Scopes { format } = &sub {
        return cmd_tokens_scopes(format);
    }
    let db_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL must be set (proxilion-cli tokens writes directly to postgres)")?;
    let pool = sqlx::PgPool::connect(&db_url)
        .await
        .context("connecting to postgres")?;
    match sub {
        TokensCmd::Issue { name, scope } => {
            if scope.is_empty() {
                return Err(anyhow!(
                    "--scope is required (at least one; use `*` for a bootstrap admin token)"
                ));
            }
            let plaintext = generate_token();
            let hash = token_hash(&plaintext);
            let row: (uuid::Uuid,) = sqlx::query_as(
                "INSERT INTO operator_tokens (token_hash, name, scopes)
                 VALUES ($1, $2, $3) RETURNING id",
            )
            .bind(&hash[..])
            .bind(&name)
            .bind(&scope)
            .fetch_one(&pool)
            .await
            .context("inserting operator_tokens")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "id": row.0.to_string(),
                    "name": name,
                    "scopes": scope,
                    "token": plaintext,
                    "note": "This token is shown ONCE. Store it in a secrets manager."
                }))?
            );
            Ok(())
        }
        TokensCmd::List { all } => {
            let rows: Vec<(
                uuid::Uuid,
                String,
                Vec<String>,
                chrono::DateTime<chrono::Utc>,
                Option<chrono::DateTime<chrono::Utc>>,
                Option<chrono::DateTime<chrono::Utc>>,
                Option<String>,
            )> = sqlx::query_as(
                "SELECT id, name, scopes, created_at, last_used_at, revoked_at, revoked_reason
                 FROM operator_tokens
                 WHERE ($1 OR revoked_at IS NULL)
                 ORDER BY created_at DESC",
            )
            .bind(all)
            .fetch_all(&pool)
            .await
            .context("selecting operator_tokens")?;
            let arr: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "id": r.0.to_string(),
                        "name": r.1,
                        "scopes": r.2,
                        "created_at": r.3.to_rfc3339(),
                        "last_used_at": r.4.map(|t: chrono::DateTime<chrono::Utc>| t.to_rfc3339()),
                        "revoked_at": r.5.map(|t: chrono::DateTime<chrono::Utc>| t.to_rfc3339()),
                        "revoked_reason": r.6,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr)?);
            Ok(())
        }
        TokensCmd::Revoke { id, reason } => {
            let uuid =
                uuid::Uuid::parse_str(&id).map_err(|e| anyhow!("invalid UUID `{id}`: {e}"))?;
            let res = sqlx::query(
                "UPDATE operator_tokens
                 SET revoked_at = now(), revoked_reason = $2
                 WHERE id = $1 AND revoked_at IS NULL",
            )
            .bind(uuid)
            .bind(reason.as_deref())
            .execute(&pool)
            .await
            .context("updating operator_tokens")?;
            let n = res.rows_affected();
            if n == 0 {
                return Err(anyhow!("no active token with id {id} (already revoked?)"));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "id": id,
                    "revoked": n,
                }))?
            );
            Ok(())
        }
        TokensCmd::Scopes { .. } => unreachable!("handled above before pool open"),
    }
}

fn cmd_tokens_scopes(format: &str) -> Result<()> {
    let catalogue = shared_types::operator_scopes::SCOPE_CATALOGUE;
    match format {
        "json" => {
            let arr: Vec<_> = catalogue
                .iter()
                .map(|(s, d, e)| {
                    json!({
                        "scope": s,
                        "description": d,
                        "endpoints": e,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr)?);
        }
        _ => {
            // Pretty: aligned columns, plus a header. Width of the scope
            // column is the longest scope + 2.
            let max = catalogue.iter().map(|(s, _, _)| s.len()).max().unwrap_or(0) + 2;
            println!("{:width$}description", "scope", width = max);
            println!("{:width$}-----------", "-----", width = max);
            for (s, d, e) in catalogue {
                println!("{:width$}{}", s, d, width = max);
                println!("{:width$}  endpoints: {}", "", e, width = max);
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Policy management (ui-less-surfaces.md §4)
// ─────────────────────────────────────────────────────────────────────────

async fn cmd_policy(http: &reqwest::Client, url: &str, token: &str, sub: PolicyCmd) -> Result<()> {
    #[allow(non_snake_case)]
    let (GREEN, RED, _, RESET, _) = colors();
    match sub {
        PolicyCmd::List { mode, format } => {
            let resp = auth_header(http.get(format!("{url}/api/v1/policy")), token)
                .send()
                .await
                .context("GET /api/v1/policy")?
                .error_for_status()
                .context("/api/v1/policy returned an error")?;
            let envelope: Value = resp.json().await?;
            let policies = envelope["policies"].as_array().cloned().unwrap_or_default();
            let filtered: Vec<Value> = policies
                .into_iter()
                .filter(|p| match &mode {
                    Some(m) => p["mode"].as_str() == Some(m.as_str()),
                    None => true,
                })
                .collect();
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&filtered)?);
            } else {
                let source = envelope["source"].as_str().unwrap_or("(unset)");
                println!("source: {source}");
                println!(
                    "{:<40} {:<10} {:<10} vendor/action",
                    "id", "mode", "pic_mode"
                );
                println!("{}", "─".repeat(78));
                for p in &filtered {
                    println!(
                        "{:<40} {:<10} {:<10} {}/{}",
                        p["id"].as_str().unwrap_or(""),
                        p["mode"].as_str().unwrap_or(""),
                        p["pic_mode"].as_str().unwrap_or(""),
                        p["vendor"].as_str().unwrap_or(""),
                        p["action"].as_str().unwrap_or(""),
                    );
                }
            }
            Ok(())
        }
        PolicyCmd::Show { id, format } => {
            let resp = auth_header(http.get(format!("{url}/api/v1/policy")), token)
                .send()
                .await
                .context("GET /api/v1/policy")?
                .error_for_status()
                .context("/api/v1/policy returned an error")?;
            let envelope: Value = resp.json().await?;
            let policies = envelope["policies"].as_array().cloned().unwrap_or_default();
            let Some(found) = policies.into_iter().find(|p| p["id"].as_str() == Some(&id)) else {
                eprintln!("{RED}policy `{id}` not found{RESET}");
                std::process::exit(1);
            };
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&found)?);
            } else {
                println!("id:         {}", found["id"].as_str().unwrap_or(""));
                println!("vendor:     {}", found["vendor"].as_str().unwrap_or(""));
                println!("action:     {}", found["action"].as_str().unwrap_or(""));
                println!("mode:       {}", found["mode"].as_str().unwrap_or(""));
                println!("pic_mode:   {}", found["pic_mode"].as_str().unwrap_or(""));
                if let Some(source) = envelope["source"].as_str() {
                    println!("source:     {source}");
                }
            }
            Ok(())
        }
        PolicyCmd::Validate { file } => {
            let yaml = std::fs::read_to_string(&file)
                .with_context(|| format!("reading policy file {file}"))?;
            match policy_engine::yaml::parse_policies(&yaml) {
                Ok(policies) => {
                    println!(
                        "{GREEN}✓ valid{RESET}: {} polic{} parsed from `{file}`",
                        policies.len(),
                        if policies.len() == 1 { "y" } else { "ies" }
                    );
                    for p in &policies {
                        println!(
                            "  • {} ({}/{}, mode={:?}, pic_mode={:?})",
                            p.id, p.vendor, p.action, p.mode, p.pic_mode
                        );
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!("{RED}✗ invalid{RESET}: {e}");
                    std::process::exit(1);
                }
            }
        }
        PolicyCmd::Diff {
            before,
            after,
            format,
        } => {
            let parse = |p: &str| -> Result<Vec<policy_engine::yaml::PolicyDoc>> {
                let y = std::fs::read_to_string(p)
                    .with_context(|| format!("reading policy file {p}"))?;
                policy_engine::yaml::parse_policies(&y)
                    .with_context(|| format!("parsing policy file {p}"))
            };
            let bs = parse(&before)?;
            let as_ = parse(&after)?;
            use std::collections::BTreeMap;
            let mut b_by_id: BTreeMap<String, &policy_engine::yaml::PolicyDoc> = BTreeMap::new();
            let mut a_by_id: BTreeMap<String, &policy_engine::yaml::PolicyDoc> = BTreeMap::new();
            for p in &bs {
                b_by_id.insert(p.id.clone(), p);
            }
            for p in &as_ {
                a_by_id.insert(p.id.clone(), p);
            }
            let mut added: Vec<&str> = Vec::new();
            let mut removed: Vec<&str> = Vec::new();
            let mut modified: Vec<(String, Vec<String>)> = Vec::new();
            for (id, ap) in &a_by_id {
                match b_by_id.get(id) {
                    None => added.push(id.as_str()),
                    Some(bp) => {
                        let deltas = field_diff(bp, ap);
                        if !deltas.is_empty() {
                            modified.push((id.clone(), deltas));
                        }
                    }
                }
            }
            for id in b_by_id.keys() {
                if !a_by_id.contains_key(id) {
                    removed.push(id.as_str());
                }
            }
            if format == "json" {
                let payload = json!({
                    "added": added,
                    "removed": removed,
                    "modified": modified.iter().map(|(id, fields)| json!({
                        "id": id, "fields": fields,
                    })).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                if added.is_empty() && removed.is_empty() && modified.is_empty() {
                    println!("{GREEN}no changes{RESET}");
                    return Ok(());
                }
                if !added.is_empty() {
                    println!("{GREEN}+ added{RESET}");
                    for id in &added {
                        println!("    {id}");
                    }
                }
                if !removed.is_empty() {
                    println!("{RED}- removed{RESET}");
                    for id in &removed {
                        println!("    {id}");
                    }
                }
                if !modified.is_empty() {
                    println!("~ modified");
                    for (id, fields) in &modified {
                        println!("    {id}: {}", fields.join(", "));
                    }
                }
            }
            Ok(())
        }
        PolicyCmd::Reload => {
            let resp = auth_header(http.post(format!("{url}/api/v1/policy/reload")), token)
                .send()
                .await
                .context("POST /api/v1/policy/reload")?;
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(json!({}));
            println!("{}", serde_json::to_string_pretty(&body)?);
            if !status.is_success() {
                return Err(anyhow!("reload failed (HTTP {status})"));
            }
            Ok(())
        }
        PolicyCmd::SetMode { id, mode } => {
            if !matches!(mode.as_str(), "enforce" | "observe" | "disabled") {
                return Err(anyhow!(
                    "mode must be one of: enforce | observe | disabled (got `{mode}`)"
                ));
            }
            let resp = auth_header(
                http.post(format!("{url}/api/v1/policy/{}/mode", urlencode(&id))),
                token,
            )
            .json(&json!({"mode": mode}))
            .send()
            .await
            .context("POST /api/v1/policy/{id}/mode")?;
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(json!({}));
            println!("{}", serde_json::to_string_pretty(&body)?);
            if !status.is_success() {
                return Err(anyhow!("set-mode failed (HTTP {status})"));
            }
            Ok(())
        }
        PolicyCmd::Edit {
            file,
            editor,
            no_reload,
        } => {
            cmd_policy_edit(
                http,
                url,
                token,
                file.as_deref(),
                editor.as_deref(),
                no_reload,
            )
            .await
        }
        PolicyCmd::Simulate {
            file,
            against,
            customer_domain,
            page_limit,
            format,
            fail_if_delta_exceeds,
        } => {
            cmd_policy_simulate(
                http,
                url,
                token,
                &file,
                &against,
                customer_domain.as_deref(),
                page_limit,
                &format,
                fail_if_delta_exceeds,
            )
            .await
        }
    }
}

/// `proxilion-cli policy edit` — guided editor flow over the live
/// `policy.yaml`. Unblocked by §11.1 (the comment-preserving
/// `set_mode` edit lands in [`policy_handle::edit_mode_in_yaml`]).
/// This command writes the *whole file* (not just a single field), so
/// the operator's editor session is the source of truth — there's no
/// proxy-side merge logic to worry about; we just validate + reload.
async fn cmd_policy_edit(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    explicit_file: Option<&str>,
    explicit_editor: Option<&str>,
    no_reload: bool,
) -> Result<()> {
    #[allow(non_snake_case)]
    let (GREEN, RED, _, RESET, _) = colors();
    // 1. Resolve the policy file path.
    let path = match explicit_file {
        Some(p) => p.to_string(),
        None => resolve_policy_source(http, url, token)
            .await
            .context("could not resolve policy file path; pass --file <path>")?,
    };

    // 2. Sanity-check it exists and is a regular file before invoking
    //    the editor (cheap; saves a confusing editor-on-nothing UX).
    let original = std::fs::read_to_string(&path)
        .with_context(|| format!("reading current policy file `{path}`"))?;

    // 3. Drop a `<path>.bak` so a bad edit is recoverable.
    let backup = format!("{path}.bak");
    std::fs::write(&backup, &original).with_context(|| format!("writing backup `{backup}`"))?;

    // 4. Resolve the editor command. Precedence: --editor > $EDITOR > $VISUAL > vi.
    let editor_cmd = explicit_editor
        .map(|s| s.to_string())
        .or_else(|| std::env::var("EDITOR").ok())
        .or_else(|| std::env::var("VISUAL").ok())
        .unwrap_or_else(|| "vi".to_string());

    // 5. Spawn the editor, wait for it to exit.
    println!("opening `{path}` in `{editor_cmd}` (backup at `{backup}`)…");
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("{editor_cmd} {}", shell_quote(&path)))
        .status()
        .with_context(|| format!("spawning editor `{editor_cmd}`"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&backup);
        return Err(anyhow!(
            "editor `{editor_cmd}` exited with {status}; not reloading"
        ));
    }

    // 6. Read back, short-circuit on no-change.
    let updated = std::fs::read_to_string(&path)
        .with_context(|| format!("re-reading `{path}` after editor"))?;
    if updated == original {
        let _ = std::fs::remove_file(&backup);
        println!("{GREEN}no changes — nothing to reload{RESET}");
        return Ok(());
    }

    // 7. Local validation via the policy engine — same parse the proxy
    //    will run on reload. Roll back on failure so we never leave the
    //    file in a state that would break the next process restart.
    if let Err(e) = policy_engine::yaml::parse_policies(&updated) {
        std::fs::write(&path, &original)
            .with_context(|| format!("restoring `{path}` from in-memory original"))?;
        let _ = std::fs::remove_file(&backup);
        return Err(anyhow!(
            "{RED}✗ candidate YAML failed to parse{RESET}: {e}\n\
             rolled back to original. Re-run `proxilion-cli policy edit` to retry."
        ));
    }
    println!("{GREEN}✓ candidate YAML parses locally{RESET}");

    if no_reload {
        println!(
            "skipping hot-reload (--no-reload). \
             Run `proxilion-cli policy reload` when you're ready."
        );
        // Keep the backup on `--no-reload`; the operator may want it.
        return Ok(());
    }

    // 8. Hot-reload via the proxy. The proxy parses+validates again
    //    before swapping; on its failure we still roll the file back so
    //    a manual restart wouldn't leave the proxy stuck on bad YAML.
    let resp = auth_header(http.post(format!("{url}/api/v1/policy/reload")), token)
        .send()
        .await
        .context("POST /api/v1/policy/reload")?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(json!({}));
    if !status.is_success() {
        std::fs::write(&path, &original)
            .with_context(|| format!("restoring `{path}` from in-memory original"))?;
        return Err(anyhow!(
            "reload failed (HTTP {status}); rolled back `{path}`.\nresponse: {}",
            serde_json::to_string_pretty(&body).unwrap_or_default()
        ));
    }
    println!(
        "{GREEN}✓ reloaded{RESET}: {} polic{} live",
        body["policy_count"].as_u64().unwrap_or(0),
        if body["policy_count"].as_u64() == Some(1) {
            "y"
        } else {
            "ies"
        }
    );

    // 9. Reload succeeded → remove the backup. The operator's `git
    //    diff` is the canonical history from here.
    let _ = std::fs::remove_file(&backup);
    Ok(())
}

/// Fetch `GET /api/v1/policy` and pull out the `source` field — the
/// path the proxy is loading policy from. Returns an error when the
/// proxy hasn't been configured with a source (the synthetic empty
/// policy set; `source` is null).
async fn resolve_policy_source(http: &reqwest::Client, url: &str, token: &str) -> Result<String> {
    let resp = auth_header(http.get(format!("{url}/api/v1/policy")), token)
        .send()
        .await
        .context("GET /api/v1/policy")?
        .error_for_status()
        .context("/api/v1/policy returned an error")?;
    let envelope: Value = resp.json().await?;
    envelope["source"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| {
            anyhow!(
                "proxy reports no policy source (PROXILION_POLICY_PATH unset?); \
                 pass --file <path> to edit a local file"
            )
        })
}

/// Minimal shell-quote for a single filesystem path. The path is the
/// only operator-supplied data crossing into `sh -c`, so we just need
/// to wrap it safely. Hardens against spaces, quotes, `$`, etc. POSIX
/// single-quoting: every embedded `'` becomes `'\''`.
fn shell_quote(s: &str) -> String {
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

// Replay history against a candidate YAML and report would-have-block deltas.
// ui-less-surfaces.md §2.4.
async fn cmd_policy_simulate(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    file: &str,
    against: &str,
    customer_domain: Option<&str>,
    page_limit: u32,
    format: &str,
    fail_if_delta_exceeds: Option<f64>,
) -> Result<()> {
    use policy_engine::{Decision, Engine, RequestContext, UserCtx};
    use std::collections::HashMap;

    // 1. Parse candidate YAML.
    let candidate_yaml =
        std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?;
    let candidate = Engine::new(&candidate_yaml)
        .map_err(|e| anyhow!("candidate policy YAML failed to parse: {e}"))?;

    // 2. Resolve window.
    let since = parse_window(against)?;
    let domain = customer_domain
        .map(|s| s.to_string())
        .or_else(|| std::env::var("PROXILION_CUSTOMER_DOMAIN").ok())
        .unwrap_or_else(|| "example.com".to_string());

    // 3. Page through /api/v1/actions until exhausted or the rows pre-date `since`.
    let mut before: Option<String> = None;
    let mut total: usize = 0;
    let mut would_now_block: HashMap<String, usize> = HashMap::new();
    let mut would_now_allow: HashMap<String, usize> = HashMap::new();
    let mut was_blocked_total: HashMap<String, usize> = HashMap::new();
    let mut now_blocked_total: HashMap<String, usize> = HashMap::new();
    let mut unreplayable: usize = 0;
    let mut progress = Progress::new("simulating", "rows", format);

    let since_str = since.to_rfc3339();

    loop {
        let mut req = http.get(format!("{url}/api/v1/actions")).query(&[
            ("since", since_str.as_str()),
            ("limit", &page_limit.to_string()),
        ]);
        if let Some(b) = before.as_deref() {
            req = req.query(&[("before", b)]);
        }
        let resp = auth_header(req, token)
            .send()
            .await
            .context("GET /api/v1/actions")?
            .error_for_status()
            .context("/api/v1/actions returned an error")?;
        let envelope: Value = resp.json().await?;
        let rows = envelope["rows"].as_array().cloned().unwrap_or_default();
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            total += 1;
            progress.tick(total as u64);
            let vendor = row["vendor"].as_str().unwrap_or("").to_string();
            let action = row["action"].as_str().unwrap_or("").to_string();
            let p_0 = row["p_0"].as_str().unwrap_or("").to_string();
            let original_decision = row["decision"].as_str().unwrap_or("").to_string();
            let was_blocked = original_decision == "block"
                || original_decision == "observe_block"
                || original_decision == "pic_invariant_violation"
                || original_decision == "read_filter_blocked";

            // Rehydrate body fields from `extra` where the adapter wrote them.
            let extra = &row["extra"];
            let mut body: HashMap<String, Value> = HashMap::new();
            for k in &[
                "to_domain",
                "to_domains",
                "external_recipient",
                "recipient_count",
                "attendee_domains",
                "external_attendee",
                "attendee_count",
                "visibility",
                "summary_present",
            ] {
                if let Some(v) = extra.get(*k) {
                    if !v.is_null() {
                        body.insert((*k).to_string(), v.clone());
                    }
                }
            }
            // request_path_params, if present.
            let mut path = HashMap::new();
            if let Some(p) = extra.get("request_path_params") {
                if let Some(map) = p.as_object() {
                    for (k, v) in map {
                        if let Some(s) = v.as_str() {
                            path.insert(k.clone(), s.to_string());
                        }
                    }
                }
            }

            // Replayable iff vendor and action are present.
            if vendor.is_empty() || action.is_empty() {
                unreplayable += 1;
                continue;
            }

            let ctx = RequestContext {
                vendor,
                action,
                user: UserCtx {
                    email: p_0,
                    groups: vec![],
                },
                path,
                body,
                headers: HashMap::new(),
                customer_domain: domain.clone(),
            };

            let simulated = match candidate.evaluate(&ctx) {
                Ok(o) => o,
                Err(_) => {
                    unreplayable += 1;
                    continue;
                }
            };
            let simulated_blocked = matches!(simulated.decision, Decision::Block { .. })
                || simulated.observe_would_have.as_deref() == Some("observe_block");
            let policy_id = simulated
                .matched_policy_id
                .clone()
                .unwrap_or_else(|| "(none)".to_string());

            if was_blocked {
                *was_blocked_total.entry(policy_id.clone()).or_default() += 1;
            }
            if simulated_blocked {
                *now_blocked_total.entry(policy_id.clone()).or_default() += 1;
            }
            match (was_blocked, simulated_blocked) {
                (false, true) => {
                    *would_now_block.entry(policy_id).or_default() += 1;
                }
                (true, false) => {
                    *would_now_allow.entry(policy_id).or_default() += 1;
                }
                _ => {}
            }
        }
        // Cursor.
        before = envelope["next_before"].as_str().map(|s| s.to_string());
        if before.is_none() || rows.len() < page_limit as usize {
            break;
        }
    }
    progress.finish(total as u64);

    // 4. Render report + compute max delta percentage.
    let mut keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    keys.extend(was_blocked_total.keys().cloned());
    keys.extend(now_blocked_total.keys().cloned());
    keys.extend(would_now_block.keys().cloned());
    keys.extend(would_now_allow.keys().cloned());

    let mut rows = Vec::new();
    let mut max_pct_delta: f64 = 0.0;
    for k in &keys {
        let was = was_blocked_total.get(k).copied().unwrap_or(0);
        let now = now_blocked_total.get(k).copied().unwrap_or(0);
        let new_blocks = would_now_block.get(k).copied().unwrap_or(0);
        let new_allows = would_now_allow.get(k).copied().unwrap_or(0);
        let delta = now as i64 - was as i64;
        let pct = if total > 0 {
            (delta.unsigned_abs() as f64) * 100.0 / (total as f64)
        } else {
            0.0
        };
        if pct > max_pct_delta {
            max_pct_delta = pct;
        }
        rows.push(json!({
            "policy_id": k,
            "was_blocked": was,
            "now_blocked": now,
            "would_now_block": new_blocks,
            "would_now_allow": new_allows,
            "delta": delta,
            "delta_pct": pct,
        }));
    }

    let report = json!({
        "replayed": total,
        "unreplayable": unreplayable,
        "window": against,
        "since": since_str,
        "customer_domain": domain,
        "policies": rows,
        "max_pct_delta": max_pct_delta,
    });

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "Replayed {total} actions over `{against}` ({} unreplayable)",
            unreplayable
        );
        if total == 0 {
            println!("No history in the window.");
        } else {
            println!();
            println!(
                "{:<40} {:>8} {:>8} {:>12} {:>12}",
                "policy_id", "was_blk", "now_blk", "+would_blk", "+would_allow"
            );
            println!("{}", "─".repeat(86));
            for r in &report["policies"].as_array().unwrap().clone() {
                println!(
                    "{:<40} {:>8} {:>8} {:>12} {:>12}",
                    r["policy_id"].as_str().unwrap_or(""),
                    r["was_blocked"].as_u64().unwrap_or(0),
                    r["now_blocked"].as_u64().unwrap_or(0),
                    r["would_now_block"].as_u64().unwrap_or(0),
                    r["would_now_allow"].as_u64().unwrap_or(0),
                );
            }
            println!();
            println!("Max delta: {:.2}% of replayed events.", max_pct_delta);
        }
    }

    if let Some(threshold) = fail_if_delta_exceeds {
        if max_pct_delta > threshold {
            return Err(anyhow!(
                "max delta {max_pct_delta:.2}% exceeds threshold {threshold:.2}% (--fail-if-delta-exceeds)"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod simulate_tests {
    use super::*;

    #[test]
    fn parse_window_days() {
        let r = parse_window("last-7d").unwrap();
        let now = chrono::Utc::now();
        let diff = now.signed_duration_since(r);
        assert!(diff.num_hours() >= 168 - 1 && diff.num_hours() <= 168 + 1);
    }

    #[test]
    fn parse_window_hours_and_minutes_and_seconds() {
        parse_window("last-24h").unwrap();
        parse_window("last-15m").unwrap();
        parse_window("last-30s").unwrap();
    }

    #[test]
    fn parse_window_rejects_unknown_unit() {
        assert!(parse_window("last-7y").is_err());
    }

    #[test]
    fn parse_window_accepts_rfc3339() {
        parse_window("2026-01-01T00:00:00Z").unwrap();
    }
}

#[cfg(test)]
mod policy_edit_tests {
    use super::*;

    #[test]
    fn shell_quote_wraps_in_single_quotes() {
        assert_eq!(shell_quote("/etc/policy.yaml"), "'/etc/policy.yaml'");
        assert_eq!(
            shell_quote("path with spaces.yaml"),
            "'path with spaces.yaml'"
        );
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quote() {
        // POSIX `'\''` idiom: close, escape literal `'`, reopen.
        assert_eq!(shell_quote("o'reilly.yaml"), "'o'\\''reilly.yaml'");
    }

    #[test]
    fn shell_quote_neutralizes_metacharacters() {
        // `$`, backticks, `;`, `|`, and `&` are all literal inside
        // single quotes — the wrapper alone is enough.
        let nasty = "policy.yaml; rm -rf $HOME && echo `id`";
        let quoted = shell_quote(nasty);
        assert!(quoted.starts_with('\''));
        assert!(quoted.ends_with('\''));
        assert!(quoted.contains("$HOME"));
        assert!(quoted.contains("`id`"));
    }

    /// The candidate-YAML validation step is the same `parse_policies`
    /// call the proxy will run on reload; we pin it here as the
    /// pre-flight guard the CLI relies on. ui-less-surfaces.md §11.1
    /// → §4.1 `policy edit` chain.
    #[test]
    fn validation_step_accepts_well_formed_yaml() {
        let yaml = "\
- id: edit-test
  vendor: google
  action: drive.files.get
  decision: allow
  required_ops: []
  pic_mode: audit
";
        let parsed = policy_engine::yaml::parse_policies(yaml).expect("valid");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "edit-test");
    }

    #[test]
    fn validation_step_rejects_malformed_yaml() {
        let bad = "not yaml :: [::";
        assert!(policy_engine::yaml::parse_policies(bad).is_err());
    }
}

/// Window parser. Accepts `last-7d`, `last-24h`, `last-1h`, `last-15m`,
/// or an RFC 3339 timestamp. Returns the UTC since-cutoff.
fn parse_window(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    if let Some(rest) = s.strip_prefix("last-") {
        // Accept "7d", "24h", "1h", "15m", "30s".
        let (num, unit) = rest.split_at(
            rest.find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len()),
        );
        let n: i64 = num
            .parse()
            .map_err(|e| anyhow!("invalid window number `{num}`: {e}"))?;
        let dur = match unit {
            "d" => chrono::Duration::days(n),
            "h" => chrono::Duration::hours(n),
            "m" => chrono::Duration::minutes(n),
            "s" => chrono::Duration::seconds(n),
            other => return Err(anyhow!("unknown window unit `{other}` (use d|h|m|s)")),
        };
        return Ok(chrono::Utc::now() - dur);
    }
    // Try as RFC 3339.
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| {
            anyhow!(
                "invalid --against value `{s}` — expected an RFC3339 timestamp \
                 (e.g. 2026-06-11T14:00:00Z) or a window like \"7d\", \"24h\", \"30m\", \"45s\": {e}"
            )
        })
}

// ─────────────────────────────────────────────────────────────────────────
// Blocked-action queue
// ─────────────────────────────────────────────────────────────────────────

async fn cmd_blocked(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    sub: BlockedCmd,
) -> Result<()> {
    match sub {
        BlockedCmd::List {
            status,
            p_0,
            policy_id,
            limit,
            format,
        } => {
            let mut q = vec![("status", status), ("limit", limit.to_string())];
            if let Some(v) = p_0 {
                q.push(("p_0", v));
            }
            if let Some(v) = policy_id {
                q.push(("policy_id", v));
            }
            let resp = auth_header(http.get(format!("{url}/api/v1/blocked")), token)
                .query(&q)
                .send()
                .await
                .context("GET /api/v1/blocked")?
                .error_for_status()
                .context("/api/v1/blocked returned an error")?;
            let envelope: Value = resp.json().await?;
            let rows = envelope["rows"].as_array().cloned().unwrap_or_default();
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                println!(
                    "{:<38} {:<11} {:<22} {:<22} policy_id",
                    "id", "status", "p_0", "action"
                );
                println!("{}", "─".repeat(120));
                for r in &rows {
                    let id = r["id"].as_str().unwrap_or("");
                    // char-safe: byte-slicing `&id[..36]` would panic if the
                    // server ever returned an id with a multibyte char straddling
                    // byte 36. Every other truncation here is char-counted too.
                    let id_short = format!("{}…", id.chars().take(36).collect::<String>());
                    println!(
                        "{:<38} {:<11} {:<22} {:<22} {}",
                        id_short,
                        r["status"].as_str().unwrap_or(""),
                        truncate(r["p_0"].as_str().unwrap_or(""), 22),
                        truncate(r["action"].as_str().unwrap_or(""), 22),
                        r["policy_id"].as_str().unwrap_or(""),
                    );
                }
                println!("\n{} row(s)", rows.len());
            }
            Ok(())
        }
        BlockedCmd::Show { id, format } => {
            let resp = auth_header(
                http.get(format!("{url}/api/v1/blocked/{}", urlencode(&id))),
                token,
            )
            .send()
            .await
            .context("GET /api/v1/blocked/{id}")?
            .error_for_status()
            .context("/api/v1/blocked/{id} returned an error")?;
            let body: Value = resp.json().await?;
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                pretty_blocked_record(&body);
            }
            Ok(())
        }
        BlockedCmd::Approve {
            id,
            justification,
            approver,
            ttl,
        } => {
            let user = std::env::var("USER").unwrap_or_else(|_| "cli".into());
            let approver = approver.unwrap_or_else(|| format!("{user}@cli"));
            let mut body = json!({
                "justification": justification,
                "approver_subject": approver,
            });
            if let Some(t) = ttl {
                body["ttl_minutes"] = json!(t);
            }
            let resp = auth_header(
                http.post(format!("{url}/api/v1/blocked/{}/approve", urlencode(&id))),
                token,
            )
            .json(&body)
            .send()
            .await
            .context("POST /api/v1/blocked/{id}/approve")?;
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(json!({}));
            println!("{}", serde_json::to_string_pretty(&body)?);
            if !status.is_success() {
                return Err(anyhow!("approve failed (HTTP {status})"));
            }
            Ok(())
        }
        BlockedCmd::Reject { id, reason } => {
            let body = match reason {
                Some(r) => json!({"reason": r}),
                None => json!({}),
            };
            let resp = auth_header(
                http.post(format!("{url}/api/v1/blocked/{}/reject", urlencode(&id))),
                token,
            )
            .json(&body)
            .send()
            .await
            .context("POST /api/v1/blocked/{id}/reject")?;
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(json!({}));
            println!("{}", serde_json::to_string_pretty(&body)?);
            if !status.is_success() {
                return Err(anyhow!("reject failed (HTTP {status})"));
            }
            Ok(())
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn pretty_blocked_record(v: &Value) {
    println!("{}", bold("blocked action"));
    for k in [
        "id",
        "request_id",
        "session_id",
        "p_0",
        "vendor",
        "action",
        "method",
        "path",
        "layer",
        "policy_id",
        "detail",
        "predecessor_pca_id",
        "status",
        "created_at",
        "expires_at",
        "approver_subject",
        "override_pca_id",
        "justification",
        "reject_reason",
    ] {
        if let Some(val) = v.get(k) {
            if !val.is_null() {
                println!("  {:<22} {}", k, val);
            }
        }
    }
    if let Some(ops) = v.get("requested_ops").and_then(|v| v.as_array()) {
        if !ops.is_empty() {
            println!("  {}", bold("requested_ops:"));
            for o in ops {
                if let Some(s) = o.as_str() {
                    println!("    {s}");
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Notifier (ui-less-surfaces.md §4.1)
// ─────────────────────────────────────────────────────────────────────────

async fn cmd_notifier(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    sub: NotifierCmd,
) -> Result<()> {
    match sub {
        NotifierCmd::Show { format } => {
            let resp = auth_header(http.get(format!("{url}/api/v1/notifier/show")), token)
                .send()
                .await
                .context("GET /api/v1/notifier/show")?
                .error_for_status()
                .context("/api/v1/notifier/show returned an error")?;
            let body: Value = resp.json().await?;
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                let webhook = &body["webhook"];
                let configured = webhook["configured"].as_bool().unwrap_or(false);
                #[allow(non_snake_case)]
                let (GREEN, _, _, RESET, YELLOW) = colors();
                if !configured {
                    println!("webhook: {YELLOW}not configured{RESET}");
                    println!(
                        "  set PROXILION_BLOCKED_WEBHOOK_URL + PROXILION_BLOCKED_WEBHOOK_HMAC_KEY to enable"
                    );
                } else {
                    println!(
                        "webhook: {GREEN}configured{RESET}  ({})",
                        webhook["proxy_public_url_redacted"]
                            .as_str()
                            .unwrap_or("unknown")
                    );
                }
                let burst = &body["burst"];
                if burst.is_null() {
                    println!("burst:   disabled");
                } else {
                    println!(
                        "burst:   threshold={} window={}s flush={}s",
                        burst["threshold"].as_u64().unwrap_or(0),
                        burst["window_seconds"].as_u64().unwrap_or(0),
                        burst["flush_interval_seconds"].as_u64().unwrap_or(0),
                    );
                }
            }
            Ok(())
        }
        NotifierCmd::Test { driver } => {
            if !matches!(driver.as_str(), "all" | "webhook" | "slack" | "email") {
                return Err(anyhow!(
                    "driver must be one of: all | webhook | slack | email (got `{driver}`)"
                ));
            }
            let resp = auth_header(http.post(format!("{url}/api/v1/notifier/test")), token)
                .json(&json!({ "driver": driver }))
                .send()
                .await
                .context("POST /api/v1/notifier/test")?;
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(json!({}));
            println!("{}", serde_json::to_string_pretty(&body)?);
            if !status.is_success() {
                return Err(anyhow!("notifier test failed (HTTP {status})"));
            }
            Ok(())
        }
        NotifierCmd::Config => {
            let resp = auth_header(http.get(format!("{url}/api/v1/notifier/config")), token)
                .send()
                .await
                .context("GET /api/v1/notifier/config")?
                .error_for_status()?;
            let body: Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            Ok(())
        }
        NotifierCmd::SetWebhook {
            url: hook_url,
            hmac_hex,
            disabled,
        } => {
            let body = json!({
                "driver": "webhook",
                "enabled": !disabled,
                "config": { "url": hook_url, "hmac_key": hmac_hex },
            });
            let resp = auth_header(http.post(format!("{url}/api/v1/notifier/config")), token)
                .json(&body)
                .send()
                .await
                .context("POST /api/v1/notifier/config")?;
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(json!({}));
            println!("{}", serde_json::to_string_pretty(&body)?);
            if !status.is_success() {
                return Err(anyhow!("notifier set-webhook failed (HTTP {status})"));
            }
            Ok(())
        }
        NotifierCmd::SetEmail {
            smtp_url,
            from,
            to,
            disabled,
        } => {
            let body = json!({
                "driver": "email",
                "enabled": !disabled,
                "config": {
                    "smtp_url": smtp_url,
                    "from": from,
                    "to": to,
                },
            });
            let resp = auth_header(http.post(format!("{url}/api/v1/notifier/config")), token)
                .json(&body)
                .send()
                .await
                .context("POST /api/v1/notifier/config")?;
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(json!({}));
            println!("{}", serde_json::to_string_pretty(&body)?);
            if !status.is_success() {
                return Err(anyhow!("notifier set-email failed (HTTP {status})"));
            }
            Ok(())
        }
        NotifierCmd::SetSlack {
            incoming_webhook_url,
            signing_secret,
            disabled,
        } => {
            let body = json!({
                "driver": "slack",
                "enabled": !disabled,
                "config": {
                    "incoming_webhook_url": incoming_webhook_url,
                    "signing_secret": signing_secret,
                },
            });
            let resp = auth_header(http.post(format!("{url}/api/v1/notifier/config")), token)
                .json(&body)
                .send()
                .await
                .context("POST /api/v1/notifier/config")?;
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(json!({}));
            println!("{}", serde_json::to_string_pretty(&body)?);
            if !status.is_success() {
                return Err(anyhow!("notifier set-slack failed (HTTP {status})"));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod pure_helper_tests {
    use super::*;

    #[test]
    fn resolve_color_honors_never_always_and_auto_matrix() {
        // §3.2 — `always`/`never` are absolute regardless of TTY/NO_COLOR.
        assert!(resolve_color(ColorChoice::Always, true, false));
        assert!(resolve_color(ColorChoice::Always, false, false));
        assert!(!resolve_color(ColorChoice::Never, false, true));
        assert!(!resolve_color(ColorChoice::Never, true, true));
        // `auto`: color iff NO_COLOR unset AND stdout is a TTY.
        assert!(resolve_color(ColorChoice::Auto, false, true));
        assert!(!resolve_color(ColorChoice::Auto, true, true)); // NO_COLOR set
        assert!(!resolve_color(ColorChoice::Auto, false, false)); // piped / non-TTY
        assert!(!resolve_color(ColorChoice::Auto, true, false));
    }

    #[test]
    fn colors_returns_empty_strings_when_disabled_and_codes_when_enabled() {
        // The `colors()` tuple is the single gate every styled site reads.
        // Default global is disabled → all empty (the test-process default).
        let (g, r, d, rs, y) = colors();
        if should_color() {
            assert_eq!(
                (g, r, d, rs, y),
                ("\x1b[32m", "\x1b[31m", "\x1b[2m", "\x1b[0m", "\x1b[33m")
            );
        } else {
            assert_eq!((g, r, d, rs, y), ("", "", "", "", ""));
            // bold() is gated by the same predicate.
            assert_eq!(bold("x"), "x");
        }
    }

    #[test]
    fn progress_is_inert_for_json_format_and_under_test_non_tty() {
        // §3.5 — a `--format json` run never animates progress (machine
        // output stays clean), and under the test harness (stderr is not a
        // TTY) the indicator is inert regardless of format. `tick`/`finish`
        // must be safe no-ops in the inert state.
        let mut p = Progress::new("simulating", "rows", "json");
        assert!(!p.active, "json format must disable progress");
        p.tick(100);
        p.finish(100);
        // Non-json under the (non-TTY) test harness is also inert.
        let mut p2 = Progress::new("exporting", "bytes", "pretty");
        assert!(!p2.active, "non-TTY stderr must disable progress in tests");
        p2.tick(1);
        p2.finish(1);
    }

    #[test]
    fn cli_command_tree_is_internally_consistent() {
        // clap's debug_assert validates the whole derive tree (no
        // duplicate args, valid value-parsers, etc). Catches a malformed
        // subcommand/arg at test time rather than at first invocation —
        // including the new `completion` arm.
        Cli::command().debug_assert();
    }

    #[test]
    fn completion_generates_a_nonempty_script_for_every_supported_shell() {
        // §3.4 — `proxilion-cli completion <shell>` must emit a script for
        // each clap_complete shell. Generate into a buffer and assert it
        // references the binary name, so a broken command tree surfaces here.
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            let mut cmd = Cli::command();
            let mut buf: Vec<u8> = Vec::new();
            clap_complete::generate(shell, &mut cmd, "proxilion-cli", &mut buf);
            let script = String::from_utf8(buf).expect("completion script is utf8");
            assert!(
                !script.is_empty() && script.contains("proxilion-cli"),
                "{shell:?} completion script missing binary name",
            );
        }
    }

    #[test]
    fn format_metric_value_integers_drop_decimal() {
        assert_eq!(format_metric_value(0.0), "0");
        assert_eq!(format_metric_value(1.0), "1");
        assert_eq!(format_metric_value(-7.0), "-7");
        assert_eq!(format_metric_value(1234567.0), "1234567");
    }

    #[test]
    fn format_metric_value_fractions_keep_six_digits() {
        let s = format_metric_value(1.5);
        assert!(s.starts_with("1.5"));
        assert!(s.contains('.'));
        let s2 = format_metric_value(0.0001);
        assert!(s2.starts_with("0.000"));
    }

    #[test]
    fn parse_since_accepts_rfc3339_and_duration() {
        parse_since("2026-01-01T00:00:00Z").unwrap();
        parse_since("5m").unwrap();
        parse_since("24h").unwrap();
        parse_since("7d").unwrap();
        assert!(parse_since("nonsense").is_err());
    }

    #[test]
    fn urlencode_preserves_unreserved_chars() {
        assert_eq!(urlencode("abc-DEF_123.~"), "abc-DEF_123.~");
    }

    #[test]
    fn urlencode_percent_encodes_reserved_chars() {
        assert_eq!(urlencode(" "), "%20");
        assert_eq!(urlencode("/"), "%2F");
        assert_eq!(urlencode("&=?"), "%26%3D%3F");
        assert_eq!(urlencode("a b"), "a%20b");
    }

    #[test]
    fn generate_token_format_and_uniqueness() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert!(t1.starts_with(TOKEN_PREFIX));
        assert_eq!(t1.len(), TOKEN_PREFIX.len() + TOKEN_BODY_LEN);
        // body chars are base32 alphabet
        let body = &t1[TOKEN_PREFIX.len()..];
        assert!(
            body.chars()
                .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
        );
        assert_ne!(t1, t2);
    }

    #[test]
    fn token_hash_is_sha256_stable_32_bytes() {
        let h1 = token_hash("foo");
        let h2 = token_hash("foo");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
        let h3 = token_hash("bar");
        assert_ne!(h1, h3);
    }

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate("", 5), "");
    }

    #[test]
    fn truncate_long_string_gets_ellipsis() {
        let s = truncate("abcdef", 4);
        assert_eq!(s.chars().count(), 4);
        assert!(s.ends_with('…'));
    }

    #[test]
    fn truncate_unicode_counts_chars_not_bytes() {
        // 6 multi-byte chars; bytes > 6 but chars == 6
        assert_eq!(truncate("ééééée", 6), "ééééée");
        let s = truncate("ééééééé", 5);
        assert_eq!(s.chars().count(), 5);
    }

    #[test]
    fn matches_tail_filter_no_filter_always_true() {
        assert!(matches_tail_filter("{}", None, None, None));
        assert!(matches_tail_filter("invalid-json", None, None, None));
    }

    #[test]
    fn matches_tail_filter_decision_match() {
        let data = r#"{"decision":"block","vendor":"google","action":"x"}"#;
        assert!(matches_tail_filter(data, Some("block"), None, None));
        assert!(!matches_tail_filter(data, Some("allow"), None, None));
    }

    #[test]
    fn matches_tail_filter_combines_decision_vendor_action() {
        let data = r#"{"decision":"allow","vendor":"google","action":"drive.files.get"}"#;
        assert!(matches_tail_filter(
            data,
            Some("allow"),
            Some("google"),
            Some("drive.files.get")
        ));
        assert!(!matches_tail_filter(
            data,
            Some("allow"),
            Some("google"),
            Some("gmail.messages.send")
        ));
    }

    #[test]
    fn matches_tail_filter_invalid_json_passes_through() {
        // Don't drop events we can't parse.
        assert!(matches_tail_filter("not json", Some("block"), None, None));
    }

    #[test]
    fn make_mock_jwt_three_parts_with_decodable_payload() {
        let payload = serde_json::json!({"sub":"alice","iss":"test"});
        let jwt = make_mock_jwt(&payload);
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let body_bytes = base64::Engine::decode(&B64URL, parts[1]).unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(decoded["sub"], "alice");
        assert_eq!(decoded["iss"], "test");
        assert_eq!(parts[2], "signature");
    }

    #[test]
    fn field_diff_detects_no_changes_when_identical() {
        let yaml = "\
- id: p1
  vendor: google
  action: drive.files.get
  decision: allow
  required_ops: []
  pic_mode: audit
";
        let docs = policy_engine::yaml::parse_policies(yaml).unwrap();
        assert!(field_diff(&docs[0], &docs[0]).is_empty());
    }

    #[test]
    fn field_diff_flags_vendor_action_and_required_ops_changes() {
        let before_y = "\
- id: p1
  vendor: google
  action: drive.files.get
  decision: allow
  required_ops: []
  pic_mode: audit
";
        let after_y = "\
- id: p1
  vendor: github
  action: drive.files.list
  decision: allow
  required_ops:
    - 'drive:read:file/x'
  pic_mode: audit
";
        let b = &policy_engine::yaml::parse_policies(before_y).unwrap()[0];
        let a = &policy_engine::yaml::parse_policies(after_y).unwrap()[0];
        let diffs = field_diff(b, a);
        let joined = diffs.join("|");
        assert!(joined.contains("vendor:"));
        assert!(joined.contains("action:"));
        assert!(joined.contains("required_ops"));
    }
}
