# UI-less surfaces — outcome-as-a-service for secure managed agents

**Status:** Proposed (2026-05-11). Supersedes the dashboard portions of
[`spec.md`](./spec.md): §0.5 (dashboard scaffold), §1.6 (dashboard live
action feed + PCA chain inspector), and the UI portions of §2.3 (block-queue
+ justified-override). The proxy-side endpoints those steps already delivered
remain — only the React/Next.js dashboard is dropped.

**Authority:** This file is the spec for the customer-facing surfaces of
Proxilion. Anything not covered here (PIC chain shape, OAuth interception,
read-filter rules, policy engine internals) is unchanged from `spec.md`.

---

## 0. Why no dashboard

Proxilion's customer is a security team that already owns:

- A metrics stack (Grafana / Datadog / Honeycomb / New Relic) for graphs.
- A ticketing or chat tool (Slack / Teams / PagerDuty / Jira) for human
  decisions.
- A SIEM or data lake (Splunk / Elastic / Snowflake / BigQuery) for audit
  retention and queryable forensics.
- A terminal, with `jq`, for ad-hoc grep.

Building a Proxilion-specific React dashboard means:

1. Re-implementing each of those surfaces, badly, in one tab they have to
   remember to open. Diminishing returns.
2. Owning a long maintenance tail (auth, RBAC, accessibility, browser
   support, screenshot rot, Next.js upgrades) that doesn't move the
   product's outcome forward.
3. Creating a *second* source of truth for the audit log. The audit log is
   the customer's data — it belongs in their lake, indexed by their tools,
   not behind a self-hosted React app.

The outcome customers buy is **"managed AI agents you don't own are
constrained to act only inside human authority, and you can prove it
forever."** Achieving that outcome requires:

- **Telemetry** so people can see what the system is doing →
  Prometheus `/metrics`, scraped by their stack.
- **Control** so people can change policy, switch enforcement modes,
  search history, download evidence → `proxilion-cli` + HTTP API + NDJSON
  streaming exports.
- **Human-in-the-loop** for the blocked-action approval flow → Slack /
  email / generic webhook, with signed one-click approve / reject links.

Three surfaces. None of them is a dashboard.

---

## 1. The three surfaces

```
                   ┌──────────────────────────────────────────────┐
                   │  Customer's existing tooling                 │
                   │                                              │
                   │   Grafana ── pulls ── /metrics               │
                   │   Slack   ── pushes / pulls ── /api/v1/blocked│
                   │   SIEM    ── pulls / pushes ── /api/v1/actions │
                   │   Terminal ── proxilion-cli ── any of the above │
                   └──────────────────────────────────────────────┘
                                       │
                                       ▼
                   ┌──────────────────────────────────────────────┐
                   │              Proxilion proxy                 │
                   │                                              │
                   │   /metrics          (Prometheus exposition)  │
                   │   /api/v1/...        (audit + control HTTP)  │
                   │   /api/v1/actions/stream  (SSE NDJSON)        │
                   │   Slack/webhook OUT  (block notifications)   │
                   └──────────────────────────────────────────────┘
```

| Surface | What it gives | Where it lives | Who consumes it |
|---|---|---|---|
| **A. Telemetry** | Counters, gauges, histograms covering every PIC decision, OAuth step, adapter call, policy hit, block, approval | `GET /metrics` (Prometheus exposition format) | Customer's Grafana / Datadog / etc. — *they* draw the graphs they care about |
| **B. Control + audit** | Policy CRUD; mode toggle (observe / enforce); log search; log download (JSON / NDJSON / CSV); live tail; killswitch; manual block override | `proxilion-cli` (thin wrapper over the existing HTTP API) | Terminal, scripts, CI, runbooks |
| **C. Human-in-the-loop** | "This action was blocked, approve or reject?" interactive messages with signed one-click links | Slack (interactive blocks) / email (signed mailto) / generic webhook (any other tool) | Whoever the customer designates: secops on-call, the user's manager, a shared channel |

Everything else — the metrics dashboard layout, the alert routing, the long-term audit retention — happens in the customer's own tools, against feeds Proxilion exposes.

---

## 2. Enforcement modes — `observe` vs `enforce`, per policy

The biggest operational complaint about preventative security tooling is
"it blocks me from doing my job." The mitigation is to let customers
roll out policies in **observe** mode first, watch the metric, then promote
to **enforce** once the false-positive rate is acceptable.

### 2.1 The mode dimension

Every Layer-B policy and the system-wide PIC enforcement layer carry a
`mode` field with three possible values:

| Mode | Decision recorded | Action taken | Use case |
|---|---|---|---|
| `observe` | yes | request proceeds untouched | Roll-out, tuning, baseline |
| `enforce` | yes | matched action is blocked / quarantined / require-confirmation | Production |
| `disabled` | no | nothing — policy is not evaluated | Emergency disable; otherwise prefer `observe` |

PIC invariant violations (chain breakage, ops monotonicity break) have
their own runtime-gate setting (`spec.md` §1.4 / §2.4) which mirrors this
two-mode model: `pic_invariants.mode: observe | enforce`. In `observe`
mode a tampered PCA is logged and metric'd but the request still flows.

### 2.2 YAML

`config/policy.yaml` example:

```yaml
defaults:
  # Applied to any policy that doesn't set mode explicitly.
  mode: observe          # safe default — flip to enforce after baseline
  pic_invariants:
    mode: enforce        # crypto invariants always enforce by default;
                         # observe is a deliberate exception for migrations

policies:
  - id: drive-injection-filter
    mode: enforce
    match:
      vendor: google
      action: drive.files.get
    then:
      read_filter:
        patterns: [...]

  - id: gmail-external-recipient
    mode: observe         # not yet enforcing — collecting baseline
    match:
      vendor: google
      action: gmail.messages.send
      body.to_domain:
        not_in: ["${customer_domain}"]
    then:
      decision: block
      reason: "external recipient"
```

### 2.3 Hot reload

The proxy watches the policy file (`inotify` on Linux, `kqueue` on macOS,
fall back to 5s polling everywhere else) and reloads on change. A reload
is atomic: the new policy set is parsed and validated *before* it replaces
the live set. Validation failure leaves the previous set running and
emits `proxilion_policy_reload_failures_total{reason}`. Successful reloads
emit `proxilion_policy_reload_success_total` and a structured log line
with the diff (added / removed / modified policy ids).

### 2.4 Per-policy mode flip from the CLI

```bash
proxilion-cli policy set-mode gmail-external-recipient enforce
proxilion-cli policy set-mode gmail-external-recipient observe
proxilion-cli policy list --mode=observe        # show what's still in dry-run
proxilion-cli policy diff main feature/new-rules  # YAML diff helper
```

The CLI edits the YAML file in place (preserving comments via `yq` semantics
or a hand-rolled CST-preserving editor — see §11) and triggers the same
hot-reload path as a manual edit.

**Status (2026-05-11) — observe mode + hot reload shipped.** Delivered:

- [crates/policy-engine/src/yaml.rs](../../crates/policy-engine/src/yaml.rs) — new top-level `mode: enforce | observe | disabled` field on `PolicyDoc` (default `enforce`). The `pic_invariants.mode` knob the spec sketches at the file level isn't a YAML field; PIC enforcement remains controlled by the existing per-policy `pic_mode: audit | runtime-gate`, which already mirrors the observe/enforce shape for Layer A.
- [crates/policy-engine/src/rego.rs](../../crates/policy-engine/src/rego.rs) — `Engine::evaluate` now demotes `Block` / `RequireConfirmation` / `RateLimit` to `Decision::Allow` in observe mode and surfaces an `observe_would_have: Option<String>` ("observe_block" / "observe_require_confirmation" / "observe_rate_limit") on the `Outcome`. `disabled` policies are skipped entirely without consuming the match slot, so a later policy can still fire.
- [crates/proxy/src/adapters/google_{drive,gmail,calendar}.rs](../../crates/proxy/src/adapters/) — all three adapters now record the would-have label on the `action_events.decision` column and emit `proxilion_observe_would_have_blocked_total{policy_id,reason}` per match.
- [crates/proxy/src/policy_handle.rs](../../crates/proxy/src/policy_handle.rs) — `PolicyHandle` wraps `ArcSwap<Engine>` for lock-free atomic swaps. Three reload paths: API (`POST /api/v1/policy/reload`), file watcher background task (5s mtime poll, ui-less-surfaces.md §2.3 fallback semantics), and in-memory mode flip (`POST /api/v1/policy/{id}/mode`, round-trips the mutated YAML back into the cached buffer). **Parse failures leave the previous engine live** — load-bearing for production safety, verified end-to-end below.
- [crates/proxy/src/api/policy.rs](../../crates/proxy/src/api/policy.rs) — three new endpoints: `GET /api/v1/policy` (lists `{id, vendor, action, mode, pic_mode}` for every loaded policy plus `source` path), `POST /api/v1/policy/reload`, `POST /api/v1/policy/{id}/mode` (body `{"mode":"enforce|observe|disabled"}`). 400 on unknown mode, 404 on unknown policy, 409 on reload-after-parse-failure.
- Metrics: `proxilion_policy_reload_success_total`, `proxilion_policy_reload_failures_total{reason="io_error|parse_error|no_source"}`, `proxilion_observe_would_have_blocked_total{policy_id,reason}`.

**Unit tests** (4 new in `policy-engine/tests/observe_mode.rs`, 5 new in `policy_handle::tests`): observe demotes block→allow with label, enforce passes decision through, disabled skips evaluation, default mode is enforce; swap atomicity, bad YAML keeps previous engine, set_mode round-trips through the YAML cache, set_mode 404 on unknown id, reload-without-source returns error. `cargo test --workspace` is green at **84 passing** (was 74).

**End-to-end verification (2026-05-11)** via [scripts/stress-observe-reload.sh](../../scripts/stress-observe-reload.sh) against the live compose stack:
- `GET /api/v1/policy` returns all 5 policies with current modes + source path.
- `POST /api/v1/policy/drive-injection-filter/mode {"mode":"observe"}` round-trips: subsequent `GET` shows `mode: observe`.
- Invalid mode → 400; unknown policy → 404.
- File watcher: append a 6th policy on disk → watcher detects within 3s (well under the 12s budget), `GET` reflects 6 policies.
- Write garbage YAML to disk → watcher reads it, fails to parse, leaves the previous 6-policy engine live; `proxilion_policy_reload_failures_total{reason="parse_error"}=1` ticks.
- Restore file → watcher reloads cleanly, `proxilion_policy_reload_success_total` ticks.

**Spec deviations to flag.**

1. **No `pic_invariants.mode` top-level field.** §2.2 sketches a `defaults: { pic_invariants: { mode: enforce } }` block. PIC invariant enforcement is already per-policy via the existing `pic_mode: audit | runtime-gate`, which gives the same observability story without adding a defaults pre-processor. If a customer asks for global PIC observe-mode (e.g. for a migration), it's a one-line `for_each_policy` over the loaded set.
2. **CST-preserving editor not used.** §11.1 flags `yq` vs hand-rolled CST. We use `serde_yaml` round-trip on `set_mode` — comments and key ordering ARE NOT preserved across writes. The mutation lives in memory; the file watcher picks up the operator's manual edits independently. A CST-preserving editor is a follow-up when a customer reports a real comment-mangling regression.
3. ~~`policy simulate` not yet shipped.~~ **Resolved 2026-05-12.** [`crates/cli/src/main.rs::cmd_policy_simulate`](../../crates/cli/src/main.rs) implements `proxilion-cli policy simulate <file> --against last-7d`. The flow: parse the candidate YAML into a `policy_engine::Engine`, page through `/api/v1/actions` (200-line limit, follows `next_before` cursors), rehydrate a `RequestContext` per historical row from `vendor`, `action`, `p_0`, and the body-shape fields the adapters write into `action_events.extra` (`to_domain`/`to_domains`/`external_recipient` for Gmail; `attendee_domains`/`external_attendee` for Calendar; `request_path_params` for Drive), then aggregate per-`policy_id` counts: `was_blocked` (history), `now_blocked` (candidate), `would_now_block` / `would_now_allow` (deltas). Output: `--format pretty` (aligned columns + max-pct summary) or `--format json`. `--fail-if-delta-exceeds 5.0` exits 1 when any policy's delta-percentage of total replayed events exceeds the threshold, suitable for CI gates. 4 unit tests cover the window parser (`last-7d` / `last-15m` / `last-30s` / RFC 3339 / unknown unit).<br><br>**Deviations.** (a) Reads/writes whose body fields aren't in `extra` (default-deny privacy posture per §6.4) are replayed with empty body context — match expressions against `body.*` will not fire, undercounting deltas for policies that gate on body shape. The customer can opt their policies into `audit_body: full` for a richer simulation pass. (b) Groups are unknown post-hoc (we don't persist them on the action_events row), so `groups`-based match expressions are skipped. (c) Replay is single-shot; no cron-friendly "watch this trend over weeks" surface — that's a daily-cron-running-this-CLI ergonomic, not a missing primitive.

---

### 2.5 What `observe` mode actually does on the wire

In `observe` mode, the decision pipeline runs identically:

1. Layer-B policy evaluates → would-have-blocked / would-have-quarantined / etc.
2. PIC required-ops template computed → would-have-been-rejected by Trust Plane.
3. The `action_events` row is persisted with `decision = "observe_$X"` where
   `$X` is the would-have decision (`observe_block`, `observe_quarantine`,
   `observe_require_confirmation`).
4. The request continues to the upstream as if nothing happened.
5. `proxilion_observe_would_have_blocked_total{policy_id,reason}` ticks.

This is what lets a customer roll out a new policy, leave it in `observe`
for a week, and graph `would_have_blocked_total` by policy id — if the
shape looks safe, promote to `enforce`. If not, refine the policy and
re-baseline.

---

## 3. Surface A — Prometheus `/metrics`

### 3.1 Endpoint

`GET /metrics` on the same port as the rest of the proxy (8443 by default).
Returns Prometheus exposition format. No auth in v1 — same trust boundary
as `/api/v1/*` (assume operator network is private; revisit when the proxy
is exposed to a multi-tenant ingress).

`PROXILION_METRICS_EXPORTER` env: `prometheus` (default) or `otlp` for OTLP
push to a customer-specified collector. Both can be on at once.

### 3.2 Metric names — the contract

Every name is `proxilion_<subsystem>_<thing>_<unit>` (Prometheus naming
convention). Labels are kept low-cardinality on purpose: `vendor`, `action`
(verb only, never the URL path), `decision`, `mode`, `policy_id`,
`reason_code`. **Never** label by `p_0`, `pca_id`, `request_id`,
`session_id`, or anything user-shaped — those go in logs / action_events,
not metrics.

```
# OAuth interception
proxilion_oauth_authorize_total{result="ok|denied|error"}
proxilion_oauth_callback_total{idp,result}
proxilion_oauth_token_refreshes_total{vendor,result}
proxilion_oauth_active_sessions{}                       # gauge

# PIC / Trust Plane
proxilion_pca_issue_total{result,hop_class}             # hop_class = "0|1|2|n"
proxilion_pca_cache_hits_total{}
proxilion_pca_cache_misses_total{reason}
proxilion_pca_verify_total{result="intact|broken"}
proxilion_pca_verify_duration_seconds{}                  # histogram, le buckets per spec.md §1.5
proxilion_pic_invariant_violations_total{kind="continuity|monotonicity|p0|hop|signature"}

# Adapter calls (one bucket per vendor.action)
proxilion_adapter_requests_total{vendor,action,decision,mode}
proxilion_adapter_request_duration_seconds{vendor,action}  # histogram
proxilion_adapter_upstream_errors_total{vendor,action,kind="timeout|5xx|network"}

# Policy engine
proxilion_policy_evaluations_total{policy_id,result="match|nomatch|error"}
proxilion_policy_evaluation_duration_seconds{}            # histogram, p99<1ms budget
proxilion_policy_reload_success_total{}
proxilion_policy_reload_failures_total{reason}

# Read-filter
proxilion_readfilter_scans_total{vendor,action,result="clean|stripped|quarantined"}
proxilion_readfilter_quarantined_bytes_total{vendor}

# Block + override
proxilion_blocks_total{policy_id,reason}
proxilion_observe_would_have_blocked_total{policy_id,reason}
proxilion_overrides_requested_total{channel="slack|email|webhook|cli"}
proxilion_overrides_resolved_total{outcome="approved|rejected|expired",channel}
proxilion_overrides_pending{}                              # gauge
proxilion_override_latency_seconds{outcome}                # histogram

# Killswitch
proxilion_killswitch_invocations_total{scope="session|user|agent|all"}
proxilion_killswitch_revoked_capabilities_total{}

# Federation / Trust Plane health
proxilion_trust_plane_up{}                                 # gauge 0/1
proxilion_federation_bridge_up{}                           # gauge 0/1

# Action stream + audit log
proxilion_action_events_persisted_total{decision}
proxilion_action_events_persist_failures_total{reason}
proxilion_audit_export_bytes_total{format="json|ndjson|csv"}
proxilion_audit_export_requests_total{format}

# Process / runtime
proxilion_build_info{version,git_sha,rust_version}
process_*                                                  # standard prometheus rust client
```

### 3.3 Cardinality discipline

| Label | Allowed values (approx) | Why this bound |
|---|---|---|
| `vendor` | ~10 (google, slack, jira, salesforce, …) | Adapters are hand-written |
| `action` | ~50 per vendor | Verb only, never `:id` or paths |
| `decision` | 5 (allow / block / require_confirmation / rate_limit / observe_*) | Enum |
| `mode` | 3 (observe / enforce / disabled) | Enum |
| `policy_id` | bounded by customer's YAML (typically <100) | Customer-controlled, document the bound |
| `reason_code` | <30 per policy | Curated set, not free-text |
| `idp` | 4 (okta / azure / google / oidc) | Enum |

Total active series ceiling per metric: low-thousands at the 99th-percentile
deployment, fits comfortably in a Prometheus single-node setup.

### 3.4 Customer-side: dashboards-as-code, not a UI

Proxilion ships a Grafana dashboard JSON in `ops/grafana/proxilion.json`,
designed for *their* Grafana, not ours. The dashboard is documentation in
JSON form — they import it, version it, modify it. We never run a
Grafana ourselves. Same approach for Datadog: a `ops/datadog/monitors.tf`
Terraform module with the recommended alerts. For OTLP customers,
`ops/otel/` has the equivalent OTel collector config snippets.

The Grafana JSON answers the four questions a security team will actually
ask:

1. **Are we secure?** (`pic_invariant_violations_total` rate, `blocks_total`
   rate, `oauth_authorize_total{result!=ok}` rate)
2. **Are we annoying people?** (`blocks_total` rate, `overrides_pending`
   gauge, `override_latency_seconds` histogram)
3. **What rolls out next?** (`observe_would_have_blocked_total` by
   `policy_id` — the candidates to promote to `enforce`)
4. **Is the system healthy?** (`trust_plane_up`, `*_request_duration_seconds`
   p99, `policy_reload_failures_total`)

### 3.5 SLOs the customer can write against the metrics

These aren't promises Proxilion makes — they're suggested SLOs the customer
can write against the data, surfaced in the bundled Grafana dashboard:

- Decision latency p99 < 50ms (adapter request duration minus upstream).
- `pca_verify_duration_seconds` p99 < 5ms warm / < 20ms cold.
- Override approval latency p50 < 5 min (signals Slack rollout is working).
- Policy evaluation p99 < 1ms (already a budget in `spec.md` §0.3).

---

## 4. Surface B — `proxilion-cli`

A single Rust binary built from `crates/cli/`. Wraps the existing HTTP API,
adds shell ergonomics (pretty / JSON / NDJSON output, paging, `--watch`,
`--filter` shorthand, `--format=csv`, tab-completion, `--explain`).

### 4.1 Command tree

```
proxilion <command> [subcommand] [flags]

GLOBAL FLAGS
  --endpoint URL         (default: $PROXILION_ENDPOINT or https://localhost:8443)
  --token  TOKEN         (default: $PROXILION_OPERATOR_TOKEN)
  --format pretty|json|ndjson|csv|tsv
  --no-color
  -v / -vv               (verbose / debug logging from the CLI itself)

COMMANDS
  status                              system + health snapshot, exit≠0 if unhealthy
  setup                               run the /api/v1/setup/status checklist locally
  selftest                            synthetic transaction end-to-end (already in spec)

  actions
    tail                              live SSE stream (= /actions/stream)
        --filter <expr>               e.g. decision=block, vendor=google, action=*.send
        --since 5m
        --output json|ndjson|csv
    list                              paginated history (= /actions)
        --since 24h --until now
        --vendor google --action drive.files.get
        --decision block
        --p_0 alice@org.com
        --session-id UUID
        --limit 500 --all
    show <action_id>                  full record + chain (= /actions/:id)
    export                            bulk download
        --since 2026-01-01 --until 2026-05-01
        --format ndjson|csv|json
        --output proxilion-audit-2026-01.ndjson.zst
        --compress zst|gz|none
    verify <pca_id>                   verify chain by leaf id (= /pca/:id/verify)
    chain <session_id>                ordered chain for a session (= /sessions/:id/chain)

  blocked
    list                              pending block queue
        --since 24h
        --policy-id ...
        --pending|--approved|--rejected|--expired
    show <id>                         full block record + chain + suggested fix
    approve <id> --justification "<text>" [--ttl 30m]
    reject  <id> --reason "<text>"

  policy
    list [--mode observe|enforce|disabled]
    show <id>
    edit                              opens $EDITOR on policy.yaml, validates, hot-reloads
    set-mode <id> observe|enforce|disabled
    validate <file>                   parse + simulate; exit code 0/1; works in CI
    simulate <file> --against last-7d   replay history against a candidate policy,
                                        report would-have-block deltas
    diff <branch-or-file> <branch-or-file>
    reload                            force hot-reload (also runs on file change)

  pic
    invariants                        show current mode (observe|enforce) per invariant
    set-invariants-mode observe|enforce
    show <pca_id>                     PCA JSON + CBOR hex (= /pca/:id)
    verify <pca_id>                   = /pca/:id/verify

  killswitch
    revoke session <session_id>
    revoke user <p_0>
    revoke agent <agent_session_id>
    revoke all --confirm              global stop, must type yes

  notifier                            Slack / email / webhook diagnostics
    show                                webhook + burst-suppressor state
    test                                fire a synthetic notification
    # Coming in a future iteration when the `notifier_config` table lands:
    #   test slack | test email | test webhook
    #   set slack.bot_token <token> / channel <#channel>
    #   set email.smtp.url smtp://... --from sec-ops@org.com
    #   set webhook.url https://... --hmac-secret <hex>

  clients                             OAuth client registry (replaces SQL editing)
    list
    add <client_id> --name "Anthropic Managed Claude" --redirect-uri ...
    rotate <client_id>
    revoke <client_id>

  metrics
    sample                            curl /metrics and pretty-print top series
    serve                             local Prometheus pushgateway shim (rarely needed)

  trust-plane
    info                              upstream Trust Plane status + CAT key info
    rotate-cat-key                    triggered rotation; emits new kid; clients re-fetch

  version                             build info, embeds git SHA + rust toolchain
```

### 4.2 Output modes

| `--format` | Use case |
|---|---|
| `pretty` (default) | Human in a terminal. ANSI color, columns, time-relative. |
| `json` | One JSON document, for `jq` consumption of single results. |
| `ndjson` | One JSON document per line, for streaming + `jq -c`. Default for `tail` and `export`. |
| `csv` / `tsv` | Spreadsheet / SQL import. Headers on first line; deterministic column order. |

`pretty` mode never truncates IDs silently — it abbreviates with `…` and
shows the full ID with `proxilion actions show <id>`. `pretty` mode always
exits 0 / 1 / 2 with documented meanings (0 = ok, 1 = matched but
unhealthy, 2 = transport error).

### 4.3 Composability examples

```bash
# Live tail of blocked actions, formatted for humans
proxilion actions tail --filter decision=block

# Dump last 30 days of audit log to an S3-ready file
proxilion actions export --since 30d --format ndjson --compress zst \
  --output /tmp/proxilion-$(date +%F).ndjson.zst

# Grafana / Splunk: pipe NDJSON straight in
proxilion actions tail --output ndjson | splunk -i forward:tcp:9997

# CI: fail the build if any policy would have changed behavior
proxilion policy validate config/policy.yaml &&
  proxilion policy simulate config/policy.yaml --against last-7d \
    --fail-if-delta-exceeds 5%

# On-call runbook: who's blocked right now?
proxilion blocked list --pending --since 1h --format ndjson | jq '.action'

# Killswitch in one keystroke
proxilion killswitch revoke user alice@org.com
```

### 4.4 Authentication

The CLI authenticates with an **operator token** — `pxl_operator_*`,
issued once at install (`proxilion-cli init` mints it, prints once,
stores hashed in `operator_tokens`). Tokens are scoped: a CI bot might
have `policy:read, policy:simulate` only; an on-call human has
`blocks:approve, killswitch:revoke`. Scopes are documented and listed
by `proxilion-cli tokens scopes`.

WebAuthn / passkey login is **not** a v1 requirement because the CLI
is the only UI — operators authenticate to the CLI, not to a browser.
Passkeys land if and only if we add a notifier-served HTML page for
approve-from-mobile use cases (§5.4).

**Status (2026-05-11) — operator tokens shipped.** Delivered:

- [migrations/0006_operator_tokens.sql](../../migrations/0006_operator_tokens.sql) — `operator_tokens` table: `id`, `token_hash` (SHA-256 of plaintext, raw bytes), `name`, `scopes TEXT[]`, `created_at`, `last_used_at`, `revoked_at`, `revoked_reason`. Partial index on `revoked_at` for fast active-token lookup.
- [crates/proxy/src/operator_auth.rs](../../crates/proxy/src/operator_auth.rs) — token format (`pxl_operator_<52 base32 chars>`, same shape as agent bearer), SHA-256 hashing, `OperatorPrincipal` extension, `middleware()` extracts `Authorization: Bearer pxl_operator_*`, looks up hash, rejects revoked/missing/malformed with `401 unauthorized` (fixed body, no info leak). Successful auth attaches `OperatorPrincipal` to request extensions for downstream handlers + fires a `tokio::spawn`-ed best-effort `last_used_at` update. The `require_scope(...)` helper exists and is unit-tested but per-endpoint scope checks are a follow-up (see deviation 1).
- [crates/proxy/src/server.rs](../../crates/proxy/src/server.rs) — all five `/api/v1/*` routers (`pca`, `actions`, `blocked`, `killswitch`, `policy`) are merged and wrapped in a single `operator_auth::middleware` layer. `/healthz`, `/metrics`, `/admin`, `/admin/setup`, `/oauth/*`, and the adapter routes (`/google/*`) remain outside the operator-auth boundary — those have their own auth model (the agent's `pxl_live_*` bearer).
- [crates/cli/src/main.rs](../../crates/cli/src/main.rs) — three new subcommands: `tokens issue --name <n> --scope <scopes>` (mints + prints once, hashes + persists), `tokens list [--all]` (active or full history), `tokens revoke <id> --reason <r>`. Writes directly to postgres via `DATABASE_URL` — that's the bootstrap path the spec describes ("proxilion-cli init mints it, prints once").
- Metrics: `proxilion_operator_auth_total{result="ok|rejected",reason}`. Reason buckets are bounded (`missing`, `malformed`, `unknown_or_revoked`, `no_principal`, `scope_denied`).
- Default posture: **enforced**. Set `PROXILION_DISABLE_OPERATOR_AUTH=1` to bypass for local dev — emits a loud `WARN` on every startup so it's visible in CI/prod logs. The docker compose file flips this on for the dev stack so the existing demo and stress scripts continue to work; production deployments leave it unset.

**Unit tests** (7 new in `operator_auth::tests`): token-format validation (correct shape; rejected: wrong prefix, lowercase, wrong length), wildcard scope acceptance, exact-scope acceptance + rejection on miss, SHA-256 hash stability. `cargo test --workspace` is green at **87 passing** (was 80).

**End-to-end verification (2026-05-11)** via [scripts/stress-operator-tokens.sh](../../scripts/stress-operator-tokens.sh):
- `proxilion-cli tokens issue` mints an admin (`*` scope) token and a narrow `policy:read,actions:read` ci-bot token. `tokens list` returns 2 rows.
- Toggle proxy to enforced (`PROXILION_DISABLE_OPERATOR_AUTH=0` + restart). Unauthed `/api/v1/policy` → 401, bogus token → 401, valid admin → 200, valid ci-bot → 200.
- `tokens revoke <id>` flips `revoked_at`. Subsequent request with the revoked token → 401; admin token unaffected.
- `proxilion_operator_auth_total{result="ok"}` and `{result="rejected"}` both tick. `last_used_at` is updated within ~1s of a successful request.
- Restore disabled mode → unauthed requests succeed again, preserving the dev-compose default.

**Update (2026-05-11) — per-endpoint scope enforcement shipped + `proxilion-cli policy / blocked` subcommands wired.** Delivered:

- [crates/proxy/src/operator_auth.rs](../../crates/proxy/src/operator_auth.rs) — `scope_check` middleware function used via `axum::middleware::from_fn_with_state("scope:name", scope_check)`. When the outer operator-auth middleware is disabled (`PROXILION_DISABLE_OPERATOR_AUTH=1`) it attaches a synthetic wildcard principal so the per-route checks are no-ops; in enforced mode an absent principal would have already 401'd at the outer layer. Wrong scope → `403 scope_denied` with a structured body `{ "code": "scope_denied", "required": "<scope>", "have": [...], "error": "insufficient scope" }`.
- [crates/proxy/src/api/{mod,actions,blocked,killswitch,policy}.rs](../../crates/proxy/src/api/) — every route layered with its specific scope:

| Method + path | Scope |
|---|---|
| `GET /api/v1/pca/{id}` + `/verify` | `pca:read` |
| `GET /api/v1/actions*` (list, recent, stream, {id}, sessions chain) | `actions:read` |
| `GET /api/v1/actions/export` | `actions:export` |
| `GET /api/v1/blocked` + `/{id}` | `blocks:read` |
| `POST /api/v1/blocked/{id}/{approve,reject}` | `blocks:approve` |
| `POST /api/v1/killswitch/{session,user,all}/...` | `killswitch:revoke` |
| `GET /api/v1/policy` | `policy:read` |
| `POST /api/v1/policy/reload` + `…/{id}/mode` | `policy:write` |
- [crates/cli/src/main.rs](../../crates/cli/src/main.rs) — new global `--token / $PROXILION_OPERATOR_TOKEN` flag; new subcommands `policy {list,reload,set-mode}` and `blocked {list,show,approve,reject}` (covers ui-less-surfaces.md §4.1's `policy` and `blocked` blocks). Each command builds the request via a small `auth_header()` helper so absent tokens (dev mode) still produce a clean request.

**End-to-end verification (2026-05-11)** via [scripts/stress-scope-and-cli.sh](../../scripts/stress-scope-and-cli.sh) — 21 assertions, all passing:
- Mint three tokens (policy-read-only, blocks-approve, wildcard admin).
- `policy:read` token → `GET /policy = 200`, `POST /policy/reload = 403`, `POST /killswitch/all = 403`, body carries `required` + `have`.
- `blocks:approve` token → `GET /blocked = 200`, `GET /policy = 403`.
- CLI happy-path: `policy list / set-mode / reload`, then seed a blocked-action with a real Trust-Plane-minted PCA_0, `blocked list / show / approve`, then re-seed and exercise `reject`.
- CLI fail-path: `proxilion-cli blocked approve` with the `policy:read` token surfaces the 403 to the operator.
- Metric `proxilion_operator_auth_total{result="rejected",reason="scope_denied"}` ticks.

**Spec deviations to flag.**

1. **`POST /api/v1/policy/{id}/mode` round-trips through serde_yaml.** Same caveat as the original notice: comments / key ordering are not preserved across writes. Still tracked alongside §11.1 (CST-preserving editor).
2. **No `proxilion-cli init` wrapper.** §4.4 sketches `proxilion-cli init` as the bootstrap command. We ship the same functionality split into the three explicit verbs (`issue`/`list`/`revoke`) — that fits better with operator scripting (`set -e`-friendly, JSON output to `jq`) than a one-shot `init` that prints a token to a TTY. A thin `init` alias can be added when an installer needs it.
3. ~~No `proxilion-cli tokens scopes` listing.~~ **Resolved 2026-05-12.** [crates/shared-types/src/operator_scopes.rs](../../crates/shared-types/src/operator_scopes.rs) is now the single source of truth for the scope catalogue (`SCOPE_CATALOGUE: &[(scope, description, endpoints)]`). [crates/proxy/src/operator_auth.rs](../../crates/proxy/src/operator_auth.rs) consumes it; the CLI ships `proxilion-cli tokens scopes [--format pretty|json]` ([crates/cli/src/main.rs::cmd_tokens_scopes](../../crates/cli/src/main.rs)). The command does not require `DATABASE_URL` — it's a pure read of the in-binary catalogue, so it works in CI / container builds where the env-less invariant matters. 3 unit tests in `operator_scopes::tests` pin "no duplicate scopes," "wildcard present," and "every entry has a non-empty description + endpoints list."
4. **`last_used_at` writes are fire-and-forget.** Under sustained load every request triggers one `UPDATE`. If write amplification shows up in profiles, the natural mitigation is to debounce (only update when stale > 60s) — moka-cache the in-memory timestamp the same way the bearer refresh coordinator caches mutexes. Not yet a real bottleneck on the dev stack.

### 4.5 Distribution

- `cargo install proxilion-cli` (workspace member already exists per
  `spec.md` §0.1).
- Pre-built static binaries in GitHub releases (linux-amd64, linux-arm64,
  darwin-arm64, darwin-amd64, windows-amd64).
- `brew install proxilion/tap/proxilion-cli`.
- A 600 KB single binary, no runtime dependencies, no Node/Python.

---

## 5. Surface C — Slack / email / generic webhook approvals

This is the surface that earns its keep. Everything else is "we exposed
the data, you went and got it." This one is "we pushed something into
your existing tool, you clicked yes."

### 5.1 The flow

```
                Agent              Proxilion              Slack channel              Approver
                  │                    │                       │                         │
                  │  POST /gmail/send  │                       │                         │
                  │ ──────────────────▶│                       │                         │
                  │                    │ Layer-B block decision│                         │
                  │                    │ persist blocked_actions                         │
                  │  HTTP 202 ⏸︎       │  signed Slack message ▶│                         │
                  │ ◀──────────────────│ "Approve / Reject"    │  notify channel members │
                  │                    │                       │ ──────────────────────▶ │
                  │                    │                       │  click ✅ Approve       │
                  │                    │  Slack interaction    │ ◀─────────────────────  │
                  │                    │  webhook   ◀──────────│                         │
                  │                    │ POST /api/v1/blocked/:id/approve                │
                  │                    │ create override PCA branch                      │
                  │  resume + execute  │                       │                         │
                  │ ◀──────────────────│                       │                         │
                  │                    │ post "approved by @alice" reply in thread       │
                  │                    │ ─────────────────────▶│                         │
```

### 5.2 The blocked-action object

```json
{
  "id": "01HFAB...",
  "session_id": "...",
  "p_0": "alice@org.com",
  "vendor": "google",
  "action": "gmail.messages.send",
  "method": "POST",
  "path": "/gmail/v1/users/me/messages/send",
  "summary": "Send to evilcorp.example (external) — 1 recipient",
  "request_canonical_json": "{...}",
  "policy_id": "gmail-external-recipient",
  "policy_reason": "external recipient",
  "pic_invariant_violated": null,
  "predecessor_pca_id": "...",
  "required_ops": ["gmail:send:alice@org.com:to:evilcorp.example"],
  "missing_ops": ["gmail:send:alice@org.com:to:evilcorp.example"],
  "suggested_fix": "Add `gmail:send:alice@org.com:to:evilcorp.example` to alice@org.com's PCA_0 ops (org IdP group), or override this single send.",
  "status": "pending",
  "created_at": "...",
  "expires_at": "...",
  "override_pca_id": null
}
```

### 5.3 Slack interactive message

The message uses Slack's Block Kit. One message per blocked action,
posted to the customer-configured channel (`#proxilion-blocks` by
default), threaded by `policy_id` so a burst of similar blocks doesn't
flood the channel — they fold into a thread.

```
Header:      🛑  Blocked: gmail.messages.send
Body:        alice@org.com → evilcorp.example  (external recipient)
             Policy: gmail-external-recipient
             Subject: "Q4 forecast — please review"
             [Approve once]  [Approve + add to policy exception]  [Reject]  [Why?]
Footer:      Expires in 30 min · Action ID 01HFAB…
```

- **[Approve once]** — single-use override; creates an override PCA branch
  per `spec.md` §2.3; sets `expires_at = now + ttl` (default 30 min); the
  underlying action retries automatically (the agent's request that was
  blocked is still suspended on the proxy side waiting for the decision).
- **[Approve + add to policy exception]** — same as Approve, but also
  appends a YAML exception block to `policy.yaml`. Generates a PR-style
  diff in the message thread that the security owner can edit later.
- **[Reject]** — operator chooses from a short reason list (Suspicious /
  Wrong recipient / Not authorized / Testing); reason is logged and
  attached to the PCA `reject_attestation`. Agent sees a 403 with a
  redacted reason.
- **[Why?]** — opens an ephemeral message with the full
  `request_canonical_json` (truncated to 4 KB), the matched policy YAML,
  and a link to the PCA chain JSON for forensic review.

Slack interactivity is verified per Slack's signed-request scheme:
- `X-Slack-Signature` (HMAC-SHA256 over timestamp + body, keyed by the
  app's signing secret stored in `notifier_config`).
- 5-minute timestamp skew window.
- Idempotency: each Slack interaction has a unique `trigger_id`; we record
  it in `blocked_actions.slack_trigger_id` so a double-click can't approve
  twice.

The approver's identity (`U_SLACK123`) is mapped to a Proxilion operator
identity via `notifier_config.slack.user_map` (an IdP-group lookup is the
production path; manual map is fine for v1). The mapped operator
identity is what attests the override PCA — same as a CLI `blocked approve`.

**Status (2026-05-11) — shipped.** Delivered:

- [crates/proxy/src/notifier/slack.rs](../../crates/proxy/src/notifier/slack.rs) — `SlackNotifier { incoming_webhook_url, signing_secret, proxy_public_url }`. `notify(&BlockedNotification)` POSTs a Block Kit JSON envelope (header / context section / detail context / actions buttons / footer). Button `value` carries `approve:<uuid>` / `reject:<uuid>` — the interaction webhook parses these to route. `SlackSigningSecret::verify(signature, timestamp, body)` implements Slack's `v0:<ts>:<body>` scheme with constant-time compare + 5-minute skew window.
- [crates/proxy/src/api/notifier_slack.rs](../../crates/proxy/src/api/notifier_slack.rs) — `POST /api/v1/notifier/slack/interact` lives **outside** the operator-auth boundary; the signed request IS the credential. Reads the raw request body (so signature verification matches Slack's byte-exact computation), verifies via the configured `signing_secret`, parses the form-encoded JSON `payload`, and routes the button via `parse_button_value` → `approve_inner` / `reject_inner` with `channel="slack"` and `approver_subject="slack:<username>"`.
- [crates/proxy/src/notifier/handle.rs](../../crates/proxy/src/notifier/handle.rs) — generalized to `Handle<T>` with per-driver `NotifierHandle` (webhook) and `SlackHandle` aliases. New `Notifiers` bundle holds both; `AdapterState.notifier: Notifiers` and `blocked::persist_and_notify` fan out to **both** drivers in parallel when both are configured.
- [crates/proxy/src/api/notifier.rs](../../crates/proxy/src/api/notifier.rs) — `POST /api/v1/notifier/config` now accepts `driver: "slack"` with `config: { incoming_webhook_url, signing_secret }`. `GET` redacts both the signing_secret and the URL.
- [crates/cli/src/main.rs](../../crates/cli/src/main.rs) — `proxilion-cli notifier set-slack --incoming-webhook-url <u> --signing-secret <s> [--disabled]`.
- Metrics: `proxilion_slack_post_total{result,layer}`, `proxilion_slack_post_failures_total{reason}`, `proxilion_slack_interact_total{result}`, `proxilion_notifier_config_changes_total{driver="slack"}`.

**Unit tests** (5 new in `notifier::slack::tests`): Block Kit payload shape (header + approve/reject buttons with `style: primary|danger`), button value round-trip + rejection of bad shapes, signed-request verify happy path + rejection of stale timestamp + rejection of tampered body + rejection of missing `v0=` prefix. `cargo test --workspace` is green at **119 proxy tests** (was 110).

**End-to-end verification (2026-05-11)** via [scripts/stress-slack-driver.sh](../../scripts/stress-slack-driver.sh) — 12 assertions, all passing:
- `proxilion-cli notifier set-slack` persists row + hot-swaps notifier.
- `/api/v1/notifier/show` reports `slack: configured: true`.
- `/api/v1/notifier/config` redacts `signing_secret` (echoes `signing_secret_set: true`) and the URL.
- Seeded blocked-action row + valid Slack-signed POST → approval succeeds, blocked row → `overridden`, approver = `slack:<username>`.
- Missing signature → 401. Bad signature → 401. 10-minute-old timestamp → 401 (replay rejected even with valid HMAC).
- Reject button → row → `rejected`.
- Metrics: `proxilion_slack_interact_total{result="ok"}=2`, `{result="rejected_signature"}=2`.

**Spec deviations to flag.**

1. **No `[Approve once]` vs `[Approve + add to policy exception]` distinction.** The Block Kit message ships two buttons: Approve and Reject. The "add to policy exception" path requires a YAML editor that we'd plumb back into the policy hot-reload — a follow-up when a customer asks for it. For v1 the single-use approve covers the operational case.
2. **No `[Why?]` button.** Hover-context with full request_canonical_json was a v1.5 ergonomics nicety. The blocked-action row carries all the same fields; an operator who wants forensic context calls `proxilion-cli blocked show <id>`.
3. ~~No `slack_trigger_id` idempotency check.~~ **Resolved 2026-05-12.** [migrations/0011_slack_trigger_id.sql](../../migrations/0011_slack_trigger_id.sql) adds `blocked_actions.slack_trigger_id TEXT` with a unique partial index `WHERE slack_trigger_id IS NOT NULL` (rejects two distinct trigger_ids racing on the same row at the DB layer). [crates/proxy/src/api/notifier_slack.rs::claim_trigger_id](../../crates/proxy/src/api/notifier_slack.rs) runs before the existing `approve_inner` / `reject_inner` dispatch: an atomic `UPDATE … WHERE id=$1 AND status='pending' AND slack_trigger_id IS NULL` returns one of four states — **Fresh** (proceed), **Retry** (Slack delivered the same trigger_id twice → return idempotent success message), **Conflict** (different trigger_id already claimed the row → 409), or **Error** (continue and rely on the existing `FOR UPDATE` race protection inside `approve_inner`). New metrics: `proxilion_slack_interact_total{result="retry_idempotent|conflict_other_trigger|claim_error"}`. The FOR UPDATE inside `approve_inner` remains the canonical race protection; trigger_id is strictly additive (gives idempotent retry semantics + an audit trail of which Slack click owned the override).
4. **No `user_map` from Slack user to Proxilion operator.** The approver_subject is recorded as `slack:<username>`. An IdP-group lookup that maps Slack users to operator tokens is a v2 piece tied to operator-token-with-scopes (ui-less-surfaces.md §4.4 deviation 1). Today: every Slack user in the channel can approve (the customer controls who's in the channel).
5. ~~No burst-suppression / thread folding.~~ **Resolved 2026-05-12.** [crates/proxy/src/notifier/slack.rs::with_burst](../../crates/proxy/src/notifier/slack.rs) plumbs the same `BurstSuppressor` the webhook driver uses; suppressed events skip the per-event POST and a periodic flush calls the new `notify_summary(&BurstSummary)` method which emits a *dedicated* Slack Block Kit layout (no Approve/Reject buttons — the summary is informational; the per-burst exemplar names the canonical vendor/action/layer so the operator can find the queue). [crates/proxy/src/server.rs::build_notifiers](../../crates/proxy/src/server.rs) attaches the suppressor + spawns the flush loop with the per-policy `BurstResolver` already used by the webhook driver, so `policy.yaml`'s `notifier_burst:` block hot-applies to the Slack path too. New metrics: `proxilion_slack_summary_sent_total{policy_id}`, `proxilion_slack_summary_failures_total{reason}`. **One deviation** — the spec calls for the summary to be "folded into a thread" via `thread_ts`. We post the summary as a standalone message instead; threading requires storing the original parent `message_ts` per `(policy_id, p_0)` bucket, which is one schema row away. Today's standalone summary still collapses the channel noise (one message per burst window), so the operational pain point — channel mute — is solved.

### 5.4 Email approvals (for orgs that don't live in Slack)

Configurable per-policy; can coexist with Slack. The email contains:

- Plain-text and HTML bodies. Both have a one-click **Approve** and
  **Reject** link.
- Each link is a signed URL:
  `https://proxilion.local/api/v1/blocked/<id>/approve?token=<bearer>`
  where `<bearer>` is a single-use HMAC-signed token bound to
  `(blocked_action_id, action, expires_at, approver_email)`.
- Token TTL = block expiry (default 30 min). Single-use enforced by
  `consumed_at` column in `notifier_tokens`.
- Reject link opens a `mailto:` with the reason text pre-filled so the
  approver can hit send — server polls the reply mailbox (or accepts the
  click+form on the rejection landing page).
- DMARC / SPF / DKIM aligned via the customer's SMTP relay.

If the approver clicks Approve from a mobile mail client and they're not
already logged in, the URL serves a *single-purpose HTML page* (no SPA,
no React) — just the block summary, a confirm button, and the result.
This is the **one** server-rendered HTML page Proxilion ships. It's
~80 lines of HTML, no JS framework. It exists because most security
people read email on a phone.

**Update (2026-05-11) — outbound email composer + SMTP delivery shipped.** Builds on the signed-URL plumbing below: every blocked-action persist mints two single-use `notifier_tokens` (approve + reject) and emails plain-text + HTML bodies with both one-click links. Delivered:

- [crates/proxy/src/notifier/email.rs](../../crates/proxy/src/notifier/email.rs) — `EmailNotifier` wraps a lettre `AsyncSmtpTransport<Tokio1Executor>` with a 10s timeout. `notify(&BlockedNotification)` issues two tokens (one per action), composes a multipart alternative (text/plain + text/html), and sends via SMTP. HTML body has Approve (green) + Reject (red) buttons; plain-text mirrors the same two links. HTML-escapes every field that goes into the body.
- [Cargo.toml](../../Cargo.toml) + [crates/proxy/Cargo.toml](../../crates/proxy/Cargo.toml) — `lettre = { version = "0.11", default-features = false, features = ["smtp-transport", "tokio1-rustls-tls", "rustls-platform-verifier", "builder", "tokio1"] }`. Pulls in TLS support; no native-tls dep.
- [crates/proxy/src/notifier/handle.rs](../../crates/proxy/src/notifier/handle.rs) — `EmailHandle = Handle<EmailNotifier>` joins `NotifierHandle` (webhook) and `SlackHandle` in the `Notifiers` bundle.
- [crates/proxy/src/blocked.rs](../../crates/proxy/src/blocked.rs) — `persist_and_notify` fans out to **all three** drivers in parallel (`tokio::spawn` per driver). The owned-notification snapshot is cloned per branch.
- [crates/proxy/src/server.rs](../../crates/proxy/src/server.rs) — `build_notifiers` consults `notifier_config` for the `email` row at startup. Config shape: `{ smtp_url: "smtps://user:pass@host:465", from: "RFC 5322 mailbox", to: <string|array> }`. No env fallback — SMTP credentials live in DB only.
- [crates/proxy/src/api/notifier.rs](../../crates/proxy/src/api/notifier.rs) — `POST /api/v1/notifier/config { driver: "email", config: { smtp_url, from, to } }` validates + builds + persists + hot-swaps. `to` accepts either a single string or an array of strings. `GET` redacts `smtp_url` (since the URL may contain `user:pass`) to `smtp_url_redacted = scheme://host/...`; `from` and `to` echo plaintext.
- [crates/cli/src/main.rs](../../crates/cli/src/main.rs) — `proxilion-cli notifier set-email --smtp-url <u> --from <addr> --to <addr1> [--to <addr2>] [--disabled]`.
- Metrics: `proxilion_email_send_total{result,layer}`, `proxilion_email_send_failures_total{reason="token_issue|build|smtp"}`, `proxilion_notifier_config_changes_total{driver="email"}`.

**Unit tests** (4 new in `notifier::email::tests`): HTML-escape sanitization, invalid `smtp_url` rejection, empty `to` rejection, malformed `from` rejection. `cargo test --workspace` is green at **123 proxy tests** (was 119).

**End-to-end verification (2026-05-11)** via [scripts/stress-email-driver.sh](../../scripts/stress-email-driver.sh) — 13 assertions, all passing, exercised against a live `axllent/mailpit:v1.27` SMTP-test container inside the compose network:
- `proxilion-cli notifier set-email` persists + hot-swaps.
- `/api/v1/notifier/show` reports `email: configured: true`.
- `/api/v1/notifier/config` redacts `smtp_url` (echoes `smtp_url_redacted`), preserves `from` + `to`.
- Bad SMTP URL → 400. Missing `to` → 400. Empty `to` array → 400. Malformed `from` → 400.
- DB row survives env-less proxy restart; email notifier is rebuilt at boot from `notifier_config`.
- `--disabled` hot-swaps the notifier to None; `/show` flips to `email: configured: false`.
- Metric increments per config change.

**Spec deviations to flag.**

1. **No DKIM signing on the proxy side.** §5.4 calls out DMARC / SPF / DKIM alignment "via the customer's SMTP relay." We accept whatever relay the customer configures; if the relay handles DKIM (most do, e.g. SES, SendGrid, Mailgun, Postmark), alignment works. The proxy itself doesn't sign — it's a customer-relay concern.
2. **`mailto:` reject link not generated.** §5.4 sketches a `mailto:` rejection link that pre-fills the reason text and lets the approver hit Send. We use the same HTTP signed-URL flow as the approve path (both go through `/notifier/approve` with `action=reject`). The signed-URL approach is friendlier on mobile mail clients that show preview cards for HTTP URLs but not for `mailto:`.
3. **Single global `to` recipient list.** Spec implies per-policy routing (different recipients for different policies). v1 sends to the same list for every blocked action. A `body.audit_body_routing` extension to the policy YAML would route per-policy in v2.
4. ~~No bcc / cc.~~ **Resolved 2026-05-12.** [crates/proxy/src/notifier/email.rs::EmailNotifier::new_with_recipients](../../crates/proxy/src/notifier/email.rs) accepts optional `cc: &[String]` and `bcc: &[String]` slices alongside `to`. The same single-string-or-array shape that `to` accepts on the `POST /api/v1/notifier/config { driver: "email" }` payload (and on the DB row) now applies to `cc` and `bcc` — each independently optional, each independently validated against the lettre `Mailbox` parser. The `GET /api/v1/notifier/config` view echoes both. `EmailNotifier::new` remains as a back-compat alias (empty cc / bcc) so existing call sites are untouched. No metric churn — the existing `proxilion_email_send_total` covers all three recipient types under the same row.
5. ~~No retry on transient SMTP failures.~~ **Resolved 2026-05-12.** [crates/proxy/src/notifier/email.rs](../../crates/proxy/src/notifier/email.rs) now wraps `transport.send(...)` in a retry loop: lettre's `Error::is_permanent` short-circuits permanent failures (auth refused, bad recipient, 5xx) — no point burning the retry budget on those. Transient failures (timeout, 4xx, network blip) retry up to `max_retries = 3` (matches the webhook + SIEM forwarder budgets) with `250ms × 4ⁿ` exponential backoff capped at 10s. New metric reasons: `proxilion_email_send_failures_total{reason="smtp_permanent|smtp_transient_exhausted"}` (replaces the prior single `reason="smtp"`). `with_max_retries(0)` is exposed for tests that need to keep the loop fast.


endpoints + landing page are live. Delivered:

- [migrations/0007_notifier_tokens.sql](../../migrations/0007_notifier_tokens.sql) — `notifier_tokens(token_id, blocked_id, action CHECK approve|reject, approver_hint, issued_by, expires_at, consumed_at)` with a partial index on unconsumed tokens for cheap lookup.
- [crates/proxy/src/api/blocked.rs](../../crates/proxy/src/api/blocked.rs) — `POST /api/v1/blocked/{id}/issue-link` (scope `blocks:approve`) accepts `{ action, ttl_minutes?, approver_hint? }`, validates `action ∈ {approve, reject}` + `ttl_minutes ∈ 1..=1440`, checks the row is still `pending`, inserts the token row, and returns `{ token_id, url: "/notifier/approve?t=<uuid>", action, expires_at }`. The `approve_inner` + `reject_inner` were refactored from the operator-facing handlers into reusable inner functions that take a `channel` label.
- [crates/proxy/src/api/notifier_public.rs](../../crates/proxy/src/api/notifier_public.rs) — `GET /notifier/approve?t=<uuid>` renders a single HTML page with a confirm form; `POST /notifier/approve` (urlencoded body `t=<uuid> & justification=... | reason=...`) calls `approve_inner`/`reject_inner` with `channel="email"` and marks the token consumed inside the same transaction that locked it `FOR UPDATE`. Replay-safe by construction: a second click on the same link sees `consumed_at IS NOT NULL` and renders the "already used" page.
- [crates/proxy/static-html/approve.html](../../crates/proxy/static-html/approve.html) — single-file template, no JS framework, embeds via `include_str!`. Light/dark color scheme via `prefers-color-scheme`. ~80 lines of HTML + CSS. **All user-supplied fields are HTML-escaped via `html_escape()`** before substitution — the `<script>alert(1)</script>` payload in the `detail` column is rendered as `&lt;script&gt;`.
- [crates/proxy/src/server.rs](../../crates/proxy/src/server.rs) — `notifier_public::router(...)` is merged into the app **outside** the operator-auth boundary. The single-use token IS the credential.
- Metrics: `proxilion_overrides_requested_total{channel="email_link"}` ticks on every issued link; `proxilion_overrides_resolved_total{outcome="approved|rejected",channel="email"}` ticks on every consumed link.

**Unit tests** (2 new in `notifier_public::tests`): `html_escape_handles_payload_attacks` (XSS sanitization on `<` `>` `&` `"` `'`) and `template_substitutions_fill_all_placeholders` (no unfilled `{{...}}` placeholders, real fields propagate).

**End-to-end verification (2026-05-11)** via [scripts/stress-signed-link-approve.sh](../../scripts/stress-signed-link-approve.sh) — 14 assertions, all passing:
- Real `PCA_0` minted via mock-okta → Trust Plane, seeded into `pca_cache` + a pending `blocked_actions` row.
- `POST /api/v1/blocked/{id}/issue-link {"action":"approve"}` returns `{token_id, url, action, expires_at}`.
- `GET /notifier/approve?t=...` renders without an operator token, carries `p_0`, escapes the `<script>` payload in the `detail` field.
- `POST` with short justification → validation error, token still unconsumed.
- `POST` with valid justification → success banner with the freshly-minted override PCA id + hop; blocked row flips to `overridden` with `approver_subject = "on-call@acme.com"` (taken from the link's `approver_hint`).
- Re-clicking the consumed link → "already used."
- Reject path: same shape, blocked row → `rejected`.
- Negative paths: invalid `action` → 400; resolved row → 409; expired token surfaced in HTML; unknown UUID → friendly error page.

**Spec deviations to flag.**

1. **No outbound email composer.** §5.4 promises Plain-text + HTML mail bodies, DMARC/SPF/DKIM alignment, signed mailto reject links. We ship the *chokepoint* (signed URL + landing page); the email body composition + SMTP delivery is the next layer. The notifier driver model (Slack / Email / Webhook trait) lives in §10.3 as a separate deferred item.
2. **Single signed URL — not HMAC-signed query string.** §5.4 specifies a URL with an HMAC token. We use a UUID-keyed `notifier_tokens` row (essentially a single-use bearer in DB rather than a self-contained signed JWT). Both shapes are equivalent for one-time-use links; the DB-keyed shape is replay-resistant by construction (single-use enforced by `consumed_at` UPDATE inside the locking transaction) and doesn't require key rotation. A future iteration can layer HMAC-signed URLs on top for stateless verification if a customer's email infrastructure needs that.
3. ~~Metric `_total` counters coalesce to 1.~~ **Resolved 2026-05-11.** Root-caused to a `get_or_create_counter` non-idempotency bug in `metrics-util 0.19.1` (used by `metrics-exporter-prometheus 0.16.2`): each `metrics::counter!("name")` call site was inserting a *fresh* `Arc<AtomicU64>` into the registry's sharded hashmap, so increments split across N counters with the LAST-inserted one rendered. Confirmed via a minimal repro that printed Arc addresses — two `registry.get_or_create_counter(&same_key, |c| c.clone())` calls returned different Arc pointers. Bumping `metrics-exporter-prometheus = "0.17"` (pulls `metrics-util 0.20.3`) makes `get_or_create_counter` idempotent and counters accumulate correctly. Live verification: 5 unauth probes → `proxilion_auth_attempts_total{result="rejected"} 5`; signed-link stress's `proxilion_overrides_requested_total{channel="email_link"} = 3` after 3 issue-link calls.

### 5.5 Generic webhook (for everyone else)

For PagerDuty / Opsgenie / Teams / Jira / custom:

- Outbound: `POST <webhook_url>` with the blocked-action JSON envelope
  and an `X-Proxilion-Signature` HMAC. Customer's webhook handler does
  whatever (creates a Jira ticket, fires PagerDuty incident, posts to
  Teams) and eventually returns its own approve/reject via:
- Inbound: `POST /api/v1/blocked/:id/{approve,reject}` with the same
  HMAC signature scheme. This is just `proxilion-cli blocked approve`
  over the wire.

This makes Proxilion notifier-agnostic without writing a Teams plugin and
a Jira plugin and an Opsgenie plugin.

**Status (2026-05-11) — outbound webhook driver shipped.** Delivered:

- [crates/proxy/src/notifier/mod.rs](../../crates/proxy/src/notifier/mod.rs) — `BlockedNotification` envelope (`schema: "proxilion.blocked_action.v1"`, `blocked_id`, `p_0`, `vendor`, `action`, `method`, `path`, `layer`, `policy_id`, `detail`, `predecessor_pca_id`, `requested_ops`, plus `approve_url` and `reject_url` for one-click operator landing).
- [crates/proxy/src/notifier/webhook.rs](../../crates/proxy/src/notifier/webhook.rs) — `WebhookNotifier` POSTs JSON with `x-proxilion-signature: sha256=<hmac>`, `x-proxilion-schema: proxilion.blocked_action.v1`, `x-proxilion-blocked-id: <uuid>`. Retry policy mirrors the SIEM forwarder (no retry on 4xx; exp-backoff on 5xx/transport up to 3 attempts).
- [crates/proxy/src/blocked.rs](../../crates/proxy/src/blocked.rs) — `persist_and_notify(db, notifier, record)` is the new adapter call. Persistence runs first (synchronous, durable); the webhook is spawned on tokio so a slow receiver never slows the request response. The three Google adapters (Drive / Gmail / Calendar) all switched to this signature.
- Config: `PROXILION_BLOCKED_WEBHOOK_URL` + `PROXILION_BLOCKED_WEBHOOK_HMAC_KEY`. Empty URL → notifier disabled. URL set without key → refuse-to-sign-without-a-key (warn + disable). Invalid hex / too-short key → same.
- Metrics: `proxilion_notifier_send_total{result,layer}` and `proxilion_notifier_send_failures_total{reason="serialize|client_error|server_error_exhausted|transport_exhausted"}`.

**Unit tests** (`notifier::webhook::tests`, 5 new): HMAC round-trip, hex-validation rejection paths, wiremock'd POST asserting signature + schema + blocked-id headers and body content, no-retry-on-4xx, retry-on-5xx-then-success. `cargo test --workspace` is green at **74 passing**.

**End-to-end verification (2026-05-11)** via [scripts/stress-notifier.sh](../../scripts/stress-notifier.sh) against the live compose stack:
- Proxy log confirms `blocked-action webhook notifier installed url=http://…`.
- Negative paths: empty `PROXILION_BLOCKED_WEBHOOK_HMAC_KEY` → warn + run without the notifier (refuse to sign with no key). Too-short hex (`dead`) → warn + run without. Both verified in CI-friendly assertions.
- Restore path: setting both env vars again brings the notifier back to nominal state.
- Live POST to a `mendhak/http-https-echo` receiver inside the compose network is unit-tested via wiremock; full adapter→notifier→receiver round-trip requires a seeded signed-PCA in cache (CI harness gap shared with §1.1 / §1.3).

**Spec deviations to flag.**

1. **Driver model elided.** §10.3 sketches a `Notifier` trait with `slack` / `email` / `webhook` implementations and a `Vec<Box<dyn Notifier>>` fan-out. We ship one driver (`WebhookNotifier`) and one optional field (`AdapterState.notifier: Option<Arc<WebhookNotifier>>`). Slack interactive Block Kit + email signed-URL landing are bigger pieces and intentionally deferred to a follow-up that adds the trait, the burst-suppression layer (§5.6), and the per-policy channel routing.
2. **No inbound Slack interaction webhook.** §8.3 lists `POST /api/v1/notifier/slack/interact` and `GET /api/v1/notifier/approve` as new endpoints. Outbound notifications work today via the customer's webhook handler calling `POST /api/v1/blocked/{id}/approve` directly (the same endpoint the CLI hits). Adding signed approve/reject URLs that bypass the operator-token requirement lands with the email/HTML-landing-page work.
3. **No burst suppression yet.** §5.6 promises that 50 blocks/minute in the same `(policy_id, p_0)` collapse to one threaded message. The current implementation fires one webhook per block. Tracked alongside the Slack driver.

### 5.6 Block-burst suppression

If 50 blocks fire in a minute from the same `(policy_id, p_0)`, Slack
gets one message with a counter, not 50 messages — "57 more blocks of
this kind suppressed; click for the full list." Threshold and window
configurable per-policy. This is the difference between "approval flow
helps" and "approval flow has been muted by the team."

**Status (2026-05-11) — shipped.** Delivered:

- [crates/proxy/src/notifier/burst.rs](../../crates/proxy/src/notifier/burst.rs) — `BurstSuppressor` keyed by `(policy_id, p_0)`. Each bucket holds a sliding window of recent timestamps; once the window count hits `threshold`, subsequent events are dropped and a per-bucket `suppressed` counter accrues with an `exemplar` snapshot of the first dropped event. Defaults: `threshold=50`, `window=60s`, `flush_interval=30s`. Events with no `policy_id` (Layer-A invariant breaks, read-filter blocks) bypass the suppressor — they're rare enough that collapsing distinct attack signals would lose information.
- [crates/proxy/src/notifier/webhook.rs](../../crates/proxy/src/notifier/webhook.rs) — `WebhookNotifier::with_burst(...)` attaches the suppressor; `notify(...)` consults it before each POST. New `notify_summary(...)` method delivers `BurstSummary` envelopes on a separate schema (`proxilion.blocked_action_burst.v1`) so receivers can route differently.
- [crates/proxy/src/server.rs](../../crates/proxy/src/server.rs) — `build_blocked_notifier` now attaches the suppressor by default and spawns a flush loop that drains every 30s. Startup log line confirms `with burst suppression`.
- Metrics: `proxilion_notifier_suppressed_total{policy_id}` (counter, increments per dropped event); `proxilion_notifier_summary_sent_total{policy_id}` (counter, increments per delivered summary).

**Unit tests** (6 new in `notifier::burst::tests`): passes-through below threshold, suppresses above threshold + drain returns the right summary, separate `(policy_id, p_0)` keys stay independent, window expiry resets the bucket, missing `policy_id` bypasses, summary carries exemplar.

**End-to-end verification (2026-05-11)** via [scripts/stress-burst-and-notifier-cli.sh](../../scripts/stress-burst-and-notifier-cli.sh) — 13 assertions, all passing:
- `notifier show` reports `not-configured` when env-less, then `configured` with default burst block (threshold=50 / window=60s / flush=30s) after restart with `PROXILION_BLOCKED_WEBHOOK_URL` set.
- `notifier test` POSTs a synthetic envelope to the receiver — receiver echoes `"action": "notifier.test"` with `policy_id == "proxilion.test"`.
- 60 synthetic notifications on the same bucket → receiver sees exactly 50 raw events; `proxilion_notifier_suppressed_total` ticks.
- After 18s the burst-summary envelope arrives. The body contains `"schema": "proxilion.blocked_action_burst.v1"`, `"suppressed_count": 11`, and a full `exemplar` block with vendor/action/layer.
- `proxilion_notifier_summary_sent_total` ticks once per delivered summary.

**Spec deviations to flag.**

1. ~~Per-policy threshold/window not yet honored.~~ **Resolved 2026-05-11.** `PolicyDoc` now carries an optional `notifier_burst: { threshold, window_seconds }` block (`crates/policy-engine/src/yaml.rs`). `Engine::burst_override_for(policy_id)` returns the override pair; the proxy wires a resolver closure into `BurstSuppressor::with_resolver(...)` that consults the live policy engine on every `admit()` call, so a `policy.yaml` hot-reload immediately changes threshold/window for in-flight buckets. Both fields are individually optional — `threshold: 5` alone keeps the default window, `window_seconds: 10` alone keeps the default threshold. Policies without a `notifier_burst:` block fall through to `BurstConfig::default()` (threshold=50, window=60s). Verified by 4 policy-engine tests + 2 burst-suppressor resolver tests + live stress.
2. ~~No "click for the full list" deep link.~~ **Resolved 2026-05-12.** [crates/proxy/src/notifier/burst.rs::BurstSummary::with_details_url](../../crates/proxy/src/notifier/burst.rs) populates a percent-encoded `<proxy_public_url>/api/v1/blocked?policy_id=<id>[&p_0=<email>]` link on every flushed summary. The Slack driver's summary message renders this as an "Open full list" button; the webhook driver carries the field on the JSON envelope (schema `proxilion.blocked_action_burst.v1`). `with_details_url("")` is a no-op so test fixtures and the env-less burst path stay clean. Three new unit tests cover the URL shape (round-trip, empty-base no-op, p_0-omitted-when-absent).
3. **Suppression state is in-process.** A proxy restart wipes the buckets. For a multi-replica deployment, suppression is per-pod — bursts get collapsed at each pod rather than across the fleet. Spec.md §13's design partner won't notice; a Redis-backed shared suppressor is the v2 path if we add multi-region.

### 5.7 Expiry & escalation

- Default TTL 30 min, configurable per-policy.
- 5 min before expiry, post an `@here` reminder into the thread.
- On expiry, the block is finalized as `rejected (expired)`; the agent
  has long since received its 403 / 202 timeout response, so this is just
  bookkeeping for the audit log.
- Optional escalation: if no decision in 10 min, send to a backup channel
  / user. Configurable per-policy.

**Status (2026-05-12) — proactive expiry sweeper shipped; reminders + escalation deferred.**

- [crates/proxy/src/blocked_expiry.rs](../../crates/proxy/src/blocked_expiry.rs) — new module with `sweep_once(&PgPool)` (single SQL `UPDATE blocked_actions SET status='expired', resolved_at=now() WHERE status='pending' AND expires_at < now() RETURNING …`) and `spawn(db, interval)` background task. Default tick interval 60s. Each expired row gets a structured `tracing::info!` line plus a `proxilion_blocked_expired_total{policy_id}` increment AND a `proxilion_overrides_resolved_total{outcome="expired",channel="sweeper"}` increment — so a single PromQL `sum by(outcome) (rate(proxilion_overrides_resolved_total[5m]))` covers the approve / reject / expired triumvirate without joining tables.
- Per-tick the sweeper also runs `SELECT count(*) FROM blocked_actions WHERE status='pending'` and sets the `proxilion_overrides_pending` gauge. That's the gauge the new Grafana dashboard's "annoyance" quadrant pulls — keeps Grafana off the DB entirely.
- Spawned in [crates/proxy/src/server.rs](../../crates/proxy/src/server.rs) alongside the policy watcher.
- Existing lazy expiry at `GET /api/v1/blocked` (in [api/blocked.rs](../../crates/proxy/src/api/blocked.rs)) is retained as a belt-and-suspenders for the moment between sweeper ticks.

**Deviations.**

1. **No 5-min `@here` reminder.** The reminder requires either (a) the original Slack `message_ts` so a thread reply makes sense, or (b) a separate "reminder" Block Kit shape. Both add the same complexity as the §5.3 dev 5 thread-folding work — when that ships, the reminder slots into the same path. The expiry sweep itself, which is the load-bearing bookkeeping piece, ships today.
2. **No 10-min escalation to a backup channel.** Per-policy escalation lives one schema column away (`blocked_actions.escalation_at`) but the customer-facing semantics — "which channel is the backup?" — depend on the per-policy notifier routing (§5.4 dev 3) we haven't yet shipped. Folding both in a single follow-up will be cleaner than landing them out of order.
3. **No `notifier` fan-out on expiry.** Spec text implies a notification when the row flips to expired. We deliberately don't: the agent has already received its timeout response, the operator's blocked-action message is timestamped enough to explain what happened, and a "the thing you didn't decide on has timed out" message is exactly the kind of channel-noise the burst suppressor exists to prevent. The structured log + metric increment is enough; if a customer wants an outbound expiry notification, the SIEM forwarder (§7) reads `action_events` and surfaces this without notifier involvement.

---

## 6. The audit log as the data product

The audit log is the customer's data. Proxilion's job is to expose it in
formats their tools can ingest.

### 6.1 Surfaces

- **HTTP, JSON**: `GET /api/v1/actions` (already in spec). Paginated
  envelope, all the filters from §1.6.
- **HTTP, NDJSON streaming**: `GET /api/v1/actions/stream` (already in
  spec). One event per line. SSE `event: action` framing.
- **HTTP, NDJSON bulk export**: `GET /api/v1/actions/export?format=ndjson&since=...&until=...`.
  Returns a streaming response (chunked), one JSON document per line, no
  pagination cursor. The proxy streams directly from a postgres cursor;
  memory is O(1) regardless of result size.
- **HTTP, CSV export**: `?format=csv`. First line is the column header,
  documented + stable.
- **HTTP, JSON Lines (gzip / zstd)**: `Accept-Encoding: gzip` / `zstd`
  honored on the export endpoint.
- **SIEM forwarder** (`spec.md` §3.3): proxy-initiated push to a customer
  webhook for every persisted action_event. Same payload as NDJSON.

### 6.2 Schema stability

The action_event JSON shape is a versioned contract:
`{"schema": "proxilion.action_event.v1", ...}`. Field additions are
non-breaking (consumers must ignore unknown fields). Field removals or
type changes bump to `v2` and `v1` continues to be emitted for one minor
release minimum. Documented in `docs/audit/schema-v1.md`.

### 6.3 Retention

Proxilion does **not** manage retention. The proxy keeps `action_events`
indefinitely by default; a cron-friendly `proxilion-cli actions purge
--older-than 90d` exists for customers who don't tier to a SIEM. Most
customers tier — the SIEM is the long-term system of record, the proxy is
the queryable working set.

### 6.4 Privacy / minimization

Request and response bodies are **not** persisted by default. Only their
hashes go into `action_events`. The full body is held in the
`quarantined_payloads` table only when the read-filter quarantined it
(i.e., the customer specifically asked us to). This is a privacy default,
not a feature — opt-in to fuller body persistence is per-policy:
`then.audit_body: hash | redact_pii | full`.

**Status (2026-05-11) — shipped.** Delivered:

- [migrations/0009_action_event_bodies.sql](../../migrations/0009_action_event_bodies.sql) — `action_event_bodies (request_id PK, mode CHECK in (hash, redact_pii, full), request_hash, response_hash, request_body_b64, response_body_b64, request_bytes, response_bytes, created_at)`. Joined by `request_id` (not the `action_events.id` UUID) so the adapter can insert without awaiting the action_events row's generated id; intentionally NO foreign key so deletes from `action_events` don't cascade — body retention has its own lifecycle (customers will tier audit-body rows to cold storage on a different cadence than the action_events row count).
- [crates/policy-engine/src/yaml.rs](../../crates/policy-engine/src/yaml.rs) — `PolicyDoc.audit_body: Option<AuditBodyMode>` with `Hash | RedactPii | Full` variants (kebab/snake-case YAML). `Outcome.audit_body` surfaces the directive to the adapter.
- [crates/proxy/src/audit_body.rs](../../crates/proxy/src/audit_body.rs) — `persist(db, request_id, mode, request, response)` writes the row. `redact_pii_bytes()` runs the regex set; binary content (first 256 bytes contain a null) is left intact since pattern-matching binary data is noisy. Redactor patterns: email, US SSN, US phone (10-digit + parens / dots / dashes), credit-card-shaped 13–19-digit runs (no Luhn check — false positives acceptable for redaction; false negatives are not), `Bearer <token>`, `pxl_live_*` / `pxl_operator_*` / `sk-*` / `ghp_*` / `xox?-*` API-key shapes. Order matters: known-token shapes redact BEFORE the digit-pattern redactors so a Slack token's leading 10-digit workspace id isn't pre-redacted by the phone regex (regression caught + fixed during the build-out).
- Adapter call sites (Drive / Gmail / Calendar): `if let Some(mode) = outcome.audit_body { crate::audit_body::persist(..., request_id, mode, req_bytes, &final_body).await; }`. Skipped entirely when the policy doesn't opt in — the privacy default is unchanged.
- [crates/proxy/src/api/actions.rs](../../crates/proxy/src/api/actions.rs) — `GET /api/v1/actions/{id}` now includes an `audit_body: { mode, request_hash, response_hash, request_body_b64, response_body_b64, request_bytes, response_bytes }` field when a row exists in `action_event_bodies` for the request_id. Null when the policy didn't opt in.
- Metrics: `proxilion_audit_body_persisted_total{mode}` and `proxilion_audit_body_persist_failures_total{mode}`. Both cardinality-bounded by the enum.

**Unit tests** (9 new in `audit_body::tests`): email / SSN / phone (four format variations) / credit-card-shaped / `Bearer <token>` / API-key shapes (4 patterns) / binary input unchanged / text input redacted / SHA-256 hex matches the known vector for "hello".

**End-to-end verification (2026-05-11)** via [scripts/stress-audit-body.sh](../../scripts/stress-audit-body.sh) — 10 assertions, all passing:
- Schema + CHECK constraint enforced (`mode='leak_all'` rejected by Postgres).
- Three rows (one per mode) round-trip through INSERT + SELECT.
- Hot reload picks up `audit_body: full` and `audit_body: redact_pii` policies.
- `GET /api/v1/actions/{id}` surfaces the audit_body object with correct mode + body_b64 + hash; returns `audit_body: null` when no row exists.
- Decoupled lifecycle: deleting an `action_events` row leaves the `action_event_bodies` row intact (no FK, no cascade).

**Spec deviations to flag.**

1. **Adapter call sites pre-Layer-B and post-Layer-A.** The body capture fires AFTER the upstream call completes and ONLY when a policy matched (no policy → skipped). Layer-A blocks (PIC invariant violations) never reach the publish path, so they never get an audit_body row even on a policy with `audit_body: full`. This is the right shape: a request that was refused at the chain layer didn't produce a meaningful body to capture, only the predecessor PCA + the refused-ops-set, both already stored in `pca_cache` + `blocked_actions`.
2. **No streaming-body support.** Bodies are buffered up to `MAX_BODY` (10 MB) before capture. Streaming-body redaction is in scope for §15 #6 in `spec.md`, not this PR.
3. **PII redactor is regex-only.** No NER, no PII detection model, no per-customer pattern override. The customer can disable redact_pii and use `full` + their own downstream redactor if their threat model demands one. Pattern catalogue lives in `audit_body.rs::redactors()` — adding a new shape is a one-line PR.
4. **`hash` mode persists SHA-256 only.** Spec sketch hints at storing per-field hashes (e.g. hash of subject, hash of body). We store request-body and response-body hashes, not field-level. Sufficient for tamper-detection + audit; field-level would be a follow-up if a customer needs to grep audits by `subject_hash`.

---

## 7. SIEM integration — pull, not push

We do not "alert SIEM." We expose the data so the SIEM can pull it the
way the customer's SIEM pulls things:

- **Splunk**: an HTTP Event Collector forwarder, configured via the
  generic webhook (§5.5). Or `splunk forward` consuming `proxilion-cli
  actions tail`.
- **Elastic**: a Logstash / Beats pipeline against
  `/api/v1/actions/export` polled on an interval.
- **Snowflake / BigQuery**: a scheduled
  `proxilion-cli actions export --since 1h --format ndjson` dropped on
  S3 / GCS, ingested by their existing data pipeline.
- **Datadog Logs**: their built-in HTTP poller against `/api/v1/actions`.

The customer's data team writes whichever they prefer. Proxilion ships
example configs in `ops/siem/` for the top four (Splunk, Elastic,
Datadog, Snowflake).

---

## 8. What we delete vs. keep from the existing spec

### 8.1 Deleted

- **`spec.md` §0.5 — Dashboard scaffold (Next.js 15).** The scaffold is
  not built; remove the step. Replace with new §0.5: "Metrics + CLI +
  notifier crates scaffolded" (see §10 below for the new milestone shape).
- **`spec.md` §1.6 — Dashboard live action feed + PCA chain inspector.**
  The *proxy-side* endpoints (`/actions`, `/actions/stream`,
  `/actions/:id`, `/sessions/:id/chain`) shipped — they stay. The
  dashboard React work is dropped. §1.6 becomes "CLI consumes
  /actions/stream + /actions; ships pretty + ndjson tail."
- **`spec.md` §2.3 — Block-queue + justified-override dashboard UI.**
  The proxy-side `/api/v1/blocked` endpoints + override PCA branch logic
  stay. The React `dashboard/app/blocked/page.tsx` is replaced by the
  Slack/email/webhook flow described in §5 here.
- **`spec.md` §4.3 — Static marketing site.** Unchanged — that's
  proxilion.com, not the product UI. (Already shipped in `site/`.)

### 8.2 Kept verbatim

- The PIC chain math, OAuth interception, read-filter, policy engine,
  Trust Plane integration, federation, killswitch design — *every*
  protocol-level piece of `spec.md` is unchanged.
- The HTTP API surface (`/api/v1/*`) is unchanged and grows by exactly
  the endpoints below.

### 8.3 New endpoints (proxy)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/metrics` | Prometheus exposition |
| `GET` | `/api/v1/actions/export` | NDJSON / CSV streaming bulk export |
| `POST` | `/api/v1/blocked/:id/approve` | Approve (Slack / email / CLI / webhook all funnel here) |
| `POST` | `/api/v1/blocked/:id/reject` | Reject |
| `POST` | `/api/v1/notifier/slack/interact` | Slack interaction webhook (signed-body verified) |
| `GET`  | `/api/v1/notifier/approve` | Email signed-URL landing page (HTML) |
| `POST` | `/api/v1/notifier/test` | Send a synthetic test notification to verify wiring |
| `GET`  | `/api/v1/policy` | List policies + modes (drives `proxilion-cli policy list`) |
| `POST` | `/api/v1/policy/reload` | Force hot-reload |
| `POST` | `/api/v1/policy/:id/mode` | Flip a single policy's mode |
| `POST` | `/api/v1/policy/simulate` | Replay history against a candidate YAML |
| `POST` | `/api/v1/killswitch/:scope/:id` | Killswitch (already in spec §3.2; re-listed) |

### 8.4 New tables (postgres)

**Status (2026-05-11) — `notifier_config` shipped (webhook driver).** Delivered:

- [migrations/0010_notifier_config.sql](../../migrations/0010_notifier_config.sql) — `notifier_config (id PK CHECK in (webhook,slack,email), enabled, config JSONB, updated_at, updated_by)`. v1 ships only the `webhook` driver row; `slack` / `email` rows are reserved for §5.3 / §5.4.
- [crates/proxy/src/notifier/handle.rs](../../crates/proxy/src/notifier/handle.rs) — `NotifierHandle` wraps `Arc<ArcSwap<Option<Arc<WebhookNotifier>>>>`. All consumers (adapters via `AdapterState.notifier`, public approve flow via `NotifierApiState.notifier`, blocked-action notify via `persist_and_notify`) call `current()` per use; `replace()` atomically hot-swaps.
- [crates/proxy/src/api/notifier.rs](../../crates/proxy/src/api/notifier.rs) — `GET /api/v1/notifier/config` (scope `notifier:read`) reads the row + redacts `hmac_key` (echoes `hmac_key_set: bool` instead) and the URL (`url_redacted`). `POST /api/v1/notifier/config` (scope `notifier:write`) validates `{ driver: "webhook", config: { url, hmac_key } }`, builds a new `WebhookNotifier`, persists to DB, then calls `NotifierHandle::replace(...)`. Returns 400 on missing url / missing hmac / invalid hex / unknown driver.
- [crates/proxy/src/server.rs](../../crates/proxy/src/server.rs) — startup calls `build_notifier_handle(&cfg, &core.db, ...)`. The handle's initial value is resolved by `resolve_webhook_config`: DB row wins (when `enabled=true` AND both `url` + `hmac_key` are present); env vars are the fallback for the no-DB bootstrap path.
- [crates/cli/src/main.rs](../../crates/cli/src/main.rs) — `proxilion-cli notifier set-webhook --url <u> --hmac-hex <h> [--disabled]` POSTs to `/api/v1/notifier/config`. `proxilion-cli notifier config` GETs the redacted view.
- Metric: `proxilion_notifier_config_changes_total{driver}` per successful set.

**Unit tests** (3 new in `notifier::handle::tests`): starts-none, replace swaps in new (clones see the same swap), replace-to-none clears.

**End-to-end verification (2026-05-11)** via [scripts/stress-notifier-config-hotswap.sh](../../scripts/stress-notifier-config-hotswap.sh) — 14 assertions, all passing:
- Schema + CHECK constraint enforced.
- `proxilion-cli notifier set-webhook` persists + hot-swaps without restart.
- After setting URL=A, `notifier test` POSTs to A. After setting URL=B, the next `notifier test` POSTs to B; receiver A's POST count is unchanged.
- `notifier config` GET redacts `hmac_key` (shows `hmac_key_set: true`) and the URL.
- `set-webhook --disabled` clears the active notifier; `notifier test` → 412.
- Four negative paths (unknown driver / missing url / missing hmac / short hmac) → 400.
- After full proxy restart with env vars cleared, the DB-stored row is loaded and the notifier is operational — confirms DB-first bootstrap.

**Spec deviations to flag.**

1. **Only the `webhook` driver is exposed today.** The migration's CHECK accepts `slack` and `email` for forward-compat, but `set_config` returns 400 for those drivers until §5.3 / §5.4 ship.
2. **Flush loop captures the initial notifier instance.** Burst-summary delivery uses the notifier that was alive when `spawn_flush_loop` started. A subsequent `replace()` swaps the live `notify` path; the next flush tick still drains accumulated buckets to the OLD notifier. For v1 this is the right shape — pending buckets get delivered one last time. A future improvement would route flushes through the handle on each tick.

```sql
-- 0010_notifier_config.sql (shipped)
CREATE TABLE notifier_config (
    id          TEXT PRIMARY KEY CHECK (id IN ('webhook','slack','email')),
    enabled     BOOLEAN NOT NULL DEFAULT true,
    config      JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT
);

CREATE TABLE notifier_tokens (
    token_id        UUID PRIMARY KEY,
    blocked_id      UUID NOT NULL REFERENCES blocked_actions(id) ON DELETE CASCADE,
    action          TEXT NOT NULL,            -- "approve" | "reject"
    approver_hint   TEXT,                     -- email or slack user id
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ
);

-- 0005_operator_tokens.sql
CREATE TABLE operator_tokens (
    id            UUID PRIMARY KEY,
    token_hash    BYTEA NOT NULL UNIQUE,       -- SHA-256 of pxl_operator_*
    name          TEXT NOT NULL,
    scopes        TEXT[] NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);

-- blocked_actions gets two new columns
ALTER TABLE blocked_actions
    ADD COLUMN slack_trigger_id TEXT,           -- idempotency key for Slack
    ADD COLUMN notification_channels TEXT[];    -- e.g. ["slack","email"]
```

---

## 9. New crate layout

```
crates/
  proxy/                   # unchanged, plus the new endpoints
  policy-engine/           # unchanged
  cli/                     # GROWN — was a stub; now the primary UI
    src/
      main.rs
      commands/
        actions.rs
        blocked.rs
        policy.rs
        pic.rs
        killswitch.rs
        notifier.rs
        clients.rs
        metrics.rs
        trust_plane.rs
      output.rs            # pretty / json / ndjson / csv writers
      http.rs              # thin axum-client wrapper
  shared-types/            # extended with notifier + cli DTOs
  metrics/                 # NEW — Prometheus exporter facade + OTLP
    src/
      lib.rs               # re-exports + registry
      labels.rs            # cardinality-bounded label types
  notifier/                # NEW — Slack / email / webhook drivers
    src/
      lib.rs
      slack.rs             # Block Kit message build, signed-request verify
      email.rs             # SMTP + signed-URL token issuance
      webhook.rs           # generic outbound + signed-request verify
      template.rs          # single-purpose approve.html (no JS framework)
      burst.rs             # de-dupe / batching
```

### 9.1 `metrics` crate

Wraps `prometheus-client` (Rust's modern crate, OpenMetrics-aware) and
`opentelemetry-otlp` behind a single `metrics::counter!(...)`,
`metrics::histogram!(...)` facade. Internally registers each series at
process start (cardinality bound checked at registration; runtime label
values that don't match the registered set are dropped with a warn-once
log, never silently allowed to blow up cardinality).

### 9.2 `notifier` crate

A driver model:

```rust
#[async_trait]
pub trait Notifier: Send + Sync {
    async fn notify_block(&self, block: &BlockedAction) -> Result<NotificationHandle>;
    async fn resolve(&self, handle: &NotificationHandle, outcome: Outcome) -> Result<()>;
    fn name(&self) -> &'static str;
}
```

Drivers: `SlackNotifier`, `EmailNotifier`, `WebhookNotifier`. The proxy
holds `Vec<Box<dyn Notifier>>` and fans out (configurable per policy).
Approval comes back through `POST /api/v1/blocked/:id/approve` regardless
of which driver delivered the notification — that handler is driver-agnostic.

---

## 10. Milestone re-shape

The pivot doesn't change the overall M0–M5 envelope; it changes what
"M1 done" and "M2 done" look like.

### 10.1 Replaces `spec.md` §13 (Milestones)

| Milestone | Weeks | Outcome (revised) |
|---|---|---|
| M0 — Foundation | 1 | Workspace, CI, dev compose stack with Trust Plane (unchanged). `cli` crate scaffolded with `status`, `selftest`, `version`. `metrics` crate scaffolded with `/metrics` endpoint exposing a hello-world counter. |
| M1 — Drive read path end-to-end | 3 | OAuth → bridge → Trust Plane → OAuth interception → Drive read → PCA chain audited. **`proxilion-cli actions tail / list / show / export` works end-to-end.** `/metrics` exposes adapter + PIC + policy counters. **No React dashboard.** |
| M2 — Gmail write gate + override | 2 | Block + Slack-mediated override loop closed; override creates attested PCA branch. **`proxilion-cli blocked list / approve / reject` works.** Email + generic-webhook drivers ship alongside Slack. |
| M3 — Killswitch + stream + invariant enforcement | 1 | Runtime-gate enforces; NATS stream; killswitch revokes session's PCA issuance right. SIEM forwarder ships. **`proxilion-cli killswitch` works.** |
| M4 — Calendar + harden | 1 | Helm chart, marketing site (already shipped), public repo, recorded demo (terminal + Slack, no browser). |
| M5 — First design partner | 9+ | One real org running Proxilion in front of Claude managed agents, Okta-federated. |

### 10.2 Detailed M1 redo (replaces `spec.md` §1.6)

**Step 1.6 (revised) — `proxilion-cli` actions surface + Prometheus
`/metrics`**

**Phase:** M1
**Goal:** Operator can search history, tail live actions, export bulk
audit, and read PIC chain inspector output entirely from a terminal.
Customer's Grafana scrapes `/metrics` and renders the bundled dashboard.
**Files:** `crates/cli/src/commands/actions.rs`,
`crates/cli/src/output.rs`, `crates/metrics/src/lib.rs`,
`crates/proxy/src/metrics.rs`, `crates/proxy/src/api/export.rs`,
`ops/grafana/proxilion.json`, `ops/datadog/monitors.tf`.
**Prerequisites:** Steps 1.1–1.5.

**Acceptance:**
- `proxilion-cli actions tail` streams live events with sub-second
  latency from proxy → terminal.
- `proxilion-cli actions list --since 24h --decision block --format ndjson`
  returns paginated NDJSON.
- `proxilion-cli actions export --since 30d --format ndjson --compress zst`
  produces a >100 MB streaming export with constant proxy-side memory.
- `proxilion-cli actions show <id>` renders the full PCA chain
  ASCII-art (root→leaf, hop / p_0 / ops diff / signature ✓-or-✗)
  equivalent to the dropped React inspector.
- `curl https://localhost:8443/metrics` returns Prometheus exposition
  format with all metrics from §3.2 populated.
- `ops/grafana/proxilion.json` imports cleanly into Grafana 10+ and
  renders the four panels of §3.4.

### 10.3 Detailed M2 redo (replaces `spec.md` §2.3 UI portion)

**Step 2.3 (revised) — Block notification + signed-URL approval +
attested PCA branch**

**Phase:** M2
**Goal:** When an action is blocked, an authorized approver receives a
Slack interactive message (or signed email link, or webhook), clicks
Approve, and the agent's blocked request resumes against an
attested override PCA branch.
**Files:** `crates/notifier/`, `crates/proxy/src/api/blocked.rs`
(handler logic; endpoints already in spec), `crates/proxy/src/pic_executor.rs`
(override PCA branch construction — unchanged from spec §2.3),
`crates/proxy/static-approval/approve.html` (the one server-rendered page).

**Acceptance:**
- Slack interactive message arrives within 5s of a Layer-B block.
- Clicking Approve in Slack creates an override PCA whose provenance
  links to BOTH the blocked PCA and the approver's `PCA_op_origin`.
- Email path: signed URL works on iOS Mail (tested), single-use,
  expires correctly.
- Webhook path: outbound signed POST + inbound signed POST round-trip
  works against a `httpbin`-style harness.
- `proxilion-cli blocked approve <id> --justification "..."` produces
  the identical override PCA as the Slack click would (the CLI is a
  thin wrapper over the same endpoint).
- Burst suppression: 50 blocks/min collapse to 1 thread with counter.

---

## 11. Open questions

1. **Editor preservation for `policy.yaml`.** YAML round-trip without
   trashing comments needs a CST-aware library. Options: vendor `yamlfmt`
   logic, depend on `serde_yaml::Value` + a separate comment-attachment
   pass, or shell out to `yq`. Decision: prototype in M0 with `yq`,
   replace if it shows up in profiles. Tracked.
2. **Slack workspace vs Slack app distribution.** Customers self-host
   Proxilion; do they each install a per-workspace Slack app, or do we
   ship a public Slack app they install once with workspace-scoped
   tokens? Latter is friendlier; depends on Slack's review process for a
   security app. Open.
3. **Email DMARC alignment.** Customers' SMTP relays vary wildly.
   Document the three known-good configurations (Postmark, SES, internal
   relay) in `docs/install/email.md` rather than try to be smart.
4. **Multi-tenant approver mapping.** §5.3 hand-waves "map Slack user ID
   to operator identity." For an org with hundreds of approvers, this
   needs SCIM or an IdP-group sync. Out of scope for v1; document.
5. **The one-HTML-page exception.** §5.4's mobile approve page is the
   single React-less HTML file Proxilion serves. We should be principled
   about not letting it grow into a SPA. Lint rule:
   `find crates/proxy/static-approval -name '*.js'` must be empty in CI.
6. **OTLP push vs scrape.** Default is `/metrics` scrape. Some customers
   (Datadog Agent, Grafana Cloud) prefer push. The exporter facade
   supports both; defaulting to scrape avoids egress firewall conversations.
7. **CLI vs API auth tokens — same or different?** Likely same scheme
   (`pxl_operator_*`), different scopes. Confirm in the M0 implementation.

---

## 12. The 30-second pitch, post-pivot

> Proxilion sits in the OAuth path between your hosted AI agents and
> your SaaS providers. Every action the agent takes is bound to a
> cryptographic chain rooted at the human user. The chain is verifiable
> forever. When the agent tries to do something outside that user's
> authority — read a finance doc, send an external email, share a file
> — Proxilion either blocks it or asks a human to approve. The human
> gets a Slack message; one click. The audit log is yours, in
> NDJSON, streamed to your SIEM. Metrics in Prometheus, drawn by your
> Grafana. The only thing we don't ship is another dashboard.

Three surfaces. No tab to babysit. Outcome as a service.
