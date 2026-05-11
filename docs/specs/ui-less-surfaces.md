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

  notifier                            Slack / email / webhook config
    test slack
    test email
    test webhook
    show
    set slack.bot_token <token>
    set slack.channel <#channel>
    set email.smtp.url smtp://... --from sec-ops@org.com
    set webhook.url https://... --hmac-secret <hex>

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

### 5.6 Block-burst suppression

If 50 blocks fire in a minute from the same `(policy_id, p_0)`, Slack
gets one message with a counter, not 50 messages — "57 more blocks of
this kind suppressed; click for the full list." Threshold and window
configurable per-policy. This is the difference between "approval flow
helps" and "approval flow has been muted by the team."

### 5.7 Expiry & escalation

- Default TTL 30 min, configurable per-policy.
- 5 min before expiry, post an `@here` reminder into the thread.
- On expiry, the block is finalized as `rejected (expired)`; the agent
  has long since received its 403 / 202 timeout response, so this is just
  bookkeeping for the audit log.
- Optional escalation: if no decision in 10 min, send to a backup channel
  / user. Configurable per-policy.

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

```sql
-- 0004_notifier.sql
CREATE TABLE notifier_config (
    id          TEXT PRIMARY KEY,             -- "slack", "email", "webhook"
    enabled     BOOLEAN NOT NULL DEFAULT false,
    config      JSONB NOT NULL,               -- per-driver structured config
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
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
