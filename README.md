# Proxilion

> Confused-deputy defense for managed AI agents.

Managed AI agents (Anthropic's hosted Claude, OpenAI's Workspace Agents,
Google's Vertex agents, plus the growing field of OSS Claude-likes) act on
behalf of your users. When they call your SaaS APIs (Google Drive, Gmail,
Calendar, Salesforce, …), the OAuth token doesn't carry *which user* the
agent is acting for. The agent can act beyond that user's authority, and
nothing in the stack stops it.

Proxilion is a **self-hosted, MIT-licensed** reverse proxy (and pre-flight
advisor, and audit ingester) that binds every action the agent takes to a
cryptographic `PCA` chain rooted at the *human user* the agent is acting for.
The Trust Plane refuses to issue authority the user doesn't have. Every
action is audit-logged in a way that's both human-legible and
cryptographically verifiable.

**Free. MIT. Self-hosted. No telemetry. No paid product. No SaaS path.**

## What Proxilion actually does

Cryptographic capability chains alone don't stop a managed agent from acting
on the wrong data. Proxilion is the deployable enforcement layer that turns
the math into something a security team can install. The pieces that are
original Proxilion work:

- **OAuth interception.** Proxilion sits in the OAuth flow between the agent
  platform and your SaaS providers, swaps in a Proxilion-issued bearer token,
  and stays in path for every subsequent request.
- **Read-filtering for prompt injection.** Response bodies from Drive, Gmail,
  and other upstreams are scanned for known injection patterns (delimiter
  confusion, hidden Unicode, base64-encoded directives, "ignore prior
  instructions") and stripped or quarantined before the agent reads them.
- **Write-gating with human-in-the-loop.** External email sends, mass deletes,
  external file shares are blocked unless a real human explicitly approves
  through Slack or email. Configurable per sender, per domain, per op. Every
  approval captures the reviewer's *justification* — a Slack Block Kit modal
  (`views.open`, when a bot token is set) or the email confirmation form — so
  the audit row records *why*, not just *who*. The email link lands on a form
  and consumes its single-use token on **POST**, not GET (prefetch-safe).
- **Real-time action stream + killswitch.** Every agent action streams to the
  `/admin` SSE tail and your SIEM the moment it happens. One `proxilion-cli`
  call (or `/admin` click) revokes every capability tied to that agent or user
  within one request cycle.
- **YAML policy engine.** A compiled match-expression engine for rules like
  "this agent can read engineering docs but never finance," with hot-reload.
- **SaaS adapters.** Google Drive, Gmail, and Calendar at launch, each one
  upstream-aware so policy can reason about specific files, recipients, and
  events. Pattern is open; add Salesforce, Jira, Notion in a few hundred LOC.
- **The thesis.** That the OAuth integration boundary is the single
  preventative chokepoint for governing managed agents you don't own, and
  that prevention-by-construction is still possible there.

## Architecture at a glance

Every agent request crosses Proxilion on the way to the SaaS provider. The
proxy resolves the session to a human principal, verifies the cryptographic
authority chain, evaluates policy, mints a *narrowed* successor capability,
forwards the call, then filters the response before the agent ever reads it.

```mermaid
flowchart LR
    A["Managed AI agent"] -->|"OAuth + API calls<br/>(Proxilion bearer)"| P{{"Proxilion proxy<br/>(in-path, your perimeter)"}}
    P -->|"1 · resolve session<br/>+ verify PCA chain"| TP[("Trust Plane<br/>CAT signing keys")]
    P -->|"2 · Layer B policy"| POL[["policy.yaml<br/>match-expr engine"]]
    P -->|"3 · mint narrowed PCA_2"| TP
    P -->|"4 · forward"| G[("Google Drive /<br/>Gmail / Calendar")]
    G -->|"response"| P
    P -->|"5 · read-filter<br/>quarantine injection"| A
    P -.->|"every action (signed)"| NATS["NATS JetStream"]
    NATS --> SIEM["SIEM / webhook forwarder"]
    NATS --> DASH["/admin chain inspector + SSE tail"]
```

**The two enforcement layers compose** — a request must clear *both*:

```mermaid
flowchart TB
    R["Agent request"] --> LA["Layer A — PIC ops grammar<br/>(enforced by construction)"]
    LA -->|"action NOT in PCA ops set"| BLK["Refused — non-expressible<br/>Trust Plane won't mint successor"]
    LA -->|"action in ops set"| LB["Layer B — content / context policy<br/>(YAML match-expression engine)"]
    LB -->|"allow"| FWD["Forward to SaaS<br/>then read-filter the response"]
    LB -->|"block / require_confirmation / rate_limit"| HITL["Human-in-the-loop<br/>Slack modal / email link"]
```

- **Layer A (PIC, by construction).** Defeats the confused deputy, cross-user
  access, privilege escalation, identity laundering, and forged chains —
  these are *non-expressible*, not merely detected. The Trust Plane refuses to
  issue authority the principal never held.
- **Layer B (Proxilion-original, in the hot path).** Of the operations PIC
  *allows*, decides which need read-filtering (prompt-injection quarantine),
  write-gating, confirmation, or an outright block, based on request/response
  **content**. Authored in YAML, evaluated at p99 < 1 ms.

**The PIC chain** is a monotonic capability ladder rooted at the human:

```
PCA_0   p_0 = alice@acme.com   ops = { drive:*, gmail:send:*, … }   hop 0   ← root, signed by CAT key
  └── PCA_1   p_0 = alice       ops ⊆ PCA_0.ops  (granted scope)     hop 1   ← narrowed at OAuth callback
        └── PCA_2   p_0 = alice  ops ⊆ PCA_1.ops (this request)      hop 2   ← per-request successor
```

Three invariants hold on every link, and verification walks the chain
leaf→root checking all three:

| Invariant | Rule | What it kills |
|---|---|---|
| **Provenance** | each link carries its predecessor's CAT signature | forged / spliced chains |
| **Identity** | `p_0` is copied from the predecessor, never re-derived | identity laundering via token exchange |
| **Continuity** | `child.ops ⊆ parent.ops`, `child.hop == parent.hop + 1` | privilege escalation across hops |

**The per-request hot path** — what happens on every SaaS call the agent makes
(this is the sequence the integration tests in [§Testing](#testing) pin
end-to-end):

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant P as Proxilion
    participant TP as Trust Plane
    participant G as Google SaaS
    A->>P: GET /google/drive/v3/files/{id}<br/>Authorization: Bearer pxl_live_…
    P->>P: resolve session from bearer (DB JOIN)<br/>+ in-process kill-cache check
    P->>P: Layer B — evaluate policy.yaml against the request
    alt blocked by a Layer-B policy
        P-->>A: 403 policy_blocked + a blocked_actions row → HITL queue
    else allowed
        P->>TP: Layer A — mint PCA_2 successor (ops narrowed to this action)
        alt ops not ⊆ parent (runtime-gate)
            TP-->>P: 422 invariant violation
            P-->>A: 403 pic_invariant_violation (+ pic_invariant blocked row)
        else issued
            TP-->>P: PCA_2 at hop+1
            P->>G: forward with the Proxilion-held Google token
            G-->>P: response body
            P->>P: read-filter (quarantine prompt-injection patterns)
            P-->>A: filtered response
        end
    end
    Note over P,G: every outcome is signed into the action stream → NATS → SIEM
```

## Credits: standing on PIC's shoulders

The cryptographic primitive Proxilion uses for signed authority chains is the
**[PIC protocol](https://www.pic-protocol.org/)** (Provenance, Identity,
Continuity) by **[Nicola Gallo](https://github.com/ngallo)**. PIC's three
formal invariants, *provenance* (every action traces back to an immutable
origin), *identity* (the origin identity cannot mutate across hops), and
*continuity* (authority can only shrink, never broaden), are what let
Proxilion say "this exact action was authorized by this exact human" and
prove it years later. Credit and respect to Nicola for designing and
publishing the protocol. We consume the upstream Rust reference
implementation as a SHA-pinned dependency; we do not vendor or reimplement
it.

## Quickstart

```bash
git clone https://github.com/clay-good/proxilion
cd proxilion

# 1. Generate a CAT signing key for the local Trust Plane.
echo "TRUST_PLANE_CAT_KEY_HEX=$(openssl rand -hex 32)" > .env

# 2. Bring up postgres + Trust Plane + mock-okta.
docker compose up -d --wait postgres trust-plane mock-okta

# 3. Drive the mock OAuth flow and obtain a verifiable PCA_0.
bash scripts/smoke-pic.sh
```

You should see a JSON `PCA_0` with `p_0`, granted ops, and a base64 COSE
signature. Open <https://localhost:8443/admin/> in a browser to paste that
PCA id into the chain inspector.

## Three deployment modes, one PIC fabric

A single architecture can't cover every managed-agent platform. Proxilion
runs in **whichever mode each platform supports**, and the PIC semantics,
audit log, policy engine, and admin UI are identical across all three.

| Mode | What sits where | Covers | Status |
|---|---|---|---|
| **1. In-path proxy** | Agent's OAuth + API URLs point at Proxilion; TLS terminated inside your perimeter | Anthropic Managed Claude, OpenAI Workspace Agents, OSS Claude-likes, Vertex for cross-vendor flows | ✅ Implemented (M1) |
| **2. Pre-flight advisor** | Platform calls `POST /v1/check` before each SaaS action; we never see the OAuth token or body | Any platform exposing a pre-flight webhook | 🟡 Planned (M3) |
| **3. Audit-only ingestion** | Platform forwards events after the fact (SIEM-style) | Platforms with action-log export but no pre-flight hook (likely Lindy, Decagon, Moveworks) | 🟡 Planned (M3) |

What Proxilion **does not** promise: cryptographic enforcement *at the SaaS
provider*. That requires SaaS-side adoption of PIC (RFC 8693-shaped token
exchange validating chains). The three modes give the strongest enforcement
possible without SaaS cooperation; we are upfront about that ceiling.

## What's in the repo

```
proxilion/
├── crates/
│   ├── proxy/              # axum reverse proxy + OAuth interception + adapters
│   ├── cli/                # `proxilion-cli` operator binary
│   ├── policy-engine/      # YAML → match expression + ops template grammar
│   └── shared-types/       # re-exports of upstream provenance-core
├── site/                   # proxilion.com (static HTML, no build) — landing + /pic explainer
├── docs/specs/spec.md      # the design doc
├── ops/                    # Prometheus scrape config + Grafana JSON
├── docker/                 # Dockerfiles for proxy and trust-plane
├── migrations/             # postgres SQL for OAuth + PCA + audit tables
├── scripts/                # dev helpers (cert gen, smoke test)
└── docker-compose.yml      # full dev stack
```

No Next.js dashboard. The proxy serves a single embedded static admin
page at `/admin/` for chain inspection; everything else (log queries,
metrics, alerting) goes through `proxilion-cli`, Prometheus, and your
existing observability stack.

## Visibility and trust

In **Mode 1**, the proxy terminates TLS inside your perimeter and sees
plaintext request and response bodies. That visibility is what enables
Layer-B policy (prompt-injection quarantine, external-send gates) and
full-fidelity audit. It also means the proxy MUST run on your
infrastructure. CAT keys + plaintext SaaS payloads belong inside your
perimeter, not someone else's. To minimize the in-memory cleartext
surface: **adapters opt into body-field exposure**. The Drive read adapter
declares no body fields in the policy context; only adapters that
actually need them (Gmail send → `body.to_domains` / `body.external_recipient`) do.

In **Modes 2 and 3**, the proxy never sees the body or the OAuth token.
The platform sends us metadata; we evaluate, mint a PCA, and respond.

## Trust model in one paragraph

PIC's preventative property depends on the **CAT signing key** being
customer-held. Proxilion is self-hosted for that reason; we never see your
keys, your traffic, or your PCAs. The marketing site at
[proxilion.com](https://proxilion.com) is static HTML that points here (with
a [/pic](https://proxilion.com/pic/) explainer of the underlying protocol);
it deploys to Cloudflare Workers Static Assets from `main` with no build step.
No telemetry, no phone-home, no upsell paths in the admin UI.

## Threat model

What each layer defends, and — just as important — what it deliberately does
not (the honest ceiling of an interception proxy). Authority: [spec.md §10](docs/specs/spec.md).

| Threat | Status | How |
|---|---|---|
| Confused deputy (agent acts beyond the human's authority) | **Defended by PIC, by construction** | Trust Plane refuses to mint the successor PCA — the action is *non-expressible*, not merely detected |
| Cross-user access (act for Alice, read Bob's data) | **Defended by PIC** | `p_0 = alice` is immutable; `read:drive:bob/*` isn't in Alice's ops set → refused |
| Privilege escalation via chain length | **Defended by PIC** | the monotonicity invariant (`child.ops ⊆ parent.ops`) refuses any broadening hop |
| Identity laundering via token exchange | **Defended by PIC** | `p_0` is copied from the predecessor, never re-derived from a token |
| Forged / spliced chain | **Defended by PIC** | any link without a valid predecessor CAT signature fails verification |
| Prompt injection via documents | **Defended by Proxilion (Layer B)** | the read filter quarantines known injection patterns before the agent reads them |
| Unauthorized state change within the user's ops | **Defended by Proxilion (Layer B)** | the write gate blocks (or sends to human approval) |
| Bearer theft from a compromised agent process | **Defended by Proxilion** | the `pxl_live_` bearer is opaque and Proxilion-only; the killswitch revokes it within one request cycle |
| Insider misuse via the agent | **Defended (audit)** | every action is signed into the PCA chain and streamed to the SOC |
| Compromised Proxilion / Trust Plane / IdP | **Not defended** | customer infrastructure; CAT keys and the federation source are the trust root |
| Out-of-band egress (HTTP that skips OAuth) | **Not defended** | the customer's egress controls cover this — Proxilion only sees the OAuth path |
| Side-channel exfiltration through *allowed* actions | **Not defended** | a determined attacker can encode data into permitted Drive writes |

## Policy cheat sheet

Layer-B policy is a list of rules in `config/policy.yaml`. Each rule binds a
`vendor` + `action`, an optional `match` expression, a `decision`, and a
`pic_mode`. Hot-reloaded via `proxilion-cli policy reload`.

```yaml
- id: gmail-external-send-gate        # block any send with an external recipient
  vendor: google
  action: gmail.messages.send
  match:
    body.external_recipient: { equals: true }
  decision: block                     # allow | block | require_confirmation | rate_limit
  override: requires_justification    # human-in-the-loop can release it
  required_ops:                        # ${...} templates; list-valued vars fan out per element
    - "gmail:send:${user.email}:to:${body.to_domains}"
  pic_mode: runtime-gate              # audit (observe) | runtime-gate (enforce Layer A)
```

**Match-expression operators** (spec.md §0.3). A top-level mapping is `AND`ed;
the right-hand side of any clause may interpolate `${path.id}`,
`${user.email}`, `${customer_domain}`, etc.

| Operator | Scalar field | List-valued `body.*` field (JSON array) |
|---|---|---|
| `equals` / `not_equals` | exact string compare | single-value membership / non-membership |
| `in` / `not_in` | is / isn't in the literal set | `in` = **any** element in set, `not_in` = **no** element in set |
| `matches` | regex over the value | regex over the array's JSON form |
| `greater_than` / `less_than` | numeric compare | (scalar only) |
| `all` / `any` / `not` | combinators over sub-expressions | — |
| `exists` | field is present | — |

**Authoring an external-send gate — gate on the boolean, not a domain field.**
The adapter computes `body.external_recipient` over **all** recipients
(to + cc + bcc), so `body.external_recipient: { equals: true }` blocks a send
the moment *any* recipient is external — the gate the example above uses.
Do **not** gate on `body.to_domain` (the alphabetically-first recipient domain):
a send to `[bob@acme.com, eve@evil.example]` sorts `acme.com` first, so a
`to_domain not_in [acme.com]` clause never fires and the external recipient
slips through — a fail-open hole. Note too that the list form
`body.to_domains: { not_in: ["${customer_domain}"] }` fires only when *every*
recipient is external (`not_in` = "no element in set"), so it also misses a
mixed internal+external send; reach for it only when you genuinely mean
"all-external," and use `external_recipient` for "any-external."

## CLI cheat sheet

`proxilion-cli` is the operator surface — there is no web dashboard. Output
defaults to an aligned `pretty` table; `--format json|ndjson` for machines.
Global `--color auto|always|never` gates ANSI (honors `NO_COLOR` and non-TTY
pipes). Destructive commands take `--dry-run` to preview the blast radius
(count of bearers/clients that *would* be revoked) without changing anything.

| Command | What it does |
|---|---|
| `status` / `health` / `selftest` | one-screen readiness + synthetic end-to-end probe |
| `pic show <id>` / `pic verify <id>` | fetch a PCA; walk the chain leaf→root and report invariant verification |
| `actions tail` / `actions list` / `actions export` | live SSE stream / query / bulk export of the signed action log |
| `policy list` / `policy show <id>` / `policy validate <file>` / `policy diff` | inspect the loaded rule set; `validate` parses **and compiles** a candidate YAML locally — decision shapes, read-filter regexes, and match-expression operators/regexes/thresholds, plus unknown-key rejection — so the `BadDecision`/`BadRegex`/`UnsupportedOp` class is caught in CI, not as a fail-closed 500 on the first matching request (no proxy hit) |
| `policy set-mode <id> …` / `policy edit` / `policy reload` | flip observe↔enforce, `$EDITOR` the live YAML, hot-reload |
| `policy simulate` | replay traffic and report would-have-blocked deltas per policy |
| `blocked list` / `blocked show <id>` / `blocked approve <id>` / `blocked reject <id>` | the human-in-the-loop queue |
| `killswitch session\|user\|all [--dry-run]` | revoke an agent/user's authority (or preview the blast radius); rejected on the next request |
| `clients list\|add\|revoke` / `tokens …` | OAuth client + operator-token registry |
| `metrics sample` / `trust-plane …` / `notifier …` | Prometheus, Trust Plane, and notifier diagnostics |
| `completion bash\|zsh\|fish` | emit a shell completion script (offline) |

**Shell completion** (subcommand discovery without memorization):

```bash
# bash
proxilion-cli completion bash | sudo tee /etc/bash_completion.d/proxilion-cli
# zsh — write to a directory on your $fpath, e.g.
proxilion-cli completion zsh > "${fpath[1]}/_proxilion-cli"
# fish
proxilion-cli completion fish > ~/.config/fish/completions/proxilion-cli.fish
```

## Observability cheat sheet

The proxy exposes OpenMetrics at `GET /metrics` (spec.md §3.2). The series an
operator actually alerts on — the ones that say "is enforcement working and
healthy":

| Metric | Type | What it tells you |
|---|---|---|
| `proxilion_pic_invariant_violations_total` | counter | Layer-A refusals — agents attempting actions outside their authority (the confused-deputy signal) |
| `proxilion_blocks_total` | counter | Layer-B policy blocks, by `policy_id` / decision |
| `proxilion_readfilter_scans_total{result}` | counter | read-filter outcomes (`clean` / `stripped` / `quarantined`) — prompt-injection hits |
| `proxilion_pca_verify_failures_total` | counter | PCA signature verifications that failed — tampering or key drift |
| `proxilion_overrides_pending` / `_resolved_total{outcome}` | gauge / counter | the human-in-the-loop queue depth and approve/reject throughput |
| `proxilion_override_justification_present_total{surface,decision}` | counter | over `_resolved_total`: the per-surface fill rate — did the reviewer record *why*, not just *who* (the field that matters at incident review) |
| `proxilion_oauth_token_refreshes_total{result}` | counter | Google refreshes, incl. the `coalesced` label (the 50→1 stampede defense) |
| `proxilion_adapter_request_duration_seconds` | histogram | end-to-end latency per `{vendor,action}` (policy + mint + upstream + filter) |
| `proxilion_policy_evaluation_duration_seconds` | histogram | the Layer-B engine's hot-path budget (target p99 < 1 ms) |
| `proxilion_trust_plane_up` / `proxilion_federation_bridge_up` | gauge | dependency liveness |
| `proxilion_operator_auth_total{result}` | counter | operator-API auth accept/reject (token + scope) |

Two lower-traffic confidence counters round out the set:
`proxilion_adapter_path_encoded_total{vendor}` proves the §6.1 path-encode
(confused-deputy) fix is exercised in prod, and
`proxilion_policy_list_match_total{op,result}` proves list-valued policy gates
(e.g. the external-send gate) actually fire post-§6.2-fix. The edge resource
caps (production-readiness.md PR-2) add
`proxilion_ingress_rejections_total{reason="body_limit"|"timeout"|"rate_limit"|"load_shed"}`
— requests shed at the ingress before policy runs (oversize body → `413`,
wedged adapter request → `408`, over-quota source IP → `429`, server at its
concurrency ceiling → `503`).

Pull them with `proxilion-cli metrics sample` (top series by sample count) or
scrape into Prometheus; the bundled Grafana dashboard lives in
[`ops/grafana/`](ops/) (its "Approval quality & resource bounds" row charts the
override-justification fill rate and the burst-suppressor bucket bound).

The `reason` / `code` label values on the block counters (and the `code` field
in every 4xx/5xx response envelope) are the stable error codes catalogued in
[docs/error-codes.md](docs/error-codes.md) — each with its default HTTP status,
when it fires, and the suggested operator action. That table is the source of
truth for alerting and runbooks. The burn-rate alert rules
([ops/prometheus/alerts.yml](ops/prometheus/alerts.yml), `promtool`-gated in CI)
and the on-call procedures ([docs/ops/runbooks/](docs/ops/runbooks/README.md),
one per paging alert + the killswitch / DB-failover / key-compromise /
incident-response deep dives) close the loop from metric to page to fix.

## Design decisions

| Decision | Why |
|---|---|
| **Self-hosted, in-path proxy** | Layer-B policy and full-fidelity audit require plaintext bodies; CAT keys + cleartext SaaS payloads must stay inside the customer perimeter, never ours. |
| **No web dashboard** | A dashboard is a standing attack surface and a maintenance tax. The terminal (`proxilion-cli`), Prometheus, and a single embedded `/admin/` chain-inspector cover the operator's needs. |
| **Default-deny body exposure** | Adapters opt **into** exposing `body.*` fields to policy (Gmail send declares `to_domains`; Drive read declares none) to minimize in-memory cleartext surface. |
| **PIC as a SHA-pinned dependency** | We consume the upstream reference implementation, never vendor or reimplement it — the cryptography stays auditable against its source of truth. |
| **YAML match-expression interpreter, not Rego** | A direct interpreter keeps the build slim and the p99 < 1 ms hot-path budget; the `evaluate` API is Rego-swappable later without touching adapters. |
| **Best-effort, isolated audit sinks** | The durable `action_events` row is written by the primary before fan-out; NATS / SIEM / notifier failures (incl. retryable 429s) never block the request or each other. |
| **Justification capture as graceful enhancement** | The Slack approve modal needs a bot token (`PROXILION_SLACK_BOT_TOKEN`); when it's set, the click opens a `views.open` modal and the override commits on `view_submission` with the reviewer's text. Without it, the original direct-commit path (incoming-webhook only) is unchanged — the feature is purely additive, no schema or config-row change. |

## Testing

The default suite is hermetic — `cargo test --workspace --locked` needs no
database or network and is what the `fmt` / `clippy` / `test` / `build-release`
CI jobs gate on. Beyond it, a set of **DB-backed integration tests** drives
real handlers against a real Postgres (the proxy is a binary-only crate, so
these live as in-module `#[cfg(test)]` tests that can reach private handlers).
They are **opt-in**: each returns early unless `PROXILION_TEST_DATABASE_URL`
is set, so the default `cargo test` run skips them. The CI `integration` job
provisions a `postgres:16-alpine` service and sets that env var, so they run
for real on every push; locally:

```bash
docker run -d --name pg -e POSTGRES_USER=proxilion -e POSTGRES_PASSWORD=proxilion \
    -e POSTGRES_DB=proxilion_test -p 55432:5432 postgres:16-alpine
PROXILION_TEST_DATABASE_URL=postgres://proxilion:proxilion@localhost:55432/proxilion_test \
    cargo test -p proxy db_backed
```

They migrate the schema (`sqlx::migrate!`) and assert security-critical
properties end-to-end:

| Flow | Property pinned |
|---|---|
| email approval landing | the single-use token is consumed only on **POST**, never on a prefetch GET; a re-GET shows "already used" |
| `killswitch --dry-run` | the preview `count(*)` equals the real revoke exactly, changes no state, and writes no `kill_records` row |
| `actions purge --dry-run` | the dry-run counts old `action_events` without deleting; the real purge removes rows past the cutoff while recent rows survive; a future cutoff is refused |
| blocked-queue `list` / `show` | status/policy filters, the auto-expire-on-list of past-due pending rows, and unknown-id → 404 |
| Drive adapter, audit mode | policy eval → PIC mint vs a **wiremock'd Trust Plane** (422 → audit fallback) → upstream GET to a **wiremock'd Google** → read-filter quarantines an injection pattern (replaced by `[redacted by proxilion read-filter]`) while surrounding text passes through |
| Drive adapter, runtime-gate (mint refused) | the same 422 is **not** passed through — `proxy_request` returns `PicInvariantViolation` (403), never calls upstream, and persists a `layer='pic_invariant'` blocked row (prevention by construction) |
| Drive adapter, runtime-gate (valid mint, happy path) | Trust Plane *issues* a successor → the PCA_2 is cached at `hop=2` with the leaf as predecessor (the chain grows a hop) and a clean upstream body passes through untouched |
| Drive adapter, read-filter `block_request` | a matched pattern quarantines the **whole** response → `ReadFilterBlocked` (403) + a `layer='read_filter'` blocked row (vs the `replace_with_marker` row above, which lets the request proceed) |
| Drive adapter, `require_confirmation` | the human-in-the-loop gate on a Drive read denies the agent (428) **and** persists exactly one `status='pending'`, `layer='policy'` blocked row (the twelfth-audit fix — the guard once matched only a hard `block`, so the row was silently skipped) |
| Gmail send, external recipient | the flagship Layer-B gate blocks before any mint/upstream — `PolicyBlocked` (403) + a `layer='policy'` blocked row carrying `policy_id` + `override_allowed` |
| Calendar `events.insert`, external attendee | the write gate (the Calendar adapter's distinguishing path) blocks before any mint/upstream — `PolicyBlocked` (403) + a `layer='policy'` blocked row; completes the Drive/Gmail/Calendar trio |
| Google token refresh, 50 concurrent | the per-bearer mutex coalesces a stampede: with an expired token, **50 concurrent** refreshers hit Google **exactly once** (asserted via wiremock's `received_requests`) and all see the fresh token |
| Operator-auth boundary (the gate for all `/api/v1/*`) | the real `middleware` + `scope_check` composition, driven via `tower::oneshot` against seeded `operator_tokens`: valid+scope → 200, wildcard → 200, revoked → 401, unknown → 401, wrong scope → 403, missing/malformed → 401, and a successful auth touches `last_used_at` |
| OAuth federation callback (replay binding) | a federation token whose `state` matches the callback session establishes it (`pca_0_id`/`p_0` written); a token minted for a *different* session is rejected (`BridgeRejected`, 401) and the target session stays untouched — session-fixation defense (§6.4); a *second* token naming the **same** already-bound session is rejected (`SessionGone`) without overwriting its identity — same-session re-bind defense (thirteenth-audit fix) |
| OAuth Google callback (atomic credential persist) | the encrypted `google_tokens` row commits or rolls back atomically with the `agent_bearers` row that references it — a rolled-back transaction leaves **zero** rows, a committed one leaves exactly one (thirteenth-audit fix — the row was once written on the bare pool before the fallible Trust Plane mint, orphaning encrypted credentials on any failure) |
| Slack approval `trigger_id` release | after a Slack approve/reject `Fresh`-claims the `trigger_id` on a `pending` row, a **failed** commit releases the claim so a fresh click re-claims cleanly (the action isn't wedged), while a release *after* the row committed is a no-op — the `status='pending'` guard never un-claims a row that did mutate (seventeenth-audit fix) |
| Email approval link survives a failed commit | the public approval `submit` form runs `approve_inner` against a `pending` row naming an **absent** predecessor PCA → the commit fails, the row stays `pending`, and the single-use `notifier_tokens` row is **not** consumed (`consumed_at IS NULL`) so a fresh GET still renders the live form — the email sibling of the Slack-wedge fix (eighteenth-audit fix — the token was once burned regardless of outcome, wedging the link on any transient failure) |

These run in the CI `integration` job (postgres service) on every push, against
in-process wiremock Trust Plane + Google. The shared scaffolding lives in
[`crates/proxy/src/test_support.rs`](crates/proxy/src/test_support.rs).

## License

MIT. Built on [`clay-good/provenance`](https://github.com/clay-good/provenance)
(MIT), our single PIC dependency, SHA-pinned in [`Cargo.toml`](Cargo.toml).
See [NOTICE](NOTICE) and [docs/specs/spec.md](docs/specs/spec.md) §3 for
attribution and detail.

## Contributing

Issues and PRs welcome. There's no CLA; contributions land under the
repository's MIT license. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
dev setup, the CI gates you'll need to pass (`cargo fmt --check`,
`cargo clippy -- -D warnings`, `cargo test --workspace --locked`,
`cargo audit --deny warnings`), the per-spec contribution model, and
the deliberate non-goals.

## Security

Found a vulnerability? **Do not open a public GitHub issue.** See
[SECURITY.md](SECURITY.md) for the private disclosure address,
response SLAs (72 hours to acknowledge, scaled by severity to patch),
in-scope / out-of-scope surfaces, and what we already defend against
so you can lead with where you got past it.

**Verification posture.** The shipped code has been through twenty-nine rounds of
adversarial multi-subsystem auditing (crypto/auth/oauth · adapters/MIME ·
policy-engine · notifiers/forwarders/PIC · operator-API · CLI/config/server),
each pass sweeping every lane in parallel for reachable panics, fail-open gates,
authz inversions, secret leaks, and DoS amplification. Every finding landed with
a regression test that fails if the defect returns; the full ledger — defect,
root cause, trigger, fix, and pinning test — is in the
[`[Unreleased] → Fixed`](CHANGELOG.md) section of the changelog and the audit
addenda in [surface-delight-and-correctness.md](docs/specs/surface-delight-and-correctness.md).
The twenty-ninth pass (2026-06-16) ran five parallel auditors over the same lanes
with the same **sibling-drift** focus and surfaced **no new reachable security
defects** — the **eleventh consecutive clean security sweep** (19th–29th). It
folded in one documentation-only fix (like the 19th/23rd/27th/28th): the
`observe` mode pipeline note in [ui-less-surfaces.md](docs/specs/ui-less-surfaces.md)
§2.5 enumerated a non-existent `observe_quarantine` decision label and omitted the
real `observe_rate_limit`, drifting from the authoritative three-label set emitted
by [`observe_demote`](crates/policy-engine/src/rego.rs) (`observe_block` /
`observe_require_confirmation` / `observe_rate_limit`) — the same set already
correct in `schema-v1.md` and the §3.2 metric contract. Quarantine is a read-filter
response-body outcome, never a Layer-B `Decision`, so it never flows through
`observe_demote`; both the enumeration and the prose above it were corrected. No
runtime change; the test count held.
The twenty-eighth pass (2026-06-16) ran four parallel auditors over the same lanes
and surfaced **no new reachable security defects** — the **tenth consecutive clean
security sweep** (19th–28th). It finished the sibling-drift cleanup the 27th pass
opened: the same dropped-dashboard drift the 27th fixed in `trace.rs` was re-pointed
across the remaining **production** doc-comments — [`pic/verifier.rs`](crates/proxy/src/pic/verifier.rs)
(×3), [`api/mod.rs`](crates/proxy/src/api/mod.rs), [`policy-engine/rego.rs`](crates/policy-engine/src/rego.rs),
and the `BurstSummary` flush-path docstring — at the `proxilion-cli` / `/admin`
inspector that actually consumes them. Two of those were genuine **code-vs-doc
contradictions**, not cosmetic: `api/mod.rs` still documented the `/api/v1/*` routes
as *unauthenticated* even though they now sit behind the `operator_auth` middleware
(enforced by default), and a comment in [`oauth/routes.rs`](crates/proxy/src/oauth/routes.rs)
claimed the federation `bridge_callback` was "skipped for metric simplicity" when it
already emits `proxilion_oauth_callback_total` with an `infer_idp`-derived label. Also
corrected a stale `~line 169` cross-reference in the Drive adapter and three function-
signature drifts in [ui-less-surfaces.md](docs/specs/ui-less-surfaces.md). No runtime
change; the test count held.
The twenty-seventh pass (2026-06-16) swept all lanes in parallel with the same
**sibling-drift** focus and surfaced **no new reachable defects** — the **ninth
consecutive clean security sweep** (19th–27th). It re-confirmed the four hex
decoders' `is_ascii()` char-boundary guards, the fail-closed `MAX_CHAIN_HOPS=64`
chain walk, the linear-time (ReDoS-immune) `matches` interpreter with both
`greater_than`/`less_than` quoted-threshold `BadShape` fail-closed, and the
burn-before-commit approval class closed on all three surfaces. It folded in one
documentation-only cleanup (like the 23rd pass): twelve stale "dashboard" comments
in [policy-engine `trace.rs`](crates/policy-engine/src/trace.rs) — referencing the
React/Next.js dashboard dropped in the 2026-05-11 UI pivot — were re-pointed at the
actual trace consumers (the `proxilion-cli` and the embedded `/admin` chain
inspector). No runtime change.
The twenty-sixth pass (2026-06-16) swept the lanes in parallel with the same
**sibling-drift** focus and surfaced **no new reachable defects** — the **eighth
consecutive clean security sweep** (19th–26th); it re-confirmed that all three hex
decoders (`server.rs` token-encryption key, `forwarder/siem.rs` and
`notifier/webhook.rs` HMAC keys) carry the `is_ascii()` char-boundary guard with no
N-1-of-N drift, that every interpolated Drive/Gmail/Calendar path segment routes
through `encoded_segment`, and that the burn-before-commit approval class stays
closed on all three surfaces with no fourth claim site.
The twenty-fifth pass (2026-06-16) re-ran all six lanes in parallel and surfaced
**no new reachable defects** — the seventh consecutive clean security sweep
(19th–25th), and the sixth fully-clean pass in that run (the 23rd carried a
documentation-only fix). Crypto/auth re-confirmed the AES-256-GCM envelope rejects
a corrupt nonce length before `Nonce::from_slice` (no panic), PKCE-S256 compares
with `subtle::ct_eq`, and every secret is redacted in its `Debug` impl; PIC/proxy-core
re-verified cryptographic chain continuity (a forged `predecessor_id` pointer fails
the `child.cat_sig == parent.signature()` check), the `MAX_CHAIN_HOPS=64` cycle
bound, and the re-read-after-lock that coalesces 50 concurrent refreshes into one
Google call. The twenty-fourth pass (2026-06-16) likewise surfaced no new defects;
each lane re-traced its highest-risk surfaces with the same **sibling-drift** focus:
PIC/crypto re-confirmed the fail-closed,
`MAX_CHAIN_HOPS=64`-bounded chain walk terminates a crafted A→B→A cycle with
`ChainTooLong` (never a loop or a "valid" result) and that all four hex decoders
carry the `!is_ascii()` char-boundary guard; the flagship Gmail external-send gate
stays fail-closed on an unparseable recipient header (the permissive fallback can
only over-count external recipients, never drop one Gmail would route); the
burn-before-commit class stays closed on all three approval surfaces; and every
protected `/api/v1/*` route is bound to a catalogued `scope_check`. No runtime
behavior changed.
The twenty-third pass (2026-06-16) re-ran all six lanes in parallel; the security
sweep was clean — the **fifth consecutive clean security sweep** (19th–23rd) — with
exactly one documentation-accuracy fix: the `operator_auth` module docstring had
drifted from the canonical scope catalogue (it listed a non-existent `tokens:admin`
scope and omitted `actions:purge`, `notifier:read`, `notifier:write`) and now points
at [`SCOPE_CATALOGUE`](crates/shared-types/src/operator_scopes.rs), the runtime
source of truth, instead of a duplicate list. No runtime behavior changed. The
sibling-drift re-confirmations (hex-decode guards, fail-closed chain-walk,
`encoded_segment`, quoted-threshold `BadShape`, commit-gated approval claims) all
held.
The twenty-second pass (2026-06-16) re-ran all six lanes in parallel and surfaced
**no new reachable defects** — the **fourth consecutive fully-clean pass** (19th,
20th, 21st, 22nd). Each lane re-traced its highest-risk surfaces with the same
sibling-drift focus and re-confirmed every prior fix intact: auth-code
single-spend with a transient-failure-retryable consume, all four `is_ascii()`-guarded
hex decoders (the family is closed), the fail-closed PIC chain-walk with its
`MAX_CHAIN_HOPS=64` cyclic bound, `encoded_segment` on every interpolated upstream
path, the quoted-threshold `BadShape` shared across `greater_than`/`less_than`,
and commit-gated single-use approval claims across all three surfaces
(Slack/email/operator-API), with the Slack modal path structurally immune for
holding no single-use claim.
The twenty-first pass (2026-06-16) re-ran all six lanes in parallel and surfaced
**no new reachable defects** — the third consecutive fully-clean pass (19th, 20th,
21st). Each lane re-traced its highest-risk surfaces with an explicit sibling-drift
focus (the class that produced the 17th/18th approval-wedge fixes) and re-confirmed
the prior fixes intact: atomic in-caller-tx Google-token persistence, the
fail-closed PIC chain-walk with its `MAX_CHAIN_HOPS=64` cyclic bound,
`encoded_segment` on every interpolated upstream path, the quoted-threshold
`BadShape` across both `greater_than`/`less_than`, the three `is_ascii()`-guarded
hex decoders, and commit-gated single-use approval claims across all three surfaces
(Slack/email/operator-API).
The twentieth pass (2026-06-16) re-ran all six lanes in parallel and surfaced
**no new reachable defects**. The one candidate raised — that `GET /api/v1/setup/status`
answers without an operator token — was investigated and confirmed **intentional**:
it is the pre-token onboarding readiness probe (the chicken-and-egg surface that
tells a fresh operator how to configure the system so they *can* mint their first
token), mounted outside `operator_auth` by design in the same public tier as
`/healthz`, and it discloses only booleans and counts — no secrets, no token
values, no capability URLs. Gating it would break onboarding for zero
confidentiality gain. All five other lanes re-confirmed their prior fixes intact
(fail-closed chain-walk, `encoded_segment` path encoding, quoted-threshold
`BadShape`, the three `is_ascii()`-guarded hex decoders, and commit-gated
single-use approval claims across Slack/email/operator-API).
The nineteenth pass (2026-06-16) re-ran all six lanes in parallel and surfaced
**no new reachable defects**. After two consecutive single-finding passes (17th
and 18th) that were sibling-drift misses across the three approval surfaces, this
pass scrutinized the **third** surface hardest and confirmed the operator-API
`approve`/`reject` path carries **no** burn-before-commit sibling of the
Slack/email wedge: it claims no single-use trigger or token and runs the entire
override inside one transaction that rolls back cleanly on any pre-commit error,
so a retry re-locks and re-checks `pending` with nothing consumed. The chain-walk,
the quoted-threshold fail-closed across both comparison operators, the
`encoded_segment` path-encoding across all three adapters, and the catalogued
operator-scope gates were all re-confirmed intact. A stale CLI help string (the
`blocked list --limit` ceiling read `1..=200` while both the CLI and the server
clamp to `1..=500`) was corrected alongside the pass.
The eighteenth pass (2026-06-16) re-ran all six lanes in parallel and surfaced
**one** defect, in the notifier/approvals lane: the **email/public-landing sibling
of the seventeenth-pass Slack wedge** — a textbook sibling-drift miss where the
prior fix hardened one approval surface and left the symmetric hole on the other.
The public approval `submit` handler consumed the single-use `notifier_tokens` row
**unconditionally**, so a genuinely reachable *transient* approve/reject failure
(predecessor PCA absent from `pca_cache`, a Trust-Plane blip, or a pool error — all
of which leave the blocked row `pending`) still burned the link, leaving the action
unreviewable and forcing an operator to mint a fresh one (default-deny held; an
availability bug, not authz). Fixed by consuming the token only when the decision
actually committed — the outer `FOR UPDATE` token lock plus `approve_inner`'s own
`FOR UPDATE` + `status='pending'` guard keep a retry from ever double-approving —
pinned by a db-backed regression test. The other five lanes cleared.
The seventeenth pass (2026-06-16) — after two consecutive clean sweeps — re-ran
all six lanes in parallel and surfaced **one** defect, in the notifier/approvals
lane: a Slack-approval **wedge** where the interaction handler claimed the inbound
`trigger_id` on the still-`pending` blocked row *before* the override commit, and
the direct-commit path never released that claim when the commit failed for a
reachable transient reason — so Slack's automatic retry reported a false success
(no override minted) and a fresh click hit a `Conflict`, permanently wedging that
action's Slack approval path (default-deny held throughout; an availability bug,
not authz). Fixed with a `release_trigger_id` that clears the claim on the
approve/reject error path, guarded so it can never un-claim a row that did commit,
and pinned by a db-backed regression test. The other five lanes cleared.
The sixteenth pass (2026-06-15) — the second consecutive fully-clean sweep —
re-ran all six lanes in parallel with an explicit sibling-drift focus and
surfaced **no new reachable defects**: the chain-walk was re-confirmed fail-closed
at every link and bounded against cyclic chains (`MAX_CHAIN_HOPS = 64` →
`ChainTooLong`), the quoted-threshold `BadShape` fail-closed was re-confirmed
across **both** `greater_than` and `less_than`, every interpolated adapter path
segment was re-confirmed to route through `encoded_segment`, and the single-use
`notifier_tokens` `FOR UPDATE` + status guard was re-confirmed to defeat replay
even when the best-effort `consumed_at` write fails — so the ledger is unchanged
from the fourteenth pass.
The fifteenth pass (2026-06-15) re-swept all six lanes in parallel and surfaced
**no new reachable defects** — each lane re-traced its highest-risk surfaces and
confirmed the prior fixes intact (a coverage check also confirmed all three
`from_hex`/`hex_decode_32` siblings carry dedicated non-ASCII regression tests),
so the ledger is unchanged from the fourteenth pass.
The fourteenth pass swept the PIC/crypto lane and found one: `hex_decode_32`, the
decoder for the operator-supplied `PROXILION_TOKEN_ENCRYPTION_KEY`, guarded only on
byte length before slicing the string at byte offsets, so a 64-*byte* key carrying
any multibyte codepoint panicked the boot path on a char boundary — the third
`from_hex` sibling to need the ASCII guard the 4th pass added to the two HMAC-key
decoders (now fixed and pinned). The five other lanes cleared with no findings.
The thirteenth pass swept the OAuth/federation lane and found two: the Google
callback persisted its AES-GCM-encrypted `google_tokens` row on the bare pool
*before* the fallible Trust Plane mint and the bearer transaction, so any failure
in that window orphaned an encrypted credential no bearer could reference (now
persisted inside the same transaction, atomic with the bearer); and the
federation bridge's establish UPDATE lacked a `pca_0_id IS NULL` guard, so a
replayed token could re-bind an already-established session's identity (now a
one-shot establish — defense-in-depth ahead of the JWKS signature swap). The five
other lanes cleared with no findings.
The twelfth pass added a dedicated logic-correctness lane (hunting wrong-*decision*
bugs, not crashes or leaks) and found one: the Drive adapter's Layer-B denial
guard had drifted from its Gmail/Calendar siblings and matched only a hard
`block`, so a `require_confirmation` policy on a Drive read denied the agent
correctly but persisted no review row and fired no notifier — the
human-in-the-loop gate was silently unreviewable. The fix folds the guard into a
single shared predicate so the three adapters can't diverge again.
The eleventh pass extended the tenth's `deny_unknown_fields` hardening to the
*nested* policy-config structs — a typo'd `quarantine_actoin: block_request`
under a `read_filter:` block had silently fallen back to the marker-splice
default, downgrading an intended hard block of an injected response to one the
agent still reads — and closed a CLI subtraction-overflow panic on an absurd
`--since`/`--against` duration that the fifth pass's checked *constructors* had
left on a separate `DateTime - TimeDelta` surface. The tenth pass closed a
capability-URL secret leak (Slack/webhook/SIEM endpoint tokens reaching logs via
`reqwest`'s URL-bearing error Display and boot-time `info!` lines), made `policy
validate` compile policies rather than only shape-check the YAML, hardened two
fail-open shapes to fail closed (a typo'd policy key, a malformed PCA-cache `ops`
column), and bounded the CLI live-tail's SSE reassembly buffer. This is a track
record, not a guarantee — the threat-model table above states the honest ceiling
of an interception proxy.

**One known pre-production gap, by design.** The federation-bridge token
signature is **not** verified in M0/M1 — upstream `provenance-bridge` ships no
binary target yet, so `/oauth/bridge/callback` trusts the token payload
(spec.md §0.4). Anyone who can reach that callback could forge `p_0`/`ops`, so
the proxy emits a loud `warn!` at boot whenever the OAuth router is mounted and
the route must not be exposed in production until the JWKS-backed
`jsonwebtoken::decode` swap lands. The smoke/CI/demo flows use the stub
deliberately.

**Path to production (M5).** The full hardening breakdown to close that gap and
make Proxilion safe to expose — federation signature verification (the P0
above), edge DoS controls, key rotation, SLOs + runbooks, HA + DR, and a
signed/SBOM'd `v0.1.0` — lives in
[docs/specs/production-readiness.md](docs/specs/production-readiness.md) (PR-1
… PR-13) with a Go-Live Gate checklist. **PR-2 (edge DoS controls) is complete
at the application layer** — four operator-tunable controls on the agent-facing
ingress, each rejection feeding `proxilion_ingress_rejections_total{reason}`:

| Control | Env var (default) | Reject |
|---|---|---|
| Request-body cap (before any body is buffered) | `PROXILION_MAX_REQUEST_BODY_BYTES` (10 MiB) | `413` |
| Per-request timeout (adapter routes; SSE/streaming exempt) | `PROXILION_REQUEST_TIMEOUT_SECS` (30 s) | `408` |
| Per-IP rate limit (token bucket) | `PROXILION_RATE_LIMIT_PER_SEC` (50) / `PROXILION_RATE_LIMIT_BURST` (100) | `429` + `Retry-After` |
| Global concurrency limit + load-shed | `PROXILION_MAX_CONCURRENT_REQUESTS` (1024) | `503` |

Each takes `0` to disable. The rate limiter keys on a **trusted-proxy-aware**
client IP: `X-Forwarded-For` is believed only when the TCP peer is in
`PROXILION_TRUSTED_PROXIES` (default empty = trust nothing), walked
right-to-left so a spoofed prefix is ignored. Rate-limit and load-shed are
implemented dependency-free (token bucket on `moka`, semaphore on `tokio`).
Remaining PR-2 work (interlinks PR-7): the L4 connection/handshake cap and the
at-scale overload load test (the FD-ulimit guidance now lives in the
[config reference](docs/ops/config-reference.md)).

**PR-4 (transport & trust-boundary hardening) is complete.** Ingress TLS is
terminated by rustls/aws-lc-rs, which never negotiates below **TLS 1.2**;
`PROXILION_TLS_MIN_VERSION=1.3` (Helm `proxy.tls.minVersion`) pins 1.3-only
for a hardened deploy, and cipher suites are rustls defaults (AEAD-only, no
CBC/RC4/3DES). Full certificate verification on every outbound client
(Trust Plane, upstream SaaS, IdP JWKS, NATS, SIEM, Slack, SMTP) is enforced
in CI by the [`tls-cert-verification`](.github/workflows/tls-cert-verification.yml)
gate, which forbids any production crate from disabling cert/hostname
verification. The per-hop TLS/mTLS matrix, cipher posture, public-route
surface, and the staging `testssl`/`nmap` go-live check live in
[docs/ops/tls-mtls-matrix.md](docs/ops/tls-mtls-matrix.md).

**PR-5 (SLOs + alerting) and PR-6 (runbooks) — the operability contract.**
Five SLOs (99.9% request availability, sub-ms added latency, federation/issuance
success, approval-path liveness, killswitch propagation) are defined with
rationale and measurement windows in [docs/ops/slos.md](docs/ops/slos.md), and
[ops/prometheus/alerts.yml](ops/prometheus/alerts.yml) implements 16 alerts +
7 recording rules — Google-SRE multi-window multi-burn-rate for availability
plus federation, security-invariant (`pca_verify`/`pic` must read zero), and
operational signals — gated in CI by `promtool`
([`prometheus-rules`](.github/workflows/prometheus-rules.yml)). **Every alert
links to a runbook**: each paging alert resolves to a full detection →
diagnosis → mitigation → verification → escalation procedure in
[docs/ops/runbooks/](docs/ops/runbooks/README.md), backed by dedicated
critical-procedure runbooks for the
[killswitch](docs/ops/runbooks/killswitch.md) (with the one-request-cycle
cross-replica propagation guarantee), [DB failover](docs/ops/runbooks/db-failover.md),
[key compromise](docs/ops/runbooks/key-compromise.md), and
[security incident response](docs/ops/runbooks/incident-response.md) (an
incident-commander checklist that preserves the tamper-evident audit log as
evidence *before* mitigating). Remaining PR-5/PR-6 work is staging execution:
Alertmanager routing, the synthetic burn drill, and the killswitch / DB-failover
/ PITR-restore drills.

**Configuration is one authoritative, drift-gated reference.** Every
operator-facing variable the proxy reads — type, default, source precedence,
security note, and the env ⇔ TOML ⇔ Helm mapping — is documented in
[docs/ops/config-reference.md](docs/ops/config-reference.md), with the
copy-and-edit template in [config/proxilion.example.toml](config/proxilion.example.toml).
Values resolve last-writer-wins through four layers:

```text
built-in defaults  →  TOML file  →  PROXILION_* env vars  →  programmatic overrides
                      (PROXILION_CONFIG_FILE)               (embed / tests only)
```

Secrets read from a mounted `<VAR>_FILE` in preference to the env var (the
Vault / External-Secrets convention), and the reference is kept honest by a CI
test ([config_docs.rs](crates/proxy/tests/config_docs.rs)) that fails the build
if any `env::var`/`secret_env` read or any `FileConfig` field is left
undocumented — so the config surface cannot drift from its docs. (PR-13's
config-reference slice; the deployment guide + signed PRR remain.)

## The Skill Overreach problem

The agent platforms now ship "skills." You train one agent for the whole
org, attach it to Drive, Gmail, Salesforce, Jira, Notion, and an internal
API or two, and hand it out to every employee. That single agent now holds
the *union* of every permission any of its users have. In effect, you have
deployed a super-user. The OAuth scope says `drive.readonly` for the
tenant; the skill says "summarize anything the user asks about"; the
runtime has no idea whether the human on the other end is an intern, a
finance lead, or the CEO.

That is the Skill Overreach problem. A skill is authority defined at the
agent level. A user is authority defined at the human level. The gap
between them is exactly where confused-deputy attacks, prompt-injection
exfiltration, and insider laundering live.

Proxilion is the only thing in the stack that forces the skilled agent
back into the Human User box. Every call the agent makes is bound to a
PCA chain rooted at the specific human it is acting for at that moment.
The intern's request to "summarize Q3 financials" fails the same way it
would if the intern opened Drive directly. The CEO's request succeeds.
The skill stays the same; the *authority* is no longer the skill's, it is
the user's. Prevention by construction, even when the skill itself is
overpowered.
