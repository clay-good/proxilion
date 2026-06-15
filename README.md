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
- **Real-time action stream + killswitch.** Every agent action streams to an
  operator dashboard and your SIEM the moment it happens. One click revokes
  every capability tied to that agent or user within one request cycle.
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
actually need them (Gmail send → `body.to_domain`) do.

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
| `policy list` / `policy show <id>` / `policy validate <file>` / `policy diff` | inspect the loaded rule set; `validate` parse-checks a candidate YAML locally (CI-safe, no proxy hit) |
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
(e.g. the external-send gate) actually fire post-§6.2-fix.

Pull them with `proxilion-cli metrics sample` (top series by sample count) or
scrape into Prometheus; the bundled Grafana dashboard lives in
[`ops/grafana/`](ops/) (its "Approval quality & resource bounds" row charts the
override-justification fill rate and the burst-suppressor bucket bound).

The `reason` / `code` label values on the block counters (and the `code` field
in every 4xx/5xx response envelope) are the stable error codes catalogued in
[docs/error-codes.md](docs/error-codes.md) — each with its default HTTP status,
when it fires, and the suggested operator action. That table is the source of
truth for alerting and runbooks.

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
| Gmail send, external recipient | the flagship Layer-B gate blocks before any mint/upstream — `PolicyBlocked` (403) + a `layer='policy'` blocked row carrying `policy_id` + `override_allowed` |
| Calendar `events.insert`, external attendee | the write gate (the Calendar adapter's distinguishing path) blocks before any mint/upstream — `PolicyBlocked` (403) + a `layer='policy'` blocked row; completes the Drive/Gmail/Calendar trio |
| Google token refresh, 50 concurrent | the per-bearer mutex coalesces a stampede: with an expired token, **50 concurrent** refreshers hit Google **exactly once** (asserted via wiremock's `received_requests`) and all see the fresh token |
| Operator-auth boundary (the gate for all `/api/v1/*`) | the real `middleware` + `scope_check` composition, driven via `tower::oneshot` against seeded `operator_tokens`: valid+scope → 200, wildcard → 200, revoked → 401, unknown → 401, wrong scope → 403, missing/malformed → 401, and a successful auth touches `last_used_at` |
| OAuth federation callback (replay binding) | a federation token whose `state` matches the callback session establishes it (`pca_0_id`/`p_0` written); a token minted for a *different* session is rejected (`BridgeRejected`, 401) and the target session stays untouched — session-fixation defense (§6.4) |

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

**Verification posture.** The shipped code has been through nine rounds of
adversarial multi-subsystem auditing (crypto/auth/oauth · adapters/MIME ·
policy-engine · notifiers/forwarders/PIC · operator-API · CLI/config/server),
each pass sweeping every lane in parallel for reachable panics, fail-open gates,
authz inversions, secret leaks, and DoS amplification. Every finding landed with
a regression test that fails if the defect returns; the full ledger — defect,
root cause, trigger, fix, and pinning test — is in the
[`[Unreleased] → Fixed`](CHANGELOG.md) section of the changelog and the audit
addenda in [surface-delight-and-correctness.md](docs/specs/surface-delight-and-correctness.md).
The most recent pass came back clean across all but one low-severity
display-correctness item (an SSE multibyte-codepoint reassembly fix in the CLI
live-tail). This is a track record, not a guarantee — the threat-model table
above states the honest ceiling of an interception proxy.

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
