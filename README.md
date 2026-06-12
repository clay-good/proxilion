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
├── site/                   # proxilion.com, static, Cloudflare Pages
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
[proxilion.com](https://proxilion.com) is a static HTML page that points
here. No telemetry, no phone-home, no upsell paths in the admin UI.

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

List-valued set semantics let a recipient-domain gate match directly on the
array the adapter exposes, e.g. `body.to_domains: { not_in: ["${customer_domain}"] }`
fires when every recipient is external.

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
| `policy list` / `policy show <id>` / `policy diff` | inspect the loaded rule set |
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
| blocked-queue `list` / `show` | status/policy filters, the auto-expire-on-list of past-due pending rows, and unknown-id → 404 |
| Drive adapter, audit mode | policy eval → PIC mint vs a **wiremock'd Trust Plane** (422 → audit fallback) → upstream GET to a **wiremock'd Google** → read-filter quarantines an injection pattern (replaced by `[redacted by proxilion read-filter]`) while surrounding text passes through |
| Drive adapter, runtime-gate (mint refused) | the same 422 is **not** passed through — `proxy_request` returns `PicInvariantViolation` (403), never calls upstream, and persists a `layer='pic_invariant'` blocked row (prevention by construction) |
| Drive adapter, runtime-gate (valid mint, happy path) | Trust Plane *issues* a successor → the PCA_2 is cached at `hop=2` with the leaf as predecessor (the chain grows a hop) and a clean upstream body passes through untouched |
| Drive adapter, read-filter `block_request` | a matched pattern quarantines the **whole** response → `ReadFilterBlocked` (403) + a `layer='read_filter'` blocked row (vs the `replace_with_marker` row above, which lets the request proceed) |
| Gmail send, external recipient | the flagship Layer-B gate blocks before any mint/upstream — `PolicyBlocked` (403) + a `layer='policy'` blocked row carrying `policy_id` + `override_allowed` |
| Google token refresh, 50 concurrent | the per-bearer mutex coalesces a stampede: with an expired token, **50 concurrent** refreshers hit Google **exactly once** (asserted via wiremock's `received_requests`) and all see the fresh token |

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
