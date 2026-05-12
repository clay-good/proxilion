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
  through Slack or a ticket. Configurable per sender, per domain, per op.
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
