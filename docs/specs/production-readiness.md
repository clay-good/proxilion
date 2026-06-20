# Production Readiness — M5 Hardening Spec

> Companion to [`spec.md`](./spec.md). This document specifies everything
> required to take Proxilion from "feature-complete, heavily audited,
> pre-`v0.1.0`" to **safe to expose in production in front of a managed
> agent**. It is the milestone **M5 — Production Hardening** referenced in
> `spec.md` §13.

**Status (2026-06-19):** In progress. The workspace builds clean and the full
suite is green (DB-backed lane runs in CI). The advertised M0–M4 surface (OAuth
interception, read-filter, write-gate + human-in-the-loop approvals, killswitch
+ SSE, policy engine, Drive/Gmail/Calendar adapters, CLI, metrics, Grafana, Helm
chart, marketing site, demo) is shipped. **The deliberate federation-signature
gap (PR-1) still blocks production** — though its verification primitive
(`oauth::idp_verify`, algorithm-pinned, fail-closed, RFC 8725/9700
rejections tested) has now landed (Approach A); the JWKS layer + callback→
Trust-Plane issuance rewiring remain before the P0 closes. **PR-2 is now complete at the application
layer** — all four edge resource-exhaustion controls (request-body cap,
per-request adapter timeout, per-IP rate limit, global concurrency limit +
load-shed) are live and dependency-free (see PR-2's Status below); the
remaining PR-2 surface is the L4 connection cap, FD-ulimit docs, and the
at-scale overload load test, all interlinked with PR-7. **PR-4
(transport & trust-boundary hardening) is now complete** — configurable
ingress TLS floor (1.2 default, 1.3 opt-in), a CI gate proving every
outbound client verifies certificates, trusted-proxy config, and a per-hop
TLS/mTLS matrix doc (its remaining surface is the staging TLS scan and the
mesh-wiring Helm path). The rest of the operational/release surface below
remains open. Each work item carries its own
`Status:` line; update it in place as work lands, same convention as
`spec.md`'s playbook.

This spec follows the project's documentation convention: when a work item
ships, record it in the three canonical places (`CHANGELOG.md` `[Unreleased]`,
the relevant `docs/specs/` Status block here, and `README.md`), and land
every behavior change with a regression test.

## How to read this

Work items are labelled `PR-N` and grouped by track. Each item states:

- **Priority** — P0 (blocks production), P1 (blocks GA / first design
  partner), P2 (fast-follow, can trail the first deploy by weeks).
- **Goal / Why** — the one-sentence outcome and the risk it removes.
- **Current state** — what exists today, with file references, so the diff
  is surgical.
- **Spec** — the required end state, concretely.
- **Acceptance** — the verifiable done criteria (tests, drills, gates).
- **Effort** — rough engineering estimate.
- **References** — external standards / prior art the spec is grounded in.

The **Go-Live Gate** (§ end) is the checklist that must be fully green before
`/oauth/bridge/callback` (or any IdP-facing route) is exposed to untrusted
networks.

---

## Track A — Security blockers (P0)

These are the items that make it *unsafe* to expose Proxilion today. None
may be waived for a production deploy.

### PR-1 — Federation token signature verification (the showstopper)

**Priority:** P0. **Effort:** 3–5 days.

**Status (2026-06-19): in progress — verification primitive landed
(Approach A chosen).** The cryptographic core is implemented and tested:
`oauth::idp_verify::verify_id_token`
([idp_verify.rs](../../crates/proxy/src/oauth/idp_verify.rs)) verifies an
`id_token` signature with the algorithm **pinned server-side** to an operator
allow-list (RS256/ES256 default; `none`/HS\* impossible), enforces
`iss`/`aud`/`exp`/`nbf` with ≤ 60 s skew, fail-closed. Eleven unit tests pin
the RFC 8725 / RFC 9700 rejections (tampered payload, `alg:none`,
RS256→HS256 confusion, expired/`nbf`-future, unknown `iss`/`aud`, symmetric or
empty allow-list). The **JWKS fetch + `kid`-rotation layer**
([jwks.rs](../../crates/proxy/src/oauth/jwks.rs)) is also landed:
`JwksResolver` resolves `jwks_uri` + `kid` → `DecodingKey` with an HTTPS-only
fetch, TTL cache, refresh-once-on-unknown-`kid` (throttled per endpoint to
avoid a thundering-herd DoS), fail-closed; five tests incl. the end-to-end
resolve→verify chain. **Design note:** we verify with `jsonwebtoken` directly
rather than calling upstream `provenance-bridge`'s `JwtHandler::validate` — at
the SHA we pin, that handler selects the algorithm from the *token header* and
never enforces its allow-list (the confusion pattern this PR exists to kill),
so reusing it verbatim would be unsafe. The **production-boot guard** is also
landed: `PROXILION_ENV` (`development`/`staging`/`production`) +
`Config::federation_boot_refusal`; a protected env refuses to boot
(`server::run` fails closed) while the insecure payload-only stub is active —
the hard-fail successor to the §0.4 boot `warn!`. **Still open before this P0
closes:** the OAuth-callback rewiring to mint PCA_0 from the verified identity
via Trust Plane `POST /v1/pca/issue` (needs a live Trust Plane to smoke) and to
flip `insecure_bridge_stub` off, deleting/gating the payload-only
`validate_federation_token` path, replacing the `alg:none` fixtures, and
`scripts/smoke-pic.sh`.

**Goal.** No request may mint or carry authority on the strength of an
**unverified** token. Every token that establishes the human principal
(`p_0`) and its ops set must have its signature cryptographically verified
against a trusted key before any PCA is issued or any session is bound.

**Why.** Today `GET /oauth/bridge/callback`
([oauth/routes.rs:28](../../crates/proxy/src/oauth/routes.rs#L28) →
`bridge_callback` → `validate_federation_token`) accepts the federation JWT
**payload-only**: it base64-decodes the claims, checks `exp`/`iat`, and
trusts `pca_0_id`, `p_0`, and `ops` without verifying the signature
([oauth/bridge.rs:74](../../crates/proxy/src/oauth/bridge.rs#L74)). The test
fixtures even sign with `alg:none`
([oauth/bridge.rs:105](../../crates/proxy/src/oauth/bridge.rs#L105)). Anyone
who can reach that callback can forge an arbitrary human principal and an
arbitrary ops set — which **defeats the entire confused-deputy thesis of the
product.** The proxy emits a loud boot `warn!`
([server.rs:282](../../crates/proxy/src/server.rs#L282)) precisely because
this route must not be exposed in production as-is.

**Current state / what we get for free.** Upstream
`clay-good/provenance` ships `crates/provenance-bridge`, which is
*library-only* (no `main.rs`) but **already contains a complete JWT
credential handler** (`handlers/jwt.rs`): it fetches the IdP JWKS (1-hour
cache), matches `kid`, builds an RSA/EC decoding key, verifies the signature
with `jsonwebtoken::decode`, and checks `iss`/`aud`/`exp`/`nbf` with
configurable per-issuer algorithms (defaulting to RS256/ES256). The
`FederationBridge` type is a `CredentialHandler` registry with
`validate(credential, type)` / `validate_auto(credential)`. Proxilion
previously depended on `provenance-bridge` and removed it as unused
([Cargo.toml](../../Cargo.toml) note); `provenance-core` is already pinned by
SHA, establishing the pattern.

There are **two** distinct tokens in the federation path, and the spec must
be explicit about which key verifies which:

1. **IdP token** — the Okta / Azure AD / Google Workspace / OIDC `id_token`.
   Verified against the **IdP's** published JWKS (`jwks_uri` from OIDC
   discovery). This is exactly what upstream `handlers/jwt.rs` does.
2. **Bridge→proxy callback token** — the JWT delivered to
   `/oauth/bridge/callback` carrying `pca_0_id`/`p_0`/`ops`
   (`FederationClaims`). Verified against the **bridge's** signing key. This
   is the token `validate_federation_token` trusts blindly today.

**Spec.** Choose one of two architectures; **Approach A is recommended.**

- **Approach A (recommended): in-process federation, no callback token to
  forge.** Re-add `provenance-bridge` as a SHA-pinned git dependency (same
  mechanism and review discipline as `provenance-core` — a single
  reviewed `rev =` line in `Cargo.toml`). Fold federation into the proxy:
  after the IdP redirects back, the proxy calls the upstream JWT
  `CredentialHandler` **in-process** to verify the IdP `id_token` against the
  IdP JWKS (signature + `iss`/`aud`/`exp`/`nbf`, algorithm **pinned** to an
  allow-list — never read `alg` from the token, never accept `none`/HS\*),
  then calls Trust Plane `POST /v1/pca/issue` to mint PCA_0 from the verified
  principal + ops. Because issuance now happens in-process from a
  *verified* identity, **the bridge→proxy callback token (#2) ceases to
  exist** — there is no second hop and nothing to forge. The
  `FederationClaims` / `validate_federation_token` payload-only path is
  deleted (or retained only behind an explicit, default-off
  `PROXILION_INSECURE_BRIDGE_STUB=1` dev flag that refuses to start when
  `PROXILION_ENV=production`).

- **Approach B: standalone bridge service.** Publish a thin
  `provenance-bridge-bin` (upstream) or a small `crates/federation-bridge`
  binary in this repo that wraps the library as an HTTP service, signs the
  callback JWT with its own key, and **publishes a JWKS**. The proxy then
  verifies the callback token via `jsonwebtoken::decode` with the algorithm
  **pinned** (Ed25519/EdDSA or RS256), `iss`/`aud`/`exp`/`nbf` enforced, and
  a cached JWKS keyed by `kid` with rotation support (see PR-3). Choose this
  only if you need many proxy replicas fanning into one federation point, or
  federation decoupled from the proxy release cycle.

Either approach MUST satisfy these invariants (grounded in RFC 8725 / RFC
9700):

- **Algorithm allow-list, server-side.** The set of acceptable `alg` values
  is configured by the operator and enforced by the verifier; the token's
  own `alg` header is never trusted to select the verification algorithm.
  `none` is never acceptable; HS\* is never acceptable for an asymmetric
  trust relationship (defeats the RS256→HS256 confusion attack).
- **Full claim validation.** `iss` matches a configured trusted issuer;
  `aud` matches Proxilion's configured audience; `exp`/`nbf` enforced with a
  bounded clock-skew (≤ 60 s); reject tokens missing required claims.
- **JWKS hygiene.** JWKS fetched over TLS from the discovery `jwks_uri`,
  cached with a TTL aligned to the IdP rotation cadence, refreshed on
  unknown-`kid` (with negative-cache + rate-limit to avoid a thundering-herd
  DoS against the IdP), old keys honored through a rotation grace window.
- **Fail-closed.** Any verification failure → `401`/`403`, a persisted
  blocked/denied audit row, and a metric increment — never a fall-through to
  the trusted path.
- **No production boot with the stub.** Remove the conditions that make
  server.rs emit the §0.4 `warn!`; replace with a hard refusal to mount any
  IdP-facing route while an insecure stub is active and `PROXILION_ENV` is
  `production`/`staging`.

**Acceptance.**
- New unit + DB-backed tests: a token with a **valid** signature from the
  configured key is accepted and binds the correct `p_0`/`ops`; a token with
  a **tampered payload** (valid-looking claims, wrong/no signature) is
  rejected with a fail-closed audit row; `alg:none` and an RS256-key-as-HS256
  confusion attempt are both rejected; an expired/`nbf`-future token is
  rejected; an unknown `iss`/`aud` is rejected; an unknown `kid` triggers a
  single rate-limited JWKS refresh then rejects if still unknown.
- The existing `alg:none` test fixtures are replaced with properly-signed
  fixtures (a test keypair + a published test JWKS).
- `scripts/smoke-pic.sh` is updated to drive the **verified** path end to
  end and fails if signature verification is bypassed.
- Boot in `PROXILION_ENV=production` with the insecure stub enabled →
  process refuses to start (tested).
- `spec.md` §0.4 / Step 0.4 deviation block updated to "resolved"; the
  README "One known pre-production gap" section removed.

**References.** RFC 8725 (JWT BCP — algorithm pinning, `none`/confusion
mitigations); RFC 9700 (OAuth 2.0 Security BCP, Jan 2025); RFC 7517 (JWK) /
RFC 7515 (JWS); upstream `provenance-bridge/src/handlers/jwt.rs`;
`jsonwebtoken` crate (reuse `DecodingKey`, set `Validation.algorithms`).

---

### PR-2 — Edge abuse & DoS controls

**Priority:** P0. **Effort:** 2–3 days.

**Status (2026-06-19): implemented (application-layer controls).** All four
edge resource-exhaustion controls are live and operator-tunable (each with a
`0` disable sentinel):

1. **Body cap** — `axum::extract::DefaultBodyLimit`, default 10 MiB,
   `PROXILION_MAX_REQUEST_BODY_BYTES`, → `413`, applied before any
   adapter/policy code reads the body.
2. **Per-request timeout** — `tower_http::TimeoutLayer`, default 30 s,
   `PROXILION_REQUEST_TIMEOUT_SECS`, → `408`, scoped to the agent-facing
   Drive/Gmail/Calendar adapter routes (deliberately NOT the long-lived
   SSE/streaming-export routes).
3. **Per-IP rate limit** — an in-house token bucket
   ([edge.rs](../../crates/proxy/src/edge.rs)), default 50 req/s + 100 burst,
   `PROXILION_RATE_LIMIT_PER_SEC` / `PROXILION_RATE_LIMIT_BURST`, →
   `429`+`Retry-After`. Keyed on a **trusted-proxy-aware** client IP: the
   `X-Forwarded-For` chain is believed *only* when the direct TCP peer is a
   configured trusted proxy (`PROXILION_TRUSTED_PROXIES`, default empty =
   trust nothing), walked right-to-left so an attacker-spoofed prefix is
   ignored. Bucket table bounded (100k cap, 10-min idle eviction).
4. **Concurrency limit + load-shed** — a `tokio::sync::Semaphore`-backed global
   in-flight ceiling ([edge.rs](../../crates/proxy/src/edge.rs)), default 1024,
   `PROXILION_MAX_CONCURRENT_REQUESTS`, → `503` via `try_acquire` (fail-fast,
   never a queue).

All four rejections increment `proxilion_ingress_rejections_total{reason}`
(`body_limit`/`timeout` counted at the outermost edge middleware;
`rate_limit`/`load_shed` counted at their shed site because their statuses are
shared with upstream-rate-limit / `/healthz`-readiness responses). The
rate-limit and load-shed controls were implemented **dependency-free** (token
bucket on `moka`, semaphore on `tokio` — both already in the tree) rather than
pulling `tower_governor`; the security-critical trusted-proxy keying is cleaner
to own than to bend a third-party key extractor around. See
[server.rs](../../crates/proxy/src/server.rs),
[edge.rs](../../crates/proxy/src/edge.rs), and
[config.rs](../../crates/proxy/src/config.rs).

**Still open (deferred to PR-7 / PR-13):** per-principal/per-session rate
limiting (a documented fast-follow; per-IP is the P0), the L4 connection /
TLS-handshake cap at the `axum-server` layer, the FD-ulimit deployment
documentation, and the overload-shedding **load test** that exercises these
controls at scale (PR-7's acceptance gate). The concurrency limit is
per-replica; whether per-IP rate state must be centralized across replicas is
the PR-7 statelessness-audit decision.

**Goal.** A single agent, tenant, or unauthenticated caller cannot exhaust
the proxy's CPU, memory, file descriptors, or upstream/IdP quota.

**Why.** Proxilion is in the synchronous hot path of every agent request and
terminates TLS for untrusted callers. Today there is a **per-policy burst
limiter** at the policy layer (`notifier/burst`, per-policy buckets) and
adapter-side response caps (`MAX_BODY = 10 MiB`,
[google_calendar.rs:36](../../crates/proxy/src/adapters/google_calendar.rs#L36),
via `read_bounded`), but there is **no edge rate limit, no global concurrency
limit / load-shed, and no ingress request-body cap** on the agent→proxy
direction. An attacker can open unbounded concurrent requests or POST
unbounded request bodies before policy ever runs.

**Current state.** Graceful shutdown with a 30 s drain exists
([server.rs:313](../../crates/proxy/src/server.rs#L313)); outbound reqwest
clients set timeouts; ingress has no `DefaultBodyLimit`, no
`tower_governor`/IP rate limit, no `GlobalConcurrencyLimit`/`LoadShed`, and no
blanket per-request `TimeoutLayer` on the agent-facing router.

**Spec.**
- **Ingress body cap.** Apply `axum::extract::DefaultBodyLimit` (or
  `tower_http::limit::RequestBodyLimitLayer`) on the agent-facing router,
  default 10 MiB to match the adapter response cap and `spec.md` §15.6,
  operator-configurable. Oversize → `413`.
- **Per-request timeout.** A `tower_http::timeout::TimeoutLayer` (or
  `tower::timeout`) on the agent-facing router, default 30 s, configurable;
  distinct from the upstream-call timeout. Health/readiness routes exempt.
- **Rate limiting.** `tower_governor` keyed by client IP (honoring a
  configured trusted-proxy header allow-list — never trust
  `X-Forwarded-For` blindly), with a global limiter as the backstop.
  Sensible default quota + burst, operator-tunable per the existing config
  layering. `429` with `Retry-After`. Per-principal/per-session limiting is a
  fast-follow; per-IP is the P0.
- **Concurrency + load-shed.** A `GlobalConcurrencyLimitLayer` sized from
  the connection-pool and CPU budget, fronted by `LoadShed` so excess load
  returns `503` fast rather than queueing into memory exhaustion.
- **Connection limits.** Cap accepted TCP connections / TLS handshakes at
  the `axum-server` layer; document FD ulimit requirements.
- Every shed/limited/over-cap event increments a labelled metric (feeds the
  PR-5 SLOs) and is sampled into structured logs (not one-per-request).

**Acceptance.** Load test (PR-7) demonstrates the proxy sheds to `503`/`429`
under overload instead of OOMing or unbounded latency; an oversize body is
rejected with `413` before adapter code runs; a single IP exceeding quota
gets `429`+`Retry-After`; metrics for each control are present and wired to a
Grafana panel. Unit tests for the body cap and rate-limit key extraction
(including spoofed `X-Forwarded-For` rejection).

**References.** `tower_governor`, `tower_http` (`limit`, `timeout`),
`tower` (`limit`, `load_shed`); OWASP API Security Top 10 (API4: Unrestricted
Resource Consumption).

---

### PR-3 — Key management, rotation & in-memory hygiene

**Priority:** P0. **Effort:** 3–4 days.

**Status (2026-06-19): in progress — memory hygiene + inventory landed.**
The decoded HMAC key material is now scrubbed on drop: `SiemHmacKey` and
`WebhookSecret` wrap their bytes in `zeroize::Zeroizing` with explicit
redacting `Debug` impls ([siem.rs](../../crates/proxy/src/forwarder/siem.rs),
[webhook.rs](../../crates/proxy/src/notifier/webhook.rs)); the
token-encryption key was already scrubbed (inside `Aes256Gcm`, no `Debug`).
A new [docs/ops/key-inventory.md](../ops/key-inventory.md) enumerates and
classifies every secret the proxy holds. **Production secret sourcing** is
also landed: every secret reads from `<VAR>_FILE` (Docker/K8s mounted-secret
convention) in preference to the env var, enabling External Secrets / Vault /
KMS-backed Secret mounts (`secret_env` in
[config.rs](../../crates/proxy/src/config.rs)). **Still open before this P0
closes:** versioned keys with rotation overlap (`kid`/version, add → flip →
drain → retire; lazy/`proxilion-cli` re-wrap for the token-encryption key),
KMS envelope encryption for the DEK, and the per-key rotation runbooks
(with PR-6).

**Goal.** Every signing/encryption secret can be rotated without downtime,
is sourced safely in production, and does not linger in process memory longer
than needed.

**Why.** Proxilion holds several long-lived secrets: the token-encryption
key (`PROXILION_TOKEN_ENCRYPTION_KEY`,
[crypto/token_cipher.rs](../../crates/proxy/src/crypto/token_cipher.rs)),
HMAC keys for signed links / SIEM, operator-token hashing material, and (via
the Helm `secret.yaml`) the Trust Plane CAT key. Today keys are loaded from
hex/env at boot with char-boundary-safe decoders (well-audited), but there is
**no documented rotation path, no key-id (`kid`) versioning for Proxilion's
own keys, and `zeroize` is not applied to decoded key material** (only a
stray comment references it,
[forwarder/siem.rs:805](../../crates/proxy/src/forwarder/siem.rs#L805)). A
leaked key today means a manual, downtime-incurring redeploy with no overlap
window.

**Spec.**
- **Key inventory & classification.** Enumerate every secret (purpose,
  algorithm, length, blast radius, owner) in a new `docs/ops/key-inventory.md`.
- **Versioned keys with overlap.** For each Proxilion-issued
  signature/MAC/encryption secret, support an *active* key plus N
  *also-accept* predecessors selected by `kid`/version, so rotation is:
  add new (also-accept) → flip active → drain grace window → retire old.
  Token-encryption rotation re-encrypts lazily on next touch or via a
  one-shot `proxilion-cli` re-wrap command.
- **Production secret sourcing.** Document and support sourcing from a
  secret manager / mounted file (not just env), with an
  `*_FILE` convention and guidance for Kubernetes Secrets backed by an
  external store (External Secrets Operator / Vault / cloud KMS). Envelope
  encryption (KMS-wrapped DEK) for the token-encryption key is the
  recommended pattern; spec the interface, keep the default file/env path.
- **Memory hygiene.** Wrap decoded key bytes in `zeroize`/`secrecy` types so
  they are scrubbed on drop and excluded from `Debug`. Audit for accidental
  key logging.
- **Rotation runbooks.** One runbook per key (links into PR-6) covering
  planned rotation and emergency (compromise) rotation, including killswitch
  interplay and audit-chain continuity (PIC profile / `kid` on persisted
  PCAs already exists — `spec.md` §15.11).

**Acceptance.** A documented, tested rotation drill for at least the
token-encryption key and one HMAC key completes with **zero rejected
in-flight requests** across the flip. Keys are `zeroize`-wrapped (compile-time
enforced via type, not convention). `proxilion-cli` exposes the re-wrap /
rotation helpers. Emergency-rotation runbook rehearsed in staging.

**References.** OWASP Key Management Cheat Sheet; NIST SP 800-57 (key
lifecycle); `secrecy` / `zeroize` crates; External Secrets Operator; cloud
KMS envelope-encryption patterns.

---

### PR-4 — Transport & trust-boundary hardening

**Priority:** P0. **Effort:** 1–2 days.

**Status (2026-06-19): implemented.** The application-layer and CI/Helm/docs
surface of PR-4 is complete:

- **Ingress TLS floor enforced + configurable.** `build_tls_config`
  ([server.rs](../../crates/proxy/src/server.rs)) builds the rustls listener
  with an explicit protocol-version floor (`PROXILION_TLS_MIN_VERSION`,
  Helm `proxy.tls.minVersion`, default `1.2`, `1.3` opt-in). rustls/aws-lc-rs
  cannot negotiate below 1.2 structurally; cipher suites are rustls defaults
  (AEAD-only). The crypto provider is selected explicitly so the builder is
  self-contained and unit-tested.
- **Outbound cert verification proven by a CI gate.** The new
  [`tls-cert-verification`](../../.github/workflows/tls-cert-verification.yml)
  workflow forbids any production crate from disabling cert/hostname
  verification and forbids an unconditional hardcoded disable anywhere; the
  lone permitted `danger_accept_invalid_certs` is the flag-gated
  `proxilion-cli --insecure` debug opt-in.
- **Trusted-proxy config is the single source of truth** (shared with PR-2's
  rate-limit keying), defaulting to trust-nothing; exposed via
  `proxy.trustedProxies` in Helm.
- **TLS/mTLS matrix per hop, cipher posture, and the public-route list** are
  documented in [docs/ops/tls-mtls-matrix.md](../ops/tls-mtls-matrix.md),
  which also carries the staging `testssl`/`nmap` go-live check.

**Still open:** the staging nmap/testssl scan itself (a go-live execution
step, documented in the matrix), and the mTLS *mesh wiring* recommendation
for proxy↔Trust-Plane / proxy↔NATS is documented but not yet shipped as a
Helm path (interlinks PR-7/PR-11).

**Goal.** Every hop in the deployment is authenticated and encrypted, and
the proxy's own trust assumptions about its network are explicit.

**Why.** The proxy terminates TLS (rustls/aws-lc-rs) and calls Trust Plane,
upstream SaaS, IdP JWKS, NATS, SIEM, Slack, and SMTP. Production needs a
clear statement of which hops require TLS/mTLS, minimum TLS version, and how
the proxy decides a caller is "internal."

**Spec.**
- **TLS floor.** Enforce TLS 1.2+ (prefer 1.3) on ingress; document cipher
  posture (rustls defaults are acceptable — state it). Certificate
  provisioning via cert-manager in the Helm path; `certs/` + `dev-cert.sh`
  remain dev-only.
- **Upstream verification.** Confirm full certificate verification on every
  outbound client (reqwest rustls) — no `danger_accept_invalid_certs`
  anywhere; add a CI grep gate. JWKS/discovery fetches over HTTPS only.
- **mTLS where it counts.** Recommend (and document Helm wiring for) mTLS or
  a mesh (e.g. service-mesh / network policy) between proxy ↔ Trust Plane and
  proxy ↔ NATS, since those carry authority-issuance and the action stream.
- **Trusted-proxy config.** A single source of truth for which forwarded
  headers are trusted (shared with PR-2's rate-limit keying), defaulting to
  *trust nothing* unless an operator declares the front proxy CIDR.
- **Security headers / surface.** Confirm admin/SSE/setup surfaces set
  appropriate `Cache-Control`/`no-store` and are bound to the operator-auth
  tier (already audited); document the public-tier route list as a hardening
  reference (it exists in `server.rs`).

**Acceptance.** CI gate forbids invalid-cert acceptance; Helm values expose
TLS min-version and trusted-proxy CIDR; a deployment doc states the
TLS/mTLS matrix per hop; nmap/testssl run against a staging deploy shows no
TLS < 1.2 and no weak suites.

**References.** Mozilla TLS config (Intermediate); RFC 9700 §4 (network
trust); rustls defaults.

---

## Track B — Operational readiness (P1)

These block GA / the first design partner (`spec.md` M5 outcome) but not a
locked-down pilot.

### PR-5 — SLOs, SLIs, error budgets & alerting

**Priority:** P1. **Effort:** 3–4 days.

**Status (2026-06-20): in progress — SLOs + alert rules landed.** Five SLOs
defined with rationale + windows in [docs/ops/slos.md](../ops/slos.md);
[ops/prometheus/alerts.yml](../../ops/prometheus/alerts.yml) implements 16
alerts + 7 recording rules — Google SRE multi-window multi-burn-rate for the
99.9% availability SLO (fast-burn page / slow-burn ticket), plus federation,
security-invariant, and operational alerts. Every alert carries a
`runbook_url` into [docs/ops/runbooks/](../ops/runbooks/README.md) (first-pass
content; PR-6 expands). `prometheus.yml` loads the rules and a
[`prometheus-rules`](../../.github/workflows/prometheus-rules.yml) CI job runs
`promtool check rules`/`check config`. Latency SLIs use the summary
`{quantile="0.99"}` series (the recorder renders histograms as summaries, no
`set_buckets`). The Grafana dashboard now carries an **SLO/error-budget row**
(availability, error-budget burn, policy-eval p99, federation success, +
multi-window burn-rate panel) in
[ops/grafana/proxilion.json](../../ops/grafana/proxilion.json). **Still
open:** Alertmanager routing wiring and the staging fault-injection burn
drill (the "a synthetic burn fires the page within budget" acceptance check).

**Goal.** Operators get paged on user-impacting conditions *before* the
budget is exhausted, and never on noise.

**Why.** Rich metrics and a bundled Grafana dashboard exist
([ops/grafana/proxilion.json](../../ops/grafana/proxilion.json)), and
Prometheus scrape config exists
([ops/prometheus/prometheus.yml](../../ops/prometheus/prometheus.yml)), but
there are **no SLO definitions and no alerting rules**. You cannot run a
service in production without an alerting contract.

**Spec.**
- **Define SLIs/SLOs** for the user-facing journeys: proxy request
  availability (non-5xx that aren't policy denials), proxy added-latency
  (p99 overhead budget — `spec.md` §9 already targets sub-ms policy eval),
  approval-path liveness (Slack/email round-trip), killswitch propagation
  (≤ one request cycle — `spec.md` M3), and federation/issuance success rate.
  Pick explicit targets (e.g. 99.9% availability, p99 added latency < X ms)
  and document the rationale + measurement window.
- **Multi-window, multi-burn-rate alerts.** Author Prometheus alert rules
  (`ops/prometheus/alerts.yml`) using the Google SRE pattern: fast-burn
  (page: ~2% budget in 1 h, confirmed by a short window) and slow-burn
  (ticket: ~5–10% in 6 h / 3 d). Cover each SLO above plus operational
  signals: JWKS fetch failures (PR-1), rate-limit/load-shed surges (PR-2),
  DB pool saturation, NATS publish failures, blocked-queue backlog growth,
  cert-expiry < 14 d.
- **Routing.** Document Alertmanager routing/severity and link each alert to
  its PR-6 runbook (every alert MUST name a runbook).
- **Dashboard.** Extend the Grafana JSON with an SLO/error-budget row.

**Acceptance.** `promtool check rules ops/prometheus/alerts.yml` passes in
CI; each alert has a runbook link; a synthetic burn (staging fault
injection) fires the fast-burn page within its detection budget; the
error-budget panel renders.

**References.** Google SRE Workbook "Alerting on SLOs" (multi-window
multi-burn-rate); SRE Book Ch. 4 (SLOs); `promtool`.

### PR-6 — Runbooks & incident response

**Priority:** P1. **Effort:** 3–5 days.

**Goal.** An on-call engineer can resolve any paging alert from a written
procedure, and security incidents have a defined response.

**Why.** No runbooks exist. The system has several failure modes unique to
its position (federation outage, killswitch misfire, approval-path wedge —
note the 17th/18th audit found and fixed real burn-before-commit wedge bugs
in exactly this area).

**Spec.** A `docs/ops/runbooks/` set, one per paging alert and per critical
procedure, each with detection → diagnosis → mitigation → verification →
escalation:
- Federation/IdP/JWKS outage (fail-closed behavior, what users see, how to
  confirm it's upstream).
- Trust Plane unavailable / issuance failing.
- Killswitch operation drill (revoke a session/agent and verify
  ≤ one-request-cycle propagation) and **accidental killswitch recovery**.
- Approval-path wedge (Slack `trigger_id` / email single-use token) — detect
  and clear, referencing the resolved audit fixes.
- DB primary failover / connection exhaustion / migration gone wrong.
- Key compromise → emergency rotation (PR-3) and audit-chain implications.
- Certificate expiry / renewal failure.
- NATS / SIEM forwarder backlog or outage (does the proxy fail open or
  closed for the audit stream? — state it explicitly).
- **Security incident response plan**: severity matrix (reuse `SECURITY.md`),
  evidence preservation (audit log is cryptographically verifiable — leverage
  it), comms, and the coordinated-disclosure SLA already in `SECURITY.md`.

**Acceptance.** Every PR-5 alert links to a runbook; the killswitch drill and
the DB-failover drill are executed in staging and the runbooks corrected
against reality; an incident-commander checklist exists.

**References.** Google SRE Book (Emergency Response, Managing Incidents);
PagerDuty Incident Response docs; existing `SECURITY.md`.

### PR-7 — High availability, horizontal scaling & capacity

**Priority:** P1. **Effort:** 4–6 days.

**Goal.** Proxilion runs as N replicas behind a load balancer with no shared
in-process state that breaks correctness, survives a replica loss with no
dropped guarantees, and has a documented capacity model.

**Why.** The Helm chart deploys the proxy
([deploy/helm/proxilion/templates/proxy.yaml](../../deploy/helm/proxilion/templates/proxy.yaml)),
but production HA requires an explicit **statelessness audit**: several
subsystems use in-process caches (`kill_cache`, PCA cache, per-policy burst
buckets, JWKS cache from PR-1). For correctness under multiple replicas, the
killswitch and burst/rate state in particular must be reasoned about — a
revocation must take effect across *all* replicas within the M3 guarantee,
and per-policy burst limits must not silently multiply by replica count.

**Spec.**
- **Statelessness audit.** Classify every in-process cache as (a) safe to be
  replica-local (pure perf cache backed by DB truth), or (b) requires shared
  state / DB-authority / pub-sub invalidation. The killswitch already streams
  via NATS (M3) — confirm revocation invalidates *all* replicas' caches
  (NATS fan-out or short TTL + DB check); document the worst-case propagation
  bound per replica. Decide whether per-policy burst (PR-2 sibling) is
  best-effort-per-replica (documented) or must be centralized.
- **Kubernetes HA.** `replicas >= 2`, readiness gate excludes draining pods,
  `PodDisruptionBudget`, anti-affinity, `HorizontalPodAutoscaler` keyed on
  CPU + a custom in-flight/queue metric, graceful-shutdown drain aligned with
  the LB dereg + the existing 30 s drain.
- **Capacity model.** Document req/s per replica, memory per connection, DB
  connections per replica × replicas vs Postgres `max_connections` (size a
  PgBouncer in front if needed), NATS throughput, and IdP JWKS QPS.
- **Postgres HA** (interlinks PR-8): primary + replica with automated
  failover (e.g. Patroni or a managed HA Postgres); connection pooling.

**Acceptance.** A load test (k6/vegeta) at target req/s across ≥ 2 replicas
sustains the PR-5 latency SLO; killing one replica mid-load drops zero
correctness guarantees (killswitch still propagates within bound;
re-auth/retry behavior documented); a revocation issued to one replica is
enforced by the others within the documented bound (tested); capacity doc
published with the numbers from the run.

**References.** Google SRE (load balancing, addressing cascading failures);
Kubernetes PDB/HPA/anti-affinity docs; Patroni; PgBouncer.

### PR-8 — Backup, restore & disaster recovery

**Priority:** P1. **Effort:** 2–3 days.

**Goal.** Postgres (the system of record for sessions, PCAs, blocked queue,
operator tokens, and the audit log) can be restored to a defined RPO/RTO, and
the restore has actually been performed.

**Why.** Migrations exist (`migrations/0001`–`0014`, applied by
`sqlx::migrate!`), but there is **no documented backup, PITR, RPO/RTO, or
tested restore.** The audit log's value (cryptographically verifiable
history) is zero if it isn't durable.

**Spec.**
- **Backup strategy.** Continuous WAL archiving + periodic base backups
  (pgBackRest recommended: compression, incremental, retention, parallel
  restore) enabling **point-in-time recovery**. State target **RPO** (e.g.
  ≤ 5 min) and **RTO** (e.g. ≤ 1 h) and size the schedule to meet them.
- **Restore drills.** A documented, scheduled restore-to-a-timestamp drill
  into a scratch environment; verify audit-chain integrity post-restore
  (re-run `/api/v1/pca/{id}/verify` sampling).
- **Migration safety.** Document the forward-only migration policy, how to
  roll a deploy back when a migration is incompatible (expand/contract
  pattern), and pre-deploy backup gating.
- **Secrets/DR.** Where the encryption keys (PR-3) live relative to the DB
  backups so a backup alone cannot decrypt stored upstream tokens (don't back
  up the DEK next to the ciphertext).

**Acceptance.** A PITR restore to an arbitrary timestamp completes in staging
within RTO; audit-chain verification passes on the restored DB; the backup
job + retention is in the Helm/ops manifests; runbook (PR-6) references the
exact restore commands; RPO/RTO published.

**References.** PostgreSQL Continuous Archiving & PITR docs; pgBackRest;
Patroni + pgBackRest integration.

---

## Track C — Release engineering & supply chain (P1/P2)

### PR-9 — `v0.1.0` release cut, versioning & compatibility

**Priority:** P1. **Effort:** 1–2 days.

**Goal.** A tagged, reproducible, documented `v0.1.0` that operators can pin,
with a stated compatibility contract.

**Why.** There are **no git tags**; the project explicitly defers SemVer
until `v0.1.0` ([CHANGELOG.md](../../CHANGELOG.md) header). Production
operators must pin a version, not `main`.

**Spec.**
- **Cut `v0.1.0`** once all P0s land. Convert `[Unreleased]` to a dated
  `0.1.0` section; adopt SemVer going forward (the CHANGELOG already promises
  this).
- **Compatibility contract.** Declare what is stable in `0.x`: the config
  surface, the policy YAML schema, the audit-log schema
  ([docs/audit/schema-v1.md](../../docs/audit/schema-v1.md)), the DB
  migration path, the CLI/admin API, the metric names (operators build alerts
  on them — treat renames as breaking). State the MSRV (`rust-version = 1.85`)
  and the upstream `provenance-*` pin policy.
- **Upgrade docs.** A short "upgrading" guide and a deprecation policy.

**Acceptance.** `git tag v0.1.0` on a green commit with release notes; the
release workflow produces artifacts for the tag (PR-10/11); a documented
compatibility/MSRV/upgrade policy lands.

**References.** SemVer 2.0; Keep a Changelog (already used).

### PR-10 — SBOM, build provenance & artifact signing

**Priority:** P1. **Effort:** 2–3 days.

**Goal.** Every released artifact is verifiable: an operator can confirm
*what* is inside it and *that this project's CI built it*.

**Why.** CI already runs `cargo audit --deny warnings` and `cargo deny check`
([.github/workflows/supply-chain.yml](../../.github/workflows/supply-chain.yml)),
and `release.yml` builds + uploads `proxilion-cli`
([.github/workflows/release.yml](../../.github/workflows/release.yml)) — but
there is **no SBOM, no build provenance, and no signatures.** For a security
product this is table stakes.

**Spec.**
- **SBOM.** Generate a CycloneDX SBOM (`cargo-cyclonedx`) for every release
  artifact (CLI + proxy + container images), attach to the GitHub release,
  and embed an auditable dependency list (`cargo auditable`) in the binaries.
- **Build provenance (SLSA).** Emit SLSA build provenance via GitHub's
  artifact attestations / `slsa-github-generator`; target **SLSA Build L3**
  (ephemeral, isolated runners; signed provenance). Document the verification
  command.
- **Keyless signing.** Sign all release artifacts and container images with
  **cosign keyless** (Sigstore Fulcio + Rekor) bound to the repo's GitHub
  Actions OIDC identity; publish verification instructions and (for the Helm
  path) an admission/verify policy operators can adopt.
- **Verification in docs.** A "verify what you downloaded" section in the
  install docs with copy-paste `cosign verify` / `gh attestation verify`
  commands.

**Acceptance.** A release produces: signed binaries + container images, a
CycloneDX SBOM, and SLSA provenance, all attached/attested; the documented
`cosign verify` / `gh attestation verify` commands succeed against a real
release; `cargo auditable` data is present in shipped binaries.

**References.** SLSA v1.0 (Build L3); Sigstore cosign (keyless, Fulcio,
Rekor); CycloneDX; `slsa-github-generator`; GitHub artifact attestations;
`cargo-cyclonedx`, `cargo-auditable`.

### PR-11 — Container images & deployment artifacts

**Priority:** P1. **Effort:** 2–3 days.

**Goal.** A first-class, minimal, multi-arch **proxy** container image is
published and consumed by the Helm chart.

**Why.** `release.yml` publishes the CLI binary only; the Helm chart needs a
published proxy image. `docker/` holds Dockerfiles (trust-plane,
federation-bridge per Step 0.4) but the proxy's production image
publish-and-pin story isn't in release CI.

**Spec.**
- **Proxy image.** Multi-stage build on a pinned base, **distroless/minimal**
  runtime, non-root, read-only root FS, multi-arch (amd64 + arm64), published
  to a registry (GHCR) on tag, **digest-pinned** in the Helm `values.yaml`.
- **Image scanning.** Trivy/Grype scan in CI gating on fixable
  HIGH/CRITICAL; integrate with PR-10 signing/SBOM/provenance (sign the
  image, attach SBOM attestation).
- **Trust Plane / bridge images.** If Approach B (PR-1) is chosen, publish
  pinned images for those too; otherwise document the upstream Trust Plane
  image pin.

**Acceptance.** `helm install` pulls a signed, digest-pinned, multi-arch
proxy image that runs non-root read-only; image scan gate is green; image
carries SBOM + provenance attestations (PR-10).

**References.** Distroless / Chainguard images; Trivy/Grype; OCI image signing
(cosign); Kubernetes Pod Security Standards (restricted).

---

## Track D — Assurance & go-live (P2)

### PR-12 — External security assessment & ASVS mapping

**Priority:** P2 (but must complete before "first design partner" GA).
**Effort:** external + 2–3 days internal.

**Goal.** Independent confirmation that the security claims hold, and a
mapped, gap-assessed control baseline.

**Why.** Proxilion has an exceptional *internal* audit track record (29
multi-subsystem passes; see
[surface-delight-and-correctness.md](./surface-delight-and-correctness.md)),
but no **external** assessment. A product whose entire value is security
should be pentested by someone who didn't write it. `SECURITY.md` already
defines a coordinated-disclosure SLA (72 h ack, severity-based fix windows) —
that part is done.

**Spec.**
- **Threat-model refresh.** Update `spec.md` §10 to reflect the
  post-PR-1 architecture; STRIDE/attack-tree over the federation, approval,
  killswitch, and audit-integrity paths.
- **OWASP ASVS mapping.** Map controls to ASVS L2 (a web app handling
  authority); record gaps as tracked issues.
- **External pentest.** Scope and commission a third-party assessment
  focused on the OAuth/federation boundary (post-PR-1), the approval
  surfaces, multi-tenant isolation, and audit-log integrity; remediate
  findings; publish a summary.
- **Fuzzing.** Add `cargo-fuzz` targets for the parsers on the attack
  surface (JWT/JWKS decode, policy match-expr, CBOR/COSE PCA decode, audit
  body canonicalization) and run them in CI nightly.

**Acceptance.** Threat model updated; ASVS L2 gap list triaged to zero
criticals; external pentest completed with criticals/highs remediated;
fuzz targets in CI with no open crashers.

**References.** OWASP ASVS 4/5.0; OWASP API Security Top 10; STRIDE;
`cargo-fuzz`; RFC 9700.

### PR-13 — Production deployment guide & go-live (PRR)

**Priority:** P2. **Effort:** 2–3 days.

**Goal.** A new operator can stand up a production-grade Proxilion from one
authoritative guide, and there is a formal go-live gate.

**Why.** Install fragments exist
([docs/install/](../../docs/install/), Helm `README.md`), but there is no
single production deployment guide or production-readiness review.

**Spec.**
- **Deployment guide.** End-to-end: sizing (PR-7), Postgres HA + backups
  (PR-8), secret sourcing + rotation (PR-3), TLS/mTLS (PR-4), IdP/federation
  setup (PR-1), policy authoring, observability wiring (PR-5), upgrade/rollback
  (PR-9), and artifact verification (PR-10/11).
- **Config reference.** Generate/maintain a complete, authoritative config
  reference (every env var / Helm value, default, security note) from the
  config struct ([config.rs](../../crates/proxy/src/config.rs)).
- **Go-live checklist (PRR).** A signed-off production-readiness review (see
  the Go-Live Gate below) required before exposing any IdP-facing route.

**Acceptance.** A fresh staging environment is brought up *solely* from the
guide and passes the Go-Live Gate; the config reference matches `config.rs`
(CI drift check); the PRR checklist is filled and signed for the first deploy.

**References.** Google SRE PRR (Production Readiness Review) model.

---

## Go-Live Gate (Production Readiness Review)

Do **not** expose `/oauth/bridge/callback` or any IdP-facing route to an
untrusted network until **all P0** are green and the P1 items below are
satisfied:

- [~] **PR-1** Federation token signatures verified; no payload-only trust;
      production boot refuses the insecure stub; `alg:none`/confusion
      rejected. *Verification primitive + JWKS/`kid`-rotation layer +
      production-boot stub-refusal guard landed + tested (`oauth::idp_verify`
      algorithm-pinned rejections; `oauth::jwks` HTTPS-only
      fetch/cache/rotation/throttle; `PROXILION_ENV` boot refusal); remaining:
      callback→Trust-Plane issuance rewiring, `alg:none` fixture replacement,
      e2e smoke.*
- [~] **PR-2** Ingress body cap, per-request timeout, per-IP rate limit
      (`429`+`Retry-After`, trusted-proxy XFF), concurrency limit + load-shed
      (`503`) all active at the application layer. Remaining: L4 connection cap
      + FD-ulimit docs + at-scale overload load test (interlinks PR-7).
- [~] **PR-3** Keys `zeroize`-wrapped; documented, tested zero-downtime
      rotation; production secret sourcing. *Memory hygiene (HMAC keys
      `Zeroizing` + redacted `Debug`; token key already scrubbed), key
      inventory doc, and `*_FILE` secret sourcing landed; remaining:
      versioned-key rotation overlap, KMS envelope, rotation runbooks.*
- [~] **PR-4** TLS ≥ 1.2 enforced (1.3 opt-in); outbound cert verification
      proven (CI gate); trusted-proxy config explicit; per-hop TLS/mTLS
      matrix documented. Remaining: staging nmap/testssl scan + mesh-wiring
      Helm path (interlinks PR-7/PR-11).
- [~] **PR-5** SLOs defined; burn-rate alerts firing correctly; every alert
      → runbook. *SLOs + 16 alerts/7 recording rules landed (multi-window
      multi-burn-rate), every alert links a runbook, `promtool` CI gate added;
      remaining: Grafana SLO row, Alertmanager routing, staging burn drill.*
- [ ] **PR-6** Runbooks for every paging alert; killswitch + DB-failover
      drills executed.
- [ ] **PR-7** ≥ 2 replicas; statelessness audit done; killswitch propagates
      across replicas within bound; capacity model published.
- [ ] **PR-8** PITR restore drill passed; RPO/RTO met; audit-chain verified
      post-restore.
- [ ] **PR-9** `v0.1.0` tagged; compatibility/MSRV/upgrade policy published.
- [ ] **PR-10/11** Signed, SBOM'd, provenance-attested, scanned artifacts;
      proxy image published + digest-pinned.
- [ ] **PR-12** Threat model refreshed; ASVS L2 zero-criticals; external
      pentest criticals/highs remediated (required for GA / first design
      partner, may trail a locked-down pilot).
- [ ] **PR-13** Deployment guide + config reference + signed PRR.

## Out of scope (explicitly deferred to v2)

Per `spec.md` §15, these are **not** production-readiness blockers and are
intentionally excluded from M5: per-business-unit signing keys / full
multi-tenancy (§15.3), WebAuthn/passkeys for operators (§15.4, v1 is
password + TOTP), refresh-token issuance to the agent (§15.5), streaming
(non-buffered) body filtering above the 10 MiB cap (§15.6), first-class SAML
in the federation bridge (§15.7), and strict single-PIC-profile chain
*enforcement* (§15.11, today surfaced for audit). Also deferred: the
`ApproveBody.ttl_minutes` enforcement (blocked upstream on PIC §6.6 — do not
build unprompted).

## Suggested sequencing

1. **P0 security** in parallel: PR-1 (critical path, start first), PR-2,
   PR-3, PR-4.
2. **P1 operational**: PR-5 + PR-6 together (alerts need runbooks), then
   PR-7 + PR-8 (HA and DR interlink at Postgres).
3. **P1 release**: PR-9 → PR-10 → PR-11 (tag, then sign/SBOM, then images).
4. **P2 assurance**: PR-12 (external, long lead — kick off early once PR-1
   lands so the pentest hits the real architecture) and PR-13 (writes up
   everything above).

---

## Research provenance

The external standards and current-version facts this spec is grounded in
were gathered 2026-06-19:

- **JWT/JWKS:** RFC 8725 (JWT BCP), RFC 7517/7515, RFC 9700 (OAuth 2.0
  Security BCP, Jan 2025); `jsonwebtoken` (Keats) crate; algorithm-confusion
  (`none`, RS256→HS256) mitigations. Upstream `provenance-bridge` already
  implements a complete JWKS-verifying JWT handler (verified against the repo
  on `main`).
- **SRE/SLO:** Google SRE Workbook "Alerting on SLOs" (multi-window
  multi-burn-rate); SRE Book Ch. 4 + Emergency Response.
- **Supply chain:** SLSA v1.0 (Build L3); Sigstore cosign keyless
  (Fulcio/Rekor); CycloneDX; `slsa-github-generator`; GitHub artifact
  attestations; `cargo-auditable`, `cargo-cyclonedx`.
- **Datastore DR/HA:** PostgreSQL Continuous Archiving & PITR; pgBackRest;
  Patroni; PgBouncer.
- **Proxy hardening:** `tower_governor`, `tower_http` (limit/timeout),
  `tower` (load_shed/concurrency); OWASP API Security Top 10.
- **Assurance:** OWASP ASVS; `cargo-fuzz`.
