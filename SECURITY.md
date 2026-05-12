# Security policy

Proxilion is a security tool. The threat model is in [docs/specs/spec.md](docs/specs/spec.md) §10; the deployment-side
trust model is in the README's "Trust model in one paragraph" section. This
file covers how to report something we don't already know about.

## Reporting a vulnerability

**Do not open a public GitHub issue for a suspected vulnerability.** Most
of Proxilion's risk surface (OAuth bearer brokerage, PCA chain integrity,
operator-token scope checks, signed-URL approvals) is hot-path code where
a stray writeup can become an exploit recipe before the fix lands.

Send reports to **`hi@claygood.com`** with subject prefix `[proxilion-sec]`.
Include:

- A minimal reproduction (a `curl` against a default `docker compose`
  bring-up is ideal — see [Quickstart](README.md#quickstart)).
- The affected commit SHA or release tag.
- Your assessment of impact (DoS, info-leak, auth bypass, chain forgery,
  privilege escalation, etc.) — even rough is fine.
- Whether you have a CVE reservation or want us to coordinate one.

If you prefer encrypted reporting, request the PGP key in your first
mail and we'll send it before any sensitive detail is exchanged.

## What we commit to

- **Acknowledge within 72 hours.** Most reports get a same-day reply;
  the 72-hour ceiling is the worst case (weekend / travel).
- **Triage within 7 days.** Confirmed, reproducible, or sent back for
  more detail. We'll tell you which.
- **Patch on a schedule proportional to severity:**
  - **Critical** (chain forgery, auth bypass, RCE): patch + advisory
    within 7 days. Coordinated disclosure preferred.
  - **High** (DoS of a deployed proxy, operator-scope bypass, secret
    exfiltration): 14 days.
  - **Medium / Low**: 30 days, may be batched into a release.
- **Credit you in the advisory** unless you tell us not to. Names,
  handles, and links are all fine.
- **Won't sue, won't threaten.** Good-faith research under the umbrella
  conventions: no DoS against third-party infrastructure (only your
  own Proxilion deployment), no social-engineering of contributors or
  customers, no operational data exfil. If you're a researcher acting
  in good faith and we can verify it, we'll work with you.

## What we won't pay

There is no bug bounty. Proxilion is MIT-licensed open source funded
by no entity. Anyone who wants to fund a bounty program is welcome to
contact us, but we won't accept invoices from researchers in lieu of
that. Disclosure stays free.

## In scope

- The Proxilion proxy binary (`crates/proxy`).
- The `proxilion-cli` operator tool (`crates/cli`).
- The policy engine (`crates/policy-engine`).
- Shared types (`crates/shared-types`).
- The Helm chart in `deploy/helm/proxilion/` and the reference
  `docker-compose.yml`.
- The demo scripts under `demo/` if a vulnerability there would
  trick an operator into a broken security posture on real install
  (e.g. a copy-pasteable insecure example).
- The static approve / reject landing page in `crates/proxy/static-html/`.

## Out of scope

- The upstream PIC reference implementation
  (`provenance-core`, `provenance-plane`). Report those directly to
  the upstream authors at <https://github.com/clay-good/provenance>.
- Vulnerabilities in transitive dependencies that are already tracked
  in `.cargo/audit.toml` with documented unblock conditions, unless
  you have a reproducer demonstrating exploitability in Proxilion's
  code paths. (We do scan via [cargo-audit](.github/workflows/cargo-audit.yml)
  weekly; a report there is a "no, we know" not a "you missed
  something.")
- Operator misconfiguration (a Proxilion deployment running with
  `PROXILION_DISABLE_OPERATOR_AUTH=1` in production, a `policy.yaml`
  with `decision: allow` everywhere). Documented loud-failure modes
  are the contract.
- Self-hosted Slack / email / SMTP relay configuration outside the
  proxy. We document three known-good email setups
  in [docs/install/email.md](docs/install/email.md); customer-specific
  relay bugs go to those relays.
- Findings against versions older than the most recent `main` SHA.
  We don't backport.
- "Best practice" theatre — TLS 1.2 enabled, HSTS not set, CSP could
  be tighter. Open a PR if it's substantive; opening a vuln report
  for it isn't a great use of either of our days.

## What we ship to defend against this report category

The codebase is structured so common report shapes have already been
designed for:

- **Operator-token theft.** Tokens are 52-base32-char opaque bearers
  hashed (`SHA-256`) at rest; only `token_hash` is in the DB. A
  stolen DB doesn't yield usable tokens. ([operator_auth.rs](crates/proxy/src/operator_auth.rs))
- **Replay of signed approval URLs.** Single-use, single-purpose,
  consumed inside a `FOR UPDATE` transaction. Replays return a
  resolved-state 409. ([api/blocked.rs](crates/proxy/src/api/blocked.rs))
- **Slack interaction forgery.** Per-driver signing secret + 5-min
  timestamp window + constant-time HMAC compare. ([notifier/slack.rs](crates/proxy/src/notifier/slack.rs))
- **PCA-chain forgery / replay.** Trust Plane refuses any successor
  whose ops aren't a subset of the predecessor's; the proxy doesn't
  trust its own pca_cache for verification — the `/verify` endpoint
  re-checks signatures against the configured CAT key. ([pic/verifier.rs](crates/proxy/src/pic/verifier.rs))
- **Information leak in error responses.** `AppError::IntoResponse`
  emits fixed-shape redacted bodies; `Bearer` Debug is redacted;
  `TokenCipher` never derives Debug. ([adapters/error.rs](crates/proxy/src/adapters/error.rs))
- **Policy-bypass via YAML edit.** All mutations validate by parsing
  into an `Engine` before swap; failure leaves the live engine alone.
  ([policy_handle.rs](crates/proxy/src/policy_handle.rs))

If your finding lives in one of these areas, lead with the assumption
we've thought about it — we'd love to be wrong, but you'll save a
round-trip by saying which guard you got past.

## Coordinated disclosure

If a customer reports something to you privately and asks you to
coordinate, that's fine — reach out at `hi@claygood.com` first so we
can set the timeline before any third-party advisory text gets
finalized. We'll do the same in the other direction.
