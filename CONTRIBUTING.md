# Contributing to Proxilion

Issues and PRs welcome. There's no CLA; contributions land under the
repository's MIT license. The bar for review is: does this make the
security posture stronger, the operator surface easier to live with,
or the upstream-Google adapter set more useful — without growing the
binary or the configuration surface unnecessarily.

If you're reporting a security vulnerability, **read
[SECURITY.md](SECURITY.md) first** — please don't open a public
GitHub issue for it.

## Where the design lives

Specs are the source of truth, the code follows them, not the other
way around. If you're proposing a behavior change, expect the review
to start with "where does the spec say that?" — and the answer can
absolutely be "it doesn't yet, here's the diff."

- [docs/specs/spec.md](docs/specs/spec.md) — primary spec. M0–M5
  milestones, the PIC integration, OAuth interception, threat model.
- [docs/specs/ui-less-surfaces.md](docs/specs/ui-less-surfaces.md) —
  the three surfaces (Prometheus `/metrics`, `proxilion-cli`,
  Slack / email / webhook approvals) and the notifier shapes.
- [docs/specs/qiuth-patterns.md](docs/specs/qiuth-patterns.md) —
  five cross-cutting patterns ported from
  [qiuth](https://github.com/clay-good/qiuth): `ConfigBuilder`,
  `PolicyTrace`, `ErrorCode` registry, `PolicyLoader` trait,
  coverage gate. Each section has a Status block with what's shipped.
- [docs/specs/](docs/specs/) — the spec files have **deviation** and
  **open question** blocks. Anything you ship that changes a
  documented deviation should also update the spec text in the same
  PR so the docs don't drift.

## Local dev setup

You need: Rust 1.85+ (the workspace pins `rust-toolchain.toml`),
Docker + Docker Compose, `psql` (or `docker exec` into the postgres
container), `git`, and on macOS, the standard `xcode-select`
tooling. We test on Linux + macOS; Windows works through WSL2 but
isn't routinely exercised.

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

The `docker compose` stack is the same one CI uses. If your change
needs a new service, add it to `docker-compose.yml` *and* update the
compose smoke in `.github/workflows/` (we don't want CI green and
local broken or vice-versa).

## What CI gates on

Four workflows in `.github/workflows/`:

| Workflow | What it runs | Where it lives |
|---|---|---|
| `ci.yml` | `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --workspace --locked`, `cargo build --release` | [.github/workflows/ci.yml](.github/workflows/ci.yml) |
| `coverage.yml` | `cargo llvm-cov` with a 60% / 60% floor | [.github/workflows/coverage.yml](.github/workflows/coverage.yml) |
| `cargo-audit.yml` | `cargo audit --deny warnings` on PRs, push, weekly cron, manual | [.github/workflows/cargo-audit.yml](.github/workflows/cargo-audit.yml) |
| `static-html-no-js.yml` | Lints the one server-rendered HTML page to keep it script-free | [.github/workflows/static-html-no-js.yml](.github/workflows/static-html-no-js.yml) |

Run them locally before pushing:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- \
    -D warnings \
    -A clippy::type_complexity \
    -A clippy::too_many_arguments \
    -A clippy::result_large_err
cargo test --workspace --locked
cargo audit --deny warnings    # cargo install cargo-audit
```

The three clippy `-A` flags are codebase-style choices documented in
[.github/workflows/ci.yml](.github/workflows/ci.yml). All other
warnings are errors. Prefer a per-site `#[allow(clippy::lint_name)]`
with an inline justification over expanding the workspace-level
allow list — the next contributor needs to know *why* we don't care
about a given lint at that site.

## Style

- **Comments.** Sparse, only where the *why* is non-obvious. Don't
  explain *what* — names already do that. Don't reference the
  current task / PR / issue number in comments; that belongs in
  commit messages and rots in code. The spec files cite line ranges
  back into the code as anchors — those *are* useful and worth
  keeping.
- **Error shapes.** Add a variant to
  [`shared_types::ErrorCode`](crates/shared-types/src/error_code.rs)
  rather than threading a new string code. Snapshot test
  `wire_strings_are_stable` will fail loudly if you rename anything
  published.
- **Logging.** `tracing::info!` for state transitions worth
  reading at p99; `warn!` for recoverable badness;
  `error!` reserved for truly exceptional. No `println!` outside
  of the CLI's user-facing output and the demo scripts.
- **Metrics.** Counter names are `proxilion_<noun>_<verb>_total`.
  Labels are bounded enums; never label by free-form strings
  (`policy_id` is the only label where the customer's YAML
  controls cardinality, and that's documented in
  [ui-less-surfaces.md §3.3](docs/specs/ui-less-surfaces.md)).
- **SQL.** Migrations are numbered, additive, and idempotent
  (`ADD COLUMN IF NOT EXISTS`, etc.). Backward-compat lives at the
  schema layer; new columns are nullable until the read path is
  ready, then `NOT NULL` in a follow-up migration once the
  write path is fully rolled out.

## Tests

- **Unit tests** live next to the code as `#[cfg(test)] mod tests`.
  They should be runnable without postgres, without network,
  without a fixture filesystem (use `tempfile` if you need files).
  ~80% of the test surface is here.
- **Integration tests** live in `crates/<x>/tests/`. They're
  allowed to compose multiple modules of the same crate but still
  shouldn't require external services. Use `wiremock` (already in
  dev-deps) for HTTP-shaped uplinks.
- **Stress scripts** live in `scripts/stress-*.sh`. They drive
  against a live `docker compose` stack, exercise real network /
  DB paths, and assert against the live metrics + audit rows.
  Treat them as "the test we'd run before a release cut" — slower
  than unit tests, more end-to-end honest.

If your change touches a behavior the existing tests cover, you
should be adding to that suite, not creating a parallel one. If
there's no test for what you're about to change, add one *before*
the change so we have a passing baseline to compare against.

## Commit style

Look at `git log --oneline` to see the shape — a one-line summary
prefixed with the area you touched, e.g.:

```
ui-less-surfaces + qiuth-patterns + spec follow-throughs: ConfigBuilder, PolicyTrace, ...
```

For larger PRs, follow with a body explaining the *why* and any
non-obvious *what*. The pattern in recent commits is:

- **What's new** (one paragraph)
- **Why** (the spec section or operational story)
- **Tests** (counts, what's now green)
- **Deviations** (anything that diverges from the spec sketch)

Squash-merge is fine; we don't enforce sign-off (no DCO, no CLA).

## Where to start

- Look for items in
  [docs/specs/spec.md §15](docs/specs/spec.md) and
  [docs/specs/ui-less-surfaces.md §11](docs/specs/ui-less-surfaces.md)
  labelled "Open" — those are the deliberately-unanswered design
  questions.
- Check the `**Deviations**` blocks throughout the specs; many close
  out by reference to a follow-up that's still doable.
- The `proxilion-cli` command tree
  ([ui-less-surfaces.md §4.1](docs/specs/ui-less-surfaces.md)) lists
  the full operator surface — gaps there are easy to scope.
- A new SaaS adapter (Slack, Notion, Jira, Salesforce) follows the
  template in `crates/proxy/src/adapters/google_*.rs` — Layer-A ops
  atom + Layer-B policy match + read filter + action stream. The
  Calendar adapter is the smallest, look at it first.

## Out of scope by design

Don't open a PR for these without prior discussion in an issue —
they're intentional non-goals, not gaps:

- A web dashboard. The "ui-less" pivot is the product. The single
  approve / reject HTML landing page in
  [crates/proxy/static-html/](crates/proxy/static-html/) is the
  exception; a [`static-html-no-js`](.github/workflows/static-html-no-js.yml)
  workflow keeps it from drifting into a SPA.
- Telemetry / phone-home. The proxy never emits a packet to a
  Proxilion-owned domain. Metrics are scraped by the customer's
  Grafana. There is no `cloud.proxilion.com`.
- Multi-tenant SaaS hosting. Proxilion is self-hosted only; it sees
  the customer's OAuth tokens and PCA chain material. A hosted
  shape isn't part of v1 and changes the threat model substantially.
- Per-platform integrations that aren't documented in the spec.
  Slack-bot-token support, OTLP push, an integrations marketplace —
  these are tracked as decision-resolved "v2 if a customer asks";
  shipping unused egress code violates the [spec.md](docs/specs/spec.md)
  §0 "no speculative features" rule.
- Dependencies that pull in a JIT, a sandboxed VM, or a JS runtime.
  Anything that grows the supply-chain surface by an order of
  magnitude. The PIC implementation and Rego policy engine are
  the largest we accept; both are pinned and reviewable.
