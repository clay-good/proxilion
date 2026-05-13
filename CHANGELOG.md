# Changelog

All notable changes to Proxilion. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
follows [Semantic Versioning](https://semver.org/) once it reaches a
tagged `v0.1.0` (not yet — see [docs/specs/spec.md](docs/specs/spec.md)
§13 milestones).

Until v0.1.0, the canonical reference is the most recent commit on
`main` plus the deviation / status blocks in
[docs/specs/](docs/specs/).

---

## [Unreleased]

### Changed

- **`LogFormat` wired through `Config`** (qiuth-patterns.md §2.3
  follow-through). [crates/proxy/src/main.rs](crates/proxy/src/main.rs)
  now loads `Config` before `init_tracing` and passes `cfg.log_format`
  into the tracing subscriber. Previously `init_tracing` read
  `PROXILION_LOG_FORMAT` directly via `std::env::var`, bypassing the
  layered config — operators could not set `log_format = "pretty"`
  from `proxilion.toml`. The `#[allow(dead_code)]` annotation on
  `Config::log_format` is dropped now that the field has a consumer.

### Removed

- **`Config::from_env()` removed** (qiuth-patterns.md §2.4 Phase 3).
  The Phase 2 backward-compat shim — kept under `#[allow(dead_code)]`
  while callers migrated — had zero remaining call sites
  ([crates/proxy/src/config.rs](crates/proxy/src/config.rs)).
  `Config::load()` is now the single production entry point
  (defaults → optional TOML file → env vars); embed/test callers use
  `ConfigBuilder::defaults()…build()` directly. Module docstring updated.

### Added

- **Public-repo polish.**
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — adopts Contributor
  Covenant 2.1 verbatim with project-specific scope, reporting
  channel (`hi@claygood.com` with `[proxilion-conduct]` prefix),
  and enforcement ladder.
  [.github/ISSUE_TEMPLATE/](.github/ISSUE_TEMPLATE/) — structured
  bug-report and feature-request forms with required fields
  (commit SHA, deploy mode, repro, spec section). Blank issues
  disabled to force structured context up front; security
  vulnerabilities redirected to SECURITY.md.
  [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md)
  — what's-new / why / tests / deviations / pre-flight checklist.
  [Justfile](Justfile) — `just ci` runs every local CI gate;
  `just install-tools` one-shots the dev-tool installs;
  `just demo`, `just smoke`, `just up`, `just nuke` for common
  compose operations.
- **Repository docs.**
  [SECURITY.md](SECURITY.md) — vulnerability disclosure policy with
  private reporting address, response SLAs, in-scope / out-of-scope
  enumeration, and the existing-defense catalogue.
  [CONTRIBUTING.md](CONTRIBUTING.md) — spec-first contribution
  model, full CI gate matrix with local reproduction commands,
  style guidance, and the deliberate non-goals.
- **Release workflow** (`.github/workflows/release.yml`) — on `v*.*.*`
  tag push (or manual `workflow_dispatch`), builds `proxilion-cli`
  for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `x86_64-apple-darwin`, and `aarch64-apple-darwin`, packs each
  with `LICENSE` / `README.md` / `CHANGELOG.md` into a `.tar.gz`,
  computes SHA-256 checksums, and uploads to the GitHub Release.
  Proxy binary is intentionally not shipped — operators install
  the proxy via Docker (Dockerfile + Helm chart) rather than raw
  binary. `cargo publish` step deferred until the workspace is
  crates.io-ready.
- **CI gate** (`.github/workflows/ci.yml`) — `cargo fmt --check`,
  `cargo clippy -- -D warnings`, `cargo test --workspace --locked`,
  `cargo build --release` with `RUSTFLAGS="-D warnings"`. Three lint
  families are allowed in the command line with documented rationale
  (`type_complexity`, `too_many_arguments`, `result_large_err`); all
  other warnings are errors.
- **Supply-chain CI** (`.github/workflows/supply-chain.yml`) — runs
  `cargo audit --deny warnings` *and* `cargo deny check` (advisories,
  bans, licenses, sources) on PRs, pushes to `main`, a weekly cron,
  and manual dispatch. `.cargo/audit.toml` + `deny.toml` document two
  ignored advisories with unblock conditions. `deny.toml` adds an
  MIT-compatible license allow-list, source restrictions (crates.io
  + the SHA-pinned `clay-good/provenance` git URL only), and
  duplicate-version warnings.
- **Asciinema demo recorder** (`demo/scripts/record-demo.sh`) —
  wraps `./run.sh` or any subset of scenario scripts into a
  `.cast` file under `demo/recordings/`. Closes `spec.md §4.4 dev 2`.
- **Comment-preserving `policy.yaml` edit** —
  [`policy_handle::edit_mode_in_yaml`](crates/proxy/src/policy_handle.rs)
  replaces the lossy `serde_yaml::Value` round-trip in `set_mode`
  with a line-oriented in-place edit that preserves comments, key
  ordering, blank lines, and trailing inline comments byte-for-byte.
  `serde_yaml` is the fallback for exotic YAML shapes. Closes
  `ui-less-surfaces.md §11.1`.
- **`proxilion-cli policy edit`** —
  [`cmd_policy_edit`](crates/cli/src/main.rs) opens `$EDITOR` /
  `$VISUAL` / `vi` on the live `policy.yaml` (path resolved from
  `GET /api/v1/policy`), backs up to `<path>.bak`, validates locally
  via `policy_engine::yaml::parse_policies`, rolls back on parse
  failure, hot-reloads via `POST /api/v1/policy/reload` with
  proxy-side rollback too. Closes `ui-less-surfaces.md §4.1` dev.
- **`blocked_actions.request_canonical_json`** —
  [migrations/0014_blocked_request_canonical_json.sql](migrations/0014_blocked_request_canonical_json.sql)
  + [`blocked::canonical_request_json`](crates/proxy/src/blocked.rs).
  Deterministic 4 KB-bounded JSON snapshot of the request at block
  time (method, path, vendor, action, path_params, body — body
  honoring `§5.4` default-deny). Threaded through all 9 block call
  sites in the Drive / Gmail / Calendar adapters. Surfaced on
  `GET /api/v1/blocked/{id}` and rendered in the Slack `[Why?]`
  ephemeral. Closes `spec.md §2.1 dev 3`.
- **Multi-tenant approver mapping doc**
  ([docs/install/multi-tenant-approvers.md](docs/install/multi-tenant-approvers.md))
  — three sizing tiers (<25, 25–250, 250+ approvers), Okta-SCIM
  cron-sync skeleton, rationale for static map over live IdP
  lookup on the Slack 3-second budget. Closes
  `ui-less-surfaces.md §11 Q4`.
- **Per-driver `notifier test`** —
  `POST /api/v1/notifier/test` accepts
  `{ "driver": "all|webhook|slack|email" }`. CLI plumbs
  `--driver`. Single-driver requests against an unconfigured driver
  return 412 with a `driver`-keyed envelope. Closes
  `ui-less-surfaces.md §4.1` `test slack | email | webhook` sketch.

### Changed

- **`cargo fmt --all`** ran workspace-wide; 52 files reformatted to
  rustfmt defaults. Going forward `ci.yml/fmt` keeps the workspace
  canonical.
- **Stale deviation notes** updated to match shipped reality —
  `§8.4 dev 1` (slack/email drivers exposed since `§5.3` + `§5.4`
  landed), `§5.4 dev 1` (HTML email body has been shipped via
  `multipart/alternative`), `§2.1 dev 1` (per-recipient ops-atom
  expansion landed in the `§2.2` list-valued template work).
- **`ui-less-surfaces.md §11` open questions** — all 7 now resolved,
  the last two (Q2 Slack workspace-vs-app, Q6 OTLP push vs scrape)
  as decision-tracking with rationale rather than code changes.
- **Clippy hygiene** — small inline fixes for
  `let_underscore_future`, `unnecessary_unwrap`,
  `unnecessary_get_then_check`, `needless_range_loop`, and
  `doc_lazy_continuation` so the new `ci.yml` clippy gate lands
  green on `-D warnings`. Two `from_*-takes-self` builder methods
  carry `#[allow(clippy::wrong_self_convention)]` with rationale
  (qiuth-patterns §2 fluent-builder shape).

### Security

- **Bumped `async-nats 0.38 → 0.48`** to drop the vulnerable
  `rustls-webpki 0.102.8` transitive dep. Closes 4 Dependabot
  alerts:
  - 1 HIGH — RUSTSEC-2025-XXXX (DoS via panic on malformed CRL BIT
    STRING)
  - 1 MEDIUM — webpki: CRLs not considered authoritative by
    Distribution Point
  - 2 LOW — webpki name-constraint acceptance for wildcards / URI
    names
  Workspace now resolves a single `rustls-webpki 0.103.13`.

### Tests

- 164 proxy + **58** policy-engine (was 16, **+42 new**) + 9 CLI;
  all 13 test binaries green.
- `cargo audit --deny warnings` exits 0 with the two documented
  ignores filtered.
- **Test backfill** (qiuth-patterns.md §6 ratchet plan groundwork):
  `match_expr.rs` (the entire spec.md §0.3 operator vocabulary
  interpreter — 209 LOC, previously zero inline tests) gets 33 new
  unit tests covering every operator branch (`equals` /
  `not_equals` / `in` / `not_in` / `matches` / `greater_than` /
  `less_than`), every combinator (`all` / `any` / `not` /
  `exists`), the top-level AND semantics, missing-field
  asymmetries, regex error paths, and four shape-error branches.
  `decision.rs` gets 9 new tests pinning `Pattern::is_match`
  (literal case-sensitivity, regex anchors + alternation) and the
  `Decision` enum's snake_case wire-format contract.
- New test surfaces from prior commits: `policy_handle`
  comment-preservation (4 tests), CLI `policy edit` shell-quote +
  local-validation (5 tests), `blocked::canonical_request_json`
  shape + default-deny + truncation + determinism (4 tests),
  `api::notifier` test-driver classification + `TestRequest`
  deserialization (2 tests).

---

## Prior history

Pre-`Unreleased` commits are summarized in the git log
(`git log --oneline`). Highlights of the immediate predecessor
batches:

- **`3a83449`** — Slack `user_map`, Block-Kit `[Why?]` button,
  Calendar `calendarList`, full §3.2 metric contract, CLI
  completion, OAuth client registry.
- **`9195f9a`** — comprehensive policy eval, per-policy email
  routing + escalation, `last_used_at` debounce, flush-loop
  hot-swap, `calendar.events.delete`.
- **`463953e`** — Config TOML file loader, PolicyTrace adapter
  wiring, audit schema doc, actions purge.
- **`b7d618b`** — `ErrorCode`/`PolicyTrace`, `PolicyLoader`,
  `ConfigBuilder`, coverage gate, CLI scopes+simulate, Slack
  trigger_id idempotency, notifier burst+details_url, SMTP retry,
  Grafana four-quadrant, expiry sweeper, kill-cache, email cc/bcc,
  SIEM batch.
- **`8573dcf`** — M3 + M4 + `ui-less-surfaces.md` spec items:
  notifier matrix, audit + policy hot reload, signed-URL approval,
  operator tokens.
- **`16ba2bf`** — Step 2.3 + 3.2 + 2.4: override loop, killswitch,
  audit-mode enforcement.
- **`f0b3345`** — Gmail adapter, list-valued ops expansion,
  Cloudflare Workers config.

---

[Unreleased]: https://github.com/clay-good/proxilion/compare/d69a804...HEAD
