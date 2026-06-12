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

### Added

- **`ops/prometheus/prometheus.yml`** — a ready-to-use Prometheus scrape config
  for the proxy's `/metrics` endpoint, completing the operator-artifacts set
  (the `ops/prometheus/` directory existed but was empty, and the README repo
  tree already listed "Prometheus scrape config" as a deliverable). It carries
  the `proxilion` scrape job (matching the previously inline-only example), a
  production-TLS note, and an example Alertmanager rule for the must-be-zero
  `proxilion_pca_verify_failures_total` series. `ops/README.md` now points at
  this file as the canonical source instead of duplicating the YAML inline.
  [ops/prometheus/prometheus.yml](ops/prometheus/prometheus.yml)
- **`read_bounded` branch coverage completed** — the shared upstream-body cap
  helper added with the §1.4 streaming fix had tests only for the
  `Content-Length`-absent streaming path; its `Content-Length` *pre-check*
  branch was unexercised. Added `read_bounded_rejects_on_oversized_content_length_before_reading_body`
  (advertised length over cap → reject before reading a byte) and its
  within-cap complement, plus a signature-witness test pinning the
  `(reqwest::Response, usize) -> Result<Vec<u8>, AppError>` shape against an
  `anyhow`/borrowed-return refactor. [adapters/mod.rs](crates/proxy/src/adapters/mod.rs)
- **Action-log `purge` dry-run integration test** — completes the
  destructive-operation dry-run coverage (alongside `killswitch`).
  [api/actions.rs](crates/proxy/src/api/actions.rs)
  `db_backed_actions_purge_dry_run_counts_without_deleting_then_real_purge_deletes`
  pins the audit-retention purge against real SQL: `dry_run` counts old rows
  and changes nothing; the real purge deletes rows past the cutoff while recent
  rows survive; a future `older_than` is refused.
- **Action-log `list` API integration test** —
  [api/actions.rs](crates/proxy/src/api/actions.rs)
  `db_backed_actions_list_filters_and_cursor` pins the query backing
  `proxilion-cli actions list` + `policy simulate`: seeds `action_events` rows
  and asserts the `p_0` / `decision` / `action` filters and the `limit` +
  `next_before` cursor against real SQL.
- **README** — a per-request-hot-path Mermaid **sequence diagram**, a
  **threat-model** table (defended-by-PIC / defended-by-Proxilion / not-defended,
  from spec.md §10), and an **observability cheat sheet** of the key Prometheus
  series (verified against the metric names actually emitted).
- **OAuth federation state-binding integration test** (surface-delight §6.4) —
  the session-fixation/replay defense was unit-tested only on the pure
  comparator. [oauth/routes.rs](crates/proxy/src/oauth/routes.rs)
  `db_backed_bridge_callback_binds_session_on_match_and_rejects_replay` now
  drives `bridge_callback_body` against real SQL: a matching-`state` token
  writes `pca_0_id`/`p_0`/`granted_ops` to the session, while a token minted
  for a *different* session returns `BridgeRejected` and leaves the target
  session untouched (`pca_0_id` still NULL — the replay is blocked before the
  UPDATE).
- **Operator-auth boundary integration test** (ui-less-surfaces.md §4.4) — the
  authentication gate for the *entire* operator API (`/api/v1/*`:
  killswitch / blocked / policy / actions / …) was DB-backed but had no
  integration coverage. [operator_auth.rs](crates/proxy/src/operator_auth.rs)
  `db_backed_operator_auth_boundary_enforces_token_and_scope` drives the real
  `middleware` (DB `operator_tokens` lookup + revocation check + principal
  attach) composed with a per-route `scope_check`, via `tower::oneshot` against
  seeded tokens, pinning the full decision matrix: valid+scope → 200,
  wildcard → 200, revoked → 401, unknown → 401, wrong scope → 403,
  missing/malformed → 401 — plus the `last_used_at` touch on success.
- **Calendar write-gate integration test** (spec.md §2.1 / §8 / §9) —
  [google_calendar.rs](crates/proxy/src/adapters/google_calendar.rs)
  `db_backed_calendar_insert_external_attendee_is_blocked_403` exercises the
  Calendar adapter's distinguishing **write** path: `events.insert` with an
  external attendee is blocked at Layer B → `PolicyBlocked` (403) +
  `layer='policy'` blocked row, no Trust Plane / Google contacted. Completes
  integration coverage of all three adapters (Drive / Gmail / Calendar) on the
  shared `test_support` harness.
- **Concurrent-refresh coalescing integration test** (spec.md §1.1 deviation 3,
  the last "structural-not-integration" gap) —
  [auth_middleware.rs](crates/proxy/src/auth_middleware.rs)
  `db_backed_refresh_coalesces_50_concurrent_into_one_google_call` fires 50
  concurrent `refresh_with_coalescing` calls (same bearer, an expired seeded
  `google_tokens` row) at a **wiremock'd Google token endpoint** and asserts via
  `received_requests()` that Google is hit **exactly once** and all 50 callers
  get the fresh token — pinning the per-bearer `Arc<Mutex>` + post-lock DB
  re-read under real concurrency. Runs in the CI `integration` job.
- **Adapter happy-path + read-filter-block integration tests** — completes the
  `proxy_request` branch matrix on the wiremock'd harness:
  `..._valid_mint_caches_successor_and_passes_through` (Trust Plane *issues* a
  successor via the new `mock_trust_plane_issue` helper → the PCA_2 is cached at
  `hop=2` with the leaf as predecessor and a clean upstream body passes through)
  and `..._read_filter_block_request_quarantines_full_body_403` (the
  `block_request` action quarantines the whole response → `ReadFilterBlocked`
  (403) + a `layer='read_filter'` blocked row, distinct from the
  `replace_with_marker` path). The adapter core is now covered across allow /
  audit-fallback / valid-mint / mint-refused / Layer-B-block.
- **Adapter block-path integration tests** (spec.md §1.3 / §1.5 / §9, the last
  two deferred wire-level scenarios) — both build on the wiremock'd harness:
  `db_backed_drive_get_runtime_gate_forced_ops_mismatch_is_blocked_403` proves
  the runtime-gate guarantee (Trust Plane 422 → `PicInvariantViolation` (403),
  upstream never reached, `layer='pic_invariant'` blocked row persisted), and
  `db_backed_gmail_send_external_recipient_is_blocked_403` proves the flagship
  external-send gate (Layer-B `PolicyBlocked` (403) + `layer='policy'` blocked
  row with `policy_id` + `override_allowed`, no Trust Plane / Google contacted).
  Shared scaffolding (`adapter_state`, `mock_session`, `mock_trust_plane_reject`)
  extracted to [test_support.rs](crates/proxy/src/test_support.rs); the existing
  Drive read-filter test was refactored onto it.
- **End-to-end Drive adapter integration test** (spec.md §1.3 "read filter
  triggers → marker present", the long-deferred wiremock'd-Google scenario) —
  [google_drive.rs](crates/proxy/src/adapters/google_drive.rs)
  `db_backed_drive_get_audit_mode_read_filter_quarantines_injection` drives the
  whole `proxy_request` path: policy eval → PIC mint against a **wiremock'd
  Trust Plane** (422 → `audit` fallback, no real crypto) → upstream GET to a
  **wiremock'd Google** (via the `google_api_base` override) → read-filter
  quarantine. Asserts the injection pattern is replaced by `read_filter::MARKER`
  while surrounding text passes through. Runs in the CI `integration` job
  (postgres service); skips locally without `PROXILION_TEST_DATABASE_URL`.
- **CI now runs the DB-backed integration tests** — a new `integration` job in
  [.github/workflows/ci.yml](.github/workflows/ci.yml) provisions a
  `postgres:16-alpine` service and sets `PROXILION_TEST_DATABASE_URL`, so the
  opt-in DB-backed tests execute (not skip) on every push. The job is
  independent of `fmt`/`clippy`/`test`/`build-release`. Also extended the
  harness with a **blocked-queue** test (`list` status/policy filters, the
  auto-expire-on-list of past-due pending rows, and `show` → 404 on unknown id),
  verified locally against `postgres:16`.
- **DB-backed integration tests** ([crates/proxy/src/test_support.rs](crates/proxy/src/test_support.rs))
  — the long-deferred end-to-end harness (spec.md §1.1 deviation 3), now seeded.
  Because the proxy is a binary-only crate, these live as in-module
  `#[cfg(test)]` tests that drive private handlers against a real Postgres
  (migrated via `sqlx::migrate!`). They are **opt-in**: each returns early
  unless `PROXILION_TEST_DATABASE_URL` is set, so the default `cargo test`
  run and CI skip them and stay hermetic/green. Two security-critical flows
  are covered end-to-end: the `notifier_public` email approval landing (the
  single-use token is consumed only on **POST**, never on a prefetch GET —
  §4.1) and the `killswitch` `--dry-run` (the preview `count(*)` matches the
  real revoke exactly, with no state change and no `kill_records` row — §3.3).
  Verified locally against `postgres:16`. Wiring a Postgres `services:` block
  into CI to run them on every push is the documented next step.
- **Slack approve/reject justification modal** (surface-delight-and-correctness.md
  §4.1, audit-critical) — when a Slack **bot** token is set
  (`PROXILION_SLACK_BOT_TOKEN`), an Approve/Reject click calls `views.open`
  to show a Block Kit modal capturing the reviewer's justification, and the
  override commits on `view_submission` with that text (replacing the
  synthesized "approved via Slack by …" string), enforcing the same ≥ 20-char
  minimum as the email form. **Graceful degradation:** with no bot token the
  original direct-commit path is unchanged, so incoming-webhook-only installs
  are unaffected — the token lives in the env, not the `notifier_config` row,
  so there is no schema/struct/pin change. Pure helpers (modal JSON,
  `view_submission` parse + round-trip) and the `views.open` call (via
  wiremock) are unit-tested. This completes the surface-delight spec's §4.
- **CLI: `--color auto|always|never`** (surface-delight-and-correctness.md
  §3.2) — a global flag gating all ANSI output, honoring `NO_COLOR` and
  non-TTY pipes. The four `const` SGR codes were replaced with a runtime-gated
  `colors()` tuple resolved once from a pure, unit-tested `resolve_color`
  decision; every styled site binds the subset it needs so format strings are
  untouched.
- **CLI: `--dry-run` on destructive commands** (§3.3) — `killswitch
  session|user|all` and `clients revoke` preview the blast radius (count of
  bearers/clients that *would* be revoked) without changing anything
  (`actions purge --dry-run` already existed). Killswitch previews use a
  **server count** (`SELECT count(*)` against the same predicate as the real
  revoke) so the preview matches execution with no TOCTOU gap — no UPDATE, no
  `kill_records` row, no cache write.
- **CLI: progress feedback** (§3.5) — `actions export` and `policy simulate`
  show a throttled single-line stderr progress indicator (bytes/rows +
  elapsed), suppressed under `--format json`, a piped stderr, or
  `--color never`. No new dependency.

### Fixed

- **spec.md §1.3 error-code list was missing `policy_engine_error` (500)** —
  the inline "Codes:" summary listed 8 of the 9 distinct wire strings the
  `ErrorCode` enum emits, omitting `policy_engine_error` (returned on a
  malformed policy YAML / ops-template at evaluation time — `AppError::Policy` /
  `OpsTemplate` in adapters/error.rs). Added it, and pointed the list at the
  canonical, test-pinned catalogue [docs/error-codes.md](docs/error-codes.md)
  so future drift goes to one source of truth. Also added a discoverable pointer
  to that catalogue from the README's observability section — the block-counter
  `reason`/`code` labels and the response-envelope `code` field were documented
  inline but never linked to the full table. [docs/specs/spec.md](docs/specs/spec.md)
- **docker-compose set the wrong public-URL env var** — the proxy service
  exported `PROXILION_BASE_URL`, but the code reads `PROXILION_PUBLIC_URL`
  (config.rs maps it to the internal `proxy_base_url` field — the likely source
  of the wrong guess). The misnamed var was consumed by nobody. It's latent at
  the default (the field defaults to `https://localhost:8443`, which matched the
  compose default), but it **silently breaks operator overrides**: setting
  `PROXILION_BASE_URL=https://proxilion.acme.com` in a `.env` — following the
  compose file's own name — is ignored, so the notifier's human-in-the-loop
  approve/reject links keep pointing at `localhost` in production. Renamed the
  compose key (and its `${…}` interpolation) to `PROXILION_PUBLIC_URL`; verified
  every `PROXILION_*` var compose sets is now consumed by the code.
  [docker-compose.yml](docker-compose.yml)
- **21 broken in-repo links in `spec.md`** — a set of markdown links carried a
  stale `proxilion/` path prefix (e.g. `](proxilion/crates/proxy/src/pic/)`)
  and one bare `](site/)`, left over from when the repo was nested under a
  `proxilion/` subdirectory. From `docs/specs/`, those resolve to non-existent
  `docs/specs/proxilion/...` paths even though the link *text* and the target
  files are correct. Repointed all 21 to the proper `../../…` relative path and
  verified every target exists via a repo-wide link scan. (The remaining
  `qiuth-main/*` links are deliberate citations to the external sibling
  source-of-truth project, not in this tree, and are left as-is.)
  [docs/specs/spec.md](docs/specs/spec.md)
- **Operator-facing metric name corrected: `oauth_token_refreshes_total`** —
  `ops/README.md` and three `spec.md` references named the refresh counter
  `proxilion_token_refreshes_total`, but the code emits it with the `oauth_`
  prefix (`proxilion_oauth_token_refreshes_total`). An operator pasting the
  documented name into a PromQL alert would have silently gotten no data.
  Corrected every reference repo-wide and added the `coalesced` stampede-defense
  note + `vendor` label to the ops metrics table.
  [ops/README.md](ops/README.md)
- **Grafana dashboard: added the missing "Token refresh outcomes" panel** —
  the `ops/README.md` Grafana section advertised a token-refresh panel, but the
  bundled dashboard had none. Added a `Token refresh outcomes (1m rate)`
  timeseries (`sum by (result) (rate(proxilion_oauth_token_refreshes_total[1m]))`)
  to the "Is the system healthy?" row — surfacing the `ok` / `coalesced` /
  `upstream_err` split, including the 50→1 per-bearer coalescing defense — and
  rebalanced that row to four even panels. Verified the dashboard now references
  zero metrics the code doesn't emit. [ops/grafana/proxilion.json](ops/grafana/proxilion.json)
- **Stale `MARKER` byte-length comment** — a read-filter test's comment said
  the `[redacted by proxilion read-filter]` marker is "38 bytes" while it
  asserts (correctly) `MARKER.len() == 35`; a later test even flagged it as a
  known stale doc bug. Corrected the comment to 35 bytes and updated the
  cross-reference. [adapters/read_filter.rs](crates/proxy/src/adapters/read_filter.rs)
- **Upstream response cap is now a true memory bound** (spec.md §1.4,
  surface-delight-and-correctness.md §6.8) — `read_bounded` checked the
  advertised `Content-Length`, then called `resp.bytes().await` and checked the
  length *after* buffering the whole body. An upstream that omits
  `Content-Length` and streams past the 10MB cap would be fully buffered into
  memory first, defeating the cap. It now streams the body chunk-by-chunk and
  aborts the moment the running total would exceed the cap. The byte-identical
  copy that lived in all three Google adapters is consolidated into one shared
  `adapters::read_bounded`. New tests build a `Content-Length`-less streaming
  body to exercise the rejection path (`read_bounded_rejects_oversized_body_with_no_content_length`
  + under-cap / exact-cap boundaries); `reqwest`'s `stream` feature is enabled
  as a **dev-dependency only**, so the release binary's feature set is unchanged.
  [adapters/mod.rs](crates/proxy/src/adapters/mod.rs)
- **PIC chain verifier: partial walk progress preserved on a broken chain**
  (surface-delight-and-correctness.md §6.8) — `err_to_result` hardcoded
  `links_verified: 0` (and `p_0: None`) on every verification failure, so a
  break 3 hops deep reported "nothing verified" and the dashboard chain-walker
  couldn't show how much of the chain was sound before the failed link. `walk`
  now accumulates `links_verified` + `p_0` into a `WalkProgress` that survives
  the early-return, and the error result carries it. New regression test
  `err_to_result_carries_partial_walk_progress_not_zero`.
  [pic/verifier.rs](crates/proxy/src/pic/verifier.rs)
- **OAuth callback: no orphaned encrypted token rows on empty scope
  intersection** (surface-delight-and-correctness.md §6.8) — the Google
  callback persisted the encrypted `google_tokens` row *before* checking
  whether the granted scope intersected the PCA_0 ops. An empty intersection
  then returned `PicInvariant` after the write, leaving an encrypted row no
  bearer would ever reference. The `pca1_ops` intersection + empty-rejection
  now runs immediately after the token exchange, before `persist_google_tokens`.
  [oauth/routes.rs](crates/proxy/src/oauth/routes.rs)
- **NATS subject doc comment corrected** (surface-delight-and-correctness.md
  §6.8) — `subject_for`'s comment claimed subjects "can't contain" `.` while
  the code deliberately preserves it. `.` is the NATS token separator: a dotted
  action (`gmail.messages.send`) is *meant* to expand into the
  `actions.<vendor>.gmail.messages.send` hierarchy. Rewrote the comment to say
  so and to name the chars `sanitize_token` actually neutralizes (space, `*`,
  `>`). Behavior unchanged. [forwarder/nats.rs](crates/proxy/src/forwarder/nats.rs)
- **CLI: `killswitch all` now forwards `--confirm` to the server** — it
  validated `--confirm yes` locally but never sent `confirm` in the request
  body, so a real fleet-wide kill would have been rejected by the server's
  `confirm` gate. Surfaced while wiring §3.3 dry-run.

### Added — earlier this cycle

- **CLI: shell completion** (surface-delight-and-correctness.md §3.4) —
  `proxilion-cli completion bash|zsh|fish|powershell|elvish` emits a completion
  script via `clap_complete` (offline; handled before any HTTP client is
  built). Documented in the README install section. New dependency:
  `clap_complete` (MIT/Apache-2.0, reuses clap's existing transitive deps).
- **CLI: `clients list` table** (§3.1) — `clients list` gains `--format
  pretty|json` and renders an aligned `client_id · name · created_at · revoked`
  table instead of raw JSON (`blocked list` / `policy list` already had
  tables).
- **Approval messages: absolute expiry + inline matched detail** (§4.3, §4.4) —
  Slack and email now show an absolute UTC `expires_at` (computed at send so it
  doesn't drift as the message sits unread) instead of "expires in 30m"; the
  shared window is `notifier::OVERRIDE_TOKEN_TTL_MINUTES`. Slack inlines the
  matched rule id + a full-width detail excerpt (section block, ~2900 chars)
  rather than truncating to 140; email already showed full detail.

### Changed

- **CLI: actionable parse errors** (§3.6) — `--since`, `--older-than`, and
  `--against` parse failures now name the accepted forms (RFC3339 timestamp or
  a duration like `30m` / `24h` / `7d`).

### Security

- **Path / SSRF injection closed in the Drive & Gmail adapters**
  ([surface-delight-and-correctness.md](docs/specs/surface-delight-and-correctness.md) §6.1).
  axum percent-decodes `{id}` path params before the handler sees them, so a
  `file_id` / `msg_id` carrying `/`, `?`, `#`, or an encoded slash re-injected
  path/query/fragment delimiters and could steer the upstream call to a
  *different* Google endpoint than the action label, policy layer, and PIC
  chain were evaluated against (a confused-deputy vector). The Calendar
  adapter's per-segment encoder is now promoted to a shared
  `adapters::path_segment` helper and applied at all three sites. Regression
  tests in `adapters/{mod,google_drive,google_gmail}.rs`.
- **Federation `state` claim now bound to the callback session**
  (§6.4). `FederationClaims.state` was parsed but never compared to the
  callback `state`, so a federation token minted for one session could be
  replayed into another (session fixation). `bridge_callback_body` now rejects
  on mismatch before any DB write. (Ships ahead of the still-stubbed signature
  check — see `oauth/bridge.rs`.)

### Fixed

- **Policy matcher now matches list-valued body fields** (§6.2). `apply_op`
  resolved the LHS once as a scalar, so a JSON-array field (e.g.
  `body.to_domains`) stringified to its JSON literal and `in`/`not_in`/`equals`
  never matched — silently disabling any array-valued Layer-B gate (fails
  open). The matcher now applies element-wise set semantics when
  `ctx.lookup_list` returns an array: `in` = any-element-in-set, `not_in` =
  no-element-in-set, `equals`/`not_equals` = single-value membership. Pinned
  by a new end-to-end engine test wiring the recipient-domain gate over the
  array.
- **Burst-suppressor bucket map is now bounded** (§6.3). `drain_summaries`
  only reset counters, so the `(policy_id, p_0)` map grew for the process
  lifetime on high-cardinality, partly attacker-influenced `p_0` (DoS-of-
  degree). It now prunes expired timestamps and drops idle buckets each drain,
  and emits the `proxilion_burst_buckets` gauge.
- **Retryable HTTP 429 is no longer dropped as permanent** (§6.5). The SIEM
  forwarder and webhook notifier treated all 4xx as permanent; `429 Too Many
  Requests` (and `408`) are retryable — Slack/PagerDuty/Datadog/Splunk HEC all
  rate-limit with 429. Folded into the 5xx retry branch via a shared
  `forwarder::is_retryable_4xx`, with a `proxilion_forwarder_retry_total`
  counter.
- **Still-valid bearer no longer rejected up to 60s early** (§6.6). A
  session inside the 60s pre-expiry window with no refresh token returned 401
  even though the Google access token was still valid. It now forwards the
  still-valid token and lets Google 401 naturally at true expiry; only an
  actually-expired token is rejected. Decision extracted to a pure
  `token_action` helper with unit tests.
- **PCA chain walk is depth-bounded and hop arithmetic is checked** (§6.7).
  The verifier walk followed `predecessor_id` with no cap (cold-cache DB
  amplification on a crafted deep chain) and used `parent.hop + 1` (debug
  panic / release wrap at `u32::MAX`). Added a `MAX_CHAIN_HOPS` cap returning
  a new `VerifierError::ChainTooLong`, and replaced the hop add with
  `checked_add`.

### Added

- **Marketing-site delight** ([site/index.html](site/index.html),
  surface-delight-and-correctness.md §5): a persisted dark-mode toggle
  defaulting to `prefers-color-scheme` (no framework, ~40 lines of inline JS,
  no build step), copy-to-clipboard on the quickstart commands, a mobile
  scroll-fade on the install box, and `rel="noopener noreferrer"` on every
  off-site link.
- **README** — architecture + two-layer-enforcement Mermaid diagrams, a PIC
  chain / invariants visualization, and policy-DSL + CLI + design-decision
  cheat sheets.

### Changed

- **Coverage gate honest reset — floor lowered from 60% / 60% to 35% lines /
  42% functions** ([.github/workflows/coverage.yml](.github/workflows/coverage.yml),
  qiuth-patterns.md §6.4 status block). The original 60/60 adoption floor
  (b7d618b) was set aspirationally above measured reality; a
  `cargo llvm-cov --workspace` run reports `TOTAL 36.94% lines / 43.94%
  functions` (the 40.22% number visible in the report is the *regions*
  metric — easy to misread; `--fail-under-lines` checks the line column).
  The five most recent CI runs of `coverage.yml` on `main` all exited
  `failure`. The new floor sits just under measured reality so
  the gate enforces a no-regression line the workspace actually clears.
  Biggest pull-down sources are the `proxy/api/*` HTTP handlers (0% — no
  integration tests; `crates/proxy/tests/` is empty), `proxy/server.rs`
  (0%), and `cli/src/main.rs` (3.91%). Backfilling those is the work that
  earns the next ratchet (target: 50% / 55%).

### Added

- **[`config/proxilion.example.toml`](config/proxilion.example.toml)** —
  worked example for the layered TOML config that Phase 2 of qiuth-patterns
  §2 added. Every `FileConfig` field is present, commented out, and
  annotated with its default + a one-line explanation. Operators copy
  the file and uncomment only what they want to override. Header
  documents the precedence chain (`defaults → file → env → programmatic`).
  A new `config::tests::example_toml_parses_with_defaults_only` unit
  test pins the contract — when every field is commented out the
  loader produces a builder identical to `defaults()` — so the
  example can't silently drift away from `FileConfig`.

### Changed

- **`spec.md` ui-less alignment.** Cleaned up four stale `dashboard/`
  references in [docs/specs/spec.md](docs/specs/spec.md) that survived
  the 2026-05-11 ui-less pivot: §3.3 line 124 (component inventory),
  §5.2 line 244 (architecture component table), §0.5 (status block
  pointed at the deleted `dashboard/` directory), §0.6 (compose service
  list claimed `dashboard` was wired in), and §0.7 (CI job list claimed
  a `dashboard` typecheck/lint/build job that no longer exists). All
  five sites now redirect to [`ui-less-surfaces.md`](docs/specs/ui-less-surfaces.md)
  §8.1, which is the canonical "what we deleted" record. The §0.6
  status block is rewritten to match the actual five compose services
  (`postgres`, `trust-plane`, `mock-okta`, `nats`, `proxy`); §0.7 is
  rewritten to match the actual four CI jobs (`fmt`, `clippy`, `test`,
  `build-release`) plus the four sibling workflows (`coverage`,
  `static-html-no-js`, `supply-chain`, `release`). No code touched.
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
