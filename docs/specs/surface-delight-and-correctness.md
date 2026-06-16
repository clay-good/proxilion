# Spec — Surface Delight & Correctness

**One line:** Make the three customer-facing surfaces (CLI, human-in-the-loop approvals, marketing site) a pleasure to use, and close the concrete correctness gaps an audit of the existing code surfaced — without adding a dashboard.

**Status:** Implemented (2026-06-11). Every item in this spec has landed with regression tests: the correctness work-stream (§6.1–§6.7), the marketing-site delight (§5.1–§5.4), all of CLI delight §3 (§3.1 tables, §3.2 `--color`, §3.3 `--dry-run`, §3.4 completion, §3.5 progress, §3.6 errors), and all of approval delight §4 — §4.1 justification capture across CLI (`--justification`), email (form + token-on-POST, [api/notifier_public.rs](../../crates/proxy/src/api/notifier_public.rs)), and **Slack (Block Kit `views.open` modal gated on `PROXILION_SLACK_BOT_TOKEN`, [api/notifier_slack.rs](../../crates/proxy/src/api/notifier_slack.rs))**; §4.2 read-only context (the GET landing already serves it); §4.3 absolute expiry; §4.4 inline detail. The only remaining nicety is a *dedicated* §4.2 "View details" link distinct from the GET landing — low value since the landing is already non-destructive. Companion to [spec.md](spec.md) and [ui-less-surfaces.md](ui-less-surfaces.md). This spec **extends** the three surfaces defined in `ui-less-surfaces.md` (it does not supersede them) and **adds** a correctness work-stream (§6) for bugs found during the 2026-06-11 repo audit. The "no React dashboard" decision in `ui-less-surfaces.md` §0 stands — every item here lands in a surface that already exists. *(Addendum 2026-06-13: a follow-up audit found three of the five §7 observability series were declared but never emitted; they were wired and dashboarded — see §7 Status and §9 Phase 5.)* *(Addendum 2026-06-15: a third audit pass — a parallel multi-subsystem sweep over crypto/auth, PIC, adapters, policy-engine, notifiers/forwarders, and the operator API — surfaced three more defects, all fixed with regression tests (see CHANGELOG `[Unreleased] → Fixed`): a **fail-open** in the flagship Gmail external-send gate when a recipient header is RFC-5322-malformed but Gmail-routable (`split_addresses` dropped the recipients silently → `body.external_recipient` collapsed to `false`); a reachable **panic** in the OAuth callback/refresh path from an unbounded upstream `expires_in` (`Duration::seconds`/`DateTime` overflow, now clamped via `oauth::token_expiry`); and a Slack inbound-signature check that HMAC'd the re-serialized `u64` timestamp instead of the raw header (fail-closed fragility). The PIC chain-walk and the operator-API authz/SQL/token-lifecycle surfaces were re-audited and cleared with no findings.)* *(Addendum 2026-06-15b: a fourth audit pass — a fresh parallel multi-subsystem sweep (crypto/auth/oauth, PIC, adapters/policy-engine, notifiers/forwarders/operator-API, and CLI/config/server) — surfaced six more defects, all fixed with regression tests (see CHANGELOG `[Unreleased] → Fixed`): a **secret leak** where `GET /api/v1/notifier/config` returned the cleartext webhook / Slack incoming-webhook URL (itself a bearer credential) to `notifier:read` operators alongside the redacted twin — the three hand-rolled redaction branches are now one pure `redact_notifier_config` helper; a **config precedence bug** where `from_env_layer` unconditionally clobbered five file-set `Option` fields (SIEM/NATS/blocked-webhook) to `None` when the env var was unset, silently disabling audit forwarding; the same `GET …/notifier/config` route was **double-gated** behind `notifier:write` (chained `route_layer` over one `MethodRouter`), defeating least-privilege read; a reachable **panic** in `from_hex` (SIEM + webhook HMAC keys) on a non-ASCII operator-supplied key (byte-index slice off a char boundary); a **fail-open documented example** — the canonical §9 `gmail-external-send-gate` gated on the singular alphabetically-first `to_domain` (masked when an internal recipient sorts first) instead of the all-recipients `external_recipient` boolean production already used; and a CLI `policy simulate --page-limit > 500` **silent truncation** to the first page. The crypto/auth and PIC subsystems were swept again and cleared with no findings.)* *(Addendum 2026-06-15c: a fifth audit pass — a fresh parallel multi-subsystem sweep (crypto/auth/oauth, adapters/policy-engine, notifiers/forwarders/PIC/operator-API, and CLI/config/server) — surfaced three code defects plus one contract-honesty gap, all fixed with regression tests (see CHANGELOG `[Unreleased] → Fixed`): a **HIGH** CLI `urlencode` bug that percent-encoded the Unicode *scalar value* instead of the UTF-8 *bytes* (`é`→`%E9`, `日`→`%65E5`), silently breaking `killswitch user <p_0>` and every other id/query path for any non-ASCII principal; a **MEDIUM** unbounded read-filter `QuarantineSample` fan-out (one allocation + one serial DB INSERT per match on attacker-influenceable `application/json` bodies up to the 10MB cap), now capped at `MAX_SAMPLES = 100` while keeping the match count exact; a **LOW** `parse_window` panic on an overflowing `--against last-<N><unit>` magnitude (switched to chrono's checked `try_*` constructors); and the `ApproveBody.ttl_minutes` override-lifetime field that was bounds-validated but never applied — the docstring + a misleading test were corrected and proxy-side TTL enforcement is now tracked as §10 open question #5. The crypto/auth/oauth and PIC subsystems were swept again and cleared with no findings.)* *(Addendum 2026-06-15d: a sixth audit pass — a fresh parallel multi-subsystem sweep (crypto/auth/oauth, adapters/policy-engine, notifiers/forwarders/PIC/operator-API, and CLI/config/server) — surfaced two reachable-panic / availability defects, both fixed with regression tests (see CHANGELOG `[Unreleased] → Fixed`): a **MEDIUM** char-boundary panic in the Slack `[Why?]` handler ([api/notifier_slack.rs](../../crates/proxy/src/api/notifier_slack.rs) `handle_why`), which capped the agent-influenced request snapshot with a raw byte slice `&s[..2048]` — panicking whenever byte 2048 fell mid-codepoint (any non-ASCII filename/subject/title) and aborting the handler future on every such blocked row, now truncated on a char boundary via the pure `cap_request_snippet` helper; and a **LOW/MEDIUM** unbounded `multipart/*` recursion in Gmail send ([adapters/google_gmail.rs](../../crates/proxy/src/adapters/google_gmail.rs) `parse_mime`), where `mailparse::parse_mail` descends into every subpart with no depth bound — a deeply-nested payload (well within axum's 2 MB body cap) overflows the worker stack *during parsing*, now guarded by a cheap pre-scan (`count_multipart_markers` ≤ `MAX_MIME_MULTIPART = 100`) that rejects before the recursive parser runs. The other two sweep lanes (crypto/auth/oauth and CLI/config/server) were cleared with no findings.)* *(Addendum 2026-06-15e: a seventh audit pass — a fresh parallel multi-subsystem sweep (adapters/MIME, policy-engine, crypto/PIC/oauth/auth, and notifiers/forwarders/config/CLI) — surfaced one fail-open correctness defect, fixed with regression tests (see CHANGELOG `[Unreleased] → Fixed`): a **MEDIUM** silently-disabled numeric deny gate in [match_expr.rs](../../crates/policy-engine/src/match_expr.rs) `apply_op`, where a YAML-quoted `greater_than`/`less_than` threshold (`greater_than: "100"` → `serde_yaml::Value::String`, not `Number`) coerced to `None` and the comparison fell through to `Ok(false)` — so a deny condition an operator believed was blocking never matched and allowed every request. The threshold is policy config (not runtime data), so a non-numeric value is now an authoring error that fails **closed** via `MatchError::BadShape` (the adapters' `evaluate` error arm rejects the request), mirroring how `matches` already errors on a malformed RHS; a *numeric* string is accepted as the number it denotes. The LHS (runtime request value) is unchanged — a non-numeric value still degrades gracefully to no-match. The other three lanes (adapters/MIME, crypto/PIC/oauth/auth, notifiers/forwarders/config/CLI) were swept again and cleared with no findings. *Also evaluated and deliberately deferred:* §10 open question #5 (proxy-side override-TTL enforcement via a `pca_cache.expires_at` column) — investigation confirmed there is no consumption path for the override successor PCA in the request hot path (the auth middleware resolves `pca_1_id`, never `override_pca_id`), so adding `expires_at` would enforce a lifetime on a row nothing yet reads; the work stays blocked on the spec.md §6.6 upstream `successor-with-attestation` branch, as the open question already records.)* *(Addendum 2026-06-15f: an eighth audit pass — a fresh parallel multi-subsystem sweep (crypto/auth/oauth, adapters/MIME/policy-engine, notifiers/forwarders/PIC/operator-API, and CLI/config/server) — surfaced one authz / least-privilege defect, fixed with a regression test (see CHANGELOG `[Unreleased] → Fixed`): a **MEDIUM** off-catalogue scope gate where `POST /api/v1/notifier/test` ([api/notifier.rs](../../crates/proxy/src/api/notifier.rs) `router`) gated on the string `notifier:test`, which exists nowhere in the canonical operator-scope catalogue ([operator_scopes.rs](../../crates/shared-types/src/operator_scopes.rs)), the CLI, or this spec — both the catalogue and [ui-less-surfaces.md](ui-less-surfaces.md) §8.3 document `/test` as covered by `notifier:write`. Because `scope_check` passes only on an exact scope match or the `*` wildcard, and `tokens issue` only mints catalogued scopes, the gate was a **least-privilege inversion**: a `notifier:write` operator got 403 on the flagship verify-your-wiring endpoint while only a wildcard admin token could reach it. Fixed by gating `/test` on `notifier:write` and routing all four notifier-router gates through named `*_SCOPE` constants pinned to the catalogue by the new `router_scope_gates_are_all_catalogued` test. The other three lanes were swept again and cleared with no findings.)* *(Addendum 2026-06-15g: a ninth audit pass — a fresh parallel multi-subsystem sweep (crypto/auth/oauth, adapters/MIME/policy-engine, notifiers/forwarders/PIC/operator-API, and CLI/config/server) — surfaced one **LOW** display-correctness defect on a customer-facing surface, fixed with regression tests (see CHANGELOG `[Unreleased] → Fixed`): the `proxilion-cli actions tail` live-tail loop ([cli/src/main.rs](../../crates/cli/src/main.rs) `actions_tail`) decoded each SSE `bytes_stream()` chunk with `std::str::from_utf8(&chunk).unwrap_or("")`, so a multibyte UTF-8 codepoint split across a **TCP fragment boundary** (arbitrary byte offsets, common under real network conditions) made the *entire* chunk decode to `""` — silently dropping every frame's worth of bytes in it, not just the split char. The trigger is precisely the international content this proxy gates (a filename / subject / attendee name with `日本語`, `café`, or emoji). Fixed by buffering raw bytes across chunks and decoding only the longest valid-UTF-8 prefix via the new pure `decode_utf8_streaming` helper (retains an incomplete trailing sequence for the next chunk; skips genuinely-invalid bytes without stalling). The `--format json|ndjson` pipe paths and all persisted data are unaffected. The other three lanes were swept again and cleared with no findings.)* *(Addendum 2026-06-15h: a tenth audit pass — a fresh parallel multi-subsystem sweep (policy-engine/CLI, adapters/PIC, api/oauth/auth/crypto, notifiers/config/forwarders + docs) — surfaced a small cluster of defects, all fixed with regression tests (see CHANGELOG `[Unreleased] → Fixed`): a **MEDIUM** capability-URL **secret leak** where Slack/webhook/SIEM endpoint URLs (whose tokens live in the path/query) reached logs two ways — `reqwest::Error`'s `Display` appends ` for url (…)` and was logged with `%e` on every transport failure ([notifier/slack.rs](../../crates/proxy/src/notifier/slack.rs), [notifier/webhook.rs](../../crates/proxy/src/notifier/webhook.rs), [forwarder/siem.rs](../../crates/proxy/src/forwarder/siem.rs)), and boot-time `info!(url = %url, …)` lines logged the raw endpoint unconditionally ([server.rs](../../crates/proxy/src/server.rs)) — fixed via `Error::without_url()` on the error sites and a new `config::redacted_endpoint` (`scheme://host[:port]` only, userinfo/path/query dropped) on the boot sites; a **MEDIUM operator-trust gap** where `proxilion-cli policy validate` only YAML-shape-checked and green-lit policies the engine rejects at runtime (bad decision / read-filter regex / unknown match operator) — the runtime error page even tells operators to run `policy validate` — fixed by adding [`Engine::validate`](../../crates/policy-engine/src/rego.rs) + a context-free every-branch [`match_expr::validate`](../../crates/policy-engine/src/match_expr.rs) and wiring them into the CLI; two **fail-open → fail-closed** hardenings (`PolicyDoc` gained `deny_unknown_fields` so a typo'd key can't silently default to match-everything-allow; the PCA-cache `ops` JSONB decode now fails closed via `CacheError::Decode` instead of `unwrap_or_default()` to a universally-subset empty op set); a **LOW** client-side DoS where the CLI live-tail's SSE reassembly buffer was unbounded (now capped at 10 MB); a defense-in-depth **boot `warn!`** so the documented M0/M1 federation-bridge signature stub (`/oauth/bridge/callback` trusts the token payload — spec.md §0.4) can never ship silently; and several [ui-less-surfaces.md](ui-less-surfaces.md) doc-drift fixes (a mis-numbered migration caption, copy-pasteable CLI examples with non-existent flags, a fictional `PROXILION_METRICS_EXPORTER`/OTLP env var). The PIC chain-walk, the confused-deputy gates, and the operator-API authz surfaces were re-audited and cleared with no new findings.)* *(Addendum 2026-06-15i: an eleventh audit pass — a fresh parallel multi-subsystem sweep (crypto/auth/oauth, adapters/MIME/policy-engine, notifiers/forwarders/PIC/operator-API, and CLI/config/server) — surfaced two defects, both fixed with regression tests (see CHANGELOG `[Unreleased] → Fixed`): a **MEDIUM fail-open** where the tenth-pass `deny_unknown_fields` hardening of `PolicyDoc` was never extended to the *nested* config structs, so a typo'd `quarantine_actoin: block_request` under a `read_filter:` block was silently dropped and `quarantine_action` fell back to its `replace_with_marker` default — downgrading an operator's intended hard block of an injected upstream response to a marker-splice that still reaches the agent (and `Engine::validate`, behind `policy validate`, runs after the unknown key is gone, so it green-lit the broken policy); fixed by adding `#[serde(deny_unknown_fields)]` to `ReadFilterCfg` (plus `RecipientsCfg`/`BurstCfg` for the same silent-drop footgun on `escalation_after_minutes`/`threshold`/`window_seconds`) in [yaml.rs](../../crates/policy-engine/src/yaml.rs); and a **LOW** CLI panic where `parse_window`/`parse_since` ([cli/src/main.rs](../../crates/cli/src/main.rs)), already guarded against constructor overflow by the fifth pass's `try_*` switch, still panicked on the *separate* `chrono::Utc::now() - dur` subtraction surface (`DateTime - TimeDelta` is `expect`-on-`checked_sub_signed`) for a magnitude that builds a valid `Duration` yet pushes the date past `NaiveDate`'s ±262k-year range (`--older-than 100000000d`, `--against last-100000000d`) — now subtracted via `checked_sub_signed`. The crypto/auth/oauth and notifiers/forwarders/PIC/operator-API lanes were swept again and cleared with no findings.)* *(Addendum 2026-06-15j: a twelfth audit pass — a fresh parallel multi-subsystem sweep (crypto/auth/oauth, adapters/MIME/policy-engine, notifiers/forwarders/PIC/operator-API, and CLI/config/server), plus a dedicated **logic-correctness** lane tracing the policy-decision / override-commit / ops-narrowing core for wrong-decision (not crash/leak) bugs — surfaced one defect, fixed with regression tests (see CHANGELOG `[Unreleased] → Fixed`): a **MEDIUM** copy-template drift in the Google adapters' shared Layer-B denial path where the Drive `proxy_request` guard matched only `AppError::PolicyBlocked` while the Gmail and Calendar copies matched `PolicyBlocked | RequireConfirmation` — so a `decision: require_confirmation` policy on a Drive read (`drive.files.{list,get,export}`) returned the correct 428 to the agent but persisted **no** `blocked_actions` row and fired **no** notifier, leaving the gate silently unreviewable and uncounted (the identical rule on Gmail/Calendar enqueued the pending review correctly). The decision was right; the audit/operator surface was wrong-by-adapter. Fixed by hoisting the guard into one shared `adapters::persists_blocked_action` predicate all three `proxy_request` bodies route through (mirroring the tenth-pass `read_bounded` consolidation), so the three can't diverge again; pinned by a context-free predicate unit test over every `AppError` variant and a DB-backed end-to-end test asserting a `require_confirmation` Drive read writes exactly one `status='pending'`/`layer='policy'` row. The other four lanes — crypto/auth/oauth, the MIME/policy-engine and read-filter surfaces, notifiers/forwarders/PIC/operator-API, and CLI/config/server — were swept again, and the logic-correctness lane separately traced `Engine::evaluate` first-match precedence, observe-vs-enforce demotion, list/scalar match semantics, `mint_successor` ops narrowing + hop increment, the override approve/reject idempotency (`FOR UPDATE` + `status='pending'`), and `narrowed_ops_for_pca1`/`intersect_scope_with_ops` subset preservation — all cleared with no further findings.)*

**Author intent:** The three surfaces are functionally complete (see `ui-less-surfaces.md` §3–§5 status blocks), but "complete" is not the same as "delightful," and the audit found six real defects ranging from a path-injection / confused-deputy vector to a silently-broken flagship policy gate. This spec packages the polish and the fixes as one coherent unit of work so the delight items don't ship on top of latent correctness bugs.

---

## Table of Contents

1. Why this spec, why now
2. Design principles (what "delight" means for a UI-less product)
3. Surface A — `proxilion-cli` delight
4. Surface B — human-in-the-loop approval delight (Slack / email)
5. Surface C — marketing site delight
6. Correctness fixes (the bug work-stream)
7. New & changed metrics
8. Out of scope (explicit non-goals)
9. Implementation playbook (per-step, with verify criteria)
10. Open questions

---

## 1. Why this spec, why now

The 2026-06-11 audit reached two conclusions:

1. **The surfaces work but under-delight.** The CLI emits raw JSON blobs where a human reading a terminal wants an aligned table; destructive commands lack a `--dry-run`; there is no shell completion; approvals capture *who* but never *why*; the marketing site ships dark-mode CSS variables but no toggle and no copy button on its one install command.
2. **Six concrete defects exist in shipped code.** Two are high severity: a path/SSRF injection in the Drive and Gmail adapters (a confused-deputy vector on exactly the requests the proxy exists to gate), and a policy-engine matcher that can never match list-valued body fields — which silently breaks the flagship `gmail-external-send-gate` example from `spec.md` §9.

Shipping delight on top of latent correctness bugs is backwards. This spec sequences the fixes first (§6, §9 Phase 0), then the polish (§3–§5).

---

## 2. Design principles

The product is deliberately UI-less (`ui-less-surfaces.md` §0). "Good UI" here is therefore **not** a web app — it is the felt quality of the surfaces a security engineer actually touches: a terminal, a Slack message, an email, and the one marketing page that decides whether they try it at all.

1. **The terminal is the UI.** Tables, color, and completion are not decoration; they are the difference between `jq`-piping every command and reading output directly. Respect `NO_COLOR` and non-TTY pipes.
2. **Every approval is an audit artifact.** An approve/reject that records *who* but not *why* loses the single most valuable field at incident-review time. Justification capture is a correctness requirement wearing a UX hat.
3. **Reversible-by-default for destructive ops.** A killswitch with no `--dry-run` is a footgun. Show the blast radius before the bang.
4. **No new always-on surface.** Nothing here adds a server users must remember to open. The marketing site stays a single static file; the CLI stays a thin HTTP wrapper.
5. **Observable.** Every new behavior emits a metric (§7), consistent with `ui-less-surfaces.md` §3.

---

## 3. Surface A — `proxilion-cli` delight

Reference: [crates/cli/src/main.rs](../../crates/cli/src/main.rs). The CLI already has `pretty | json | ndjson` formats, SSE tail, `$EDITOR` policy edit, and humantime parsing. The gaps below are what stop it from feeling first-class.

### 3.1 Colored, aligned tables for every list command — `[x]` Done (2026-06-11)

Today `blocked list` and `policy list` print raw JSON ([main.rs](../../crates/cli/src/main.rs) `blocked`/`policy` arms); only `actions list` renders a table. **Requirement:** every `*-list` command's `pretty` format renders an aligned ASCII table. Minimum columns:

| Command | Columns |
|---|---|
| `blocked list` | `blocked_id` · `p_0` · `policy_id` · `status` · `expires_at` |
| `policy list` | `policy_id` · `mode` · `layer` · `last_reload` |
| `clients list` | `client_id` · `name` · `created_at` · `revoked` |

`--format json` / `ndjson` behavior is unchanged.

*Implementation note (2026-06-11):* `blocked list` and `policy list` already rendered aligned tables; the gap was `clients list` (raw JSON, no `--format`). It now takes `--format pretty|json` and renders the `client_id · name · created_at · revoked` table. A fully shared auto-width helper across all three is deferred — each table uses fixed column widths today; unifying them is cosmetic and not blocking.

### 3.2 Global `--color auto|always|never`, honoring `NO_COLOR` — `[x]` Done (2026-06-11)

Color constants exist but are applied inconsistently. **Requirement:** a top-level `--color` flag (default `auto`) gates all ANSI output. `auto` = color iff stdout is a TTY. `never`, the `NO_COLOR` env var, and a non-TTY pipe all disable color. One `should_color()` predicate, checked at every styled write-site.

*Implementation note (2026-06-11):* The four `const` SGR codes were replaced with a runtime-gated `colors()` tuple resolved once in `main` via `set_color_mode` (`--color` + `NO_COLOR` + `stdout().is_terminal()`); the decision logic is the pure, unit-tested `resolve_color`. Each styled write-site binds the subset it needs (`let (GREEN, RED, ..) = colors();`), so the format strings are untouched and a single predicate gates everything.

### 3.3 `--dry-run` on every destructive command — `[x]` Done (2026-06-11)

`killswitch session|user|all` ([main.rs](../../crates/cli/src/main.rs) killswitch arm) executes after only a `--confirm yes` gate. **Requirement:** `--dry-run` resolves the target and prints the blast radius (count of sessions/bearers that *would* be revoked, the resolved `p_0`/session ids) **without** calling the revoke endpoint. Applies to `killswitch *`, `clients revoke`, and `actions purge`. This needs a proxy-side read-only "resolve target" path (count only) — see §9 Phase 2.

*Implementation note (2026-06-11):* Resolved per open question #2 with a **server count** (no TOCTOU gap). `KillBody` gained `dry_run: bool`; each killswitch handler ([api/killswitch.rs](../../crates/proxy/src/api/killswitch.rs)) runs `SELECT count(*)` against the same predicate as the real UPDATE and returns a `KillResponse { record_id: nil, bearers_revoked: <count>, dry_run: true }` with no UPDATE, no `kill_records` row, and no cache write (the `all` dry-run skips the `confirm` gate since a preview is read-only). `clients revoke --dry-run` previews client-side (the CLI owns the postgres connection for `clients`); `actions purge --dry-run` already existed server-side. **Bug fixed alongside:** the CLI's `killswitch all` validated `--confirm yes` locally but never forwarded `confirm` in the request body, so a real fleet kill would have been rejected by the server's `confirm` gate — the CLI now forwards it.

### 3.4 Shell completion — `[x]` Done (2026-06-11)

**Requirement:** `proxilion-cli completion bash|zsh|fish` emits a completion script via `clap_complete`. Documented in `README.md` install section. Subcommand discovery without memorization is the single biggest first-run ergonomics win.

### 3.5 Progress feedback on long operations — `[x]` Done (2026-06-11)

`actions export` and `policy simulate` can stream thousands of rows with only a trailing `eprintln`. **Requirement:** when stderr is a TTY, show a lightweight progress indicator (rows processed, elapsed). Suppressed under `--format json`, non-TTY, and `--color never`. No new heavy dependency — a periodic stderr counter is sufficient.

*Implementation note (2026-06-11):* A small `Progress` helper renders a throttled (~8×/s) single-line `\r<label>: <n> <unit> · <elapsed>s` to stderr. Active only when `format != "json"`, `--color never` is unset, and `stderr().is_terminal()` — so machine pipelines and piped stderr stay clean. Wired into `actions export` (bytes) and `policy simulate` (rows). No new dependency.

### 3.6 Actionable error messages — `[x]` Done (2026-06-11)

Errors like `invalid --older-than` ([main.rs](../../crates/cli/src/main.rs)) state the problem but not the fix. **Requirement:** parse-failure messages name the accepted forms (e.g. `expected RFC3339 timestamp or duration like "24h", "7d"`). Bounded scope: the ~6 user-input parse sites, not a framework.

---

## 4. Surface B — human-in-the-loop approval delight

References: [notifier/slack.rs](../../crates/proxy/src/notifier/slack.rs), [notifier/email.rs](../../crates/proxy/src/notifier/email.rs), [api/notifier_slack.rs](../../crates/proxy/src/api/notifier_slack.rs), the email approve/reject landing handler in [api/notifier_public.rs](../../crates/proxy/src/api/notifier_public.rs).

### 4.1 Capture justification on approve — `[x]` Done (2026-06-11) (audit-critical)

Both surfaces record the approver but synthesize the justification (`"approved via Slack by {approver}"`). The reviewer-supplied *reason* — the field that matters six months later — is never captured.

**Requirement:**
- **Slack:** the **Approve** button opens a Block Kit modal with a single required free-text "Justification" input before the override commits. **Reject** opens the same modal (reason optional). The entered text becomes the override `justification`, replacing the synthesized string. **`[x]` Done (2026-06-11)** — when a Slack *bot* token is configured via `PROXILION_SLACK_BOT_TOKEN`, the Approve/Reject click calls `views.open` ([api/notifier_slack.rs](../../crates/proxy/src/api/notifier_slack.rs) `justification_modal` + `views_open`) and the modal's `view_submission` commits the override with the entered text (`handle_view_submission`), enforcing the same ≥ 20-char minimum as the email form. **Graceful degradation:** with no bot token the original direct-commit path (synthesized justification) is unchanged, so incoming-webhook-only installs are unaffected — the bot token lives in the env, not the per-driver `notifier_config` row, so this is purely additive (no struct/schema/pin change). The pure helpers (modal JSON, `view_submission` parse, round-trip) and the `views.open` call (via wiremock) are unit-tested.
- **Email:** the approve/reject link lands on a confirmation page (it already redirects to `/notifier/approve?t=…`) that now renders a short form with a justification textarea and a confirm button. This also fixes the email-client link-prefetch hazard (a prefetch can today consume the single-use token silently) — the token is consumed on **form POST**, not on GET. **`[x]` Done** — already in place: [api/notifier_public.rs](../../crates/proxy/src/api/notifier_public.rs) renders a form on `GET /notifier/approve` (no consumption) and consumes the token + commits the override only on `POST`, with a ≥ 20-char justification required on approve and a reason required on reject.
- **CLI:** `blocked approve <id> --justification "<text>"` makes `--justification` required for `approve` (optional for `reject`). **`[x]` Done** — already in place: `--justification` is a required `String` arg on `approve` and `--reason` is `Option<String>` on `reject`.

The justification column already exists on the override audit row; this populates it with human intent instead of boilerplate.

### 4.2 Email "View details (no action)" link — `[~]` Largely covered

Slack has a non-destructive **Why?** button; email has no read-only path — to see full context an operator must approve or reject. **Requirement:** the email body gains a `View details` link to a read-only page (no token consumption) showing policy, matched detail, requested ops, and the request snapshot. Mirrors Slack's forensic affordance.

*Note (2026-06-11):* The `GET /notifier/approve?t=…` landing already **is** a read-only page (it renders the form without consuming the token) showing policy, matched detail, requested ops, and the request snapshot. A *dedicated* "View details" link distinct from the approve/reject CTA is the only remaining nicety and is low value given the landing is already non-destructive.

### 4.3 Absolute "expires at" timestamp — `[x]` Done (2026-06-11)

Messages say "expires in 30 minutes" (relative, computed at send) — misleading once the message sits unread. **Requirement:** Slack footer and email body show an absolute `expires_at` (UTC, e.g. `2026-06-11 14:35 UTC`) alongside or instead of the relative phrasing.

### 4.4 Inline the matched detail (stop truncating to 140 chars) — `[x]` Done (2026-06-11)

Slack truncates `detail` to 140 chars ([notifier/slack.rs](../../crates/proxy/src/notifier/slack.rs)); email truncates similarly. The matched pattern / rule is often exactly what the approver needs and is exactly what gets cut. **Requirement:** show the matched rule id and a longer detail excerpt (Slack section block tolerates ~3000 chars) inline, so a confident approve needs zero clicks.

*Implementation note (2026-06-11):* Slack now renders the detail as a full-width `section` block (`*Matched rule:* \`<policy_id>\`` + detail capped at 2900 chars) instead of a 140-char `context` element. Email already inlined the policy id and full (un-truncated) detail, so no email change was needed.

---

## 5. Surface C — marketing site delight

Reference: [site/index.html](../../site/index.html) — a single static file, strong on SEO/accessibility/semantics. Keep it one file; keep JS minimal and inline.

### 5.1 Dark-mode toggle — `[x]` Done (2026-06-11)

The CSS variables and theming are already in place but `<meta name="color-scheme">` is `light` only — a dark-OS visitor gets a light page with no escape. **Requirement:** ~20 lines of inline JS toggling a `data-theme` attribute, persisted to `localStorage`, defaulting to `prefers-color-scheme`. No framework, no build step.

### 5.2 Copy-to-clipboard on the install command — `[x]` Done (2026-06-11)

The `git clone …` snippet is plain selectable text. **Requirement:** a copy button using the Clipboard API with a "Copied" confirmation. Highest-ROI conversion polish on the page.

### 5.3 Safe external links — `[x]` Done (2026-06-11)

External links (GitHub, pic-protocol.org) lack `rel="noopener"`. **Requirement:** add `rel="noopener noreferrer"` (and `target="_blank"` where opening a new tab is intended) to every off-site link. Small security + UX correctness fix.

### 5.4 Mobile install-snippet scroll affordance — `[x]` Done (2026-06-11)

The install box is `overflow-x: auto` with no visual cue it scrolls on a phone. **Requirement:** a fade/scroll indicator so mobile visitors don't miss the tail of the command. Lowest priority.

---

## 6. Correctness fixes (the bug work-stream)

Each item: file:line, the defect, why it is wrong, impact, the fix, and the regression test that proves it. Severity ranked. Findings #1 and #2 are blocking and land in Phase 0 (§9) **before** any delight work.

### 6.1 HIGH — Path / SSRF injection in Drive & Gmail adapters — `[x]` Done (2026-06-11)

**Where:** [google_drive.rs:76](../../crates/proxy/src/adapters/google_drive.rs#L76) (`get_file`), [google_drive.rs:99](../../crates/proxy/src/adapters/google_drive.rs#L99) (`export_file`), [google_gmail.rs:150](../../crates/proxy/src/adapters/google_gmail.rs#L150) (`get_message`).

**Defect:** the attacker-controlled path id is interpolated raw:
```rust
upstream_path: format!("/drive/v3/files/{}", file_id),
```
This string becomes the upstream URL at [google_drive.rs:358](../../crates/proxy/src/adapters/google_drive.rs#L358) / [google_gmail.rs:407](../../crates/proxy/src/adapters/google_gmail.rs#L407) (`format!("{}{}", base, upstream_path)` → `reqwest.get(url)`). axum percent-**decodes** the `{id}` path param before the handler sees it, so a `file_id` carrying `?`, `#`, or an encoded `/` (e.g. `..%2F..%2Foauth2%2Fv4%2Ftoken`) re-injects literal path/query/fragment delimiters and steers the call to a **different** Google endpoint than the one the action label, policy layer, and PIC chain were evaluated against.

**Why it's a bug, not intent:** the Calendar adapter percent-encodes *every* segment via `urlencoding()` ([google_calendar.rs:101-133](../../crates/proxy/src/adapters/google_calendar.rs#L101-L133)); Drive and Gmail simply omit it. An inconsistency, not a design choice.

**Impact:** confused-deputy / authorization-bypass on the exact requests the proxy exists to gate. HIGH.

**Fix:** percent-encode each interpolated id. Promote Calendar's `urlencoding()` into a shared adapter helper (e.g. `adapters::path_segment()`) and call it at all three sites.

**Test:** unit test asserting `get_file("a/b?x")` / `get_message("..%2F..")` produce an `upstream_path` with the delimiters percent-escaped; mirror Calendar's existing `urlencoding_escapes_slashes` test ([google_calendar.rs:952](../../crates/proxy/src/adapters/google_calendar.rs#L952)).

### 6.2 HIGH — Policy matcher never matches list-valued body fields — `[x]` Done (2026-06-11)

**Where:** [match_expr.rs:110](../../crates/policy-engine/src/match_expr.rs#L110) (`eval_field` resolves `let lhs = ctx.lookup(field);`) and the `in` / `not_in` / `equals` arms of `apply_op` ([match_expr.rs:132-141](../../crates/policy-engine/src/match_expr.rs#L132-L141)).

**Defect:** `eval_field` resolves the LHS once as a **scalar**. When the body field is a JSON **array** (e.g. `body.to_domains = ["evil.com","spam.com"]`), `lookup` stringifies it to the JSON literal `["evil.com","spam.com"]`, so `in`/`not_in` compare each allowed element against that whole bracketed string — never equal. The correct primitive already exists and is tested — `RequestContext::lookup_list` ([context.rs:38](../../crates/policy-engine/src/context.rs#L38)) — but `match_expr` never calls it. A test comment even records operators "work around this" ([context.rs](../../crates/policy-engine/src/context.rs) line ~645).

**Impact:** the flagship Layer-B example from `spec.md` §9 — `gmail-external-send-gate` ("block when a recipient domain is not in the allowed set") — does not work. An `in`-style **allow**-gate over an array silently never fires (**fails open** — the dangerous direction); a `not_in` **block**-gate matches unconditionally (blocks everything). HIGH.

**Fix:** when `ctx.lookup_list(field)` returns `Some(elements)`, apply set semantics element-wise (define and document: `in` = any-element-in-set, `not_in` = no-element-in-set). Thread the field name into `apply_op`, or resolve both scalar and list forms in `eval_field` and dispatch on shape.

**Test:** policy fixture with `body.to_domains = ["a.com","b.com"]` asserting `in: ["a.com"]` matches and `not_in: ["c.com"]` matches, plus the negative cases. Wire the actual `gmail-external-send-gate` YAML from `spec.md` §9 into an end-to-end engine test so the regression can't recur silently.

### 6.3 MEDIUM — Burst-suppressor bucket map grows unbounded — `[x]` Done (2026-06-11)

**Where:** [notifier/burst.rs:193](../../crates/proxy/src/notifier/burst.rs#L193) (`admit` → `entry(key).or_default()`), [notifier/burst.rs:221-243](../../crates/proxy/src/notifier/burst.rs#L221-L243) (`drain_summaries`).

**Defect:** `buckets: HashMap<(String, Option<String>), Bucket>` is keyed on `(policy_id, p_0)`. `drain_summaries` uses `iter_mut` and only resets counters — entries are **never removed**. `p_0` is high-cardinality, partly attacker-influenced principal identity, so a stream of blocks across many `p_0` values grows the map for the process lifetime.

**Impact:** slow unbounded memory growth (DoS-of-degree). MEDIUM.

**Fix:** in `drain_summaries` (or a periodic sweep) drop buckets whose timestamp window is empty after pruning and whose `suppressed == 0`.

**Test:** insert N distinct `p_0` keys, advance the clock past the window, drain, assert `buckets.len()` returns to 0.

### 6.4 MEDIUM — Federation `state` claim never bound to the session (replay) — `[x]` Done (2026-06-11)

**Where:** [oauth/bridge.rs:30](../../crates/proxy/src/oauth/bridge.rs#L30) (`FederationClaims.state`), [oauth/routes.rs:190-228](../../crates/proxy/src/oauth/routes.rs#L190-L228) (`bridge_callback_body`).

**Defect:** `FederationClaims.state` is parsed but never compared to `params.state` (the session UUID) in the bridge callback. A federation token minted for one session can be replayed into another. (The sibling issue — `validate_federation_token` being payload-only with no signature check, [bridge.rs:74](../../crates/proxy/src/oauth/bridge.rs#L74) — is a *documented* pre-production stub per the module header and `spec.md` §0.4; the missing `state` binding is **not** documented.)

**Impact:** session-fixation / replay across federation callbacks. MEDIUM (gated behind the same not-yet-production federation path, but should be fixed alongside the signature step, not after).

**Fix:** in `bridge_callback_body`, reject when `claims.state != params.state`. Add it next to the signature-verification TODO so they ship together.

**Test:** callback with a token whose `state` differs from the query `state` returns 400/401 and does not establish a session. **`[x]` Done (2026-06-11)** — the pure check is unit-tested (`federation_state_matches_only_when_claim_equals_session`), and the end-to-end property is now pinned by a DB-backed integration test ([oauth/routes.rs](../../crates/proxy/src/oauth/routes.rs) `db_backed_bridge_callback_binds_session_on_match_and_rejects_replay`): a matching-state token writes `pca_0_id`/`p_0`/`granted_ops` to the session, while a mismatched-state token returns `BridgeRejected` (401) and leaves the target session **untouched** (`pca_0_id` still NULL — the replay is blocked *before* the UPDATE). Runs in the CI `integration` job.

### 6.5 LOW/MEDIUM — Retryable HTTP 429 dropped as permanent in all forwarders — `[x]` Done (2026-06-11)

**Where:** [forwarder/siem.rs:200](../../crates/proxy/src/forwarder/siem.rs#L200), [forwarder/siem.rs:323](../../crates/proxy/src/forwarder/siem.rs#L323), [notifier/webhook.rs:172](../../crates/proxy/src/notifier/webhook.rs#L172), [notifier/webhook.rs:243](../../crates/proxy/src/notifier/webhook.rs#L243).

**Defect:** retry logic treats `status().is_client_error()` (all 4xx) as permanent. `429 Too Many Requests` is retryable — Slack, PagerDuty, Datadog, and Splunk HEC all rate-limit with 429. Under load, deliverable audit/notification events are silently dropped.

**Impact:** audit/notification delivery loss exactly when volume is highest. LOW/MEDIUM.

**Fix:** special-case `StatusCode::TOO_MANY_REQUESTS` (and arguably `408 Request Timeout`) into the 5xx retry branch; honor `Retry-After` when present.

**Test:** mock upstream returns 429 then 200; assert the forwarder retries and succeeds.

### 6.6 LOW — Still-valid bearer rejected up to 60s early when no refresh token — `[x]` Done (2026-06-11)

**Where:** [auth_middleware.rs:207-213](../../crates/proxy/src/auth_middleware.rs#L207-L213).

**Defect:** `needs_refresh = expires_at <= now + 60s`. When true **and** there is no refresh token, the middleware returns `AuthFail::Refresh` → 401, even though the Google access token is still valid for up to 60 more seconds.

**Impact:** spurious 401s ~60s before true expiry on refresh-token-less sessions. LOW.

**Fix:** when no refresh token is present, reject only if actually expired (`expires_at <= now`); otherwise forward with the still-valid token and let Google 401 naturally at true expiry.

**Test:** session with `expires_at = now + 30s` and no refresh token forwards successfully rather than 401-ing.

### 6.7 LOW — PCA chain walk lacks depth bound; `u32` hop overflow — `[x]` Done (2026-06-11)

**Where:** [pic/verifier.rs:154-207](../../crates/proxy/src/pic/verifier.rs#L154-L207) (`walk`), [pic/verifier.rs:245](../../crates/proxy/src/pic/verifier.rs#L245) (`parent.hop + 1`).

**Defect:** the chain walk follows `predecessor_id` with no visited-set and no max-hop cap; a crafted deep chain forces unbounded DB round-trips (bounded only by the strictly-increasing hop invariant — DoS-of-degree, not a hang). Separately, `parent.hop + 1` on `u32` panics in debug / wraps in release for a crafted `hop == u32::MAX` row.

**Impact:** cold-path DB amplification + a panic/wrap edge. LOW.

**Fix:** add a sane `MAX_CHAIN_HOPS` bound returning a verification error past the cap; replace `parent.hop + 1` with `parent.hop.checked_add(1)` and treat overflow as invalid.

**Test:** a 1000-hop synthetic chain is rejected at the cap; a `hop == u32::MAX` parent yields a verification error, not a panic.

### 6.8 Minor — confirm-or-document (not scheduled)

Recorded for triage. Two items resolved:

- **(resolved)** `nats.rs` `sanitize_token` keeps `.` though the doc comment claimed subjects "can't contain" it — the comment was self-contradictory, since `.` is the NATS token *separator* and is deliberately preserved so a dotted action (`gmail.messages.send`) expands into the documented `<prefix>.<vendor>.gmail.messages.send` hierarchy (subscribed as `actions.*.gmail.messages.send`). Rewrote the comment in [forwarder/nats.rs](../../crates/proxy/src/forwarder/nats.rs) to state this explicitly and to name the genuinely-reserved chars that `sanitize_token` neutralizes (space, `*`, `>`). No code change — the keep-`.` behavior was already correct.
- **(resolved)** Google tokens were persisted before the `pca1_ops.is_empty()` check, orphaning encrypted `google_tokens` rows on an empty scope intersection. The intersection + empty-rejection now runs immediately after the token exchange, *before* `persist_google_tokens`, so an empty-intersection callback returns `PicInvariant` without writing a row no bearer would reference ([oauth/routes.rs](../../crates/proxy/src/oauth/routes.rs)).

A third item resolved:

- **(resolved)** `err_to_result` hardcoded `links_verified: 0` (and `p_0: None`) on every chain-verification failure, discarding how far the walk got before the break. A break 3 hops deep reported `links_verified: 0`, so the dashboard chain-walker showed "nothing verified" even when most of the chain was sound. `walk` now accumulates `links_verified` + `p_0` into a `WalkProgress` owned by `verify_chain`; the `?`-early-returns leave it holding the partial state, which `err_to_result` reports instead of zeroing ([pic/verifier.rs](../../crates/proxy/src/pic/verifier.rs)). Pinned by `err_to_result_carries_partial_walk_progress_not_zero`.

The fourth (and final) item — **confirmed correct, documented, and a related gap fixed:**

- **(confirmed by design)** The read-filter egress allowlist skips binary types, so `BlockRequest`/`ReplaceWithMarker` don't apply to a Drive `export` of PDF/docx. This is exactly what `spec.md` §1.4 mandates — *"Filtering binary file exports is meaningless — gate on content-type."* Quarantine patterns are textual; scanning compressed binary bytes is wasted work and a false-positive risk. A policy that wants to stop a binary export wholesale expresses that as a Layer-B action gate on `drive.files.export`, not as a read-filter content match. Captured the rationale in a doc comment on `should_scan` ([adapters/read_filter.rs](../../crates/proxy/src/adapters/read_filter.rs)) so this doesn't get re-flagged as an oversight.
- **(resolved — related gap found while confirming the above)** The sibling §1.4 requirement — *"Buffer responses with a 10MB cap; reject larger"* — was enforced as `resp.bytes().await` followed by a length check, which buffers the **entire** body into memory *before* the check. An upstream that omits `Content-Length` and streams past the cap would be fully buffered first, defeating the cap as a memory bound. Replaced the byte-identical `read_bounded` copied across all three Google adapters with one shared `adapters::read_bounded` that streams chunk-by-chunk and aborts the instant the running total would exceed the cap — a *true* memory bound ([adapters/mod.rs](../../crates/proxy/src/adapters/mod.rs)). Pinned by `read_bounded_rejects_oversized_body_with_no_content_length` (+ under-cap / exact-cap boundary tests).

---

## 7. New & changed metrics

Consistent with `ui-less-surfaces.md` §3, every new behavior is observable:

| Metric | Type | Surface | Why |
|---|---|---|---|
| `proxilion_override_justification_present_total{surface,decision}` | counter | §4.1 | Track that approvals carry real justification (vs empty) per surface |
| `proxilion_adapter_path_encoded_total{vendor}` | counter | §6.1 | Confidence the encode path is exercised in prod |
| `proxilion_policy_list_match_total{op,result}` | counter | §6.2 | Detect list-field gates actually firing post-fix |
| `proxilion_forwarder_retry_total{forwarder,status}` | counter | §6.5 | Surface 429-driven retries |
| `proxilion_burst_buckets` | gauge | §6.3 | Prove the map stays bounded |

*Status (2026-06-13): all five series wired + dashboarded.* An audit found
that while `proxilion_forwarder_retry_total` (§6.5) and
`proxilion_burst_buckets` (§6.3) shipped with their respective fixes, the other
three series in this table were declared here but never emitted. Closed:

- `proxilion_override_justification_present_total{surface,decision}` — emitted
  in [api/blocked.rs](../../crates/proxy/src/api/blocked.rs) `approve_inner` /
  `reject_inner` on every committed override, gated on non-empty justification
  text, labelled by the existing `channel` surface (`api`/`email`/`slack`) and
  the decision. Divided by `proxilion_overrides_resolved_total` it yields the
  per-surface fill rate. Threading the surface label into `reject_inner` also
  fixed a latent mislabel — the reject path hardcoded `channel="api"` for the
  pre-existing `overrides_resolved_total` counter regardless of the real
  surface.
- `proxilion_adapter_path_encoded_total{vendor}` — emitted by the new
  `adapters::encoded_segment(vendor, s)` wrapper that every Drive/Gmail/Calendar
  production call site now routes through; the pure `path_segment` stays
  metric-free for the encoding unit tests.
- `proxilion_policy_list_match_total{op,result}` — emitted in
  [match_expr.rs](../../crates/policy-engine/src/match_expr.rs) `apply_op` on the
  §6.2 list-valued path, labelled by operator (`in`/`not_in`/`equals`/
  `not_equals`) and outcome (`match`/`no_match`), proving the flagship gate
  actually fires post-fix. Added `metrics` (the no-op-without-recorder facade)
  to the policy-engine crate for this.

The bundled Grafana dashboard ([ops/grafana/proxilion.json](../../ops/grafana/proxilion.json))
gained an "Approval quality & resource bounds" row with the override-justification
fill-rate and burst-bucket panels (§9 Phase 5 step 15).

CLI/site items (§3, §5) are client-side and emit no server metrics.

---

## 8. Out of scope (explicit non-goals)

- **A web dashboard, in any form.** Re-affirms `ui-less-surfaces.md` §0. The marketing site stays a single static file; it is not an app.
- **A TUI.** The CLI gains tables and color, not a full-screen interactive interface.
- **Slack/email snooze, escalation, per-policy channel routing.** Already tracked as deferred in `ui-less-surfaces.md` §5.7; this spec does not pull them forward.
- **Federation signature verification.** The documented stub ([bridge.rs:74](../../crates/proxy/src/oauth/bridge.rs#L74)) stays out of scope here; §6.4 fixes only the *undocumented* state-binding gap. Full federation lands with the bridge service (`spec.md` §0.4).
- **Rich text / WYSIWYG anything.** Plain text, markdown, Block Kit — no editors.

---

## 9. Implementation playbook (per-step, with verify criteria)

Ordered so correctness blockers land first. Each step is independently shippable.

**Phase 0 — Blocking fixes (do first)**
1. §6.1 adapter path encoding → **verify:** new escaping unit tests pass; existing adapter tests unaffected; manual `cargo test -p proxilion-proxy adapters` green.
2. §6.2 list-valued policy matching → **verify:** `gmail-external-send-gate` end-to-end engine test (the §9 YAML) blocks an external domain and allows an internal one; scalar-field tests unchanged.

**Phase 1 — Remaining correctness**
3. §6.3 burst-map bounding → **verify:** map returns to 0 after drain past window.
4. §6.4 federation state binding → **verify:** mismatched-state callback rejected.
5. §6.5 429 retry → **verify:** mock 429-then-200 retries and succeeds.
6. §6.6 bearer near-expiry → **verify:** 30s-remaining no-refresh session forwards, not 401.
7. §6.7 chain-walk bound + checked hop → **verify:** deep chain capped; `u32::MAX` hop errors not panics.

**Phase 2 — CLI delight**
8. §3.2 `--color` + `should_color()` → **verify:** `NO_COLOR=1` and piped stdout emit no ANSI; TTY emits color.
9. §3.1 list tables → **verify:** `blocked list` / `policy list` / `clients list` pretty output is an aligned table; `--format json` byte-identical to today.
10. §3.3 `--dry-run` (needs proxy read-only resolve-count path) → **verify:** `killswitch user <p0> --dry-run` prints a count and makes no revoke call (assert via metrics/no state change).
11. §3.4 completion, §3.5 progress, §3.6 error messages → **verify:** completion script sources cleanly in bash/zsh; long export shows a counter on a TTY only; parse errors name accepted forms.

**Phase 3 — Approval delight**
12. §4.1 justification capture (Slack modal + email form + CLI flag) → **verify:** override audit row carries operator-entered text; email token consumed on POST not GET (prefetch-safe).
13. §4.2 email view-details, §4.3 absolute expiry, §4.4 inline detail → **verify:** read-only page consumes no token; messages show a UTC `expires_at`; matched rule id visible without truncation.

**Phase 4 — Site delight**
14. §5.1 dark-mode toggle, §5.2 copy button, §5.3 `rel=noopener`, §5.4 scroll cue → **verify:** toggle persists across reload and respects `prefers-color-scheme`; copy button writes the clone command to the clipboard; all external links carry `rel="noopener noreferrer"`.

**Phase 5 — Observability** — `[x]` Done (2026-06-13)
15. §7 metrics → **verify:** each new series appears in `GET /metrics` and the bundled Grafana dashboard (`ops/grafana/proxilion.json`) references the override-justification and burst-bucket series. **Done:** all five §7 series are now emitted (the three that were declared-but-unwired — `override_justification_present`, `adapter_path_encoded`, `policy_list_match` — were closed 2026-06-13; see §7 Status) and the dashboard's new "Approval quality & resource bounds" row references both required series.

---

## 10. Open questions

1. ~~**List-match set semantics (§6.2):** is `in` over an array "any element matches" or "all elements match"?~~ **Resolved 2026-06-11:** `in` = any-element-in-set, `not_in` = no-element-in-set, `equals` = single-value membership, `not_equals` = non-membership. Implemented in [match_expr.rs](../../crates/policy-engine/src/match_expr.rs) `apply_op` and pinned by the end-to-end `list_match_blocks_fully_external_recipient_set` test in [gmail_external_send.rs](../../crates/policy-engine/tests/gmail_external_send.rs).
2. ~~**Dry-run count endpoint (§3.3):** server count or client-side resolve?~~ **Resolved 2026-06-11:** server count. The killswitch handlers accept `dry_run` and run a `SELECT count(*)` against the same predicate as the real revoke, so the preview matches execution with no TOCTOU gap (no separate route, just a read-only branch on the existing endpoints). `clients revoke` previews client-side because the CLI already owns the `clients` postgres connection.
3. **Justification requiredness (§4.1):** required on **approve** is settled (audit value); is it also required on **reject**, or optional? Default proposed: required on approve, optional on reject.
4. **Email confirmation page hosting (§4.1, §4.2):** the approve/reject/view pages are served by the proxy itself ([api/notifier_public.rs](../../crates/proxy/src/api/notifier_public.rs)). Confirm this stays in-proxy and is not pushed to the static site (it needs request state and token validation).
5. **Override TTL enforcement (`ApproveBody.ttl_minutes`):** `POST /api/v1/blocked/{id}/approve` accepts and bounds-validates `ttl_minutes` (1..=1440) but does **not** yet apply it — `PicExecutor::mint_successor` takes no expiry and `pca_cache` has no `expires_at` column, so an override's real lifetime is governed by the PCA chain, not the requested TTL. As of 2026-06-15 the field docstring states this honestly (accepted now so the wire contract is stable). Proper enforcement needs either an upstream `successor-with-attestation` endpoint that stamps a PoC expiry (the same blocker as the spec.md §6.6 operator-attestation branch) **or** a proxy-side `pca_cache.expires_at` column the verifier/auth-path honors. Decide which when the §6.6 upstream work lands; until then, do not advertise TTL as enforced.
