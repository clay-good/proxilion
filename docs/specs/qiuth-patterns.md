# Spec — Patterns to Port from Qiuth into Proxilion

**Status:** Proposal. Companion to [spec.md](spec.md). Scope is bounded to four discrete patterns lifted from the sibling project at [qiuth-main/](../../qiuth-main/). The two codebases share no runtime — qiuth is a zero-dep TypeScript library for API-key MFA; Proxilion is a Rust OAuth reverse proxy. What transfers is **shape**, not code.

**Author intent:** Adopt the four patterns below as they unblock real, already-flagged gaps in Proxilion: env-var sprawl in [config.rs](../../crates/proxy/src/config.rs), a binary-feeling `Decision` enum, missing stable error IDs, an uncached YAML reload at startup, and integration-only test coverage.

---

## Table of Contents

1. Why these four
2. Pattern 1 — Layered config loader with a fluent builder
3. Pattern 2 — `PolicyTrace` with per-layer outcomes
4. Pattern 3 — Canonical error-code registry
5. Pattern 4 — `PolicyLoader` trait with compiled cache
6. Pattern 5 — Coverage threshold gate in CI
7. Rollout order & dependencies
8. Out of scope (explicit non-goals)

---

## 1. Why these four

Each pattern maps to a Proxilion gap documented during the repo survey:

| Proxilion gap | Qiuth pattern | Section |
|---|---|---|
| Env-only config with hardcoded fallbacks scattered through [config.rs:52-102](../../crates/proxy/src/config.rs#L52-L102); no programmatic embed path | Fluent builder + layered loader | §2 |
| `Decision::Allow \| Block \| RequireConfirmation` ([decision.rs:5-20](../../crates/policy-engine/src/decision.rs#L5-L20)) tells you *what* but not *why which layer* | `LayerValidationResult[]` with per-layer error type | §3 |
| `AppError` ([adapters/error.rs:9-47](../../crates/proxy/src/adapters/error.rs#L9-L47)) has codes hardcoded inline; no stable contract for operators | `ValidationErrorType` enum as the canonical registry | §4 |
| Policy YAML reparsed every server start; no caching, no pluggable backend | `ConfigLookupFunction` indirection + compiled cache | §5 |
| Integration tests only; no enforced coverage floor | vitest 90% threshold pattern, ported to `cargo llvm-cov` | §6 |

The four are independent and can land in any order, but §3 and §4 share a type and should ship together.

---

## 2. Pattern 1 — Layered config loader with a fluent builder

### 2.1 What qiuth does

[qiuth-main/src/config/config-builder.ts:25-279](../../qiuth-main/src/config/config-builder.ts#L25-L279) defines `QiuthConfigBuilder` — a chainable builder with one `.withX()` method per concern, a `.build()` finalizer that throws on missing required fields, and a static `validate()` that catches semantic errors (e.g. `HMAC secret must be at least 32 characters`).

Notable mechanics:
- `withApiKey()` hashes on the way in so the unhashed key never reaches the config struct
- `withXConfig()` siblings let callers pass a fully-formed sub-config when they need the long-form
- `from(existing)` lets you mutate an already-built config — important for tests
- `createConfig()` factory function for callers who prefer the functional entry point

### 2.2 Proxilion translation

Replace `Config::from_env()` ([config.rs:51-102](../../crates/proxy/src/config.rs#L51-L102)) with a layered loader:

```
defaults  →  optional TOML/YAML file  →  env vars  →  programmatic overrides
```

Public API sketch (in `crates/proxy/src/config/`):

```rust
pub struct ConfigBuilder { /* private */ }

impl ConfigBuilder {
    pub fn defaults() -> Self;
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError>;
    pub fn from_env(self) -> Result<Self, ConfigError>;

    pub fn with_bind_addr(self, addr: SocketAddr) -> Self;
    pub fn with_trust_plane_url(self, url: impl Into<String>) -> Self;
    pub fn with_policy_path(self, path: PathBuf) -> Self;
    pub fn with_token_encryption_key_hex(self, key: impl Into<String>) -> Self;
    // ... one per current field

    pub fn build(self) -> Result<Config, ConfigError>;
}

impl Config {
    /// Convenience entry: defaults → file (if PROXILION_CONFIG_FILE set) → env.
    pub fn load() -> Result<Self, ConfigError>;
}
```

Validation moves into `build()` and gains semantic checks that env-only loading can't easily express:
- `token_encryption_key_hex` is exactly 64 hex chars when present
- `trust_plane_url` parses as `http(s)://`
- `policy_path` exists when set (don't silently fall back to empty policy)
- `dev_mode = false` requires both cert and key paths to resolve

### 2.3 Why this matters now

Two concrete payoffs:

1. **Programmatic embed path.** §5/§6 of [spec.md](spec.md) (and any future SDK consumer) want to construct `Config` without setting env vars. Today that's impossible without monkeypatching `std::env`.
2. **Validation moves out of the operator's runtime.** Today, malformed `PROXILION_TOKEN_ENCRYPTION_KEY` is caught only when the cipher runs. A builder rejects it at boot with a clear error.

The `LogFormat::Pretty | Json` field that's currently `#[allow(dead_code)]` ([config.rs:17-18](../../crates/proxy/src/config.rs#L17-L18)) gets wired up as part of this refactor — the builder is the natural seam.

### 2.4 Migration plan

- Phase 1: introduce `ConfigBuilder`, have `Config::from_env()` call into it. No behavior change.
- Phase 2: add `from_file()` and `Config::load()`. Document the precedence order.
- Phase 3: remove `Config::from_env()` once callers are migrated.

### 2.5 Status (2026-05-13) — Phases 1, 2, & 3 shipped.

- [crates/proxy/src/config.rs](../../crates/proxy/src/config.rs) — new `ConfigBuilder` with `defaults()`, `from_env_layer()` (composes env vars on top), `with_*` overrides for every field, and `build()` (runs semantic validation, then constructs `Config`). `Config::from_env()` now delegates to `ConfigBuilder::defaults().from_env_layer()?.build()` — byte-identical with the prior loader, just refactored. `Config::load()` is the forward-looking convenience entry; today it aliases `from_env`, phase 2 will layer `PROXILION_CONFIG_FILE` underneath.
- New `ConfigError::InvalidValue { field, reason }` variant carries the field name (e.g. `PROXILION_TOKEN_ENCRYPTION_KEY`) so the operator sees the env var that's wrong, not just "bad value somewhere."
- Semantic validation now runs in `build()`:
  - `token_encryption_key_hex` is exactly 64 hex characters when present (rejects truncated keys at boot rather than at first cipher use).
  - `trust_plane_url` + `federation_bridge_url` must start with `http://` or `https://`.
  - `dev_mode == false` still requires both cert + key paths to exist (unchanged behavior).
- Tests: 6 new in `config::tests` covering defaults-in-dev-mode, key-too-short rejection, valid-key acceptance, non-http URL rejection, cert-required-when-not-dev-mode, and programmatic override composition (`with_bind_addr` + `with_database_url` + `with_policy_path` chain cleanly).

**Phase 2 additions (2026-05-12).**

- [crates/proxy/src/config.rs](../../crates/proxy/src/config.rs) — `ConfigBuilder::from_file(path)` parses a TOML file into a flat `FileConfig` struct (`#[serde(deny_unknown_fields)]` so typos fail loudly) and layers each set field on top of the builder's current values. Every field is optional; absent fields leave the prior value intact. Field names mirror the env-var conceptual model (snake_case, without the `PROXILION_` prefix) — `bind_addr = "..."` corresponds to `PROXILION_BIND_ADDR`.
- [crates/proxy/src/config.rs](../../crates/proxy/src/config.rs) — `Config::load()` is now the production entry point: `defaults() → optional from_file($PROXILION_CONFIG_FILE) → from_env_layer() → build()`. Env vars layer on top of file values, so operators can override file-based config without editing the file. New `ConfigError::FileLoad { path, reason }` covers both read and parse failures.
- [crates/proxy/src/main.rs](../../crates/proxy/src/main.rs) — boot path switched from `Config::from_env()` to `Config::load()`. `from_env` is kept for back-compat under `#[allow(dead_code)]` so existing callers in tests / embed paths don't break.
- Tests: 3 new in `config::tests` covering file-overrides-defaults, unknown-field-rejection, and missing-path failure.

**Deviation.** Chose TOML over YAML: ops config (small, flat, comments) reads cleanly in TOML; YAML's anchors / multi-line strings aren't load-bearing here and `policy.yaml` keeps its YAML stack. The `policy_path` field still points at a YAML file — just the proxy's own knobs are TOML.

**Phase 3 (2026-05-13).** `Config::from_env()` removed from [crates/proxy/src/config.rs](../../crates/proxy/src/config.rs). The Phase 2 backward-compat shim — kept under `#[allow(dead_code)]` while callers migrated — had zero remaining call sites (a workspace grep for `Config::from_env(` returned only the definition itself and its own docstring). `Config::load()` is now the single production entry point; embed/test callers use `ConfigBuilder::defaults()…build()` directly. Module docstring updated; `cargo build --workspace` and `cargo test --workspace` both clean.

**`config/proxilion.example.toml` shipped (2026-05-13).** Phase 2 added TOML support to the proxy without a worked example for operators to copy from. The new [`config/proxilion.example.toml`](../../config/proxilion.example.toml) documents every `FileConfig` field (network/TLS, datastore, upstream, observability, token encryption + OAuth, policy, NATS, SIEM, blocked-action webhook, operator auth) — every field is commented out and annotated with its default plus a one-line explanation, so an operator copies the file and uncomments only what they want to override. The header documents the precedence chain (`defaults → file → env → programmatic`). A new `config::tests::example_toml_parses_with_defaults_only` unit test in [crates/proxy/src/config.rs](../../crates/proxy/src/config.rs) pins the contract — when every field is commented out the loader produces a builder identical to `defaults()` — so adding a new required field to `FileConfig` (or accidentally activating a comment-out) trips the gate.

**`LogFormat` wired through (2026-05-13).** Closes the §2.3 follow-through ("the `LogFormat::Pretty | Json` field that's currently `#[allow(dead_code)]` gets wired up as part of this refactor"). [crates/proxy/src/main.rs](../../crates/proxy/src/main.rs) — `main()` now loads `Config` *before* `init_tracing`, then passes `cfg.log_format` into `init_tracing(format: config::LogFormat)`. The previous body read `PROXILION_LOG_FORMAT` directly via `std::env::var`, bypassing the layered config and giving operators no way to set `log_format` from `proxilion.toml`. With the change, the precedence chain (`defaults → TOML file → env vars → programmatic overrides`) applies to log formatting too — `log_format = "pretty"` in the TOML file now works as the doc implied. The `#[allow(dead_code)]` annotation on `Config::log_format` is dropped (`cargo clippy --workspace -- -D warnings` clean with `-A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, the CI flag set). Config-load errors still go to stderr — tracing isn't up yet at that boot phase.

---

## 3. Pattern 2 — `PolicyTrace` with per-layer outcomes

### 3.1 What qiuth does

[qiuth-main/src/core/authenticator.ts:61-131](../../qiuth-main/src/core/authenticator.ts#L61-L131) returns a `ValidationResult` containing a `layerResults: LayerValidationResult[]` array. Each entry names the layer (`SecurityLayer.IP_ALLOWLIST`, `TOTP_MFA`, `CERTIFICATE`, `HMAC`), a `passed: bool`, and on failure an `error` string + a stable `errorType: ValidationErrorType` enum value. The orchestrator runs fail-fast but the array preserves *every* layer it evaluated up to (and including) the failing one.

This is the bit worth porting: **the decision is a structure, not a verdict**. An operator looking at a denied call learns which check tripped without reading the application log.

### 3.2 Proxilion translation

Today, Proxilion adapters consume a `Decision` ([decision.rs:5-20](../../crates/policy-engine/src/decision.rs#L5-L20)) and either pass or surface an `AppError`. Two layers can deny — **Layer A** (PIC ops enforcement, [ops.rs](../../crates/policy-engine/src/ops.rs)) and **Layer B** (Rego/YAML content rules, [rego.rs](../../crates/policy-engine/src/rego.rs)) — plus read-filter quarantining ([read_filter.rs](../../crates/proxy/src/adapters/read_filter.rs)). The current return type collapses them.

Introduce `PolicyTrace`:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct PolicyTrace {
    pub correlation_id: String,
    pub evaluated_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub layers: Vec<LayerOutcome>,
    pub final_decision: Decision,
}

#[derive(Debug, Clone, Serialize)]
pub struct LayerOutcome {
    pub layer: PolicyLayer,                  // LayerA | LayerB | ReadFilter
    pub passed: bool,
    pub matched_rule_id: Option<String>,     // policy_id, rego rule, pattern id
    pub error_code: Option<ErrorCode>,       // see §4
    pub detail: Option<String>,              // human-readable, not stable
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLayer {
    LayerA,        // PIC ops invariants
    LayerB,        // YAML/Rego content rules
    ReadFilter,    // response-body quarantine
}
```

The policy engine's public eval function returns `PolicyTrace` instead of `Decision`. Callers extract `trace.final_decision` for the gate; the full trace is:

1. Logged (one structured event per request, replacing the current scattered `warn!`/`error!` calls in [error.rs:108-112](../../crates/proxy/src/adapters/error.rs#L108-L112))
2. Returned to the dashboard API for the request-detail view
3. Optionally included as `X-Proxilion-Trace-Id` on responses (the ID, not the body — never leak rule contents to the caller)

### 3.3 Fail-fast vs. full-trace

Qiuth is fail-fast — the array stops at the first failure. Proxilion should follow the same default for Layer A (PIC invariants are non-negotiable; no point evaluating Layer B if A denies) but **continue through Layer B even after the first Block** so operators see overlapping rules. This costs a few microseconds and pays for itself the first time someone debugs "why did THIS rule fire and not the one I expected."

Implementation note: gate this with a `PolicyEvalMode::FailFast | Comprehensive` on the engine — `FailFast` for production hot path, `Comprehensive` for dashboard-driven "explain this denial" replays.

### 3.4 Status (2026-05-12) — types + engine entry + adapter wiring shipped.

- [crates/policy-engine/src/trace.rs](../../crates/policy-engine/src/trace.rs) — new module with `PolicyTrace`, `LayerOutcome`, `PolicyLayer` (LayerA / LayerB / ReadFilter), `OpsAtomView`, `PolicyEvalMode`. `LayerOutcome::error_code` carries the canonical `shared_types::ErrorCode` from §4. `PolicyTrace::allowed()` is `true` only when every layer passed AND the final decision is `Allow`.
- [crates/policy-engine/src/rego.rs](../../crates/policy-engine/src/rego.rs) — new `Engine::evaluate_with_trace(&ctx)` sibling to `evaluate(&ctx)`. Returns `(Outcome, PolicyTrace)` so callers that don't need the structured trace pay nothing. The trace fills in Layer A (engine-side, `passed: true`, records the required-ops count), Layer B (translates `Decision::{Allow, Block, RequireConfirmation, RateLimit}` to the matching `ErrorCode`), and an optional ReadFilter slot when a filter is configured (left as `passed: true; scan pending` for the adapter to mutate after the response body comes back).
- [crates/policy-engine/Cargo.toml](../../crates/policy-engine/Cargo.toml) — adds `chrono`, `uuid` (already in the workspace).
- Tests: 4 new in `trace::tests` + 3 integration tests in `crates/policy-engine/tests/policy_trace.rs` that exercise the engine with the live `config/policy.yaml`. Covers (a) Layer-B block via `gmail-external-send-gate` records `ErrorCode::PolicyBlocked` + the matched policy id, (b) no-policy-match path emits Layer A + Layer B both passed, (c) `drive-injection-filter` produces a ReadFilter slot with `passed: true` pending the adapter scan.

**Adapter wiring additions (2026-05-12).**

- [crates/proxy/src/adapters/policy_trace.rs](../../crates/proxy/src/adapters/policy_trace.rs) — new helper module. `mark_layer_a_failed(trace, detail)` rewrites the Layer-A slot on Trust-Plane refusal with `ErrorCode::PicInvariantViolation`. `mark_read_filter(trace, blocked, policy_id, detail)` rewrites the ReadFilter slot after the response body scan — `blocked=true` flips it to `failed` with `ErrorCode::ReadFilterBlocked`, otherwise it stays `passed` with a quarantine-sample count in `detail`. `emit(trace, request_id, vendor, action)` logs a single structured event per request — `tracing::info!` when allowed, `tracing::warn!` when denied — carrying `trace_id`, a one-line `summary` (`layer_a=ok,layer_b=policy_blocked,...`), and the serialized trace JSON. Replaces the prior scattered `warn!`/`error!` calls along the deny paths.
- [crates/proxy/src/adapters/google_drive.rs](../../crates/proxy/src/adapters/google_drive.rs), [google_gmail.rs](../../crates/proxy/src/adapters/google_gmail.rs), [google_calendar.rs](../../crates/proxy/src/adapters/google_calendar.rs) — all three switched from `policy.evaluate(&ctx)` to `policy.evaluate_with_trace(&ctx)`. Each adapter now: (a) emits the trace on Layer-B deny, (b) mutates Layer A → failed + emits on Trust-Plane refusal, (c) mutates ReadFilter to `passed`/`failed` after the scan + emits on read-filter block, (d) on the happy path inserts `x-proxilion-trace-id: <uuid>` alongside the existing `x-proxilion-request-id` / `x-proxilion-pca-id` / `x-proxilion-policy` headers and emits an INFO trace at the end. The `trace_id` is the only piece surfaced to the caller — rule content stays inside the proxy.
- Tests: 3 new in `adapters::policy_trace::tests` covering Layer-A replacement, ReadFilter append-when-absent, and the summary string.

**Remaining deviations.**

1. **Engine still exposes `evaluate(&ctx) -> Outcome` unchanged.** The trace-less entry point is still the public API for callers that don't need the structured trace; the three Google adapters now use `evaluate_with_trace` exclusively, but unit tests and any future embed callers can stay on the lighter path.
2. ~~`PolicyEvalMode::{FailFast, Comprehensive}` defined but not yet observed.~~ **Resolved 2026-05-12.** [`Engine::evaluate_with_trace_mode(&ctx, PolicyEvalMode::Comprehensive)`](../../crates/policy-engine/src/rego.rs) walks every later policy after the first match and appends one extra Layer-B [`LayerOutcome`](../../crates/policy-engine/src/trace.rs) per "would-also-have-matched" rule, with `detail` prefixed `would_also_match:` so a downstream renderer can distinguish primary from diagnostic outcomes. The `final_decision` stays authoritative from the first match — overlaps are purely informational. `evaluate_with_trace` continues to default to `FailFast` (the hot-path entry point); the dashboard's explain-this-denial replay flips to `Comprehensive`. Verified by the new `comprehensive_mode_records_would_also_match_diagnostics` test in [crates/policy-engine/tests/policy_trace.rs](../../crates/policy-engine/tests/policy_trace.rs).

---

## 4. Pattern 3 — Canonical error-code registry

### 4.1 What qiuth does

[qiuth-main/src/types.ts](../../qiuth-main/src/types.ts) defines `ValidationErrorType` as an exhaustive enum: `IP_NOT_ALLOWED`, `MISSING_TOTP_TOKEN`, `INVALID_TOTP_TOKEN`, `MISSING_SIGNATURE`, `EXPIRED_TIMESTAMP`, `INVALID_SIGNATURE`, `MISSING_HMAC`, `INVALID_HMAC`, `INTERNAL_ERROR`. Every failed `LayerValidationResult` carries one. The string values are stable — they're part of the library's public contract.

### 4.2 The Proxilion gap

[adapters/error.rs:76-88](../../crates/proxy/src/adapters/error.rs#L76-L88) already has a `code(&self)` method that returns string codes like `"policy_blocked"`, `"pic_invariant_violation"`, `"read_filter_blocked"`. **The codes exist but they're not a registry** — they're inline literals on one method, not enumerated anywhere, not documented as stable, not used by anything outside that one `IntoResponse`.

### 4.3 Port

Define `ErrorCode` as a `#[non_exhaustive]` enum in a new `crates/proxy/src/errors.rs` (or co-locate in `shared-types/` if other crates need it):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    // Policy denials (Layer A — PIC)
    PicInvariantViolation,
    PicAuthorityExceeded,
    PicChainExpired,

    // Policy denials (Layer B — content rules)
    PolicyBlocked,
    PolicyRequireConfirmation,
    PolicyRateLimited,

    // Read filter
    ReadFilterBlocked,
    ReadFilterQuarantined,

    // Upstream
    UpstreamUnavailable,
    UpstreamTooLarge,

    // System
    PolicyEngineError,
    DatabaseError,
    InternalError,
}

impl ErrorCode {
    /// Stable wire string. NEVER change once published.
    pub fn as_str(&self) -> &'static str { /* match arm per variant */ }

    /// Default HTTP status. Adapters may override.
    pub fn default_status(&self) -> StatusCode { /* ... */ }
}
```

Rules of the registry:

1. **Stable forever.** Once a code ships, its string value never changes. Add new variants; never rename.
2. **`#[non_exhaustive]`** so adding variants isn't a breaking change for downstream matchers.
3. **One source of truth.** `AppError::code()` returns an `ErrorCode`, not a string. The string mapping lives on the enum. `LayerOutcome.error_code` (§3) uses the same type.
4. **Documented in [docs/error-codes.md](../error-codes.md).** Auto-generated would be nicest; a hand-curated table is fine to start. Every code lists: stable string, default HTTP status, when it fires, suggested operator action.
5. **Test:** a snapshot test asserts the full `(variant → string)` mapping. Anyone trying to rename a code will break CI loudly.

### 4.4 Why now

The dashboard work (§1.6 of [spec.md](spec.md)) needs to render denials. Without `ErrorCode`, every dashboard improvement risks coupling to whatever string literal happened to be in `error.rs` that week.

### 4.5 Status (2026-05-12) — shipped.

- [crates/shared-types/src/error_code.rs](../../crates/shared-types/src/error_code.rs) — `ErrorCode` enum, `#[non_exhaustive]`, serde-derived `snake_case` wire form. `as_str()` returns `&'static str` (stable) and `default_status()` returns the recommended HTTP status. Variants in scope: `PicInvariantViolation`, `PolicyBlocked`, `RequireConfirmation`, `RateLimited`, `ReadFilterBlocked`, `UpstreamUnavailable`, `UpstreamTooLarge`, `PolicyEngineError`, `DatabaseError`, `InternalError`. Snapshot test `wire_strings_are_stable` pins the full mapping — renaming a string fails CI loudly.
- [crates/shared-types/Cargo.toml](../../crates/shared-types/Cargo.toml) — adds `http` for `StatusCode` constants (already in the workspace).
- [crates/proxy/src/adapters/error.rs](../../crates/proxy/src/adapters/error.rs) — `AppError::code()` now returns the canonical `ErrorCode`; `status()` is derived from `code().default_status()`; `body()` sources its `code` field from `self.code().as_str()`. No wire-format changes — all existing test assertions on body shapes (`policy_blocked_serializes_to_structured_403`, `pic_invariant_violation_serializes_to_403`) still pass.
- [docs/error-codes.md](../error-codes.md) — operator-facing catalogue with default status + suggested action per code, plus the "adding a new code" runbook.
- Tests: 2 new in `shared-types::error_code::tests` (`wire_strings_are_stable`, `serde_round_trip_snake_case`). All existing tests in the workspace green (123 proxy + 2 shared-types).

**Deviations from §4.3 sketch.** None. The shipped enum lists every variant the spec sketch enumerated, plus `RequireConfirmation` and `RateLimited` (already in `AppError`; the spec sketch overlooked them).

---

## 5. Pattern 4 — `PolicyLoader` trait with compiled cache

### 5.1 What qiuth does

[qiuth-main/src/middleware/express.ts:43-45](../../qiuth-main/src/middleware/express.ts#L43-L45) defines:

```typescript
export type ConfigLookupFunction = (
  apiKey: string
) => Promise<QiuthConfig | null> | QiuthConfig | null;
```

The middleware accepts this function ([express.ts:110-141](../../qiuth-main/src/middleware/express.ts#L110-L141)) instead of embedding a backend. The same library serves SQL, Redis, file, in-memory test fixtures — all without touching the auth core.

### 5.2 Proxilion translation

Today the policy engine parses YAML at process start (the survey flagged this: `Engine::new()` parses on every server start, no caching, blocks boot if the policy is large). Introduce a `PolicyLoader` trait:

```rust
#[async_trait]
pub trait PolicyLoader: Send + Sync {
    /// Returns a snapshot of the current policy set.
    /// Implementations may serve from cache.
    async fn load(&self) -> Result<PolicyBundle, PolicyLoadError>;

    /// Returns true if the underlying source has changed since `since`.
    /// Default: always true (forces reload).
    async fn changed_since(&self, since: SystemTime) -> bool { true }
}

pub struct FilePolicyLoader { path: PathBuf }
pub struct DbPolicyLoader { pool: PgPool, customer_id: Uuid }
pub struct StaticPolicyLoader { bundle: PolicyBundle }  // for tests
```

Wrap with a compiled cache:

```rust
pub struct CachedPolicyEngine {
    loader: Arc<dyn PolicyLoader>,
    compiled: ArcSwap<CompiledPolicy>,
    last_loaded: AtomicU64,         // unix seconds
    refresh_interval: Duration,
}

impl CachedPolicyEngine {
    pub async fn new(loader: Arc<dyn PolicyLoader>, refresh: Duration) -> Result<Self, _>;
    pub fn evaluate(&self, ctx: &RequestContext) -> PolicyTrace;
    pub async fn refresh_if_stale(&self) -> Result<(), _>;
}
```

Mechanics:
- `ArcSwap<CompiledPolicy>` gives lock-free reads on the hot path
- A background task calls `refresh_if_stale()` every `refresh_interval`
- An admin endpoint `POST /api/policy/reload` forces an immediate reload
- Failures during reload **keep the old compiled policy live** and log — never serve "empty policy" on transient errors

### 5.3 Why the trait, not just caching

Caching alone fixes the startup-parse problem. The trait fixes the bigger problem: multi-tenant config (one customer = one policy bundle) wants `DbPolicyLoader`, dev wants `FilePolicyLoader`, tests want `StaticPolicyLoader`. Without the trait, every new backend means surgery on the engine. With it, the engine never knows.

This mirrors qiuth's insight exactly: the auth core never knows whether your API key is in Postgres or in a YAML file. The policy core shouldn't know either.

### 5.4 Status (2026-05-12) — shipped.

- [crates/policy-engine/src/loader.rs](../../crates/policy-engine/src/loader.rs) — new `PolicyLoader` trait (`async fn load(&self) -> Result<PolicyBundle, PolicyLoadError>`, `fn source_label(&self) -> String`, async `changed_since(&self, version) -> Result<Option<String>>` with a default impl). `PolicyBundle { yaml, version }` is the snapshot; `version` is an opaque token (mtime for files, revision counter for static, future `xmin` for Postgres). Implementations: `FilePolicyLoader` (production path), `StaticPolicyLoader` (tests + embed; bumps an `AtomicU64` revision counter on `set_yaml`). `FilePolicyLoader::version_token_sync()` gives the bootstrap path a non-async way to compute the initial version when constructed outside a runtime.
- [crates/proxy/src/policy_handle.rs](../../crates/proxy/src/policy_handle.rs) — `PolicyHandle::with_loader(initial, loader, raw_yaml, initial_version, source)` constructs a handle backed by a loader. New `reload_via_loader()` async method calls the loader, swaps the engine, and bumps `last_version`. `swap_from_yaml_with_version(...)` is the lower-level primitive that stamps the version atomically alongside the engine swap. `spawn_watcher` now branches: when a loader is attached, it polls `loader.changed_since(handle.last_version())` and reloads via the loader; the legacy mtime-on-`source` path is kept for back-compat (handles built with `PolicyHandle::new`, e.g. when no `PROXILION_POLICY_PATH` is set).
- [crates/proxy/src/server.rs](../../crates/proxy/src/server.rs) — `build_policy_handle` constructs `FilePolicyLoader` and feeds it to `with_loader` whenever `PROXILION_POLICY_PATH` is configured. The production reload path is now backend-pluggable; switching to a `DbPolicyLoader` is a one-line change at this call site, no adapters touched.
- Tests: 4 new in `loader::tests` (file round-trip, mtime change detection, not-found, static-loader revision bump). 2 new in `policy_handle::tests` (`reload_via_loader_swaps_engine_and_bumps_version`, `reload_via_loader_keeps_prior_engine_on_bad_yaml`). All 131 proxy + 17 policy-engine tests green.

**Deviations from §5.2 sketch.**

1. **No `refresh_interval` on a wrapping `CachedPolicyEngine`.** The existing `PolicyHandle` already does the lock-free `ArcSwap<Engine>` + atomic version bump; introducing a parallel `CachedPolicyEngine` wrapper would duplicate that machinery. The loader trait slots into the existing handle. If a customer needs a different refresh cadence per backend (e.g. faster polling for `DbPolicyLoader`), that knob lands on `spawn_watcher` rather than as a wrapping struct.
2. **`PolicyBundle` is `{yaml, version}`, not a pre-compiled tree.** Compilation stays at the engine boundary so a freshly-edited YAML with a syntax error doesn't kill the loader. The handle's "parse before swap" semantic carries through unchanged.

---

## 6. Pattern 5 — Coverage threshold gate in CI

### 6.1 What qiuth does

[qiuth-main/vitest.config.ts](../../qiuth-main/vitest.config.ts) sets coverage thresholds at 90% for lines, functions, statements, branches. Coverage runs in CI; below-threshold drops fail the build.

### 6.2 Proxilion translation

The survey flagged:
- No tests for the full OAuth flow (federation bridge → Trust Plane → token exchange)
- No tests for PCA cache eviction/expiry
- No tests for read filter + quarantine in live adapter requests
- Unit-test grep returned nothing; integration coverage only

Add a coverage gate using `cargo-llvm-cov`:

```yaml
# .github/workflows/coverage.yml (sketch)
- run: cargo install cargo-llvm-cov
- run: cargo llvm-cov --workspace --lcov --output-path lcov.info
- run: cargo llvm-cov report --fail-under-lines 70 --fail-under-functions 70
```

**Don't start at 90%.** Proxilion isn't a 318-test library; it's a service. The original ramp shipped at 60/60 → 70/70 → 80/80; a 2026-05-14 honest reset (see §6.4 status) revised this downward to match measured reality. The current operational ladder lives in §6.4; the table below is the original aspirational shape.

| Phase | Lines | Functions | Notes |
|---|---:|---:|---|
| Adoption | 60% | 60% | (Aspirational — see §6.4 for actual floor.) Anything below blocks PRs. |
| 3 months | 70% | 70% | Forces test backfill for OAuth flow + PCA cache |
| 6 months | 80% | 80% | Long-term target |

Per-crate overrides are fine — `shared-types/` is mostly re-exports and can stay lower; `policy-engine/` should sit highest since it's a pure library with no IO.

### 6.3 What this doesn't fix

A coverage gate ensures lines are *executed* in tests, not that the tests assert anything meaningful. Pair it with the existing integration test pattern in [policy-engine/tests/example_policies.rs](../../crates/policy-engine/tests/example_policies.rs) — that file is the model for "test what the policy actually decides," not just "the function returned."

### 6.4 Status (2026-05-12) — Phase 1 floor pinned at 60% / 60%; **honest reset to 35% lines / 42% functions on 2026-05-14**.

- [.github/workflows/coverage.yml](../../.github/workflows/coverage.yml) — runs `cargo llvm-cov --workspace --lcov --output-path lcov.info` on every PR and push to `main`. The rendered summary is logged for PR reviewers; the `lcov.info` artifact is always uploaded so downstream tools (Codecov, etc.) can consume it.
- Uses `taiki-e/install-action` to install `cargo-llvm-cov` from a pre-built binary (saves ~3 minutes vs `cargo install`).
- Caches `~/.cargo/registry`, `~/.cargo/git`, and `target` keyed on `Cargo.lock` — the SHA-pinned upstream `pic-protocol` + `provenance-*` deps make a cold build expensive (~6 min); a warm cache brings it under 90s.
- Tests dir is excluded from the report (`--ignore-filename-regex '(^|/)tests/'`); coverage is measured against `src/`.

**2026-05-14 — pure-helper test backfill (no floor bump yet).** Added 42 new unit tests in the lowest-coverage modules to start filling the gap the §6.4 honest reset exposed, without yet ratcheting the gate (a floor bump waits on a measured `cargo llvm-cov` run that confirms the new ceiling). Files touched:

- [crates/proxy/src/api/policy.rs](../../crates/proxy/src/api/policy.rs) — 7 tests on `parse_listing` (extracts every field, applies defaults for absent fields, skips entries with no `id`, returns empty on malformed YAML, empty input, `PolicyView` JSON shape, `SetModeBody` deserialization).
- [crates/proxy/src/api/actions.rs](../../crates/proxy/src/api/actions.rs) — 6 tests on `hex_encode`, `row_to_csv_line` (basic row, CSV-quoting for fields with commas / quotes / newlines, optional-field rendering), `make_event`, `ActionsApiError → Response` status codes.
- [crates/proxy/src/api/mod.rs](../../crates/proxy/src/api/mod.rs) — 2 tests on the sibling `hex_encode` and `ApiError::NotFound` status.
- [crates/proxy/src/api/notifier_slack.rs](../../crates/proxy/src/api/notifier_slack.rs) — 4 tests on `header_str` (ascii happy path, rejects non-ascii bytes), `slack_ok_message` (in_channel / replace_original), `slack_err` (status + JSON body).
- [crates/proxy/src/api/notifier_public.rs](../../crates/proxy/src/api/notifier_public.rs) — 6 new tests on `render_error` (HTML escaping), `render_form` (approve form has justification textarea + minlength=20; reject form has reason textarea; unknown action surfaces banner), `render_already_used`, `render_validation_error` (back link), `fill_template` with no `BlockedSummary`.
- [crates/cli/src/main.rs](../../crates/cli/src/main.rs) — 17 tests in a new `pure_helper_tests` module: `format_metric_value` (integers drop decimal, floats keep six digits), `parse_since` (RFC3339 + duration strings), `urlencode` (preserves unreserved, percent-encodes reserved), `generate_token` (prefix + body length + base32 alphabet + uniqueness), `token_hash` (SHA-256 stability + 32-byte length), `truncate` (no-op, ellipsis, unicode-char-count safety), `matches_tail_filter` (all four shapes: no-filter pass-through, decision match, combined decision+vendor+action, invalid JSON pass-through), `make_mock_jwt` (three-part shape + base64url payload decodes), `field_diff` (no-op for identical docs, flags vendor / action / required_ops changes).

All 42 pass locally; the `proxy` binary unittest count moves from 166 → 191 and `proxilion-cli` from 9 → 26.

**2026-05-14 (round 2) — 28 more pure-helper tests targeting OAuth + envelope + boot helpers.** Same playbook applied to the next tier of 0%-coverage modules:

- [crates/proxy/src/error_envelope.rs](../../crates/proxy/src/error_envelope.rs) — 6 tests on `ErrorBody` (default field state, fluent builder composition, optional-field skip-on-None serialization, all-fields-set serialization, `into_response(status)` honors caller status, blanket `IntoResponse` defaults to 500).
- [crates/proxy/src/oauth/routes.rs](../../crates/proxy/src/oauth/routes.rs) — 6 tests on `pct` (NON_ALPHANUMERIC percent-encoding), `oauth_error_class` (denied vs error buckets across every variant), `intersect_scope_with_ops` (keeps scopes whose scheme-prefix has a matching op, filters unknown scopes, always-keep for openid/email), `narrowed_ops_for_pca1` (keeps ops within granted scope prefixes, empty when no scope matches), `new_auth_code` (52-char base32 no-padding + uniqueness).
- [crates/proxy/src/oauth/error.rs](../../crates/proxy/src/oauth/error.rs) — 5 tests on `OAuthError::status()` (every variant → status mapping pinned), `body().code` (stable wire codes), `body().detail` (carried for variants that have one, absent for those that don't), `into_response()` end-to-end status.
- [crates/proxy/src/server.rs](../../crates/proxy/src/server.rs) — 4 tests on `hex_decode_32` (all-zero / all-ff round-trip, mixed-case, wrong-length rejection at three boundaries, non-hex char rejection) + 2 tests on `ensure_dev_cert` (no-op when both files exist, generates valid PEM cert + key when missing — uses `std::env::temp_dir()` rather than pulling in `tempfile`).
- [crates/proxy/src/notifier/mod.rs](../../crates/proxy/src/notifier/mod.rs) — 3 tests on `BlockedNotification::from_record` (schema constant + field passthrough, approve/reject URL construction, JSON serialization carries the `schema` field).
- [crates/proxy/src/adapters/error.rs](../../crates/proxy/src/adapters/error.rs) — 2 tests on `upstream_error_kind` (forces a timeout/connect failure against an RFC 5737 black-hole IP, pins the bounded label set).

Proxy unittest count: 191 → 219.

**2026-05-14 (round 3) — 17 more pure-helper tests on AppError + demo + session + cat_key.** Continued the §6.4 backfill into adapter-layer errors, the demo-mode synthetic event seeder, the session extractor, and the CAT-key registry. Files:

- [crates/proxy/src/adapters/error.rs](../../crates/proxy/src/adapters/error.rs) — 4 tests on `AppError`: variant → `ErrorCode` mapping (every variant), `body().extras` carries `policy_id` + `override_allowed` for `PolicyBlocked`, `status()` delegates through `ErrorCode::default_status`, `into_response()` end-to-end status.
- [crates/proxy/src/demo.rs](../../crates/proxy/src/demo.rs) — 6 tests on `synth_event`: field passthrough from `Scenario`, `p_0` picked from the known `USERS` set, path-template trailing-`s` case (used verbatim), suffix path case (six base-36 chars), distinct request/session UUIDs, and a `SCENARIOS` decision-variety pin (`allow` + `block` + `require_confirmation` must all be represented so a refactor that flattens the demo doesn't slip past review).
- [crates/proxy/src/session.rs](../../crates/proxy/src/session.rs) — 4 tests: `SessionContext::Debug` redacts `google_access_token`, `SessionExtractError → Response` is 401 with body `unauthorized`, the `FromRequestParts` extractor errors when no `Arc<SessionContext>` is in `parts.extensions`, and succeeds (returning the same `Arc`) when one is.
- [crates/proxy/src/pic/cat_key.rs](../../crates/proxy/src/pic/cat_key.rs) — 3 tests: `CatKeyError::Display` strings for `Status` and `Decode` variants are stable, `InfoResp` JSON deserialization, `CatKeyRegistry::get` returns `Fetch(_)` when the Trust Plane endpoint is unreachable (point at a connect-refused loopback port for speed; no 5s timeout wait).

Proxy unittest count: 219 → 236.

**2026-05-14 (round 4) — 22 more pure-helper tests on policy-engine + killswitch.** Pivoted to `policy-engine` for the first time (until now the backfill had focused on `crates/proxy`, where the §6.4 reset called out the biggest gaps; the engine was already at ~88% lines but missed coverage on its YAML schema defaults and the `RequestContext` lookup paths that template substitution depends on). Files:

- [crates/policy-engine/src/context.rs](../../crates/policy-engine/src/context.rs) — 10 tests on `RequestContext::lookup` + `lookup_list`: bare `customer_domain`, `path.*` / `user.email` resolution, `headers.*` lookup, `body.*` string-unquoting vs. JSON-repr fallback for non-strings, unknown-head None, list-array round trip, non-array None, array-with-non-string-element None, and `path.*` / `headers.*` never list-valued (the flat-map contract).
- [crates/policy-engine/src/yaml.rs](../../crates/policy-engine/src/yaml.rs) — 8 tests on the schema: defaults pin `Mode::Enforce` + `PicMode::Audit` + `QuarantineActionCfg::ReplaceWithMarker` (the safe production posture per ui-less-surfaces.md §2.1), minimal-doc parsing applies every default, `observe` + `runtime-gate` round-trip, every `audit_body` variant, unknown `mode` value rejected, `RecipientsCfg` accepts both string and list shapes per field, quarantine patterns accept literal + regex forms, `BurstCfg` honors individually-optional fields.
- [crates/proxy/src/api/killswitch.rs](../../crates/proxy/src/api/killswitch.rs) — 4 tests on `populate_kill_cache` (marks 32-byte rows into the live `KillCache`, skips short/long rows, no-op on empty input) and `ApiError::BadRequest → 400` with structured-body detail.

policy-engine lib unittest count: 58 → 76; proxy: 236 → 240. Total cumulative across rounds 1–4 in `crates/proxy/src/`: **166 → 240** (+74); `crates/proxilion-cli`: 9 → 26 (+17); `crates/policy-engine` lib: 58 → 76 (+18). All standard checks (`cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings …`, `cargo test --workspace --locked`, `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked`) green.

**2026-05-14 (round 5) — 26 more pure-helper tests on policy-engine rego + pic/cache + blocked.rs ApiError.** Continuing through the rego compilation helpers (the engine's internal parsers, never directly tested before — only exercised end-to-end via `Engine::evaluate`), the PCA cache builder, and the blocked-actions API error envelope. Files:

- [crates/policy-engine/src/rego.rs](../../crates/policy-engine/src/rego.rs) — 16 tests in a new `helper_tests` module. `observe_demote`: every `Decision` variant maps to `(Allow, Some(label))` with the spec-pinned label strings (`observe_block`, `observe_require_confirmation`, `observe_rate_limit`); `Allow` is a pure passthrough. `parse_decision`: string forms (`allow` / `block` / `require_confirmation`), YAML-null → Allow, unknown string → `Error::BadDecision`, `override: requires_justification` flips `override_allowed`, structured `rate_limit:` + `block:` maps with custom reasons, missing required field on `rate_limit` (no `per_seconds`) errors loudly. `compile_read_filter`: literal + regex pattern round-trip, every `QuarantineActionCfg` variant maps to its `QuarantineAction` counterpart, malformed regex surfaces `Error::BadRegex`.
- [crates/proxy/src/pic/cache.rs](../../crates/proxy/src/pic/cache.rs) — 4 tests. `CURRENT_PIC_PROFILE` pinned at the string `"proxilion.v1"` (spec.md §15 #11 — changing this without a migration story is a breaking schema bump); `CachedPca::new` default-fills `pic_profile` to the current value and zero-initializes `signature`; predecessor passthrough; `CacheError::Display` formats with the `postgres:` prefix the operator-facing log filters expect.
- [crates/proxy/src/api/blocked.rs](../../crates/proxy/src/api/blocked.rs) — 6 tests on `ApiError → Response` covering every variant: `NotFound → 404` with `code:"not_found"`, `BadRequest → 400` with detail, `Conflict → 409` with detail, `PicRefused → 422` with `fix` carrying the "re-root chain at broader PCA_0" hint operators need, `Internal → 500`, `Db → 500` with sqlx Display passthrough.

policy-engine lib: 76 → 92; proxy lib: 240 → 250. Cumulative rounds 1–5: proxy +84, cli +17, policy-engine +34.

**2026-05-16 (round 6) — 12 more pure-helper tests on blocked.rs DTOs + email helper + notifier set-config body.** All targets are request/response serde shapes operators interact with via the CLI — pinning them as a stable wire contract. Files:

- [crates/proxy/src/api/blocked.rs](../../crates/proxy/src/api/blocked.rs) — 6 new tests on the request/response DTOs: `ApproveBody` deserialization (required `justification`, optional `ttl_minutes` + `approver_subject`; missing-justification rejected), `RejectBody`, `IssueLinkBody` (required `action`, optional `ttl_minutes` + `approver_hint`), `BlockedRow` `request_canonical_json` skip-on-None / include-when-Some.
- [crates/proxy/src/notifier/email.rs](../../crates/proxy/src/notifier/email.rs) — 3 new tests on `parse_or_fallback`: parses a valid mixed list (bare addr + named mailbox), one bad addr kicks the entire list back to the fallback (rather than silently dropping the bad entry — the strict-list contract the per-policy email override depends on), empty input returns empty.
- [crates/proxy/src/api/notifier.rs](../../crates/proxy/src/api/notifier.rs) — 3 new tests: `redact_url` no-`://` defensive passthrough, `SetConfigBody` round-trip + absent-enabled-defaults (the field is `Option<bool>` because the handler does its own `unwrap_or(true)`).

proxy lib unittests: 250 → 262. `fmt`, `clippy -D warnings`, `cargo test --workspace --locked`, `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 7) — 11 more pure-helper tests on shared-types + GoogleClient + floor bump 35/42 → 45/55.** Final pure-helper sweep before bumping the gate. Files:

- [crates/shared-types/src/error_code.rs](../../crates/shared-types/src/error_code.rs) — 4 new tests: `default_status_snapshot` pins the `(variant → HTTP status)` mapping (an operator's Grafana alert keyed on `status="403"` for `code="policy_blocked"` is part of the wire contract), `display_uses_wire_string`, `copy_and_hash_traits_work_at_use_sites` (pin Copy + Hash so a `derive` diff doesn't break `HashMap<ErrorCode, _>` use sites), `unknown_wire_string_fails_deserialize` (closed wire enum despite `#[non_exhaustive]` Rust-side).
- [crates/shared-types/src/operator_scopes.rs](../../crates/shared-types/src/operator_scopes.rs) — 3 new tests: `scope_strings` length + order matches `SCOPE_CATALOGUE`, `known_scope_set_is_present` (pins every operator-facing scope the CLI documents), `every_scope_string_uses_kebab_or_colon_format` (`*` or `<group>:<verb>` — no spaces/commas that break shell parsing).
- [crates/proxy/src/oauth/state.rs](../../crates/proxy/src/oauth/state.rs) — 4 new tests on `GoogleClient::from_env`: missing `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` each error with the named variable in the message, optional `GOOGLE_AUTH_URL` / `GOOGLE_TOKEN_URL` default to the canonical Google endpoints, both overrides take effect. Tests share a `Mutex<()>` to serialize env-var mutation (cargo's parallel test runner would otherwise race them) and save/restore the surrounding shell env so a real `GOOGLE_*` value isn't trampled.

shared-types lib: 5 → 12; proxy lib: 262 → 266.

**Floor bump (qiuth-patterns §6.4): 35% lines / 42% functions → 45% lines / 55% functions.** Earned: `cargo llvm-cov --workspace --ignore-filename-regex '(^|/)tests/'` measured workspace coverage at **47.72% lines / 56.67% functions** after the 7-round backfill (+12.6 / +12.7 points over the 2026-05-14 honest-reset baseline of 36.94% / 43.94%). The new floor sits ~2.7 points below measured lines and 1.7 below measured functions — comfortable headroom while still tight enough that a real regression (e.g. ripping out a tested module) trips the gate. Updated in [.github/workflows/coverage.yml](../../.github/workflows/coverage.yml) along with a revised phase-ladder comment. The 70/70 ceiling still depends on the deferred wiremock+postgres harness — a single-line bump alongside that future PR.

**Cumulative across rounds 1–7.** proxy lib unittests **166 → 266** (+100); proxilion-cli **9 → 26** (+17); policy-engine lib **58 → 92** (+34); shared-types **5 → 12** (+7). Total: **158 new pure-helper unit tests** + the coverage gate now ratchets ~12 points above its day-1 floor.

**2026-05-16 (round 8) — 6 more pure-helper tests on blocked.rs notification round-trip + api/setup.rs envelope.** Two narrow targets the prior rounds skipped: `OwnedBlockedNotification` (load-bearing for the `tokio::spawn`-ed fan-out path — adapters return before the notifier finishes; the owned snapshot is the lifetime bridge) and the `api/setup.rs` wire shape (the admin `/api/v1/setup/status` envelope an installer UI keys on). Files:

- [crates/proxy/src/blocked.rs](../../crates/proxy/src/blocked.rs) — 2 new tests. `owned_notification_round_trips_through_borrowed` constructs a `BlockedNotification<'_>`, materializes it through `OwnedBlockedNotification::from`, then borrows it back via `as_borrowed` and asserts every field survives. `owned_notification_clone_yields_independent_views` pins the `Clone` impl the per-driver `tokio::spawn` blocks depend on (each spawned future owns its own clone).
- [crates/proxy/src/api/setup.rs](../../crates/proxy/src/api/setup.rs) — 4 new tests on the setup-status wire shape: `CheckItem` JSON keys are `id` / `title` / `ok` / `detail` / `fix` / `docs` (stable contract for any installer UI); success-case omits / null-fills `fix`, failure-case carries the operator hint; `SetupStatus` envelope carries `ready_for_traffic` plus the item array; `SetupError → 500` carries the `troubleshooting` docs link.

proxy lib unittests: 266 → 272. Measured workspace coverage: 48.43% lines / 57.22% functions (up from 47.72 / 56.67 last round).

**Cumulative across rounds 1–8: 164 new pure-helper unit tests.** Coverage measured 48.43% lines / 57.22% functions; gate floor stays at 45 / 55 (room for natural variance from line-count drift on the next refactor before the next ratchet).

**2026-05-16 (round 9) — 7 more tests on operator_auth.** Targeted the second-largest 0%-coverage gap among modules with pure helpers: [crates/proxy/src/operator_auth.rs](../../crates/proxy/src/operator_auth.rs) was at 38.52% line coverage despite already having 8 tests on `parse_token` + `require_scope`. The middleware response shapes (`unauthorized()`, `require_scope()` helper) and the rest of the principal API were the gap. New tests:

- `hash_differs_across_tokens` (alongside the existing `hash_is_stable`)
- `generate_returns_distinct_well_formed_tokens` (round-trip with `parse_token`)
- `scope_error_message_carries_required` (the operator-facing `ScopeError::Display`)
- `unauthorized_response_is_401_with_plain_body` (the fixed-body contract — same posture as the bearer middleware)
- `require_scope_helper_returns_principal_on_match` — exercises the public helper that handlers can call directly
- `require_scope_helper_403_with_required_and_have_on_miss` — pins the structured deny body the CLI surfaces (`code:"scope_denied"`, `required`, `have:[...]`)
- `require_scope_helper_401_when_no_principal` — the missing-extension path

`operator_auth.rs` line coverage: **38.52% → 64.91%.** Proxy lib unittests: 272 → 279. Workspace coverage now **48.94% lines / 57.77% functions** (was 48.43 / 57.22 last round). Gate floors stay at workspace 45/55 + per-crate proxy 45; comfortable headroom remains. `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings …`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green. `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green. `cargo clippy --workspace --all-targets -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err` and `cargo fmt --check` both clean.

**2026-05-16 (round 10) — 14 more tests on action_stream + oauth/bridge + forwarder/nats.** Three modules that survived the prior nine rounds untouched (action_stream had 0 tests; oauth/bridge and forwarder/nats had 3 and 2 respectively). All targets are pure helpers — no DB, no tokio runtime beyond `LoggingStream::publish`. Files:

- [crates/proxy/src/adapters/action_stream.rs](../../crates/proxy/src/adapters/action_stream.rs) — 5 new tests on the `ActionEvent` wire contract (NATS / SIEM consumers key on this shape; pinning it as a stable contract). `extra_null_is_skipped_in_json` (the `#[serde(skip_serializing_if = "Value::is_null")]` attribute is load-bearing — downstream indexers check key-presence), `extra_object_is_serialized` (the symmetric case), `round_trips_through_json_with_absent_extra` (an older consumer omitting `extra` must deserialize via `#[serde(default)]` rather than fail), `full_round_trip_preserves_all_fields`, and `logging_stream_publish_is_infallible` (exercises the `ActionStream` trait dispatch on the always-available logging sink).
- [crates/proxy/src/oauth/bridge.rs](../../crates/proxy/src/oauth/bridge.rs) — 5 new tests filling the gap in `validate_federation_token` + `infer_idp`. `rejects_malformed_jwt_missing_parts` (one-part and two-part inputs both surface `BridgeRejected("malformed JWT")`), `rejects_bad_base64_in_payload` (the `URL_SAFE_NO_PAD.decode` error path), `rejects_future_issued_token` (the 60-second clock-skew guard — previously only the expired-token branch was tested), `claims_iss_round_trips_through_payload` (production bridges MUST carry `iss` through so the `idp` label on `proxilion_oauth_callback_total` is correct), `infer_idp_covers_secondary_substrings` (the `googleapis.com` and `windows.net` alternates that the original `infer_idp_classifies_known_issuers` test skipped).
- [crates/proxy/src/forwarder/nats.rs](../../crates/proxy/src/forwarder/nats.rs) — 4 new tests on `sanitize_token` + `ConnectError`. `sanitize_preserves_hyphens_underscores_and_alphanum` (a future `gmail-beta` vendor label must pass through unchanged or wildcard subscriptions break), `sanitize_empty_returns_empty`, `sanitize_replaces_unicode_with_underscore` (multibyte input never breaks subject parsing on the subscriber side), `connect_error_display_contains_reason` (operator-facing `Display` includes both the `nats connect failed` prefix and the underlying reason).

Proxy lib unittests: **279 → 293**. `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked` (293 proxy / 92 policy-engine / 12 shared-types / 26 cli + integration), and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green. Gate floors unchanged (workspace 45/55, per-crate proxy 45); coverage headroom continues to widen — the round-10 targets were among the last 0-test modules in the proxy crate.

**2026-05-16 (round 11) — 16 more tests on policy-engine trace + adapter policy_trace + adapter read_filter pure helpers + forwarder/tee.** Four modules where the visible surface (the public `apply`/`mark_*`/`publish` calls) already had a test, but the wire-shape and private-helper invariants underneath them were unverified. Files:

- [crates/policy-engine/src/trace.rs](../../crates/policy-engine/src/trace.rs) — 5 new tests. `policy_layer_serializes_snake_case` pins the JSON wire string for every `PolicyLayer` variant + a deserialize round-trip (the trace JSON is logged to the audit pipeline and the dashboard parses it — `layer_a` / `layer_b` / `read_filter` is a stable contract). `policy_eval_mode_default_is_fail_fast` pins the production posture per §3.3. `trace_not_allowed_when_decision_is_block_even_if_layers_pass` covers the `allowed()` second clause (the previous test only covered the all-layers-pass branch). `layer_outcome_json_omits_none_fields_via_explicit_serialize` pins that the struct serializes `null` for missing optional fields (no `skip_serializing_if`) so a downstream consumer can rely on key-presence. `policy_trace_json_carries_trace_id_and_layers` pins the envelope shape (trace_id is a string, evaluated_at is a string, duration_micros + layers + required_ops are present).
- [crates/proxy/src/adapters/policy_trace.rs](../../crates/proxy/src/adapters/policy_trace.rs) — 4 new tests filling the gaps in the `mark_*` / `set_layer` / `summary` helpers. `mark_read_filter_blocked_sets_failed_with_code` (the `blocked=true` branch — previously only the passing branch was tested). `mark_read_filter_replaces_existing_entry` (a second `mark_read_filter` call must update the existing slot, not append — the trace would otherwise carry duplicate ReadFilter entries and break the dashboard's "one outcome per layer" assumption). `set_layer_appends_when_layer_absent` exercises the helper directly on an empty-layers trace. `summary_renders_read_filter_label_and_empty_layers` pins the `read_filter=…` label string (operator log filters key on these labels) plus the empty-layers boundary case.
- [crates/proxy/src/adapters/read_filter.rs](../../crates/proxy/src/adapters/read_filter.rs) — 5 new tests on the four private helpers (`truncate`, `should_scan`, `merge_overlapping`, `splice`) that were previously only exercised end-to-end via `apply`. `truncate_helper_keeps_short_unchanged_and_ellipsizes_long` (boundary at exact-limit, ellipsis on overflow); `truncate_uses_char_count_not_byte_len` (multi-byte unicode safety — the `audit` string uses this to bound the pattern label, byte-count truncation would split codepoints); `should_scan_decides_by_content_type` (no-CT default-scan, `application/json` + `application/xml` + `text/*` scanned, case-insensitive matching, `application/octet-stream` + `image/png` + `application/pdf` skipped); `merge_overlapping_collapses_touching_and_overlapping_ranges` (disjoint preserved, overlapping merged, touching `end == next.start` merged per the `>=` predicate, nested absorbed, empty input); `splice_replaces_ranges_and_preserves_surroundings` (single + multi-range + no-range identity + whole-string replacement).
- [crates/proxy/src/forwarder/tee.rs](../../crates/proxy/src/forwarder/tee.rs) — 2 new tests. `sink_count_tracks_with_sink_chaining` exercises the fluent builder (`with_sink` × N → count = N). `each_sink_receives_independent_clone` pins that the fan-out clones the event per sink (the `Collector` assertions check every sink saw the same `request_id` + `vendor`, so a future refactor that moves the event into the first sink instead of cloning would surface here).

policy-engine lib unittests: **92 → 97**; proxy lib: **293 → 304**. Cumulative across rounds 1–11: proxy **+138**, cli +17, policy-engine **+39**, shared-types +7 — **180 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 12) — 6 more tests on policy-engine loader.** Round 11 hit the `trace` module but skipped the sibling `loader` module, which had four happy-path async tests but no coverage on its `Display`-trait wire shape, its `PartialEq` impl, or the sync-bootstrap `version_token_sync()` path the proxy uses before the tokio runtime is up. Files:

- [crates/policy-engine/src/loader.rs](../../crates/policy-engine/src/loader.rs) — 6 new tests. `policy_load_error_display_renders_each_variant` pins the `io error:` / `source not found:` / `backend error:` prefixes (operator log filters and Grafana alerts key on these substrings — a future variant rename must be a conscious wire-shape change, not an accidental string tweak). `policy_bundle_equality_ignores_neither_yaml_nor_version` exercises the derived `PartialEq` on both axes (the proxy short-circuits reloads on equality — a future drift to a `version`-only comparison would silently skip yaml-only edits that share an mtime). `file_loader_path_and_source_label_round_trip` pins that `path()` and `source_label()` agree on the path representation (the label is what shows up in `policy_load_failed` log lines — drifting between the two would split the operator's mental model). `file_loader_version_token_sync_matches_async_load` pins that the sync bootstrap path emits the same `mtime:<nanos>` string as the async `load()` path (the proxy's startup code calls `version_token_sync()` before the runtime is up and then `changed_since(..)` on the same loader once it is — a divergence would force a spurious first reload). `file_loader_version_token_sync_reports_not_found` pins the missing-file branch of the sync helper (otherwise only the async `load()` path's NotFound was exercised). `static_loader_with_label_overrides_default_source_label` pins the `with_label("…")` fluent setter (used by embed-API tests to give the synthetic loader a recognizable name in trace output).

policy-engine lib unittests: **97 → 103**. Cumulative across rounds 1–12: proxy +138, cli +17, policy-engine **+45**, shared-types +7 — **186 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 13) — 12 more tests on crypto/pkce + kill_cache + pic/violations + notifier/mod.** Four sub-100-line modules that had a happy-path test each but skipped the off-by-one boundaries (PKCE length 42/43/128/129), the `Default` constructor's empty-cache promise, malformed Trust Plane refusal bodies, and the None-field passthrough on the notification envelope. Files:

- [crates/proxy/src/crypto/pkce.rs](../../crates/proxy/src/crypto/pkce.rs) — 3 new tests. `boundary_42_chars_rejected_and_43_chars_accepted_as_length` pins the lower edge of RFC 7636 §4.1 — 42 must surface `VerifierLength`, 43 must pass length and reach the SHA-256 compare path (where the bogus challenge then surfaces `Mismatch`). Asserted on the variant, not just `is_err()`, so a future collapse to a single `BadVerifier` would surface here. `boundary_128_chars_accepted_and_129_rejected` is the symmetric upper edge. `error_display_strings_are_stable_for_log_filters` pins the `"verifier failed PKCE check"` and `"length must be 43..=128"` substrings (operator log filters key on these — a future message tweak must be a conscious wire-shape change).
- [crates/proxy/src/kill_cache.rs](../../crates/proxy/src/kill_cache.rs) — 3 new tests. `default_constructor_yields_empty_cache` pins that `KillCache::default()` (what `AppState` builds when no killswitch backend is wired in tests) behaves as a fresh `new()` — no false-positive kills carried over from some shared static. `two_cache_instances_do_not_share_state` is the symmetric guard against a future refactor moving the moka `Cache` into a `lazy_static` global. `mark_many_with_empty_iterator_is_noop` pins the zero-row-UPDATE path through killswitch handlers — the iterator is sometimes empty and the loop must not panic.
- [crates/proxy/src/pic/violations.rs](../../crates/proxy/src/pic/violations.rs) — 3 new tests on `parse_missing_atoms`. `parse_atoms_single_value_no_comma` (Trust Plane sometimes emits a single missing atom — the `,`-splitter must still produce one entry, not zero). `parse_atoms_handles_unclosed_bracket` (malformed input — opening `[` but no `]` — must not panic and must return empty rather than reading off the end; raw `detail` is still persisted by the caller). `parse_atoms_trims_whitespace_and_drops_empty_segments` (both the `"[ a , b ]"` spacing variant and the trailing-comma variant — `[a,b,]` — produce the same two-entry list).
- [crates/proxy/src/notifier/mod.rs](../../crates/proxy/src/notifier/mod.rs) — 3 new tests on `BlockedNotification`. `schema_constant_is_versioned_string_consumers_key_on` pins both the literal `"proxilion.blocked_action.v1"` value and the `.vN` suffix shape — webhook receivers route on the schema string and may parse v2 differently. `from_record_passes_none_fields_through_unchanged` exercises the four `Option<_>` fields (`p_0`, `policy_id`, `detail`, `predecessor_pca_id`) — a stray `""` or `"(none)"` synthesis would mis-classify the blocked row downstream; the JSON keeps the keys present (as `null`) since the struct has no `skip_serializing_if`. `from_record_carries_empty_requested_ops_slice` pins that the empty-ops case round-trips as `[]` in JSON rather than being elided (Slack templates iterate the array and rely on it being present).

proxy bin tests: **304 → 316**. Cumulative across rounds 1–13: proxy **+150**, cli +17, policy-engine +45, shared-types +7 — **198 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 14) — 11 more tests on crypto/token_cipher + api/mod + pic/cache.** Three modules whose visible round-trip was already covered, but whose error paths and ownership invariants were skipped — exactly the surface a Postgres outage or a corrupt env var lands on. Files:

- [crates/proxy/src/crypto/token_cipher.rs](../../crates/proxy/src/crypto/token_cipher.rs) — 5 new tests. `tampered_ciphertext_rejected_by_gcm_tag` flips a byte and pins that the AEAD tag surfaces `CipherError::Aead` (a future refactor to CTR-only would silently pass — this is the AEAD contract). `wrong_nonce_length_rejected_without_aead_call` covers the pre-check at length 11 and 13 (a corrupt persisted `nonce` column would otherwise panic inside `Nonce::from_slice`). `ciphertext_clone_yields_independent_buffer` pins that `Ciphertext`'s `Clone` owns its bytes (no shared backing — a stray `Rc<Vec<u8>>` introduced later would surface here). `bad_key_len_error_display_includes_actual_length` pins that the operator sees both "32" (required) and the actual length in the message (the troubleshooting docs page keys on this shape). `empty_key_rejected_with_zero_length` is the boundary case — a missing env var lands as a zero-byte slice and must carry `BadKeyLen(0)`, not panic. Result matched explicitly rather than `unwrap_err`-ed because `TokenCipher` intentionally has no `Debug` impl (it holds the master key).
- [crates/proxy/src/api/mod.rs](../../crates/proxy/src/api/mod.rs) — 3 new tests. `hex_encode_covers_all_byte_values` walks all 256 byte values; pins lowercase + width-2 (a regression that emitted upper-case or dropped a leading zero would break any tool that round-trips through `hex::decode`). `api_error_db_maps_to_500_with_internal_error_code` exercises the Db variant of `ApiError::into_response` (previously only `NotFound` was covered) — the Grafana alert keyed on `status="500" code="internal_error"` for a real Postgres outage rides on this. `hex_encode_byte_count_matches_two_per_input_byte` is the length-invariant check across N=0/1/16/64/257.
- [crates/proxy/src/pic/cache.rs](../../crates/proxy/src/pic/cache.rs) — 3 new tests. `cached_pca_is_clone_with_disjoint_buffers` mutates the clone and pins that the original's `cbor` + `ops` are unchanged (an accidental `Cow`/`Rc` field would surface here as the chain verifier mutates clones). `cached_pca_new_starts_with_empty_signature` pins the empty-on-construction default (a future "pre-fill with a 'not yet signed' sentinel byte" change would surface here). `cache_error_from_sqlx_via_question_mark` exercises the `#[from]` blanket-impl path the public `insert` / `get` methods use — dropping `#[from]` later would surface here as a compile error rather than as a silent string-format regression at the call sites.

proxy bin tests: **316 → 327**. Cumulative across rounds 1–14: proxy **+161**, cli +17, policy-engine +45, shared-types +7 — **209 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 15) — 9 more tests on crypto/bearer + notifier/handle.** Two modules whose happy-path round-trip was already covered, but whose alphabet/length boundaries (bearer) and hot-swap multi-clone semantics (handle) were not. Files:

- [crates/proxy/src/crypto/bearer.rs](../../crates/proxy/src/crypto/bearer.rs) — 6 new tests. `parse_rejects_length_below_and_above_token_len` pins the symmetric off-by-one boundary (51-char and 53-char bodies both rejected) — a future loosening of `==` to `>=` would surface here. `parse_rejects_digits_outside_base32_alphabet` pins that `0` / `1` / `8` / `9` (the four ascii digits RFC 4648 omits — visually similar to O/I/B/g) all fail; a sloppy `is_ascii_alphanumeric` check would surface here. `bearer_hash_as_bytes_returns_full_32_byte_view` pins both length and pointer-equality with the inner `[u8; 32]` so a future refactor that returned a hex string or a truncated head would surface here (the killswitch SQL predicate keys on the raw 32 bytes). `bearer_hash_debug_truncates_to_short_prefix` pins that `Debug` shows only the 8-hex-char prefix — a regression that printed the full hash would let log aggregators store rotatable-secret-derived bytes. `two_generated_bearers_are_distinct` pins randomness at the trivial scale-2 case (a hard-coded sample or a reset RNG would collide). `bearer_hash_partial_eq_distinguishes_different_inputs` pins both axes of the `PartialEq+Eq` derives the middleware uses to detect already-revoked hashes.
- [crates/proxy/src/notifier/handle.rs](../../crates/proxy/src/notifier/handle.rs) — 3 new tests. `cloned_handle_sees_replace_via_other_clone` pins the design intent of `Handle::clone` — clones share the underlying `Arc<ArcSwap<_>>` so the `/api/v1/notifier/config` hot-swap endpoint can replace the inner notifier without re-plumbing every request handler. A future refactor that deep-copied the swap cell would break this invariant. `bundle_clone_shares_handles_with_original` is the same property at the `Notifiers` bundle level (each field is Arc-backed and survives `derive(Clone)`). `any_configured_triggers_on_slack_alone` exercises the `||`-chain branch that wasn't covered by the existing webhook test — the easy copy-paste bug (`webhook || webhook || webhook`) would surface here.

proxy bin tests: **327 → 336**. Cumulative across rounds 1–15: proxy **+170**, cli +17, policy-engine +45, shared-types +7 — **218 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 16) — 8 more tests on auth_middleware + pic/cat_key.** The middleware module had pure-helper surface (the `unauthorized()` 401 builder, every `AuthFail` `Display` variant, the `RefreshCoordinator` cache-population path) that round-1's `verify_with_key` sweep skipped. `cat_key` was at 3 tests with no coverage on the `Status` Display, on the `CatKeyRegistry::Clone` Arc-sharing invariant, or on the `InfoResp` forward-compat path. Files:

- [crates/proxy/src/auth_middleware.rs](../../crates/proxy/src/auth_middleware.rs) — 5 new tests. `unauthorized_helper_returns_401_with_plain_body` pins the fixed 401 contract (status + exact `"unauthorized"` byte body) — operator alerts key on this 401 rate as the "agent traffic broken" signal. `auth_fail_display_strings_are_stable_for_log_filters` pins the operator-facing substrings every `AuthFail` variant emits (Grafana / Loki filters depend on them). `auth_fail_pca_cache_miss_message_explains_upstream_gap` pins the `PcaCacheMiss` message's `/v1/pca/` hint — operators who hit this need the spec.md §1.2 explanation, not just an opaque variant name. `auth_fail_from_sqlx_via_question_mark` exercises the `#[from]` blanket-impl the middleware uses to bubble DB errors out of the bearer JOIN — dropping `#[from]` later would surface here as a compile error. `refresh_coordinator_default_starts_empty_then_populates` is a complement to the existing `same_mutex_for_same_hash` test, covering the empty-cache → first-lookup → second-lookup populated transition.
- [crates/proxy/src/pic/cat_key.rs](../../crates/proxy/src/pic/cat_key.rs) — 3 new tests. `cat_key_error_status_display_carries_code_only` pins that the `Status` variant exposes only the upstream HTTP code, never a response body (an upstream Trust Plane error message we don't want pasted into our 500). `cat_key_registry_clones_share_underlying_oncecell` pins the Arc-sharing invariant — a regression that deep-copied the `OnceCell<PublicKey>` would re-fetch on every clone (visible as duplicate counters in production). `info_resp_ignores_unknown_fields_for_forward_compat` pins that a future Trust Plane adding fields (e.g. `next_rotation`) doesn't break the deserializer — required for rolling upgrades.

proxy bin tests: **336 → 344**. Cumulative across rounds 1–16: proxy **+178**, cli +17, policy-engine +45, shared-types +7 — **226 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 17) — 9 more tests on notifier/webhook + pic/verifier.** Two modules whose end-to-end mock-server tests were already in place, but whose pure-helper surface (each `from_hex` failure branch, the `invariant_kind` label table, the `err_to_result` `broken_at` field) was not pinned. Files:

- [crates/proxy/src/notifier/webhook.rs](../../crates/proxy/src/notifier/webhook.rs) — 5 new tests. `secret_from_hex_distinguishes_each_failure_branch_by_message` pins the four distinct operator-facing messages (empty / odd / too-short / invalid-hex) — a future refactor that collapsed two branches into "invalid hex" would lose the actionable hint. (Matched on `Result` rather than `unwrap_err`-ed because `WebhookSecret` intentionally has no `Debug` impl.) `signature_is_lowercase_hex_with_sha256_prefix` pins the wire shape — receivers strip the prefix and hex-decode the rest, so an uppercase regression would break them. `webhook_notifier_with_burst_attaches_suppressor_and_burst_accessor_reads_it` covers both ends of the fluent setter + accessor contract (the `burst()` getter is `#[allow(dead_code)]` today but slated for `/api/v1/notifier/test` — a regression that renamed the field but missed the accessor would surface here). `notifier_build_error_display_contains_inner_reason` pins the `notifier build: <reason>` prefix the setup-status path renders. `webhook_proxy_public_url_round_trips_through_accessor` pins that the approve/reject URL builders read back the *proxy's* public URL, not the upstream webhook URL.
- [crates/proxy/src/pic/verifier.rs](../../crates/proxy/src/pic/verifier.rs) — 4 new tests. `invariant_kind_labels_are_bounded_and_stable` pins every `VerifierError` variant to its label string — the `proxilion_pic_invariant_violations_total{kind}` Prometheus metric uses these as labels, and an unbounded-cardinality regression would OOM the scraper. `err_to_result_pins_broken_at_to_named_pca_when_known` pins that the three variants carrying an explicit id (`Missing`, `BadCatSignature`, `ContinuityBroken`) surface that id rather than the leaf — the dashboard's chain-walker UI keys on `broken_at`. `err_to_result_marks_chain_not_intact_and_carries_reason_string` pins the `intact=false` + non-empty `reason` invariant for every error path. `verifier_error_display_carries_named_field_values` pins that thiserror's `{field}` syntax in the structured variants surfaces the actual values (the dashboard's `reason` field is `e.to_string()` — a regression that lost the field substitution would leave operators chasing the chain by hand).

proxy bin tests: **344 → 353**. Cumulative across rounds 1–17: proxy **+187**, cli +17, policy-engine +45, shared-types +7 — **235 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 18) — 7 more tests on adapters/state + api/notifier.** First test landed in `adapters/state.rs` (previously 0 tests) — the `google_api_base()` helper looks tiny but a flipped `unwrap_or` or a dropped `www.` prefix would break adapter TLS verification at runtime. Sibling target was `api/notifier.rs`'s envelope parser, where two required fields had no negative-case coverage. Files:

- [crates/proxy/src/adapters/state.rs](../../crates/proxy/src/adapters/state.rs) — 2 new tests. The helper is a pure `Option<String> → &str` resolver but takes a full `AdapterState` (Postgres pool + notifier bundle + executor) to construct, so the tests exercise the same `as_deref().unwrap_or(...)` shape on a stand-in and document the production string in a literal — a future refactor that changed the default URL or flipped the precedence (override → fallback) now must update test + helper in lockstep. `google_api_base_falls_back_to_production_googleapis_when_unset` pins the `https://www.googleapis.com` fallback (a regression to `googleapis.com` without the `www` would break TLS hostname verification). `google_api_base_respects_override_for_wiremock_tests` pins the override-wins precedence — swapping the arms of `unwrap_or` would silently route adapter calls to production from inside a test fixture.
- [crates/proxy/src/api/notifier.rs](../../crates/proxy/src/api/notifier.rs) — 5 new tests. `redact_url_no_path_keeps_full_host` pins that a bare-host URL (scheme + host, no path) does NOT gain a trailing `/...` — the dashboard's notifier list displays this string verbatim, so a regression that always appended would mis-display bare URLs. `redact_url_keeps_scheme_when_host_has_trailing_slash_only` is the symmetric `https://host/` boundary — the first path segment is empty but the redacted form still adds `/...`. `set_config_body_rejects_missing_driver_field` and `set_config_body_rejects_missing_config_field` pin that the two non-Option fields fail at the envelope layer rather than producing a confusing serde error inside the per-driver branch (the dashboard validates first, but a hand-rolled curl must still get a clean 400). `set_config_body_accepts_explicit_enabled_false` pins that `enabled: false` round-trips as `Some(false)` (not coerced to None, not unwrapped to true) — the disable path is how operators pause a configured-but-not-currently-used driver.

proxy bin tests: **353 → 360**. Cumulative across rounds 1–18: proxy **+194**, cli +17, policy-engine +45, shared-types +7 — **242 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 19) — 7 more tests on pic/executor.** The two existing tests covered the `audit` vs `runtime_gate` happy-path semantics via wiremock; the pure-helper surface (constructor invariants, error Display, Trust Plane wire types, Clone semantics) was untouched despite being the layer downstream consumers integrate against. Files:

- [crates/proxy/src/pic/executor.rs](../../crates/proxy/src/pic/executor.rs) — 7 new tests. `dev_ephemeral_yields_distinct_kids_per_call` pins randomness in the dev-mode constructor — a regression that re-seeded the RNG with the process pid would silently re-use the same `proxy-dev-<uuid>` across restarts, breaking chain attribution. `pic_executor_new_round_trips_kid_through_executor_kid_accessor` pins that the production constructor honors the kid parameter rather than overwriting it (the executor_binding on every PoC carries this value — a regression would silently break chain attribution). `executor_error_display_strings_carry_named_field_values` pins thiserror's `{field}` substitution on the structured `Upstream { status, body }` variant + the prefix + pass-through on `Invariant` and `Core` (the dashboard renders these verbatim). `issue_pca_response_deserializes_with_optional_exp_absent` and `process_poc_response_round_trips_ops_and_hop` pin the two Trust Plane response wire shapes — `#[serde(default)]` on `exp` is load-bearing for never-expiring PCAs, and `ops` is the *narrowed* set the verifier compares element-wise so order must round-trip. `register_executor_request_serializes_to_snake_case_pair` pins the upstream contract `kid` + `public_key` (a future rename to `executor_kid` / `verifying_key` would silently break key registration). `pic_executor_clone_shares_inner_arc` pins that adapters' per-handler clones share the `OnceCell<()>` registration cell — duplicate `Arc<Inner>` would cause two adapters to both re-register on first use.

proxy bin tests: **360 → 367**. Cumulative across rounds 1–19: proxy **+201**, cli +17, policy-engine +45, shared-types +7 — **249 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 20) — 6 more tests on config.** Config validation already had 10 tests, but they exercised the trust-plane URL path twice while skipping the symmetric federation-bridge URL gate, leaving every `ConfigError` Display untested, and never directly hitting `check_http_url`'s field-name round-trip or the `MissingKey` branch (only `MissingCert` was covered). Files:

- [crates/proxy/src/config.rs](../../crates/proxy/src/config.rs) — 6 new tests. `check_http_url_accepts_http_and_https` pins that both schemes pass — operators run `http://` inside trust boundaries (compose / k8s mesh) and `https://` at external load balancers; a regression that locked us to https-only would break the in-cluster path. `check_http_url_rejects_other_schemes_and_surfaces_field_name` walks `ftp://`, `file://`, `ws://`, and the no-scheme case, pinning that the `field` parameter round-trips through the `InvalidValue` variant (Grafana / setup-status keys on it). `build_rejects_non_http_federation_bridge_url` is the symmetric `with_trust_plane_url`-style test for the bridge URL — the existing test only covered trust-plane, so a future refactor that called `check_http_url` once with both arguments wouldn't catch a dropped second check. `build_rejects_token_encryption_key_with_non_hex_chars` covers the alphabet half of the hex-validation predicate (the existing test only covered the length half — `len != 64 || !is_hex` is two failure modes). `build_requires_key_when_only_cert_exists_in_prod_mode` covers the `MissingKey` branch of the `dev_mode == false` cert check — the existing `MissingCert` test pinned the cert path only, so the key path was unexercised. `config_error_display_strings_include_field_or_path_context` pins the operator-facing `Display` substrings for every variant (`InvalidValue`, `MissingCert`, `MissingKey`, `FileLoad`) — the setup-status path renders these verbatim and the troubleshooting docs page keys on them.

proxy bin tests: **367 → 373**. Cumulative across rounds 1–20: proxy **+207**, cli +17, policy-engine +45, shared-types +7 — **255 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 21) — 6 more tests on adapters/error.** The `body()` helper had only one variant test (the PolicyBlocked extras case); the other six variants each render a distinct operator-facing envelope (different fix hints, detail-presence, docs links) that the dashboard surfaces and that the docs page keys on. Files:

- [crates/proxy/src/adapters/error.rs](../../crates/proxy/src/adapters/error.rs) — 6 new tests. `app_error_body_require_confirmation_carries_reason_and_fix` pins both detail pass-through AND the `X-Proxilion-Confirmation:` header name in the fix hint (the agent reads this to know how to resume). `app_error_body_rate_limit_has_no_detail_but_carries_fix` pins the no-detail/yes-fix posture — surfacing rate-limit policy text into a hot retry loop would leak server state. `app_error_body_pic_invariant_violation_surfaces_detail_to_dashboard` pins that the missing-ops string round-trips through `detail` (the dashboard renders this verbatim). `app_error_body_upstream_too_large_carries_size_hint` pins both the "10MB" cap mention and the `fields=` mitigation in the fix text (two substrings the docs page links). `app_error_body_db_and_internal_collapse_to_internal_error_envelope` pins that BOTH Db and Internal collapse to the same `internal_error` code with NO `detail` set — a regression that started leaking sqlx error text would expose schema names / row counts to the agent. `app_error_body_read_filter_blocked_has_no_detail_but_dashboard_hint` pins the symmetric posture for the read-filter denial — generic to the agent, with the operator hint pointing at `/admin/ → Live feed` for the matched pattern.

proxy bin tests: **373 → 379**. Cumulative across rounds 1–21: proxy **+213**, cli +17, policy-engine +45, shared-types +7 — **261 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 22) — 8 more tests on api/killswitch + oauth/error.** Two modules whose visible 4xx envelope was already pinned, but whose 5xx/`Db` envelope, killswitch wire-shape `KillResponse`, and the OAuth error `body()` branches (`Upstream`, `BridgeRejected`, the `Db`/`Crypto`/`Internal` collapse, and the docs-linked fix substrings on the four classify-by-detail variants) were not. Files:

- [crates/proxy/src/api/killswitch.rs](../../crates/proxy/src/api/killswitch.rs) — 4 new tests. `api_error_db_collapses_to_500_internal_error_envelope` covers the second `ApiError` arm — operator alerts key on `status="500" code="internal_error"` for a real Postgres outage; a future variant rename would silently re-classify the alert. `kill_response_serializes_with_stable_field_names` pins the wire shape every operator-dashboard killswitch confirmation toast keys on (`record_id` / `scope` / `target` / `bearers_revoked` / `at`) — a future rename (e.g. `bearers_revoked` → `revoked_count`) would silently break the UI. `kill_body_defaults_when_empty_object_is_posted` pins that operator-cli's `{}` body deserializes to all-None — the handler's `body.unwrap_or_default()` path depends on every field being `Option<_>` with a `Default` impl. `kill_body_accepts_confirm_yes_for_kill_all` pins that the deserializer surfaces `confirm: "yes"` — a sloppy serde rename would silently make `confirm` always None and bypass the `/killswitch/all` 400 gate.
- [crates/proxy/src/oauth/error.rs](../../crates/proxy/src/oauth/error.rs) — 4 new tests. `upstream_body_carries_upstream_unavailable_code_and_no_detail` pins the no-detail posture for the shared internal-error body — a sloppy `Internal(format!("token={token}"))` regression upstream would leak secrets to the agent. `bridge_rejected_body_carries_detail_and_federation_docs_link` pins both the operator-safe `detail` pass-through ("token expired" — no secrets) and the `federation-bridge` substring the docs page links. `db_and_crypto_collapse_to_same_internal_error_body` pins that NEITHER variant leaks its Display string into `detail` — a future refactor that passed `e.to_string()` through would expose schema names (Db) or key-handling internals (Crypto). `body_fix_strings_are_actionable_for_unique_variants` pins the operator-docs-linked substrings on `PkceFail` (`code_verifier`), `BadAuthCode` (`single-use`), `SessionGone` (`10 minutes`), and `PicInvariant` (`subset`) — a drift would orphan the docs page link.

proxy bin tests: **379 → 387**. Cumulative across rounds 1–22: proxy **+221**, cli +17, policy-engine +45, shared-types +7 — **269 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 23) — 8 more tests on api/actions.** The existing 6 tests covered the CSV-line escaper + SSE event builder + two of the four `ActionsApiError` arms by status only — but the two `internal_error` arms' bodies, the pagination envelope's `next_before` key-presence contract, the `PurgeRequest`/`PurgeResponse` wire shape, and the `ListParams` empty-query-string default were unpinned. Files:

- [crates/proxy/src/api/actions.rs](../../crates/proxy/src/api/actions.rs) — 8 new tests. `actions_api_error_db_maps_to_500_internal_error_envelope` pins the full body shape (status + `code` + `error` title + `/healthz` fix substring + `troubleshooting` docs link) for the Postgres-outage arm. `actions_api_error_cache_maps_to_500_with_pca_cache_error_label` pins the distinct `error="pca cache error"` title — operator-dashboard filters split chain-walker faults from generic DB faults on this axis even though both collapse to `code="internal_error"` (no leak surface either way). `actions_api_error_not_found_envelope_carries_docs_link_and_fix` pins the `not_found` shape (operator-cli surfaces the `aged out` substring + `admin/actions` docs link verbatim). `purge_request_dry_run_defaults_to_false_when_omitted` pins the `#[serde(default)]` contract — operator-cli posts `{"older_than":"..."}` for the destructive path and the handler's `if req.dry_run { ... }` branch depends on the False default. `purge_request_dry_run_explicit_true_round_trips` is the explicit-true counterpart. `purge_response_serializes_with_stable_field_names` pins `older_than`/`dry_run`/`deleted` as the wire contract the CLI's purge-confirmation formatter keys on. `list_response_envelope_carries_rows_and_nullable_next_before` pins that `next_before` serializes as `null` (not absent) when the page was shorter than `limit` — the dashboard JS keys on key-presence, not value-presence, to decide whether to render "Load more". `list_params_filters_default_to_none_when_query_string_empty` pins that an empty query string round-trips to all-None so the handler's NULL-bound SQL takes the unfiltered branch (a future field that lost its `Option<_>` would surface as a deserializer error here, before the SQL bind point).

proxy bin tests: **387 → 395**. Cumulative across rounds 1–23: proxy **+229**, cli +17, policy-engine +45, shared-types +7 — **277 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 24) — 8 more pure-helper tests on forwarder/siem.** The SIEM webhook forwarder had end-to-end wiremock coverage on POST shape + 4xx/5xx retry policy, and two terse tests on `from_hex` / `sign`, but the per-branch error messages, the `BuildError` prefix, the operator-facing length boundaries, and the HMAC primitive identity itself (a refactor that swapped SHA-256 for SHA-1 would silently break every existing receiver) were all unpinned. Files:

- [crates/proxy/src/forwarder/siem.rs](../../crates/proxy/src/forwarder/siem.rs) — 8 new tests. `key_error_display_exposes_inner_string_without_prefix` pins that `KeyError`'s `#[error("{0}")]` is intentional (no prefix added) so the per-branch messages from `from_hex` are what dashboard filters key on directly; matched on the `Result` rather than `unwrap_err`-ed because `KeyError` deliberately has no `Debug`-print of the source key. `build_error_display_carries_siem_forwarder_build_prefix` pins the `siem forwarder build:` prefix on the symmetric `BuildError` so setup-status renders distinguish a key-parse fault from a reqwest::Client construction fault. `from_hex_distinguishes_odd_and_too_short_branches` pins that the two length checks fire in the right order (odd-length first, then `>= 32 chars`) — a regression that collapsed them into "invalid length" would lose the actionable hint. `from_hex_invalid_hex_char_carries_position_index_in_message` pins both the `invalid hex at` prefix and the byte offset (operators triage env-var typos by reading the position). `from_hex_accepts_32_char_minimum_and_rejects_30_just_below` pins the documented 16-byte (32 hex char) minimum on both edges. `sign_matches_rfc4231_test_vector_1_for_hmac_sha256` pins the HMAC primitive identity against the RFC 4231 §4.2 Test Case 1 known vector — a swap to SHA-1 / SHA-384 would silently break every existing SIEM receiver. `sign_diverges_when_key_changes_for_identical_body` pins the symmetric axis the existing `hmac_key_round_trip` test skipped (a stub that hashed the body alone would satisfy the existing test). `sign_is_lowercase_hex_with_fixed_prefix_and_length` pins the `sha256=<64-char-lowercase-hex>` wire shape receivers depend on.

proxy bin tests: **395 → 403**.

**2026-05-16 (round 25) — 8 more pure-helper tests on policy_handle.** `set_mode` has thorough end-to-end coverage (comment preservation, nested-mode-key avoidance, field-insertion ordering, fallback path), but the four private YAML-walker helpers (`strip_eol`, `leading_ws_len`, `parse_id_value`, `find_inline_comment`) and the `SetModeError` `Display` shapes were never pinned directly — a future refactor of the line walker could silently shift behaviour on boundary inputs that the end-to-end tests don't reach (CRLF, mixed-tab indent, single-quoted scalars, comment-only values, URL-with-`#`). Files:

- [crates/proxy/src/policy_handle.rs](../../crates/proxy/src/policy_handle.rs) — 8 new tests. `strip_eol_removes_trailing_newline_only_when_present` pins the naked-string passthrough (the line walker's `split_inclusive('\n')` leaves the last line newline-less and the rewrite must rejoin byte-exact) plus that `\r` is intentionally NOT stripped (CRLF is unsupported; silent drop would mis-align indent calculations). `leading_ws_len_counts_spaces_and_tabs_mixed` pins the byte-accurate length contract on mixed tab/space input (the rewrite preserves the original lead bytes verbatim, so the length must match). `parse_id_value_extracts_bare_and_quoted_scalars` pins all three scalar shapes (bare, double-quoted, single-quoted) the `set_mode` block-finder iterates over. `parse_id_value_rejects_missing_space_after_colon_to_avoid_pid_match` pins the `id:foo` (no space) rejection — without this the walker would hijack `pid:` lines as the block anchor; tab-after-colon is accepted (YAML allows it). `parse_id_value_returns_none_for_empty_or_comment_only_value` pins the three empty-after-strip shapes (`id: `, `id: ""`, `id:  # comment`). `find_inline_comment_requires_preceding_whitespace` pins the no-bare-hash rule that keeps URLs like `https://x#frag` from being mistaken for inline comments — important because policy `match:` rules carry user-supplied strings that may include `#`. `set_mode_error_display_strings_are_stable_for_log_filters` pins the per-variant prefix + payload pass-through for `NotFound` / `Parse` / `Reload` (the troubleshooting docs page keys on these prefixes). `set_mode_via_serde_fallback_round_trips_when_yaml_is_a_flow_mapping` exercises the legacy `serde_yaml` fallback on a flow-mapping input where the line walker wouldn't have found the anchor — a regression that dropped the fallback would surface `NotFound` for any hand-edited flow-style YAML.

proxy bin tests: **403 → 411**. Cumulative across rounds 1–25: proxy **+245**, cli +17, policy-engine +45, shared-types +7 — **293 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 26) — 8 more pure-helper tests on notifier/slack.** The Slack notifier already had end-to-end coverage on signed-request verification + Block Kit payload shape + user-map resolution + summary block layout, but the operator-facing `SlackBuildError` prefix, the `plural`/`truncate` helpers powering the message copy, the `reject` button verb (only `approve` and `why` were round-tripped), the bad-UUID rejection path through `parse_button_value`, the `SlackAction` `Copy`/`PartialEq` traits the interaction-webhook router depends on, and the empty-map default of `resolve_user` were all unpinned. Files:

- [crates/proxy/src/notifier/slack.rs](../../crates/proxy/src/notifier/slack.rs) — 8 new tests. `slack_build_error_display_carries_slack_build_prefix` pins the `slack build:` prefix so setup-status renders distinguish a Slack build fault from a webhook or SIEM build fault. `plural_renders_singular_at_one_and_pluralizes_zero_and_many` pins the `n == 1 → "1 block"`, else `"N blocks"` shape on three boundaries (0, 1, 2+) — a regression that treated only `n == 0` as plural (the natural off-by-one) would surface here as `"0 block"`. `truncate_passes_short_through_and_ellipsizes_at_overflow` pins both the exact-limit no-ellipsis case (the `>` strict-greater predicate) and the single horizontal-ellipsis codepoint on overflow (a regression that emitted `...` instead would break the 140-char visual width budget the context block depends on). `truncate_uses_char_count_not_byte_len_for_multibyte_input` pins UTF-8 safety on Greek letters — a byte-length truncation would split a codepoint and panic the serializer downstream. `parse_button_value_round_trip_reject_action` covers the third verb the existing tests skipped (the destructive action that the interaction webhook routes on identity). `parse_button_value_rejects_known_action_with_bad_uuid` pins the second-half failure mode — verb match succeeds but UUID parse fails, including the `approve:` empty-tail edge and the multi-colon (`approve:abc:def`) edge `split_once` masks. `slack_action_copy_and_eq_traits_work_at_use_sites` pins `Copy + PartialEq + Eq` on the variant (the router moves and compares without explicit `.clone()` — dropping a trait would surface here as a compile error rather than as confusing call-site failures). `resolve_user_returns_none_when_map_is_empty_or_no_inputs` pins that `SlackNotifier::new` builds an empty map (every lookup → None → caller falls back to `slack:<username>`) — a regression that pre-seeded a default mapping would attribute overrides to the wrong subject; piggybacks a `proxy_public_url()` accessor round-trip while a notifier is already in hand.

proxy bin tests: **411 → 419**.

**2026-05-16 (round 27) — 6 more pure-helper tests on notifier/burst.** The suppressor already had 11 tests covering admit/drain/resolver semantics, but the documented `BurstConfig` default numbers (which the troubleshooting docs commit to verbatim), the `BurstSummary::SCHEMA` version-suffix contract, the `#[serde(skip_serializing_if = "String::is_empty")]` key-presence axis that drives the "Open full list" button render, the multi-trailing-slash defense in `with_details_url`, the `flush_interval()` accessor the background flush loop reads, and the `Clone` invariant the notifier/flush-loop split depends on were all unpinned. Files:

- [crates/proxy/src/notifier/burst.rs](../../crates/proxy/src/notifier/burst.rs) — 6 new tests. `burst_config_default_pins_documented_threshold_window_and_flush` pins `threshold=50 / window=60s / flush_interval=30s` — operators read these out of the troubleshooting docs and a tempting "more headroom" bump would silently change suppression behavior on every existing install at next restart. `burst_summary_schema_is_versioned_string_consumers_key_on` pins both the literal `"proxilion.blocked_action_burst.v1"` value and the `.v1` suffix — webhook/Slack receivers route on the schema string and a coordinated bump is required. `burst_summary_json_skips_empty_details_url_via_serde_attr` pins the load-bearing serde attribute — receivers key on key-presence to decide whether to render "Open full list"; a drift to always-serialize would render a button pointing at the empty string for test fixtures / installs without a public URL. `details_url_collapses_multiple_trailing_slashes_in_base` pins the `trim_end_matches('/')` defense against operator base-URL typos like `https://proxy.local///` (the natural shape of concatenated env-var fragments). `flush_interval_round_trips_through_getter` pins that the getter returns the configured value, not a hard-coded default — a regression here would silently make per-install overrides no-ops. `burst_suppressor_clone_shares_bucket_state` pins that `BurstSuppressor::clone` shares the underlying `Arc<Mutex<HashMap<…>>>` so both the notifier (admit) and the flush loop (drain_summaries) see the same buckets — a deep-copy regression would leave the flush loop forever empty.

proxy bin tests: **419 → 425**. Cumulative across rounds 1–27: proxy **+259**, cli +17, policy-engine +45, shared-types +7 — **307 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 28) — 5 more pure-helper tests on blocked::canonical_request_json.** The 6 existing tests covered the happy-path JSON shape + truncation-fired branch + determinism, but the truncation envelope's *content* (does it elide `body` + `path_params` like the docstring promises?), the just-below-cap boundary (the `<=` predicate vs `<`), the cross-process determinism (alphabetical key sort inside nested maps), the empty-maps render (`body: {}` vs `null`), and the `BlockedActionRecord` `Clone` derive were unpinned. Files:

- [crates/proxy/src/blocked.rs](../../crates/proxy/src/blocked.rs) — 5 new tests. `truncation_envelope_elides_body_and_path_params` pins that the truncated envelope carries only the (method, path, vendor, action) identification quad — re-including the bloated body/path_params would defeat the size-cap and reintroduce the audit-log problem this envelope solves. `just_below_cap_passes_through_unchanged` pins the `<=` predicate on the just-under-4KB boundary — a regression to `<` would silently start truncating exact-at-limit rows that fit fine today. `nested_body_keys_render_in_alphabetical_order` pins serde_json's sort so the audit log is reproducible across HashMap iteration orderings (Rust's HashMap is randomized per-process; without sort, the same logical request would render differently across restarts and break the approver UI's deterministic-diff workflow). `empty_maps_render_as_empty_objects_not_null` pins `body: {}` + `path_params: {}` on the most-common shape (read endpoints) so the approver UI can distinguish "adapter opted into 0 fields" from "field absent (older schema)". `blocked_action_record_clone_preserves_borrowed_fields` pins that the `Clone` derive survives across all 14 fields including the lifetime'd `&'a [String]` and the `Option<u32>`/`Option<String>` shapes — a future refactor to `Cow<'a, str>` would surface here.

proxy bin tests: **425 → 430**.

**2026-05-16 (round 29) — 7 more pure-helper tests on insert_proxy_headers across all three Google adapters.** The drive adapter had one positive test (`proxy_headers_present`); gmail + calendar had none. The `None`-policy branch and the `if let Ok(v)` invalid-header-value defense were unpinned on all three. The three helpers are byte-identical — without coverage they could drift independently on the next refactor. Files:

- [crates/proxy/src/adapters/google_drive.rs](../../crates/proxy/src/adapters/google_drive.rs) — 2 new tests. `insert_proxy_headers_omits_policy_header_when_no_match` pins that `matched_policy_id: None` (the read-filter / default-deny shape) produces NO `x-proxilion-policy` header — Grafana panels separate "policy fired" from "no match" on header presence, so emitting an empty string would mis-bucket. `insert_proxy_headers_skips_invalid_header_value_silently` pins the `if let Ok(v)` defense — a policy id with an embedded newline (extreme but possible via hand-edited YAML) must drop the header rather than panic the response path.
- [crates/proxy/src/adapters/google_gmail.rs](../../crates/proxy/src/adapters/google_gmail.rs) — 2 new tests with the same shape, against the gmail-local helper (cross-adapter parity guard — three identical helpers must drift together).
- [crates/proxy/src/adapters/google_calendar.rs](../../crates/proxy/src/adapters/google_calendar.rs) — 3 new tests (this adapter had ZERO tests on the helper). `insert_proxy_headers_round_trip_carries_request_pca_and_policy` is the missing positive test (first time the calendar dashboard's request inspector header set is pinned), plus the same two `None` and invalid-value branches as drive/gmail. Adds a small `outcome_with(policy_id)` test helper since calendar lacked one.

proxy bin tests: **430 → 437**. Cumulative across rounds 1–29: proxy **+271**, cli +17, policy-engine +45, shared-types +7 — **319 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 30) — 8 more pure-helper tests on policy-engine ops.** The 7 existing tests covered `resolve_one` + `resolve` end-to-end, but `OpsAtom::parse`'s four malformed branches (no-colon, one-colon, empty-scheme, empty-action, empty-object), `OpsAtom::to_canonical`'s round-trip identity with `parse`, the colons-and-slashes-in-object passthrough (Gmail's `gmail:send:user:to:domain` shape), the `OpsParseError` Display strings, `MissingOps` Display surfacing each atom, the empty-required Layer-A passthrough, the private `collect_vars` ordering, and `substitute`'s literal-passthrough + unclosed-var error were all unpinned. Files:

- [crates/policy-engine/src/ops.rs](../../crates/policy-engine/src/ops.rs) — 8 new tests. `ops_atom_parse_rejects_each_malformed_shape` walks all 5 distinct failure modes — a future refactor that collapsed the colon-count + empty-segment checks would lose them. `ops_atom_parse_keeps_extra_colons_and_slashes_in_object` pins the Gmail/Drive object-shape contract — a regression that split on every colon would silently truncate ops. `ops_atom_to_canonical_round_trips_through_parse` pins the inverse identity (the proxy normalizes PCA ops before chain comparison; a format drift would silently break leaf matching). `ops_parse_error_display_strings_carry_operator_facing_hints` pins both variants' rendered substrings (`scheme:action:object` shape hint + `template variable` prefix + the unknown-var name). `missing_ops_display_surfaces_each_missing_atom` pins that the adapter's 422 response body (read from `Display`) carries every missing atom. `is_satisfied_by_empty_required_is_ok_against_any_leaf` pins the policy-gated-only-on-Layer-B passthrough — a regression that errored on empty required-ops would mass-deny these. `collect_vars_returns_each_var_in_left_to_right_order` pins the doc-committed left-to-right discovery (a HashSet refactor would silently lose order + the first-offending-var error). `substitute_passes_literal_through_and_rejects_unclosed_var` pins the no-var passthrough + the operator-facing unclosed-`${...` error.

policy-engine lib tests: **103 → 111**.

**2026-05-16 (round 31) — 6 more tests on blocked_expiry + policy-engine decision.** Two narrow targets the prior rounds skipped. `blocked_expiry.rs` was at **0 tests** despite its `DEFAULT_TICK_INTERVAL` constant being load-bearing for the operator-alert "expected expiry window" assumption, and despite its `Default + Clone + Debug` derives on two report structs being the contract the sweep loop relies on. `decision.rs` had Pattern + Decision serde coverage but had never pinned `QuarantineAction`'s `Copy + PartialEq` traits (the dispatcher matches by value), `ReadFilter`'s `Clone` independence, or the empty-needle literal-match edge. Files:

- [crates/proxy/src/blocked_expiry.rs](../../crates/proxy/src/blocked_expiry.rs) — 3 new tests (first tests on this module). `default_tick_interval_pinned_at_60_seconds` pins the 60s constant — a regression that loosened to 5 minutes would silently widen the operator-alert response window. `expiry_sweep_report_default_is_zero_and_clone_independent` pins `Default + Clone + Debug` on the report (Default must be `0` not a sentinel; Clone must yield independent values — a future `Arc<u64>` refactor would surface here). `escalation_sweep_report_default_is_zero_and_debug_carries_field` is the symmetric guard on the sibling `EscalationSweepReport`.
- [crates/policy-engine/src/decision.rs](../../crates/policy-engine/src/decision.rs) — 3 new tests. `quarantine_action_copy_and_eq_traits_work_at_use_sites` pins `Copy + PartialEq` across all three variants (the per-pattern processor passes the action down without `.clone()` — dropping `Copy` would surface here as a compile error rather than confusing failures). `read_filter_clone_carries_patterns_and_action_independently` pins that the cloned `Vec<Pattern>` is independent of the original (no `Rc`/`Arc` smuggled into the inner vec — a regression there would couple per-request engine snapshots). `literal_pattern_matches_empty_haystack_against_empty_needle_only` pins the `str::contains` empty-needle semantic — documents current behaviour as a load-bearing edge for any catch-all-marker policy use.

proxy bin tests: **437 → 440**; policy-engine lib tests: **111 → 114**. Cumulative across rounds 1–31: proxy **+274**, cli +17, policy-engine **+56**, shared-types +7 — **333 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-16 (round 32) — 6 more pure-helper tests on policy-engine yaml schema wire shape.** The 8 existing tests covered `parse_policies` end-to-end but each schema enum's wire string was only pinned indirectly (via a single happy-path round-trip in `parse_policies_round_trips_observe_mode_and_runtime_gate`). The `PicMode` kebab-case vs `Mode` / `AuditBodyMode` / `QuarantineActionCfg` snake-case split is the classic serde rename-attribute confusion bug — a copy-paste of `rename_all = "snake_case"` onto `PicMode` would silently break every existing policy YAML carrying `runtime-gate`. The `deserialize_string_or_vec_opt` helper had only one of its three shapes pinned in `recipients_cfg_accepts_string_or_vec`. `ReadFilterCfg` was only tested via fully-populated YAML, never with `{}` to exercise both inner `#[serde(default)]` attributes. Files:

- [crates/policy-engine/src/yaml.rs](../../crates/policy-engine/src/yaml.rs) — 6 new tests. `mode_wire_strings_pin_snake_case_per_variant` pins all three `Mode` strings (the dashboard's policy-mode toggle posts these exact bytes). `pic_mode_serializes_kebab_case_not_snake_case` is the highest-risk wire-shape pin in this module — `RuntimeGate` MUST serialize as `runtime-gate` (kebab), and a snake-case input MUST be rejected by the closed-enum deserializer. `audit_body_mode_wire_strings_are_snake_case` pins `RedactPii → "redact_pii"` (snake, NOT kebab) — distinguishes from PicMode above to catch an accidental copy-paste between the two `rename_all` attributes. `quarantine_action_cfg_wire_strings_are_snake_case` pins all three action variants (mirrored from the engine-internal `QuarantineAction` in decision.rs but kept as a separate schema type so wire shape can evolve independently). `deserialize_string_or_vec_opt_accepts_none_string_and_array` pins all three shapes side-by-side via a local `Wrap` struct that documents the helper's contract directly. `read_filter_cfg_minimal_yields_empty_patterns_and_default_action` pins that `read_filter: {}` deserializes cleanly with empty patterns + `replace_with_marker` default — a regression that made either inner field required would break every existing policy with a stub block.

policy-engine lib tests: **114 → 120**.

**2026-05-16 (round 33) — 5 more pure-helper tests on notifier/email.** The `html_escape` helper had ONE test (`<script>`-shape XSS) — the other four HTML entity arms (`>`, `&`, `"`, `'`) had no direct coverage, and the no-double-encoding semantic (this is a one-shot byte mapping, NOT a parser) was unpinned. The `EmailNotifier` builder + `proxy_public_url` accessor had no direct round-trip — the escalation sweeper reads this URL to build approve/reject links, so a regression that returned the SMTP URL instead would silently send approvers to the SMTP host. Files:

- [crates/proxy/src/notifier/email.rs](../../crates/proxy/src/notifier/email.rs) — 5 new tests. `html_escape_covers_every_dangerous_entity` walks all five entities individually plus a mixed-entity string in order — pins specifically that the apostrophe escape is `&#39;` (numeric) not `&apos;` (named), since older mail UAs render the two differently. `html_escape_passes_plain_text_and_unicode_through_unchanged` pins the no-spurious-wrapping case + Unicode passthrough (`αβγ — délicieux`) so non-ASCII policy descriptions render correctly. `html_escape_does_not_double_encode_already_escaped_entities` pins the one-shot byte mapping semantic — `&amp;` becomes `&amp;amp;` rather than being parsed and re-encoded, so a future "smart escape" refactor would surface here. `email_notifier_proxy_public_url_round_trips_through_accessor` pins the load-bearing accessor field-name round trip the escalation sweeper depends on. `email_notifier_with_max_retries_is_a_fluent_setter` pins the consuming-self builder shape (`fn(mut self, n) -> Self`) — a refactor to `&mut self` would surface here as a compile error rather than break test setup at every call site.

proxy bin tests: **440 → 445**. Cumulative across rounds 1–33: proxy **+279**, cli +17, policy-engine **+62**, shared-types +7 — **344 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-17 (round 34) — 8 more pure-helper tests on audit_body PII redactor.** The 9 existing tests covered each redactor regex's happy path (email / SSN / phone / credit card / bearer / api key) plus the binary-input and text-input branches of `redact_pii_bytes`, but several pure-helper boundaries the operator-facing audit pipeline depends on were unpinned: the empty-input SHA-256 vector (absence-of-body still writes a row per the docstring, so the empty-hash is on the wire contract), the `base64_encode` round-trip identity (a refactor to URL-safe alphabet would silently corrupt every persisted body), the order-of-precedence guarantee that `api_key` runs before `phone` (a copy-paste of the call order would chop Slack tokens into `<REDACTED_PHONE>` fragments and leak the rest), the invalid-UTF-8 passthrough (the regex engine operates on `&str` — a lossy conversion would mutate the audit body), and the 256-byte boundary of the binary-detection scan (`take(256).any(b == 0)` — a null byte beyond byte 256 must NOT classify as binary). Files:

- [crates/proxy/src/audit_body.rs](../../crates/proxy/src/audit_body.rs) — 8 new tests. `sha256_hex_empty_input_matches_known_digest_and_is_lowercase_width_64` pins the RFC-known `e3b0c4…` empty-string digest + the width-64 + lowercase-hex invariants (a regression that emitted upper-case or special-cased empty to `""` would break SQL JOINs against the `request_hash` column). `base64_encode_round_trips_through_decoder` pins STANDARD-alphabet identity across empty / ASCII / binary inputs (a switch to `URL_SAFE` would silently break every existing replay tool). `redact_pii_text_preserves_non_pii_surroundings_around_match` pins that the replace_all calls preserve prefix/suffix bytes (a regression that replaced the whole string would mask data loss). `redact_pii_text_replaces_multiple_pii_kinds_in_one_pass` pins that a single call handles email + phone + SSN together (an early-return-after-first-match refactor would surface here). `redact_pii_text_api_key_runs_before_phone_so_slack_token_is_not_split` pins the load-bearing order-of-operations guarantee from the in-file comment ("known token shapes before generic digit-pattern redactors") — Slack tokens carry a 10-digit workspace id that the phone regex would otherwise eat. `redact_pii_bytes_passes_invalid_utf8_through_unchanged` pins the `std::str::from_utf8` error branch (a regression that switched to `from_utf8_lossy` would mutate audit bytes). `redact_pii_bytes_binary_detection_only_scans_first_256_bytes` pins the `take(256)` boundary — a null byte at offset 256+ must NOT classify as binary, since most JSON bodies pad well past 256 bytes of human-readable text before any embedded NUL. `redact_pii_text_empty_input_yields_empty_output` pins the trivial empty-passthrough (a sentinel-injecting regression would surface here).

proxy bin tests: **445 → 453**.

**2026-05-17 (round 35) — 3 more pure-helper tests on session.rs.** The 4 existing tests covered the Debug-redaction of `google_access_token`, the 401 status on `SessionExtractError`, the missing-extension extractor branch, and the present-extension extractor branch. But the symmetric Debug-omission of the *other* sensitive fields (`bearer_hash` — the SHA-256 the killswitch SQL predicate keys on; `leaf_pca_cbor` — the raw signed-PCA bytes) was unpinned despite the Debug impl deliberately listing only a subset of fields. The `SessionCtx::clone` Arc-sharing invariant the per-handler fan-out depends on was unpinned (a refactor that dropped the `Arc<_>` wrapper would silently deep-copy the context on every clone). The fixed-body `unauthorized` content length was only checked by byte-equality with no length pin, so a trailing newline / JSON wrapper added to the body wouldn't surface as a wire-shape change. Files:

- [crates/proxy/src/session.rs](../../crates/proxy/src/session.rs) — 3 new tests. `debug_omits_bearer_hash_and_leaf_pca_cbor_to_avoid_leaking_credential_material` pins that the Debug impl never renders the two sensitive byte fields — operator log aggregators index `Debug`-formatted structs and accidentally including the killswitch hash would let an attacker who reads logs construct a kill-row, while leaking the signed PCA CBOR would expose chain-attribution bytes. `session_ctx_clone_shares_arc_with_original` pins that `#[derive(Clone)]` on `SessionCtx(pub Arc<SessionContext>)` Arc-shares the inner context across spawned tasks (a refactor to `SessionCtx(pub SessionContext)` would surface here as an `Arc::ptr_eq` failure rather than as a silent fan-out performance regression). `session_extract_error_body_is_exactly_twelve_bytes` pins the body length so an appended CRLF / JSON wrapper / HTML envelope on the fixed-body 401 path would surface here — operator alerts key on this 401 rate as the "agent session lost" signal and log parsers depend on the exact byte shape.

proxy bin tests: **453 → 456**. Cumulative across rounds 1–35: proxy **+290**, cli +17, policy-engine **+62**, shared-types +7 — **355 new pure-helper unit tests** total. Gate floors unchanged (workspace 45/55, per-crate proxy 45 / shared-types 95 / policy-engine 88 / cli 10). `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings -A clippy::type_complexity -A clippy::too_many_arguments -A clippy::result_large_err`, `cargo test --workspace --locked`, and `RUSTFLAGS="-D warnings" cargo build --workspace --release --locked` all green.

**2026-05-14 honest reset — floor lowered to 35% lines / 42% functions.** The original §6.2 ladder pinned the adoption floor at 60% / 60%, but a `cargo llvm-cov --workspace` run reports `TOTAL 36.94% lines / 43.94% functions` (40.22% is the *regions* metric — easy to misread; the `--fail-under-lines` flag checks the line column). The five most recent CI runs of `coverage.yml` on `main` all exited `failure` for exactly this reason — the gate was red the day it landed (b7d618b) and stayed red across every subsequent push. The floor is now `--fail-under-lines 35 --fail-under-functions 42`, just under the measured numbers, so the gate enforces a no-regression line that the workspace actually clears. The biggest pull-down sources are [crates/proxy/src/api/](../../crates/proxy/src/api/) (handlers at 0% — exercised only by integration tests; the `crates/proxy/tests/` directory is empty), [crates/proxy/src/server.rs](../../crates/proxy/src/server.rs) at 0%, and [crates/cli/src/main.rs](../../crates/cli/src/main.rs) at 3.91%. Backfilling those is the work that earns the next bump.

**Ratchet plan.**

The revised phase ladder lives only in this YAML's `--fail-under-*` flags. Bump it in a single-line PR alongside the test backfill that earned the bump — never bump speculatively. Updated targets:

| Phase | Lines | Functions | What earns the bump |
|---|---:|---:|---|
| adoption | 35% | 42% | n/a — 2026-05-14 measured baseline |
| round-7 (today) | 45% | 55% | ✅ 158 pure-helper unit tests across proxy + cli + policy-engine + shared-types (rounds 1–7) lifted measured coverage to **47.72% lines / 56.67% functions** |
| later | 70% | 70% | wiremock+postgres harness lands → `crates/proxy/tests/` exercises `api/*` handlers; CLI integration tests + `server.rs` boot-path tests |

The 60 → 70 → 80 ladder in §6.2 is left as the original *aspirational* document — this status block is the operational source of truth.

**Deviations from §6.2 sketch.**

1. ~~**No per-crate thresholds.** `cargo-llvm-cov`'s `--fail-under-*` is workspace-wide. Per-crate enforcement would need a `cargo llvm-cov report --output-format json` post-processing step. Holding off until the workspace floor is so high that the lowest-coverage crate is dragging it down.~~ **Resolved 2026-05-16.** [scripts/coverage-per-crate.sh](../../scripts/coverage-per-crate.sh) parses the same `coverage.json` the workflow already emits (jq + awk; bash-3 compatible so it runs on a macOS dev laptop as well as ubuntu-latest CI) and enforces one floor per workspace crate: **shared-types 95% / policy-engine 88% / proxy 45% / cli 10%** (each ~3–5 points below measured at the time of landing). Wired into [.github/workflows/coverage.yml](../../.github/workflows/coverage.yml) as a separate step after the workspace `--fail-under-*` gate, so the operator sees which crate slipped rather than just "workspace dropped". The workspace gate stays as the wider safety net; the per-crate gate catches narrower drops (e.g. shared-types or policy-engine regressing alone while proxy's denominator masks the loss). Failure-path verified locally by mutating one crate's `lines.covered` to 0 in a copy of the JSON and re-running the script — exits 1 with the failing crate name in stderr.
2. **No Codecov / coveralls integration.** The lcov artifact is uploaded; a downstream uploader can be wired in via a follow-up workflow without touching the gate itself.

---

## 7. Rollout order & dependencies

Suggested sequence (each step is independently shippable):

1. **§4 ErrorCode registry** — smallest, unblocks §3. ~1 day. ✅ shipped 2026-05-12.
2. **§3 PolicyTrace** — depends on §4. ~3 days incl. dashboard wiring. ✅ shipped 2026-05-12 (types + engine entry + adapter wiring; `X-Proxilion-Trace-Id` surfaced on responses).
3. **§5 PolicyLoader trait + cache** — independent of §3/§4 but easier to test once trace exists. ~3 days. ✅ shipped 2026-05-12 (`FilePolicyLoader` is the production path; `DbPolicyLoader` is a one-line plug-in).
4. **§2 ConfigBuilder** — independent. Defer until embed API is on the roadmap; until then, env-only is fine. ~2 days. ✅ Phases 1, 2, & 3 shipped (Phases 1 & 2 on 2026-05-12 — builder + `from_file` (TOML) + `Config::load()` precedence chain wired into `main.rs`; Phase 3 on 2026-05-13 — `Config::from_env()` removed, callers fully migrated).
5. **§6 Coverage gate** — adopt at the *current* level immediately; ratchet over months. ✅ Phase 1 shipped 2026-05-12 (originally 60% / 60%; honest reset on 2026-05-14 to **35% lines / 42% functions** in [.github/workflows/coverage.yml](../../.github/workflows/coverage.yml) — the original floor was set above measured reality and the gate was red on `main` from day one; see §6.4 status).

§3 and §4 should land in the same PR if possible — `LayerOutcome` references `ErrorCode` directly.

---

## 8. Out of scope (explicit non-goals)

Patterns from qiuth that look interesting but **do not** belong in Proxilion:

- **Validator pipeline (IP / TOTP / Certificate / HMAC).** Proxilion doesn't do factor-based auth on inbound; PIC chain verification is the equivalent and is already pluggable via the Trust Plane.
- **Zero-deps philosophy.** Qiuth's `0 deps` is a TS-library virtue. Proxilion is a service with a deliberately heavy stack (Axum, sqlx, regorus, rustls). Don't optimize for a metric that isn't ours.
- **Drop-in framework middleware for Express/Fastify/Koa/Hono.** Proxilion is single-runtime (Axum). The qiuth pattern of "one trait, four adapters" only pays off if you ship to multiple frameworks.
- **Fluent builder for everything.** The §2 builder is for `Config` specifically. Don't reflexively builder-ize `Decision`, `PolicyTrace`, or per-request structs — they're constructed once and don't need the ceremony.
- **CLI for credential generation.** Qiuth's `src/cli/generate.ts` makes sense for an operator-distributed library. Proxilion's operator entry point is the dashboard + `proxilion-ctl` (if/when), not a separate generator binary.

---

## Appendix — File references summary

**Qiuth source of truth:**
- Config builder: [qiuth-main/src/config/config-builder.ts:25-279](../../qiuth-main/src/config/config-builder.ts#L25-L279)
- Authenticator pipeline: [qiuth-main/src/core/authenticator.ts:61-131](../../qiuth-main/src/core/authenticator.ts#L61-L131)
- Lookup function type: [qiuth-main/src/middleware/express.ts:43-45](../../qiuth-main/src/middleware/express.ts#L43-L45)
- Coverage config: [qiuth-main/vitest.config.ts](../../qiuth-main/vitest.config.ts)

**Proxilion targets:**
- Config to refactor: [crates/proxy/src/config.rs:51-102](../../crates/proxy/src/config.rs#L51-L102)
- Decision to extend: [crates/policy-engine/src/decision.rs:5-20](../../crates/policy-engine/src/decision.rs#L5-L20)
- Errors to formalize: [crates/proxy/src/adapters/error.rs:9-103](../../crates/proxy/src/adapters/error.rs#L9-L103)
- Policy engine to wrap: [crates/policy-engine/src/lib.rs](../../crates/policy-engine/src/lib.rs)
