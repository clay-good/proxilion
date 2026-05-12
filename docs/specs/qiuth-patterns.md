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

### 2.5 Status (2026-05-12) — Phase 1 shipped.

- [crates/proxy/src/config.rs](../../crates/proxy/src/config.rs) — new `ConfigBuilder` with `defaults()`, `from_env_layer()` (composes env vars on top), `with_*` overrides for every field, and `build()` (runs semantic validation, then constructs `Config`). `Config::from_env()` now delegates to `ConfigBuilder::defaults().from_env_layer()?.build()` — byte-identical with the prior loader, just refactored. `Config::load()` is the forward-looking convenience entry; today it aliases `from_env`, phase 2 will layer `PROXILION_CONFIG_FILE` underneath.
- New `ConfigError::InvalidValue { field, reason }` variant carries the field name (e.g. `PROXILION_TOKEN_ENCRYPTION_KEY`) so the operator sees the env var that's wrong, not just "bad value somewhere."
- Semantic validation now runs in `build()`:
  - `token_encryption_key_hex` is exactly 64 hex characters when present (rejects truncated keys at boot rather than at first cipher use).
  - `trust_plane_url` + `federation_bridge_url` must start with `http://` or `https://`.
  - `dev_mode == false` still requires both cert + key paths to exist (unchanged behavior).
- Tests: 6 new in `config::tests` covering defaults-in-dev-mode, key-too-short rejection, valid-key acceptance, non-http URL rejection, cert-required-when-not-dev-mode, and programmatic override composition (`with_bind_addr` + `with_database_url` + `with_policy_path` chain cleanly).

**Deviations from §2.2 sketch.**

1. **No `from_file()` yet.** That's phase 2 — needs a decision between TOML and YAML (TOML feels right for ops config, YAML keeps consistency with `policy.yaml`). Holding off until a customer asks for either.
2. **No `Config::load()` precedence chain yet.** Today it's an alias for `from_env`. Adding the file layer is `defaults().from_file(path)?.from_env_layer()?.build()` — same builder, just an extra layer call.

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

### 3.4 Status (2026-05-12) — types + engine entry shipped; adapter wiring deferred.

- [crates/policy-engine/src/trace.rs](../../crates/policy-engine/src/trace.rs) — new module with `PolicyTrace`, `LayerOutcome`, `PolicyLayer` (LayerA / LayerB / ReadFilter), `OpsAtomView`, `PolicyEvalMode`. `LayerOutcome::error_code` carries the canonical `shared_types::ErrorCode` from §4. `PolicyTrace::allowed()` is `true` only when every layer passed AND the final decision is `Allow`.
- [crates/policy-engine/src/rego.rs](../../crates/policy-engine/src/rego.rs) — new `Engine::evaluate_with_trace(&ctx)` sibling to `evaluate(&ctx)`. Returns `(Outcome, PolicyTrace)` so callers that don't need the structured trace pay nothing. The trace fills in Layer A (engine-side, `passed: true`, records the required-ops count), Layer B (translates `Decision::{Allow, Block, RequireConfirmation, RateLimit}` to the matching `ErrorCode`), and an optional ReadFilter slot when a filter is configured (left as `passed: true; scan pending` for the adapter to mutate after the response body comes back).
- [crates/policy-engine/Cargo.toml](../../crates/policy-engine/Cargo.toml) — adds `chrono`, `uuid` (already in the workspace).
- Tests: 4 new in `trace::tests` + 3 integration tests in `crates/policy-engine/tests/policy_trace.rs` that exercise the engine with the live `config/policy.yaml`. Covers (a) Layer-B block via `gmail-external-send-gate` records `ErrorCode::PolicyBlocked` + the matched policy id, (b) no-policy-match path emits Layer A + Layer B both passed, (c) `drive-injection-filter` produces a ReadFilter slot with `passed: true` pending the adapter scan.

**Deviations from §3.2/§3.3 sketch.**

1. **Engine still exposes `evaluate(&ctx) -> Outcome` unchanged.** The spec sketch implies replacing the verdict-shaped return type; we ship the new typed path alongside the old one so the three adapters (Drive / Gmail / Calendar), the policy-handle, and ~12 existing tests don't have to change in one PR. Adapter migration to `evaluate_with_trace` is the natural next step — at that point the trace's Layer-A entry can be mutated to `failed` on Trust-Plane refusal, and the trace can be logged + surfaced via `X-Proxilion-Trace-Id`.
2. **`PolicyEvalMode::{FailFast, Comprehensive}` defined but not yet observed.** The current engine evaluates fail-fast by structure (the YAML interpreter returns on the first match). `Comprehensive` mode that walks every later policy for "would also have matched" diagnostics is a follow-up tied to the dashboard's explain-this-denial replay path — file an issue when a customer asks.
3. **Read-filter Layer outcome is `passed: true; scan pending` until the adapter runs.** Adapter-side mutation of the trace lands when the wiring happens; today the engine emits the slot so the trace's shape is stable.

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

**Don't start at 90%.** Proxilion isn't a 318-test library; it's a service. Realistic ramp:

| Phase | Lines | Functions | Notes |
|---|---:|---:|---|
| Adoption | 60% | 60% | Pin the current floor. Anything below blocks PRs. |
| 3 months | 70% | 70% | Forces test backfill for OAuth flow + PCA cache |
| 6 months | 80% | 80% | Long-term target |

Per-crate overrides are fine — `shared-types/` is mostly re-exports and can stay lower; `policy-engine/` should sit highest since it's a pure library with no IO.

### 6.3 What this doesn't fix

A coverage gate ensures lines are *executed* in tests, not that the tests assert anything meaningful. Pair it with the existing integration test pattern in [policy-engine/tests/example_policies.rs](../../crates/policy-engine/tests/example_policies.rs) — that file is the model for "test what the policy actually decides," not just "the function returned."

### 6.4 Status (2026-05-12) — Phase 1 floor pinned at 60% / 60%.

- [.github/workflows/coverage.yml](../../.github/workflows/coverage.yml) — runs `cargo llvm-cov --workspace --lcov --output-path lcov.info` on every PR and push to `main`. Threshold: `--fail-under-lines 60 --fail-under-functions 60`. The rendered summary is logged for PR reviewers; the `lcov.info` artifact is always uploaded so downstream tools (Codecov, etc.) can consume it.
- Uses `taiki-e/install-action` to install `cargo-llvm-cov` from a pre-built binary (saves ~3 minutes vs `cargo install`).
- Caches `~/.cargo/registry`, `~/.cargo/git`, and `target` keyed on `Cargo.lock` — the SHA-pinned upstream `pic-protocol` + `provenance-*` deps make a cold build expensive (~6 min); a warm cache brings it under 90s.
- Tests dir is excluded from the report (`--ignore-filename-regex '(^|/)tests/'`); coverage is measured against `src/`.

**Ratchet plan.**

The phase ladder in §6.2 (60 → 70 → 80) lives only in this YAML's `--fail-under-*` flags. Bump it in a single-line PR alongside the test backfill that earned the bump — never bump speculatively. The 3-month / 6-month targets in the table are aspirational, not calendar-bound.

**Deviations from §6.2 sketch.**

1. **No per-crate thresholds.** `cargo-llvm-cov`'s `--fail-under-*` is workspace-wide. Per-crate enforcement would need a `cargo llvm-cov report --output-format json` post-processing step. Holding off until the workspace floor is so high that the lowest-coverage crate is dragging it down.
2. **No Codecov / coveralls integration.** The lcov artifact is uploaded; a downstream uploader can be wired in via a follow-up workflow without touching the gate itself.

---

## 7. Rollout order & dependencies

Suggested sequence (each step is independently shippable):

1. **§4 ErrorCode registry** — smallest, unblocks §3. ~1 day. ✅ shipped 2026-05-12.
2. **§3 PolicyTrace** — depends on §4. ~3 days incl. dashboard wiring. ✅ shipped 2026-05-12 (types + engine entry; adapter wiring deferred).
3. **§5 PolicyLoader trait + cache** — independent of §3/§4 but easier to test once trace exists. ~3 days. ✅ shipped 2026-05-12 (`FilePolicyLoader` is the production path; `DbPolicyLoader` is a one-line plug-in).
4. **§2 ConfigBuilder** — independent. Defer until embed API is on the roadmap; until then, env-only is fine. ~2 days. ✅ Phase 1 shipped 2026-05-12 (`from_env` delegates to builder; semantic validation runs in `build()`).
5. **§6 Coverage gate** — adopt at the *current* level immediately; ratchet over months. ✅ Phase 1 shipped 2026-05-12 (60% lines / 60% functions floor in [.github/workflows/coverage.yml](../../.github/workflows/coverage.yml)).

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
