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

---

## 7. Rollout order & dependencies

Suggested sequence (each step is independently shippable):

1. **§4 ErrorCode registry** — smallest, unblocks §3. ~1 day.
2. **§3 PolicyTrace** — depends on §4. ~3 days incl. dashboard wiring.
3. **§5 PolicyLoader trait + cache** — independent of §3/§4 but easier to test once trace exists. ~3 days.
4. **§2 ConfigBuilder** — independent. Defer until embed API is on the roadmap; until then, env-only is fine. ~2 days.
5. **§6 Coverage gate** — adopt at the *current* level immediately; ratchet over months.

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
