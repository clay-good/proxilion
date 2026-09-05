# HA & horizontal scaling

> production-readiness.md **PR-7**. What is safe to run as N replicas, what
> changes meaning when you do, and the Kubernetes primitives the chart ships.

**Bottom line.** The proxy is safe to run as N replicas today. Postgres is the
source of truth for every correctness-bearing decision; every in-process cache
is either a pure accelerator that falls through to the DB on a miss, or a
*limit* that is enforced per replica and therefore multiplies by N — those you
must size (§2). The one thing that is **not** safe to leave at its default is
the PIC executor identity, which the boot guard now enforces (§3).

## 1. Statelessness audit

| In-process state | What it holds | Class | Multi-replica behavior |
|---|---|---|---|
| [`kill_cache`](../../crates/proxy/src/kill_cache.rs) `Cache<[u8;32],()>` (1 h TTL, 100k) | revoked bearer hashes | **A — accelerator** | Negative cache only. A *miss* always reads `agent_bearers`, so a kill on replica A is enforced by B on its next request. See §4 for the bound. |
| [`pic::verifier`](../../crates/proxy/src/pic/verifier.rs) `Cache<Uuid, VerificationResult>` (60 s, 10k) | chain-verification results by leaf PCA | **A — accelerator** | Result is a pure function of DB rows + the CAT public key. Worst case a revoked-then-reverified chain is stale for ≤ 60 s per replica. |
| [`pic::cache`](../../crates/proxy/src/pic/cache.rs) `PcaCache` | PCA CBOR | **A — DB-backed** | Backed by the `pca_cache` table, not process memory. Shared by construction. |
| [`operator_auth`](../../crates/proxy/src/operator_auth.rs) `touch_cache` (`Uuid → Instant`) | debounce for `last_used_at` writes | **A — accelerator** | Worst case N× as many `last_used_at` UPDATEs. Cosmetic. |
| [`oauth::jwks`](../../crates/proxy/src/oauth/jwks.rs) JWKS cache + unknown-`kid` throttle | IdP verifying keys | **A — accelerator** | Independent per replica, so steady-state IdP QPS is N/hour and the unknown-`kid` refresh throttle admits at most N per minute fleet-wide. Size §5 against your IdP's rate limit. |
| [`pic::cat_key`](../../crates/proxy/src/pic/cat_key.rs) CAT key (1 h TTL + 1 h stale grace) | Trust Plane CAT verifying key | **A — accelerator** | Refetched once the TTL elapses, so a CAT rotation reaches every replica within an hour with no fleet roll. One refresh at a time per replica; a failing refresh keeps serving the last key for at most one more hour, then fails closed. |
| [`edge`](../../crates/proxy/src/edge.rs) rate-limit buckets (`IpAddr → Bucket`) | per-IP token buckets | **B — per-replica limit** | Effective fleet limit is `rate_limit_per_sec × N`. See §2. |
| [`edge`](../../crates/proxy/src/edge.rs) concurrency `Semaphore` | global in-flight ceiling | **B — per-replica limit** | Effective fleet ceiling is `max_concurrent_requests × N`. See §2. |
| [`notifier::burst`](../../crates/proxy/src/notifier/burst.rs) `BurstSuppressor` buckets | approval-notification suppression | **B — per-replica limit** | Best-effort by design: a burst spread across replicas can emit up to N× the configured notifications. Accepted (notification noise, not an authority decision). |
| [`auth_middleware`](../../crates/proxy/src/auth_middleware.rs) `RefreshCoordinator` locks | per-bearer Google-refresh mutex | **B — per-replica coalescing** | Coalesces a refresh stampede *within* a replica; up to N concurrent refreshes fleet-wide for one bearer. Google tolerates this; the last write to `google_tokens` wins. |
| [`pic::executor`](../../crates/proxy/src/pic/executor.rs) keypair + `registered: OnceCell` | executor signing identity | **C — must be pinned** | See §3. |
| [`policy_handle`](../../crates/proxy/src/policy_handle.rs) | compiled policy bundle | **A — config** | Each replica hot-reloads the same ConfigMap. A `checksum/policy` pod annotation rolls the fleet on change. |

**Class A** is safe to be replica-local with no configuration change.
**Class B** is safe but changes the *meaning* of a number you configured.
**Class C** needs an explicit operator decision.

## 2. Settings that multiply by replica count

Divide the fleet-wide budget by the replica count before setting these:

| Setting | Fleet-wide effect |
|---|---|
| `PROXILION_RATE_LIMIT_PER_SEC` / `_BURST` | `value × N` per client IP, unless your ingress already load-balances by source IP affinity |
| `PROXILION_MAX_CONCURRENT_REQUESTS` | `value × N` in flight |
| Notification burst limits | up to `value × N` notifications per window |

Postgres connections are the other side of the same arithmetic: the pool is
per replica, so size `max_connections` (or a PgBouncer in front) for
`pool_size × N` plus the Trust Plane's own connections.

## 3. Executor identity — the one hard requirement

The PIC executor signs every Proof-of-Custody the proxy submits. Without
`PROXILION_EXECUTOR_KID` + `PROXILION_EXECUTOR_KEY` each **process** mints a
throwaway Ed25519 keypair at boot, so:

- an N-replica fleet presents N distinct executors to the Trust Plane, and
  every rolling restart adds N more registry entries that never expire;
- there is nothing stable to revoke if an executor is compromised;
- the audit trail attributes hops to identities that exist nowhere else.

None of that is recoverable after the fact, so `PROXILION_ENV=staging` or
`production` **refuses to boot** unless both are set
(`Config::executor_boot_refusal`). Setting only one is treated as unset and
logged loudly — two replicas registering different public keys under one
`kid` is worse than an honest ephemeral identity. Generate the seed with
`openssl rand -hex 32` and mount it via `PROXILION_EXECUTOR_KEY_FILE`; see
[key-inventory.md](key-inventory.md).

## 4. Killswitch propagation across replicas

A revocation UPDATEs `agent_bearers` and marks the hash in the *issuing*
replica's kill cache. Other replicas learn on their next request for that
bearer, because a kill-cache **miss** falls through to the DB. The bound is
therefore **one request cycle**, not a cache TTL — there is no window in which
a replica serves a revoked bearer from stale positive state. The 1 h TTL only
governs how long the accelerator keeps saving a DB round-trip.
[runbooks/killswitch.md](runbooks/killswitch.md) has the operator procedure.

## 5. Kubernetes HA (what the chart ships)

| Value | Default | Why |
|---|---|---|
| `proxy.replicaCount` | `2` | Survive a single pod loss. |
| `proxy.ha.podDisruptionBudget.enabled` / `.minAvailable` | `true` / `1` | Keep one proxy serving through a node drain or cluster upgrade. Only rendered above one replica — a PDB on a one-replica Deployment blocks drains outright. |
| `proxy.ha.spreadAcrossNodes` | `true` | `topologySpreadConstraints` with `maxSkew: 1` on `kubernetes.io/hostname`, `ScheduleAnyway` so a single-node dev cluster still schedules. |
| `proxy.ha.affinity` | `{}` | Raw affinity block merged verbatim, for zone-level anti-affinity or node-pool pinning. |
| `proxy.terminationGracePeriodSeconds` | `45` | The proxy drains for 30 s on SIGTERM; the kubelet must wait longer or in-flight agent requests are SIGKILLed. |
| `proxy.autoscaling.*` | off | HPA on CPU. A queue-depth custom metric is the better signal — see below. |

## 6. Remaining PR-7 work

- **Capacity numbers.** The formulas above are right; the constants (req/s per
  replica, memory per connection, NATS throughput) need a k6/vegeta run at
  target load across ≥ 2 replicas, held against the PR-5 latency SLO.
- **HPA on a real signal.** CPU is a lagging proxy for the thing that actually
  saturates (in-flight requests against `max_concurrent_requests`); wire the
  custom metric once the load test says where the knee is.
- **Replica-loss drill.** Kill one replica mid-load and confirm zero dropped
  correctness guarantees, and that a revocation issued to one replica is
  enforced by the others within the §4 bound.
- **Postgres HA** (interlocks PR-8): primary + replica with automated
  failover, and PgBouncer if `pool_size × N` outgrows `max_connections`.
