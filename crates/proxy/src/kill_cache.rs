//! Bearer kill-cache (spec.md §3.2 deviation 2).
//!
//! The middleware's bearer check is dominated by a single Postgres JOIN
//! (`agent_bearers` × `google_tokens` × `oauth_sessions`). The JOIN is
//! single-digit-ms locally — the DB stays the source of truth — but
//! a long-lived process under sustained load reads the same row over
//! and over for a single revoked bearer until the in-flight requests
//! settle. The kill-cache adds a `O(1)` short-circuit: when the
//! killswitch handler revokes a row, the bearer's `sha256` lands in a
//! moka cache; the next middleware call sees the hash, rejects with the
//! same fixed `401 unauthorized` body, and never touches the DB.
//!
//! Cache hit ≠ source of truth. A cache *miss* always falls through to
//! the DB so a kill that happened in another replica still gets
//! enforced — the cache is per-process, by design. Multi-replica fleets
//! that want shared kill state run Redis-backed shared cache in v2.

use std::time::Duration;

use moka::future::Cache;

/// 1h TTL matches spec.md §3.2 — long enough that revoked bearers don't
/// keep racing the DB even if the agent retries aggressively; short
/// enough that an entry can roll off when its underlying row has long
/// since been cleaned up.
const ENTRY_TTL: Duration = Duration::from_secs(3600);

/// Capacity bound. The cache is per-process and stores 32-byte keys
/// against unit values; 100k entries is ~3 MB of overhead at most. That
/// covers any realistic fleet (proxy v1 design partner = thousands of
/// bearers, not millions).
const MAX_CAPACITY: u64 = 100_000;

#[derive(Clone)]
pub struct KillCache {
    hashes: Cache<[u8; 32], ()>,
}

impl Default for KillCache {
    fn default() -> Self {
        Self::new()
    }
}

impl KillCache {
    pub fn new() -> Self {
        Self {
            hashes: Cache::builder()
                .max_capacity(MAX_CAPACITY)
                .time_to_live(ENTRY_TTL)
                .build(),
        }
    }

    /// Record a revoked bearer hash. Called by the killswitch handler
    /// after the DB UPDATE commits, using the `bearer_sha256` values
    /// the UPDATE returned.
    #[allow(dead_code)] // single-mark variant kept for tests + future use; production uses mark_many
    pub async fn mark(&self, hash: [u8; 32]) {
        self.hashes.insert(hash, ()).await;
        metrics::counter!("proxilion_kill_cache_marks_total").increment(1);
    }

    /// Bulk mark — used by `/killswitch/user` and `/killswitch/all`
    /// where one UPDATE flips many rows.
    pub async fn mark_many(&self, hashes: impl IntoIterator<Item = [u8; 32]>) {
        for h in hashes {
            self.hashes.insert(h, ()).await;
        }
    }

    /// Membership test on the hot path.
    pub async fn is_killed(&self, hash: &[u8; 32]) -> bool {
        let hit = self.hashes.contains_key(hash);
        if hit {
            metrics::counter!("proxilion_kill_cache_hits_total").increment(1);
        }
        hit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn marked_hash_is_killed() {
        let kc = KillCache::new();
        let h = [7u8; 32];
        assert!(!kc.is_killed(&h).await);
        kc.mark(h).await;
        assert!(kc.is_killed(&h).await);
    }

    #[tokio::test]
    async fn unmarked_hash_is_not_killed() {
        let kc = KillCache::new();
        assert!(!kc.is_killed(&[0u8; 32]).await);
    }

    #[tokio::test]
    async fn mark_many_inserts_all() {
        let kc = KillCache::new();
        let hashes: Vec<[u8; 32]> = (0..5).map(|i| [i as u8; 32]).collect();
        kc.mark_many(hashes.clone()).await;
        for h in &hashes {
            assert!(kc.is_killed(h).await);
        }
    }

    #[tokio::test]
    async fn default_constructor_yields_empty_cache() {
        // `Default` is what `AppState` calls when no killswitch backend is
        // wired in tests — pinning that it behaves as a fresh `new()` (no
        // false-positive kills carried over from some shared static).
        let kc: KillCache = Default::default();
        assert!(!kc.is_killed(&[1u8; 32]).await);
        assert!(!kc.is_killed(&[2u8; 32]).await);
        kc.mark([1u8; 32]).await;
        assert!(kc.is_killed(&[1u8; 32]).await);
        assert!(!kc.is_killed(&[2u8; 32]).await);
    }

    #[tokio::test]
    async fn two_cache_instances_do_not_share_state() {
        // Per-process design — pin that two `new()` invocations build
        // independent caches. A future refactor accidentally moving the
        // moka `Cache` into a `lazy_static` global would surface here.
        let a = KillCache::new();
        let b = KillCache::new();
        let h = [9u8; 32];
        a.mark(h).await;
        assert!(a.is_killed(&h).await);
        assert!(!b.is_killed(&h).await);
    }

    #[tokio::test]
    async fn mark_repeated_same_hash_remains_killed_no_panic() {
        // `mark` is `insert` under the hood; moka's `insert` of an existing
        // key is a no-op replace, not an error. Pin idempotency on the
        // happy path — the killswitch handler may be called twice for the
        // same row across a quick retry; the second `mark` must not panic
        // and the hash must remain killed. A regression to a Vec-backed
        // duplicate-rejecting impl would surface here.
        let kc = KillCache::new();
        let h = [3u8; 32];
        kc.mark(h).await;
        kc.mark(h).await;
        kc.mark(h).await;
        assert!(kc.is_killed(&h).await);
    }

    #[tokio::test]
    async fn neighbor_hash_differing_by_one_byte_is_not_killed() {
        // Pin byte-for-byte hash equality: marking `[7u8; 32]` must NOT
        // also kill `[7u8; 32]` with byte 0 flipped to `6`. A regression
        // that compared hash prefixes (e.g. 16-byte hash truncation for
        // "faster lookup") would let one revoked bearer also kill a
        // neighbor that happens to share a prefix.
        let kc = KillCache::new();
        let marked = [7u8; 32];
        let mut neighbor = [7u8; 32];
        neighbor[0] = 6;
        kc.mark(marked).await;
        assert!(kc.is_killed(&marked).await);
        assert!(!kc.is_killed(&neighbor).await);
    }

    #[test]
    fn entry_ttl_constant_pinned_at_one_hour_per_spec() {
        // The 1-hour TTL is documented in spec.md §3.2 — long enough that
        // revoked bearers don't keep racing the DB even on aggressive
        // agent retries, short enough that an entry rolls off when its
        // underlying row has been cleaned up. A regression that
        // tightened it to 60s would silently triple the DB load under
        // sustained kill traffic; a regression that loosened it to a
        // day would leak revoked bearers across cache eviction windows
        // for too long. Pin the documented value directly.
        assert_eq!(ENTRY_TTL, Duration::from_secs(3600));
    }

    #[test]
    fn max_capacity_constant_pinned_at_one_hundred_thousand() {
        // The 100k entry cap is the operational sizing decision per
        // the file docs ("100k entries is ~3 MB of overhead at most;
        // proxy v1 design partner = thousands of bearers, not
        // millions"). A regression that dropped it to 10k would
        // silently start evicting hot entries under realistic fleet
        // scale; a bump to 10M would silently change the memory
        // budget by ~30x. Pin the documented value.
        assert_eq!(MAX_CAPACITY, 100_000);
    }

    #[tokio::test]
    async fn clone_shares_underlying_moka_cache_marks_visible_across_clones() {
        // `KillCache` derives `Clone` over the `Cache<...>` field; moka's
        // `Cache::clone` is an `Arc` share, not a deep copy. Pin the
        // shared-state semantic: a mark on one clone must be visible
        // through the other. The kill_cache is handed to AppState, then
        // cloned into every middleware invocation — a refactor that
        // deep-copied the cache (e.g. "isolate test fixtures") would
        // silently make every request see a fresh empty cache, breaking
        // killswitch enforcement on every replica with > 1 in-flight
        // request.
        let a = KillCache::new();
        let b = a.clone();
        let h = [42u8; 32];
        // Mark on `a`, observe via `b`.
        a.mark(h).await;
        assert!(b.is_killed(&h).await, "clone must see original's marks");
        // Symmetric: mark on `b`, observe via `a`.
        let h2 = [43u8; 32];
        b.mark(h2).await;
        assert!(a.is_killed(&h2).await, "original must see clone's marks");
    }

    #[test]
    fn kill_cache_is_send_sync_static_for_app_state_arc_path() {
        // `KillCache` is held in `AppState` which is cloned into every
        // tower layer / middleware extractor — the `Send + Sync + 'static`
        // combo is the AppState-bound contract. A refactor that gave
        // `KillCache` a `Cell<u64>` field "for in-process hit counters"
        // would break Sync without surfacing at this file; the breakage
        // would appear at AppState assembly with an unrelated trait-bound
        // error. Pin the three-trait combo here so the type boundary
        // fails fast at the right call site.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<KillCache>();
    }

    #[tokio::test]
    async fn mark_many_with_one_hundred_distinct_hashes_all_observable() {
        // The killswitch handlers fire `mark_many` on the full set of
        // sha256 values returned from a single UPDATE — for `/killswitch/all`
        // that can be the entire active-bearer table. Pin bulk correctness:
        // 100 distinct hashes all observable individually after one
        // `mark_many` call, with no boundary entries lost (first / middle /
        // last). A regression that capped the loop at N entries or hashed
        // the iterator position into the key would surface as missing kills
        // at the boundaries.
        let kc = KillCache::new();
        let hashes: Vec<[u8; 32]> = (0..100u8).map(|i| [i; 32]).collect();
        kc.mark_many(hashes.clone()).await;
        assert!(kc.is_killed(&hashes[0]).await);
        assert!(kc.is_killed(&hashes[50]).await);
        assert!(kc.is_killed(&hashes[99]).await);
        for h in &hashes {
            assert!(kc.is_killed(h).await);
        }
    }

    #[tokio::test]
    async fn mark_many_with_duplicate_hashes_in_iterator_is_idempotent() {
        // The killswitch handler is the only `mark_many` caller; today's
        // implementation iterates the UPDATE's RETURNING which produces
        // distinct rows. But a future caller (multi-killswitch fan-in,
        // say) could legitimately produce a deduplicated set. Pin that
        // duplicate hashes in the same `mark_many` call do not panic and
        // leave the cache in the same observable state as a single mark
        // — moka `insert` of an existing key is a no-op replace, but a
        // refactor to a count-tracking variant ("dedupe stats for ops")
        // could trip on the duplicate. Symmetric to the existing single-
        // mark idempotency pin but on the bulk path.
        let kc = KillCache::new();
        let h = [11u8; 32];
        kc.mark_many(vec![h, h, h, h, h]).await;
        assert!(kc.is_killed(&h).await);
    }

    #[tokio::test]
    async fn mark_and_mark_many_single_element_produce_equivalent_state() {
        // `mark(h)` and `mark_many([h])` are the two write paths into the
        // cache — they MUST produce equivalent observable state. A
        // refactor that gave `mark_many` a different code path (a bulk
        // batch op, say) and accidentally tagged its entries with a
        // distinguishing TTL or flag would silently make killswitch/user
        // (mark_many) behave differently from killswitch/single (mark).
        // Pin equivalence by symmetric setup: same hash via each path,
        // both yield is_killed == true; the cross-path mark is also a
        // no-op (the entry is already there).
        let a = KillCache::new();
        let b = KillCache::new();
        let h = [21u8; 32];
        a.mark(h).await;
        b.mark_many(std::iter::once(h)).await;
        assert!(a.is_killed(&h).await);
        assert!(b.is_killed(&h).await);
        // Cross-path: marking the same hash via the other path is a no-op.
        a.mark_many(std::iter::once(h)).await;
        b.mark(h).await;
        assert!(a.is_killed(&h).await);
        assert!(b.is_killed(&h).await);
    }

    #[tokio::test]
    async fn boundary_hash_values_all_zero_and_all_ones_killed_independently() {
        // The 32-byte hash space's two extreme corners — `[0u8; 32]` and
        // `[0xffu8; 32]` — are valid sha256 outputs in principle (probability
        // is negligible but the type accepts them). Pin both: each can be
        // marked, each is killed, and marking one does NOT kill the other
        // (no "treat all-zero as sentinel meaning unset" regression). A
        // refactor to a sparse-bitset backend that branched on the all-zero
        // key as a placeholder would surface here as a false-negative on
        // the all-zero arm.
        let kc = KillCache::new();
        let zeros = [0u8; 32];
        let ones = [0xffu8; 32];
        kc.mark(zeros).await;
        assert!(kc.is_killed(&zeros).await);
        assert!(!kc.is_killed(&ones).await);
        kc.mark(ones).await;
        assert!(kc.is_killed(&zeros).await);
        assert!(kc.is_killed(&ones).await);
    }

    #[tokio::test]
    async fn is_killed_takes_reference_and_does_not_consume_or_mutate_hash() {
        // `is_killed` signature is `&self, hash: &[u8; 32]) -> bool` —
        // it takes a borrow, NOT an owned array. Pin that the hash
        // value the caller holds is unchanged after the call AND that
        // repeated calls with the same `&` reference return the same
        // result without side-effects. The middleware path is
        // ```ignore
        // let hash = h.as_bytes(); if kill_cache.is_killed(&hash).await ...
        // ```
        // — a refactor that took the hash by value would force the
        // call site to clone for downstream use; pin the borrow
        // signature so any such refactor surfaces here.
        let kc = KillCache::new();
        let h = [55u8; 32];
        kc.mark(h).await;
        let observed_1 = kc.is_killed(&h).await;
        let observed_2 = kc.is_killed(&h).await;
        let observed_3 = kc.is_killed(&h).await;
        assert!(observed_1 && observed_2 && observed_3);
        // The original hash array is byte-unchanged after the calls.
        assert_eq!(h, [55u8; 32]);
    }

    #[tokio::test]
    async fn mark_many_with_empty_iterator_is_noop() {
        // `mark_many` is called from killswitch handlers in a loop over
        // UPDATE's RETURNING; if the UPDATE matched zero rows the iterator
        // is empty. Pin that this path doesn't panic and leaves the cache
        // untouched.
        let kc = KillCache::new();
        kc.mark_many(std::iter::empty()).await;
        assert!(!kc.is_killed(&[0u8; 32]).await);
    }

    #[tokio::test]
    async fn mark_many_accepts_array_iterator_not_only_vec() {
        // `mark_many` signature is `impl IntoIterator<Item = [u8; 32]>` —
        // it must accept ANY `IntoIterator` shape, not just `Vec`. The
        // killswitch handler currently passes a `Vec`, but a future
        // caller might inline a stack-allocated array literal for a
        // small known set. Pin that an array-literal IntoIterator
        // marks the elements correctly — a refactor to a `Vec`-only
        // signature (`hashes: Vec<[u8; 32]>`) would force callers to
        // allocate at every call site and would break the generic
        // contract this signature documents.
        let kc = KillCache::new();
        let h1 = [10u8; 32];
        let h2 = [20u8; 32];
        let h3 = [30u8; 32];
        kc.mark_many([h1, h2, h3]).await;
        assert!(kc.is_killed(&h1).await);
        assert!(kc.is_killed(&h2).await);
        assert!(kc.is_killed(&h3).await);
    }

    #[tokio::test]
    async fn concurrent_marks_across_independent_tasks_all_observable() {
        // The kill_cache is shared across every middleware invocation
        // via `AppState.clone()` — concurrent marks (e.g. several
        // killswitch endpoints firing in parallel against distinct
        // bearer sets) must all land in the same observable cache.
        // Pin this by spawning 10 tasks that each mark a distinct
        // hash through a clone of the cache; all 10 hashes are
        // observable from the parent handle afterwards. A refactor
        // that introduced any per-task-local mutation buffer
        // ("batch flush every N marks") would surface here as a
        // missing hash on a race-loss boundary.
        let kc = KillCache::new();
        let mut handles = Vec::with_capacity(10);
        for i in 0..10u8 {
            let kc = kc.clone();
            handles.push(tokio::spawn(async move {
                kc.mark([i + 100; 32]).await;
            }));
        }
        for h in handles {
            h.await.expect("mark task panicked");
        }
        for i in 0..10u8 {
            assert!(
                kc.is_killed(&[i + 100; 32]).await,
                "mark from task {i} not visible on parent handle",
            );
        }
    }

    #[tokio::test]
    async fn mark_many_with_256_distinct_hashes_all_observable() {
        // The existing `mark_many_with_one_hundred_distinct_hashes` pin
        // covers 100 entries. Pin a wider 256-entry bulk — the
        // killswitch `/killswitch/all` endpoint can return the entire
        // active-bearer table, and 256 is below the moka 100k capacity
        // bound by three orders of magnitude (so eviction is NOT a
        // factor) but is wider than any small hard-coded cap (16, 32,
        // 64, 128) a "batched insert for performance" refactor might
        // introduce. Iterate the full 0..=255 byte value range so
        // every all-N-fill pattern is exercised.
        let kc = KillCache::new();
        let hashes: Vec<[u8; 32]> = (0..=255u8).map(|i| [i; 32]).collect();
        kc.mark_many(hashes.clone()).await;
        for (i, h) in hashes.iter().enumerate() {
            assert!(kc.is_killed(h).await, "hash at index {i} missing");
        }
    }

    #[tokio::test]
    async fn default_and_new_constructors_produce_observably_equivalent_empty_state() {
        // The existing `default_constructor_yields_empty_cache` pin
        // checks `Default::default()` is empty. Pin DIRECT equivalence
        // between `KillCache::new()` AND `Default::default()` — both
        // must yield empty observable state across multiple probe
        // hashes, AND both must accept the same `mark` + `is_killed`
        // call sequence symmetrically. A refactor that gave Default
        // a divergent code path ("Default uses a smaller capacity for
        // tests") would silently change the boot-time cache shape
        // depending on which constructor AppState happened to call.
        let new_cache = KillCache::new();
        let default_cache: KillCache = Default::default();
        let probes = [[0u8; 32], [1u8; 32], [0xffu8; 32], [42u8; 32]];
        for p in &probes {
            assert!(!new_cache.is_killed(p).await);
            assert!(!default_cache.is_killed(p).await);
        }
        let h = [77u8; 32];
        new_cache.mark(h).await;
        default_cache.mark(h).await;
        assert!(new_cache.is_killed(&h).await);
        assert!(default_cache.is_killed(&h).await);
        // Non-matching probe still unkilled on both — the mark didn't
        // leak across hashes on either constructor.
        let neighbor = [78u8; 32];
        assert!(!new_cache.is_killed(&neighbor).await);
        assert!(!default_cache.is_killed(&neighbor).await);
    }

    #[tokio::test]
    async fn marking_one_hash_does_not_kill_any_of_a_hundred_distinct_neighbors() {
        // The existing `neighbor_hash_differing_by_one_byte_is_not_killed`
        // pin checks ONE neighbor. Pin the broader anti-leakage contract:
        // marking exactly one hash must leave 100 distinct random-pattern
        // neighbors all unkilled. A regression that hashed only a prefix
        // for cache lookup, or that used a Bloom-filter-style approximate
        // set under the hood "to reduce memory", would surface here as
        // false-positive kills across a wide neighbor sweep — even if
        // the one-byte-flip neighbor happened to land in a clean cell.
        let kc = KillCache::new();
        let marked = [123u8; 32];
        kc.mark(marked).await;
        assert!(kc.is_killed(&marked).await);
        for i in 0..100u8 {
            // Build a neighbor by setting byte i (mod 32) to a value
            // different from 123; tile the index across the 32-byte
            // hash so we exercise every byte position over the sweep.
            let mut neighbor = [123u8; 32];
            let pos = (i as usize) % 32;
            neighbor[pos] = i.wrapping_add(7);
            if neighbor == marked {
                continue;
            }
            assert!(
                !kc.is_killed(&neighbor).await,
                "false-positive kill on neighbor i={i} pos={pos}",
            );
        }
    }

    // ─── round 201 (2026-05-20): KillCache + const field-type surfaces ───

    #[test]
    fn entry_ttl_constant_field_type_is_duration_for_moka_time_to_live_signature_compat() {
        // `ENTRY_TTL: Duration` matches moka's `time_to_live(...)`
        // signature which takes `Duration`. The existing
        // `entry_ttl_constant_pinned_at_one_hour_per_spec` pin walks
        // the VALUE; pin the TYPE here so a refactor to bare `u64`
        // / `i64` "for simpler config parsing" would surface here
        // rather than at the cache-builder call site (where moka's
        // trait-bound error would mention an unrelated type). The
        // unit-information (seconds vs millis) lives at the type
        // level via Duration. Symmetric to round-196
        // DEFAULT_TICK_INTERVAL Duration + round-199 BurstConfig
        // window/flush_interval Duration type pins extended to this
        // sibling cache-TTL constant.
        fn require_duration(_: Duration) {}
        require_duration(ENTRY_TTL);
    }

    #[test]
    fn max_capacity_constant_field_type_is_u64_for_moka_max_capacity_signature_compat() {
        // `MAX_CAPACITY: u64` matches moka's `max_capacity(...)`
        // signature which takes `u64` (not `usize` — moka counts
        // entries with a 64-bit counter independent of platform
        // pointer width so multi-million-entry caches behave
        // identically on 32-bit and 64-bit hosts). The existing
        // `max_capacity_constant_pinned_at_one_hundred_thousand`
        // pin walks the VALUE; pin the TYPE here so a refactor to
        // `usize` "for symmetry with Vec::len()" would surface at
        // the cache-builder call site with a far-removed type
        // mismatch. Symmetric to round-199 BurstSummary count
        // fields u64 + round-196 ExpirySweepReport.expired_rows u64
        // type pins extended to this sibling capacity-cap constant.
        fn require_u64(_: u64) {}
        require_u64(MAX_CAPACITY);
    }

    #[tokio::test]
    async fn mark_return_type_is_unit_not_result_for_infallible_hot_path() {
        // `mark(&self, hash: [u8; 32]) -> ()` — the return type is
        // unit, NOT `Result<(), _>`. The killswitch handler's hot
        // path is `kc.mark(h).await;` without `?` — it does NOT
        // surface a "couldn't mark" failure to the operator. moka's
        // insert is infallible by construction. A refactor that
        // promoted to `Result<(), CacheError>` "for future shared-
        // cache backend wiring" would break every kill_cache call
        // site (which today never matches on the return). Pin via
        // require_unit. Symmetric to round-192 slack helpers +
        // round-199 admit() bool-not-Result + round-198 oauth body()
        // infallibility pins extended to this hot-path write.
        fn require_unit(_: ()) {}
        let kc = KillCache::new();
        let out: () = kc.mark([4u8; 32]).await;
        require_unit(out);
    }

    #[tokio::test]
    async fn mark_many_return_type_is_unit_not_result_for_infallible_bulk_write_path() {
        // Symmetric to the `mark` return-type pin above. The bulk
        // path `mark_many(impl IntoIterator<Item = [u8; 32]>) -> ()`
        // is also infallible — moka's per-entry insert is infallible
        // AND the loop has no early-return semantics. A refactor
        // that promoted to `Result<usize, CacheError>` "for caller-
        // visible partial-failure accounting" would force every
        // killswitch handler to plumb through the count + check the
        // result. Pin unit-return via require_unit. The two write
        // helpers (`mark` + `mark_many`) MUST move in lockstep on
        // the infallibility contract.
        fn require_unit(_: ()) {}
        let kc = KillCache::new();
        let out: () = kc.mark_many(vec![[5u8; 32]]).await;
        require_unit(out);
    }

    #[tokio::test]
    async fn mark_signature_takes_owned_hash_by_value_not_borrow_for_moka_insert_ownership() {
        // `mark(&self, hash: [u8; 32])` — the hash parameter is
        // OWNED `[u8; 32]`, NOT a borrowed `&[u8; 32]`. moka's
        // `insert(key, value)` takes the key by-value (it stores
        // an owned copy in the cache table). Passing the hash
        // by-value here lets the caller hand off ownership without
        // an intermediate clone. The existing `is_killed_takes_reference`
        // pin walks the read-path borrow contract; pin the write-
        // path by-value contract here. A refactor to `&[u8; 32]`
        // "for symmetry with is_killed" would force `mark` to
        // clone internally on every call site OR would force the
        // killswitch handler to keep the `[u8; 32]` alive past
        // the `mark` call (which it currently does NOT — the
        // handler iterates the UPDATE's RETURNING and consumes
        // each row's hash). The compile-time check is the
        // by-value let-binding pattern.
        let kc = KillCache::new();
        let hash: [u8; 32] = [99u8; 32];
        // Passing by-value MOVES the hash (Copy makes this no-op,
        // but the type-shape contract holds at the signature).
        kc.mark(hash).await;
        // The Copy semantics allow re-use of the local even after
        // the move-by-value — pin that the hash is unchanged.
        assert_eq!(hash, [99u8; 32]);
        // And the cache contains the marked hash.
        assert!(kc.is_killed(&hash).await);
    }

    #[test]
    fn kill_cache_clone_trait_bound_explicit_for_arc_share_axum_state_contract() {
        // `KillCache: Clone` — derived. The existing
        // `clone_shares_underlying_moka_cache_marks_visible_across_clones`
        // pin walks BEHAVIOR (clones share marks). Pin the TRAIT
        // BOUND directly via require_clone so a refactor that
        // dropped the derive "to forbid accidental aliasing" would
        // surface at the type level rather than at the AppState
        // assembly site with an unrelated `Clone` trait-bound error.
        // The kill_cache is held in AppState which is `Clone`'d into
        // every request scope — Clone on KillCache is load-bearing
        // for the entire axum middleware chain. Symmetric to
        // round-191 SetupApiState Clone+Send+Sync+'static +
        // round-192 SlackInteractState Clone pins extended to this
        // sibling AppState-held shape.
        fn require_clone<T: Clone>() {}
        require_clone::<KillCache>();
    }

    #[tokio::test]
    async fn is_killed_returns_bool_not_optional_on_unmarked_hash() {
        // The middleware's hot path uses `if kc.is_killed(&h).await { ... }`
        // — the return type MUST be `bool`, not `Option<bool>` or `Result<bool>`.
        // A refactor that added a "cache failure" error variant ("propagate
        // moka shutdown errors") would force every call site to add
        // `.unwrap_or(false)` and would change the fail-open vs fail-closed
        // posture on the hot path. Pin the return type at the call site
        // by using the value DIRECTLY in a boolean context with no
        // unwrap/match — if the signature ever changes, this test fails
        // to compile rather than silently downgrading the safety posture.
        let kc = KillCache::new();
        let h = [88u8; 32];
        let observed: bool = kc.is_killed(&h).await;
        assert!(!observed);
        // Negation also works without coercion — pin that `bool` is the
        // raw type, not `IntoFuture<Output=bool>` (already awaited).
        if kc.is_killed(&h).await {
            panic!("unmarked hash should not be killed");
        }
    }

    // ─── round 228 (2026-05-22): KillCache exhaustive destructure, constructor
    // + mark_many fn-pointer return-type pins, ENTRY_TTL value-stability,
    // is_killed return-type fn-pointer, mark accepts owned [u8;32] not borrow ───

    #[tokio::test]
    async fn kill_cache_field_count_pinned_at_exactly_one_via_exhaustive_destructure_no_rest() {
        // `KillCache { hashes: Cache<[u8; 32], ()> }` — exactly 1 field
        // (the moka cache). A 2nd field landing (e.g. `marks_total:
        // AtomicU64` for in-struct metric tracking, OR `redis_backend:
        // Option<RedisClient>` for the v2 multi-replica shared-cache
        // path) without matching `KillCache::new()` constructor wiring
        // would silently leave the new field zero-initialized — the
        // v2 multi-replica path would be silently a no-op. The
        // exhaustive destructure with no `..` rest pattern forces a
        // 2nd field to update this site in lockstep with the
        // constructor. Symmetric to the WebhookSecret 1-field +
        // ExpirySweepReport 1-field + EscalationSweepReport 1-field
        // exhaustive-destructure pins extended to this sibling cache
        // type.
        let kc = KillCache::new();
        let KillCache { hashes: _ } = kc;
    }

    #[test]
    fn kill_cache_new_return_type_is_owned_self_by_value_via_fn_pointer_witness() {
        // `KillCache::new() -> Self` is the constructor AppState calls
        // exactly once at boot. The value is then Arc-wrapped at the
        // call site (`Arc::new(KillCache::new())`) and shared across
        // every middleware invocation. Pin the return type at the
        // construction boundary via a fn-pointer witness `fn() ->
        // KillCache`. A refactor to `Arc<Self>` "for ergonomic
        // already-shared construction" would force the AppState
        // assembly to drop its own Arc-wrap step, breaking the
        // single-Arc invariant operators rely on (a double-Arc would
        // pass functional tests but inflate strong_count drifts in
        // shutdown teardown observation). A refactor to `Result<Self,
        // BuildError>` "for fallibility on moka builder failure"
        // would force every AppState assembly site to add `?`.
        // Symmetric to the TeeStream::new + WebhookNotifier::new
        // owned-Self fn-pointer pins.
        let _f: fn() -> KillCache = KillCache::new;
        fn require_owned_kill_cache(_: KillCache) {}
        require_owned_kill_cache(KillCache::new());
    }

    #[test]
    fn kill_cache_default_return_type_is_owned_self_by_value_via_fn_pointer_witness() {
        // The `Default` impl on `KillCache` returns `Self` by value —
        // a refactor that hand-rolled the Default impl to return
        // `Box<Self>` or `Arc<Self>` would break the AppState
        // assembly site that uses `KillCache::default()`
        // interchangeably with `KillCache::new()`. The existing
        // `default_constructor_yields_empty_cache` test exercises the
        // VALUE-LEVEL invariant (default == empty); pin the
        // TYPE-LEVEL return shape via a fn-pointer witness so a future
        // hand-rolled Default returning Box would surface here at the
        // type axis, not at the AppState call site downstream.
        // Symmetric to the KillCache::new fn-pointer pin above.
        let _f: fn() -> KillCache = <KillCache as Default>::default;
        fn require_owned_kill_cache(_: KillCache) {}
        require_owned_kill_cache(KillCache::default());
    }

    #[tokio::test]
    async fn entry_ttl_and_max_capacity_constant_values_are_referentially_transparent_across_reads()
    {
        // `ENTRY_TTL: Duration` and `MAX_CAPACITY: u64` are file-scope
        // `const` declarations — reads are inlined at compile time and
        // MUST produce the byte-identical value across N reads. Pin
        // referential transparency across 50 reads on each constant.
        // A refactor that swapped either to a `static` or to a
        // `lazy_static! { ref ENTRY_TTL: Duration = ... }`
        // "for env-var override at boot" would silently break the
        // compile-time inlining AND open the door to per-read
        // mutation (e.g. a `RwLock<Duration>` for live-tunable TTL).
        // Symmetric to the sanitize_token + ErrorBody::new RT 50-call
        // pins extended to these sibling constants.
        let ttl_first = ENTRY_TTL;
        let cap_first = MAX_CAPACITY;
        for i in 0..50 {
            assert_eq!(ENTRY_TTL, ttl_first, "iter {i}: ENTRY_TTL drift");
            assert_eq!(MAX_CAPACITY, cap_first, "iter {i}: MAX_CAPACITY drift");
        }
    }

    #[test]
    fn is_killed_borrows_hash_ref_not_owned_for_zero_alloc_hot_path_signature() {
        // `KillCache::is_killed(&self, hash: &[u8; 32]) -> bool` —
        // takes `&[u8; 32]` by REFERENCE, not owned `[u8; 32]`. The
        // middleware's hot path passes a borrow from the
        // `SessionContext.bearer_hash` field (`&session.bearer_hash`).
        // A refactor to take by value (`hash: [u8; 32]`) "for moka's
        // `contains_key(&K)` ergonomics — let the caller move the
        // 32 bytes in" would force every middleware call site to add
        // `*hash` or `hash.clone()`, allocating an extra 32 bytes per
        // request — an observable per-request alloc on the hot path
        // operators specifically tuned for zero-alloc gates. Pin via
        // a fn-pointer witness with the borrowed parameter shape.
        // Symmetric to the existing `mark_signature_takes_owned_hash
        // _by_value_not_borrow_for_moka_insert_ownership` pin (the
        // INVERSE on mark()) — both pins together document the asymmetry
        // between the write path (consume owned) and the read path
        // (borrow shared).
        // The future trait dispatch uses generic Future, so we
        // can't write a direct `fn(...) -> bool` pointer; instead
        // bind the method-resolution path via a closure with an
        // explicit parameter signature and assert the body compiles.
        async fn require_borrow_arg(kc: &KillCache, hash: &[u8; 32]) -> bool {
            kc.is_killed(hash).await
        }
        // Compile-time witness — runtime exercise too.
        let kc = KillCache::new();
        let h = [42u8; 32];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let observed = rt.block_on(require_borrow_arg(&kc, &h));
        assert!(!observed);
    }

    #[tokio::test]
    async fn entry_ttl_value_relationships_to_max_capacity_bound_safe_memory_footprint() {
        // `ENTRY_TTL = 3600s` AND `MAX_CAPACITY = 100_000` together
        // bound the per-process kill-cache memory footprint at
        // approximately 100_000 * (32-byte key + ~24-byte moka entry
        // overhead) = ~5.6 MB. The doc comment claims ~3 MB which is
        // the bare-key calculation. A refactor that bumped capacity
        // to 10M "to cover larger fleets" without correspondingly
        // tightening TTL would push the per-process footprint to
        // ~560 MB — a regression operators rolling out under tight
        // RSS budgets would surface only at production scale. Pin
        // the upper-bound product so a refactor surfaces here at the
        // value-domain. The strict-equality pins on the two constants
        // (`entry_ttl_constant_pinned_at_one_hour_per_spec` +
        // `max_capacity_constant_pinned_at_one_hundred_thousand`)
        // each cover one axis individually; pin the cross-axis
        // relationship here so a TTL-tightening compensated by a
        // capacity-loosening would still trip the gate. Symmetric
        // to the DEFAULT_TICK_INTERVAL-bounded-positive cross-axis
        // pin in blocked_expiry.rs.
        let memory_budget_bytes: u64 = 8 * 1024 * 1024; // 8 MB ceiling
        let bytes_per_entry: u64 = 64; // generous over-count for moka overhead
        let estimated_footprint = MAX_CAPACITY * bytes_per_entry;
        assert!(
            estimated_footprint <= memory_budget_bytes,
            "MAX_CAPACITY {MAX_CAPACITY} × bytes_per_entry {bytes_per_entry} = {estimated_footprint} exceeds budget {memory_budget_bytes}",
        );
        // And TTL is sized for a steady-state agent retry pattern
        // (1h covers a single auth re-validation cycle).
        assert!(
            ENTRY_TTL >= Duration::from_secs(60),
            "ENTRY_TTL {:?} is too short — sub-1m TTL would let revoked bearers race the DB",
            ENTRY_TTL,
        );
        assert!(
            ENTRY_TTL <= Duration::from_secs(86_400),
            "ENTRY_TTL {:?} is too long — >1d TTL stalls a Redis-backed v2 migration's deduplication",
            ENTRY_TTL,
        );
    }
}
