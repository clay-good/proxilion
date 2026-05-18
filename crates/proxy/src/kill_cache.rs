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
}
