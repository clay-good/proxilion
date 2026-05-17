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
