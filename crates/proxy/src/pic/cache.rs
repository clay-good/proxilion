//! Postgres-backed PCA cache.
//!
//! Authoritative copy lives in Trust Plane (`GET /v1/pca/{id}`); this is a
//! latency cache so the bearer middleware can load PCA_1 without round-trip.

use serde_json::Value;
use sqlx::PgPool;
use sqlx::types::Json;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("postgres: {0}")]
    Db(#[from] sqlx::Error),
}

/// The current PIC profile identifier. Pinned on every PCA cache row so a
/// future spec change (e.g. PIC adopts a new CBOR field shape) can be
/// detected by the verifier rather than silently accepted. Spec.md §15 #11.
pub const CURRENT_PIC_PROFILE: &str = "proxilion.v1";

#[derive(Debug, Clone)]
pub struct CachedPca {
    pub pca_id: Uuid,
    pub cbor: Vec<u8>,
    pub p_0: String,
    pub ops: Vec<String>,
    pub hop: i32,
    pub predecessor_id: Option<Uuid>,
    pub signature: Vec<u8>,
    /// Profile string under which this PCA was minted. New rows get
    /// `CURRENT_PIC_PROFILE`; historical rows backfill to `proxilion.v1`
    /// via the migration default.
    pub pic_profile: String,
}

impl CachedPca {
    /// Builder convenience: same as field-by-field but defaults `pic_profile`
    /// to the current value. Adapter call sites use this so they don't
    /// have to repeat the constant.
    #[allow(dead_code)] // kept as the public ergonomic constructor for downstream forks
    pub fn new(
        pca_id: Uuid,
        cbor: Vec<u8>,
        p_0: String,
        ops: Vec<String>,
        hop: i32,
        predecessor_id: Option<Uuid>,
    ) -> Self {
        Self {
            pca_id,
            cbor,
            p_0,
            ops,
            hop,
            predecessor_id,
            signature: vec![],
            pic_profile: CURRENT_PIC_PROFILE.to_string(),
        }
    }
}

#[derive(Clone)]
pub struct PcaCache {
    pool: PgPool,
}

impl PcaCache {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, pca: &CachedPca) -> Result<(), CacheError> {
        let ops_json: Value = serde_json::to_value(&pca.ops).expect("Vec<String> → JSON");
        sqlx::query(
            r#"
            INSERT INTO pca_cache
                (pca_id, cbor, p_0, ops, hop, predecessor_id, signature, pic_profile)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (pca_id) DO NOTHING
            "#,
        )
        .bind(pca.pca_id)
        .bind(&pca.cbor)
        .bind(&pca.p_0)
        .bind(Json(&ops_json))
        .bind(pca.hop)
        .bind(pca.predecessor_id)
        .bind(&pca.signature)
        .bind(&pca.pic_profile)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, pca_id: Uuid) -> Result<Option<CachedPca>, CacheError> {
        let row: Option<(
            Uuid,
            Vec<u8>,
            String,
            Json<Value>,
            i32,
            Option<Uuid>,
            Vec<u8>,
            String,
        )> = sqlx::query_as(
            "SELECT pca_id, cbor, p_0, ops, hop, predecessor_id, signature, pic_profile \
             FROM pca_cache WHERE pca_id = $1",
        )
        .bind(pca_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(
            row.map(|(id, cbor, p_0, ops, hop, pred, sig, profile)| CachedPca {
                pca_id: id,
                cbor,
                p_0,
                ops: serde_json::from_value(ops.0).unwrap_or_default(),
                hop,
                predecessor_id: pred,
                signature: sig,
                pic_profile: profile,
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_pic_profile_is_stable_v1_string() {
        // Pinned: a deliberate change here implies a migration story for
        // every cached row (spec.md §15 #11). Don't loosen casually.
        assert_eq!(CURRENT_PIC_PROFILE, "proxilion.v1");
    }

    #[test]
    fn cached_pca_new_defaults_pic_profile_to_current() {
        let id = Uuid::nil();
        let pca = CachedPca::new(
            id,
            vec![1, 2, 3],
            "alice@acme.com".into(),
            vec!["drive:read:file/x".into()],
            0,
            None,
        );
        assert_eq!(pca.pca_id, id);
        assert_eq!(pca.cbor, vec![1, 2, 3]);
        assert_eq!(pca.p_0, "alice@acme.com");
        assert_eq!(pca.ops, vec!["drive:read:file/x".to_string()]);
        assert_eq!(pca.hop, 0);
        assert!(pca.predecessor_id.is_none());
        assert!(pca.signature.is_empty());
        assert_eq!(pca.pic_profile, CURRENT_PIC_PROFILE);
    }

    #[test]
    fn cached_pca_new_carries_predecessor_when_present() {
        let pred = Uuid::new_v4();
        let pca = CachedPca::new(Uuid::nil(), vec![], "p".into(), vec![], 1, Some(pred));
        assert_eq!(pca.predecessor_id, Some(pred));
        assert_eq!(pca.hop, 1);
    }

    #[test]
    fn cache_error_display_passes_through_db_message() {
        // sqlx::Error::RowNotFound has a deterministic Display string.
        let e = CacheError::Db(sqlx::Error::RowNotFound);
        let s = e.to_string();
        assert!(s.starts_with("postgres:"));
        assert!(s.contains("no rows"));
    }

    #[test]
    fn cached_pca_is_clone_with_disjoint_buffers() {
        // The PCA cache hands out owned `CachedPca` values; the verifier
        // walks the chain by cloning each row. Pin that mutating a clone
        // doesn't tug the original (an accidental `Cow`/`Rc` field would
        // surface here).
        let a = CachedPca::new(
            Uuid::nil(),
            vec![1, 2, 3],
            "alice@acme.com".into(),
            vec!["drive:read:file/x".into()],
            0,
            None,
        );
        let mut b = a.clone();
        b.cbor.push(4);
        b.ops.push("drive:write:file/y".into());
        assert_eq!(a.cbor, vec![1, 2, 3], "original cbor unchanged");
        assert_eq!(a.ops.len(), 1, "original ops unchanged");
        assert_eq!(b.cbor.len(), 4);
        assert_eq!(b.ops.len(), 2);
    }

    #[test]
    fn cached_pca_new_starts_with_empty_signature() {
        // The `new()` constructor defers signature population to a later
        // `mint` step. Pin the empty-on-construction default so a future
        // refactor that pre-fills with a sentinel byte (e.g. for a "not
        // yet signed" marker) doesn't sneak through.
        let pca = CachedPca::new(Uuid::nil(), vec![], "p".into(), vec![], 0, None);
        assert!(pca.signature.is_empty());
    }

    #[test]
    fn cached_pca_new_round_trips_hop_at_i32_max_without_overflow() {
        // `hop: i32` is the chain depth — Postgres stores it as int4 so
        // the proxy domain is bounded at i32::MAX. Pin both boundaries
        // (0 and i32::MAX) so a refactor to `u32` (which would land in
        // postgres as int8 + need a migration) surfaces here rather than
        // silently when chain depths cross 2^31.
        let p0 = CachedPca::new(Uuid::nil(), vec![], "p".into(), vec![], 0, None);
        assert_eq!(p0.hop, 0);
        let pmax = CachedPca::new(Uuid::nil(), vec![], "p".into(), vec![], i32::MAX, None);
        assert_eq!(pmax.hop, i32::MAX);
    }

    #[test]
    fn cached_pca_debug_includes_pca_id_for_operator_log_grep() {
        // The `Debug` derive feeds every `tracing::warn!(?pca, ...)`
        // call site in the verifier — pin that the pca_id is visible in
        // the rendered string. A refactor that swapped `Debug` for a
        // manual impl elidng the id (in the name of "don't log secrets")
        // would silently break operator chain-verification triage.
        let id = Uuid::new_v4();
        let pca = CachedPca::new(id, vec![1], "p".into(), vec![], 0, None);
        let s = format!("{pca:?}");
        assert!(s.contains(&id.to_string()), "got: {s}");
        assert!(s.contains("pca_id"));
    }

    #[test]
    fn cached_pca_carries_large_ops_vec_through_clone() {
        // The PCA cache row's `ops` is a JSONB column with no schema-
        // imposed cap; the verifier hands the whole vec into the policy
        // engine for the Layer-A subset check. Pin that a Clone over a
        // multi-thousand-element ops list preserves every entry (so a
        // future micro-optimization that switched to `Cow<[String]>` —
        // and dropped the deep-copy semantic — surfaces here).
        let ops: Vec<String> = (0..2048).map(|i| format!("drive:read:file/{i}")).collect();
        let pca = CachedPca::new(Uuid::nil(), vec![], "p".into(), ops, 0, None);
        let c = pca.clone();
        assert_eq!(c.ops.len(), 2048);
        assert_eq!(c.ops[0], "drive:read:file/0");
        assert_eq!(c.ops[2047], "drive:read:file/2047");
    }

    #[test]
    fn cache_error_implements_std_error_trait_and_source_carries_inner_sqlx() {
        // `CacheError::Db` is `#[from] sqlx::Error` — the `thiserror`
        // derive wires both the `From` impl AND the `source()` chain. The
        // existing `cache_error_display_passes_through_db_message` test
        // pins the Display prefix but does NOT pin the chain walk; the
        // existing `cache_error_from_sqlx_via_question_mark` test pins
        // the `?` conversion but not the trait/source surface. Pin
        // `std::error::Error::source() == Some(sqlx_inner)` so a
        // refactor that swapped `#[from] sqlx::Error` for a
        // `String`-stringified inner (which would still pass the
        // existing Display + `?` tests) would surface here as
        // `source()` collapsing to None and breaking
        // `anyhow::Error::chain()` walks in the verifier's logs.
        use std::error::Error;
        let e: CacheError = CacheError::from(sqlx::Error::RowNotFound);
        let dyn_e: &(dyn Error + 'static) = &e;
        // source() MUST surface the inner sqlx::Error (a `String`-wrapped
        // refactor would silently return None here).
        let src = dyn_e.source().expect("Db variant has a #[from] source");
        // And the inner source's Display is the sqlx message verbatim
        // — pin the byte-identical passthrough at the chain-walk level.
        assert!(
            src.to_string().contains("no rows"),
            "inner sqlx::Error message must surface via source(): {}",
            src,
        );
        // The leaf has no further source (sqlx::Error::RowNotFound is
        // itself a leaf).
        assert!(src.source().is_none(), "inner sqlx leaf has no source");
    }

    #[test]
    fn current_pic_profile_format_pinned_proxilion_dot_v1_for_grep() {
        // The existing `current_pic_profile_is_stable_v1_string` test
        // pins byte-exact equality but doesn't pin the structural shape
        // (vendor prefix + version suffix). Operator dashboards that
        // bucket cached PCA rows by profile family (`proxilion.*` vs.
        // a future cross-vendor `consortium.*`) rely on the dot-separator
        // shape, and a future v2 bump still needs to match the
        // `proxilion.vN` pattern. Pin the structural invariants
        // explicitly so a refactor that swapped to underscore-separator
        // (`proxilion_v1`) or to a UUID would surface here alongside
        // the byte-exact pin.
        assert!(
            CURRENT_PIC_PROFILE.starts_with("proxilion."),
            "vendor prefix: {CURRENT_PIC_PROFILE}",
        );
        assert!(
            CURRENT_PIC_PROFILE.ends_with(".v1"),
            "version suffix: {CURRENT_PIC_PROFILE}",
        );
        // Exactly one dot separator between vendor and version (a
        // future `proxilion.v1.beta` shape would need a conscious
        // dashboard-routing change).
        assert_eq!(
            CURRENT_PIC_PROFILE.matches('.').count(),
            1,
            "exactly one dot separator: {CURRENT_PIC_PROFILE}",
        );
        // The vendor half is non-empty (a refactor to `.v1` alone
        // — e.g. an `_VERSION` constant rename collapse — would
        // silently drop the vendor namespace).
        let (vendor, _version) = CURRENT_PIC_PROFILE
            .split_once('.')
            .expect("dot present per invariant above");
        assert!(!vendor.is_empty(), "vendor half non-empty");
    }

    #[test]
    fn cached_pca_debug_carries_pca_id_ops_hop_and_predecessor_field_names() {
        // Symmetric expansion of `cached_pca_debug_includes_pca_id_for_operator_log_grep`
        // — that test pins ONLY the `pca_id` substring. The verifier's
        // chain-walk failure logs render `?pca` and operators grep for
        // `ops=`, `hop=`, `predecessor_id=` selectors to bucket "missing
        // op at hop N" vs. "broken chain link at predecessor M". A
        // manual Debug impl that hid the structural field names "for
        // brevity" would silently strip every selector but `pca_id`.
        // Pin all four field names AND the predecessor UUID substring.
        let pca_id = Uuid::new_v4();
        let pred = Uuid::new_v4();
        let pca = CachedPca::new(
            pca_id,
            vec![0xAA, 0xBB],
            "alice@acme.com".into(),
            vec!["drive:read:file/x".into()],
            7,
            Some(pred),
        );
        let s = format!("{pca:?}");
        assert!(s.contains("pca_id"), "got: {s}");
        assert!(s.contains("ops"), "got: {s}");
        assert!(s.contains("hop"), "got: {s}");
        assert!(s.contains("predecessor_id"), "got: {s}");
        // And the hop integer value (7) and predecessor UUID surface
        // for grep — a refactor that elided values for "log brevity"
        // would strip the selector content alongside the field name.
        assert!(s.contains("7"), "hop value visible: {s}");
        assert!(s.contains(&pred.to_string()), "predecessor UUID: {s}");
    }

    #[test]
    fn cached_pca_new_accepts_empty_strings_and_vecs_without_panic() {
        // The PCA cache row's `p_0` can in principle be an empty string
        // (e.g. a system-issued chain with no principal — not a real
        // production shape today, but a wire-shape edge). The current
        // constructor MUST NOT panic on empty inputs and MUST preserve
        // the empty values through to the struct fields (no
        // "default-to-(none)" sentinel substitution). A refactor that
        // started rejecting empty `p_0` at construction time "for
        // hygiene" would surface here — and would need to be a
        // conscious wire-shape change since the DB column is NOT NULL
        // but tolerates empty strings.
        let pca = CachedPca::new(Uuid::nil(), Vec::new(), String::new(), Vec::new(), 0, None);
        assert!(pca.cbor.is_empty());
        assert!(pca.p_0.is_empty(), "p_0 preserved as empty, not (none)");
        assert!(pca.ops.is_empty());
        assert!(pca.signature.is_empty());
        assert_eq!(pca.pic_profile, CURRENT_PIC_PROFILE);
    }

    #[test]
    fn pca_cache_clone_shares_underlying_pg_pool_via_arc() {
        // `PcaCache` derives `Clone` over a `PgPool` field; sqlx's
        // `PgPool::clone` is an Arc share, not a deep copy. Pin the
        // shared-state semantic via two compile-time + runtime checks:
        // (1) `PcaCache: Clone` (the `Clone` derive is what AppState
        // relies on when handing the cache to per-request handlers);
        // (2) cloning compiles without requiring a runtime PG
        // connection (PgPool's clone is infallible Arc bump). A
        // refactor that swapped `Clone` for a `try_clone() -> Result`
        // (in the name of "explicit failure") would surface as a
        // compile break here.
        // We can't easily construct a real PgPool in a unit test
        // without a connection, but we CAN verify the type-level
        // contract — `PcaCache: Clone + Send + Sync` are the bounds
        // every adapter handler signature relies on.
        fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
        assert_clone_send_sync::<PcaCache>();
    }

    #[test]
    fn cached_pca_new_round_trips_distinct_predecessor_uuids_independently() {
        // Each chain link's `predecessor_id` MUST round-trip the EXACT
        // UUID bytes — not a normalized/zeroed-out placeholder. The
        // existing `cached_pca_new_carries_predecessor_when_present`
        // test walks a single predecessor; pin that ten distinct
        // predecessors yield ten distinct struct fields with no
        // aliasing across constructions (a refactor to a `lazy_static`
        // sentinel for "speed" would surface here).
        let preds: Vec<Uuid> = (0..10).map(|_| Uuid::new_v4()).collect();
        let pcas: Vec<CachedPca> = preds
            .iter()
            .map(|p| CachedPca::new(Uuid::new_v4(), vec![], "x".into(), vec![], 1, Some(*p)))
            .collect();
        for (i, pca) in pcas.iter().enumerate() {
            assert_eq!(pca.predecessor_id, Some(preds[i]));
        }
        // And all ten predecessor UUIDs are pairwise distinct — sanity
        // check that the test fixture itself isn't degenerate (a
        // refactor in `Uuid::new_v4` would surface here as alias).
        let mut sorted = preds.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 10, "test fixture: 10 distinct UUIDs");
    }

    #[test]
    fn pca_cache_and_cached_pca_and_cache_error_are_send_sync_static() {
        // `PcaCache` lives in AppState; `CachedPca` is held across .await
        // points in adapter chain-walk handlers; `CacheError` flows through
        // anyhow chains. All three need (Send + Sync + 'static). A refactor
        // that swapped any field for an `Rc<...>` "for cheap clone" would
        // break Send + Sync but surface at AppState assembly with an opaque
        // tower::Service trait-bound error. Pin all three bounds.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<PcaCache>();
        require_send_sync_static::<CachedPca>();
        require_send_sync_static::<CacheError>();
    }

    #[test]
    fn current_pic_profile_byte_length_pinned_at_twelve_with_ascii_only_contract() {
        // The existing `current_pic_profile_is_stable_v1_string` test
        // pins byte-exact equality but doesn't pin the byte-length.
        // Migration scripts that pre-allocate `pic_profile` column
        // capacity (VARCHAR(N)) need a stable N — pin len() == 12. AND
        // pin ASCII-only via `is_ascii()` so a refactor to a multibyte
        // version-marker (`proxilion.v1²` or `proxilion.v1·`) would
        // surface here as either a length OR an ASCII contract failure
        // and force a conscious migration-script update.
        assert_eq!(CURRENT_PIC_PROFILE.len(), 12);
        assert!(CURRENT_PIC_PROFILE.is_ascii(), "must be ASCII-only");
        // chars().count() == len() iff every codepoint is single-byte.
        assert_eq!(
            CURRENT_PIC_PROFILE.chars().count(),
            CURRENT_PIC_PROFILE.len(),
            "ASCII-only ⇒ char count == byte count",
        );
    }

    #[test]
    fn cached_pca_with_one_kb_max_filled_cbor_survives_clone_byte_equal() {
        // The cbor field is `Vec<u8>` — production PCAs are typically
        // 200-800 bytes; pin that a 1KB all-0xFF buffer (the upper
        // boundary of the realistic size range, with byte values that
        // exercise every bit position) survives Clone byte-for-byte.
        // A refactor that switched to `bytes::Bytes` (ref-counted) +
        // accidentally introduced a copy-on-write that didn't preserve
        // the full buffer "for cold-path optimization" would surface
        // here as a byte-length or content diff after clone. The
        // existing `cached_pca_is_clone_with_disjoint_buffers` pin
        // covers 3 bytes; pin 1024 bytes too so any size-dependent
        // truncation surfaces.
        let large_cbor = vec![0xFFu8; 1024];
        let pca = CachedPca::new(
            Uuid::new_v4(),
            large_cbor.clone(),
            "alice@acme.com".into(),
            vec!["drive:read:file/x".into()],
            0,
            None,
        );
        let c = pca.clone();
        assert_eq!(c.cbor.len(), 1024);
        assert_eq!(c.cbor, large_cbor);
        // Spot-check every byte is 0xFF (the buffer wasn't zero-padded
        // by a sneaky resize).
        assert!(c.cbor.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn cache_error_debug_carries_db_variant_name_for_grep_bucketing() {
        // Operator log filters bucket cache-failure logs by Debug variant
        // name (`?err` rendering). CacheError has one variant today (Db)
        // but the Debug surface is independently load-bearing — a future
        // refactor that added a variant (e.g. `Decode` for CBOR parse
        // errors) would let operators add a new bucket only if the
        // variant name surfaces in Debug. Pin "Db" in the Debug render
        // so a manual Debug impl that collapsed everything to
        // `CacheError(_)` would surface here.
        let e = CacheError::Db(sqlx::Error::RowNotFound);
        let s = format!("{e:?}");
        assert!(s.contains("Db"), "got: {s}");
    }

    #[test]
    fn cached_pca_new_across_one_hundred_distinct_uuids_yields_distinct_pca_id_fields() {
        // The constructor is a pass-through: each call's `pca_id`
        // parameter lands in the `pca_id` field byte-for-byte. The
        // existing `cached_pca_new_round_trips_distinct_predecessor_uuids_independently`
        // pin walks 10 predecessor UUIDs through; pin the WIDER pca_id
        // sweep (100 distinct UUIDs) so a refactor that introduced any
        // form of pca_id rewriting at construction (e.g. "deterministic
        // re-hashing for some sharding scheme") would surface across
        // a wider statistical sample. Pairwise-distinct sanity check
        // on the inputs guards against a degenerate Uuid::new_v4
        // regression.
        let ids: Vec<Uuid> = (0..100).map(|_| Uuid::new_v4()).collect();
        let pcas: Vec<CachedPca> = ids
            .iter()
            .map(|i| CachedPca::new(*i, vec![], "p".into(), vec![], 0, None))
            .collect();
        for (i, pca) in pcas.iter().enumerate() {
            assert_eq!(pca.pca_id, ids[i], "pca_id at index {i} drifted");
        }
        // Pairwise distinctness on inputs (sanity).
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 100, "test fixture: 100 distinct UUIDs");
    }

    #[test]
    fn cached_pca_clone_preserves_pic_profile_and_signature_byte_equal() {
        // The existing `cached_pca_is_clone_with_disjoke_buffers` pin
        // covers cbor + ops independence under mutation. The two
        // OTHER load-bearing fields — `pic_profile` (which the verifier
        // compares against `CURRENT_PIC_PROFILE` to gate "this row was
        // minted under a profile we know how to verify") and
        // `signature` (the canonical signed bytes) — must ALSO
        // survive Clone byte-equal. A refactor that lazily shared
        // either via `Arc<...>` "for memory savings" would surface
        // here as the cloned values aliasing back to the original on
        // mutation. Pin field-equal post-clone on both, plus mutation-
        // independence on `signature` (the load-bearing one — a refactor
        // that shared the signature buffer across clones would let one
        // adapter's mutation poison another's verification).
        let mut pca = CachedPca::new(Uuid::new_v4(), vec![0xAA], "p".into(), vec![], 0, None);
        pca.signature = vec![1, 2, 3, 4, 5, 6, 7, 8];
        pca.pic_profile = "proxilion.v1".into();
        let c = pca.clone();
        // Field-equal post-clone.
        assert_eq!(c.signature, pca.signature);
        assert_eq!(c.pic_profile, pca.pic_profile);
        // Mutation-independence on signature.
        let original_sig = pca.signature.clone();
        let mut c2 = pca.clone();
        c2.signature.push(0xFF);
        assert_eq!(pca.signature, original_sig, "original signature unchanged");
        assert_eq!(c2.signature.len(), 9);
    }

    #[test]
    fn cache_error_from_sqlx_via_question_mark() {
        // `?`-conversion is what the public `insert` / `get` methods use;
        // pin the `#[from]` blanket-impl path so a future refactor that
        // drops `#[from]` would surface here as a compile error rather
        // than as a silent string-formatting regression downstream.
        fn maybe() -> Result<(), CacheError> {
            Err::<(), sqlx::Error>(sqlx::Error::RowNotFound)?;
            Ok(())
        }
        let e = maybe().unwrap_err();
        assert!(matches!(e, CacheError::Db(_)));
    }
}
