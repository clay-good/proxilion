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
