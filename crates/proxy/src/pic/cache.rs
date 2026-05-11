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

#[derive(Debug, Clone)]
pub struct CachedPca {
    pub pca_id: Uuid,
    pub cbor: Vec<u8>,
    pub p_0: String,
    pub ops: Vec<String>,
    pub hop: i32,
    pub predecessor_id: Option<Uuid>,
    pub signature: Vec<u8>,
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
            INSERT INTO pca_cache (pca_id, cbor, p_0, ops, hop, predecessor_id, signature)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, pca_id: Uuid) -> Result<Option<CachedPca>, CacheError> {
        let row: Option<(Uuid, Vec<u8>, String, Json<Value>, i32, Option<Uuid>, Vec<u8>)> =
            sqlx::query_as(
                "SELECT pca_id, cbor, p_0, ops, hop, predecessor_id, signature \
                 FROM pca_cache WHERE pca_id = $1",
            )
            .bind(pca_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(id, cbor, p_0, ops, hop, pred, sig)| CachedPca {
            pca_id: id,
            cbor,
            p_0,
            ops: serde_json::from_value(ops.0).unwrap_or_default(),
            hop,
            predecessor_id: pred,
            signature: sig,
        }))
    }
}
