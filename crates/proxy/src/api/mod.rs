//! Management/observability HTTP API consumed by the dashboard.
//!
//! Authority: spec.md §1.5 + §1.6. M1 mounts these routes *unauthenticated*
//! on the same axum app as the agent OAuth endpoints — the assumption is
//! that operator traffic terminates at the proxy from inside a trust
//! boundary (compose network, k8s service). §1.6 will revisit when the
//! dashboard's auth story lands.

pub mod actions;
pub mod blocked;
pub mod killswitch;
pub mod notifier;
pub mod notifier_public;
pub mod notifier_slack;
pub mod policy;
pub mod setup;

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use uuid::Uuid;

use crate::pic::{PcaCache, PicVerifier};

#[derive(Clone)]
pub struct ApiState {
    pub verifier: Arc<PicVerifier>,
    pub pca_cache: PcaCache,
}

pub fn router(state: ApiState) -> Router {
    use crate::operator_auth::scope_check;
    use axum::middleware::from_fn_with_state;
    Router::new()
        .route(
            "/api/v1/pca/{id}",
            get(get_pca).route_layer(from_fn_with_state("pca:read", scope_check)),
        )
        .route(
            "/api/v1/pca/{id}/verify",
            get(verify_pca).route_layer(from_fn_with_state("pca:read", scope_check)),
        )
        .with_state(state)
}

#[derive(Serialize)]
struct PcaView {
    pca_id: Uuid,
    p_0: String,
    ops: Vec<String>,
    hop: i32,
    predecessor_id: Option<Uuid>,
    /// PIC profile pinned at insert time (spec.md §15 #11).
    pic_profile: String,
    /// CBOR bytes, hex-encoded (small enough to inline for inspection).
    cbor_hex: String,
}

async fn get_pca(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PcaView>, ApiError> {
    let Some(row) = state.pca_cache.get(id).await? else {
        return Err(ApiError::NotFound);
    };
    Ok(Json(PcaView {
        pca_id: row.pca_id,
        p_0: row.p_0,
        ops: row.ops,
        hop: row.hop,
        predecessor_id: row.predecessor_id,
        pic_profile: row.pic_profile,
        cbor_hex: hex_encode(&row.cbor),
    }))
}

async fn verify_pca(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = state
        .verifier
        .verify_chain(id)
        .await
        .map_err(ApiError::Verifier)?;
    Ok(Json(serde_json::json!({
        "intact": result.intact,
        "links_verified": result.links_verified,
        "p_0": result.p_0,
        "broken_at": result.broken_at,
        "reason": result.reason,
        "pic_profile": result.pic_profile,
        "pic_profile_mismatch_at": result.pic_profile_mismatch_at,
    })))
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("not found")]
    NotFound,
    #[error(transparent)]
    Db(#[from] crate::pic::cache::CacheError),
    #[error("verifier: {0}")]
    Verifier(crate::pic::VerifierError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        use crate::error_envelope::ErrorBody;
        let (status, body) = match &self {
            ApiError::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody::new("not found", "not_found")
                    .with_fix("The PCA id isn't in pca_cache. Either the chain was evicted, or it never landed here (Trust Plane has no GET /v1/pca/{id} endpoint yet — see spec §1.2).")
                    .with_docs("https://proxilion.com/docs/admin/pca-cache"),
            ),
            ApiError::Db(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody::new("database error", "internal_error")
                    .with_detail(e.to_string())
                    .with_fix("Check that postgres is reachable: curl /healthz. If degraded, restart postgres or check disk space.")
                    .with_docs("https://proxilion.com/docs/troubleshooting"),
            ),
            ApiError::Verifier(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody::new("chain verification error", "verifier_error")
                    .with_detail(e.to_string())
                    .with_fix("Inspect the PCA chain via /api/v1/pca/{id} and walk the broken_at link. Re-fetch the predecessor from Trust Plane if needed.")
                    .with_docs("https://proxilion.com/docs/pic/verify"),
            ),
        };
        body.into_response(status)
    }
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_lowercase() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn api_error_not_found_response() {
        let r = ApiError::NotFound.into_response();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn hex_encode_covers_all_byte_values() {
        // The encoder is hot-path for `/api/v1/pca/{id}` — a regression
        // that emitted upper-case or truncated leading zeros would break
        // any downstream tool that round-trips through `hex::decode`.
        let all: Vec<u8> = (0u8..=255).collect();
        let s = hex_encode(&all);
        assert_eq!(s.len(), 512);
        assert!(s.starts_with("000102"), "leading zero bytes keep width 2");
        assert!(s.ends_with("fdfeff"), "high-byte tail is lowercase");
        // Every char is a valid lowercase hex digit.
        for ch in s.chars() {
            assert!(
                ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
                "non-lowercase hex char: {ch}",
            );
        }
    }

    #[test]
    fn api_error_db_maps_to_500_with_internal_error_code() {
        // The Db path is hit on a real Postgres outage; the dashboard
        // surfaces the `code` field — pin both the 500 status and the
        // `internal_error` machine-readable code so a Grafana alert keyed
        // on `code="internal_error" status="500"` doesn't drift silently.
        let e = ApiError::Db(crate::pic::cache::CacheError::Db(sqlx::Error::RowNotFound));
        let r = e.into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn hex_encode_byte_count_matches_two_per_input_byte() {
        // Length invariant — operator-visible cbor blobs are often size-
        // bounded by a CLI flag and the proxy enforces "2 * len" upstream.
        for n in [0usize, 1, 16, 64, 257] {
            let buf = vec![0xa5u8; n];
            assert_eq!(hex_encode(&buf).len(), n * 2);
        }
    }
}
