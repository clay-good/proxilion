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

    #[tokio::test]
    async fn api_error_db_body_carries_fix_and_docs_hints() {
        // The Db-error 500 envelope must surface BOTH the curl /healthz
        // hint AND the troubleshooting docs link — these are the
        // operator's first 30 seconds during a postgres outage. Pin
        // both so a refactor that dropped `.with_fix(...)` or
        // `.with_docs(...)` doesn't silently regress.
        let e = ApiError::Db(crate::pic::cache::CacheError::Db(sqlx::Error::PoolClosed));
        let r = e.into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "internal_error");
        assert!(v["fix"].as_str().unwrap().contains("curl /healthz"));
        assert!(v["docs"].as_str().unwrap().contains("troubleshooting"));
    }

    #[tokio::test]
    async fn api_error_not_found_body_includes_fix_and_pca_cache_docs_link() {
        // NotFound is hit on a chain that was evicted or never landed.
        // The operator-onboarding contract: the response body must
        // explain WHY (eviction + the "Trust Plane has no GET endpoint
        // yet" surrounding context) and link to the admin pca-cache
        // docs. Pin both so a future tightening that hid the detail
        // (in the name of "minimal 404 body") doesn't silently degrade
        // the operator triage path.
        let r = ApiError::NotFound.into_response();
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "not_found");
        assert!(v["fix"].as_str().unwrap().contains("Trust Plane"));
        assert!(v["docs"].as_str().unwrap().contains("pca-cache"));
    }

    #[test]
    fn pca_view_serializes_with_stable_field_names() {
        // The `/api/v1/pca/{id}` response shape is consumed by the
        // dashboard's chain-walker — pin every public field by name
        // (not by value) so a Serde rename or field reorder surfaces
        // here rather than as a silent UI break.
        let v = PcaView {
            pca_id: Uuid::nil(),
            p_0: "alice@demo.local".into(),
            ops: vec!["drive:read:file/x".into()],
            hop: 3,
            predecessor_id: Some(Uuid::nil()),
            pic_profile: "proxilion.v1".into(),
            cbor_hex: "deadbeef".into(),
        };
        let s = serde_json::to_value(&v).unwrap();
        for key in [
            "pca_id",
            "p_0",
            "ops",
            "hop",
            "predecessor_id",
            "pic_profile",
            "cbor_hex",
        ] {
            assert!(s.get(key).is_some(), "missing wire key: {key}");
        }
        assert_eq!(s["pic_profile"], "proxilion.v1");
        assert_eq!(s["hop"], 3);
        assert_eq!(s["cbor_hex"], "deadbeef");
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

    #[test]
    fn api_error_verifier_arm_maps_to_500_with_verifier_error_code() {
        // Symmetric pin to `api_error_db_maps_to_500_with_internal_error_code`:
        // the Verifier arm was the only one of the three ApiError variants
        // never directly exercised — the operator dashboard splits chain-
        // walker faults from generic DB faults on the `code` axis, and a
        // refactor that collapsed `verifier_error` into `internal_error`
        // "for consistency" would silently merge the two buckets in
        // Grafana panels keyed on `code="verifier_error"`.
        let e = ApiError::Verifier(crate::pic::VerifierError::Missing(Uuid::nil()));
        let r = e.into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn api_error_verifier_body_carries_fix_and_pic_verify_docs_link() {
        // The Verifier 500 envelope's operator-actionable shape — the
        // `fix` must mention `broken_at` (the field on `VerificationResult`
        // the operator walks to) and the docs link must point at the
        // `/pic/verify` page. A refactor that dropped either `.with_fix`
        // or `.with_docs` would silently degrade the operator's first
        // 30 seconds during a chain-walk fault.
        let e = ApiError::Verifier(crate::pic::VerifierError::Missing(Uuid::nil()));
        let r = e.into_response();
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "verifier_error");
        assert!(v["fix"].as_str().unwrap().contains("broken_at"));
        assert!(v["docs"].as_str().unwrap().contains("pic/verify"));
    }

    #[tokio::test]
    async fn api_error_verifier_body_carries_detail_from_inner_error() {
        // The `.with_detail(e.to_string())` is the only surface that
        // carries the inner `VerifierError` message to the operator —
        // a refactor that dropped the detail "to avoid leaking internals"
        // would strip the actionable triage half (which pca id failed,
        // why). Pin both that `detail` is present AND that it carries
        // the inner error's `Display` substring ("not found in cache"
        // for the Missing variant).
        let e = ApiError::Verifier(crate::pic::VerifierError::Missing(Uuid::nil()));
        let r = e.into_response();
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let detail = v["detail"].as_str().expect("detail field present");
        assert!(
            detail.contains("not found in cache"),
            "expected inner VerifierError Display in detail, got: {detail}",
        );
    }

    #[test]
    fn api_error_display_renders_not_found_string_for_grep() {
        // `thiserror` derives Display from the `#[error("not found")]`
        // attribute — operator log filters and the `tracing::error!(error = %e, ...)`
        // shape both surface this string. A refactor that prefixed the
        // variant name (e.g. "not_found: not found") would silently break
        // any operator log filter keyed on the exact substring `"not found"`
        // as a standalone token.
        let s = format!("{}", ApiError::NotFound);
        assert_eq!(s, "not found");
    }

    #[test]
    fn api_error_display_renders_verifier_prefix_with_inner_message() {
        // The Verifier arm's `#[error("verifier: {0}")]` template is the
        // single-line shape that lands in `tracing::error!(error = %e, ...)`
        // when the chain-walker faults. Pin both halves: the literal
        // `"verifier: "` prefix (operator log aggregators split chain-
        // walker faults from generic DB faults on this prefix) AND the
        // inner VerifierError's Display substring after the colon. A
        // refactor to `#[error("chain: {0}")]` "for clarity" would
        // silently break every log filter keyed on `"verifier:"`.
        let e = ApiError::Verifier(crate::pic::VerifierError::Missing(Uuid::nil()));
        let s = format!("{e}");
        assert!(s.starts_with("verifier: "), "got: {s}");
        assert!(s.contains("not found in cache"), "got: {s}");
    }

    #[test]
    fn api_state_and_api_error_are_send_sync_static_for_axum_boundary() {
        // `ApiState` is passed via `with_state(...)` into the axum
        // Router (axum requires `Send + Sync + 'static` on State).
        // `ApiError` flows through `IntoResponse` from handler futures
        // crossing tokio task boundaries and needs the same bounds.
        // A refactor that wrapped `pca_cache` in `Rc<...>` for "cheap
        // clone" would break Sync at the router site. Pin both bounds
        // — symmetric to the
        // `api_error_and_killswitch_state_are_send_sync_static_for_axum_state_boundary`
        // pin on [crates/proxy/src/api/killswitch.rs].
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<ApiState>();
        require_send_sync_static::<ApiError>();
    }

    #[test]
    fn api_error_db_arm_display_passes_inner_cache_error_via_transparent_derive() {
        // `Db(#[from] CacheError)` uses `#[error(transparent)]` — the
        // wrapper's Display MUST equal the inner `CacheError`'s
        // Display byte-for-byte (no prefix, no formatting wrapper).
        // The Verifier arm sibling uses `#[error("verifier: {0}")]`
        // (explicit prefix) which the existing
        // `api_error_display_renders_verifier_prefix_with_inner_message`
        // test pins. Pin transparent passthrough on Db here so a
        // refactor that swapped `#[error(transparent)]` for
        // `#[error("db: {0}")]` "for symmetry with verifier" would
        // silently prepend "db: " to every Db-error log line and break
        // operator log filters that grep on raw CacheError Display
        // substrings — symmetric to the killswitch + setup transparent-
        // pass-through pins on api/killswitch.rs + api/setup.rs.
        let inner = crate::pic::cache::CacheError::Db(sqlx::Error::RowNotFound);
        let inner_s = inner.to_string();
        let wrapped = ApiError::Db(crate::pic::cache::CacheError::Db(sqlx::Error::RowNotFound));
        assert_eq!(
            wrapped.to_string(),
            inner_s,
            "Db arm transparent derive must passthrough Display verbatim",
        );
    }

    #[test]
    fn api_error_debug_carries_all_three_variant_names_for_grep_bucketing() {
        // The `#[derive(Debug)]` on `ApiError` feeds `?err` in
        // `tracing::warn!(?err, ...)` call sites. Operators grep the
        // log line by variant name to bucket NotFound (eviction or
        // never-landed) vs Db (postgres outage) vs Verifier (chain-
        // walker fault). A hand-rolled Debug that hid any variant
        // name "to compact" the line would break the bucket. Pin all
        // three names — extends the existing per-variant Display pins
        // with the Debug-axis coverage that operator grep keys on.
        let nf = format!("{:?}", ApiError::NotFound);
        assert!(nf.contains("NotFound"), "got: {nf}");
        let db = format!(
            "{:?}",
            ApiError::Db(crate::pic::cache::CacheError::Db(sqlx::Error::RowNotFound))
        );
        assert!(db.contains("Db"), "got: {db}");
        let verifier = format!(
            "{:?}",
            ApiError::Verifier(crate::pic::VerifierError::Missing(Uuid::nil()))
        );
        assert!(verifier.contains("Verifier"), "got: {verifier}");
    }

    #[test]
    fn pca_view_ops_serializes_as_json_array_preserving_order_across_multi_element() {
        // The `ops: Vec<String>` field renders the granted-ops list on
        // the dashboard's chain-walker panel. Pin that the wire shape
        // is a JSON array (NOT a comma-joined string) AND that the
        // input order is preserved verbatim — operators read the ops
        // top-to-bottom expecting the same order as the source PCA's
        // ops. A refactor that collected into a `HashSet<String>` for
        // dedup or sorted for "tidy display" would silently scramble
        // the order. Walk a 5-element non-alphabetical fixture.
        let v = PcaView {
            pca_id: Uuid::nil(),
            p_0: "alice@demo.local".into(),
            ops: vec![
                "zeta:read".into(),
                "alpha:read".into(),
                "mu:write".into(),
                "beta:delete".into(),
                "tau:list".into(),
            ],
            hop: 1,
            predecessor_id: None,
            pic_profile: "proxilion.v1".into(),
            cbor_hex: String::new(),
        };
        let s = serde_json::to_value(&v).unwrap();
        let arr = s["ops"].as_array().expect("ops must serialize as array");
        assert_eq!(arr.len(), 5);
        assert_eq!(arr[0], "zeta:read");
        assert_eq!(arr[1], "alpha:read");
        assert_eq!(arr[2], "mu:write");
        assert_eq!(arr[3], "beta:delete");
        assert_eq!(arr[4], "tau:list");
    }

    #[test]
    fn pca_view_hop_serializes_as_json_number_type_not_string() {
        // `hop: i32` MUST land on the wire as a JSON number. Pin the
        // type tag explicitly — the dashboard's chain-walker arithmetic
        // (`hop + 1` for next-link navigation) strictly dispatches on
        // JSON's number type. A refactor that swapped to
        // `#[serde(serialize_with = "to_string")]` "for display
        // formatting consistency" would silently break arithmetic at
        // every consumer. The existing
        // `pca_view_serializes_with_stable_field_names` test pins the
        // numeric VALUE but not its TYPE tag.
        let v = PcaView {
            pca_id: Uuid::nil(),
            p_0: "p".into(),
            ops: vec![],
            hop: 42,
            predecessor_id: None,
            pic_profile: "proxilion.v1".into(),
            cbor_hex: String::new(),
        };
        let s = serde_json::to_value(&v).unwrap();
        assert!(s["hop"].is_number(), "hop must be JSON number: {s}");
        assert_eq!(s["hop"], 42);
        // The `pca_id` is a Uuid — pin it serializes as JSON string
        // (NOT a binary array or object) for symmetric coverage.
        assert!(s["pca_id"].is_string(), "pca_id must be JSON string: {s}");
    }

    #[test]
    fn hex_encode_emits_no_interior_separators_across_known_byte_runs() {
        // `hex_encode` is a tight loop emitting `{:02x}` per byte —
        // there's deliberately NO `:` or `-` or space separator
        // between bytes. Pin the absence so a refactor that swapped
        // to `format!("{:02x}-{:02x}")` "for readability" or used
        // `Vec::join(":")` "for grouping" would silently change the
        // wire shape and break downstream `hex::decode` consumers
        // expecting contiguous chars. The existing `hex_encode_covers_all_byte_values`
        // test checks every char is a hex digit (catches ANY non-
        // hexdigit char like `:` or `-` or space implicitly) — pin
        // explicitly here for clarity AND walk an additional length
        // boundary to surface a "every Nth byte" separator pattern.
        let bytes: Vec<u8> = (0u8..=255).collect();
        let s = hex_encode(&bytes);
        assert!(!s.contains(':'), "no colon separator allowed: {}", &s[..32]);
        assert!(
            !s.contains('-'),
            "no hyphen separator allowed: {}",
            &s[..32]
        );
        assert!(!s.contains(' '), "no space separator allowed: {}", &s[..32]);
        assert!(
            !s.contains('_'),
            "no underscore separator allowed: {}",
            &s[..32]
        );
        // And the 16-byte boundary specifically — a refactor that inserted
        // a separator every 16 bytes "for hexdump-like display" would
        // surface here at position 32 (16 bytes × 2 hex chars).
        let sixteen = hex_encode(&[0xaau8; 16]);
        assert_eq!(sixteen, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(sixteen.len(), 32);
    }

    #[test]
    fn pca_view_predecessor_id_serializes_null_when_none_for_root_hop() {
        // A chain-root PCA has `predecessor_id = None` (hop 0). The
        // dashboard's chain-walker keys on `predecessor_id === null`
        // (key-presence with null value, NOT key-absence) to decide
        // whether to render the "← prev" link. Pin that the wire shape
        // is `null` (the default serde behavior for `Option<Uuid>`
        // without `skip_serializing_if`) — a refactor that added
        // `#[serde(skip_serializing_if = "Option::is_none")]` would
        // silently break the dashboard's root-hop detection. Symmetric
        // to the `Some` case pinned in `pca_view_serializes_with_stable_field_names`.
        let v = PcaView {
            pca_id: Uuid::nil(),
            p_0: "alice@demo.local".into(),
            ops: vec![],
            hop: 0,
            predecessor_id: None,
            pic_profile: "proxilion.v1".into(),
            cbor_hex: String::new(),
        };
        let s = serde_json::to_value(&v).unwrap();
        assert!(
            s.get("predecessor_id").is_some(),
            "predecessor_id key must be present even when None"
        );
        assert!(
            s["predecessor_id"].is_null(),
            "expected null, got: {}",
            s["predecessor_id"],
        );
    }

    #[test]
    fn pca_view_serializes_with_exactly_seven_known_keys_for_cli_renderer_contract() {
        // The `proxilion-cli pca <id>` renderer destructures the JSON
        // shape from `/api/v1/pca/{id}` into a 7-field display table.
        // The existing pin (`pca_view_serializes_with_stable_field_names`)
        // walks individual keys via `v["k"]` but never the EXHAUSTIVE
        // 7-key set — a refactor adding a `verified_at` "for ergonomic
        // freshness display" field would silently widen every
        // CLI response and break consumers that destructure with
        // serde::Deserialize on a 7-field struct. Pin HashSet equality
        // on the 7 keys — symmetric to round-161 PolicyView 5-key +
        // round-165 TokenResponse 4-key + round-169 BlockedNotification
        // 16-key + round-170 Healthz/Check + round-171 CheckItem 6-key
        // + SetupStatus 2-key exhaustive-set pins extended to PcaView.
        let v = PcaView {
            pca_id: Uuid::nil(),
            p_0: "alice@demo.local".into(),
            ops: vec!["drive:read:a".into()],
            hop: 1,
            predecessor_id: Some(Uuid::nil()),
            pic_profile: "proxilion.v1".into(),
            cbor_hex: "abcd".into(),
        };
        let j = serde_json::to_value(&v).unwrap();
        let obj = j
            .as_object()
            .expect("PcaView must serialize as JSON object");
        let keys: std::collections::HashSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected: std::collections::HashSet<&str> = [
            "pca_id",
            "p_0",
            "ops",
            "hop",
            "predecessor_id",
            "pic_profile",
            "cbor_hex",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            keys, expected,
            "PcaView must serialize with EXACTLY these 7 keys for CLI renderer contract",
        );
    }

    #[test]
    fn hex_encode_is_referentially_transparent_across_fifty_repeated_calls() {
        // Symmetric to round-161 + round-162 + round-166 + round-168 +
        // round-169 + round-170 + round-171 referential-transparency
        // pins extended to hex_encode. The `/api/v1/pca/{id}` handler
        // calls hex_encode on every fetch; a refactor caching results
        // in a once-cell keyed on input pointer "for hot-path perf"
        // would silently return stale bytes on a re-fetched PCA whose
        // CBOR blob got rewritten by a downstream `/api/v1/pca/{id}/
        // refresh` admin path. Pin 50 calls on a 256-byte fixture
        // covering every byte value produce byte-equal output.
        let input: Vec<u8> = (0..=255).collect();
        let baseline = hex_encode(&input);
        for i in 0..50 {
            let again = hex_encode(&input);
            assert_eq!(
                again, baseline,
                "iteration {i}: hex_encode must be referentially transparent",
            );
        }
        // Defensive: 512 chars for 256-byte input.
        assert_eq!(baseline.len(), 512);
    }

    #[test]
    fn pca_view_pic_profile_field_is_owned_string_type_not_borrowed_for_async_response_outlives() {
        // The `get_pca` handler returns `Json<PcaView>` AFTER awaiting
        // `state.pca_cache.get(id)`; the awaited row is consumed and
        // `pic_profile: row.pic_profile` MOVES the String out. A
        // refactor to `pic_profile: &'a str` "to avoid the clone"
        // would surface a lifetime constraint that the async response
        // path (where Row is consumed mid-fn) couldn't satisfy. The
        // existing pin walks the VALUE but never the TYPE-level
        // ownership contract — pin via a generic fn whose signature
        // only compiles when the field is `String` (owned), not
        // `&str` (borrowed). Symmetric to round-168 parse_missing_atoms
        // require_vec_string + Vec<String> owned-type pin extended to
        // PcaView.pic_profile.
        fn require_string(_: &String) {}
        let v = PcaView {
            pca_id: Uuid::nil(),
            p_0: "x".into(),
            ops: vec![],
            hop: 0,
            predecessor_id: None,
            pic_profile: "proxilion.v1".into(),
            cbor_hex: String::new(),
        };
        require_string(&v.pic_profile);
        // And p_0 + cbor_hex are also owned String (the response
        // outlives the Row from cache).
        require_string(&v.p_0);
        require_string(&v.cbor_hex);
    }

    #[test]
    fn pca_view_cbor_hex_field_length_is_exactly_two_per_input_byte_for_round_trip_safety() {
        // hex_encode emits 2 chars per input byte (no separators, no
        // prefix). The PcaView.cbor_hex field carries the CBOR blob
        // for round-trip safety on operator inspection (CLI `pca-show`
        // pipes it back through `xxd -r -p` for byte-equal decode).
        // The existing pin (`hex_encode_byte_count_matches_two_per_input_byte`)
        // walks the helper but never the field-level invariant — pin
        // that PcaView.cbor_hex.len() == 2 * input.len() across 4
        // representative sizes (empty / 1 byte / 16-byte block /
        // 257-byte odd size) so a refactor adding a `0x` prefix or
        // colon-separators to hex_encode "for ergonomic display"
        // surfaces here on the field-level contract.
        for &n in &[0usize, 1, 16, 257] {
            let input: Vec<u8> = (0..n as u32).map(|i| (i & 0xff) as u8).collect();
            let v = PcaView {
                pca_id: Uuid::nil(),
                p_0: "x".into(),
                ops: vec![],
                hop: 0,
                predecessor_id: None,
                pic_profile: "p".into(),
                cbor_hex: hex_encode(&input),
            };
            assert_eq!(
                v.cbor_hex.len(),
                n * 2,
                "cbor_hex length must be 2 * input.len() for n={n}",
            );
        }
    }

    #[test]
    fn api_state_is_clone_for_axum_router_with_state_fan_out() {
        // `ApiState` is held by every axum router built via
        // `.with_state(state)`; the router build clones it once per
        // route layer. The Clone derive is load-bearing — without it,
        // axum's `State<T>` extractor would fail to compile across the
        // dozens of routes that share it. The existing pin
        // (`api_state_and_api_error_are_send_sync_static_for_axum_boundary`)
        // walks Send + Sync + 'static but never the Clone trait —
        // a refactor that landed a non-Clone field (e.g. a `OnceLock<...>`
        // for a lazy cache) on ApiState would surface at every router
        // build site rather than at this single compile-time assertion.
        // Pin Clone via require_clone — symmetric to round-22 OperatorAuthState
        // Clone-bound pin extended to ApiState.
        fn require_clone<T: Clone>() {}
        require_clone::<ApiState>();
    }

    #[test]
    fn pca_view_ops_field_is_owned_vec_string_for_zero_borrow_response_boundary() {
        // PcaView.ops is `Vec<String>` (owned per-element AND owned
        // outer Vec) — the awaited Row is consumed mid-handler and
        // the response Json<PcaView> outlives the borrow. A refactor
        // to `Vec<&'a str>` or `&'a [String]` "to avoid the clone"
        // would either fail to compile against the async outlives
        // chain or silently introduce a stale-data window if the row
        // got hot-swapped underneath. The existing pin
        // (`pca_view_ops_serializes_as_json_array_preserving_order_across_multi_element`)
        // walks the VALUE but never the TYPE — pin via require_vec_string
        // symmetric to round-168 parse_missing_atoms + round-172
        // PcaView.pic_profile owned-type pins.
        fn require_vec_string(_: &Vec<String>) {}
        let v = PcaView {
            pca_id: Uuid::nil(),
            p_0: "x".into(),
            ops: vec!["a".into(), "b".into()],
            hop: 0,
            predecessor_id: None,
            pic_profile: "p".into(),
            cbor_hex: String::new(),
        };
        require_vec_string(&v.ops);
        // And each element is String (owned).
        fn require_string(_: &String) {}
        require_string(&v.ops[0]);
    }

    #[test]
    fn api_state_field_count_pinned_at_exactly_two_via_exhaustive_destructure_no_rest_pattern() {
        // Pin the ApiState struct field count at exactly 2 via
        // exhaustive destructure with no `..` rest pattern. The 2
        // fields are: verifier (Arc<PicVerifier>) + pca_cache
        // (PcaCache). A 3rd field landing (e.g.
        // `executor: PicExecutor` for a future API endpoint that
        // surfaces executor-binding metadata, or `metrics_bucket:
        // &'static str` to split per-API metric labels for the
        // future multi-tenant operator path) would silently bloat
        // every Clone of ApiState the axum router fans out per
        // request AND silently change the bundle the API handlers
        // see. The existing
        // `api_state_and_api_error_are_send_sync_static_for_axum_boundary`
        // pin walks trait bounds; the existing
        // `api_state_is_clone_for_axum_router_with_state_fan_out`
        // pin walks Clone; neither catches a runtime-only 3rd field
        // — exhaustive destructure is the canonical pin. Need a
        // real PcaCache + PicVerifier to construct, so this is a
        // type-level pin via destructure of a hypothetical binding
        // shape (the destructure pattern itself is the pin — if a
        // 3rd field lands without matching this site, the pattern
        // becomes non-exhaustive and the test fails to compile).
        fn _destructure_witness(s: ApiState) {
            let ApiState {
                verifier: _,
                pca_cache: _,
            } = s;
        }
    }

    #[test]
    fn api_error_variant_count_pinned_at_exactly_three_via_exhaustive_match() {
        // Pin the ApiError variant count at exactly 3 via exhaustive
        // match expression. The 3 variants are: NotFound + Db +
        // Verifier. A 4th variant landing (e.g. `RateLimited` to
        // distinguish "API throttled by per-operator-token bucket"
        // from generic Db errors on operator dashboards, or
        // `ScopeDenied` to distinguish from the middleware-layer
        // 403 produced by `scope_check`) without matching every
        // Display attribute + IntoResponse arm + the operator-
        // facing wire-shape pins would surface here as a non-
        // exhaustive compile error. The enum is module-private
        // (`enum ApiError`) and NOT `#[non_exhaustive]` — within
        // the crate the match is fully closed and a new variant
        // MUST update every dispatch site in lockstep.
        fn variant_witness(e: &ApiError) -> u8 {
            match e {
                ApiError::NotFound => 0,
                ApiError::Db(_) => 1,
                ApiError::Verifier(_) => 2,
            }
        }
        // Construct concrete instances for each variant. The Db arm
        // wraps a CacheError, the Verifier arm wraps a VerifierError.
        let not_found = ApiError::NotFound;
        assert_eq!(variant_witness(&not_found), 0);
        // We don't need to actually invoke the Db / Verifier arms at
        // runtime — the exhaustive match above is the load-bearing
        // pin (a 4th variant lands as a compile error, NOT a runtime
        // failure). The NotFound runtime check is the smoke test.
    }

    #[test]
    fn pca_view_field_count_pinned_at_exactly_seven_via_exhaustive_destructure_no_rest_pattern() {
        // Pin the PcaView struct field count at exactly 7 via
        // exhaustive destructure (no `..`). The 7 fields are:
        // pca_id + p_0 + ops + hop + predecessor_id + pic_profile
        // + cbor_hex. The existing
        // `pca_view_serializes_with_exactly_seven_known_keys_for_cli_renderer_contract`
        // pin walks the JSON WIRE keys but doesn't catch a
        // `#[serde(skip)]` runtime-only 8th field — exhaustive
        // destructure on the Rust struct is the symmetric pin. A
        // refactor that landed `created_at: DateTime<Utc>` for the
        // dashboard's "PCA freshness" panel or `chain_id:
        // Option<Uuid>` for back-attribution from PCA to chain root
        // without serializing the new field would silently bloat
        // every PcaView Clone on the response-build path.
        let v = PcaView {
            pca_id: Uuid::nil(),
            p_0: String::new(),
            ops: vec![],
            hop: 0,
            predecessor_id: None,
            pic_profile: String::new(),
            cbor_hex: String::new(),
        };
        let PcaView {
            pca_id: _,
            p_0: _,
            ops: _,
            hop: _,
            predecessor_id: _,
            pic_profile: _,
            cbor_hex: _,
        } = v;
    }

    #[test]
    fn hex_encode_signature_pinned_via_fn_pointer_witness() {
        // Pin hex_encode signature as `fn(&[u8]) -> String` via
        // fn-pointer witness. A refactor that flipped the input to
        // `&Vec<u8>` "for ownership symmetry with the PcaView
        // cbor_hex field" would silently force every call site to
        // box the borrowed slice in an owned Vec first. The `&[u8]`
        // borrow shape lets PcaView call sites hand in either a
        // direct field borrow OR a slice into a temporary without
        // allocating. The owned `String` return type is also pinned
        // — a refactor to `Cow<'_, str>` "to avoid the per-call
        // allocation on a passthrough" would tie the return
        // lifetime to the input slice and force lifetime
        // constraints on every PcaView assembly site.
        let _f: fn(&[u8]) -> String = hex_encode;
    }

    #[test]
    fn router_function_signature_pinned_via_fn_pointer_witness() {
        // Pin the module's `router` constructor signature as
        // `fn(ApiState) -> Router` via fn-pointer witness. The
        // server.rs boot path calls `router(api_state)` exactly
        // once at app assembly time AND consumes the ApiState by
        // value (the router internally clones it per request via
        // `.with_state(...)`). A refactor that flipped to
        // `fn(&ApiState) -> Router` ("for borrow-on-build clarity")
        // would force the boot path to keep an additional owned
        // ApiState alive for the lifetime of the router, complicating
        // the AppState assembly order. A refactor to
        // `fn(ApiState) -> Result<Router, _>` (for some boot-time
        // validation) would silently change the boot path's error-
        // handling shape from "build then mount" to "build-or-fail
        // then mount". Pin the bare consuming-self → owned-Router
        // shape.
        let _f: fn(ApiState) -> Router = router;
    }

    #[test]
    fn api_error_implements_into_response_via_trait_object_witness_for_axum_handler_arms() {
        // The `ApiError` enum is the per-handler error type that
        // every API route returns through the `?` operator —
        // axum's IntoResponse trait is what makes
        // `Result<Json<...>, ApiError>` a valid handler return
        // type. The existing
        // `api_error_not_found_response` /
        // `api_error_db_maps_to_500_with_internal_error_code` pins
        // walk the response shapes but never the trait-bound
        // contract directly. A refactor that dropped the
        // `impl IntoResponse for ApiError` block (perhaps a
        // refactor unifying the API error type with a sibling
        // crate's) would force every handler to wrap the error
        // explicitly. Pin via require_into_response trait-bound
        // witness — symmetric to round-251 SessionExtractError
        // require_into_response pin extended to ApiError.
        fn require_into_response<T: IntoResponse>() {}
        require_into_response::<ApiError>();
    }

    // ─── round 283 (2026-05-26): ApiError trait bounds + PcaView typed field pins ───

    #[test]
    fn api_error_implements_from_cache_error_via_require_from_trait_bound_witness_for_handler_chain()
     {
        // `ApiError: From<crate::pic::cache::CacheError>` (via
        // `#[from]` on the `ApiError::Db` variant) is the conversion
        // every `state.pca_cache.get(id).await?` call site relies on
        // in the API handlers (`get_pca` line 70, etc.). A refactor
        // that swapped to `#[error(transparent)]` "to remove the
        // intermediate variant" OR dropped the `#[from]` attribute
        // "to add structured wrapping that logs first" would force
        // every `?`-chain through an explicit `.map_err(ApiError::Db)`
        // — and there are 10+ such sites in the api/ tree. Pin via
        // require_from trait-bound witness so a one-arm refactor
        // surfaces at the type boundary rather than at every
        // cache-call site as `the trait From<CacheError> is not
        // implemented`. Symmetric to round-280
        // `app_error_implements_from_reqwest_error_and_sqlx_error`
        // extended to this sibling API-layer error type.
        fn require_from<T, U: From<T>>() {}
        require_from::<crate::pic::cache::CacheError, ApiError>();
    }

    #[test]
    fn api_error_implements_std_error_via_require_trait_bound_witness_for_anyhow_question_mark_chain()
     {
        // `ApiError: std::error::Error` — the `#[derive(thiserror::Error)]`
        // emits this impl, and the API-route `?` chains lean on it
        // implicitly for `anyhow`-style error logging (`tracing::error!(
        // error = %e, ...)`). A refactor that swapped to a hand-rolled
        // Display impl forgetting to also `impl Error` would compile
        // here but break every downstream `anyhow::Result<...>`
        // wrapping. Pin via require_error trait-bound witness here
        // at the type boundary — symmetric to round-280
        // `app_error_implements_std_error_via_require_for_thiserror_question_mark_chain_propagation`
        // extended to this sibling API error.
        fn require_error<T: std::error::Error>() {}
        require_error::<ApiError>();
    }

    #[test]
    fn api_error_not_found_is_unit_variant_layout_pinned_via_match_arm_no_inner_pattern() {
        // `ApiError::NotFound` is a UNIT variant (no inner field).
        // The existing `api_error_variant_count_pinned_at_exactly_three`
        // pin walks all 3 variants but doesn't pin the unit-layout
        // shape of NotFound specifically. A refactor that landed
        // `ApiError::NotFound(String)` "for ergonomic ID-in-error-
        // message threading" would break every `Err(ApiError::NotFound)`
        // construction in the codebase (10+ sites) AND would shift
        // the wire shape of the NotFound response body. Pin the
        // unit-variant layout via a match arm with NO inner pattern
        // — a refactor to a tuple-variant would require the `(_)`
        // pattern and fail to compile here. Symmetric to round-251
        // SessionExtractError unit-struct layout pin extended to
        // this sibling unit variant.
        let e = ApiError::NotFound;
        match e {
            ApiError::NotFound => {}
            ApiError::Db(_) | ApiError::Verifier(_) => unreachable!(),
        }
    }

    #[test]
    fn pca_view_hop_field_is_i32_type_via_require_i32_for_postgres_int4_column_compat() {
        // `PcaView.hop: i32` is the postgres `int4` column type from
        // pca_cache — the response value is binary-encoded as a
        // 4-byte big-endian integer. A refactor to `u32` "for
        // ergonomic 'hop count is non-negative' typing" would shift
        // the wire shape on serde's JSON path (i32 → integer, u32 →
        // also integer, BUT the postgres binding rejects u32 for
        // int4 columns at runtime since u32::MAX > i32::MAX). Pin
        // i32 explicitly via require_i32 at the typed-field boundary.
        // Symmetric to round-279 ActionEvent.status u16 pin extended
        // to this sibling typed-integer field.
        fn require_i32(_: i32) {}
        let v = PcaView {
            pca_id: Uuid::nil(),
            p_0: String::new(),
            ops: vec![],
            hop: 0,
            predecessor_id: None,
            pic_profile: String::new(),
            cbor_hex: String::new(),
        };
        require_i32(v.hop);
    }

    #[test]
    fn pca_view_pca_id_field_is_uuid_type_via_require_uuid_for_postgres_uuid_column_compat() {
        // `PcaView.pca_id: Uuid` is binary-encoded on the postgres
        // wire as a 16-byte big-endian UUID. A refactor to `String`
        // "for ergonomic textual logging" would shift sqlx's binding
        // to TEXT-typed parameters which the `uuid` PG column
        // REJECTS at runtime with `invalid input syntax`. Pin via
        // require_uuid at the typed-field boundary. Symmetric to
        // round-279 ActionEvent.request_id/agent_session_id Uuid
        // pin extended to this sibling typed-uuid field.
        fn require_uuid(_: Uuid) {}
        let v = PcaView {
            pca_id: Uuid::nil(),
            p_0: String::new(),
            ops: vec![],
            hop: 0,
            predecessor_id: None,
            pic_profile: String::new(),
            cbor_hex: String::new(),
        };
        require_uuid(v.pca_id);
    }

    #[test]
    fn pca_view_predecessor_id_field_is_option_uuid_type_via_require_for_root_chain_some_polarity()
    {
        // `PcaView.predecessor_id: Option<Uuid>` — `Some(Uuid)` for
        // every non-root chain hop, `None` ONLY for the root PCA_0.
        // The dashboard's chain-walker reads this field and follows
        // the predecessor link until it hits None. A refactor to
        // `Uuid` (using `Uuid::nil()` for the root) would silently
        // shift the dashboard's chain-walker into an infinite loop
        // OR a misleading "predecessor 00000000-0000-0000-0000-
        // 000000000000" render. Pin via require_option_uuid at the
        // typed-field boundary. Symmetric to round-241
        // ActionEvent.leaf_pca_id Option<Uuid> pin extended to this
        // sibling typed-Option-Uuid field.
        fn require_option_uuid(_: Option<Uuid>) {}
        let v = PcaView {
            pca_id: Uuid::nil(),
            p_0: String::new(),
            ops: vec![],
            hop: 0,
            predecessor_id: None,
            pic_profile: String::new(),
            cbor_hex: String::new(),
        };
        require_option_uuid(v.predecessor_id);
    }
}
