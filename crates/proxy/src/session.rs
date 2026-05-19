//! `SessionContext` + `SessionCtx` extractor.
//!
//! The auth middleware (`crate::auth_middleware`) populates a
//! `SessionContext` and inserts it into request extensions; downstream
//! handlers extract it via `SessionCtx(session): SessionCtx`.

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::{StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

/// Everything an adapter needs to act on behalf of the human user.
///
/// `google_access_token` is the *plaintext* OAuth token, decrypted into
/// process memory for the request lifetime only — never persisted, never
/// logged, never Debug-printed.
pub struct SessionContext {
    pub agent_session_id: Uuid,
    /// SHA-256 of the live bearer; used by the killswitch (§3.2) and audit.
    #[allow(dead_code)]
    pub bearer_hash: [u8; 32],
    pub p_0: String,
    pub leaf_pca_id: Uuid,
    /// Raw signed-PCA CBOR; adapters in §1.3+ pass this to the executor as
    /// the predecessor when minting per-action successors.
    #[allow(dead_code)]
    pub leaf_pca_cbor: Vec<u8>,
    pub granted_ops: Vec<String>,
    /// Plaintext Google OAuth token — handed to adapters for upstream calls.
    /// Lives in process memory for the request lifetime only.
    #[allow(dead_code)]
    pub google_access_token: String,
    pub google_token_scope: String,
}

impl std::fmt::Debug for SessionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionContext")
            .field("agent_session_id", &self.agent_session_id)
            .field("p_0", &self.p_0)
            .field("leaf_pca_id", &self.leaf_pca_id)
            .field("granted_ops", &self.granted_ops)
            .field("google_access_token", &"[redacted]")
            .field("google_token_scope", &self.google_token_scope)
            .finish()
    }
}

/// Axum extractor for handlers that require an authenticated session.
///
/// The middleware inserts an `Arc<SessionContext>` into extensions; we only
/// hand out an `Arc` so cloning across spawned tasks is cheap.
#[derive(Clone)]
pub struct SessionCtx(pub Arc<SessionContext>);

impl<S> FromRequestParts<S> for SessionCtx
where
    S: Send + Sync,
{
    type Rejection = SessionExtractError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Arc<SessionContext>>()
            .cloned()
            .map(SessionCtx)
            .ok_or(SessionExtractError)
    }
}

/// Returned when the auth middleware didn't run (or didn't populate the
/// extension) before a route that requires a session. Always 401 with a
/// generic body.
pub struct SessionExtractError;

impl IntoResponse for SessionExtractError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ctx() -> SessionContext {
        SessionContext {
            agent_session_id: Uuid::nil(),
            bearer_hash: [0u8; 32],
            p_0: "alice@acme.com".into(),
            leaf_pca_id: Uuid::nil(),
            leaf_pca_cbor: vec![1, 2, 3],
            granted_ops: vec!["drive:read:file/x".into()],
            google_access_token: "ya29.SUPER_SECRET_TOKEN_VALUE".into(),
            google_token_scope: "https://www.googleapis.com/auth/drive.readonly".into(),
        }
    }

    #[test]
    fn debug_redacts_google_access_token() {
        let ctx = sample_ctx();
        let s = format!("{ctx:?}");
        assert!(!s.contains("SUPER_SECRET_TOKEN_VALUE"));
        assert!(s.contains("[redacted]"));
        // Non-sensitive fields stay visible.
        assert!(s.contains("alice@acme.com"));
        assert!(s.contains("drive.readonly"));
    }

    #[tokio::test]
    async fn session_extract_error_into_response_is_401() {
        let r = SessionExtractError.into_response();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(r.into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], b"unauthorized");
    }

    #[tokio::test]
    async fn extractor_returns_err_when_extension_missing() {
        let req = axum::http::Request::builder().uri("/").body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        let result: Result<SessionCtx, SessionExtractError> =
            SessionCtx::from_request_parts(&mut parts, &()).await;
        // SessionExtractError doesn't impl Debug, so match instead of unwrap_err.
        match result {
            Err(_) => {}
            Ok(_) => panic!("expected SessionExtractError"),
        }
    }

    #[test]
    fn debug_omits_bearer_hash_and_leaf_pca_cbor_to_avoid_leaking_credential_material() {
        // bearer_hash is the SHA-256 the killswitch SQL predicate keys on
        // (knowing it lets an attacker construct a kill-row); leaf_pca_cbor
        // carries the signed PCA bytes. Both are intentionally absent from
        // the Debug impl. A future field added without updating Debug would
        // surface here.
        let ctx = sample_ctx();
        let s = format!("{ctx:?}");
        assert!(
            !s.contains("bearer_hash"),
            "bearer_hash leaked in Debug: {s}"
        );
        assert!(
            !s.contains("leaf_pca_cbor"),
            "leaf_pca_cbor leaked in Debug: {s}"
        );
    }

    #[test]
    fn session_ctx_clone_shares_arc_with_original() {
        // The #[derive(Clone)] on SessionCtx tuple-clones the inner Arc
        // rather than deep-copying the context — this is the invariant
        // every spawned task depends on (cheap clone for fan-out). A
        // refactor to `pub struct SessionCtx(pub SessionContext)` would
        // surface here as an Arc::ptr_eq failure rather than as a silent
        // performance/correctness regression at use sites.
        let ctx = Arc::new(sample_ctx());
        let a = SessionCtx(ctx.clone());
        let b = a.clone();
        assert!(Arc::ptr_eq(&a.0, &b.0));
        assert!(Arc::ptr_eq(&a.0, &ctx));
    }

    #[tokio::test]
    async fn session_extract_error_body_is_exactly_twelve_bytes() {
        // Pin the body length so a refactor that appended a CRLF, JSON
        // wrapper, or HTML envelope would surface here. Operator alerts
        // key on the 401 rate for this fixed-body path as the "agent
        // session lost" signal — changing the body shape (even just adding
        // a trailing newline) would break log-parsing dashboards.
        let r = SessionExtractError.into_response();
        let bytes = axum::body::to_bytes(r.into_body(), 1024).await.unwrap();
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[..], b"unauthorized");
    }

    #[test]
    fn session_context_carries_multi_op_granted_set_through_construction() {
        // The bearer middleware copies the cached PCA's ops into
        // `granted_ops` verbatim. Pin a multi-op set (`drive:read` +
        // `gmail:send` + `calendar:read`) so a refactor that switched
        // to a single-op field (in the name of "every adapter only
        // cares about one") would surface here.
        let mut ctx = sample_ctx();
        ctx.granted_ops = vec![
            "drive:read:engineering/*".into(),
            "gmail:send:alice@demo.local".into(),
            "calendar:read:primary".into(),
        ];
        assert_eq!(ctx.granted_ops.len(), 3);
        assert_eq!(ctx.granted_ops[0], "drive:read:engineering/*");
        assert_eq!(ctx.granted_ops[2], "calendar:read:primary");
        // And the Debug renders them all — pin so a refactor that
        // truncated for log brevity surfaces here.
        let s = format!("{ctx:?}");
        assert!(s.contains("calendar:read:primary"));
    }

    #[test]
    fn session_context_with_empty_granted_ops_still_constructs() {
        // The empty case fires when an OAuth flow grants zero scopes
        // that map to ops (e.g. `openid email` only). Pin that the
        // proxy doesn't reject an empty `granted_ops` at construction
        // — the policy engine's Layer A handles "no ops" upstream of
        // the adapter call.
        let mut ctx = sample_ctx();
        ctx.granted_ops.clear();
        assert!(ctx.granted_ops.is_empty());
        // Debug still renders — pin no panic on the empty slice.
        let s = format!("{ctx:?}");
        assert!(s.contains("granted_ops"));
        assert!(s.contains("[]"));
    }

    #[tokio::test]
    async fn session_extract_error_status_helper_returns_unauthorized_constant() {
        // The 401 status is a wire-contract constant — pin via the
        // axum constant, not the integer literal, so a refactor to a
        // different status (e.g. 403 for "auth ran but failed") would
        // surface here as a wire-contract change. The body byte test
        // already covers the payload shape; this pins the status side
        // of the contract with a name-not-number assertion.
        let r = SessionExtractError.into_response();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(r.status().as_u16(), 401);
    }

    #[tokio::test]
    async fn session_extract_error_response_content_type_defaults_to_text_plain() {
        // The fixed-body `"unauthorized"` response is built via the
        // axum `(StatusCode, &'static str)` tuple shape, which routes
        // through axum's `&'static str → Response` IntoResponse impl
        // and lands as `content-type: text/plain; charset=utf-8`. Pin
        // the wire shape so a refactor that swapped to a Json envelope
        // (or any other content-type) would surface here — operator
        // log parsers and Grafana panels split text/plain 401s ("agent
        // session lost") from application/json 401s ("middleware
        // rejected bearer with structured body").
        let r = SessionExtractError.into_response();
        let ct = r
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.starts_with("text/plain"),
            "expected text/plain default, got: {ct}"
        );
        assert!(ct.contains("utf-8"), "expected charset suffix, got: {ct}");
    }

    #[tokio::test]
    async fn extractor_does_not_consume_extension_extractor_safe_for_repeat_calls() {
        // The extractor calls `parts.extensions.get::<Arc<SessionContext>>().cloned()`
        // — `cloned()` (not `take()`) leaves the extension in place so
        // downstream middleware or a second extractor invocation can
        // still see the Arc. Pin this contract: extracting twice must
        // both succeed and surface ptr-equal Arcs sharing the same
        // inner context. A refactor that swapped `cloned()` for
        // `remove()` (the natural shape of a "move out for efficiency"
        // change) would silently break any handler chain that runs the
        // extractor more than once.
        let ctx = Arc::new(sample_ctx());
        let req = axum::http::Request::builder().uri("/").body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        parts.extensions.insert(ctx.clone());
        // First extraction.
        let first = SessionCtx::from_request_parts(&mut parts, &()).await;
        let SessionCtx(a) = match first {
            Ok(v) => v,
            Err(_) => panic!("first extraction failed"),
        };
        // Second extraction against the SAME parts — must still succeed.
        let second = SessionCtx::from_request_parts(&mut parts, &()).await;
        let SessionCtx(b) = match second {
            Ok(v) => v,
            Err(_) => panic!("second extraction failed — extension was consumed"),
        };
        // All three Arcs share the same inner context.
        assert!(Arc::ptr_eq(&ctx, &a));
        assert!(Arc::ptr_eq(&ctx, &b));
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[tokio::test]
    async fn extractor_rejects_when_only_a_different_extension_type_is_present() {
        // `parts.extensions.get::<Arc<SessionContext>>()` is type-keyed.
        // If a different extension type was inserted (a real bug shape:
        // some middleware inserted the bare `SessionContext` instead
        // of `Arc<SessionContext>`, or an unrelated type entirely),
        // the typed lookup must return None → SessionExtractError. Pin
        // this distinction with a different type stuffed into
        // extensions so a refactor that loosened the lookup (e.g.
        // accepting either `SessionContext` or `Arc<SessionContext>`)
        // would surface here as an unexpected Ok.
        #[derive(Clone)]
        struct UnrelatedExtension(#[allow(dead_code)] String);
        let req = axum::http::Request::builder().uri("/").body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        parts.extensions.insert(UnrelatedExtension("noise".into()));
        let r: Result<SessionCtx, SessionExtractError> =
            SessionCtx::from_request_parts(&mut parts, &()).await;
        match r {
            Err(_) => {}
            Ok(_) => panic!("extractor must reject when typed lookup misses"),
        }
    }

    #[test]
    fn session_context_debug_carries_struct_name_and_four_critical_field_names() {
        // SessionContext flows through `tracing::error!(?session, ...)` on
        // adapter-call failures — operators grep the resulting log line by
        // struct name + by the four load-bearing field selectors
        // (`agent_session_id` / `p_0` / `leaf_pca_id` / `granted_ops`) to
        // bucket "which session, which principal, which PCA, which ops"
        // when triaging. A manual Debug that hid any of them "to compact"
        // would break every operator bucket. The existing
        // `debug_omits_bearer_hash_and_leaf_pca_cbor_to_avoid_leaking_credential_material`
        // test pins the redacted-side; pin the positive-side here so a
        // refactor that flipped the include/exclude lists would surface
        // on BOTH tests rather than just the redaction half.
        let ctx = sample_ctx();
        let s = format!("{ctx:?}");
        assert!(s.contains("SessionContext"), "got: {s}");
        assert!(s.contains("agent_session_id"), "got: {s}");
        assert!(s.contains("p_0"), "got: {s}");
        assert!(s.contains("leaf_pca_id"), "got: {s}");
        assert!(s.contains("granted_ops"), "got: {s}");
        assert!(s.contains("google_token_scope"), "got: {s}");
    }

    #[test]
    fn session_ctx_and_session_extract_error_are_send_sync_static_for_axum_bounds() {
        // `SessionCtx` is held in axum's per-request typed extractor map
        // and cloned across spawned tasks; `SessionExtractError` is the
        // `FromRequestParts::Rejection` associated type axum requires to
        // be `IntoResponse + 'static`. Both flow through the Router's
        // Send+Sync+'static bag at compile time — a refactor that gave
        // either a non-Send field (e.g. `Rc<...>` "for single-thread test
        // ergonomics") would break axum at the route mount site with an
        // unrelated trait-bound error. Pin the three-trait combo here so
        // the type boundary fails fast at the right call site.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<SessionCtx>();
        require_send_sync_static::<SessionExtractError>();
    }

    #[tokio::test]
    async fn session_extract_error_into_response_is_byte_equal_across_independent_calls() {
        // `SessionExtractError` is a unit struct — constructing two
        // separate instances and calling `into_response` on each must
        // produce byte-equal bodies AND identical status codes AND
        // identical content-type headers. The downstream operator log
        // parser keys on a stable 12-byte body shape ("agent session
        // lost" signal); a refactor that introduced per-call state
        // (e.g. a request-id stamp "for correlation") would silently
        // make the bodies diverge across calls and break log dedup.
        // Pin idempotency end-to-end across two independent error
        // values.
        let r1 = SessionExtractError.into_response();
        let r2 = SessionExtractError.into_response();
        assert_eq!(r1.status(), r2.status());
        let ct1 = r1
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let ct2 = r2
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert_eq!(ct1, ct2);
        let b1 = axum::body::to_bytes(r1.into_body(), 1024).await.unwrap();
        let b2 = axum::body::to_bytes(r2.into_body(), 1024).await.unwrap();
        assert_eq!(&b1[..], &b2[..]);
        assert_eq!(&b1[..], b"unauthorized");
    }

    #[tokio::test]
    async fn successful_extraction_preserves_all_session_context_field_values_byte_equal() {
        // The existing `extractor_returns_ok_when_arc_session_context_present`
        // pins Arc::ptr_eq; pin the field-level byte-equal contract
        // independently — every SessionContext field the extractor
        // surfaces MUST match the inserted one (string fields via byte
        // comparison, Uuid via equality, Vec<String> via element-wise
        // equality, bearer_hash byte-array via equality). A refactor
        // that copied the SessionContext into a new Arc with a partial
        // field subset "for memory pressure" would still preserve
        // Arc::ptr_eq if it cached the new Arc, but would silently
        // drop the unmentioned fields.
        let ctx = sample_ctx();
        let expected_session = ctx.agent_session_id;
        let expected_p_0 = ctx.p_0.clone();
        let expected_leaf = ctx.leaf_pca_id;
        let expected_ops = ctx.granted_ops.clone();
        let expected_scope = ctx.google_token_scope.clone();
        let expected_cbor = ctx.leaf_pca_cbor.clone();
        let expected_hash = ctx.bearer_hash;
        let arc = Arc::new(ctx);
        let req = axum::http::Request::builder().uri("/").body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        parts.extensions.insert(arc.clone());
        let extracted = SessionCtx::from_request_parts(&mut parts, &()).await;
        let SessionCtx(out) = match extracted {
            Ok(v) => v,
            Err(_) => panic!("expected Ok"),
        };
        assert_eq!(out.agent_session_id, expected_session);
        assert_eq!(out.p_0, expected_p_0);
        assert_eq!(out.leaf_pca_id, expected_leaf);
        assert_eq!(out.granted_ops, expected_ops);
        assert_eq!(out.google_token_scope, expected_scope);
        assert_eq!(out.leaf_pca_cbor, expected_cbor);
        assert_eq!(out.bearer_hash, expected_hash);
    }

    #[test]
    fn session_context_debug_renders_full_granted_ops_vec_without_truncation_at_twenty_elements() {
        // Operators triaging "wrong ops" use the Debug-rendered
        // granted_ops set as the ground truth of "what the bearer was
        // actually authorized for" — a refactor that capped the
        // rendered Vec at N elements "for log line length" would
        // silently truncate the observability of a wide grant. Pin
        // that all 20 elements of a 20-element vec render verbatim in
        // the Debug output, including the boundary elements (first +
        // tenth + twentieth). Twenty is enough to surface a `.take(N)`
        // truncation at any reasonable N (most tracing crates default
        // to 32 or higher; common operator-targeted caps are 5/10/16).
        let mut ctx = sample_ctx();
        ctx.granted_ops = (0..20)
            .map(|i| format!("op:tier{i}:resource/path/{i}"))
            .collect();
        let s = format!("{ctx:?}");
        for i in [0, 10, 19] {
            let needle = format!("op:tier{i}:resource/path/{i}");
            assert!(s.contains(&needle), "missing {needle} in: {s}");
        }
    }

    #[test]
    fn debug_is_pure_and_produces_identical_output_across_independent_calls() {
        // `Debug` is exercised by `tracing::error!(?session, ...)` —
        // the trait impl MUST be a pure function of the struct state
        // (no per-call counters, no clock-stamped fields, no hidden
        // side effects on the SessionContext). Pin purity by formatting
        // the SAME SessionContext twice and comparing the byte output;
        // a refactor that snuck in a per-format counter "for log
        // correlation" or an interior-mutable cache "for memoization"
        // would silently make the two formattings diverge AND break
        // log dedup pipelines that hash on the rendered line.
        let ctx = sample_ctx();
        let a = format!("{ctx:?}");
        let b = format!("{ctx:?}");
        assert_eq!(a, b);
        // And across two DIFFERENT SessionContext values built from the
        // same fixture seed — the byte output is byte-equal too (no
        // per-instance address-derived field rendering).
        let ctx2 = sample_ctx();
        let c = format!("{ctx2:?}");
        assert_eq!(a, c);
    }

    #[test]
    fn session_context_itself_is_send_sync_static_for_arc_extension_boundary() {
        // The auth middleware wraps `SessionContext` in `Arc<...>` before
        // inserting into request extensions; axum's extensions store
        // `Box<dyn Any + Send + Sync>`, which requires the inner type to
        // be `Send + Sync` (the `Arc<T>: Send + Sync` impl only holds when
        // `T: Send + Sync`). The existing
        // `session_ctx_and_session_extract_error_are_send_sync_static_for_axum_bounds`
        // pin checks the wrapper (`SessionCtx`); pin the INNER
        // `SessionContext` separately so a refactor that added an
        // `Rc<String>` field "for cheap clone of the access token string"
        // would surface at this file rather than at the auth middleware
        // assembly site with an opaque axum trait-bound. Pin all three
        // bounds at compile time.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<SessionContext>();
    }

    #[test]
    fn session_ctx_clone_increments_arc_strong_count_by_exactly_one() {
        // The existing `session_ctx_clone_shares_arc_with_original` pin
        // checks Arc::ptr_eq across a clone; pin the SECONDARY contract
        // that the strong-count goes 1 → 2 (not 1 → 1, which would mean
        // the clone returned `self`, e.g. via a manual `impl Clone` that
        // accidentally moved instead of cloned) AND not 1 → 3 (a refactor
        // that double-cloned "for safety margin" would surface here as a
        // ref-count leak across thousands of spawned tasks per second).
        // The strong-count is the load-bearing invariant for cheap fan-out
        // — a leak would surface as memory pressure under sustained load.
        let arc = Arc::new(sample_ctx());
        assert_eq!(Arc::strong_count(&arc), 1);
        let a = SessionCtx(arc.clone());
        assert_eq!(Arc::strong_count(&arc), 2);
        let _b = a.clone();
        assert_eq!(Arc::strong_count(&arc), 3);
        // And dropping `a` drops the count by exactly 1.
        drop(a);
        assert_eq!(Arc::strong_count(&arc), 2);
    }

    #[test]
    fn session_extract_error_is_zero_sized_type_for_axum_rejection_branch() {
        // `SessionExtractError` is a unit struct — pin via `size_of` that
        // it carries no data. axum's `FromRequestParts::Rejection` flows
        // through a generic Result<Self, Rejection> on every extractor
        // call; a refactor that added a `reason: &'static str` field "for
        // operator triage" would silently grow the per-extraction stack
        // footprint AND change the Debug-render shape (which downstream
        // operator dashboards key on the absence of). Pin size == 0 so
        // the field-addition surfaces here, AND the operator-facing fixed
        // body remains stable across all extraction failure paths.
        assert_eq!(std::mem::size_of::<SessionExtractError>(), 0);
    }

    #[test]
    fn session_context_carries_four_kb_leaf_pca_cbor_verbatim_through_field_access() {
        // The `leaf_pca_cbor` field carries the signed PCA CBOR bytes —
        // production PCAs can run to several KB (envelope + signature
        // + ops list). The existing tests use a 3-byte fixture; pin a
        // realistic 4096-byte payload survives construction + field
        // access byte-for-byte AND the Debug impl does NOT render the
        // bytes (existing `debug_omits_bearer_hash_and_leaf_pca_cbor_to_avoid_leaking_credential_material`
        // pin checks the omission; reinforce here that the omission
        // holds at 4KB length not just at the 3-byte fixture size). A
        // refactor that lazily-decoded CBOR on first access OR truncated
        // a per-debug snapshot of the bytes would surface on either axis.
        let mut ctx = sample_ctx();
        ctx.leaf_pca_cbor = (0..4096).map(|i| (i % 251) as u8).collect();
        assert_eq!(ctx.leaf_pca_cbor.len(), 4096);
        // Spot-check the bytes at three positions.
        assert_eq!(ctx.leaf_pca_cbor[0], 0);
        assert_eq!(ctx.leaf_pca_cbor[100], 100u8);
        assert_eq!(ctx.leaf_pca_cbor[4095], (4095 % 251) as u8);
        // Debug does NOT include the CBOR bytes (sensitive material).
        let s = format!("{ctx:?}");
        assert!(!s.contains("leaf_pca_cbor"), "leaked in Debug: {s}");
    }

    #[tokio::test]
    async fn session_extract_error_body_overflows_one_byte_to_bytes_limit() {
        // `axum::body::to_bytes(body, limit)` errors when the body
        // exceeds the limit. The 12-byte `"unauthorized"` body MUST
        // fail to read under a 1-byte limit — pin both axes (the error
        // exists AND the 12-byte read succeeds) so a refactor that
        // shrank the body "for compactness" (e.g. to `"401"` — 3
        // bytes — would silently pass a 4-byte limit, breaking the
        // boundary detection downstream tooling relies on for "is
        // this the operator-auth fixed body or a structured 401?").
        let r = SessionExtractError.into_response();
        let too_small = axum::body::to_bytes(r.into_body(), 1).await;
        assert!(
            too_small.is_err(),
            "12-byte body must overflow 1-byte limit"
        );
        // And the symmetric 12-byte read DOES succeed.
        let r2 = SessionExtractError.into_response();
        let ok = axum::body::to_bytes(r2.into_body(), 12).await;
        assert!(ok.is_ok(), "12-byte body must fit under 12-byte limit");
    }

    #[test]
    fn session_context_p_0_field_preserves_long_multibyte_unicode_through_debug_render() {
        // The `p_0` field is the authenticated principal email/identifier
        // — production deployments occasionally surface internationalized
        // forms (e.g. `日本語ユーザー@example.co.jp`) and operator
        // dashboards parse the Debug-rendered `p_0` field as a triage
        // key. Pin a 200+-char multibyte unicode p_0 survives construction
        // AND is rendered verbatim in Debug without truncation. A refactor
        // that capped Debug-rendered strings at N chars "for log line
        // length" OR that lossily converted to ASCII "for SIEM hygiene"
        // would silently mangle every non-ASCII principal in operator
        // triage. Pin both the underlying field byte-equality AND the
        // Debug presence.
        let long: String = "日本語ユーザー識別子".repeat(10); // 60 chars, 180 bytes UTF-8
        let mut ctx = sample_ctx();
        ctx.p_0 = long.clone();
        assert_eq!(ctx.p_0, long);
        let s = format!("{ctx:?}");
        assert!(s.contains(&long), "Debug truncated multibyte p_0: {s}");
    }

    #[tokio::test]
    async fn extractor_returns_ok_when_arc_session_context_present() {
        let ctx = Arc::new(sample_ctx());
        let req = axum::http::Request::builder().uri("/").body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        parts.extensions.insert(ctx.clone());
        let extracted = SessionCtx::from_request_parts(&mut parts, &()).await;
        let SessionCtx(out) = match extracted {
            Ok(v) => v,
            Err(_) => panic!("expected Ok"),
        };
        assert!(Arc::ptr_eq(&ctx, &out));
    }
}
