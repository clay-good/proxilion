//! Federation-bridge integration.
//!
//! Status: payload-only JWT decoding for M0/M1 (see spec.md §0.4 Status —
//! upstream `provenance-bridge` has no binary target and a real bridge
//! service isn't deployed). Before production, swap `validate_federation_token`
//! for a JWKS-backed signature check via `jsonwebtoken::decode`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde::Deserialize;
use uuid::Uuid;

use super::error::OAuthError;

/// Claims emitted by the (future) federation-bridge when it 302s the user
/// back to the proxy after PCA_0 issuance.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // `state` / `iat` round-trip for log correlation and clock-skew checks
pub struct FederationClaims {
    /// Trust Plane PCA id (UUID).
    pub pca_0_id: Uuid,
    /// Origin principal (subject of PCA_0).
    pub p_0: String,
    /// Granted ops for PCA_0 (Trust Plane's canonical string form).
    pub ops: Vec<String>,
    /// PCA_0 CBOR, base64-encoded — lets us cache without an extra
    /// round-trip to Trust Plane.
    #[serde(default)]
    pub pca_0_cbor_b64: Option<String>,
    /// Bridge-assigned correlation id (for log correlation).
    pub state: String,
    /// Issued-at epoch seconds.
    pub iat: i64,
    /// Expiration epoch seconds.
    pub exp: i64,
    /// Upstream IdP issuer URL (e.g. `https://acme.okta.com`). Carried
    /// from the IdP-emitted JWT through the federation bridge for
    /// observability — drives the `idp` label on
    /// `proxilion_oauth_callback_total` (spec.md §3.2). Optional today:
    /// the bridge stub may not surface it; production bridges always
    /// will. `None` → `idp="unknown"` on the callback metric.
    #[serde(default)]
    pub iss: Option<String>,
}

/// Coarsely classify an IdP issuer URL into the bounded label set the
/// spec.md §3.2 contract calls out (`okta|azure|google|oidc|unknown`).
/// Substring match is intentional — Okta's iss is `https://<tenant>.okta.com`,
/// Azure AD's is `https://login.microsoftonline.com/<tenant>/v2.0`, Google
/// Workspace's is `https://accounts.google.com`. Anything else falls through
/// to the generic `oidc` bucket (still useful — the customer can join the
/// label against `proxilion_oauth_callback_total{result}` to see if generic
/// OIDC IdPs are erroring at a different rate).
pub fn infer_idp(iss: Option<&str>) -> &'static str {
    let Some(s) = iss else { return "unknown" };
    let s = s.to_ascii_lowercase();
    if s.contains("okta.com") || s.contains("oktapreview.com") {
        "okta"
    } else if s.contains("microsoftonline.com") || s.contains("windows.net") {
        "azure"
    } else if s.contains("accounts.google.com") || s.contains("googleapis.com") {
        "google"
    } else if !s.is_empty() {
        "oidc"
    } else {
        "unknown"
    }
}

/// Decode a federation-bridge JWT.
///
/// **Payload-only** — does not verify the signature. Acceptable for dev /
/// CI / smoke; **not** acceptable for production. The signature step is
/// stubbed deliberately so the swap is one function.
pub fn validate_federation_token(jwt: &str) -> Result<FederationClaims, OAuthError> {
    let mut parts = jwt.split('.');
    let (_h, payload, _s) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) => (h, p, s),
        _ => return Err(OAuthError::BridgeRejected("malformed JWT".into())),
    };
    let bytes = B64URL
        .decode(payload)
        .map_err(|_| OAuthError::BridgeRejected("bad base64".into()))?;
    let claims: FederationClaims = serde_json::from_slice(&bytes)
        .map_err(|e| OAuthError::BridgeRejected(format!("bad claims: {e}")))?;

    let now = chrono::Utc::now().timestamp();
    if now > claims.exp {
        return Err(OAuthError::BridgeRejected(
            "federation token expired".into(),
        ));
    }
    if claims.iat > now + 60 {
        return Err(OAuthError::BridgeRejected(
            "federation token issued in the future".into(),
        ));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt(payload: &serde_json::Value) -> String {
        let header = B64URL.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let body = B64URL.encode(payload.to_string().as_bytes());
        format!("{header}.{body}.signature")
    }

    #[test]
    fn rejects_expired_token() {
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": ["drive:read:engineering/*"],
            "state": "abc",
            "iat": 0,
            "exp": 1,
        }));
        let err = validate_federation_token(&jwt).unwrap_err();
        assert!(matches!(err, OAuthError::BridgeRejected(_)));
    }

    #[test]
    fn infer_idp_classifies_known_issuers() {
        assert_eq!(infer_idp(Some("https://acme.okta.com")), "okta");
        assert_eq!(infer_idp(Some("https://example.oktapreview.com")), "okta");
        assert_eq!(
            infer_idp(Some("https://login.microsoftonline.com/abc/v2.0")),
            "azure"
        );
        assert_eq!(infer_idp(Some("https://accounts.google.com")), "google");
        assert_eq!(
            infer_idp(Some("https://id.example.org/realms/main")),
            "oidc"
        );
        assert_eq!(infer_idp(Some("")), "unknown");
        assert_eq!(infer_idp(None), "unknown");
    }

    #[test]
    fn rejects_malformed_jwt_missing_parts() {
        // No dots → split yields one token, second/third are None.
        let err = validate_federation_token("not-a-jwt").unwrap_err();
        match err {
            OAuthError::BridgeRejected(m) => assert!(m.contains("malformed")),
            other => panic!("expected BridgeRejected, got {other:?}"),
        }
        // Two parts only — same path.
        let err = validate_federation_token("header.payload").unwrap_err();
        assert!(matches!(err, OAuthError::BridgeRejected(_)));
    }

    #[test]
    fn rejects_bad_base64_in_payload() {
        // Header is valid base64, payload uses non-URL-safe `+/` and an
        // odd length so `URL_SAFE_NO_PAD` decode errors.
        let header = B64URL.encode(br#"{"alg":"none"}"#);
        let jwt = format!("{header}.@@@bad-base64@@@.sig");
        let err = validate_federation_token(&jwt).unwrap_err();
        match err {
            OAuthError::BridgeRejected(m) => assert!(m.contains("bad base64")),
            other => panic!("expected BridgeRejected, got {other:?}"),
        }
    }

    #[test]
    fn rejects_future_issued_token() {
        let now = chrono::Utc::now().timestamp();
        // iat is more than 60s in the future — clock-skew guard fires.
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": [],
            "state": "abc",
            "iat": now + 3600,
            "exp": now + 7200,
        }));
        let err = validate_federation_token(&jwt).unwrap_err();
        match err {
            OAuthError::BridgeRejected(m) => assert!(m.contains("future")),
            other => panic!("expected BridgeRejected, got {other:?}"),
        }
    }

    #[test]
    fn claims_iss_round_trips_through_payload() {
        // The `iss` field is `Option<String>` and `#[serde(default)]` — a
        // production federation bridge MUST round-trip it through so the
        // callback metric's `idp` label is correct. Bridge stubs may omit
        // it (default = None).
        let now = chrono::Utc::now().timestamp();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": [],
            "state": "s",
            "iat": now,
            "exp": now + 60,
            "iss": "https://login.microsoftonline.com/abc/v2.0",
        }));
        let claims = validate_federation_token(&jwt).unwrap();
        assert_eq!(infer_idp(claims.iss.as_deref()), "azure");
    }

    #[test]
    fn infer_idp_covers_secondary_substrings() {
        // Per the docstring on `infer_idp`, googleapis.com and windows.net
        // are alternate substrings that still classify as google / azure.
        // The primary-substring test covers okta.com / microsoftonline.com /
        // accounts.google.com — this fills the OR branch.
        assert_eq!(
            infer_idp(Some("https://oauth2.googleapis.com/token")),
            "google"
        );
        assert_eq!(infer_idp(Some("https://sts.windows.net/abc/v2.0")), "azure");
    }

    #[test]
    fn accepts_token_at_exact_60s_clock_skew_boundary() {
        // The clock-skew guard is `claims.iat > now + 60` — pin the
        // boundary inclusively. `iat == now + 60` must STILL accept
        // (the 60-second allowance is a permissive equality, not a
        // strict less-than). A refactor that flipped the comparison
        // to `>=` would silently shrink the allowance by one second
        // and surface as flaky federation flow tests under skewed
        // clocks. Symmetric pin at `now + 61` rejects.
        let now = chrono::Utc::now().timestamp();
        let jwt_ok = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": [],
            "state": "s",
            "iat": now + 60,
            "exp": now + 120,
        }));
        assert!(validate_federation_token(&jwt_ok).is_ok());
        let jwt_bad = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": [],
            "state": "s",
            "iat": now + 61,
            "exp": now + 120,
        }));
        assert!(matches!(
            validate_federation_token(&jwt_bad).unwrap_err(),
            OAuthError::BridgeRejected(_)
        ));
    }

    #[test]
    fn federation_claims_round_trip_pca_cbor_b64_optional() {
        // `pca_0_cbor_b64` is `Option<String>` with `#[serde(default)]`
        // — a production bridge that pre-fetches the PCA bytes from
        // Trust Plane MUST be able to round-trip them through the JWT
        // body so the proxy can cache without an extra round-trip.
        // Stub bridges omit it (None). Pin both shapes — the
        // `#[serde(default)]` is load-bearing because absent-field
        // would otherwise error the whole claims parse.
        let now = chrono::Utc::now().timestamp();
        let with = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": [],
            "state": "s",
            "iat": now,
            "exp": now + 60,
            "pca_0_cbor_b64": "AAECAwQF",
        }));
        let c = validate_federation_token(&with).unwrap();
        assert_eq!(c.pca_0_cbor_b64.as_deref(), Some("AAECAwQF"));

        let without = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": [],
            "state": "s",
            "iat": now,
            "exp": now + 60,
        }));
        let c = validate_federation_token(&without).unwrap();
        assert!(c.pca_0_cbor_b64.is_none());
    }

    #[test]
    fn federation_claims_clone_preserves_every_field() {
        // The router clones `FederationClaims` into the per-request
        // OAuthState before persisting `pca_0_id` to the session row.
        // Pin that the Clone derive carries every field — a refactor
        // that switched a String to Cow<str> would surface here as a
        // borrow-checker rewrite of the call site.
        let now = chrono::Utc::now().timestamp();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:bob@demo.local",
            "ops": ["drive:read:engineering/*", "gmail:send:alice@external.com"],
            "state": "abc",
            "iat": now,
            "exp": now + 60,
            "iss": "https://acme.okta.com",
        }));
        let c = validate_federation_token(&jwt).unwrap();
        let dup = c.clone();
        assert_eq!(dup.p_0, "user:bob@demo.local");
        assert_eq!(dup.ops.len(), 2);
        assert_eq!(dup.state, "abc");
        assert_eq!(dup.iat, now);
        assert_eq!(dup.exp, now + 60);
        assert_eq!(dup.iss.as_deref(), Some("https://acme.okta.com"));
    }

    #[test]
    fn infer_idp_case_insensitive_against_mixed_case_issuers() {
        // The `to_ascii_lowercase()` step is load-bearing — IdPs
        // sometimes emit the host portion in mixed case. Pin the
        // classifier collapses these to the same bucket as the
        // canonical-case form so a metric label split doesn't appear
        // for the same upstream IdP.
        assert_eq!(infer_idp(Some("https://Acme.OKTA.com")), "okta");
        assert_eq!(
            infer_idp(Some("https://Login.MicrosoftOnline.com/abc/v2.0")),
            "azure"
        );
        assert_eq!(infer_idp(Some("https://Accounts.Google.com")), "google");
    }

    #[test]
    fn validate_federation_token_at_exact_exp_boundary_accepts_inclusive() {
        // The exp check is `if now > claims.exp` — strict greater. So
        // a token with `exp == now` MUST still pass (not reject). Pin
        // the inclusive boundary; a refactor that flipped to `>=` would
        // silently shrink the validity window by one second and make
        // federation flows flaky around the wall-clock boundary. We
        // construct `exp` exactly at `now` via a tight chain: read now,
        // pin exp = now, decode. (There's a 1-microsecond race against
        // `Utc::now()` inside `validate_federation_token` advancing —
        // unlikely to flake but accepted.)
        let now = chrono::Utc::now().timestamp();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": [],
            "state": "s",
            "iat": now - 10,
            "exp": now,
        }));
        // `exp == now` → strict-greater check `now > exp` is false → accept.
        assert!(
            validate_federation_token(&jwt).is_ok(),
            "exp == now must accept (strict-greater check, not >=)"
        );
    }

    #[test]
    fn validate_federation_token_with_b64_valid_but_json_invalid_carries_bad_claims_msg() {
        // The third failure mode after malformed-JWT and bad-base64:
        // header + signature parts present, payload is valid base64,
        // but the decoded bytes don't deserialize to FederationClaims
        // (e.g. missing required field `pca_0_id`). Pin the operator-
        // facing message contains `"bad claims"` so a refactor that
        // collapsed the three error messages would lose actionable
        // triage signal. (Operator log filters key on the substring.)
        let header = B64URL.encode(br#"{"alg":"none"}"#);
        // Payload is valid base64 of valid JSON, but missing every
        // required field of FederationClaims (no pca_0_id, no p_0,
        // etc.) — serde will surface a missing-field error.
        let payload = B64URL.encode(br#"{"unrelated":true}"#);
        let jwt = format!("{header}.{payload}.sig");
        let err = validate_federation_token(&jwt).unwrap_err();
        match err {
            OAuthError::BridgeRejected(m) => {
                assert!(
                    m.contains("bad claims"),
                    "missing `bad claims` substring: {m}"
                );
            }
            other => panic!("expected BridgeRejected, got {other:?}"),
        }
    }

    #[test]
    fn infer_idp_returns_oidc_bucket_for_non_well_known_https_issuer_variants() {
        // The fallback `oidc` bucket is the catch-all for generic OIDC
        // IdPs (Keycloak, Auth0, custom). Pin three distinct shapes so a
        // refactor that tightened the fallback (e.g. requiring an
        // `https://` prefix) would surface here. Operator dashboards
        // panel on `idp=oidc` rate as a "non-named-IdP traffic" signal;
        // shrinking the bucket would silently hide it under "unknown".
        assert_eq!(
            infer_idp(Some("https://auth.example.com/realms/main")),
            "oidc"
        );
        assert_eq!(infer_idp(Some("https://login.acme.dev")), "oidc");
        assert_eq!(
            infer_idp(Some("https://keycloak.internal/auth/realms/main")),
            "oidc"
        );
    }

    #[test]
    fn validate_federation_token_with_invalid_uuid_pca_0_id_carries_bad_claims_msg() {
        // `FederationClaims::pca_0_id` is typed `Uuid` — serde delegates
        // to `Uuid`'s Deserialize impl which rejects non-UUID strings
        // (wrong segment count, non-hex chars, missing hyphens). The
        // existing `validate_federation_token_with_b64_valid_but_json_invalid_carries_bad_claims_msg`
        // test pins the missing-field path; pin the value-validation
        // path here as a distinct failure mode so a refactor that
        // swapped `pca_0_id: Uuid` for `pca_0_id: String` (with a
        // later runtime parse) would silently start accepting garbage
        // pca ids through the deserialize gate. The "bad claims"
        // substring is the operator-facing triage signal — pin it
        // surfaces here too.
        let now = chrono::Utc::now().timestamp();
        let header = B64URL.encode(br#"{"alg":"none"}"#);
        let payload = B64URL.encode(
            serde_json::json!({
                "pca_0_id": "not-a-uuid",
                "p_0": "user:alice@demo.local",
                "ops": [],
                "state": "s",
                "iat": now,
                "exp": now + 60,
            })
            .to_string()
            .as_bytes(),
        );
        let jwt = format!("{header}.{payload}.sig");
        let err = validate_federation_token(&jwt).unwrap_err();
        match err {
            OAuthError::BridgeRejected(m) => {
                assert!(
                    m.contains("bad claims"),
                    "missing `bad claims` substring: {m}",
                );
            }
            other => panic!("expected BridgeRejected, got {other:?}"),
        }
    }

    #[test]
    fn validate_federation_token_ignores_header_content_payload_only_validation() {
        // The docstring on `validate_federation_token` commits to
        // "payload-only" validation as the M0/M1 stub contract
        // (signature check stubbed deliberately so the swap to
        // JWKS-backed verify is one function). Pin that the HEADER
        // value is NEVER inspected: an arbitrarily-shaped header
        // (random bytes, claims-style JSON, even an empty string)
        // must be accepted as long as the payload + signature
        // segments are dot-separated. A refactor that started
        // validating the header (e.g. checking `alg == "none"` or
        // requiring `typ == "JWT"`) would silently break the stub's
        // forward-compat contract — every existing test fixture +
        // production bridge stub would start failing at the same
        // call site without an obvious reason.
        let now = chrono::Utc::now().timestamp();
        let payload = B64URL.encode(
            serde_json::json!({
                "pca_0_id": "00000000-0000-0000-0000-000000000001",
                "p_0": "user:alice@demo.local",
                "ops": [],
                "state": "s",
                "iat": now,
                "exp": now + 60,
            })
            .to_string()
            .as_bytes(),
        );
        // Three distinct header shapes — base64 of garbage, an empty
        // string, and a non-base64 raw token. All MUST accept.
        for header in [
            B64URL.encode(b"definitely-not-jwt-header"),
            String::new(),
            "raw-non-base64-bytes!@#".into(),
        ] {
            let jwt = format!("{header}.{payload}.sig");
            assert!(
                validate_federation_token(&jwt).is_ok(),
                "payload-only validation: header `{header}` must not be inspected",
            );
        }
    }

    #[test]
    fn validate_federation_token_ignores_signature_content_payload_only_validation() {
        // Symmetric to the header pin above — the SIGNATURE segment
        // is the third dot-separated part and the function NEVER
        // inspects it (the `(_h, payload, _s)` destructure binds
        // signature to `_s` and immediately drops it). Pin that an
        // empty signature, a base64-shaped fake, and a raw garbage
        // string all accept. A refactor that started validating the
        // signature (e.g. requiring non-empty `_s` as a sanity check)
        // would silently break the empty-signature fixtures the
        // bridge stub emits during early development.
        let now = chrono::Utc::now().timestamp();
        let header = B64URL.encode(br#"{"alg":"none"}"#);
        let payload = B64URL.encode(
            serde_json::json!({
                "pca_0_id": "00000000-0000-0000-0000-000000000001",
                "p_0": "user:alice@demo.local",
                "ops": [],
                "state": "s",
                "iat": now,
                "exp": now + 60,
            })
            .to_string()
            .as_bytes(),
        );
        for sig in ["", "AAECAwQF", "definitely-not-a-valid-signature!@#$%"] {
            let jwt = format!("{header}.{payload}.{sig}");
            assert!(
                validate_federation_token(&jwt).is_ok(),
                "payload-only validation: signature `{sig}` must not be inspected",
            );
        }
    }

    #[test]
    fn validate_federation_token_accepts_jwt_with_extra_segments_using_first_three() {
        // The destructure `(parts.next(), parts.next(), parts.next())`
        // consumes the first three dot-separated segments from
        // `split('.')` and leaves any additional segments in the
        // iterator (never inspected). So a 5-part JWT (4 dots)
        // accepts based on the first 3 segments. This is technically
        // out-of-spec for RFC 7519 JWTs (which have exactly 3
        // segments for JWS or 5 for JWE), but the payload-only stub
        // accepts it because the segment-count check isn't enforced.
        // Pin this behavior so a future refactor that tightened the
        // segment-count check (the natural "be strict about JWT
        // shape" cleanup) would surface here as a deliberate
        // wire-shape change — and would need coordinated bridge-stub
        // updates to match. A regression that silently REJECTED such
        // JWTs would break any bridge stub that accidentally emits
        // an extra trailing dot.
        let now = chrono::Utc::now().timestamp();
        let header = B64URL.encode(br#"{"alg":"none"}"#);
        let payload = B64URL.encode(
            serde_json::json!({
                "pca_0_id": "00000000-0000-0000-0000-000000000001",
                "p_0": "user:alice@demo.local",
                "ops": [],
                "state": "s",
                "iat": now,
                "exp": now + 60,
            })
            .to_string()
            .as_bytes(),
        );
        // Five-part JWT — extra segments after the signature.
        let jwt = format!("{header}.{payload}.sig.extra1.extra2");
        assert!(
            validate_federation_token(&jwt).is_ok(),
            "extra segments after signature must be silently ignored (first 3 used)",
        );
    }

    #[test]
    fn federation_claims_debug_carries_pca_0_id_and_p_0_for_log_grep() {
        // `FederationClaims` derives `Debug` — the OAuth callback
        // handler feeds `?claims` into `tracing::info!` so operators
        // can grep the request_id + the bridge-decoded principal/
        // pca_0_id from a single log line. Pin that the Debug
        // rendering surfaces BOTH the `pca_0_id` (as the canonical
        // hyphenated-lowercase uuid form via Uuid's Debug, which is
        // identical to Display in `format!("{:?}", uuid)`) AND the
        // `p_0` principal string. A manual Debug impl that hid
        // either field (in the name of "don't log PII") would
        // silently break operator forensics on the OAuth callback
        // path. Note: the routes module separately decides what to
        // actually log; this test pins the trait shape, not the log
        // policy.
        let now = chrono::Utc::now().timestamp();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "12345678-1234-5678-1234-567812345678",
            "p_0": "user:carol@demo.local",
            "ops": [],
            "state": "trace-abc",
            "iat": now,
            "exp": now + 60,
        }));
        let claims = validate_federation_token(&jwt).unwrap();
        let s = format!("{claims:?}");
        assert!(
            s.contains("12345678-1234-5678-1234-567812345678"),
            "pca_0_id missing from Debug: {s}",
        );
        assert!(
            s.contains("carol@demo.local"),
            "p_0 missing from Debug: {s}",
        );
        // The struct name itself is part of the Debug derive's output —
        // operator grep against `?claims` keys on the struct prefix.
        assert!(
            s.contains("FederationClaims"),
            "struct name missing from Debug: {s}",
        );
    }

    #[test]
    fn validate_federation_token_state_field_round_trips_verbatim_through_payload() {
        // The `state` field is the bridge-assigned correlation id —
        // the OAuth callback handler reads it and persists alongside
        // the session row so operator dashboards can join the proxy's
        // request_id against the bridge's emitted JWT for cross-system
        // tracing. A refactor that normalized the value (e.g.
        // lowercased it, trimmed whitespace, URL-decoded it) would
        // silently break that join across distinct character classes.
        // Pin three shapes the bridge might emit: a uuid-style string,
        // a mixed-case opaque token, and a token containing characters
        // operators sometimes embed in correlation ids (`-_.:`).
        // The deserialize must pass them through byte-identically.
        let now = chrono::Utc::now().timestamp();
        for state_value in [
            "00112233-4455-6677-8899-aabbccddeeff",
            "MixedCaseStateTokenABC123",
            "trace-id:req_42.proxy/v1",
        ] {
            let jwt = make_jwt(&serde_json::json!({
                "pca_0_id": "00000000-0000-0000-0000-000000000001",
                "p_0": "user:alice@demo.local",
                "ops": [],
                "state": state_value,
                "iat": now,
                "exp": now + 60,
            }));
            let claims = validate_federation_token(&jwt).unwrap();
            assert_eq!(
                claims.state, state_value,
                "state must round-trip byte-identically: input `{state_value}` got `{}`",
                claims.state,
            );
        }
    }

    #[test]
    fn accepts_fresh_token() {
        let now = chrono::Utc::now().timestamp();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": ["drive:read:engineering/*"],
            "state": "abc",
            "iat": now,
            "exp": now + 60,
        }));
        let c = validate_federation_token(&jwt).unwrap();
        assert_eq!(c.p_0, "user:alice@demo.local");
        assert_eq!(c.ops, vec!["drive:read:engineering/*".to_string()]);
    }
}
