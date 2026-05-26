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
    fn federation_claims_is_send_sync_static_for_oauth_callback_handler_boundary() {
        // `FederationClaims` is built by the OAuth `/callback` handler
        // and passed across the `tokio::spawn`-ed audit-write boundary
        // (the audit row carrying `pca_0_id` + `p_0` + the bridge
        // `state` correlation id is dispatched async). axum + tokio
        // require Send+Sync+'static on values held across await points
        // in spawned tasks. A refactor that, e.g., added an `Rc<...>`
        // on a future field "for cheap clone of the ops list" would
        // break Send and surface at the audit-spawn site with an opaque
        // tower::Service trait-bound. Pin the three-trait combo at
        // this file boundary so the failure surfaces here.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<FederationClaims>();
    }

    #[test]
    fn infer_idp_returns_static_str_from_canonical_five_label_set() {
        // `infer_idp` returns `&'static str` (the metric-label set is
        // fixed at compile time). Pin the lifetime contract via a
        // helper that takes `&'static str` only — a refactor to
        // `String` "for ergonomic dynamic labels" would silently start
        // heap-allocating on every OAuth callback. AND pin the
        // canonical 5-label set `{okta, azure, google, oidc, unknown}`
        // exhaustively. The existing pins exercise individual labels
        // but never pin the type bound NOR the closed-set invariant.
        fn require_static_str(_: &'static str) {}
        for iss in [
            Some("https://acme.okta.com"),
            Some("https://login.microsoftonline.com/abc/v2.0"),
            Some("https://accounts.google.com"),
            Some("https://keycloak.internal/auth"),
            Some(""),
            None,
        ] {
            let label = infer_idp(iss);
            require_static_str(label);
            assert!(
                matches!(label, "okta" | "azure" | "google" | "oidc" | "unknown"),
                "non-canonical label `{label}` for iss {iss:?}",
            );
        }
    }

    #[test]
    fn validate_federation_token_empty_string_rejects_with_malformed_message() {
        // An empty string is the boundary input — `split('.').next()`
        // yields `Some("")` and the second/third `.next()` yield None,
        // so the destructure fails with the malformed-JWT branch. Pin
        // both the rejection AND the operator-facing `"malformed"`
        // substring (the OAuth `/callback` handler's log filter keys on
        // this substring to bucket "agent sent nothing" separately from
        // "agent sent something that wasn't a JWT"). A refactor that
        // pre-checked `is_empty()` and returned a distinct
        // `BridgeRejected("empty token")` variant would silently
        // split the bucket; pin the existing path explicitly.
        let err = validate_federation_token("").unwrap_err();
        match err {
            OAuthError::BridgeRejected(m) => {
                assert!(m.contains("malformed"), "missing `malformed`: {m}")
            }
            other => panic!("expected BridgeRejected, got {other:?}"),
        }
    }

    #[test]
    fn federation_claims_ops_field_round_trips_fifty_element_vec_verbatim() {
        // The `ops` field is `Vec<String>` — production federation
        // bridges occasionally surface wide grants (a service principal
        // with 50+ ops covering Drive + Calendar + Gmail at multiple
        // scope shapes). The existing pins exercise 1-2 ops only —
        // widen to N=50 so a refactor that capped the inner Vec at N
        // "for postgres array column safety" OR that deduplicated "for
        // RBAC hygiene" would surface here. Element-wise byte-equal
        // across 50 distinct strings with mixed colon-separated +
        // wildcard-suffix shapes.
        let now = chrono::Utc::now().timestamp();
        let ops: Vec<String> = (0..50)
            .map(|i| format!("vendor{i}:read:path/{i}/*"))
            .collect();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:wide@demo.local",
            "ops": ops,
            "state": "s",
            "iat": now,
            "exp": now + 60,
        }));
        let claims = validate_federation_token(&jwt).unwrap();
        assert_eq!(claims.ops.len(), 50, "ops count drift");
        for (i, op) in claims.ops.iter().enumerate() {
            assert_eq!(op, &format!("vendor{i}:read:path/{i}/*"));
        }
    }

    #[test]
    fn infer_idp_does_not_match_okta_io_or_microsoft_com_false_positives() {
        // The infer_idp substring matches are deliberately conservative:
        // `okta.com` + `oktapreview.com` → okta; `microsoftonline.com` +
        // `windows.net` → azure; `accounts.google.com` + `googleapis.com`
        // → google. A look-alike domain like `okta.io` (the docs domain,
        // NOT an IdP) MUST NOT match okta — it falls through to oidc.
        // Similarly `microsoft.com` (Microsoft corp marketing site, NOT
        // an IdP) MUST NOT match azure. Pin the negative side so a
        // refactor that loosened `okta.com` to `okta` (substring
        // alone) would surface here as a false-positive label drift,
        // which would silently flip operators' metric panels to attribute
        // unrelated traffic to the wrong IdP.
        assert_eq!(infer_idp(Some("https://www.okta.io/docs")), "oidc");
        assert_eq!(infer_idp(Some("https://www.microsoft.com/")), "oidc");
        assert_eq!(infer_idp(Some("https://google.com/search")), "oidc");
        // The leading "https://accounts.google.something-else.com"
        // also must NOT match google (since the substring `accounts.google.com`
        // wouldn't be in there if `.something-else.com` interposes).
        assert_eq!(
            infer_idp(Some("https://accounts.google.evilcorp.com/x")),
            "oidc",
        );
    }

    #[test]
    fn validate_federation_token_preserves_iss_field_byte_equal_through_payload_round_trip() {
        // The existing `claims_iss_round_trips_through_payload` pin
        // checks the inferred IdP label (azure) — pin the byte-equal
        // round-trip of the RAW `iss` string itself across an upper-
        // case variant + a URL with path + query. Operators key on the
        // raw iss for cross-system join (Grafana's IdP-side dashboard
        // uses the exact issuer string the IdP emits in its own logs).
        // A refactor that normalized iss (lowercase, trim, strip path)
        // would silently break the join.
        let now = chrono::Utc::now().timestamp();
        for raw_iss in [
            "https://Tenant.OKTA.com",
            "https://login.microsoftonline.com/abc/v2.0?token=x",
            "https://accounts.google.com/oauth/v2",
        ] {
            let jwt = make_jwt(&serde_json::json!({
                "pca_0_id": "00000000-0000-0000-0000-000000000001",
                "p_0": "user:alice@demo.local",
                "ops": [],
                "state": "s",
                "iat": now,
                "exp": now + 60,
                "iss": raw_iss,
            }));
            let claims = validate_federation_token(&jwt).unwrap();
            assert_eq!(
                claims.iss.as_deref(),
                Some(raw_iss),
                "iss must round-trip byte-equal, got {:?}",
                claims.iss,
            );
        }
    }

    #[test]
    fn infer_idp_is_referentially_transparent_across_fifty_calls_on_same_input() {
        // `infer_idp` is a pure substring classifier — no I/O, no
        // global state, no time-of-day input. Pin referential
        // transparency across 50 calls per input so a refactor that,
        // e.g., memoized the result in a thread-local LRU keyed on
        // the input POINTER (not content) would surface here as a
        // non-deterministic label on the second call. Symmetric to
        // the burst/siem/audit_body referentially-transparent pins
        // in rounds 193+199+200. The metric `idp` label feeds Grafana
        // panels that join on stable label cardinality — a 1-in-50
        // drift would silently fork one IdP into two label values.
        for raw in [
            Some("https://acme.okta.com"),
            Some("https://login.microsoftonline.com/abc/v2.0"),
            Some("https://accounts.google.com"),
            Some("https://keycloak.internal/auth"),
            Some(""),
            None,
        ] {
            let first = infer_idp(raw);
            for i in 0..50 {
                let next = infer_idp(raw);
                assert_eq!(
                    next, first,
                    "iter {i}: infer_idp drift on input {raw:?}: got {next} vs first {first}",
                );
            }
        }
    }

    #[test]
    fn validate_federation_token_is_referentially_transparent_across_fifty_calls_on_same_jwt() {
        // Same purity pin for the JWT decode path. `validate_federation_token`
        // reads `chrono::Utc::now()` for the exp/iat clock-skew checks
        // but is otherwise a pure decode — a refactor that mixed a
        // per-call nonce into the parse "for replay hardening" or
        // that LRU-cached the parsed claims by JWT-string pointer
        // would surface here as a non-deterministic `state` field on
        // the second call. The OAuth callback handler depends on the
        // decode being pure modulo the wall-clock — pin across 50
        // calls on the same fresh JWT.
        let now = chrono::Utc::now().timestamp();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": ["drive:read:engineering/*"],
            "state": "trace-fixed",
            "iat": now,
            "exp": now + 3600,
        }));
        let first = validate_federation_token(&jwt).expect("first decode");
        for i in 0..50 {
            let c = validate_federation_token(&jwt).expect("decode");
            assert_eq!(c.pca_0_id, first.pca_0_id, "iter {i}: pca_0_id drift");
            assert_eq!(c.p_0, first.p_0, "iter {i}: p_0 drift");
            assert_eq!(c.ops, first.ops, "iter {i}: ops drift");
            assert_eq!(c.state, first.state, "iter {i}: state drift");
            assert_eq!(c.iat, first.iat, "iter {i}: iat drift");
            assert_eq!(c.exp, first.exp, "iter {i}: exp drift");
        }
    }

    #[test]
    fn federation_claims_field_types_pinned_for_oauth_callback_session_persist_contract() {
        // `FederationClaims` is decoded from the bridge JWT and its
        // fields cross several .await boundaries before the OAuth
        // callback handler INSERTs the session row: `pca_0_id` keys
        // the postgres `sessions.pca_0_id UUID` column; `p_0` keys
        // `sessions.p_0 TEXT`; `ops` keys `sessions.granted_ops
        // TEXT[]`; `iat`/`exp` are timestamp-seconds typed `i64` for
        // direct `chrono::Utc::now().timestamp()` arithmetic. Pin
        // all 5 field types at the struct boundary so a refactor
        // that, e.g., switched `pca_0_id` to String "for ergonomic
        // bridge-stub fixtures" would surface here, not as a cascading
        // sqlx bind-type-mismatch at the INSERT call site.
        fn require_uuid(_: Uuid) {}
        fn require_string(_: String) {}
        fn require_vec_string(_: Vec<String>) {}
        fn require_i64(_: i64) {}
        let now = chrono::Utc::now().timestamp();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": ["drive:read:engineering/*"],
            "state": "s",
            "iat": now,
            "exp": now + 60,
        }));
        let c = validate_federation_token(&jwt).expect("decode");
        require_uuid(c.pca_0_id);
        require_string(c.p_0.clone());
        require_vec_string(c.ops.clone());
        require_i64(c.iat);
        require_i64(c.exp);
        require_string(c.state.clone());
    }

    #[test]
    fn federation_claims_iss_and_pca_0_cbor_b64_field_types_pinned_for_optional_bridge_contract() {
        // The two `#[serde(default)]` optional fields — `iss` and
        // `pca_0_cbor_b64` — MUST stay typed `Option<String>` to
        // preserve the bridge-stub-vs-production contract (stubs omit
        // them; production fills them). A refactor to bare String
        // with empty-string default "for ergonomic always-some access"
        // would silently collapse the present-vs-absent distinction
        // and break the `idp="unknown"` fallback on the callback
        // metric (which keys on `iss.as_deref()` being None). Pin
        // both at the field boundary via require_opt_string.
        fn require_opt_string(_: Option<String>) {}
        let now = chrono::Utc::now().timestamp();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": [],
            "state": "s",
            "iat": now,
            "exp": now + 60,
            "iss": "https://acme.okta.com",
            "pca_0_cbor_b64": "AAECAwQF",
        }));
        let c = validate_federation_token(&jwt).expect("decode");
        require_opt_string(c.iss.clone());
        require_opt_string(c.pca_0_cbor_b64.clone());
    }

    #[test]
    fn validate_federation_token_return_type_is_result_owned_by_value_for_cross_await_propagation()
    {
        // The OAuth `/callback` handler awaits the decode and then
        // moves the `FederationClaims` value across multiple .await
        // boundaries (session INSERT, PCA cache insert, audit row
        // emit). Pin that the return type is `Result<FederationClaims,
        // OAuthError>` owned-by-value (not `Result<&'a FederationClaims,
        // _>` borrowed or `Result<Box<FederationClaims>, _>` heap-
        // boxed). A refactor to borrowed return "for zero-alloc decode"
        // would tie every claims value to the input JWT string's
        // lifetime, which is freed when the request body is dropped —
        // any spawned audit task holding a `claims_ref` would dangle.
        // require_owned_claims forces the by-value contract.
        fn require_owned_claims(_: Result<FederationClaims, OAuthError>) {}
        let now = chrono::Utc::now().timestamp();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": [],
            "state": "s",
            "iat": now,
            "exp": now + 60,
        }));
        require_owned_claims(validate_federation_token(&jwt));
    }

    #[test]
    fn infer_idp_returns_unknown_for_empty_string_distinctly_from_oidc_fallback() {
        // The `infer_idp` cascade has a subtle ordering: empty string
        // input MUST return "unknown" (the final else branch's
        // `!s.is_empty()` check fails) and NOT "oidc" (the catch-all
        // for non-well-known issuers). Distinguishing "unknown"
        // (bridge stub gave us nothing) from "oidc" (generic OIDC
        // IdP) is load-bearing for operator dashboards — a refactor
        // that simplified the cascade to drop the `is_empty()` guard
        // "since lowercase empty string contains no well-known
        // substrings" would silently collapse "unknown" into "oidc"
        // and break the panel that watches the unknown-vs-generic-
        // OIDC ratio. Pin the empty-string-→-unknown distinction
        // independently from the existing None→unknown pin.
        assert_eq!(infer_idp(Some("")), "unknown");
        assert_eq!(infer_idp(None), "unknown");
        // And the close-to-empty boundary — a single whitespace
        // also routes to oidc (non-empty string after lowercase
        // contains no well-known substring). Pin so the
        // `is_empty()` guard's behavior at byte-length-1 is
        // operator-visible.
        assert_eq!(infer_idp(Some(" ")), "oidc");
    }

    // ─── round 221 (2026-05-22): FederationClaims field-count, skew boundary,
    // BridgeRejected message stability, infer_idp ordering + numeric types ───

    #[test]
    fn federation_claims_field_count_pinned_at_exactly_eight_via_exhaustive_destructure() {
        // `FederationClaims` is decoded from the bridge JWT payload and
        // every field crosses several `.await` boundaries before the
        // OAuth callback INSERTs the session row. A 9th field landing
        // (e.g. `nbf: i64` not-before, `aud: String` audience, or
        // `jti: String` jwt-id) without matching INSERT column wiring
        // would silently DROP the field on every persist — the bridge
        // would emit it, the proxy would deserialize it (via
        // `#[serde(default)]` if added defensively, otherwise hard fail),
        // and then never persist it. The exhaustive destructure with no
        // `..` rest pattern catches the field-count drift at compile
        // time: adding a 9th field forces this destructure to update in
        // lockstep with the OAuth-callback INSERT site. Symmetric to the
        // ErrorBody 6-field + CachedPca 8-field + ActionEvent 16-field +
        // OAuthState 6-field exhaustive-destructure pins.
        let now = chrono::Utc::now().timestamp();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": ["drive:read:*"],
            "pca_0_cbor_b64": "AAECAwQF",
            "state": "trace-fixed",
            "iat": now,
            "exp": now + 60,
            "iss": "https://acme.okta.com",
        }));
        let c = validate_federation_token(&jwt).expect("decode");
        // Exhaustive destructure: no `..` rest pattern. A 9th field
        // landing breaks this match and forces an update.
        let FederationClaims {
            pca_0_id: _,
            p_0: _,
            ops: _,
            pca_0_cbor_b64: _,
            state: _,
            iat: _,
            exp: _,
            iss: _,
        } = c;
    }

    #[test]
    fn validate_federation_token_rejects_iat_one_second_past_skew_window_boundary() {
        // The clock-skew guard is `if claims.iat > now + 60 { ... }`. The
        // existing `accepts_token_at_exact_60s_clock_skew_boundary` pin
        // covers the INCLUSIVE 60s edge (iat == now + 60 → accept).
        // Pin the EXCLUSIVE off-by-one at iat == now + 61 → reject so a
        // refactor that loosened `>` to `>=` would silently widen the
        // skew window by 1s (or, more dangerously, tightened it to
        // reject the canonical 60s boundary). Symmetric to the
        // pkce boundary 42/43/127/128 + 60s-inclusive pins.
        let now = chrono::Utc::now().timestamp();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "user:alice@demo.local",
            "ops": ["drive:read:*"],
            "state": "skew-test",
            "iat": now + 61,
            "exp": now + 3600,
        }));
        let err = validate_federation_token(&jwt).unwrap_err();
        match err {
            OAuthError::BridgeRejected(m) => {
                assert!(m.contains("future"), "got: {m}");
            }
            other => panic!("expected BridgeRejected, got {other:?}"),
        }
    }

    #[test]
    fn bridge_rejected_message_strings_byte_distinct_for_operator_grep_buckets() {
        // The three `BridgeRejected` arms in `validate_federation_token`
        // emit distinct messages: `"malformed JWT"`, `"bad base64"`,
        // `"bad claims: {e}"`, `"federation token expired"`,
        // `"federation token issued in the future"`. Operator Loki
        // / Grafana alerts split on these substrings to bucket
        // bridge failures into "agent mis-implemented" (malformed) vs.
        // "bridge mis-encoded" (base64/claims) vs. "clock skew"
        // (expired/future). Pin pairwise byte-distinctness so a
        // refactor that softened all four to a single
        // `"bridge validation failed: {detail}"` umbrella message
        // would silently collapse the four buckets onto one alert.
        // Symmetric to the OAuthError Display + ErrorCode wire-string
        // pairwise-distinct pins.
        let now = chrono::Utc::now().timestamp();
        let malformed_err = validate_federation_token("not-a-jwt").unwrap_err();
        let bad_b64_jwt = "header.!notb64!.signature";
        let bad_b64_err = validate_federation_token(bad_b64_jwt).unwrap_err();
        let expired_jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "x", "ops": [], "state": "s",
            "iat": 0, "exp": 1,
        }));
        let expired_err = validate_federation_token(&expired_jwt).unwrap_err();
        let future_jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "x", "ops": [], "state": "s",
            "iat": now + 3600, "exp": now + 7200,
        }));
        let future_err = validate_federation_token(&future_jwt).unwrap_err();
        fn msg(e: &OAuthError) -> String {
            match e {
                OAuthError::BridgeRejected(m) => m.clone(),
                other => panic!("expected BridgeRejected, got {other:?}"),
            }
        }
        let ms = [
            msg(&malformed_err),
            msg(&bad_b64_err),
            msg(&expired_err),
            msg(&future_err),
        ];
        // Pairwise distinct.
        for i in 0..ms.len() {
            for j in (i + 1)..ms.len() {
                assert_ne!(ms[i], ms[j], "msg {i} and {j} collide: {:?}", ms[i]);
            }
        }
        // And byte-anchored substrings the operator grep depends on.
        assert!(ms[0].contains("malformed"));
        assert!(ms[1].contains("base64"));
        assert!(ms[2].contains("expired"));
        assert!(ms[3].contains("future"));
    }

    #[test]
    fn infer_idp_priority_order_okta_wins_over_azure_when_both_substrings_present() {
        // The `infer_idp` cascade uses `if / else if` ordering: okta is
        // checked first, then azure, then google, then oidc. A
        // pathological issuer that contains BOTH `okta.com` AND
        // `microsoftonline.com` substrings would match the FIRST arm
        // (okta). Pin the priority order so a refactor that switched
        // to a `HashMap` lookup OR re-ordered the arms (e.g. alphabetized
        // them to `azure | google | okta`) would silently flip the
        // dashboard label for an ambiguous fixture. The most likely
        // way this matters in production: an okta-fronted-by-azure
        // gateway whose iss URL legitimately contains both substrings.
        let s = "https://acme.okta.com/realms/microsoftonline.com-proxy";
        assert_eq!(infer_idp(Some(s)), "okta");
        // Symmetric: azure wins over google.
        let s2 = "https://login.microsoftonline.com/tenant/accounts.google.com-proxy";
        assert_eq!(infer_idp(Some(s2)), "azure");
        // Symmetric: google wins over oidc fallback.
        let s3 = "https://accounts.google.com/realms/oidc-alias";
        assert_eq!(infer_idp(Some(s3)), "google");
    }

    #[test]
    fn federation_claims_iat_and_exp_field_types_pinned_i64_for_chrono_timestamp_arithmetic() {
        // The clock-skew guard does `claims.iat > now + 60` where `now`
        // is `chrono::Utc::now().timestamp()` (returning `i64`). The exp
        // guard does `now > claims.exp` symmetrically. A refactor that
        // typed iat/exp as `u64` "for non-negative epoch semantics"
        // would force a cast at the comparison site (silent on values
        // within i64::MAX but a compile error on the bare comparison)
        // OR a refactor to `i32` "for postgres `integer` column compat"
        // would silently overflow past 2038-01-19 (the Unix epoch
        // 2^31). Pin both as `i64` via require_i64 so the type axis
        // surfaces at the struct boundary. Symmetric to the
        // ActionEvent.status u16 + ListResponse.policy_count usize
        // numeric-type pins.
        fn require_i64(_: i64) {}
        let now = chrono::Utc::now().timestamp();
        let jwt = make_jwt(&serde_json::json!({
            "pca_0_id": "00000000-0000-0000-0000-000000000001",
            "p_0": "x", "ops": [], "state": "s",
            "iat": now, "exp": now + 60,
        }));
        let c = validate_federation_token(&jwt).expect("decode");
        require_i64(c.iat);
        require_i64(c.exp);
    }

    #[test]
    fn infer_idp_return_type_is_static_str_via_fn_pointer_witness_for_metric_label_borrow() {
        // `infer_idp` returns `&'static str` from a closed 5-label set
        // (`okta | azure | google | oidc | unknown`). The return value
        // is used as a Prometheus metric label
        // (`proxilion_oauth_callback_total{idp="okta"}`) — `metrics`
        // crate label values are `Cow<'static, str>`, so the static
        // branch avoids per-callback allocation on the hot OAuth
        // callback path. A refactor to `String` "for ergonomic
        // dynamic-idp-name extraction from iss" would force a
        // heap-allocate-per-callback regression. Pin the `&'static
        // str` return via fn-pointer type capture so the type axis
        // surfaces at the helper boundary, not at the metric-emit
        // call site far away.
        let _f: fn(Option<&str>) -> &'static str = infer_idp;
        // And exercise across the 5-label set to catch a refactor
        // that satisfied the fn-pointer pin via a leaked &'static
        // String — `Box::leak` would still type-check.
        assert_eq!(infer_idp(Some("https://acme.okta.com")), "okta");
        assert_eq!(
            infer_idp(Some("https://login.microsoftonline.com/abc")),
            "azure"
        );
        assert_eq!(infer_idp(Some("https://accounts.google.com")), "google");
        assert_eq!(infer_idp(Some("https://id.example.org")), "oidc");
        assert_eq!(infer_idp(None), "unknown");
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

    #[test]
    fn federation_claims_field_count_pinned_at_exactly_eight_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the FederationClaims struct field count at exactly 8
        // via exhaustive destructure (no `..`). The 8 fields are:
        // pca_0_id (Uuid) + p_0 (String) + ops (Vec<String>) +
        // pca_0_cbor_b64 (Option<String>) + state (String) + iat
        // (i64) + exp (i64) + iss (Option<String>). A 9th field
        // landing (e.g. `nbf: Option<i64>` for a future not-before
        // clock-skew check, or `jti: Option<String>` for
        // anti-replay nonce tracking) would silently extend the
        // federation-bridge wire contract the proxy must
        // round-trip per spec.md §0.4 AND silently change what the
        // OAuth callback handler can extract from the JWT. Pin via
        // exhaustive destructure.
        let v = FederationClaims {
            pca_0_id: Uuid::nil(),
            p_0: String::new(),
            ops: vec![],
            pca_0_cbor_b64: None,
            state: String::new(),
            iat: 0,
            exp: 0,
            iss: None,
        };
        let FederationClaims {
            pca_0_id: _,
            p_0: _,
            ops: _,
            pca_0_cbor_b64: _,
            state: _,
            iat: _,
            exp: _,
            iss: _,
        } = v;
    }

    #[test]
    fn validate_federation_token_signature_pinned_via_fn_pointer_witness() {
        // Pin validate_federation_token signature as
        // `fn(&str) -> Result<FederationClaims, OAuthError>` via
        // fn-pointer witness. The JWT input is by BORROW (the
        // OAuth callback holds the raw token in a String field on
        // the request struct and passes a slice through). A
        // refactor to `fn(String) -> ...` "for consume-and-decode
        // clarity" would silently force every call site to box
        // the borrowed JWT. The owned `Result<FederationClaims,
        // OAuthError>` return is also pinned — the error variant
        // funnels through the OAuthError envelope downstream.
        let _f: fn(&str) -> Result<FederationClaims, OAuthError> = validate_federation_token;
    }

    #[test]
    fn infer_idp_signature_pinned_via_fn_pointer_witness() {
        // Pin infer_idp signature as `fn(Option<&str>) ->
        // &'static str` via fn-pointer witness. The arg is
        // `Option<&str>` (NOT `&str` and NOT `&Option<String>`) —
        // the None arm is wire-distinct from `Some("")` (per the
        // documented contract) and a refactor to either alternate
        // shape would silently change which inputs return
        // "unknown". The `&'static str` return is load-bearing
        // because the OAuth callback labels the
        // `proxilion_oauth_callback_total{idp}` metric with the
        // returned value — `&'static str` lets the metrics SDK
        // intern the label without per-call allocation. A
        // refactor to `String` "for dynamic per-tenant labels"
        // would silently force allocation per OAuth callback
        // AND blow up metric cardinality.
        let _f: fn(Option<&str>) -> &'static str = infer_idp;
    }

    #[test]
    fn infer_idp_returns_only_bounded_label_set_per_spec_md_section_3_2() {
        // The spec.md §3.2 contract is that infer_idp returns
        // exactly one of the bounded set `okta|azure|google|oidc|
        // unknown`. The existing `infer_idp_classifies_known_issuers`
        // pin walks the 5 known mappings via individual asserts;
        // pin the closed-set invariant directly so a refactor
        // adding a 6th bucket (e.g. `auth0` or `keycloak`) would
        // silently extend the metric cardinality without an
        // operator-dashboard update. Sweep a representative
        // sample of inputs and assert every result lands in the
        // 5-label set.
        let probes = [
            None,
            Some(""),
            Some("https://acme.okta.com"),
            Some("https://acme.oktapreview.com"),
            Some("https://login.microsoftonline.com/x"),
            Some("https://login.windows.net/x"),
            Some("https://accounts.google.com"),
            Some("https://googleapis.com"),
            Some("https://id.example.org"),
            Some("https://keycloak.example.com"),
            Some("https://login.auth0.com"),
        ];
        let allowed: std::collections::HashSet<&'static str> =
            ["okta", "azure", "google", "oidc", "unknown"]
                .iter()
                .copied()
                .collect();
        for p in &probes {
            let label = infer_idp(*p);
            assert!(
                allowed.contains(label),
                "infer_idp({p:?}) returned `{label}` not in bounded set",
            );
        }
    }

    #[test]
    fn federation_claims_is_send_sync_static_for_axum_extension_propagation() {
        // FederationClaims flows through the OAuth callback's
        // request-extension store across `.await` boundaries —
        // Send + Sync + 'static are load-bearing. The existing
        // Clone pin walks Clone; this walks the auto-trait combo
        // directly. A refactor adding an Rc<...> field "for
        // shared metadata across the callback chain" would
        // surface here. Pin via require_send_sync_static —
        // symmetric to round-176/177 trait-bound pins extended
        // to FederationClaims.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<FederationClaims>();
    }

    #[test]
    fn federation_claims_string_fields_are_owned_for_jwt_decode_outlives_request() {
        // FederationClaims.p_0 + state fields are owned String —
        // captured fresh from the JWT decode and consumed
        // downstream after `.await` boundaries (the OAuth
        // callback awaits Trust Plane + DB writes before
        // persisting the claims). A refactor to `&'a str` "to
        // avoid the decode-time allocation" would tie the
        // lifetime to the JWT payload buffer that's dropped
        // mid-handler. Pin owned-String type on all three
        // String-shaped fields via require_string +
        // pattern-match. Symmetric to round-176/185/272
        // owned-String pins extended to FederationClaims.
        fn require_string(_: &String) {}
        let v = FederationClaims {
            pca_0_id: Uuid::nil(),
            p_0: "alice".into(),
            ops: vec![],
            pca_0_cbor_b64: Some("base64".into()),
            state: "corr-id".into(),
            iat: 0,
            exp: 0,
            iss: Some("https://acme.okta.com".into()),
        };
        require_string(&v.p_0);
        require_string(&v.state);
        // ops is Vec<String> — pin each element is String via
        // require_string on a sample element when present.
        let v_ops = FederationClaims {
            pca_0_id: Uuid::nil(),
            p_0: "x".into(),
            ops: vec!["drive:read:*".into()],
            pca_0_cbor_b64: None,
            state: "x".into(),
            iat: 0,
            exp: 0,
            iss: None,
        };
        require_string(&v_ops.ops[0]);
    }
}
