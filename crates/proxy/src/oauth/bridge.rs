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
