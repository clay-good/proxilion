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
        return Err(OAuthError::BridgeRejected("federation token expired".into()));
    }
    if claims.iat > now + 60 {
        return Err(OAuthError::BridgeRejected("federation token issued in the future".into()));
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
