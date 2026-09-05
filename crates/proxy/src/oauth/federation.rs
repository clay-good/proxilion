//! Verified in-process federation (production-readiness.md PR-1, Approach A).
//!
//! Composes the two PR-1 primitives into the single call the OAuth callback
//! makes: [`jwks::JwksResolver`] turns the token's `kid` into the IdP's
//! public key, and [`idp_verify::verify_id_token`] verifies the signature
//! and every claim with the algorithm pinned server-side.
//!
//! **Why this type exists rather than the two calls inline in the handler:**
//! the `kid` extraction sits between them, and getting it wrong is the whole
//! attack surface — reading `alg` from the header to pick the algorithm is
//! exactly the RFC 8725 confusion this PR kills. Keeping the sequence in one
//! place means the handler cannot accidentally reorder or skip a step, and
//! the sequence is unit-testable without a database or an HTTP server.
//!
//! Every path is fail-closed: there is no branch that returns an identity
//! without a verified signature.

use std::sync::Arc;

use jsonwebtoken::Algorithm;

use super::error::OAuthError;
use super::idp_verify::{IdpVerifyConfig, VerifiedIdentity, verify_id_token};
use super::jwks::JwksResolver;

/// A configured, verified federation path: one trusted issuer, its JWKS
/// endpoint, and the server-side verification policy.
pub struct VerifiedFederation {
    /// The IdP's JWKS endpoint (`https://` enforced at fetch time).
    jwks_uri: String,
    resolver: JwksResolver,
    verify: IdpVerifyConfig,
}

impl VerifiedFederation {
    pub fn new(
        jwks_uri: impl Into<String>,
        resolver: JwksResolver,
        verify: IdpVerifyConfig,
    ) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            resolver,
            verify,
        }
    }

    /// The trusted issuer this path verifies against — used for the
    /// `idp` metric label before a token is (or fails to be) verified.
    pub fn issuer(&self) -> &str {
        &self.verify.issuer
    }

    /// Verify an IdP `id_token` and return the human identity it binds.
    ///
    /// The token's `kid` header selects the *key*; it never selects the
    /// *algorithm* — that comes only from the operator allow-list carried
    /// in `self.verify`.
    pub async fn verify(&self, id_token: &str) -> Result<VerifiedIdentity, OAuthError> {
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|e| OAuthError::BridgeRejected(format!("malformed id_token header: {e}")))?;
        let Some(kid) = header.kid else {
            // Without a `kid` we cannot pin which published key signed
            // this token. Trying every key in the JWKS would turn key
            // rotation into an oracle; fail closed instead.
            return Err(OAuthError::BridgeRejected(
                "id_token header has no kid".into(),
            ));
        };
        let key = self
            .resolver
            .resolve(&self.jwks_uri, &kid)
            .await
            .map_err(|e| OAuthError::BridgeRejected(e.to_string()))?;
        verify_id_token(id_token, &key, &self.verify)
            .map_err(|e| OAuthError::BridgeRejected(e.to_string()))
    }
}

/// Parse an operator-configured algorithm allow-list (`"RS256,ES256"`).
///
/// Unknown names are an error rather than a silent drop: a typo that
/// emptied the list would otherwise become a boot-time "accepts nothing"
/// or, worse, read as "accepts anything" to whoever wrote it. `none` and
/// the HS\* family are not accepted here at all — they are structurally
/// unsafe for an asymmetric IdP trust relationship (RFC 8725 §3.1/§3.2),
/// and [`IdpVerifyConfig::validate`] rejects them again at verify time.
pub fn parse_algorithms(raw: &str) -> Result<Vec<Algorithm>, String> {
    let mut out = Vec::new();
    for tok in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let alg = match tok.to_ascii_uppercase().as_str() {
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            "PS256" => Algorithm::PS256,
            "PS384" => Algorithm::PS384,
            "PS512" => Algorithm::PS512,
            "ES256" => Algorithm::ES256,
            "ES384" => Algorithm::ES384,
            "EDDSA" => Algorithm::EdDSA,
            other => {
                return Err(format!(
                    "unsupported or unsafe id_token algorithm {other:?} \
                     (asymmetric only: RS*/PS*/ES*/EdDSA; none and HS* are refused)"
                ));
            }
        };
        if !out.contains(&alg) {
            out.push(alg);
        }
    }
    if out.is_empty() {
        return Err("algorithm allow-list is empty".to_string());
    }
    Ok(out)
}

/// Build the production federation path from resolved config values.
pub fn build(
    issuer: &str,
    audience: &str,
    jwks_uri: &str,
    algorithms: Vec<Algorithm>,
    http: reqwest::Client,
) -> Arc<VerifiedFederation> {
    let mut verify = IdpVerifyConfig::new(issuer, audience);
    verify.algorithms = algorithms;
    Arc::new(VerifiedFederation::new(
        jwks_uri,
        JwksResolver::http(http),
        verify,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::jwks::{JwksError, JwksSource};
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde::Serialize;

    // Same throwaway EC P-256 keypair as `idp_verify` / `jwks` tests.
    const TEST_EC_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/cMFpcJsolBgFOlZ
vzaoxlWrL34DXi590Q6YbUlWd46hRANCAATG5fYBBV7BWx9mONRN4cKfQB6xqdlM
heWXRko1Gm2FyFpjjFQWWLNw425FE+m3lCoelUdEpmZNLvP/eJA0+eY+
-----END PRIVATE KEY-----";

    const KID: &str = "test-1";
    const ISS: &str = "https://acme.okta.com";
    const AUD: &str = "proxilion";
    const JWKS_URI: &str = "https://acme.okta.com/oauth2/v1/keys";

    struct StaticJwks(JwkSet);

    #[async_trait::async_trait]
    impl JwksSource for StaticJwks {
        async fn fetch(&self, _uri: &str) -> Result<JwkSet, JwksError> {
            Ok(self.0.clone())
        }
    }

    fn jwks() -> JwkSet {
        serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "kid": KID,
                "use": "sig",
                "alg": "ES256",
                "x": "xuX2AQVewVsfZjjUTeHCn0AesanZTIXll0ZKNRpthcg",
                "y": "WmOMVBZYs3DjbkUT6beUKh6VR0SmZk0u8_94kDT55j4",
            }]
        }))
        .expect("static test JWKS")
    }

    fn federation() -> VerifiedFederation {
        let mut verify = IdpVerifyConfig::new(ISS, AUD);
        verify.algorithms = vec![Algorithm::ES256];
        VerifiedFederation::new(
            JWKS_URI,
            JwksResolver::new(Arc::new(StaticJwks(jwks()))),
            verify,
        )
    }

    #[derive(Serialize)]
    struct Claims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
        pic_ops: Vec<String>,
    }

    fn claims() -> Claims {
        Claims {
            iss: ISS.into(),
            sub: "user-123".into(),
            aud: AUD.into(),
            exp: chrono::Utc::now().timestamp() + 300,
            pic_ops: vec!["drive:read:engineering/*".into()],
        }
    }

    fn sign(kid: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = kid.map(str::to_string);
        let key = EncodingKey::from_ec_pem(TEST_EC_PRIV_PEM.as_bytes()).unwrap();
        encode(&header, &claims(), &key).unwrap()
    }

    #[tokio::test]
    async fn verifies_a_signed_token_end_to_end_and_carries_ops() {
        let id = federation().verify(&sign(Some(KID))).await.expect("verify");
        assert_eq!(id.principal, format!("oidc:{ISS}#user-123"));
        assert_eq!(id.ops, vec!["drive:read:engineering/*"]);
    }

    #[tokio::test]
    async fn rejects_a_token_without_a_kid_header() {
        let err = federation().verify(&sign(None)).await.unwrap_err();
        assert!(
            matches!(&err, OAuthError::BridgeRejected(m) if m.contains("no kid")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_an_unknown_kid_fail_closed() {
        let err = federation()
            .verify(&sign(Some("rotated-out")))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, OAuthError::BridgeRejected(m) if m.contains("rotated-out")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_a_tampered_payload() {
        // Flip a byte in the payload segment — signature no longer matches.
        let token = sign(Some(KID));
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        let last = parts[1].pop().unwrap();
        parts[1].push(if last == 'A' { 'B' } else { 'A' });
        let err = federation().verify(&parts.join(".")).await.unwrap_err();
        assert!(matches!(err, OAuthError::BridgeRejected(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn rejects_a_non_jwt_string() {
        let err = federation().verify("not-a-jwt").await.unwrap_err();
        assert!(
            matches!(&err, OAuthError::BridgeRejected(m) if m.contains("malformed id_token header")),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_algorithms_accepts_the_asymmetric_families_and_dedupes() {
        assert_eq!(
            parse_algorithms("RS256, ES256 ,rs256").unwrap(),
            vec![Algorithm::RS256, Algorithm::ES256]
        );
        assert_eq!(parse_algorithms("EdDSA").unwrap(), vec![Algorithm::EdDSA]);
    }

    #[test]
    fn parse_algorithms_refuses_symmetric_none_and_empty() {
        for raw in ["HS256", "none", "RS256,HS512", "garbage"] {
            assert!(parse_algorithms(raw).is_err(), "{raw} must be refused");
        }
        assert!(parse_algorithms("").is_err());
        assert!(parse_algorithms("  , ").is_err());
    }
}
