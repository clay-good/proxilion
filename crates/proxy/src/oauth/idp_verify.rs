//! In-process IdP `id_token` signature verification (production-readiness.md
//! PR-1, Approach A).
//!
//! This is the cryptographic core that closes the federation showstopper:
//! no request may carry authority on the strength of an **unverified**
//! token. [`verify_id_token`] verifies an OIDC `id_token`'s **signature**
//! against the IdP's published key and validates `iss`/`aud`/`exp`/`nbf`
//! with a bounded clock skew, **fail-closed** — any failure is an error,
//! never a fall-through to a trusted path.
//!
//! ## Why we verify here rather than reuse the upstream handler verbatim
//!
//! Upstream `provenance-bridge`'s `JwtHandler::validate` (at the SHA this
//! repo pins) reads the algorithm from the **token's own header**
//! (`let alg = header.alg; … Validation::new(alg)`) and never enforces its
//! configured `algorithms` allow-list. That is exactly the
//! algorithm-confusion pattern RFC 8725 / RFC 9700 forbid: the verifier
//! must choose the algorithm **server-side**, never trust the attacker's
//! `alg` header. We therefore verify with `jsonwebtoken` directly and pin
//! [`Validation::algorithms`] to an operator allow-list that can never
//! contain `none` or an HS\* (symmetric) algorithm — defeating both the
//! `alg:none` bypass and the RS256→HS256 public-key-as-HMAC confusion.
//!
//! The JWKS fetch/cache + `kid` rotation layer (resolving a `kid` to the
//! [`DecodingKey`] passed here) and the OAuth-callback rewiring that calls
//! Trust Plane `POST /v1/pca/issue` from the verified identity are the
//! next PR-1 slice; this module is the verification primitive they build on.

#![allow(dead_code)] // wired into the callback flow in the next PR-1 slice

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, errors::ErrorKind};
use serde::Deserialize;

/// Maximum tolerated clock skew, in seconds, for `exp`/`nbf` — RFC 9700
/// bounds this; the spec caps it at 60 s.
pub const MAX_LEEWAY_SECS: u64 = 60;

/// Operator-configured verification policy for one trusted issuer.
#[derive(Debug, Clone)]
pub struct IdpVerifyConfig {
    /// Exact `iss` this policy trusts (e.g. `https://acme.okta.com`).
    pub issuer: String,
    /// Proxilion's configured audience (`aud`).
    pub audience: String,
    /// Server-side algorithm allow-list. Enforced by the verifier; the
    /// token's own `alg` is never trusted to select the algorithm. MUST
    /// be asymmetric — `none`/HS\* are rejected by [`Self::validate`].
    pub algorithms: Vec<Algorithm>,
    /// Clock-skew allowance in seconds (clamped to [`MAX_LEEWAY_SECS`]).
    pub leeway_secs: u64,
}

impl IdpVerifyConfig {
    /// A policy for `issuer`/`audience` using the safe default allow-list
    /// (RS256 + ES256) and the maximum permitted clock skew.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            algorithms: vec![Algorithm::RS256, Algorithm::ES256],
            leeway_secs: MAX_LEEWAY_SECS,
        }
    }

    /// Reject a structurally-unsafe policy before it is ever used to admit
    /// a token: an empty allow-list (would accept nothing meaningfully /
    /// could be misread as "any"), or one containing `none`/HS\*.
    fn validate(&self) -> Result<(), IdpVerifyError> {
        if self.algorithms.is_empty() {
            return Err(IdpVerifyError::DisallowedAlgorithm);
        }
        if self.algorithms.iter().copied().any(is_forbidden) {
            return Err(IdpVerifyError::DisallowedAlgorithm);
        }
        Ok(())
    }
}

/// The verified human identity extracted from a signature-checked
/// `id_token`. `principal` becomes `p_0` for PCA_0 issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// Canonical principal `oidc:{iss}#{sub}`.
    pub principal: String,
    pub issuer: String,
    pub subject: String,
    /// `exp` (epoch seconds) of the verified token.
    pub expires_at: i64,
}

/// Fail-closed verification outcomes. Every variant is a rejection; there
/// is no "accepted but unverified" state.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdpVerifyError {
    /// `iss` is not the configured trusted issuer.
    #[error("federation token rejected: untrusted issuer")]
    UntrustedIssuer,
    /// The token's algorithm is not in the server-side allow-list (covers
    /// `alg:none` and the RS256→HS256 confusion attempt).
    #[error("federation token rejected: algorithm not allowed")]
    DisallowedAlgorithm,
    /// Signature, `aud`, `exp`, `nbf`, or a required claim failed.
    #[error("federation token rejected: {0}")]
    Verification(String),
    /// The token is not a well-formed JWT.
    #[error("federation token rejected: malformed token: {0}")]
    Malformed(String),
}

/// Is `alg` forbidden for an asymmetric IdP trust relationship? `none` is
/// not representable in `jsonwebtoken::Algorithm` (so it can never be in an
/// allow-list and is rejected at decode); the HS\* family is symmetric and
/// enables the public-key-as-HMAC confusion attack.
fn is_forbidden(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}

/// Verify a signed OIDC `id_token` against `key`, with the algorithm and
/// every claim pinned by `config`. Returns the verified principal or a
/// fail-closed [`IdpVerifyError`].
///
/// `key` is the IdP's public key (resolved by `kid` from its JWKS in the
/// surrounding layer). The algorithm used to verify is taken **only** from
/// `config.algorithms`, never from the token header.
pub fn verify_id_token(
    token: &str,
    key: &DecodingKey,
    config: &IdpVerifyConfig,
) -> Result<VerifiedIdentity, IdpVerifyError> {
    config.validate()?;

    // Pin verification to the operator allow-list. `Validation::new` seeds
    // the algorithm; we then overwrite `.algorithms` with the full
    // allow-list so `decode` rejects any token whose header `alg` is not in
    // the set. The token's `alg` is NEVER consulted to select the algorithm.
    let mut validation = Validation::new(config.algorithms[0]);
    validation.algorithms = config.algorithms.clone();
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[config.audience.as_str()]);
    validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = config.leeway_secs.min(MAX_LEEWAY_SECS);

    let data = decode::<IdTokenClaims>(token, key, &validation).map_err(classify)?;
    let claims = data.claims;

    // jsonwebtoken already enforced `iss == config.issuer` via set_issuer;
    // re-check as defense-in-depth so a future Validation refactor that
    // dropped the issuer pin can't silently widen trust.
    if claims.iss != config.issuer {
        return Err(IdpVerifyError::UntrustedIssuer);
    }

    let principal = format!("oidc:{}#{}", claims.iss, claims.sub);
    Ok(VerifiedIdentity {
        principal,
        issuer: claims.iss,
        subject: claims.sub,
        expires_at: claims.exp,
    })
}

/// Minimal claim set we extract after verification. `aud`/`nbf` are
/// validated by `jsonwebtoken` and need not be deserialized here.
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    exp: i64,
}

fn classify(e: jsonwebtoken::errors::Error) -> IdpVerifyError {
    match e.kind() {
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
            IdpVerifyError::DisallowedAlgorithm
        }
        ErrorKind::InvalidIssuer => IdpVerifyError::UntrustedIssuer,
        ErrorKind::InvalidSignature
        | ErrorKind::ExpiredSignature
        | ErrorKind::ImmatureSignature
        | ErrorKind::InvalidAudience
        | ErrorKind::MissingRequiredClaim(_) => IdpVerifyError::Verification(e.to_string()),
        _ => IdpVerifyError::Malformed(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde::Serialize;

    // Throwaway EC P-256 keypair generated solely for these tests
    // (`openssl ecparam -genkey -name prime256v1`). NOT used anywhere in
    // production — the real key is resolved from the IdP's JWKS.
    const TEST_EC_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/cMFpcJsolBgFOlZ
vzaoxlWrL34DXi590Q6YbUlWd46hRANCAATG5fYBBV7BWx9mONRN4cKfQB6xqdlM
heWXRko1Gm2FyFpjjFQWWLNw425FE+m3lCoelUdEpmZNLvP/eJA0+eY+
-----END PRIVATE KEY-----";
    const TEST_EC_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExuX2AQVewVsfZjjUTeHCn0AesanZ
TIXll0ZKNRpthchaY4xUFlizcONuRRPpt5QqHpVHRKZmTS7z/3iQNPnmPg==
-----END PUBLIC KEY-----";

    const ISS: &str = "https://acme.okta.com";
    const AUD: &str = "proxilion";

    #[derive(Serialize)]
    struct Claims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        nbf: Option<i64>,
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn enc_key() -> EncodingKey {
        EncodingKey::from_ec_pem(TEST_EC_PRIV_PEM.as_bytes()).unwrap()
    }

    fn dec_key() -> DecodingKey {
        DecodingKey::from_ec_pem(TEST_EC_PUB_PEM.as_bytes()).unwrap()
    }

    fn cfg() -> IdpVerifyConfig {
        // Allow only ES256 so the HS256-confusion fixture is rejected by
        // the allow-list, not merely by a key-type mismatch.
        let mut c = IdpVerifyConfig::new(ISS, AUD);
        c.algorithms = vec![Algorithm::ES256];
        c
    }

    fn sign_es256(claims: &Claims) -> String {
        encode(&Header::new(Algorithm::ES256), claims, &enc_key()).unwrap()
    }

    fn valid_claims() -> Claims {
        Claims {
            iss: ISS.into(),
            sub: "user-123".into(),
            aud: AUD.into(),
            exp: now() + 300,
            nbf: None,
        }
    }

    #[test]
    fn accepts_valid_signed_token_and_binds_principal() {
        let token = sign_es256(&valid_claims());
        let id = verify_id_token(&token, &dec_key(), &cfg()).unwrap();
        assert_eq!(id.principal, format!("oidc:{ISS}#user-123"));
        assert_eq!(id.issuer, ISS);
        assert_eq!(id.subject, "user-123");
    }

    #[test]
    fn rejects_tampered_payload() {
        // Flip a byte in the payload segment — signature no longer matches.
        let token = sign_es256(&valid_claims());
        let parts: Vec<&str> = token.split('.').collect();
        let mut payload = parts[1].to_string();
        // Mutate the last char to a different base64url char.
        let last = payload.pop().unwrap();
        payload.push(if last == 'A' { 'B' } else { 'A' });
        let tampered = format!("{}.{}.{}", parts[0], payload, parts[2]);
        let err = verify_id_token(&tampered, &dec_key(), &cfg()).unwrap_err();
        assert!(
            matches!(
                err,
                IdpVerifyError::Verification(_) | IdpVerifyError::Malformed(_)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_alg_none() {
        // Hand-craft an `alg:none` token: jsonwebtoken cannot encode it.
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        let header = B64.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let body = B64.encode(serde_json::to_vec(&valid_claims()).unwrap());
        let token = format!("{header}.{body}.");
        let err = verify_id_token(&token, &dec_key(), &cfg()).unwrap_err();
        assert!(
            matches!(
                err,
                IdpVerifyError::DisallowedAlgorithm | IdpVerifyError::Malformed(_)
            ),
            "alg:none must be rejected, got {err:?}"
        );
    }

    #[test]
    fn rejects_rs256_to_hs256_confusion() {
        // Attacker signs with HS256 using the (public) EC key bytes as the
        // HMAC secret, hoping the verifier trusts the token's `alg`. With
        // the allow-list pinned to ES256, decode rejects on algorithm.
        let claims = valid_claims();
        let hs_key = EncodingKey::from_secret(TEST_EC_PUB_PEM.as_bytes());
        let token = encode(&Header::new(Algorithm::HS256), &claims, &hs_key).unwrap();
        let err = verify_id_token(&token, &dec_key(), &cfg()).unwrap_err();
        assert_eq!(err, IdpVerifyError::DisallowedAlgorithm);
    }

    #[test]
    fn rejects_expired_token() {
        let mut c = valid_claims();
        c.exp = now() - 120; // expired well beyond the 60 s leeway
        let token = sign_es256(&c);
        let err = verify_id_token(&token, &dec_key(), &cfg()).unwrap_err();
        assert!(
            matches!(err, IdpVerifyError::Verification(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_not_yet_valid_token() {
        let mut c = valid_claims();
        c.nbf = Some(now() + 3600); // not valid for an hour
        let token = sign_es256(&c);
        let err = verify_id_token(&token, &dec_key(), &cfg()).unwrap_err();
        assert!(
            matches!(err, IdpVerifyError::Verification(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_untrusted_issuer() {
        let mut c = valid_claims();
        c.iss = "https://evil.example.com".into();
        let token = sign_es256(&c);
        let err = verify_id_token(&token, &dec_key(), &cfg()).unwrap_err();
        assert!(
            matches!(
                err,
                IdpVerifyError::UntrustedIssuer | IdpVerifyError::Verification(_)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_wrong_audience() {
        let mut c = valid_claims();
        c.aud = "some-other-app".into();
        let token = sign_es256(&c);
        let err = verify_id_token(&token, &dec_key(), &cfg()).unwrap_err();
        assert!(
            matches!(err, IdpVerifyError::Verification(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_config_with_symmetric_algorithm() {
        // A misconfigured allow-list containing HS* must be refused before
        // any token is admitted — defense against an operator footgun.
        let token = sign_es256(&valid_claims());
        let mut c = cfg();
        c.algorithms = vec![Algorithm::ES256, Algorithm::HS256];
        assert_eq!(
            verify_id_token(&token, &dec_key(), &c).unwrap_err(),
            IdpVerifyError::DisallowedAlgorithm
        );
    }

    #[test]
    fn rejects_empty_algorithm_allow_list() {
        let token = sign_es256(&valid_claims());
        let mut c = cfg();
        c.algorithms = vec![];
        assert_eq!(
            verify_id_token(&token, &dec_key(), &c).unwrap_err(),
            IdpVerifyError::DisallowedAlgorithm
        );
    }

    #[test]
    fn leeway_is_clamped_to_max() {
        // Even if an operator sets an absurd leeway, the verifier clamps to
        // MAX_LEEWAY_SECS so a token expired by > 60 s is still rejected.
        let mut c = cfg();
        c.leeway_secs = 100_000;
        let mut claims = valid_claims();
        claims.exp = now() - 600; // 10 min ago — outside the 60 s clamp
        let token = sign_es256(&claims);
        let err = verify_id_token(&token, &dec_key(), &c).unwrap_err();
        assert!(
            matches!(err, IdpVerifyError::Verification(_)),
            "got {err:?}"
        );
    }
}
