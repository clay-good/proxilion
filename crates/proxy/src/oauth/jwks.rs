//! JWKS fetch + cache + `kid` resolution for in-process federation
//! (production-readiness.md PR-1, Approach A).
//!
//! [`JwksResolver`] turns an IdP's `jwks_uri` + a token's `kid` into the
//! [`DecodingKey`] that [`super::idp_verify::verify_id_token`] verifies
//! against. It satisfies the PR-1 "JWKS hygiene" invariants:
//!
//! - **TLS only.** The HTTP source refuses any non-`https://` `jwks_uri`.
//! - **Cached with a TTL** aligned to the IdP rotation cadence.
//! - **Refreshed on an unknown `kid`** (key rotation), but at most once per
//!   throttle window per endpoint, with a negative result after that — so a
//!   storm of tokens bearing an unknown `kid` cannot turn into a
//!   thundering-herd DoS against the IdP's JWKS endpoint.
//! - **Fail-closed.** Every path returns a typed [`JwksError`]; there is no
//!   "couldn't resolve, trust anyway" branch.
//!
//! The fetch is behind the [`JwksSource`] trait so the cache/rotation/
//! throttle logic is unit-tested without a network or a mock HTTP server;
//! [`HttpJwksSource`] is the production reqwest-backed implementation.

#![allow(dead_code)] // wired into the callback flow in the next PR-1 slice

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::JwkSet;
use moka::future::Cache;

/// How long a fetched JWKS is trusted before a routine re-fetch. One hour
/// matches the common IdP rotation cadence (upstream `provenance-bridge`
/// uses the same); an unknown `kid` forces an early refresh regardless.
const JWKS_TTL: Duration = Duration::from_secs(3600);

/// Minimum gap between *forced* refreshes triggered by an unknown `kid` for
/// a given endpoint. Bounds JWKS QPS against the IdP under a flood of
/// unknown-`kid` tokens (RFC 9700 / the PR-1 thundering-herd note).
const UNKNOWN_KID_REFRESH_THROTTLE: Duration = Duration::from_secs(60);

/// Upper bound on cached distinct JWKS endpoints (one per trusted issuer in
/// practice; the cap is a memory backstop).
const MAX_CACHED_ENDPOINTS: u64 = 256;

/// Fail-closed JWKS resolution outcomes.
#[derive(Debug, thiserror::Error)]
pub enum JwksError {
    /// The JWKS could not be fetched (network, TLS, non-2xx, or bad JSON),
    /// or the `jwks_uri` was not `https://`.
    #[error("jwks fetch failed: {0}")]
    Fetch(String),
    /// The token's `kid` is not present in the (freshly-refreshed) JWKS.
    #[error("no key with kid {0:?} in jwks")]
    UnknownKid(String),
    /// A JWK matched the `kid` but could not be turned into a verifying key.
    #[error("invalid jwk for kid {kid:?}: {reason}")]
    InvalidJwk { kid: String, reason: String },
}

/// Source of JWKS documents. Abstracted so the resolver's cache/rotation
/// logic is testable without HTTP; production uses [`HttpJwksSource`].
#[async_trait::async_trait]
pub trait JwksSource: Send + Sync {
    async fn fetch(&self, jwks_uri: &str) -> Result<JwkSet, JwksError>;
}

/// Production JWKS source: fetches over HTTPS with a bounded client.
pub struct HttpJwksSource {
    http: reqwest::Client,
}

impl HttpJwksSource {
    pub fn new(http: reqwest::Client) -> Self {
        Self { http }
    }
}

#[async_trait::async_trait]
impl JwksSource for HttpJwksSource {
    async fn fetch(&self, jwks_uri: &str) -> Result<JwkSet, JwksError> {
        // JWKS hygiene: discovery/JWKS fetches over TLS only. Reject a
        // plaintext URI before any request so a misconfiguration can't
        // ship keys over the wire in the clear.
        if !jwks_uri.starts_with("https://") {
            return Err(JwksError::Fetch(format!(
                "jwks_uri must be https://, got {jwks_uri:?}"
            )));
        }
        let resp = self
            .http
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| JwksError::Fetch(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(JwksError::Fetch(format!("status {}", resp.status())));
        }
        resp.json::<JwkSet>()
            .await
            .map_err(|e| JwksError::Fetch(format!("decode: {e}")))
    }
}

/// Caches JWKS per endpoint and resolves a `kid` to a [`DecodingKey`],
/// refreshing once (throttled) on an unknown `kid` to follow rotation.
pub struct JwksResolver {
    source: Arc<dyn JwksSource>,
    cache: Cache<String, Arc<JwkSet>>,
    /// Throttle gate: presence of an entry means "an unknown-`kid` refresh
    /// for this endpoint happened recently; don't refresh again yet."
    refresh_throttle: Cache<String, ()>,
}

impl JwksResolver {
    pub fn new(source: Arc<dyn JwksSource>) -> Self {
        Self {
            source,
            cache: Cache::builder()
                .time_to_live(JWKS_TTL)
                .max_capacity(MAX_CACHED_ENDPOINTS)
                .build(),
            refresh_throttle: Cache::builder()
                .time_to_live(UNKNOWN_KID_REFRESH_THROTTLE)
                .max_capacity(MAX_CACHED_ENDPOINTS)
                .build(),
        }
    }

    /// Construct the production resolver from a reqwest client.
    pub fn http(http: reqwest::Client) -> Self {
        Self::new(Arc::new(HttpJwksSource::new(http)))
    }

    /// Resolve `kid` at `jwks_uri` to a verifying key. Uses the cached JWKS
    /// when present; on a cache miss or an unknown `kid` it fetches/refreshes
    /// (the latter throttled per endpoint), and fails closed if the key is
    /// still absent.
    pub async fn resolve(&self, jwks_uri: &str, kid: &str) -> Result<DecodingKey, JwksError> {
        // 1. Use the cached set, fetching on a cold cache.
        let set = match self.cache.get(jwks_uri).await {
            Some(set) => set,
            None => {
                let set = Arc::new(self.source.fetch(jwks_uri).await?);
                self.cache.insert(jwks_uri.to_string(), set.clone()).await;
                set
            }
        };
        if let Some(jwk) = set.find(kid) {
            return decode_key(jwk, kid);
        }

        // 2. Unknown kid — the IdP may have rotated. Force a single refresh
        //    per throttle window, then fail closed if still unknown.
        if self.refresh_throttle.get(jwks_uri).await.is_some() {
            return Err(JwksError::UnknownKid(kid.to_string()));
        }
        self.refresh_throttle.insert(jwks_uri.to_string(), ()).await;
        let refreshed = Arc::new(self.source.fetch(jwks_uri).await?);
        self.cache
            .insert(jwks_uri.to_string(), refreshed.clone())
            .await;
        match refreshed.find(kid) {
            Some(jwk) => decode_key(jwk, kid),
            None => Err(JwksError::UnknownKid(kid.to_string())),
        }
    }
}

fn decode_key(jwk: &jsonwebtoken::jwk::Jwk, kid: &str) -> Result<DecodingKey, JwksError> {
    DecodingKey::from_jwk(jwk).map_err(|e| JwksError::InvalidJwk {
        kid: kid.to_string(),
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::idp_verify::{IdpVerifyConfig, verify_id_token};
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Matches the throwaway EC P-256 keypair in `idp_verify`'s tests; the
    // public half is published below as a JWK with kid "test-1".
    const TEST_EC_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/cMFpcJsolBgFOlZ
vzaoxlWrL34DXi590Q6YbUlWd46hRANCAATG5fYBBV7BWx9mONRN4cKfQB6xqdlM
heWXRko1Gm2FyFpjjFQWWLNw425FE+m3lCoelUdEpmZNLvP/eJA0+eY+
-----END PRIVATE KEY-----";

    const KID: &str = "test-1";
    const ISS: &str = "https://acme.okta.com";
    const AUD: &str = "proxilion";

    fn jwks_json(kid: &str) -> JwkSet {
        // The EC public key derived from TEST_EC_PRIV_PEM, as a JWK.
        serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": "xuX2AQVewVsfZjjUTeHCn0AesanZTIXll0ZKNRpthcg",
                "y": "WmOMVBZYs3DjbkUT6beUKh6VR0SmZk0u8_94kDT55j4",
                "kid": kid,
                "alg": "ES256",
                "use": "sig",
            }]
        }))
        .unwrap()
    }

    /// Fake source: returns a scripted JwkSet per call and counts fetches,
    /// so tests can assert caching (no refetch) and rotation (kid appears on
    /// a later fetch).
    struct ScriptedSource {
        responses: Vec<JwkSet>,
        calls: AtomicUsize,
    }
    impl ScriptedSource {
        fn new(responses: Vec<JwkSet>) -> Self {
            Self {
                responses,
                calls: AtomicUsize::new(0),
            }
        }
        fn count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    #[async_trait::async_trait]
    impl JwksSource for ScriptedSource {
        async fn fetch(&self, _uri: &str) -> Result<JwkSet, JwksError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            // Saturate at the last scripted response.
            let idx = n.min(self.responses.len() - 1);
            Ok(self.responses[idx].clone())
        }
    }

    #[derive(Serialize)]
    struct Claims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
    }

    fn signed_token(kid: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_string());
        let claims = Claims {
            iss: ISS.into(),
            sub: "user-1".into(),
            aud: AUD.into(),
            exp: chrono::Utc::now().timestamp() + 300,
        };
        let key = EncodingKey::from_ec_pem(TEST_EC_PRIV_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    const URL: &str = "https://idp.example.com/jwks";

    #[tokio::test]
    async fn resolves_kid_to_key_that_verifies_a_real_token() {
        // End-to-end: the resolved DecodingKey (built from the JWK) must
        // verify a token actually signed by the matching private key —
        // tying jwks resolution to idp_verify.
        let src = Arc::new(ScriptedSource::new(vec![jwks_json(KID)]));
        let resolver = JwksResolver::new(src);
        let key = resolver.resolve(URL, KID).await.unwrap();
        let id = verify_id_token(&signed_token(KID), &key, &{
            let mut c = IdpVerifyConfig::new(ISS, AUD);
            c.algorithms = vec![Algorithm::ES256];
            c
        })
        .unwrap();
        assert_eq!(id.principal, format!("oidc:{ISS}#user-1"));
    }

    #[tokio::test]
    async fn caches_jwks_across_calls() {
        let src = Arc::new(ScriptedSource::new(vec![jwks_json(KID)]));
        let resolver = JwksResolver::new(src.clone());
        resolver.resolve(URL, KID).await.unwrap();
        resolver.resolve(URL, KID).await.unwrap();
        resolver.resolve(URL, KID).await.unwrap();
        assert_eq!(src.count(), 1, "second/third resolve must hit the cache");
    }

    #[tokio::test]
    async fn unknown_kid_forces_one_refresh_then_picks_up_rotation() {
        // Call 1 caches a set WITHOUT the new kid; the unknown-kid path
        // forces exactly one refresh, which returns the rotated set WITH
        // the kid → resolves.
        let src = Arc::new(ScriptedSource::new(vec![
            jwks_json("old-kid"),
            jwks_json("rotated-kid"),
        ]));
        let resolver = JwksResolver::new(src.clone());
        let key = resolver.resolve(URL, "rotated-kid").await.unwrap();
        assert_eq!(src.count(), 2, "exactly one forced refresh on unknown kid");
        // And the refreshed key verifies a token signed under the rotated kid.
        let mut cfg = IdpVerifyConfig::new(ISS, AUD);
        cfg.algorithms = vec![Algorithm::ES256];
        assert!(verify_id_token(&signed_token("rotated-kid"), &key, &cfg).is_ok());
    }

    #[tokio::test]
    async fn unknown_kid_refresh_is_throttled_against_thundering_herd() {
        // The kid is never present. The first unknown-kid resolve forces a
        // refresh (2 fetches: cold + forced). Subsequent unknown-kid
        // resolves within the throttle window must NOT refetch.
        let src = Arc::new(ScriptedSource::new(vec![jwks_json("present-kid")]));
        let resolver = JwksResolver::new(src.clone());
        assert!(resolver.resolve(URL, "absent").await.is_err());
        let after_first = src.count();
        assert_eq!(after_first, 2, "cold fetch + one forced refresh");
        for _ in 0..5 {
            assert!(resolver.resolve(URL, "absent").await.is_err());
        }
        assert_eq!(
            src.count(),
            after_first,
            "throttle must suppress further forced refreshes"
        );
    }

    #[tokio::test]
    async fn http_source_rejects_non_https_uri() {
        let src = HttpJwksSource::new(reqwest::Client::new());
        let err = src.fetch("http://idp.example.com/jwks").await.unwrap_err();
        assert!(
            matches!(err, JwksError::Fetch(m) if m.contains("https")),
            "plaintext jwks_uri must be refused before any request"
        );
    }
}
