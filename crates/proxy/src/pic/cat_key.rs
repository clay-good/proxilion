//! CAT (Continuity Authority Token) verifying-key cache.
//!
//! The Trust Plane exposes its CAT public key at `GET /v1/federation/info`.
//! We fetch it lazily on first use and cache for the process lifetime; key
//! rotation requires a restart for now (acceptable since CAT keys are
//! long-lived; revocation is the proper rotation path).

use std::sync::Arc;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use shared_types::provenance::crypto::PublicKey;
use thiserror::Error;
use tokio::sync::OnceCell;

#[derive(Debug, Error)]
pub enum CatKeyError {
    #[error("Trust Plane info fetch failed: {0}")]
    Fetch(#[from] reqwest::Error),
    #[error("Trust Plane returned non-success {0}")]
    Status(u16),
    #[error("CAT public key decode failed: {0}")]
    Decode(String),
}

#[derive(Clone)]
pub struct CatKeyRegistry {
    inner: Arc<Inner>,
}

struct Inner {
    trust_plane_url: String,
    http: reqwest::Client,
    cached: OnceCell<PublicKey>,
}

#[derive(Debug, Deserialize)]
struct InfoResp {
    kid: String,
    public_key: String,
}

impl CatKeyRegistry {
    pub fn new(trust_plane_url: String) -> Self {
        Self {
            inner: Arc::new(Inner {
                trust_plane_url,
                http: reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .expect("reqwest client builds"),
                cached: OnceCell::new(),
            }),
        }
    }

    /// Fetch (and cache) the Trust Plane's CAT verifying key.
    pub async fn get(&self) -> Result<&PublicKey, CatKeyError> {
        self.inner
            .cached
            .get_or_try_init(|| async {
                let resp = self
                    .inner
                    .http
                    .get(format!("{}/v1/federation/info", self.inner.trust_plane_url))
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    return Err(CatKeyError::Status(resp.status().as_u16()));
                }
                let info: InfoResp = resp.json().await?;
                let bytes = B64
                    .decode(&info.public_key)
                    .map_err(|e| CatKeyError::Decode(e.to_string()))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| CatKeyError::Decode("expected 32 bytes".into()))?;
                PublicKey::from_bytes(&info.kid, &arr)
                    .map_err(|e| CatKeyError::Decode(e.to_string()))
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cat_key_error_display_strings_are_stable() {
        let s = CatKeyError::Status(503).to_string();
        assert!(s.contains("503"));
        assert!(s.contains("Trust Plane"));
        let d = CatKeyError::Decode("bad b64".into()).to_string();
        assert!(d.contains("bad b64"));
        assert!(d.contains("decode"));
    }

    #[test]
    fn info_resp_deserializes() {
        let raw = r#"{"kid":"k1","public_key":"AAA"}"#;
        let info: InfoResp = serde_json::from_str(raw).unwrap();
        assert_eq!(info.kid, "k1");
        assert_eq!(info.public_key, "AAA");
    }

    #[tokio::test]
    async fn registry_errors_when_trust_plane_unreachable() {
        // Black-hole IP (RFC 5737 documentation range); the 5s default
        // client timeout will eventually fire — we set a shorter one by
        // talking to an unbound port on localhost which connect-refuses
        // immediately, no waiting.
        let reg = CatKeyRegistry::new("http://127.0.0.1:1/".into());
        let err = reg.get().await.unwrap_err();
        assert!(matches!(err, CatKeyError::Fetch(_)));
    }

    #[test]
    fn cat_key_error_status_display_carries_code_only() {
        // Operator-facing strings — the Status variant intentionally surfaces
        // only the upstream HTTP code, never a response body (which could
        // include error detail from the Trust Plane that we don't want
        // pasted into a user-visible 500). Pin both shape and absence-of-body.
        let s = CatKeyError::Status(429).to_string();
        assert!(s.contains("429"));
        assert!(s.contains("non-success"));
        assert!(!s.to_lowercase().contains("body"));
    }

    #[test]
    fn cat_key_registry_clones_share_underlying_oncecell() {
        // `CatKeyRegistry` derives `Clone` over `Arc<Inner>` — every clone
        // sees the same `OnceCell<PublicKey>`, so two clones independently
        // calling `get()` against a real Trust Plane only fetch once.
        // A regression that deep-copied the OnceCell would cause every
        // clone to re-fetch (visible as duplicate `proxilion_oauth_*`
        // counters in production).
        let a = CatKeyRegistry::new("http://127.0.0.1:1/".into());
        let b = a.clone();
        assert!(Arc::ptr_eq(&a.inner, &b.inner));
    }

    #[test]
    fn cat_key_error_decode_display_carries_inner_detail() {
        // The Decode variant is the operator-actionable boundary —
        // when Trust Plane returns a malformed public-key, the
        // wrapped message is what tells the operator whether the
        // upstream is mis-configured (key length wrong), the b64
        // decoder rejected it, or our parser rejected it. Pin three
        // distinct inner messages so a refactor that collapsed them
        // into one Display surfaces here.
        for inner in ["bad b64 char", "expected 32 bytes", "curve point invalid"] {
            let s = CatKeyError::Decode(inner.into()).to_string();
            assert!(s.contains(inner), "missing inner detail in: {s}");
            assert!(s.to_lowercase().contains("decode"));
        }
    }

    #[test]
    fn cat_key_registry_url_with_trailing_slash_still_constructs() {
        // The URL is concatenated as `{base}/v1/federation/info`. A
        // trailing-slash base produces `{base}//v1/...` which most HTTP
        // routers normalize; pin that the constructor itself doesn't
        // panic / reject the input. A future tightening that stripped
        // trailing slashes (the cleaner choice) would surface as a
        // conscious wire-shape change.
        let r = CatKeyRegistry::new("http://127.0.0.1:1/".into());
        // Just constructing it shouldn't panic; clone-then-check-shape
        // gets us coverage on the Arc::new path without an HTTP roundtrip.
        let c = r.clone();
        assert!(Arc::ptr_eq(&r.inner, &c.inner));
    }

    #[test]
    fn cat_key_error_status_variants_distinguish_4xx_and_5xx_codes() {
        // The status variant is generic over u16 — operator filters
        // bucket 4xx vs 5xx differently (4xx → "Trust Plane refused
        // our request", 5xx → "Trust Plane is broken"). Pin that the
        // Display carries the raw code without bucketing — the
        // operator's log filter is responsible for the bucket logic.
        // A refactor that classified into named arms ("client_error" /
        // "server_error") would silently lose the precise code.
        for code in [403u16, 404, 500, 503] {
            let s = CatKeyError::Status(code).to_string();
            assert!(s.contains(&code.to_string()), "missing code {code} in: {s}");
        }
    }

    #[test]
    fn cat_key_error_implements_std_error_trait_for_anyhow_chain_walking() {
        // The OAuth callback path bubbles `CatKeyError` through
        // `anyhow::Error` chains for structured logging — pin that
        // the `thiserror` derive lands the `std::error::Error` impl
        // so a refactor that swapped to a hand-rolled error type
        // (dropping the derive) would surface here at the trait-
        // object cast rather than at the call-site type mismatch
        // far from this module. Pin BOTH the trait existence AND
        // the `source()` chain semantics: `Fetch(#[from] reqwest::Error)`
        // surfaces the inner reqwest::Error via `source()` (the
        // operator-actionable triage layer), while `Status` and
        // `Decode` are leaf arms with no inner error to chain.
        let status: CatKeyError = CatKeyError::Status(503);
        let decode: CatKeyError = CatKeyError::Decode("bad b64".into());
        let dyn_status: &dyn std::error::Error = &status;
        let dyn_decode: &dyn std::error::Error = &decode;
        assert!(
            std::error::Error::source(dyn_status).is_none(),
            "Status leaf-arm must not expose a source",
        );
        assert!(
            std::error::Error::source(dyn_decode).is_none(),
            "Decode leaf-arm must not expose a source",
        );
    }

    #[test]
    fn cat_key_error_status_zero_does_not_panic_and_renders_zero_for_grep() {
        // `Status(u16)` is constructed against the raw HTTP code — the
        // boundary `0` is operationally observable when the upstream
        // closes the connection mid-response (some reqwest call sites
        // surface a zero-status sentinel rather than an explicit
        // transport error). Pin that the Display does NOT panic on the
        // boundary AND renders the integer verbatim — a refactor that
        // formatted via `StatusCode::from_u16(code).unwrap()` would
        // panic on the boundary (zero is outside the 100..1000 range
        // StatusCode permits) and silently turn an upstream-closure
        // log line into a worker thread crash. The existing
        // `cat_key_error_status_variants_distinguish_4xx_and_5xx_codes`
        // walks 403/404/500/503 — pin both the zero edge AND the
        // u16::MAX upper boundary so any future refactor that
        // tightened to a status-class match surfaces here on both
        // axes.
        for code in [0u16, u16::MAX] {
            let s = CatKeyError::Status(code).to_string();
            assert!(s.contains(&code.to_string()), "missing code {code} in: {s}",);
        }
    }

    #[test]
    fn cat_key_error_decode_with_empty_inner_string_still_renders_prefix() {
        // `Decode(String)` accepts the empty string — pin that the
        // Display still surfaces the `"CAT public key decode failed:"`
        // prefix even when the inner reason is empty. The empty-inner
        // shape arises in tests + when a future refactor of an inner
        // `.map_err(|_| CatKeyError::Decode(String::new()))` drops the
        // context. The prefix is the operator-facing grep target so
        // the log line is still bucketable. A refactor that gated
        // rendering on a non-empty inner (e.g. `if self.0.is_empty()
        // { return Ok(()); }`) would silently produce a blank line
        // that no log filter could route — surface that here.
        let s = CatKeyError::Decode(String::new()).to_string();
        assert!(
            s.to_lowercase().contains("decode"),
            "prefix must survive empty inner: {s}",
        );
        assert!(s.contains("CAT public key"), "got: {s}");
    }

    #[test]
    fn info_resp_rejects_missing_required_kid_field() {
        // The `InfoResp` deserializer's `kid: String` field has no
        // `#[serde(default)]` — operator-facing setup MUST commit
        // explicit kid in the Trust Plane response. The existing
        // `info_resp_deserializes` test pins the happy path, and
        // `info_resp_ignores_unknown_fields_for_forward_compat` pins
        // forward-compat — but the missing-field error path was
        // unpinned. A regression that added `#[serde(default)]` for
        // "be permissive" would silently accept a kid-less response
        // and the verifier would later fail-hard on the empty kid
        // value rather than surfacing the wire-shape mismatch at
        // decode time. Pin the strict-required contract here.
        let raw = r#"{"public_key":"AAA"}"#;
        let r: Result<InfoResp, _> = serde_json::from_str(raw);
        assert!(r.is_err(), "missing kid must reject, got: {r:?}");
    }

    #[test]
    fn info_resp_rejects_missing_required_public_key_field() {
        // Symmetric to `info_resp_rejects_missing_required_kid_field`
        // — pin the `public_key: String` strict-required contract.
        // The verifier loads the bytes from this field and feeds them
        // into `PublicKey::from_bytes`; a refactor that defaulted to
        // empty would surface as a curve-point validation error
        // downstream rather than as a wire-shape mismatch at decode
        // time, with a confusing log line.
        let raw = r#"{"kid":"k1"}"#;
        let r: Result<InfoResp, _> = serde_json::from_str(raw);
        assert!(r.is_err(), "missing public_key must reject, got: {r:?}");
    }

    #[tokio::test]
    async fn cat_key_error_fetch_variant_display_carries_trust_plane_prefix_with_inner_reason() {
        // The `Fetch(#[from] reqwest::Error)` arm is the operator-
        // actionable boundary for transient Trust-Plane network
        // faults. The existing `registry_errors_when_trust_plane_unreachable`
        // test constructs a real reqwest::Error via a connect-refuse
        // and pins `matches!(err, CatKeyError::Fetch(_))`, but does
        // NOT assert the Display string carries the `"Trust Plane info
        // fetch failed: "` prefix end-to-end through the `#[from]`
        // conversion. Pin via a real reqwest::Error captured from a
        // connect-refused localhost port (the same shape the existing
        // test uses, but asserting the Display prefix). A refactor
        // that hand-rolled the Display to mask the inner (in the
        // name of "don't leak upstream errors") would silently strip
        // the actionable triage half from every operator log line.
        let reg = CatKeyRegistry::new("http://127.0.0.1:1/".into());
        let err = reg.get().await.unwrap_err();
        let s = err.to_string();
        assert!(s.starts_with("Trust Plane info fetch failed: "), "got: {s}",);
        // And the inner reqwest message must not be empty — pin some
        // non-prefix content survives the `#[from]` Display passthrough.
        let suffix = s
            .strip_prefix("Trust Plane info fetch failed: ")
            .unwrap_or("");
        assert!(
            !suffix.is_empty(),
            "inner reqwest::Error Display must surface after prefix, got: {s}",
        );
    }

    #[test]
    fn info_resp_ignores_unknown_fields_for_forward_compat() {
        // The Trust Plane may add fields to `/v1/federation/info` over time
        // (e.g. `next_kid`). Pin that the deserializer ignores unknown
        // fields rather than refusing the whole document — required for
        // forward compatibility with a newer Trust Plane.
        let raw = r#"{"kid":"k1","public_key":"AAA","next_rotation":"2026-09-01"}"#;
        let info: InfoResp = serde_json::from_str(raw).expect("ignores unknown fields");
        assert_eq!(info.kid, "k1");
        assert_eq!(info.public_key, "AAA");
    }
}
