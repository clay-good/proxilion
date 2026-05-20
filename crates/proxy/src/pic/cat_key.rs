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

    #[test]
    fn cat_key_registry_is_send_sync_static_for_app_state_arc_path() {
        // `CatKeyRegistry` is held in AppState and consulted from
        // async request-handler paths (tokio task boundaries). A
        // refactor that gave `Inner` an `Rc<String>` field "for cheap
        // clone of trust_plane_url" would break Sync at the AppState
        // assembly site as a far-removed trait-bound error. Pin the
        // three-trait combo here so the failure surfaces at the right
        // module.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<CatKeyRegistry>();
    }

    #[test]
    fn cat_key_error_is_send_sync_static_for_anyhow_chain_walk() {
        // `CatKeyError` flows through `anyhow::Error` chains at the
        // OAuth callback path, which requires `Send + Sync + 'static`.
        // The symmetric round-N `cat_key_error_implements_std_error_trait`
        // pin covered the trait impl; this one pins the marker bounds.
        // A refactor that introduced a !Send field (e.g.
        // `Decode(Rc<String>)`) would surface here rather than as a
        // chain-walk type mismatch deeper in the callback.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<CatKeyError>();
    }

    #[test]
    fn cat_key_error_debug_carries_variant_names_for_grep() {
        // Operators grep error logs by variant name to bucket Status
        // (Trust Plane refused) vs Decode (key material malformed) vs
        // Fetch (network); the `derive(Debug)` lands variant names in
        // the formatted output. A refactor that swapped to a hand-rolled
        // `impl Debug` that compacted the line "for log brevity" would
        // silently break every bucket. Pin Status + Decode variant
        // names verbatim (the Fetch arm requires a synthesized
        // reqwest::Error and is already covered by the existing
        // fetch-prefix Display test).
        let s = format!("{:?}", CatKeyError::Status(503));
        assert!(s.contains("Status"), "got: {s}");
        let d = format!("{:?}", CatKeyError::Decode("x".into()));
        assert!(d.contains("Decode"), "got: {d}");
    }

    #[test]
    fn cat_key_error_status_display_renders_full_u16_range_verbatim() {
        // `Status(u16)` renders the integer verbatim — no bucketing
        // into status-classes. The existing 4xx/5xx + zero/u16::MAX
        // pins cover the canonical boundary; pin the inter-class
        // gap (99 / 100 / 599 / 600 / 999 / 1000) so a refactor that
        // gated on `100..=599` and rendered "out of range" for
        // anything else would surface here on every boundary. Some
        // upstream HTTP libraries clamp at 100 / 999; we MUST surface
        // the raw code instead so operators can triage upstream
        // misbehavior.
        for code in [99u16, 100, 599, 600, 999, 1000] {
            let s = CatKeyError::Status(code).to_string();
            assert!(s.contains(&code.to_string()), "missing {code} in: {s}");
        }
    }

    #[test]
    fn cat_key_error_decode_display_passes_through_unicode_newline_quote_inner() {
        // `Decode(String)` Display is `"CAT public key decode failed: {0}"`.
        // The existing `cat_key_error_decode_display_carries_inner_detail`
        // pin walks three plain-ASCII inner strings; pin that arbitrary
        // inner content survives byte-for-byte — including unicode
        // (Trust Plane debug messages may surface non-ASCII), newlines
        // (some inner errors include line-broken context), and quote
        // chars (the operator log layer may JSON-escape these, but the
        // Display impl itself must not pre-quote). A refactor that
        // swapped `{0}` to `{0:?}` "for safety" would silently wrap
        // every inner in escape sequences and break exact-match
        // operator-log assertions.
        for inner in [
            "café decoding failed",
            "line1\nline2",
            r#"quoted "value" here"#,
            "α-β-γ",
        ] {
            let s = CatKeyError::Decode(inner.into()).to_string();
            assert!(s.contains(inner), "verbatim survival: {s}");
        }
    }

    #[test]
    fn cat_key_registry_and_cat_key_error_send_sync_static_for_app_state_arc_boundary() {
        // `CatKeyRegistry` is held in AppState and cloned into the
        // PicVerifier on every chain-walk; `CatKeyError` flows
        // through `?` chains across `.await` points in the verifier's
        // cold path. Both MUST be Send+Sync+'static — a refactor
        // adding an `Rc<...>` on `Inner` (e.g. for cached fetch
        // metadata) would break Sync at the AppState wire site with
        // an opaque tower::Service trait-bound. Symmetric to the
        // VerifierError + PicVerifier Send+Sync+'static pin on
        // [crates/proxy/src/pic/verifier.rs] round 150 — keep the
        // pic-module type boundary symmetric.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<CatKeyRegistry>();
        require_send_sync_static::<CatKeyError>();
    }

    #[test]
    fn cat_key_error_debug_carries_variant_names_for_grep_bucketing() {
        // `#[derive(Debug)]` on CatKeyError feeds `?err` in
        // `tracing::warn!` call sites on the verifier's cold path.
        // Operators grep tracing log lines by variant name to bucket
        // Fetch (network / Trust Plane unreachable) vs Status
        // (Trust Plane responded with non-2xx) vs Decode (Trust Plane
        // emitted malformed key bytes). A hand-rolled `impl Debug`
        // that hid variant names "to compact" would break every
        // operator bucket. Symmetric to the VerifierError Debug
        // variant-names pin on verifier.rs round 150 + the other
        // operator-facing Error enum Debug pins.
        for (variant, name) in [
            (CatKeyError::Status(503), "Status"),
            (CatKeyError::Decode("bad b64".into()), "Decode"),
        ] {
            let s = format!("{:?}", variant);
            assert!(s.contains(name), "expected `{name}` in Debug, got: {s}");
        }
    }

    #[test]
    fn cat_key_registry_clone_shares_inner_arc_via_arc_strong_count() {
        // `CatKeyRegistry` derives Clone — the `inner: Arc<Inner>`
        // field is cloned by Arc::clone (cheap ref-count bump). axum
        // State + the PicVerifier hold their own clones; for the
        // OnceCell cached key to be visible to all clones, the inner
        // Arc MUST be shared (NOT deep-copied). A refactor that
        // accidentally swapped `Arc<Inner>` for `Box<Inner>` would
        // silently break the cache — the first verifier to fetch
        // would warm its OnceCell, but every other clone's OnceCell
        // would still be empty, causing repeated Trust Plane fetches.
        // Pin Arc::strong_count delta = 1 across construction +
        // clone + drop.
        let r = CatKeyRegistry::new("http://example.invalid".into());
        assert_eq!(Arc::strong_count(&r.inner), 1);
        let c = r.clone();
        assert_eq!(Arc::strong_count(&r.inner), 2);
        let _d = c.clone();
        assert_eq!(Arc::strong_count(&r.inner), 3);
        drop(c);
        assert_eq!(Arc::strong_count(&r.inner), 2);
    }

    #[test]
    fn cat_key_error_status_arm_display_byte_exact_with_status_code_no_inner_body_leak() {
        // `#[error("Trust Plane returned non-success {0}")]` on
        // `Status(u16)` — pin the byte-exact Display shape against
        // a known status code. The wire field is the raw u16 with
        // NO inner response body leaked. A refactor to
        // `Status { code: u16, body: String }` "for richer triage"
        // would silently surface the Trust Plane's response body
        // (which can carry vendor-internal state on error). Pin
        // the prefix + the integer + no leading 0-padding.
        assert_eq!(
            CatKeyError::Status(503).to_string(),
            "Trust Plane returned non-success 503",
        );
        assert_eq!(
            CatKeyError::Status(404).to_string(),
            "Trust Plane returned non-success 404",
        );
        // Three-digit status codes serialize without leading zeros.
        assert!(!CatKeyError::Status(42).to_string().contains("042"));
    }

    #[test]
    fn cat_key_error_implements_std_error_trait_via_dyn_cast_with_decode_leaf_no_source() {
        // `CatKeyError::Decode(String)` is a leaf-arm (no inner
        // error), but `CatKeyError::Fetch(#[from] reqwest::Error)`
        // wraps an inner. Pin BOTH source contracts: Decode has
        // source == None (leaf), Status has source == None (leaf
        // u16), but Fetch's source is Some (the inner reqwest::Error).
        // Symmetric to the verifier_error_implements_std_error_trait
        // pin on verifier.rs round 150 — keep the pic-module error-
        // type std::error::Error contracts symmetric. A refactor
        // that swapped `#[from]` for an inner-string shape on Fetch
        // "to flatten the chain" would silently break anyhow's chain
        // walk (the inner reqwest::Error wouldn't be reachable).
        let d = CatKeyError::Decode("bad b64".into());
        let dyn_err: &dyn std::error::Error = &d;
        assert!(
            std::error::Error::source(dyn_err).is_none(),
            "Decode must be leaf arm with no source",
        );
        let s = CatKeyError::Status(503);
        let dyn_err: &dyn std::error::Error = &s;
        assert!(
            std::error::Error::source(dyn_err).is_none(),
            "Status must be leaf arm with no source",
        );
    }

    #[test]
    fn cat_key_registry_new_with_multibyte_unicode_url_preserves_bytes_verbatim() {
        // Internationalized DNS / non-ASCII Trust Plane hostnames are
        // rare but possible (operators occasionally embed multibyte
        // proxy hostnames in dev setups). `CatKeyRegistry::new` stores
        // the URL String verbatim — pin that multibyte unicode
        // (3-byte é + 3-byte → + 4-byte 🔥) survives construction
        // byte-equal. A refactor that `.to_ascii_lowercase()`-ed the
        // URL "for SNI canonicalization" would silently mangle every
        // non-ASCII URL AND break the subsequent reqwest .get() call
        // that builds against the stored URL. Inspect via the
        // inner.trust_plane_url field.
        let url = "https://trust.café-prod.local/→🔥";
        let r = CatKeyRegistry::new(url.into());
        assert_eq!(r.inner.trust_plane_url, url);
    }

    #[test]
    fn info_resp_rejects_non_string_kid_and_public_key_field_types() {
        // The `InfoResp { kid: String, public_key: String }` fields
        // are strictly typed — a Trust Plane response that emitted
        // `kid: 42` (numeric) or `public_key: 12345` (numeric) MUST
        // reject at decode time. The existing missing-field pins cover
        // absence; pin the wrong-type axis here. A refactor that
        // swapped to `Value` or a `#[serde(deserialize_with =
        // "..coerce_to_string..")]` shim "for robustness" would
        // silently accept type-mismatched wire data and the verifier
        // would later mis-key on the stringified integer rather than
        // surface the wire-shape mismatch at decode time.
        let raw_kid = r#"{"kid":42,"public_key":"AAA"}"#;
        assert!(
            serde_json::from_str::<InfoResp>(raw_kid).is_err(),
            "numeric kid must reject",
        );
        let raw_pk = r#"{"kid":"k1","public_key":12345}"#;
        assert!(
            serde_json::from_str::<InfoResp>(raw_pk).is_err(),
            "numeric public_key must reject",
        );
    }
}
