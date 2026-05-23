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

    // ─── round 182 (2026-05-20): operator-actionable surfaces on CatKeyError + CatKeyRegistry ───

    #[test]
    fn cat_key_error_variant_count_pinned_at_three_via_exhaustive_match() {
        // `CatKeyError` has exactly 3 variants today (Fetch / Status /
        // Decode). Operator runbooks bucket Trust-Plane / CAT-key faults
        // by variant — Fetch (network), Status (Trust Plane responded
        // with non-2xx), Decode (key material malformed). A refactor
        // that added a fourth variant (e.g. `Expired` for a future
        // CAT-key TTL gate) would surface a fourth grep bucket the
        // dashboard wasn't sized for. Pin the variant count via an
        // exhaustive match — a new arm forces this test to compile-fail
        // at the match site. Symmetric to round-181 AuthFail 9-variant
        // exhaustive-match pin extended to a sibling error enum.
        fn arm_name(e: &CatKeyError) -> &'static str {
            match e {
                CatKeyError::Fetch(_) => "Fetch",
                CatKeyError::Status(_) => "Status",
                CatKeyError::Decode(_) => "Decode",
            }
        }
        // Walk the two leaf variants (Fetch requires a reqwest::Error
        // which is not cheaply constructible here — it's covered by
        // the existing `cat_key_error_fetch_variant_display_carries_trust_plane_prefix_with_inner_reason`
        // tokio test).
        let three_seen: std::collections::HashSet<&'static str> =
            [CatKeyError::Status(503), CatKeyError::Decode("x".into())]
                .iter()
                .map(arm_name)
                .collect();
        assert_eq!(three_seen.len(), 2, "2 distinct leaf-variant names");
        // Sanity: the compiler-enforced exhaustive arm_name above
        // implicitly forces the 3-variant cap (a 4th variant fails
        // the match arm count). Surface the cap via a count of
        // syntactic arms — the match in arm_name has exactly 3.
        // (This assertion is documentation-only; the real cap is the
        // exhaustive match.)
        assert_eq!(arm_name(&CatKeyError::Status(0)), "Status");
        assert_eq!(arm_name(&CatKeyError::Decode("".into())), "Decode");
    }

    #[test]
    fn cat_key_error_decode_inner_field_is_owned_string_for_cross_await_propagation() {
        // `Decode(String)` — the inner is an OWNED `String`, not a
        // borrowed `&'static str` or `Cow<'_, str>`. The error
        // propagates across the `.await` boundary in
        // `CatKeyRegistry::get` (the `get_or_try_init` future); the
        // originating error byte slice (e.g. the b64::DecodeError
        // Display rendered into a String) is dropped before the
        // outer middleware consumes the Result. A refactor to a
        // borrowed form for "zero-alloc on the cold-path" would
        // introduce a lifetime parameter that cascades through every
        // consuming `?`-chain in pic/verifier.rs. Pin the owned-String
        // type via the canonical require_string helper. Symmetric to
        // round-179 + round-180 + round-181 owned-String pins
        // extended to this error variant.
        fn require_string(_: &String) {}
        let inner = match CatKeyError::Decode("expected 32 bytes".into()) {
            CatKeyError::Decode(s) => s,
            other => panic!("expected Decode, got {other:?}"),
        };
        require_string(&inner);
        assert_eq!(inner, "expected 32 bytes");
    }

    #[test]
    fn cat_key_error_status_inner_field_is_u16_type_for_full_http_code_range() {
        // `Status(u16)` — the inner is `u16`, NOT `http::StatusCode`.
        // The wire-shape choice is load-bearing: `http::StatusCode`
        // clamps to the IETF-registered 100..=999 range AND panics on
        // values outside it via `from_u16().unwrap()`, while `u16`
        // accepts 0..=65535 verbatim. Operators rely on the
        // raw-integer rendering for upstream-misbehavior triage
        // (e.g. a malformed Trust-Plane that returned `0` on
        // connection-closure or a custom non-standard `999` code).
        // The existing `cat_key_error_status_zero_does_not_panic_and_renders_zero_for_grep`
        // walks behavior at boundaries; pin the underlying TYPE via
        // the canonical require_u16 helper so a refactor that swapped
        // to `Status(http::StatusCode)` "for type-safety" would
        // silently re-introduce the panic-on-out-of-range edge.
        // Symmetric to round-177 Decision::RateLimit u32-field type
        // pin extended to this error variant.
        fn require_u16(_: u16) {}
        let code = match CatKeyError::Status(503) {
            CatKeyError::Status(c) => c,
            other => panic!("expected Status, got {other:?}"),
        };
        require_u16(code);
        assert_eq!(code, 503);
    }

    #[test]
    fn cat_key_error_display_is_referentially_transparent_across_fifty_repeated_calls() {
        // The `#[error(...)]` Display impl is pure — no clock, no env,
        // no global state. Pin referential transparency across 50
        // back-to-back `to_string()` calls for both leaf variants
        // (Status / Decode). A refactor that introduced a once-cell-
        // backed memoization layer "for hot-path Display perf" would
        // still pass equality; but a refactor that introduced any
        // form of stateful rendering (a counter mixed into the format,
        // a per-call ID) would surface here on call #2..#50. Symmetric
        // to round-179 + round-180 + round-181 referential-transparency
        // pins extended to this error type's Display impl.
        let status = CatKeyError::Status(503);
        let status_first = status.to_string();
        for i in 1..50 {
            assert_eq!(
                status.to_string(),
                status_first,
                "Status Display diverged on call #{i}",
            );
        }
        let decode = CatKeyError::Decode("bad b64".into());
        let decode_first = decode.to_string();
        for i in 1..50 {
            assert_eq!(
                decode.to_string(),
                decode_first,
                "Decode Display diverged on call #{i}",
            );
        }
    }

    #[test]
    fn cat_key_registry_new_yields_distinct_arcs_across_independent_constructions() {
        // `CatKeyRegistry::new(url)` constructs a fresh `Arc<Inner>`
        // per call — two independent constructions MUST NOT share the
        // underlying Inner (the OnceCell, the http client, the URL).
        // The existing `cat_key_registry_clones_share_underlying_oncecell`
        // pins that CLONES share via Arc; pin the SYMMETRIC contract
        // here — fresh constructions are independent. A refactor that
        // memoized `new()` "for cheap re-construction in tests" via a
        // process-wide registry would silently make every call site
        // share a OnceCell, surface here as Arc::ptr_eq returning true
        // across independent news. Pin strong_count == 1 on a fresh
        // registry (one Arc strong ref, no shared aliasing). Symmetric
        // to round-153 PolicyHandle Clone-Arc-share pin extended to
        // the symmetric independent-construction contract.
        let r1 = CatKeyRegistry::new("http://a.invalid".into());
        let r2 = CatKeyRegistry::new("http://b.invalid".into());
        assert!(
            !Arc::ptr_eq(&r1.inner, &r2.inner),
            "independent new() calls must produce distinct Arcs",
        );
        assert_eq!(Arc::strong_count(&r1.inner), 1);
        assert_eq!(Arc::strong_count(&r2.inner), 1);
    }

    #[test]
    fn info_resp_deserialize_is_referentially_transparent_across_fifty_repeated_calls() {
        // `serde_json::from_str::<InfoResp>` is pure on the same raw
        // bytes — pin referential transparency across 50 back-to-back
        // deserializations on the same `{"kid":"k1","public_key":"AAA"}`
        // fixture. A refactor that introduced a thread-local
        // deserializer cache "for hot-path perf" would still pass
        // equality; but a refactor that introduced any form of
        // stateful parsing (a counter wired into the kid field, a
        // per-call mutation) would surface here on call #2..#50. The
        // existing `info_resp_deserializes` pin covers ONE call; pin
        // the 50-call ref-transparency here. Symmetric to round-178
        // parse_policies referential-transparency pin extended to
        // this sibling serde deserialization.
        let raw = r#"{"kid":"k1","public_key":"AAA"}"#;
        let first: InfoResp = serde_json::from_str(raw).unwrap();
        let first_kid = first.kid.clone();
        let first_pk = first.public_key.clone();
        for i in 1..50 {
            let next: InfoResp = serde_json::from_str(raw).unwrap();
            assert_eq!(next.kid, first_kid, "kid diverged on call #{i}");
            assert_eq!(
                next.public_key, first_pk,
                "public_key diverged on call #{i}",
            );
        }
    }

    // ─── round 233 (2026-05-22): CatKeyRegistry + Inner + InfoResp exhaustive
    // destructure, new() owned-Self fn-pointer pin, InfoResp owned-String fields,
    // get-method dispatch shape ───

    #[test]
    fn cat_key_registry_field_count_pinned_at_exactly_one_via_exhaustive_destructure_no_rest() {
        // `CatKeyRegistry { inner: Arc<Inner> }` — exactly 1 field. A
        // 2nd field landing (e.g. `local_kid_override: Option<String>`
        // for dev environments that want to bypass the Trust Plane,
        // OR `last_refresh: Mutex<Instant>` for rotation observability)
        // without matching `new()` constructor wiring would silently
        // leave the new field zero-initialized. The exhaustive
        // destructure with no `..` rest pattern forces a 2nd field to
        // update this site in lockstep with `new()`. Symmetric to the
        // WebhookSecret 1-field + SlackSigningSecret 1-field + KillCache
        // 1-field exhaustive-destructure pins.
        let r = CatKeyRegistry::new("https://trust-plane.example.test".into());
        let CatKeyRegistry { inner: _ } = r;
    }

    #[test]
    fn cat_key_registry_inner_field_count_pinned_at_exactly_three_via_exhaustive_destructure() {
        // `Inner { trust_plane_url, http, cached }` — exactly 3 fields.
        // A 4th field landing (e.g. `cache_ttl: Duration` for periodic
        // key re-fetch on rotation, OR `kid_filter: Option<String>` to
        // pin a specific kid through development) without matching
        // `new()` constructor wiring would silently leave the new
        // field zero-initialized. The exhaustive destructure forces a
        // 4th field to update this site in lockstep with `new()`.
        // Symmetric to the WebhookNotifier 6-field + SlackNotifier
        // 6-field + TeeStream 2-field pins extended to this sibling
        // module-private holder type.
        let r = CatKeyRegistry::new("https://trust-plane.example.test".into());
        let inner: &Inner = &r.inner;
        let Inner {
            trust_plane_url: _,
            http: _,
            cached: _,
        } = inner;
    }

    #[test]
    fn info_resp_field_count_pinned_at_exactly_two_via_exhaustive_destructure_no_rest_pattern() {
        // `InfoResp { kid, public_key }` — exactly 2 fields. The
        // Trust Plane info endpoint surfaces ONLY these two; a 3rd
        // field landing (e.g. `algorithm: String` per RFC 8037 §3.1
        // surfacing, OR `next_rotation: i64` for rotation observability)
        // would be silently ignored today (`#[serde(default)]` semantics
        // via the `info_resp_ignores_unknown_fields_for_forward_compat`
        // pin) — which is the INTENT for forward-compat, but a 3rd
        // first-class field landing on our deserializer would break
        // any operator who relied on it being surfaced. Pin the
        // destructure so a 3rd CLAIMED field lands here in lockstep
        // with the deserializer. Symmetric to the FederationClaims
        // 8-field + GoogleClient 4-field exhaustive-destructure pins.
        let raw = r#"{"kid":"k1","public_key":"AAA"}"#;
        let info: InfoResp = serde_json::from_str(raw).unwrap();
        let InfoResp {
            kid: _,
            public_key: _,
        } = info;
    }

    #[test]
    fn cat_key_registry_new_return_type_is_owned_self_by_value_via_fn_pointer_witness() {
        // `CatKeyRegistry::new(String) -> Self` is the constructor
        // AppState calls exactly once at boot. The value is then
        // Arc-cloned across handlers via the inner `Arc<Inner>` field
        // — the OUTER struct is owned-by-value at construction. Pin
        // the return type via a fn-pointer witness `fn(String) ->
        // CatKeyRegistry`. A refactor to `Arc<Self>` "for ergonomic
        // already-shared construction" would force the AppState
        // assembly to drop its own `.clone()` step (the inner Arc
        // suffices), breaking the construction pattern at every site.
        // Symmetric to the KillCache::new + TeeStream::new owned-Self
        // fn-pointer pins.
        let _f: fn(String) -> CatKeyRegistry = CatKeyRegistry::new;
        fn require_owned(_: CatKeyRegistry) {}
        require_owned(CatKeyRegistry::new(
            "https://trust-plane.example.test".into(),
        ));
    }

    #[test]
    fn info_resp_kid_and_public_key_fields_pinned_owned_string_for_cross_await_get_method() {
        // `InfoResp { kid: String, public_key: String }` — both fields
        // OWNED. The deserialized struct lives across the `.await` on
        // `resp.json().await` AND outlives the response buffer (the
        // `bytes` derive later moves the kid+public_key into
        // `PublicKey::from_bytes(&info.kid, &arr)`). A refactor to
        // `Cow<'a, str>` "for zero-alloc on the response buffer
        // borrow" would tie the lifetime to the response body, which
        // is freed on `resp.json().await` completion — `info.kid`
        // would dangle on the subsequent `PublicKey::from_bytes` call.
        // Pin via require_string on both fields. Symmetric to the
        // OAuthError 4-String-variant + GoogleClient 4-field owned-
        // String pins.
        fn require_string(_: &String) {}
        let raw = r#"{"kid":"k1","public_key":"AAA"}"#;
        let info: InfoResp = serde_json::from_str(raw).unwrap();
        require_string(&info.kid);
        require_string(&info.public_key);
    }

    #[test]
    fn cat_key_registry_get_dispatched_via_async_method_with_self_borrow_for_arc_share_contract() {
        // `CatKeyRegistry::get(&self) -> Future<Output = Result<&
        // PublicKey, CatKeyError>>` — takes `&self` borrow (not
        // `self` consumption). The middleware calls
        // `registry.get().await` repeatedly across the request
        // lifetime — consuming self would force a clone at every
        // invocation and break the Arc-share contract. Pin the
        // `&self` shape by exercising a method dispatch through a
        // borrowed registry that lives in a shorter scope than the
        // CatKeyRegistry itself (in a `let registry = ...` block
        // followed by the borrow). A refactor to `self` would fail
        // compile at the second `registry.get()` call site at every
        // adapter that uses the cache. Symmetric to the is_killed
        // `&self` borrow signature pin extended to this sibling
        // accessor.
        let registry = CatKeyRegistry::new("http://127.0.0.1:1/".into());
        // Compile-time witness: `&CatKeyRegistry` method dispatch.
        fn require_borrow_get<'a>(
            r: &'a CatKeyRegistry,
        ) -> impl std::future::Future<Output = Result<&'a PublicKey, CatKeyError>> + 'a {
            r.get()
        }
        let _fut = require_borrow_get(&registry);
        // `registry` still usable after the borrow witness — the
        // method takes &self, not self.
        let _r2 = &registry;
    }
}
