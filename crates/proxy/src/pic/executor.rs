//! Trust Plane client and executor-key holder.
//!
//! Responsibilities:
//!   * Hold the proxy's Ed25519 executor key pair (PROXY_EXECUTOR_KEY env in
//!     production; ephemeral in dev).
//!   * Lazily register the public key with Trust Plane on first use
//!     (`POST /v1/keys/executor`).
//!   * Mint PCA_0 via `POST /v1/pca/issue` (federation entry).
//!   * Mint successor PCAs via `POST /v1/poc/process` after building +
//!     signing a PoC.
//!
//! NB: The upstream Trust Plane successor route is `/v1/poc/process`, not
//! `/v1/pca/successor` as drafted in spec.md §1.1. Verified against
//! `provenance-main/.../api/mod.rs`. Spec is out of date — flagged in
//! the §1.1 Status note.

use std::sync::Arc;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::OnceCell;
use tracing::{debug, info, instrument};

use shared_types::provenance::{
    self as pc, crypto::KeyPair, pca::ExecutorBinding, poc::PocBuilder,
};

use policy_engine::PicMode;

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("Trust Plane returned {status}: {body}")]
    Upstream { status: u16, body: String },
    #[error("Trust Plane request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("invariant violation (Trust Plane refused PCA): {0}")]
    Invariant(String),
    #[error("provenance-core: {0}")]
    Core(String),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
}

/// Trust Plane client. Clone is cheap (Arc-shared state).
#[derive(Clone)]
#[allow(dead_code)] // mint_pca_0 / executor_kid land in §1.2 (bearer middleware)
pub struct PicExecutor {
    inner: Arc<Inner>,
}

struct Inner {
    http: reqwest::Client,
    trust_plane_url: String,
    keypair: KeyPair,
    kid: String,
    registered: OnceCell<()>,
}

impl PicExecutor {
    /// `key_seed` — 32 raw bytes of the Ed25519 seed.
    pub fn new(
        trust_plane_url: String,
        kid: String,
        key_seed: &[u8; 32],
    ) -> Result<Self, ExecutorError> {
        let keypair =
            KeyPair::from_bytes(&kid, key_seed).map_err(|e| ExecutorError::Core(e.to_string()))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("Proxilion/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            inner: Arc::new(Inner {
                http,
                trust_plane_url,
                keypair,
                kid,
                registered: OnceCell::new(),
            }),
        })
    }

    pub fn dev_ephemeral(trust_plane_url: String) -> Result<Self, ExecutorError> {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        Self::new(
            trust_plane_url,
            format!("proxy-dev-{}", uuid::Uuid::new_v4()),
            &seed,
        )
    }

    #[allow(dead_code)] // surfaced to observability/diagnostics in §1.2
    pub fn executor_kid(&self) -> &str {
        &self.inner.kid
    }

    /// Ensure this executor's public key is registered with Trust Plane.
    /// Idempotent; the OnceCell guarantees one registration per process.
    #[instrument(skip(self))]
    pub async fn ensure_registered(&self) -> Result<(), ExecutorError> {
        let inner = self.inner.clone();
        inner
            .registered
            .get_or_try_init(|| async {
                let pk_bytes = self.inner.keypair.verifying_key_bytes();
                let body = RegisterExecutorRequest {
                    kid: self.inner.kid.clone(),
                    public_key: B64.encode(pk_bytes),
                };
                let resp = self
                    .inner
                    .http
                    .post(format!("{}/v1/keys/executor", self.inner.trust_plane_url))
                    .json(&body)
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(ExecutorError::Upstream { status, body });
                }
                info!(kid = %self.inner.kid, "registered executor key with Trust Plane");
                Ok::<(), ExecutorError>(())
            })
            .await?;
        Ok(())
    }

    /// Mint PCA_0 from an external credential (e.g. an IdP JWT).
    ///
    /// Currently not invoked from the OAuth flow because the federation-bridge
    /// service is deferred (see spec.md §0.4 Status); kept here so the §1.2
    /// bearer middleware and the future bridge wrapper can call it.
    #[allow(dead_code)]
    #[instrument(skip(self, credential))]
    pub async fn mint_pca_0(
        &self,
        credential: &str,
        credential_type: &str,
        requested_ops: &[String],
    ) -> Result<IssuePcaResponse, ExecutorError> {
        let body = IssuePcaRequest {
            credential: credential.to_owned(),
            credential_type: credential_type.to_owned(),
            ops: requested_ops.to_vec(),
            executor_binding: std::collections::HashMap::from([
                ("service".to_string(), "proxilion-proxy".to_string()),
                ("kid".to_string(), self.inner.kid.clone()),
            ]),
        };
        let resp = self
            .inner
            .http
            .post(format!("{}/v1/pca/issue", self.inner.trust_plane_url))
            .json(&body)
            .send()
            .await?;
        match resp.status() {
            s if s.is_success() => {
                let parsed: IssuePcaResponse = resp.json().await?;
                record_pca_issue("ok", parsed.hop);
                Ok(parsed)
            }
            StatusCode::UNPROCESSABLE_ENTITY | StatusCode::FORBIDDEN => {
                let body = resp.text().await.unwrap_or_default();
                record_pca_issue("invariant", 0);
                Err(ExecutorError::Invariant(body))
            }
            status => {
                let body = resp.text().await.unwrap_or_default();
                record_pca_issue("upstream_error", 0);
                Err(ExecutorError::Upstream {
                    status: status.as_u16(),
                    body,
                })
            }
        }
    }

    /// Mint a successor PCA by submitting a signed PoC.
    ///
    /// `predecessor_pca_bytes` is the *signed* CBOR of the predecessor (as
    /// returned by Trust Plane, base64-decoded). `requested_ops` is the
    /// narrowed ops set for the successor — Trust Plane enforces ⊆.
    #[instrument(skip(self, predecessor_pca_bytes))]
    pub async fn mint_successor(
        &self,
        predecessor_pca_bytes: Vec<u8>,
        requested_ops: Vec<String>,
        binding: ExecutorBinding,
    ) -> Result<ProcessPocResponse, ExecutorError> {
        self.ensure_registered().await?;

        let poc = PocBuilder::new(predecessor_pca_bytes)
            .ops(requested_ops)
            .executor(binding)
            .build()
            .map_err(|e| ExecutorError::Core(e.to_string()))?;

        let signed = self
            .inner
            .keypair
            .sign_poc(&poc)
            .map_err(|e| ExecutorError::Core(e.to_string()))?;
        let signed_bytes = signed
            .to_bytes()
            .map_err(|e| ExecutorError::Core(e.to_string()))?;

        let req = ProcessPocRequest {
            poc: B64.encode(signed_bytes),
        };
        debug!(executor = %self.inner.kid, "submitting PoC");
        let resp = self
            .inner
            .http
            .post(format!("{}/v1/poc/process", self.inner.trust_plane_url))
            .json(&req)
            .send()
            .await?;
        match resp.status() {
            s if s.is_success() => {
                let parsed: ProcessPocResponse = resp.json().await?;
                record_pca_issue("ok", parsed.hop);
                Ok(parsed)
            }
            StatusCode::UNPROCESSABLE_ENTITY | StatusCode::FORBIDDEN => {
                let body = resp.text().await.unwrap_or_default();
                record_pca_issue("invariant", 0);
                Err(ExecutorError::Invariant(body))
            }
            status => {
                let body = resp.text().await.unwrap_or_default();
                record_pca_issue("upstream_error", 0);
                Err(ExecutorError::Upstream {
                    status: status.as_u16(),
                    body,
                })
            }
        }
    }
}

/// spec.md §3.2 — `proxilion_pca_issue_total{result,hop_class}`. `hop_class`
/// is `0 | 1 | 2 | n` per the spec's curated label set so cardinality stays
/// bounded regardless of how deep a customer's chains get. `0` only fires
/// on the `mint_pca_0` path; `1` is a typical first agent action; `2` is
/// the post-override branch; everything ≥3 collapses into `n`. Refusals
/// don't carry a hop (we never learned what hop the Trust Plane would have
/// minted), so they use the empty-string hop_class to keep the series
/// distinct from any real successor row.
fn record_pca_issue(result: &'static str, hop: u32) {
    let hop_class = match (result, hop) {
        ("ok", 0) => "0",
        ("ok", 1) => "1",
        ("ok", 2) => "2",
        ("ok", _) => "n",
        _ => "",
    };
    metrics::counter!(
        "proxilion_pca_issue_total",
        "result" => result,
        "hop_class" => hop_class,
    )
    .increment(1);
}

/// Outcome of an attempt to mint a successor PCA when the policy's
/// `pic_mode` is consulted (see spec.md §2.4).
///
/// * `Issued` — Trust Plane minted a fresh successor; adapter chains on
///   the new PCA.
/// * `AuditFallback` — Trust Plane refused with a monotonicity violation
///   and the policy was in `audit` mode. The adapter proceeds with the
///   request against the predecessor PCA (no new leaf), and the proxy
///   records a `pic_violations` row.
#[derive(Debug)]
pub enum SuccessorOutcome {
    Issued(ProcessPocResponse),
    AuditFallback { detail: String },
}

impl PicExecutor {
    /// Audit-aware wrapper around `mint_successor` (spec.md §2.4).
    ///
    /// Audit-mode semantics: the upstream Trust Plane does not yet
    /// expose an `audit-mode-successor` endpoint (open question #2 in
    /// §15). v1 short-circuits per the spec's stated fallback — on
    /// monotonicity violation in audit mode, the request proceeds with
    /// the predecessor's PCA as the leaf. Confused-deputy semantics are
    /// **not** preserved on that action's PCA; this is acceptable for
    /// audit-only and is the documented trade-off.
    #[instrument(skip(self, predecessor_pca_bytes))]
    pub async fn request_or_audit_successor(
        &self,
        predecessor_pca_bytes: Vec<u8>,
        requested_ops: Vec<String>,
        binding: ExecutorBinding,
        mode: PicMode,
    ) -> Result<SuccessorOutcome, ExecutorError> {
        match self
            .mint_successor(predecessor_pca_bytes, requested_ops, binding)
            .await
        {
            Ok(resp) => Ok(SuccessorOutcome::Issued(resp)),
            Err(ExecutorError::Invariant(detail)) => match mode {
                PicMode::RuntimeGate => Err(ExecutorError::Invariant(detail)),
                PicMode::Audit => {
                    info!(detail = %detail, "pic invariant violated in audit mode; passing through");
                    Ok(SuccessorOutcome::AuditFallback { detail })
                }
            },
            Err(other) => Err(other),
        }
    }
}

// Wire types mirroring upstream Trust Plane's JSON API. We re-declare rather
// than importing from `provenance-plane` to keep the dependency surface
// narrow (provenance-plane drags in storage backends, etc.).

#[derive(Debug, Serialize)]
#[allow(dead_code)] // constructed by mint_pca_0
struct IssuePcaRequest {
    credential: String,
    credential_type: String,
    ops: Vec<String>,
    executor_binding: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // hop / exp surfaced once we exercise mint_pca_0
pub struct IssuePcaResponse {
    /// Base64-encoded signed PCA CBOR.
    pub pca: String,
    pub hop: u32,
    pub p_0: String,
    pub ops: Vec<String>,
    #[serde(default)]
    pub exp: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProcessPocRequest {
    poc: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // hop / exp surfaced once we exercise more flows
pub struct ProcessPocResponse {
    pub pca: String,
    pub hop: u32,
    pub p_0: String,
    pub ops: Vec<String>,
    #[serde(default)]
    pub exp: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterExecutorRequest {
    kid: String,
    public_key: String,
}

// Sanity import — silences "unused crate" warning on `pc::*` if we don't end
// up calling anything else from the namespace in this module.
#[allow(unused_imports)]
use pc as _pc;

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn server_with_responses(
        keys_status: u16,
        poc_status: u16,
        poc_body: &str,
    ) -> MockServer {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/keys/executor"))
            .respond_with(ResponseTemplate::new(keys_status).set_body_string("{}"))
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/poc/process"))
            .respond_with(
                ResponseTemplate::new(poc_status)
                    .set_body_string(poc_body)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&s)
            .await;
        s
    }

    #[tokio::test]
    async fn audit_mode_returns_fallback_on_invariant() {
        let server = server_with_responses(
            200,
            403,
            "ops not subset of predecessor: missing [drive:read:bob/secret]",
        )
        .await;
        let exec = PicExecutor::dev_ephemeral(server.uri()).unwrap();
        let binding = ExecutorBinding::new().with("service", "test");
        // predecessor_pca_bytes is opaque to the executor (PocBuilder copies it);
        // an empty Vec is fine for the audit-fallback path since we never reach
        // signing if Trust Plane refuses — but PoCBuilder requires a non-empty
        // predecessor. Use a token byte.
        let res = exec
            .request_or_audit_successor(
                vec![0u8; 16],
                vec!["drive:read:bob/secret".into()],
                binding,
                PicMode::Audit,
            )
            .await
            .unwrap();
        match res {
            SuccessorOutcome::AuditFallback { detail } => {
                assert!(detail.contains("ops not subset"), "got: {detail}");
            }
            SuccessorOutcome::Issued(_) => panic!("expected audit fallback"),
        }
    }

    #[tokio::test]
    async fn runtime_gate_mode_propagates_invariant_error() {
        let server = server_with_responses(
            200,
            422,
            "ops not subset of predecessor: missing [gmail:send:external]",
        )
        .await;
        let exec = PicExecutor::dev_ephemeral(server.uri()).unwrap();
        let binding = ExecutorBinding::new().with("service", "test");
        let err = exec
            .request_or_audit_successor(
                vec![0u8; 16],
                vec!["gmail:send:external".into()],
                binding,
                PicMode::RuntimeGate,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ExecutorError::Invariant(_)), "got: {err:?}");
    }

    #[test]
    fn dev_ephemeral_yields_distinct_kids_per_call() {
        // The dev-ephemeral constructor builds a fresh random kid each
        // call. Pin distinctness so a future regression that re-seeded the
        // RNG with the process pid (or some other fixed value) would
        // surface here. The kid prefix is operator-visible — both must
        // start with `proxy-dev-`.
        let a = PicExecutor::dev_ephemeral("http://127.0.0.1:1/".into()).unwrap();
        let b = PicExecutor::dev_ephemeral("http://127.0.0.1:1/".into()).unwrap();
        assert_ne!(a.executor_kid(), b.executor_kid());
        assert!(a.executor_kid().starts_with("proxy-dev-"));
        assert!(b.executor_kid().starts_with("proxy-dev-"));
    }

    #[test]
    fn pic_executor_new_round_trips_kid_through_executor_kid_accessor() {
        // Production callers pass a stable kid (the PROXY_EXECUTOR_KEY
        // env's matching kid string) and read it back via `executor_kid()`
        // to put on every PoC's executor_binding. A regression that
        // generated a fresh kid in `new()` and ignored the parameter
        // would silently break chain attribution downstream.
        let seed = [7u8; 32];
        let exec =
            PicExecutor::new("http://127.0.0.1:1/".into(), "proxy-prod-1".into(), &seed).unwrap();
        assert_eq!(exec.executor_kid(), "proxy-prod-1");
    }

    #[test]
    fn executor_error_display_strings_carry_named_field_values() {
        // The middleware + adapter layers log `error = %e` for each path.
        // Pin the structured `Upstream { status, body }` variant's
        // thiserror substitution — a regression that dropped one of the
        // fields would silently lose troubleshooting context.
        let s = ExecutorError::Upstream {
            status: 503,
            body: "trust plane down".into(),
        }
        .to_string();
        assert!(s.contains("503"));
        assert!(s.contains("trust plane down"));

        // Invariant carries an opaque body. Pin the prefix so a future
        // variant rename surfaces here, plus pass-through of the inner
        // string (the dashboard renders this verbatim).
        let s = ExecutorError::Invariant("ops not subset".into()).to_string();
        assert!(s.contains("invariant violation"));
        assert!(s.contains("ops not subset"));

        let s = ExecutorError::Core("cbor encode".into()).to_string();
        assert!(s.contains("provenance-core"));
        assert!(s.contains("cbor encode"));
    }

    #[test]
    fn issue_pca_response_deserializes_with_optional_exp_absent() {
        // Trust Plane omits `exp` on long-lived PCAs. Pin both the
        // success-with-exp and the success-without-exp variants —
        // `#[serde(default)]` on the field is load-bearing for forward
        // compat with PCAs that never expire.
        let raw = r#"{"pca":"b64bytes","hop":1,"p_0":"alice@demo.local","ops":["drive:read:x"]}"#;
        let resp: IssuePcaResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.hop, 1);
        assert_eq!(resp.p_0, "alice@demo.local");
        assert_eq!(resp.ops, vec!["drive:read:x".to_string()]);
        assert!(resp.exp.is_none());

        let raw_with_exp =
            r#"{"pca":"b64","hop":0,"p_0":"alice","ops":[],"exp":"2027-01-01T00:00:00Z"}"#;
        let resp: IssuePcaResponse = serde_json::from_str(raw_with_exp).unwrap();
        assert_eq!(resp.exp.as_deref(), Some("2027-01-01T00:00:00Z"));
    }

    #[test]
    fn process_poc_response_round_trips_ops_and_hop() {
        // Symmetric to IssuePcaResponse but on the successor-mint path.
        // `ops` is the *narrowed* set — pin that the array round-trip
        // preserves order (downstream PicVerifier compares element-wise).
        let raw = r#"{"pca":"b64","hop":2,"p_0":"bob","ops":["a:read:x","b:write:y"]}"#;
        let resp: ProcessPocResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.hop, 2);
        assert_eq!(resp.p_0, "bob");
        assert_eq!(
            resp.ops,
            vec!["a:read:x".to_string(), "b:write:y".to_string()],
        );
    }

    #[test]
    fn register_executor_request_serializes_to_snake_case_pair() {
        // Trust Plane's `POST /v1/keys/executor` expects `kid` + `public_key`
        // — the wire field names are part of the upstream contract. Pin both
        // so a future rename (e.g. `executor_kid` / `verifying_key`) would
        // surface here as a wire-shape regression.
        let req = RegisterExecutorRequest {
            kid: "proxy-prod-1".into(),
            public_key: "base64-encoded-bytes".into(),
        };
        let j = serde_json::to_value(&req).unwrap();
        assert_eq!(j["kid"], "proxy-prod-1");
        assert_eq!(j["public_key"], "base64-encoded-bytes");
        assert_eq!(
            j.as_object().unwrap().len(),
            2,
            "only the two contract fields",
        );
    }

    #[test]
    fn successor_outcome_debug_carries_variant_name_and_detail() {
        // `SuccessorOutcome` derives Debug; the adapter call site
        // logs `?outcome` for chain-issuance audit. Pin both the
        // variant name and the `detail` field on the AuditFallback
        // arm so a manual Debug impl that hid the detail would
        // surface here (the audit trail loses signal otherwise).
        let af = SuccessorOutcome::AuditFallback {
            detail: "ops not subset of predecessor: missing [drive:write:secret]".into(),
        };
        let s = format!("{af:?}");
        assert!(s.contains("AuditFallback"));
        assert!(s.contains("ops not subset"));
    }

    #[test]
    fn process_poc_request_serializes_to_single_wire_field() {
        // Trust Plane's `POST /v1/poc/process` accepts exactly one
        // field: `poc` (base64-encoded signed PoC bytes). Pin the
        // single-field shape so a refactor that added a sibling
        // field (e.g. `requested_ops`) would surface as a wire-shape
        // change. The contract is "the PoC carries everything."
        let req = ProcessPocRequest {
            poc: "base64-encoded-bytes".into(),
        };
        let j = serde_json::to_value(&req).unwrap();
        assert_eq!(j["poc"], "base64-encoded-bytes");
        assert_eq!(
            j.as_object().unwrap().len(),
            1,
            "only the single `poc` field is on the wire",
        );
    }

    #[test]
    fn issue_pca_request_serializes_with_four_wire_fields() {
        // Trust Plane's `POST /v1/pca/issue` accepts four fields:
        // `credential`, `credential_type`, `ops`, `executor_binding`.
        // Pin all four by name + count so a future refactor that
        // renamed `credential_type` to `cred_type` (a common
        // shortening) would surface here as a wire-shape break.
        let req = IssuePcaRequest {
            credential: "the-jwt".into(),
            credential_type: "federation_token".into(),
            ops: vec!["drive:read:x".into()],
            executor_binding: std::collections::HashMap::from([
                ("service".to_string(), "proxilion-proxy".to_string()),
                ("kid".to_string(), "proxy-prod-1".to_string()),
            ]),
        };
        let j = serde_json::to_value(&req).unwrap();
        for key in ["credential", "credential_type", "ops", "executor_binding"] {
            assert!(j.get(key).is_some(), "missing wire key: {key}");
        }
        assert_eq!(j.as_object().unwrap().len(), 4);
        assert_eq!(j["credential_type"], "federation_token");
    }

    #[test]
    fn executor_error_transport_and_base64_display_strings_carry_distinct_prefixes() {
        // The Display strings for Upstream/Invariant/Core were pinned
        // already; the two remaining variants (Transport via #[from]
        // reqwest::Error, Base64 via #[from] base64::DecodeError) had
        // no direct coverage. Pin both prefixes — operator log filters
        // split "transport flake" from "encoded-bytes corruption" on
        // these substrings; a refactor that collapsed the messages
        // would silently break the triage split.
        // Transport: construct a real reqwest::Error via a 1ms-timeout
        // against an RFC 5737 black-hole IP (immediate connect-refuse
        // on localhost:1; no waiting).
        let rt = tokio::runtime::Runtime::new().unwrap();
        let reqwest_err = rt.block_on(async {
            reqwest::Client::builder()
                .timeout(Duration::from_millis(1))
                .build()
                .unwrap()
                .get("http://127.0.0.1:1/")
                .send()
                .await
                .expect_err("must error")
        });
        let e = ExecutorError::from(reqwest_err);
        let s = e.to_string();
        assert!(s.starts_with("Trust Plane request failed:"), "got: {s}");
        // Base64: construct via a real DecodeError from a non-b64 input.
        let b64_err = base64::engine::general_purpose::STANDARD
            .decode("@@@")
            .expect_err("non-b64 must error");
        let e = ExecutorError::from(b64_err);
        let s = e.to_string();
        assert!(s.starts_with("base64:"), "got: {s}");
    }

    #[test]
    fn successor_outcome_debug_includes_issued_variant_name_for_audit_trail() {
        // The symmetric pin to `successor_outcome_debug_carries_variant_name_and_detail`
        // (which only covered AuditFallback). The adapter logs
        // `?outcome` for every chain-issuance — pin that the Issued
        // arm's variant name shows up in the rendered Debug string so
        // operator audit trails can grep for "Issued" vs
        // "AuditFallback" to bucket runtime-gate vs audit-mode
        // outcomes.
        let resp = ProcessPocResponse {
            pca: "base64-blob".into(),
            hop: 2,
            p_0: "user:alice@demo.local".into(),
            ops: vec!["drive:read:engineering/*".into()],
            exp: None,
        };
        let out = SuccessorOutcome::Issued(resp);
        let s = format!("{out:?}");
        assert!(s.contains("Issued"), "missing Issued variant name: {s}");
        // The inner ProcessPocResponse's Debug derive must surface
        // through too — pin one of its fields (hop) as a sanity check.
        assert!(
            s.contains("hop"),
            "inner ProcessPocResponse fields lost: {s}"
        );
    }

    #[test]
    fn executor_error_implements_std_error_trait_for_anyhow_chains() {
        // Adapter call sites bubble ExecutorError through anyhow chains
        // for structured logging; the `thiserror` derive must land the
        // `std::error::Error` impl. Pin via a trait-object cast so a
        // refactor that dropped `#[derive(Error)]` would surface as a
        // compile error here rather than as a confusing trait-bound
        // failure at a distant call site. All five variants must
        // satisfy the trait (the derive is per-enum, not per-variant,
        // so testing one is sufficient — pick Invariant since it's the
        // most common operator-facing surface).
        let e: ExecutorError = ExecutorError::Invariant("ops not subset".into());
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.to_string().contains("invariant violation"));
        // Also pin the Upstream arm directly — distinct construction
        // path (no #[from], just named fields) so the trait must work
        // on both shapes.
        let e: ExecutorError = ExecutorError::Upstream {
            status: 500,
            body: "trust plane internal".into(),
        };
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.to_string().contains("500"));
    }

    #[test]
    fn pic_executor_and_error_and_outcome_are_send_sync_static_for_axum_boundary() {
        // `PicExecutor` lives in `AppState` and crosses tokio task boundaries
        // on every adapter call; `ExecutorError` flows through anyhow chains
        // and is held across `.await` in handler `Result<_, _>` shapes;
        // `SuccessorOutcome` is the audit-mode wrapper held across the
        // adapter's `?`-propagation chain. All three need (Send + Sync +
        // 'static). A refactor that introduced an `Rc<...>` on Inner "for
        // cheaper clone of the http client config" would break Send without
        // surfacing here; the breakage would land at AppState assembly with
        // an unrelated trait-bound error. Pin all three bounds at this file.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<PicExecutor>();
        require_send_sync_static::<ExecutorError>();
        require_send_sync_static::<SuccessorOutcome>();
    }

    #[test]
    fn dev_ephemeral_yields_twenty_distinct_kids_under_burst() {
        // The existing `dev_ephemeral_yields_distinct_kids_per_call` pin
        // checks distinctness across TWO calls. Pin the broader contract:
        // 20 back-to-back ephemeral executors yield 20 distinct kids — a
        // refactor that re-seeded the UUIDv4 RNG with the process pid + a
        // tight-loop counter (a fringe but real pattern from "deterministic
        // tests please") would surface here as the burst losing entropy
        // within a single second. UUIDv4 collision probability at N=20 is
        // negligible; any collision under this load is a real regression.
        // Also pin every kid carries the `proxy-dev-` prefix so a refactor
        // that changed the marker would surface in lockstep.
        let mut kids = std::collections::HashSet::new();
        for _ in 0..20 {
            let exec = PicExecutor::dev_ephemeral("http://127.0.0.1:1/".into()).unwrap();
            assert!(exec.executor_kid().starts_with("proxy-dev-"));
            assert!(
                kids.insert(exec.executor_kid().to_string()),
                "kid collision: {}",
                exec.executor_kid()
            );
        }
        assert_eq!(kids.len(), 20);
    }

    #[test]
    fn executor_kid_returns_byte_equal_value_across_repeated_calls_on_same_executor() {
        // `executor_kid(&self) -> &str` borrows from `self.inner.kid` via
        // an `Arc<Inner>`. Repeated calls on the SAME executor MUST return
        // byte-equal strings — pin via three sequential calls + collected
        // values compared all-equal. A refactor that introduced any form
        // of interior mutation (e.g. a debug-mode counter appended to the
        // kid for tracing) would surface here. The middleware code path
        // calls executor_kid() multiple times per request (once at audit
        // log, once at PoC binding); the value MUST be stable across
        // those calls or the audit row and the PoC's executor_binding
        // would silently disagree.
        let exec = PicExecutor::new(
            "http://127.0.0.1:1/".into(),
            "proxy-stable-1".into(),
            &[42u8; 32],
        )
        .unwrap();
        let a = exec.executor_kid().to_string();
        let b = exec.executor_kid().to_string();
        let c = exec.executor_kid().to_string();
        assert_eq!(a, "proxy-stable-1");
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn executor_error_debug_carries_all_five_variant_names_for_grep_bucketing() {
        // Operator log filters bucket adapter failures by Debug variant
        // name (`?err` in handler error logs). The existing pins cover
        // Display strings for Upstream/Invariant/Core/Transport/Base64,
        // but Debug for grep bucketing is independently load-bearing —
        // a manual Debug impl that collapsed all variants to a single
        // "ExecutorError(_)" rendering would silently break grep-based
        // alerting that splits transport-flake from invariant-violation
        // from base64-corruption. Pin all five variant names render in
        // Debug.
        let upstream = ExecutorError::Upstream {
            status: 503,
            body: "x".into(),
        };
        assert!(format!("{upstream:?}").contains("Upstream"));
        let invariant = ExecutorError::Invariant("x".into());
        assert!(format!("{invariant:?}").contains("Invariant"));
        let core = ExecutorError::Core("x".into());
        assert!(format!("{core:?}").contains("Core"));
        // Transport: real reqwest::Error via 1ms timeout against
        // localhost:1 (immediate connect-refuse).
        let rt = tokio::runtime::Runtime::new().unwrap();
        let reqwest_err = rt.block_on(async {
            reqwest::Client::builder()
                .timeout(Duration::from_millis(1))
                .build()
                .unwrap()
                .get("http://127.0.0.1:1/")
                .send()
                .await
                .expect_err("must error")
        });
        let transport = ExecutorError::from(reqwest_err);
        assert!(format!("{transport:?}").contains("Transport"));
        // Base64: real DecodeError from non-b64 input.
        let b64_err = base64::engine::general_purpose::STANDARD
            .decode("@@@")
            .expect_err("non-b64 must error");
        let b64 = ExecutorError::from(b64_err);
        assert!(format!("{b64:?}").contains("Base64"));
    }

    #[test]
    fn process_poc_response_with_empty_ops_vec_deserializes_successfully() {
        // The wire contract allows `ops: []` — a successor PCA that
        // happens to be a no-op narrowing (the caller asked for nothing
        // beyond the predecessor's ops set, validly). The existing
        // `process_poc_response_round_trips_ops_and_hop` test pins the
        // multi-element ops path; pin the empty-ops boundary so a
        // refactor that swapped `Vec<String>` to a `NonEmptyVec<String>`
        // wrapper "for type-level safety" would surface here. Operator-
        // facing test fixtures (audit-mode replay) frequently use
        // empty-ops PCAs to test the no-op-but-still-attested path.
        let raw = r#"{"pca":"b64","hop":3,"p_0":"carol","ops":[]}"#;
        let resp: ProcessPocResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.hop, 3);
        assert_eq!(resp.p_0, "carol");
        assert!(
            resp.ops.is_empty(),
            "expected empty ops, got: {:?}",
            resp.ops
        );
        assert!(resp.exp.is_none());
    }

    #[test]
    fn pic_executor_new_with_kid_containing_unicode_round_trips_byte_for_byte() {
        // Production operators today use ASCII-only kid values, but the
        // signature is `kid: String` — Trust Plane accepts UTF-8 kids.
        // Pin that a kid carrying multibyte unicode (`é` 2-byte +
        // `→` 3-byte + `🔥` 4-byte) round-trips through executor_kid()
        // byte-for-byte. A refactor that called `.to_ascii_lowercase()`
        // or `.replace(non_ascii, "?")` "for SIEM ingest hygiene" at the
        // constructor boundary would silently mangle every non-ASCII
        // kid before it reached the upstream Trust Plane's
        // RegisterExecutorRequest body — making the registered key
        // unfindable by the upstream-side lookup against the operator's
        // configured kid.
        let unicode_kid = "proxy-é-→-🔥";
        let exec =
            PicExecutor::new("http://127.0.0.1:1/".into(), unicode_kid.into(), &[5u8; 32]).unwrap();
        assert_eq!(exec.executor_kid(), unicode_kid);
        // Clone preserves the multibyte kid too — the Arc-share semantics
        // mustn't drop the UTF-8 bytes at the clone boundary.
        let c = exec.clone();
        assert_eq!(c.executor_kid(), unicode_kid);
    }

    #[test]
    fn pic_executor_clone_shares_inner_arc() {
        // `Clone` is part of the design contract — adapters hold a
        // per-handler clone of the executor, and the `OnceCell<()>` for
        // registration must be shared so two adapters don't both
        // re-register on first use. Pin Arc-sharing.
        let a = PicExecutor::dev_ephemeral("http://127.0.0.1:1/".into()).unwrap();
        let b = a.clone();
        assert!(Arc::ptr_eq(&a.inner, &b.inner));
    }

    #[test]
    fn executor_error_upstream_display_byte_exact_trust_plane_returned_status_body_shape() {
        // `#[error("Trust Plane returned {status}: {body}")]` — the
        // operator-facing log filter buckets Trust Plane outages by this
        // exact prefix. The existing `executor_error_implements_std_error_trait_for_anyhow_chains`
        // pin only checks `.contains("500")`; pin the BYTE-EXACT full
        // Display shape via `assert_eq!` across three status codes (400,
        // 500, 503) so a refactor that softened the message to "trust
        // plane: {status}: {body}" (dropping the proper-noun prefix) OR
        // that swapped the colon for a dash would silently break every
        // operator alert filter keyed on `"Trust Plane returned"`. The
        // integer renders with no zero-padding (status 503 → "503" not
        // "0503"). Symmetric to the `email_build_error_display_carries_byte_exact_email_build_prefix_with_inner`
        // pin on `crates/proxy/src/notifier/email.rs` and the cat_key
        // Status arm pin on `crates/proxy/src/pic/cat_key.rs`.
        for (status, body) in [
            (400u16, "bad credential"),
            (500u16, "trust plane internal"),
            (503u16, "service unavailable"),
        ] {
            let e = ExecutorError::Upstream {
                status,
                body: body.to_string(),
            };
            let expected = format!("Trust Plane returned {status}: {body}");
            assert_eq!(e.to_string(), expected);
            // No zero-padding on the status integer (a refactor to
            // `{status:04}` "for fixed-width log columns" would surface
            // here as a non-equal string).
            assert!(
                !e.to_string().contains(&format!("0{status}")),
                "zero-padding leaked: {}",
                e
            );
        }
    }

    #[test]
    fn issue_pca_response_with_explicit_exp_field_deserializes_to_some_string() {
        // The existing `process_poc_response_with_empty_ops_vec_deserializes_successfully`
        // pin walks `exp.is_none()` on the missing-field path via
        // `ProcessPocResponse`. Pin the SYMMETRIC `Some` path on
        // `IssuePcaResponse` so a refactor that swapped
        // `#[serde(default)] exp: Option<String>` for the stricter
        // `exp: String` "to require the field on the wire" would
        // silently start rejecting every Trust Plane response carrying
        // an exp claim. The Trust Plane returns `exp` as an RFC 3339
        // timestamp string (NOT a u64 epoch) — pin both that the field
        // deserializes as Some AND that the inner string round-trips
        // byte-for-byte (no normalization smuggled in via a serde
        // visitor).
        let raw = r#"{"pca":"b64-blob","hop":0,"p_0":"alice","ops":["drive:read:x"],"exp":"2026-12-31T23:59:59Z"}"#;
        let resp: IssuePcaResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.exp.as_deref(), Some("2026-12-31T23:59:59Z"));
        // The other four fields round-trip too (sanity: the exp field
        // didn't displace any other field via a serde ordering quirk).
        assert_eq!(resp.pca, "b64-blob");
        assert_eq!(resp.hop, 0);
        assert_eq!(resp.p_0, "alice");
        assert_eq!(resp.ops, vec!["drive:read:x".to_string()]);
    }

    #[test]
    fn process_poc_response_missing_exp_field_via_serde_default_yields_none() {
        // `ProcessPocResponse.exp` carries `#[serde(default)]` — when
        // Trust Plane omits the `exp` claim (e.g. for a session-bound
        // PCA with no absolute expiry), the field MUST deserialize to
        // None without surfacing a parse error. The existing
        // `process_poc_response_round_trips_ops_and_hop` pin walks an
        // input without `exp` and reads through, but does NOT assert
        // `exp == None` explicitly (it only checks hop/p_0/ops). Pin
        // the `#[serde(default)]` contract directly: a refactor that
        // dropped the attribute "for explicit wire shape" would surface
        // here as `serde_json::from_str` returning Err on the
        // missing-field path. Symmetric to the
        // `issue_pca_response_with_explicit_exp_field_deserializes_to_some_string`
        // pin on the IssuePcaResponse side.
        let raw = r#"{"pca":"b64","hop":1,"p_0":"bob","ops":["a:write:y"]}"#;
        let resp: ProcessPocResponse = serde_json::from_str(raw).unwrap();
        assert!(resp.exp.is_none(), "exp must default to None when missing");
        // Symmetric pin on IssuePcaResponse — both wire shapes carry the
        // same `#[serde(default)]` attribute on `exp` and must move in
        // lockstep on the missing-field contract.
        let raw_issue = r#"{"pca":"b64","hop":0,"p_0":"alice","ops":[]}"#;
        let resp: IssuePcaResponse = serde_json::from_str(raw_issue).unwrap();
        assert!(
            resp.exp.is_none(),
            "IssuePcaResponse exp must default to None"
        );
    }

    #[test]
    fn successor_outcome_audit_fallback_debug_carries_detail_field_name_for_grep_selector() {
        // The existing `successor_outcome_debug_carries_variant_name_and_detail`
        // pin checks the variant name AND the inner detail string body,
        // but does NOT pin the `detail:` field NAME render in the
        // Debug struct format. Operator log filters bucket
        // `?outcome` rendering on `detail=` / `detail:` selectors to
        // pull the audit-mode-fallback rationale out of structured
        // logs — a manual Debug impl that hid the field name
        // (rendering just the body as `AuditFallback("ops not subset")`
        // tuple-style instead of `AuditFallback { detail: "..." }`
        // struct-style) would silently strip the grep handle. Pin
        // the `detail` field-name substring directly. Symmetric to the
        // `cached_pca_debug_carries_pca_id_ops_hop_and_predecessor_field_names`
        // pin on `crates/proxy/src/pic/cache.rs`.
        let af = SuccessorOutcome::AuditFallback {
            detail: "ops not subset of predecessor".into(),
        };
        let s = format!("{af:?}");
        assert!(s.contains("detail"), "field name absent: {s}");
        assert!(s.contains("AuditFallback"), "variant name absent: {s}");
        // The body still surfaces (sanity: the field-name addition
        // doesn't strip the value).
        assert!(s.contains("ops not subset"), "body absent: {s}");
    }

    #[test]
    fn pic_executor_clone_executor_kid_returns_byte_equal_to_original_across_arc_share() {
        // The existing `pic_executor_clone_shares_inner_arc` pin checks
        // `Arc::ptr_eq` on the inner Arc, AND the existing
        // `executor_kid_returns_byte_equal_value_across_repeated_calls_on_same_executor`
        // pin checks repeated calls on ONE executor — but neither pin
        // checks that A.clone().executor_kid() == A.executor_kid()
        // byte-for-byte across the Arc-share boundary. A refactor that
        // introduced any clone-time mutation of the kid (e.g. appending
        // a clone-index "for per-clone trace disambiguation") would
        // surface here as the clone's kid drifting from the original's.
        // Pin the cross-clone consistency contract directly.
        let a = PicExecutor::new(
            "http://127.0.0.1:1/".into(),
            "proxy-original-kid".into(),
            &[7u8; 32],
        )
        .unwrap();
        let b = a.clone();
        let c = b.clone(); // chain of two clones
        assert_eq!(a.executor_kid(), "proxy-original-kid");
        assert_eq!(b.executor_kid(), a.executor_kid());
        assert_eq!(c.executor_kid(), a.executor_kid());
        // And the underlying inner Arc is shared across the chain.
        assert!(Arc::ptr_eq(&a.inner, &b.inner));
        assert!(Arc::ptr_eq(&b.inner, &c.inner));
    }

    #[test]
    fn dev_ephemeral_kid_suffix_after_proxy_dev_prefix_parses_as_valid_uuid_v4() {
        // The `dev_ephemeral` constructor formats the kid as
        // `format!("proxy-dev-{}", uuid::Uuid::new_v4())`. The existing
        // `dev_ephemeral_yields_twenty_distinct_kids_under_burst` pin
        // checks distinctness + the `proxy-dev-` prefix, but does NOT
        // verify the suffix is a parseable UUID. A refactor that
        // swapped `Uuid::new_v4()` for an incrementing process counter
        // "for deterministic test fixtures" would silently change the
        // kid shape from a 36-char dashed UUID to a small integer
        // string — and break every operator tool that parses the
        // suffix as a UUID for downstream lookups in the Trust Plane's
        // executor-key registry. Pin both that the suffix parses AND
        // that the parsed UUID is version 4 (not v1/v3/v5/nil). Pin
        // total kid length (10-byte prefix + 36-byte UUID = 46 bytes).
        let exec = PicExecutor::dev_ephemeral("http://127.0.0.1:1/".into()).unwrap();
        let kid = exec.executor_kid();
        let suffix = kid
            .strip_prefix("proxy-dev-")
            .expect("kid must carry proxy-dev- prefix");
        let parsed =
            uuid::Uuid::parse_str(suffix).expect("dev-ephemeral kid suffix must parse as a UUID");
        // UUIDv4 — random; version nibble is 4 per RFC 4122 §4.4.
        assert_eq!(
            parsed.get_version_num(),
            4,
            "dev-ephemeral must mint v4 UUIDs, got version {} for kid {kid}",
            parsed.get_version_num(),
        );
        // And the canonical kid length is 10 (prefix) + 36 (dashed UUID)
        // = 46 bytes — pin a single-byte drift would surface here.
        assert_eq!(kid.len(), 46, "kid length drift: {kid:?}");
    }

    // ─── round 239 (2026-05-22): ExecutorError + SuccessorOutcome variant
    // counts, PicExecutor + Inner + IssuePcaResponse field counts, and
    // PicExecutor::new return-type fn-pointer witness ───

    #[test]
    fn executor_error_variant_count_pinned_at_exactly_five_via_exhaustive_match_no_underscore_fallback()
     {
        // `ExecutorError { Upstream, Transport, Invariant, Core, Base64 }` —
        // exactly 5 variants. A 6th variant landing (e.g.
        // `Timeout(Duration)` for a per-call deadline-exceeded surface OR
        // `RateLimited { retry_after: u32 }` for the Trust Plane's 429
        // response branch) without matching arms in `into_response`-style
        // handler error code and in the operator-grep alert filters would
        // silently fall through any existing wildcard `_ => …` and lose its
        // distinct triage bucket. Pin the variant count via an exhaustive
        // match with NO underscore fallback so the compiler forces every
        // call site to update in lockstep with a new variant addition.
        // Symmetric to the `AppError` 11-variant + `OAuthError` exhaustive-
        // match pins in rounds 230 + 220 extended to this sibling error
        // type. The Transport / Base64 / Core arms construct minimal real
        // inner values; Upstream uses named fields.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let transport_err = rt.block_on(async {
            reqwest::Client::builder()
                .timeout(Duration::from_millis(1))
                .build()
                .unwrap()
                .get("http://127.0.0.1:1/")
                .send()
                .await
                .expect_err("must error")
        });
        let b64_err = base64::engine::general_purpose::STANDARD
            .decode("@@@")
            .expect_err("non-b64 must error");
        let variants: [ExecutorError; 5] = [
            ExecutorError::Upstream {
                status: 503,
                body: "x".into(),
            },
            ExecutorError::Transport(transport_err),
            ExecutorError::Invariant("x".into()),
            ExecutorError::Core("x".into()),
            ExecutorError::Base64(b64_err),
        ];
        for e in variants {
            match e {
                ExecutorError::Upstream { .. } => {}
                ExecutorError::Transport(_) => {}
                ExecutorError::Invariant(_) => {}
                ExecutorError::Core(_) => {}
                ExecutorError::Base64(_) => {}
            }
        }
    }

    #[test]
    fn pic_executor_field_count_pinned_at_exactly_one_inner_arc_via_exhaustive_destructure() {
        // `PicExecutor { inner: Arc<Inner> }` — exactly 1 field. A 2nd
        // field landing on the outer wrapper (e.g.
        // `metrics_label: &'static str` for per-executor metric
        // bucketing OR `circuit_breaker: CircuitBreaker` per-Trust-Plane
        // damping) without matching `Clone` and `new()` wiring would
        // silently leave the new field defaulted on every clone (the
        // current derive(Clone) clones `inner` only — a 2nd field would
        // need explicit handling). The exhaustive destructure with no
        // `..` rest pattern forces a 2nd field to update this site in
        // lockstep with both the constructor and the Clone derive.
        // Symmetric to the `TeeStream` 2-field + `BurstSuppressor`
        // 3-field exhaustive-destructure pins in rounds 224 + 235
        // extended to this sibling Arc-wrapping shape.
        let exec = PicExecutor::dev_ephemeral("http://127.0.0.1:1/".into()).unwrap();
        let PicExecutor { inner: _ } = exec;
    }

    #[test]
    fn inner_module_private_field_count_pinned_at_exactly_five_via_exhaustive_destructure_no_rest()
    {
        // `Inner { http, trust_plane_url, keypair, kid, registered }` —
        // module-private holder for executor state, exactly 5 fields. A
        // 6th field landing (e.g. `executor_kid_signature: Signature` for
        // a self-signed kid-binding payload OR
        // `last_register_at: OnceCell<Instant>` for re-registration
        // backoff observability) without matching `new()` wiring would
        // silently zero-initialize the new field on every PicExecutor
        // construction — and re-registration logic keyed on
        // `last_register_at` would see `None` forever, never tripping.
        // The exhaustive destructure with no `..` rest pattern forces a
        // 6th field to update this site in lockstep with the constructor.
        // Symmetric to the `BatchState` 3-field + `Bucket` 3-field
        // module-private exhaustive-destructure pins in rounds 236 + 235
        // extended to this sibling holder.
        let exec = PicExecutor::dev_ephemeral("http://127.0.0.1:1/".into()).unwrap();
        let Inner {
            http: _,
            trust_plane_url: _,
            keypair: _,
            kid: _,
            registered: _,
        } = &*exec.inner;
    }

    #[test]
    fn successor_outcome_variant_count_pinned_at_exactly_two_via_exhaustive_match_no_underscore() {
        // `SuccessorOutcome { Issued, AuditFallback }` — exactly 2
        // variants for the audit-aware mint wrapper (spec.md §2.4). A 3rd
        // variant landing (e.g. `RuntimeGateRefused(String)` to split
        // "audit mode passed through" from "runtime-gate refused" at the
        // OUTCOME level rather than at the Err path OR `Pending` for an
        // async-mint-not-yet-complete state if the Trust Plane added a
        // queued-issuance API) without matching arms at the adapter's
        // `match outcome { ... }` dispatch site would silently fall
        // through any existing wildcard `_ => …`. Pin the variant count
        // via an exhaustive match with NO underscore fallback. Symmetric
        // to the `ExecutorError` 5-variant pin above and the `AppError`
        // 11-variant exhaustive-match pin extended to this two-bucket
        // outcome type. The Issued arm carries a `ProcessPocResponse`,
        // the AuditFallback arm a struct payload — pin both shapes.
        let issued = SuccessorOutcome::Issued(ProcessPocResponse {
            pca: "b64".into(),
            hop: 1,
            p_0: "alice".into(),
            ops: vec![],
            exp: None,
        });
        let fallback = SuccessorOutcome::AuditFallback {
            detail: "ops not subset".into(),
        };
        for outcome in [issued, fallback] {
            match outcome {
                SuccessorOutcome::Issued(_) => {}
                SuccessorOutcome::AuditFallback { detail: _ } => {}
            }
        }
    }

    #[test]
    fn issue_pca_response_field_count_pinned_at_exactly_five_via_exhaustive_destructure() {
        // `IssuePcaResponse { pca, hop, p_0, ops, exp }` — Trust Plane
        // wire response on PCA_0 issuance, exactly 5 fields. A 6th field
        // landing (e.g. `kid: String` for the Trust Plane's signing key
        // identifier OR `chain_root: String` for the federation entry
        // marker the Layer-A invariant check keys on) without matching
        // both `#[derive(Deserialize)]` field-by-field bindings AND
        // downstream consumer reads at the adapter / pic/cache assembly
        // site would silently drop the new field on the floor. The
        // exhaustive destructure with no `..` rest pattern forces a 6th
        // field to update this site in lockstep with the wire-shape
        // consumer chain. Symmetric to the `ProcessPocResponse` 5-field
        // implicit shape (covered by `process_poc_response_round_trips_ops_and_hop`)
        // pinned EXPLICITLY here for IssuePcaResponse.
        let raw = r#"{"pca":"b64","hop":0,"p_0":"alice","ops":["drive:read:x"],"exp":"2026-12-31T23:59:59Z"}"#;
        let resp: IssuePcaResponse = serde_json::from_str(raw).unwrap();
        let IssuePcaResponse {
            pca: _,
            hop: _,
            p_0: _,
            ops: _,
            exp: _,
        } = resp;
    }

    #[test]
    fn pic_executor_new_return_type_is_result_self_executor_error_via_fn_pointer_witness() {
        // `PicExecutor::new(String, String, &[u8; 32]) -> Result<Self,
        // ExecutorError>` — the boot path bubbles via `?` symmetric to
        // `SiemForwarder::new` / `EmailNotifier::new_with_recipients` /
        // `SlackNotifier::new`. Pin via fn-pointer witness so a refactor
        // that swapped to `Result<Self, anyhow::Error>` "for ergonomic
        // boot-path bubbling" OR to a panicking `pub fn new` "for ease of
        // construction at the call site" would surface here at the
        // constructor boundary rather than as a confusing trait-bound
        // failure at the distant boot site. The 3 distinct error
        // pathways from this constructor — KeyPair seed-validation
        // (`Core`), reqwest client build (`Transport` via `?`) — all
        // flow through the `ExecutorError` enum and are tested
        // individually elsewhere; pin the OUTER result type shape here.
        // Symmetric to the SiemForwarder::new + EmailNotifier::new_with_recipients
        // fn-pointer pins extended to this sibling boot-path constructor.
        let _f: fn(String, &[u8; 32]) -> Result<PicExecutor, ExecutorError> =
            |url, seed| PicExecutor::new(url, "proxy-test".into(), seed);
        let _f2: fn(String) -> Result<PicExecutor, ExecutorError> = PicExecutor::dev_ephemeral;
        let result = PicExecutor::new(
            "http://127.0.0.1:1/".into(),
            "proxy-fn-pointer".into(),
            &[3u8; 32],
        );
        assert!(result.is_ok());
    }
}
