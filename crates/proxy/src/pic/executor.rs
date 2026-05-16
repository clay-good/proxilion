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
    fn pic_executor_clone_shares_inner_arc() {
        // `Clone` is part of the design contract — adapters hold a
        // per-handler clone of the executor, and the `OnceCell<()>` for
        // registration must be shared so two adapters don't both
        // re-register on first use. Pin Arc-sharing.
        let a = PicExecutor::dev_ephemeral("http://127.0.0.1:1/".into()).unwrap();
        let b = a.clone();
        assert!(Arc::ptr_eq(&a.inner, &b.inner));
    }
}
