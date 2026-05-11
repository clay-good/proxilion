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
    self as pc,
    crypto::KeyPair,
    pca::ExecutorBinding,
    poc::PocBuilder,
};

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
    pub fn new(trust_plane_url: String, kid: String, key_seed: &[u8; 32]) -> Result<Self, ExecutorError> {
        let keypair = KeyPair::from_bytes(&kid, key_seed)
            .map_err(|e| ExecutorError::Core(e.to_string()))?;
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
        Self::new(trust_plane_url, format!("proxy-dev-{}", uuid::Uuid::new_v4()), &seed)
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
            s if s.is_success() => Ok(resp.json().await?),
            StatusCode::UNPROCESSABLE_ENTITY | StatusCode::FORBIDDEN => {
                let body = resp.text().await.unwrap_or_default();
                Err(ExecutorError::Invariant(body))
            }
            status => {
                let body = resp.text().await.unwrap_or_default();
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
            s if s.is_success() => Ok(resp.json().await?),
            StatusCode::UNPROCESSABLE_ENTITY | StatusCode::FORBIDDEN => {
                let body = resp.text().await.unwrap_or_default();
                Err(ExecutorError::Invariant(body))
            }
            status => {
                let body = resp.text().await.unwrap_or_default();
                Err(ExecutorError::Upstream {
                    status: status.as_u16(),
                    body,
                })
            }
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
