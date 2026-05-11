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
