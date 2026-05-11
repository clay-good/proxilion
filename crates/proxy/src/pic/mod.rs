//! Proxy-side PIC integration: executor key + Trust Plane client + PCA cache.

pub mod cache;
pub mod cat_key;
pub mod executor;
pub mod verifier;

pub use cache::{CachedPca, PcaCache};
pub use cat_key::CatKeyRegistry;
pub use executor::{ExecutorError, PicExecutor};
#[allow(unused_imports)]
pub use verifier::{PicVerifier, VerificationResult, VerifierError};
