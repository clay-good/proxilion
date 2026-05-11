//! Proxy-side PIC integration: executor key + Trust Plane client + PCA cache.

pub mod cache;
pub mod cat_key;
pub mod executor;
pub mod verifier;
pub mod violations;

pub use cache::{CachedPca, PcaCache};
pub use cat_key::CatKeyRegistry;
pub use executor::{ExecutorError, PicExecutor, SuccessorOutcome};
#[allow(unused_imports)]
pub use violations::{PicViolationRecord, parse_missing_atoms};
#[allow(unused_imports)]
pub use verifier::{PicVerifier, VerificationResult, VerifierError};
