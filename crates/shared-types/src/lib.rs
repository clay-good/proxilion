//! Stable internal type surface for Proxilion.
//!
//! Other crates depend on `shared_types::provenance::*` rather than
//! `provenance_core` directly, so we can absorb upstream churn in one place.

pub use provenance_core as provenance;

pub mod error_code;
pub use error_code::ErrorCode;

pub mod operator_scopes;
