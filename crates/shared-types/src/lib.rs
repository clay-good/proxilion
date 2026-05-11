//! Stable internal type surface for Proxilion.
//!
//! Other crates depend on `shared_types::provenance::*` rather than
//! `provenance_core` directly, so we can absorb upstream churn in one place.

pub use provenance_core as provenance;
