//! Proxilion policy engine.
//!
//! Layer A (PIC-native ops grammar) and Layer B (YAML-authored content/context
//! policy). See spec.md §9.

pub mod context;
pub mod decision;
pub mod loader;
mod match_expr;
pub mod ops;
pub mod rego;
pub mod trace;
pub mod yaml;

pub use loader::{
    FilePolicyLoader, PolicyBundle, PolicyLoadError, PolicyLoader, StaticPolicyLoader,
};

pub use context::{RequestContext, UserCtx};
pub use decision::{Decision, Pattern, QuarantineAction, ReadFilter};
pub use ops::{MissingOps, OpsAtom, OpsExpression};
pub use rego::{Engine, Outcome};
pub use trace::{LayerOutcome, OpsAtomView, PolicyEvalMode, PolicyLayer, PolicyTrace};
pub use yaml::{AuditBodyMode, Mode, PicMode};
