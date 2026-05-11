//! SaaS adapters. Each adapter owns its routes; all share `AdapterState`,
//! `AppError`, and the read-filter + action-stream helpers.

pub mod action_stream;
pub mod error;
pub mod google_drive;
pub mod google_gmail;
pub mod read_filter;
pub mod state;

#[allow(unused_imports)]
pub use action_stream::{ActionEvent, ActionStream, LoggingStream};
#[allow(unused_imports)]
pub use error::AppError;
pub use state::AdapterState;
