//! Shared HTTP error envelope.
//!
//! Every 4xx/5xx body across the proxy looks the same:
//!
//! ```json
//! {
//!   "error":  "human-friendly title",
//!   "code":   "machine_code",
//!   "detail": "what specifically went wrong (optional)",
//!   "fix":    "how to fix it (optional, plain English)",
//!   "docs":   "https://proxilion.com/docs/... (optional)"
//! }
//! ```
//!
//! Optional fields are omitted when null. Each error type in the proxy uses
//! `ErrorBody::new` (with code + message) and chains `.with_detail()` /
//! `.with_fix()` / `.with_docs()` etc. The point is to make every failure
//! self-describing: an operator pasting our body into a search bar should
//! get to a fix in seconds.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[allow(dead_code)] // referenced from docs / future callers
pub const DOCS_BASE: &str = "https://proxilion.com/docs";

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    /// One-line human title.
    pub error: &'static str,
    /// Stable machine code (snake_case).
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Plain-English fix suggestion. Should read as an imperative ("Set
    /// PROXILION_TOKEN_ENCRYPTION_KEY to ...", "Run `proxilion-cli ...`").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<&'static str>,
    /// Link to a relevant docs page (full URL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs: Option<&'static str>,
    /// Optional structured extras (policy_id, override_allowed, etc.).
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub extras: serde_json::Value,
}

impl ErrorBody {
    pub fn new(error: &'static str, code: &'static str) -> Self {
        Self {
            error,
            code,
            detail: None,
            fix: None,
            docs: None,
            extras: serde_json::Value::Null,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_fix(mut self, fix: &'static str) -> Self {
        self.fix = Some(fix);
        self
    }

    pub fn with_docs(mut self, docs: &'static str) -> Self {
        self.docs = Some(docs);
        self
    }

    pub fn with_extras(mut self, extras: serde_json::Value) -> Self {
        self.extras = extras;
        self
    }

    pub fn into_response(self, status: StatusCode) -> Response {
        (status, Json(self)).into_response()
    }
}

impl IntoResponse for ErrorBody {
    fn into_response(self) -> Response {
        // Default: 500. Callers should always specify status via
        // `into_response(status)`; we only implement IntoResponse so the
        // type can be used in test fixtures and helpers.
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
    }
}
