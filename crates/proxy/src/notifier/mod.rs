//! Blocked-action notifiers (ui-less-surfaces.md §10.3).
//!
//! When a Layer-A invariant or Layer-B policy denies an action, the proxy
//! persists a `blocked_actions` row and optionally fires a notification
//! to a customer-configured outbound channel — a generic webhook in v1.
//! The webhook receiver (PagerDuty / Slack incoming-webhook / Jira /
//! custom) is responsible for translating into operator UI; this proxy
//! ships one driver because two adapters cover 90% of integrations.
//!
//! The notifier is fire-and-forget from the adapter's perspective — its
//! failure never blocks the request response, never blocks the durable
//! `blocked_actions` row. Customers who need stricter at-least-once
//! semantics should pull from `/api/v1/blocked` on a schedule.

pub mod burst;
pub mod email;
pub mod handle;
pub mod slack;
pub mod webhook;

#[allow(unused_imports)]
pub use burst::{BurstConfig, BurstSummary, BurstSuppressor};
#[allow(unused_imports)]
pub use email::{EmailBuildError, EmailNotifier};
#[allow(unused_imports)]
pub use handle::{EmailHandle, Handle, NotifierHandle, Notifiers, SlackHandle};
#[allow(unused_imports)]
pub use slack::{
    SlackAction, SlackBuildError, SlackNotifier, SlackSigningSecret, parse_button_value,
};
#[allow(unused_imports)]
pub use webhook::{NotifierBuildError, WebhookNotifier, WebhookSecret};

use serde::Serialize;
use uuid::Uuid;

/// The envelope every notifier driver receives. Mirrors the
/// `ui-less-surfaces.md §5.2` shape — fields a human approver needs to
/// decide. PCA chain bytes / requested_ops are kept light here; deeper
/// inspection happens via `/api/v1/blocked/{id}`.
#[derive(Debug, Clone, Serialize)]
pub struct BlockedNotification<'a> {
    pub schema: &'static str,
    pub blocked_id: Uuid,
    pub request_id: Uuid,
    pub session_id: Uuid,
    pub p_0: Option<&'a str>,
    pub vendor: &'a str,
    pub action: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub layer: &'a str,
    pub policy_id: Option<&'a str>,
    pub detail: Option<&'a str>,
    pub predecessor_pca_id: Option<Uuid>,
    pub requested_ops: &'a [String],
    pub approve_url: String,
    pub reject_url: String,
}

impl<'a> BlockedNotification<'a> {
    pub const SCHEMA: &'static str = "proxilion.blocked_action.v1";

    pub fn from_record(
        blocked_id: Uuid,
        r: &'a crate::blocked::BlockedActionRecord<'_>,
        proxy_public_url: &str,
    ) -> BlockedNotification<'a> {
        BlockedNotification {
            schema: Self::SCHEMA,
            blocked_id,
            request_id: r.request_id,
            session_id: r.session_id,
            p_0: r.p_0,
            vendor: r.vendor,
            action: r.action,
            method: r.method,
            path: r.path,
            layer: r.layer,
            policy_id: r.policy_id,
            detail: r.detail,
            predecessor_pca_id: r.predecessor_pca_id,
            requested_ops: r.requested_ops,
            approve_url: format!("{proxy_public_url}/api/v1/blocked/{blocked_id}/approve"),
            reject_url: format!("{proxy_public_url}/api/v1/blocked/{blocked_id}/reject"),
        }
    }
}
