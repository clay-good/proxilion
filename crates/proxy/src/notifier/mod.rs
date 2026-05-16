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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocked::BlockedActionRecord;

    fn sample_record<'a>(ops: &'a [String]) -> BlockedActionRecord<'a> {
        BlockedActionRecord {
            request_id: Uuid::nil(),
            session_id: Uuid::nil(),
            p_0: Some("alice@acme.com"),
            vendor: "google",
            action: "gmail.messages.send",
            method: "POST",
            path: "/gmail/v1/users/me/messages/send",
            layer: "policy",
            policy_id: Some("gmail-external-send-gate"),
            detail: Some("external recipient"),
            predecessor_pca_id: Some(Uuid::nil()),
            requested_ops: ops,
            escalation_after_minutes: None,
            request_canonical_json: None,
        }
    }

    #[test]
    fn from_record_carries_schema_and_field_passthrough() {
        let ops = vec!["gmail:send:bob@external.com".to_string()];
        let r = sample_record(&ops);
        let id = Uuid::nil();
        let n = BlockedNotification::from_record(id, &r, "https://proxy.example");
        assert_eq!(n.schema, BlockedNotification::SCHEMA);
        assert_eq!(n.schema, "proxilion.blocked_action.v1");
        assert_eq!(n.blocked_id, id);
        assert_eq!(n.vendor, "google");
        assert_eq!(n.action, "gmail.messages.send");
        assert_eq!(n.method, "POST");
        assert_eq!(n.layer, "policy");
        assert_eq!(n.policy_id, Some("gmail-external-send-gate"));
        assert_eq!(n.detail, Some("external recipient"));
        assert_eq!(n.requested_ops.len(), 1);
    }

    #[test]
    fn from_record_constructs_approve_and_reject_urls() {
        let ops: Vec<String> = vec![];
        let r = sample_record(&ops);
        let id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let n = BlockedNotification::from_record(id, &r, "https://proxy.example");
        assert_eq!(
            n.approve_url,
            "https://proxy.example/api/v1/blocked/01234567-89ab-cdef-0123-456789abcdef/approve"
        );
        assert_eq!(
            n.reject_url,
            "https://proxy.example/api/v1/blocked/01234567-89ab-cdef-0123-456789abcdef/reject"
        );
    }

    #[test]
    fn serializes_to_json_with_schema_field() {
        let ops = vec!["x".to_string()];
        let r = sample_record(&ops);
        let n = BlockedNotification::from_record(Uuid::nil(), &r, "https://x");
        let j = serde_json::to_value(&n).unwrap();
        assert_eq!(j["schema"], "proxilion.blocked_action.v1");
        assert_eq!(j["vendor"], "google");
        assert_eq!(j["action"], "gmail.messages.send");
    }

    #[test]
    fn schema_constant_is_versioned_string_consumers_key_on() {
        // The schema string is a stable contract — webhook receivers route
        // on `schema == "proxilion.blocked_action.v1"` and may parse
        // differently for `v2`. Pin both the value and the .vN suffix shape.
        assert_eq!(BlockedNotification::SCHEMA, "proxilion.blocked_action.v1");
        assert!(BlockedNotification::SCHEMA.starts_with("proxilion."));
        assert!(BlockedNotification::SCHEMA.ends_with(".v1"));
    }

    #[test]
    fn from_record_passes_none_fields_through_unchanged() {
        // `p_0`, `policy_id`, `detail`, `predecessor_pca_id` are all
        // Optional — when the source record carries None, the notification
        // must too, not synthesize a placeholder string. Downstream
        // receivers test key-presence; a stray "" or "(none)" would
        // mis-classify the blocked row as having a policy.
        let ops: Vec<String> = vec![];
        let r = BlockedActionRecord {
            request_id: Uuid::nil(),
            session_id: Uuid::nil(),
            p_0: None,
            vendor: "g",
            action: "a",
            method: "POST",
            path: "/p",
            layer: "invariant",
            policy_id: None,
            detail: None,
            predecessor_pca_id: None,
            requested_ops: &ops,
            escalation_after_minutes: None,
            request_canonical_json: None,
        };
        let n = BlockedNotification::from_record(Uuid::nil(), &r, "https://x");
        assert!(n.p_0.is_none());
        assert!(n.policy_id.is_none());
        assert!(n.detail.is_none());
        assert!(n.predecessor_pca_id.is_none());
        // And the JSON keeps them as JSON null (not absent — the struct
        // has no `skip_serializing_if`, so key-presence is part of the
        // contract receivers can rely on).
        let j = serde_json::to_value(&n).unwrap();
        assert!(j.get("p_0").is_some_and(|v| v.is_null()));
        assert!(j.get("policy_id").is_some_and(|v| v.is_null()));
    }

    #[test]
    fn from_record_carries_empty_requested_ops_slice() {
        // The PIC layer sometimes blocks without a discrete ops list
        // (e.g. a monotonicity refusal where the upstream body didn't
        // surface atoms). `requested_ops` must come through as an empty
        // slice, not be elided — Slack templates iterate it and expect
        // either content or an explicit "(none)" rendering at template time.
        let ops: Vec<String> = vec![];
        let r = sample_record(&ops);
        let n = BlockedNotification::from_record(Uuid::nil(), &r, "https://x");
        assert!(n.requested_ops.is_empty());
        let j = serde_json::to_value(&n).unwrap();
        assert_eq!(j["requested_ops"], serde_json::json!([]));
    }
}
