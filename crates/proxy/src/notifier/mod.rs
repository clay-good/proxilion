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
    fn approve_url_handles_trailing_slash_in_proxy_public_url() {
        // Operators sometimes paste their public URL with a trailing
        // slash. The current implementation does NOT strip it — the
        // resulting URL has a double slash before `/api/v1/...`. Pin
        // this exact behavior so a "fix the double slash" refactor
        // surfaces alongside the docs that tell operators to omit the
        // trailing slash. (HTTP routers normalize the double slash,
        // so this is currently functional — but the wire shape is
        // part of operator-facing observability.)
        let ops: Vec<String> = vec![];
        let r = sample_record(&ops);
        let n = BlockedNotification::from_record(Uuid::nil(), &r, "https://proxy.example/");
        assert!(
            n.approve_url
                .starts_with("https://proxy.example//api/v1/blocked/"),
            "got: {}",
            n.approve_url,
        );
    }

    #[test]
    fn from_record_carries_multi_op_slice_through_serialize() {
        // The PIC layer can produce multi-atom missing-ops lists. Pin
        // that all three atoms make it through `from_record` AND
        // through `serde_json::to_value` as a 3-element JSON array
        // — a regression that flattened the slice into a comma-joined
        // string (matching the Slack template's iteration shape) would
        // break webhook receivers that iterate the JSON array.
        let ops = vec![
            "drive:read:bob/secret.docx".to_string(),
            "drive:write:bob/*".to_string(),
            "gmail:send:bob@external.com".to_string(),
        ];
        let r = sample_record(&ops);
        let n = BlockedNotification::from_record(Uuid::nil(), &r, "https://x");
        assert_eq!(n.requested_ops.len(), 3);
        let j = serde_json::to_value(&n).unwrap();
        let arr = j["requested_ops"].as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], "drive:read:bob/secret.docx");
        assert_eq!(arr[2], "gmail:send:bob@external.com");
    }

    #[test]
    fn from_record_invariant_layer_round_trips_through_json() {
        // The `layer` field distinguishes "policy" blocks from
        // "invariant" blocks (PIC monotonicity refusals). The PIC path
        // sets `layer = "invariant"`, the policy path sets
        // `layer = "policy"` — pin that the value passes through to
        // the wire JSON verbatim so a Slack mrkdwn template's
        // `*Layer:* {{layer}}` render is byte-stable for both paths.
        let ops: Vec<String> = vec![];
        let r = BlockedActionRecord {
            request_id: Uuid::nil(),
            session_id: Uuid::nil(),
            p_0: None,
            vendor: "google",
            action: "drive.files.get",
            method: "GET",
            path: "/drive/v3/files/x",
            layer: "invariant",
            policy_id: None,
            detail: None,
            predecessor_pca_id: None,
            requested_ops: &ops,
            escalation_after_minutes: None,
            request_canonical_json: None,
        };
        let n = BlockedNotification::from_record(Uuid::nil(), &r, "https://x");
        assert_eq!(n.layer, "invariant");
        let j = serde_json::to_value(&n).unwrap();
        assert_eq!(j["layer"], "invariant");
    }

    #[test]
    fn debug_renders_struct_name_and_key_field_names_for_operator_grep() {
        // `BlockedNotification` flows through `tracing::warn!(?n, ...)` on
        // the notifier dispatch path when a fan-out hop fails — operators
        // grep the resulting log line by struct name AND by the
        // `blocked_id` / `request_id` / `schema` field names to bucket
        // which blocked row tripped which sink. A manual Debug that
        // dropped the struct-name prefix "for brevity" would silently
        // collapse all notifier-failure log lines onto each other; a
        // manual Debug that hid field names "to compact" the output
        // would strip every selector but the value. Pin the four-way
        // shape (struct name + three load-bearing field names) so a
        // refactor lands as a test failure rather than as a quiet
        // observability degradation.
        let ops: Vec<String> = vec![];
        let r = sample_record(&ops);
        let n = BlockedNotification::from_record(Uuid::nil(), &r, "https://x");
        let s = format!("{n:?}");
        assert!(s.contains("BlockedNotification"), "got: {s}");
        assert!(s.contains("blocked_id"), "got: {s}");
        assert!(s.contains("request_id"), "got: {s}");
        assert!(s.contains("schema"), "got: {s}");
    }

    #[test]
    fn approve_and_reject_urls_share_prefix_and_differ_only_by_verb_segment() {
        // The two URLs are constructed symmetrically — same scheme +
        // host + `/api/v1/blocked/{id}/` prefix, differing only by the
        // final `approve` vs `reject` segment. Pin this so a refactor
        // that introduced separate URL templates (e.g. one routes to
        // `/api/v1/blocked/{id}/approve` and the other to a different
        // endpoint family like `/approver/{id}/reject` for vendor
        // routing) would surface here as a structural divergence. The
        // Slack template + email template both build button URLs from
        // these two fields and rely on the prefix being identical.
        let ops: Vec<String> = vec![];
        let r = sample_record(&ops);
        let id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let n = BlockedNotification::from_record(id, &r, "https://proxy.example");
        let prefix = "https://proxy.example/api/v1/blocked/01234567-89ab-cdef-0123-456789abcdef/";
        assert!(n.approve_url.starts_with(prefix), "got: {}", n.approve_url);
        assert!(n.reject_url.starts_with(prefix), "got: {}", n.reject_url);
        assert_eq!(&n.approve_url[prefix.len()..], "approve");
        assert_eq!(&n.reject_url[prefix.len()..], "reject");
    }

    #[test]
    fn approve_and_reject_urls_each_contain_blocked_id_exactly_once() {
        // The blocked_id must appear ONCE in each URL — the path
        // template is `/api/v1/blocked/{id}/{verb}` and the verb segment
        // is a fixed literal. A refactor that accidentally interpolated
        // the id twice (e.g. `/blocked/{id}/{id}/approve` via a copy-paste
        // typo) would still pass a `.contains(id)` check but would route
        // operators to a 404. Pin the count.
        let ops: Vec<String> = vec![];
        let r = sample_record(&ops);
        let id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let n = BlockedNotification::from_record(id, &r, "https://proxy.example");
        let id_str = id.to_string();
        assert_eq!(
            n.approve_url.matches(&id_str).count(),
            1,
            "got: {}",
            n.approve_url
        );
        assert_eq!(
            n.reject_url.matches(&id_str).count(),
            1,
            "got: {}",
            n.reject_url
        );
    }

    #[test]
    fn from_record_with_empty_proxy_public_url_still_yields_well_formed_path() {
        // Operator boot-up edge case: `proxy_public_url` is sourced from
        // `PROXILION_PUBLIC_URL` env which an operator may leave empty
        // during initial install. The current implementation does NOT
        // validate the input — an empty base produces a path-only URL
        // starting with `/api/v1/blocked/{id}/approve`. Pin this so a
        // future hardening that started rejecting empty bases at
        // `from_record` time would surface here as a wire-shape change
        // rather than at a downstream HTTP send site. Today's contract
        // is "the operator gets the URL they configured, even if it's
        // empty"; the notifier doesn't second-guess.
        let ops: Vec<String> = vec![];
        let r = sample_record(&ops);
        let id = Uuid::nil();
        let n = BlockedNotification::from_record(id, &r, "");
        assert!(
            n.approve_url.starts_with("/api/v1/blocked/"),
            "got: {}",
            n.approve_url
        );
        assert!(
            n.approve_url.ends_with("/approve"),
            "got: {}",
            n.approve_url
        );
        assert!(
            n.reject_url.starts_with("/api/v1/blocked/"),
            "got: {}",
            n.reject_url
        );
        assert!(n.reject_url.ends_with("/reject"), "got: {}", n.reject_url);
    }

    #[test]
    fn schema_constant_is_static_str_with_exactly_three_dot_separated_segments() {
        // `SCHEMA: &'static str` is the version tag webhook receivers
        // route on. The dotted shape `proxilion.blocked_action.v1` has
        // exactly three segments (`vendor.family.version`) — a refactor
        // that flattened to `proxilion_blocked_action_v1` (underscore
        // form) would still pass the `.starts_with("proxilion.")` /
        // `.ends_with(".v1")` checks if `proxilion.` were re-prefixed
        // by accident, but cross-vendor schema registries bucket on
        // segment count. Pin both the count and the type-level static
        // bound (a refactor to `&str` with a runtime lifetime would
        // surface here as a compile break, not at the receiver).
        let _: &'static str = BlockedNotification::SCHEMA;
        let segments: Vec<&str> = BlockedNotification::SCHEMA.split('.').collect();
        assert_eq!(segments.len(), 3, "got: {segments:?}");
        assert_eq!(segments[0], "proxilion");
        assert_eq!(segments[1], "blocked_action");
        assert_eq!(segments[2], "v1");
    }

    #[test]
    fn from_record_passes_non_ascii_p_0_principal_through_verbatim() {
        // The `p_0` principal is end-user-supplied via the IdP claim
        // and can be a non-ASCII identifier (operators in jurisdictions
        // with localized email systems or non-Latin display names see
        // this routinely). The wire path must preserve the UTF-8 bytes
        // exactly — a refactor that introduced `.to_ascii_lowercase()`
        // or any normalization "for grep-friendliness" would silently
        // alter the principal that the human approver sees in the
        // Slack card / email body vs. the principal recorded in
        // `blocked_actions`, breaking forensic correlation. Pin a
        // mixed Cyrillic + email-local-part form end-to-end through
        // both the struct field and the JSON wire.
        let ops: Vec<String> = vec![];
        let p_0 = "алиса@демо.рф";
        let r = BlockedActionRecord {
            request_id: Uuid::nil(),
            session_id: Uuid::nil(),
            p_0: Some(p_0),
            vendor: "google",
            action: "drive.files.get",
            method: "GET",
            path: "/drive/v3/files/x",
            layer: "policy",
            policy_id: None,
            detail: None,
            predecessor_pca_id: None,
            requested_ops: &ops,
            escalation_after_minutes: None,
            request_canonical_json: None,
        };
        let n = BlockedNotification::from_record(Uuid::nil(), &r, "https://x");
        assert_eq!(n.p_0, Some(p_0));
        let j = serde_json::to_value(&n).unwrap();
        assert_eq!(j["p_0"], p_0);
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

    #[test]
    fn blocked_notification_serializes_with_exactly_sixteen_known_keys_for_webhook_consumer_contract()
     {
        // Webhook receivers (Slack incoming-webhook bridges, PagerDuty
        // routers, custom SOC integrations) key on the EXHAUSTIVE field
        // set of the v1 envelope. The existing tests pin individual keys
        // via substring `.contains` / `j["k"]` but never the SET as a
        // closed contract — a refactor adding `escalation_after_minutes`
        // "for ergonomic Slack template display" would silently ship a
        // 17th key to every receiver, and any consumer doing a closed-
        // set validation (PagerDuty's "extra field" warning) would
        // start emitting noise. Pin the 16-key set as exhaustive,
        // symmetric to round-161 PolicyView 5-key + round-165
        // TokenResponse 4-key + round-166 insert_proxy_headers 3-header
        // exhaustive-set pins extended to webhook envelope.
        let ops: Vec<String> = vec!["drive:read:a".into()];
        let r = sample_record(&ops);
        let n = BlockedNotification::from_record(Uuid::nil(), &r, "https://x");
        let j = serde_json::to_value(&n).unwrap();
        let obj = j
            .as_object()
            .expect("envelope must serialize as JSON object");
        let keys: std::collections::HashSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected: std::collections::HashSet<&str> = [
            "schema",
            "blocked_id",
            "request_id",
            "session_id",
            "p_0",
            "vendor",
            "action",
            "method",
            "path",
            "layer",
            "policy_id",
            "detail",
            "predecessor_pca_id",
            "requested_ops",
            "approve_url",
            "reject_url",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            keys, expected,
            "BlockedNotification v1 envelope must carry EXACTLY these 16 keys for webhook consumers",
        );
    }

    #[test]
    fn blocked_notification_static_borrow_is_send_sync_for_tokio_spawn_webhook_fanout() {
        // The webhook + slack + email fan-out spawns one task per driver
        // (`tokio::spawn(async move { driver.notify(&n).await })`); the
        // notification must be `Send` to cross the spawn boundary AND
        // `Sync` so multiple drivers can read the same envelope concurrently.
        // The 'a borrow makes Sync impossible at arbitrary lifetimes;
        // pin the 'static instantiation specifically — symmetric to
        // round-168 PicViolationRecord<'static> Send + Sync pin extended
        // to BlockedNotification at the fan-out boundary. A refactor
        // adding a non-Sync field (e.g. `RefCell<...>` for some
        // lazy-rendered URL "for performance") would break here rather
        // than at the spawn call site with an opaque trait-bound error.
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<BlockedNotification<'static>>();
    }

    #[test]
    fn from_record_preserves_multibyte_unicode_in_vendor_action_path_detail_verbatim() {
        // Symmetric to round-162 blocked.rs multibyte vendor + action +
        // round-166 google_drive PolicyBlocked.reason + round-167
        // calendar reason + round-168 parse_missing_atoms multibyte
        // pins extended to BlockedNotification's vendor + action + path
        // + detail fields. A copy-paste `to_ascii_lowercase()` "for SIEM
        // hygiene" landing on the from_record builder would silently
        // mangle non-ASCII vendor labels (a future Microsoft365 adapter
        // localized as `microsoft365.café` or a path including a
        // unicode file id). Pin byte-equal passthrough on 4 distinct
        // fields with multibyte content.
        let ops: Vec<String> = vec![];
        let multibyte_path = "/drive/files/café/secret.docx";
        let multibyte_detail = "policy `外部送信ブロック` denied to_domain=eve🔥@evil.example";
        let r = BlockedActionRecord {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            p_0: Some("alice@日本.jp"),
            vendor: "google.café",
            action: "drive.files.récupérer",
            method: "GET",
            path: multibyte_path,
            layer: "policy",
            policy_id: Some("drive-外部-gate"),
            detail: Some(multibyte_detail),
            predecessor_pca_id: None,
            requested_ops: &ops,
            escalation_after_minutes: None,
            request_canonical_json: None,
        };
        let n = BlockedNotification::from_record(Uuid::nil(), &r, "https://x");
        assert_eq!(n.vendor, "google.café");
        assert_eq!(n.action, "drive.files.récupérer");
        assert_eq!(n.path, multibyte_path);
        assert_eq!(n.detail, Some(multibyte_detail));
        assert_eq!(n.policy_id, Some("drive-外部-gate"));
        assert_eq!(n.p_0, Some("alice@日本.jp"));
        // And through JSON serialization — webhook receivers see the
        // exact same byte sequences.
        let j = serde_json::to_value(&n).unwrap();
        assert_eq!(j["vendor"], "google.café");
        assert_eq!(j["path"], multibyte_path);
        assert_eq!(j["detail"], multibyte_detail);
    }

    #[test]
    fn schema_constant_is_static_str_lifetime_for_zero_alloc_webhook_header_propagation() {
        // The SCHEMA constant is propagated into the X-Schema header of
        // outbound webhooks and into the Slack action_id; both flows
        // expect a 'static str so the value can be reused across an
        // unbounded number of notifications without allocation. The
        // existing pin (`schema_constant_is_versioned_string_consumers_key_on`)
        // walks the VALUE but not the LIFETIME — a refactor to
        // `pub const SCHEMA: String = String::from("...")` "for builder
        // ergonomics" would either fail compile (const fn String) or
        // silently flip the type to one that allocates per access. Pin
        // 'static via require_static_str — symmetric to round-163
        // ConfigError + round-165 oauth token_type + round-168
        // pic_mode static-str pins extended to BlockedNotification SCHEMA.
        fn require_static_str(_: &'static str) {}
        require_static_str(BlockedNotification::SCHEMA);
        // Also pin: the `schema` field on a BlockedNotification instance
        // is the SAME &'static str, not a String allocated from it.
        let ops: Vec<String> = vec![];
        let r = sample_record(&ops);
        let n = BlockedNotification::from_record(Uuid::nil(), &r, "https://x");
        require_static_str(n.schema);
    }

    #[test]
    fn approve_and_reject_urls_carry_no_query_string_for_csrf_token_round_trip() {
        // The approver UI (ui-less-surfaces.md §10.4) builds an HTML
        // form that POSTs back to these URLs; the URLs themselves must
        // NOT carry a query string because the CSRF token is signed
        // separately and surfaced as a form-body field, not a URL param
        // (the URL would leak via Referer headers on the redirect).
        // The existing pins walk URL structure and verb-segment
        // differentiation but never the no-query-string contract — a
        // refactor that appended `?token=...` "for one-click approve
        // from email links" would silently re-introduce the leak.
        // Pin the absence of `?` (and `#` fragment) on both URLs.
        let ops: Vec<String> = vec![];
        let r = sample_record(&ops);
        let n = BlockedNotification::from_record(Uuid::nil(), &r, "https://proxy.example.com");
        assert!(
            !n.approve_url.contains('?'),
            "approve URL must not carry query string: {}",
            n.approve_url,
        );
        assert!(
            !n.reject_url.contains('?'),
            "reject URL must not carry query string: {}",
            n.reject_url,
        );
        assert!(
            !n.approve_url.contains('#'),
            "approve URL must not carry fragment: {}",
            n.approve_url,
        );
        assert!(
            !n.reject_url.contains('#'),
            "reject URL must not carry fragment: {}",
            n.reject_url,
        );
    }

    #[test]
    fn from_record_is_referentially_transparent_across_fifty_repeated_calls_on_same_input() {
        // Symmetric to round-161 parse_listing + round-162 canonical_request_json
        // + round-166 enforce_pre_request_decision + round-168
        // parse_missing_atoms referential-transparency pins extended to
        // BlockedNotification::from_record. The fan-out path may call
        // `from_record` multiple times if the operator clicks "resend"
        // on a stale notification; a refactor caching the JSON via a
        // once-cell keyed on `&record as *const _` "for hot-path perf"
        // would silently return stale URLs on a record whose
        // blocked_id was reissued. Pin 50 calls on the same record
        // produce byte-equal JSON.
        let ops: Vec<String> = vec!["drive:read:a".into(), "gmail:send:b".into()];
        let r = sample_record(&ops);
        let blocked_id = Uuid::new_v4();
        let baseline = serde_json::to_string(&BlockedNotification::from_record(
            blocked_id,
            &r,
            "https://x.example",
        ))
        .unwrap();
        for i in 0..50 {
            let again = serde_json::to_string(&BlockedNotification::from_record(
                blocked_id,
                &r,
                "https://x.example",
            ))
            .unwrap();
            assert_eq!(
                again, baseline,
                "iteration {i}: from_record + serialize must be referentially transparent",
            );
        }
    }
}
