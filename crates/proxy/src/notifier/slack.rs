//! Slack interactive notifier (ui-less-surfaces.md §5.3).
//!
//! Two halves:
//!   * outbound — posts a Block Kit message to a Slack incoming-webhook URL
//!     when a blocked-action row commits. Buttons carry `approve:<uuid>` /
//!     `reject:<uuid>` values so the interaction webhook can route them.
//!   * inbound — `POST /api/v1/notifier/slack/interact` (lives in
//!     `crate::api::notifier_slack`) verifies the request via Slack's
//!     `v0=<hmac>` signed-request scheme + 5-minute timestamp skew window
//!     and calls `approve_inner` / `reject_inner` on the matched blocked
//!     row.
//!
//! Authentication for outbound: Slack incoming webhooks are themselves
//! capability URLs — possession is authority. We treat the URL as
//! credential material and persist it only in `notifier_config.config`
//! (redacted on GET), never in env.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, warn};
use uuid::Uuid;

use super::BlockedNotification;
use super::burst::{BurstSummary, BurstSuppressor};

type HmacSha256 = Hmac<Sha256>;

/// Slack signing secret — the 32-char hex string Slack shows you on the
/// app's "Basic Information" page. Used to verify inbound interaction
/// webhooks, NOT to sign outbound posts (incoming-webhook URLs are
/// already capability-style auth).
#[derive(Clone)]
pub struct SlackSigningSecret(Vec<u8>);

impl SlackSigningSecret {
    pub fn new(s: impl Into<String>) -> Self {
        // Slack signing secrets are 32-char hex strings, but Slack treats
        // them as opaque bytes — we just keep the original.
        Self(s.into().into_bytes())
    }

    /// Verify Slack's `v0=<hmac>` scheme.
    ///
    /// `signature` is the value of `X-Slack-Signature` (must start with
    /// `v0=`). `timestamp` is `X-Slack-Request-Timestamp`. `body` is the
    /// raw form-encoded request bytes.
    pub fn verify(&self, signature: &str, timestamp: &str, body: &[u8]) -> bool {
        let Some(sig_hex) = signature.strip_prefix("v0=") else {
            return false;
        };
        // 5-minute skew window (Slack docs).
        let ts: u64 = match timestamp.parse() {
            Ok(t) => t,
            Err(_) => return false,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.abs_diff(ts) > 300 {
            return false;
        }
        let mut basestring = format!("v0:{ts}:").into_bytes();
        basestring.extend_from_slice(body);
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(&basestring);
        let tag = mac.finalize().into_bytes();
        let mut hex = String::with_capacity(tag.len() * 2);
        for b in tag {
            use std::fmt::Write;
            write!(&mut hex, "{:02x}", b).unwrap();
        }
        // Constant-time compare.
        use subtle::ConstantTimeEq;
        hex.as_bytes().ct_eq(sig_hex.as_bytes()).into()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("slack build: {0}")]
pub struct SlackBuildError(pub String);

pub struct SlackNotifier {
    incoming_webhook_url: String,
    signing_secret: SlackSigningSecret,
    proxy_public_url: String,
    http: reqwest::Client,
    /// Optional burst suppressor (ui-less-surfaces.md §5.3 dev 5 / §5.6).
    /// When set, `notify()` consults it before POSTing; suppressed
    /// events are collapsed into a single summary message emitted by the
    /// flush loop via `notify_summary`.
    burst: Option<BurstSuppressor>,
    /// Map of Slack user id (e.g. `U01ABC`) and/or username (without `@`)
    /// to a stable operator subject — typically the operator's email. When
    /// the interaction webhook resolves the clicker, this map is consulted
    /// first so the attested override carries the operator's identity
    /// rather than an opaque `slack:<username>`. Closes ui-less-surfaces.md
    /// §5.3 dev 4.
    user_map: HashMap<String, String>,
}

impl SlackNotifier {
    pub fn new(
        incoming_webhook_url: String,
        signing_secret: SlackSigningSecret,
        proxy_public_url: String,
    ) -> Result<Self, SlackBuildError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent(concat!(
                "Proxilion-Slack/",
                env!("CARGO_PKG_VERSION"),
                " (+https://proxilion.com)"
            ))
            .build()
            .map_err(|e| SlackBuildError(e.to_string()))?;
        Ok(Self {
            incoming_webhook_url,
            signing_secret,
            proxy_public_url,
            http,
            burst: None,
            user_map: HashMap::new(),
        })
    }

    /// Attach a burst suppressor. Without it the notifier passes every
    /// event through unconditionally.
    pub fn with_burst(mut self, suppressor: BurstSuppressor) -> Self {
        self.burst = Some(suppressor);
        self
    }

    /// Replace the slack-user → operator-subject map.
    pub fn with_user_map(mut self, map: HashMap<String, String>) -> Self {
        self.user_map = map;
        self
    }

    /// Resolve a Slack user (id or username) to a configured operator
    /// subject. Returns `None` when no mapping is configured for either
    /// key — callers fall back to the `slack:<username>` shape.
    pub fn resolve_user(
        &self,
        slack_user_id: Option<&str>,
        slack_username: Option<&str>,
    ) -> Option<String> {
        if let Some(id) = slack_user_id {
            if let Some(v) = self.user_map.get(id) {
                return Some(v.clone());
            }
        }
        if let Some(u) = slack_username {
            if let Some(v) = self.user_map.get(u) {
                return Some(v.clone());
            }
        }
        None
    }

    pub fn signing_secret(&self) -> &SlackSigningSecret {
        &self.signing_secret
    }

    pub fn proxy_public_url(&self) -> &str {
        &self.proxy_public_url
    }

    /// POST a Block Kit message to the incoming webhook. Best-effort.
    pub async fn notify(&self, n: &BlockedNotification<'_>) {
        if let Some(b) = &self.burst {
            if !b.admit(n, Instant::now()).await {
                // Suppressed — the flush loop will emit a thread-style
                // summary message for this bucket.
                return;
            }
        }
        let payload = block_kit_payload(n);
        match self
            .http
            .post(&self.incoming_webhook_url)
            .header("content-type", "application/json")
            .body(payload.to_string())
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                metrics::counter!(
                    "proxilion_slack_post_total",
                    "result" => "ok",
                    "layer" => n.layer.to_string()
                )
                .increment(1);
                debug!(blocked_id = %n.blocked_id, "slack post ok");
            }
            Ok(r) => {
                warn!(status = %r.status(), "slack: incoming-webhook non-success");
                metrics::counter!(
                    "proxilion_slack_post_failures_total",
                    "reason" => "http_error"
                )
                .increment(1);
            }
            Err(e) => {
                warn!(error = %e, "slack: transport error");
                metrics::counter!(
                    "proxilion_slack_post_failures_total",
                    "reason" => "transport"
                )
                .increment(1);
            }
        }
    }

    /// POST a single Slack message that summarizes a burst. Uses a
    /// dedicated Block Kit layout so receivers can visually distinguish
    /// summaries from per-event approvals — the summary has *no*
    /// approve/reject buttons (clicking through to the full queue is
    /// the operator's path).
    pub async fn notify_summary(&self, s: &BurstSummary) {
        let payload = summary_block_kit_payload(s);
        match self
            .http
            .post(&self.incoming_webhook_url)
            .header("content-type", "application/json")
            .body(payload.to_string())
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                metrics::counter!(
                    "proxilion_slack_summary_sent_total",
                    "policy_id" => s.policy_id.clone()
                )
                .increment(1);
                debug!(policy_id = %s.policy_id, suppressed = s.suppressed_count, "slack summary delivered");
            }
            Ok(r) => {
                warn!(status = %r.status(), "slack summary: non-success");
                metrics::counter!(
                    "proxilion_slack_summary_failures_total",
                    "reason" => "http_error"
                )
                .increment(1);
            }
            Err(e) => {
                warn!(error = %e, "slack summary: transport error");
                metrics::counter!(
                    "proxilion_slack_summary_failures_total",
                    "reason" => "transport"
                )
                .increment(1);
            }
        }
    }
}

/// Build the Block Kit JSON for a burst summary message. ui-less-surfaces.md §5.6.
fn summary_block_kit_payload(s: &BurstSummary) -> serde_json::Value {
    let header = format!("📦 {} suppressed", plural(s.suppressed_count, "block"));
    let p_0 = s.p_0.as_deref().unwrap_or("(any)");
    let exemplar_line = match &s.exemplar {
        Some(e) => format!(
            "*Exemplar:* `{}.{}` (layer `{}`)",
            e.vendor, e.action, e.layer
        ),
        None => "*Exemplar:* —".to_string(),
    };
    let mut blocks = vec![
        serde_json::json!({
            "type": "header",
            "text": { "type": "plain_text", "text": header }
        }),
        serde_json::json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!(
                    "*Policy:* `{}`  ·  *p_0:* `{}`\n*Window:* {}s  ·  *Suppressed:* {}\n{}",
                    s.policy_id, p_0, s.window_seconds, s.suppressed_count, exemplar_line
                )
            }
        }),
    ];
    if !s.details_url.is_empty() {
        blocks.push(serde_json::json!({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": { "type": "plain_text", "text": "Open full list" },
                    "url": s.details_url,
                }
            ]
        }));
    }
    serde_json::json!({ "blocks": blocks })
}

fn plural(n: u64, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// Build the Block Kit JSON. Format mirrors ui-less-surfaces.md §5.3.
/// Buttons carry `value: "approve:<blocked_id>"` / `"reject:<blocked_id>"`
/// — the interaction webhook parses these to route to approve_inner /
/// reject_inner.
fn block_kit_payload(n: &BlockedNotification<'_>) -> serde_json::Value {
    let header = format!("🛑 Blocked: {}", n.action);
    let p_0 = n.p_0.unwrap_or("(unknown)");
    let policy = n.policy_id.unwrap_or("—");
    let detail = n.detail.unwrap_or("");
    let context = format!(
        "*Policy:* `{policy}`  ·  *Layer:* {layer}\n*p_0:* `{p_0}`\n*Path:* `{path}`",
        layer = n.layer,
        path = n.path,
    );
    let approve_value = format!("approve:{}", n.blocked_id);
    let reject_value = format!("reject:{}", n.blocked_id);
    let why_value = format!("why:{}", n.blocked_id);

    serde_json::json!({
        "blocks": [
            { "type": "header",
              "text": { "type": "plain_text", "text": header } },
            { "type": "section",
              "text": { "type": "mrkdwn", "text": context } },
            { "type": "context",
              "elements": [
                  { "type": "mrkdwn", "text": format!("_{}_", truncate(detail, 140)) }
              ] },
            { "type": "actions",
              "elements": [
                  { "type": "button",
                    "text": { "type": "plain_text", "text": "Approve" },
                    "style": "primary",
                    "value": approve_value },
                  { "type": "button",
                    "text": { "type": "plain_text", "text": "Reject" },
                    "style": "danger",
                    "value": reject_value },
                  { "type": "button",
                    "text": { "type": "plain_text", "text": "Why?" },
                    "value": why_value }
              ] },
            { "type": "context",
              "elements": [
                  { "type": "mrkdwn",
                    "text": format!("blocked_id `{}` · expires in 30m", n.blocked_id) }
              ] }
        ],
    })
}

fn truncate(s: &str, n: usize) -> String {
    let mut out: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        out.push('…');
    }
    out
}

/// Parse a Slack button `value` field into `(action, blocked_id)`. Returns
/// `None` on any shape failure.
pub fn parse_button_value(v: &str) -> Option<(SlackAction, Uuid)> {
    let (action_str, id_str) = v.split_once(':')?;
    let action = match action_str {
        "approve" => SlackAction::Approve,
        "reject" => SlackAction::Reject,
        "why" => SlackAction::Why,
        _ => return None,
    };
    let id = Uuid::parse_str(id_str).ok()?;
    Some((action, id))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlackAction {
    Approve,
    Reject,
    /// ui-less-surfaces.md §5.3: "[Why?]" — operator wants forensic
    /// context for the blocked row without taking action. Handled with
    /// an ephemeral Slack response, no state change.
    Why,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn n() -> BlockedNotification<'static> {
        BlockedNotification {
            schema: BlockedNotification::SCHEMA,
            blocked_id: Uuid::nil(),
            request_id: Uuid::nil(),
            session_id: Uuid::nil(),
            p_0: Some("alice@acme.com"),
            vendor: "google",
            action: "gmail.messages.send",
            method: "POST",
            path: "/gmail/v1/users/me/messages/send",
            layer: "policy",
            policy_id: Some("gmail-external"),
            detail: Some("external recipient"),
            predecessor_pca_id: None,
            requested_ops: &[],
            approve_url: String::new(),
            reject_url: String::new(),
        }
    }

    #[test]
    fn block_kit_payload_has_header_and_buttons() {
        let p = block_kit_payload(&n());
        assert_eq!(p["blocks"][0]["type"], "header");
        let actions = &p["blocks"][3]["elements"];
        assert_eq!(actions[0]["value"], format!("approve:{}", Uuid::nil()));
        assert_eq!(actions[1]["value"], format!("reject:{}", Uuid::nil()));
        assert_eq!(actions[2]["value"], format!("why:{}", Uuid::nil()));
        assert_eq!(actions[0]["style"], "primary");
        assert_eq!(actions[1]["style"], "danger");
        // Why button is neutral (no `style` attribute).
        assert!(actions[2].get("style").is_none());
    }

    #[test]
    fn parse_button_value_round_trip_why() {
        let id = Uuid::new_v4();
        let (a, parsed) = parse_button_value(&format!("why:{id}")).unwrap();
        assert_eq!(a, SlackAction::Why);
        assert_eq!(parsed, id);
    }

    #[test]
    fn user_map_resolves_by_id_then_username() {
        let mut m = HashMap::new();
        m.insert("U01ABC".to_string(), "alice@acme.com".to_string());
        m.insert("bob".to_string(), "bob@acme.com".to_string());
        let n = SlackNotifier::new(
            "https://hooks.slack.com/services/T/B/X".into(),
            SlackSigningSecret::new("s"),
            "https://proxy.local".into(),
        )
        .unwrap()
        .with_user_map(m);
        assert_eq!(
            n.resolve_user(Some("U01ABC"), None).as_deref(),
            Some("alice@acme.com")
        );
        assert_eq!(
            n.resolve_user(None, Some("bob")).as_deref(),
            Some("bob@acme.com")
        );
        // Id takes precedence over username.
        assert_eq!(
            n.resolve_user(Some("U01ABC"), Some("bob")).as_deref(),
            Some("alice@acme.com")
        );
        // Unmapped → None.
        assert!(n.resolve_user(Some("U_UNKNOWN"), Some("charlie")).is_none());
    }

    #[test]
    fn parse_button_value_round_trip() {
        let id = Uuid::new_v4();
        let v = format!("approve:{id}");
        let (a, parsed) = parse_button_value(&v).unwrap();
        assert_eq!(a, SlackAction::Approve);
        assert_eq!(parsed, id);
    }

    #[test]
    fn parse_button_rejects_bad_shape() {
        assert!(parse_button_value("approve").is_none());
        assert!(parse_button_value("delete:abc-not-uuid").is_none());
        assert!(parse_button_value(&format!("unknown:{}", Uuid::nil())).is_none());
    }

    #[test]
    fn verify_signed_request() {
        let secret = SlackSigningSecret::new("8f742231b10e8888abcd99e1b18bf76c");
        // Use a real timestamp close to now so the skew window passes.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let body = b"token=xyzz0WbapA4vBCDEFasx0q6G&action=approve";
        let basestring = format!("v0:{ts}:");
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(b"8f742231b10e8888abcd99e1b18bf76c").unwrap();
        mac.update(basestring.as_bytes());
        mac.update(body);
        let tag = mac.finalize().into_bytes();
        let mut sig = String::from("v0=");
        for b in tag {
            use std::fmt::Write;
            write!(&mut sig, "{:02x}", b).unwrap();
        }
        assert!(secret.verify(&sig, &ts, body));
    }

    #[test]
    fn verify_rejects_old_timestamp() {
        let secret = SlackSigningSecret::new("8f742231b10e8888abcd99e1b18bf76c");
        // 10 minutes ago — outside skew window.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ts = (now - 600).to_string();
        let body = b"x=1";
        // Compute a real signature so we know the timestamp is the only
        // reason for rejection.
        let basestring = format!("v0:{ts}:");
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(b"8f742231b10e8888abcd99e1b18bf76c").unwrap();
        mac.update(basestring.as_bytes());
        mac.update(body);
        let tag = mac.finalize().into_bytes();
        let mut sig = String::from("v0=");
        for b in tag {
            use std::fmt::Write;
            write!(&mut sig, "{:02x}", b).unwrap();
        }
        assert!(!secret.verify(&sig, &ts, body));
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let secret = SlackSigningSecret::new("8f742231b10e8888abcd99e1b18bf76c");
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let basestring = format!("v0:{ts}:");
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(b"8f742231b10e8888abcd99e1b18bf76c").unwrap();
        mac.update(basestring.as_bytes());
        mac.update(b"action=approve");
        let tag = mac.finalize().into_bytes();
        let mut sig = String::from("v0=");
        for b in tag {
            use std::fmt::Write;
            write!(&mut sig, "{:02x}", b).unwrap();
        }
        // Verify with a TAMPERED body.
        assert!(!secret.verify(&sig, &ts, b"action=reject"));
    }

    #[test]
    fn summary_block_kit_has_header_and_open_full_list_button_when_url_present() {
        let s = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "gmail-x".into(),
            p_0: Some("alice@acme.com".into()),
            suppressed_count: 7,
            window_seconds: 60,
            exemplar: Some(super::super::burst::SuppressedEvent {
                policy_id: "gmail-x".into(),
                p_0: Some("alice@acme.com".into()),
                vendor: "google".into(),
                action: "gmail.messages.send".into(),
                layer: "policy".into(),
            }),
            details_url: "https://proxy.local/api/v1/blocked?policy_id=gmail-x".into(),
        };
        let p = summary_block_kit_payload(&s);
        let blocks = p["blocks"].as_array().unwrap();
        // Header carries the count.
        let header_text = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(header_text.contains("7"));
        // The mrkdwn section mentions the policy_id and the exemplar.
        let section_text = blocks[1]["text"]["text"].as_str().unwrap();
        assert!(section_text.contains("gmail-x"));
        assert!(section_text.contains("gmail.messages.send"));
        // Action block with the "Open full list" button points at details_url.
        let actions = blocks[2]["elements"].as_array().unwrap();
        assert_eq!(actions[0]["text"]["text"], "Open full list");
        assert_eq!(
            actions[0]["url"],
            "https://proxy.local/api/v1/blocked?policy_id=gmail-x"
        );
    }

    #[test]
    fn summary_block_kit_omits_button_when_url_empty() {
        let s = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "p".into(),
            p_0: None,
            suppressed_count: 1,
            window_seconds: 60,
            exemplar: None,
            details_url: String::new(),
        };
        let p = summary_block_kit_payload(&s);
        let blocks = p["blocks"].as_array().unwrap();
        // Header + section, no action block.
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn slack_build_error_display_carries_slack_build_prefix() {
        // Operator-facing error envelope: the prefix lets setup-status
        // surface this distinctly from a webhook or SIEM build fault.
        let e = SlackBuildError("reqwest client: dns resolve failed".into());
        assert_eq!(
            e.to_string(),
            "slack build: reqwest client: dns resolve failed"
        );
    }

    #[test]
    fn plural_renders_singular_at_one_and_pluralizes_zero_and_many() {
        // Slack copy reads "1 block suppressed" vs "0 blocks suppressed" /
        // "7 blocks suppressed". A regression that treated only `n == 0` as
        // plural (the natural off-by-one) would surface here as "0 block".
        assert_eq!(plural(0, "block"), "0 blocks");
        assert_eq!(plural(1, "block"), "1 block");
        assert_eq!(plural(2, "block"), "2 blocks");
        assert_eq!(plural(42, "request"), "42 requests");
    }

    #[test]
    fn truncate_passes_short_through_and_ellipsizes_at_overflow() {
        // No ellipsis when within limit (exact-limit included — `chars().count() > n`
        // is strict greater-than).
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello", 5), "hello");
        // Overflow adds a single horizontal-ellipsis char (one codepoint,
        // three bytes — the slack `mrkdwn` element renders it as a single
        // glyph; a regression that emitted `...` instead would break the
        // 140-char visual width budget the context block depends on).
        let out = truncate("hello world", 5);
        assert_eq!(out, "hello…");
    }

    #[test]
    fn truncate_uses_char_count_not_byte_len_for_multibyte_input() {
        // Each Greek alpha is two bytes; `n=3` must keep three glyphs, not
        // three bytes (which would split a codepoint and panic the
        // serializer downstream).
        assert_eq!(truncate("ααααα", 3), "ααα…");
        // Symmetric: at exact-limit no ellipsis even when bytes > n.
        assert_eq!(truncate("ααα", 3), "ααα");
    }

    #[test]
    fn parse_button_value_round_trip_reject_action() {
        // The existing test pinned `approve` and `why`; pin `reject` too —
        // it's the destructive action and the interaction webhook routes
        // on the variant identity.
        let id = Uuid::new_v4();
        let (a, parsed) = parse_button_value(&format!("reject:{id}")).unwrap();
        assert_eq!(a, SlackAction::Reject);
        assert_eq!(parsed, id);
    }

    #[test]
    fn parse_button_value_rejects_known_action_with_bad_uuid() {
        // The split + verb-match succeeds but the second half is not a
        // valid UUID — the function must return None rather than panic
        // or fall through to a default UUID.
        assert!(parse_button_value("approve:not-a-uuid").is_none());
        assert!(parse_button_value("reject:").is_none());
        // Multiple colons: split_once takes the first, so the verb is
        // "approve" and the rest "abc:def" — neither a valid UUID nor a
        // re-split target.
        assert!(parse_button_value("approve:abc:def").is_none());
    }

    #[test]
    fn slack_action_copy_and_eq_traits_work_at_use_sites() {
        // The interaction webhook routes by matching on the enum variant
        // after a `Copy`; a regression that dropped `Copy` or `PartialEq`
        // would surface here as a compile error rather than as a confusing
        // failure at the routing call site.
        let a = SlackAction::Approve;
        let a2 = a; // Copy
        assert_eq!(a, a2);
        assert_ne!(SlackAction::Approve, SlackAction::Reject);
        assert_ne!(SlackAction::Reject, SlackAction::Why);
    }

    #[test]
    fn resolve_user_returns_none_when_map_is_empty_or_no_inputs() {
        // The default `SlackNotifier::new` constructor leaves the user
        // map empty — every lookup must surface None (caller falls back
        // to `slack:<username>`). A regression that pre-seeded a default
        // mapping would attribute overrides to the wrong subject.
        let n = SlackNotifier::new(
            "https://hooks.slack.com/services/T/B/X".into(),
            SlackSigningSecret::new("s"),
            "https://proxy.local".into(),
        )
        .unwrap();
        assert!(n.resolve_user(Some("U01ABC"), None).is_none());
        assert!(n.resolve_user(None, Some("alice")).is_none());
        // Both inputs None — never matches.
        assert!(n.resolve_user(None, None).is_none());
        // Public-URL accessor pins the field-name round-trip while we
        // already hold a notifier (cheap symmetric guard for a getter the
        // approve/reject URL builders depend on).
        assert_eq!(n.proxy_public_url(), "https://proxy.local");
    }

    #[test]
    fn verify_rejects_wrong_prefix() {
        let secret = SlackSigningSecret::new("abc");
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        // No "v0=" prefix.
        assert!(!secret.verify("abcdef0123", &ts, b"x"));
    }

    #[test]
    fn truncate_at_exact_n_passes_through_without_appending_ellipsis() {
        // The `truncate` helper uses strict `> n` for the append-ellipsis
        // predicate. The exact-equal boundary (chars == n) must return
        // the prefix verbatim with NO ellipsis suffix. Different shape
        // from the read_filter sibling helper (which uses `<= n` on the
        // no-truncate branch); the symmetric pin here catches a "harmonize
        // the two helpers" refactor that flipped one direction without
        // updating the other — the 140-char context-block budget the
        // `block_kit_payload` site depends on relies on this exact
        // boundary not eating the final visible char.
        let s: String = "x".repeat(140);
        assert_eq!(truncate(&s, 140), s);
        assert!(!truncate(&s, 140).ends_with('…'));
        // Just-over by one char surfaces the ellipsis.
        let over: String = "x".repeat(141);
        let t = truncate(&over, 140);
        assert!(t.ends_with('…'));
        assert_eq!(t.chars().count(), 141); // 140 prefix + ellipsis
    }

    #[test]
    fn plural_pluralizes_word_that_already_ends_in_s_naively() {
        // The `plural` helper is a naive "append s" formatter — it does
        // NOT know about English plurals (`box` → `boxes`, `query` →
        // `queries`). Pin the current naive shape so a future "smart
        // pluralizer" refactor would surface here as a wire-shape change
        // (operator-facing message rendering) rather than silently
        // changing every burst-summary subject line. The boundary that
        // matters is the `word == s` case: `1 block` (good), `2 blocks`
        // (good), `2 blockss` would be wrong but only the boundary on a
        // word ending in `s` produces the visibly-awkward `processs`. We
        // pin the naive behavior across both 1 (singular) and many.
        assert_eq!(plural(1, "process"), "1 process");
        assert_eq!(plural(2, "process"), "2 processs");
        assert_eq!(plural(0, "block"), "0 blocks");
    }

    /// Silence unused-import warnings on the no-test build paths.
    #[allow(dead_code)]
    fn _used(_: chrono::DateTime<Utc>) {}
}
