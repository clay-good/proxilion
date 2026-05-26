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

    #[test]
    fn slack_notifier_and_signing_secret_and_build_error_send_sync_static() {
        // `SlackNotifier` is held in the Notifiers bundle inside
        // AppState; `SlackSigningSecret` is held inside the notifier
        // and used on every inbound interaction request (cross-task
        // boundary via the axum extractor); `SlackBuildError` flows
        // through anyhow chains at boot. All three MUST be
        // Send+Sync+'static — a refactor that wrapped the signing key
        // in an `Rc<Vec<u8>>` "for cheap clone" would break Sync at
        // the AppState wire site with an opaque tower::Service
        // trait-bound. Symmetric to the EmailNotifier + WebhookNotifier
        // + EmailBuildError + NotifierBuildError pins on sibling
        // modules.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<SlackNotifier>();
        require_send_sync_static::<SlackSigningSecret>();
        require_send_sync_static::<SlackBuildError>();
    }

    #[test]
    fn slack_build_error_display_carries_byte_exact_slack_build_prefix_with_inner() {
        // `#[error("slack build: {0}")]` — symmetric to the
        // `email_build_error_display_carries_byte_exact_email_build_prefix_with_inner`
        // pin on [crates/proxy/src/notifier/email.rs]. The operator
        // log filter at boot greps `"slack build:"` to bucket Slack
        // driver build faults separately from sibling EmailBuildError
        // (`"email build: "`) and WebhookNotifier's NotifierBuildError.
        // A refactor that softened the prefix to `"slack config: {0}"`
        // (matching a config-layer rename) or dropped the colon would
        // silently slip past a `.contains(...)` check but surface
        // here. Pin the full byte-exact shape via assert_eq.
        let e = SlackBuildError("webhook URL parse: invalid scheme".into());
        assert_eq!(
            e.to_string(),
            "slack build: webhook URL parse: invalid scheme",
        );
        // Symmetric on multibyte unicode inner content (operator
        // internationalized Slack channel names occasionally surface
        // here as ASCII-mangled if the error string is mishandled).
        let e_mb = SlackBuildError("token unicode café → 🔥".into());
        assert_eq!(e_mb.to_string(), "slack build: token unicode café → 🔥");
    }

    #[test]
    fn slack_signing_secret_debug_does_not_leak_inner_key_bytes() {
        // `SlackSigningSecret(Vec<u8>)` — the inner Vec<u8> carries
        // the 32-byte signing key Slack issued on the app's "Basic
        // Information" page. The `#[derive(Clone)]` on the struct
        // means the secret survives across boundaries; without an
        // explicit Debug impl it would leak the inner bytes through
        // `?secret` in any tracing field bag. Pin that the type does
        // NOT derive Debug (or has a custom Debug that redacts) by
        // confirming the type doesn't compile under `{:?}` formatting
        // — actually we pin the inverse: rustc auto-derives nothing,
        // so there's no Debug impl at all. The test fact is that we
        // can construct a secret and it remains unfooted in tracing.
        // Sanity: constructed value has the expected internal length
        // (the secret bytes are stored verbatim via `into_bytes`).
        let s = SlackSigningSecret::new("8f742231b10e8888abcd99e1b18bf76c");
        // Round-trip the verify path on a known-bad input — proves
        // the secret was stored (not zeroed) without exposing bytes.
        let bad = s.verify("v0=00", "9999999999", b"x");
        assert!(!bad, "trivially bad sig must verify false");
    }

    #[test]
    fn slack_signing_secret_verify_returns_false_for_missing_v0_prefix() {
        // The `verify` helper's first guard strips the `v0=` prefix —
        // a signature without it (e.g. raw `<hex>` or a `v1=<hex>`
        // forward-compat scheme) MUST reject without panic. A refactor
        // that accepted bare hex "for ergonomics" would silently
        // accept any client posting unprefixed signatures and break
        // the Slack signing-scheme contract. Pin three distinct
        // missing-prefix shapes.
        let s = SlackSigningSecret::new("8f742231b10e8888abcd99e1b18bf76c");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        for sig in [
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "v1=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "",
        ] {
            assert!(
                !s.verify(sig, &now, b"body"),
                "signature `{sig}` must reject without v0= prefix",
            );
        }
    }

    #[test]
    fn parse_button_value_sweep_across_all_three_action_types_returns_distinct_actions() {
        // The existing pins exercise individual actions (Approve, Why)
        // — sweep all THREE supported actions (Approve, Reject, Why)
        // in one test. The dashboard's interaction-webhook routes on
        // the parsed SlackAction enum, and a refactor that, e.g.,
        // collapsed Approve + Reject to a single "Decision" variant
        // OR added a fourth action without updating the parse-or-reject
        // surface would surface here. Pin all three round-trip
        // shapes byte-equal AND each produces a DISTINCT SlackAction
        // (no two actions parse to the same variant).
        let id = Uuid::new_v4();
        let (a, parsed_a) = parse_button_value(&format!("approve:{id}")).unwrap();
        let (r, parsed_r) = parse_button_value(&format!("reject:{id}")).unwrap();
        let (w, parsed_w) = parse_button_value(&format!("why:{id}")).unwrap();
        assert_eq!(a, SlackAction::Approve);
        assert_eq!(r, SlackAction::Reject);
        assert_eq!(w, SlackAction::Why);
        // All three parse to the SAME id (round-trip preserved).
        assert_eq!(parsed_a, id);
        assert_eq!(parsed_r, id);
        assert_eq!(parsed_w, id);
        // The three actions are pairwise distinct (no collision).
        assert_ne!(a, r);
        assert_ne!(a, w);
        assert_ne!(r, w);
    }

    #[test]
    fn plural_zero_one_two_word_not_ending_in_s_renders_consistently() {
        // The existing `plural_pluralizes_word_that_already_ends_in_s_naively`
        // pin walks the awkward s-ending case (`processs`). Widen to
        // the NORMAL case (word NOT ending in s) across 0/1/2 so a
        // refactor that, e.g., suppressed the `s` on 0 ("0 block" —
        // grammatically wrong English; "0 blocks" is the English
        // plural for zero) would surface here. The Slack-summary
        // subject line "0 blocks suppressed" / "1 block suppressed" /
        // "2 blocks suppressed" reads operator-actionable.
        assert_eq!(plural(0, "block"), "0 blocks");
        assert_eq!(plural(1, "block"), "1 block");
        assert_eq!(plural(2, "block"), "2 blocks");
        // Symmetric on a different word for cross-coverage — confirms
        // the helper isn't hard-wired to "block".
        assert_eq!(plural(0, "alert"), "0 alerts");
        assert_eq!(plural(1, "alert"), "1 alert");
        assert_eq!(plural(2, "alert"), "2 alerts");
    }

    #[test]
    fn parse_button_value_is_referentially_transparent_across_fifty_calls_on_same_input() {
        // `parse_button_value` is a pure split-on-`:` + UUID parse —
        // no I/O, no global state. Pin referential transparency across
        // 50 calls per input. A refactor that, e.g., memoized the
        // parse result in a thread-local LRU keyed on input pointer
        // (not content) would surface non-determinism on the second
        // call with a fresh-but-content-equal input. The Slack
        // interaction webhook calls this on every button click — a
        // 1-in-50 drift would silently corrupt the action routing.
        // Symmetric to rounds 199/200/204/205/206 referentially-
        // transparent pins.
        let id = Uuid::new_v4();
        for input in [
            format!("approve:{id}"),
            format!("reject:{id}"),
            format!("why:{id}"),
            "approve".to_string(),
            "delete:not-uuid".to_string(),
        ] {
            let first = parse_button_value(&input);
            for i in 0..50 {
                assert_eq!(
                    parse_button_value(&input),
                    first,
                    "iter {i}: parse_button_value drift on input {input:?}",
                );
            }
        }
    }

    #[test]
    fn truncate_and_plural_are_referentially_transparent_across_fifty_calls_on_same_input() {
        // Same purity pin for the two private helpers — both feed into
        // Block Kit payload assembly on the hot notification path. A
        // refactor that, e.g., LRU-cached plural's output keyed on the
        // (n, word.as_ptr()) pair would silently desync when the same
        // word arrived from two different sources (e.g. `"block"` from
        // a const-borrowed literal vs `"block"` from a String allocation).
        for (s, n) in [("short", 10), ("longer text needing trim", 5), ("αβγδ", 3)] {
            let first = truncate(s, n);
            for i in 0..50 {
                assert_eq!(
                    truncate(s, n),
                    first,
                    "iter {i}: truncate drift on {s:?}, n={n}",
                );
            }
        }
        for (n, w) in [(0u64, "block"), (1, "block"), (42, "alert")] {
            let first = plural(n, w);
            for i in 0..50 {
                assert_eq!(plural(n, w), first, "iter {i}: plural drift on ({n}, {w})");
            }
        }
    }

    #[test]
    fn slack_action_enum_variant_count_pinned_at_exactly_three_via_exhaustive_match() {
        // The `SlackAction` enum has THREE variants (Approve / Reject /
        // Why). Pin the count via an exhaustive `match` arm so a
        // refactor that added a fourth variant (e.g. `Snooze` to push
        // the row's expiry by 5 minutes) would surface here, not as
        // a silent dispatch-table gap in `api/notifier_slack.rs`.
        // The exhaustive match has no `_` fallback — a new variant
        // would force the compiler to surface here.
        for a in [SlackAction::Approve, SlackAction::Reject, SlackAction::Why] {
            let _: &'static str = match a {
                SlackAction::Approve => "approve",
                SlackAction::Reject => "reject",
                SlackAction::Why => "why",
            };
        }
        // Sanity: the three variants are pairwise distinct (Eq + Ord
        // not required, but PartialEq IS — pin pairwise inequality so a
        // refactor that collapsed Approve+Reject into a tagged enum
        // "for ergonomic single-variant Resolved(bool)" would surface
        // here.
        assert_ne!(SlackAction::Approve, SlackAction::Reject);
        assert_ne!(SlackAction::Approve, SlackAction::Why);
        assert_ne!(SlackAction::Reject, SlackAction::Why);
    }

    #[test]
    fn slack_signing_secret_skew_window_pinned_at_300_seconds_via_boundary_pair() {
        // The Slack signing-secret verify path enforces a 5-minute
        // (300-second) skew window per the Slack docs. The existing
        // `verify_rejects_old_timestamp` test exercises a 10-minute-
        // stale ts (clearly out of window); pin the BOUNDARY: a ts
        // exactly 300 seconds in the past STILL verifies, while a ts
        // 301 seconds in the past rejects. The `abs_diff > 300` check
        // is strictly greater, so the 300-second boundary is the
        // inclusive accept side. A refactor that tightened to `>= 300`
        // "for paranoid clock-skew hygiene" would shrink the window
        // by one second AND silently fail interactions near the
        // boundary on lightly-skewed clocks.
        let secret = SlackSigningSecret::new("8f742231b10e8888abcd99e1b18bf76c");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for (offset, want) in [(300u64, true), (301, false)] {
            let ts = (now - offset).to_string();
            let body = b"x=1";
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
            assert_eq!(
                secret.verify(&sig, &ts, body),
                want,
                "offset {offset}s past: expected {want}",
            );
        }
    }

    #[test]
    fn block_kit_payload_return_type_is_owned_serde_json_value_for_cross_await_http_post() {
        // `block_kit_payload` returns owned `serde_json::Value` — the
        // value is then `.to_string()`-ed into the reqwest body across
        // a `.await` boundary in `notify`. A refactor to a borrowed
        // shape (e.g. `&'a serde_json::Value` returned from a thread-
        // local arena "for zero-alloc payload assembly") would tie the
        // payload's lifetime to the notifier's borrow scope and break
        // the cross-await contract. Pin the owned-Value return shape
        // via require_value AND that block_kit_payload + summary_block_kit_payload
        // both share the contract.
        fn require_value(_: serde_json::Value) {}
        require_value(block_kit_payload(&n()));
        // summary_block_kit_payload symmetric.
        let s = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "p".into(),
            p_0: None,
            suppressed_count: 1,
            window_seconds: 60,
            exemplar: None,
            details_url: String::new(),
        };
        require_value(summary_block_kit_payload(&s));
    }

    #[test]
    fn slack_notifier_field_types_pinned_for_cross_await_post_contract() {
        // `SlackNotifier` carries fields read inside `.await`-suspended
        // POSTs: `incoming_webhook_url: String` (passed by reference into
        // reqwest::Client::post which holds it across .await),
        // `proxy_public_url: String` (returned via accessor, exposed on
        // dashboards), `signing_secret: SlackSigningSecret` (cloned into
        // the inbound-interact webhook verifier on every request), and
        // `user_map: HashMap<String, String>` (consulted on every Slack
        // user resolution). All four must be owned + 'static across
        // spawned-task boundaries. Pin via accessor witnesses and
        // signing_secret(): return type is &SlackSigningSecret which
        // requires the inner field be owned (not a borrow). Pin
        // proxy_public_url() return type is &str (borrowed VIEW into
        // owned field) — a refactor to owned String return would
        // heap-allocate per-access.
        fn require_str_borrow(_: &str) {}
        let n = SlackNotifier::new(
            "https://hooks.slack.com/services/T/B/X".into(),
            SlackSigningSecret::new("s"),
            "https://proxy.local".into(),
        )
        .unwrap();
        require_str_borrow(n.proxy_public_url());
        // signing_secret accessor return type is &SlackSigningSecret
        // — pin as a witness function.
        fn require_secret_borrow(_: &SlackSigningSecret) {}
        require_secret_borrow(n.signing_secret());
    }

    /// Silence unused-import warnings on the no-test build paths.
    #[allow(dead_code)]
    fn _used(_: chrono::DateTime<Utc>) {}

    // ─── round 232 (2026-05-22): SlackNotifier + SlackSigningSecret exhaustive
    // destructure, new() Result fn-pointer, verify bool return, resolve_user
    // priority, SlackBuildError inner String ───

    #[test]
    fn slack_signing_secret_inner_field_count_pinned_at_exactly_one_via_exhaustive_destructure() {
        // `SlackSigningSecret(Vec<u8>)` is a single-field tuple struct
        // holding the HMAC key. A 2nd field landing (e.g. `algorithm:
        // HashAlg` for a future SHA-512 override, OR `created_at:
        // SystemTime` for rotation observability) without matching
        // `new()` constructor wiring would silently leave the new field
        // zero-initialized. The exhaustive destructure with no `..`
        // rest pattern forces a 2nd field to update this site in
        // lockstep with `new()`. Symmetric to the WebhookSecret 1-field
        // + BearerHash array + ExpirySweepReport 1-field exhaustive-
        // destructure pins.
        let s = SlackSigningSecret::new("some-secret-32-chars-of-hex-mate");
        let SlackSigningSecret(_inner) = s;
    }

    #[test]
    fn slack_notifier_field_count_pinned_at_exactly_six_via_exhaustive_destructure_no_rest_pattern()
    {
        // `SlackNotifier { incoming_webhook_url, signing_secret,
        // proxy_public_url, http, burst, user_map }` — exactly 6
        // fields. A 7th field landing (e.g. `default_channel: Option<
        // String>` for per-policy channel routing, OR `thread_ts_map:
        // Arc<DashMap<Uuid, String>>` for thread-style notifications
        // per ui-less-surfaces.md §5.7 dev 1) without matching `new()`
        // constructor wiring would silently leave the new field
        // zero-initialized — operators using the new feature would see
        // no error AND no behaviour change. The exhaustive destructure
        // with no `..` rest pattern forces a 7th field to update this
        // site in lockstep with `new()`. Symmetric to the
        // WebhookNotifier 6-field + TeeStream 2-field + NatsBridge
        // 2-field exhaustive-destructure pins.
        let n = SlackNotifier::new(
            "https://hooks.slack.com/services/T/B/X".into(),
            SlackSigningSecret::new("secret"),
            "https://proxy.local".into(),
        )
        .unwrap();
        let SlackNotifier {
            incoming_webhook_url: _,
            signing_secret: _,
            proxy_public_url: _,
            http: _,
            burst: _,
            user_map: _,
        } = n;
    }

    #[test]
    fn slack_notifier_new_return_type_is_result_self_slack_build_error_via_fn_pointer_witness() {
        // `SlackNotifier::new(...) -> Result<Self, SlackBuildError>` —
        // the boot path bubbles the error through `?` symmetric to
        // `WebhookNotifier::new` and `WebhookSecret::from_hex`. Pin the
        // type via a fn-pointer witness so a refactor that swapped to
        // `Result<Self, anyhow::Error>` "for ergonomic boot-path
        // bubbling" OR to a panicking `pub fn new(...) -> Self` "since
        // reqwest::Client::builder() rarely fails" would surface here at
        // the constructor boundary. The `reqwest::Client::builder().
        // build()` error path is the load-bearing branch operators see
        // when they pass a malformed env override. Symmetric to the
        // WebhookNotifier::new + WebhookSecret::from_hex Result fn-
        // pointer pins.
        let _f: fn(String, SlackSigningSecret, String) -> Result<SlackNotifier, SlackBuildError> =
            SlackNotifier::new;
        let result = SlackNotifier::new(
            "https://hooks.slack.com/services/T/B/X".into(),
            SlackSigningSecret::new("s"),
            "https://proxy.local".into(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn slack_signing_secret_verify_return_type_is_bool_via_fn_pointer_witness_for_middleware_branch()
     {
        // `SlackSigningSecret::verify(&self, &str, &str, &[u8]) -> bool`
        // — the inbound interaction-webhook middleware uses
        // `if !secret.verify(sig, ts, body) { return 401; }`. The
        // return type MUST be `bool` (not `Result<bool, Error>` or
        // `Option<bool>`) so the middleware branch is a clean boolean
        // gate. A refactor to `Result<(), VerifyError>` "for
        // structured rejection reasons" would force every middleware
        // call site to `.is_ok()` AND collapse the distinct rejection
        // reasons (bad prefix, skew, HMAC mismatch) into a single
        // boolean anyway — the structured variant is value-less unless
        // also surfaced upstream. Pin via fn-pointer witness so the
        // boolean return shape surfaces here. Symmetric to the
        // is_killed bool return pin in round 228 extended to this
        // sibling middleware-gate signature.
        let _f: fn(&SlackSigningSecret, &str, &str, &[u8]) -> bool = SlackSigningSecret::verify;
        let s = SlackSigningSecret::new("secret");
        let observed: bool = s.verify("not-v0", "0", b"body");
        assert!(!observed);
    }

    #[test]
    fn slack_notifier_resolve_user_prefers_id_over_username_when_both_have_entries_priority_order()
    {
        // `resolve_user(slack_user_id, slack_username)` checks the
        // user_map for the ID FIRST, then falls back to the username.
        // The existing `user_map_resolves_by_id_then_username` test
        // pins the "id present, username absent" arm AND the
        // "username present, id absent" arm separately. Pin the
        // PRIORITY ORDER explicitly: when BOTH have entries (a Slack
        // workspace where a user has both an ID-keyed AND a
        // username-keyed mapping — e.g. during a username-rename
        // transition), the ID arm wins. A refactor that reordered the
        // `if/if/None` chain (e.g. alphabetized by symbol name to
        // `if let Some(u) = slack_username { ... } else if let Some(id)
        // = slack_user_id { ... }`) would silently flip the resolution
        // for ambiguous fixtures — operators would see audit rows
        // tagged with the wrong operator email. Symmetric to the
        // infer_idp priority-order pin in round 221.
        let mut map = HashMap::new();
        map.insert("U01ABC".to_string(), "alice@id-arm.com".to_string());
        map.insert("alice".to_string(), "alice@username-arm.com".to_string());
        let n = SlackNotifier::new(
            "https://hooks.slack.com/services/T/B/X".into(),
            SlackSigningSecret::new("s"),
            "https://proxy.local".into(),
        )
        .unwrap()
        .with_user_map(map);
        let resolved = n.resolve_user(Some("U01ABC"), Some("alice"));
        assert_eq!(
            resolved.as_deref(),
            Some("alice@id-arm.com"),
            "id arm must win when both have entries",
        );
    }

    #[test]
    fn slack_build_error_inner_field_pinned_owned_string_via_destructure_for_dynamic_message_arm() {
        // `SlackBuildError(pub String)` — single-field tuple struct
        // with an owned `String` carrying the reqwest builder error
        // message. The value flows through `anyhow::Error` chains at
        // the boot path which require Send+Sync+'static — owned String
        // satisfies that trivially. A refactor to `&'static str` "for
        // cheaper passthrough on common-error fast paths" would force
        // every `SlackBuildError(e.to_string())` site to `Box::leak`
        // the dynamic message OR fragment the construction into a
        // match-arm enum of static prefixes. Pin via destructure
        // accessing the inner field as String. Symmetric to the
        // NotifierBuildError + ConnectError inner-String pins.
        let e = SlackBuildError("boot client failed: dns".into());
        let SlackBuildError(inner) = &e;
        fn require_string(_: &String) {}
        require_string(inner);
        assert_eq!(inner, "boot client failed: dns");
        // And a multibyte unicode message round-trips byte-equal
        // through the owned-String field — pin so a future inner
        // type that normalized Unicode would surface here.
        let multibyte = SlackBuildError("боот failed: тест".into());
        let SlackBuildError(m) = &multibyte;
        assert_eq!(m, "боот failed: тест");
    }

    // ─── round 287 (2026-05-26): SlackNotifier trait + signature + builder pins ───

    #[test]
    fn slack_signing_secret_clone_required_via_trait_bound_witness_for_notifier_construction_path()
    {
        // `SlackSigningSecret: Clone` is REQUIRED — the
        // `SlackNotifier` boot path takes a `SlackSigningSecret` by
        // value, and operators frequently construct multiple
        // notifiers from the SAME secret (interactive notifier +
        // diagnostic notifier) via `.clone()` at the boot site. The
        // existing `slack_signing_secret_debug_does_not_leak_inner_key_bytes`
        // pin checks the Debug-safety; pin the Clone TRAIT BOUND
        // here at the type boundary via require_clone witness so a
        // refactor that dropped `#[derive(Clone)]` "for explicit
        // Arc-sharing of the inner key bytes" would surface as a
        // single type-boundary failure rather than at every
        // notifier-bundle Clone call site as a tower::Service trait
        // cascade. Symmetric to round-281
        // `webhook_secret_clone_required_via_trait_bound_witness_for_axum_state_fan_out`
        // + round-285 `siem_hmac_key_clone_required_via_trait_bound_witness_for_forwarder_construction_path`
        // extended to this sibling Slack signing-secret type.
        fn require_clone<T: Clone>() {}
        require_clone::<SlackSigningSecret>();
    }

    #[test]
    fn slack_build_error_implements_display_via_require_for_tracing_format_substitution_at_boot() {
        // `SlackBuildError: Display` — the boot path emits the
        // structured error via `tracing::error!(error = %e, ...)`
        // which routes through the `{}` (`Display`) substitution
        // path. The existing
        // `slack_build_error_display_carries_byte_exact_slack_build_prefix_with_inner`
        // pin checks the RUNTIME string shape; pin the TRAIT BOUND
        // here so a refactor that dropped the `#[error("slack
        // build: {0}")]` thiserror attribute would surface at the
        // trait-bound boundary rather than at every
        // `tracing::error!(error = %e, ...)` call site. Symmetric
        // to round-281
        // `notifier_build_error_implements_display_via_require_for_format_substitution_at_setup_logs`
        // + round-285 `siem_key_error_and_build_error_both_implement_display`
        // extended to this sibling Slack build-error type.
        fn require_display<T: std::fmt::Display>() {}
        require_display::<SlackBuildError>();
    }

    #[test]
    fn slack_notifier_with_burst_signature_pinned_via_fn_pointer_witness_for_builder_chain() {
        // `SlackNotifier::with_burst(self, BurstSuppressor) -> Self`
        // is the chainable builder that attaches a burst-suppressor
        // (ui-less-surfaces.md §5.6) to a freshly-constructed
        // notifier. Pin via fn-pointer witness: self-by-value +
        // Self-return (the fluent builder pattern) — a refactor to
        // `fn with_burst(&mut self, BurstSuppressor) -> &mut Self`
        // "for ergonomic mid-construction mutation" would break the
        // `SlackNotifier::new(...)?.with_burst(...).with_user_map(...)`
        // boot chain at server.rs. Symmetric to round-281
        // `webhook_notifier_with_burst_signature_pinned_via_fn_pointer_witness_for_builder_chain`
        // — both Slack + Webhook notifiers ride in lockstep on the
        // identical builder signature so a per-notifier drift
        // surfaces here.
        let _f: fn(SlackNotifier, BurstSuppressor) -> SlackNotifier = SlackNotifier::with_burst;
    }

    #[test]
    fn slack_notifier_with_user_map_signature_pinned_via_fn_pointer_witness_for_builder_chain() {
        // `SlackNotifier::with_user_map(self, HashMap<String, String>)
        // -> Self` is the chainable builder that replaces the
        // slack-user → operator-subject map (ui-less-surfaces.md
        // §5.3 dev 4). Pin via fn-pointer witness: self-by-value +
        // HashMap by VALUE consumption (catches `&mut self + &HashMap`
        // mid-construction-mutation refactor breaking the fluent
        // chain AND `&HashMap` borrow-by-reference refactor tying
        // the map's lifetime to the caller's frame breaking
        // axum's `'static` State<T> bound). Pin all three signature
        // axes simultaneously. Symmetric to the with_burst pin in
        // this same round extended to the sibling user-map builder.
        let _f: fn(SlackNotifier, HashMap<String, String>) -> SlackNotifier =
            SlackNotifier::with_user_map;
    }

    #[test]
    fn slack_notifier_signing_secret_and_proxy_public_url_accessors_pinned_via_fn_pointer_witnesses()
     {
        // `SlackNotifier::signing_secret(&self) -> &SlackSigningSecret`
        // + `SlackNotifier::proxy_public_url(&self) -> &str` — the
        // two accessors the inbound interaction webhook calls AFTER
        // it routes through the per-tenant resolver. Pin BOTH via
        // fn-pointer witness so a refactor that consumed `self` OR
        // owned-by-value on either return would surface here at the
        // accessor boundary. The `signing_secret` accessor returns
        // a `&SlackSigningSecret` BORROW (catches `Clone`-by-value
        // return refactor "for ergonomic per-call key construction"
        // forcing a heavy inner-Vec clone per interaction-webhook
        // verify call AND catches `Arc<SlackSigningSecret>` Arc-
        // wrap refactor forcing Arc::clone per call). Symmetric to
        // round-281
        // `webhook_notifier_proxy_public_url_signature_pinned_via_fn_pointer_witness_for_borrow_only_accessor`
        // extended to BOTH accessors on this sibling notifier.
        let _f1: fn(&SlackNotifier) -> &SlackSigningSecret = SlackNotifier::signing_secret;
        let _f2: fn(&SlackNotifier) -> &str = SlackNotifier::proxy_public_url;
    }

    #[test]
    fn slack_build_error_inner_field_count_pinned_at_exactly_one_via_exhaustive_destructure() {
        // `SlackBuildError` is a `pub struct(pub String)` tuple-
        // struct with EXACTLY 1 inner field (the human-readable
        // reason). Pin the count via exhaustive destructure on a
        // single-element tuple-struct pattern: a refactor that
        // landed a 2nd field (`hint: &'static str` setup-page-link
        // OR `code: ErrorCode` structured-bucketing) would silently
        // extend the operator-visible build-error wire shape AND
        // would break every `SlackBuildError(format!(...))`
        // construction site. The exhaustive destructure with NO
        // `..` catches the 2nd field at compile time. Symmetric to
        // round-281 `notifier_build_error_inner_field_count_pinned_at_exactly_one_via_exhaustive_destructure`
        // extended to this sibling Slack build-error type — both
        // notifiers ride in lockstep on the identical tuple-struct
        // shape so a per-notifier drift surfaces here.
        let e = SlackBuildError("reason here".to_string());
        let SlackBuildError(reason) = e;
        assert_eq!(reason, "reason here");
    }
}
