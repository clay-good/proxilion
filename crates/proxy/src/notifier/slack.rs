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

use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, warn};
use uuid::Uuid;

use super::BlockedNotification;

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
        })
    }

    pub fn signing_secret(&self) -> &SlackSigningSecret {
        &self.signing_secret
    }

    pub fn proxy_public_url(&self) -> &str {
        &self.proxy_public_url
    }

    /// POST a Block Kit message to the incoming webhook. Best-effort.
    pub async fn notify(&self, n: &BlockedNotification<'_>) {
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
                    "value": reject_value }
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
        _ => return None,
    };
    let id = Uuid::parse_str(id_str).ok()?;
    Some((action, id))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlackAction {
    Approve,
    Reject,
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
        assert_eq!(actions[0]["style"], "primary");
        assert_eq!(actions[1]["style"], "danger");
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

    /// Silence unused-import warnings on the no-test build paths.
    #[allow(dead_code)]
    fn _used(_: chrono::DateTime<Utc>) {}
}
