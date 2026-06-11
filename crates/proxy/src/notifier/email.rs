//! Email notifier (ui-less-surfaces.md §5.4).
//!
//! On a blocked-action commit, the email driver mints two single-use
//! signed-URL tokens (`notifier_tokens`: one for approve, one for reject),
//! composes a plain-text + HTML body that embeds both links, and sends
//! via SMTP to the configured recipient(s). The recipient clicks a link;
//! the existing `/notifier/approve` landing page (which already handles
//! `notifier_tokens`) does the work — single-use, expiry-checked, replay-
//! proof.
//!
//! Reuses the same DB-token plumbing as the spec's signed-URL design;
//! this driver just adds the "compose + send via SMTP" half.
//!
//! Authentication for outbound: ENV-less. SMTP credentials live in
//! `notifier_config.config` as `smtp_url` (e.g. `smtps://user:pass@host:465`).
//! The proxy doesn't speak STARTTLS-without-AUTH — most customer relays
//! require auth, and "no auth" is one URL form (`smtp://user:pass@…:25`)
//! that we don't go out of our way to disable.

use std::sync::Arc;
use std::time::Duration;

use lettre::message::{Mailbox, MultiPart, SinglePart, header::ContentType};
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::{AsyncTransport, Message, Tokio1Executor};
use sqlx::PgPool;
use tracing::{debug, warn};

use super::BlockedNotification;

/// Per-policy recipient override resolver. Returns the policy's
/// `notifier_recipients:` block as `(to, cc, bcc)`; each list is `Some` only
/// when the policy explicitly set it. `None` outer → fall through to the
/// global recipients on the notifier. ui-less-surfaces.md §5.4 dev 3.
pub type EmailRecipientsResolver = Arc<
    dyn Fn(
            &str,
        ) -> Option<(
            Option<Vec<String>>,
            Option<Vec<String>>,
            Option<Vec<String>>,
        )> + Send
        + Sync,
>;

#[derive(Debug, thiserror::Error)]
#[error("email build: {0}")]
pub struct EmailBuildError(pub String);

pub struct EmailNotifier {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    to: Vec<Mailbox>,
    /// Optional CC list (ui-less-surfaces.md §5.4 dev 4). Empty by default.
    cc: Vec<Mailbox>,
    /// Optional BCC list. Empty by default. Recipients here see neither
    /// the To nor each other's BCC entries.
    bcc: Vec<Mailbox>,
    proxy_public_url: String,
    db: PgPool,
    /// Max SMTP retries on transient send failures (ui-less-surfaces.md
    /// §5.4 dev 5). 0 disables retry; 3 is the production default,
    /// chosen to match the webhook + SIEM forwarder's retry budget.
    max_retries: u32,
    /// Optional per-policy recipient resolver (ui-less-surfaces.md §5.4
    /// dev 3). When set, each notify() call looks up the matched policy
    /// id and substitutes the policy's `notifier_recipients:` block for
    /// any of to/cc/bcc that the policy explicitly overrode.
    recipients_resolver: Option<EmailRecipientsResolver>,
}

impl EmailNotifier {
    #[allow(dead_code)] // back-compat alias; new callers use `new_with_recipients`
    pub fn new(
        smtp_url: &str,
        from: &str,
        to: &[String],
        proxy_public_url: String,
        db: PgPool,
    ) -> Result<Self, EmailBuildError> {
        Self::new_with_recipients(smtp_url, from, to, &[], &[], proxy_public_url, db)
    }

    /// Build with optional cc + bcc lists. ui-less-surfaces.md §5.4 dev 4.
    /// Empty `cc` / `bcc` slices are equivalent to [`Self::new`].
    pub fn new_with_recipients(
        smtp_url: &str,
        from: &str,
        to: &[String],
        cc: &[String],
        bcc: &[String],
        proxy_public_url: String,
        db: PgPool,
    ) -> Result<Self, EmailBuildError> {
        let transport: AsyncSmtpTransport<Tokio1Executor> =
            AsyncSmtpTransport::<Tokio1Executor>::from_url(smtp_url)
                .map_err(|e| EmailBuildError(format!("smtp url: {e}")))?
                .timeout(Some(Duration::from_secs(10)))
                .build();
        let from: Mailbox = from
            .parse()
            .map_err(|e| EmailBuildError(format!("from address: {e}")))?;
        if to.is_empty() {
            return Err(EmailBuildError(
                "at least one `to` recipient required".into(),
            ));
        }
        let to: Vec<Mailbox> = to
            .iter()
            .map(|s| {
                s.parse::<Mailbox>()
                    .map_err(|e| EmailBuildError(format!("to address `{s}`: {e}")))
            })
            .collect::<Result<_, _>>()?;
        let cc: Vec<Mailbox> = cc
            .iter()
            .map(|s| {
                s.parse::<Mailbox>()
                    .map_err(|e| EmailBuildError(format!("cc address `{s}`: {e}")))
            })
            .collect::<Result<_, _>>()?;
        let bcc: Vec<Mailbox> = bcc
            .iter()
            .map(|s| {
                s.parse::<Mailbox>()
                    .map_err(|e| EmailBuildError(format!("bcc address `{s}`: {e}")))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            transport,
            from,
            to,
            cc,
            bcc,
            proxy_public_url,
            db,
            max_retries: 3,
            recipients_resolver: None,
        })
    }

    /// Override the SMTP retry budget. Tests use 0 to keep them fast.
    #[allow(dead_code)]
    pub fn with_max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    /// Attach a per-policy recipient resolver. ui-less-surfaces.md §5.4 dev 3.
    pub fn with_recipients_resolver(mut self, r: EmailRecipientsResolver) -> Self {
        self.recipients_resolver = Some(r);
        self
    }

    pub fn proxy_public_url(&self) -> &str {
        &self.proxy_public_url
    }

    /// Re-fire the email notifier as an escalation reminder
    /// (ui-less-surfaces.md §5.7 dev 2). Identical body shape to
    /// [`Self::notify`] but the Subject is prefixed `REMINDER:` so the
    /// approver's mail client renders the second message distinctly
    /// from the original. Fresh tokens are minted — the original
    /// approve/reject links may have been consumed mid-deliberation.
    pub async fn notify_escalation(&self, n: &BlockedNotification<'_>) {
        self.notify_inner(n, true).await;
    }

    pub async fn notify(&self, n: &BlockedNotification<'_>) {
        self.notify_inner(n, false).await;
    }

    async fn notify_inner(&self, n: &BlockedNotification<'_>, is_escalation: bool) {
        // Issue two single-use signed-URL tokens — one approve, one reject.
        // Both inherit a 30-minute TTL (same as the existing email flow).
        let (approve_token, reject_token) = match issue_tokens(&self.db, n).await {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, "email: token issue failed");
                metrics::counter!(
                    "proxilion_email_send_failures_total",
                    "reason" => "token_issue"
                )
                .increment(1);
                return;
            }
        };

        let approve_url = format!(
            "{}/notifier/approve?t={}",
            self.proxy_public_url, approve_token
        );
        let reject_url = format!(
            "{}/notifier/approve?t={}",
            self.proxy_public_url, reject_token
        );

        // §4.3 — absolute expiry (UTC) computed at send so it doesn't drift as
        // the message sits unread. Matches the `now() + interval '30 minutes'`
        // window the tokens were minted with above (`OVERRIDE_TOKEN_TTL_MINUTES`).
        let expires = (chrono::Utc::now()
            + chrono::Duration::minutes(super::OVERRIDE_TOKEN_TTL_MINUTES))
        .format("%Y-%m-%d %H:%M")
        .to_string();

        let subject = if is_escalation {
            format!(
                "[Proxilion] REMINDER: Blocked: {} by {}",
                n.action,
                n.p_0.unwrap_or("(unknown)")
            )
        } else {
            format!(
                "[Proxilion] Blocked: {} by {}",
                n.action,
                n.p_0.unwrap_or("(unknown)")
            )
        };

        let plain = format!(
            "Proxilion blocked an action that needs your review.\n\n\
             p_0:           {p_0}\n\
             vendor/action: {vendor}/{action}\n\
             path:          {path}\n\
             policy:        {policy}\n\
             detail:        {detail}\n\
             blocked_id:    {blocked_id}\n\n\
             Approve:  {approve_url}\n\
             Reject:   {reject_url}\n\n\
             Both links are single-use and expire at {expires} UTC.\n",
            p_0 = n.p_0.unwrap_or("(unknown)"),
            vendor = n.vendor,
            action = n.action,
            path = n.path,
            policy = n.policy_id.unwrap_or("—"),
            detail = n.detail.unwrap_or(""),
            blocked_id = n.blocked_id,
        );

        let html = format!(
            r#"<!doctype html><html><body style="font:15px/1.5 system-ui,sans-serif;max-width:640px;margin:24px auto;padding:0 16px">
<h2 style="margin:0 0 8px">🛑 Proxilion blocked an action</h2>
<p style="color:#6a737d;margin:0 0 16px">A managed agent attempted an action that requires your approval.</p>
<table style="border-collapse:collapse;width:100%;font-size:14px">
  <tr><td style="padding:4px 0;color:#6a737d">p_0</td><td><code>{p_0}</code></td></tr>
  <tr><td style="padding:4px 0;color:#6a737d">vendor / action</td><td><code>{vendor}/{action}</code></td></tr>
  <tr><td style="padding:4px 0;color:#6a737d">path</td><td><code>{path}</code></td></tr>
  <tr><td style="padding:4px 0;color:#6a737d">policy</td><td><code>{policy}</code></td></tr>
  <tr><td style="padding:4px 0;color:#6a737d">detail</td><td>{detail}</td></tr>
  <tr><td style="padding:4px 0;color:#6a737d">blocked_id</td><td><code>{blocked_id}</code></td></tr>
</table>
<p style="margin:24px 0 8px">
  <a href="{approve_url}" style="display:inline-block;padding:10px 18px;background:#00b386;color:white;text-decoration:none;border-radius:4px;font-weight:600;margin-right:8px">Approve</a>
  <a href="{reject_url}" style="display:inline-block;padding:10px 18px;background:#f85149;color:white;text-decoration:none;border-radius:4px;font-weight:600">Reject</a>
</p>
<p style="font-size:12px;color:#6a737d;margin-top:24px">Both links are single-use and expire at {expires} UTC.</p>
</body></html>"#,
            p_0 = html_escape(n.p_0.unwrap_or("(unknown)")),
            vendor = html_escape(n.vendor),
            action = html_escape(n.action),
            path = html_escape(n.path),
            policy = html_escape(n.policy_id.unwrap_or("—")),
            detail = html_escape(n.detail.unwrap_or("")),
            blocked_id = n.blocked_id,
        );

        // ui-less-surfaces.md §5.4 dev 3 — per-policy recipient override.
        // The resolver may return per-list Some(...) values; for each list
        // the policy explicitly set, use it instead of the global default.
        // Parse on demand; on parse failure, fall back to the global default
        // for that list so a typo in policy YAML can't black-hole a block.
        let (to_list, cc_list, bcc_list) = self.resolve_recipients(n.policy_id);

        let mut builder = Message::builder().from(self.from.clone()).subject(subject);
        for to in &to_list {
            builder = builder.to(to.clone());
        }
        for cc in &cc_list {
            builder = builder.cc(cc.clone());
        }
        for bcc in &bcc_list {
            builder = builder.bcc(bcc.clone());
        }
        let message = match builder.multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(plain),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html),
                ),
        ) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "email: message build failed");
                metrics::counter!(
                    "proxilion_email_send_failures_total",
                    "reason" => "build"
                )
                .increment(1);
                return;
            }
        };

        // ui-less-surfaces.md §5.4 dev 5 — SMTP retry on transient
        // failures. lettre's `Error::is_permanent` lets us short-circuit
        // 5xx-class SMTP responses (auth failure, bad recipient) instead
        // of paying the full backoff budget for an error that will never
        // recover. Anything else (timeout, network blip, server-busy
        // 4xx) is retried with the same exp backoff shape as the webhook
        // notifier.
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            // `Message` is Clone — send() consumes it, so we clone per
            // attempt to keep the original around for retries.
            let outcome = self.transport.send(message.clone()).await;
            match outcome {
                Ok(_) => {
                    metrics::counter!(
                        "proxilion_email_send_total",
                        "result" => "ok",
                        "layer" => n.layer.to_string(),
                        "kind" => if is_escalation { "escalation" } else { "initial" }
                    )
                    .increment(1);
                    debug!(blocked_id = %n.blocked_id, attempt, is_escalation, "email sent");
                    return;
                }
                Err(e) if e.is_permanent() => {
                    warn!(error = %e, "email: permanent SMTP failure; not retrying");
                    metrics::counter!(
                        "proxilion_email_send_failures_total",
                        "reason" => "smtp_permanent"
                    )
                    .increment(1);
                    return;
                }
                Err(e) => {
                    warn!(error = %e, attempt, "email: transient SMTP failure");
                    if attempt > self.max_retries {
                        metrics::counter!(
                            "proxilion_email_send_failures_total",
                            "reason" => "smtp_transient_exhausted"
                        )
                        .increment(1);
                        return;
                    }
                }
            }
            let backoff_ms = 250u64 * 4u64.saturating_pow(attempt.saturating_sub(1));
            tokio::time::sleep(Duration::from_millis(backoff_ms.min(10_000))).await;
        }
    }
}

impl EmailNotifier {
    /// Resolve the effective `(to, cc, bcc)` for a notification by layering
    /// the policy's `notifier_recipients:` override on top of the global
    /// defaults. ui-less-surfaces.md §5.4 dev 3.
    fn resolve_recipients(
        &self,
        policy_id: Option<&str>,
    ) -> (Vec<Mailbox>, Vec<Mailbox>, Vec<Mailbox>) {
        let override_lists =
            policy_id.and_then(|id| self.recipients_resolver.as_ref().and_then(|r| r(id)));
        let Some((to_o, cc_o, bcc_o)) = override_lists else {
            return (self.to.clone(), self.cc.clone(), self.bcc.clone());
        };
        let to = match to_o {
            Some(list) => parse_or_fallback(&list, &self.to, "to"),
            None => self.to.clone(),
        };
        let cc = match cc_o {
            Some(list) => parse_or_fallback(&list, &self.cc, "cc"),
            None => self.cc.clone(),
        };
        let bcc = match bcc_o {
            Some(list) => parse_or_fallback(&list, &self.bcc, "bcc"),
            None => self.bcc.clone(),
        };
        (to, cc, bcc)
    }
}

fn parse_or_fallback(list: &[String], fallback: &[Mailbox], field: &str) -> Vec<Mailbox> {
    let mut out = Vec::with_capacity(list.len());
    for s in list {
        match s.parse::<Mailbox>() {
            Ok(m) => out.push(m),
            Err(e) => {
                warn!(
                    field, addr = %s, error = %e,
                    "email: per-policy recipient parse failed; falling back to global default"
                );
                return fallback.to_vec();
            }
        }
    }
    out
}

async fn issue_tokens(
    db: &PgPool,
    n: &BlockedNotification<'_>,
) -> Result<(uuid::Uuid, uuid::Uuid), sqlx::Error> {
    let approve: (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO notifier_tokens (blocked_id, action, approver_hint, issued_by, expires_at)
         VALUES ($1, 'approve', $2, 'email-notifier', now() + interval '30 minutes')
         RETURNING token_id",
    )
    .bind(n.blocked_id)
    .bind(n.p_0.unwrap_or(""))
    .fetch_one(db)
    .await?;
    let reject: (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO notifier_tokens (blocked_id, action, approver_hint, issued_by, expires_at)
         VALUES ($1, 'reject', $2, 'email-notifier', now() + interval '30 minutes')
         RETURNING token_id",
    )
    .bind(n.blocked_id)
    .bind(n.p_0.unwrap_or(""))
    .fetch_one(db)
    .await?;
    Ok((approve.0, reject.0))
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_handles_xss() {
        let s = html_escape("<script>alert(1)</script>");
        assert!(!s.contains("<script>"));
        assert!(s.contains("&lt;script&gt;"));
    }

    #[test]
    fn html_escape_covers_every_dangerous_entity() {
        // Five entities the escaper must catch — the previous test only
        // covered `<` and `>`. A regression that dropped any single arm
        // (the easy one is the lone-apostrophe case: `&#39;` is the
        // numeric entity, not `&apos;` — pin the exact bytes operators'
        // email clients render so a switch to `&apos;` doesn't silently
        // change rendering in older mail UAs).
        assert_eq!(html_escape("<"), "&lt;");
        assert_eq!(html_escape(">"), "&gt;");
        assert_eq!(html_escape("&"), "&amp;");
        assert_eq!(html_escape("\""), "&quot;");
        assert_eq!(html_escape("'"), "&#39;");
        // Mixed input: every entity in one string, in order.
        assert_eq!(
            html_escape("<a href=\"x\" rel='y'>&"),
            "&lt;a href=&quot;x&quot; rel=&#39;y&#39;&gt;&amp;"
        );
    }

    #[test]
    fn html_escape_passes_plain_text_and_unicode_through_unchanged() {
        // No entity in the input → byte-identical output (no spurious
        // entity wrapping, no double-encoding). Unicode codepoints
        // outside the entity table pass through unchanged so non-ASCII
        // policy descriptions render correctly in operator mail clients.
        assert_eq!(html_escape("hello world"), "hello world");
        assert_eq!(html_escape("αβγ — délicieux"), "αβγ — délicieux");
        assert_eq!(html_escape(""), "");
    }

    #[tokio::test]
    async fn email_notifier_proxy_public_url_round_trips_through_accessor() {
        // The escalation sweeper reads `proxy_public_url()` to build
        // approve / reject URLs; a regression that returned the SMTP URL
        // instead would silently send approvers to the SMTP host. Pin
        // the field-name round-trip through the public accessor while we
        // already have a notifier in hand.
        let pool = make_dummy_pool();
        let n = EmailNotifier::new(
            "smtp://localhost:25",
            "sec@x.com",
            &["a@x.com".into()],
            "https://proxy.acme.com".into(),
            pool,
        )
        .expect("builds");
        assert_eq!(n.proxy_public_url(), "https://proxy.acme.com");
    }

    #[tokio::test]
    async fn email_notifier_with_max_retries_is_a_fluent_setter() {
        // `with_max_retries(0)` lets the test suite keep SMTP-failure
        // paths fast — pin the fluent-builder shape (consumes self,
        // returns Self) so a future refactor to `&mut self` would
        // surface here as a compile error rather than break test setup
        // at every call site.
        let pool = make_dummy_pool();
        let n = EmailNotifier::new(
            "smtp://localhost:25",
            "sec@x.com",
            &["a@x.com".into()],
            "https://proxy.local".into(),
            pool,
        )
        .expect("builds")
        .with_max_retries(0);
        // No public accessor for max_retries (intentional — internal
        // tuning knob). Existence of the consuming-self chain is the
        // contract; reaching this line is success.
        assert_eq!(n.proxy_public_url(), "https://proxy.local");
    }

    #[test]
    fn html_escape_does_not_double_encode_already_escaped_entities() {
        // Standard expectation for HTML escape: it's a one-shot byte
        // mapping, NOT a parser. `&amp;` in the input becomes `&amp;amp;`
        // out — pin that so a future "smart escape" refactor doesn't
        // silently start parsing entities (which would change rendering
        // for content that already contains literal `&amp;` strings).
        assert_eq!(html_escape("&amp;"), "&amp;amp;");
        assert_eq!(html_escape("&lt;script&gt;"), "&amp;lt;script&amp;gt;");
    }

    #[tokio::test]
    async fn invalid_smtp_url_errors() {
        let pool_placeholder = make_dummy_pool();
        let err = EmailNotifier::new(
            "not-a-url",
            "sec@x.com",
            &["a@x.com".into()],
            "https://proxy.local".into(),
            pool_placeholder,
        )
        .err()
        .expect("expected build error");
        assert!(err.0.contains("smtp url"));
    }

    #[tokio::test]
    async fn empty_recipients_errors() {
        let pool_placeholder = make_dummy_pool();
        let err = EmailNotifier::new(
            "smtp://localhost:25",
            "sec@x.com",
            &[],
            "https://proxy.local".into(),
            pool_placeholder,
        )
        .err()
        .expect("expected build error");
        assert!(err.0.contains("recipient"));
    }

    #[tokio::test]
    async fn malformed_from_errors() {
        let pool_placeholder = make_dummy_pool();
        let err = EmailNotifier::new(
            "smtp://localhost:25",
            "not-an-email",
            &["a@x.com".into()],
            "https://proxy.local".into(),
            pool_placeholder,
        )
        .err()
        .expect("expected build error");
        assert!(err.0.contains("from"));
    }

    #[tokio::test]
    async fn per_policy_resolver_overrides_to_cc_bcc() {
        let pool = make_dummy_pool();
        let n = EmailNotifier::new_with_recipients(
            "smtp://localhost:25",
            "sec@acme.com",
            &["default-to@acme.com".into()],
            &["default-cc@acme.com".into()],
            &["default-bcc@acme.com".into()],
            "https://proxy.local".into(),
            pool,
        )
        .expect("builds");

        let resolver: EmailRecipientsResolver = Arc::new(|policy_id| match policy_id {
            "security" => Some((
                Some(vec!["sec-team@acme.com".into()]),
                None,
                Some(vec!["audit@acme.com".into()]),
            )),
            _ => None,
        });
        let n = n.with_recipients_resolver(resolver);

        // Policy with an override: to + bcc replaced, cc inherits the default.
        let (to, cc, bcc) = n.resolve_recipients(Some("security"));
        assert_eq!(to.len(), 1);
        assert_eq!(to[0].email.to_string(), "sec-team@acme.com");
        assert_eq!(cc.len(), 1);
        assert_eq!(cc[0].email.to_string(), "default-cc@acme.com");
        assert_eq!(bcc.len(), 1);
        assert_eq!(bcc[0].email.to_string(), "audit@acme.com");

        // Policy with no override: every list falls through to global.
        let (to, cc, bcc) = n.resolve_recipients(Some("other"));
        assert_eq!(to[0].email.to_string(), "default-to@acme.com");
        assert_eq!(cc[0].email.to_string(), "default-cc@acme.com");
        assert_eq!(bcc[0].email.to_string(), "default-bcc@acme.com");

        // No policy id at all: also falls through.
        let (to, _, _) = n.resolve_recipients(None);
        assert_eq!(to[0].email.to_string(), "default-to@acme.com");
    }

    #[tokio::test]
    async fn per_policy_resolver_invalid_addr_falls_back_to_global() {
        let pool = make_dummy_pool();
        let n = EmailNotifier::new_with_recipients(
            "smtp://localhost:25",
            "sec@acme.com",
            &["default-to@acme.com".into()],
            &[],
            &[],
            "https://proxy.local".into(),
            pool,
        )
        .expect("builds");

        let resolver: EmailRecipientsResolver =
            Arc::new(|_id| Some((Some(vec!["not-an-email".into()]), None, None)));
        let n = n.with_recipients_resolver(resolver);

        let (to, _cc, _bcc) = n.resolve_recipients(Some("any"));
        // Malformed override address — global default must be preserved so
        // the block doesn't go to a black hole.
        assert_eq!(to.len(), 1);
        assert_eq!(to[0].email.to_string(), "default-to@acme.com");
    }

    /// A dummy pool stub for constructor-error tests. The constructor
    /// never touches the pool when it errors out earlier in validation,
    /// so we can use an unbuilt pool wrapper for these failure paths.
    fn make_dummy_pool() -> PgPool {
        // PgPool can't be built without an actual connection string, but
        // we can use `connect_lazy` which only resolves when first queried.
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/x")
            .expect("lazy pool builds")
    }

    fn mbox(s: &str) -> Mailbox {
        s.parse().unwrap()
    }

    #[test]
    fn parse_or_fallback_returns_parsed_list_on_success() {
        let fallback = vec![mbox("fallback@example.com")];
        let list = vec![
            "alice@example.com".to_string(),
            "Bob <bob@example.com>".to_string(),
        ];
        let out = parse_or_fallback(&list, &fallback, "to");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].email.to_string(), "alice@example.com");
        assert_eq!(out[1].email.to_string(), "bob@example.com");
    }

    #[test]
    fn parse_or_fallback_returns_fallback_when_any_addr_malformed() {
        // Per the helper's contract: ONE bad address kicks the whole list
        // back to the fallback (rather than silently dropping the bad one).
        let fallback = vec![mbox("fallback@example.com")];
        let list = vec![
            "alice@example.com".to_string(),
            "not an address".to_string(),
        ];
        let out = parse_or_fallback(&list, &fallback, "to");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].email.to_string(), "fallback@example.com");
    }

    #[test]
    fn parse_or_fallback_fail_fast_on_mid_list_malformed_returns_fallback_not_partial() {
        // The existing "any malformed kicks back to fallback" test
        // uses a 2-element list (good, bad). Pin the mid-list shape
        // where the FIRST TWO addresses parse successfully but the
        // third fails — the helper must STILL return the fallback
        // (NOT the parsed first-two-plus-fallback hybrid). A
        // regression that switched from `return fallback.to_vec()`
        // to `out.extend(fallback.clone())` would silently start
        // delivering to the first valid addresses PLUS the fallback,
        // doubling the recipient list on every transient YAML typo
        // and surfacing here as `out.len() == 3` (2 parsed + 1
        // fallback) where this test expects 1.
        let fallback = vec![mbox("fallback@example.com")];
        let list = vec![
            "alice@example.com".to_string(),
            "Bob <bob@example.com>".to_string(),
            "definitely not an email".to_string(),
            "carol@example.com".to_string(), // never reached on failure path
        ];
        let out = parse_or_fallback(&list, &fallback, "to");
        assert_eq!(
            out.len(),
            1,
            "expected fallback-only, got {} addresses",
            out.len()
        );
        assert_eq!(out[0].email.to_string(), "fallback@example.com");
    }

    #[test]
    fn parse_or_fallback_field_param_does_not_affect_output_only_log_label() {
        // The `field` parameter (e.g. "to" / "cc" / "bcc") is used
        // ONLY in the warn! log line — it must not influence which
        // addresses are returned. Pin via a happy-path call against
        // distinct field labels: same input + different field →
        // byte-identical output. A regression that started routing
        // on `field` (e.g. "bcc → strip display names") would
        // silently corrupt the per-policy BCC overrides without
        // surfacing as an obvious test failure.
        let fallback = vec![mbox("fallback@example.com")];
        let list = vec!["Bob <bob@example.com>".to_string()];
        let out_to = parse_or_fallback(&list, &fallback, "to");
        let out_cc = parse_or_fallback(&list, &fallback, "cc");
        let out_bcc = parse_or_fallback(&list, &fallback, "bcc");
        assert_eq!(out_to.len(), 1);
        assert_eq!(out_to[0].email.to_string(), "bob@example.com");
        assert_eq!(out_to[0].email.to_string(), out_cc[0].email.to_string());
        assert_eq!(out_to[0].email.to_string(), out_bcc[0].email.to_string());
    }

    #[test]
    fn parse_or_fallback_works_with_empty_fallback_when_input_is_valid() {
        // Boundary: the global fallback is sometimes empty (an install
        // that requires per-policy recipients with no proxy-wide
        // default). When the input parses cleanly, the empty fallback
        // is never consulted — surface the parsed list as usual. A
        // regression that pre-checked `fallback.is_empty()` and
        // bailed early (returning the empty fallback even on
        // happy-path parses) would silently drop every per-policy
        // email override and break the §5.7 escalation pipeline.
        let fallback: Vec<Mailbox> = vec![];
        let list = vec!["alice@example.com".to_string()];
        let out = parse_or_fallback(&list, &fallback, "to");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].email.to_string(), "alice@example.com");
        // Symmetric: empty fallback + malformed input → empty out
        // (the fallback IS the empty vec — surfaced verbatim).
        let bad = vec!["not an email".to_string()];
        let out = parse_or_fallback(&bad, &fallback, "to");
        assert!(
            out.is_empty(),
            "empty fallback must propagate when used: {out:?}"
        );
    }

    #[test]
    fn parse_or_fallback_empty_input_returns_empty() {
        let fallback = vec![mbox("fallback@example.com")];
        let out = parse_or_fallback(&[], &fallback, "to");
        assert!(out.is_empty());
    }

    #[test]
    fn email_notifier_and_build_error_are_send_sync_static_for_app_state_arc_path() {
        // `EmailNotifier` is wired into `Notifiers` (held by AppState as
        // `Arc<Notifiers>`) and its async send path crosses tokio task
        // boundaries via TeeStream + the escalation sweeper. `EmailBuildError`
        // flows through `anyhow::Error` chains at boot. Pin the three-trait
        // combo on both types so a refactor that introduced a `Cell<...>`
        // field on the notifier (e.g. "for in-process retry tracking") or
        // an `Rc<String>` inside `EmailBuildError` would break Send/Sync at
        // the AppState site rather than as a far-removed trait-bound error.
        // Symmetric to the
        // `siem_forwarder_and_key_types_are_send_sync_static_for_app_state_arc_path`
        // pin on [crates/proxy/src/forwarder/siem.rs].
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<EmailNotifier>();
        require_send_sync_static::<EmailBuildError>();
    }

    #[test]
    fn email_build_error_implements_std_error_trait_with_no_source_leaf_contract() {
        // `EmailBuildError` is a `thiserror::Error` derive with the
        // `#[error("email build: {0}")]` shape — a leaf arm carrying
        // only a `String`. Pin the `std::error::Error` impl via dyn-cast
        // AND confirm `source() == None` so a refactor that swapped to
        // a `#[from] lettre::transport::smtp::Error` wrapping shape
        // "for richer triage" would surface here at the trait cast
        // (source becomes Some) rather than as a silently-doubled
        // detail string in operator logs (the inner Display would
        // duplicate via the chain walk AND via the wrapper Display).
        let e = EmailBuildError("smtp url: bad scheme".into());
        let dyn_err: &dyn std::error::Error = &e;
        assert!(
            std::error::Error::source(dyn_err).is_none(),
            "EmailBuildError must be leaf arm with no source",
        );
    }

    #[test]
    fn email_build_error_debug_carries_struct_name_for_grep_bucketing() {
        // `EmailBuildError` feeds `?e` in `tracing::warn!` call sites
        // at boot and at notifier-driver hot-swap (`/api/v1/notifier/config`)
        // paths. Operators grep the resulting log line by struct name to
        // bucket "email driver build fault" separately from the sibling
        // KeyError / BuildError / ConnectError shapes that share the
        // `?e` log convention. A hand-rolled `impl Debug` that hid the
        // struct name "to compact" the line would break the bucket.
        // Pin the struct-name shape — symmetric to the
        // `key_error_and_build_error_debug_carries_struct_name_for_grep`
        // pin on [crates/proxy/src/forwarder/siem.rs].
        let s = format!("{:?}", EmailBuildError("inner reason".into()));
        assert!(s.contains("EmailBuildError"), "got: {s}");
    }

    #[test]
    fn email_build_error_display_carries_byte_exact_email_build_prefix_with_inner() {
        // `#[error("email build: {0}")]` — pin the byte-exact
        // prefix-plus-inner Display shape via `assert_eq!`. The existing
        // `invalid_smtp_url_errors` / `malformed_from_errors` / `empty_recipients_errors`
        // tests use `.contains(...)` substring checks on the INNER half;
        // pin the full wrapper shape here so a refactor that softened
        // to `"email config: {0}"` (matching a config-layer rename) or
        // dropped the colon ("email build {0}") would silently slip past
        // a `.contains(...)` check but surface here. Operator log
        // filters historically grep `"email build:"` to bucket email-
        // driver boot failures separately from SMTP-send failures.
        let e = EmailBuildError("smtp url: bad scheme".into());
        assert_eq!(e.to_string(), "email build: smtp url: bad scheme");
    }

    #[test]
    fn html_escape_preserves_char_order_across_interleaved_safe_and_unsafe_chars() {
        // The escaper is a per-char pass that emits ONE entity (or the
        // raw char) per input char. Pin that the OUTPUT preserves input
        // CHAR ORDER across an interleaved safe/unsafe sequence — a
        // refactor that swapped to a regex `replace_all` pass per
        // entity (the "looks tidier" form) would silently re-order
        // matches when entity matches overlap in non-obvious ways.
        // Cross-pin against the previous tests which exercise pure-
        // unsafe input only — this one fuses safe interior chars
        // between every unsafe char.
        let input = "a<b>c&d\"e'f";
        let out = html_escape(input);
        assert_eq!(out, "a&lt;b&gt;c&amp;d&quot;e&#39;f");
    }

    #[tokio::test]
    async fn email_notifier_constructor_accepts_three_recipient_to_list_with_display_names() {
        // The existing constructor tests use a 1-element `to:` list.
        // Pin a 3-element to-list (a real install: security + ops + a
        // shared on-call alias) including a display-name shape on one
        // entry — `Bob <bob@example.com>`. A refactor that started
        // rejecting display-name shapes "for SMTP-strict compatibility"
        // OR that capped to-list at N=1 "for fan-out hygiene" would
        // silently break every operator install with > 1 approver.
        // Pin both axes: the constructor succeeds AND each parsed
        // mailbox surfaces the expected email field byte-for-byte
        // through `resolve_recipients(None)` (the global default
        // path).
        let pool = make_dummy_pool();
        let n = EmailNotifier::new(
            "smtp://localhost:25",
            "sec@acme.com",
            &[
                "alice@acme.com".into(),
                "Bob <bob@acme.com>".into(),
                "oncall@acme.com".into(),
            ],
            "https://proxy.acme.com".into(),
            pool,
        )
        .expect("3-recipient to-list with display-name must construct");
        let (to, _cc, _bcc) = n.resolve_recipients(None);
        assert_eq!(to.len(), 3);
        assert_eq!(to[0].email.to_string(), "alice@acme.com");
        assert_eq!(to[1].email.to_string(), "bob@acme.com");
        assert_eq!(to[2].email.to_string(), "oncall@acme.com");
    }

    #[test]
    fn html_escape_preserves_whitespace_newline_carriage_return_and_tab_unchanged() {
        // The escaper handles only the five "dangerous" HTML chars —
        // ASCII whitespace (`\n`, `\r`, `\t`, ` `) MUST pass through
        // verbatim. Policy descriptions and detail strings carry
        // multi-line content (operators paste shell output into YAML);
        // a refactor that escaped `\n` to `&#10;` "for HTML attribute
        // safety in the wrong context" would silently mangle every
        // multi-line policy description rendered in the approver
        // email body. Pin all four whitespace bytes round-trip
        // byte-equal. The existing pins exercise non-whitespace
        // (alphanumerics + multibyte unicode) only.
        assert_eq!(html_escape("a\nb"), "a\nb");
        assert_eq!(html_escape("a\rb"), "a\rb");
        assert_eq!(html_escape("a\tb"), "a\tb");
        assert_eq!(html_escape("a b"), "a b");
        // Multi-line interleaved with one entity — newline preserved
        // even when an entity fires elsewhere in the same input.
        assert_eq!(html_escape("line1\n<b>line2"), "line1\n&lt;b&gt;line2");
    }

    #[test]
    fn html_escape_byte_length_delta_per_special_char_matches_capacity_hint() {
        // `String::with_capacity(s.len())` is the capacity hint for the
        // output buffer; the actual output is LARGER by an exact delta
        // per escaped char: `<` → 4 (3 extra), `>` → 4 (3 extra), `&` →
        // 5 (4 extra), `"` → 6 (5 extra), `'` → 5 (4 extra). Pin the
        // per-arm delta so a refactor that swapped `&#39;` for `&apos;`
        // ("HTML5-native name") would change `'` → 6 (+5 instead of
        // +4) AND trigger realloc-on-every-render. Symmetric to the
        // notifier_public.rs pin in round 130; pin the same surface
        // at the email rendering site so a cross-module drift surfaces
        // here too.
        assert_eq!(html_escape("<").len() - "<".len(), 3);
        assert_eq!(html_escape(">").len() - ">".len(), 3);
        assert_eq!(html_escape("&").len() - "&".len(), 4);
        assert_eq!(html_escape("\"").len() - "\"".len(), 5);
        assert_eq!(html_escape("'").len() - "'".len(), 4);
    }

    #[test]
    fn email_build_error_inner_string_field_carries_multibyte_unicode_verbatim() {
        // `EmailBuildError(pub String)` — the inner String is operator-
        // facing (it surfaces via `tracing::warn!("{e}", ...)` at boot
        // when the SMTP URL parse fails). Operators occasionally land a
        // multibyte unicode policy id or hostname in the SMTP URL via
        // internationalized DNS (e.g. `smtp://relay.café-prod.local:25`);
        // pin the inner field carries multibyte unicode verbatim through
        // Display + Debug + struct-field access without truncation OR
        // lossy ASCII conversion "for SIEM hygiene". The existing
        // `email_build_error_display_carries_byte_exact_email_build_prefix_with_inner`
        // pin uses ASCII-only inner content; widen here to multibyte
        // (3-byte é + 3-byte → + 4-byte 🔥) so a `.to_ascii_lowercase()`
        // OR `.replace(non_ascii, '?')` refactor surfaces.
        let inner = "smtp host café-prod → 🔥 unreachable";
        let e = EmailBuildError(inner.into());
        // Public field carries the bytes verbatim.
        assert_eq!(e.0, inner);
        // Display wraps in the `email build: ` prefix without altering
        // the inner bytes.
        assert_eq!(e.to_string(), format!("email build: {inner}"));
        // Debug includes the multibyte bytes too (struct-name + field).
        let dbg = format!("{e:?}");
        assert!(dbg.contains("EmailBuildError"), "got: {dbg}");
        assert!(dbg.contains("café"), "multibyte truncated in Debug: {dbg}");
        assert!(dbg.contains("🔥"), "4-byte emoji truncated in Debug: {dbg}");
    }

    #[tokio::test]
    async fn email_notifier_new_with_recipients_with_empty_cc_and_bcc_equivalent_to_new() {
        // The `new_with_recipients` doc comment promises:
        //   "Empty `cc` / `bcc` slices are equivalent to `Self::new`."
        // Pin the equivalence behaviorally: build BOTH constructors
        // with the same `to` list and inspect `resolve_recipients(None)`
        // to confirm the global cc + bcc are both empty Vecs. A refactor
        // that started seeding `cc` with the `from` address "for audit
        // hygiene" via the `new_with_recipients` path but NOT the
        // `new` path (the natural shape of a partial-only update)
        // would surface here as an asymmetric divergence in the
        // returned `(to, cc, bcc)` tuple lengths.
        let pool_a = make_dummy_pool();
        let na = EmailNotifier::new(
            "smtp://localhost:25",
            "sec@acme.com",
            &["a@acme.com".into()],
            "https://proxy.acme.com".into(),
            pool_a,
        )
        .expect("new constructs");
        let pool_b = make_dummy_pool();
        let nb = EmailNotifier::new_with_recipients(
            "smtp://localhost:25",
            "sec@acme.com",
            &["a@acme.com".into()],
            &[],
            &[],
            "https://proxy.acme.com".into(),
            pool_b,
        )
        .expect("new_with_recipients constructs");
        let (ta, ca, ba) = na.resolve_recipients(None);
        let (tb, cb, bb) = nb.resolve_recipients(None);
        assert_eq!(ta.len(), tb.len());
        assert_eq!(ta[0].email.to_string(), tb[0].email.to_string());
        assert!(ca.is_empty() && cb.is_empty(), "cc must be empty for both");
        assert!(ba.is_empty() && bb.is_empty(), "bcc must be empty for both");
    }

    #[tokio::test]
    async fn email_notifier_with_recipients_resolver_is_consuming_fluent_setter() {
        // `with_recipients_resolver` takes `Arc<dyn Fn(...) + Send +
        // Sync>` by value and returns Self — symmetric to
        // `with_max_retries`. Pin the consuming-fluent shape so a
        // refactor to `&mut self` would surface here as a compile
        // error rather than break test setup at every call site. AND
        // pin that attaching a resolver THEN calling
        // `resolve_recipients` on a policy the resolver handles
        // surfaces the override — proves the field write took effect.
        let pool = make_dummy_pool();
        let n = EmailNotifier::new(
            "smtp://localhost:25",
            "sec@acme.com",
            &["default-to@acme.com".into()],
            "https://proxy.acme.com".into(),
            pool,
        )
        .expect("builds");
        let resolver: EmailRecipientsResolver = Arc::new(|policy_id| {
            if policy_id == "p1" {
                Some((Some(vec!["override-to@acme.com".into()]), None, None))
            } else {
                None
            }
        });
        // Consume + return Self — chain another fluent call to prove
        // the return type is Self not &Self.
        let n = n.with_recipients_resolver(resolver).with_max_retries(0);
        let (to, _, _) = n.resolve_recipients(Some("p1"));
        assert_eq!(to.len(), 1);
        assert_eq!(to[0].email.to_string(), "override-to@acme.com");
    }

    // ─── round 210 (2026-05-21): purity + ownership surfaces on email helpers ───

    #[test]
    fn html_escape_is_referentially_transparent_across_fifty_calls_on_same_input() {
        // `html_escape` is on the hot path for every approver-email
        // body assembly — called for the policy description, the
        // matched-pattern label, and the request snippet. A refactor
        // that introduced a thread-local LRU keyed on input pointer
        // "for hot-path perf" would silently surface different output
        // on equal-content-different-allocation inputs and fork
        // operator-rendered mail bodies. Pin 50 calls byte-equal on
        // a representative interleaved-safe-and-unsafe input.
        // Symmetric to the audit_body redact-helper RT pins (round 194)
        // + the slack `parse_button_value` / `truncate` / `plural`
        // RT pins (round 207) extended to this sibling escaper.
        let input = "<a href=\"x\" rel='y'>café & co.</a>";
        let baseline = html_escape(input);
        for i in 0..50 {
            let again = html_escape(input);
            assert_eq!(
                again, baseline,
                "iteration {i}: html_escape must be referentially transparent",
            );
        }
    }

    #[test]
    fn html_escape_return_type_is_owned_string_for_cross_await_lettre_message_body() {
        // `html_escape` returns `String` — its output flows into the
        // `lettre::Message` body builder which is then `.send().await`-ed
        // through the SMTP transport. A refactor to `Cow<'a, str>` "for
        // zero-alloc on no-entity inputs" would introduce a lifetime
        // parameter tied to the borrowed `&str` argument and break the
        // cross-await assembly contract on the escalation send path. Pin
        // via require_string. Symmetric to round 207's
        // `block_kit_payload_return_type_is_owned_serde_json_value_...`
        // pin extended to this sibling owned-content helper.
        fn require_string(_: &String) {}
        let s = html_escape("<b>");
        require_string(&s);
        assert_eq!(s, "&lt;b&gt;");
    }

    #[test]
    fn parse_or_fallback_is_referentially_transparent_across_fifty_calls_on_same_input() {
        // `parse_or_fallback` is called per-policy at every notify send
        // to resolve `to` / `cc` / `bcc` from operator YAML. A refactor
        // that introduced a per-call counter mixin (e.g. round-robin
        // shuffling of the parsed mailbox order "for fair-share rotation
        // across team members") would silently fork the To: header
        // across calls on the same input. Pin 50 calls byte-equal on a
        // 3-element happy-path input via `.email.to_string()` projection
        // (Mailbox itself lacks PartialEq, so the bridge through
        // `email.to_string()` is the byte-level handle). Symmetric to
        // the html_escape RT pin above + round 204's
        // `infer_idp_is_referentially_transparent_...` pin extended
        // to this sibling notifier helper.
        let fallback = vec![mbox("fallback@example.com")];
        let list = vec![
            "alice@example.com".to_string(),
            "Bob <bob@example.com>".to_string(),
            "carol@example.com".to_string(),
        ];
        let baseline: Vec<String> = parse_or_fallback(&list, &fallback, "to")
            .iter()
            .map(|m| m.email.to_string())
            .collect();
        for i in 0..50 {
            let again: Vec<String> = parse_or_fallback(&list, &fallback, "to")
                .iter()
                .map(|m| m.email.to_string())
                .collect();
            assert_eq!(
                again, baseline,
                "iteration {i}: parse_or_fallback must be referentially transparent",
            );
        }
    }

    #[test]
    fn parse_or_fallback_return_type_is_owned_vec_mailbox_for_cross_await_smtp_send() {
        // `parse_or_fallback` returns `Vec<Mailbox>` — the resolved
        // recipients flow into the `lettre::Message` builder whose
        // `.send().await` crosses the SMTP-transport suspension. A
        // refactor to `Cow<'a, [Mailbox]>` "for zero-alloc on the
        // happy path where the global default is reused verbatim"
        // would introduce a lifetime parameter tied to the `fallback`
        // borrow and break the cross-await contract. Pin via
        // require_owned_vec. Symmetric to round 206's
        // `merge_overlapping_and_splice_return_types_owned_by_value_...`
        // pin extended to this sibling notifier helper.
        fn require_owned_vec(_: &Vec<Mailbox>) {}
        let fallback = vec![mbox("fallback@example.com")];
        let list = vec!["alice@example.com".to_string()];
        let out = parse_or_fallback(&list, &fallback, "to");
        require_owned_vec(&out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn email_build_error_inner_string_field_is_owned_string_for_cross_await_anyhow_propagation() {
        // `EmailBuildError(pub String)` — the inner field is `String`
        // (owned) because the error value flows through `anyhow::Error`
        // chains at boot (`?` from `EmailNotifier::new(...)` into
        // `boot.rs` async setup that crosses `.await` at the next config
        // load). A refactor to `&'static str` "for stack-allocated
        // error messages on the common bad-scheme arm" would surface
        // here as a require_string compile error AND foreclose the
        // dynamic-message arm operators rely on (the SMTP URL is
        // operator-supplied, not a known set). Pin via require_string.
        // Symmetric to round 204's
        // `federation_claims_field_types_pinned_...` pin extended to
        // this sibling error type.
        fn require_string(_: &String) {}
        let e = EmailBuildError("smtp url: bad scheme".into());
        require_string(&e.0);
    }

    #[tokio::test]
    async fn email_notifier_proxy_public_url_return_type_is_borrowed_str_view_for_zero_alloc_per_send()
     {
        // `EmailNotifier::proxy_public_url()` returns `&str` — a borrowed
        // view into the notifier's owned `proxy_public_url: String`
        // field. The escalation sweeper reads this on every retry to
        // assemble approve/reject URLs; a refactor to a heap-allocating
        // `String` return "for type symmetry with `.signing_secret()`"
        // would silently double the per-retry allocation footprint AND
        // foreclose `Arc<EmailNotifier>::as_ref().proxy_public_url()`
        // sharing across spawn boundaries. Pin via require_borrowed_str.
        // Symmetric to round 207's
        // `slack_notifier_field_types_pinned_...` pin (which checks
        // borrowed-view accessors on the slack notifier) extended to
        // this sibling email notifier.
        fn require_borrowed_str(_: &str) {}
        let pool = make_dummy_pool();
        let n = EmailNotifier::new(
            "smtp://localhost:25",
            "sec@x.com",
            &["a@x.com".into()],
            "https://proxy.acme.com".into(),
            pool,
        )
        .expect("builds");
        let url = n.proxy_public_url();
        require_borrowed_str(url);
        // Pointer identity: the returned `&str` data pointer must lie
        // inside the notifier struct (witness of borrowed-view contract
        // — a heap-allocated `String` return would have a different
        // base pointer per call).
        let a_ptr = n.proxy_public_url().as_ptr();
        let b_ptr = n.proxy_public_url().as_ptr();
        assert_eq!(
            a_ptr, b_ptr,
            "proxy_public_url must return a borrowed view, not a heap-allocated copy",
        );
        assert_eq!(url, "https://proxy.acme.com");
    }

    #[test]
    fn parse_or_fallback_preserves_input_order_across_three_element_happy_path() {
        // The existing happy-path test uses a 2-element list. Pin
        // ORDER PRESERVATION across a 3-element list so a refactor that
        // collected into a `HashSet` "for dedup" would silently change
        // the recipient order in the To: header (operators recognize
        // their team by which name appears first in mail-client lists).
        // The existing test pins length + per-position equality on 2
        // elements; this extends to 3 to catch a refactor that worked
        // on a 2-element fixture but broke at 3.
        let fallback = vec![mbox("fallback@example.com")];
        let list = vec![
            "alice@example.com".to_string(),
            "Bob <bob@example.com>".to_string(),
            "carol@example.com".to_string(),
        ];
        let out = parse_or_fallback(&list, &fallback, "to");
        assert_eq!(out.len(), 3, "got: {out:?}");
        assert_eq!(out[0].email.to_string(), "alice@example.com");
        assert_eq!(out[1].email.to_string(), "bob@example.com");
        assert_eq!(out[2].email.to_string(), "carol@example.com");
    }

    // ─── round 238 (2026-05-22): EmailBuildError + EmailNotifier exhaustive
    // destructure, recipient Vec<Mailbox> field type pins, max_retries u32,
    // with_max_retries fluent self pin ───

    #[test]
    fn email_build_error_inner_field_count_pinned_at_exactly_one_via_exhaustive_destructure() {
        // `EmailBuildError(pub String)` — single-field tuple struct
        // carrying the boot-validation failure message. A 2nd field
        // landing (e.g. `field: &'static str` for the named field that
        // failed validation — "to" / "from" / "cc" — surfaced
        // directly on the variant rather than threaded through the
        // message string, OR `inner: Option<lettre::error::Error>` to
        // preserve the structured source error for `std::error::
        // Error::source()`) without matching `new_with_recipients()`
        // constructor wiring would silently leave the new field
        // zero-initialized OR break the boot-path filter operators
        // grep on. The exhaustive destructure with no `..` rest
        // pattern forces a 2nd field to update this site in lockstep
        // with `new_with_recipients`. Symmetric to the
        // NotifierBuildError + SlackBuildError + KeyError + BuildError
        // 1-field exhaustive-destructure pins.
        let e = EmailBuildError("from address: invalid format".into());
        let EmailBuildError(_inner) = e;
    }

    #[tokio::test]
    async fn email_notifier_field_count_pinned_at_exactly_nine_via_exhaustive_destructure_no_rest()
    {
        // `EmailNotifier { transport, from, to, cc, bcc,
        // proxy_public_url, db, max_retries, recipients_resolver }` —
        // exactly 9 fields. A 10th field landing (e.g. `reply_to:
        // Option<Mailbox>` for a no-reply automated-sender pattern,
        // OR `signing_key: Option<SmimeKey>` for S/MIME-signed
        // notification emails) without matching
        // `new_with_recipients()` constructor wiring would silently
        // leave the new field zero-initialized — operators using the
        // new feature would see no error AND no behaviour change. The
        // exhaustive destructure forces a 10th field to update this
        // site in lockstep. Symmetric to the SlackNotifier 6-field +
        // WebhookNotifier 6-field + SiemForwarder 5-field exhaustive-
        // destructure pins extended to this sibling notifier shape.
        let pool = make_dummy_pool();
        let n = EmailNotifier::new_with_recipients(
            "smtp://user:pass@example.com:25",
            "from@example.com",
            &["to@example.com".to_string()],
            &[],
            &[],
            "https://proxy.local".into(),
            pool,
        )
        .unwrap();
        let EmailNotifier {
            transport: _,
            from: _,
            to: _,
            cc: _,
            bcc: _,
            proxy_public_url: _,
            db: _,
            max_retries: _,
            recipients_resolver: _,
        } = n;
    }

    #[tokio::test]
    async fn email_notifier_recipient_fields_to_cc_bcc_all_pinned_owned_vec_mailbox_via_require() {
        // `EmailNotifier.to: Vec<Mailbox>`, `.cc: Vec<Mailbox>`, and
        // `.bcc: Vec<Mailbox>` — all three are OWNED `Vec<Mailbox>`.
        // The lettre `Message::builder()` chain at `notify_inner()`
        // borrows each field via `.iter()` and crosses the
        // `.transport.send().await` boundary holding the borrow. A
        // refactor to `Box<[Mailbox]>` "for slightly cheaper size
        // since the recipient lists are append-only after boot" would
        // pass any value-equality test but break the
        // `with_recipients_resolver` override path that today does
        // `let mut to = self.to.clone(); to.extend(...)` — Box<[T]>
        // can't be extended. A refactor to `HashSet<Mailbox>` "for
        // de-dup of accidental duplicate recipients" would silently
        // change the iteration ORDER in the To: header. Pin via
        // require_vec_mailbox on all three fields. Symmetric to the
        // ActionEvent owned-String + GoogleClient owned-String
        // field-type pins extended to this sibling notifier shape.
        fn require_vec_mailbox(_: &Vec<Mailbox>) {}
        let pool = make_dummy_pool();
        let n = EmailNotifier::new_with_recipients(
            "smtp://user:pass@example.com:25",
            "from@example.com",
            &["to@example.com".to_string()],
            &["cc@example.com".to_string()],
            &["bcc@example.com".to_string()],
            "https://proxy.local".into(),
            pool,
        )
        .unwrap();
        let EmailNotifier { to, cc, bcc, .. } = n;
        require_vec_mailbox(&to);
        require_vec_mailbox(&cc);
        require_vec_mailbox(&bcc);
    }

    #[tokio::test]
    async fn email_notifier_max_retries_field_pinned_u32_for_lettre_retry_budget_type_compat() {
        // `EmailNotifier.max_retries: u32` — chosen to match the
        // webhook + SIEM forwarder retry-budget field type. A refactor
        // to `usize` "to align with collection lengths" would silently
        // change the platform-specific width (u32 on 32-bit, u64 on
        // 64-bit), breaking byte-equal serialization on
        // notifier_config dashboards. A refactor to `u8` "since 3 is
        // the production default" would cap retries at 255 and
        // silently truncate any operator-tunable value above that.
        // The existing fluent setter `with_max_retries(mut self, n:
        // u32)` pins the parameter type; pin the FIELD type
        // explicitly via require_u32 so a refactor surfaces here at
        // the destructure level too. Symmetric to the ActionEvent.
        // status u16 + ExpirySweepReport.expired_rows u64 numeric-
        // type pins.
        fn require_u32(_: u32) {}
        let pool = make_dummy_pool();
        let n = EmailNotifier::new_with_recipients(
            "smtp://user:pass@example.com:25",
            "from@example.com",
            &["to@example.com".to_string()],
            &[],
            &[],
            "https://proxy.local".into(),
            pool,
        )
        .unwrap();
        require_u32(n.max_retries);
        assert_eq!(
            n.max_retries, 3,
            "production default per ui-less-surfaces.md §5.4"
        );
    }

    #[tokio::test]
    async fn email_notifier_with_max_retries_consumes_self_and_returns_self_via_fn_pointer_witness()
    {
        // `EmailNotifier::with_max_retries(mut self, n: u32) -> Self`
        // — consumes self by value AND returns Self by value (the
        // fluent builder shape that AppState chains). A refactor to
        // `&mut self -> &mut Self` "for ergonomic conditional retry
        // tuning (no temporaries required)" would break the move-
        // chain at every `EmailNotifier::new(...).with_max_retries(n)`
        // site — the chain depends on the consuming-and-returning
        // shape so the final binding can be moved into `Arc::new(...)`
        // without a let-rebind step. Pin via fn-pointer witness with
        // the consuming-self shape. Symmetric to the TeeStream::
        // with_sink + BurstSuppressor::new owned-Self pins extended
        // to this sibling fluent setter.
        let _f: fn(EmailNotifier, u32) -> EmailNotifier = EmailNotifier::with_max_retries;
        let pool = make_dummy_pool();
        let n = EmailNotifier::new_with_recipients(
            "smtp://user:pass@example.com:25",
            "from@example.com",
            &["to@example.com".to_string()],
            &[],
            &[],
            "https://proxy.local".into(),
            pool,
        )
        .unwrap();
        let n = n.with_max_retries(0);
        assert_eq!(n.max_retries, 0);
    }

    #[tokio::test]
    async fn email_notifier_new_with_recipients_return_type_is_result_via_fn_pointer_witness() {
        // `EmailNotifier::new_with_recipients(&str, &str, &[String],
        // &[String], &[String], String, PgPool) -> Result<Self,
        // EmailBuildError>` — the boot path bubbles via `?` symmetric
        // to `WebhookNotifier::new` / `SlackNotifier::new` /
        // `SiemForwarder::new`. Pin via fn-pointer witness so a
        // refactor that swapped to `Result<Self, anyhow::Error>` "for
        // ergonomic boot-path bubbling" would surface here at the
        // constructor boundary. The 3 distinct error variants from
        // this constructor — SMTP URL parse, from-address parse, and
        // empty-recipients — all flow through the `EmailBuildError`
        // String inner and are tested individually; pin the type
        // shape of the OUTER result via fn-pointer. Symmetric to the
        // SiemForwarder::new + SlackNotifier::new fn-pointer pins.
        let _f: fn(
            &str,
            &str,
            &[String],
            &[String],
            &[String],
            String,
            PgPool,
        ) -> Result<EmailNotifier, EmailBuildError> = EmailNotifier::new_with_recipients;
        let pool = make_dummy_pool();
        let result = EmailNotifier::new_with_recipients(
            "smtp://user:pass@example.com:25",
            "from@example.com",
            &["to@example.com".to_string()],
            &[],
            &[],
            "https://proxy.local".into(),
            pool,
        );
        assert!(result.is_ok());
    }

    // ─── round 288 (2026-05-26): EmailBuildError Display + EmailNotifier accessor/builder pins ───

    #[test]
    fn email_build_error_implements_display_via_require_for_tracing_format_substitution_at_boot() {
        // `EmailBuildError: Display` — the boot path emits the
        // structured error via `tracing::error!(error = %e, ...)`
        // which routes through the `{}` (`Display`) substitution
        // path. The existing
        // `email_build_error_display_carries_byte_exact_email_build_prefix_with_inner`
        // pin walks the RUNTIME string; pin the TRAIT BOUND here so
        // a refactor that dropped the `#[error("email build: {0}")]`
        // thiserror attribute "to hand-roll a richer Display impl in
        // a separate file" would surface at the trait-bound boundary
        // rather than at every `tracing::error!(error = %e, ...)`
        // call site as a generic Display-not-satisfied message.
        // Symmetric to round-281
        // `notifier_build_error_implements_display_via_require_for_format_substitution_at_setup_logs`
        // + round-285
        // `siem_key_error_and_build_error_both_implement_display_via_require_for_tracing_substitution`
        // + round-287
        // `slack_build_error_implements_display_via_require_for_tracing_format_substitution_at_boot`
        // — all four notifier-family build-error types pinned in
        // lockstep.
        fn require_display<T: std::fmt::Display>() {}
        require_display::<EmailBuildError>();
    }

    #[test]
    fn email_notifier_with_recipients_resolver_signature_pinned_via_fn_pointer_witness_for_builder_chain()
     {
        // `EmailNotifier::with_recipients_resolver(self,
        // EmailRecipientsResolver) -> Self` is the chainable builder
        // that attaches a per-policy recipient resolver (ui-less-
        // surfaces.md §5.4 dev 3). Pin via fn-pointer witness: self-
        // by-value + resolver-by-value (Arc<dyn Fn(...) -> ...>) +
        // Self-return for the fluent builder. A refactor to
        // `fn with_recipients_resolver(&mut self, &EmailRecipientsResolver)
        // -> &mut Self` "for ergonomic mid-construction mutation"
        // would break the `EmailNotifier::new_with_recipients(...)?.with_recipients_resolver(...).with_max_retries(...)`
        // boot chain at server.rs. AND tying the resolver lifetime
        // by borrow would break the `Send + Sync + 'static` axum
        // State<T> bound. Symmetric to round-287
        // `slack_notifier_with_user_map_signature_pinned_via_fn_pointer_witness_for_builder_chain`
        // extended to this sibling email-notifier builder.
        let _f: fn(EmailNotifier, EmailRecipientsResolver) -> EmailNotifier =
            EmailNotifier::with_recipients_resolver;
    }

    #[test]
    fn email_notifier_proxy_public_url_signature_pinned_via_fn_pointer_witness_for_borrow_accessor()
    {
        // `EmailNotifier::proxy_public_url(&self) -> &str` is the
        // accessor for the configured proxy-public URL used in
        // signed-link assembly. Pin via fn-pointer witness: `&self`
        // borrow (catches `self`-consuming refactor breaking the
        // accessor's idempotency every notifier-config endpoint
        // relies on) + `&str` return BORROWED (catches `String`
        // owned-return refactor forcing a per-call alloc on the
        // hot path AND breaking the `/api/v1/notifier/config` GET
        // route's `.to_owned()` chain). Symmetric to round-281
        // `webhook_notifier_proxy_public_url_signature_pinned_via_fn_pointer_witness_for_borrow_only_accessor`
        // + round-287
        // `slack_notifier_signing_secret_and_proxy_public_url_accessors_pinned_via_fn_pointer_witnesses`
        // — all three notifier-family proxy_public_url accessors
        // pinned in lockstep on the identical `fn(&Self) -> &str`
        // shape.
        let _f: fn(&EmailNotifier) -> &str = EmailNotifier::proxy_public_url;
    }

    #[test]
    fn email_notifier_new_back_compat_alias_signature_pinned_via_fn_pointer_witness_for_callers() {
        // `EmailNotifier::new(&str, &str, &[String], String, PgPool)
        // -> Result<Self, EmailBuildError>` is the back-compat alias
        // for the older 5-arg constructor (line 73 marks it as
        // `#[allow(dead_code)]` because new callers use
        // `new_with_recipients` but the alias is preserved for
        // older boot sites that haven't migrated). Pin via fn-pointer
        // witness so a refactor that REMOVED the alias "to drop dead
        // code" would surface here AND a refactor that widened the
        // return type to `Result<Self, anyhow::Error>` would also
        // surface. The 5-arg shape is the operator-visible API on
        // the README and the back-compat preservation matters for
        // every external integration that pinned to the older
        // signature. Symmetric to round-287
        // `slack_notifier_new_return_type_is_result_self_slack_build_error_via_fn_pointer_witness`
        // extended to this back-compat alias.
        let _f: fn(
            &str,
            &str,
            &[String],
            String,
            PgPool,
        ) -> Result<EmailNotifier, EmailBuildError> = EmailNotifier::new;
    }

    #[test]
    fn html_escape_signature_pinned_via_fn_pointer_witness_for_message_body_assembly_hot_path() {
        // `html_escape(&str) -> String` is invoked once per
        // `notify()` call to escape user-controlled fields (the
        // matched policy reason, principal, etc.) before they land
        // in the HTML body of the email. The existing
        // `html_escape_return_type_is_owned_string_for_cross_await_lettre_message_body`
        // pin walks the return-type axis only; pin the FULL fn-
        // pointer signature here. A refactor to `fn(String) -> String`
        // consume-and-escape would force every call site to clone
        // the input first; `fn(&str) -> Cow<'_, str>` zero-alloc-
        // fast-path refactor would tie return lifetime to input
        // breaking the cross-await lettre `.body(text)` consumption
        // boundary. Symmetric to round-284
        // `sha256_hex_signature_pinned_via_fn_pointer_witness_for_persist_bind_hot_path`
        // extended to this sibling text-encoder helper.
        let _f: fn(&str) -> String = html_escape;
    }

    #[test]
    fn parse_or_fallback_signature_pinned_via_fn_pointer_witness_for_per_policy_recipient_resolution()
     {
        // `parse_or_fallback(list: &[String], fallback: &[Mailbox],
        // field: &str) -> Vec<Mailbox>` is the helper that resolves
        // the per-policy recipient override (ui-less-surfaces.md
        // §5.4 dev 3) — when the resolver returns a Some list, it
        // parses each address; on parse failure it logs the error
        // and falls back to the global default. Pin the FULL
        // signature via fn-pointer witness: all 3 args BORROWED
        // (catches `Vec<String>`-by-value consume-and-parse refactor
        // forcing per-callsite clone of the resolver's returned
        // list AND breaking the cross-`Some(...)`-match borrow
        // chain) + `Vec<Mailbox>` OWNED return (catches `&[Mailbox]`
        // borrow-return refactor tying return lifetime to the
        // fallback slice making the lettre `Message::builder()`
        // chain borrow-across-await impossible). The existing
        // `parse_or_fallback_return_type_is_owned_vec_mailbox_for_cross_await_smtp_send`
        // pin walks the return type only; pin the full fn-pointer
        // signature here at the boundary. Symmetric to round-284
        // `redact_pii_text_signature_pinned_via_fn_pointer_witness_for_bytes_to_text_chain`
        // extended to this sibling per-policy resolver helper.
        let _f: fn(&[String], &[Mailbox], &str) -> Vec<Mailbox> = parse_or_fallback;
    }
}
