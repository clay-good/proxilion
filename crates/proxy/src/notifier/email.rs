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
             Both links are single-use and expire in 30 minutes.\n",
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
<p style="font-size:12px;color:#6a737d;margin-top:24px">Both links are single-use and expire in 30 minutes.</p>
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
}
