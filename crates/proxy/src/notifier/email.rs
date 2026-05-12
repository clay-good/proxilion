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
}
