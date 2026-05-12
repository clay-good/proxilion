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

use std::time::Duration;

use lettre::message::{Mailbox, MultiPart, SinglePart, header::ContentType};
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::{AsyncTransport, Message, Tokio1Executor};
use sqlx::PgPool;
use tracing::{debug, warn};

use super::BlockedNotification;

#[derive(Debug, thiserror::Error)]
#[error("email build: {0}")]
pub struct EmailBuildError(pub String);

pub struct EmailNotifier {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    to: Vec<Mailbox>,
    proxy_public_url: String,
    db: PgPool,
}

impl EmailNotifier {
    pub fn new(
        smtp_url: &str,
        from: &str,
        to: &[String],
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
            return Err(EmailBuildError("at least one `to` recipient required".into()));
        }
        let to: Vec<Mailbox> = to
            .iter()
            .map(|s| {
                s.parse::<Mailbox>()
                    .map_err(|e| EmailBuildError(format!("to address `{s}`: {e}")))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            transport,
            from,
            to,
            proxy_public_url,
            db,
        })
    }

    pub fn proxy_public_url(&self) -> &str {
        &self.proxy_public_url
    }

    pub async fn notify(&self, n: &BlockedNotification<'_>) {
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

        let approve_url = format!("{}/notifier/approve?t={}", self.proxy_public_url, approve_token);
        let reject_url = format!("{}/notifier/approve?t={}", self.proxy_public_url, reject_token);

        let subject = format!(
            "[Proxilion] Blocked: {} by {}",
            n.action,
            n.p_0.unwrap_or("(unknown)")
        );

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

        let mut builder = Message::builder()
            .from(self.from.clone())
            .subject(subject);
        for to in &self.to {
            builder = builder.to(to.clone());
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

        match self.transport.send(message).await {
            Ok(_) => {
                metrics::counter!(
                    "proxilion_email_send_total",
                    "result" => "ok",
                    "layer" => n.layer.to_string()
                )
                .increment(1);
                debug!(blocked_id = %n.blocked_id, "email sent");
            }
            Err(e) => {
                warn!(error = %e, "email: smtp send failed");
                metrics::counter!(
                    "proxilion_email_send_failures_total",
                    "reason" => "smtp"
                )
                .increment(1);
            }
        }
    }
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
