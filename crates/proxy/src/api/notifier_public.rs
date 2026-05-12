//! Public-facing (operator-token-less) approval landing page
//! (ui-less-surfaces.md §5.4).
//!
//! Mounted outside the `operator_auth` layer — the single-use
//! `notifier_tokens` row IS the authentication. The token itself is
//! issued by an operator via `POST /api/v1/blocked/{id}/issue-link`
//! (which IS operator-token-gated). The signed URL is then emailed,
//! Slack-DM'd, or otherwise transmitted to the human approver.
//!
//! Routes:
//!   GET  /notifier/approve?t=<uuid>   — renders an HTML form
//!   POST /notifier/approve            — form submit: actually performs
//!                                       the approve/reject, marks token
//!                                       consumed, renders a success page

use std::sync::Arc;

use axum::{
    Form, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::blocked::{ApproveBody, BlockedApiState, RejectBody, approve_inner, reject_inner};

#[derive(Clone)]
pub struct NotifierPublicState {
    pub db: PgPool,
    pub blocked: Arc<BlockedApiState>,
}

pub fn router(state: NotifierPublicState) -> Router {
    Router::new()
        .route("/notifier/approve", get(landing).post(submit))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct TokenQ {
    t: Uuid,
}

#[derive(Debug, Deserialize)]
struct SubmitForm {
    t: Uuid,
    /// Required when action=approve; 20-char minimum (mirrors API rule).
    justification: Option<String>,
    /// Required when action=reject.
    reason: Option<String>,
}

const HTML_TEMPLATE: &str = include_str!("../../static-html/approve.html");

async fn landing(State(state): State<NotifierPublicState>, Query(q): Query<TokenQ>) -> Response {
    let row = match load_token(&state.db, q.t).await {
        Ok(Some(r)) => r,
        Ok(None) => return render_error("Link unknown or already used"),
        Err(e) => return render_error(&format!("Internal error: {e}")),
    };
    let blocked = match load_blocked(&state.db, row.blocked_id).await {
        Ok(b) => b,
        Err(e) => return render_error(&format!("Cannot load blocked action: {e}")),
    };
    if row.consumed_at.is_some() {
        return render_already_used(&row, &blocked);
    }
    if row.expires_at <= Utc::now() {
        return render_error(&format!(
            "Link expired at {}. Ask the operator to issue a new one.",
            row.expires_at.to_rfc3339()
        ));
    }
    render_form(&row, &blocked)
}

async fn submit(
    State(state): State<NotifierPublicState>,
    Form(form): Form<SubmitForm>,
) -> Response {
    // Re-fetch + lock the token row.
    let mut tx = match state.db.begin().await {
        Ok(t) => t,
        Err(e) => return render_error(&format!("db begin: {e}")),
    };
    let row: Option<TokenRow> = sqlx::query_as(
        "SELECT token_id, blocked_id, action, approver_hint, issued_by,
                expires_at, consumed_at
         FROM notifier_tokens
         WHERE token_id = $1 FOR UPDATE",
    )
    .bind(form.t)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some(row) = row else {
        return render_error("Link unknown or already used");
    };
    if row.consumed_at.is_some() {
        return render_error("Link already used");
    }
    if row.expires_at <= Utc::now() {
        return render_error("Link expired");
    }

    let approver = row
        .approver_hint
        .clone()
        .unwrap_or_else(|| "email-link@proxilion".to_string());
    let action_outcome: Result<String, String> = match row.action.as_str() {
        "approve" => {
            let justification = form.justification.unwrap_or_default();
            if justification.trim().len() < 20 {
                return render_validation_error(
                    &row,
                    "Justification must be at least 20 characters.",
                );
            }
            match approve_inner(
                &state.blocked,
                row.blocked_id,
                ApproveBody {
                    justification: justification.clone(),
                    ttl_minutes: None,
                    approver_subject: Some(approver.clone()),
                },
                "email",
            )
            .await
            {
                Ok(r) => Ok(format!(
                    "Approved. Override PCA {} minted at hop {}.",
                    r.override_pca_id, r.hop
                )),
                Err(e) => Err(format!("{e}")),
            }
        }
        "reject" => {
            let reason = form.reason.unwrap_or_default();
            if reason.trim().is_empty() {
                return render_validation_error(&row, "Reason is required.");
            }
            match reject_inner(
                &state.blocked,
                row.blocked_id,
                RejectBody {
                    reason: reason.clone(),
                    approver_subject: Some(approver.clone()),
                },
            )
            .await
            {
                Ok(_) => Ok("Rejected.".into()),
                Err(e) => Err(format!("{e}")),
            }
        }
        other => return render_error(&format!("Unknown action `{other}`")),
    };

    // Mark consumed regardless of outcome — the token has been spent.
    // Worth doing in the same tx as the operation? Approve does its
    // own transactional work in `approve_inner` (commits on success).
    // Consuming the token after-the-fact is acceptable because the
    // OUTER lock here (FOR UPDATE on notifier_tokens row) means another
    // concurrent click sees consumed_at=NULL+row-locked and blocks
    // until we mark it.
    if let Err(e) =
        sqlx::query("UPDATE notifier_tokens SET consumed_at = now() WHERE token_id = $1")
            .bind(form.t)
            .execute(&mut *tx)
            .await
    {
        tracing::warn!(error = %e, "notifier_token: failed to mark consumed");
    }
    if let Err(e) = tx.commit().await {
        tracing::warn!(error = %e, "notifier_token: commit failed");
    }

    let blocked = load_blocked(&state.db, row.blocked_id).await.ok();
    let title = match row.action.as_str() {
        "approve" => "Action approved",
        _ => "Action rejected",
    };
    match action_outcome {
        Ok(msg) => render_result(title, &row, blocked.as_ref(), &msg, true),
        Err(msg) => render_result(title, &row, blocked.as_ref(), &msg, false),
    }
}

#[derive(Debug, sqlx::FromRow)]
struct TokenRow {
    #[allow(dead_code)]
    token_id: Uuid,
    blocked_id: Uuid,
    action: String,
    approver_hint: Option<String>,
    #[allow(dead_code)]
    issued_by: Option<String>,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

async fn load_token(db: &PgPool, token_id: Uuid) -> Result<Option<TokenRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT token_id, blocked_id, action, approver_hint, issued_by,
                expires_at, consumed_at
         FROM notifier_tokens WHERE token_id = $1",
    )
    .bind(token_id)
    .fetch_optional(db)
    .await
}

#[derive(Debug, Clone)]
struct BlockedSummary {
    p_0: Option<String>,
    vendor: String,
    action: String,
    path: String,
    policy_id: Option<String>,
    detail: Option<String>,
    created_at: DateTime<Utc>,
    requested_ops: Vec<String>,
}

async fn load_blocked(db: &PgPool, id: Uuid) -> Result<BlockedSummary, String> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT p_0, vendor, action, path, policy_id, detail, at, requested_ops
         FROM blocked_actions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "blocked row not found".to_string())?;
    Ok(BlockedSummary {
        p_0: row.try_get("p_0").ok(),
        vendor: row.try_get("vendor").unwrap_or_default(),
        action: row.try_get("action").unwrap_or_default(),
        path: row.try_get("path").unwrap_or_default(),
        policy_id: row.try_get("policy_id").ok(),
        detail: row.try_get("detail").ok(),
        created_at: row.try_get("at").unwrap_or_else(|_| Utc::now()),
        requested_ops: row.try_get("requested_ops").unwrap_or_default(),
    })
}

fn render_error(msg: &str) -> Response {
    let html = format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>Proxilion · Error</title>
<style>body{{font:15px/1.5 system-ui;max-width:640px;margin:4vh auto;padding:0 16px}}
.err{{padding:12px;border-left:4px solid #f85149;background:rgba(248,81,73,0.08);border-radius:0 4px 4px 0}}</style>
</head><body><h1>Proxilion</h1><div class="err">{}</div></body></html>"#,
        html_escape(msg)
    );
    (StatusCode::OK, Html(html)).into_response()
}

fn render_already_used(row: &TokenRow, blocked: &BlockedSummary) -> Response {
    render_result(
        "Link already used",
        row,
        Some(blocked),
        &format!(
            "This link was already consumed. Action `{}` taken at {}.",
            row.action,
            row.consumed_at
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| "unknown".into())
        ),
        true,
    )
}

fn render_validation_error(row: &TokenRow, msg: &str) -> Response {
    // Re-render the form with the error banner above it.
    // To keep the implementation simple, we render an error page with a
    // "back" hint rather than preserving form state — the form is short.
    render_error(&format!(
        "{} <br><br><a href=\"/notifier/approve?t={}\">Back</a>",
        msg, row.token_id
    ))
}

fn render_form(row: &TokenRow, blocked: &BlockedSummary) -> Response {
    let form = match row.action.as_str() {
        "approve" => format!(
            r#"<form method="post" action="/notifier/approve">
<input type="hidden" name="t" value="{}">
<label for="j">Justification (≥ 20 characters)</label>
<textarea id="j" name="justification" required minlength="20" placeholder="Why are you approving this action?"></textarea>
<div style="margin-top:12px"><button type="submit" class="primary">Approve action</button></div>
</form>"#,
            row.token_id
        ),
        "reject" => format!(
            r#"<form method="post" action="/notifier/approve">
<input type="hidden" name="t" value="{}">
<label for="r">Reason</label>
<textarea id="r" name="reason" required placeholder="Why are you rejecting this?"></textarea>
<div style="margin-top:12px"><button type="submit" class="reject">Reject action</button></div>
</form>"#,
            row.token_id
        ),
        other => format!("<div class=\"banner-err\">Unknown action `{other}`</div>"),
    };
    let html = fill_template(row, Some(blocked), &form);
    (StatusCode::OK, Html(html)).into_response()
}

fn render_result(
    title: &str,
    row: &TokenRow,
    blocked: Option<&BlockedSummary>,
    msg: &str,
    ok: bool,
) -> Response {
    let banner_class = if ok { "banner-ok" } else { "banner-err" };
    let body = format!(
        r#"<div class="{banner_class}"><strong>{title}.</strong> {}</div>"#,
        html_escape(msg)
    );
    let html = fill_template(row, blocked, &body);
    (StatusCode::OK, Html(html)).into_response()
}

fn fill_template(row: &TokenRow, blocked: Option<&BlockedSummary>, body: &str) -> String {
    let action_title = match row.action.as_str() {
        "approve" => "Approve blocked action",
        "reject" => "Reject blocked action",
        _ => "Blocked action",
    };
    let expires = row.expires_at.format("%Y-%m-%d %H:%M UTC").to_string();
    let (p_0, vendor, verb, path, policy_id, detail, created_at, ops) = match blocked {
        Some(b) => (
            b.p_0.as_deref().unwrap_or("(unknown)").to_string(),
            b.vendor.clone(),
            b.action.clone(),
            b.path.clone(),
            b.policy_id.clone().unwrap_or_default(),
            b.detail.clone().unwrap_or_default(),
            b.created_at.to_rfc3339(),
            b.requested_ops.join(", "),
        ),
        None => (
            "(unknown)".into(),
            "—".into(),
            "—".into(),
            "—".into(),
            "—".into(),
            "—".into(),
            "—".into(),
            "—".into(),
        ),
    };
    HTML_TEMPLATE
        .replace("{{ACTION_TITLE}}", &html_escape(action_title))
        .replace("{{ACTION}}", &html_escape(&row.action))
        .replace("{{EXPIRES_AT}}", &html_escape(&expires))
        .replace("{{P_0}}", &html_escape(&p_0))
        .replace("{{VENDOR}}", &html_escape(&vendor))
        .replace("{{VERB}}", &html_escape(&verb))
        .replace("{{PATH}}", &html_escape(&path))
        .replace("{{POLICY_ID}}", &html_escape(&policy_id))
        .replace("{{DETAIL}}", &html_escape(&detail))
        .replace("{{CREATED_AT}}", &html_escape(&created_at))
        .replace("{{REQUESTED_OPS}}", &html_escape(&ops))
        .replace("{{FORM_OR_RESULT}}", body)
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
    fn html_escape_handles_payload_attacks() {
        let s = "<script>alert(1)</script> & quote \" + apostrophe '";
        let escaped = html_escape(s);
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("&lt;script&gt;"));
        assert!(escaped.contains("&amp;"));
        assert!(escaped.contains("&quot;"));
        assert!(escaped.contains("&#39;"));
    }

    #[test]
    fn template_substitutions_fill_all_placeholders() {
        let row = TokenRow {
            token_id: Uuid::new_v4(),
            blocked_id: Uuid::new_v4(),
            action: "approve".into(),
            approver_hint: None,
            issued_by: None,
            expires_at: Utc::now() + chrono::Duration::minutes(30),
            consumed_at: None,
        };
        let blocked = BlockedSummary {
            p_0: Some("alice@acme.com".into()),
            vendor: "google".into(),
            action: "gmail.messages.send".into(),
            path: "/gmail/v1/users/me/messages/send".into(),
            policy_id: Some("gmail-external-send".into()),
            detail: Some("external recipient".into()),
            created_at: Utc::now(),
            requested_ops: vec!["gmail:send:alice@acme.com".into()],
        };
        let html = fill_template(&row, Some(&blocked), "<p>body</p>");
        assert!(!html.contains("{{"), "unfilled placeholder: {html}");
        assert!(html.contains("alice@acme.com"));
        assert!(html.contains("gmail.messages.send"));
    }
}
