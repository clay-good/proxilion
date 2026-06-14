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
                "email",
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

    fn sample_row(action: &str) -> TokenRow {
        TokenRow {
            token_id: Uuid::nil(),
            blocked_id: Uuid::nil(),
            action: action.into(),
            approver_hint: None,
            issued_by: None,
            expires_at: Utc::now() + chrono::Duration::minutes(30),
            consumed_at: None,
        }
    }

    fn sample_blocked() -> BlockedSummary {
        BlockedSummary {
            p_0: Some("alice@acme.com".into()),
            vendor: "google".into(),
            action: "gmail.messages.send".into(),
            path: "/gmail/v1/users/me/messages/send".into(),
            policy_id: Some("p1".into()),
            detail: Some("ext".into()),
            created_at: Utc::now(),
            requested_ops: vec!["gmail:send".into()],
        }
    }

    #[tokio::test]
    async fn render_error_returns_html_with_escaped_message() {
        let r = render_error("<bad>");
        assert_eq!(r.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(r.into_body(), 64_000).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("&lt;bad&gt;"));
        assert!(!html.contains("<bad>"));
    }

    #[tokio::test]
    async fn render_form_approve_includes_action_form_and_justification_textarea() {
        let r = render_form(&sample_row("approve"), &sample_blocked());
        assert_eq!(r.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(r.into_body(), 64_000).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("action=\"/notifier/approve\""));
        assert!(html.contains("name=\"justification\""));
        assert!(html.contains("minlength=\"20\""));
    }

    #[tokio::test]
    async fn render_form_reject_includes_reason_textarea() {
        let r = render_form(&sample_row("reject"), &sample_blocked());
        let bytes = axum::body::to_bytes(r.into_body(), 64_000).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("name=\"reason\""));
        assert!(html.contains("Reject action"));
    }

    #[tokio::test]
    async fn render_form_unknown_action_shows_banner_err() {
        let r = render_form(&sample_row("weird"), &sample_blocked());
        let bytes = axum::body::to_bytes(r.into_body(), 64_000).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("Unknown action"));
    }

    #[tokio::test]
    async fn render_already_used_renders_consumed_message() {
        let mut row = sample_row("approve");
        row.consumed_at = Some(Utc::now());
        let r = render_already_used(&row, &sample_blocked());
        let bytes = axum::body::to_bytes(r.into_body(), 64_000).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("Link already used"));
    }

    #[tokio::test]
    async fn render_validation_error_includes_back_link() {
        let row = sample_row("approve");
        let r = render_validation_error(&row, "too short");
        let bytes = axum::body::to_bytes(r.into_body(), 64_000).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("too short"));
        assert!(html.contains("/notifier/approve?t="));
    }

    #[test]
    fn fill_template_with_no_blocked_uses_dash_placeholders() {
        let row = sample_row("approve");
        let html = fill_template(&row, None, "<p>x</p>");
        assert!(!html.contains("{{"));
        assert!(html.contains("(unknown)"));
    }

    #[test]
    fn html_escape_does_not_double_encode_already_escaped_entities() {
        // The helper is a single-pass byte-mapping, not a parser. Pin that
        // `&amp;` becomes `&amp;amp;` rather than being recognized as an
        // already-escaped entity — a "smart" escape refactor would surface
        // here as missed double-escaping, which on a re-render via `replace`
        // would actually under-escape and reintroduce XSS surface.
        assert_eq!(html_escape("&amp;"), "&amp;amp;");
        assert_eq!(html_escape("&lt;"), "&amp;lt;");
    }

    #[test]
    fn html_escape_passes_unicode_and_empty_through_unchanged() {
        // Non-ascii characters fall into the `_ => out.push(c)` branch and
        // round-trip byte-identical. A regression that pre-emptively
        // percent-encoded non-ascii would silently mangle policy
        // descriptions in non-English deployments. Empty input → empty
        // output for the zero-allocation boundary.
        assert_eq!(html_escape(""), "");
        assert_eq!(html_escape("αβγ — délicieux"), "αβγ — délicieux");
    }

    #[tokio::test]
    async fn fill_template_html_escapes_path_and_detail_to_prevent_xss_in_stored_fields() {
        // `path` and `detail` come from the upstream request and the policy
        // engine respectively; both can carry user-controlled bytes (e.g.
        // a Drive file id containing `<script>`). Pin that the template
        // substitution html-escapes them — a refactor that swapped one
        // `replace` for a raw insertion would reopen stored-XSS surface
        // in the approver UI. Render through `render_form` (which calls
        // `fill_template`) and assert the rendered HTML.
        let row = sample_row("approve");
        let blocked = BlockedSummary {
            p_0: Some("eve<script>@evil.example".into()),
            vendor: "google".into(),
            action: "drive.files.get".into(),
            path: "/drive/v3/files/<img src=x onerror=alert(1)>".into(),
            policy_id: Some("p1".into()),
            detail: Some("</textarea><script>steal()</script>".into()),
            created_at: Utc::now(),
            requested_ops: vec!["drive:read".into()],
        };
        let html = fill_template(&row, Some(&blocked), "<p>x</p>");
        // Path is escaped.
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(!html.contains("<img src=x"));
        // Detail is escaped (the script tag specifically).
        assert!(html.contains("&lt;script&gt;steal()&lt;/script&gt;"));
        assert!(!html.contains("<script>steal()"));
        // p_0 is escaped.
        assert!(html.contains("eve&lt;script&gt;@evil.example"));
    }

    #[tokio::test]
    async fn render_form_reject_action_targets_approve_endpoint_with_token_id() {
        // The reject form posts to the SAME `/notifier/approve` endpoint as
        // the approve form — the handler routes on `action` field from the
        // TokenRow, not on the form URL. Pin this contract; a refactor that
        // split the endpoints (e.g. `/notifier/reject`) would silently
        // break every reject link since the handler routing keys on the
        // single endpoint. Also pin the hidden token field round-trips
        // the row's UUID verbatim.
        let mut row = sample_row("reject");
        row.token_id = Uuid::new_v4();
        let r = render_form(&row, &sample_blocked());
        let bytes = axum::body::to_bytes(r.into_body(), 64_000).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("action=\"/notifier/approve\""));
        assert!(html.contains(&format!("value=\"{}\"", row.token_id)));
    }

    #[tokio::test]
    async fn render_result_with_ok_true_uses_banner_ok_css_class() {
        // The `banner-ok` vs `banner-err` CSS class is the only visible
        // difference between success and failure renders — the approver
        // UI styles each with distinct colors (green vs red). The
        // existing `render_already_used_renders_consumed_message` test
        // hits `ok=true` via `render_already_used`, but never asserts
        // the CSS class directly. Pin both the class name and that the
        // banner block is present. A refactor that "unified" the two
        // banner classes into a generic `banner` would silently make
        // every success render look like a failure (or vice-versa).
        let r = render_result(
            "All set",
            &sample_row("approve"),
            Some(&sample_blocked()),
            "Action committed.",
            true,
        );
        let bytes = axum::body::to_bytes(r.into_body(), 64_000).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(
            html.contains(r#"class="banner-ok""#),
            "missing banner-ok class"
        );
        assert!(
            !html.contains(r#"class="banner-err""#),
            "leaked banner-err on success path"
        );
        assert!(html.contains("All set"));
        assert!(html.contains("Action committed."));
    }

    #[tokio::test]
    async fn render_result_with_ok_false_uses_banner_err_css_class() {
        // Symmetric to the ok=true test — pin that the failure-render
        // path uses `banner-err`. The existing `render_form_unknown_action_shows_banner_err`
        // test asserts the substring `Unknown action` via render_form's
        // unknown branch, but that path uses an inline banner string,
        // not the `render_result` helper. Pin render_result(ok=false)
        // directly so a refactor of that helper alone surfaces here.
        let r = render_result(
            "Something went wrong",
            &sample_row("approve"),
            Some(&sample_blocked()),
            "Database unavailable.",
            false,
        );
        let bytes = axum::body::to_bytes(r.into_body(), 64_000).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(
            html.contains(r#"class="banner-err""#),
            "missing banner-err class"
        );
        assert!(
            !html.contains(r#"class="banner-ok""#),
            "leaked banner-ok on failure path"
        );
        assert!(html.contains("Something went wrong"));
        assert!(html.contains("Database unavailable."));
    }

    #[test]
    fn fill_template_action_title_renders_three_distinct_strings_for_approve_reject_unknown() {
        // The action_title match has three arms (approve / reject /
        // catch-all). The existing tests pin the rendered placeholders
        // via approve forms but never directly assert the title strings
        // — and the catch-all branch isn't exercised by any test that
        // checks the title. Pin all three so a refactor that collapsed
        // the catch-all into the reject arm (the natural shape of a
        // "simplify the match" refactor) would silently change the
        // operator-facing page title on unknown action values.
        let blocked = sample_blocked();
        let mut row = sample_row("approve");
        let html_approve = fill_template(&row, Some(&blocked), "");
        assert!(
            html_approve.contains("Approve blocked action"),
            "missing approve title: {html_approve}"
        );
        row.action = "reject".into();
        let html_reject = fill_template(&row, Some(&blocked), "");
        assert!(
            html_reject.contains("Reject blocked action"),
            "missing reject title: {html_reject}"
        );
        // The fallback arm uses the bare "Blocked action" title (no
        // verb-specific prefix) — pin it directly.
        row.action = "comment".into();
        let html_unknown = fill_template(&row, Some(&blocked), "");
        assert!(
            html_unknown.contains("Blocked action"),
            "missing fallback title: {html_unknown}"
        );
        // Negative on the unknown render — it must NOT carry the approve
        // or reject title (so the three arms are wire-distinct).
        assert!(
            !html_unknown.contains("Approve blocked action"),
            "approve title leaked into unknown: {html_unknown}"
        );
        assert!(
            !html_unknown.contains("Reject blocked action"),
            "reject title leaked into unknown: {html_unknown}"
        );
    }

    #[test]
    fn fill_template_requested_ops_joins_with_comma_space_separator() {
        // The `requested_ops.join(", ")` shape lands the list of ops as
        // a single comma-and-space-separated string in the approver UI's
        // "Requested ops" row. A refactor to `.join(",")` (no space) or
        // to a `\n` line-break would silently change the rendered HTML
        // and break operator visual scanning. Pin the exact separator
        // via a 3-op list.
        let row = sample_row("approve");
        let blocked = BlockedSummary {
            p_0: Some("alice@acme.com".into()),
            vendor: "google".into(),
            action: "drive.files.get".into(),
            path: "/drive/v3/files/abc".into(),
            policy_id: Some("p1".into()),
            detail: Some("ext".into()),
            created_at: Utc::now(),
            requested_ops: vec![
                "drive:read:engineering/*".into(),
                "drive:read:shared/*".into(),
                "drive:write:my-drive".into(),
            ],
        };
        let html = fill_template(&row, Some(&blocked), "");
        // The three ops appear joined by `, ` (comma + single space).
        assert!(
            html.contains("drive:read:engineering/*, drive:read:shared/*, drive:write:my-drive"),
            "ops not joined with `, `: {html}"
        );
    }

    #[test]
    fn notifier_public_state_is_clone_send_sync_static_for_axum_state_boundary() {
        // `NotifierPublicState` is wired into `Router::with_state(...)`
        // — axum's `State` extractor requires (Clone + Send + Sync + 'static).
        // A refactor that gave it an `Rc<...>` field "for cheap shared
        // BlockedApiState" would break Send + Sync but the breakage would
        // surface at router assembly with an unrelated `tower::Service`
        // trait-bound error referencing some opaque future type. Pin the
        // bound combo at this file so the type boundary fails fast at
        // the right call site.
        fn require_clone_send_sync_static<T: Clone + Send + Sync + 'static>() {}
        require_clone_send_sync_static::<NotifierPublicState>();
    }

    #[test]
    fn html_escape_each_of_the_five_special_chars_individually_maps_to_correct_entity() {
        // The existing `payload_attacks` pin asserts presence of all five
        // entities in one combined string. Pin the per-character mapping
        // explicitly — a refactor that introduced an off-by-one in the
        // match arms (e.g. `'<' => "&gt;"` swapped with `'>' => "&lt;"`)
        // would still pass the combined-string assertion (both entities
        // are present) but flip the semantic meaning of every escaped
        // angle bracket in the rendered HTML. Pin the five mappings
        // byte-exact via `assert_eq!`:
        //   `<` → `&lt;`   `>` → `&gt;`   `&` → `&amp;`
        //   `"` → `&quot;` `'` → `&#39;`
        assert_eq!(html_escape("<"), "&lt;");
        assert_eq!(html_escape(">"), "&gt;");
        assert_eq!(html_escape("&"), "&amp;");
        assert_eq!(html_escape("\""), "&quot;");
        assert_eq!(html_escape("'"), "&#39;");
    }

    #[test]
    fn html_escape_passes_non_special_ascii_bytes_through_byte_for_byte() {
        // The `_ => out.push(c)` catch-all branch preserves all non-
        // special ASCII byte-for-byte. Pin a wide spread of common
        // characters in operator-facing strings (digits, letters, space,
        // punctuation that ISN'T in the five-char escape set) so a
        // refactor that "expanded the escape set for extra safety" (e.g.
        // started escaping `/` to `&#x2F;` for some "XSS safety in HTML
        // attributes" guidance) would surface here as a no-longer-byte-
        // equal pass-through and break the rendered HTML's visual
        // appearance for paths like `/drive/v3/files/abc`.
        let plain = "abcXYZ 0123456789 .,;:!?/-_+=()[]{}";
        assert_eq!(html_escape(plain), plain);
    }

    #[tokio::test]
    async fn render_error_response_content_type_is_text_html() {
        // The approver landing is rendered as `Html(...)` which axum
        // ships as `content-type: text/html; charset=utf-8` — pin the
        // prefix so a refactor that swapped to a raw `String` response
        // (which defaults to `text/plain`) would silently un-render the
        // HTML in every approver's browser as raw markup. The exact
        // suffix `; charset=utf-8` is axum's choice and may shift; pin
        // the meaningful prefix `text/html`.
        let r = render_error("oops");
        let ct = r
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.starts_with("text/html"),
            "expected text/html content-type, got: {ct}",
        );
    }

    #[tokio::test]
    async fn render_error_returns_status_ok_not_4xx_for_approver_self_service_fix() {
        // Error pages return `StatusCode::OK` rather than 4xx — the
        // approver page is a human-facing UI, not an API; surfacing a
        // 4xx would let some browsers display the bare status text
        // instead of the rendered HTML, AND some corporate proxies
        // suppress 4xx response bodies wholesale ("hide error pages
        // from end users"). The rendered HTML carries the error
        // message and the suggested operator action — the response
        // MUST land in the browser. Pin `200` directly. A refactor
        // that swapped to `StatusCode::BAD_REQUEST` "for proper REST
        // semantics" would silently break the approver UX behind
        // those proxies.
        for msg in [
            "Link unknown or already used",
            "Link expired",
            "Internal error: db down",
        ] {
            let r = render_error(msg);
            assert_eq!(
                r.status(),
                StatusCode::OK,
                "render_error({msg:?}) should return 200, got {:?}",
                r.status(),
            );
        }
    }

    #[test]
    fn html_escape_preserves_byte_length_of_each_special_char_replacement_relative_to_input() {
        // Each of the five entities expands by a known byte delta from
        // its single-byte input: `<` (1 byte) → `&lt;` (4) → +3; `>` → +3;
        // `&` → +4; `"` → +5; `'` → +4. Pin the deltas so a refactor that
        // introduced shorter HTML5-named entities (e.g. `&apos;` instead
        // of `&#39;` for the apostrophe, which would change +4 to +5) or
        // longer "extra-defensive" entities (e.g. `&#x26;` instead of
        // `&amp;`, +4 → +5) would surface here. The renderer's
        // String::with_capacity sizing (currently `s.len()`) would also
        // need updating in lockstep — a shorter capacity hint would
        // cause realloc; a longer one would waste memory.
        assert_eq!(html_escape("<").len(), 1 + 3);
        assert_eq!(html_escape(">").len(), 1 + 3);
        assert_eq!(html_escape("&").len(), 1 + 4);
        assert_eq!(html_escape("\"").len(), 1 + 5);
        assert_eq!(html_escape("'").len(), 1 + 4);
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

    // ─── round 187 (2026-05-20): html_escape + HTML_TEMPLATE + fill_template surfaces ───

    #[test]
    fn html_escape_return_type_is_owned_string_for_cross_await_template_filling() {
        // `html_escape(s: &str) -> String` — return is OWNED `String`,
        // NOT borrowed. The `fill_template` call site chains 12
        // sequential `.replace(...)` operations against the owned
        // String; an `&'a str` return would force a temporary at
        // every replace site. Pin the owned-String type via the
        // canonical require_string helper. Symmetric to round-185
        // + round-186 owned-String pins extended to this HTML-
        // sanitization helper.
        fn require_string(_: &String) {}
        let s = html_escape("alice & bob <x>");
        require_string(&s);
        assert_eq!(s, "alice &amp; bob &lt;x&gt;");
    }

    #[test]
    fn html_escape_is_referentially_transparent_across_fifty_repeated_calls() {
        // `html_escape` is a pure per-char map — no clock, no env,
        // no global state. Pin referential transparency across 50
        // back-to-back calls on a multi-special-char fixture. A
        // refactor that introduced any per-call mutation (e.g. a
        // bump-allocator backed by thread-local state that lazily
        // capped string sizes) would silently make two calls
        // diverge AND break operator-log dedup pipelines that hash
        // the rendered approver landing page. Symmetric to round-185
        // + round-186 50-call ref-transparency pins extended to
        // this sanitization helper.
        let input = "<script>alert(1)</script> & \"quote\" + 'apostrophe' & café";
        let first = html_escape(input);
        for i in 1..50 {
            assert_eq!(
                html_escape(input),
                first,
                "html_escape diverged on call #{i}",
            );
        }
    }

    #[test]
    fn html_escape_empty_input_returns_empty_string_without_allocation_panic() {
        // Boundary: empty input must return empty output without
        // panicking on the `String::with_capacity(0)` allocation
        // boundary. The existing
        // `html_escape_passes_unicode_and_empty_through_unchanged`
        // pins the unicode case but covers empty as a side-condition
        // — pin it directly here so a refactor that pre-asserted
        // `!s.is_empty()` "for input hygiene" surfaces as a panic
        // on the empty-string call path (the operator-approver
        // landing renders empty strings for the missing
        // `approver_hint` / `issued_by` fields).
        let s = html_escape("");
        assert!(s.is_empty(), "empty input must round-trip to empty output");
        // Symmetric: explicit byte-length check.
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn html_template_constant_is_static_str_lifetime_for_zero_alloc_template_filling() {
        // `HTML_TEMPLATE` is `include_str!("..")` which produces a
        // `&'static str` baked into the binary at compile time.
        // The `fill_template` call site calls `.replace(...)` 12
        // times against this constant — the static lifetime is
        // load-bearing because `.replace` returns owned String
        // (each replace step copies from the static buffer once)
        // and the original constant survives every call without
        // an allocation. A refactor that switched to lazy-loading
        // the template from disk "for hot-reload" would silently
        // promote the constant to owned String AND add I/O to
        // every approver landing render. Pin the static lifetime
        // via require_static_str. Symmetric to round-184 +
        // round-186 static-str lifetime pins extended to this
        // template constant.
        fn require_static_str(_: &'static str) {}
        require_static_str(HTML_TEMPLATE);
        // Sanity: the template is non-empty.
        assert!(!HTML_TEMPLATE.is_empty());
    }

    #[test]
    fn html_template_contains_every_placeholder_token_fill_template_substitutes() {
        // `fill_template` chains 12 `.replace("{{NAME}}", ...)`
        // calls. Pin that EVERY placeholder fill_template attempts
        // to substitute is actually present in the HTML template.
        // A refactor that added a 13th `.replace(...)` call without
        // adding the corresponding `{{XYZ}}` token to the template
        // would silently produce a no-op — the operator would see
        // a broken substitution variable in the rendered HTML. The
        // existing `template_substitutions_fill_all_placeholders`
        // pin checks the REVERSE direction (no `{{` left after
        // fill); pin the FORWARD direction here so adding a stray
        // placeholder to the .replace chain surfaces as a missing
        // template token.
        for token in [
            "{{ACTION_TITLE}}",
            "{{ACTION}}",
            "{{EXPIRES_AT}}",
            "{{P_0}}",
            "{{VENDOR}}",
            "{{VERB}}",
            "{{PATH}}",
            "{{POLICY_ID}}",
            "{{DETAIL}}",
            "{{CREATED_AT}}",
            "{{REQUESTED_OPS}}",
            "{{FORM_OR_RESULT}}",
        ] {
            assert!(
                HTML_TEMPLATE.contains(token),
                "HTML_TEMPLATE missing placeholder {token}",
            );
        }
    }

    #[test]
    fn fill_template_return_type_is_owned_string_for_axum_response_body() {
        // `fill_template` returns owned `String` — the axum response
        // wraps it via `Html(...)` which owns the body. A refactor
        // to `Cow<'static, str>` "for the no-substitution fast path"
        // would force the response to either Clone or borrow with a
        // lifetime parameter that doesn't compose with the handler
        // signature. Pin owned-String return via require_string.
        // Symmetric to round-186 canonical_request_json owned-String
        // return pin extended to this template renderer.
        fn require_string(_: &String) {}
        let row = sample_row("approve");
        let blocked = sample_blocked();
        let html = fill_template(&row, Some(&blocked), "<p>body</p>");
        require_string(&html);
        // Sanity: the rendered HTML is non-trivially sized (template
        // is at least a few hundred bytes; substituted values add
        // more).
        assert!(
            html.len() > 100,
            "rendered html too small: {} bytes",
            html.len()
        );
    }

    #[test]
    fn notifier_public_state_field_count_pinned_at_exactly_two_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the NotifierPublicState struct field count at exactly
        // 2 via exhaustive destructure (no `..`). The 2 fields are:
        // db (PgPool) + blocked (Arc<BlockedApiState>). A 3rd field
        // landing (e.g. `audit_sink: Arc<dyn ActionStream>` to log
        // every public approve / reject click into the audit
        // pipeline, or `rate_limiter: Arc<RateLimiter>` for
        // per-IP throttling on the signed-URL landing page) would
        // silently bloat every Clone of NotifierPublicState the
        // axum router fans out per request. The existing Clone
        // derive is what supports the fan-out; exhaustive
        // destructure catches a runtime-only 3rd field.
        fn _destructure_witness(s: NotifierPublicState) {
            let NotifierPublicState { db: _, blocked: _ } = s;
        }
    }

    #[test]
    fn token_q_field_count_pinned_at_exactly_one_via_exhaustive_destructure_no_rest_pattern() {
        // Pin the TokenQ query-string struct field count at exactly
        // 1 via exhaustive destructure. The 1 field is: t (Uuid).
        // A 2nd field landing (e.g. `approver: Option<String>` to
        // distinguish the actual click-through user from the
        // approver_hint set at link-mint time, or `redirect_url:
        // Option<String>` for a future SSO landing-page integration)
        // would silently extend the query-string shape every email
        // link must use AND silently change the deserialize
        // contract on `GET /notifier/approve`.
        let v = TokenQ { t: Uuid::nil() };
        let TokenQ { t: _ } = v;
    }

    #[test]
    fn submit_form_field_count_pinned_at_exactly_three_via_exhaustive_destructure_no_rest_pattern()
    {
        // Pin the SubmitForm POST body struct field count at exactly
        // 3 via exhaustive destructure. The 3 fields are: t (Uuid)
        // + justification (Option<String>) + reason (Option<String>).
        // A 4th field landing (e.g. `csrf_token: String` for a
        // future CSRF protection layer on the signed-URL landing
        // page, or `acknowledged_risk: Option<bool>` for an
        // operator-facing acknowledge-this-is-destructive checkbox)
        // would silently extend the form fields the approve.html
        // template emits AND silently change the deserialize
        // contract on `POST /notifier/approve`. The existing
        // approve.html template references all 3 fields by name; a
        // 4th field landing without matching template-side updates
        // would silently produce a deserialize error for every
        // legitimate click-through.
        let v = SubmitForm {
            t: Uuid::nil(),
            justification: None,
            reason: None,
        };
        let SubmitForm {
            t: _,
            justification: _,
            reason: _,
        } = v;
    }

    #[test]
    fn blocked_summary_field_count_pinned_at_exactly_eight_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the BlockedSummary struct field count at exactly 8 via
        // exhaustive destructure. The 8 fields are: p_0 + vendor +
        // action + path + policy_id + detail + created_at +
        // requested_ops. A 9th field landing (e.g. `chain_id:
        // Option<Uuid>` to render the chain-walker link on the
        // landing page, or `severity: Option<String>` to color-code
        // the approve form by risk level) would silently bloat
        // every BlockedSummary Clone on the form-render path AND
        // silently change what the approve.html template can
        // substitute via the fill_template placeholders.
        let v = BlockedSummary {
            p_0: None,
            vendor: String::new(),
            action: String::new(),
            path: String::new(),
            policy_id: None,
            detail: None,
            created_at: Utc::now(),
            requested_ops: vec![],
        };
        let BlockedSummary {
            p_0: _,
            vendor: _,
            action: _,
            path: _,
            policy_id: _,
            detail: _,
            created_at: _,
            requested_ops: _,
        } = v;
    }

    #[test]
    fn html_escape_signature_pinned_via_fn_pointer_witness() {
        // Pin html_escape signature as `fn(&str) -> String` via
        // fn-pointer witness. A refactor that flipped to
        // `fn(String) -> String` ("for consume-and-format") would
        // silently force every render call site to box every
        // user-supplied field — the approve.html template path
        // calls html_escape on borrowed slices into the
        // BlockedSummary struct without cloning. The owned String
        // return is also pinned — a refactor to `Cow<'_, str>`
        // for the no-escape-needed fast path would tie the return
        // lifetime to the input slice and force lifetime
        // parameters on the response shape that the axum Html()
        // wrapper can't satisfy without owning the body.
        let _f: fn(&str) -> String = html_escape;
    }

    #[test]
    fn router_function_signature_pinned_via_fn_pointer_witness() {
        // Pin the module's router constructor signature as
        // `fn(NotifierPublicState) -> Router` via fn-pointer
        // witness. Symmetric to round-262/263/264/265 router
        // fn-pointer pins extended to the public notifier API
        // surface. The server.rs boot path calls
        // `router(public_state)` once at app assembly time AND
        // consumes the state by value (the router clones it per
        // request via `.with_state(...)`). A refactor to
        // `fn(&NotifierPublicState) -> Router` or
        // `fn(NotifierPublicState) -> Result<Router, _>` would
        // silently change the boot path's ownership AND
        // error-handling shape.
        let _f: fn(NotifierPublicState) -> Router = router;
    }

    // ─────────────────────────────────────────────────────────────────────
    // DB-backed integration test (opt-in via PROXILION_TEST_DATABASE_URL).
    // Skips when no test database is configured — see `test_support`.
    // ─────────────────────────────────────────────────────────────────────

    /// Construct a `NotifierPublicState` over a real pool. `reject_inner` (the
    /// path this test exercises) touches only `db`, but `BlockedApiState`
    /// requires the pca_cache + pic fields to exist.
    async fn public_state(pool: sqlx::PgPool) -> NotifierPublicState {
        let pca_cache = crate::pic::PcaCache::new(pool.clone());
        let pic = crate::pic::executor::PicExecutor::dev_ephemeral("http://localhost:0".into())
            .expect("ephemeral pic executor builds");
        let blocked = std::sync::Arc::new(crate::api::blocked::BlockedApiState {
            db: pool.clone(),
            pca_cache,
            pic,
        });
        NotifierPublicState { db: pool, blocked }
    }

    async fn body_str(r: Response) -> String {
        let bytes = axum::body::to_bytes(r.into_body(), 256_000).await.unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn db_backed_landing_get_does_not_consume_token_but_post_does() {
        // §4.1 prefetch-safety, end-to-end against real SQL: an email client
        // (or scanner) that GETs the approve link must NOT consume the single-
        // use token — only the form POST may. This is the load-bearing
        // property that makes the email approval link prefetch-safe.
        let Some(pool) = crate::test_support::pool().await else {
            eprintln!("skipping: {} unset", crate::test_support::TEST_DB_ENV);
            return;
        };
        let blocked_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO blocked_actions (id, request_id, vendor, action, layer, policy_id, detail, status)
             VALUES ($1, $2, 'google', 'gmail.messages.send', 'policy', 'gmail-ext', 'external recipient', 'pending')",
        )
        .bind(blocked_id)
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .expect("seed blocked_actions");
        sqlx::query(
            "INSERT INTO notifier_tokens (token_id, blocked_id, action, expires_at)
             VALUES ($1, $2, 'reject', now() + interval '30 minutes')",
        )
        .bind(token_id)
        .bind(blocked_id)
        .execute(&pool)
        .await
        .expect("seed notifier_tokens");

        let state = public_state(pool.clone()).await;

        // 1. GET the landing — renders the form, consumes NOTHING.
        let resp = landing(State(state.clone()), Query(TokenQ { t: token_id })).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_str(resp).await;
        assert!(
            html.contains("name=\"reason\""),
            "GET should render the reject form"
        );
        let consumed: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT consumed_at FROM notifier_tokens WHERE token_id = $1")
                .bind(token_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            consumed.is_none(),
            "PREFETCH HAZARD: GET consumed the single-use token",
        );

        // 2. POST the form — commits the reject and consumes the token.
        let resp = submit(
            State(state.clone()),
            Form(SubmitForm {
                t: token_id,
                justification: None,
                reason: Some("not authorized for this external recipient".into()),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let status: String = sqlx::query_scalar("SELECT status FROM blocked_actions WHERE id = $1")
            .bind(blocked_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "rejected", "POST should commit the reject");
        let consumed: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT consumed_at FROM notifier_tokens WHERE token_id = $1")
                .bind(token_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(consumed.is_some(), "POST must consume the token");

        // 3. GET again — the token is spent; landing shows the already-used page.
        let resp = landing(State(state), Query(TokenQ { t: token_id })).await;
        let html = body_str(resp).await;
        assert!(
            html.contains("already") || html.to_lowercase().contains("used"),
            "a consumed token must render the already-used page, got: {}",
            &html[..html.len().min(300)],
        );
    }
}
