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
