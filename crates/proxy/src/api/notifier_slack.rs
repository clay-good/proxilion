//! Slack interaction webhook (ui-less-surfaces.md §5.3).
//!
//! Slack POSTs button clicks to `/api/v1/notifier/slack/interact` with a
//! signed `application/x-www-form-urlencoded` body containing a single
//! `payload` field — the actual JSON. We verify the v0 signed-request
//! scheme using the per-driver `signing_secret` from `notifier_config`,
//! then route the button value (`approve:<uuid>` / `reject:<uuid>`) to
//! the existing `approve_inner` / `reject_inner` helpers.
//!
//! Mounted OUTSIDE the operator_auth layer — the Slack signed request IS
//! the credential.

use std::sync::Arc;

use axum::{
    Router,
    body::{self, Body},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use sqlx::PgPool;
use tracing::{info, warn};

use crate::api::blocked::{ApproveBody, BlockedApiState, RejectBody, approve_inner, reject_inner};
use crate::notifier::{SlackAction, SlackHandle, parse_button_value};

#[derive(Clone)]
pub struct SlackInteractState {
    pub slack: SlackHandle,
    pub blocked: Arc<BlockedApiState>,
    /// Direct DB handle for the trigger_id idempotency claim. The
    /// approve/reject pipeline runs through `BlockedApiState` but the
    /// pre-flight claim needs to UPDATE before either is called.
    pub db: PgPool,
}

/// Outcome of attempting to claim a `slack_trigger_id` on a blocked row.
enum TriggerClaim {
    /// First time we've seen this trigger_id; proceed.
    Fresh,
    /// Trigger_id already claimed this row — Slack retry of the same
    /// click. Return the prior success without re-running approve/reject.
    Retry,
    /// Some other trigger_id already claimed the row. Reject.
    Conflict,
    /// DB unavailable / unexpected.
    Error(String),
}

/// Atomically claim `slack_trigger_id` on a `pending` row. The unique
/// partial index on `blocked_actions.slack_trigger_id` enforces
/// "at most one trigger_id per row" at the database layer; this query
/// surfaces the racing-trigger_id case as `Conflict` instead of a 500.
async fn claim_trigger_id(db: &PgPool, blocked_id: uuid::Uuid, trigger_id: &str) -> TriggerClaim {
    // Single-statement claim: only succeeds when the row is still pending
    // AND no trigger_id is set. Returns the row's id so we can distinguish
    // "claimed now" (1 row) from "couldn't claim" (0 rows).
    let res = sqlx::query_scalar::<_, uuid::Uuid>(
        "UPDATE blocked_actions
            SET slack_trigger_id = $2
          WHERE id = $1
            AND status = 'pending'
            AND slack_trigger_id IS NULL
        RETURNING id",
    )
    .bind(blocked_id)
    .bind(trigger_id)
    .fetch_optional(db)
    .await;

    match res {
        Ok(Some(_)) => TriggerClaim::Fresh,
        Ok(None) => {
            // Couldn't claim. Two reasons matter: same trigger_id already
            // recorded (Slack retry → Retry), OR row is not pending /
            // a different trigger_id is set (Conflict).
            let existing: Result<Option<(String,)>, sqlx::Error> = sqlx::query_as(
                "SELECT slack_trigger_id FROM blocked_actions
                  WHERE id = $1 AND slack_trigger_id IS NOT NULL",
            )
            .bind(blocked_id)
            .fetch_optional(db)
            .await;
            match existing {
                Ok(Some((existing_tid,))) if existing_tid == trigger_id => TriggerClaim::Retry,
                Ok(_) => TriggerClaim::Conflict,
                Err(e) => TriggerClaim::Error(e.to_string()),
            }
        }
        Err(e) => TriggerClaim::Error(e.to_string()),
    }
}

pub fn router(state: SlackInteractState) -> Router {
    Router::new()
        .route("/api/v1/notifier/slack/interact", post(interact))
        .with_state(state)
}

/// Slack uses form-encoded bodies with a JSON-string `payload` field. We
/// take the raw `Request<Body>` so we can verify the signature against the
/// EXACT bytes Slack sent (parsing-then-reserializing won't byte-match).
async fn interact(State(state): State<SlackInteractState>, req: Request<Body>) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = match body::to_bytes(body, 1024 * 1024).await {
        Ok(b) => b.to_vec(),
        Err(_) => return slack_err(StatusCode::BAD_REQUEST, "body read failed"),
    };

    // Verify signature.
    let Some(slack) = state.slack.current() else {
        return slack_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "slack driver not configured",
        );
    };
    let sig = header_str(&parts.headers, "x-slack-signature");
    let ts = header_str(&parts.headers, "x-slack-request-timestamp");
    let Some(sig) = sig else {
        return slack_err(StatusCode::UNAUTHORIZED, "missing signature header");
    };
    let Some(ts) = ts else {
        return slack_err(StatusCode::UNAUTHORIZED, "missing timestamp header");
    };
    if !slack.signing_secret().verify(sig, ts, &bytes) {
        metrics::counter!(
            "proxilion_slack_interact_total",
            "result" => "rejected_signature"
        )
        .increment(1);
        return slack_err(StatusCode::UNAUTHORIZED, "signature mismatch");
    }

    // Parse the form body: a single `payload=<urlencoded-json>` field.
    let form: std::collections::HashMap<String, String> = match serde_urlencoded::from_bytes(&bytes)
    {
        Ok(m) => m,
        Err(e) => {
            return slack_err(StatusCode::BAD_REQUEST, &format!("form parse: {e}"));
        }
    };
    let Some(payload_raw) = form.get("payload") else {
        return slack_err(StatusCode::BAD_REQUEST, "missing payload");
    };
    let payload: serde_json::Value = match serde_json::from_str(payload_raw) {
        Ok(v) => v,
        Err(e) => return slack_err(StatusCode::BAD_REQUEST, &format!("payload json: {e}")),
    };

    // Extract `actions[0].value` and the user that clicked.
    let value = payload["actions"][0]["value"].as_str().unwrap_or("");
    let user_id = payload["user"]["id"].as_str();
    let user_name = payload["user"]["username"].as_str();
    let approver = user_name.or(user_id).unwrap_or("slack-user");

    let Some((action, blocked_id)) = parse_button_value(value) else {
        return slack_err(StatusCode::BAD_REQUEST, "unrecognized button value");
    };

    // [Why?] (ui-less-surfaces.md §5.3 dev 2) — short-circuit before the
    // trigger_id idempotency claim. Why is purely informational: it doesn't
    // mutate the blocked row, doesn't consume a trigger_id, and returns an
    // ephemeral message visible only to the clicker.
    if matches!(action, SlackAction::Why) {
        return handle_why(&state.db, blocked_id).await;
    }

    // Trigger-id idempotency (ui-less-surfaces.md §5.3 deviation 3).
    // Slack retries delivery on timeout/network failure; without this
    // claim, a retry would attempt a second approve_inner call against
    // an already-overridden row and return 409 to the Slack user.
    let trigger_id = payload["trigger_id"].as_str().unwrap_or("").to_string();
    if !trigger_id.is_empty() {
        match claim_trigger_id(&state.db, blocked_id, &trigger_id).await {
            TriggerClaim::Fresh => {}
            TriggerClaim::Retry => {
                metrics::counter!(
                    "proxilion_slack_interact_total",
                    "result" => "retry_idempotent",
                )
                .increment(1);
                info!(blocked_id = %blocked_id, "slack interaction is a retry of a prior trigger_id; returning idempotent success");
                return slack_ok_message("Already processed (retry).");
            }
            TriggerClaim::Conflict => {
                metrics::counter!(
                    "proxilion_slack_interact_total",
                    "result" => "conflict_other_trigger",
                )
                .increment(1);
                warn!(blocked_id = %blocked_id, "slack interaction conflicts with prior trigger_id");
                return slack_err(
                    StatusCode::CONFLICT,
                    "this action was already approved or rejected",
                );
            }
            TriggerClaim::Error(e) => {
                metrics::counter!(
                    "proxilion_slack_interact_total",
                    "result" => "claim_error",
                )
                .increment(1);
                warn!(blocked_id = %blocked_id, error = %e, "trigger_id claim failed; proceeding without idempotency");
                // Continue — the FOR UPDATE inside approve_inner is still
                // the canonical race protection.
            }
        }
    }

    // ui-less-surfaces.md §5.3 dev 4 — user_map resolution. Prefer a
    // mapped operator subject (typically the operator's email) over the
    // opaque `slack:<username>` shape so the attested override carries
    // the operator's stable identity.
    let approver_subject = slack
        .resolve_user(user_id, user_name)
        .unwrap_or_else(|| format!("slack:{approver}"));
    let outcome: Result<String, String> = match action {
        SlackAction::Approve => {
            // Slack messages don't carry a justification field today; we
            // synthesize one from the Slack user id so the audit row is
            // not empty. A future iteration could prompt the user for a
            // reason via a modal-open call before recording.
            let justification = format!(
                "approved via Slack by {approver} at {}",
                chrono::Utc::now().to_rfc3339()
            );
            match approve_inner(
                &state.blocked,
                blocked_id,
                ApproveBody {
                    justification: justification.clone(),
                    ttl_minutes: None,
                    approver_subject: Some(approver_subject.clone()),
                },
                "slack",
            )
            .await
            {
                Ok(r) => Ok(format!(
                    "✅ Approved by *{approver}* — override PCA `{}` minted at hop {}.",
                    r.override_pca_id, r.hop
                )),
                Err(e) => Err(format!("Approve failed: {e}")),
            }
        }
        SlackAction::Why => unreachable!("Why was handled above"),
        SlackAction::Reject => {
            let reason = format!("rejected via Slack by {approver}");
            match reject_inner(
                &state.blocked,
                blocked_id,
                RejectBody {
                    reason,
                    approver_subject: Some(approver_subject.clone()),
                },
            )
            .await
            {
                Ok(_) => Ok(format!("❌ Rejected by *{approver}*.")),
                Err(e) => Err(format!("Reject failed: {e}")),
            }
        }
    };

    let (label, text) = match &outcome {
        Ok(t) => ("ok", t.clone()),
        Err(t) => ("error", t.clone()),
    };
    metrics::counter!(
        "proxilion_slack_interact_total",
        "result" => label,
    )
    .increment(1);
    info!(blocked_id = %blocked_id, result = label, "slack interaction handled");

    // Return a `response_type: ephemeral` message that replaces the
    // original (Block Kit). This shows immediate feedback in the channel
    // to the clicker.
    let body = serde_json::json!({
        "response_type": "in_channel",
        "replace_original": true,
        "text": text,
    });
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// 200 OK with a Slack-shaped Block-Kit-ish text response. Used for the
/// idempotent-retry path so the same Slack user sees the same kind of
/// success message as a first-time approval.
fn slack_ok_message(text: &str) -> Response {
    let body = serde_json::json!({
        "response_type": "in_channel",
        "replace_original": true,
        "text": text,
    });
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Render the forensic-context ephemeral message (ui-less-surfaces.md
/// §5.3 dev 2). Returns the blocked row's policy_id / detail / path /
/// requested_ops as Slack mrkdwn, visible only to the clicker
/// (`response_type: "ephemeral"`).
async fn handle_why(db: &PgPool, blocked_id: uuid::Uuid) -> Response {
    type WhyRow = (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
        Vec<String>,
        chrono::DateTime<chrono::Utc>,
        Option<String>,
    );
    let row: Result<Option<WhyRow>, sqlx::Error> = sqlx::query_as(
        "SELECT status, p_0, policy_id, detail, path, vendor, action, requested_ops, expires_at, \
                request_canonical_json \
         FROM blocked_actions WHERE id = $1",
    )
    .bind(blocked_id)
    .fetch_optional(db)
    .await;
    let text = match row {
        Ok(Some((
            status,
            p_0,
            policy_id,
            detail,
            path,
            vendor,
            action,
            ops,
            expires_at,
            request_canonical_json,
        ))) => {
            // Truncate requested_ops list for channel hygiene; full set is
            // visible via `proxilion-cli blocked show <id>`.
            let ops_preview = if ops.is_empty() {
                "—".to_string()
            } else if ops.len() <= 5 {
                ops.join(", ")
            } else {
                format!("{}, … (+{} more)", ops[..5].join(", "), ops.len() - 5)
            };
            // Render the request snapshot as a fenced code block when
            // present. Keep the §5.3 dev 2 "4 KB cap" honored at the
            // adapter side (canonical_request_json already truncates);
            // we hard-cap here at 2 KB as a defense-in-depth so a
            // pre-truncation column can't fill a Slack channel.
            const SLACK_REQ_CAP: usize = 2048;
            let request_block = match request_canonical_json {
                Some(s) => {
                    let snippet = if s.len() > SLACK_REQ_CAP {
                        format!("{}…", &s[..SLACK_REQ_CAP])
                    } else {
                        s
                    };
                    format!("\n*Request:*\n```\n{snippet}\n```")
                }
                None => String::new(),
            };
            format!(
                "*Why blocked* `{id}`\n\
                 *Status:* `{status}`  ·  *Vendor:* `{vendor}`  ·  *Action:* `{action}`\n\
                 *p_0:* `{p_0}`  ·  *Policy:* `{policy_id}`\n\
                 *Path:* `{path}`\n\
                 *Requested ops:* {ops_preview}\n\
                 *Detail:* {detail}\n\
                 *Expires at:* `{expires_at}`{request_block}",
                id = blocked_id,
                p_0 = p_0.as_deref().unwrap_or("—"),
                policy_id = policy_id.as_deref().unwrap_or("—"),
                path = path.as_deref().unwrap_or("—"),
                detail = detail.as_deref().unwrap_or("—"),
            )
        }
        Ok(None) => format!("Blocked action `{blocked_id}` not found."),
        Err(e) => {
            warn!(error = %e, %blocked_id, "why: DB lookup failed");
            format!("Could not fetch details for `{blocked_id}`.")
        }
    };
    metrics::counter!("proxilion_slack_interact_total", "result" => "why").increment(1);
    let body = serde_json::json!({
        "response_type": "ephemeral",
        "replace_original": false,
        "text": text,
    });
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn slack_err(status: StatusCode, msg: &str) -> Response {
    warn!(status = %status, msg, "slack interact rejected");
    (
        status,
        [("content-type", "application/json")],
        serde_json::json!({ "error": msg }).to_string(),
    )
        .into_response()
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn header_str_reads_ascii_header() {
        let mut h = HeaderMap::new();
        h.insert("x-slack-signature", HeaderValue::from_static("v0=abc"));
        assert_eq!(header_str(&h, "x-slack-signature"), Some("v0=abc"));
        assert_eq!(header_str(&h, "x-slack-timestamp"), None);
    }

    #[test]
    fn header_str_returns_none_for_non_ascii() {
        let mut h = HeaderMap::new();
        h.insert("x-custom", HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap());
        assert!(header_str(&h, "x-custom").is_none());
    }

    #[tokio::test]
    async fn slack_ok_message_is_in_channel_replace_original() {
        let r = slack_ok_message("approved");
        assert_eq!(r.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["response_type"], "in_channel");
        assert_eq!(v["replace_original"], true);
        assert_eq!(v["text"], "approved");
    }

    #[tokio::test]
    async fn slack_err_carries_status_and_message() {
        let r = slack_err(StatusCode::UNAUTHORIZED, "bad sig");
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], "bad sig");
    }

    #[test]
    fn header_str_is_case_insensitive_per_http_spec() {
        // HTTP header names are case-insensitive per RFC 7230 §3.2 —
        // axum's HeaderMap normalizes on insert, so a lookup against
        // any case must succeed. Pin this here because the call sites
        // pass lower-case literals (`"x-slack-signature"`) but Slack's
        // SDKs sometimes send mixed case (`"X-Slack-Signature"`). A
        // refactor that bypassed HeaderMap's normalization (e.g. by
        // iterating raw bytes) would silently miss the header from
        // Slack's Go SDK.
        let mut h = HeaderMap::new();
        h.insert("X-Slack-Signature", HeaderValue::from_static("v0=abc"));
        // Looked up via lower-case (the call-site shape) — must hit.
        assert_eq!(header_str(&h, "x-slack-signature"), Some("v0=abc"));
    }

    #[tokio::test]
    async fn slack_err_emits_500_for_internal_error_path() {
        // The signature-mismatch + bad-payload paths use 4xx; the
        // (rare) DB-failure path during trigger_id claim falls back
        // to slack_err with 500. Pin that the helper accepts any
        // status — a regression that hardcoded UNAUTHORIZED (the
        // common case) would silently downgrade every 500 to a 401
        // and break the operator dashboard's "Slack delivery health"
        // panel keyed on 5xx counts.
        let r = slack_err(StatusCode::INTERNAL_SERVER_ERROR, "db down");
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], "db down");
    }

    #[tokio::test]
    async fn slack_ok_message_carries_empty_text_through_to_wire() {
        // Edge: the synthesized success message can be empty in the
        // future if a feature flag elides per-action text. Pin that
        // `slack_ok_message("")` returns a 200 with `text: ""` rather
        // than panicking on a `.unwrap()` against an empty string —
        // the helper does NOT validate its input.
        let r = slack_ok_message("");
        assert_eq!(r.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["text"], "");
        assert_eq!(v["response_type"], "in_channel");
        assert_eq!(v["replace_original"], true);
    }
}
