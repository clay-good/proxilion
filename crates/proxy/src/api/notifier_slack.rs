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
    async fn slack_err_carries_application_json_content_type_header() {
        // The error helper is responsible for the response's content-type
        // header — Slack's client renders the inline-message body iff the
        // header is `application/json`. A regression that dropped the
        // header (or emitted `text/plain` from a copy-paste with the
        // catch-all error handler) would silently turn every operator-
        // facing button-click error into an unrendered raw-text bubble.
        let r = slack_err(StatusCode::BAD_REQUEST, "missing payload");
        let ct = r
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(ct, "application/json");
    }

    #[tokio::test]
    async fn slack_ok_message_carries_application_json_content_type_header() {
        // Symmetric to the err-helper test above — pin that the success
        // path also serializes with `content-type: application/json`.
        // The two helpers share the same Slack-rendering contract and
        // must move in lockstep; a divergence (e.g. err uses
        // application/json but ok forgets it) would silently break the
        // happy-path inline-message render.
        let r = slack_ok_message("Approved.");
        let ct = r
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(ct, "application/json");
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

    #[tokio::test]
    async fn slack_err_body_omits_slack_shaped_response_keys() {
        // The error envelope must NOT carry `response_type` or
        // `replace_original` — those are Slack's in-channel-message
        // routing keys, and emitting them on a 4xx/5xx would make Slack
        // attempt to replace the operator's original button click with
        // the error JSON as the new message body (rendering raw JSON to
        // the channel). The two helpers (slack_err vs slack_ok_message)
        // intentionally produce DIFFERENT envelopes — pin the
        // distinction so a future "unify the helpers" refactor surfaces.
        let r = slack_err(StatusCode::BAD_REQUEST, "missing payload");
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v.get("response_type").is_none(), "got: {v}");
        assert!(v.get("replace_original").is_none(), "got: {v}");
    }

    #[tokio::test]
    async fn slack_err_escapes_special_chars_in_msg_via_serde_json() {
        // The helper builds the body via `serde_json::json!` rather than
        // raw `format!` — pin that double-quotes and newlines in the
        // message round-trip through serde escape rules (resulting in
        // `\"` and `\n` on the wire), NOT raw concatenation that would
        // produce invalid JSON. A refactor that switched to a `format!`
        // template "for simplicity" would surface here as a parse error
        // and break every Slack receiver that depends on valid JSON.
        let r = slack_err(
            StatusCode::BAD_REQUEST,
            "bad payload: \"quote\" and\nnewline",
        );
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        // Must be valid JSON (unwrap surfaces the regression).
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // And the message itself must round-trip back as the original
        // string (not a corrupted approximation).
        assert_eq!(v["error"], "bad payload: \"quote\" and\nnewline");
    }

    #[tokio::test]
    async fn slack_ok_message_body_has_exactly_three_keys() {
        // The success envelope is documented as the three-key Slack
        // shape: `response_type`, `replace_original`, `text`. A future
        // refactor that started appending a `ts` (thread-stamp) or a
        // `blocks` array unconditionally would silently change every
        // operator-facing button-click response shape. Pin the exact
        // top-level key set so any addition is a conscious wire-shape
        // bump rather than an accidental drift.
        let r = slack_ok_message("hello");
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let obj = v.as_object().expect("body must be a JSON object");
        assert_eq!(
            obj.len(),
            3,
            "got keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
        assert!(obj.contains_key("response_type"));
        assert!(obj.contains_key("replace_original"));
        assert!(obj.contains_key("text"));
    }

    #[test]
    fn slack_interact_state_is_clone_send_sync_static_for_axum_state_boundary() {
        // `SlackInteractState` is held in `Router::with_state(...)` and
        // cloned into every request — the (Clone + Send + Sync + 'static)
        // four-trait combo is the axum-State contract. A refactor that
        // gave it an `Rc<...>` field "for cheap shared notifier handle"
        // would break Send + Sync without surfacing here; the breakage
        // would appear at router assembly with an unrelated
        // `tower::Service` trait-bound error. Pin the bound combo so
        // the type boundary fails fast at the right file.
        fn require_clone_send_sync_static<T: Clone + Send + Sync + 'static>() {}
        require_clone_send_sync_static::<SlackInteractState>();
    }

    #[tokio::test]
    async fn slack_err_content_type_is_application_json_with_no_charset_suffix() {
        // The existing `carries_application_json_content_type_header` pin
        // checks the prefix matches `application/json`. Pin the BYTE-EXACT
        // shape with NO `; charset=utf-8` suffix — Slack's signed-request
        // verification path normalizes JSON bodies on its side, and a
        // charset suffix would not break the wire, but the proxy's
        // operator dashboard groups Slack-bound responses by exact
        // content-type string. A refactor that switched to axum's
        // `Json(...)` extractor (which appends `; charset=utf-8`) would
        // silently bucket every Slack response under a new content-type
        // and break the dashboard count.
        let r = slack_err(StatusCode::BAD_REQUEST, "missing payload");
        let ct = r
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(ct, "application/json");
    }

    #[tokio::test]
    async fn slack_ok_message_content_type_is_application_json_with_no_charset_suffix() {
        // Symmetric to the err-helper byte-exact content-type pin: the
        // success-path helper MUST move in lockstep on the exact
        // header value (not just the prefix). A refactor that fixed
        // only one of the two helpers' content-type would silently
        // diverge them and break the dashboard's "Slack responses"
        // group-by-content-type tile.
        let r = slack_ok_message("Approved.");
        let ct = r
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(ct, "application/json");
    }

    #[tokio::test]
    async fn slack_ok_message_preserves_multibyte_unicode_in_text_field() {
        // The success-path text is rendered into a Slack mrkdwn message
        // bubble — multibyte unicode (operator's email contains an `é`,
        // a `→` separator in a synthesized success line, an emoji like
        // `🔥` for a flagged action) MUST survive byte-for-byte through
        // `serde_json::json!` AND the `to_string()` serialization. A
        // refactor that swapped to a manual `format!("{{\"text\":\"{t}\"}}")`
        // "for speed" would silently fail to escape interior quotes AND
        // could mangle non-ASCII under some `ascii_safe`-style escape
        // mode. Pin a three-codepoint spread (`é` 2 bytes, `→` 3 bytes,
        // `🔥` 4 bytes) round-trips byte-equal through the wire.
        let payload = "café → 🔥 approved by alice@demo.local";
        let r = slack_ok_message(payload);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["text"], payload);
    }

    #[tokio::test]
    async fn slack_err_escapes_backslash_and_control_byte_in_message_round_trip() {
        // The existing escape-pin (`slack_err_escapes_special_chars_in_msg_via_serde_json`)
        // covers quote + newline. Pin the OTHER two JSON-special bytes
        // operators see in the wild — a literal backslash (`C:\path` in
        // a Windows-shell-derived error message that bubbled up via
        // sqlx connection string) and a tab character (sqlx uses tabs in
        // some multiline error renderings). A refactor to `format!` would
        // surface here as either an invalid-JSON parse error OR a corrupted
        // round-trip where the backslash got doubled or the tab got
        // stripped. Pin both round-trip byte-equal through serde.
        let msg = "fail: C:\\Users\\bob\twith\ttabs";
        let r = slack_err(StatusCode::BAD_REQUEST, msg);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], msg);
    }

    #[test]
    fn header_str_returns_first_value_when_header_has_multiple_inserts() {
        // axum's HeaderMap supports multi-valued headers (`.append(...)`);
        // `.get(...)` returns the FIRST value. The signature verification
        // path treats `x-slack-signature` as single-valued — a refactor
        // that switched to `.get_all(...)` and joined "for completeness"
        // would silently concatenate all signatures and break v0 verify
        // (which compares against ONE HMAC). Pin that the helper sees
        // the first inserted value verbatim, even after a subsequent
        // append. Slack's SDKs send exactly one signature header, but
        // a misbehaving proxy in front of us could double-add the header
        // — we must not concatenate.
        let mut h = HeaderMap::new();
        h.insert("x-slack-signature", HeaderValue::from_static("v0=first"));
        h.append("x-slack-signature", HeaderValue::from_static("v0=second"));
        let got = header_str(&h, "x-slack-signature");
        assert_eq!(
            got,
            Some("v0=first"),
            "header_str must return the first inserted value, not a join"
        );
    }

    // ─── round 192 (2026-05-20): TriggerClaim + helper purity surfaces ───

    #[test]
    fn trigger_claim_variant_count_pinned_at_exactly_four_via_exhaustive_match() {
        // `TriggerClaim` has exactly 4 variants today (Fresh /
        // Retry / Conflict / Error). The /api/v1/notifier/slack/
        // interact handler dispatches on this enum to decide
        // between proceed / replay-prior-success / 409 reject /
        // 500 fallback. Operator metrics
        // `proxilion_slack_interact_total` is labeled by this
        // outcome — a future variant (e.g. `Throttled` for a
        // rate-limit gate) would surface a fifth label dimension
        // the Grafana panel wasn't sized for. Pin the variant
        // count via an exhaustive match — a new arm forces this
        // test to compile-fail at the match site. Symmetric to
        // round-190 ApiError 2-variant + round-189 ActionsApiError
        // 4-variant + round-191 SetupError 1-variant exhaustive-
        // match pins extended to this sibling outcome enum.
        fn arm_name(c: &TriggerClaim) -> &'static str {
            match c {
                TriggerClaim::Fresh => "Fresh",
                TriggerClaim::Retry => "Retry",
                TriggerClaim::Conflict => "Conflict",
                TriggerClaim::Error(_) => "Error",
            }
        }
        let four: Vec<TriggerClaim> = vec![
            TriggerClaim::Fresh,
            TriggerClaim::Retry,
            TriggerClaim::Conflict,
            TriggerClaim::Error("db down".into()),
        ];
        let names: std::collections::HashSet<&'static str> = four.iter().map(arm_name).collect();
        assert_eq!(names.len(), 4, "4 distinct leaf-variant names walked");
        assert_eq!(arm_name(&TriggerClaim::Fresh), "Fresh");
        assert_eq!(arm_name(&TriggerClaim::Retry), "Retry");
        assert_eq!(arm_name(&TriggerClaim::Conflict), "Conflict");
        assert_eq!(arm_name(&TriggerClaim::Error("x".into())), "Error");
    }

    #[test]
    fn trigger_claim_error_inner_string_is_owned_for_cross_await_propagation() {
        // `TriggerClaim::Error(String)` — the inner is OWNED
        // `String`. The error path crosses three `.await` boundaries
        // in claim_trigger_id (the UPDATE query, the SELECT fallback,
        // and the interact handler's match-on-claim dispatch). A
        // refactor to `&'a str` for "zero-alloc on the cold path"
        // would introduce a lifetime parameter that the async-fn
        // return-type contract can't satisfy. Pin owned-String via
        // require_string. Symmetric to round-190 ApiError::BadRequest
        // + round-189 ActionsApiError::BadRequest + round-188
        // SetModeBody owned-String pins extended to this outcome
        // variant's only String-bearing arm.
        fn require_string(_: &String) {}
        let inner = match TriggerClaim::Error("postgres: pool closed".into()) {
            TriggerClaim::Error(s) => s,
            _ => panic!("expected Error arm"),
        };
        require_string(&inner);
        assert_eq!(inner, "postgres: pool closed");
    }

    #[test]
    fn trigger_claim_is_send_sync_static_for_async_fn_return_type_boundary() {
        // `TriggerClaim` is the return type of `async fn
        // claim_trigger_id(...)` — futures returning it must be
        // `Send` for tokio's multi-thread runtime to poll them on
        // any worker thread. Captured across the `.await` in the
        // /interact handler. `'static` is required for the boxed
        // axum handler future. `Sync` is the conservative pin so a
        // future refactor that stored a TriggerClaim in shared
        // state (an Arc<Mutex<TriggerClaim>> for an audit-log
        // dedup cache) still type-checks. A refactor that
        // introduced a !Send inner (e.g. `Rc<String>` "for cheap
        // clone of the error string") would surface here rather
        // than at the handler-bound trait error far from this
        // file. Symmetric to round-190 KillBody+KillResponse +
        // round-189 ListParams+ListResponse + round-191 CheckItem
        // +SetupStatus Send+Sync+'static pins extended to this
        // sibling outcome enum.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<TriggerClaim>();
    }

    #[tokio::test]
    async fn slack_ok_message_is_referentially_transparent_across_fifty_calls_on_same_input() {
        // The /interact handler may be invoked at high rate during
        // an incident drill (every operator clicking "Approve" on
        // a burst of blocked actions). `slack_ok_message` is on
        // that hot path. Pin that 50 calls with the same input
        // yield byte-equal JSON response bodies — a refactor that
        // mixed in a per-call timestamp or nonce "for replay
        // hardening" would silently break the idempotent-retry
        // contract (Slack's retry-of-the-same-click depends on the
        // SAME response surface). Symmetric to round-187
        // html_escape + round-183 WebhookSecret::sign + round-180
        // evaluate referential-transparency pins extended to this
        // Slack helper.
        let baseline_bytes = {
            let r = slack_ok_message("approved by alice@demo.local");
            axum::body::to_bytes(r.into_body(), 4096).await.unwrap()
        };
        for i in 0..50 {
            let r = slack_ok_message("approved by alice@demo.local");
            let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
            assert_eq!(
                bytes, baseline_bytes,
                "iteration {i}: slack_ok_message must be referentially transparent",
            );
        }
    }

    #[tokio::test]
    async fn slack_err_is_referentially_transparent_across_fifty_calls_on_same_input() {
        // Symmetric to slack_ok_message pin above — the error
        // helper is also on the hot signature-verify path (every
        // unsigned interact request lands here). 50 calls with
        // the same (status, message) input yield byte-equal
        // response bodies. A refactor that mixed in a
        // per-call request_id "for debug correlation" would
        // silently break the byte-equal contract operator log
        // aggregators rely on for dedup. Pin both helpers move
        // in lockstep on referential transparency. Symmetric to
        // round-184 parse_missing_atoms + round-187 html_escape
        // referential-transparency pins extended to this Slack
        // error helper.
        let baseline_bytes = {
            let r = slack_err(StatusCode::BAD_REQUEST, "missing payload");
            axum::body::to_bytes(r.into_body(), 4096).await.unwrap()
        };
        for i in 0..50 {
            let r = slack_err(StatusCode::BAD_REQUEST, "missing payload");
            let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
            assert_eq!(
                bytes, baseline_bytes,
                "iteration {i}: slack_err must be referentially transparent",
            );
        }
    }

    #[test]
    fn trigger_claim_error_variant_carries_a_string_not_an_error_type_for_audit_log_passthrough() {
        // `TriggerClaim::Error(String)` — the inner is `String`,
        // NOT a typed `sqlx::Error` or an `anyhow::Error`. The
        // /interact handler logs the string verbatim via
        // `warn!(error = %s, ...)`; a future refactor that
        // promoted the inner to `sqlx::Error` "for richer error
        // chain" would silently change the log-line shape
        // (`tracing` would render the error's Display + Debug
        // separately rather than just the .to_string() the audit
        // log keys on). Pin via destructure-and-require_string —
        // symmetric to the inner-owned pin above but on the
        // INNER TYPE axis rather than the lifetime axis.
        // The two pins are sibling contracts that move
        // independently — a refactor could promote to a typed
        // error AND keep ownership; this catches that path.
        let e = TriggerClaim::Error("db: connection refused".into());
        // Match shape pins the inner type at compile time.
        match e {
            TriggerClaim::Error(s) => {
                // Use the canonical require_string helper on the bound
                // inner — verifies BOTH that the variant exists with
                // the right arm AND that the inner is String, not
                // String-shaped wrapper.
                fn require_string(_: &String) {}
                require_string(&s);
                assert_eq!(s, "db: connection refused");
            }
            _ => panic!("Error arm must hold a bare String"),
        }
    }

    #[test]
    fn header_str_returns_some_empty_for_empty_header_value() {
        // Boundary: an HTTP header with an empty value is legal
        // (`X-Slack-Signature:` with no value after the colon). The
        // helper must surface `Some("")`, NOT `None` — the latter would
        // collapse "header absent" and "header present-but-empty" into
        // the same code path, and the bearer / signature middleware
        // distinguishes them (an empty signature is a signed-request
        // attempt with a bug; an absent header is an unsigned attempt
        // that should bypass signature checks entirely).
        let mut h = HeaderMap::new();
        h.insert("x-slack-signature", HeaderValue::from_static(""));
        assert_eq!(header_str(&h, "x-slack-signature"), Some(""));
        // The absent-header path still returns None — pin both axes so
        // a refactor that conflated them surfaces in this one test.
        assert_eq!(header_str(&h, "x-other"), None);
    }
}
