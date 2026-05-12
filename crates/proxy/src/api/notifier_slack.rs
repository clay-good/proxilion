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

use crate::api::blocked::{
    approve_inner, reject_inner, ApproveBody, BlockedApiState, RejectBody,
};
use crate::notifier::{parse_button_value, SlackAction, SlackHandle};

#[derive(Clone)]
pub struct SlackInteractState {
    pub slack: SlackHandle,
    pub blocked: Arc<BlockedApiState>,
    #[allow(dead_code)] // future: write `slack_trigger_id` for replay protection
    pub db: PgPool,
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
    let form: std::collections::HashMap<String, String> =
        match serde_urlencoded::from_bytes(&bytes) {
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
    let approver = payload["user"]["username"]
        .as_str()
        .or_else(|| payload["user"]["id"].as_str())
        .unwrap_or("slack-user");

    let Some((action, blocked_id)) = parse_button_value(value) else {
        return slack_err(StatusCode::BAD_REQUEST, "unrecognized button value");
    };

    let approver_subject = format!("slack:{approver}");
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
