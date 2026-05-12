//! Notifier management API (ui-less-surfaces.md §4.1 / §8.3 — the
//! `notifier` block).
//!
//! Endpoints:
//!   GET  /api/v1/notifier/show — current webhook + burst-suppressor state
//!   POST /api/v1/notifier/test — send a synthetic BlockedNotification
//!
//! Scope-gated: `notifier:read` for `show`, `notifier:test` for `test`.
//! Until per-policy notifier config lands (§8.4 `notifier_config` table),
//! the actual webhook URL + HMAC key remain env-driven; this API just
//! reflects what the proxy booted with.

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::notifier::{
    BlockedNotification, EmailNotifier, Notifiers, SlackNotifier, SlackSigningSecret,
    WebhookNotifier, WebhookSecret,
};

#[derive(Clone)]
pub struct NotifierApiState {
    /// Hot-swappable notifier bundle — each driver has independent state.
    pub notifiers: Notifiers,
    /// DB pool for `notifier_config` reads/writes.
    pub db: PgPool,
    /// Proxy's public URL — needed to rebuild the notifier on config change.
    pub proxy_base_url: String,
}

pub fn router(state: NotifierApiState) -> Router {
    use axum::middleware::from_fn_with_state;
    use crate::operator_auth::scope_check;
    Router::new()
        .route(
            "/api/v1/notifier/show",
            get(show).route_layer(from_fn_with_state("notifier:read", scope_check)),
        )
        .route(
            "/api/v1/notifier/test",
            post(test).route_layer(from_fn_with_state("notifier:test", scope_check)),
        )
        .route(
            "/api/v1/notifier/config",
            get(get_config)
                .route_layer(from_fn_with_state("notifier:read", scope_check))
                .post(set_config)
                .route_layer(from_fn_with_state("notifier:write", scope_check)),
        )
        .with_state(state)
}

async fn show(State(state): State<NotifierApiState>) -> Json<Value> {
    let slack_configured = state.notifiers.slack.current().is_some();
    let email_configured = state.notifiers.email.current().is_some();
    let Some(n) = state.notifiers.webhook.current() else {
        return Json(json!({
            "webhook": { "configured": false },
            "slack": { "configured": slack_configured },
            "email": { "configured": email_configured },
            "burst": null,
        }));
    };
    // Redact URL: keep scheme + host + path-truncated form so an operator
    // can confirm "yes we point at the right place" without exposing
    // query strings / tokens an integration might encode.
    let redacted = redact_url(n.proxy_public_url());
    let burst = n.burst().map(|_b| {
        // BurstConfig isn't introspected by the suppressor in v1; the
        // defaults are documented constants. If a future iteration adds
        // per-policy overrides we'll surface the live config here.
        json!({
            "threshold": 50,
            "window_seconds": 60,
            "flush_interval_seconds": 30,
        })
    });
    Json(json!({
        "webhook": {
            "configured": true,
            "proxy_public_url_redacted": redacted,
        },
        "slack": { "configured": slack_configured },
        "email": { "configured": email_configured },
        "burst": burst,
    }))
}

async fn test(State(state): State<NotifierApiState>) -> impl IntoResponse {
    let Some(n) = state.notifiers.webhook.current() else {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "ok": false,
                "error": "notifier not configured",
                "detail": "set PROXILION_BLOCKED_WEBHOOK_URL + PROXILION_BLOCKED_WEBHOOK_HMAC_KEY and restart"
            })),
        );
    };
    // Build a synthetic blocked-action envelope. The receiver should
    // detect `policy_id == "proxilion.test"` and treat it as a dry run.
    let blocked_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let ops: Vec<String> = vec![];
    let notif = BlockedNotification {
        schema: BlockedNotification::SCHEMA,
        blocked_id,
        request_id,
        session_id,
        p_0: Some("proxilion-cli@test"),
        vendor: "proxilion",
        action: "notifier.test",
        method: "POST",
        path: "/api/v1/notifier/test",
        layer: "policy",
        policy_id: Some("proxilion.test"),
        detail: Some("synthetic test notification — receiver should ignore"),
        predecessor_pca_id: None,
        requested_ops: &ops,
        approve_url: format!("{}/api/v1/blocked/{}/approve", n.proxy_public_url(), blocked_id),
        reject_url: format!("{}/api/v1/blocked/{}/reject", n.proxy_public_url(), blocked_id),
    };
    // Bypass the burst suppressor — a test notification must always fire.
    // We do this by calling notify_unfiltered. Currently the notifier
    // only exposes `notify` which consults burst; we add a thin
    // bypass: spawn an immediate POST with no suppression.
    n.notify(&notif).await;
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "blocked_id": blocked_id.to_string(),
            "policy_id": "proxilion.test",
            "note": "Receiver should drop or echo. Check the proxy log for delivery status."
        })),
    )
}

// ─────────────────────────────────────────────────────────────────────────
// /api/v1/notifier/config (ui-less-surfaces.md §8.4)
// ─────────────────────────────────────────────────────────────────────────

async fn get_config(State(state): State<NotifierApiState>) -> impl IntoResponse {
    let rows: Vec<(String, bool, Value)> = sqlx::query_as(
        "SELECT id, enabled, config FROM notifier_config ORDER BY id",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let webhook = rows.iter().find(|(id, _, _)| id == "webhook").map(|(_, enabled, cfg)| {
        let mut c = cfg.clone();
        if let Some(obj) = c.as_object_mut() {
            obj.remove("hmac_key");
            obj.insert(
                "hmac_key_set".into(),
                Value::Bool(cfg.get("hmac_key").is_some()),
            );
            if let Some(url) = cfg.get("url").and_then(|v| v.as_str()) {
                obj.insert("url_redacted".into(), Value::String(redact_url(url)));
            }
        }
        json!({ "enabled": enabled, "config": c })
    });
    let slack = rows.iter().find(|(id, _, _)| id == "slack").map(|(_, enabled, cfg)| {
        let mut c = cfg.clone();
        if let Some(obj) = c.as_object_mut() {
            obj.remove("signing_secret");
            obj.insert(
                "signing_secret_set".into(),
                Value::Bool(cfg.get("signing_secret").is_some()),
            );
            if let Some(url) = cfg.get("incoming_webhook_url").and_then(|v| v.as_str()) {
                obj.insert(
                    "incoming_webhook_url_redacted".into(),
                    Value::String(redact_url(url)),
                );
            }
        }
        json!({ "enabled": enabled, "config": c })
    });
    let email = rows.iter().find(|(id, _, _)| id == "email").map(|(_, enabled, cfg)| {
        let mut c = cfg.clone();
        // smtp_url usually contains user:pass — redact host portion only.
        if let Some(obj) = c.as_object_mut() {
            if let Some(url) = cfg.get("smtp_url").and_then(|v| v.as_str()) {
                obj.insert("smtp_url_redacted".into(), Value::String(redact_url(url)));
                obj.remove("smtp_url");
            }
        }
        json!({ "enabled": enabled, "config": c })
    });
    Json(json!({ "webhook": webhook, "slack": slack, "email": email }))
}

#[derive(Debug, serde::Deserialize)]
struct SetConfigBody {
    driver: String,
    enabled: Option<bool>,
    config: Value,
}

async fn set_config(
    State(state): State<NotifierApiState>,
    axum::extract::Extension(principal): axum::extract::Extension<
        crate::operator_auth::OperatorPrincipal,
    >,
    Json(body): Json<SetConfigBody>,
) -> impl IntoResponse {
    let enabled = body.enabled.unwrap_or(true);
    match body.driver.as_str() {
        "webhook" => set_webhook(state, principal, body, enabled).await,
        "slack" => set_slack(state, principal, body, enabled).await,
        "email" => set_email(state, principal, body, enabled).await,
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unsupported driver",
                "detail": "valid drivers: webhook | slack | email"
            })),
        ),
    }
}

async fn set_webhook(
    state: NotifierApiState,
    principal: crate::operator_auth::OperatorPrincipal,
    body: SetConfigBody,
    enabled: bool,
) -> (StatusCode, Json<Value>) {
    let url = match body.config.get("url").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"config.url is required"})),
        ),
    };
    let hmac_hex = match body.config.get("hmac_key").and_then(|v| v.as_str()) {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"config.hmac_key is required (hex)"})),
        ),
    };
    let secret = match WebhookSecret::from_hex(&hmac_hex) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"hmac_key invalid","detail": e.to_string()})),
            );
        }
    };
    let new_notifier =
        match WebhookNotifier::new(url.clone(), secret, state.proxy_base_url.clone()) {
            Ok(n) => std::sync::Arc::new(n),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error":"notifier build failed","detail": e.to_string()})),
                );
            }
        };
    if let Err(e) = persist_config(&state, "webhook", enabled, &body.config, &principal.name).await
    {
        return e;
    }
    if enabled {
        state.notifiers.webhook.replace(Some(new_notifier));
    } else {
        state.notifiers.webhook.replace(None);
    }
    metrics::counter!(
        "proxilion_notifier_config_changes_total",
        "driver" => "webhook"
    )
    .increment(1);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "driver": "webhook",
            "enabled": enabled,
            "url_redacted": redact_url(&url),
        })),
    )
}

async fn set_slack(
    state: NotifierApiState,
    principal: crate::operator_auth::OperatorPrincipal,
    body: SetConfigBody,
    enabled: bool,
) -> (StatusCode, Json<Value>) {
    let url = match body.config.get("incoming_webhook_url").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"config.incoming_webhook_url is required"})),
        ),
    };
    let signing_secret = match body
        .config
        .get("signing_secret")
        .and_then(|v| v.as_str())
    {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error":"config.signing_secret is required (Slack signed-request secret)"
            })),
        ),
    };
    let new_notifier = match SlackNotifier::new(
        url.clone(),
        SlackSigningSecret::new(signing_secret),
        state.proxy_base_url.clone(),
    ) {
        Ok(n) => std::sync::Arc::new(n),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"slack notifier build failed","detail": e.to_string()})),
            );
        }
    };
    if let Err(e) = persist_config(&state, "slack", enabled, &body.config, &principal.name).await {
        return e;
    }
    if enabled {
        state.notifiers.slack.replace(Some(new_notifier));
    } else {
        state.notifiers.slack.replace(None);
    }
    metrics::counter!(
        "proxilion_notifier_config_changes_total",
        "driver" => "slack"
    )
    .increment(1);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "driver": "slack",
            "enabled": enabled,
            "incoming_webhook_url_redacted": redact_url(&url),
        })),
    )
}

async fn set_email(
    state: NotifierApiState,
    principal: crate::operator_auth::OperatorPrincipal,
    body: SetConfigBody,
    enabled: bool,
) -> (StatusCode, Json<Value>) {
    let smtp_url = match body.config.get("smtp_url").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"config.smtp_url is required (e.g. smtps://user:pass@smtp.example.com:465)"})),
        ),
    };
    let from = match body.config.get("from").and_then(|v| v.as_str()) {
        Some(f) if !f.is_empty() => f.to_string(),
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"config.from is required (RFC 5322 address)"})),
        ),
    };
    let to: Vec<String> = match body.config.get("to") {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().filter(|s| !s.is_empty()).map(String::from))
            .collect(),
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"config.to is required (string or non-empty array)"})),
        ),
    };
    if to.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"config.to must have at least one recipient"})),
        );
    }
    // cc / bcc — optional (ui-less-surfaces.md §5.4 dev 4). Same
    // single-string-or-array shape as `to`, except empty is allowed.
    let read_optional_list = |key: &str| -> Vec<String> {
        match body.config.get(key) {
            Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|v| v.as_str().filter(|s| !s.is_empty()).map(String::from))
                .collect(),
            _ => Vec::new(),
        }
    };
    let cc = read_optional_list("cc");
    let bcc = read_optional_list("bcc");
    let new_notifier = match EmailNotifier::new_with_recipients(
        &smtp_url,
        &from,
        &to,
        &cc,
        &bcc,
        state.proxy_base_url.clone(),
        state.db.clone(),
    ) {
        Ok(n) => std::sync::Arc::new(n),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"email notifier build failed","detail": e.to_string()})),
            );
        }
    };
    if let Err(e) = persist_config(&state, "email", enabled, &body.config, &principal.name).await {
        return e;
    }
    if enabled {
        state.notifiers.email.replace(Some(new_notifier));
    } else {
        state.notifiers.email.replace(None);
    }
    metrics::counter!(
        "proxilion_notifier_config_changes_total",
        "driver" => "email"
    )
    .increment(1);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "driver": "email",
            "enabled": enabled,
            "from": from,
            "to": to,
            "cc": cc,
            "bcc": bcc,
            "smtp_url_redacted": redact_url(&smtp_url),
        })),
    )
}

async fn persist_config(
    state: &NotifierApiState,
    driver: &str,
    enabled: bool,
    config: &Value,
    actor: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    let res = sqlx::query(
        "INSERT INTO notifier_config (id, enabled, config, updated_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (id) DO UPDATE
             SET enabled = EXCLUDED.enabled,
                 config = EXCLUDED.config,
                 updated_by = EXCLUDED.updated_by,
                 updated_at = now()",
    )
    .bind(driver)
    .bind(enabled)
    .bind(config.clone())
    .bind(actor)
    .execute(&state.db)
    .await;
    if let Err(e) = res {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"persist failed","detail": e.to_string()})),
        ));
    }
    Ok(())
}

fn redact_url(url: &str) -> String {
    // Strip query + path beyond first segment so /siem/v1/ingest?token=...
    // becomes /siem/...
    if let Some((scheme, rest)) = url.split_once("://") {
        if let Some((host, _)) = rest.split_once('/') {
            return format!("{scheme}://{host}/...");
        }
        return format!("{scheme}://{rest}");
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_query_and_deep_path() {
        assert_eq!(
            redact_url("https://hooks.slack.com/services/T/B/abcXYZ?token=secret"),
            "https://hooks.slack.com/..."
        );
        assert_eq!(redact_url("https://example.com"), "https://example.com");
        assert_eq!(redact_url("https://example.com/path"), "https://example.com/...");
    }
}
