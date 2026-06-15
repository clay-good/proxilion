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
    use crate::operator_auth::scope_check;
    use axum::middleware::from_fn_with_state;
    Router::new()
        .route(
            "/api/v1/notifier/show",
            get(show).route_layer(from_fn_with_state("notifier:read", scope_check)),
        )
        .route(
            "/api/v1/notifier/test",
            post(test).route_layer(from_fn_with_state("notifier:test", scope_check)),
        )
        // Each method gets its OWN `.route()` call so its scope layer wraps only
        // that method. Chaining `get(..).route_layer(read).post(..).route_layer(write)`
        // on a single MethodRouter applies the *second* `route_layer` over the
        // whole router (axum semantics), double-gating GET behind `notifier:write`
        // and defeating least-privilege `notifier:read` access. axum merges the two
        // same-path MethodRouters since the methods don't overlap.
        .route(
            "/api/v1/notifier/config",
            get(get_config).route_layer(from_fn_with_state("notifier:read", scope_check)),
        )
        .route(
            "/api/v1/notifier/config",
            post(set_config).route_layer(from_fn_with_state("notifier:write", scope_check)),
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

/// `POST /api/v1/notifier/test` — fire a synthetic notification.
///
/// Body (all fields optional):
/// ```json
/// { "driver": "all" | "webhook" | "slack" | "email" }
/// ```
///
/// Default driver is `"all"` (fan out to every configured driver,
/// matching the §4.1 sketch). Specifying a single driver returns 412
/// when that driver isn't configured so the operator gets a fast,
/// targeted failure instead of a "tested-something" yes-answer.
async fn test(
    State(state): State<NotifierApiState>,
    body: Option<Json<TestRequest>>,
) -> impl IntoResponse {
    let driver = body
        .as_ref()
        .and_then(|b| b.driver.clone())
        .unwrap_or_else(|| "all".to_string());

    // Pick a `proxy_public_url` to mint the synthetic approve/reject
    // links against. Any configured driver knows its public URL; we
    // prefer webhook → slack → email so the URL is deterministic when
    // multiple drivers are live. Falls back to a placeholder when
    // nothing is configured (the per-driver dispatch below will 412
    // before we ever serialize a notification with this).
    let proxy_url = state
        .notifiers
        .webhook
        .current()
        .map(|n| n.proxy_public_url().to_string())
        .or_else(|| {
            state
                .notifiers
                .slack
                .current()
                .map(|n| n.proxy_public_url().to_string())
        })
        .or_else(|| {
            state
                .notifiers
                .email
                .current()
                .map(|n| n.proxy_public_url().to_string())
        })
        .unwrap_or_else(|| "http://proxilion.local".to_string());

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
        approve_url: format!("{}/api/v1/blocked/{}/approve", proxy_url, blocked_id),
        reject_url: format!("{}/api/v1/blocked/{}/reject", proxy_url, blocked_id),
    };

    let mut fired = Vec::<&'static str>::new();
    let mut not_configured = Vec::<&'static str>::new();

    let want_webhook = matches!(driver.as_str(), "all" | "webhook");
    let want_slack = matches!(driver.as_str(), "all" | "slack");
    let want_email = matches!(driver.as_str(), "all" | "email");

    if !want_webhook && !want_slack && !want_email {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "unsupported driver",
                "detail": "valid drivers: all | webhook | slack | email"
            })),
        );
    }

    if want_webhook {
        match state.notifiers.webhook.current() {
            Some(n) => {
                n.notify(&notif).await;
                fired.push("webhook");
            }
            None => not_configured.push("webhook"),
        }
    }
    if want_slack {
        match state.notifiers.slack.current() {
            Some(n) => {
                n.notify(&notif).await;
                fired.push("slack");
            }
            None => not_configured.push("slack"),
        }
    }
    if want_email {
        match state.notifiers.email.current() {
            Some(n) => {
                n.notify(&notif).await;
                fired.push("email");
            }
            None => not_configured.push("email"),
        }
    }

    // Targeted single-driver request against an unconfigured driver:
    // hard 412 so the operator's setup script fails noisily.
    if driver != "all" && fired.is_empty() {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "ok": false,
                "error": "driver not configured",
                "detail": format!("driver `{driver}` has no active configuration — set it via POST /api/v1/notifier/config"),
                "driver": driver,
            })),
        );
    }
    // Fan-out request with zero configured drivers: same 412 but a
    // catalogue answer.
    if fired.is_empty() {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "ok": false,
                "error": "no notifier driver configured",
                "detail": "configure at least one driver via POST /api/v1/notifier/config (webhook | slack | email)",
            })),
        );
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "blocked_id": blocked_id.to_string(),
            "policy_id": "proxilion.test",
            "fired": fired,
            "not_configured": not_configured,
            "note": "Receiver should drop or echo. Check the proxy log for delivery status."
        })),
    )
}

#[derive(serde::Deserialize, Debug)]
struct TestRequest {
    driver: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────
// /api/v1/notifier/config (ui-less-surfaces.md §8.4)
// ─────────────────────────────────────────────────────────────────────────

/// Strip secret-bearing fields from a stored notifier `config` JSON before it's
/// returned by `GET /api/v1/notifier/config`.
///
/// - Each `secret_field` (opaque token / signing key) is removed and replaced
///   with a `<field>_set` boolean so an operator can confirm "a value is set"
///   without seeing it.
/// - Each `url_field` is removed and replaced with a host-only `<field>_redacted`
///   form. **SECURITY:** a webhook / Slack incoming-webhook URL is *itself* a
///   bearer credential (possession ⇒ ability to post / replay a `?token=`), so
///   the cleartext MUST NOT survive into the response handed to a `notifier:read`
///   operator. This single helper (rather than three hand-rolled branches) is the
///   fix for the divergence that left `url` / `incoming_webhook_url` leaking while
///   only `smtp_url` was stripped.
///
/// Fields that are neither secret nor URL (e.g. Slack `user_map` — non-secret
/// id↔email mappings already visible in the audit trail) pass through unchanged.
fn redact_notifier_config(cfg: &Value, secret_fields: &[&str], url_fields: &[&str]) -> Value {
    let mut c = cfg.clone();
    if let Some(obj) = c.as_object_mut() {
        for f in secret_fields {
            let present = obj.remove(*f).is_some();
            obj.insert(format!("{f}_set"), Value::Bool(present));
        }
        for f in url_fields {
            if let Some(url) = cfg.get(*f).and_then(|v| v.as_str()) {
                obj.insert(format!("{f}_redacted"), Value::String(redact_url(url)));
                obj.remove(*f);
            }
        }
    }
    c
}

async fn get_config(State(state): State<NotifierApiState>) -> impl IntoResponse {
    let rows: Vec<(String, bool, Value)> =
        sqlx::query_as("SELECT id, enabled, config FROM notifier_config ORDER BY id")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
    let redact = |id: &str, secret_fields: &[&str], url_fields: &[&str]| {
        rows.iter().find(|(rid, _, _)| rid == id).map(|(_, enabled, cfg)| {
            json!({ "enabled": enabled, "config": redact_notifier_config(cfg, secret_fields, url_fields) })
        })
    };
    let webhook = redact("webhook", &["hmac_key"], &["url"]);
    let slack = redact("slack", &["signing_secret"], &["incoming_webhook_url"]);
    let email = redact("email", &[], &["smtp_url"]);
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
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"config.url is required"})),
            );
        }
    };
    let hmac_hex = match body.config.get("hmac_key").and_then(|v| v.as_str()) {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"config.hmac_key is required (hex)"})),
            );
        }
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
    // ui-less-surfaces.md §10.3 dev 2 — re-attach the boot-time burst
    // suppressor so the hot-swapped notifier keeps the suppression
    // history. Cloning the suppressor shares the inner `buckets` Arc;
    // counts and exemplars survive the swap.
    let new_notifier = match WebhookNotifier::new(url.clone(), secret, state.proxy_base_url.clone())
    {
        Ok(mut n) => {
            if let Some(b) = state.notifiers.webhook_burst.clone() {
                n = n.with_burst(b);
            }
            std::sync::Arc::new(n)
        }
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
    let url = match body
        .config
        .get("incoming_webhook_url")
        .and_then(|v| v.as_str())
    {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"config.incoming_webhook_url is required"})),
            );
        }
    };
    let signing_secret = match body.config.get("signing_secret").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error":"config.signing_secret is required (Slack signed-request secret)"
                })),
            );
        }
    };
    // Optional `user_map: { "U01ABC": "alice@acme.com", "bob": "bob@acme.com" }`
    // — ui-less-surfaces.md §5.3 dev 4. Slack user id OR username → operator subject.
    let user_map = match body.config.get("user_map") {
        Some(Value::Object(m)) => {
            let mut out = std::collections::HashMap::with_capacity(m.len());
            for (k, v) in m {
                let Some(s) = v.as_str() else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error":"user_map values must be strings",
                            "key": k
                        })),
                    );
                };
                if !s.is_empty() {
                    out.insert(k.clone(), s.to_string());
                }
            }
            out
        }
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"error":"user_map must be an object of slack_user_id_or_username → operator_subject"}),
                ),
            );
        }
        None => std::collections::HashMap::new(),
    };
    let new_notifier = match SlackNotifier::new(
        url.clone(),
        SlackSigningSecret::new(signing_secret),
        state.proxy_base_url.clone(),
    ) {
        Ok(mut n) => {
            n = n.with_user_map(user_map.clone());
            // ui-less-surfaces.md §10.3 dev 2 — re-attach boot-time suppressor.
            if let Some(b) = state.notifiers.slack_burst.clone() {
                n = n.with_burst(b);
            }
            std::sync::Arc::new(n)
        }
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
            "user_map_entries": user_map.len(),
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
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"error":"config.smtp_url is required (e.g. smtps://user:pass@smtp.example.com:465)"}),
                ),
            );
        }
    };
    let from = match body.config.get("from").and_then(|v| v.as_str()) {
        Some(f) if !f.is_empty() => f.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"config.from is required (RFC 5322 address)"})),
            );
        }
    };
    let to: Vec<String> = match body.config.get("to") {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().filter(|s| !s.is_empty()).map(String::from))
            .collect(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"config.to is required (string or non-empty array)"})),
            );
        }
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
    // Two secrets can hide in a notifier URL: (1) a token in the query/deep
    // path (`/siem/v1/ingest?token=…`), and (2) `user:pass@` userinfo in the
    // authority — the SMTP `smtps://user:pass@host:465` shape (spec
    // ui-less-surfaces.md §5.5: redact to `scheme://host/...`). Strip BOTH:
    // truncate to the first path segment AND drop any userinfo so a
    // `notifier:read` operator never sees the SMTP password in
    // `smtp_url_redacted`.
    fn host_only(authority: &str) -> &str {
        // Userinfo is everything before the LAST `@` in the authority.
        authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host)
    }
    if let Some((scheme, rest)) = url.split_once("://") {
        if let Some((authority, _)) = rest.split_once('/') {
            return format!("{scheme}://{}/...", host_only(authority));
        }
        return format!("{scheme}://{}", host_only(rest));
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
        assert_eq!(
            redact_url("https://example.com/path"),
            "https://example.com/..."
        );
    }

    /// Driver-string parsing: `all` fans out, a single name targets,
    /// anything else is a 400 from the API layer (we exercise the
    /// classification here without needing a live DB / notifier).
    #[test]
    fn test_request_driver_classification() {
        let parse = |s: &str| {
            (
                matches!(s, "all" | "webhook"),
                matches!(s, "all" | "slack"),
                matches!(s, "all" | "email"),
            )
        };
        assert_eq!(parse("all"), (true, true, true));
        assert_eq!(parse("webhook"), (true, false, false));
        assert_eq!(parse("slack"), (false, true, false));
        assert_eq!(parse("email"), (false, false, true));
        assert_eq!(parse("bogus"), (false, false, false));
    }

    /// `TestRequest` accepts a missing body (default `all`) and an
    /// explicit `{ "driver": "slack" }` shape.
    #[test]
    fn test_request_deserializes_optional_driver() {
        let req: TestRequest = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(req.driver, None);
        let req: TestRequest = serde_json::from_str(r#"{"driver":"slack"}"#).unwrap();
        assert_eq!(req.driver.as_deref(), Some("slack"));
    }

    #[test]
    fn redact_url_preserves_scheme_only_uri() {
        // No `://` separator — return as-is. Defensive: callers should
        // pass a real URL, but the helper shouldn't panic on garbage.
        assert_eq!(redact_url("just-a-token"), "just-a-token");
    }

    #[test]
    fn redact_notifier_config_strips_url_borne_secrets_for_every_driver() {
        // Regression for the secret-leak: webhook `url` and slack
        // `incoming_webhook_url` are bearer credentials and MUST NOT survive
        // into the GET response — only the redacted twin may. Mirrors the
        // already-correct email `smtp_url` handling.
        let webhook = redact_notifier_config(
            &json!({"url": "https://hooks.example.com/x?token=SECRET", "hmac_key": "deadbeef"}),
            &["hmac_key"],
            &["url"],
        );
        assert!(webhook.get("url").is_none(), "cleartext webhook url leaked");
        assert!(webhook.get("hmac_key").is_none(), "hmac_key leaked");
        assert_eq!(webhook["hmac_key_set"], json!(true));
        assert_eq!(
            webhook["url_redacted"],
            json!("https://hooks.example.com/...")
        );
        assert!(
            !webhook.to_string().contains("SECRET"),
            "the secret token must not appear anywhere in the output"
        );

        let slack = redact_notifier_config(
            &json!({"incoming_webhook_url": "https://hooks.slack.com/services/T/B/SECRET", "user_map": {"U1": "a@b.c"}}),
            &["signing_secret"],
            &["incoming_webhook_url"],
        );
        assert!(
            slack.get("incoming_webhook_url").is_none(),
            "cleartext slack url leaked"
        );
        assert_eq!(slack["signing_secret_set"], json!(false));
        // Non-secret fields (user_map) pass through untouched.
        assert_eq!(slack["user_map"], json!({"U1": "a@b.c"}));
        assert!(!slack.to_string().contains("SECRET"));

        let email = redact_notifier_config(
            &json!({"smtp_url": "smtps://user:pass@mail.example.com:465"}),
            &[],
            &["smtp_url"],
        );
        assert!(email.get("smtp_url").is_none());
        assert!(!email.to_string().contains("pass"));
    }

    #[test]
    fn set_config_body_round_trips() {
        let raw = r#"{"driver":"webhook","enabled":true,"config":{"url":"https://x"}}"#;
        let b: SetConfigBody = serde_json::from_str(raw).unwrap();
        assert_eq!(b.driver, "webhook");
        assert_eq!(b.enabled, Some(true));
        assert_eq!(b.config["url"], "https://x");
    }

    #[test]
    fn set_config_body_enabled_defaults_via_unwrap_or_true() {
        // The handler unwraps `enabled.unwrap_or(true)`, but the field
        // itself is `Option<bool>` and must accept absent.
        let b: SetConfigBody = serde_json::from_str(r#"{"driver":"slack","config":{}}"#).unwrap();
        assert!(b.enabled.is_none());
    }

    #[test]
    fn redact_url_no_path_keeps_full_host() {
        // The host+scheme form (no path segment after the host) must NOT
        // gain a trailing `/...` — the redacted shape should look like
        // the original. A regression that always appended `/...` would
        // mis-display "the URL is bare" in the dashboard's notifier list.
        assert_eq!(redact_url("https://hooks.example"), "https://hooks.example",);
        // With a custom port — still no `/`, still pass-through.
        assert_eq!(redact_url("http://localhost:9100"), "http://localhost:9100",);
    }

    #[test]
    fn redact_url_keeps_scheme_when_host_has_trailing_slash_only() {
        // `https://host/` → first path segment is empty, so the redacted
        // form is `https://host/...`. Pin this so a future fast-path
        // that returned the bare host wouldn't accidentally surface a
        // path-containing URL as path-less.
        assert_eq!(
            redact_url("https://example.com/"),
            "https://example.com/...",
        );
    }

    #[test]
    fn set_config_body_rejects_missing_driver_field() {
        // `driver` is non-Option — required by the operator contract.
        // The dashboard validates first, but a hand-rolled curl that
        // forgets the field must surface as a 400, not as a silent
        // routing into the `_` arm (which would emit a less specific
        // error). Pin that deserialization fails for the missing case.
        let res: Result<SetConfigBody, _> = serde_json::from_str(r#"{"config":{}}"#);
        assert!(res.is_err(), "missing driver must fail to deserialize");
    }

    #[test]
    fn set_config_body_rejects_missing_config_field() {
        // Symmetric to driver — `config` is the per-driver payload and
        // the handlers index into it; absence here would surface as a
        // confusing serde error inside the driver branch. Pin the early
        // failure at the envelope layer.
        let res: Result<SetConfigBody, _> = serde_json::from_str(r#"{"driver":"webhook"}"#);
        assert!(res.is_err(), "missing config must fail to deserialize");
    }

    #[test]
    fn redact_url_strips_userinfo_credentials() {
        // `scheme://user:pass@host` carries a secret in the authority — the
        // SMTP `smtps://user:pass@host:465` shape. The helper must drop the
        // userinfo so `smtp_url_redacted` never leaks the password to a
        // `notifier:read` operator (spec ui-less-surfaces.md §5.5).
        assert_eq!(
            redact_url("https://user:pass@host.example/path/to/thing"),
            "https://host.example/...",
        );
        // SMTP, with a port, no deep path.
        assert_eq!(
            redact_url("smtps://relay-user:s3cret@smtp.example.com:465"),
            "smtps://smtp.example.com:465",
        );
        // SMTP submission path — port preserved, path truncated, creds gone.
        assert_eq!(
            redact_url("smtps://relay-user:s3cret@smtp.example.com:587/submit"),
            "smtps://smtp.example.com:587/...",
        );
        // No userinfo present → host[:port] untouched (the @-split is a no-op).
        assert_eq!(
            redact_url("https://host.example/x"),
            "https://host.example/..."
        );
    }

    #[test]
    fn redact_url_keeps_ftp_and_unusual_schemes_intact() {
        // The helper is scheme-agnostic — it splits on `://` and
        // preserves whatever came before. Pin a non-https scheme so
        // a refactor that hardcoded `https`/`http` recognition would
        // surface here (operators sometimes configure file:// for
        // testing, or a future v2 mqtt:// driver).
        assert_eq!(
            redact_url("ftp://files.example/x/y"),
            "ftp://files.example/..."
        );
        assert_eq!(
            redact_url("mqtt://broker.local/topic"),
            "mqtt://broker.local/..."
        );
    }

    #[test]
    fn test_request_defaults_via_default_impl_on_optional_driver() {
        // Empty object → `driver: None`. The handler then `unwrap_or(\"all\")`s.
        // Pin both halves so a serde refactor that swapped to a required
        // field (or to a non-Option default) would surface here as a
        // wire-shape change rather than as a 400-on-empty-body.
        let req: TestRequest = serde_json::from_str("{}").unwrap();
        assert!(req.driver.is_none());
        // Forward-compat — extra fields ignored.
        let req: TestRequest =
            serde_json::from_str(r#"{"driver":"all","future":"value"}"#).unwrap();
        assert_eq!(req.driver.as_deref(), Some("all"));
    }

    #[test]
    fn redact_url_empty_string_returns_empty_without_panic() {
        // Boundary: an operator-cli call that passes a missing notifier
        // URL (the `Option::unwrap_or_default()` shape on a non-required
        // field) lands here as `""`. The helper must surface `""` rather
        // than panic on `split_once`, since the show / setup-status
        // endpoints render every configured driver's URL through
        // redact_url before logging — a panic on one notifier's empty
        // URL would crash the entire setup-status response.
        assert_eq!(redact_url(""), "");
    }

    #[test]
    fn redact_url_preserves_host_port_in_authority_segment() {
        // The authority segment (host[:port]) is everything between
        // `://` and the first `/`. A `:port` suffix is part of the
        // authority and must survive — a regression that split on `:`
        // (to strip "credentials" from a userinfo-shaped authority)
        // would silently drop the port and break the operator's
        // ability to distinguish `siem.local:8080/...` from a different
        // service on `siem.local:9090/...` in the redacted log line.
        assert_eq!(
            redact_url("https://siem.local:8080/ingest?token=secret"),
            "https://siem.local:8080/..."
        );
        // The no-path-with-port case must also survive (mirrors the
        // no-path-no-port `redact_url_no_path_keeps_full_host` test).
        assert_eq!(
            redact_url("https://siem.local:8080"),
            "https://siem.local:8080"
        );
    }

    #[test]
    fn set_config_body_accepts_extra_unknown_fields_for_forward_compat() {
        // Symmetric to `test_request_defaults_via_default_impl_on_optional_driver`'s
        // forward-compat pin: SetConfigBody must accept (and ignore)
        // unknown fields so the operator CLI can add forward-compat
        // shaped fields (e.g. a future `tags: [...]` field) without
        // breaking older proxies. A regression that added
        // `#[serde(deny_unknown_fields)]` to SetConfigBody would
        // force every CLI shape change to be a coordinated proxy
        // upgrade — surfacing here as a parse error.
        let raw = r#"{"driver":"webhook","enabled":true,"config":{"url":"https://x"},"future_field":"ignored"}"#;
        let b: SetConfigBody = serde_json::from_str(raw).unwrap();
        assert_eq!(b.driver, "webhook");
        assert_eq!(b.enabled, Some(true));
        assert_eq!(b.config["url"], "https://x");
    }

    #[test]
    fn set_config_body_with_slack_driver_round_trips_distinct_from_webhook() {
        // The existing round-trip test pins the `driver: "webhook"`
        // shape. Pin the `driver: "slack"` shape directly so a refactor
        // that hardcoded the deserializer to expect a webhook-style
        // `url` field inside `config` (rather than slack's
        // `bot_token` + `signing_secret`) would surface here. The
        // SetConfigBody is driver-agnostic at the envelope layer —
        // each driver's per-driver handler validates its own `config`
        // payload.
        let raw = r#"{"driver":"slack","enabled":false,"config":{"bot_token":"xoxb-AAA","signing_secret":"abc"}}"#;
        let b: SetConfigBody = serde_json::from_str(raw).unwrap();
        assert_eq!(b.driver, "slack");
        assert_eq!(b.enabled, Some(false));
        assert_eq!(b.config["bot_token"], "xoxb-AAA");
        assert_eq!(b.config["signing_secret"], "abc");
    }

    #[test]
    fn set_config_body_accepts_explicit_enabled_false() {
        // The disable path — `enabled: false` is how operators turn a
        // configured-but-paused driver off. Pin that the field round-trips
        // as `Some(false)` (not coerced to None or unwrapped to true).
        let raw = r#"{"driver":"webhook","enabled":false,"config":{}}"#;
        let b: SetConfigBody = serde_json::from_str(raw).unwrap();
        assert_eq!(b.enabled, Some(false));
    }

    #[test]
    fn notifier_api_state_is_send_sync_static_for_axum_state_boundary() {
        // `NotifierApiState` is wired into the axum Router via
        // `with_state(state)` — axum's `State<NotifierApiState>` extractor
        // requires `Send + Sync + 'static`. A refactor that gave any
        // field an `Rc<...>` (e.g. wrapping `proxy_base_url` in
        // `Rc<String>` "for cheap clone of the boot-immutable URL")
        // would break Sync and surface at the router assembly site with
        // a far-removed `tower::Service` trait-bound error. Pin the
        // three-trait combo here so the failure surfaces at the right
        // module. Symmetric to the
        // `api_error_and_killswitch_state_are_send_sync_static_for_axum_state_boundary`
        // and `actions_api_state_and_actions_api_error_send_sync_static_for_axum_state_boundary`
        // pins on sibling api/* modules.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<NotifierApiState>();
    }

    #[test]
    fn test_request_and_set_config_body_debug_carries_struct_names_for_grep_bucketing() {
        // Both `TestRequest` and `SetConfigBody` carry `#[derive(Debug)]`
        // which feeds `?req` / `?body` in handler-level tracing fields.
        // Operators grep the log line by struct name to bucket the
        // notifier-config edit path vs. the notifier-test fire path.
        // A hand-rolled `impl Debug` that hid the struct name "to
        // compact the line" would break every operator bucket.
        // Symmetric to the
        // `key_error_and_build_error_debug_carries_struct_name_for_grep`
        // and `actions_api_error_debug_carries_variant_names_for_grep_bucketing`
        // pins on sibling modules.
        let req = TestRequest {
            driver: Some("webhook".into()),
        };
        let req_dbg = format!("{req:?}");
        assert!(
            req_dbg.contains("TestRequest"),
            "missing TestRequest in Debug: {req_dbg}",
        );
        assert!(
            req_dbg.contains("driver"),
            "missing driver field in Debug: {req_dbg}",
        );
        let body = SetConfigBody {
            driver: "webhook".into(),
            enabled: Some(true),
            config: serde_json::json!({}),
        };
        let body_dbg = format!("{body:?}");
        assert!(
            body_dbg.contains("SetConfigBody"),
            "missing SetConfigBody in Debug: {body_dbg}",
        );
        for field in ["driver", "enabled", "config"] {
            assert!(
                body_dbg.contains(field),
                "missing {field} in SetConfigBody Debug: {body_dbg}",
            );
        }
    }

    #[test]
    fn redact_url_path_truncation_marker_is_byte_exact_three_char_dot_dot_dot_suffix() {
        // The `/...` path-truncation marker is the operator-facing
        // signal "this URL had a path that we hid". Receiver-side
        // dashboards split on the exact `/...` suffix to render the
        // "redacted" badge. A refactor to `/<hidden>` or `/***` or
        // `/(path-redacted)` would silently break every dashboard
        // filter. The existing tests pin the round-trip shape; pin
        // the byte-exact suffix here so a one-byte drift surfaces.
        let s = redact_url("https://hooks.example/services/T/B/C");
        assert!(
            s.ends_with("/..."),
            "must end with byte-exact `/...` suffix, got: {s}",
        );
        // The suffix is exactly 4 bytes — slash + three dots. A
        // refactor to a 2-dot ellipsis (`/..`) or a Unicode horizontal
        // ellipsis (`/…` = `/\u{2026}` = 4 bytes but different chars)
        // would surface here.
        let suffix = &s.as_bytes()[s.len() - 4..];
        assert_eq!(suffix, b"/...", "suffix bytes must equal `/...`");
        // Symmetric: trailing-slash-only input lands on `/...` too —
        // pin via byte-exact suffix.
        let s2 = redact_url("https://example.com/");
        assert_eq!(&s2.as_bytes()[s2.len() - 4..], b"/...");
    }

    #[test]
    fn redact_url_is_idempotent_applying_twice_equals_applying_once() {
        // The output of `redact_url` is itself a valid URL shape (the
        // `/...` suffix is not a valid path component on the wire but
        // the helper treats it as the first path segment on a re-run).
        // Pin idempotency: `redact_url(redact_url(x)) == redact_url(x)`
        // across all the input shapes the helper handles. A refactor
        // that started stripping the `/...` suffix "for clean re-
        // redaction" or that appended an additional `/...` on each
        // call "for layered redaction" would surface here as a
        // divergence between one-pass and two-pass output. The
        // dashboard's redact-on-read path may invoke this helper
        // multiple times on the same URL (e.g. once at fetch, once
        // at render); pin determinism. Symmetric to the
        // `sanitize_token_is_idempotent_applying_twice_equals_applying_once`
        // and `redact_pii_text_is_idempotent_across_two_passes_on_pii_heavy_input`
        // pins on sibling helpers.
        for input in [
            "https://hooks.slack.com/services/T/B/abcXYZ?token=secret",
            "https://example.com",
            "https://example.com/",
            "https://siem.local:8080/ingest",
            "ftp://files.example/x/y",
            "just-a-token",
            "",
        ] {
            let once = redact_url(input);
            let twice = redact_url(&once);
            assert_eq!(
                once, twice,
                "idempotency broke on input {input:?}: once={once:?}, twice={twice:?}",
            );
        }
    }

    #[test]
    fn set_config_body_config_field_preserves_deeply_nested_json_value_verbatim() {
        // The `config: Value` field is `serde_json::Value` (not `String`,
        // not `Map<String, String>`) so the per-driver handlers can
        // index into deeply-nested config shapes without re-parsing.
        // Pin that a deeply-nested config object (3 levels deep with
        // mixed types — string, bool, int, array, null) round-trips
        // through deserialization byte-equivalently to the input JSON.
        // A refactor that switched the field to a flat `Value::Object`
        // "for schema validation" would silently flatten nested
        // structures and break the per-driver handlers that walk the
        // nested shapes (e.g. the slack handler reads
        // `config["user_map"][slack_id]`).
        let raw = r#"{
            "driver": "webhook",
            "enabled": true,
            "config": {
                "url": "https://hook.example",
                "options": {
                    "retries": 5,
                    "backoff_ms": 100,
                    "headers": ["x-foo", "x-bar"],
                    "tls": {
                        "verify": true,
                        "ca_path": null
                    }
                }
            }
        }"#;
        let b: SetConfigBody = serde_json::from_str(raw).unwrap();
        assert_eq!(b.config["url"], "https://hook.example");
        assert_eq!(b.config["options"]["retries"], 5);
        assert_eq!(b.config["options"]["backoff_ms"], 100);
        assert_eq!(b.config["options"]["headers"][0], "x-foo");
        assert_eq!(b.config["options"]["headers"][1], "x-bar");
        assert_eq!(b.config["options"]["tls"]["verify"], true);
        assert!(b.config["options"]["tls"]["ca_path"].is_null());
        // The nested object IS an object (not coerced to a string).
        assert!(b.config["options"].is_object());
        assert!(b.config["options"]["headers"].is_array());
    }

    #[tokio::test]
    async fn notifier_api_state_clone_shares_notifiers_hot_swap_state_across_clones() {
        use std::sync::Arc;
        // `NotifierApiState` derives `Clone` — axum's State extractor
        // clones the state into every request scope. The inner
        // `Notifiers` bundle MUST share its hot-swap state across all
        // clones (the §10.3 contract): a replace through one clone's
        // bundle must be visible on a sibling clone's bundle. The
        // existing `notifier_api_state_is_send_sync_static_for_axum_state_boundary`
        // pin only checks the type bounds — pin the observable Clone-
        // share semantic here. Symmetric to the
        // `killswitch_api_state_clone_shares_inner_kill_cache_handle`
        // pin on sibling api/killswitch.rs round 158-era backfill.
        use sqlx::postgres::PgPoolOptions;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/x")
            .expect("lazy pool builds");
        let state = NotifierApiState {
            notifiers: Notifiers::empty(),
            db: pool,
            proxy_base_url: "https://proxy.local".into(),
        };
        let clone_a = state.clone();
        let clone_b = state.clone();
        // Replace webhook via clone_a; observe via clone_b.
        let secret = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let webhook = Arc::new(
            WebhookNotifier::new(
                "https://shared-webhook.example".into(),
                secret,
                "https://proxy.local".into(),
            )
            .unwrap(),
        );
        clone_a.notifiers.webhook.replace(Some(webhook));
        assert!(
            clone_b.notifiers.webhook.current().is_some(),
            "Notifiers bundle not shared across NotifierApiState Clone — refactor broke axum State propagation",
        );
        // proxy_base_url is also cheap-cloned (String); pin both clones
        // observe the same value.
        assert_eq!(clone_a.proxy_base_url, "https://proxy.local");
        assert_eq!(clone_b.proxy_base_url, "https://proxy.local");
    }

    #[test]
    fn notifier_api_state_field_count_pinned_at_exactly_three_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the NotifierApiState struct field count at exactly 3 via
        // exhaustive destructure pattern (no `..` rest). The 3 fields
        // are: notifiers (Notifiers) + db (PgPool) + proxy_base_url
        // (String). A 4th field landing (e.g. `metrics: MetricsHandle`
        // for the notifier API to report send-success / send-failure
        // counters live, or `audit_sink: Arc<dyn ActionStream>` to
        // tee a per-config-change event into the audit pipeline)
        // would silently bloat every Clone of NotifierApiState the
        // axum router fans out per request AND silently change what
        // every notifier API handler sees. The existing
        // Notifiers-shared-across-Clone test walks Arc semantics on
        // ONE field (notifiers); exhaustive destructure pins the
        // catch-all-fields contract symmetrically.
        fn _destructure_witness(s: NotifierApiState) {
            let NotifierApiState {
                notifiers: _,
                db: _,
                proxy_base_url: _,
            } = s;
        }
    }

    #[test]
    fn test_request_field_count_pinned_at_exactly_one_via_exhaustive_destructure_no_rest_pattern() {
        // Pin the TestRequest body struct field count at exactly 1
        // via exhaustive destructure pattern. The 1 field is: driver
        // (Option<String>). A 2nd field landing (e.g.
        // `target_user: Option<String>` to send the synthetic
        // BlockedNotification to a specific operator instead of the
        // configured-default channel, or `dry_run: Option<bool>`
        // for "validate config without emitting") would silently
        // extend the CLI's expected request body shape AND silently
        // change the deserialize contract for the
        // `/api/v1/notifier/test` endpoint. Pin via exhaustive
        // destructure.
        let v = TestRequest { driver: None };
        let TestRequest { driver: _ } = v;
    }

    #[test]
    fn set_config_body_field_count_pinned_at_exactly_three_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the SetConfigBody request-body field count at exactly
        // 3 via exhaustive destructure. The 3 fields are: driver
        // (String) + enabled (Option<bool>) + config (Value). A 4th
        // field landing (e.g. `actor: Option<String>` for
        // operator-attribution into the audit log of config
        // changes, or `effective_at: Option<DateTime<Utc>>` for a
        // future scheduled-config-change feature) would silently
        // extend the CLI's expected request body shape AND silently
        // change the handler's deserialize contract for the
        // `/api/v1/notifier/config` POST endpoint.
        let v = SetConfigBody {
            driver: String::new(),
            enabled: None,
            config: serde_json::Value::Null,
        };
        let SetConfigBody {
            driver: _,
            enabled: _,
            config: _,
        } = v;
    }

    #[test]
    fn redact_url_signature_pinned_via_fn_pointer_witness() {
        // Pin redact_url signature as `fn(&str) -> String` via
        // fn-pointer witness. A refactor that flipped to
        // `fn(String) -> String` ("for consume-and-format
        // clarity") would silently force every call site to
        // allocate a String from the borrowed config-field URL.
        // The borrow shape lets the show / get_config handlers call
        // `redact_url(url)` on a borrowed &str slice into the
        // serde_json Value tree without cloning. The owned String
        // return is also pinned — a refactor to `Cow<'_, str>` for
        // the "passthrough already-redacted" path would tie the
        // return lifetime to the input slice and force lifetime
        // parameters on the response shape.
        let _f: fn(&str) -> String = redact_url;
    }

    #[test]
    fn router_function_signature_pinned_via_fn_pointer_witness() {
        // Pin the module's router constructor signature as
        // `fn(NotifierApiState) -> Router` via fn-pointer witness.
        // Symmetric to round-262 api/mod.rs + round-263 api/policy.rs
        // router fn-pointer pins extended to the notifier API. The
        // server.rs boot path calls `router(notifier_state)` once
        // at app assembly AND consumes the state by value (the
        // router internally clones it per request via
        // `.with_state(...)`). A refactor to
        // `fn(&NotifierApiState) -> Router` or
        // `fn(NotifierApiState) -> Result<Router, _>` would silently
        // change the boot path's ownership AND error-handling
        // shape.
        let _f: fn(NotifierApiState) -> Router = router;
    }

    #[test]
    fn notifier_api_state_is_clone_for_axum_router_state_fan_out() {
        // The axum `with_state` extractor relies on the State<T>
        // type being Clone (the router clones per request to
        // construct the handler arg). The existing
        // `#[derive(Clone)]` is what makes this work; a refactor
        // that dropped the derive (perhaps a refactor unifying
        // notifier state with a sibling crate's that's !Clone)
        // would surface at hundreds of router-build sites in
        // server.rs rather than at this single trait-bound
        // assertion. Pin Clone via require_clone — symmetric to
        // round-76 OperatorAuthState Clone trait-bound pin
        // extended to NotifierApiState.
        fn require_clone<T: Clone>() {}
        require_clone::<NotifierApiState>();
    }
}
