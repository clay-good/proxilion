//! Google Calendar adapter (`/google/calendar/v3/...`).
//!
//! Authority: spec.md §4.1 / §8. Four routes — `list_events`, `get_event`,
//! `insert_event`, `update_event` — share the same template as the Drive
//! and Gmail adapters: build a `RequestContext`, evaluate Layer B (policy),
//! mint a PCA_2 successor with the narrowed ops (Layer A), forward to
//! Google, apply the read filter on reads, publish the action event.
//!
//! Body fields exposed to the policy engine (writes only — default-deny per
//! spec.md §5.4): attendee count, external-attendee flag, attendee-domain
//! list, summary presence, visibility. Reads expose no body context.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap};
use axum::http::{HeaderName, HeaderValue, Method, Response, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use serde_json::{Value, json};
use shared_types::provenance::pca::ExecutorBinding;
use tracing::{info, instrument, warn};
use uuid::Uuid;

use super::action_stream::ActionEvent;
use super::error::AppError;
use super::read_filter;
use super::state::AdapterState;
use crate::pic::{CachedPca, PcaCache, SuccessorOutcome};
use crate::session::SessionCtx;
use policy_engine::{Decision, Outcome, RequestContext, UserCtx};

const MAX_BODY: usize = 10 * 1024 * 1024;
/// 1MB cap on agent-supplied event JSON. Google Calendar's hard cap is
/// ~1MB; we surface the limit at the proxy with a structured error rather
/// than letting Google return an opaque 4xx.
const MAX_EVENT_JSON: usize = 1024 * 1024;

pub fn router(state: AdapterState) -> Router {
    Router::new()
        .route(
            "/google/calendar/v3/calendars/{calendarId}/events",
            get(list_events).post(insert_event),
        )
        .route(
            "/google/calendar/v3/calendars/{calendarId}/events/{eventId}",
            get(get_event)
                .put(update_event)
                .patch(patch_event)
                .delete(delete_event),
        )
        .with_state(state)
}

#[instrument(skip(state, session, query))]
async fn list_events(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Path(calendar_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response<axum::body::Body>, AppError> {
    let mut policy_path = HashMap::new();
    policy_path.insert("cid".to_string(), calendar_id.clone());
    proxy_request(
        &state,
        &session,
        CalendarRequest {
            action: "calendar.events.list".into(),
            upstream_path: format!(
                "/calendar/v3/calendars/{}/events",
                urlencoding(&calendar_id)
            ),
            method: Method::GET,
            policy_path,
            query,
            body_for_policy: HashMap::new(),
            upstream_body: None,
        },
    )
    .await
}

#[instrument(skip(state, session, query))]
async fn get_event(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Path((calendar_id, event_id)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response<axum::body::Body>, AppError> {
    let mut policy_path = HashMap::new();
    policy_path.insert("cid".to_string(), calendar_id.clone());
    policy_path.insert("eid".to_string(), event_id.clone());
    proxy_request(
        &state,
        &session,
        CalendarRequest {
            action: "calendar.events.get".into(),
            upstream_path: format!(
                "/calendar/v3/calendars/{}/events/{}",
                urlencoding(&calendar_id),
                urlencoding(&event_id)
            ),
            method: Method::GET,
            policy_path,
            query,
            body_for_policy: HashMap::new(),
            upstream_body: None,
        },
    )
    .await
}

#[instrument(skip(state, session, query, body))]
async fn insert_event(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Path(calendar_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Result<Response<axum::body::Body>, AppError> {
    let raw = serde_json::to_vec(&body).map_err(|e| AppError::Internal(e.to_string()))?;
    if raw.len() > MAX_EVENT_JSON {
        return Err(AppError::UpstreamTooLarge);
    }
    let mut policy_path = HashMap::new();
    policy_path.insert("cid".to_string(), calendar_id.clone());
    let body_ctx = build_event_body_ctx(&body, &state.customer_domain);
    proxy_request(
        &state,
        &session,
        CalendarRequest {
            action: "calendar.events.insert".into(),
            upstream_path: format!(
                "/calendar/v3/calendars/{}/events",
                urlencoding(&calendar_id)
            ),
            method: Method::POST,
            policy_path,
            query,
            body_for_policy: body_ctx,
            upstream_body: Some(raw),
        },
    )
    .await
}

#[instrument(skip(state, session, query, body))]
async fn update_event(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Path((calendar_id, event_id)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Result<Response<axum::body::Body>, AppError> {
    update_or_patch(
        &state,
        &session,
        calendar_id,
        event_id,
        query,
        body,
        Method::PUT,
        "calendar.events.update",
    )
    .await
}

/// `events.delete` (spec.md §4.1 dev 2). No request body; Google returns
/// 204 No Content on success. Policy context surfaces `path.cid` + `path.eid`
/// so a customer can gate destructive deletes (e.g. block on managed
/// calendars). The default `required_ops` template for delete is
/// `calendar:delete:${user.email}/event/${path.eid}` — opt-in via policy.
#[instrument(skip(state, session, query))]
async fn delete_event(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Path((calendar_id, event_id)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response<axum::body::Body>, AppError> {
    let mut policy_path = HashMap::new();
    policy_path.insert("cid".to_string(), calendar_id.clone());
    policy_path.insert("eid".to_string(), event_id.clone());
    proxy_request(
        &state,
        &session,
        CalendarRequest {
            action: "calendar.events.delete".into(),
            upstream_path: format!(
                "/calendar/v3/calendars/{}/events/{}",
                urlencoding(&calendar_id),
                urlencoding(&event_id)
            ),
            method: Method::DELETE,
            policy_path,
            query,
            body_for_policy: HashMap::new(),
            upstream_body: None,
        },
    )
    .await
}

#[instrument(skip(state, session, query, body))]
async fn patch_event(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Path((calendar_id, event_id)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Result<Response<axum::body::Body>, AppError> {
    update_or_patch(
        &state,
        &session,
        calendar_id,
        event_id,
        query,
        body,
        Method::PATCH,
        "calendar.events.patch",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn update_or_patch(
    state: &AdapterState,
    session: &std::sync::Arc<crate::session::SessionContext>,
    calendar_id: String,
    event_id: String,
    query: HashMap<String, String>,
    body: Value,
    method: Method,
    action: &'static str,
) -> Result<Response<axum::body::Body>, AppError> {
    let raw = serde_json::to_vec(&body).map_err(|e| AppError::Internal(e.to_string()))?;
    if raw.len() > MAX_EVENT_JSON {
        return Err(AppError::UpstreamTooLarge);
    }
    let mut policy_path = HashMap::new();
    policy_path.insert("cid".to_string(), calendar_id.clone());
    policy_path.insert("eid".to_string(), event_id.clone());
    let body_ctx = build_event_body_ctx(&body, &state.customer_domain);
    proxy_request(
        state,
        session,
        CalendarRequest {
            action: action.into(),
            upstream_path: format!(
                "/calendar/v3/calendars/{}/events/{}",
                urlencoding(&calendar_id),
                urlencoding(&event_id)
            ),
            method,
            policy_path,
            query,
            body_for_policy: body_ctx,
            upstream_body: Some(raw),
        },
    )
    .await
}

struct CalendarRequest {
    action: String,
    upstream_path: String,
    method: Method,
    policy_path: HashMap<String, String>,
    query: HashMap<String, String>,
    /// Default-deny body exposure (spec.md §5.4). Reads expose nothing;
    /// writes expose recipient-domain-shaped context for policy match
    /// against external-attendee gates.
    body_for_policy: HashMap<String, Value>,
    /// Bytes to forward verbatim on writes. `None` on GET.
    upstream_body: Option<Vec<u8>>,
}

async fn proxy_request(
    state: &AdapterState,
    session: &std::sync::Arc<crate::session::SessionContext>,
    req: CalendarRequest,
) -> Result<Response<axum::body::Body>, AppError> {
    let request_id = Uuid::new_v4();
    let ctx = build_policy_ctx(state, session, &req);

    let (outcome, mut policy_trace) = state.policy.load().evaluate_with_trace(&ctx)?;
    // ui-less-surfaces.md §5.7 dev 2 — per-policy escalation deadline.
    let escalation_after_minutes = outcome
        .matched_policy_id
        .as_deref()
        .and_then(|id| state.policy.load().escalation_after_minutes_for(id));
    let requested_ops: Vec<String> = outcome
        .required_ops
        .required
        .iter()
        .map(|a| a.to_canonical())
        .collect();
    let method_str = req.method.to_string();

    // Layer B.
    if let Err(e) = enforce_pre_request_decision(&outcome) {
        super::policy_trace::emit(&policy_trace, request_id, "google", &req.action);
        if matches!(
            e,
            AppError::PolicyBlocked { .. } | AppError::RequireConfirmation(_)
        ) {
            let detail = format!("{e}");
            crate::blocked::persist_and_notify(
                &state.auth.db,
                &state.notifier,
                crate::blocked::BlockedActionRecord {
                    request_id,
                    session_id: session.agent_session_id,
                    p_0: Some(&session.p_0),
                    vendor: "google",
                    action: &req.action,
                    method: &method_str,
                    path: &req.upstream_path,
                    layer: "policy",
                    policy_id: outcome.matched_policy_id.as_deref(),
                    detail: Some(&detail),
                    predecessor_pca_id: Some(session.leaf_pca_id),
                    requested_ops: &requested_ops,
                        escalation_after_minutes,
                },
            )
            .await;
        }
        return Err(e);
    }

    // Layer A: narrowed PCA_2.
    let leaf_ops: Vec<String> = if requested_ops.is_empty() {
        session.granted_ops.clone()
    } else {
        requested_ops.clone()
    };

    let binding = ExecutorBinding::new()
        .with("service", "proxilion-proxy")
        .with("action", req.action.as_str())
        .with("request_id", request_id.to_string().as_str());

    let (pca2_id, audit_violation_detail) = match state
        .pic
        .request_or_audit_successor(
            session.leaf_pca_cbor.clone(),
            leaf_ops.clone(),
            binding,
            outcome.pic_mode,
        )
        .await
    {
        Ok(SuccessorOutcome::Issued(pca2)) => {
            let pca2_cbor = B64
                .decode(&pca2.pca)
                .map_err(|e| AppError::Internal(format!("PCA_2 base64: {e}")))?;
            let pca2_id = Uuid::new_v4();
            let cache = PcaCache::new(state.auth.db.clone());
            cache
                .insert(&CachedPca {
                    pca_id: pca2_id,
                    cbor: pca2_cbor,
                    p_0: pca2.p_0.clone(),
                    ops: pca2.ops.clone(),
                    hop: pca2.hop as i32,
                    predecessor_id: Some(session.leaf_pca_id),
                    signature: vec![],
                pic_profile: crate::pic::cache::CURRENT_PIC_PROFILE.to_string(),
                })
                .await
                .map_err(|e| AppError::Internal(format!("pca_cache: {e}")))?;
            (pca2_id, None)
        }
        Ok(SuccessorOutcome::AuditFallback { detail }) => {
            let missing = crate::pic::violations::parse_missing_atoms(&detail);
            crate::pic::violations::persist(
                &state.auth.db,
                crate::pic::PicViolationRecord {
                    request_id,
                    session_id: session.agent_session_id,
                    p_0: Some(&session.p_0),
                    vendor: "google",
                    action: &req.action,
                    method: &method_str,
                    path: &req.upstream_path,
                    policy_id: outcome.matched_policy_id.as_deref(),
                    predecessor_pca_id: Some(session.leaf_pca_id),
                    attempted_ops: &leaf_ops,
                    missing_atoms: &missing,
                    pic_mode: "audit",
                    detail: Some(&detail),
                },
            )
            .await;
            metrics::counter!(
                "proxilion_pic_violations_total",
                "mode" => "audit",
                "vendor" => "google",
                "action" => req.action.clone(),
            )
            .increment(1);
            (session.leaf_pca_id, Some(detail))
        }
        Err(crate::pic::ExecutorError::Invariant(d)) => {
            super::policy_trace::mark_layer_a_failed(&mut policy_trace, d.clone());
            super::policy_trace::emit(&policy_trace, request_id, "google", &req.action);
            crate::pic::violations::persist(
                &state.auth.db,
                crate::pic::PicViolationRecord {
                    request_id,
                    session_id: session.agent_session_id,
                    p_0: Some(&session.p_0),
                    vendor: "google",
                    action: &req.action,
                    method: &method_str,
                    path: &req.upstream_path,
                    policy_id: outcome.matched_policy_id.as_deref(),
                    predecessor_pca_id: Some(session.leaf_pca_id),
                    attempted_ops: &leaf_ops,
                    missing_atoms: &crate::pic::violations::parse_missing_atoms(&d),
                    pic_mode: "runtime_gate",
                    detail: Some(&d),
                },
            )
            .await;
            metrics::counter!(
                "proxilion_pic_violations_total",
                "mode" => "runtime_gate",
                "vendor" => "google",
                "action" => req.action.clone(),
            )
            .increment(1);
            crate::blocked::persist_and_notify(
                &state.auth.db,
                &state.notifier,
                crate::blocked::BlockedActionRecord {
                    request_id,
                    session_id: session.agent_session_id,
                    p_0: Some(&session.p_0),
                    vendor: "google",
                    action: &req.action,
                    method: &method_str,
                    path: &req.upstream_path,
                    layer: "pic_invariant",
                    policy_id: outcome.matched_policy_id.as_deref(),
                    detail: Some(&d),
                    predecessor_pca_id: Some(session.leaf_pca_id),
                    requested_ops: &leaf_ops,
                        escalation_after_minutes,
                },
            )
            .await;
            return Err(AppError::PicInvariantViolation(d));
        }
        Err(crate::pic::ExecutorError::Upstream { status, body }) => {
            return Err(AppError::Internal(format!("trust plane {status}: {body}")));
        }
        Err(other) => return Err(AppError::Internal(other.to_string())),
    };

    // Upstream call.
    let upstream_url = format!("{}{}", state.google_api_base(), req.upstream_path);
    let mut builder = state
        .upstream
        .request(req.method.clone(), &upstream_url)
        .header(
            AUTHORIZATION,
            HeaderValue::try_from(format!("Bearer {}", session.google_access_token))
                .map_err(|_| AppError::Internal("bad google bearer".into()))?,
        );
    if !req.query.is_empty() {
        builder = builder.query(&req.query);
    }
    if let Some(b) = req.upstream_body.as_ref() {
        builder = builder.header(CONTENT_TYPE, "application/json").body(b.clone());
    }
    let upstream_resp = builder.send().await?;
    let status = upstream_resp.status();
    let content_type = upstream_resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let body_bytes = read_bounded(upstream_resp, MAX_BODY).await?;

    // Read filter — only on GETs.
    let (final_body, filter_outcome) =
        if req.method == Method::GET && outcome.read_filter.is_some() {
            let filter = outcome.read_filter.as_ref().expect("guarded above");
            let compiled = read_filter::CompiledFilter::compile(filter)
                .map_err(|e| AppError::Internal(format!("read-filter regex: {e}")))?;
            let (b, o) = read_filter::apply(&body_bytes, &compiled, content_type.as_deref());
            if o.block {
                super::policy_trace::mark_read_filter(
                    &mut policy_trace,
                    true,
                    outcome.matched_policy_id.clone(),
                    format!("BlockRequest pattern matched ({} hits)", o.matches),
                );
                super::policy_trace::emit(&policy_trace, request_id, "google", &req.action);
                crate::blocked::persist_and_notify(
                    &state.auth.db,
                    &state.notifier,
                    crate::blocked::BlockedActionRecord {
                        request_id,
                        session_id: session.agent_session_id,
                        p_0: Some(&session.p_0),
                        vendor: "google",
                        action: &req.action,
                        method: &method_str,
                        path: &req.upstream_path,
                        layer: "read_filter",
                        policy_id: outcome.matched_policy_id.as_deref(),
                        detail: Some("BlockRequest pattern matched"),
                        predecessor_pca_id: None,
                        requested_ops: &[],
                        escalation_after_minutes,
                    },
                )
                .await;
                return Err(AppError::ReadFilterBlocked);
            }
            persist_quarantine_samples(
                &state.auth.db,
                request_id,
                session.agent_session_id,
                outcome.matched_policy_id.as_deref(),
                &o.samples,
            )
            .await;
            super::policy_trace::mark_read_filter(
                &mut policy_trace,
                false,
                outcome.matched_policy_id.clone(),
                format!("{} matches, {} samples", o.matches, o.samples.len()),
            );
            (b, o)
        } else {
            (body_bytes, Default::default())
        };

    // Observe mode (ui-less-surfaces.md §2.5): if the policy would have
    // blocked / required_confirmation / rate_limited but is in observe
    // mode, the engine returns Decision::Allow + an `observe_would_have`
    // label. The action event records the "would have" outcome so the
    // operator can promote the policy to enforce later.
    let decision_label = match &outcome.decision {
        Decision::Allow => outcome
            .observe_would_have
            .as_deref()
            .unwrap_or("allow"),
        Decision::Block { .. } => "block",
        Decision::RequireConfirmation { .. } => "require_confirmation",
        Decision::RateLimit { .. } => "rate_limit",
    };
    if let Some(woulda) = outcome.observe_would_have.as_deref() {
        // Strip the `observe_` prefix to keep the metric label bounded.
        let reason = woulda.strip_prefix("observe_").unwrap_or(woulda);
        metrics::counter!(
            "proxilion_observe_would_have_blocked_total",
            "policy_id" => outcome
                .matched_policy_id
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            "reason" => reason.to_string(),
        )
        .increment(1);
    }
    // Per-policy audit-body capture (ui-less-surfaces.md §6.4).
    if let Some(mode) = outcome.audit_body {
        let req_bytes: &[u8] = req.upstream_body.as_deref().unwrap_or(&[]);
        crate::audit_body::persist(&state.auth.db, request_id, mode, req_bytes, &final_body).await;
    }
    state
        .stream
        .publish(ActionEvent {
            request_id,
            agent_session_id: session.agent_session_id,
            p_0: session.p_0.clone(),
            leaf_pca_id: Some(pca2_id),
            vendor: "google".to_string(),
            action: req.action.clone(),
            method: req.method.to_string(),
            path: req.upstream_path.clone(),
            status: status.as_u16(),
            decision: decision_label.to_string(),
            block_reason: None,
            read_filter_triggered: filter_outcome.triggered,
            quarantined_count: filter_outcome.matches,
            at: Utc::now(),
            policy_id: outcome.matched_policy_id.clone(),
            extra: json!({
                "request_path_params": req.policy_path,
                "attendee_count": ctx.body.get("attendee_count"),
                "attendee_domains": ctx.body.get("attendee_domains"),
                "external_attendee": ctx.body.get("external_attendee"),
                "visibility": ctx.body.get("visibility"),
                "pic_audit_violation": audit_violation_detail,
            }),
        })
        .await;

    info!(
        request_id = %request_id,
        action = %req.action,
        status = status.as_u16(),
        pca2_id = %pca2_id,
        "proxied calendar request"
    );

    let mut builder = Response::builder().status(status);
    let resp_headers = builder.headers_mut().expect("fresh builder has headers");
    if let Some(ct) = content_type.as_deref() {
        if let Ok(v) = HeaderValue::from_str(ct) {
            resp_headers.insert(CONTENT_TYPE, v);
        }
    }
    insert_proxy_headers(resp_headers, request_id, &outcome, pca2_id);
    if let Ok(v) = HeaderValue::from_str(&policy_trace.trace_id.to_string()) {
        resp_headers.insert(HeaderName::from_static("x-proxilion-trace-id"), v);
    }
    super::policy_trace::emit(&policy_trace, request_id, "google", &req.action);
    Ok(builder
        .body(axum::body::Body::from(final_body))
        .map_err(|e| AppError::Internal(e.to_string()))?)
}

fn build_policy_ctx(
    state: &AdapterState,
    session: &crate::session::SessionContext,
    req: &CalendarRequest,
) -> RequestContext {
    RequestContext {
        vendor: "google".into(),
        action: req.action.clone(),
        user: UserCtx {
            email: session.p_0.clone(),
            groups: vec![],
        },
        path: req.policy_path.clone(),
        body: req.body_for_policy.clone(),
        headers: HashMap::new(),
        customer_domain: state.customer_domain.clone(),
    }
}

fn enforce_pre_request_decision(outcome: &Outcome) -> Result<(), AppError> {
    match &outcome.decision {
        Decision::Allow => Ok(()),
        Decision::Block {
            reason,
            override_allowed,
        } => Err(AppError::PolicyBlocked {
            policy_id: outcome.matched_policy_id.clone(),
            reason: reason.clone(),
            override_allowed: *override_allowed,
        }),
        Decision::RequireConfirmation { reason } => {
            Err(AppError::RequireConfirmation(reason.clone()))
        }
        Decision::RateLimit { .. } => Err(AppError::RateLimit),
    }
}

async fn read_bounded(resp: reqwest::Response, max: usize) -> Result<Vec<u8>, AppError> {
    if let Some(len) = resp.content_length() {
        if len as usize > max {
            return Err(AppError::UpstreamTooLarge);
        }
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > max {
        return Err(AppError::UpstreamTooLarge);
    }
    Ok(bytes.to_vec())
}

fn insert_proxy_headers(headers: &mut HeaderMap, request_id: Uuid, outcome: &Outcome, pca_id: Uuid) {
    headers.insert(
        HeaderName::from_static("x-proxilion-request-id"),
        HeaderValue::from_str(&request_id.to_string()).expect("uuid"),
    );
    headers.insert(
        HeaderName::from_static("x-proxilion-pca-id"),
        HeaderValue::from_str(&pca_id.to_string()).expect("uuid"),
    );
    if let Some(pid) = outcome.matched_policy_id.as_deref() {
        if let Ok(v) = HeaderValue::from_str(pid) {
            headers.insert(HeaderName::from_static("x-proxilion-policy"), v);
        }
    }
}

async fn persist_quarantine_samples(
    db: &sqlx::PgPool,
    request_id: Uuid,
    session_id: Uuid,
    policy_id: Option<&str>,
    samples: &[read_filter::QuarantineSample],
) {
    for s in samples {
        let res = sqlx::query(
            "INSERT INTO quarantined_payloads
                (request_id, session_id, policy_id, pattern, snippet)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(request_id)
        .bind(session_id)
        .bind(policy_id)
        .bind(&s.pattern)
        .bind(&s.snippet)
        .execute(db)
        .await;
        if let Err(e) = res {
            warn!(error = %e, "failed to persist quarantine sample");
        }
    }
}

/// Build the body context exposed to the policy engine for calendar
/// writes. Default-deny — we only surface the fields a customer might want
/// to gate on (external attendees, attendee count, visibility), never the
/// description or summary content.
fn build_event_body_ctx(event: &Value, customer_domain: &str) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    let attendees: Vec<String> = event
        .get("attendees")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.get("email").and_then(|e| e.as_str()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let domains: Vec<String> = attendees
        .iter()
        .filter_map(|e| domain_of(e))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let external = domains.iter().any(|d| !d.eq_ignore_ascii_case(customer_domain));
    out.insert("attendee_count".to_string(), Value::from(attendees.len()));
    out.insert(
        "attendee_domains".to_string(),
        Value::Array(domains.iter().map(|d| Value::String(d.clone())).collect()),
    );
    out.insert("external_attendee".to_string(), Value::Bool(external));
    if let Some(v) = event.get("visibility").and_then(|v| v.as_str()) {
        out.insert("visibility".to_string(), Value::String(v.to_string()));
    }
    out.insert(
        "summary_present".to_string(),
        Value::Bool(event.get("summary").and_then(|v| v.as_str()).is_some()),
    );
    out
}

fn domain_of(email: &str) -> Option<String> {
    email
        .rsplit_once('@')
        .map(|(_, d)| d.to_ascii_lowercase().trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Minimal path-segment encoder. Google Calendar IDs are typically email-
/// shaped (`primary`, `alice@org.com`, hex strings); we percent-encode
/// `/` `#` and other reserved chars defensively.
fn urlencoding(s: &str) -> String {
    use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
    const PATH: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'/')
        .add(b'?')
        .add(b'#')
        .add(b'&')
        .add(b'%');
    utf8_percent_encode(s, PATH).to_string()
}

// Silence unused-import lints for re-exports kept symmetrical with the
// Drive / Gmail adapters.
#[allow(dead_code)]
const _USED: (Option<Bytes>, Option<Json<()>>, StatusCode) = (None, None, StatusCode::OK);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_of_works() {
        assert_eq!(domain_of("alice@acme.com").as_deref(), Some("acme.com"));
        assert_eq!(
            domain_of("Bob@Example.COM").as_deref(),
            Some("example.com")
        );
        assert_eq!(domain_of("invalid").as_deref(), None);
    }

    #[test]
    fn urlencoding_escapes_slashes() {
        // Calendar IDs can be email-shaped or contain `/`; verify reserved
        // chars are encoded so the upstream path stays well-formed.
        assert_eq!(urlencoding("primary"), "primary");
        assert_eq!(urlencoding("alice@acme.com"), "alice@acme.com");
        assert_eq!(urlencoding("a/b#c"), "a%2Fb%23c");
        assert_eq!(urlencoding("spaces are fine"), "spaces%20are%20fine");
    }

    #[test]
    fn body_ctx_external_attendee_flagged() {
        let ev = json!({
            "summary": "Q4 strategy review",
            "attendees": [
                {"email": "alice@acme.com"},
                {"email": "consultant@othercorp.com"},
            ],
            "visibility": "private"
        });
        let ctx = build_event_body_ctx(&ev, "acme.com");
        assert_eq!(ctx.get("external_attendee"), Some(&Value::Bool(true)));
        assert_eq!(ctx.get("attendee_count"), Some(&Value::from(2)));
        assert_eq!(ctx.get("visibility"), Some(&Value::String("private".into())));
        assert_eq!(ctx.get("summary_present"), Some(&Value::Bool(true)));
        // Domains de-duplicated + sorted.
        let domains = ctx.get("attendee_domains").unwrap().as_array().unwrap();
        let s: Vec<&str> = domains.iter().filter_map(|d| d.as_str()).collect();
        assert_eq!(s, vec!["acme.com", "othercorp.com"]);
    }

    #[test]
    fn body_ctx_internal_only_is_not_external() {
        let ev = json!({
            "attendees": [
                {"email": "alice@acme.com"},
                {"email": "bob@acme.com"},
            ],
        });
        let ctx = build_event_body_ctx(&ev, "acme.com");
        assert_eq!(ctx.get("external_attendee"), Some(&Value::Bool(false)));
        assert_eq!(ctx.get("attendee_count"), Some(&Value::from(2)));
    }

    #[test]
    fn body_ctx_no_attendees() {
        let ev = json!({"summary": "personal hold"});
        let ctx = build_event_body_ctx(&ev, "acme.com");
        assert_eq!(ctx.get("attendee_count"), Some(&Value::from(0)));
        assert_eq!(ctx.get("external_attendee"), Some(&Value::Bool(false)));
        // Missing visibility absent, not Null.
        assert!(ctx.get("visibility").is_none());
    }

    #[test]
    fn body_ctx_missing_email_skipped() {
        let ev = json!({
            "attendees": [
                {"displayName": "no email"},
                {"email": "alice@acme.com"},
            ],
        });
        let ctx = build_event_body_ctx(&ev, "acme.com");
        assert_eq!(ctx.get("attendee_count"), Some(&Value::from(1)));
    }
}
