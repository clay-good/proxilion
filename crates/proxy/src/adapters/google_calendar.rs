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
use super::error::{AppError, upstream_error_kind};
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
        // spec.md §4.1 dev 3 — calendarList discovery. Agent can enumerate
        // the calendars the user has subscribed to; the PIC-bound ops atom
        // gates discovery the same way it gates event-level access.
        .route(
            "/google/calendar/v3/users/me/calendarList",
            get(list_calendar_list),
        )
        .with_state(state)
}

#[instrument(skip(state, session, query))]
async fn list_calendar_list(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response<axum::body::Body>, AppError> {
    proxy_request(
        &state,
        &session,
        CalendarRequest {
            action: "calendar.calendarList.list".into(),
            upstream_path: "/calendar/v3/users/me/calendarList".to_string(),
            method: Method::GET,
            policy_path: HashMap::new(),
            query,
            body_for_policy: HashMap::new(),
            upstream_body: None,
        },
    )
    .await
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
    // spec.md §3.2 — `proxilion_adapter_request_duration_seconds`.
    let adapter_started = std::time::Instant::now();
    let ctx = build_policy_ctx(state, session, &req);

    // spec.md §3.2 — `proxilion_policy_evaluations_total` + duration.
    let eval_started = std::time::Instant::now();
    let eval_result = state.policy.load().evaluate_with_trace(&ctx);
    metrics::histogram!("proxilion_policy_evaluation_duration_seconds")
        .record(eval_started.elapsed().as_secs_f64());
    let (outcome, mut policy_trace) = match eval_result {
        Ok(pair) => {
            metrics::counter!(
                "proxilion_policy_evaluations_total",
                "policy_id" => pair.0.matched_policy_id.clone().unwrap_or_else(|| "(none)".into()),
                "result" => if pair.0.matched_policy_id.is_some() { "match" } else { "nomatch" },
            )
            .increment(1);
            pair
        }
        Err(e) => {
            metrics::counter!(
                "proxilion_policy_evaluations_total",
                "policy_id" => "(error)",
                "result" => "error",
            )
            .increment(1);
            return Err(e.into());
        }
    };
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
        if super::persists_blocked_action(&e) {
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
                    request_canonical_json: Some(crate::blocked::canonical_request_json(
                        &method_str,
                        &req.upstream_path,
                        "google",
                        &req.action,
                        &req.policy_path,
                        &req.body_for_policy,
                    )),
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
                    request_canonical_json: Some(crate::blocked::canonical_request_json(
                        &method_str,
                        &req.upstream_path,
                        "google",
                        &req.action,
                        &req.policy_path,
                        &req.body_for_policy,
                    )),
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
        builder = builder
            .header(CONTENT_TYPE, "application/json")
            .body(b.clone());
    }
    let upstream_resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            // spec.md §3.2 — `proxilion_adapter_upstream_errors_total{vendor,action,kind}`.
            metrics::counter!(
                "proxilion_adapter_upstream_errors_total",
                "vendor" => "google",
                "action" => req.action.clone(),
                "kind" => upstream_error_kind(&e),
            )
            .increment(1);
            return Err(e.into());
        }
    };
    let status = upstream_resp.status();
    if status.is_server_error() {
        metrics::counter!(
            "proxilion_adapter_upstream_errors_total",
            "vendor" => "google",
            "action" => req.action.clone(),
            "kind" => "5xx",
        )
        .increment(1);
    }
    let content_type = upstream_resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let body_bytes = super::read_bounded(upstream_resp, MAX_BODY).await?;

    // Read filter — only on GETs.
    let (final_body, filter_outcome) =
        if let (&Method::GET, Some(filter)) = (&req.method, outcome.read_filter.as_ref()) {
            let compiled = read_filter::CompiledFilter::compile(filter)
                .map_err(|e| AppError::Internal(format!("read-filter regex: {e}")))?;
            let (b, o) = read_filter::apply(&body_bytes, &compiled, content_type.as_deref());
            // spec.md §3.2 — readfilter scan + quarantined-bytes counters.
            let scan_result = if !o.triggered {
                "clean"
            } else if o.block {
                "quarantined"
            } else {
                "stripped"
            };
            metrics::counter!(
                "proxilion_readfilter_scans_total",
                "vendor" => "google",
                "action" => req.action.clone(),
                "result" => scan_result,
            )
            .increment(1);
            if o.triggered {
                let quarantined_bytes = if o.block {
                    body_bytes.len() as u64
                } else {
                    (body_bytes.len() as u64).saturating_sub(b.len() as u64)
                };
                metrics::counter!(
                    "proxilion_readfilter_quarantined_bytes_total",
                    "vendor" => "google",
                )
                .increment(quarantined_bytes);
            }
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
                        request_canonical_json: Some(crate::blocked::canonical_request_json(
                            &method_str,
                            &req.upstream_path,
                            "google",
                            &req.action,
                            &req.policy_path,
                            &req.body_for_policy,
                        )),
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
        Decision::Allow => outcome.observe_would_have.as_deref().unwrap_or("allow"),
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
    // spec.md §3.2 — `proxilion_adapter_requests_total{vendor,action,decision,mode}`.
    metrics::counter!(
        "proxilion_adapter_requests_total",
        "vendor" => "google",
        "action" => req.action.clone(),
        "decision" => decision_label.to_string(),
        "mode" => if outcome.observe_would_have.is_some() { "observe" } else { "enforce" },
    )
    .increment(1);
    metrics::histogram!(
        "proxilion_adapter_request_duration_seconds",
        "vendor" => "google",
        "action" => req.action.clone(),
    )
    .record(adapter_started.elapsed().as_secs_f64());
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
    builder
        .body(axum::body::Body::from(final_body))
        .map_err(|e| AppError::Internal(e.to_string()))
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

fn insert_proxy_headers(
    headers: &mut HeaderMap,
    request_id: Uuid,
    outcome: &Outcome,
    pca_id: Uuid,
) {
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
                .filter_map(|a| {
                    a.get("email")
                        .and_then(|e| e.as_str())
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    let domains: Vec<String> = attendees
        .iter()
        .filter_map(|e| domain_of(e))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let external = domains
        .iter()
        .any(|d| !d.eq_ignore_ascii_case(customer_domain));
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
    // Promoted to the shared `adapters::path_segment` helper so Drive and
    // Gmail encode identically (surface-delight-and-correctness.md §6.1).
    // Routes through `encoded_segment` so the §7
    // `proxilion_adapter_path_encoded_total{vendor}` counter covers Calendar
    // too. This thin wrapper is retained for the adapter's existing call
    // sites and tests.
    super::encoded_segment("google", s)
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
        assert_eq!(domain_of("Bob@Example.COM").as_deref(), Some("example.com"));
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
        assert_eq!(
            ctx.get("visibility"),
            Some(&Value::String("private".into()))
        );
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
        assert!(!ctx.contains_key("visibility"));
    }

    fn outcome_with(policy_id: Option<&str>) -> Outcome {
        use policy_engine::{OpsExpression, PicMode};
        Outcome {
            matched_policy_id: policy_id.map(String::from),
            decision: Decision::Allow,
            required_ops: OpsExpression::default(),
            read_filter: None,
            pic_mode: PicMode::Audit,
            mode: policy_engine::Mode::Enforce,
            observe_would_have: None,
            audit_body: None,
        }
    }

    #[test]
    fn insert_proxy_headers_round_trip_carries_request_pca_and_policy() {
        // First positive test for calendar's helper (gmail + drive had
        // their own; calendar was the gap). Pin the three-header round
        // trip the dashboard's "calendar request inspector" panel reads.
        let mut h = HeaderMap::new();
        let req = Uuid::new_v4();
        let pca = Uuid::new_v4();
        insert_proxy_headers(&mut h, req, &outcome_with(Some("cal-policy")), pca);
        assert_eq!(
            h.get("x-proxilion-request-id").unwrap().to_str().unwrap(),
            req.to_string()
        );
        assert_eq!(
            h.get("x-proxilion-pca-id").unwrap().to_str().unwrap(),
            pca.to_string()
        );
        assert_eq!(
            h.get("x-proxilion-policy").unwrap().to_str().unwrap(),
            "cal-policy"
        );
    }

    #[test]
    fn insert_proxy_headers_omits_policy_header_when_no_match() {
        // Calendar paths can also surface `matched_policy_id: None` (e.g.
        // a default-allow read with no matching policy); the helper must
        // skip the policy header rather than emit an empty value.
        let mut h = HeaderMap::new();
        insert_proxy_headers(&mut h, Uuid::nil(), &outcome_with(None), Uuid::nil());
        assert!(h.contains_key("x-proxilion-request-id"));
        assert!(h.contains_key("x-proxilion-pca-id"));
        assert!(!h.contains_key("x-proxilion-policy"));
    }

    #[test]
    fn insert_proxy_headers_skips_invalid_header_value_silently() {
        // Defense against a policy id with non-visible-ASCII bytes — must
        // drop the header gracefully via `if let Ok(v)` rather than
        // panicking the response path. Mirrors the same defense in drive
        // + gmail — three identical helpers that must drift together.
        let mut h = HeaderMap::new();
        insert_proxy_headers(
            &mut h,
            Uuid::nil(),
            &outcome_with(Some("bad\nid")),
            Uuid::nil(),
        );
        assert!(h.contains_key("x-proxilion-request-id"));
        assert!(!h.contains_key("x-proxilion-policy"));
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

    #[test]
    fn domain_of_filters_empty_after_trim_unlike_gmail_variant() {
        // Calendar's domain_of has an extra `.filter(|s| !s.is_empty())` step
        // that gmail's omits — the bare `@` case lands as None here. Pin
        // this divergence so a refactor that "unified" the two helpers
        // doesn't silently change either contract; calendar's external_
        // attendee gate depends on `domain_of` returning None (not Some(""))
        // so the empty-domain attendee never flips `external_attendee`.
        assert_eq!(domain_of("@"), None);
        assert_eq!(domain_of(""), None);
        // Whitespace-only domain half also collapses to None via the filter.
        assert_eq!(domain_of("alice@   "), None);
    }

    #[test]
    fn urlencoding_passes_unreserved_through_and_encodes_path_set_members() {
        // The PATH set encodes ` ` `/` `?` `#` `&` `%` and CONTROLS. Walk
        // each reserved byte individually to pin the per-byte mapping —
        // a refactor that dropped `&` (e.g. a copy-paste from a query-
        // string encoder) would silently break calendar IDs containing
        // `&` against Google's path parser.
        assert_eq!(urlencoding(" "), "%20");
        assert_eq!(urlencoding("/"), "%2F");
        assert_eq!(urlencoding("?"), "%3F");
        assert_eq!(urlencoding("#"), "%23");
        assert_eq!(urlencoding("&"), "%26");
        assert_eq!(urlencoding("%"), "%25");
        // Unreserved per RFC 3986 stays raw; the `@` is intentionally NOT
        // in the PATH set since calendar IDs are typically email-shaped.
        assert_eq!(urlencoding("ABCabc0-9._~@:"), "ABCabc0-9._~@:");
    }

    #[test]
    fn urlencoding_handles_multibyte_utf8_and_empty_input() {
        // `utf8_percent_encode` walks UTF-8 byte-by-byte; pin that a
        // multibyte codepoint gets each of its bytes encoded (the
        // CONTROLS+PATH set covers the high-bit byte range implicitly via
        // CONTROLS = ascii 0..=0x1F + 0x7F, but `é` (0xC3 0xA9) bytes are
        // outside CONTROLS — they stay raw). Pin both: empty in / empty
        // out, and multibyte passthrough.
        assert_eq!(urlencoding(""), "");
        assert_eq!(urlencoding("résumé"), "r%C3%A9sum%C3%A9");
    }

    #[test]
    fn body_ctx_visibility_absent_renders_no_visibility_key() {
        // The `if let Some(v) = event.get("visibility")` branch must NOT
        // insert `visibility: null` — the policy engine's `body.visibility`
        // lookup differentiates "key absent" from "key present with null"
        // and an empty-string fallback would silently match `visibility ==
        // ""` rules. The no_attendees test asserts this implicitly; this
        // test isolates the contract directly.
        let ev = json!({
            "summary": "hold",
            "attendees": [{"email": "alice@acme.com"}],
        });
        let ctx = build_event_body_ctx(&ev, "acme.com");
        assert!(
            !ctx.contains_key("visibility"),
            "visibility key must be absent when source field is missing"
        );
        // summary_present still true since `summary` was provided.
        assert_eq!(ctx.get("summary_present"), Some(&Value::Bool(true)));
    }

    #[test]
    fn body_ctx_summary_absent_renders_false_not_missing_key() {
        // Asymmetric with visibility: `summary_present` is ALWAYS inserted
        // (the policy engine's external-meeting rule reads this as a hard
        // boolean), with `false` when the source is missing. A refactor
        // that "unified" both fields into the visibility-style absent-key
        // pattern would surface here as a missing key + downstream None
        // → false coercion, hiding the explicit contract.
        let ev = json!({
            "attendees": [{"email": "alice@acme.com"}],
        });
        let ctx = build_event_body_ctx(&ev, "acme.com");
        assert_eq!(ctx.get("summary_present"), Some(&Value::Bool(false)));
    }

    #[test]
    fn enforce_pre_request_decision_allow_returns_ok_for_calendar() {
        // First test on enforce_pre_request_decision in the calendar
        // adapter — drive + gmail each have their own coverage of this
        // helper (drive: Allow/Block/RequireConfirmation/RateLimit;
        // gmail: Block/RequireConfirmation), but calendar's was the
        // gap. The three helpers are byte-identical match expressions
        // — without coverage they could drift independently on the
        // next refactor that touched only one. Pin all four arms here
        // so calendar's contract moves in lockstep with its siblings.
        let r = enforce_pre_request_decision(&outcome_with(Some("any")));
        assert!(r.is_ok(), "Allow must surface Ok, got {r:?}");
    }

    #[test]
    fn enforce_pre_request_decision_block_carries_policy_id_reason_and_override_for_calendar() {
        // Pin all three fields preserved through the `Decision::Block`
        // → `AppError::PolicyBlocked` translation. A refactor that
        // dropped any single field on the calendar arm (a copy-paste
        // bug from drive that forgot to copy `override_allowed`, say)
        // would silently change the dashboard's "this block is
        // overridable" indicator on every calendar deny.
        let mut o = outcome_with(Some("cal-deny"));
        o.decision = Decision::Block {
            reason: "external attendee".into(),
            override_allowed: true,
        };
        let err = enforce_pre_request_decision(&o).unwrap_err();
        match err {
            AppError::PolicyBlocked {
                policy_id,
                reason,
                override_allowed,
            } => {
                assert_eq!(policy_id.as_deref(), Some("cal-deny"));
                assert_eq!(reason, "external attendee");
                assert!(override_allowed);
            }
            other => panic!("expected PolicyBlocked, got {other:?}"),
        }
    }

    #[test]
    fn enforce_pre_request_decision_require_confirmation_carries_reason_for_calendar() {
        // The agent SDK reads the reason string out of the body's
        // `detail` field to surface a confirmation prompt to the
        // operator. A regression that swapped the inner String for the
        // empty string (a "redact for privacy" change) would silently
        // strip the operator's reason from every calendar confirm
        // prompt — pin the round-trip directly.
        let mut o = outcome_with(Some("any"));
        o.decision = Decision::RequireConfirmation {
            reason: "review external event invite".into(),
        };
        let err = enforce_pre_request_decision(&o).unwrap_err();
        match err {
            AppError::RequireConfirmation(r) => {
                assert_eq!(r, "review external event invite");
            }
            other => panic!("expected RequireConfirmation, got {other:?}"),
        }
    }

    #[test]
    fn enforce_pre_request_decision_rate_limit_returns_app_error_for_calendar() {
        // The fourth arm — pin `Decision::RateLimit { .. }` → bare
        // `AppError::RateLimit` (no inner field, intentional: the
        // rate-limit body surface deliberately hides current-window
        // counts from abusers per spec.md §3.4). A refactor that
        // passed the rate-limit reason through to AppError would
        // silently start leaking server state into agent error bodies.
        let mut o = outcome_with(Some("any"));
        o.decision = Decision::RateLimit {
            burst: 5,
            per_seconds: 60,
        };
        let err = enforce_pre_request_decision(&o).unwrap_err();
        assert!(
            matches!(err, AppError::RateLimit),
            "expected AppError::RateLimit, got {err:?}"
        );
    }

    #[test]
    fn body_ctx_external_attendee_case_insensitive_against_customer_domain() {
        // The external check uses `eq_ignore_ascii_case`; pin that an
        // attendee at `ALICE@Acme.COM` against `customer_domain: "acme.com"`
        // does NOT flip external_attendee. The `domain_of` lowercase normalizer
        // makes this case-insensitive on its own, but the symmetric guard
        // on `customer_domain` ensures the operator-configured domain can
        // be mixed-case in the YAML without silently flagging every internal
        // recipient as external.
        let ev = json!({
            "attendees": [{"email": "Alice@Acme.COM"}],
        });
        let ctx = build_event_body_ctx(&ev, "ACME.COM");
        assert_eq!(ctx.get("external_attendee"), Some(&Value::Bool(false)));
        // attendee_domains is lowercased post-de-dup.
        let domains = ctx.get("attendee_domains").unwrap().as_array().unwrap();
        let s: Vec<&str> = domains.iter().filter_map(|d| d.as_str()).collect();
        assert_eq!(s, vec!["acme.com"]);
    }

    #[test]
    fn max_body_constant_is_ten_mebibytes_byte_exact_parity_with_drive_adapter() {
        // spec.md §5.5 — every Google adapter (drive + calendar + gmail)
        // shares the same 10 MiB upstream-body budget. Drive's round-166
        // pin walks the byte-exact value on its module-local MAX_BODY;
        // calendar is a deliberate parallel and a drift between the two
        // (e.g. a calendar-only refactor to 5 MiB "for shorter timeouts")
        // would silently shift the budget below the per-vendor median
        // for one adapter only. Pin byte-exact value AND const-block > 0
        // AND usize type-tag — symmetric to drive's pin.
        assert_eq!(MAX_BODY, 10 * 1024 * 1024);
        assert_eq!(MAX_BODY, 10_485_760);
        const _MAX_BODY_POSITIVE: () = assert!(MAX_BODY > 0);
        const _MAX_IS_USIZE: usize = MAX_BODY;
        assert_eq!(_MAX_IS_USIZE, 10_485_760);
    }

    #[test]
    fn max_event_json_constant_is_one_mebibyte_byte_exact_for_google_calendar_upstream_cap() {
        // Google Calendar's published upstream cap on event JSON is ~1 MiB
        // (see module docstring); the proxy surfaces the limit BEFORE the
        // upstream call so operators see a structured 413 rather than an
        // opaque Google 4xx. The constant is calendar-specific (drive
        // doesn't have it; the read endpoints don't accept agent bodies)
        // — pin byte-exact value AND `MAX_EVENT_JSON < MAX_BODY`
        // (otherwise the per-event cap would never trip; the body cap
        // would always win first).
        assert_eq!(MAX_EVENT_JSON, 1024 * 1024);
        assert_eq!(MAX_EVENT_JSON, 1_048_576);
        const _MAX_EVENT_JSON_POSITIVE: () = assert!(MAX_EVENT_JSON > 0);
        // Relationship invariant: per-event cap strictly tighter than
        // overall body cap so the structured 413 surfaces with the
        // event-specific message.
        const _EVENT_TIGHTER_THAN_BODY: () = assert!(MAX_EVENT_JSON < MAX_BODY);
        assert_eq!(MAX_BODY / MAX_EVENT_JSON, 10);
    }

    #[test]
    fn domain_of_preserves_multibyte_unicode_in_domain_part_verbatim() {
        // `domain_of` calls `.to_ascii_lowercase().trim()` — ASCII letters
        // get lowercased but multibyte unicode (`café`, `日本`) passes
        // through unchanged. The existing module pins ASCII-only domain
        // lowercasing (`Bob@Example.COM` → `example.com`) but never the
        // multibyte case. A refactor to `.to_lowercase()` (locale-aware
        // unicode lowercase) "for stricter normalization" would silently
        // mangle non-ASCII domains — e.g. `İSTANBUL.tr` lowercases under
        // Turkish locale to `istanbul.tr` AND under en-US to `i̇stanbul.tr`
        // (with a combining dot above U+0307). Pin byte-equal verbatim
        // passthrough for a multibyte domain.
        assert_eq!(
            domain_of("user@café.com").as_deref(),
            Some("café.com"),
            "multibyte é must pass through unchanged",
        );
        // ASCII case still lowered on the same input.
        assert_eq!(
            domain_of("user@CAFÉ.com").as_deref(),
            Some("cafÉ.com"),
            "ASCII C/A/F lowered but É (non-ASCII) preserved verbatim per to_ascii_lowercase contract",
        );
        // Cross-script: Japanese.
        assert_eq!(
            domain_of("alice@日本.jp").as_deref(),
            Some("日本.jp"),
            "Japanese characters must pass through unchanged",
        );
    }

    #[test]
    fn urlencoding_preserves_at_sign_and_dot_verbatim_for_email_shaped_calendar_ids() {
        // Google Calendar IDs are typically email-shaped (`primary`,
        // `alice@org.com`, hex strings). The PATH AsciiSet encodes
        // `' '`, `/`, `?`, `#`, `&`, `%` — but explicitly NOT `@` or
        // `.`. A refactor that switched to `percent_encoding::NON_ALPHANUMERIC`
        // (a stricter set) would silently encode `@` as `%40` and
        // break every email-shaped calendar ID at the Google upstream
        // (which expects `alice@org.com` byte-equal in the path).
        // Pin `@` + `.` + alphanum verbatim passthrough.
        assert_eq!(urlencoding("alice@org.com"), "alice@org.com");
        assert_eq!(urlencoding("primary"), "primary");
        assert_eq!(urlencoding("abc123"), "abc123");
        // Hex strings (the other common calendar-id shape) survive byte-equal.
        assert_eq!(
            urlencoding("0123456789abcdef0123456789abcdef"),
            "0123456789abcdef0123456789abcdef",
        );
        // And the reserved chars ARE still encoded.
        assert_eq!(urlencoding("a/b"), "a%2Fb");
        assert_eq!(urlencoding("a?b"), "a%3Fb");
    }

    #[test]
    fn urlencoding_encodes_percent_sign_to_prevent_double_decode_on_google_upstream() {
        // The PATH AsciiSet explicitly includes `%` — without this, a
        // calendar id that legitimately contained `%` (e.g. from a prior
        // double-encode upstream) would be ambiguous at Google's path
        // parser (it would attempt to decode `%XX` as a hex escape). Pin
        // that `%` is ALWAYS encoded as `%25` AND that a literal `%2F`
        // surface in an input is itself further encoded to `%252F` (the
        // helper is NOT idempotent — this is the safety contract; a
        // refactor dropping `%` from the encode set "to avoid double-
        // encoding" would silently let `%2F` flow through and be decoded
        // to `/` by Google's path parser, opening a path-traversal vector).
        assert_eq!(urlencoding("%"), "%25");
        assert_eq!(urlencoding("a%b"), "a%25b");
        // Non-idempotency: applying twice produces double-encoded output.
        let once = urlencoding("a/b");
        assert_eq!(once, "a%2Fb");
        let twice = urlencoding(&once);
        assert_eq!(twice, "a%252Fb", "double-encode must produce %25 prefix");
    }

    #[test]
    fn enforce_pre_request_decision_block_preserves_reason_string_multibyte_unicode_verbatim() {
        // Symmetric to round-166 google_drive.rs PolicyBlocked.reason
        // multibyte pin extended to calendar adapter. The existing
        // calendar pin (round-66) walks ASCII-only reasons; a refactor
        // applying `.to_ascii_lowercase()` "for SIEM hygiene" on the
        // calendar arm alone would silently mangle non-English reasons
        // and split the dashboard's "blocked-by-policy" bucket between
        // calendar and drive on the same multibyte input.
        let reason: String = "外部参加者ブロック café→🔥".into();
        let err = enforce_pre_request_decision(&Outcome {
            matched_policy_id: Some("cal-external-attendee-gate".into()),
            decision: Decision::Block {
                reason: reason.clone(),
                override_allowed: true,
            },
            required_ops: policy_engine::OpsExpression::default(),
            read_filter: None,
            pic_mode: policy_engine::PicMode::Audit,
            mode: policy_engine::Mode::Enforce,
            observe_would_have: None,
            audit_body: None,
        })
        .unwrap_err();
        match err {
            AppError::PolicyBlocked {
                reason: out_reason,
                policy_id,
                override_allowed,
            } => {
                assert_eq!(
                    out_reason, reason,
                    "multibyte reason must pass through byte-equal"
                );
                assert_eq!(policy_id.as_deref(), Some("cal-external-attendee-gate"));
                assert!(override_allowed);
            }
            other => panic!("expected PolicyBlocked, got {other:?}"),
        }
    }

    #[test]
    fn calendar_request_field_count_pinned_at_exactly_seven_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the CalendarRequest struct field count at exactly 7
        // via exhaustive destructure (no `..`). The 7 fields are:
        // action (String) + upstream_path (String) + method
        // (Method) + policy_path (HashMap) + query (HashMap) +
        // body_for_policy (HashMap) + upstream_body
        // (Option<Vec<u8>>). A 8th field landing (e.g.
        // `upstream_content_type: Option<String>` symmetric with
        // the gmail adapter — currently calendar hardcodes
        // application/json at every call site, which is the
        // intentional simplification; lifting it would silently
        // change the adapter contract) would extend the
        // adapter→policy-engine handoff AND silently change what
        // every calendar handler assembles per request. Pin via
        // exhaustive destructure.
        let v = CalendarRequest {
            action: String::new(),
            upstream_path: String::new(),
            method: Method::GET,
            policy_path: std::collections::HashMap::new(),
            query: std::collections::HashMap::new(),
            body_for_policy: std::collections::HashMap::new(),
            upstream_body: None,
        };
        let CalendarRequest {
            action: _,
            upstream_path: _,
            method: _,
            policy_path: _,
            query: _,
            body_for_policy: _,
            upstream_body: _,
        } = v;
    }

    #[test]
    fn enforce_pre_request_decision_signature_pinned_via_fn_pointer_witness() {
        // Pin enforce_pre_request_decision signature as
        // `fn(&Outcome) -> Result<(), AppError>` via fn-pointer
        // witness. Symmetric to round-273 drive + round-274
        // gmail pins extended to the calendar adapter — the 3
        // Google adapters carry IDENTICAL dispatch signatures;
        // pinning each catches per-adapter drift refactor in
        // lockstep across the 3 sibling files.
        let _f: fn(&Outcome) -> Result<(), AppError> = enforce_pre_request_decision;
    }

    #[test]
    fn insert_proxy_headers_signature_pinned_via_fn_pointer_witness() {
        // Pin insert_proxy_headers signature symmetric to round-273
        // drive + round-274 gmail pins. The 3 Google adapters
        // share the same header-insertion helper signature — a
        // drift in one would silently introduce a per-adapter
        // header contract mismatch breaking the dashboard's
        // per-request inspector panel which displays headers
        // identically across all 3 vendors.
        use axum::http::HeaderMap;
        let _f: fn(&mut HeaderMap, Uuid, &Outcome, Uuid) = insert_proxy_headers;
    }

    #[test]
    fn urlencoding_signature_pinned_via_fn_pointer_witness() {
        // Pin urlencoding signature as `fn(&str) -> String` via
        // fn-pointer witness. The helper takes the input by
        // BORROW (callers pass borrowed slices into the calendar
        // event-id / calendar-id path params) and returns owned
        // bytes. A refactor to `fn(String) -> String` "for
        // consume-and-format clarity" would force every call site
        // to box the borrowed path-param string. A refactor to
        // `Cow<'_, str>` return "to avoid the per-call allocation
        // on the no-encoding-needed fast path" would tie the
        // return lifetime to the input slice and force lifetime
        // parameters on the upstream-path assembly site.
        let _f: fn(&str) -> String = urlencoding;
    }

    #[test]
    fn build_event_body_ctx_signature_pinned_via_fn_pointer_witness() {
        // Pin build_event_body_ctx signature as
        // `fn(&Value, &str) -> HashMap<String, Value>` via
        // fn-pointer witness. The function takes the event JSON
        // BORROW + customer_domain BORROW and returns an OWNED
        // HashMap (the policy-engine RequestContext.body field
        // owns its map per-request). A refactor to
        // `fn(Value, &str)` consuming the event "for ownership
        // symmetry" would silently force every call site to
        // clone the parsed JSON. A refactor to a borrowed-Value
        // map return would tie lifetimes to the inputs in a way
        // the policy_engine handoff can't satisfy.
        let _f: fn(&Value, &str) -> std::collections::HashMap<String, Value> = build_event_body_ctx;
    }

    #[test]
    fn domain_of_signature_pinned_via_fn_pointer_witness() {
        // Pin domain_of signature as `fn(&str) -> Option<String>`
        // via fn-pointer witness. The 3 Google adapters all carry
        // a `domain_of` helper but calendar's variant has the
        // load-bearing `.filter(!is_empty)` divergence (the gmail
        // sibling does NOT filter empty domains, per the
        // round-38 pin). Pin the calendar shape directly so a
        // unification refactor that aligned the two helpers
        // would surface here as well as at the gmail-side
        // divergence pin. The owned `Option<String>` return is
        // load-bearing — a `Option<&str>` refactor would tie
        // the return lifetime to the input email slice.
        let _f: fn(&str) -> Option<String> = domain_of;
    }

    // ─────────────────────────────────────────────────────────────────────
    // DB-backed adapter integration test (opt-in via PROXILION_TEST_DATABASE_URL).
    // Skips when no test DB — see test_support.
    // ─────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn db_backed_calendar_insert_external_attendee_is_blocked_403() {
        // The Calendar adapter's distinguishing path: a WRITE gate. spec.md §9
        // calendar-external-attendee-gate blocks `events.insert` whenever an
        // attendee's domain isn't the customer's. The block lands at Layer B
        // (before any mint / upstream POST) → PolicyBlocked (403) + a
        // `layer='policy'` blocked_actions row. Decided purely on the exposed
        // body context (`body.external_attendee`), so no Trust Plane / Google
        // is contacted. Mirrors the Gmail external-send gate for the third
        // adapter, completing the trio's integration coverage.
        let Some(pool) = crate::test_support::pool().await else {
            eprintln!("skipping: {} unset", crate::test_support::TEST_DB_ENV);
            return;
        };
        use std::collections::HashMap;

        let leaf_pca_id = Uuid::new_v4();
        crate::test_support::seed_pca_cache(&pool, leaf_pca_id, "alice@acme.com").await;

        let policy_yaml = r#"
- id: calendar-external-attendee-gate
  vendor: google
  action: calendar.events.insert
  match:
    body.external_attendee:
      equals: true
  decision: block
  override: requires_justification
  pic_mode: runtime-gate
"#;
        // Dead Trust Plane / Google URLs — the gate must block before either.
        let state = crate::test_support::adapter_state(
            pool.clone(),
            policy_yaml,
            "http://127.0.0.1:1".into(),
            "http://127.0.0.1:1".into(),
        );
        let session = crate::test_support::mock_session(leaf_pca_id, "alice@acme.com");

        let before: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM blocked_actions WHERE layer = 'policy' AND policy_id = 'calendar-external-attendee-gate'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let mut body_for_policy = HashMap::new();
        body_for_policy.insert("external_attendee".to_string(), Value::Bool(true));
        body_for_policy.insert(
            "attendee_domains".to_string(),
            Value::Array(vec![Value::String("othercorp.example".into())]),
        );
        let err = proxy_request(
            &state,
            &session,
            CalendarRequest {
                action: "calendar.events.insert".into(),
                upstream_path: "/calendar/v3/calendars/primary/events".into(),
                method: Method::POST,
                policy_path: HashMap::new(),
                query: HashMap::new(),
                body_for_policy,
                upstream_body: None,
            },
        )
        .await
        .expect_err("an external attendee must be blocked");

        assert!(
            matches!(err, AppError::PolicyBlocked { .. }),
            "expected PolicyBlocked, got: {err:?}",
        );
        assert_eq!(err.status(), StatusCode::FORBIDDEN, "must map to 403");
        match &err {
            AppError::PolicyBlocked {
                policy_id,
                override_allowed,
                ..
            } => {
                assert_eq!(
                    policy_id.as_deref(),
                    Some("calendar-external-attendee-gate")
                );
                assert!(
                    override_allowed,
                    "gate declares override: requires_justification"
                );
            }
            other => panic!("expected PolicyBlocked, got {other:?}"),
        }

        let after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM blocked_actions WHERE layer = 'policy' AND policy_id = 'calendar-external-attendee-gate'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            after,
            before + 1,
            "a Layer-B blocked_actions row must be persisted"
        );
    }
}
