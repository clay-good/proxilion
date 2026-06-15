//! Google Gmail adapter (`/google/gmail/v1/...`).
//!
//! Authority: spec.md §2.1. Three routes — `send`, `list`, `get` — share the
//! same template as `google_drive::proxy_request`: build a `RequestContext`,
//! evaluate Layer B (policy), mint a PCA_2 successor with the narrowed ops
//! (Layer A), forward to Google, apply the read filter on reads, publish the
//! action event.
//!
//! The novelty over Drive is the **send** path: it parses the RFC 2822 body
//! out of the `{ "raw": "<base64url>" }` payload, extracts recipient domains
//! plus subject + attachment count, and exposes them under `body.*` so the
//! policy engine can implement the gmail-external-send-gate per spec.md §9.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap};
use axum::http::{HeaderName, HeaderValue, Method, Response, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::{URL_SAFE as B64URL, URL_SAFE_NO_PAD as B64URL_NP};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use serde::{Deserialize, Serialize};
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
/// Hard cap on the raw RFC2822 payload from agents. Gmail itself caps at
/// 35MB with attachments; we refuse anything past 10MB at the proxy.
const MAX_RAW_MIME: usize = 10 * 1024 * 1024;

pub fn router(state: AdapterState) -> Router {
    Router::new()
        .route(
            "/google/gmail/v1/users/me/messages/send",
            post(send_message),
        )
        .route("/google/gmail/v1/users/me/messages", get(list_messages))
        .route("/google/gmail/v1/users/me/messages/{id}", get(get_message))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct SendBody {
    /// base64url (with or without padding) of the RFC 2822 message.
    raw: String,
}

#[derive(Debug, Serialize)]
struct SendUpstreamBody<'a> {
    raw: &'a str,
}

#[instrument(skip(state, session, body))]
async fn send_message(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Json(body): Json<SendBody>,
) -> Result<Response<axum::body::Body>, AppError> {
    // Decode raw RFC 2822 and extract recipient + subject + attachment info.
    if body.raw.len() > MAX_RAW_MIME * 4 / 3 + 16 {
        return Err(AppError::Internal(
            "gmail send: raw payload exceeds 10MB cap".into(),
        ));
    }
    let raw_bytes = decode_b64url(&body.raw)
        .map_err(|e| AppError::Internal(format!("gmail send: bad base64url: {e}")))?;
    if raw_bytes.len() > MAX_RAW_MIME {
        return Err(AppError::Internal(
            "gmail send: decoded payload exceeds 10MB cap".into(),
        ));
    }
    let parsed = parse_mime(&raw_bytes)
        .map_err(|e| AppError::Internal(format!("gmail send: parse failure: {e}")))?;

    let body_ctx = build_send_body_ctx(&parsed, &state.customer_domain, session.p_0.as_str());

    proxy_request(
        &state,
        &session,
        GmailRequest {
            action: "gmail.messages.send".into(),
            upstream_path: "/gmail/v1/users/me/messages/send".into(),
            method: Method::POST,
            policy_path: HashMap::new(),
            query: HashMap::new(),
            body_for_policy: body_ctx,
            // Re-serialize the raw payload — we never trust round-trip of the
            // mailparse output (it normalizes headers). Forward exactly what
            // the agent sent.
            upstream_body: Some(
                serde_json::to_vec(&SendUpstreamBody { raw: &body.raw })
                    .map_err(|e| AppError::Internal(e.to_string()))?,
            ),
            upstream_content_type: Some("application/json".into()),
        },
    )
    .await
}

#[instrument(skip(state, session, query))]
async fn list_messages(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response<axum::body::Body>, AppError> {
    proxy_request(
        &state,
        &session,
        GmailRequest {
            action: "gmail.messages.list".into(),
            upstream_path: "/gmail/v1/users/me/messages".into(),
            method: Method::GET,
            policy_path: HashMap::new(),
            query,
            body_for_policy: HashMap::new(),
            upstream_body: None,
            upstream_content_type: None,
        },
    )
    .await
}

#[instrument(skip(state, session, query))]
async fn get_message(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Path(msg_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response<axum::body::Body>, AppError> {
    let mut policy_path = HashMap::new();
    policy_path.insert("id".to_string(), msg_id.clone());
    proxy_request(
        &state,
        &session,
        GmailRequest {
            action: "gmail.messages.get".into(),
            upstream_path: format!(
                "/gmail/v1/users/me/messages/{}",
                super::encoded_segment("google", &msg_id)
            ),
            method: Method::GET,
            policy_path,
            query,
            body_for_policy: HashMap::new(),
            upstream_body: None,
            upstream_content_type: None,
        },
    )
    .await
}

struct GmailRequest {
    action: String,
    upstream_path: String,
    method: Method,
    policy_path: HashMap<String, String>,
    query: HashMap<String, String>,
    /// Body fields the adapter chose to expose to the policy engine
    /// (default-deny per spec.md §5.4).
    body_for_policy: HashMap<String, Value>,
    /// Optional bytes to send upstream verbatim (for `send`).
    upstream_body: Option<Vec<u8>>,
    upstream_content_type: Option<String>,
}

async fn proxy_request(
    state: &AdapterState,
    session: &std::sync::Arc<crate::session::SessionContext>,
    req: GmailRequest,
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
        let (layer_label, detail_str) = match &e {
            AppError::PolicyBlocked { .. } => ("policy", format!("{e}")),
            AppError::RequireConfirmation(_) => ("policy", "require_confirmation".to_string()),
            _ => ("policy", format!("{e}")),
        };
        if matches!(
            e,
            AppError::PolicyBlocked { .. } | AppError::RequireConfirmation(_)
        ) {
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
                    layer: layer_label,
                    policy_id: outcome.matched_policy_id.as_deref(),
                    detail: Some(&detail_str),
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
        if let Some(ct) = req.upstream_content_type.as_deref() {
            builder = builder.header(CONTENT_TYPE, ct);
        }
        builder = builder.body(b.clone());
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

    // Read filter — only for read paths.
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
                "to_domain": ctx.body.get("to_domain"),
                "to_domains": ctx.body.get("to_domains"),
                "external_recipient": ctx.body.get("external_recipient"),
                "recipient_count": ctx.body.get("recipient_count"),
                "attachment_count": ctx.body.get("attachment_count"),
                "pic_audit_violation": audit_violation_detail,
            }),
        })
        .await;

    info!(
        request_id = %request_id,
        action = %req.action,
        status = status.as_u16(),
        pca2_id = %pca2_id,
        "proxied gmail request"
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
    req: &GmailRequest,
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

// ============ body parsing ============

#[derive(Debug, Default)]
struct ParsedSend {
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    subject: Option<String>,
    attachment_count: usize,
    body_text_preview: Option<String>,
}

fn decode_b64url(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // Gmail's `raw` is base64url; padding is optional. Try padded first,
    // fall back to no-pad.
    B64URL.decode(s).or_else(|_| B64URL_NP.decode(s))
}

fn parse_mime(raw: &[u8]) -> Result<ParsedSend, mailparse::MailParseError> {
    let parsed = mailparse::parse_mail(raw)?;
    let mut out = ParsedSend::default();
    for header in parsed.get_headers() {
        let key = header.get_key();
        let value = header.get_value();
        match key.to_ascii_lowercase().as_str() {
            "to" => out.to.extend(split_addresses(&value)),
            "cc" => out.cc.extend(split_addresses(&value)),
            "bcc" => out.bcc.extend(split_addresses(&value)),
            "subject" => out.subject = Some(value),
            _ => {}
        }
    }
    // Count attachments + capture a preview of the first text/plain part.
    count_parts(&parsed, &mut out);
    Ok(out)
}

fn count_parts(part: &mailparse::ParsedMail<'_>, out: &mut ParsedSend) {
    if part.subparts.is_empty() {
        let ct = part.ctype.mimetype.to_ascii_lowercase();
        let disposition: String = part
            .get_headers()
            .into_iter()
            .find(|h: &&mailparse::MailHeader<'_>| {
                h.get_key().eq_ignore_ascii_case("Content-Disposition")
            })
            .map(|h: &mailparse::MailHeader<'_>| h.get_value().to_ascii_lowercase())
            .unwrap_or_default();
        if disposition.starts_with("attachment") {
            out.attachment_count += 1;
            return;
        }
        if ct.starts_with("text/plain") && out.body_text_preview.is_none() {
            if let Ok(body) = part.get_body() {
                let preview: String = body.chars().take(512).collect();
                out.body_text_preview = Some(preview);
            }
        }
    } else {
        for sub in &part.subparts {
            count_parts(sub, out);
        }
    }
}

/// Split a comma-separated address list into bare email addresses.
/// Handles `"Name" <addr@host>` and bare `addr@host` and groups (`undisclosed:;`).
fn split_addresses(value: &str) -> Vec<String> {
    // mailparse::addrparse handles RFC 5322 properly.
    if let Ok(list) = mailparse::addrparse(value) {
        let mut out = Vec::new();
        for info in list.iter() {
            match info {
                mailparse::MailAddr::Single(s) => out.push(s.addr.clone()),
                mailparse::MailAddr::Group(g) => {
                    for m in &g.addrs {
                        out.push(m.addr.clone());
                    }
                }
            }
        }
        return out;
    }
    // Fail-closed on a parse error. `addrparse` rejects RFC-5322-malformed
    // header values (unbalanced quotes, dangling angle brackets, unterminated
    // groups), but Gmail's own parser is more lenient and may still *route*
    // such a header. We forward `body.raw` to Gmail verbatim, so if we drop
    // the recipients here the §9 `gmail-external-send-gate` — decided on
    // `body.external_recipient`, derived from these addresses — sees an empty
    // set and fails OPEN (an external send slips through unblocked). Instead,
    // fall back to a permissive split that still surfaces any `@`-bearing
    // token, stripping address-syntax noise, so domain extraction keeps
    // flagging external recipients.
    value
        .split([',', ' ', '\t', '\r', '\n', ';', '<', '>', '"', '(', ')'])
        .map(str::trim)
        .filter(|t| t.contains('@'))
        .map(str::to_owned)
        .collect()
}

fn domain_of(email: &str) -> Option<String> {
    email
        .rsplit_once('@')
        .map(|(_, d)| d.trim().to_ascii_lowercase())
}

fn build_send_body_ctx(
    parsed: &ParsedSend,
    customer_domain: &str,
    from_p0: &str,
) -> HashMap<String, Value> {
    let mut recipients: Vec<String> = Vec::new();
    recipients.extend(parsed.to.iter().cloned());
    recipients.extend(parsed.cc.iter().cloned());
    recipients.extend(parsed.bcc.iter().cloned());

    let domains: Vec<String> = recipients
        .iter()
        .filter_map(|r| domain_of(r))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let to_domain_first = domains.first().cloned().unwrap_or_default();

    let cd = customer_domain.to_ascii_lowercase();
    let external_recipient = domains.iter().any(|d| d != &cd);

    let mut body = HashMap::new();
    body.insert(
        "to".into(),
        Value::Array(parsed.to.iter().map(|s| Value::String(s.clone())).collect()),
    );
    body.insert(
        "cc".into(),
        Value::Array(parsed.cc.iter().map(|s| Value::String(s.clone())).collect()),
    );
    body.insert(
        "bcc".into(),
        Value::Array(
            parsed
                .bcc
                .iter()
                .map(|s| Value::String(s.clone()))
                .collect(),
        ),
    );
    // `to_domain` is the FIRST unique recipient domain (alphabetical). This
    // matches the spec.md §9 example policy which compares a single value via
    // `not_in`. Multi-domain expansion is §2.2.
    body.insert("to_domain".into(), Value::String(to_domain_first));
    body.insert(
        "to_domains".into(),
        Value::Array(domains.into_iter().map(Value::String).collect()),
    );
    body.insert("external_recipient".into(), Value::Bool(external_recipient));
    body.insert(
        "recipient_count".into(),
        Value::Number((recipients.len() as u64).into()),
    );
    body.insert(
        "attachment_count".into(),
        Value::Number((parsed.attachment_count as u64).into()),
    );
    body.insert(
        "subject_present".into(),
        Value::Bool(parsed.subject.is_some()),
    );
    body.insert("from_p0".into(), Value::String(from_p0.to_owned()));
    body
}

// Quiet unused-import warnings on rarely-used types.
#[allow(dead_code)]
const _USED: (Option<Bytes>, StatusCode) = (None, StatusCode::OK);

#[cfg(test)]
mod tests {
    use super::*;

    fn build_raw(to: &str, subject: &str, body: &str) -> String {
        let raw =
            format!("To: {to}\r\nFrom: alice@acme.com\r\nSubject: {subject}\r\n\r\n{body}\r\n");
        B64URL_NP.encode(raw.as_bytes())
    }

    #[test]
    fn decode_handles_padded_and_unpadded() {
        let padded = B64URL.encode(b"hello world");
        let unpadded = B64URL_NP.encode(b"hello world");
        assert_eq!(decode_b64url(&padded).unwrap(), b"hello world");
        assert_eq!(decode_b64url(&unpadded).unwrap(), b"hello world");
    }

    #[test]
    fn parse_simple_message() {
        let raw = "To: bob@acme.com\r\nFrom: alice@acme.com\r\nSubject: hi\r\n\r\nhello\r\n";
        let p = parse_mime(raw.as_bytes()).unwrap();
        assert_eq!(p.to, vec!["bob@acme.com".to_string()]);
        assert_eq!(p.subject.as_deref(), Some("hi"));
        assert_eq!(p.attachment_count, 0);
        assert!(p.body_text_preview.as_deref().unwrap().starts_with("hello"));
    }

    #[test]
    fn parse_multiple_recipients_with_display_names() {
        let raw = "To: \"Bob\" <bob@acme.com>, eve@evilcorp.example\r\nCc: c@third.example\r\nFrom: alice@acme.com\r\nSubject: x\r\n\r\n.\r\n";
        let p = parse_mime(raw.as_bytes()).unwrap();
        assert_eq!(p.to.len(), 2);
        assert!(p.to.iter().any(|a| a == "bob@acme.com"));
        assert!(p.to.iter().any(|a| a == "eve@evilcorp.example"));
        assert_eq!(p.cc, vec!["c@third.example".to_string()]);
    }

    #[test]
    fn body_ctx_flags_external_recipient() {
        let raw_b64 = build_raw("bob@acme.com, eve@evil.example", "hi", ".");
        let raw = decode_b64url(&raw_b64).unwrap();
        let p = parse_mime(&raw).unwrap();
        let ctx = build_send_body_ctx(&p, "acme.com", "alice@acme.com");
        assert_eq!(ctx.get("external_recipient"), Some(&Value::Bool(true)));
        assert_eq!(ctx.get("recipient_count").unwrap().as_u64(), Some(2));
        let domains = ctx.get("to_domains").unwrap().as_array().unwrap();
        let strs: Vec<&str> = domains.iter().filter_map(|v| v.as_str()).collect();
        assert!(strs.contains(&"acme.com"));
        assert!(strs.contains(&"evil.example"));
    }

    #[test]
    fn body_ctx_all_internal_is_not_external() {
        let raw = "To: bob@acme.com\r\nFrom: alice@acme.com\r\nSubject: x\r\n\r\n.\r\n";
        let p = parse_mime(raw.as_bytes()).unwrap();
        let ctx = build_send_body_ctx(&p, "acme.com", "alice@acme.com");
        assert_eq!(ctx.get("external_recipient"), Some(&Value::Bool(false)));
    }

    #[test]
    fn body_ctx_attachment_count_counts_attachments() {
        // Multipart with one text part + one attachment.
        let raw = "From: alice@acme.com\r\nTo: bob@acme.com\r\nSubject: x\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"BNDRY\"\r\n\r\n--BNDRY\r\nContent-Type: text/plain\r\n\r\nbody\r\n--BNDRY\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"x.pdf\"\r\n\r\nPDF-BODY\r\n--BNDRY--\r\n";
        let p = parse_mime(raw.as_bytes()).unwrap();
        assert_eq!(p.attachment_count, 1);
    }

    #[test]
    fn malformed_b64url_is_rejected() {
        let err = decode_b64url("not-base64!@#$").unwrap_err();
        assert!(format!("{err}").contains("Invalid"));
    }

    #[test]
    fn empty_to_yields_empty_to_domain() {
        // Pathological: no To header at all.
        let raw = "From: alice@acme.com\r\nSubject: x\r\n\r\n.\r\n";
        let p = parse_mime(raw.as_bytes()).unwrap();
        let ctx = build_send_body_ctx(&p, "acme.com", "alice@acme.com");
        assert_eq!(ctx.get("to_domain"), Some(&Value::String(String::new())));
        assert_eq!(ctx.get("recipient_count").unwrap().as_u64(), Some(0));
    }

    #[test]
    fn domain_of_helper() {
        assert_eq!(
            domain_of("alice@example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            domain_of("alice@ExAmPle.COM").as_deref(),
            Some("example.com")
        );
        assert_eq!(domain_of("no-at-symbol"), None);
    }

    fn outcome(decision: Decision) -> Outcome {
        use policy_engine::{OpsExpression, PicMode};
        Outcome {
            matched_policy_id: Some("gmail-test".into()),
            decision,
            required_ops: OpsExpression::default(),
            read_filter: None,
            pic_mode: PicMode::Audit,
            mode: policy_engine::Mode::Enforce,
            observe_would_have: None,
            audit_body: None,
        }
    }

    #[test]
    fn enforce_allow_returns_ok_for_gmail_adapter() {
        // The Allow arm of enforce_pre_request_decision had no test on
        // the gmail adapter (drive has it as `enforce_allow_is_ok` —
        // this is the parity guard so a refactor that touched the
        // gmail helper alone can't silently regress the happy path).
        // A regression that mapped Allow → AppError::Internal (the
        // natural shape of an incomplete match arm expansion) would
        // 500 every gmail send.
        let r = enforce_pre_request_decision(&outcome(Decision::Allow));
        assert!(r.is_ok(), "Allow must surface Ok, got {r:?}");
    }

    #[test]
    fn enforce_rate_limit_returns_app_error_rate_limit_for_gmail() {
        // The fourth arm — `Decision::RateLimit { .. }` → bare
        // `AppError::RateLimit` (no inner field, intentional per
        // spec.md §3.4 to hide current-window counts from abusers).
        // Drive has `enforce_rate_limit`; this is the gmail parity
        // guard so a refactor that started passing the rate-limit
        // reason through to AppError on the gmail arm alone would
        // surface here.
        let err = enforce_pre_request_decision(&outcome(Decision::RateLimit {
            burst: 5,
            per_seconds: 60,
        }))
        .unwrap_err();
        assert!(
            matches!(err, AppError::RateLimit),
            "expected AppError::RateLimit, got {err:?}"
        );
    }

    #[test]
    fn enforce_block_returns_policy_blocked() {
        let e = enforce_pre_request_decision(&outcome(Decision::Block {
            reason: "external".into(),
            override_allowed: true,
        }))
        .unwrap_err();
        assert!(matches!(e, AppError::PolicyBlocked { .. }));
    }

    #[test]
    fn enforce_require_confirmation() {
        let e = enforce_pre_request_decision(&outcome(Decision::RequireConfirmation {
            reason: "review send".into(),
        }))
        .unwrap_err();
        assert!(matches!(e, AppError::RequireConfirmation(_)));
    }

    #[test]
    fn insert_proxy_headers_omits_policy_header_when_no_match() {
        // Outcomes from default-deny or read-filter paths can carry
        // `matched_policy_id: None` — the helper must skip the policy
        // header entirely (rather than emit an empty value or `(none)`),
        // since downstream Grafana panels filter by header presence to
        // separate "policy fired" from "no policy matched".
        let mut h = HeaderMap::new();
        let mut o = outcome(Decision::Allow);
        o.matched_policy_id = None;
        insert_proxy_headers(&mut h, Uuid::nil(), &o, Uuid::nil());
        assert!(h.contains_key("x-proxilion-request-id"));
        assert!(h.contains_key("x-proxilion-pca-id"));
        assert!(!h.contains_key("x-proxilion-policy"));
    }

    #[test]
    fn insert_proxy_headers_skips_invalid_header_value_silently() {
        // `HeaderValue::from_str` rejects bytes outside the visible-ASCII
        // range (e.g. newline, NUL). A policy id that smuggled one in
        // (extreme edge — operator could in principle name a policy with
        // an embedded `\n` in YAML) must not panic the response path;
        // the `if let Ok(v)` arm gracefully drops the header instead.
        let mut h = HeaderMap::new();
        let mut o = outcome(Decision::Allow);
        o.matched_policy_id = Some("bad\nid".into());
        insert_proxy_headers(&mut h, Uuid::nil(), &o, Uuid::nil());
        // request_id + pca_id still present; policy header skipped.
        assert!(h.contains_key("x-proxilion-request-id"));
        assert!(!h.contains_key("x-proxilion-policy"));
    }

    #[test]
    fn domain_of_trims_surrounding_whitespace_on_domain_half() {
        // The rsplit_once helper trims after splitting, so a stray space
        // inside `alice@ acme.com` (an LLM-generated address fragment, or
        // a hand-edited MIME header) round-trips to `acme.com` rather than
        // ` acme.com`. A regression that dropped the `.trim()` would
        // surface here as a missed match against `customer_domain`.
        assert_eq!(domain_of("alice@ acme.com  ").as_deref(), Some("acme.com"));
    }

    #[test]
    fn domain_of_returns_none_on_empty_string_and_bare_at() {
        // Defensive boundaries: empty input has no `@` so rsplit_once → None;
        // a bare `@` produces an empty-domain split, but rsplit_once treats
        // the split as `("", "")` → Some("") (lowercased empty). Pin the
        // observed contract so a refactor that filtered empty domains
        // would surface here (and would need to update the call sites in
        // build_send_body_ctx that currently rely on Some("") to round-trip).
        assert_eq!(domain_of(""), None);
        assert_eq!(domain_of("@").as_deref(), Some(""));
    }

    #[test]
    fn split_addresses_handles_group_form_and_returns_inner_addresses() {
        // RFC 5322 group form: `name:addr1,addr2;`. mailparse's addrparse
        // returns a MailAddr::Group; the helper must flatten member addrs
        // into the output rather than dropping the group. A regression
        // that handled only Single would silently drop every grouped
        // recipient on `To:` headers some MUAs emit.
        let out = split_addresses("team:bob@acme.com, eve@evil.example;");
        assert!(out.iter().any(|a| a == "bob@acme.com"), "got: {out:?}");
        assert!(out.iter().any(|a| a == "eve@evil.example"), "got: {out:?}");
    }

    #[test]
    fn split_addresses_returns_empty_on_empty_input() {
        // Pin the empty-input passthrough — addrparse on "" returns Ok with
        // no addresses, so the helper yields an empty Vec. A refactor that
        // pre-emptively errored on empty would surface here as a missing
        // "no recipients" passthrough through `build_send_body_ctx`.
        assert!(split_addresses("").is_empty());
    }

    #[test]
    fn split_addresses_fails_closed_on_unparseable_header() {
        // An unbalanced-quote header value makes mailparse::addrparse return
        // Err. Gmail's parser is more lenient and may still route it, so the
        // helper must NOT silently drop the recipient (which would let the
        // external-send gate fail open). Confirm the precondition (addrparse
        // really errors) and that the permissive fallback still surfaces the
        // `@`-bearing address so its domain can be extracted.
        let weird = "\"unterminated <bob@evil.example>";
        assert!(
            mailparse::addrparse(weird).is_err(),
            "precondition: addrparse must reject this header"
        );
        let out = split_addresses(weird);
        assert!(
            out.iter().any(|a| a == "bob@evil.example"),
            "fallback must surface the @-token, got: {out:?}"
        );
    }

    #[test]
    fn external_send_gate_is_fail_closed_on_unparseable_recipient_header() {
        // End-to-end of the §9 gmail-external-send-gate input: a To header
        // that addrparse rejects but that names an external recipient must
        // still set `external_recipient = true`. Before the fail-closed fix
        // the dropped recipient collapsed `external_recipient` to false and
        // the gate let the external send through.
        let p = ParsedSend {
            to: split_addresses("\"unterminated <bob@evil.example>"),
            ..Default::default()
        };
        let ctx = build_send_body_ctx(&p, "acme.com", "alice@acme.com");
        assert_eq!(
            ctx.get("external_recipient"),
            Some(&Value::Bool(true)),
            "unparseable external recipient must fail closed"
        );
    }

    #[test]
    fn build_send_body_ctx_dedupes_domains_via_btreeset_for_alphabetical_to_domain() {
        // Three recipients across two distinct domains; the BTreeSet collapse
        // produces a stable alphabetical `to_domain` (first key). Pin both
        // the de-dup (`to_domains.len() == 2` despite three recipients) and
        // the alphabetical-first selection — a refactor to HashSet would
        // silently break the spec.md §9 single-value `not_in` comparison
        // by randomizing which domain lands as `to_domain`.
        let raw = "To: bob@zeta.example, alice@acme.com, carol@zeta.example\r\nFrom: x@x.example\r\nSubject: x\r\n\r\n.\r\n";
        let p = parse_mime(raw.as_bytes()).unwrap();
        let ctx = build_send_body_ctx(&p, "internal.example", "x@internal.example");
        let domains = ctx.get("to_domains").unwrap().as_array().unwrap();
        let strs: Vec<&str> = domains.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(strs.len(), 2, "expected 2 unique domains, got: {strs:?}");
        assert_eq!(strs, vec!["acme.com", "zeta.example"]);
        assert_eq!(
            ctx.get("to_domain").unwrap().as_str().unwrap(),
            "acme.com",
            "to_domain must be alphabetical-first"
        );
        assert_eq!(ctx.get("recipient_count").unwrap().as_u64(), Some(3));
    }

    #[test]
    fn build_send_body_ctx_subject_present_round_trips_some_and_none() {
        // The `Subject:` header maps to `subject_present: bool`. Pin that a
        // missing Subject in the raw MIME produces `false`, and a present
        // (even empty-string) Subject produces `true` — the latter is the
        // edge case where mailparse returns `Some("")` rather than `None`,
        // and the policy author expects `subject_present` to mean "the
        // header was present" not "the value was non-empty".
        let no_subj = "From: a@x.example\r\nTo: b@y.example\r\n\r\n.\r\n";
        let p = parse_mime(no_subj.as_bytes()).unwrap();
        let ctx = build_send_body_ctx(&p, "x.example", "a@x.example");
        assert_eq!(ctx.get("subject_present"), Some(&Value::Bool(false)));

        let with_subj = "From: a@x.example\r\nTo: b@y.example\r\nSubject: hello\r\n\r\n.\r\n";
        let p2 = parse_mime(with_subj.as_bytes()).unwrap();
        let ctx2 = build_send_body_ctx(&p2, "x.example", "a@x.example");
        assert_eq!(ctx2.get("subject_present"), Some(&Value::Bool(true)));
    }

    #[test]
    fn parse_mime_carries_bcc_recipients_through_to_body_ctx() {
        // `Bcc:` was previously only exercised via the unit's overall flow,
        // never asserted on. Pin that bcc round-trips into recipient_count
        // + the bcc array, and that bcc-only recipients on an external
        // domain still flip `external_recipient`.
        let raw = "From: alice@acme.com\r\nTo: bob@acme.com\r\nBcc: spy@evil.example\r\nSubject: x\r\n\r\n.\r\n";
        let p = parse_mime(raw.as_bytes()).unwrap();
        assert_eq!(p.bcc, vec!["spy@evil.example".to_string()]);
        let ctx = build_send_body_ctx(&p, "acme.com", "alice@acme.com");
        assert_eq!(ctx.get("recipient_count").unwrap().as_u64(), Some(2));
        assert_eq!(ctx.get("external_recipient"), Some(&Value::Bool(true)));
    }

    #[test]
    fn count_parts_recurses_into_nested_multipart_attachments() {
        // multipart/mixed → multipart/related → application/pdf attachment.
        // count_parts must recurse through both wrappers and tally the
        // single attachment. A refactor that stopped at the first nesting
        // level would silently miss attachments in any mail composed by a
        // client that wrapped inline images in multipart/related.
        let raw = "From: a@x.example\r\nTo: b@x.example\r\nSubject: x\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"OUTER\"\r\n\r\n--OUTER\r\nContent-Type: multipart/related; boundary=\"INNER\"\r\n\r\n--INNER\r\nContent-Type: text/plain\r\n\r\nhi\r\n--INNER\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"x.pdf\"\r\n\r\nPDF\r\n--INNER--\r\n--OUTER--\r\n";
        let p = parse_mime(raw.as_bytes()).unwrap();
        assert_eq!(p.attachment_count, 1);
    }

    #[test]
    fn gmail_request_field_count_pinned_at_exactly_eight_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the GmailRequest struct field count at exactly 8 via
        // exhaustive destructure (no `..`). The 8 fields are:
        // action (String) + upstream_path (String) + method
        // (Method) + policy_path (HashMap) + query (HashMap) +
        // body_for_policy (HashMap) + upstream_body
        // (Option<Vec<u8>>) + upstream_content_type
        // (Option<String>). A 9th field landing (e.g.
        // `headers_for_policy: HashMap<String, String>` to narrow
        // the header set the policy engine sees beyond default-deny,
        // or `attachment_summary: Option<AttachmentSummary>` to
        // pass parsed-attachment metadata into the policy engine)
        // would silently extend the adapter→policy-engine handoff
        // contract AND silently change what every Gmail handler
        // assembles per request. Pin via exhaustive destructure
        // (the struct is private — pinned inside the module's
        // tests block).
        let v = GmailRequest {
            action: String::new(),
            upstream_path: String::new(),
            method: Method::GET,
            policy_path: std::collections::HashMap::new(),
            query: std::collections::HashMap::new(),
            body_for_policy: std::collections::HashMap::new(),
            upstream_body: None,
            upstream_content_type: None,
        };
        let GmailRequest {
            action: _,
            upstream_path: _,
            method: _,
            policy_path: _,
            query: _,
            body_for_policy: _,
            upstream_body: _,
            upstream_content_type: _,
        } = v;
    }

    #[test]
    fn send_body_field_count_pinned_at_exactly_one_via_exhaustive_destructure_no_rest_pattern() {
        // Pin the SendBody POST body field count at exactly 1 via
        // exhaustive destructure. The 1 field is: raw (String) —
        // the base64url-encoded RFC 2822 message. A 2nd field
        // landing (e.g. `thread_id: Option<String>` to thread a
        // reply, or `labels: Vec<String>` for post-send label
        // application) would silently extend the
        // `users.messages.send` POST body shape every Gmail-using
        // agent must conform to AND silently change the
        // deserialize contract. Pin via exhaustive destructure.
        let v = SendBody { raw: String::new() };
        let SendBody { raw: _ } = v;
    }

    #[test]
    fn parsed_send_field_count_pinned_at_exactly_six_via_exhaustive_destructure_no_rest_pattern() {
        // Pin the ParsedSend struct field count at exactly 6 via
        // exhaustive destructure. The 6 fields are: to + cc + bcc
        // + subject + attachment_count + body_text_preview. A 7th
        // field landing (e.g. `reply_to: Vec<String>` for a future
        // anti-spoofing policy authoring path, or `headers_seen:
        // Vec<String>` for richer policy-author visibility into the
        // MIME header set) would silently extend the parsed-MIME
        // envelope every build_send_body_ctx call site reads
        // AND silently change what fields the policy engine can
        // match on. Pin via exhaustive destructure on the Default-
        // built fixture (ParsedSend derives Default).
        let v = ParsedSend::default();
        let ParsedSend {
            to: _,
            cc: _,
            bcc: _,
            subject: _,
            attachment_count: _,
            body_text_preview: _,
        } = v;
    }

    #[test]
    fn enforce_pre_request_decision_signature_pinned_via_fn_pointer_witness() {
        // Pin enforce_pre_request_decision signature as
        // `fn(&Outcome) -> Result<(), AppError>` via fn-pointer
        // witness. Symmetric to round-273 google_drive pin
        // extended to the gmail adapter — the 3 Google adapters
        // (drive, gmail, calendar) currently carry IDENTICAL
        // signature for this dispatch function; pinning each
        // adapter's signature symmetrically catches a per-adapter
        // drift refactor in lockstep.
        let _f: fn(&Outcome) -> Result<(), AppError> = enforce_pre_request_decision;
    }

    #[test]
    fn insert_proxy_headers_signature_pinned_via_fn_pointer_witness() {
        // Pin insert_proxy_headers signature symmetric to round-273
        // google_drive pin. The 3 Google adapters share the same
        // header-insertion helper signature — a drift in one
        // would silently introduce a per-adapter header contract
        // mismatch on the response, breaking dashboard's "per-
        // request inspector" panel which displays the headers
        // identically across all 3 vendors.
        use axum::http::HeaderMap;
        let _f: fn(&mut HeaderMap, Uuid, &Outcome, Uuid) = insert_proxy_headers;
    }

    #[test]
    fn parse_mime_signature_pinned_via_fn_pointer_witness() {
        // Pin parse_mime signature as `fn(&[u8]) ->
        // Result<ParsedSend, mailparse::MailParseError>` via
        // fn-pointer witness. The function takes the decoded
        // MIME bytes by BORROW (the b64url-decoded buffer is
        // owned by the caller — `send_message` holds it across
        // the `.await` boundary) and returns an owned
        // ParsedSend with the `mailparse::MailParseError` error
        // type. A refactor to `fn(Vec<u8>) -> ...` "for
        // consume-and-cache" would silently force every call
        // site to clone the decoded buffer. A refactor to a
        // wrapping error type "to unify mail-parse + policy-
        // engine errors" would silently change the call-site
        // `?`-chain conversion.
        let _f: fn(&[u8]) -> Result<ParsedSend, mailparse::MailParseError> = parse_mime;
    }

    #[test]
    fn get_message_upstream_path_percent_encodes_the_msg_id_segment() {
        // §6.1 regression: a message id that already contains an encoded
        // slash (`..%2F..`) would, without re-encoding, decode through axum to
        // literal `../..` path traversal against the Gmail base. Mirror the
        // exact `format!` the handler uses.
        let evil = "..%2F..%2Foauth2";
        assert_eq!(
            format!(
                "/gmail/v1/users/me/messages/{}",
                super::super::path_segment(evil)
            ),
            "/gmail/v1/users/me/messages/..%252F..%252Foauth2"
        );
        let id = "18f0a1b2c3d4e5f6";
        assert_eq!(
            format!(
                "/gmail/v1/users/me/messages/{}",
                super::super::path_segment(id)
            ),
            "/gmail/v1/users/me/messages/18f0a1b2c3d4e5f6"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // DB-backed adapter integration test (opt-in via PROXILION_TEST_DATABASE_URL).
    // Skips when no test DB — see test_support.
    // ─────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn db_backed_gmail_send_external_recipient_is_blocked_403() {
        // spec.md §1.5 / §9 flagship Layer-B gate: a `gmail.messages.send` with
        // an external recipient is blocked at Layer B (before any mint or
        // upstream call) — `proxy_request` returns PolicyBlocked (403) and
        // persists a `blocked_actions` row (layer='policy') the human-in-the-
        // loop queue reads. The block is decided purely on the exposed body
        // context (`body.external_recipient`), so no Trust Plane / Google is
        // contacted.
        let Some(pool) = crate::test_support::pool().await else {
            eprintln!("skipping: {} unset", crate::test_support::TEST_DB_ENV);
            return;
        };
        use std::collections::HashMap;

        let leaf_pca_id = Uuid::new_v4();
        crate::test_support::seed_pca_cache(&pool, leaf_pca_id, "alice@acme.com").await;

        let policy_yaml = r#"
- id: gmail-external-send-gate
  vendor: google
  action: gmail.messages.send
  match:
    body.external_recipient:
      equals: true
  decision: block
  override: requires_justification
  pic_mode: runtime-gate
"#;
        // Dead Trust Plane / Google URLs — the gate must block before reaching
        // either, so neither is contacted.
        let state = crate::test_support::adapter_state(
            pool.clone(),
            policy_yaml,
            "http://127.0.0.1:1".into(),
            "http://127.0.0.1:1".into(),
        );
        let session = crate::test_support::mock_session(leaf_pca_id, "alice@acme.com");

        let before: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM blocked_actions WHERE layer = 'policy' AND policy_id = 'gmail-external-send-gate'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let mut body_for_policy = HashMap::new();
        body_for_policy.insert(
            "external_recipient".to_string(),
            serde_json::Value::Bool(true),
        );
        body_for_policy.insert(
            "to_domains".to_string(),
            serde_json::Value::Array(vec![serde_json::Value::String("evilcorp.example".into())]),
        );
        let err = proxy_request(
            &state,
            &session,
            GmailRequest {
                action: "gmail.messages.send".into(),
                upstream_path: "/gmail/v1/users/me/messages/send".into(),
                method: Method::POST,
                policy_path: HashMap::new(),
                query: HashMap::new(),
                body_for_policy,
                upstream_body: None,
                upstream_content_type: None,
            },
        )
        .await
        .expect_err("external send must be blocked");

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
                assert_eq!(policy_id.as_deref(), Some("gmail-external-send-gate"));
                assert!(
                    override_allowed,
                    "gate declares override: requires_justification"
                );
            }
            other => panic!("expected PolicyBlocked, got {other:?}"),
        }

        let after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM blocked_actions WHERE layer = 'policy' AND policy_id = 'gmail-external-send-gate'",
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
