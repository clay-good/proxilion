//! Google Drive read adapter (`/google/drive/v3/files/...`).
//!
//! Authority: spec.md §1.3. Three routes — `list`, `get`, `export` — share
//! the `proxy_request` template: build a `RequestContext`, evaluate Layer B
//! (policy), mint a PCA_2 successor with the narrowed ops (Layer A), forward
//! to Google, apply the read filter, publish the action event.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap};
use axum::http::{HeaderName, HeaderValue, Response, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use serde_json::Value;
use shared_types::provenance::pca::ExecutorBinding;
use tracing::{info, instrument};
use uuid::Uuid;

use super::action_stream::ActionEvent;
use super::error::AppError;
use super::read_filter;
use super::state::AdapterState;
use crate::pic::{CachedPca, PcaCache, SuccessorOutcome};
use crate::session::SessionCtx;
use policy_engine::{Decision, Outcome, PicMode, RequestContext, UserCtx};

/// 10 MB cap on upstream bodies — spec.md §1.3 pitfall.
const MAX_BODY: usize = 10 * 1024 * 1024;

pub fn router(state: AdapterState) -> Router {
    Router::new()
        .route("/google/drive/v3/files", get(list_files))
        .route("/google/drive/v3/files/{id}", get(get_file))
        .route("/google/drive/v3/files/{id}/export", get(export_file))
        .with_state(state)
}

#[instrument(skip(state, session, query))]
async fn list_files(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response<axum::body::Body>, AppError> {
    proxy_request(
        &state,
        &session,
        DriveRequest {
            action: "drive.files.list".into(),
            upstream_path: "/drive/v3/files".into(),
            policy_path: HashMap::new(),
            query,
            body_for_policy: HashMap::new(),
        },
    )
    .await
}

#[instrument(skip(state, session, query))]
async fn get_file(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Path(file_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response<axum::body::Body>, AppError> {
    let mut policy_path = HashMap::new();
    policy_path.insert("id".to_string(), file_id.clone());
    proxy_request(
        &state,
        &session,
        DriveRequest {
            action: "drive.files.get".into(),
            upstream_path: format!("/drive/v3/files/{}", file_id),
            policy_path,
            query,
            body_for_policy: HashMap::new(),
        },
    )
    .await
}

#[instrument(skip(state, session, query))]
async fn export_file(
    State(state): State<AdapterState>,
    SessionCtx(session): SessionCtx,
    Path(file_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response<axum::body::Body>, AppError> {
    let mut policy_path = HashMap::new();
    policy_path.insert("id".to_string(), file_id.clone());
    proxy_request(
        &state,
        &session,
        DriveRequest {
            action: "drive.files.export".into(),
            upstream_path: format!("/drive/v3/files/{}/export", file_id),
            policy_path,
            query,
            body_for_policy: HashMap::new(),
        },
    )
    .await
}

struct DriveRequest {
    action: String,
    upstream_path: String,
    policy_path: HashMap<String, String>,
    query: HashMap<String, String>,
    /// Body fields the adapter chooses to expose to the policy engine.
    /// Default-deny per spec.md §5.4: an adapter must explicitly opt in
    /// (e.g. Gmail send declares `body.to_domain`). Drive read endpoints
    /// have no body fields worth inspecting, so they leave this empty.
    body_for_policy: HashMap<String, Value>,
}

async fn proxy_request(
    state: &AdapterState,
    session: &std::sync::Arc<crate::session::SessionContext>,
    req: DriveRequest,
) -> Result<Response<axum::body::Body>, AppError> {
    let request_id = Uuid::new_v4();
    let ctx = build_policy_ctx(state, session, &req);

    let (outcome, mut policy_trace) = state.policy.load().evaluate_with_trace(&ctx)?;
    // ui-less-surfaces.md §5.7 dev 2 — per-policy escalation deadline.
    let escalation_after_minutes = outcome
        .matched_policy_id
        .as_deref()
        .and_then(|id| state.policy.load().escalation_after_minutes_for(id));
    // Compute the ops the next-hop PCA would carry. Hoisted above the Layer-B
    // gate so the block record (if we end up blocking) carries the same
    // `requested_ops` an override would re-mint with.
    let requested_ops: Vec<String> = outcome
        .required_ops
        .required
        .iter()
        .map(|a| a.to_canonical())
        .collect();

    // Layer B: policy.
    if let Err(e) = enforce_pre_request_decision(&outcome) {
        super::policy_trace::emit(&policy_trace, request_id, "google", &req.action);
        if matches!(e, AppError::PolicyBlocked { .. }) {
            crate::blocked::persist_and_notify(
                &state.auth.db,
                &state.notifier,
                crate::blocked::BlockedActionRecord {
                    request_id,
                    session_id: session.agent_session_id,
                    p_0: Some(&session.p_0),
                    vendor: "google",
                    action: &req.action,
                    method: "GET",
                    path: &req.upstream_path,
                    layer: "policy",
                    policy_id: outcome.matched_policy_id.as_deref(),
                    detail: Some(&format!("{e}")),
                    predecessor_pca_id: Some(session.leaf_pca_id),
                    requested_ops: &requested_ops,
                        escalation_after_minutes,
                },
            )
            .await;
        }
        return Err(e);
    }
    // No required_ops on the matching policy → fall back to PCA_1's ops so
    // monotonicity still holds and the chain grows by one hop per §5.4.
    let leaf_ops: Vec<String> = if requested_ops.is_empty() {
        session.granted_ops.clone()
    } else {
        requested_ops.clone()
    };

    let binding = ExecutorBinding::new()
        .with("service", "proxilion-proxy")
        .with("action", req.action.as_str())
        .with("request_id", request_id.to_string().as_str());

    let (leaf_pca_id, audit_violation_detail) = match state
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
            // Cache PCA_2 locally.
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
            // Audit mode (§2.4): persist the violation, emit metric, and
            // proceed with the predecessor PCA as the leaf. Confused-deputy
            // semantics are NOT preserved on this hop — documented trade-off.
            let missing = crate::pic::violations::parse_missing_atoms(&detail);
            crate::pic::violations::persist(
                &state.auth.db,
                crate::pic::PicViolationRecord {
                    request_id,
                    session_id: session.agent_session_id,
                    p_0: Some(&session.p_0),
                    vendor: "google",
                    action: &req.action,
                    method: "GET",
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
                    method: "GET",
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
                    method: "GET",
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
    let pca2_id = leaf_pca_id;
    // Silence dead_code on PicMode import in case adapter never imports the
    // enum at top level otherwise.
    let _ = PicMode::Audit;

    // Upstream call to Google.
    let upstream_url = format!("{}{}", state.google_api_base(), req.upstream_path);
    let upstream_resp = state
        .upstream
        .get(&upstream_url)
        .header(
            AUTHORIZATION,
            HeaderValue::try_from(format!("Bearer {}", session.google_access_token))
                .map_err(|_| AppError::Internal("bad google bearer".into()))?,
        )
        .query(&req.query)
        .send()
        .await?;
    let status = upstream_resp.status();
    let content_type = upstream_resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    let body_bytes = read_bounded(upstream_resp, MAX_BODY).await?;

    // Read filter.
    let (final_body, filter_outcome) = if let Some(filter) = outcome.read_filter.as_ref() {
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
                    method: "GET",
                    path: &req.upstream_path,
                    layer: "read_filter",
                    policy_id: outcome.matched_policy_id.as_deref(),
                    detail: Some("BlockRequest pattern matched"),
                    // Override doesn't apply to read-filter blocks: the upstream
                    // content already crossed our wire. Audit only.
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

    // Action event.
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
    // Per-policy audit-body capture (ui-less-surfaces.md §6.4). Skipped
    // entirely when `outcome.audit_body` is None — privacy default.
    if let Some(mode) = outcome.audit_body {
        crate::audit_body::persist(&state.auth.db, request_id, mode, &[], &final_body).await;
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
            method: "GET".to_string(),
            path: req.upstream_path.clone(),
            status: status.as_u16(),
            decision: decision_label.to_string(),
            block_reason: None,
            read_filter_triggered: filter_outcome.triggered,
            quarantined_count: filter_outcome.matches,
            at: Utc::now(),
            policy_id: outcome.matched_policy_id.clone(),
            extra: serde_json::json!({
                "request_path_params": req.policy_path,
                "pic_audit_violation": audit_violation_detail,
            }),
        })
        .await;

    info!(
        request_id = %request_id,
        action = %req.action,
        status = status.as_u16(),
        pca2_id = %pca2_id,
        "proxied drive request"
    );

    // Build response.
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
    req: &DriveRequest,
) -> RequestContext {
    // Default-deny body exposure (spec.md §5.4). Adapters declare which body
    // fields the policy engine can see in `req.body_for_policy`; everything
    // else stays inside the proxy and never enters the evaluation context.
    RequestContext {
        vendor: "google".into(),
        action: req.action.clone(),
        user: UserCtx {
            email: session.p_0.clone(),
            groups: vec![],
        },
        path: req.policy_path.clone(),
        body: req.body_for_policy.clone(),
        headers: Default::default(),
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
            tracing::warn!(error = %e, "failed to persist quarantine sample");
        }
    }
}

// Block-record persistence lives in `crate::blocked`. Adapters build
// `BlockedActionRecord` at the deny point and call `blocked::persist`.

// Silence the unused import on `Bytes` / `Json` / `StatusCode` if a future
// refactor moves their call sites.
#[allow(dead_code)]
const _USED: (
    Option<Bytes>,
    Option<Json<()>>,
    StatusCode,
) = (None, None, StatusCode::OK);

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use policy_engine::{OpsExpression, PicMode};

    fn outcome(decision: Decision) -> Outcome {
        Outcome {
            matched_policy_id: Some("test-policy".into()),
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
    fn enforce_allow_is_ok() {
        assert!(enforce_pre_request_decision(&outcome(Decision::Allow)).is_ok());
    }

    #[test]
    fn enforce_block_returns_policy_blocked() {
        let err = enforce_pre_request_decision(&outcome(Decision::Block {
            reason: "external send blocked".into(),
            override_allowed: true,
        }))
        .unwrap_err();
        match err {
            AppError::PolicyBlocked {
                policy_id,
                reason,
                override_allowed,
            } => {
                assert_eq!(policy_id.as_deref(), Some("test-policy"));
                assert_eq!(reason, "external send blocked");
                assert!(override_allowed);
            }
            other => panic!("expected PolicyBlocked, got {other:?}"),
        }
    }

    #[test]
    fn enforce_require_confirmation() {
        let err = enforce_pre_request_decision(&outcome(Decision::RequireConfirmation {
            reason: "high-risk delete".into(),
        }))
        .unwrap_err();
        assert!(matches!(err, AppError::RequireConfirmation(_)));
    }

    #[test]
    fn enforce_rate_limit() {
        let err = enforce_pre_request_decision(&outcome(Decision::RateLimit {
            burst: 1,
            per_seconds: 60,
        }))
        .unwrap_err();
        assert!(matches!(err, AppError::RateLimit));
    }

    #[test]
    fn proxy_headers_present() {
        let mut h = HeaderMap::new();
        let req_id = Uuid::new_v4();
        let pca_id = Uuid::new_v4();
        insert_proxy_headers(&mut h, req_id, &outcome(Decision::Allow), pca_id);
        assert_eq!(
            h.get("x-proxilion-request-id").unwrap().to_str().unwrap(),
            req_id.to_string()
        );
        assert_eq!(
            h.get("x-proxilion-pca-id").unwrap().to_str().unwrap(),
            pca_id.to_string()
        );
        assert_eq!(
            h.get("x-proxilion-policy").unwrap().to_str().unwrap(),
            "test-policy"
        );
    }

    #[tokio::test]
    async fn policy_blocked_serializes_to_structured_403() {
        let err = AppError::PolicyBlocked {
            policy_id: Some("gmail-external-send-gate".into()),
            reason: "to_domain not in customer_domain".into(),
            override_allowed: true,
        };
        let resp = err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "policy_blocked");
        // Structured extras now carry policy_id + override_allowed.
        assert_eq!(v["extras"]["policy_id"], "gmail-external-send-gate");
        assert_eq!(v["extras"]["override_allowed"], true);
        // The shared envelope adds fix + docs hints.
        assert!(v["fix"].as_str().is_some(), "fix must be present");
        assert!(v["docs"].as_str().is_some(), "docs must be present");
    }

    #[tokio::test]
    async fn pic_invariant_violation_serializes_to_403() {
        let err = AppError::PicInvariantViolation(
            "monotonicity: drive:read:file/secret not in PCA_1.ops".into(),
        );
        let resp = err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "pic_invariant_violation");
        assert!(v["detail"]
            .as_str()
            .unwrap()
            .contains("monotonicity"));
    }
}
