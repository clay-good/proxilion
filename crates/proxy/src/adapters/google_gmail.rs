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
//! + subject + attachment count, and exposes them under `body.*` so the
//! policy engine can implement the gmail-external-send-gate per spec.md §9.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap};
use axum::http::{HeaderName, HeaderValue, Method, Response, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use base64::engine::general_purpose::{URL_SAFE as B64URL, URL_SAFE_NO_PAD as B64URL_NP};
use chrono::Utc;
use serde::{Deserialize, Serialize};
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
            upstream_body: Some(serde_json::to_vec(&SendUpstreamBody { raw: &body.raw })
                .map_err(|e| AppError::Internal(e.to_string()))?),
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
            upstream_path: format!("/gmail/v1/users/me/messages/{}", msg_id),
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
    let ctx = build_policy_ctx(state, session, &req);

    let (outcome, mut policy_trace) = state.policy.load().evaluate_with_trace(&ctx)?;
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
                },
            )
            .await;
            return Err(AppError::PicInvariantViolation(d));
        }
        Err(crate::pic::ExecutorError::Upstream { status, body }) => {
            return Err(AppError::Internal(format!(
                "trust plane {status}: {body}"
            )));
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
    let upstream_resp = builder.send().await?;
    let status = upstream_resp.status();
    let content_type = upstream_resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let body_bytes = read_bounded(upstream_resp, MAX_BODY).await?;

    // Read filter — only for read paths.
    let (final_body, filter_outcome) = if req.method == Method::GET && outcome.read_filter.is_some()
    {
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
    Ok(builder
        .body(axum::body::Body::from(final_body))
        .map_err(|e| AppError::Internal(e.to_string()))?)
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
    B64URL
        .decode(s)
        .or_else(|_| B64URL_NP.decode(s))
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
    let mut out = Vec::new();
    // mailparse::addrparse handles RFC 5322 properly.
    if let Ok(list) = mailparse::addrparse(value) {
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
    }
    out
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
    body.insert("to".into(), Value::Array(
        parsed.to.iter().map(|s| Value::String(s.clone())).collect(),
    ));
    body.insert("cc".into(), Value::Array(
        parsed.cc.iter().map(|s| Value::String(s.clone())).collect(),
    ));
    body.insert("bcc".into(), Value::Array(
        parsed.bcc.iter().map(|s| Value::String(s.clone())).collect(),
    ));
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
    body.insert(
        "from_p0".into(),
        Value::String(from_p0.to_owned()),
    );
    body
}

// Quiet unused-import warnings on rarely-used types.
#[allow(dead_code)]
const _USED: (Option<Bytes>, StatusCode) = (None, StatusCode::OK);

#[cfg(test)]
mod tests {
    use super::*;

    fn build_raw(to: &str, subject: &str, body: &str) -> String {
        let raw = format!(
            "To: {to}\r\nFrom: alice@acme.com\r\nSubject: {subject}\r\n\r\n{body}\r\n"
        );
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
        assert_eq!(domain_of("alice@example.com").as_deref(), Some("example.com"));
        assert_eq!(domain_of("alice@ExAmPle.COM").as_deref(), Some("example.com"));
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
}
