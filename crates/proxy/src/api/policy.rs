//! Policy management API (ui-less-surfaces.md §8.3).
//!
//! Endpoints:
//!   GET  /api/v1/policy                — list current policies + modes
//!   POST /api/v1/policy/reload         — re-read file from disk + atomic swap
//!   POST /api/v1/policy/{id}/mode      — flip a single policy's mode

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::policy_handle::{PolicyHandle, SetModeError};

#[derive(Clone)]
pub struct PolicyApiState {
    pub policy: PolicyHandle,
}

pub fn router(state: PolicyApiState) -> Router {
    use crate::operator_auth::scope_check;
    use axum::middleware::from_fn_with_state;
    Router::new()
        .route(
            "/api/v1/policy",
            get(list_policies).route_layer(from_fn_with_state("policy:read", scope_check)),
        )
        .route(
            "/api/v1/policy/reload",
            post(reload).route_layer(from_fn_with_state("policy:write", scope_check)),
        )
        .route(
            "/api/v1/policy/{id}/mode",
            post(set_mode).route_layer(from_fn_with_state("policy:write", scope_check)),
        )
        .with_state(state)
}

#[derive(Debug, Clone, Serialize)]
struct PolicyView {
    id: String,
    vendor: String,
    action: String,
    mode: String,
    pic_mode: String,
}

#[derive(Debug, Clone, Serialize)]
struct ListResponse {
    source: Option<String>,
    policy_count: usize,
    policies: Vec<PolicyView>,
}

async fn list_policies(State(state): State<PolicyApiState>) -> Json<ListResponse> {
    // We don't expose the full Engine reflection API yet; instead we parse
    // the current raw YAML for the listing. That's the canonical source of
    // truth the file watcher and `set_mode` both round-trip through.
    let raw = state.policy.raw_yaml();
    let policies = parse_listing(&raw);
    Json(ListResponse {
        source: state.policy.source().map(|p| p.display().to_string()),
        policy_count: state.policy.load().policy_count(),
        policies,
    })
}

fn parse_listing(yaml: &str) -> Vec<PolicyView> {
    let docs: Vec<serde_yaml::Value> = match serde_yaml::from_str(yaml) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    docs.into_iter()
        .filter_map(|d| {
            let m = d.as_mapping()?;
            let id = m.get(serde_yaml::Value::String("id".into()))?.as_str()?;
            let vendor = m
                .get(serde_yaml::Value::String("vendor".into()))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let action = m
                .get(serde_yaml::Value::String("action".into()))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mode = m
                .get(serde_yaml::Value::String("mode".into()))
                .and_then(|v| v.as_str())
                .unwrap_or("enforce");
            let pic_mode = m
                .get(serde_yaml::Value::String("pic_mode".into()))
                .and_then(|v| v.as_str())
                .unwrap_or("audit");
            Some(PolicyView {
                id: id.to_string(),
                vendor: vendor.to_string(),
                action: action.to_string(),
                mode: mode.to_string(),
                pic_mode: pic_mode.to_string(),
            })
        })
        .collect()
}

async fn reload(State(state): State<PolicyApiState>) -> impl IntoResponse {
    let report = state.policy.reload_from_disk();
    let status = if report.ok {
        StatusCode::OK
    } else {
        StatusCode::CONFLICT
    };
    (status, Json(report))
}

#[derive(Debug, Deserialize)]
struct SetModeBody {
    mode: String,
}

async fn set_mode(
    State(state): State<PolicyApiState>,
    Path(id): Path<String>,
    Json(body): Json<SetModeBody>,
) -> impl IntoResponse {
    let mode = match body.mode.as_str() {
        "enforce" => policy_engine::Mode::Enforce,
        "observe" => policy_engine::Mode::Observe,
        "disabled" => policy_engine::Mode::Disabled,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid mode",
                    "detail": format!("mode must be enforce|observe|disabled, got `{other}`"),
                })),
            );
        }
    };
    match state.policy.set_mode(&id, mode) {
        Ok(report) => (StatusCode::OK, Json(serde_json::json!(report))),
        Err(SetModeError::NotFound(id)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "policy not found",
                "detail": format!("no policy with id `{id}`"),
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "set_mode failed",
                "detail": e.to_string(),
            })),
        ),
    }
}
