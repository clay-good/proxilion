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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listing_extracts_id_vendor_action_mode_pic_mode() {
        let yaml = r#"- id: gmail-external-send-gate
  vendor: google
  action: gmail.users.messages.send
  mode: enforce
  pic_mode: audit
- id: drive-injection-filter
  vendor: google
  action: drive.files.get
  mode: observe
  pic_mode: enforce
"#;
        let out = parse_listing(yaml);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, "gmail-external-send-gate");
        assert_eq!(out[0].vendor, "google");
        assert_eq!(out[0].action, "gmail.users.messages.send");
        assert_eq!(out[0].mode, "enforce");
        assert_eq!(out[0].pic_mode, "audit");
        assert_eq!(out[1].id, "drive-injection-filter");
        assert_eq!(out[1].mode, "observe");
        assert_eq!(out[1].pic_mode, "enforce");
    }

    #[test]
    fn parse_listing_applies_defaults_for_missing_optional_fields() {
        let yaml = "- id: bare-policy\n";
        let out = parse_listing(yaml);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "bare-policy");
        assert_eq!(out[0].vendor, "");
        assert_eq!(out[0].action, "");
        assert_eq!(out[0].mode, "enforce");
        assert_eq!(out[0].pic_mode, "audit");
    }

    #[test]
    fn parse_listing_skips_entries_without_id() {
        let yaml = "- vendor: google\n  action: drive.files.get\n- id: ok\n";
        let out = parse_listing(yaml);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "ok");
    }

    #[test]
    fn parse_listing_returns_empty_on_malformed_yaml() {
        let out = parse_listing("not: valid: yaml: : :");
        assert!(out.is_empty());
    }

    #[test]
    fn parse_listing_empty_input_yields_empty_vec() {
        assert!(parse_listing("").is_empty());
    }

    #[test]
    fn policy_view_serializes_to_json() {
        let v = PolicyView {
            id: "p1".into(),
            vendor: "google".into(),
            action: "drive.files.get".into(),
            mode: "enforce".into(),
            pic_mode: "audit".into(),
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"id\":\"p1\""));
        assert!(s.contains("\"vendor\":\"google\""));
        assert!(s.contains("\"pic_mode\":\"audit\""));
    }

    #[test]
    fn set_mode_body_deserializes() {
        let b: SetModeBody = serde_json::from_str(r#"{"mode":"observe"}"#).unwrap();
        assert_eq!(b.mode, "observe");
    }

    #[test]
    fn parse_listing_returns_empty_when_yaml_is_single_mapping_not_array() {
        // The handler's listing path expects a top-level YAML array. A
        // single-mapping document (`id: foo` not wrapped in `-`) fails the
        // `Vec<Value>` deserialize, surfaces as `Err`, and is mapped to
        // `vec![]` — operators get an empty listing rather than a 500.
        // A refactor that silently tried to treat the single mapping as
        // a one-element list would surface here.
        let yaml = "id: not-an-array\nvendor: google\n";
        assert!(parse_listing(yaml).is_empty());
    }

    #[test]
    fn parse_listing_drops_non_mapping_entries_in_array() {
        // The YAML walker filter_maps on `as_mapping()`. A scalar entry
        // mixed with a real policy must be dropped silently rather than
        // erroring the entire listing — defensive against hand-edited
        // policy files. A refactor that surfaced the error would silently
        // hide every valid policy on a single bad entry.
        let yaml = "- just-a-string\n- id: real-one\n  vendor: google\n";
        let out = parse_listing(yaml);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "real-one");
    }

    #[test]
    fn list_response_json_carries_source_policy_count_and_policies_keys() {
        // The admin UI keys on these three field names. Pin the wire shape
        // so a future rename (e.g. `source` → `path`) would surface here.
        let r = ListResponse {
            source: Some("/etc/proxilion/policies.yaml".into()),
            policy_count: 2,
            policies: vec![PolicyView {
                id: "p1".into(),
                vendor: "google".into(),
                action: "drive.files.get".into(),
                mode: "enforce".into(),
                pic_mode: "audit".into(),
            }],
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["source"], "/etc/proxilion/policies.yaml");
        assert_eq!(v["policy_count"], 2);
        assert_eq!(v["policies"].as_array().unwrap().len(), 1);
        assert_eq!(v["policies"][0]["id"], "p1");
    }

    #[test]
    fn list_response_json_renders_null_source_when_loader_has_no_path() {
        // The static / embed-API loaders return None from .source(); the
        // wire shape must render this as JSON null (not absent) so the
        // admin UI can distinguish "in-memory policies" from "file path
        // dropped on a refactor". Stay-on-the-wire test for the option
        // serializer default.
        let r = ListResponse {
            source: None,
            policy_count: 0,
            policies: vec![],
        };
        let v = serde_json::to_value(&r).unwrap();
        assert!(v.get("source").is_some(), "key must be present");
        assert!(v["source"].is_null());
        assert_eq!(v["policy_count"], 0);
        assert!(v["policies"].as_array().unwrap().is_empty());
    }

    #[test]
    fn set_mode_body_rejects_missing_mode_field() {
        // The handler's mode-switch path depends on serde failing fast on
        // an empty `{}` body — a refactor to `Option<String>` with a
        // silent fall-through to "enforce" would let an operator's
        // mistyped curl silently flip a policy back to enforce.
        let r: Result<SetModeBody, _> = serde_json::from_str("{}");
        assert!(r.is_err());
    }

    #[test]
    fn set_mode_body_accepts_unknown_extra_fields() {
        // serde's default is `deny_unknown_fields: false`. Pin the
        // permissive contract — the CLI may send forward-compat fields
        // (e.g. `audit_note`) that the proxy hasn't learned yet, and the
        // mode flip must still apply rather than 400.
        let b: SetModeBody =
            serde_json::from_str(r#"{"mode":"disabled","audit_note":"experiment"}"#).unwrap();
        assert_eq!(b.mode, "disabled");
    }

    #[test]
    fn parse_listing_preserves_source_order_across_multiple_policies() {
        // The admin UI's policy table relies on the source YAML's order
        // being preserved verbatim (operators sort their policies by
        // intent — most-specific first; alphabetizing them on the wire
        // would break the mental model). serde_yaml's Vec<Value> parse
        // preserves order, and parse_listing's filter_map preserves it
        // too. Pin via three policies authored in deliberately non-
        // alphabetical order — a refactor that switched to a HashMap or
        // BTreeMap as intermediate state would silently sort the output.
        let yaml = "\
- id: zeta
  vendor: google
  action: gmail.messages.send
- id: alpha
  vendor: google
  action: drive.files.get
- id: mu
  vendor: google
  action: calendar.events.list
";
        let v = parse_listing(yaml);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].id, "zeta", "source order preserved at index 0");
        assert_eq!(v[1].id, "alpha", "source order preserved at index 1");
        assert_eq!(v[2].id, "mu", "source order preserved at index 2");
    }
}
