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
    fn policy_api_state_is_send_sync_static_for_axum_state_boundary() {
        // `PolicyApiState` is passed via `with_state(...)` into the axum
        // Router; axum requires `Send + Sync + 'static`. A refactor that
        // gave `PolicyApiState` an `Rc<...>` field (e.g. wrapping the
        // hot-reload handle "for cheap clone") would break Sync at the
        // router site with a far-removed trait-bound error. Pin the
        // three-trait combo here — symmetric to the
        // `api_error_and_killswitch_state_are_send_sync_static_for_axum_state_boundary`
        // pin on [crates/proxy/src/api/killswitch.rs] and the
        // `setup_api_state_and_setup_error_are_send_sync_static_for_axum_boundary`
        // pin on [crates/proxy/src/api/setup.rs].
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<PolicyApiState>();
    }

    #[test]
    fn policy_view_and_list_response_debug_carry_struct_names_for_grep() {
        // Both `PolicyView` and `ListResponse` derive `Debug` — the
        // hot-reload code path uses `tracing::debug!(?listing, ...)`
        // when reload reports return non-empty Vecs. Operators grep
        // the log line by struct name to bucket policy-list rendering
        // events. A hand-rolled `impl Debug` that hid struct names "to
        // compact" the line would break the bucket. Pin both struct
        // names — symmetric to the variant-name pins on api/killswitch.rs.
        let v = PolicyView {
            id: "p1".into(),
            vendor: "google".into(),
            action: "drive.files.get".into(),
            mode: "enforce".into(),
            pic_mode: "audit".into(),
        };
        let s = format!("{v:?}");
        assert!(s.contains("PolicyView"), "got: {s}");
        let r = ListResponse {
            source: None,
            policy_count: 0,
            policies: vec![],
        };
        let s = format!("{r:?}");
        assert!(s.contains("ListResponse"), "got: {s}");
    }

    #[test]
    fn policy_view_clone_preserves_every_field_byte_equal() {
        // `PolicyView` derives `Clone` — the listing handler clones
        // views into JSON envelopes (via Vec collect). Pin that every
        // field round-trips a clone without aliasing or truncation. A
        // refactor that switched any field to `Arc<str>` or `Cow<str>`
        // for "cheaper clone" would silently change the mutation safety
        // contract — pin via mutation independence: mutating the source
        // post-clone MUST NOT alias the clone.
        let mut v = PolicyView {
            id: "id-original".into(),
            vendor: "google".into(),
            action: "drive.files.get".into(),
            mode: "enforce".into(),
            pic_mode: "audit".into(),
        };
        let c = v.clone();
        v.id.push_str("-MUTATED");
        v.vendor.push_str("-MUTATED");
        v.action.push_str("-MUTATED");
        v.mode.push_str("-MUTATED");
        v.pic_mode.push_str("-MUTATED");
        assert_eq!(c.id, "id-original");
        assert_eq!(c.vendor, "google");
        assert_eq!(c.action, "drive.files.get");
        assert_eq!(c.mode, "enforce");
        assert_eq!(c.pic_mode, "audit");
    }

    #[test]
    fn parse_listing_preserves_multibyte_unicode_in_id_vendor_action_verbatim() {
        // YAML supports utf-8 in scalars. Operators sometimes use
        // non-ASCII policy ids (e.g. localized rule names) or vendor
        // tags. Pin that `parse_listing` passes multibyte chars
        // through byte-for-byte rather than lossy-converting (a
        // refactor that called `.replace(non_ascii, "?")` "for log
        // hygiene" would silently mangle every non-ASCII policy
        // surface and break the admin UI's display). Walk through
        // 2-byte (`é`), 3-byte (`→`), and 4-byte (`🔥`) codepoints in
        // distinct fields.
        let yaml = "- id: café-rule\n  vendor: googlé\n  action: drive→files🔥get\n";
        let out = parse_listing(yaml);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "café-rule");
        assert_eq!(out[0].vendor, "googlé");
        assert_eq!(out[0].action, "drive→files🔥get");
    }

    #[test]
    fn set_mode_body_deserializes_arbitrary_mode_string_verbatim_no_case_normalization() {
        // The `SetModeBody { mode: String }` deserializer is a plain
        // String — case + whitespace preservation is operator-visible
        // through the handler's exact-match arms ("enforce" / "observe"
        // / "disabled" all-lowercase). Pin that serde does NOT
        // lowercase or trim, so the handler's match-arm rejection of
        // "ENFORCE" or " enforce " produces a 400 with a useful
        // operator-facing message rather than silently accepting the
        // case variant. A refactor that added
        // `#[serde(deserialize_with = "lowercase")]` "for ergonomic
        // CLI" would silently accept "ENFORCE" past the handler's
        // exact-match.
        let upper: SetModeBody = serde_json::from_str(r#"{"mode":"ENFORCE"}"#).unwrap();
        assert_eq!(upper.mode, "ENFORCE");
        let padded: SetModeBody = serde_json::from_str(r#"{"mode":" enforce "}"#).unwrap();
        assert_eq!(padded.mode, " enforce ");
        let bogus: SetModeBody = serde_json::from_str(r#"{"mode":"warp-speed"}"#).unwrap();
        assert_eq!(bogus.mode, "warp-speed");
    }

    #[test]
    fn parse_listing_skips_entries_where_id_is_not_a_string() {
        // The `as_str()` call on the `id` field returns None for
        // numeric or boolean YAML scalars, and `filter_map` drops the
        // entry. Pin that an operator typo (`id: 42` instead of
        // `id: "p42"`) doesn't surface as a numeric "id" in the admin
        // UI's listing — it gets silently dropped. A refactor that
        // surfaced the entry with `id: ""` (the natural `unwrap_or`
        // default applied to `id` "for consistency with vendor /
        // action") would silently render an empty-id row in the
        // admin table that no `set_mode` call could target.
        let yaml = "- id: 42\n  vendor: google\n- id: true\n  vendor: google\n- id: real\n  vendor: google\n";
        let out = parse_listing(yaml);
        assert_eq!(
            out.len(),
            1,
            "non-string id entries must be dropped: {out:?}"
        );
        assert_eq!(out[0].id, "real");
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

    #[test]
    fn set_mode_body_is_send_sync_static_for_axum_json_extractor_boundary() {
        // `SetModeBody` is the body type the axum `Json<SetModeBody>`
        // extractor deserializes into; it crosses the handler's
        // `.await` boundary on the `state.policy.set_mode(...)` call.
        // axum's `FromRequest` blanket impl requires the extracted
        // type to be `Send + 'static`; `Sync` is structurally upheld
        // by the plain-String field. Symmetric to the
        // `policy_api_state_is_send_sync_static_for_axum_state_boundary`
        // pin on `PolicyApiState` and to the
        // `set_config_body` Send+Sync+'static implications baked into
        // the sibling notifier State pin (round 160). A refactor that
        // introduced an `Rc<String>` field "for cheap clone of the
        // inner mode string" would break Send + Sync but the breakage
        // would surface at the extractor site with an opaque
        // tower::Service trait-bound error rather than here. Pin the
        // three-trait combo so a refactor lands clean diagnostics at
        // this file boundary.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<SetModeBody>();
    }

    #[test]
    fn policy_view_serializes_with_exactly_five_known_keys_for_admin_ui_table_columns() {
        // `PolicyView` is the per-row JSON shape the admin UI renders
        // as a table — five columns: id, vendor, action, mode,
        // pic_mode. A refactor that added a sixth field (e.g.
        // `last_reload_at: DateTime<Utc>` "for ergonomic display")
        // would silently widen every row in the admin table and
        // could shift downstream operator tooling that keys on the
        // exact column count. Pin the exhaustive 5-key set so a
        // wire-shape change is a deliberate decision rather than a
        // drive-by. Symmetric to the `list_response_serializes_with_exactly_three_known_keys`
        // pin below.
        let v = PolicyView {
            id: "p1".into(),
            vendor: "google".into(),
            action: "drive.files.get".into(),
            mode: "enforce".into(),
            pic_mode: "audit".into(),
        };
        let val = serde_json::to_value(&v).unwrap();
        let obj = val.as_object().expect("top-level must be object");
        let keys: std::collections::HashSet<&str> = obj.keys().map(String::as_str).collect();
        let expected: std::collections::HashSet<&str> =
            ["id", "vendor", "action", "mode", "pic_mode"]
                .into_iter()
                .collect();
        assert_eq!(keys, expected, "got: {keys:?}");
    }

    #[test]
    fn list_response_serializes_with_exactly_three_known_keys_for_admin_ui_table_shape() {
        // `ListResponse` is the top-level JSON envelope `GET /api/v1/policy`
        // returns: three keys — source, policy_count, policies. The
        // admin UI renders the listing under those exact names and
        // dashboards key on `policy_count` for the cluster-wide
        // policy-count metric. A refactor that added a fourth key
        // (e.g. `last_reload_ms: u64` "for the dashboard reload
        // toast") would silently widen the wire shape and break
        // downstream operator tooling. Pin the exhaustive 3-key set
        // so a wire-shape change surfaces here. Symmetric to the
        // `policy_view_serializes_with_exactly_five_known_keys` pin
        // above.
        let r = ListResponse {
            source: Some("/etc/proxilion/policies.yaml".into()),
            policy_count: 2,
            policies: vec![],
        };
        let val = serde_json::to_value(&r).unwrap();
        let obj = val.as_object().expect("top-level must be object");
        let keys: std::collections::HashSet<&str> = obj.keys().map(String::as_str).collect();
        let expected: std::collections::HashSet<&str> =
            ["source", "policy_count", "policies"].into_iter().collect();
        assert_eq!(keys, expected, "got: {keys:?}");
        // Symmetric pin on the None-source polarity — the key set must
        // not shift on the absent-source branch (it stays present as
        // JSON null per the round-N `null_source` pin).
        let r2 = ListResponse {
            source: None,
            policy_count: 0,
            policies: vec![],
        };
        let val2 = serde_json::to_value(&r2).unwrap();
        let obj2 = val2.as_object().expect("top-level must be object");
        let keys2: std::collections::HashSet<&str> = obj2.keys().map(String::as_str).collect();
        assert_eq!(keys2, expected, "None-source polarity got: {keys2:?}");
    }

    #[test]
    fn policy_view_and_list_response_json_keys_are_lowercase_snake_case_no_kebab_no_uppercase() {
        // The wire convention across the admin API is lowercase
        // snake_case (matches the `policy_count` / `pic_mode` shapes
        // already in flight). A refactor that surfaced one as
        // PascalCase OR kebab-case (e.g. via a `#[serde(rename_all =
        // "kebab-case")]` "for hyphen-friendly URLs" on a future
        // shared types crate) would silently break every operator
        // dashboard regex bucket. Pin absence of uppercase ASCII AND
        // absence of `-` across BOTH structs' serialized keys.
        // Symmetric to the `oauth_error_body_code_is_lowercase_snake_case`
        // and `actions_api_error_body_code_lowercase_snake_case` pins.
        let v = PolicyView {
            id: "p1".into(),
            vendor: "google".into(),
            action: "drive.files.get".into(),
            mode: "enforce".into(),
            pic_mode: "audit".into(),
        };
        let val = serde_json::to_value(&v).unwrap();
        for key in val.as_object().unwrap().keys() {
            assert!(
                !key.chars().any(|c| c.is_ascii_uppercase()),
                "PolicyView key `{key}` carries uppercase",
            );
            assert!(
                !key.contains('-'),
                "PolicyView key `{key}` carries kebab `-`",
            );
        }
        let r = ListResponse {
            source: None,
            policy_count: 0,
            policies: vec![],
        };
        let val = serde_json::to_value(&r).unwrap();
        for key in val.as_object().unwrap().keys() {
            assert!(
                !key.chars().any(|c| c.is_ascii_uppercase()),
                "ListResponse key `{key}` carries uppercase",
            );
            assert!(
                !key.contains('-'),
                "ListResponse key `{key}` carries kebab `-`",
            );
        }
    }

    #[test]
    fn parse_listing_is_referentially_transparent_across_fifty_repeated_calls() {
        // `parse_listing` is pure (no clock, no env, no global state —
        // serde_yaml has no interior mutability, and the closure
        // chain is `as_mapping → as_str → to_string` all pure).
        // Pin referential transparency by calling 50 times with the
        // same YAML and asserting every call yields a byte-equal
        // (via PartialEq on PolicyView) result. A refactor that
        // introduced any form of state (a once-cell-backed cache, a
        // counter, a `tracing::warn!` that mutated a global counter
        // and surfaced via a future "warn-once" gate) would surface
        // here. Symmetric to the `verify_pkce_s256_is_referentially_transparent`
        // pin on [crates/proxy/src/crypto/pkce.rs] and the
        // `redact_url_is_idempotent_applying_twice_equals_applying_once`
        // (round 160) idempotency pin — both are pure-function
        // invariants on operator-facing surfaces. Spread the input
        // across three policies + multi-byte unicode so the pin
        // covers a realistic admin-list shape.
        let yaml = "- id: café-rule\n  vendor: google\n  action: drive.files.get\n  mode: enforce\n  pic_mode: audit\n- id: bare\n- id: zeta\n  vendor: google\n  action: gmail.messages.send\n  mode: observe\n  pic_mode: enforce\n";
        let first = parse_listing(yaml);
        assert_eq!(first.len(), 3, "fixture sanity: 3 policies");
        for i in 0..50 {
            let again = parse_listing(yaml);
            assert_eq!(again.len(), first.len(), "call {i} length drift");
            for (a, b) in first.iter().zip(again.iter()) {
                assert_eq!(a.id, b.id, "call {i} id drift");
                assert_eq!(a.vendor, b.vendor, "call {i} vendor drift");
                assert_eq!(a.action, b.action, "call {i} action drift");
                assert_eq!(a.mode, b.mode, "call {i} mode drift");
                assert_eq!(a.pic_mode, b.pic_mode, "call {i} pic_mode drift");
            }
        }
    }

    #[test]
    fn policy_view_clone_serializes_byte_equal_to_original_across_independent_passes() {
        // `PolicyView` derives `Clone` AND `Serialize` — operator
        // tooling expects the cloned view to serialize to a byte-
        // identical JSON document as the original (no per-clone
        // identity smuggling, no insertion-order-sensitivity that
        // would surface as a key reorder on the second serialize).
        // The existing `policy_view_clone_preserves_every_field_byte_equal`
        // pin checks field-level equality; pin the SERIALIZED form
        // byte-equality so a refactor to a manual `Serialize` impl
        // that interleaved any clock or counter "for trace tagging"
        // would surface here as a multi-pass diff between original
        // and clone. Symmetric to the round-N
        // `expiry_and_escalation_report_debug_is_deterministic_across_independent_constructions`
        // pin on the sibling reports — both axes pin byte-stability
        // across independent constructions of equal-field values.
        let v = PolicyView {
            id: "p1".into(),
            vendor: "google".into(),
            action: "drive.files.get".into(),
            mode: "enforce".into(),
            pic_mode: "audit".into(),
        };
        let c = v.clone();
        let s_v = serde_json::to_string(&v).unwrap();
        let s_c = serde_json::to_string(&c).unwrap();
        assert_eq!(s_v, s_c, "clone serializes to non-byte-equal JSON");
        // And the serialization is deterministic across two passes on
        // the SAME instance (no insertion-order or once-cell-backed
        // drift between consecutive calls).
        let s_v_again = serde_json::to_string(&v).unwrap();
        assert_eq!(s_v, s_v_again, "two-pass serialize drift on same instance");
    }

    // ─── round 188 (2026-05-20): PolicyView + parse_listing + ListResponse surfaces ───

    #[test]
    fn policy_view_all_five_fields_are_owned_string_type_for_arc_swap_outlives_yaml_source() {
        // `PolicyView { id, vendor, action, mode, pic_mode }` — every
        // field is an OWNED `String`, not a borrowed `&str`. The
        // PolicyHandle's underlying `Arc<str>` source bytes get
        // dropped on the next hot-reload; the `Vec<PolicyView>`
        // returned to the HTTP handler must outlive that drop. A
        // refactor to `&'a str` for "zero-alloc on the listing
        // path" would introduce a lifetime parameter that would
        // cascade through the entire response-building chain. Pin
        // the owned-String type via require_string on all 5 fields.
        // Symmetric to round-176 PolicyBundle + round-185
        // owned-String pins extended to PolicyView's full struct.
        fn require_string(_: &String) {}
        let v = PolicyView {
            id: "p-shared".into(),
            vendor: "google".into(),
            action: "drive.files.get".into(),
            mode: "enforce".into(),
            pic_mode: "audit".into(),
        };
        require_string(&v.id);
        require_string(&v.vendor);
        require_string(&v.action);
        require_string(&v.mode);
        require_string(&v.pic_mode);
    }

    #[test]
    fn list_response_policy_count_field_is_usize_type_for_vec_len_compat() {
        // `ListResponse.policy_count: usize` — type is `usize`, NOT
        // `u32` / `i64`. The source value comes from
        // `Engine::policy_count() -> usize` and is the canonical
        // slice-len type across the codebase. A refactor that
        // narrowed to u32 "for explicit byte-size clarity on the
        // wire" would silently truncate on the (operationally
        // implausible but type-correct) u32::MAX-row boundary AND
        // force a cast at the Engine call site. Pin via the
        // canonical require_usize helper. Symmetric to round-186
        // CANONICAL_REQUEST_MAX_LEN usize type pin extended to
        // this response-shape field.
        fn require_usize(_: usize) {}
        let r = ListResponse {
            source: None,
            policy_count: 0,
            policies: vec![],
        };
        require_usize(r.policy_count);
    }

    #[test]
    fn parse_listing_skips_entries_without_required_id_field() {
        // The id field is what every operator-facing tool (dashboard
        // table, /api/v1/policy/{id}/mode endpoint, audit-row join)
        // keys on. The parser uses `m.get(...)?.as_str()?` which
        // short-circuits to None when either the key is missing or
        // the value is non-string — and the outer `filter_map`
        // drops the None. Pin that an entry WITHOUT `id` is dropped
        // entirely (not synthesized with an empty string or a
        // generated UUID), so an operator who fat-fingered `id:` to
        // `name:` sees their entry missing rather than silently
        // re-labeled. The existing `parse_listing_skips_entries_where_id_is_not_a_string`
        // pin covers the non-string-value branch; pin the
        // entirely-missing-key branch here.
        let yaml = "\
- vendor: drive
  action: files.get
  mode: enforce
- id: p-valid
  vendor: gmail
  action: messages.send
  mode: enforce
";
        let listing = parse_listing(yaml);
        assert_eq!(
            listing.len(),
            1,
            "missing-id entry must drop, got: {listing:?}"
        );
        assert_eq!(listing[0].id, "p-valid");
    }

    #[test]
    fn parse_listing_empty_yaml_array_returns_empty_vec_without_error() {
        // `parse_listing` accepts `"[]"` (legitimate "no policies
        // loaded yet" state at boot or after a clear-all) and MUST
        // return an empty Vec. A refactor that pre-required at
        // least one entry "for non-empty-config safety" would
        // surface here as panic or empty-list-rejected. The setup-
        // status page reads this listing and counts zero — pin the
        // empty contract end-to-end. Also walk an empty-string
        // input (a hot-reload race where the file was being
        // written when read).
        assert!(parse_listing("[]").is_empty());
        assert!(parse_listing("").is_empty());
        // Whitespace-only input also yields empty (yaml-parsed as
        // null, then the `as_mapping` filter drops every entry).
        assert!(parse_listing("   \n   ").is_empty());
    }

    #[test]
    fn parse_listing_applies_documented_defaults_for_omitted_mode_and_pic_mode() {
        // The parser's `.unwrap_or("enforce")` on mode AND
        // `.unwrap_or("audit")` on pic_mode are the documented
        // safe-production defaults (spec.md §9). An operator who
        // writes a minimal policy (only `id`, `vendor`, `action`,
        // `decision`) MUST see those defaults surface in the
        // listing — otherwise their dashboard shows an empty cell
        // for mode/pic_mode and the policy executes against an
        // implicit default that the operator can't audit. Pin the
        // default-substitution shape so a refactor that propagated
        // `None` to the wire (e.g. via `Option<String>`) would
        // surface here. Symmetric to round-178 default_pic_mode
        // helper pin extended to the listing-time fallback path.
        let yaml = "\
- id: p-minimal
  vendor: drive
  action: files.get
";
        let listing = parse_listing(yaml);
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].mode, "enforce", "default mode must be enforce");
        assert_eq!(
            listing[0].pic_mode, "audit",
            "default pic_mode must be audit",
        );
    }

    #[test]
    fn set_mode_body_mode_field_is_owned_string_for_axum_extract_outlives_request_body() {
        // `SetModeBody.mode: String` — owned, not borrowed. The
        // axum `Json(body): Json<SetModeBody>` extractor consumes
        // the request body bytes and the deserializer takes
        // ownership of every String field. A refactor to
        // `mode: &'a str` "for zero-alloc on the dispatch
        // arm" would introduce a lifetime parameter that the
        // Json extractor's owned-content contract can't satisfy.
        // Pin the owned-String type via require_string. Symmetric
        // to round-185 + round-187 owned-String pins extended to
        // this API request body field.
        fn require_string(_: &String) {}
        let body: SetModeBody = serde_json::from_str(r#"{"mode":"observe"}"#).unwrap();
        require_string(&body.mode);
        assert_eq!(body.mode, "observe");
    }

    #[test]
    fn policy_api_state_field_count_pinned_at_exactly_one_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the PolicyApiState struct field count at exactly 1 via
        // exhaustive destructure pattern (no `..` rest). The 1 field
        // is: policy (PolicyHandle). A 2nd field landing (e.g.
        // `audit_sink: Arc<dyn ActionStream>` to emit a per-mode-
        // change audit row when set_mode succeeds, or
        // `metrics_bucket: &'static str` to split per-state metric
        // labels) would silently bloat every Clone of PolicyApiState
        // the axum router fans out per request AND silently change
        // what the policy API handlers see. The existing
        // `policy_api_state_is_send_sync_static` pin walks trait
        // bounds; the existing Clone derivation walks the trait;
        // neither catches a runtime-only 2nd field — exhaustive
        // destructure is the canonical pin.
        fn _destructure_witness(s: PolicyApiState) {
            let PolicyApiState { policy: _ } = s;
        }
    }

    #[test]
    fn policy_view_field_count_pinned_at_exactly_five_via_exhaustive_destructure_no_rest_pattern() {
        // Pin the PolicyView struct field count at exactly 5 via
        // exhaustive destructure (no `..`). The 5 fields are: id +
        // vendor + action + mode + pic_mode. A 6th field landing
        // (e.g. `updated_at: DateTime<Utc>` for the dashboard's
        // "last edited" column, or `audit_body: Option<String>` to
        // surface the per-policy audit-body setting in the admin UI
        // table) would silently bloat every PolicyView Vec on the
        // response-build path. The existing
        // `policy_view_serializes_with_exactly_five_known_keys`
        // pin walks JSON wire keys; this pins the Rust struct
        // shape symmetrically so a `#[serde(skip)]` runtime-only
        // 6th field can't bypass.
        let v = PolicyView {
            id: String::new(),
            vendor: String::new(),
            action: String::new(),
            mode: String::new(),
            pic_mode: String::new(),
        };
        let PolicyView {
            id: _,
            vendor: _,
            action: _,
            mode: _,
            pic_mode: _,
        } = v;
    }

    #[test]
    fn list_response_field_count_pinned_at_exactly_three_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the ListResponse struct field count at exactly 3 via
        // exhaustive destructure (no `..`). The 3 fields are:
        // source + policy_count + policies. A 4th field landing
        // (e.g. `last_reload_at: Option<DateTime<Utc>>` for the
        // dashboard's "policies were last reloaded N seconds ago"
        // operator-facing indicator, or `engine_version:
        // &'static str` for back-attribution from listing to engine
        // build) would silently bloat every list_policies response
        // AND silently change the existing
        // `list_response_serializes_with_exactly_three_known_keys`
        // JSON wire shape via `#[serde(skip)]` runtime-only field
        // bypass.
        let v = ListResponse {
            source: None,
            policy_count: 0,
            policies: vec![],
        };
        let ListResponse {
            source: _,
            policy_count: _,
            policies: _,
        } = v;
    }

    #[test]
    fn set_mode_body_field_count_pinned_at_exactly_one_via_exhaustive_destructure_no_rest_pattern()
    {
        // Pin the SetModeBody request-body struct field count at
        // exactly 1 via exhaustive destructure (no `..`). The 1
        // field is: mode (String). A 2nd field landing (e.g.
        // `actor: Option<String>` for operator-attribution into the
        // audit log of mode flips, or `expires_at:
        // Option<DateTime<Utc>>` for a future time-bounded mode
        // override per ui-less-surfaces.md §8.4 future work)
        // would silently extend the CLI's expected request body
        // shape AND silently change the handler's deserialize
        // contract. The existing
        // `set_mode_body_accepts_unknown_extra_fields` test pins
        // forward-compat acceptance (serde permissive default),
        // but doesn't catch the addition of a NEW required field
        // — exhaustive destructure is the canonical pin.
        let v = SetModeBody {
            mode: String::new(),
        };
        let SetModeBody { mode: _ } = v;
    }

    #[test]
    fn parse_listing_signature_pinned_via_fn_pointer_witness() {
        // Pin parse_listing signature as `fn(&str) -> Vec<PolicyView>`
        // via fn-pointer witness. A refactor that flipped to
        // `fn(String) -> Vec<PolicyView>` ("for consume-and-cache
        // on the rare-but-large-policy path") would silently force
        // every call site to clone the raw_yaml() arc-string. The
        // borrow shape lets the list_policies handler call
        // parse_listing(&raw) without owning the bytes. The owned
        // `Vec<PolicyView>` return type is also pinned — a refactor
        // to `&'a [PolicyView]` "to avoid the per-call allocation"
        // would tie the return lifetime to the input buffer and
        // force lifetime parameters on the response shape. The
        // function is `Vec<PolicyView>` (not `Result<...>`) — pin
        // the no-error infallible contract (silently-skip-bad-yaml
        // is the documented behavior, ensuring the admin UI never
        // 500s on a malformed-but-recoverable yaml stage).
        let _f: fn(&str) -> Vec<PolicyView> = parse_listing;
    }

    #[test]
    fn router_function_signature_pinned_via_fn_pointer_witness() {
        // Pin the module's router constructor signature as
        // `fn(PolicyApiState) -> Router` via fn-pointer witness.
        // Symmetric to round-262 api/mod.rs router fn-pointer pin
        // extended to the policy API surface. The server.rs boot
        // path calls `router(policy_state)` exactly once at app
        // assembly time AND consumes the state by value (the
        // router internally clones it per request via
        // `.with_state(...)`). A refactor to
        // `fn(&PolicyApiState) -> Router` or
        // `fn(PolicyApiState) -> Result<Router, _>` would silently
        // change the boot path's ownership AND error-handling
        // shape.
        let _f: fn(PolicyApiState) -> Router = router;
    }
}
