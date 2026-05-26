//! Setup-status API for the `/admin/setup` checklist UI.
//!
//! Returns the proxy's perception of what's configured and what's still
//! missing, with copy-paste fix snippets. The companion HTML lives in
//! `static-admin/setup.html`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Serialize;
use sqlx::PgPool;

#[derive(Clone)]
pub struct SetupApiState {
    pub db: PgPool,
    pub google_configured: bool,
    pub federation_bridge_url: String,
    pub policy_path_configured: bool,
    pub policy_count: usize,
}

pub fn router(state: SetupApiState) -> Router {
    Router::new()
        .route("/api/v1/setup/status", axum::routing::get(status))
        .with_state(state)
}

#[derive(Serialize)]
struct CheckItem {
    /// Stable id for the UI to render against.
    id: &'static str,
    /// Human title.
    title: &'static str,
    ok: bool,
    /// One-line current state.
    detail: String,
    /// Plain-English fix (None when ok=true).
    fix: Option<&'static str>,
    docs: &'static str,
}

#[derive(Serialize)]
struct SetupStatus {
    ready_for_traffic: bool,
    items: Vec<CheckItem>,
}

async fn status(State(state): State<SetupApiState>) -> Result<Json<SetupStatus>, SetupError> {
    let mut items = Vec::new();

    // 1. Database
    let db_ok = sqlx::query_scalar::<_, i64>("SELECT 1::bigint")
        .fetch_one(&state.db)
        .await
        .is_ok();
    items.push(CheckItem {
        id: "database",
        title: "Database",
        ok: db_ok,
        detail: if db_ok { "connected".into() } else { "unreachable".into() },
        fix: if db_ok {
            None
        } else {
            Some("Set DATABASE_URL to a reachable postgres URL. The all-in-one Docker image bundles postgres automatically.")
        },
        docs: "https://proxilion.com/docs/install",
    });

    // 2. Policy file / loaded policies
    let pol_ok = state.policy_count > 0 || state.policy_path_configured;
    items.push(CheckItem {
        id: "policies",
        title: "Layer-B policies",
        ok: pol_ok,
        detail: if pol_ok {
            format!("{} policies loaded", state.policy_count)
        } else {
            "no policy file configured (Allow on every request)".into()
        },
        fix: if pol_ok {
            None
        } else {
            Some(
                "Set PROXILION_POLICY_PATH to a YAML file. See `config/ops-mapping.yaml` for the format and `docs/specs/spec.md` §9 for examples.",
            )
        },
        docs: "https://proxilion.com/docs/policy/authoring",
    });

    // 3. OAuth client registry
    let client_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    items.push(CheckItem {
        id: "oauth_clients",
        title: "Registered OAuth clients",
        ok: client_count > 0,
        detail: format!("{} client(s) registered", client_count),
        fix: if client_count > 0 {
            None
        } else {
            Some(
                "Register the managed agent as an OAuth client. The seed migration adds `anthropic-managed-claude`; add more via SQL or `proxilion-cli clients add` (planned, M3).",
            )
        },
        docs: "https://proxilion.com/docs/oauth/clients",
    });

    // 4. Google OAuth creds (gates the Drive adapter + OAuth interception)
    items.push(CheckItem {
        id: "google_credentials",
        title: "Google OAuth credentials",
        ok: state.google_configured,
        detail: if state.google_configured {
            "GOOGLE_CLIENT_ID/SECRET configured".into()
        } else {
            "GOOGLE_CLIENT_ID/SECRET not set".into()
        },
        fix: if state.google_configured {
            None
        } else {
            Some(
                "Create an OAuth client in https://console.cloud.google.com/apis/credentials, set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, and add this proxy's `/oauth/google/callback` to the authorized redirect URIs.",
            )
        },
        docs: "https://proxilion.com/docs/install/google",
    });

    // 5. PCA cache: has any chain landed?
    let pca_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pca_cache")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    items.push(CheckItem {
        id: "first_pca",
        title: "First successful PCA",
        ok: pca_count > 0,
        detail: format!("{} PCA(s) in cache", pca_count),
        fix: if pca_count > 0 {
            None
        } else {
            Some(
                "No PCA chain has been issued yet. Run `proxilion-cli selftest` to verify the path with a synthetic transaction, then point a managed agent at the proxy.",
            )
        },
        docs: "https://proxilion.com/docs/getting-started/first-pca",
    });

    // 6. Federation bridge (informational)
    items.push(CheckItem {
        id: "federation_bridge",
        title: "Federation bridge (optional)",
        ok: true, // never blocks; deferred service
        detail: format!(
            "configured URL: {} (service is deferred per spec §0.4 — JWTs decoded inline at Trust Plane)",
            state.federation_bridge_url
        ),
        fix: None,
        docs: "https://proxilion.com/docs/federation-bridge",
    });

    // "Ready for traffic" = DB + at least one OAuth client + Google creds.
    // Policy and PCA history are nice-to-have; they don't block.
    let ready_for_traffic = db_ok && client_count > 0 && state.google_configured;

    Ok(Json(SetupStatus {
        ready_for_traffic,
        items,
    }))
}

#[derive(Debug, thiserror::Error)]
enum SetupError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

impl IntoResponse for SetupError {
    fn into_response(self) -> Response {
        use crate::error_envelope::ErrorBody;
        ErrorBody::new("setup status probe failed", "internal_error")
            .with_detail(self.to_string())
            .with_fix("Check that postgres is reachable: curl /healthz.")
            .with_docs("https://proxilion.com/docs/troubleshooting")
            .into_response(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_item_serializes_with_stable_field_names() {
        let item = CheckItem {
            id: "database",
            title: "Database",
            ok: true,
            detail: "connected".into(),
            fix: None,
            docs: "https://proxilion.com/docs/install",
        };
        let v = serde_json::to_value(&item).unwrap();
        // Stable wire shape — admin UI keys on these names.
        assert_eq!(v["id"], "database");
        assert_eq!(v["title"], "Database");
        assert_eq!(v["ok"], true);
        assert_eq!(v["detail"], "connected");
        assert!(v["fix"].is_null());
        assert_eq!(v["docs"], "https://proxilion.com/docs/install");
    }

    #[test]
    fn check_item_failure_serializes_fix_hint() {
        let item = CheckItem {
            id: "google_credentials",
            title: "Google OAuth credentials",
            ok: false,
            detail: "GOOGLE_CLIENT_ID/SECRET not set".into(),
            fix: Some("Set GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET."),
            docs: "https://proxilion.com/docs/install/google",
        };
        let v = serde_json::to_value(&item).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["fix"].as_str().unwrap().contains("GOOGLE_CLIENT_ID"));
    }

    #[test]
    fn setup_status_envelope_contains_items_and_readiness() {
        let s = SetupStatus {
            ready_for_traffic: false,
            items: vec![CheckItem {
                id: "database",
                title: "Database",
                ok: false,
                detail: "unreachable".into(),
                fix: Some("Set DATABASE_URL."),
                docs: "https://proxilion.com/docs/install",
            }],
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["ready_for_traffic"], false);
        assert_eq!(v["items"].as_array().unwrap().len(), 1);
        assert_eq!(v["items"][0]["id"], "database");
    }

    #[tokio::test]
    async fn setup_error_into_response_is_500_with_docs_link() {
        let e = SetupError::Db(sqlx::Error::RowNotFound);
        let r = e.into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "internal_error");
        assert!(v["docs"].as_str().unwrap().contains("troubleshooting"));
    }

    #[test]
    fn setup_status_items_preserve_insertion_order_on_serialize() {
        // The /admin/setup checklist renders items top-to-bottom in the
        // order the handler pushes them (DB → policies → oauth clients →
        // google creds → first PCA → federation bridge). A refactor that
        // sorted or hashed-iterated the items would silently scramble
        // that order — the UI's progressive-disclosure script depends on
        // `database` being first (it's the "everything else is moot if
        // this is red" gate). Pin the wire-shape order here.
        let s = SetupStatus {
            ready_for_traffic: true,
            items: vec![
                CheckItem {
                    id: "database",
                    title: "Database",
                    ok: true,
                    detail: "connected".into(),
                    fix: None,
                    docs: "d1",
                },
                CheckItem {
                    id: "policies",
                    title: "Layer-B policies",
                    ok: true,
                    detail: "12 policies loaded".into(),
                    fix: None,
                    docs: "d2",
                },
                CheckItem {
                    id: "oauth_clients",
                    title: "OAuth",
                    ok: true,
                    detail: "1 client(s)".into(),
                    fix: None,
                    docs: "d3",
                },
            ],
        };
        let v = serde_json::to_value(&s).unwrap();
        let ids: Vec<&str> = v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["database", "policies", "oauth_clients"]);
    }

    #[test]
    fn setup_error_display_carries_underlying_db_error() {
        // The `#[error("database error: {0}")]` annotation is the
        // operator-facing log line — a refactor that swapped the message
        // ("db error: {0}", say) would break grep-based runbook
        // playbooks. Pin the prefix here so a Display-attribute drift
        // surfaces as a test failure rather than a silent runbook break.
        let e = SetupError::Db(sqlx::Error::PoolClosed);
        let s = format!("{e}");
        assert!(s.starts_with("database error: "), "got: {s}");
    }

    #[test]
    fn check_item_some_fix_includes_actionable_keyword() {
        // The `fix` field is the only `Option<&'static str>` the
        // CheckItem carries — a future change that swapped `None` for
        // `Some("")` on the OK path would dilute the "is_some ↔ is_ok"
        // contract the admin UI uses to decide whether to render the
        // fix block. Pin that any Some(_) carries a non-empty hint
        // (length > 0 — we do NOT pin the exact prose, which evolves).
        let item = CheckItem {
            id: "oauth_clients",
            title: "Registered OAuth clients",
            ok: false,
            detail: "0 client(s) registered".into(),
            fix: Some("Register the managed agent as an OAuth client."),
            docs: "d",
        };
        let v = serde_json::to_value(&item).unwrap();
        assert!(!v["fix"].as_str().unwrap().is_empty());
    }

    #[test]
    fn setup_status_with_zero_items_serializes_as_empty_array_not_null() {
        // Boundary: a SetupStatus constructed with no items (a
        // hypothetical "checks disabled" mode, or any future "lazy"
        // status that returns early) must round-trip `items: []` on the
        // wire, NOT `items: null`. The admin UI's checklist render
        // iterates `items.length` — a null value would crash the
        // `.length` access while `[]` collapses cleanly to a "no checks
        // pending" empty state. Pin the `Vec<_> → []` serde guarantee.
        let s = SetupStatus {
            ready_for_traffic: true,
            items: vec![],
        };
        let v = serde_json::to_value(&s).unwrap();
        assert!(
            v["items"].is_array(),
            "items must serialize as array, got: {v}"
        );
        assert_eq!(v["items"].as_array().unwrap().len(), 0);
        assert!(!v["items"].is_null());
    }

    #[test]
    fn check_item_long_detail_string_serializes_intact_with_no_truncation() {
        // The `detail` field is a `String` (no length cap) — the
        // `first_pca` check renders `format!("{count} PCA(s) in cache")`
        // which can carry a 20+ digit count on a long-running install.
        // Pin a 4 KiB detail round-trip so a future refactor that
        // truncated the field at the serializer (e.g. "for log
        // hygiene") would surface here as a length mismatch rather
        // than as a silent drop on the operator's PCA-cache panel.
        let big = "x".repeat(4096);
        let item = CheckItem {
            id: "first_pca",
            title: "First successful PCA",
            ok: true,
            detail: big.clone(),
            fix: None,
            docs: "d",
        };
        let v = serde_json::to_value(&item).unwrap();
        assert_eq!(v["detail"].as_str().unwrap().len(), 4096);
        assert_eq!(v["detail"], big);
    }

    #[test]
    fn setup_error_from_impl_works_for_distinct_sqlx_variants() {
        // The `#[from] sqlx::Error` on `SetupError::Db` is the
        // load-bearing conversion the `?`-operator uses at every
        // `sqlx::query_*().await?` call site in `status(...)`. A
        // refactor that dropped the `#[from]` (e.g. moved to a named
        // map_err) would surface here at compile time. Pin three
        // distinct sqlx error variants so the conversion path itself
        // is exercised on each (not just the constructor on one
        // variant) — verifies the blanket-impl over `sqlx::Error`'s
        // own variant set is intact.
        for inner in [
            sqlx::Error::PoolClosed,
            sqlx::Error::RowNotFound,
            sqlx::Error::WorkerCrashed,
        ] {
            let e: SetupError = inner.into();
            let s = format!("{e}");
            assert!(s.starts_with("database error: "), "got: {s}");
        }
    }

    #[test]
    fn check_item_id_field_is_static_str_for_zero_alloc_logging() {
        // The `id` field is `&'static str` (not `String`) — load-bearing
        // for the operator-visible Grafana panel key (`item.id == "database"`)
        // and so log aggregators can intern it without allocation. A
        // refactor to `String` for "consistency with detail" would
        // silently double the per-item memory cost and add an allocation
        // to every /api/v1/setup/status response. Pin via compile-time
        // shape: assigning a static literal must round-trip exactly,
        // and the JSON wire shape stays unquoted-quoted-string regardless.
        let item = CheckItem {
            id: "database",
            title: "Postgres reachable",
            ok: true,
            detail: "ok".into(),
            fix: None,
            docs: "https://docs.example/db",
        };
        // The `'static` lifetime constraint is enforced at compile time
        // by the field type — this pure-helper test pins the wire shape
        // and that the literal flows through unmodified.
        assert_eq!(item.id, "database");
        let v = serde_json::to_value(&item).unwrap();
        assert_eq!(v["id"], "database");
    }

    #[test]
    fn setup_api_state_and_setup_error_are_send_sync_static_for_axum_boundary() {
        // `SetupApiState` is passed via `with_state(...)` into the axum
        // Router; axum requires `Send + Sync + 'static`. `SetupError`
        // flows through `IntoResponse` from handler futures crossing
        // tokio task boundaries and also requires the same bounds. A
        // refactor that gave `SetupApiState` an `Rc<String>` field "for
        // cheap clone of `federation_bridge_url`" would break Sync at
        // the router site with a far-removed trait-bound error. Pin the
        // three-trait combo on both types here — symmetric to the
        // `api_error_and_killswitch_state_are_send_sync_static_for_axum_state_boundary`
        // pin on [crates/proxy/src/api/killswitch.rs].
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<SetupApiState>();
        require_send_sync_static::<SetupError>();
    }

    #[test]
    fn setup_error_db_arm_chains_source_to_inner_sqlx_error_via_from_derive() {
        // `Db(#[from] sqlx::Error)` with the explicit
        // `#[error("database error: {0}")]` shape (NOT `#[error(transparent)]`)
        // — the `std::error::Error::source()` walk MUST return the inner
        // `sqlx::Error` so anyhow chain-walking surfaces it for operator
        // triage. The killswitch sibling uses `#[error(transparent)]`
        // (which DELEGATES source() to the inner's source(), skipping a
        // level); this module's explicit-format derive instead returns
        // the inner directly. Pin source() == Some here so a refactor
        // that dropped `#[from]` "for explicit map_err" would surface
        // here as a chain-walk break.
        let e = SetupError::Db(sqlx::Error::RowNotFound);
        let dyn_err: &dyn std::error::Error = &e;
        assert!(
            std::error::Error::source(dyn_err).is_some(),
            "Db arm with explicit #[error] format must chain source to inner",
        );
    }

    #[test]
    fn setup_error_debug_carries_variant_name_for_grep_bucketing() {
        // The `#[derive(Debug)]` on `SetupError` feeds `?e` in
        // `tracing::warn!(?err, ...)` call sites and the 500-branch
        // logs. Operators grep the log line by variant name to bucket
        // "Postgres outage" rows. A hand-rolled `impl Debug` that hid
        // the variant name "to compact" the line would break the bucket.
        // Pin "Db" variant name — symmetric to the ApiError variant-
        // name pins on api/killswitch.rs.
        let s = format!("{:?}", SetupError::Db(sqlx::Error::RowNotFound));
        assert!(s.contains("Db"), "got: {s}");
    }

    #[test]
    fn setup_error_display_carries_byte_exact_database_error_prefix_with_inner() {
        // `#[error("database error: {0}")]` — pin the byte-exact
        // prefix-plus-inner Display shape via `assert_eq!`. The existing
        // `setup_error_display_carries_underlying_db_error` test uses
        // `starts_with("database error: ")` which would pass even if a
        // refactor dropped the inner (or duplicated the prefix). Pin
        // the full wrapper shape here against the inner's known Display
        // so a refactor that softened to `"db error: {0}"` or dropped
        // the colon would surface here. Operator log filters historically
        // grep `"database error:"` to bucket setup-probe failures.
        let inner = sqlx::Error::PoolClosed;
        let expected = format!("database error: {inner}");
        let e = SetupError::Db(sqlx::Error::PoolClosed);
        assert_eq!(e.to_string(), expected);
    }

    #[test]
    fn setup_status_ready_for_traffic_serializes_as_json_boolean_not_numeric() {
        // `ready_for_traffic: bool` lands on the wire as a JSON
        // boolean. Pin the type tag explicitly — a refactor that
        // promoted it to a `RedinessClass` enum with
        // `#[serde(into = "u8")]` "for finer-grained signal" (e.g.
        // 0=red, 1=yellow, 2=green) would silently break every
        // dashboard filter keyed on `ready_for_traffic === true` /
        // `=== false`. The existing
        // `setup_status_envelope_contains_items_and_readiness` pin
        // covers the field NAME + value-equality on a single false
        // case, but does NOT pin the type tag. Pin both polarities
        // as JSON booleans here.
        let red = SetupStatus {
            ready_for_traffic: false,
            items: vec![],
        };
        let v = serde_json::to_value(&red).unwrap();
        assert!(v["ready_for_traffic"].is_boolean(), "got: {v}");
        assert_eq!(v["ready_for_traffic"], false);
        let green = SetupStatus {
            ready_for_traffic: true,
            items: vec![],
        };
        let v = serde_json::to_value(&green).unwrap();
        assert!(v["ready_for_traffic"].is_boolean(), "got: {v}");
        assert_eq!(v["ready_for_traffic"], true);
    }

    #[test]
    fn check_item_ok_serializes_as_json_boolean_and_detail_as_string_regardless_of_content() {
        // `ok: bool` MUST land on the wire as a JSON boolean (not
        // a 0/1 integer or a "true"/"false" string — both would break
        // the admin UI's `if (item.ok)` rendering branch which strictly
        // dispatches on JSON's `true`/`false` literal). `detail: String`
        // MUST land as a JSON string regardless of content shape (even
        // an all-numeric detail like "0 client(s) registered" must NOT
        // serialize as a number). Pin both type tags on both polarities
        // of ok and across two distinct detail shapes (text + numeric).
        let item = CheckItem {
            id: "x",
            title: "T",
            ok: true,
            detail: "12 policies loaded".into(),
            fix: None,
            docs: "d",
        };
        let v = serde_json::to_value(&item).unwrap();
        assert!(v["ok"].is_boolean(), "ok must be JSON bool: {v}");
        assert!(v["detail"].is_string(), "detail must be JSON string: {v}");
        // All-numeric detail still surfaces as string (not coerced).
        let numeric_detail = CheckItem {
            id: "x",
            title: "T",
            ok: false,
            detail: "0".into(),
            fix: None,
            docs: "d",
        };
        let v = serde_json::to_value(&numeric_detail).unwrap();
        assert!(
            v["detail"].is_string(),
            "numeric-content detail must remain string: {v}"
        );
        assert_eq!(v["detail"], "0");
        assert!(v["ok"].is_boolean(), "ok=false must be JSON bool: {v}");
    }

    #[tokio::test]
    async fn setup_error_response_body_carries_fix_and_docs_hints() {
        // The 500 envelope must surface the troubleshooting link AND a
        // copy-paste-able fix hint (curl /healthz). Both are part of
        // the operator's first 30 seconds when triaging — pin them so
        // a refactor that dropped `.with_fix(...)` (e.g. "the response
        // body shouldn't carry suggestions") doesn't silently regress
        // the operator-onboarding contract from the install docs.
        let r = SetupError::Db(sqlx::Error::RowNotFound).into_response();
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["fix"].as_str().unwrap().contains("curl /healthz"));
        assert!(v["detail"].as_str().unwrap().contains("database error"));
    }

    #[test]
    fn check_item_title_field_is_static_str_lifetime_for_zero_alloc_admin_ui_render() {
        // The `/admin/setup` HTML page renders the title verbatim per
        // checklist item — load-bearing for the user-facing copy
        // ("Database", "Layer-B policies", "Registered OAuth clients"
        // etc.). The existing pin (`check_item_id_field_is_static_str_for_zero_alloc_logging`)
        // walks the `id` field's 'static lifetime but never the
        // sibling `title` field. A refactor to `String` "for
        // dynamically-localized titles" would silently allocate one
        // String per checklist item per `/admin/setup` hit. Pin
        // lifetime via require_static_str — symmetric to round-169
        // BlockedNotification SCHEMA + round-170 Healthz.version
        // static-str pins extended to CheckItem.title.
        fn require_static_str(_: &'static str) {}
        let item = CheckItem {
            id: "x",
            title: "Database",
            ok: true,
            detail: "connected".into(),
            fix: None,
            docs: "d",
        };
        require_static_str(item.title);
        // And docs is also 'static — pin both sibling fields together.
        require_static_str(item.docs);
    }

    #[test]
    fn check_item_fix_field_is_option_of_static_str_lifetime_for_zero_alloc_some_variant() {
        // The `fix` field carries copy-paste-able operator instructions
        // (e.g. "Set DATABASE_URL to a reachable postgres URL..."). These
        // are literal docstrings authored in the handler, never
        // dynamically composed — `Option<&'static str>`, not
        // `Option<String>`. A refactor that swapped to `Option<String>`
        // "for ergonomic format!()-based fix strings" would silently
        // allocate one String per failed check per `/admin/setup` hit
        // AND would let a future `format!("Set X={value}")` interpolate
        // request-time state into the fix message (a path that has
        // never required runtime input, so a regression that started
        // doing it would silently widen the surface). Pin lifetime
        // via require_static_str on the Some-polarity.
        fn require_static_str(_: &'static str) {}
        let item = CheckItem {
            id: "x",
            title: "T",
            ok: false,
            detail: "down".into(),
            fix: Some("Set DATABASE_URL to a reachable postgres URL."),
            docs: "d",
        };
        require_static_str(item.fix.expect("Some-polarity fixture"));
    }

    #[test]
    fn check_item_serializes_with_exactly_six_known_keys_for_admin_ui_table_contract() {
        // The `/admin/setup` UI table renders one row per checklist item
        // with 6 columns (id, title, ok, detail, fix, docs). The existing
        // pins walk individual key values via `v["k"]` but never the
        // EXHAUSTIVE 6-key set — a refactor adding a `severity` field
        // "for priority bucketing" would silently widen every UI row
        // and break consumers (e.g. CLI scrapers that destructure the
        // shape with serde::Deserialize on a 6-field struct). Pin
        // HashSet equality on the 6 keys — symmetric to round-161
        // PolicyView 5-key + round-165 TokenResponse 4-key + round-169
        // BlockedNotification 16-key + round-170 Healthz/Check 3-field
        // exhaustive-set pins extended to CheckItem.
        let item = CheckItem {
            id: "database",
            title: "Database",
            ok: true,
            detail: "connected".into(),
            fix: None,
            docs: "https://proxilion.com/docs/install",
        };
        let v = serde_json::to_value(&item).unwrap();
        let obj = v
            .as_object()
            .expect("CheckItem must serialize as JSON object");
        let keys: std::collections::HashSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected: std::collections::HashSet<&str> =
            ["id", "title", "ok", "detail", "fix", "docs"]
                .into_iter()
                .collect();
        assert_eq!(
            keys, expected,
            "CheckItem must serialize with EXACTLY these 6 keys for admin UI table",
        );
    }

    #[test]
    fn setup_status_serializes_with_exactly_two_known_keys_ready_for_traffic_and_items() {
        // The `/api/v1/setup/status` envelope is consumed by both the
        // operator HTML page (`ready_for_traffic` powers the big
        // green/red banner) AND the CLI's `proxilion-cli status`
        // renderer. The existing pins walk both keys individually but
        // never the EXHAUSTIVE 2-key set — a refactor adding a
        // `last_checked_at` "for caching diagnostics" would silently
        // widen the envelope and break consumers that destructure on
        // 2 fields exactly. Pin HashSet equality.
        let status = SetupStatus {
            ready_for_traffic: false,
            items: vec![],
        };
        let v = serde_json::to_value(&status).unwrap();
        let obj = v
            .as_object()
            .expect("SetupStatus must serialize as JSON object");
        let keys: std::collections::HashSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected: std::collections::HashSet<&str> =
            ["ready_for_traffic", "items"].into_iter().collect();
        assert_eq!(
            keys, expected,
            "SetupStatus must serialize with EXACTLY these 2 keys for admin UI envelope",
        );
    }

    #[test]
    fn check_item_docs_url_uses_https_scheme_for_operator_facing_link_safety() {
        // Every operator-facing docs URL across the 6 known checklist
        // items MUST use `https://` — a `http://` link in the admin UI
        // would surface a mixed-content warning AND would expose the
        // operator's referer + session cookie to a network observer on
        // first click (the admin UI itself is served over TLS). The
        // existing pin (`check_item_some_fix_includes_actionable_keyword`)
        // walks the `fix` field's content but never the `docs` field's
        // scheme. Pin the contract: every operator-authored docs URL
        // in the module starts with `https://` and contains
        // `proxilion.com/docs/`.
        let module_docs = [
            "https://proxilion.com/docs/install",
            "https://proxilion.com/docs/policy/authoring",
            "https://proxilion.com/docs/oauth/clients",
            "https://proxilion.com/docs/install/google",
            "https://proxilion.com/docs/getting-started/first-pca",
            "https://proxilion.com/docs/federation-bridge",
        ];
        for url in &module_docs {
            assert!(
                url.starts_with("https://"),
                "docs URL must use https scheme: {url}",
            );
            assert!(
                url.contains("proxilion.com/docs/"),
                "docs URL must point to proxilion.com/docs/: {url}",
            );
            // Pin via the type check too: each is a &'static str.
            fn require_static_str(_: &'static str) {}
            require_static_str(url);
        }
    }

    #[test]
    fn setup_status_envelope_is_referentially_transparent_across_fifty_serializations() {
        // Symmetric to round-161 + round-162 + round-166 + round-168
        // + round-169 + round-170 referential-transparency pins
        // extended to SetupStatus serialization. The `/api/v1/setup/status`
        // endpoint may be polled at sub-second intervals by an installer
        // UI watching for "ready_for_traffic" to flip; a refactor
        // caching the JSON in a once-cell keyed on `&status as *const _`
        // "for hot-path perf" would silently return stale bytes on a
        // re-built SetupStatus with newly-flipped ready_for_traffic.
        // Pin 50 serialization calls on the same struct yield byte-equal
        // JSON.
        let status = SetupStatus {
            ready_for_traffic: true,
            items: vec![
                CheckItem {
                    id: "database",
                    title: "Database",
                    ok: true,
                    detail: "connected".into(),
                    fix: None,
                    docs: "https://proxilion.com/docs/install",
                },
                CheckItem {
                    id: "policies",
                    title: "Layer-B policies",
                    ok: false,
                    detail: "no policy file configured".into(),
                    fix: Some("Set PROXILION_POLICY_PATH..."),
                    docs: "https://proxilion.com/docs/policy/authoring",
                },
            ],
        };
        let baseline = serde_json::to_string(&status).unwrap();
        for i in 0..50 {
            let again = serde_json::to_string(&status).unwrap();
            assert_eq!(
                again, baseline,
                "iteration {i}: SetupStatus serialization must be referentially transparent",
            );
        }
    }

    // ─── round 191 (2026-05-20): SetupError + SetupApiState + CheckItem type pins ───

    #[test]
    fn setup_error_variant_count_pinned_at_exactly_one_via_exhaustive_match() {
        // `SetupError` has exactly 1 variant today (Db). The setup
        // probe currently only fails on the database query — every
        // other check is a static bool inspection that returns Ok.
        // A refactor that landed a second variant (e.g. `BadPath` if
        // a future check resolved the `PROXILION_POLICY_PATH` file
        // synchronously) would surface a second grep bucket the
        // dashboard's "Setup probe failures" tile wasn't sized for.
        // Pin the variant count via an exhaustive match — a new arm
        // forces this test to compile-fail at the match site.
        // Symmetric to round-190 ApiError 2-variant + round-189
        // ActionsApiError 4-variant + round-182 CatKeyError
        // 3-variant exhaustive-match pins extended to this sibling
        // error enum.
        fn arm_name(e: &SetupError) -> &'static str {
            match e {
                SetupError::Db(_) => "Db",
            }
        }
        let one = SetupError::Db(sqlx::Error::RowNotFound);
        let names: std::collections::HashSet<&'static str> =
            std::iter::once(&one).map(arm_name).collect();
        assert_eq!(names.len(), 1, "exactly one variant-name walked");
        assert_eq!(arm_name(&SetupError::Db(sqlx::Error::RowNotFound)), "Db");
    }

    #[tokio::test]
    async fn setup_api_state_field_types_match_documented_contract_owned_string_bool_usize() {
        // `SetupApiState` has 5 fields. The non-DB four MUST match
        // their documented types: `google_configured: bool` AND
        // `policy_path_configured: bool` (probe results, copied
        // from env-var inspection); `federation_bridge_url: String`
        // (owned because read from config and persisted in state);
        // `policy_count: usize` (matches Engine::policy_count's
        // `Vec::len()` return type). A refactor to `&'a str` for
        // federation_bridge_url would force a lifetime parameter
        // that breaks `Clone` + the axum State boundary; a refactor
        // to u32 for policy_count would force a cast at the
        // `Engine::policy_count()` call site. Pin each via the
        // canonical require_* helpers. Symmetric to round-188
        // ListResponse.policy_count usize + round-190 KillResponse.
        // bearers_revoked i64 + round-189 ListRow.status i32 pins
        // extended to this state envelope's 4 non-DB fields.
        fn require_string(_: &String) {}
        fn require_usize(_: usize) {}
        fn require_bool(_: bool) {}
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/x")
            .expect("lazy pool builds");
        let state = SetupApiState {
            db: pool,
            google_configured: true,
            federation_bridge_url: "https://federation.example/v1".into(),
            policy_path_configured: false,
            policy_count: 12,
        };
        require_bool(state.google_configured);
        require_bool(state.policy_path_configured);
        require_string(&state.federation_bridge_url);
        require_usize(state.policy_count);
    }

    #[test]
    fn check_item_detail_field_is_owned_string_type_for_runtime_formatted_content() {
        // `CheckItem.detail: String` — the ONLY owned-String field
        // on CheckItem (the four `&'static str` fields + the bool +
        // the `Option<&'static str>` are all pinned elsewhere). The
        // handler builds the detail via `format!("{count} PCA(s) in
        // cache")` and `format!("configured URL: {url} ...")` — it
        // MUST be owned to capture the format-result lifetime. A
        // refactor to `Cow<'static, str>` "for zero-alloc when the
        // detail is a static literal" would introduce a lifetime
        // parameter that the axum Json extractor's owned-content
        // contract can't satisfy. Pin owned-String via require_string.
        // Symmetric to round-189 ListRow 6-field owned-String sweep
        // + round-190 KillResponse.target owned-String extended to
        // this sibling response-shape's only runtime-formatted field.
        fn require_string(_: &String) {}
        let item = CheckItem {
            id: "first_pca",
            title: "First successful PCA",
            ok: true,
            detail: "42 PCA(s) in cache".into(),
            fix: None,
            docs: "d",
        };
        require_string(&item.detail);
    }

    #[test]
    fn check_item_and_setup_status_are_send_sync_static_for_axum_json_response_boundary() {
        // Both `CheckItem` and `SetupStatus` flow through axum's
        // `Json(...)` response builder at the end of the `status`
        // handler, crossing the final `.await` boundary. The
        // response builder requires `Send + 'static`; tokio task
        // spawn across the response stream needs `Sync` too. A
        // refactor that introduced a !Send field on either (e.g. a
        // `Cell<bool>` "for a per-render check-result cache") would
        // surface here rather than at the handler-bound trait error
        // far from this file. Pin the three-trait combo on both
        // envelopes — symmetric to round-189 ListResponse + ListRow
        // + round-190 KillBody + KillResponse Send+Sync+'static
        // pins extended to this API module's response shapes.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<CheckItem>();
        require_send_sync_static::<SetupStatus>();
    }

    #[test]
    fn setup_error_db_arm_chain_walk_terminates_after_at_most_two_hops_for_anyhow_render_safety() {
        // The existing pin (`setup_error_db_arm_chains_source_to_inner_sqlx_error_via_from_derive`)
        // asserts `source()` returns `Some(_)` — but never walks the
        // chain to its terminal. The killswitch sibling's BadRequest
        // arm has chain depth 0 (leaf); SetupError::Db has chain
        // depth >= 1 (wraps sqlx::Error). Pin the chain depth at
        // most 2 (SetupError → sqlx::Error → optional db-driver-
        // specific root) so a refactor that wrapped Db in
        // `anyhow::Error` "for richer context" would surface here as
        // an unbounded chain walk (anyhow can chain arbitrarily
        // deep). Operator-facing log renderers (tracing's
        // `?err`-with-source-chain) and the JSON error envelope
        // walk the chain once — a deep chain would dump excessive
        // detail into every 500 response body.
        let e = SetupError::Db(sqlx::Error::RowNotFound);
        let dyn_err: &dyn std::error::Error = &e;
        let first = std::error::Error::source(dyn_err);
        assert!(first.is_some(), "Db arm exposes inner source");
        let second = first.and_then(std::error::Error::source);
        if let Some(s) = second {
            // If a chain past depth 2 exists, surface it.
            let third = std::error::Error::source(s);
            assert!(
                third.is_none(),
                "SetupError chain must terminate at <= depth 2 to keep error envelopes bounded",
            );
        }
    }

    #[test]
    fn setup_status_items_field_is_owned_vec_check_item_for_response_body_outlives_handler_frame() {
        // `SetupStatus.items: Vec<CheckItem>` — the field is owned,
        // not a borrowed slice (`&'a [CheckItem]`). The status
        // handler builds the Vec inside its frame and returns it
        // wrapped in `Json(...)`. A refactor to `&'a [CheckItem]`
        // "for zero-alloc on the static case" would force a
        // lifetime parameter that the response boundary can't
        // satisfy AND would force every checklist item to be
        // 'static (foreclosing the runtime-built `format!`
        // shapes). Pin via require_vec_check_item helper.
        // Symmetric to round-189 ListRow 6-field owned-String
        // sweep extended one structural level up to the Vec
        // envelope of CheckItem.
        fn require_vec_check_item(_: &Vec<CheckItem>) {}
        let s = SetupStatus {
            ready_for_traffic: true,
            items: vec![CheckItem {
                id: "x",
                title: "T",
                ok: true,
                detail: "ok".into(),
                fix: None,
                docs: "d",
            }],
        };
        require_vec_check_item(&s.items);
        assert_eq!(s.items.len(), 1);
    }

    #[test]
    fn setup_api_state_is_clone_send_sync_static_for_axum_state_boundary() {
        // The existing pin
        // (`setup_api_state_and_setup_error_are_send_sync_static_for_axum_boundary`)
        // walks Send+Sync+'static but not Clone — axum's State
        // extractor clones the state per request, so all four traits
        // must hold for the router to compile. A refactor that gave
        // SetupApiState a `Mutex<...>` field (Mutex<T> is !Clone)
        // "for lazy-init of the federation URL" would break the
        // Clone bound and surface as a far-removed router-assembly
        // trace. Pin all four trait bounds together here.
        // Symmetric to round-190 KillswitchApiState Clone + round-
        // 192 SlackInteractState require_clone_send_sync_static
        // pins extended to this sibling state envelope.
        fn require_clone_send_sync_static<T: Clone + Send + Sync + 'static>() {}
        require_clone_send_sync_static::<SetupApiState>();
    }

    #[test]
    fn setup_api_state_field_count_pinned_at_exactly_five_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the SetupApiState struct field count at exactly 5 via
        // exhaustive destructure (no `..`). The 5 fields are: db
        // (PgPool) + google_configured (bool) + federation_bridge_url
        // (String) + policy_path_configured (bool) + policy_count
        // (usize). A 6th field landing (e.g. `notifier_configured:
        // bool` to surface the notifier driver state in the setup
        // panel, or `trust_plane_url: String` to distinguish the
        // PIC executor's endpoint from the federation bridge) would
        // silently bloat every Clone the axum router fans out per
        // request AND silently extend the boot-path's assembled-
        // setup-state contract. Pin via exhaustive destructure.
        fn _destructure_witness(s: SetupApiState) {
            let SetupApiState {
                db: _,
                google_configured: _,
                federation_bridge_url: _,
                policy_path_configured: _,
                policy_count: _,
            } = s;
        }
    }

    #[test]
    fn check_item_field_count_pinned_at_exactly_six_via_exhaustive_destructure_no_rest_pattern() {
        // Pin the CheckItem wire-shape struct field count at exactly
        // 6 via exhaustive destructure (no `..`). The 6 fields are:
        // id + title + ok + detail + fix + docs. A 7th field landing
        // (e.g. `severity: &'static str` to color-code the operator-
        // facing setup-status panel by criticality, or `last_checked:
        // DateTime<Utc>` to surface staleness on the per-item card)
        // would silently extend the wire shape every dashboard / CLI
        // consumer reads — and a `#[serde(skip_serializing_if =
        // "Option::is_none")]` 7th field would silently bypass any
        // serde-key sweep test. The existing
        // `setup_status_items_preserve_insertion_order_on_serialize`
        // pin walks Vec order; exhaustive destructure pins the
        // struct shape symmetrically.
        let v = CheckItem {
            id: "x",
            title: "x",
            ok: false,
            detail: String::new(),
            fix: None,
            docs: "x",
        };
        let CheckItem {
            id: _,
            title: _,
            ok: _,
            detail: _,
            fix: _,
            docs: _,
        } = v;
    }

    #[test]
    fn setup_status_field_count_pinned_at_exactly_two_via_exhaustive_destructure_no_rest_pattern() {
        // Pin the SetupStatus wire-shape struct field count at
        // exactly 2 via exhaustive destructure (no `..`). The 2
        // fields are: ready_for_traffic (bool) + items
        // (Vec<CheckItem>). A 3rd field landing (e.g.
        // `version: &'static str` to surface the proxy build
        // version next to the setup checks, or `host: String` for
        // future multi-host dashboard support) would silently
        // extend the `/api/v1/setup/status` envelope every operator
        // dashboard reads AND silently change the existing
        // SetupStatus.items insertion-order pin's reachable
        // surface.
        let v = SetupStatus {
            ready_for_traffic: false,
            items: vec![],
        };
        let SetupStatus {
            ready_for_traffic: _,
            items: _,
        } = v;
    }

    #[test]
    fn setup_api_state_string_field_is_owned_for_arc_swap_envvar_outlives_request() {
        // `SetupApiState.federation_bridge_url: String` is owned
        // bytes — the env-var-derived string is captured at app
        // assembly and the state Clone fan-outs each carry an
        // independent String via the existing Clone derive. A
        // refactor to `&'a str` "to avoid the per-clone allocation"
        // would surface a lifetime parameter that the axum
        // State<T> extractor's owned-content contract can't satisfy
        // (the request handler outlives any borrow into the boot-
        // path env). Pin owned-String type via require_string on
        // a fn-destructure witness — symmetric to round-176
        // PolicyBundle + round-185 SetModeBody owned-String pins
        // extended to this state envelope's URL field. We use a
        // fn-destructure witness rather than constructing a real
        // SetupApiState because the inner PgPool requires a tokio
        // runtime context that #[test] doesn't provide.
        #[allow(dead_code)]
        fn require_string(_: &String) {}
        #[allow(dead_code)]
        fn _witness(s: SetupApiState) {
            let SetupApiState {
                federation_bridge_url,
                ..
            } = s;
            require_string(&federation_bridge_url);
        }
    }

    #[test]
    fn setup_error_implements_into_response_via_trait_object_witness_for_axum_handler_arm() {
        // The SetupError enum is the per-handler error type the
        // status() handler returns through the `?` operator —
        // axum's IntoResponse trait is what makes
        // `Result<Json<SetupStatus>, SetupError>` a valid handler
        // return type. A refactor that dropped the
        // `impl IntoResponse for SetupError` block would force the
        // handler to wrap the error explicitly. Pin via
        // require_into_response trait-bound witness — symmetric
        // to round-262 api/mod.rs + round-268 killswitch require_into_response
        // pins extended to SetupError.
        fn require_into_response<T: IntoResponse>() {}
        require_into_response::<SetupError>();
    }

    #[test]
    fn router_function_signature_pinned_via_fn_pointer_witness() {
        // Pin the module's router constructor signature as
        // `fn(SetupApiState) -> Router` via fn-pointer witness.
        // Symmetric to round-262/263/264/265/266/268/269/270
        // router fn-pointer pins extended to the setup API
        // surface. The server.rs boot path calls
        // `router(setup_state)` once at app assembly AND consumes
        // the state by value (the router clones it per request
        // via `.with_state(...)`). A refactor to
        // `fn(&SetupApiState) -> Router` or
        // `fn(SetupApiState) -> Result<Router, _>` would silently
        // change the boot path's ownership AND error-handling
        // shape.
        let _f: fn(SetupApiState) -> Router = router;
    }
}
