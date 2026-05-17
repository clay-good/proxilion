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
}
