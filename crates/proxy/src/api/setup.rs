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
