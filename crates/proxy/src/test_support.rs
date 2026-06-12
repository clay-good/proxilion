//! Shared scaffolding for DB-backed integration-style unit tests.
//!
//! These tests exercise real handlers against a real Postgres so the SQL,
//! the migrations, and the request/response wiring are covered end-to-end
//! (the proxy is a binary-only crate, so `crates/proxy/tests/` can't reach
//! these internals — in-module `#[cfg(test)]` tests are the only way to drive
//! private handlers directly).
//!
//! They are **opt-in**: a test calls [`pool`] and returns early when
//! `PROXILION_TEST_DATABASE_URL` is unset, so the default `cargo test` run
//! (and CI, which has no Postgres service today) simply skips them and stays
//! green. To run them:
//!
//! ```sh
//! docker run -d --name pg -e POSTGRES_USER=proxilion -e POSTGRES_PASSWORD=proxilion \
//!     -e POSTGRES_DB=proxilion_test -p 55432:5432 postgres:16-alpine
//! PROXILION_TEST_DATABASE_URL=postgres://proxilion:proxilion@localhost:55432/proxilion_test \
//!     cargo test -p proxy --  --include-ignored db_backed
//! ```

#![cfg(test)]

use sqlx::PgPool;

/// The env var that opts a process into DB-backed tests.
pub const TEST_DB_ENV: &str = "PROXILION_TEST_DATABASE_URL";

/// Connect to the test database (if configured) and apply all migrations,
/// returning a ready pool. Returns `None` — so the caller `return`s and the
/// test is skipped — when `PROXILION_TEST_DATABASE_URL` is unset.
///
/// `sqlx::migrate!` is idempotent and takes an advisory lock, so concurrent
/// test tasks sharing one database apply migrations safely.
pub async fn pool() -> Option<PgPool> {
    let url = std::env::var(TEST_DB_ENV).ok().filter(|u| !u.is_empty())?;
    let pool = PgPool::connect(&url)
        .await
        .unwrap_or_else(|e| panic!("connect {TEST_DB_ENV}: {e}"));
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations to the test database");
    Some(pool)
}

// ─────────────────────────────────────────────────────────────────────────
// Adapter-integration scaffolding (shared by the google_drive / google_gmail
// db_backed tests). These build a real `AdapterState` whose PIC executor and
// Google base point at wiremock servers, so the full `proxy_request` template
// (policy eval → PIC mint → upstream → read-filter / block) runs end-to-end.
// ─────────────────────────────────────────────────────────────────────────

use std::sync::Arc;
use uuid::Uuid;

/// Seed a predecessor `pca_cache` row — the leaf PCA an adapter's
/// audit-fallback or successor-mint references.
pub async fn seed_pca_cache(pool: &PgPool, pca_id: Uuid, p_0: &str) {
    sqlx::query(
        "INSERT INTO pca_cache (pca_id, cbor, p_0, ops, hop, signature)
         VALUES ($1, '\\x00', $2, '[]'::jsonb, 1, '\\x00')",
    )
    .bind(pca_id)
    .bind(p_0)
    .execute(pool)
    .await
    .expect("seed pca_cache");
}

/// A minimal in-memory `SessionContext` (the request principal an adapter
/// `proxy_request` operates on; the SessionCtx extractor is bypassed).
pub fn mock_session(leaf_pca_id: Uuid, p_0: &str) -> Arc<crate::session::SessionContext> {
    Arc::new(crate::session::SessionContext {
        agent_session_id: Uuid::new_v4(),
        bearer_hash: [0u8; 32],
        p_0: p_0.to_string(),
        leaf_pca_id,
        leaf_pca_cbor: vec![0u8; 4],
        granted_ops: vec!["drive:read:file/abc".into()],
        google_access_token: "ya29.test".into(),
        google_token_scope: "https://www.googleapis.com/auth/drive.readonly".into(),
    })
}

/// Build an `AdapterState` loaded with `policy_yaml`, whose PIC executor talks
/// to `trust_plane_uri` and whose upstream Google base is `google_uri` (both
/// typically wiremock servers).
pub fn adapter_state(
    pool: PgPool,
    policy_yaml: &str,
    trust_plane_uri: String,
    google_uri: String,
) -> crate::adapters::state::AdapterState {
    let engine = policy_engine::Engine::new(policy_yaml).expect("policy parses");
    let policy = crate::policy_handle::PolicyHandle::new(engine, None, policy_yaml.to_string());
    let auth = crate::auth_middleware::AuthState {
        db: pool.clone(),
        cipher: Arc::new(crate::crypto::TokenCipher::from_bytes(&[0u8; 32]).unwrap()),
        pca_cache: crate::pic::PcaCache::new(pool.clone()),
        cat_keys: crate::pic::CatKeyRegistry::new(trust_plane_uri.clone()),
        refresh_coordinator: crate::auth_middleware::RefreshCoordinator::default(),
        google_token_url: "https://oauth2.googleapis.com/token".into(),
        google_client_id: "c".into(),
        google_client_secret: "s".into(),
        http: reqwest::Client::new(),
        kill_cache: crate::kill_cache::KillCache::new(),
    };
    let pic = crate::pic::PicExecutor::dev_ephemeral(trust_plane_uri).expect("pic executor");
    crate::adapters::state::AdapterState {
        auth,
        policy,
        pic,
        upstream: reqwest::Client::new(),
        stream: Arc::new(crate::adapters::action_stream::LoggingStream),
        google_api_base: Some(google_uri),
        customer_domain: "acme.com".into(),
        notifier: crate::notifier::Notifiers::empty(),
    }
}

/// Mount a wiremock Trust Plane that registers the executor key (200) and
/// **rejects** the PoC with `422` — so an audit-mode mint falls back to the
/// predecessor and a runtime-gate mint surfaces a `PicInvariantViolation`.
pub async fn mock_trust_plane_reject() -> wiremock::MockServer {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let tp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/keys/executor"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&tp)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/poc/process"))
        .respond_with(ResponseTemplate::new(422).set_body_string("audit: missing ops"))
        .mount(&tp)
        .await;
    tp
}
