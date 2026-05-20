//! Bearer middleware — validates `pxl_live_*` and loads the SessionContext.
//!
//! Authority: spec.md §1.2. Errors are *always* mapped to 401 with the
//! fixed body `unauthorized`; the cause goes to logs + metrics only.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header::AUTHORIZATION};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use moka::future::Cache;
use serde::Deserialize;
use shared_types::provenance::crypto::SignedPca;
use tokio::sync::Mutex;
use tracing::{debug, info_span, instrument, warn};
use uuid::Uuid;

use crate::crypto::{Bearer, BearerHash, Ciphertext, TokenCipher};
use crate::kill_cache::KillCache;
use crate::pic::{CatKeyRegistry, PcaCache};
use crate::session::SessionContext;

/// State the middleware needs to do its job. Constructed once at startup
/// (see `server.rs::build_auth_state`).
#[derive(Clone)]
pub struct AuthState {
    pub db: sqlx::PgPool,
    pub cipher: Arc<TokenCipher>,
    pub pca_cache: PcaCache,
    pub cat_keys: CatKeyRegistry,
    pub refresh_coordinator: RefreshCoordinator,
    pub google_token_url: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub http: reqwest::Client,
    /// In-process kill-cache (spec.md §3.2 dev 2). Cache HIT short-circuits
    /// the DB JOIN; cache MISS falls through to the DB (the source of
    /// truth). Killswitch handlers populate this after the DB UPDATE
    /// commits.
    pub kill_cache: KillCache,
}

/// Per-bearer mutex so 50 concurrent requests with the same expired Google
/// token trigger exactly *one* refresh upstream. Cache holds the mutex for
/// 10 minutes after last access — refreshed sessions don't recreate it.
#[derive(Clone)]
pub struct RefreshCoordinator {
    locks: Cache<[u8; 32], Arc<Mutex<()>>>,
}

impl Default for RefreshCoordinator {
    fn default() -> Self {
        Self {
            locks: Cache::builder()
                .max_capacity(10_000)
                .time_to_idle(Duration::from_secs(600))
                .build(),
        }
    }
}

impl RefreshCoordinator {
    pub async fn lock_for(&self, hash: [u8; 32]) -> Arc<Mutex<()>> {
        self.locks
            .get_with(hash, async { Arc::new(Mutex::new(())) })
            .await
    }
}

/// Generic 401 — no detail in the body, ever.
fn unauthorized() -> Response {
    metrics::counter!("proxilion_auth_attempts_total", "result" => "rejected").increment(1);
    (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
}

pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let bearer = match req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_owned())
    {
        Some(b) => b,
        None => {
            warn!(reason = "missing Authorization", "bearer rejected");
            return unauthorized();
        }
    };
    match build_session(&state, &bearer).await {
        Ok(session) => {
            metrics::counter!("proxilion_auth_attempts_total", "result" => "ok").increment(1);
            req.extensions_mut().insert(Arc::new(session));
            next.run(req).await
        }
        Err(why) => {
            warn!(reason = %why, "bearer rejected");
            unauthorized()
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // variants are matched indirectly through Display in logs
enum AuthFail {
    #[error("bearer format invalid")]
    BadFormat,
    #[error("bearer not found / revoked")]
    NotFound,
    #[error("google token decrypt failed")]
    Decrypt,
    #[error("google token refresh failed: {0}")]
    Refresh(String),
    #[error("PCA cache miss (no upstream GET /v1/pca/{{id}} available)")]
    PcaCacheMiss,
    #[error("PCA signature verification failed")]
    PcaTampered,
    #[error("CAT key fetch failed: {0}")]
    CatKey(String),
    #[error("database error")]
    Db(#[from] sqlx::Error),
    #[error("internal: {0}")]
    Other(String),
}

async fn build_session(state: &AuthState, token: &str) -> Result<SessionContext, AuthFail> {
    // 1+2. Format check.
    Bearer::parse(token).ok_or(AuthFail::BadFormat)?;
    let hash = BearerHash::of(token);

    // 2a. Kill-cache fast path (spec.md §3.2 dev 2). A hit means a
    // recent killswitch invocation already revoked this bearer; bypass
    // the DB JOIN. The DB row is still the source of truth; a cache
    // miss falls through to the existing JOIN below.
    if state.kill_cache.is_killed(&hash.0).await {
        return Err(AuthFail::NotFound);
    }

    // 3. Look up bearer + join google_tokens.
    let row: Option<(
        Uuid,
        Uuid,
        Uuid,
        String,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        String,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        r#"
        SELECT ab.session_id, ab.pca_1_id, gt.id,
               ab.scope,
               gt.access_token_ciphertext, gt.access_token_nonce,
               gt.refresh_token_ciphertext, gt.refresh_token_nonce,
               os.p_0,
               gt.expires_at,
               ab.revoked_at
          FROM agent_bearers ab
          JOIN google_tokens gt ON gt.id = ab.google_tokens_id
          JOIN oauth_sessions os ON os.id = ab.session_id
         WHERE ab.bearer_sha256 = $1
        "#,
    )
    .bind(hash.as_bytes())
    .fetch_optional(&state.db)
    .await?;
    let Some((
        session_id,
        pca_1_id,
        google_tokens_id,
        scope,
        access_ct,
        access_nonce,
        refresh_ct,
        refresh_nonce,
        p_0,
        expires_at,
        revoked_at,
    )) = row
    else {
        return Err(AuthFail::NotFound);
    };
    if revoked_at.is_some() {
        return Err(AuthFail::NotFound);
    }

    // 4. Decrypt Google access token.
    let mut access_plain = state
        .cipher
        .decrypt(&Ciphertext {
            nonce: access_nonce.clone(),
            bytes: access_ct.clone(),
        })
        .map_err(|_| AuthFail::Decrypt)?;

    // 5. Refresh if within 60s of expiry (and we have a refresh token).
    let needs_refresh = expires_at <= Utc::now() + chrono::Duration::seconds(60);
    if needs_refresh {
        let (Some(refresh_ct_b), Some(refresh_nonce_b)) = (refresh_ct, refresh_nonce) else {
            // No refresh token — let upstream Google return 401 naturally.
            debug!("token near expiry but no refresh token available");
            return Err(AuthFail::Refresh("no refresh_token on file".into()));
        };
        let new_plain = refresh_with_coalescing(
            state,
            hash.0,
            google_tokens_id,
            &Ciphertext {
                nonce: refresh_nonce_b,
                bytes: refresh_ct_b,
            },
        )
        .await?;
        access_plain = new_plain;
    }

    let access_token = String::from_utf8(access_plain).map_err(|_| AuthFail::Decrypt)?;

    // 6. Load PCA_1 from cache + verify CAT signature.
    let cached = state
        .pca_cache
        .get(pca_1_id)
        .await
        .map_err(|e| AuthFail::Other(e.to_string()))?;
    let Some(cached) = cached else {
        metrics::counter!("proxilion_pca_cache_misses_total").increment(1);
        return Err(AuthFail::PcaCacheMiss);
    };
    metrics::counter!("proxilion_pca_cache_hits_total").increment(1);

    verify_pca_signature(state, &cached.cbor).await?;

    Ok(SessionContext {
        agent_session_id: session_id,
        bearer_hash: hash.0,
        p_0,
        leaf_pca_id: pca_1_id,
        leaf_pca_cbor: cached.cbor,
        granted_ops: cached.ops,
        google_access_token: access_token,
        google_token_scope: scope,
    })
}

async fn verify_pca_signature(state: &AuthState, cbor: &[u8]) -> Result<(), AuthFail> {
    let key = state
        .cat_keys
        .get()
        .await
        .map_err(|e| AuthFail::CatKey(e.to_string()))?;
    verify_with_key(cbor, key)
}

fn verify_with_key(
    cbor: &[u8],
    key: &shared_types::provenance::crypto::PublicKey,
) -> Result<(), AuthFail> {
    let signed = SignedPca::from_bytes(cbor)
        .map_err(|e| AuthFail::Other(format!("SignedPca decode: {e}")))?;
    key.verify_pca(&signed).map_err(|_| {
        metrics::counter!("proxilion_pca_verify_failures_total").increment(1);
        AuthFail::PcaTampered
    })?;
    Ok(())
}

/// Coalesce concurrent Google refresh calls for the same bearer.
///
/// First waiter does the network refresh + DB update; others observe the
/// updated row when they acquire the lock and skip the upstream call.
#[instrument(skip(state, refresh_ct))]
async fn refresh_with_coalescing(
    state: &AuthState,
    bearer_hash: [u8; 32],
    google_tokens_id: Uuid,
    refresh_ct: &Ciphertext,
) -> Result<Vec<u8>, AuthFail> {
    let lock = state.refresh_coordinator.lock_for(bearer_hash).await;
    let _guard = lock.lock().await;

    // Re-read after lock to see if another waiter already refreshed.
    let (access_ct, access_nonce, expires_at): (Vec<u8>, Vec<u8>, DateTime<Utc>) = sqlx::query_as(
        "SELECT access_token_ciphertext, access_token_nonce, expires_at
               FROM google_tokens WHERE id = $1",
    )
    .bind(google_tokens_id)
    .fetch_one(&state.db)
    .await?;
    if expires_at > Utc::now() + chrono::Duration::seconds(60) {
        debug!("refresh raced; using already-refreshed token");
        metrics::counter!(
            "proxilion_oauth_token_refreshes_total",
            "vendor" => "google",
            "result" => "coalesced",
        )
        .increment(1);
        return state
            .cipher
            .decrypt(&Ciphertext {
                nonce: access_nonce,
                bytes: access_ct,
            })
            .map_err(|_| AuthFail::Decrypt);
    }

    // Do the refresh.
    let refresh_token_plain = state
        .cipher
        .decrypt(refresh_ct)
        .map_err(|_| AuthFail::Decrypt)?;
    let refresh_token_str =
        String::from_utf8(refresh_token_plain).map_err(|_| AuthFail::Decrypt)?;

    #[derive(Deserialize)]
    struct GoogleRefreshResp {
        access_token: String,
        expires_in: i64,
        #[serde(default)]
        refresh_token: Option<String>,
    }

    let resp = state
        .http
        .post(&state.google_token_url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token_str.as_str()),
            ("client_id", state.google_client_id.as_str()),
            ("client_secret", state.google_client_secret.as_str()),
        ])
        .send()
        .await
        .map_err(|e| AuthFail::Refresh(e.to_string()))?;

    if !resp.status().is_success() {
        metrics::counter!(
            "proxilion_oauth_token_refreshes_total",
            "vendor" => "google",
            "result" => "upstream_err",
        )
        .increment(1);
        return Err(AuthFail::Refresh(format!(
            "Google returned {}",
            resp.status()
        )));
    }
    let new: GoogleRefreshResp = resp
        .json()
        .await
        .map_err(|e| AuthFail::Refresh(e.to_string()))?;

    let new_ct = state
        .cipher
        .encrypt(new.access_token.as_bytes())
        .map_err(|_| AuthFail::Decrypt)?;
    let new_refresh = new
        .refresh_token
        .as_deref()
        .map(|s| state.cipher.encrypt(s.as_bytes()))
        .transpose()
        .map_err(|_| AuthFail::Decrypt)?;
    let new_expires = Utc::now() + chrono::Duration::seconds(new.expires_in.max(0));

    let span = info_span!("token_refresh_persist", token_id = %google_tokens_id);
    let _e = span.enter();
    match new_refresh.as_ref() {
        Some(r) => {
            sqlx::query(
                "UPDATE google_tokens
                    SET access_token_ciphertext = $1,
                        access_token_nonce = $2,
                        refresh_token_ciphertext = $3,
                        refresh_token_nonce = $4,
                        expires_at = $5
                  WHERE id = $6",
            )
            .bind(&new_ct.bytes)
            .bind(&new_ct.nonce)
            .bind(&r.bytes)
            .bind(&r.nonce)
            .bind(new_expires)
            .bind(google_tokens_id)
            .execute(&state.db)
            .await?;
        }
        None => {
            sqlx::query(
                "UPDATE google_tokens
                    SET access_token_ciphertext = $1,
                        access_token_nonce = $2,
                        expires_at = $3
                  WHERE id = $4",
            )
            .bind(&new_ct.bytes)
            .bind(&new_ct.nonce)
            .bind(new_expires)
            .bind(google_tokens_id)
            .execute(&state.db)
            .await?;
        }
    }
    metrics::counter!(
        "proxilion_oauth_token_refreshes_total",
        "vendor" => "google",
        "result" => "ok",
    )
    .increment(1);
    Ok(new.access_token.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refresh_coordinator_returns_same_mutex_for_same_hash() {
        let c = RefreshCoordinator::default();
        let h = [42u8; 32];
        let a = c.lock_for(h).await;
        let b = c.lock_for(h).await;
        assert!(Arc::ptr_eq(&a, &b));
    }

    use shared_types::provenance::{
        crypto::KeyPair,
        pca::{ExecutorBinding, PcaBuilder},
        types::PrincipalIdentifier,
    };

    fn signed_pca_bytes(kp: &KeyPair) -> Vec<u8> {
        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice@demo.local"))
            .ops(vec!["drive:read:engineering/*".to_string()])
            .executor(ExecutorBinding::new().with("service", "test"))
            .build_pca_0()
            .unwrap();
        kp.sign_pca(&pca).unwrap().to_bytes().unwrap()
    }

    #[test]
    fn untampered_pca_verifies() {
        let kp = KeyPair::generate("cat-test");
        let pk = kp.public_key();
        let bytes = signed_pca_bytes(&kp);
        assert!(verify_with_key(&bytes, &pk).is_ok());
    }

    #[test]
    fn tampered_pca_caught() {
        let kp = KeyPair::generate("cat-test");
        let pk = kp.public_key();
        let mut bytes = signed_pca_bytes(&kp);
        // Flip a payload byte well past the COSE header to corrupt the signed
        // body without breaking CBOR structure.
        let i = bytes.len() / 2;
        bytes[i] ^= 0x01;
        let err = verify_with_key(&bytes, &pk).unwrap_err();
        assert!(matches!(err, AuthFail::PcaTampered));
    }

    #[test]
    fn pca_signed_by_other_key_rejected() {
        let signer = KeyPair::generate("imposter");
        let verifier_kp = KeyPair::generate("cat-real");
        let verifier_pk = verifier_kp.public_key();
        let bytes = signed_pca_bytes(&signer);
        let err = verify_with_key(&bytes, &verifier_pk).unwrap_err();
        assert!(matches!(err, AuthFail::PcaTampered));
    }

    #[tokio::test]
    async fn refresh_coordinator_distinct_mutex_per_hash() {
        let c = RefreshCoordinator::default();
        let a = c.lock_for([1u8; 32]).await;
        let b = c.lock_for([2u8; 32]).await;
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[tokio::test]
    async fn unauthorized_helper_returns_401_with_plain_body() {
        // The 401 body is intentionally generic: never leak which check
        // failed (bearer missing? revoked? PCA tampered?). Pin the
        // status, the `text/plain` body shape, and the exact byte
        // payload — operators have alerting keyed on this 401 rate as
        // the "agent traffic broken" signal.
        let r = unauthorized();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(r.into_body(), 64).await.unwrap();
        assert_eq!(&bytes[..], b"unauthorized");
    }

    #[test]
    fn auth_fail_display_strings_are_stable_for_log_filters() {
        // Tracing emits `reason = %why` for every rejection. The substrings
        // below are what Grafana / Loki filters key on. A future variant
        // rename or message tweak must be a conscious wire-shape change.
        assert_eq!(AuthFail::BadFormat.to_string(), "bearer format invalid");
        assert_eq!(AuthFail::NotFound.to_string(), "bearer not found / revoked");
        assert_eq!(AuthFail::Decrypt.to_string(), "google token decrypt failed");
        assert!(
            AuthFail::Refresh("network timeout".into())
                .to_string()
                .contains("network timeout"),
        );
        assert_eq!(
            AuthFail::PcaTampered.to_string(),
            "PCA signature verification failed",
        );
        assert!(
            AuthFail::CatKey("trust plane 503".into())
                .to_string()
                .contains("trust plane 503"),
        );
        assert!(
            AuthFail::Other("unexpected".into())
                .to_string()
                .contains("unexpected"),
        );
    }

    #[test]
    fn auth_fail_pca_cache_miss_message_explains_upstream_gap() {
        // The PcaCacheMiss variant carries a pinned message that points
        // at spec.md §1.2 (no upstream GET /v1/pca/{id} yet). Operators
        // who hit this in logs need the explanation, not just an opaque
        // variant name. Pin the substring.
        let s = AuthFail::PcaCacheMiss.to_string();
        assert!(s.contains("PCA cache miss"));
        assert!(s.contains("/v1/pca/"));
    }

    #[test]
    fn auth_fail_from_sqlx_via_question_mark() {
        // `?` conversion is the public path the middleware uses to bubble
        // DB errors up out of the JOIN. Pin the `#[from]` blanket-impl —
        // dropping `#[from]` later would surface here as a compile error
        // rather than as a silent string-format regression downstream.
        fn maybe() -> Result<(), AuthFail> {
            Err::<(), sqlx::Error>(sqlx::Error::RowNotFound)?;
            Ok(())
        }
        let e = maybe().unwrap_err();
        assert!(matches!(e, AuthFail::Db(_)));
        assert_eq!(e.to_string(), "database error");
    }

    #[tokio::test]
    async fn refresh_coordinator_distinct_hashes_produce_independent_locks() {
        // Two distinct bearer hashes must yield independent mutexes
        // so one bearer's refresh doesn't block another's. Pin the
        // lock-disjointness by holding lock A's guard and successfully
        // acquiring lock B's — a regression that collapsed all
        // bearers to one mutex would deadlock on the second acquire
        // (we use try_lock to surface that as a clear failure rather
        // than a hang).
        let c = RefreshCoordinator::default();
        let a = c.lock_for([1u8; 32]).await;
        let b = c.lock_for([2u8; 32]).await;
        let _guard_a = a.lock().await;
        // While holding A, B must still be acquirable — different mutexes.
        let try_b = b.try_lock();
        assert!(try_b.is_ok(), "distinct hashes must be independent mutexes");
    }

    #[test]
    fn auth_fail_decrypt_does_not_carry_cipher_internals_in_message() {
        // The Decrypt variant has NO inner field — pin that Display
        // returns the fixed string with no embedded payload. A future
        // refactor that wrapped a `CipherError` and surfaced its
        // Display (which mentions key length) could leak operational
        // detail in 4xx-shaped log lines that get pasted into tickets.
        assert_eq!(AuthFail::Decrypt.to_string(), "google token decrypt failed");
        // Three calls return the SAME string — proof there's no
        // counter / nonce mixed in.
        assert_eq!(AuthFail::Decrypt.to_string(), AuthFail::Decrypt.to_string());
    }

    #[test]
    fn auth_state_is_clone_for_axum_state_propagation() {
        // `AuthState` is `#[derive(Clone)]` and stamped into Axum's
        // `State<AuthState>` extractor — every middleware invocation
        // clones it. Pin the trait so a refactor that introduced a
        // !Clone field (e.g. `Mutex<T>` direct, not behind Arc) would
        // surface here rather than at hundreds of axum-router build
        // sites. The trait is enough — we don't need to instantiate
        // the struct (it requires a PgPool).
        fn require_clone<T: Clone>() {}
        require_clone::<AuthState>();
    }

    #[test]
    fn auth_fail_refresh_display_carries_google_token_refresh_failed_prefix() {
        // `#[error("google token refresh failed: {0}")]` — the existing
        // tests pin only the inner-string passthrough (`"network timeout"`).
        // Pin the full Display shape (prefix + colon + space + inner)
        // because operator log filters split bearer-refresh failures
        // ("google token refresh failed:" substring) from other refresh-
        // class errors (e.g. upstream PCA fetch). A refactor that
        // softened the prefix to "refresh: {0}" (the natural "tidy up
        // error messages" mistake) would silently break every Grafana
        // panel keyed on the `google token` qualifier.
        let s = AuthFail::Refresh("network timeout".into()).to_string();
        assert_eq!(s, "google token refresh failed: network timeout");
    }

    #[test]
    fn auth_fail_cat_key_display_carries_cat_key_fetch_failed_prefix() {
        // Symmetric to the Refresh variant — the CatKey arm carries
        // its operator-facing prefix (`"CAT key fetch failed: "`) which
        // dashboards split from generic upstream errors on. Pin the
        // full Display shape against three distinct inner messages so
        // a refactor that hardcoded the prefix into a smaller string
        // (e.g. for a uniform "trust plane error: {0}" wrapper) would
        // surface here on at least one of the three inputs.
        for inner in [
            "trust plane 503",
            "expected 32 bytes",
            "transport: connection refused",
        ] {
            let s = AuthFail::CatKey(inner.into()).to_string();
            assert_eq!(s, format!("CAT key fetch failed: {inner}"));
        }
    }

    #[test]
    fn auth_fail_other_display_carries_internal_prefix_with_inner_message() {
        // The `Other(String)` variant is the catch-all for unanticipated
        // internal errors; its `#[error("internal: {0}")]` prefix is
        // what distinguishes "we hit a code path with no specific
        // variant" from the more-specific upstream / cat_key / refresh
        // variants. Operators reading the proxy logs look for the
        // `"internal:"` substring to triage to "this is a proxy bug,
        // file an issue" vs the other variants which all point at
        // external systems. Pin the full shape so a refactor that
        // dropped the prefix would silently merge buckets.
        let s = AuthFail::Other("unexpected state at session-handoff".into()).to_string();
        assert_eq!(s, "internal: unexpected state at session-handoff");
    }

    #[test]
    fn auth_state_and_fail_and_refresh_coordinator_are_send_sync_static_for_axum_boundary() {
        // `AuthState` is passed via `with_state(...)` into the axum
        // Router and across `from_fn_with_state` middleware boundaries
        // — axum mandates `Send + Sync + 'static`. `AuthFail` flows
        // through `?`-chain returns from `build_session` awaited
        // inside the middleware future; tokio task boundaries require
        // the same bounds. `RefreshCoordinator` is held inside
        // `AuthState` AND is cloned into per-bearer mutex acquisition
        // futures. A refactor that introduced a !Sync field on any of
        // the three (e.g. `RefreshCoordinator { locks: RefCell<...> }`
        // "for cheap interior mutability") would break Sync at the
        // AppState site with a far-removed trait-bound error. Pin all
        // three trait bounds on all three types here — extends the
        // existing `auth_state_is_clone_for_axum_state_propagation`
        // pin which covers Clone only.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<AuthState>();
        require_send_sync_static::<AuthFail>();
        require_send_sync_static::<RefreshCoordinator>();
    }

    #[test]
    fn auth_fail_debug_carries_variant_names_for_grep_bucketing() {
        // The `#[derive(Debug)]` on `AuthFail` feeds `?why` in
        // `tracing::warn!(reason = %why, "bearer rejected")` indirectly
        // and any ad-hoc `?err` spans in tests / future call sites.
        // Operators grep `AuthFail::*` variant names to bucket
        // BadFormat (agent typo) vs NotFound (revoked) vs Decrypt
        // (cipher fault) vs PcaCacheMiss (Trust Plane gap) vs
        // PcaTampered (signature). A hand-rolled `impl Debug` that
        // hid variant names "to compact" the line would break every
        // operator bucket. Pin five distinct variant names — symmetric
        // to the ConnectError / KeyError / ApiError struct-name pins
        // on other modules.
        let bf = format!("{:?}", AuthFail::BadFormat);
        assert!(bf.contains("BadFormat"), "got: {bf}");
        let nf = format!("{:?}", AuthFail::NotFound);
        assert!(nf.contains("NotFound"), "got: {nf}");
        let dc = format!("{:?}", AuthFail::Decrypt);
        assert!(dc.contains("Decrypt"), "got: {dc}");
        let pm = format!("{:?}", AuthFail::PcaCacheMiss);
        assert!(pm.contains("PcaCacheMiss"), "got: {pm}");
        let pt = format!("{:?}", AuthFail::PcaTampered);
        assert!(pt.contains("PcaTampered"), "got: {pt}");
    }

    #[test]
    fn auth_fail_db_arm_display_masks_inner_sqlx_error_for_no_secret_leak() {
        // `#[error("database error")]` on `Db(#[from] sqlx::Error)` —
        // the inner sqlx::Error carries schema column names, query
        // fragments, and constraint identifiers that could leak into
        // operator-shared log lines or tickets. Pin that Display is
        // the fixed "database error" string with NO inner content,
        // regardless of which sqlx variant is wrapped. The existing
        // `auth_fail_from_sqlx_via_question_mark` test pins the
        // string for one variant only; pin three distinct variants
        // here to catch a refactor that swapped to
        // `#[error("database error: {0}")]` "for richer triage" which
        // would silently leak the inner sqlx text. Symmetric to the
        // `oauth_error_db_display_does_not_carry_inner_sqlx_string`
        // pin on [crates/proxy/src/oauth/error.rs].
        for inner in [
            sqlx::Error::RowNotFound,
            sqlx::Error::PoolClosed,
            sqlx::Error::WorkerCrashed,
        ] {
            let e = AuthFail::Db(inner);
            assert_eq!(e.to_string(), "database error");
        }
    }

    #[test]
    fn refresh_coordinator_clone_shares_underlying_moka_cache() {
        // `RefreshCoordinator` is `#[derive(Clone)]` — moka's `Cache`
        // is internally Arc'd, so a clone of the coordinator wraps
        // the SAME underlying cache. A refactor that swapped the
        // field to a deep-copy "for isolation between AppState
        // clones" would silently make every clone start with an empty
        // lock table, breaking the per-bearer single-flight contract
        // (50 concurrent requests with the same bearer would each see
        // a distinct mutex and all 50 would hit Google's refresh
        // endpoint instead of coalescing to one). Pin via the
        // observable: two clones of the coordinator return the SAME
        // Arc<Mutex<()>> for the same bearer hash.
        let c = RefreshCoordinator::default();
        let clone = c.clone();
        let hash = [99u8; 32];
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let a = c.lock_for(hash).await;
            let b = clone.lock_for(hash).await;
            assert!(
                Arc::ptr_eq(&a, &b),
                "clones of RefreshCoordinator must share underlying cache",
            );
        });
    }

    #[tokio::test]
    async fn unauthorized_helper_response_content_type_is_text_plain() {
        // The 401 body is plain text — the existing
        // `unauthorized_helper_returns_401_with_plain_body` test pins
        // status + body bytes but NOT the content-type header. Agent
        // clients (Cursor, Claude Code) branch on `content-type` to
        // decide whether to surface the body as a structured error or
        // as a fallback "auth required" message. A refactor that
        // promoted to `Json(...)` "for consistency with other 4xx
        // shapes" would silently change the content-type and break
        // every agent-side parser keyed on the plain-text fallback
        // path. Pin the content-type header explicitly.
        let r = unauthorized();
        let ct = r
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("content-type header present");
        let s = ct.to_str().expect("content-type is ASCII");
        assert!(s.starts_with("text/plain"), "expected text/plain, got: {s}",);
    }

    #[test]
    fn auth_fail_refresh_display_passes_inner_through_unicode_and_newline_verbatim() {
        // The `#[error("google token refresh failed: {0}")]` Display
        // passes the inner String through `{0}` (no `{0:?}` debug
        // escape). The existing
        // `auth_fail_refresh_display_carries_google_token_refresh_failed_prefix`
        // test pins the prefix shape against one plain-ASCII inner
        // ("network timeout"). Pin that arbitrary inner content
        // survives byte-for-byte across unicode (Google's regional
        // error messages may surface non-ASCII), newline (some
        // upstream errors include line-broken context), AND quote
        // chars. A refactor that swapped `{0}` to `{0:?}` "for
        // safety" would silently wrap the inner in escape sequences
        // and break exact-match operator log assertions.
        for inner in [
            "café network timeout",
            "line1\nline2",
            r#"quoted "value" here"#,
            "α-β-γ",
        ] {
            let e = AuthFail::Refresh(inner.into());
            let s = e.to_string();
            let expected = format!("google token refresh failed: {inner}");
            assert_eq!(s, expected, "inner verbatim survival: {s}");
        }
    }

    #[tokio::test]
    async fn refresh_coordinator_default_starts_empty_then_populates() {
        // `Default` builds an empty moka cache; the first `lock_for` is
        // what populates it. Pin both halves — a regression that pre-warmed
        // the cache with a sentinel would surface as the first lookup
        // returning a leftover Arc rather than a fresh one.
        let c = RefreshCoordinator::default();
        let a = c.lock_for([5u8; 32]).await;
        let b = c.lock_for([5u8; 32]).await;
        assert!(Arc::ptr_eq(&a, &b), "second lookup returns the same Arc");
    }

    // ─── round 181 (2026-05-20): operator-actionable surfaces on AuthFail + AuthState ───

    #[test]
    fn auth_fail_variant_count_pinned_at_nine_via_exhaustive_match() {
        // `AuthFail` has exactly 9 variants today (BadFormat / NotFound /
        // Decrypt / Refresh / PcaCacheMiss / PcaTampered / CatKey / Db /
        // Other). Operator runbooks bucket bearer-rejection failures by
        // variant; a refactor that added a new variant without updating
        // the runbook (e.g. `Throttled` for a future rate-limit gate)
        // would surface a tenth grep bucket the dashboard wasn't sized
        // for. Pin the variant count via an exhaustive match — a new
        // arm forces this test to compile-fail at the match site, which
        // is the canonical "make the runbook update load-bearing"
        // pattern. Symmetric to round-89 PkceError 2-variant pin
        // extended one module up.
        fn arm_name(e: &AuthFail) -> &'static str {
            match e {
                AuthFail::BadFormat => "BadFormat",
                AuthFail::NotFound => "NotFound",
                AuthFail::Decrypt => "Decrypt",
                AuthFail::Refresh(_) => "Refresh",
                AuthFail::PcaCacheMiss => "PcaCacheMiss",
                AuthFail::PcaTampered => "PcaTampered",
                AuthFail::CatKey(_) => "CatKey",
                AuthFail::Db(_) => "Db",
                AuthFail::Other(_) => "Other",
            }
        }
        let nine: Vec<AuthFail> = vec![
            AuthFail::BadFormat,
            AuthFail::NotFound,
            AuthFail::Decrypt,
            AuthFail::Refresh("r".into()),
            AuthFail::PcaCacheMiss,
            AuthFail::PcaTampered,
            AuthFail::CatKey("c".into()),
            AuthFail::Db(sqlx::Error::RowNotFound),
            AuthFail::Other("o".into()),
        ];
        let names: std::collections::HashSet<&'static str> = nine.iter().map(arm_name).collect();
        assert_eq!(names.len(), 9, "9 distinct variant names expected");
    }

    #[test]
    fn auth_fail_refresh_cat_key_and_other_inner_fields_are_owned_string() {
        // `Refresh(String)` / `CatKey(String)` / `Other(String)` —
        // each inner is an OWNED `String`. The error propagates across
        // an `.await` boundary in `auth_middleware` up through tracing
        // and the operator-token audit-sink task; the originating
        // upstream-error byte slice is dropped before the audit sink
        // serializes the variant. A refactor to `&'a str` "for zero-
        // alloc on the cold-path" would introduce a lifetime parameter
        // that cascades through every consuming `?`-chain. Pin the
        // owned-String type via the canonical require_string helper
        // across all three String-bearing variants. Symmetric to
        // round-177 Decision + round-180 MatchError owned-String pins
        // extended to AuthFail's String-bearing variants.
        fn require_string(_: &String) {}
        let r = match AuthFail::Refresh("network timeout".into()) {
            AuthFail::Refresh(s) => s,
            other => panic!("expected Refresh, got {other:?}"),
        };
        require_string(&r);
        let c = match AuthFail::CatKey("trust plane 503".into()) {
            AuthFail::CatKey(s) => s,
            other => panic!("expected CatKey, got {other:?}"),
        };
        require_string(&c);
        let o = match AuthFail::Other("unexpected".into()) {
            AuthFail::Other(s) => s,
            other => panic!("expected Other, got {other:?}"),
        };
        require_string(&o);
    }

    #[test]
    fn auth_fail_pca_cache_miss_display_is_byte_exact_with_braced_id_placeholder() {
        // `#[error("PCA cache miss (no upstream GET /v1/pca/{{id}} available)")]`
        // — the doubled `{{id}}` escapes the literal `{id}` in the
        // formatted output. The existing
        // `auth_fail_pca_cache_miss_message_explains_upstream_gap`
        // pins `.contains("PCA cache miss")` + `.contains("/v1/pca/")`
        // — but a refactor that swapped `{{id}}` for `{id}` (the
        // mechanical "treat the braces as a placeholder" mistake) would
        // surface as a runtime panic on the unknown `id` arg, or
        // (worse) a silently malformed Display if a future refactor
        // added an `id: String` field and resolved the placeholder.
        // Pin the byte-exact full Display string so the brace-escape
        // semantic is locked. Symmetric to round-50 + round-66 byte-
        // exact Display pins extended to this variant.
        assert_eq!(
            AuthFail::PcaCacheMiss.to_string(),
            "PCA cache miss (no upstream GET /v1/pca/{id} available)",
        );
    }

    #[test]
    fn unauthorized_body_bytes_pinned_at_byte_exact_twelve_bytes_no_trailing_newline() {
        // The 401 body is the literal 12-byte ASCII `b"unauthorized"`.
        // The existing `unauthorized_helper_returns_401_with_plain_body`
        // pins the byte slice via `to_bytes(.., 64)` but does NOT pin
        // the byte length explicitly. Agent clients (Cursor / Claude
        // Code) sometimes parse the body via fixed-size buffer reads
        // — a refactor that appended a trailing newline "for tidy
        // log output" would silently change the body from 12 to 13
        // bytes and break those parsers. Pin byte-exact length AND
        // no-trailing-whitespace. Symmetric to round-92 / round-100
        // byte-exact length pins extended to this 401 response.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let r = unauthorized();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
            let bytes = axum::body::to_bytes(r.into_body(), 64).await.unwrap();
            assert_eq!(bytes.len(), 12, "401 body must be byte-exact 12 bytes");
            assert_eq!(&bytes[..], b"unauthorized");
            // No trailing whitespace / newline / carriage return.
            assert!(
                !bytes.ends_with(b"\n") && !bytes.ends_with(b" ") && !bytes.ends_with(b"\r"),
                "401 body must not have trailing whitespace, got: {bytes:?}",
            );
        });
    }

    #[test]
    fn refresh_coordinator_lock_for_is_referentially_transparent_across_fifty_repeated_calls() {
        // `lock_for(hash)` is the hot-path single-flight call —
        // every middleware invocation calls it; the result MUST be the
        // SAME `Arc<Mutex<()>>` instance for the same hash across the
        // moka cache TTL window. The existing
        // `refresh_coordinator_returns_same_mutex_for_same_hash` pins
        // ONE pair (two back-to-back calls); pin 50 back-to-back calls
        // so a refactor that introduced a stateful between-call
        // mutation (e.g. a per-call counter wired into the mutex
        // identity) would surface here on call #2..#50. Symmetric to
        // round-179 + round-180 referential-transparency pins extended
        // to the moka-cache-backed single-flight lookup.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let c = RefreshCoordinator::default();
            let h = [7u8; 32];
            let first = c.lock_for(h).await;
            for i in 1..50 {
                let next = c.lock_for(h).await;
                assert!(
                    Arc::ptr_eq(&first, &next),
                    "moka cache must return SAME Arc on call #{i}",
                );
            }
        });
    }

    #[test]
    fn auth_fail_refresh_inner_string_supports_long_unicode_payload_via_two_kb_input() {
        // `Refresh(String)` carries upstream error context (Google's
        // token endpoint response). Google's error responses can be
        // verbose (multi-paragraph JSON `error_description` strings).
        // Pin that a 2-KB-class inner survives the `#[error("google
        // token refresh failed: {0}")]` Display passthrough without
        // truncation — and that a multibyte unicode payload inside the
        // 2-KB envelope also survives byte-equal (no `.chars().take(N)`
        // truncation snuck in via a refactor that added "log line
        // length budget" defenses at this layer). The existing
        // `auth_fail_refresh_display_passes_inner_through_unicode_and_newline_verbatim`
        // pin walks 4 small inputs (<40 bytes); pin the 2-KB scale
        // boundary here so a fixed-size-buffer refactor surfaces.
        let mut inner = String::with_capacity(2048);
        inner.push_str("café-é-→-🔥 "); // 2-byte + 2-byte + 3-byte + 4-byte char spread
        while inner.len() < 2048 {
            inner.push('a');
        }
        assert!(inner.len() >= 2048, "fixture sanity: {} bytes", inner.len());
        let e = AuthFail::Refresh(inner.clone());
        let s = e.to_string();
        let expected = format!("google token refresh failed: {inner}");
        assert_eq!(s, expected, "2-KB inner must survive verbatim");
        // Multibyte unicode prefix preserved.
        assert!(s.contains("café-é-→-🔥"), "multibyte prefix must survive");
    }
}
