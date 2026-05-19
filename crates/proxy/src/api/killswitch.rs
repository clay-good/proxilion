//! Killswitch API.
//!
//! Authority: spec.md §3.2, ui-less-surfaces.md §4.1.
//!
//! Three scopes:
//!   * `session` — revoke a single bearer (= one OAuth session).
//!   * `user`    — revoke every bearer rooted at the given p_0.
//!   * `all`     — global stop. Revokes every non-revoked bearer.
//!
//! Each call marks rows in `agent_bearers` with `revoked_at = now()` so the
//! auth middleware rejects subsequent bearers (it already checks this
//! column at every request). Trust Plane `/revoke` is upstream-deferred —
//! the chain itself is not yet revoked, but the proxy refuses to act on
//! revoked bearers, which is the operator-meaningful guarantee for v1.
//!
//! Drain: in-flight requests are NOT actively aborted — they finish or
//! time out naturally (10s upstream timeout). The next request the same
//! bearer makes is rejected. This is the §3.2 v1 simplification (the
//! AbortHandle registry is a v2 hardening).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct KillswitchApiState {
    pub db: PgPool,
    /// In-process cache populated by every killswitch invocation so the
    /// bearer middleware can short-circuit subsequent reads without
    /// hitting the DB. spec.md §3.2 dev 2.
    pub kill_cache: crate::kill_cache::KillCache,
}

pub fn router(state: KillswitchApiState) -> Router {
    use crate::operator_auth::scope_check;
    use axum::middleware::from_fn_with_state;
    let kill = || from_fn_with_state("killswitch:revoke", scope_check);
    Router::new()
        .route(
            "/api/v1/killswitch/session/{id}",
            post(kill_session).route_layer(kill()),
        )
        .route(
            "/api/v1/killswitch/user/{p0}",
            post(kill_user).route_layer(kill()),
        )
        .route("/api/v1/killswitch/all", post(kill_all).route_layer(kill()))
        .with_state(Arc::new(state))
}

#[derive(Debug, Deserialize, Default)]
struct KillBody {
    reason: Option<String>,
    operator_subject: Option<String>,
    /// Required only by `/killswitch/all`; must equal "yes".
    confirm: Option<String>,
}

#[derive(Debug, Serialize)]
struct KillResponse {
    record_id: Uuid,
    scope: &'static str,
    target: String,
    bearers_revoked: i64,
    at: DateTime<Utc>,
}

async fn kill_session(
    State(state): State<Arc<KillswitchApiState>>,
    Path(id): Path<Uuid>,
    body: Option<Json<KillBody>>,
) -> Result<Json<KillResponse>, ApiError> {
    let body = body.map(|j| j.0).unwrap_or_default();
    let reason = body.reason.clone().unwrap_or_else(|| "killswitch".into());
    let hashes: Vec<(Vec<u8>,)> = sqlx::query_as(
        "UPDATE agent_bearers
            SET revoked_at      = now(),
                revoked_reason  = $2
          WHERE session_id      = $1
            AND revoked_at IS NULL
        RETURNING bearer_sha256",
    )
    .bind(id)
    .bind(&reason)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Db)?;
    let n = hashes.len() as i64;
    populate_kill_cache(&state.kill_cache, &hashes).await;
    Ok(Json(
        persist(
            &state.db,
            "session",
            &id.to_string(),
            &reason,
            body.operator_subject.as_deref(),
            n,
        )
        .await?,
    ))
}

async fn kill_user(
    State(state): State<Arc<KillswitchApiState>>,
    Path(p0): Path<String>,
    body: Option<Json<KillBody>>,
) -> Result<Json<KillResponse>, ApiError> {
    let body = body.map(|j| j.0).unwrap_or_default();
    let reason = body.reason.clone().unwrap_or_else(|| "killswitch".into());
    let hashes: Vec<(Vec<u8>,)> = sqlx::query_as(
        "UPDATE agent_bearers ab
            SET revoked_at      = now(),
                revoked_reason  = $2
          FROM oauth_sessions os
         WHERE ab.session_id = os.id
           AND os.p_0        = $1
           AND ab.revoked_at IS NULL
        RETURNING ab.bearer_sha256",
    )
    .bind(&p0)
    .bind(&reason)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Db)?;
    let n = hashes.len() as i64;
    populate_kill_cache(&state.kill_cache, &hashes).await;
    Ok(Json(
        persist(
            &state.db,
            "user",
            &p0,
            &reason,
            body.operator_subject.as_deref(),
            n,
        )
        .await?,
    ))
}

async fn kill_all(
    State(state): State<Arc<KillswitchApiState>>,
    body: Option<Json<KillBody>>,
) -> Result<Json<KillResponse>, ApiError> {
    let body = body.map(|j| j.0).unwrap_or_default();
    if body.confirm.as_deref() != Some("yes") {
        return Err(ApiError::BadRequest(
            "/killswitch/all requires { confirm: \"yes\" } in the body".into(),
        ));
    }
    let reason = body
        .reason
        .clone()
        .unwrap_or_else(|| "killswitch:all".into());
    let hashes: Vec<(Vec<u8>,)> = sqlx::query_as(
        "UPDATE agent_bearers
            SET revoked_at      = now(),
                revoked_reason  = $1
          WHERE revoked_at IS NULL
        RETURNING bearer_sha256",
    )
    .bind(&reason)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Db)?;
    let n = hashes.len() as i64;
    populate_kill_cache(&state.kill_cache, &hashes).await;
    Ok(Json(
        persist(
            &state.db,
            "all",
            "*",
            &reason,
            body.operator_subject.as_deref(),
            n,
        )
        .await?,
    ))
}

/// Push `bearer_sha256` BYTEA values from a RETURNING result into the
/// in-process kill cache. Skips rows with the wrong length so a schema
/// drift can't poison the cache.
async fn populate_kill_cache(kc: &crate::kill_cache::KillCache, rows: &[(Vec<u8>,)]) {
    let mut buf: [u8; 32] = [0; 32];
    let mut out: Vec<[u8; 32]> = Vec::with_capacity(rows.len());
    for (h,) in rows {
        if h.len() == 32 {
            buf.copy_from_slice(h);
            out.push(buf);
        }
    }
    kc.mark_many(out).await;
}

async fn persist(
    db: &PgPool,
    scope: &'static str,
    target: &str,
    reason: &str,
    operator: Option<&str>,
    bearers_revoked: i64,
) -> Result<KillResponse, ApiError> {
    let record_id: Uuid = sqlx::query_scalar(
        "INSERT INTO kill_records (scope, target, reason, operator_subject, bearers_revoked)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id",
    )
    .bind(scope)
    .bind(target)
    .bind(reason)
    .bind(operator)
    .bind(bearers_revoked as i32)
    .fetch_one(db)
    .await
    .map_err(ApiError::Db)?;
    let at: DateTime<Utc> = sqlx::query_scalar("SELECT at FROM kill_records WHERE id = $1")
        .bind(record_id)
        .fetch_one(db)
        .await
        .map_err(ApiError::Db)?;
    metrics::counter!(
        "proxilion_killswitch_invocations_total",
        "scope" => scope.to_string()
    )
    .increment(1);
    metrics::counter!("proxilion_killswitch_revoked_capabilities_total")
        .increment(bearers_revoked as u64);
    Ok(KillResponse {
        record_id,
        scope,
        target: target.to_string(),
        bearers_revoked,
        at,
    })
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        use crate::error_envelope::ErrorBody;
        let (status, body) = match &self {
            ApiError::BadRequest(d) => (
                StatusCode::BAD_REQUEST,
                ErrorBody::new("bad request", "bad_request").with_detail(d.clone()),
            ),
            ApiError::Db(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody::new("database error", "internal_error").with_detail(e.to_string()),
            ),
        };
        body.into_response(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kill_cache::KillCache;

    #[tokio::test]
    async fn populate_kill_cache_marks_correctly_sized_rows() {
        let kc = KillCache::new();
        let rows = vec![([1u8; 32].to_vec(),), ([2u8; 32].to_vec(),)];
        populate_kill_cache(&kc, &rows).await;
        assert!(kc.is_killed(&[1u8; 32]).await);
        assert!(kc.is_killed(&[2u8; 32]).await);
        assert!(!kc.is_killed(&[3u8; 32]).await);
    }

    #[tokio::test]
    async fn populate_kill_cache_skips_wrong_length_rows() {
        let kc = KillCache::new();
        // 31 bytes (too short) + 33 bytes (too long) + 32 bytes (valid).
        let rows = vec![(vec![9u8; 31],), (vec![8u8; 33],), ([7u8; 32].to_vec(),)];
        populate_kill_cache(&kc, &rows).await;
        assert!(kc.is_killed(&[7u8; 32]).await);
        // The short/long rows can't be queried as [u8; 32]; their absence is
        // demonstrated by a different 32-byte probe returning false.
        assert!(!kc.is_killed(&[9u8; 32]).await);
        assert!(!kc.is_killed(&[8u8; 32]).await);
    }

    #[tokio::test]
    async fn populate_kill_cache_empty_input_is_no_op() {
        let kc = KillCache::new();
        populate_kill_cache(&kc, &[]).await;
        assert!(!kc.is_killed(&[0u8; 32]).await);
    }

    #[tokio::test]
    async fn api_error_bad_request_is_400_with_detail() {
        let r = ApiError::BadRequest("missing field".into()).into_response();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "bad_request");
        assert_eq!(v["detail"], "missing field");
    }

    #[tokio::test]
    async fn api_error_db_collapses_to_500_internal_error_envelope() {
        // The only ApiError arm besides BadRequest. Operator alerts key on
        // `status="500" code="internal_error"` for a real Postgres outage —
        // a future variant rename here would silently re-classify the alert.
        let r = ApiError::Db(sqlx::Error::RowNotFound).into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "internal_error");
        assert_eq!(v["error"], "database error");
        // detail surfaces the sqlx string verbatim — this is operator-facing
        // and never reaches the agent (killswitch is operator-only-gated).
        assert!(!v["detail"].as_str().unwrap().is_empty());
    }

    #[test]
    fn kill_response_serializes_with_stable_field_names() {
        // The dashboard's killswitch confirmation toast keys on every field
        // below — a future rename (e.g. `bearers_revoked` → `revoked_count`)
        // would silently break the UI.
        let r = KillResponse {
            record_id: Uuid::nil(),
            scope: "session",
            target: "abc".into(),
            bearers_revoked: 3,
            at: Utc::now(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert!(v.get("record_id").is_some());
        assert_eq!(v["scope"], "session");
        assert_eq!(v["target"], "abc");
        assert_eq!(v["bearers_revoked"], 3);
        assert!(v.get("at").is_some());
    }

    #[test]
    fn kill_body_defaults_when_empty_object_is_posted() {
        // operator-cli posts `{}` for /killswitch/session/<id> when no reason
        // is provided. The handler's `body.unwrap_or_default()` path depends
        // on every field being Option<_> with a `Default` impl.
        let body: KillBody = serde_json::from_str("{}").unwrap();
        assert!(body.reason.is_none());
        assert!(body.operator_subject.is_none());
        assert!(body.confirm.is_none());
    }

    #[test]
    fn kill_response_with_zero_bearers_revoked_serializes_cleanly() {
        // A /killswitch/user call where the p_0 has no live bearers
        // returns `bearers_revoked: 0` — pin that this lands on the
        // wire as the integer 0 (not omitted, not stringified, not
        // null). The dashboard's "no-op" toast keys on `>= 0`, so a
        // refactor that switched the field to `Option<i64>` (in the
        // name of "only emit when non-zero") would silently break
        // the operator-visible "killswitch ran, nothing to revoke"
        // confirmation.
        let r = KillResponse {
            record_id: Uuid::nil(),
            scope: "user",
            target: "alice@demo.local".into(),
            bearers_revoked: 0,
            at: Utc::now(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["bearers_revoked"], 0);
        assert!(v.get("bearers_revoked").unwrap().is_number());
    }

    #[test]
    fn kill_body_rejects_unknown_field_via_deny_or_passes_through_today() {
        // The struct does NOT carry `#[serde(deny_unknown_fields)]`.
        // Pin the forward-compat path so the CLI can add fields
        // (e.g. `notify_email`) without 400ing every existing proxy.
        // A refactor that added the deny attribute would surface
        // here as a wire-shape break the upgrade ladder must
        // address.
        let body: KillBody = serde_json::from_str(
            r#"{"reason":"r","operator_subject":"op","confirm":"yes","future_field":42}"#,
        )
        .unwrap();
        assert_eq!(body.reason.as_deref(), Some("r"));
        assert_eq!(body.operator_subject.as_deref(), Some("op"));
        assert_eq!(body.confirm.as_deref(), Some("yes"));
    }

    #[test]
    fn api_error_bad_request_display_carries_inner_message() {
        // The `#[error("{0}")]` shape on BadRequest means Display ==
        // the inner string verbatim. Pin this so a future shape
        // (`#[error("bad request: {0}")]` — symmetric with the other
        // ApiError modules) is a conscious wire-shape change. The
        // CLI's killswitch error renderer parses on the bare message.
        let e = ApiError::BadRequest("/killswitch/all needs confirm".into());
        assert_eq!(e.to_string(), "/killswitch/all needs confirm");
    }

    #[test]
    fn api_error_and_killswitch_state_are_send_sync_static_for_axum_state_boundary() {
        // `KillswitchApiState` is wrapped in `Arc<...>` and passed via
        // `with_state(...)` into the axum Router; axum requires
        // `Send + Sync + 'static` on State types. `ApiError` flows
        // through `IntoResponse` from handler futures crossing the
        // tokio task boundary and also requires the same bounds. A
        // refactor that gave `KillswitchApiState` an `Rc<...>` field
        // "for cheap clone of a config bag" would break Sync at the
        // router site with a far-removed trait-bound error. Pin all
        // three trait bounds on both types here so the failure
        // surfaces at the right module.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<KillswitchApiState>();
        require_send_sync_static::<ApiError>();
    }

    #[test]
    fn api_error_db_arm_display_passes_inner_sqlx_error_through_via_transparent_derive() {
        // `Db(#[from] sqlx::Error)` uses `#[error(transparent)]` — the
        // wrapper's Display MUST equal the inner sqlx::Error's Display
        // byte-for-byte (no prefix, no formatting wrapper). A refactor
        // that swapped `#[error(transparent)]` for an explicit
        // `#[error("db: {0}")]` (the natural shape for "add context")
        // would silently prepend "db: " to every Db-error log line and
        // break operator log filters that already grep on the raw sqlx
        // Display substrings. Pin transparent passthrough on a known
        // sqlx::Error variant with a distinctive Display string.
        let inner = sqlx::Error::RowNotFound;
        let inner_s = inner.to_string();
        let wrapped = ApiError::Db(sqlx::Error::RowNotFound);
        assert_eq!(
            wrapped.to_string(),
            inner_s,
            "transparent derive must passthrough Display verbatim",
        );
    }

    #[test]
    fn api_error_bad_request_arm_is_leaf_with_no_source() {
        // Symmetric to the Db chain pin — `BadRequest(String)` is a
        // leaf arm with no inner error. Pin source() == None so a
        // refactor that wrapped the message in an `anyhow::Error` for
        // "richer chain context" would surface here rather than as a
        // duplicated detail in operator logs (the inner anyhow chain
        // would render via source() AND duplicate via the Display).
        let e = ApiError::BadRequest("missing field".into());
        let dyn_err: &dyn std::error::Error = &e;
        assert!(
            std::error::Error::source(dyn_err).is_none(),
            "BadRequest leaf arm must not expose a source",
        );
    }

    #[test]
    fn api_error_debug_carries_variant_names_for_grep_bucketing() {
        // The `#[derive(Debug)]` on `ApiError` feeds `?e` in
        // `tracing::warn!(?err, ...)` call sites and the killswitch
        // 500-branch logs. Operators grep the log line by variant
        // name to bucket BadRequest (operator typo) vs Db (Postgres
        // outage). A hand-rolled `impl Debug` that hid variant names
        // "to compact" the line would break every operator bucket.
        // Pin both variant names — symmetric to the
        // `connect_error_debug_includes_struct_name_for_grep` pin on
        // [crates/proxy/src/forwarder/nats.rs] and the
        // `key_error_and_build_error_debug_carries_struct_name_for_grep`
        // pin on [crates/proxy/src/forwarder/siem.rs].
        let br = format!("{:?}", ApiError::BadRequest("x".into()));
        assert!(br.contains("BadRequest"), "got: {br}");
        let db = format!("{:?}", ApiError::Db(sqlx::Error::RowNotFound));
        assert!(db.contains("Db"), "got: {db}");
    }

    #[test]
    fn kill_response_scope_field_serializes_as_string_not_integer() {
        // `scope: &'static str` lands on the wire as a JSON string.
        // Pin the type tag explicitly — a refactor that promoted
        // `scope` to an enum with `#[serde(into = "u8")]` "for compact
        // wire bytes" or a `#[serde(serialize_with = ...)]` that
        // emitted a numeric discriminant would silently break every
        // dashboard filter keyed on `scope == "session"` /
        // `scope == "user"` / `scope == "all"`. The existing
        // `kill_response_serializes_with_stable_field_names` test pins
        // the field NAME but not its TYPE tag.
        let r = KillResponse {
            record_id: Uuid::nil(),
            scope: "all",
            target: "*".into(),
            bearers_revoked: 42,
            at: Utc::now(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert!(v["scope"].is_string(), "scope must be string: {v}");
        assert_eq!(v["scope"], "all");
        // target is also a string — symmetric pin on the runtime String.
        assert!(v["target"].is_string(), "target must be string: {v}");
    }

    #[test]
    fn kill_body_confirm_preserves_case_verbatim_no_normalization() {
        // The `/killswitch/all` handler checks
        // `body.confirm.as_deref() == Some("yes")` — a case-sensitive
        // exact-match against the lowercase literal. The serde
        // deserialization MUST preserve case verbatim (no lowercasing,
        // no trimming) so the handler-level check can fail-safe on
        // "YES" / " yes " / "Yes" inputs (the operator typed the wrong
        // case and the killswitch must refuse, not silently fire). A
        // refactor that added `#[serde(deserialize_with =
        // "lowercase")]` "for ergonomic CLI use" would silently let
        // every case variant past the handler's exact-match check —
        // pin verbatim preservation across three case shapes.
        let yes_upper: KillBody = serde_json::from_str(r#"{"confirm":"YES"}"#).unwrap();
        assert_eq!(yes_upper.confirm.as_deref(), Some("YES"));
        let yes_title: KillBody = serde_json::from_str(r#"{"confirm":"Yes"}"#).unwrap();
        assert_eq!(yes_title.confirm.as_deref(), Some("Yes"));
        let yes_padded: KillBody = serde_json::from_str(r#"{"confirm":" yes "}"#).unwrap();
        assert_eq!(yes_padded.confirm.as_deref(), Some(" yes "));
    }

    #[tokio::test]
    async fn populate_kill_cache_marks_one_hundred_distinct_hashes_all_observable() {
        // The existing pin walks 2 hashes. Widen to N=100 with distinct
        // 32-byte hashes — `/killswitch/all` on a realistic install
        // marks thousands of bearer hashes in a single call. Pin that
        // ALL 100 surface as `is_killed == true` AND a probe of a
        // 101st distinct hash returns `false` (no spurious population).
        // A refactor that, e.g., capped the per-call mark batch at
        // N=64 "for moka cache hot-path budget" would silently lose
        // every hash beyond the cap on a kill-all sweep and let
        // bearers continue to authenticate past revocation.
        let kc = KillCache::new();
        let rows: Vec<(Vec<u8>,)> = (0..100u8).map(|i| ([i; 32].to_vec(),)).collect();
        populate_kill_cache(&kc, &rows).await;
        for i in 0..100u8 {
            assert!(
                kc.is_killed(&[i; 32]).await,
                "hash {i} not killed after batch populate",
            );
        }
        // Sentinel: a 101st hash NOT in the input must remain unkilled.
        assert!(!kc.is_killed(&[200u8; 32]).await);
    }

    #[test]
    fn kill_response_serialized_json_object_carries_exactly_five_known_keys() {
        // The struct has 5 fields (record_id, scope, target,
        // bearers_revoked, at). When serialized the JSON object MUST
        // carry EXACTLY those 5 keys — not 4 (an elided field would
        // silently drop operator-visible state from the killswitch
        // confirmation toast) and not 6 (a refactor that surfaced an
        // internal correlation-id "for telemetry" would widen the
        // wire shape and potentially leak request-internal state to
        // the operator UI). The existing
        // `kill_response_serializes_with_stable_field_names` pin
        // checks individual key presence but NOT exact count. Pin
        // both axes.
        let r = KillResponse {
            record_id: Uuid::nil(),
            scope: "session",
            target: "abc".into(),
            bearers_revoked: 3,
            at: Utc::now(),
        };
        let v = serde_json::to_value(&r).unwrap();
        let obj = v.as_object().expect("must serialize to JSON object");
        assert_eq!(obj.len(), 5, "field count drift: {obj:?}");
        for k in ["record_id", "scope", "target", "bearers_revoked", "at"] {
            assert!(obj.contains_key(k), "missing key {k}: {obj:?}");
        }
    }

    #[test]
    fn kill_body_serialized_json_object_carries_exactly_three_known_optional_keys_when_all_set() {
        // Symmetric to the KillResponse count pin. KillBody has 3
        // optional fields (reason, operator_subject, confirm). When
        // all are set, the round-trip via serialize-then-deserialize
        // recovers exactly 3 keys. A refactor that elided a field
        // "for backwards compat with CLI v1" would silently drop the
        // killswitch authorization audit-trail. Pin via a fresh
        // KillBody serialized from a hand-built JSON with all three
        // fields populated.
        let body: KillBody = serde_json::from_str(
            r#"{"reason":"drill","operator_subject":"alice","confirm":"yes"}"#,
        )
        .unwrap();
        // All three fields populated from the input.
        assert_eq!(body.reason.as_deref(), Some("drill"));
        assert_eq!(body.operator_subject.as_deref(), Some("alice"));
        assert_eq!(body.confirm.as_deref(), Some("yes"));
        // Symmetric inspection via Debug to pin all three field names
        // are rendered (a refactor that hid a field from Debug would
        // surface here as a missing name).
        let dbg = format!("{:?}", body);
        for f in ["reason", "operator_subject", "confirm"] {
            assert!(dbg.contains(f), "missing {f} in Debug: {dbg}");
        }
    }

    #[tokio::test]
    async fn killswitch_api_state_clone_shares_inner_kill_cache_handle() {
        // `KillswitchApiState` is `#[derive(Clone)]`. Inside, the
        // `kill_cache: KillCache` field is itself Clone (wraps an
        // Arc<...>). When the axum router clones the state per
        // request-scope (axum's State<...> extractor invokes
        // `.clone()`), both clones MUST share the SAME underlying
        // KillCache so a mark from one handler is observable on a
        // sibling handler's read. The existing
        // `api_error_and_killswitch_state_are_send_sync_static_for_axum_state_boundary`
        // pin only checks Send+Sync+'static. Pin Clone-share
        // observability here: insert a marker via one clone, read
        // it back via another.
        use crate::kill_cache::KillCache;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/x")
            .expect("lazy pool builds");
        let state = KillswitchApiState {
            db: pool,
            kill_cache: KillCache::new(),
        };
        let clone_a = state.clone();
        let clone_b = state.clone();
        // Mark via clone_a; observe via clone_b — both must share
        // the same backing KillCache.
        clone_a.kill_cache.mark_many(vec![[7u8; 32]]).await;
        assert!(
            clone_b.kill_cache.is_killed(&[7u8; 32]).await,
            "kill_cache not shared across Clone — refactor broke axum State propagation",
        );
    }

    #[test]
    fn kill_response_scope_field_is_static_str_lifetime_compile_time_bound() {
        // `scope: &'static str` is the lifetime contract — the three
        // canonical scopes ("session", "user", "all") are
        // `&'static str` literals constructed at the handler site.
        // A refactor to `scope: String` would silently heap-allocate
        // on every killswitch invocation (one allocation per call,
        // bounded but unnecessary on the hot kill_all path). Pin
        // the lifetime contract via a function that takes
        // `&'static str` only — type-coercion alone fails if the
        // field's type drifts.
        fn require_static_str(_: &'static str) {}
        let r = KillResponse {
            record_id: Uuid::nil(),
            scope: "session",
            target: "abc".into(),
            bearers_revoked: 0,
            at: Utc::now(),
        };
        require_static_str(r.scope);
        // And the target field is owned String (the inverse pin —
        // target IS heap-allocated because it carries
        // operator-supplied UUIDs / p_0 emails).
        assert_eq!(r.target, "abc");
    }

    #[tokio::test]
    async fn populate_kill_cache_idempotent_across_duplicate_hash_in_same_batch() {
        // The same bearer hash appearing twice in one `RETURNING`
        // batch (a legitimate edge case if a future schema change
        // surfaced multiple `agent_bearers` rows sharing the same
        // `bearer_sha256` — e.g. soft-delete + re-issue) must NOT
        // cause `populate_kill_cache` to panic or skip. Pin
        // idempotent behavior: the same hash appearing 5 times in
        // one batch yields exactly one `is_killed == true` for
        // that hash AND no spurious effect on a different hash in
        // the same batch. A refactor that switched the inner
        // accumulator from `Vec` to a fail-on-duplicate `HashSet`
        // would surface here as a panic OR silent drop.
        let kc = KillCache::new();
        let rows: Vec<(Vec<u8>,)> = vec![
            ([7u8; 32].to_vec(),),
            ([7u8; 32].to_vec(),),
            ([7u8; 32].to_vec(),),
            ([7u8; 32].to_vec(),),
            ([7u8; 32].to_vec(),),
            ([42u8; 32].to_vec(),),
        ];
        populate_kill_cache(&kc, &rows).await;
        assert!(kc.is_killed(&[7u8; 32]).await);
        assert!(kc.is_killed(&[42u8; 32]).await);
        assert!(!kc.is_killed(&[0u8; 32]).await);
    }

    #[test]
    fn kill_body_accepts_confirm_yes_for_kill_all() {
        // /killswitch/all rejects without `confirm: "yes"` — pin that the
        // deserializer accepts the field (vs. an accidental rename in serde
        // that would silently make confirm always None and a typed BadRequest
        // bypass impossible).
        let body: KillBody = serde_json::from_str(r#"{"confirm":"yes","reason":"drill"}"#).unwrap();
        assert_eq!(body.confirm.as_deref(), Some("yes"));
        assert_eq!(body.reason.as_deref(), Some("drill"));
    }
}
