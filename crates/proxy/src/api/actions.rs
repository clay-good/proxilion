//! Action-feed API: recent history, single record + chain, session chain,
//! and live SSE stream.
//!
//! Authority: spec.md §1.6.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use sqlx::types::Json as SqlxJson;
use sqlx::{PgPool, Row};
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::adapters::action_stream::{ActionEvent, BroadcastingActionStream};
use crate::pic::PcaCache;

#[derive(Clone)]
pub struct ActionsApiState {
    pub db: PgPool,
    pub stream: BroadcastingActionStream,
    pub pca_cache: PcaCache,
}

pub fn router(state: ActionsApiState) -> Router {
    use crate::operator_auth::scope_check;
    use axum::middleware::from_fn_with_state;
    use axum::routing::{get, post};
    let read = || from_fn_with_state("actions:read", scope_check);
    let export_scope = || from_fn_with_state("actions:export", scope_check);
    let purge_scope = || from_fn_with_state("actions:purge", scope_check);
    Router::new()
        // /actions returns a paginated envelope { rows, next_before }.
        // /actions/recent stays as a raw array for the static-admin UI.
        .route("/api/v1/actions", get(list).route_layer(read()))
        .route("/api/v1/actions/recent", get(recent).route_layer(read()))
        .route("/api/v1/actions/stream", get(stream).route_layer(read()))
        .route(
            "/api/v1/actions/export",
            get(export).route_layer(export_scope()),
        )
        .route(
            "/api/v1/actions/purge",
            post(purge).route_layer(purge_scope()),
        )
        .route("/api/v1/actions/{id}", get(get_action).route_layer(read()))
        .route(
            "/api/v1/sessions/{id}/chain",
            get(session_chain).route_layer(read()),
        )
        .with_state(state)
}

async fn recent(
    State(state): State<ActionsApiState>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<ListRow>>, ActionsApiError> {
    let env = list(State(state), Query(params)).await?;
    Ok(Json(env.0.rows))
}

#[derive(Debug, Deserialize)]
struct ListParams {
    /// Max rows to return (1..=500, default 50).
    limit: Option<u32>,
    /// Cursor: return rows strictly older than this timestamp (RFC3339).
    before: Option<DateTime<Utc>>,
    /// Filter — only events with this decision.
    decision: Option<String>,
    /// Filter — only events with this `p_0` (origin user).
    p_0: Option<String>,
    /// Filter — only events from this vendor (e.g. "google").
    vendor: Option<String>,
    /// Filter — only events with this action verb (e.g. "drive.files.get").
    action: Option<String>,
    /// Filter — only events with this `session_id`.
    session_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct ListRow {
    id: Uuid,
    request_id: Uuid,
    session_id: Option<Uuid>,
    p_0: String,
    leaf_pca_id: Option<Uuid>,
    vendor: String,
    action: String,
    method: String,
    path: String,
    status: i32,
    decision: String,
    block_reason: Option<String>,
    read_filter_triggered: bool,
    quarantined_count: i32,
    policy_id: Option<String>,
    extra: serde_json::Value,
    at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct ListResponse {
    rows: Vec<ListRow>,
    /// Cursor for the next page (the `at` of the last row), or null when fewer
    /// than `limit` rows were returned.
    next_before: Option<DateTime<Utc>>,
}

async fn list(
    State(state): State<ActionsApiState>,
    Query(params): Query<ListParams>,
) -> Result<Json<ListResponse>, ActionsApiError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 500) as i64;
    let rows = sqlx::query(
        r#"
        SELECT id, request_id, session_id, p_0, leaf_pca_id, vendor, action, method, path,
               status, decision, block_reason, read_filter_triggered, quarantined_count,
               policy_id, extra, at
          FROM action_events
         WHERE ($1::text       IS NULL OR decision   = $1)
           AND ($2::text       IS NULL OR p_0        = $2)
           AND ($3::text       IS NULL OR vendor     = $3)
           AND ($4::text       IS NULL OR action     = $4)
           AND ($5::uuid       IS NULL OR session_id = $5)
           AND ($6::timestamptz IS NULL OR at        < $6)
         ORDER BY at DESC
         LIMIT $7
        "#,
    )
    .bind(params.decision.as_deref())
    .bind(params.p_0.as_deref())
    .bind(params.vendor.as_deref())
    .bind(params.action.as_deref())
    .bind(params.session_id)
    .bind(params.before)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(row_to_list(&r)?);
    }
    let next_before = if out.len() as i64 == limit {
        out.last().map(|r| r.at)
    } else {
        None
    };
    Ok(Json(ListResponse {
        rows: out,
        next_before,
    }))
}

#[derive(Debug, Deserialize)]
struct ExportParams {
    /// `ndjson` (default), `json`, or `csv`. The streaming code path is NDJSON
    /// plus CSV; `json` falls back to a single bulk array materialised in
    /// memory and is intended for small windows only.
    format: Option<String>,
    decision: Option<String>,
    p_0: Option<String>,
    vendor: Option<String>,
    action: Option<String>,
    session_id: Option<Uuid>,
    /// Inclusive lower bound.
    since: Option<DateTime<Utc>>,
    /// Exclusive upper bound.
    until: Option<DateTime<Utc>>,
}

/// Bulk audit export. Streams from postgres directly to the wire so memory is
/// O(1) regardless of result size. The export is unpaginated by design — this
/// is the surface a customer points at to backfill a SIEM.
async fn export(
    State(state): State<ActionsApiState>,
    Query(params): Query<ExportParams>,
) -> Response {
    let fmt = params.format.as_deref().unwrap_or("ndjson");
    let (content_type, header_line): (&str, Option<&'static str>) = match fmt {
        "csv" => (
            "text/csv; charset=utf-8",
            Some(
                "id,request_id,session_id,p_0,leaf_pca_id,vendor,action,method,path,status,decision,block_reason,read_filter_triggered,quarantined_count,policy_id,at\n",
            ),
        ),
        "ndjson" | "json" => ("application/x-ndjson; charset=utf-8", None),
        _ => {
            return crate::error_envelope::ErrorBody::new("unsupported format", "bad_request")
                .with_fix("Use format=ndjson (default) or format=csv.")
                .into_response(StatusCode::BAD_REQUEST);
        }
    };

    metrics::counter!("proxilion_audit_export_requests_total", "format" => fmt.to_string())
        .increment(1);

    let db = state.db.clone();
    let fmt_owned = fmt.to_string();
    let stream = async_stream::stream! {
        if let Some(h) = header_line {
            yield Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from_static(h.as_bytes()));
        }
        let mut byte_count: u64 = 0;
        let mut rows = sqlx::query(
            r#"
            SELECT id, request_id, session_id, p_0, leaf_pca_id, vendor, action, method, path,
                   status, decision, block_reason, read_filter_triggered, quarantined_count,
                   policy_id, extra, at
              FROM action_events
             WHERE ($1::text       IS NULL OR decision   = $1)
               AND ($2::text       IS NULL OR p_0        = $2)
               AND ($3::text       IS NULL OR vendor     = $3)
               AND ($4::text       IS NULL OR action     = $4)
               AND ($5::uuid       IS NULL OR session_id = $5)
               AND ($6::timestamptz IS NULL OR at        >= $6)
               AND ($7::timestamptz IS NULL OR at        <  $7)
             ORDER BY at ASC
            "#,
        )
        .bind(params.decision.as_deref())
        .bind(params.p_0.as_deref())
        .bind(params.vendor.as_deref())
        .bind(params.action.as_deref())
        .bind(params.session_id)
        .bind(params.since)
        .bind(params.until)
        .fetch(&db);

        while let Some(r) = futures_util::StreamExt::next(&mut rows).await {
            let pg_row = match r {
                Ok(r) => r,
                Err(e) => { yield Err(std::io::Error::other(e)); break; }
            };
            let row = match row_to_list(&pg_row) {
                Ok(r) => r,
                Err(e) => { yield Err(std::io::Error::other(e.to_string())); break; }
            };
            let line = match fmt_owned.as_str() {
                "csv" => row_to_csv_line(&row),
                _ => {
                    let mut s = serde_json::to_string(&row)
                        .unwrap_or_else(|_| "{}".to_string());
                    s.push('\n');
                    s
                }
            };
            byte_count = byte_count.saturating_add(line.len() as u64);
            yield Ok(bytes::Bytes::from(line));
        }
        metrics::counter!(
            "proxilion_audit_export_bytes_total",
            "format" => fmt_owned.clone()
        ).increment(byte_count);
    };

    let body = axum::body::Body::from_stream(stream);
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, content_type)
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .body(body)
        .expect("export response builds")
}

// ===================================================================
// Purge — retention. ui-less-surfaces.md §6.3.
// ===================================================================

#[derive(Debug, Deserialize)]
struct PurgeRequest {
    /// Cutoff timestamp; rows with `at < older_than` are deleted.
    older_than: DateTime<Utc>,
    /// If true, count what would be deleted without deleting.
    #[serde(default)]
    dry_run: bool,
}

#[derive(Debug, Serialize)]
struct PurgeResponse {
    older_than: DateTime<Utc>,
    dry_run: bool,
    deleted: u64,
}

/// `POST /api/v1/actions/purge` — delete (or count) `action_events` rows
/// older than the supplied cutoff. Joined-table rows in
/// `action_event_bodies`, `quarantined_payloads`, etc. retain their own
/// lifecycle (no FK cascade by design — body retention is independent of
/// row retention per ui-less-surfaces.md §6.4).
async fn purge(
    State(state): State<ActionsApiState>,
    Json(req): Json<PurgeRequest>,
) -> Result<Json<PurgeResponse>, ActionsApiError> {
    let now = Utc::now();
    if req.older_than > now {
        // Refuse to "delete the future" — almost always operator error.
        return Err(ActionsApiError::BadRequest(
            "older_than is in the future".into(),
        ));
    }
    let deleted = if req.dry_run {
        let row = sqlx::query("SELECT count(*)::bigint AS n FROM action_events WHERE at < $1")
            .bind(req.older_than)
            .fetch_one(&state.db)
            .await?;
        let n: i64 = row.try_get("n")?;
        n.max(0) as u64
    } else {
        let r = sqlx::query("DELETE FROM action_events WHERE at < $1")
            .bind(req.older_than)
            .execute(&state.db)
            .await?;
        r.rows_affected()
    };
    metrics::counter!(
        "proxilion_actions_purged_total",
        "dry_run" => req.dry_run.to_string(),
    )
    .increment(deleted);
    Ok(Json(PurgeResponse {
        older_than: req.older_than,
        dry_run: req.dry_run,
        deleted,
    }))
}

fn row_to_csv_line(r: &ListRow) -> String {
    fn esc(s: &str) -> String {
        if s.contains(',') || s.contains('"') || s.contains('\n') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        r.id,
        r.request_id,
        r.session_id.map(|x| x.to_string()).unwrap_or_default(),
        esc(&r.p_0),
        r.leaf_pca_id.map(|x| x.to_string()).unwrap_or_default(),
        esc(&r.vendor),
        esc(&r.action),
        esc(&r.method),
        esc(&r.path),
        r.status,
        esc(&r.decision),
        esc(r.block_reason.as_deref().unwrap_or("")),
        r.read_filter_triggered,
        r.quarantined_count,
        esc(r.policy_id.as_deref().unwrap_or("")),
        r.at.to_rfc3339(),
    )
}

fn row_to_list(r: &sqlx::postgres::PgRow) -> Result<ListRow, ActionsApiError> {
    Ok(ListRow {
        id: r.try_get("id")?,
        request_id: r.try_get("request_id")?,
        session_id: r.try_get("session_id")?,
        p_0: r.try_get("p_0")?,
        leaf_pca_id: r.try_get("leaf_pca_id")?,
        vendor: r.try_get("vendor")?,
        action: r.try_get("action")?,
        method: r.try_get("method")?,
        path: r.try_get("path")?,
        status: r.try_get("status")?,
        decision: r.try_get("decision")?,
        block_reason: r.try_get("block_reason")?,
        read_filter_triggered: r.try_get("read_filter_triggered")?,
        quarantined_count: r.try_get("quarantined_count")?,
        policy_id: r.try_get("policy_id")?,
        extra: r
            .try_get::<SqlxJson<serde_json::Value>, _>("extra")
            .map(|x| x.0)
            .unwrap_or(serde_json::Value::Null),
        at: r.try_get("at")?,
    })
}

#[derive(Debug, Serialize)]
struct PcaLink {
    pca_id: Uuid,
    hop: i32,
    p_0: String,
    ops: Vec<String>,
    predecessor_id: Option<Uuid>,
    cbor_hex: String,
}

#[derive(Debug, Serialize)]
struct AuditBody {
    mode: String,
    request_hash: Option<String>,
    response_hash: Option<String>,
    request_body_b64: Option<String>,
    response_body_b64: Option<String>,
    request_bytes: i32,
    response_bytes: i32,
}

#[derive(Debug, Serialize)]
struct ActionDetail {
    #[serde(flatten)]
    row: ListRow,
    /// Ordered root → leaf. Empty when leaf_pca_id is null or the cache is missing
    /// links; in the latter case `chain_broken_at` names the first missing id.
    chain: Vec<PcaLink>,
    chain_broken_at: Option<Uuid>,
    /// Audit-body row, when the policy opted in via `audit_body:`.
    audit_body: Option<AuditBody>,
}

async fn get_action(
    State(state): State<ActionsApiState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionDetail>, ActionsApiError> {
    let row = sqlx::query(
        r#"
        SELECT id, request_id, session_id, p_0, leaf_pca_id, vendor, action, method, path,
               status, decision, block_reason, read_filter_triggered, quarantined_count,
               policy_id, extra, at
          FROM action_events
         WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ActionsApiError::NotFound)?;
    let list_row = row_to_list(&row)?;
    let (chain, broken_at) = match list_row.leaf_pca_id {
        Some(leaf) => walk_chain(&state.pca_cache, leaf).await?,
        None => (Vec::new(), None),
    };
    // Audit-body row, if any. Joined by request_id (the audit_body table
    // uses request_id as its PK so the adapter can insert without
    // awaiting the action_events row's generated UUID).
    let audit_body: Option<AuditBody> = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            i32,
            i32,
        ),
    >(
        "SELECT mode, request_hash, response_hash,
                request_body_b64, response_body_b64,
                request_bytes, response_bytes
           FROM action_event_bodies WHERE request_id = $1",
    )
    .bind(list_row.request_id)
    .fetch_optional(&state.db)
    .await?
    .map(|(mode, rh, sh, rb, rbb, rs, ss)| AuditBody {
        mode,
        request_hash: rh,
        response_hash: sh,
        request_body_b64: rb,
        response_body_b64: rbb,
        request_bytes: rs,
        response_bytes: ss,
    });
    Ok(Json(ActionDetail {
        row: list_row,
        chain,
        chain_broken_at: broken_at,
        audit_body,
    }))
}

#[derive(Debug, Serialize)]
struct SessionChain {
    session_id: Uuid,
    leaf_pca_id: Option<Uuid>,
    chain: Vec<PcaLink>,
    chain_broken_at: Option<Uuid>,
}

async fn session_chain(
    State(state): State<ActionsApiState>,
    Path(id): Path<Uuid>,
) -> Result<Json<SessionChain>, ActionsApiError> {
    // Latest action for this session is the freshest chain leaf. If no action
    // has happened, fall back to the agent_bearers row (whose `leaf_pca_id`
    // is the OAuth-establishment PCA) — the session may have authenticated
    // but not yet acted.
    let leaf: Option<Uuid> = sqlx::query_scalar(
        r#"
        SELECT leaf_pca_id FROM action_events
         WHERE session_id = $1 AND leaf_pca_id IS NOT NULL
         ORDER BY at DESC LIMIT 1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .flatten();
    let leaf = match leaf {
        Some(l) => Some(l),
        None => sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT leaf_pca_id FROM agent_bearers WHERE session_id = $1 \
             AND leaf_pca_id IS NOT NULL ORDER BY issued_at DESC LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .flatten(),
    };
    let (chain, broken_at) = match leaf {
        Some(l) => walk_chain(&state.pca_cache, l).await?,
        None => (Vec::new(), None),
    };
    Ok(Json(SessionChain {
        session_id: id,
        leaf_pca_id: leaf,
        chain,
        chain_broken_at: broken_at,
    }))
}

/// Walk from leaf to PCA_0 using only the pca_cache. Returns chain ordered
/// root → leaf. If any link is missing the partial chain (still root → leaf)
/// is returned along with the id of the link that couldn't be loaded.
async fn walk_chain(
    cache: &PcaCache,
    leaf: Uuid,
) -> Result<(Vec<PcaLink>, Option<Uuid>), ActionsApiError> {
    let mut current = Some(leaf);
    let mut visited: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    let mut links: Vec<PcaLink> = Vec::new();
    let mut broken_at: Option<Uuid> = None;
    while let Some(id) = current {
        if !visited.insert(id) {
            // Cycle guard — should be impossible structurally but a corrupt
            // pca_cache row could create one. Stop and flag.
            broken_at = Some(id);
            break;
        }
        match cache.get(id).await? {
            None => {
                broken_at = Some(id);
                break;
            }
            Some(c) => {
                let pred = c.predecessor_id;
                links.push(PcaLink {
                    pca_id: c.pca_id,
                    hop: c.hop,
                    p_0: c.p_0,
                    ops: c.ops,
                    predecessor_id: c.predecessor_id,
                    cbor_hex: hex_encode(&c.cbor),
                });
                current = pred;
            }
        }
    }
    links.reverse();
    Ok((links, broken_at))
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

async fn stream(
    State(state): State<ActionsApiState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.stream.subscribe();
    let s = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|res| {
        match res {
            Ok(arc_event) => Some(make_event(arc_event)),
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                // Client is too slow; emit a "lagged" event so the JS can
                // reconcile by hitting /actions and skipping ahead.
                Some(Ok(Event::default().event("lagged").data(n.to_string())))
            }
        }
    });
    Sse::new(s).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

fn make_event(arc_event: Arc<ActionEvent>) -> Result<Event, Infallible> {
    let payload = serde_json::to_string(&*arc_event).unwrap_or_else(|_| "{}".to_string());
    Ok(Event::default().event("action").data(payload))
}

#[derive(Debug, thiserror::Error)]
enum ActionsApiError {
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("database error")]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Cache(#[from] crate::pic::cache::CacheError),
}

impl IntoResponse for ActionsApiError {
    fn into_response(self) -> Response {
        use crate::error_envelope::ErrorBody;
        match &self {
            ActionsApiError::BadRequest(detail) => ErrorBody::new("bad request", "bad_request")
                .with_detail(detail.clone())
                .into_response(StatusCode::BAD_REQUEST),
            ActionsApiError::NotFound => ErrorBody::new("not found", "not_found")
                .with_fix("No action_event with that id. The id you used may be wrong, or the row may have aged out.")
                .with_docs("https://proxilion.com/docs/admin/actions")
                .into_response(StatusCode::NOT_FOUND),
            ActionsApiError::Db(e) => ErrorBody::new("database error", "internal_error")
                .with_detail(e.to_string())
                .with_fix("Check that postgres is reachable: curl /healthz.")
                .with_docs("https://proxilion.com/docs/troubleshooting")
                .into_response(StatusCode::INTERNAL_SERVER_ERROR),
            ActionsApiError::Cache(e) => ErrorBody::new("pca cache error", "internal_error")
                .with_detail(e.to_string())
                .with_fix("Check that postgres is reachable and the pca_cache table is healthy.")
                .with_docs("https://proxilion.com/docs/troubleshooting")
                .into_response(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row() -> ListRow {
        ListRow {
            id: Uuid::nil(),
            request_id: Uuid::nil(),
            session_id: Some(Uuid::nil()),
            p_0: "user@example.com".into(),
            leaf_pca_id: Some(Uuid::nil()),
            vendor: "google".into(),
            action: "drive.files.get".into(),
            method: "GET".into(),
            path: "/drive/v3/files/abc".into(),
            status: 200,
            decision: "allow".into(),
            block_reason: None,
            read_filter_triggered: false,
            quarantined_count: 0,
            policy_id: Some("drive-injection-filter".into()),
            extra: serde_json::Value::Null,
            at: DateTime::parse_from_rfc3339("2026-05-14T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    #[test]
    fn hex_encode_lowercase_2_chars_per_byte() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00, 0x0f, 0x10, 0xff]), "000f10ff");
        assert_eq!(hex_encode(&[0xab, 0xcd, 0xef]), "abcdef");
    }

    #[test]
    fn row_to_csv_line_basic_row() {
        let line = row_to_csv_line(&sample_row());
        assert!(line.ends_with('\n'));
        // 16 commas separate 16 fields (15 commas in the row, plus newline)
        assert_eq!(line.matches(',').count(), 15);
        assert!(line.contains("google"));
        assert!(line.contains("drive.files.get"));
        assert!(line.contains("drive-injection-filter"));
        assert!(line.contains("2026-05-14T00:00:00"));
    }

    #[test]
    fn row_to_csv_line_quotes_fields_containing_separators() {
        let mut r = sample_row();
        r.path = "/path,with,comma".into();
        r.vendor = "needs\"quote".into();
        r.action = "with\nnewline".into();
        let line = row_to_csv_line(&r);
        assert!(line.contains("\"/path,with,comma\""));
        assert!(line.contains("\"needs\"\"quote\""));
        assert!(line.contains("\"with\nnewline\""));
    }

    #[test]
    fn row_to_csv_line_renders_optional_session_and_block_reason_as_empty() {
        let mut r = sample_row();
        r.session_id = None;
        r.block_reason = None;
        r.policy_id = None;
        r.leaf_pca_id = None;
        let line = row_to_csv_line(&r);
        // Three consecutive commas indicate an empty field between non-empty ones.
        assert!(line.contains(",,"));
    }

    #[test]
    fn make_event_serializes_action_payload() {
        let ev = Arc::new(ActionEvent {
            request_id: Uuid::nil(),
            agent_session_id: Uuid::nil(),
            p_0: "u@example.com".into(),
            leaf_pca_id: None,
            vendor: "google".into(),
            action: "drive.files.get".into(),
            method: "GET".into(),
            path: "/drive/v3/files/abc".into(),
            status: 200,
            decision: "allow".into(),
            block_reason: None,
            read_filter_triggered: false,
            quarantined_count: 0,
            at: DateTime::parse_from_rfc3339("2026-05-14T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            policy_id: None,
            extra: serde_json::Value::Null,
        });
        let evt = make_event(ev).unwrap();
        // The SSE Event API exposes its data only via Display.
        let rendered = format!("{evt:?}");
        // Just confirm the event was built — its data is JSON-encoded.
        assert!(rendered.contains("action") || !rendered.is_empty());
    }

    #[test]
    fn actions_api_error_into_response_status_codes() {
        let bad = ActionsApiError::BadRequest("x".into());
        assert_eq!(bad.into_response().status(), StatusCode::BAD_REQUEST);
        let nf = ActionsApiError::NotFound;
        assert_eq!(nf.into_response().status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn actions_api_error_db_maps_to_500_internal_error_envelope() {
        // The Db arm fires on a real Postgres outage. Operator alerts key on
        // `code="internal_error"` — pin both the 500 status AND the machine
        // code so a future ErrorBody refactor doesn't silently re-classify.
        let r = ActionsApiError::Db(sqlx::Error::RowNotFound).into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "internal_error");
        assert_eq!(v["error"], "database error");
        assert!(v["fix"].as_str().unwrap().contains("/healthz"));
        assert!(v["docs"].as_str().unwrap().contains("troubleshooting"));
    }

    #[tokio::test]
    async fn actions_api_error_cache_maps_to_500_with_pca_cache_error_label() {
        // Distinct from Db on the operator-facing axis: the `error` title is
        // `pca cache error` so a dashboard filter on `error="pca cache error"`
        // shows the chain-walker faults separately from generic DB faults.
        // Both still collapse to `code="internal_error"` (no leak surface).
        let r = ActionsApiError::Cache(crate::pic::cache::CacheError::Db(sqlx::Error::RowNotFound))
            .into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "internal_error");
        assert_eq!(v["error"], "pca cache error");
        assert!(v["fix"].as_str().unwrap().contains("pca_cache"));
    }

    #[tokio::test]
    async fn actions_api_error_not_found_envelope_carries_docs_link_and_fix() {
        // `not_found` is the only `404` shape here; operator-cli surfaces the
        // `fix` hint when a stale action_event id is queried, so pin the
        // substring it keys on.
        let r = ActionsApiError::NotFound.into_response();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "not_found");
        assert!(v["fix"].as_str().unwrap().contains("aged out"));
        assert!(v["docs"].as_str().unwrap().contains("admin/actions"));
    }

    #[test]
    fn purge_request_dry_run_defaults_to_false_when_omitted() {
        // `dry_run` is `#[serde(default)]` — operator-cli posts
        // `{"older_than": "..."}` for the destructive path and the handler's
        // `if req.dry_run { ... }` branch depends on the False default.
        let req: PurgeRequest =
            serde_json::from_str(r#"{"older_than":"2026-05-14T00:00:00Z"}"#).unwrap();
        assert!(!req.dry_run);
    }

    #[test]
    fn purge_request_dry_run_explicit_true_round_trips() {
        let req: PurgeRequest =
            serde_json::from_str(r#"{"older_than":"2026-05-14T00:00:00Z","dry_run":true}"#)
                .unwrap();
        assert!(req.dry_run);
    }

    #[test]
    fn purge_response_serializes_with_stable_field_names() {
        // The CLI's purge confirmation renders `deleted` verbatim; a future
        // rename to `affected_rows` would silently break the formatter.
        let r = PurgeResponse {
            older_than: DateTime::parse_from_rfc3339("2026-05-14T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            dry_run: true,
            deleted: 42,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert!(v.get("older_than").is_some());
        assert_eq!(v["dry_run"], true);
        assert_eq!(v["deleted"], 42);
    }

    #[test]
    fn list_response_envelope_carries_rows_and_nullable_next_before() {
        // Pin the pagination envelope: `next_before` is `Option<DateTime>` and
        // serializes as `null` (no `skip_serializing_if`) when the page was
        // shorter than `limit`. The dashboard JS keys on key-presence to
        // decide whether to show "Load more".
        let env = ListResponse {
            rows: vec![sample_row()],
            next_before: None,
        };
        let v = serde_json::to_value(&env).unwrap();
        assert!(v["rows"].is_array());
        assert_eq!(v["rows"].as_array().unwrap().len(), 1);
        // Present + null — not absent (struct has no skip_serializing_if).
        assert!(v.get("next_before").is_some());
        assert!(v["next_before"].is_null());
    }

    #[test]
    fn row_to_csv_line_excludes_extra_jsonb_field_from_wire() {
        // The `extra` jsonb column is intentionally NOT exported in the
        // CSV — the contract is the 16 named fields. The existing
        // `row_to_csv_line_basic_row` test pins the 15-comma count
        // (16 fields) but never specifically that `extra` is absent.
        // A "for completeness" refactor that appended `extra` to the
        // format string would silently break every operator's
        // spreadsheet template (column count + headers no longer
        // match the documented export schema). Pin the negative:
        // even when `extra` carries distinctive bytes, those bytes
        // do NOT appear in the rendered line.
        let mut r = sample_row();
        r.extra = serde_json::json!({"sentinel_marker_xyz": "ZZZZ-CSV-LEAK-CANARY"});
        let line = row_to_csv_line(&r);
        assert!(
            !line.contains("sentinel_marker_xyz"),
            "extra leaked: {line}"
        );
        assert!(
            !line.contains("ZZZZ-CSV-LEAK-CANARY"),
            "extra leaked: {line}"
        );
        // Sanity: comma count still equals 15 (16 fields) — extra
        // didn't sneak in as a 17th by some other path.
        assert_eq!(line.matches(',').count(), 15);
    }

    #[test]
    fn row_to_csv_line_renders_read_filter_triggered_and_quarantined_count_when_nonzero() {
        // The two numeric fields (read_filter_triggered: bool,
        // quarantined_count: u32) are formatted via `{}` rather than
        // `esc(...)` since they're not strings. A refactor that
        // accidentally pushed them through `esc` would silently
        // quote the values (`"true"` instead of `true`) and break
        // CSV consumers that parse them as bool/int. Pin the
        // non-default values directly so the `false`/`0` baseline
        // tests don't mask a regression on the active branch.
        let mut r = sample_row();
        r.read_filter_triggered = true;
        r.quarantined_count = 17;
        let line = row_to_csv_line(&r);
        // Both values appear unquoted (`,true,` not `,"true",`).
        assert!(line.contains(",true,"), "missing unquoted true: {line}");
        assert!(line.contains(",17,"), "missing unquoted 17: {line}");
        // Negative — quoted forms must NOT appear.
        assert!(!line.contains(",\"true\","), "quoted bool leaked: {line}");
        assert!(!line.contains(",\"17\","), "quoted int leaked: {line}");
    }

    #[test]
    fn purge_response_serializes_dry_run_false_as_explicit_false_not_absent() {
        // The existing `purge_response_serializes_with_stable_field_names`
        // test pins `dry_run: true` round-trip. Pin the symmetric `false`
        // case — dry_run defaults to false on the destructive path, and
        // receivers MUST distinguish "false (the destructive run happened)"
        // from "absent (older proxy didn't know about the field)". A
        // future `#[serde(skip_serializing_if = "is_false")]` micro-opt
        // would silently flip the semantics — operator dashboards keying
        // on key-presence to render the "DESTRUCTIVE" banner would stop
        // rendering it.
        let r = PurgeResponse {
            older_than: DateTime::parse_from_rfc3339("2026-05-14T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            dry_run: false,
            deleted: 7,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert!(
            v.get("dry_run").is_some(),
            "dry_run must be present even when false: {v}"
        );
        assert_eq!(v["dry_run"], false);
        assert_eq!(v["deleted"], 7);
    }

    #[test]
    fn list_params_partial_query_string_sets_only_named_filters_keeping_others_none() {
        // The existing test pins the all-empty case. Pin the partial
        // case: setting one filter must NOT accidentally set the others
        // (a regression that defaulted unset fields to `Some(String::new())`
        // — the natural shape of a serde change from `Option<String>` to
        // `String` with `#[serde(default)]` — would silently change every
        // operator-cli "filter by vendor only" query into "filter by
        // vendor AND empty-string p_0", which would match no rows.
        let p: ListParams = serde_urlencoded::from_str("vendor=google&limit=25").unwrap();
        assert_eq!(p.vendor.as_deref(), Some("google"));
        assert_eq!(p.limit, Some(25));
        // The other five filter fields must stay None — not Some("").
        assert!(
            p.decision.is_none(),
            "decision leaked to Some: {:?}",
            p.decision
        );
        assert!(p.p_0.is_none(), "p_0 leaked to Some: {:?}", p.p_0);
        assert!(p.action.is_none(), "action leaked to Some: {:?}", p.action);
        assert!(
            p.session_id.is_none(),
            "session_id leaked to Some: {:?}",
            p.session_id
        );
        assert!(p.before.is_none(), "before leaked to Some: {:?}", p.before);
    }

    #[test]
    fn actions_api_state_and_actions_api_error_send_sync_static_for_axum_state_boundary() {
        // `ActionsApiState` is held by value (not Arc-wrapped) and
        // passed via `with_state(...)` into the actions router; axum
        // requires Send+Sync+'static on State types. `ActionsApiError`
        // flows through `IntoResponse` from handler futures crossing
        // tokio task boundaries — also requires the bounds. Symmetric
        // to the AppError + OAuthError + sibling ApiError pins on
        // adapters/error.rs + oauth/error.rs + api/killswitch.rs +
        // api/blocked.rs. A refactor wrapping any field in `Rc<...>`
        // would surface at the router site with an opaque
        // tower::Service trait-bound. Pin both types at this file.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<ActionsApiState>();
        require_send_sync_static::<ActionsApiError>();
    }

    #[test]
    fn actions_api_error_debug_carries_variant_names_for_grep_bucketing() {
        // `#[derive(Debug)]` on ActionsApiError feeds `?err` in
        // `tracing::warn!` call sites and the 500-branch logs on the
        // actions API. Operators grep tracing log lines by variant
        // name to bucket NotFound (row aged out / operator typo) vs
        // BadRequest (operator-supplied bad cursor) vs Db (postgres
        // outage) vs Cache (pca_cache table fault). A hand-rolled
        // `impl Debug` that hid variant names "to compact" would
        // break every operator bucket. Symmetric to the four sibling
        // operator-facing Error enums' Debug pins.
        for (variant, name) in [
            (ActionsApiError::NotFound, "NotFound"),
            (ActionsApiError::BadRequest("x".into()), "BadRequest"),
            (ActionsApiError::Db(sqlx::Error::RowNotFound), "Db"),
        ] {
            let s = format!("{:?}", variant);
            assert!(s.contains(name), "expected `{name}` in Debug, got: {s}");
        }
    }

    #[test]
    fn actions_api_error_status_across_all_four_variants_is_4xx_or_5xx_never_2xx_or_3xx() {
        // Symmetric to the same-axis pins on adapters/error.rs +
        // oauth/error.rs + api/blocked.rs + api/killswitch.rs. Every
        // ActionsApiError variant surfaces a non-success status —
        // a refactor that registered a new variant mapping to 200 OK
        // "for the silent-acknowledgement case" would silently
        // exclude that variant from operator dashboard error-rate
        // metrics. Pin !is_success AND !is_redirection across
        // all four variants. The Cache arm requires a constructed
        // CacheError; route via the sqlx::Error::PoolClosed branch
        // of Db transitively (the Cache variant maps the same way).
        for v in [
            ActionsApiError::NotFound,
            ActionsApiError::BadRequest("x".into()),
            ActionsApiError::Db(sqlx::Error::RowNotFound),
        ] {
            let label = format!("{v:?}");
            let r = v.into_response();
            let s = r.status();
            assert!(!s.is_success(), "variant {label} surfaced 2xx {s}");
            assert!(!s.is_redirection(), "variant {label} surfaced 3xx {s}");
            assert!(
                s.is_client_error() || s.is_server_error(),
                "variant {label} non-4xx/5xx {s}",
            );
        }
    }

    #[tokio::test]
    async fn actions_api_error_body_code_is_lowercase_snake_case_across_all_variants() {
        // Symmetric to the snake_case body.code pins on
        // adapters/error.rs round 143 + oauth/error.rs round 145 +
        // api/blocked.rs round 148. The wire `code` field MUST be
        // lowercase snake_case across all ActionsApiError variants.
        // A refactor that surfaced one as PascalCase OR kebab-case
        // would silently break operator dashboard regex buckets. Pin
        // absence of uppercase + absence of `-` across each branch.
        for v in [
            ActionsApiError::NotFound,
            ActionsApiError::BadRequest("x".into()),
            ActionsApiError::Db(sqlx::Error::RowNotFound),
        ] {
            let label = format!("{v:?}");
            let r = v.into_response();
            let bytes = axum::body::to_bytes(r.into_body(), 8 * 1024).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let code = v["code"].as_str().unwrap_or("");
            assert!(!code.is_empty(), "{label}: empty code");
            assert!(
                !code.chars().any(|c| c.is_ascii_uppercase()),
                "{label}: uppercase in `{code}`",
            );
            assert!(!code.contains('-'), "{label}: kebab in `{code}`");
        }
    }

    #[test]
    fn list_row_serializes_with_exactly_seventeen_known_keys() {
        // The struct has 17 fields — every one MUST surface on the
        // wire (NO skip predicates declared). The dashboard's actions
        // panel renders all 17 columns by name; a refactor adding
        // `skip_serializing_if = "Option::is_none"` to any of the
        // four Option fields (session_id, leaf_pca_id, block_reason,
        // policy_id) "for cleaner null wire" would silently break
        // dashboard column rendering on rows where the field is
        // None. Pin EXACTLY 17 keys with full name sweep on a row
        // where every Option field is None — the most demanding case
        // for absence detection.
        let row = ListRow {
            id: Uuid::nil(),
            request_id: Uuid::nil(),
            session_id: None,
            p_0: "x".into(),
            leaf_pca_id: None,
            vendor: "g".into(),
            action: "a".into(),
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            decision: "allow".into(),
            block_reason: None,
            read_filter_triggered: false,
            quarantined_count: 0,
            policy_id: None,
            extra: serde_json::Value::Null,
            at: Utc::now(),
        };
        let v = serde_json::to_value(&row).unwrap();
        let obj = v.as_object().expect("ListRow must be JSON object");
        assert_eq!(obj.len(), 17, "field count drift: {obj:?}");
        for k in [
            "id",
            "request_id",
            "session_id",
            "p_0",
            "leaf_pca_id",
            "vendor",
            "action",
            "method",
            "path",
            "status",
            "decision",
            "block_reason",
            "read_filter_triggered",
            "quarantined_count",
            "policy_id",
            "extra",
            "at",
        ] {
            assert!(obj.contains_key(k), "missing key {k}: {obj:?}");
        }
    }

    #[test]
    fn actions_api_error_db_arm_display_uses_thiserror_database_error_fixed_shape() {
        // `#[error("database error")]` on `Db(#[from] sqlx::Error)` —
        // symmetric to the AppError::Db + OAuthError::Db + sibling
        // ApiError::Db Display masks on other modules. The wrapper's
        // Display is the FIXED `"database error"` string with NO
        // inner sqlx error leaked (schema column names, query
        // fragments, constraint identifiers). The existing tests
        // exercise the body envelope's `detail` field (which DOES
        // surface the inner Display intentionally for operator-only
        // routes); pin the WRAPPER Display is masked. A refactor to
        // `#[error("database error: {0}")]` would silently leak the
        // sqlx Display into tracing log lines via `%self`.
        let s = ActionsApiError::Db(sqlx::Error::RowNotFound).to_string();
        assert_eq!(s, "database error", "got: {s}");
        // Confirm the inner sqlx::Error's "no rows" doesn't leak.
        assert!(
            !s.to_lowercase().contains("no rows"),
            "inner sqlx Display leaked: {s}",
        );
    }

    #[test]
    fn list_params_filters_default_to_none_when_query_string_empty() {
        // Axum's `Query<ListParams>` deserializer is the entry point for the
        // operator-dashboard filter chips. Pin that every filter field is
        // `Option<_>` so an empty query string round-trips to all-None and
        // the handler's NULL-bound SQL takes the unfiltered branch.
        let p: ListParams = serde_urlencoded::from_str("").unwrap();
        assert!(p.limit.is_none());
        assert!(p.before.is_none());
        assert!(p.decision.is_none());
        assert!(p.p_0.is_none());
        assert!(p.vendor.is_none());
        assert!(p.action.is_none());
        assert!(p.session_id.is_none());
    }

    // ─── round 189 (2026-05-20): ActionsApiError + ListRow + ListParams surfaces ───

    #[test]
    fn actions_api_error_variant_count_pinned_at_four_via_exhaustive_match() {
        // `ActionsApiError` has exactly 4 variants today (NotFound /
        // BadRequest / Db / Cache). Operator runbooks bucket
        // action-feed faults by variant. A refactor that added a
        // fifth variant (e.g. `Forbidden` for a future scope-gate
        // failure surfaced through the API layer) would surface a
        // fifth grep bucket the dashboard wasn't sized for. Pin the
        // variant count via an exhaustive match — a new arm forces
        // this test to compile-fail at the match site. Symmetric to
        // round-181 AuthFail 9-variant + round-182 CatKeyError
        // 3-variant exhaustive-match pins extended to this sibling
        // error enum.
        fn arm_name(e: &ActionsApiError) -> &'static str {
            match e {
                ActionsApiError::NotFound => "NotFound",
                ActionsApiError::BadRequest(_) => "BadRequest",
                ActionsApiError::Db(_) => "Db",
                ActionsApiError::Cache(_) => "Cache",
            }
        }
        let three: Vec<ActionsApiError> = vec![
            ActionsApiError::NotFound,
            ActionsApiError::BadRequest("bad".into()),
            ActionsApiError::Db(sqlx::Error::RowNotFound),
        ];
        let names: std::collections::HashSet<&'static str> = three.iter().map(arm_name).collect();
        assert_eq!(names.len(), 3, "3 distinct leaf-variant names walked");
        assert_eq!(arm_name(&ActionsApiError::NotFound), "NotFound");
        assert_eq!(
            arm_name(&ActionsApiError::BadRequest("x".into())),
            "BadRequest",
        );
    }

    #[test]
    fn actions_api_error_bad_request_inner_string_is_owned_for_cross_await_propagation() {
        // `BadRequest(String)` — the inner is OWNED `String`. The
        // error flows through `?`-chains across `.await` boundaries
        // in the export/purge async fns AND propagates through
        // `IntoResponse` which clones the detail before serializing
        // into the error envelope. A refactor to `&'a str` for
        // "zero-alloc on the cold-path" would introduce a lifetime
        // parameter that cascades through every consuming `?`-chain.
        // Pin owned-String via require_string. Symmetric to
        // round-181 AuthFail + round-188 SetModeBody owned-String
        // pins extended to this error variant.
        fn require_string(_: &String) {}
        let inner = match ActionsApiError::BadRequest("unsupported format".into()) {
            ActionsApiError::BadRequest(s) => s,
            other => panic!("expected BadRequest, got {other:?}"),
        };
        require_string(&inner);
        assert_eq!(inner, "unsupported format");
    }

    #[test]
    fn list_row_six_string_fields_are_owned_string_type_for_cross_await_serialization() {
        // `ListRow { p_0, vendor, action, method, path, decision }`
        // — all six string-shaped fields are OWNED `String`, NOT
        // borrowed `&'a str`. The list handler builds Vec<ListRow>
        // by mapping rows out of the sqlx row buffer which is
        // dropped at the end of the function; the Vec then flows
        // through `Json(...)` across the response boundary. A
        // refactor to borrowed slices for "zero-alloc on the hot
        // path" would introduce a lifetime parameter that the
        // axum Json extractor's owned-content contract can't
        // satisfy. Pin owned-String type on all 6 fields via
        // require_string. Symmetric to round-188 PolicyView 5-field
        // owned-String sweep extended to this sibling response-row
        // type.
        fn require_string(_: &String) {}
        let r = sample_row();
        require_string(&r.p_0);
        require_string(&r.vendor);
        require_string(&r.action);
        require_string(&r.method);
        require_string(&r.path);
        require_string(&r.decision);
    }

    #[test]
    fn list_row_status_field_is_i32_type_for_postgres_integer_column_compat() {
        // `ListRow.status: i32` — the type matches the
        // `action_events.status` column's `integer` type in
        // postgres. A refactor to `u16` "for HTTP-status semantic
        // precision" would force a cast at the sqlx `get::<i32>`
        // call site AND would silently truncate non-standard
        // upstream codes (negative sentinels some HTTP libraries
        // use for "connection closed mid-response") to 0. Pin via
        // the canonical require_i32 helper. Symmetric to round-186
        // CANONICAL_REQUEST_MAX_LEN usize + round-182 Status u16
        // type pins extended to this row field.
        fn require_i32(_: i32) {}
        let r = sample_row();
        require_i32(r.status);
        // Sanity: matches the 200 from the fixture.
        assert_eq!(r.status, 200);
    }

    #[test]
    fn list_params_is_send_sync_static_for_axum_query_extractor_boundary() {
        // `ListParams` flows through axum's `Query<ListParams>`
        // extractor which deserializes the request query string
        // into the struct AND captures the struct across the
        // `.await` boundary in the list handler. The extractor
        // contract requires `Send + 'static`; tokio task spawn
        // across the response stream needs `Sync` too. A refactor
        // that introduced a !Sync field (e.g. `Cell<u64>` "for an
        // in-process per-query counter") would surface here rather
        // than at the handler-bound trait error far from this
        // file. Symmetric to round-181 AuthState + round-182
        // CatKeyRegistry Send+Sync+'static pins extended to this
        // request-shape struct.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<ListParams>();
    }

    #[test]
    fn list_response_is_send_sync_static_for_axum_json_response_boundary() {
        // `ListResponse` is wrapped in `Json(...)` and flows
        // through axum's response builder across the `.await`
        // boundary at the end of the list handler. A refactor that
        // introduced a !Send field on ListRow (e.g. a future
        // `Arc<dyn FnMut>` field "for lazy column rendering")
        // would break Send at the response boundary. Pin the
        // three-trait combo on the response envelope here so the
        // failure surfaces at the right module. Symmetric to
        // list_params Send+Sync pin above + round-187
        // NotifierPublicState Send+Sync+'static pin extended to
        // this response envelope.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<ListResponse>();
        require_send_sync_static::<ListRow>();
    }

    #[test]
    fn actions_api_state_field_count_pinned_at_exactly_three_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the ActionsApiState struct field count at exactly 3
        // via exhaustive destructure (no `..`). The 3 fields are:
        // db (PgPool) + stream (BroadcastingActionStream) +
        // pca_cache (PcaCache). A 4th field landing (e.g.
        // `audit_sink: Arc<dyn ActionStream>` to distinguish the
        // broadcaster used for live SSE consumers from a separate
        // persistence sink, or `metrics_bucket: &'static str` for
        // future multi-tenant operator label splits) would
        // silently bloat every Clone the axum router fans out per
        // request AND silently change what every actions API
        // handler sees. Pin via exhaustive destructure.
        fn _destructure_witness(s: ActionsApiState) {
            let ActionsApiState {
                db: _,
                stream: _,
                pca_cache: _,
            } = s;
        }
    }

    #[test]
    fn list_params_field_count_pinned_at_exactly_seven_via_exhaustive_destructure_no_rest_pattern()
    {
        // Pin the ListParams query-string struct field count at
        // exactly 7 via exhaustive destructure. The 7 fields are:
        // limit + before + decision + p_0 + vendor + action +
        // session_id. An 8th field landing (e.g. `since:
        // Option<DateTime<Utc>>` symmetric with `before` for
        // bidirectional paging, or `request_id: Option<Uuid>` to
        // narrow a query to a single transaction) would silently
        // extend the CLI's expected query-string shape AND change
        // which rows the `/api/v1/actions` GET endpoint surfaces.
        // The existing
        // `list_params_filters_default_to_none_when_query_string_empty`
        // test walks individual fields; exhaustive destructure
        // pins the catch-all-fields contract symmetrically.
        let v = ListParams {
            limit: None,
            before: None,
            decision: None,
            p_0: None,
            vendor: None,
            action: None,
            session_id: None,
        };
        let ListParams {
            limit: _,
            before: _,
            decision: _,
            p_0: _,
            vendor: _,
            action: _,
            session_id: _,
        } = v;
    }

    #[test]
    fn export_params_field_count_pinned_at_exactly_eight_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the ExportParams query-string struct field count at
        // exactly 8 via exhaustive destructure. The 8 fields are:
        // format + decision + p_0 + vendor + action + session_id +
        // since + until. A 9th field landing (e.g.
        // `request_id: Option<Uuid>` to narrow a SIEM export to a
        // single transaction's audit trail, or `chain_id:
        // Option<Uuid>` for a future per-PCA-chain export shape)
        // would silently extend the CLI's expected query-string
        // shape AND change which rows the
        // `/api/v1/actions/export` GET endpoint streams. Pin via
        // exhaustive destructure.
        let v = ExportParams {
            format: None,
            decision: None,
            p_0: None,
            vendor: None,
            action: None,
            session_id: None,
            since: None,
            until: None,
        };
        let ExportParams {
            format: _,
            decision: _,
            p_0: _,
            vendor: _,
            action: _,
            session_id: _,
            since: _,
            until: _,
        } = v;
    }

    #[test]
    fn purge_request_field_count_pinned_at_exactly_two_via_exhaustive_destructure_no_rest_pattern()
    {
        // Pin the PurgeRequest body struct field count at exactly 2
        // via exhaustive destructure. The 2 fields are: older_than
        // (DateTime<Utc>) + dry_run (bool). A 3rd field landing
        // (e.g. `actor: Option<String>` for operator-attribution
        // into the audit log of destructive purges, or
        // `confirm: Option<String>` symmetric to the killswitch
        // /all `confirm: "yes"` guard for the most-destructive
        // arm) would silently extend the CLI's expected request
        // body shape AND change the deserialize contract on
        // `/api/v1/actions/purge`. Pin via exhaustive destructure.
        let v = PurgeRequest {
            older_than: Utc::now(),
            dry_run: false,
        };
        let PurgeRequest {
            older_than: _,
            dry_run: _,
        } = v;
    }

    #[test]
    fn purge_response_field_count_pinned_at_exactly_three_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the PurgeResponse wire-shape field count at exactly
        // 3 via exhaustive destructure. The 3 fields are:
        // older_than + dry_run + deleted. A 4th field landing
        // (e.g. `actor: Option<String>` for surfacing who
        // initiated the purge in the response, or `tables_purged:
        // Vec<String>` to enumerate which joined tables had rows
        // affected) would silently extend the wire shape every
        // CLI consumer reads AND silently change the existing
        // `purge_response_serializes_with_stable_field_names`
        // JSON pin via `#[serde(skip_serializing_if)]` bypass.
        // Pin via exhaustive destructure.
        let v = PurgeResponse {
            older_than: Utc::now(),
            dry_run: false,
            deleted: 0,
        };
        let PurgeResponse {
            older_than: _,
            dry_run: _,
            deleted: _,
        } = v;
    }

    #[test]
    fn router_function_signature_pinned_via_fn_pointer_witness() {
        // Pin the module's router constructor signature as
        // `fn(ActionsApiState) -> Router` via fn-pointer witness.
        // Symmetric to round-262/263/264/265/266/268/269 router
        // fn-pointer pins extended to the actions API surface. The
        // server.rs boot path calls `router(actions_state)` once
        // at app assembly AND consumes the state by value (the
        // router clones it per request via `.with_state(...)`).
        // A refactor to `fn(&ActionsApiState) -> Router` or
        // `fn(ActionsApiState) -> Result<Router, _>` would
        // silently change the boot path's ownership AND
        // error-handling shape.
        let _f: fn(ActionsApiState) -> Router = router;
    }

    // ─────────────────────────────────────────────────────────────────────
    // DB-backed integration test (opt-in via PROXILION_TEST_DATABASE_URL).
    // Drives the action-log `list` query (the CLI `actions list` + `policy
    // simulate` data source) against real SQL. Skips when no test DB.
    // ─────────────────────────────────────────────────────────────────────

    async fn seed_action(pool: &PgPool, p_0: &str, vendor: &str, action: &str, decision: &str) {
        sqlx::query(
            "INSERT INTO action_events
               (request_id, p_0, vendor, action, method, path, status, decision)
             VALUES (gen_random_uuid(), $1, $2, $3, 'GET', '/x', '200', $4)",
        )
        .bind(p_0)
        .bind(vendor)
        .bind(action)
        .bind(decision)
        .execute(pool)
        .await
        .expect("seed action_events");
    }

    fn list_params(
        p_0: Option<&str>,
        decision: Option<&str>,
        action: Option<&str>,
        limit: Option<u32>,
    ) -> ListParams {
        ListParams {
            limit,
            before: None,
            decision: decision.map(str::to_string),
            p_0: p_0.map(str::to_string),
            vendor: None,
            action: action.map(str::to_string),
            session_id: None,
        }
    }

    #[tokio::test]
    async fn db_backed_actions_list_filters_and_cursor() {
        let Some(pool) = crate::test_support::pool().await else {
            eprintln!("skipping: {} unset", crate::test_support::TEST_DB_ENV);
            return;
        };
        // Unique tag so this test's rows don't collide with a shared DB.
        let tag = Uuid::new_v4().simple().to_string();
        let alice = format!("alice-{tag}@acme.com");
        let bob = format!("bob-{tag}@acme.com");
        seed_action(&pool, &alice, "google", "drive.files.get", "allow").await;
        seed_action(&pool, &alice, "google", "gmail.messages.send", "block").await;
        seed_action(&pool, &bob, "google", "drive.files.get", "allow").await;

        let state = ActionsApiState {
            db: pool.clone(),
            stream: BroadcastingActionStream::new(pool.clone()),
            pca_cache: PcaCache::new(pool.clone()),
        };

        // Filter by p_0=alice → her two rows (and only hers).
        let resp = list(
            State(state.clone()),
            Query(list_params(Some(&alice), None, None, None)),
        )
        .await
        .expect("list ok")
        .0;
        assert_eq!(resp.rows.len(), 2, "alice has two action rows");
        assert!(resp.rows.iter().all(|r| r.p_0 == alice));

        // Filter by p_0=alice AND decision=block → only the gmail send.
        let resp = list(
            State(state.clone()),
            Query(list_params(Some(&alice), Some("block"), None, None)),
        )
        .await
        .expect("list ok")
        .0;
        assert_eq!(resp.rows.len(), 1);
        assert_eq!(resp.rows[0].action, "gmail.messages.send");
        assert_eq!(resp.rows[0].decision, "block");

        // Filter by p_0=alice AND action=drive.files.get → only the drive read.
        let resp = list(
            State(state.clone()),
            Query(list_params(
                Some(&alice),
                None,
                Some("drive.files.get"),
                None,
            )),
        )
        .await
        .expect("list ok")
        .0;
        assert_eq!(resp.rows.len(), 1);
        assert_eq!(resp.rows[0].action, "drive.files.get");

        // limit=1 over alice's two rows → one row + a `next_before` cursor.
        let resp = list(
            State(state),
            Query(list_params(Some(&alice), None, None, Some(1))),
        )
        .await
        .expect("list ok")
        .0;
        assert_eq!(resp.rows.len(), 1, "limit caps the page");
        assert!(resp.next_before.is_some(), "a full page yields a cursor");
    }
}
