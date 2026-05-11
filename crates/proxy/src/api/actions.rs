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
    Router::new()
        // /actions returns a paginated envelope { rows, next_before }.
        // /actions/recent stays as a raw array for the static-admin UI.
        .route("/api/v1/actions", axum::routing::get(list))
        .route("/api/v1/actions/recent", axum::routing::get(recent))
        .route("/api/v1/actions/stream", axum::routing::get(stream))
        .route("/api/v1/actions/export", axum::routing::get(export))
        .route("/api/v1/actions/{id}", axum::routing::get(get_action))
        .route("/api/v1/sessions/{id}/chain", axum::routing::get(session_chain))
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
    Ok(Json(ListResponse { rows: out, next_before }))
}

#[derive(Debug, Deserialize)]
struct ExportParams {
    /// `ndjson` (default), `json`, or `csv`. The streaming code path is NDJSON
    /// + CSV; `json` falls back to a single bulk array materialised in memory
    /// and is intended for small windows only.
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
            Some("id,request_id,session_id,p_0,leaf_pca_id,vendor,action,method,path,status,decision,block_reason,read_filter_triggered,quarantined_count,policy_id,at\n"),
        ),
        "ndjson" | "json" => ("application/x-ndjson; charset=utf-8", None),
        _ => {
            return crate::error_envelope::ErrorBody::new(
                "unsupported format",
                "bad_request",
            )
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
struct ActionDetail {
    #[serde(flatten)]
    row: ListRow,
    /// Ordered root → leaf. Empty when leaf_pca_id is null or the cache is missing
    /// links; in the latter case `chain_broken_at` names the first missing id.
    chain: Vec<PcaLink>,
    chain_broken_at: Option<Uuid>,
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
    Ok(Json(ActionDetail { row: list_row, chain, chain_broken_at: broken_at }))
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
                Some(Ok(Event::default()
                    .event("lagged")
                    .data(n.to_string())))
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
    #[error("database error")]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Cache(#[from] crate::pic::cache::CacheError),
}

impl IntoResponse for ActionsApiError {
    fn into_response(self) -> Response {
        use crate::error_envelope::ErrorBody;
        match &self {
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
