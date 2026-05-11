//! Action event stream — every adapter call emits one of these.
//!
//! Two implementations:
//!   * `LoggingStream` — writes JSON to tracing. Default in tests / dev.
//!   * `BroadcastingActionStream` — persists to `action_events` and fans out
//!     over a `tokio::sync::broadcast` channel for SSE subscribers.
//!
//! NATS bridging (spec.md §3.1) can compose with either by wrapping.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEvent {
    pub request_id: Uuid,
    pub agent_session_id: Uuid,
    pub p_0: String,
    pub leaf_pca_id: Option<Uuid>,
    pub vendor: String,
    pub action: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub decision: String,
    pub block_reason: Option<String>,
    pub read_filter_triggered: bool,
    pub quarantined_count: usize,
    pub at: DateTime<Utc>,
    /// Optional matched policy id (kept out of `extra` so callers can index it).
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Value::is_null", default)]
    pub extra: Value,
}

#[async_trait]
pub trait ActionStream: Send + Sync + 'static {
    async fn publish(&self, event: ActionEvent);
}

#[derive(Default)]
#[allow(dead_code)] // kept for tests / future plain-logging deployments
pub struct LoggingStream;

#[async_trait]
impl ActionStream for LoggingStream {
    async fn publish(&self, event: ActionEvent) {
        info!(target: "proxilion.action_stream", event = ?event, "action");
    }
}

/// Persist every event to `action_events` and fan it out to live subscribers
/// (the admin UI's SSE endpoint and any future NATS bridge).
#[derive(Clone)]
pub struct BroadcastingActionStream {
    db: PgPool,
    tx: broadcast::Sender<Arc<ActionEvent>>,
}

impl BroadcastingActionStream {
    pub fn new(db: PgPool) -> Self {
        // 256-event ring buffer for slow consumers; if a subscriber lags more
        // than that, they get `RecvError::Lagged` and re-sync via the
        // /api/v1/actions/recent endpoint.
        let (tx, _rx) = broadcast::channel(256);
        Self { db, tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<ActionEvent>> {
        self.tx.subscribe()
    }
}

#[async_trait]
impl ActionStream for BroadcastingActionStream {
    async fn publish(&self, event: ActionEvent) {
        // Persist first; only after the durable record exists do we fan out.
        // Live consumers reflect ground truth.
        let res = sqlx::query(
            r#"
            INSERT INTO action_events
                (request_id, session_id, p_0, leaf_pca_id, vendor, action, method, path,
                 status, decision, block_reason, read_filter_triggered, quarantined_count,
                 policy_id, extra, at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                    $9, $10, $11, $12, $13, $14, $15, $16)
            "#,
        )
        .bind(event.request_id)
        .bind(event.agent_session_id)
        .bind(&event.p_0)
        .bind(event.leaf_pca_id)
        .bind(&event.vendor)
        .bind(&event.action)
        .bind(&event.method)
        .bind(&event.path)
        .bind(event.status as i32)
        .bind(&event.decision)
        .bind(event.block_reason.as_deref())
        .bind(event.read_filter_triggered)
        .bind(event.quarantined_count as i32)
        .bind(event.policy_id.as_deref())
        .bind(&event.extra)
        .bind(event.at)
        .execute(&self.db)
        .await;
        if let Err(e) = &res {
            warn!(error = %e, "failed to persist action_event; broadcasting anyway");
            metrics::counter!(
                "proxilion_action_events_persist_failures_total",
                "reason" => "db_error"
            )
            .increment(1);
        } else {
            metrics::counter!(
                "proxilion_action_events_persisted_total",
                "decision" => event.decision.clone()
            )
            .increment(1);
        }

        // Best-effort broadcast. `send` only errors when there are zero
        // subscribers, which is fine; we still got the event into postgres.
        let _ = self.tx.send(Arc::new(event));
    }
}
