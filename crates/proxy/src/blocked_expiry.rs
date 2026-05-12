//! Proactive expiry sweeper for `blocked_actions` (ui-less-surfaces.md §5.7).
//!
//! Without this loop, pending rows past their `expires_at` only flip to
//! `expired` when someone queries `/api/v1/blocked` or attempts an
//! approve/reject. Operationally that's fine for correctness — the row is
//! never visibly "approvable" once expired — but it leaves the audit log
//! with rows that *look* pending for hours after their actual deadline.
//!
//! The sweeper runs every `tick_interval` (default 60s), flips overdue
//! rows in a single SQL UPDATE, and emits one structured log line + a
//! `proxilion_blocked_expired_total{policy_id}` increment per row. No
//! notifier fan-out — the agent already received its 403/202 timeout
//! response when the block fired, so an "expired" message would just
//! restate that fact.

use std::time::Duration;

use sqlx::PgPool;
use tracing::{debug, info, warn};

pub const DEFAULT_TICK_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Default)]
pub struct ExpirySweepReport {
    pub expired_rows: u64,
}

/// Run one sweep. Idempotent: a no-op when no rows are overdue. The
/// per-row metric label is `policy_id` so a Grafana panel can show
/// "which policies are timing out".
pub async fn sweep_once(db: &PgPool) -> Result<ExpirySweepReport, sqlx::Error> {
    let rows: Vec<(uuid::Uuid, Option<String>, String, String)> = sqlx::query_as(
        "UPDATE blocked_actions
            SET status = 'expired',
                resolved_at = now()
          WHERE status = 'pending'
            AND expires_at < now()
        RETURNING id, policy_id, vendor, action",
    )
    .fetch_all(db)
    .await?;

    let n = rows.len() as u64;

    // Update the `proxilion_overrides_pending` gauge so Grafana doesn't
    // need a polling client of its own. Cheap aggregate — the
    // blocked_actions table is small (rarely > thousands) and `status`
    // is indexed.
    let pending: (i64,) =
        sqlx::query_as("SELECT count(*) FROM blocked_actions WHERE status = 'pending'")
            .fetch_one(db)
            .await?;
    metrics::gauge!("proxilion_overrides_pending").set(pending.0 as f64);

    for (id, policy_id, vendor, action) in &rows {
        info!(
            blocked_id = %id,
            policy_id = policy_id.as_deref().unwrap_or("(none)"),
            vendor,
            action,
            "blocked action expired (no decision before TTL)"
        );
        metrics::counter!(
            "proxilion_blocked_expired_total",
            "policy_id" => policy_id.clone().unwrap_or_else(|| "(none)".to_string())
        )
        .increment(1);
        // overrides_resolved_total{outcome="expired", channel="sweeper"}
        // keeps the resolution accounting consistent with the approve /
        // reject paths so a single PromQL sums them.
        metrics::counter!(
            "proxilion_overrides_resolved_total",
            "outcome" => "expired",
            "channel" => "sweeper"
        )
        .increment(1);
    }
    Ok(ExpirySweepReport { expired_rows: n })
}

/// Background task. Spawned by `server::run` when a DB pool is available.
/// Errors are logged but never panic — a transient DB blip should not
/// kill the loop.
pub async fn spawn(db: PgPool, tick_interval: Duration) {
    info!(
        interval_seconds = tick_interval.as_secs(),
        "blocked-action expiry sweeper started"
    );
    loop {
        tokio::time::sleep(tick_interval).await;
        match sweep_once(&db).await {
            Ok(r) if r.expired_rows > 0 => {
                debug!(expired = r.expired_rows, "expiry sweep flipped rows");
            }
            Ok(_) => {}
            Err(e) => {
                warn!(error = %e, "expiry sweep failed; will retry next tick");
                metrics::counter!(
                    "proxilion_blocked_expiry_sweep_failures_total"
                )
                .increment(1);
            }
        }
    }
}
