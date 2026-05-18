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

use crate::notifier::{BlockedNotification, EmailHandle};

pub const DEFAULT_TICK_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Default)]
pub struct ExpirySweepReport {
    pub expired_rows: u64,
}

#[derive(Debug, Clone, Default)]
pub struct EscalationSweepReport {
    pub escalated_rows: u64,
}

/// Run one sweep. Idempotent: a no-op when no rows are overdue. The
/// per-row metric label is `policy_id` so a Grafana panel can show
/// "which policies are timing out".
pub async fn sweep_once(db: &PgPool) -> Result<ExpirySweepReport, sqlx::Error> {
    let rows: Vec<(
        uuid::Uuid,
        Option<String>,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "UPDATE blocked_actions
                SET status = 'expired',
                    resolved_at = now()
              WHERE status = 'pending'
                AND expires_at < now()
            RETURNING id, policy_id, vendor, action, at",
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

    for (id, policy_id, vendor, action, blocked_at) in &rows {
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
        // spec.md §3.2 — override latency on the expired path matches the
        // TTL by construction, but record it so a single histogram covers
        // all three resolution outcomes (approved / rejected / expired).
        let latency = (chrono::Utc::now() - *blocked_at).num_milliseconds().max(0) as f64 / 1000.0;
        metrics::histogram!(
            "proxilion_override_latency_seconds",
            "outcome" => "expired",
        )
        .record(latency);
    }
    Ok(ExpirySweepReport { expired_rows: n })
}

/// Find rows whose escalation deadline has passed without a decision
/// and re-fire the email notifier (ui-less-surfaces.md §5.7 dev 2).
/// Idempotent: stamps `escalated_at = now()` so each row escalates at
/// most once. No-op when the email driver is None (e.g. only webhook /
/// Slack configured) — escalation is intentionally email-only in v1,
/// since the Slack message is in-channel and a notification-channel
/// reminder lives on the same shape as the email reminder ("REMINDER:"
/// subject prefix). Slack thread reminders (§5.7 dev 1) ride on the
/// separate thread_ts plumbing.
pub async fn sweep_escalations(
    db: &PgPool,
    email: &EmailHandle,
) -> Result<EscalationSweepReport, sqlx::Error> {
    let Some(email_driver) = email.current() else {
        return Ok(EscalationSweepReport::default());
    };
    // Claim rows in one SQL — stamp `escalated_at` immediately so two
    // concurrent sweeps (different replicas) can't double-fire. RETURNING
    // surfaces the fields the notifier envelope needs.
    let rows: Vec<EscalationRow> = sqlx::query_as(
        "UPDATE blocked_actions
            SET escalated_at = now()
          WHERE id IN (
                SELECT id FROM blocked_actions
                 WHERE status = 'pending'
                   AND escalation_at IS NOT NULL
                   AND escalation_at < now()
                   AND escalated_at IS NULL
                 FOR UPDATE SKIP LOCKED
          )
        RETURNING id, request_id, session_id, p_0, vendor, action, method,
                  path, layer, policy_id, detail, predecessor_pca_id,
                  COALESCE(requested_ops, ARRAY[]::text[]) AS requested_ops",
    )
    .fetch_all(db)
    .await?;

    let n = rows.len() as u64;
    for row in &rows {
        let proxy_url = email_driver.proxy_public_url().to_string();
        let approve_url = format!("{proxy_url}/api/v1/blocked/{}/approve", row.id);
        let reject_url = format!("{proxy_url}/api/v1/blocked/{}/reject", row.id);
        let notif = BlockedNotification {
            schema: BlockedNotification::SCHEMA,
            blocked_id: row.id,
            request_id: row.request_id,
            session_id: row.session_id,
            p_0: row.p_0.as_deref(),
            vendor: &row.vendor,
            action: &row.action,
            method: &row.method,
            path: &row.path,
            layer: &row.layer,
            policy_id: row.policy_id.as_deref(),
            detail: row.detail.as_deref(),
            predecessor_pca_id: row.predecessor_pca_id,
            requested_ops: &row.requested_ops,
            approve_url,
            reject_url,
        };
        email_driver.notify_escalation(&notif).await;
        info!(
            blocked_id = %row.id,
            policy_id = row.policy_id.as_deref().unwrap_or("(none)"),
            "blocked action escalated (no decision before escalation deadline)"
        );
        metrics::counter!(
            "proxilion_blocked_escalated_total",
            "policy_id" => row.policy_id.clone().unwrap_or_else(|| "(none)".to_string())
        )
        .increment(1);
    }
    Ok(EscalationSweepReport { escalated_rows: n })
}

#[derive(sqlx::FromRow)]
struct EscalationRow {
    id: uuid::Uuid,
    request_id: uuid::Uuid,
    session_id: uuid::Uuid,
    p_0: Option<String>,
    vendor: String,
    action: String,
    method: String,
    path: String,
    layer: String,
    policy_id: Option<String>,
    detail: Option<String>,
    predecessor_pca_id: Option<uuid::Uuid>,
    requested_ops: Vec<String>,
}

/// Background task. Spawned by `server::run` after the notifier bundle
/// is built. Errors are logged but never panic — a transient DB blip
/// should not kill the loop.
pub async fn spawn(db: PgPool, tick_interval: Duration, email: EmailHandle) {
    info!(
        interval_seconds = tick_interval.as_secs(),
        "blocked-action expiry sweeper started (with escalation)"
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
                metrics::counter!("proxilion_blocked_expiry_sweep_failures_total").increment(1);
            }
        }
        match sweep_escalations(&db, &email).await {
            Ok(r) if r.escalated_rows > 0 => {
                debug!(escalated = r.escalated_rows, "escalation sweep fired");
            }
            Ok(_) => {}
            Err(e) => {
                warn!(error = %e, "escalation sweep failed; will retry next tick");
                metrics::counter!("proxilion_blocked_escalation_sweep_failures_total").increment(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tick_interval_pinned_at_60_seconds() {
        // Operator alerts on "blocked rows that should have expired" key
        // off a 60–120s response time. A regression that loosened this
        // to 5 minutes would silently widen that window without anyone
        // noticing until a complaint. The constant is `pub const` so any
        // direct `DEFAULT_TICK_INTERVAL` import must move in lockstep.
        assert_eq!(DEFAULT_TICK_INTERVAL, Duration::from_secs(60));
    }

    #[test]
    fn expiry_sweep_report_default_is_zero_and_clone_independent() {
        // `Default + Clone + Debug` are the three traits the sweeper
        // task relies on. Default must be `0` (not some sentinel like
        // u64::MAX) so the no-overdue-rows branch can construct a
        // report without an explicit `0` literal scattered through the
        // code. Clone must yield an independent value (a future
        // refactor to `Arc<u64>` would surface here as failing the
        // mutation test below).
        let r: ExpirySweepReport = ExpirySweepReport::default();
        assert_eq!(r.expired_rows, 0);
        let mut c = r.clone();
        c.expired_rows = 42;
        // Original unaffected.
        assert_eq!(r.expired_rows, 0);
        assert_eq!(c.expired_rows, 42);
        // Debug includes the field name (operator-facing log shape).
        assert!(format!("{r:?}").contains("expired_rows"));
    }

    #[test]
    fn escalation_sweep_report_default_is_zero_and_debug_carries_field() {
        let r: EscalationSweepReport = EscalationSweepReport::default();
        assert_eq!(r.escalated_rows, 0);
        assert!(format!("{r:?}").contains("escalated_rows"));
        // Clone equivalence on the symmetric report.
        let c = r.clone();
        assert_eq!(c.escalated_rows, 0);
    }

    #[test]
    fn expiry_sweep_report_clone_at_nonzero_value_yields_independent_copy() {
        // The round-31 test pinned Clone-independence at zero; pin the
        // symmetric non-zero case so a refactor that turned the inner
        // u64 into a shared `Arc<AtomicU64>` for "concurrent updates
        // from multiple sweeps" would surface here as the clone seeing
        // a later mutation on the original. The sweep loop relies on
        // the report being a snapshot of THIS tick's flip count, not
        // a live counter that future ticks can roll into.
        let r = ExpirySweepReport { expired_rows: 17 };
        let mut c = r.clone();
        assert_eq!(c.expired_rows, 17);
        c.expired_rows = 99;
        // Original snapshot unchanged after clone mutation.
        assert_eq!(r.expired_rows, 17);
        assert_eq!(c.expired_rows, 99);
    }

    #[test]
    fn escalation_sweep_report_debug_renders_struct_name_for_grep() {
        // Operator log aggregators key on the rendered Debug shape
        // (`tracing::debug!(?r, ...)` in the spawn loop's match arm).
        // A manual Debug impl that hid the type name (e.g. rendered
        // just the field value as "17") would silently collapse the
        // expiry sweep's log lines onto the escalation sweep's, since
        // both reports carry one u64 field. Pin that the rendered
        // string carries the struct name so the two sweeps stay
        // grep-distinguishable.
        let r = EscalationSweepReport { escalated_rows: 5 };
        let s = format!("{r:?}");
        assert!(s.contains("EscalationSweepReport"), "got: {s}");
        assert!(s.contains("5"));
    }

    #[test]
    fn default_tick_interval_carries_no_subsecond_component() {
        // The `Duration::from_secs(60)` constructor pins zero subsecond
        // nanos. A regression that swapped to `Duration::from_millis(60_000)`
        // would still equal `from_secs(60)` (covered by the round-31
        // test), but a refactor that pinned to `from_secs_f64(60.5)`
        // (perhaps from a config-driven default that defaulted to 60.5
        // for some operator-overridable shape) would silently widen the
        // sweep window by half a second per tick — over a 24h run that
        // is 720 fewer ticks. Pin subsec_nanos == 0 directly.
        assert_eq!(DEFAULT_TICK_INTERVAL.subsec_nanos(), 0);
        assert_eq!(DEFAULT_TICK_INTERVAL.as_secs(), 60);
    }
}
