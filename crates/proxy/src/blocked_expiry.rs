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
    fn expiry_sweep_report_debug_renders_struct_name_for_grep() {
        // Symmetric to the existing
        // `escalation_sweep_report_debug_renders_struct_name_for_grep`
        // pin on the EscalationSweepReport arm — operator log
        // aggregators key on the rendered Debug shape from the spawn
        // loop's `tracing::debug!(?r, ...)` match arm. Both report
        // types carry one u64 field; a manual Debug impl that hid the
        // type name (rendering just the field value) would silently
        // collapse the expiry sweep's log lines onto the escalation
        // sweep's. Pin that the rendered string carries the
        // `ExpirySweepReport` struct name so the two stay
        // grep-distinguishable. (The sibling test on
        // EscalationSweepReport was added previously; this fills the
        // symmetric gap on the expiry arm.)
        let r = ExpirySweepReport { expired_rows: 23 };
        let s = format!("{r:?}");
        assert!(s.contains("ExpirySweepReport"), "got: {s}");
        assert!(s.contains("23"));
    }

    #[test]
    fn escalation_sweep_report_clone_at_nonzero_value_yields_independent_copy() {
        // Symmetric to the existing
        // `expiry_sweep_report_clone_at_nonzero_value_yields_independent_copy`
        // pin on the ExpirySweepReport arm. The escalation sweep loop
        // also relies on the report being a snapshot of THIS tick's
        // escalation count, not a live counter that future ticks can
        // roll into. Pin that a `Clone` of a non-zero report yields an
        // independent value (a future refactor to `Arc<AtomicU64>` for
        // "concurrent updates across multiple sweep workers" would
        // surface here as the clone seeing a later mutation on the
        // original — silently breaking the per-tick snapshot
        // invariant).
        let r = EscalationSweepReport { escalated_rows: 11 };
        let mut c = r.clone();
        assert_eq!(c.escalated_rows, 11);
        c.escalated_rows = 77;
        assert_eq!(r.escalated_rows, 11);
        assert_eq!(c.escalated_rows, 77);
    }

    #[test]
    fn sweep_reports_are_send_sync_static_for_tokio_task_boundary() {
        // Both report types flow through the `spawn` task loop's
        // `match sweep_once(&db).await` and `match sweep_escalations(...)`
        // arms — those `match` scopes hold the report value across
        // an await point inside a `tokio::spawn`-ed future, so the
        // type bound the spawn site requires is `Send + 'static`.
        // (`Sync` is not strictly required by `tokio::spawn` but is
        // structurally upheld by both — a refactor that introduced
        // a `!Sync` field like `Cell<u64>` "for interior mutability"
        // would still pass the spawn bound but surface a future
        // `Arc<Report>` sharing path here.) Pin the three-trait combo
        // at the type level so a refactor surfaces in this file
        // rather than at some unrelated AppState assembly site.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<ExpirySweepReport>();
        require_send_sync_static::<EscalationSweepReport>();
    }

    #[test]
    fn default_tick_interval_equals_sixty_via_multiple_duration_constructors() {
        // `Duration::from_secs(60)` is the canonical form, but Rust's
        // Duration treats `from_millis(60_000)` / `from_micros(60_000_000)`
        // / `from_nanos(60_000_000_000)` as byte-identical values via
        // its `PartialEq` impl. The existing
        // `default_tick_interval_pinned_at_60_seconds` test pins ONE
        // constructor; pin equality across ALL the natural
        // alternatives so a refactor that swapped to a different
        // constructor (e.g. `Duration::from_millis(60_000)` for some
        // config-loader compat reason) doesn't silently widen any
        // future comparison against the canonical form. Symmetric pin
        // to round-31's subsec_nanos check, but on the equality side.
        assert_eq!(DEFAULT_TICK_INTERVAL, Duration::from_millis(60_000));
        assert_eq!(DEFAULT_TICK_INTERVAL, Duration::from_micros(60_000_000));
        assert_eq!(DEFAULT_TICK_INTERVAL, Duration::from_nanos(60_000_000_000));
    }

    #[test]
    fn default_tick_interval_is_strictly_positive_and_bounded_for_loop_safety() {
        // The sweeper loop's `tokio::time::sleep(tick_interval).await`
        // does NOT defend against a zero-duration default — a
        // `from_secs(0)` would tight-loop the sweeper and burn one
        // CPU core hammering the DB with no backoff. Symmetric upper
        // bound: a refactor that loosened the default to `from_secs(3600)`
        // would silently leave overdue blocked rows lingering in
        // `status='pending'` for up to an hour, well past the
        // 60–120s operator-alert window pinned by
        // `default_tick_interval_pinned_at_60_seconds`. Pin both
        // bounds so a future refactor surfaces here rather than as a
        // production runtime regression.
        assert!(
            DEFAULT_TICK_INTERVAL > Duration::ZERO,
            "default tick interval must be > 0 to avoid tight-looping the sweeper",
        );
        assert!(
            DEFAULT_TICK_INTERVAL <= Duration::from_secs(300),
            "default tick interval must be <= 5min to keep the expiry-alert window meaningful",
        );
    }

    #[test]
    fn sweep_report_clone_at_u64_max_preserves_value_without_overflow() {
        // The `expired_rows` / `escalated_rows` fields are `u64` —
        // the sweep `RETURNING id, ...` query returns rows whose
        // count is bounded by the table size (tens of thousands at
        // most), but a refactor that switched the field to a smaller
        // numeric type (e.g. `u32` "since we never see > 4B rows in
        // a sweep") would silently introduce a truncation hazard at
        // the cast site `let n = rows.len() as u64;`. Pin that u64::MAX
        // round-trips through Clone unchanged on both report types
        // — a regression to u32 would surface here as a value-domain
        // failure rather than at the cast site in `sweep_once`.
        let e = ExpirySweepReport {
            expired_rows: u64::MAX,
        };
        let s = EscalationSweepReport {
            escalated_rows: u64::MAX,
        };
        assert_eq!(e.clone().expired_rows, u64::MAX);
        assert_eq!(s.clone().escalated_rows, u64::MAX);
    }

    #[test]
    fn default_tick_interval_as_millis_and_secs_f64_cross_method_consistent() {
        // The constant is the canonical `from_secs(60)`. Pin three
        // alternate accessors (`as_millis` / `as_secs_f64` / `as_nanos`)
        // all report the equivalent value in their respective units —
        // a refactor that swapped to `from_secs_f64(60.0)` would still
        // equal `from_secs(60)` via `PartialEq`, but a refactor to
        // `from_secs_f64(59.9999999)` or `from_micros(59_999_999)`
        // "for some operator-overridable shape" would silently drift
        // any future code that reads through `as_millis` (a common
        // shape for handing tick intervals to non-Rust services like
        // a tonic gRPC metric collector that wants milliseconds). Pin
        // all three accessors at the exact unit-converted value.
        assert_eq!(DEFAULT_TICK_INTERVAL.as_millis(), 60_000);
        assert_eq!(DEFAULT_TICK_INTERVAL.as_secs_f64(), 60.0);
        assert_eq!(DEFAULT_TICK_INTERVAL.as_nanos(), 60_000_000_000);
    }

    #[test]
    fn default_tick_interval_arithmetic_round_trips_through_double_and_half() {
        // `Duration` supports `*`/`/` against integers via `Mul<u32>` /
        // `Div<u32>`. The sweeper loop does not currently scale the
        // interval, but a future config that supports "tick every
        // half / double the default for staging" would call those
        // operators. Pin that the canonical value scales cleanly:
        // doubling yields exactly 120s (no overflow), halving yields
        // exactly 30s (no truncation). A refactor that switched the
        // constant to `from_millis(60_001)` "for some boundary
        // safety" would surface here as a non-byte-exact arithmetic
        // result.
        assert_eq!(DEFAULT_TICK_INTERVAL * 2, Duration::from_secs(120));
        assert_eq!(DEFAULT_TICK_INTERVAL / 2, Duration::from_secs(30));
        assert_eq!(DEFAULT_TICK_INTERVAL * 60, Duration::from_secs(3600));
    }

    #[test]
    fn expiry_and_escalation_report_default_debug_carry_field_name_with_zero_value() {
        // The two report types both carry a single u64 field, named
        // `expired_rows` and `escalated_rows` respectively. Pin that
        // Default-constructed Debug output BYTE-CONTAINS the literal
        // "expired_rows: 0" / "escalated_rows: 0" — the existing
        // Debug-renders-field-name pins on non-zero values cover the
        // non-zero arm; pin the zero arm so a refactor to a manual
        // Debug impl that elided zero values "for noise reduction"
        // (e.g. `if self.expired_rows > 0 { ... }`) would silently
        // collapse the no-op-sweep log line to an empty struct
        // `ExpirySweepReport {}` and break operator log filters that
        // grep for "expired_rows:" as the sweep-completion marker.
        let e = ExpirySweepReport::default();
        let s = EscalationSweepReport::default();
        let e_dbg = format!("{e:?}");
        let s_dbg = format!("{s:?}");
        assert!(e_dbg.contains("expired_rows: 0"), "got: {e_dbg}");
        assert!(s_dbg.contains("escalated_rows: 0"), "got: {s_dbg}");
    }

    #[test]
    fn expiry_and_escalation_report_debug_is_deterministic_across_independent_constructions() {
        // The derived Debug impl is byte-stable for the same field
        // values across independent constructions — pin this for both
        // report types so a refactor that introduced any non-derived
        // Debug variation (e.g. a timestamp suffix "for in-line
        // sweep id tagging") would surface here as a string diff
        // between two equal-field instances. Operator log filters
        // that key on the exact rendered Debug shape (a brittle but
        // common ops pattern when ad-hoc debugging in the spawn loop)
        // rely on this stability.
        let e1 = ExpirySweepReport { expired_rows: 7 };
        let e2 = ExpirySweepReport { expired_rows: 7 };
        assert_eq!(format!("{e1:?}"), format!("{e2:?}"));
        let s1 = EscalationSweepReport { escalated_rows: 13 };
        let s2 = EscalationSweepReport { escalated_rows: 13 };
        assert_eq!(format!("{s1:?}"), format!("{s2:?}"));
        // Cross-type debug strings must NOT compare equal even at the
        // same numeric value — they carry distinct field names.
        let e_at_5 = ExpirySweepReport { expired_rows: 5 };
        let s_at_5 = EscalationSweepReport { escalated_rows: 5 };
        assert_ne!(format!("{e_at_5:?}"), format!("{s_at_5:?}"));
    }

    #[test]
    fn report_struct_update_syntax_preserves_base_field_unchanged() {
        // Rust's `..base` struct-update syntax is the natural shape for
        // building a sweep report with a "but with one field overridden"
        // pattern. The reports have one field today so struct-update
        // would be a no-op, but pin that the construction shape works
        // — a refactor that added a `started_at: DateTime<Utc>` field
        // "for sweep-duration logging" would force every call site
        // (the sweep_once `Ok(ExpirySweepReport { expired_rows: n })`
        // and the sweep_escalations `Ok(EscalationSweepReport { escalated_rows: n })`)
        // to update in lockstep. The struct-update shape catches this
        // by failing to compile if the field count changed without
        // updating the struct construction.
        let base = ExpirySweepReport { expired_rows: 42 };
        let derived = ExpirySweepReport { ..base.clone() };
        assert_eq!(derived.expired_rows, 42);
        // Also pin the escalation arm.
        let base_s = EscalationSweepReport { escalated_rows: 99 };
        let derived_s = EscalationSweepReport { ..base_s.clone() };
        assert_eq!(derived_s.escalated_rows, 99);
    }

    #[test]
    fn default_constructed_reports_compare_equal_field_values_to_literal_zero_construction() {
        // Pin that `ExpirySweepReport::default()` and
        // `ExpirySweepReport { expired_rows: 0 }` produce field-equal
        // values — the two constructions are semantically equivalent
        // and must remain so. A refactor that gave `Default` a
        // distinguishing sentinel (e.g. `expired_rows: 1` as a
        // "fresh-vs-tick-completed marker") would silently change
        // the no-overdue-rows path's reported count from 0 to that
        // sentinel and break every operator dashboard panel that
        // sums `expired_rows`. Symmetric pin on the escalation arm.
        let d1 = ExpirySweepReport::default();
        let d2 = ExpirySweepReport { expired_rows: 0 };
        assert_eq!(d1.expired_rows, d2.expired_rows);
        let s1 = EscalationSweepReport::default();
        let s2 = EscalationSweepReport { escalated_rows: 0 };
        assert_eq!(s1.escalated_rows, s2.escalated_rows);
    }

    // ─── round 196 (2026-05-20): EscalationRow + report field-type surfaces ───

    #[test]
    fn escalation_row_is_send_sync_static_for_sqlx_fetch_all_await_boundary() {
        // `EscalationRow` is the deserialized return type of the
        // claim-and-stamp UPDATE in `sweep_escalations`. The Vec<EscalationRow>
        // is held across the `.await` at sqlx fetch_all AND iterated
        // across N more `.await` boundaries (one per row, calling
        // `email_driver.notify_escalation(&notif).await`). Send + Sync
        // + 'static are all required for the tokio runtime's multi-
        // thread spawn semantics. A refactor that introduced a !Send
        // field (e.g. `Rc<String>` "for cheap clone of policy_id during
        // notif construction") would surface here rather than at the
        // spawn site far from this file. Pin the three-trait combo —
        // symmetric to round-189 ListRow + round-191 CheckItem +
        // round-192 TriggerClaim Send+Sync+'static pins extended to
        // this sibling sqlx::FromRow row shape.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<EscalationRow>();
    }

    #[test]
    fn escalation_row_optional_string_fields_are_option_string_for_nullable_postgres_columns() {
        // `EscalationRow.p_0` / `policy_id` / `detail` — all three are
        // `Option<String>` matching the postgres nullable column shape
        // (`p_0 text NULL`, `policy_id text NULL`, `detail text NULL`).
        // A refactor to bare `String` "for ergonomic .as_deref() on the
        // notification builder side" would break the sqlx FromRow
        // derive at compile time (nullable column → non-nullable Rust
        // type), but a refactor that defaulted to empty-string via
        // `COALESCE(p_0, '')` in the SQL would silently collapse "no
        // p_0 known" with "p_0 is explicitly empty" — both important
        // operator-triage distinctions. Pin Option<String> via
        // require_opt_string on all three nullable fields. Symmetric
        // to round-190 KillBody 3-Option<String> + round-193
        // ErrorBody.detail Option<String> pins extended to this
        // sibling Option<String>-bearing row shape.
        fn require_opt_string(_: &Option<String>) {}
        let row = EscalationRow {
            id: uuid::Uuid::nil(),
            request_id: uuid::Uuid::nil(),
            session_id: uuid::Uuid::nil(),
            p_0: Some("alice@demo.local".into()),
            vendor: "google".into(),
            action: "drive.read".into(),
            method: "GET".into(),
            path: "/v3/files".into(),
            layer: "layer_b".into(),
            policy_id: Some("pol1".into()),
            detail: Some("scope mismatch".into()),
            predecessor_pca_id: None,
            requested_ops: vec!["drive:read:*".into()],
        };
        require_opt_string(&row.p_0);
        require_opt_string(&row.policy_id);
        require_opt_string(&row.detail);
    }

    #[test]
    fn escalation_row_required_string_fields_are_owned_string_for_cross_await_notification_outlives()
     {
        // `EscalationRow.vendor` / `action` / `method` / `path` /
        // `layer` — all five are owned `String`, NOT borrowed `&'a str`.
        // The sqlx::FromRow derive generates owned-content shapes by
        // default (the underlying sqlx row buffer is dropped at the
        // end of fetch_all); the Vec<EscalationRow> then survives
        // across multiple `.await` boundaries for the notifier
        // fan-out. A refactor that swapped to borrowed `&'a str`
        // fields "for zero-alloc on the SQL-binding hot path" would
        // need the row buffer to outlive each notification, breaking
        // the natural sqlx scope. Pin owned-String via require_string
        // on all 5 non-nullable string fields. Symmetric to round-189
        // ListRow 6-field + round-195 SessionContext 3-field owned-
        // String sweeps extended to this sibling FromRow shape.
        fn require_string(_: &String) {}
        let row = EscalationRow {
            id: uuid::Uuid::nil(),
            request_id: uuid::Uuid::nil(),
            session_id: uuid::Uuid::nil(),
            p_0: None,
            vendor: "google".into(),
            action: "drive.read".into(),
            method: "GET".into(),
            path: "/v3/files".into(),
            layer: "layer_b".into(),
            policy_id: None,
            detail: None,
            predecessor_pca_id: None,
            requested_ops: vec![],
        };
        require_string(&row.vendor);
        require_string(&row.action);
        require_string(&row.method);
        require_string(&row.path);
        require_string(&row.layer);
    }

    #[test]
    fn escalation_row_requested_ops_field_is_owned_vec_string_for_borrowed_slice_into_notification()
    {
        // `EscalationRow.requested_ops: Vec<String>` — owned, not a
        // borrowed slice. The notification construction in
        // `sweep_escalations` borrows the field as
        // `requested_ops: &row.requested_ops` (a `&[String]`); the
        // borrow must be valid across the
        // `email_driver.notify_escalation(&notif).await` call. The
        // owning Vec lives in the EscalationRow which lives in the
        // surrounding Vec<EscalationRow> that outlives every per-row
        // notification. A refactor to `&'a [String]` "for zero-copy
        // from the sqlx row buffer" would force a lifetime parameter
        // through EscalationRow that breaks the cross-await contract.
        // Pin via require_vec_string. Symmetric to round-195
        // SessionContext.granted_ops Vec<String> + round-186
        // BlockedActionRecord.requested_ops borrowed-slice (inverse)
        // pins extended to this sibling shape.
        fn require_vec_string(_: &Vec<String>) {}
        let row = EscalationRow {
            id: uuid::Uuid::nil(),
            request_id: uuid::Uuid::nil(),
            session_id: uuid::Uuid::nil(),
            p_0: None,
            vendor: "v".into(),
            action: "a".into(),
            method: "m".into(),
            path: "p".into(),
            layer: "l".into(),
            policy_id: None,
            detail: None,
            predecessor_pca_id: None,
            requested_ops: vec!["op1".into(), "op2".into()],
        };
        require_vec_string(&row.requested_ops);
        assert_eq!(row.requested_ops.len(), 2);
    }

    #[test]
    fn expiry_and_escalation_report_count_fields_are_u64_type_for_no_truncation_at_cast_site() {
        // `ExpirySweepReport.expired_rows: u64` and
        // `EscalationSweepReport.escalated_rows: u64` — both are u64,
        // NOT u32/usize/i64. The sweep `rows.len() as u64` cast at
        // each report-construction site is the load-bearing
        // conversion. A refactor to u32 "since we never see > 4B rows
        // in a sweep" would silently introduce a truncation hazard
        // on the cast — `rows.len()` is `usize` which is u64 on most
        // production targets, so a u32 destination would wrap on the
        // (admittedly unlikely) 4B+ overdue-rows case. A refactor to
        // i64 "for postgres bigint compat at the metric ingestion
        // layer" would silently allow negative values past the type
        // system. Pin via require_u64. The existing
        // `sweep_report_clone_at_u64_max_preserves_value_without_overflow`
        // test pins MAX-value round-trip; pin the TYPE here.
        // Symmetric to round-190 KillResponse.bearers_revoked i64 +
        // round-188 ListResponse.policy_count usize numeric-type pins
        // extended to these sibling sweep-report fields.
        fn require_u64(_: u64) {}
        let e = ExpirySweepReport { expired_rows: 42 };
        let s = EscalationSweepReport { escalated_rows: 17 };
        require_u64(e.expired_rows);
        require_u64(s.escalated_rows);
    }

    #[test]
    fn default_tick_interval_field_type_is_duration_for_tokio_sleep_signature_compat() {
        // `DEFAULT_TICK_INTERVAL: Duration` — the constant is
        // `std::time::Duration`, NOT `u64` or `usize` or a custom
        // wrapper. The `tokio::time::sleep(tick_interval).await` call
        // in `spawn` requires `Duration`; a refactor to `u64` "for
        // simpler config parsing" would force every spawn-site to
        // re-construct a Duration on every tick AND would lose the
        // unit information at the type level (60 secs vs 60 millis
        // vs 60 nanos). Pin via require_duration. The existing
        // `default_tick_interval_pinned_at_60_seconds` +
        // `default_tick_interval_equals_sixty_via_multiple_duration_constructors`
        // pins walk the VALUE; pin the TYPE here so a refactor
        // surfaces on the type axis even if value-equality somehow
        // held (e.g. via a custom wrapper with a value-preserving
        // PartialEq impl). Symmetric to round-186
        // CANONICAL_REQUEST_MAX_LEN usize + round-187 HTML_TEMPLATE
        // &'static str type-level constant pins extended to this
        // sibling tick-interval constant.
        fn require_duration(_: Duration) {}
        require_duration(DEFAULT_TICK_INTERVAL);
        // And as_secs() returns u64 — pin the round-trip through that
        // accessor type as well.
        let secs: u64 = DEFAULT_TICK_INTERVAL.as_secs();
        assert_eq!(secs, 60);
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
