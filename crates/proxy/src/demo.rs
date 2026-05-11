//! Demo mode — synthetic seed + slow synthetic-action ticker.
//!
//! When `PROXILION_DEMO=1` (or the flag is auto-detected because the DB is
//! fresh), the proxy populates `action_events` with a handful of historical
//! rows and starts a background task that emits one synthetic event every
//! few seconds. This gives the admin UI something to render the first time
//! an operator opens it, without requiring them to wire a real agent.
//!
//! All synthetic events have `policy_id = "demo"` so they're trivial to
//! exclude from real audit queries.

use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use rand::Rng;
use rand::seq::SliceRandom;
use sqlx::PgPool;
use tokio::time::sleep;
use tracing::{info, warn};
use uuid::Uuid;

use crate::adapters::action_stream::{ActionEvent, ActionStream, BroadcastingActionStream};

/// True when demo mode should run.
///
///   * `PROXILION_DEMO=1`  → force on
///   * `PROXILION_DEMO=0`  → force off
///   * unset               → on iff the `action_events` table is empty
pub async fn should_run(db: &PgPool) -> bool {
    match std::env::var("PROXILION_DEMO").as_deref() {
        Ok("0") | Ok("false") => return false,
        Ok("1") | Ok("true") => return true,
        _ => {}
    }
    match sqlx::query_scalar::<_, i64>("SELECT count(*) FROM action_events")
        .fetch_one(db)
        .await
    {
        Ok(n) => n == 0,
        Err(e) => {
            warn!(error = %e, "demo-mode probe failed; defaulting off");
            false
        }
    }
}

/// Seed `action_events` with a small history and start a background ticker.
///
/// Returns the join handle so callers can keep it alive for the program's
/// lifetime; we never need to abort it explicitly because tokio's runtime
/// shutdown will drop it cleanly.
pub fn start(stream: BroadcastingActionStream) -> tokio::task::JoinHandle<()> {
    info!("PROXILION_DEMO active — seeding synthetic action events");
    tokio::spawn(async move {
        seed_history(&stream).await;
        ticker(&stream).await;
    })
}

const USERS: &[&str] = &[
    "user:alice@demo.local",
    "user:bob@demo.local",
    "user:carol@demo.local",
];

const SCENARIOS: &[Scenario] = &[
    Scenario {
        vendor: "google",
        action: "drive.files.get",
        method: "GET",
        path_template: "/drive/v3/files/demo-file-",
        decision: "allow",
        status: 200,
        policy: "drive-injection-filter",
        read_filter_triggered: true,
        quarantined_count: 1,
        block_reason: None,
    },
    Scenario {
        vendor: "google",
        action: "drive.files.list",
        method: "GET",
        path_template: "/drive/v3/files",
        decision: "allow",
        status: 200,
        policy: "drive-injection-filter",
        read_filter_triggered: false,
        quarantined_count: 0,
        block_reason: None,
    },
    Scenario {
        vendor: "google",
        action: "gmail.messages.send",
        method: "POST",
        path_template: "/gmail/v1/users/me/messages/send",
        decision: "block",
        status: 403,
        policy: "gmail-external-send-gate",
        read_filter_triggered: false,
        quarantined_count: 0,
        block_reason: Some("to_domain not in customer_domain"),
    },
    Scenario {
        vendor: "google",
        action: "drive.files.get",
        method: "GET",
        path_template: "/drive/v3/files/finance-",
        decision: "require_confirmation",
        status: 428,
        policy: "high-risk-financial-read",
        read_filter_triggered: false,
        quarantined_count: 0,
        block_reason: Some("requires user confirmation"),
    },
];

struct Scenario {
    vendor: &'static str,
    action: &'static str,
    method: &'static str,
    path_template: &'static str,
    decision: &'static str,
    status: u16,
    policy: &'static str,
    read_filter_triggered: bool,
    quarantined_count: usize,
    block_reason: Option<&'static str>,
}

fn synth_event(scenario: &Scenario, now: chrono::DateTime<Utc>) -> ActionEvent {
    let mut rng = rand::thread_rng();
    let user = USERS.choose(&mut rng).copied().unwrap_or(USERS[0]);
    let suffix: String = (0..6)
        .map(|_| {
            let c = rng.gen_range(0..36u8);
            if c < 10 {
                (b'0' + c) as char
            } else {
                (b'a' + (c - 10)) as char
            }
        })
        .collect();
    let path = if scenario.path_template.ends_with('/') || scenario.path_template.ends_with('s') {
        scenario.path_template.to_string()
    } else {
        format!("{}{}", scenario.path_template, suffix)
    };
    ActionEvent {
        request_id: Uuid::new_v4(),
        agent_session_id: Uuid::new_v4(),
        p_0: user.to_string(),
        leaf_pca_id: Some(Uuid::new_v4()),
        vendor: scenario.vendor.to_string(),
        action: scenario.action.to_string(),
        method: scenario.method.to_string(),
        path,
        status: scenario.status,
        decision: scenario.decision.to_string(),
        block_reason: scenario.block_reason.map(str::to_string),
        read_filter_triggered: scenario.read_filter_triggered,
        quarantined_count: scenario.quarantined_count,
        at: now,
        policy_id: Some(scenario.policy.to_string()),
        extra: serde_json::json!({ "demo": true }),
    }
}

async fn seed_history(stream: &BroadcastingActionStream) {
    // 20 historical rows spread over the last 2 hours.
    let now = Utc::now();
    for i in 0..20 {
        let scenario = &SCENARIOS[i % SCENARIOS.len()];
        let at = now - ChronoDuration::minutes((20 - i as i64) * 6);
        let ev = synth_event(scenario, at);
        stream.publish(ev).await;
    }
}

async fn ticker(stream: &BroadcastingActionStream) {
    loop {
        // Random 6–12s between synthetic events. ThreadRng isn't Send across
        // await boundaries, so re-acquire it inside a tight scope each tick.
        let (secs, scenario) = {
            let mut rng = rand::thread_rng();
            let secs = rng.gen_range(6..=12);
            let scenario = SCENARIOS.choose(&mut rng).copied();
            (secs, scenario)
        };
        sleep(Duration::from_secs(secs)).await;
        let Some(scenario) = scenario else { continue };
        let ev = synth_event(&scenario, Utc::now());
        stream.publish(ev).await;
    }
}

// `SCENARIOS.choose` needs Copy on the elements; we already have it
// implicitly via `Copy` on all fields, but Scenario doesn't derive it. Add.
impl Copy for Scenario {}
impl Clone for Scenario {
    fn clone(&self) -> Self {
        *self
    }
}
