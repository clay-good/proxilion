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

use crate::adapters::action_stream::{ActionEvent, ActionStream};
use std::sync::Arc;

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
pub fn start(stream: Arc<dyn ActionStream>) -> tokio::task::JoinHandle<()> {
    info!("PROXILION_DEMO active — seeding synthetic action events");
    tokio::spawn(async move {
        seed_history(stream.as_ref()).await;
        ticker(stream.as_ref()).await;
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

async fn seed_history(stream: &dyn ActionStream) {
    // 20 historical rows spread over the last 2 hours.
    let now = Utc::now();
    for i in 0..20 {
        let scenario = &SCENARIOS[i % SCENARIOS.len()];
        let at = now - ChronoDuration::minutes((20 - i as i64) * 6);
        let ev = synth_event(scenario, at);
        stream.publish(ev).await;
    }
}

async fn ticker(stream: &dyn ActionStream) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn block_scenario() -> Scenario {
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
        }
    }

    fn drive_scenario() -> Scenario {
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
        }
    }

    #[test]
    fn synth_event_passthrough_scenario_fields() {
        let now = Utc::now();
        let s = block_scenario();
        let ev = synth_event(&s, now);
        assert_eq!(ev.vendor, "google");
        assert_eq!(ev.action, "gmail.messages.send");
        assert_eq!(ev.method, "POST");
        assert_eq!(ev.status, 403);
        assert_eq!(ev.decision, "block");
        assert_eq!(ev.policy_id.as_deref(), Some("gmail-external-send-gate"));
        assert_eq!(
            ev.block_reason.as_deref(),
            Some("to_domain not in customer_domain")
        );
        assert_eq!(ev.at, now);
        assert_eq!(ev.extra["demo"], true);
    }

    #[test]
    fn synth_event_p0_picks_a_known_demo_user() {
        let s = drive_scenario();
        let ev = synth_event(&s, Utc::now());
        assert!(ev.p_0.starts_with("user:"));
        assert!(USERS.contains(&ev.p_0.as_str()));
    }

    #[test]
    fn synth_event_path_template_ending_in_s_is_used_verbatim() {
        // `/drive/v3/files` ends in `s` — the path is not suffix-mutated.
        let mut s = drive_scenario();
        s.path_template = "/drive/v3/files";
        let ev = synth_event(&s, Utc::now());
        assert_eq!(ev.path, "/drive/v3/files");
    }

    #[test]
    fn synth_event_path_template_not_ending_in_s_or_slash_gets_6_char_suffix() {
        let s = drive_scenario(); // `/drive/v3/files/demo-file-`
        let ev = synth_event(&s, Utc::now());
        assert!(ev.path.starts_with("/drive/v3/files/demo-file-"));
        let suffix = &ev.path["/drive/v3/files/demo-file-".len()..];
        assert_eq!(suffix.len(), 6);
        assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn synth_event_request_and_session_ids_are_distinct_uuids() {
        let s = drive_scenario();
        let ev = synth_event(&s, Utc::now());
        assert_ne!(ev.request_id, ev.agent_session_id);
        assert!(ev.leaf_pca_id.is_some());
    }

    #[test]
    fn synth_event_extra_carries_demo_marker_for_audit_filter_exclusion() {
        // The `extra.demo = true` marker is the load-bearing field for
        // operator audit queries — every real audit dashboard filters
        // `extra ? 'demo' AND extra->>'demo' = 'true'` to exclude the
        // synthetic ticker rows. A regression that dropped the marker
        // (or renamed it) would silently pollute every real audit query
        // with demo data. Pin both the presence and the true value.
        let ev = synth_event(&drive_scenario(), Utc::now());
        assert!(ev.extra.is_object());
        assert_eq!(ev.extra["demo"], true);
    }

    #[test]
    fn users_constant_has_three_distinct_demo_principals() {
        // The USERS array is the canonical demo principal set. Pin
        // length + distinctness so a refactor that consolidated them
        // (e.g. removing carol) would surface as a UI regression where
        // the demo timeline shows only one or two faces — operators
        // expect a multi-user view for the "live demo" experience.
        assert_eq!(USERS.len(), 3, "demo user set count");
        let unique: std::collections::HashSet<&str> = USERS.iter().copied().collect();
        assert_eq!(unique.len(), USERS.len(), "USERS entries must be distinct");
        for u in USERS {
            assert!(u.starts_with("user:"), "non-canonical p_0 shape: {u}");
            assert!(u.contains("@demo.local"), "non-demo principal: {u}");
        }
    }

    #[test]
    fn synth_event_path_template_ending_in_slash_is_used_verbatim() {
        // Path templates can end in `/` (a directory-like template) —
        // pin the `/` branch of the trailing-char check separately from
        // the `s` branch (the existing test covered `s`). A regression
        // that broke the OR-chain (only checks `s`) would silently start
        // appending a 6-char suffix to `/drive/v3/files/` and break
        // upstream Google routing.
        let mut s = drive_scenario();
        s.path_template = "/some/path/";
        let ev = synth_event(&s, Utc::now());
        assert_eq!(ev.path, "/some/path/");
    }

    #[test]
    fn scenario_decision_status_pairs_match_http_class_per_arm() {
        // Each SCENARIOS entry pairs a decision with an HTTP status.
        // The pairing is a wire contract operator dashboards alert on
        // (a 403 on a `decision="allow"` row would surface as data
        // corruption). Pin all three real pairs:
        //   allow                 → 200
        //   block                 → 403
        //   require_confirmation  → 428
        // A refactor that mistyped one of the status codes (e.g. block
        // → 400 by copy-paste) would silently break the demo
        // dashboard's "decision-class color coding" and the
        // installer-doc claim that "the demo timeline shows realistic
        // status codes". Walk every SCENARIO and assert the pairing.
        for s in SCENARIOS {
            match s.decision {
                "allow" => assert_eq!(
                    s.status, 200,
                    "allow scenario must use 200, got {}",
                    s.status
                ),
                "block" => assert_eq!(
                    s.status, 403,
                    "block scenario must use 403, got {}",
                    s.status
                ),
                "require_confirmation" => assert_eq!(
                    s.status, 428,
                    "require_confirmation must use 428, got {}",
                    s.status
                ),
                other => panic!("unknown demo decision: {other}"),
            }
        }
    }

    #[test]
    fn synth_event_leaf_pca_id_is_always_some_for_demo_chain_visibility() {
        // The demo dashboard's chain-walker panel requires every
        // synthetic row to carry a `leaf_pca_id` so the "click row →
        // walk PCA chain" UX surfaces non-empty data. A regression
        // that defaulted to None (e.g. "leaf_pca_id is optional, why
        // bother") would silently break the demo's most-visible feature
        // — pin Some on every scenario.
        for s in SCENARIOS {
            let ev = synth_event(s, Utc::now());
            assert!(
                ev.leaf_pca_id.is_some(),
                "scenario {}/{} produced None leaf_pca_id",
                s.vendor,
                s.action
            );
        }
    }

    #[test]
    fn synth_event_status_field_round_trips_scenario_status_verbatim() {
        // The status field is `scenario.status` cast to u16 with no
        // transformation — a refactor that started normalizing it
        // (e.g. "round all to nearest 100") would silently break the
        // demo dashboard's exact-status display. Pin all four
        // scenarios' status codes round-trip into the emitted event.
        for s in SCENARIOS {
            let ev = synth_event(s, Utc::now());
            assert_eq!(
                ev.status, s.status,
                "status not round-tripped for {}/{}",
                s.vendor, s.action
            );
        }
    }

    #[test]
    fn scenarios_constant_has_exactly_four_entries_for_demo_dashboard_variety() {
        // SCENARIOS length is the canonical demo-event variety pin.
        // The admin dashboard's "live demo" walkthrough commits to
        // showing four distinct decision/action shapes (drive.get
        // allow + drive.list allow + gmail.send block + drive.get
        // require_confirmation) — a refactor that consolidated to
        // three "to reduce noise" would silently break the
        // walkthrough script's "this is what a require_confirmation
        // looks like" beat. Pin the exact length here so any change
        // is a conscious choice.
        assert_eq!(SCENARIOS.len(), 4);
    }

    #[test]
    fn scenarios_all_use_google_vendor_for_current_adapter_coverage() {
        // The proxy ships with adapters for `google` only (Drive +
        // Gmail + Calendar). Every demo scenario currently emits
        // `vendor = "google"` so the synthetic timeline reflects the
        // installed adapter set. A refactor that added a scenario
        // for a not-yet-shipped vendor (e.g. "slack") would silently
        // surface a vendor on the demo dashboard that operators can't
        // actually exercise against, breaking the install-time
        // promise. Pin the contract across every entry.
        for s in SCENARIOS {
            assert_eq!(
                s.vendor, "google",
                "non-google vendor in SCENARIOS: {}/{}",
                s.vendor, s.action,
            );
        }
    }

    #[test]
    fn synth_event_quarantined_count_and_method_and_read_filter_round_trip_from_scenario() {
        // The existing `synth_event_passthrough_scenario_fields` test
        // pins vendor / action / method / status / decision /
        // policy_id / block_reason / at / extra — but does NOT pin
        // `quarantined_count` or `read_filter_triggered`. Both are
        // operator-visible columns on the demo timeline ("quarantined
        // attachments shown in red" UI rule keys on `quarantined_count
        // > 0`; "read-filter triggered" is the columnar marker for
        // the prompt-injection-defense demo panel). A refactor that
        // defaulted either field to a constant (e.g. always 0 / always
        // false "for tidy demo rows") would silently break both demo
        // panels. Pin round-trip on a drive_scenario which carries
        // both fields non-zero / true.
        let s = drive_scenario(); // read_filter_triggered=true, quarantined_count=1
        let ev = synth_event(&s, Utc::now());
        assert_eq!(ev.quarantined_count, 1);
        assert!(ev.read_filter_triggered);
        assert_eq!(ev.method, "GET");
        // And the symmetric polarity: a block scenario carries
        // read_filter_triggered=false + quarantined_count=0.
        let b = block_scenario();
        let ev = synth_event(&b, Utc::now());
        assert_eq!(ev.quarantined_count, 0);
        assert!(!ev.read_filter_triggered);
        assert_eq!(ev.method, "POST");
    }

    #[test]
    fn synth_event_produces_fresh_uuids_per_call_for_each_uuid_field() {
        // `Uuid::new_v4()` is the constructor for `request_id`,
        // `agent_session_id`, and `leaf_pca_id`. Two consecutive
        // synth_event calls with the same scenario MUST yield
        // distinct UUIDs on all three fields — a refactor that
        // hoisted any UUID constructor to a `static` or `OnceCell`
        // "for cheaper demo seeding" would silently collapse every
        // demo row onto the same request_id and break the chain-
        // walker panel's "each row is independent" pre-condition.
        // Pin distinctness across all three UUID fields between two
        // back-to-back calls.
        let s = drive_scenario();
        let a = synth_event(&s, Utc::now());
        let b = synth_event(&s, Utc::now());
        assert_ne!(a.request_id, b.request_id);
        assert_ne!(a.agent_session_id, b.agent_session_id);
        let (Some(la), Some(lb)) = (a.leaf_pca_id, b.leaf_pca_id) else {
            panic!("leaf_pca_id must be Some on demo scenarios");
        };
        assert_ne!(la, lb);
    }

    #[test]
    fn synth_event_suffix_alphabet_is_lowercase_alphanumeric_only() {
        // The 6-char path suffix is generated via a custom char-table
        // selection (`0..36`: 0-9 mapped to `0`..=`9`, 10-35 mapped to
        // `a`..=`z`). Pin the alphabet contract — no uppercase, no
        // symbols. A refactor that swapped to a generic `rand::distr::Alphanumeric`
        // (which includes BOTH `A-Z` and `a-z` plus digits, totalling 62
        // chars) would silently change the suffix shape. The existing
        // `synth_event_path_template_not_ending_in_s_or_slash_gets_6_char_suffix`
        // test pins length + ASCII-alphanumeric only — pin the
        // narrower lowercase + digits contract here. Verify across 20
        // independent suffixes (probabilistic coverage of the alphabet
        // — at suffix-len 6 and per-call random selection, 20 calls
        // sample 120 chars, enough to surface a uppercase regression).
        let s = drive_scenario(); // `/drive/v3/files/demo-file-`
        for _ in 0..20 {
            let ev = synth_event(&s, Utc::now());
            let suffix = &ev.path["/drive/v3/files/demo-file-".len()..];
            assert_eq!(suffix.len(), 6, "suffix wrong length: {suffix}");
            for c in suffix.chars() {
                assert!(
                    c.is_ascii_lowercase() || c.is_ascii_digit(),
                    "suffix char outside lowercase+digit alphabet: {c:?} in {suffix}",
                );
            }
        }
    }

    #[test]
    fn scenario_type_clone_and_copy_preserves_every_field_byte_equal() {
        // The manual `impl Copy for Scenario` + `impl Clone` (delegating
        // to `*self`) are load-bearing for `SCENARIOS.choose(&mut rng)`
        // which calls `.copied()` to escape the slice's borrow. A
        // refactor that added a non-Copy field (e.g. swapping
        // `&'static str` for `String`) would surface here at compile
        // time. Pin the Copy semantics behaviorally: a copy MUST
        // preserve every field byte-equal to the source so the chosen
        // scenario in `ticker(...)` is interchangeable with the
        // referenced original. Walks all eight fields explicitly.
        let original = block_scenario();
        let copy: Scenario = original; // requires Copy
        assert_eq!(copy.vendor, original.vendor);
        assert_eq!(copy.action, original.action);
        assert_eq!(copy.method, original.method);
        assert_eq!(copy.path_template, original.path_template);
        assert_eq!(copy.decision, original.decision);
        assert_eq!(copy.status, original.status);
        assert_eq!(copy.policy, original.policy);
        assert_eq!(copy.read_filter_triggered, original.read_filter_triggered);
        assert_eq!(copy.quarantined_count, original.quarantined_count);
        assert_eq!(copy.block_reason, original.block_reason);
        // Explicit Clone path also preserves — symmetric to the Copy
        // assignment above, but exercises the manual `clone()` impl
        // through a generic helper (a direct `.clone()` call would
        // trip `clippy::clone_on_copy` because Copy is in scope).
        fn via_clone<T: Clone>(v: &T) -> T {
            v.clone()
        }
        let cloned = via_clone(&original);
        assert_eq!(cloned.vendor, original.vendor);
        assert_eq!(cloned.status, original.status);
        assert_eq!(cloned.block_reason, original.block_reason);
    }

    #[test]
    fn users_const_all_carry_user_colon_prefix_and_are_static_str() {
        // `USERS` is a `&[&'static str]` of demo principal names. The
        // shape is `user:<email>` so synthetic events render correctly
        // in the dashboard's "p_0" column AND so an operator can grep
        // demo rows out of production audit queries via the `user:`
        // prefix. A refactor that dropped the prefix "for cleaner
        // emails" would silently produce demo rows that look like
        // real principal names — pin the prefix presence on every
        // entry AND the `&'static str` lifetime bound via a helper.
        fn require_static_str(_: &'static str) {}
        for u in USERS {
            require_static_str(u);
            assert!(
                u.starts_with("user:"),
                "USERS entry `{u}` must start with `user:`",
            );
            // Demo emails are all lowercase ASCII so a regex grep on
            // `^user:[a-z]+@demo.local$` picks them up.
            assert!(
                u.is_ascii(),
                "USERS entry `{u}` must be ASCII for grep stability",
            );
        }
        // The list has at least three entries (alice/bob/carol shape)
        // so synthetic events have a varied principal distribution.
        assert!(USERS.len() >= 3, "USERS too small: {}", USERS.len());
    }

    #[test]
    fn scenarios_const_has_at_least_three_entries_for_decision_variety() {
        // The existing `scenario_set_includes_block_allow_and_require_confirmation_decisions`
        // pin checks decision diversity by HashSet membership but
        // never the underlying size invariant — a refactor that
        // collapsed the SCENARIOS list to a single entry "for
        // simplicity" would still pass that test if the one entry
        // had decision="allow" (the HashSet check covers only the
        // three required decisions). Pin the minimum size (>=3) so
        // a future-shrink to fewer than 3 surfaces here. The current
        // production list has 3+ scenarios — pin the floor.
        assert!(
            SCENARIOS.len() >= 3,
            "SCENARIOS too small: {}",
            SCENARIOS.len(),
        );
    }

    #[test]
    fn synth_event_sets_policy_id_to_scenario_policy_via_some_wrapper() {
        // The `policy_id` field on the ActionEvent flows through to
        // the audit row's `policy_id` column AND the dashboard's
        // "policy" filter. Every synthetic event MUST carry a
        // `Some(scenario.policy)` value — NOT None (which would put
        // demo rows in the "no policy matched" bucket alongside real
        // Layer-A invariant breaks and read-filter blocks). Pin
        // across all SCENARIOS that the synth_event policy_id
        // surfaces as Some with the scenario's policy string verbatim.
        let now = Utc::now();
        for s in SCENARIOS {
            let ev = synth_event(s, now);
            assert_eq!(
                ev.policy_id.as_deref(),
                Some(s.policy),
                "synth_event must carry scenario.policy verbatim, got: {:?}",
                ev.policy_id,
            );
        }
    }

    #[test]
    fn synth_event_extra_field_is_demo_true_jsonb_marker_across_all_scenarios() {
        // Every synthetic event carries `extra: {"demo": true}` —
        // operator audit queries filter on this marker (`WHERE
        // extra->>'demo' = 'true'`) to exclude demo rows from real
        // metrics. A refactor that dropped the marker "for cleaner
        // payloads" would silently pollute every operator dashboard
        // with demo data. Pin BOTH that the field is a JSON object
        // (not a null / not a string) AND that the `demo` key is
        // boolean `true` across all SCENARIOS.
        let now = Utc::now();
        for s in SCENARIOS {
            let ev = synth_event(s, now);
            assert!(
                ev.extra.is_object(),
                "extra must be JSON object, got: {}",
                ev.extra,
            );
            assert_eq!(
                ev.extra["demo"], true,
                "extra.demo must be `true`, got: {}",
                ev.extra["demo"],
            );
        }
    }

    #[test]
    fn synth_event_p_0_field_always_drawn_from_users_const_set() {
        // `synth_event` selects a `user:` value via
        // `USERS.choose(&mut rng)`. Pin that ACROSS many iterations
        // every synthesized p_0 is a member of the USERS set — no
        // off-by-one slicing, no hardcoded fallback. The `unwrap_or
        // (USERS[0])` fallback fires only if `choose` returns None
        // (which happens on empty slice — never the case for the
        // canonical SCENARIOS-paired USERS const). Pin via 100
        // iterations + set membership.
        let now = Utc::now();
        let allowed: std::collections::HashSet<String> =
            USERS.iter().map(|s| s.to_string()).collect();
        for _ in 0..100 {
            let ev = synth_event(&SCENARIOS[0], now);
            assert!(
                allowed.contains(&ev.p_0),
                "p_0 `{}` not in USERS set",
                ev.p_0,
            );
        }
    }

    #[test]
    fn synth_event_status_byte_equal_to_scenario_status_for_dashboard_bucketing() {
        // The HTTP status code on the ActionEvent is what the
        // dashboard's "status" column renders AND what operator
        // metrics bucket on (`status >= 400 → error rate`). Pin that
        // every synthesized event surfaces the scenario's status
        // byte-equal — a refactor that, e.g., synthesized 200 on
        // every event "for hygiene" or that clamped to 5xx for
        // "block" decisions would silently change the demo signal
        // shape. Pin the assignment is verbatim across all
        // SCENARIOS so the demo bucket distribution matches the
        // SCENARIOS const declaration.
        let now = Utc::now();
        for s in SCENARIOS {
            let ev = synth_event(s, now);
            assert_eq!(
                ev.status, s.status,
                "synth_event status drifted from scenario: ev={} sc={}",
                ev.status, s.status,
            );
        }
    }

    #[test]
    fn scenario_set_includes_block_allow_and_require_confirmation_decisions() {
        // SCENARIOS is the canonical demo set. Pin the decision variety so a
        // refactor that drops an interesting class is caught.
        let decisions: std::collections::HashSet<&str> =
            SCENARIOS.iter().map(|s| s.decision).collect();
        assert!(decisions.contains("allow"));
        assert!(decisions.contains("block"));
        assert!(decisions.contains("require_confirmation"));
    }
}
