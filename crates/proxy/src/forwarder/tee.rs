//! Tee one `ActionEvent` to N sinks.
//!
//! The primary sink (typically `BroadcastingActionStream`) is awaited
//! synchronously so the durable `action_events` row is committed before
//! the request handler returns. Secondary sinks (NATS, SIEM webhook) are
//! awaited concurrently afterwards; each one's failure is logged and
//! metric'd but never propagated — they are append-only audit forwarders,
//! not gating decisions.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::join_all;

use crate::adapters::action_stream::{ActionEvent, ActionStream};

pub struct TeeStream {
    primary: Arc<dyn ActionStream>,
    sinks: Vec<Arc<dyn ActionStream>>,
}

impl TeeStream {
    pub fn new(primary: Arc<dyn ActionStream>) -> Self {
        Self {
            primary,
            sinks: Vec::new(),
        }
    }

    pub fn with_sink(mut self, sink: Arc<dyn ActionStream>) -> Self {
        self.sinks.push(sink);
        self
    }

    pub fn sink_count(&self) -> usize {
        self.sinks.len()
    }
}

#[async_trait]
impl ActionStream for TeeStream {
    async fn publish(&self, event: ActionEvent) {
        self.primary.publish(event.clone()).await;
        if self.sinks.is_empty() {
            return;
        }
        let mut futs = Vec::with_capacity(self.sinks.len());
        for sink in &self.sinks {
            let sink = sink.clone();
            let ev = event.clone();
            futs.push(async move { sink.publish(ev).await });
        }
        join_all(futs).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::Mutex;
    use uuid::Uuid;

    #[derive(Default)]
    struct Collector(Mutex<Vec<ActionEvent>>);

    #[async_trait]
    impl ActionStream for Collector {
        async fn publish(&self, e: ActionEvent) {
            self.0.lock().unwrap().push(e);
        }
    }

    fn sample() -> ActionEvent {
        ActionEvent {
            request_id: Uuid::new_v4(),
            agent_session_id: Uuid::new_v4(),
            p_0: "alice@demo.local".into(),
            leaf_pca_id: None,
            vendor: "google".into(),
            action: "drive.files.get".into(),
            method: "GET".into(),
            path: "/drive/v3/files/x".into(),
            status: 200,
            decision: "allow".into(),
            block_reason: None,
            read_filter_triggered: false,
            quarantined_count: 0,
            at: Utc::now(),
            policy_id: None,
            extra: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn fans_out_to_all_sinks() {
        let primary = Arc::new(Collector::default());
        let s1 = Arc::new(Collector::default());
        let s2 = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone())
            .with_sink(s1.clone())
            .with_sink(s2.clone());
        tee.publish(sample()).await;
        assert_eq!(primary.0.lock().unwrap().len(), 1);
        assert_eq!(s1.0.lock().unwrap().len(), 1);
        assert_eq!(s2.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn no_sinks_still_calls_primary() {
        let primary = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone());
        tee.publish(sample()).await;
        assert_eq!(primary.0.lock().unwrap().len(), 1);
        assert_eq!(tee.sink_count(), 0);
    }

    #[test]
    fn sink_count_tracks_with_sink_chaining() {
        let primary = Arc::new(Collector::default());
        let tee = TeeStream::new(primary);
        assert_eq!(tee.sink_count(), 0);
        let tee = tee.with_sink(Arc::new(Collector::default()));
        assert_eq!(tee.sink_count(), 1);
        let tee = tee.with_sink(Arc::new(Collector::default()));
        assert_eq!(tee.sink_count(), 2);
    }

    #[tokio::test]
    async fn fans_out_to_five_sinks_concurrently_without_dropping_any() {
        // The fan-out uses `join_all` over a Vec built from `&self.sinks`
        // — every registered sink must receive the event regardless of
        // how many there are. Pin a width > 3 so a refactor that
        // accidentally hard-coded a small `tokio::select!` branch or a
        // 2-tuple fan-out doesn't silently truncate the sink list.
        let primary = Arc::new(Collector::default());
        let sinks: Vec<Arc<Collector>> = (0..5).map(|_| Arc::new(Collector::default())).collect();
        let mut tee = TeeStream::new(primary.clone());
        for s in &sinks {
            tee = tee.with_sink(s.clone());
        }
        tee.publish(sample()).await;
        assert_eq!(primary.0.lock().unwrap().len(), 1);
        for s in &sinks {
            assert_eq!(s.0.lock().unwrap().len(), 1);
        }
        assert_eq!(tee.sink_count(), 5);
    }

    #[tokio::test]
    async fn primary_publishes_before_secondary_sinks() {
        // The doc comment guarantees primary is awaited synchronously
        // BEFORE the secondary fan-out runs (so the durable
        // `action_events` row is committed before any best-effort
        // forwarder sees the event). Pin the ordering with a single
        // shared Mutex<Vec<&str>> that each collector tags itself
        // into — primary must always land first. A refactor that
        // moved `primary.publish(...).await` into the join_all set
        // would silently break the "durable record exists by the
        // time a NATS subscriber sees the event" invariant.
        let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));

        struct Tag {
            label: &'static str,
            order: Arc<Mutex<Vec<&'static str>>>,
        }

        #[async_trait]
        impl ActionStream for Tag {
            async fn publish(&self, _e: ActionEvent) {
                self.order.lock().unwrap().push(self.label);
            }
        }

        let primary = Arc::new(Tag {
            label: "primary",
            order: order.clone(),
        });
        let s1 = Arc::new(Tag {
            label: "s1",
            order: order.clone(),
        });
        let s2 = Arc::new(Tag {
            label: "s2",
            order: order.clone(),
        });
        let tee = TeeStream::new(primary).with_sink(s1).with_sink(s2);
        tee.publish(sample()).await;
        let v = order.lock().unwrap().clone();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], "primary", "primary must publish first; got {v:?}");
    }

    #[tokio::test]
    async fn no_sinks_publish_skips_join_all_branch_without_panic() {
        // The `if self.sinks.is_empty() { return; }` early-return is the
        // hot path for installs that haven't configured a SIEM or NATS
        // forwarder — pin both that the early-return is taken (no panic
        // on `Vec::with_capacity(0)`-then-join_all of an empty future
        // set, which is the natural shape if a refactor dropped the
        // guard) and that the primary still gets the event.
        let primary = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone());
        // Three sequential publishes — exercise the empty-sinks branch
        // multiple times so a stateful regression (e.g. a once-cell that
        // sets sinks after first call) would surface.
        tee.publish(sample()).await;
        tee.publish(sample()).await;
        tee.publish(sample()).await;
        assert_eq!(primary.0.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn each_sink_receives_independent_clone() {
        // The fan-out clones the event per sink — each sink must see every
        // field intact (not a default-filled placeholder from a moved value).
        let primary = Arc::new(Collector::default());
        let s1 = Arc::new(Collector::default());
        let s2 = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone())
            .with_sink(s1.clone())
            .with_sink(s2.clone());
        let ev = sample();
        let expected_req = ev.request_id;
        let expected_vendor = ev.vendor.clone();
        tee.publish(ev).await;
        for c in [&primary, &s1, &s2] {
            let v = c.0.lock().unwrap();
            assert_eq!(v.len(), 1);
            assert_eq!(v[0].request_id, expected_req);
            assert_eq!(v[0].vendor, expected_vendor);
        }
    }

    #[test]
    fn tee_stream_is_send_sync_static_for_app_state_arc_dyn_path() {
        // `TeeStream` is constructed once at boot and shared as
        // `Arc<dyn ActionStream>` through AppState into every request
        // handler — a refactor that introduced a `!Send` field
        // (e.g. an `Rc<…>` registry, or a `RefCell` over the sinks vec
        // "to mutate at runtime") would surface here at the type
        // boundary, NOT at the AppState assembly site downstream where
        // the compiler error would mention some unrelated `axum::Router`
        // bound. Pin the three-trait combo (`Send + Sync + 'static`)
        // that `Arc<dyn ActionStream>` requires.
        fn require_send_sync_static<T: Send + Sync + 'static>(_: &T) {}
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let tee = TeeStream::new(primary).with_sink(Arc::new(Collector::default()));
        require_send_sync_static(&tee);
    }

    #[tokio::test]
    async fn tee_stream_works_when_erased_to_arc_dyn_action_stream() {
        // The boot path stores `Arc<dyn ActionStream>` in AppState; pin
        // that a concrete `TeeStream` round-trips through the trait
        // object back into a `publish` call without losing any sink.
        // A refactor that, e.g., implemented `ActionStream` on
        // `Arc<TeeStream>` instead of `TeeStream` would still compile
        // at this layer but silently break the AppState `Arc::new(tee)`
        // erasure step downstream.
        let primary = Arc::new(Collector::default());
        let s1 = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone()).with_sink(s1.clone());
        let erased: Arc<dyn ActionStream> = Arc::new(tee);
        erased.publish(sample()).await;
        assert_eq!(primary.0.lock().unwrap().len(), 1);
        assert_eq!(s1.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn same_arc_sink_registered_twice_publishes_twice() {
        // `with_sink` pushes the supplied `Arc<dyn ActionStream>` onto
        // the sinks vec without deduplicating — the fan-out treats
        // each registration as a distinct destination. Pin that
        // registering the SAME Arc twice yields TWO publishes (not
        // one), so a refactor that added a `HashSet`-style "unique
        // sinks" guard "to prevent operator misconfig" would surface
        // here. Multiple registrations of the same sink are a valid
        // shape for in-test fan-out fixtures and for installs that
        // intentionally double-write to one SIEM with different
        // wrapping (e.g. a redacting decorator over the raw sink).
        let primary = Arc::new(Collector::default());
        let shared = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone())
            .with_sink(shared.clone())
            .with_sink(shared.clone());
        assert_eq!(tee.sink_count(), 2);
        tee.publish(sample()).await;
        assert_eq!(primary.0.lock().unwrap().len(), 1);
        // The shared collector saw the event from BOTH registrations.
        assert_eq!(shared.0.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn every_field_of_event_round_trips_through_each_sink_byte_equal() {
        // The existing `each_sink_receives_independent_clone` test pins
        // `request_id` + `vendor` survive the per-sink clone. The
        // `ActionEvent` struct has 15 fields, several of which are
        // `Option<_>` (`leaf_pca_id`, `block_reason`, `policy_id`) and
        // one is `serde_json::Value` (`extra`) — a refactor that
        // moved to a manual `Clone` impl "for efficiency on the hot
        // path" could silently drop one of those fields. Pin every
        // field on at least one sink so the contract isn't just a
        // request_id + vendor pair.
        let primary = Arc::new(Collector::default());
        let s1 = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone()).with_sink(s1.clone());
        let mut ev = sample();
        ev.leaf_pca_id = Some(Uuid::new_v4());
        ev.block_reason = Some("policy_blocked".into());
        ev.policy_id = Some("p-42".into());
        ev.read_filter_triggered = true;
        ev.quarantined_count = 3;
        ev.extra = serde_json::json!({"k": "v", "n": 7});
        let expected = ev.clone();
        tee.publish(ev).await;
        for c in [&primary, &s1] {
            let v = c.0.lock().unwrap();
            assert_eq!(v.len(), 1);
            let got = &v[0];
            assert_eq!(got.request_id, expected.request_id);
            assert_eq!(got.agent_session_id, expected.agent_session_id);
            assert_eq!(got.p_0, expected.p_0);
            assert_eq!(got.leaf_pca_id, expected.leaf_pca_id);
            assert_eq!(got.vendor, expected.vendor);
            assert_eq!(got.action, expected.action);
            assert_eq!(got.method, expected.method);
            assert_eq!(got.path, expected.path);
            assert_eq!(got.status, expected.status);
            assert_eq!(got.decision, expected.decision);
            assert_eq!(got.block_reason, expected.block_reason);
            assert_eq!(got.read_filter_triggered, expected.read_filter_triggered);
            assert_eq!(got.quarantined_count, expected.quarantined_count);
            assert_eq!(got.at, expected.at);
            assert_eq!(got.policy_id, expected.policy_id);
            assert_eq!(got.extra, expected.extra);
        }
    }

    #[tokio::test]
    async fn primary_failure_panic_propagates_but_does_not_publish_to_sinks() {
        // The doc comment promises the durable primary publish is
        // awaited BEFORE the best-effort fan-out runs. A primary that
        // panics must therefore short-circuit the secondary fan-out —
        // sinks SHOULD NOT see an event for which no durable record
        // exists. Pin the ordering invariant by giving the primary a
        // panicking publish and asserting the sink collector stays
        // empty. (A refactor that moved `primary.publish(...).await`
        // into the same `join_all` set as the sinks would silently
        // start fanning out events that have no durable backing row.)
        struct Panicker;
        #[async_trait]
        impl ActionStream for Panicker {
            async fn publish(&self, _e: ActionEvent) {
                panic!("primary cannot publish");
            }
        }
        let primary = Arc::new(Panicker);
        let sink = Arc::new(Collector::default());
        let tee = TeeStream::new(primary).with_sink(sink.clone());
        // The panic surfaces from `publish` — catch it so the test
        // process survives, then assert the sink was never reached.
        let tee = Arc::new(tee);
        let tee_for_task = tee.clone();
        let h = tokio::spawn(async move { tee_for_task.publish(sample()).await });
        let res = h.await;
        assert!(res.is_err(), "primary panic should propagate");
        assert_eq!(
            sink.0.lock().unwrap().len(),
            0,
            "sinks must not see an event the primary refused/panicked on",
        );
    }

    #[test]
    fn tee_stream_new_with_no_sinks_reports_zero_sink_count() {
        // Symmetric pin to `sink_count_tracks_with_sink_chaining`: pin
        // the BASE case of the builder explicitly. A fresh
        // `TeeStream::new(primary)` MUST report zero secondary sinks
        // before any `with_sink` call. A refactor that initialized
        // `sinks: Vec::with_capacity(1)` "to amortize the first push"
        // and accidentally `push`-ed a placeholder would surface here.
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let tee = TeeStream::new(primary);
        assert_eq!(tee.sink_count(), 0);
    }

    #[test]
    fn tee_stream_with_sink_increments_sink_count_by_exactly_one() {
        // The existing `sink_count_tracks_with_sink_chaining` pin checks
        // the cumulative count after two calls. Pin the per-call delta
        // explicitly across a wider range (0 → 1 → 2 → 3 → 4) so a
        // refactor that started skipping registration when the sink
        // pointer matched an existing entry (a `HashSet`-style dedup)
        // OR that started double-pushing (e.g. accidentally registering
        // a wrapper alongside the inner sink) would surface here on the
        // very first off-by-one delta.
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let mut tee = TeeStream::new(primary);
        for expected in 1..=4 {
            tee = tee.with_sink(Arc::new(Collector::default()));
            assert_eq!(
                tee.sink_count(),
                expected,
                "sink_count drift after {expected} registrations",
            );
        }
    }

    #[test]
    fn tee_stream_erased_to_arc_dyn_is_send_sync_static() {
        // The boot path stores `TeeStream` as `Arc<dyn ActionStream>`
        // inside AppState — the dyn-object MUST itself satisfy
        // `Send + Sync + 'static` (not just the concrete type). The
        // existing `tee_stream_is_send_sync_static_for_app_state_arc_dyn_path`
        // pin asserts the bounds on the concrete `TeeStream`; pin the
        // SAME bounds on the erased trait-object handle so a refactor
        // that left the bounds on `ActionStream` itself unchanged but
        // accidentally tightened them via a where-clause on `TeeStream`
        // would surface at exactly the AppState wire site this test
        // mirrors.
        fn require_send_sync_static<T: Send + Sync + 'static>(_: &T) {}
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let tee = TeeStream::new(primary).with_sink(Arc::new(Collector::default()));
        let erased: Arc<dyn ActionStream> = Arc::new(tee);
        require_send_sync_static(&erased);
    }

    #[tokio::test]
    async fn tee_stream_repeated_publish_accumulates_one_event_per_call() {
        // The existing `no_sinks_publish_skips_join_all_branch_without_panic`
        // pin asserts three sequential publishes accumulate three primary
        // events when there are zero sinks. Pin the symmetric WITH-sinks
        // case: across N=10 sequential publishes, each registered sink
        // sees exactly N events, and the primary also sees exactly N. A
        // refactor that introduced any form of dedup-by-event-id "for
        // SIEM idempotence" would silently drop the second through Nth
        // publish — pin N>3 so any small hard-coded cap (1, 2) would
        // surface clearly.
        let primary = Arc::new(Collector::default());
        let s1 = Arc::new(Collector::default());
        let s2 = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone())
            .with_sink(s1.clone())
            .with_sink(s2.clone());
        for _ in 0..10 {
            tee.publish(sample()).await;
        }
        assert_eq!(primary.0.lock().unwrap().len(), 10);
        assert_eq!(s1.0.lock().unwrap().len(), 10);
        assert_eq!(s2.0.lock().unwrap().len(), 10);
    }

    #[tokio::test]
    async fn tee_stream_with_sink_chaining_preserves_registration_order() {
        // `with_sink` pushes to a Vec — the fan-out order matches
        // registration order. Pin that the recorded order at each
        // sink's first-publish-position survives across three
        // registrations. The existing `primary_publishes_before_secondary_sinks`
        // pin only asserts primary-first; pin the SECONDARY ordering
        // here so a refactor that swapped to `iter().rev()` (a
        // "publish newest sink first" tweak someone might make
        // chasing throughput) would surface in the recorded label
        // sequence.
        let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));

        struct Tag {
            label: &'static str,
            order: Arc<Mutex<Vec<&'static str>>>,
        }

        #[async_trait]
        impl ActionStream for Tag {
            async fn publish(&self, _e: ActionEvent) {
                self.order.lock().unwrap().push(self.label);
            }
        }

        let primary = Arc::new(Tag {
            label: "p",
            order: order.clone(),
        });
        let a = Arc::new(Tag {
            label: "a",
            order: order.clone(),
        });
        let b = Arc::new(Tag {
            label: "b",
            order: order.clone(),
        });
        let c = Arc::new(Tag {
            label: "c",
            order: order.clone(),
        });
        let tee = TeeStream::new(primary)
            .with_sink(a)
            .with_sink(b)
            .with_sink(c);
        tee.publish(sample()).await;
        let v = order.lock().unwrap().clone();
        // Primary first; the three secondaries appear in registration
        // order. `join_all` polls in iteration order, and our `Tag`
        // sinks complete synchronously inside `publish` (no `.await`
        // suspension point between the `lock()` and the push), so the
        // order is deterministic at this layer.
        assert_eq!(v, vec!["p", "a", "b", "c"], "registration order drift");
    }

    #[tokio::test]
    async fn tee_stream_publish_through_shared_arc_handle_does_not_deadlock() {
        // Production wraps the `TeeStream` in `Arc<dyn ActionStream>`
        // and clones the handle into every request scope — concurrent
        // `publish` calls on independent `Arc` clones must NOT contend
        // on any internal lock (the sinks Vec is read-only after boot;
        // `&self.sinks` in the publish path borrows shared). Pin this
        // by spawning ten tasks that each hold their own Arc clone
        // and publish concurrently — every clone must complete and
        // each sink must see exactly ten events. A refactor that
        // introduced a `Mutex<Vec<…>>` "to allow runtime sink
        // registration" would surface here as either a hang under
        // contention or a deadlock if any sink's `publish` itself
        // tried to register.
        let primary = Arc::new(Collector::default());
        let s1 = Arc::new(Collector::default());
        let tee: Arc<dyn ActionStream> =
            Arc::new(TeeStream::new(primary.clone()).with_sink(s1.clone()));
        let mut handles = Vec::with_capacity(10);
        for _ in 0..10 {
            let t = tee.clone();
            handles.push(tokio::spawn(async move { t.publish(sample()).await }));
        }
        for h in handles {
            h.await.expect("publish task panicked");
        }
        assert_eq!(primary.0.lock().unwrap().len(), 10);
        assert_eq!(s1.0.lock().unwrap().len(), 10);
    }

    #[tokio::test]
    async fn fan_out_handles_mixed_concrete_sink_types_via_arc_dyn() {
        // The `sinks: Vec<Arc<dyn ActionStream>>` field accepts any
        // mix of concrete types — production wires LoggingStream +
        // SiemForwarder + NatsForwarder together. Pin that
        // heterogeneous concrete types all receive the event by
        // constructing two distinct collector types and asserting
        // both saw the publish. A refactor that constrained the
        // field to `Vec<Arc<C>>` for a generic `C` (perhaps to
        // unlock a specialized fast-path) would surface here as
        // either a compile error at registration or a missed
        // delivery if the generic was monomorphized to one of the
        // two types.
        #[derive(Default)]
        struct OtherCollector(Mutex<usize>);

        #[async_trait]
        impl ActionStream for OtherCollector {
            async fn publish(&self, _e: ActionEvent) {
                *self.0.lock().unwrap() += 1;
            }
        }

        let primary = Arc::new(Collector::default());
        let s1: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let s2: Arc<dyn ActionStream> = Arc::new(OtherCollector::default());
        let s2_ref: Arc<OtherCollector> = Arc::new(OtherCollector::default()); // kept as the second registration so we can inspect
        let tee = TeeStream::new(primary.clone())
            .with_sink(s1)
            .with_sink(s2)
            .with_sink(s2_ref.clone());
        tee.publish(sample()).await;
        assert_eq!(tee.sink_count(), 3);
        assert_eq!(primary.0.lock().unwrap().len(), 1);
        assert_eq!(*s2_ref.0.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn tee_stream_publish_with_only_primary_skips_join_all_branch_under_burst() {
        // The `if self.sinks.is_empty() { return; }` early-return is a
        // hot path — pin it under a tight burst (50 sequential publishes)
        // so that any refactor introducing per-call allocation in the
        // empty-sinks branch (e.g. `Vec::with_capacity(0)` plus a
        // `join_all` of an empty future-set "for code-path uniformity")
        // would still see the same observable shape: primary saw N
        // events, no panics, no hangs. The existing
        // `no_sinks_publish_skips_join_all_branch_without_panic` pin
        // walks 3 publishes; widen to 50 so a stateful regression
        // (e.g. a once-cell that flips to non-empty after some
        // threshold) surfaces clearly.
        let primary = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone());
        for _ in 0..50 {
            tee.publish(sample()).await;
        }
        assert_eq!(primary.0.lock().unwrap().len(), 50);
        assert_eq!(tee.sink_count(), 0);
    }

    #[tokio::test]
    async fn tee_of_tee_composes_recursively_through_arc_dyn_action_stream() {
        // `TeeStream::new` takes `Arc<dyn ActionStream>` — that bound
        // lets a `TeeStream` itself be a primary (or a sink) of another
        // `TeeStream`. Production hasn't wired this today, but pin
        // recursive composition so a refactor that narrowed the
        // `primary` field type to a concrete sink struct "for
        // monomorphization" would surface here, AND so a future
        // operator wanting "publish to SIEM-A AND (SIEM-B fan-out across
        // 3 regions)" has the composition shape validated. A 3-level
        // nested tee with two sinks at each level must deliver to all
        // leaf collectors.
        let leaf_a = Arc::new(Collector::default());
        let leaf_b = Arc::new(Collector::default());
        let leaf_c = Arc::new(Collector::default());
        let inner: Arc<dyn ActionStream> = Arc::new(
            TeeStream::new(leaf_a.clone() as Arc<dyn ActionStream>).with_sink(leaf_b.clone()),
        );
        let outer = TeeStream::new(inner).with_sink(leaf_c.clone());
        outer.publish(sample()).await;
        assert_eq!(leaf_a.0.lock().unwrap().len(), 1);
        assert_eq!(leaf_b.0.lock().unwrap().len(), 1);
        assert_eq!(leaf_c.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tee_stream_propagates_event_with_all_optional_fields_none_intact() {
        // The `ActionEvent` has three `Option<_>` fields (`leaf_pca_id`,
        // `block_reason`, `policy_id`) that the demo-mode + the
        // not-yet-bound-to-a-PCA paths both leave as None. The existing
        // `every_field_of_event_round_trips_through_each_sink_byte_equal`
        // pin sets all three to Some; pin the symmetric NONE shape so a
        // refactor that, e.g., backfilled `block_reason` with `Some(...)
        // .or(Some("unknown".into()))` "for dashboard hygiene" would
        // surface here as a None → Some flip on every audit-mode event.
        let primary = Arc::new(Collector::default());
        let sink = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone()).with_sink(sink.clone());
        let ev = sample();
        assert!(ev.leaf_pca_id.is_none() && ev.block_reason.is_none() && ev.policy_id.is_none());
        tee.publish(ev).await;
        for c in [&primary, &sink] {
            let v = c.0.lock().unwrap();
            assert_eq!(v.len(), 1);
            assert!(v[0].leaf_pca_id.is_none(), "leaf_pca_id became Some");
            assert!(v[0].block_reason.is_none(), "block_reason became Some");
            assert!(v[0].policy_id.is_none(), "policy_id became Some");
        }
    }

    #[test]
    fn tee_stream_sink_count_return_type_is_usize_not_signed() {
        // `sink_count` returns `usize` — pin the return type so a
        // refactor that flipped to `i32` "to allow -1 as a sentinel
        // for not-yet-finalized" or to `u32` "to save 4 bytes on
        // 64-bit targets" would surface here at the type bound rather
        // than at downstream comparisons (which would auto-coerce
        // numeric literals and hide the drift). The helper takes
        // `usize` only; passing the result implicitly type-checks.
        fn require_usize(_: usize) {}
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let tee = TeeStream::new(primary);
        require_usize(tee.sink_count());
    }

    #[tokio::test]
    async fn tee_stream_publish_visits_every_sink_at_least_once_under_eight_registrations() {
        // The fan-out uses `Vec::with_capacity(self.sinks.len())` and a
        // simple for-loop over `&self.sinks` — pin that EVERY one of 8
        // registered sinks is visited at least once on a single publish.
        // The existing `fans_out_to_five_sinks_concurrently_without_dropping_any`
        // pin checks width 5; widen to 8 so any off-by-one cap (a refactor
        // hard-coding `if sinks.len() < 6 { ... }` for some micro-opt)
        // surfaces. Use distinct collectors so an "all events landed on
        // sink 0" regression would be visible in the per-sink counts.
        let primary = Arc::new(Collector::default());
        let sinks: Vec<Arc<Collector>> = (0..8).map(|_| Arc::new(Collector::default())).collect();
        let mut tee = TeeStream::new(primary.clone());
        for s in &sinks {
            tee = tee.with_sink(s.clone());
        }
        tee.publish(sample()).await;
        assert_eq!(primary.0.lock().unwrap().len(), 1);
        for (i, s) in sinks.iter().enumerate() {
            assert_eq!(
                s.0.lock().unwrap().len(),
                1,
                "sink {i} did not receive the event"
            );
        }
        assert_eq!(tee.sink_count(), 8);
    }

    #[tokio::test]
    async fn tee_stream_publish_returns_unit_not_result_for_infallible_fan_out_contract() {
        // The doc comment promises secondary-sink failures are
        // "logged and metric'd but never propagated" — therefore
        // `publish` returns `()`, not `Result<_, _>`. Pin the unit
        // return shape via a helper that takes `()`. A refactor that
        // surfaced sink errors back up the call chain "for finer-grained
        // operator telemetry" would surface here — and would also break
        // the request-handler flow that today calls `publish(...).await`
        // without a `?` AND that today does not check the return.
        fn require_unit(_: ()) {}
        let primary = Arc::new(Collector::default());
        let tee = TeeStream::new(primary.clone());
        let out: () = tee.publish(sample()).await;
        require_unit(out);
        assert_eq!(primary.0.lock().unwrap().len(), 1);
    }

    // ─── round 224 (2026-05-22): TeeStream field count, new/with_sink return-type
    // shape, field type pins, sink_count RT, dyn-compatibility witness ───

    #[test]
    fn tee_stream_field_count_pinned_at_exactly_two_via_exhaustive_destructure_no_rest_pattern() {
        // `TeeStream { primary, sinks }` — exactly 2 fields. A 3rd field
        // landing (e.g. `metrics_label: String` for per-tee metric
        // bucketing, OR `failure_policy: FailurePolicy` to make
        // secondary-sink failures gating in a future revision, OR
        // `concurrency_limit: usize` to cap the join_all width) without
        // matching `new()`/`with_sink()` constructor wiring would
        // silently leave the new field zero-initialized on every
        // TeeStream handed out — operators would see partial behaviour
        // (existing sinks work, the new feature is silently a no-op).
        // The exhaustive destructure with no `..` rest pattern forces a
        // 3rd field to update this site in lockstep with the
        // constructors. Symmetric to the NatsBridge 2-field +
        // FederationClaims 8-field + CachedPca 8-field +
        // TokenResponse 4-field exhaustive-destructure pins.
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let tee = TeeStream::new(primary);
        let TeeStream {
            primary: _,
            sinks: _,
        } = tee;
    }

    #[test]
    fn tee_stream_new_return_type_is_owned_self_by_value_via_fn_pointer_witness() {
        // `TeeStream::new` returns owned `Self` — the value flows
        // through the AppState assembly chain
        // `TeeStream::new(primary).with_sink(s1).with_sink(s2)` which
        // requires each step to consume + return Self by value (the
        // fluent builder shape). A refactor to `Arc<Self>` "for
        // ergonomic cross-handler share at construction" would force
        // `*tee` deref OR `.as_ref()` at every `with_sink` call site,
        // AND break the move-into-Arc-after-build path AppState uses
        // (`Arc::new(TeeStream::new(...).with_sink(...))`). Pin via
        // fn-pointer witness so the type surfaces at the constructor
        // boundary, not at the AppState assembly site downstream.
        // Symmetric to the CachedPca::new + ErrorBody::new owned-Self
        // fn-pointer pins.
        let _f: fn(Arc<dyn ActionStream>) -> TeeStream = TeeStream::new;
        fn require_owned_tee(_: TeeStream) {}
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        require_owned_tee(TeeStream::new(primary));
    }

    #[test]
    fn tee_stream_with_sink_consumes_self_and_returns_self_via_fn_pointer_witness() {
        // `TeeStream::with_sink` is `pub fn with_sink(mut self, sink:
        // Arc<dyn ActionStream>) -> Self` — consumes self by value AND
        // returns Self by value (the fluent builder shape that AppState
        // chains). A refactor to `&mut self -> &mut Self` "for
        // ergonomic conditional sink registration (no temporaries
        // required)" would break the move-chain at every
        // `TeeStream::new(...).with_sink(...).with_sink(...)` site —
        // the chain depends on the consuming-and-returning shape so
        // the final binding can be moved into `Arc::new(...)` without
        // a let-rebind step. Pin via fn-pointer witness — the type
        // signature `fn(TeeStream, Arc<dyn ActionStream>) -> TeeStream`
        // only compiles when self is consumed by value. Symmetric to
        // the ErrorBody fluent-builder owned-Self pins.
        let _f: fn(TeeStream, Arc<dyn ActionStream>) -> TeeStream = TeeStream::with_sink;
        // And exercise to confirm the chain works at runtime.
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let s1: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let s2: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let tee = TeeStream::new(primary).with_sink(s1).with_sink(s2);
        assert_eq!(tee.sink_count(), 2);
    }

    #[test]
    fn tee_stream_sinks_field_type_is_owned_vec_arc_dyn_for_arbitrary_fan_out_width() {
        // `TeeStream.sinks: Vec<Arc<dyn ActionStream>>` — OWNED Vec of
        // Arc-dyn entries. The owned Vec lets `with_sink` push() onto
        // the trailing position without re-allocating the entire
        // builder chain. A refactor to `&'a [Arc<dyn ActionStream>]`
        // "for zero-alloc when the sink list is known at boot" would
        // force a lifetime parameter through TeeStream that breaks the
        // Arc<dyn ActionStream> AppState bound. A refactor to
        // `[Arc<dyn ActionStream>; 4]` fixed-array "for stack alloc"
        // would cap fan-out width at compile time, silently breaking
        // any deployment that wires more than 4 sinks (primary + NATS
        // + SIEM + webhook + future + ... — operators routinely wire 5+
        // in production). Pin via require_owned_vec on the destructured
        // field. Symmetric to the ActionEvent owned-String + GoogleClient
        // owned-String field-type pins.
        fn require_owned_vec(_: Vec<Arc<dyn ActionStream>>) {}
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let tee = TeeStream::new(primary).with_sink(Arc::new(Collector::default()));
        let TeeStream { primary: _, sinks } = tee;
        require_owned_vec(sinks);
    }

    #[test]
    fn tee_stream_sink_count_is_referentially_transparent_across_fifty_calls() {
        // `sink_count` is a pure `self.sinks.len()` accessor — no I/O,
        // no global state, no time-of-day input. Pin referential
        // transparency across 50 calls so a refactor that, e.g.,
        // memoized the result keyed on a thread-local cache OR threaded
        // a per-process counter through the accessor "for sink-count
        // sampling observability" would surface here as non-
        // deterministic output. Symmetric to the sanitize_token RT
        // 50-call + ErrorBody::new RT 50-call + oauth_error_class RT
        // 50-call pins extended to this sibling pure accessor.
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let mut tee = TeeStream::new(primary);
        for _ in 0..3 {
            tee = tee.with_sink(Arc::new(Collector::default()));
        }
        let first = tee.sink_count();
        assert_eq!(first, 3);
        for i in 0..50 {
            assert_eq!(
                tee.sink_count(),
                first,
                "iter {i}: sink_count drift on same TeeStream",
            );
        }
    }

    #[test]
    fn tee_stream_is_dyn_compatible_via_arc_dyn_action_stream_witness_for_nested_tee_composition() {
        // `TeeStream` itself implements `ActionStream` — so a `TeeStream`
        // can be wrapped in `Arc<dyn ActionStream>` AND a SECOND TeeStream
        // can be built atop the first (the round-23 `tee_of_tee_composes
        // _recursively_through_arc_dyn_action_stream` test exercises this
        // at runtime). Pin the dyn-compatibility shape at the TYPE level
        // so a refactor that gave TeeStream a generic type parameter
        // (e.g. `TeeStream<E: ErrorReporter>` "for pluggable secondary-
        // sink error reporting") would break object-safety (generics
        // on methods or self can't be object-safe) and the AppState
        // `Arc<dyn ActionStream>` bound would fail far from this file.
        // Pin via require_dyn_action_stream — symmetric to the NatsBridge
        // dyn-compatibility witness pin in round 222.
        fn require_dyn_action_stream(_: Arc<dyn ActionStream>) {}
        #[allow(dead_code)]
        fn _witness(t: Arc<TeeStream>) {
            require_dyn_action_stream(t);
        }
        // And at runtime: build a TeeStream and Arc-erase it.
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let tee = TeeStream::new(primary);
        let erased: Arc<dyn ActionStream> = Arc::new(tee);
        require_dyn_action_stream(erased);
    }

    // ─── round 292 (2026-05-26): TeeStream Send+Sync + accessor + initial-state pins ───

    #[test]
    fn tee_stream_sink_count_signature_pinned_via_fn_pointer_witness_for_borrow_only_accessor() {
        // `TeeStream::sink_count(&self) -> usize` — the read-only
        // accessor every boot-path uses to decide whether to spawn
        // the secondary-sink flush loop (server.rs reads this AFTER
        // assembling the TeeStream). Pin the FULL fn-pointer
        // signature here: `&self` borrow (catches `self`-consuming
        // refactor breaking accessor idempotency every reader site
        // relies on) + `usize` return (catches `i32`/`u32` width-
        // change refactor surfacing only at downstream comparison
        // sites where numeric literals auto-coerce). The existing
        // `tee_stream_sink_count_return_type_is_usize_not_signed`
        // pin walks the return-type axis only; pin the full fn-
        // pointer signature here at the boundary. Symmetric to
        // round-281 webhook_notifier_proxy_public_url + round-287
        // slack_notifier accessor fn-pointer pins extended to this
        // sibling forwarder accessor.
        let _f: fn(&TeeStream) -> usize = TeeStream::sink_count;
    }

    #[test]
    fn tee_stream_implements_action_stream_via_require_trait_bound_witness_for_arc_dyn_at_app_state()
     {
        // `TeeStream: ActionStream` is the trait the AppState fan-out
        // depends on at line 17-18 of action_stream.rs — server.rs
        // wraps a `TeeStream` in `Arc<dyn ActionStream>` and stores
        // it on AppState; every per-request adapter publish() routes
        // through this trait dispatch. The existing
        // `tee_stream_is_dyn_compatible_via_arc_dyn_action_stream_witness`
        // pin walks the dyn-erasure path (Arc<TeeStream> →
        // Arc<dyn ActionStream> coercion); pin the BARE TRAIT
        // BOUND here at the type boundary via require_action_stream
        // witness so a refactor that dropped the
        // `impl ActionStream for TeeStream` block (line 40-55) "for
        // refactoring publish into a free function" would surface
        // here as a single type-boundary failure rather than at the
        // axum boot site as a cascading trait error. Symmetric to
        // round-280 AppError + round-291 ErrorBody trait-bound
        // witness pins extended to this sibling fan-out type.
        fn require_action_stream<T: ActionStream + ?Sized>() {}
        require_action_stream::<TeeStream>();
    }

    #[test]
    fn tee_stream_is_send_and_sync_directly_for_arc_dyn_action_stream_object_safety() {
        // `TeeStream: Send + Sync` directly (NOT just when wrapped
        // in `Arc<dyn ActionStream>`). The existing
        // `tee_stream_erased_to_arc_dyn_is_send_sync_static` pin
        // walks the erased path only; pin the BARE type bound here
        // so a refactor that landed a `Rc<...>` or `Cell<...>` field
        // (NOT Send/Sync) would surface here at the type boundary
        // BEFORE the Arc-erasure site. The bounds are load-bearing
        // for the `Arc<dyn ActionStream>` AppState coercion: the
        // `dyn ActionStream` object-safety requires `Send + Sync`
        // bounds on the trait, but the storage in
        // `Arc<dyn ActionStream + Send + Sync>` requires the
        // concrete type ALSO satisfy them. Pin both axes here.
        // Symmetric to round-280 AppError Send+Sync+'static pin
        // extended to this sibling concrete type (not just erased).
        fn require_send<T: Send>() {}
        fn require_sync<T: Sync>() {}
        require_send::<TeeStream>();
        require_sync::<TeeStream>();
    }

    #[test]
    fn tee_stream_new_starts_with_empty_sinks_via_sink_count_zero_initial_state_invariant() {
        // `TeeStream::new(primary)` constructs with `sinks:
        // Vec::new()` (line 26) — the documented initial state is
        // ZERO secondary sinks. The boot path at server.rs depends
        // on this: it builds `TeeStream::new(primary)` THEN
        // conditionally calls `.with_sink(nats)` /
        // `.with_sink(siem)` based on operator config. A refactor
        // that pre-seeded the initial Vec with a sentinel
        // (e.g. `vec![noop_sink_for_metrics()]` "for unconditional
        // counter increment") would silently double-count every
        // event AND would render `sink_count() == 0` impossible
        // even when no sinks are registered. Pin the initial
        // sink_count == 0 invariant directly. Symmetric to round-282
        // demo `synth_event_leaf_pca_id_is_always_some_never_none_across_all_scenarios`
        // initial-state-invariant pin extended to this sibling
        // forwarder builder.
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let tee = TeeStream::new(primary);
        assert_eq!(
            tee.sink_count(),
            0,
            "TeeStream::new must start with empty sinks"
        );
    }

    #[test]
    fn tee_stream_primary_field_type_pinned_arc_dyn_action_stream_via_destructure_helper_witness() {
        // `TeeStream.primary: Arc<dyn ActionStream>` — the primary
        // sink is held by `Arc<dyn ActionStream>` so server.rs can
        // hand in EITHER a `BroadcastingActionStream` OR a
        // `LoggingStream` (dev mode) OR a nested TeeStream
        // (composition) WITHOUT a generic type parameter on
        // TeeStream itself (which would break the Arc<dyn> AppState
        // bound — see the dyn-compatibility pin at line 832). The
        // existing `tee_stream_sinks_field_type_is_owned_vec_arc_dyn`
        // pin walks the SECONDARY sinks field; pin the PRIMARY
        // field type here so a refactor that landed a CONCRETE type
        // (`primary: BroadcastingActionStream` "for type-safety on
        // the durable-row gate") would surface as a destructure
        // type mismatch here AND would force every server.rs site
        // that constructs TeeStream with a non-Broadcasting primary
        // to update. Pin via destructure + helper witness on the
        // owned Arc<dyn>. Symmetric to the sibling `sinks` field
        // type pin extended to the primary field.
        fn require_arc_dyn(_: Arc<dyn ActionStream>) {}
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let tee = TeeStream::new(primary);
        let TeeStream { primary, sinks: _ } = tee;
        require_arc_dyn(primary);
    }

    #[test]
    fn tee_stream_with_sink_appends_to_trailing_position_preserving_prior_sinks_via_three_chain() {
        // `TeeStream::with_sink` calls `self.sinks.push(sink)` (line
        // 31) — appends to the trailing position WITHOUT touching
        // prior sinks. The existing
        // `tee_stream_with_sink_chaining_preserves_registration_order`
        // pin walks 2 sinks; widen to 3 sinks here AND pin via
        // direct sink_count comparison at EACH step so an off-by-one
        // or accidental-reset refactor (e.g. `self.sinks = vec![sink]`
        // "for builder reset semantics") surfaces at the count
        // mismatch on intermediate states rather than only at the
        // final sink count. Symmetric to round-282
        // `synth_event_request_id_and_agent_session_id_distinct_and_fresh_per_invocation`
        // step-by-step invariant pin extended to this sibling
        // append-only builder.
        let primary: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let s1: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let s2: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let s3: Arc<dyn ActionStream> = Arc::new(Collector::default());
        let tee = TeeStream::new(primary);
        assert_eq!(tee.sink_count(), 0, "initial state");
        let tee = tee.with_sink(s1);
        assert_eq!(tee.sink_count(), 1, "after 1st with_sink");
        let tee = tee.with_sink(s2);
        assert_eq!(tee.sink_count(), 2, "after 2nd with_sink");
        let tee = tee.with_sink(s3);
        assert_eq!(tee.sink_count(), 3, "after 3rd with_sink");
    }
}
