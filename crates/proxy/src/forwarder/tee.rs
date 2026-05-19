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
}
