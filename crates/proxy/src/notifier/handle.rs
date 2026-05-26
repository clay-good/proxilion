//! Hot-swappable notifier handles (ui-less-surfaces.md §8.4 + §10.3).
//!
//! All consumers (adapters, public approve flow, /api/v1/notifier/*) read
//! the notifier through `Handle::current()` which loads the current
//! `Arc<T>` (or `None`) atomically. The config endpoint can `replace(...)`
//! the inner value; all subsequent calls see the new notifier on the
//! next snapshot.
//!
//! `NotifierHandle` (webhook) is the original; `SlackHandle` is its sibling
//! after the §5.3 driver was added. The structure is identical — kept as
//! distinct type aliases so call sites read clearly at the use point.

use std::sync::Arc;

use arc_swap::ArcSwap;

use super::{BurstSuppressor, EmailNotifier, SlackNotifier, WebhookNotifier};

/// Generic hot-swap cell for any notifier driver. Clone shares the same
/// underlying ArcSwap, so all clones see swaps. Hand-written `Clone` so
/// the bound doesn't require `T: Clone` (the inner is `Arc<T>`, which is
/// always cloneable).
pub struct Handle<T> {
    inner: Arc<ArcSwap<Option<Arc<T>>>>,
}

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Handle<T> {
    pub fn new(initial: Option<Arc<T>>) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    pub fn current(&self) -> Option<Arc<T>> {
        self.inner.load().as_ref().clone()
    }

    pub fn replace(&self, new: Option<Arc<T>>) {
        self.inner.store(Arc::new(new));
    }
}

pub type NotifierHandle = Handle<WebhookNotifier>;
pub type SlackHandle = Handle<SlackNotifier>;
pub type EmailHandle = Handle<EmailNotifier>;

/// Per-driver bundle. Cheap to clone (each field is just an Arc). The
/// adapter / approve flow holds one of these and fans out at notify time.
///
/// ui-less-surfaces.md §10.3 dev 2 — the burst suppressor instances live
/// on the bundle so the `/api/v1/notifier/config` hot-swap path can
/// re-attach the boot-time suppressor to a freshly-built notifier. Without
/// this, a config change drops burst suppression silently (the new
/// notifier has `burst: None`); with it, suppression state survives the
/// swap and the bucket history persists across config changes.
#[derive(Clone)]
pub struct Notifiers {
    pub webhook: NotifierHandle,
    pub slack: SlackHandle,
    pub email: EmailHandle,
    /// Boot-time webhook suppressor. Cloned into each new webhook notifier
    /// the hot-swap path builds; `None` only in tests / empty bundles.
    pub webhook_burst: Option<BurstSuppressor>,
    /// Boot-time Slack suppressor. Same semantics as webhook_burst.
    pub slack_burst: Option<BurstSuppressor>,
}

impl Notifiers {
    pub fn empty() -> Self {
        Self {
            webhook: Handle::new(None),
            slack: Handle::new(None),
            email: Handle::new(None),
            webhook_burst: None,
            slack_burst: None,
        }
    }

    #[allow(dead_code)] // exposed for `/admin/setup` summary in a future iteration
    pub fn any_configured(&self) -> bool {
        self.webhook.current().is_some()
            || self.slack.current().is_some()
            || self.email.current().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifier::{WebhookNotifier, WebhookSecret};

    fn mk_webhook(url: &str) -> Arc<WebhookNotifier> {
        let s = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        Arc::new(WebhookNotifier::new(url.into(), s, "https://proxy.local".into()).unwrap())
    }

    #[test]
    fn starts_none() {
        let h: NotifierHandle = Handle::new(None);
        assert!(h.current().is_none());
    }

    #[test]
    fn replace_swaps_in_new() {
        let h: NotifierHandle = Handle::new(None);
        h.replace(Some(mk_webhook("https://example.com/v1")));
        assert!(h.current().is_some());
        let h2 = h.clone();
        h.replace(Some(mk_webhook("https://example.com/v2")));
        assert!(h2.current().is_some());
    }

    #[test]
    fn replace_to_none_clears() {
        let h: NotifierHandle = Handle::new(Some(mk_webhook("https://example.com")));
        h.replace(None);
        assert!(h.current().is_none());
    }

    #[test]
    fn bundle_starts_empty() {
        let n = Notifiers::empty();
        assert!(!n.any_configured());
    }

    #[test]
    fn bundle_any_configured_when_webhook_set() {
        let n = Notifiers::empty();
        n.webhook.replace(Some(mk_webhook("https://x.example")));
        assert!(n.any_configured());
    }

    #[test]
    fn cloned_handle_sees_replace_via_other_clone() {
        // `Handle::clone` shares the underlying `Arc<ArcSwap<_>>` — the
        // hot-swap design relies on this so the `/api/v1/notifier/config`
        // endpoint can replace the inner notifier without forcing every
        // request handler to plumb the new handle through. Pin that a
        // replace through clone-A is visible to clone-B.
        let a: NotifierHandle = Handle::new(None);
        let b = a.clone();
        assert!(b.current().is_none());
        a.replace(Some(mk_webhook("https://shared.example")));
        assert!(
            b.current().is_some(),
            "swap through one clone must be visible to the other",
        );
        a.replace(None);
        assert!(b.current().is_none(), "clear is visible too");
    }

    #[test]
    fn bundle_clone_shares_handles_with_original() {
        // `Notifiers` derives `Clone`; each field is an `Arc`-backed Handle
        // (or `Option<BurstSuppressor>`). A clone that accidentally
        // deep-copied the ArcSwap would break the hot-swap design — the
        // dashboard endpoint holds one bundle, the request handlers hold a
        // clone, both must see the same notifier after a replace.
        let n = Notifiers::empty();
        let m = n.clone();
        n.webhook
            .replace(Some(mk_webhook("https://shared.example")));
        assert!(m.webhook.current().is_some());
        assert!(m.any_configured());
    }

    #[test]
    fn empty_bundle_has_none_for_burst_suppressors() {
        // The two `Option<BurstSuppressor>` fields default to None for
        // tests + empty bundles per the doc comment. Pin both — a
        // refactor that pre-built default `BurstSuppressor` instances
        // would silently activate burst suppression on every test
        // fixture (and change the semantics of "empty bundle") without
        // touching this assertion.
        let n = Notifiers::empty();
        assert!(n.webhook_burst.is_none());
        assert!(n.slack_burst.is_none());
    }

    #[test]
    fn replace_to_none_after_some_clears_for_all_clones() {
        // Symmetric to `replace_to_none_clears` but pinned across a
        // clone fan-out — the hot-swap contract is "every clone sees
        // the same current() value at every moment", so a regression
        // that deep-copied the swap on `replace(None)` would surface
        // here. Two clones, one replace-Some, observed-Some on both,
        // one replace-None, observed-None on both.
        let a: NotifierHandle = Handle::new(None);
        let b = a.clone();
        let c = a.clone();
        a.replace(Some(mk_webhook("https://example.com")));
        assert!(b.current().is_some());
        assert!(c.current().is_some());
        b.replace(None);
        assert!(a.current().is_none());
        assert!(c.current().is_none());
    }

    #[test]
    fn handle_new_with_initial_some_carries_through_first_current_call() {
        // Boot path: `server::run` builds a fresh Handle with the
        // pre-configured notifier (loaded from DB or env). Pin that
        // the first `current()` call after `Handle::new(Some(_))`
        // returns the same notifier — a regression to a lazy
        // initialization scheme would silently delay the first
        // notify-fire by one request.
        let w = mk_webhook("https://example.com/initial");
        let h: NotifierHandle = Handle::new(Some(w.clone()));
        let got = h
            .current()
            .expect("initial Some must surface on first read");
        // Pointer equality — `Handle::new(Some(arc))` must NOT clone
        // the underlying `T`. Pin this so a refactor to
        // `Handle::new(Some(Arc::new(_clone_of_inner)))` would surface
        // here as a different Arc pointer.
        assert!(Arc::ptr_eq(&w, &got));
    }

    #[test]
    fn handle_new_with_initial_none_first_current_is_none() {
        // Symmetric to `handle_new_with_initial_some_carries_through_first_current_call`
        // — pin that constructing with `None` yields `None` on first read
        // (not a default-built notifier from a refactor that pre-populated
        // an empty `Arc<T>` "for ergonomics"). The boot path's "no
        // notifier configured" branch and the `Notifiers::empty()` shape
        // both depend on this invariant.
        let h: NotifierHandle = Handle::new(None);
        assert!(
            h.current().is_none(),
            "initial None must surface on first read"
        );
        // Repeat reads of the same None must not flip to Some (defends
        // against a lazy-init refactor that materializes on first call).
        assert!(h.current().is_none());
    }

    #[tokio::test]
    async fn any_configured_triggers_on_email_alone_as_third_or_chain_branch() {
        // Symmetric coverage to `bundle_any_configured_when_webhook_set`
        // and `any_configured_triggers_on_slack_alone`. The OR-chain
        // has three branches; both prior tests pinned webhook + slack,
        // but the email branch was unpinned. A copy-paste typo in the
        // `|| self.email.current().is_some()` line (e.g. duplicating
        // the slack check) would only surface here. Builds a real
        // EmailNotifier so the type-system checks the Handle wiring
        // (Arc<EmailNotifier> → EmailHandle) at the call site too.
        use crate::notifier::EmailNotifier;
        use sqlx::postgres::PgPoolOptions;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/__notifier_handle_email_test")
            .expect("lazy connect builds");
        let email = Arc::new(
            EmailNotifier::new(
                "smtp://localhost:25",
                "sec@x.com",
                &["a@x.com".into()],
                "https://proxy.local".into(),
                pool,
            )
            .expect("EmailNotifier::new builds"),
        );
        let n = Notifiers::empty();
        assert!(!n.any_configured());
        n.email.replace(Some(email));
        assert!(n.any_configured(), "email-only must trigger any_configured");
        n.email.replace(None);
        assert!(!n.any_configured());
    }

    #[test]
    fn any_configured_triggers_on_slack_alone() {
        // Symmetric coverage to `bundle_any_configured_when_webhook_set`.
        // The OR-chain is easy to break with a copy-paste typo (`||
        // self.webhook.current()` repeated twice instead of also reading
        // `slack` / `email`); pinning the Slack branch independently
        // catches that.
        use crate::notifier::{SlackNotifier, SlackSigningSecret};
        let slack = Arc::new(
            SlackNotifier::new(
                "https://hooks.slack.com/services/T/B/C".into(),
                SlackSigningSecret::new("00112233445566778899aabbccddeeff"),
                "https://proxy.local".into(),
            )
            .unwrap(),
        );
        let n = Notifiers::empty();
        assert!(!n.any_configured());
        n.slack.replace(Some(slack));
        assert!(n.any_configured());
        n.slack.replace(None);
        assert!(!n.any_configured());
    }

    #[test]
    fn handle_is_send_sync_static_for_each_concrete_notifier_type() {
        // `NotifierHandle` / `SlackHandle` / `EmailHandle` all live in
        // AppState which is cloned into every tower layer + handler
        // extractor; the `Send + Sync + 'static` combo is the AppState-
        // bound contract. A refactor that gave `Handle<T>` a `Cell<...>`
        // field "for in-process state tracking" would break Sync without
        // surfacing at this file; the breakage would appear at AppState
        // assembly with an unrelated trait-bound error. Pin the three-
        // trait combo for all three concrete aliases here so the type
        // boundary fails fast at the right call site.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<NotifierHandle>();
        require_send_sync_static::<SlackHandle>();
        require_send_sync_static::<EmailHandle>();
        require_send_sync_static::<Notifiers>();
    }

    #[test]
    fn handle_supports_non_clone_inner_type_via_arc_indirection() {
        // The file docstring commits to "the bound doesn't require
        // T: Clone (the inner is Arc<T>, which is always cloneable)".
        // Pin this contract with a deliberately non-Clone type wrapped
        // in Arc — Handle<NonClone> must construct, swap, and clone
        // without requiring a Clone bound on the inner. A refactor that
        // added `T: Clone` to Handle's impl block (e.g. via a derive
        // that pulls it implicitly through serde or another trait)
        // would surface here as a compile failure at this test site
        // rather than silently constraining every future driver type.
        struct NonClone(#[allow(dead_code)] String);
        let a = Arc::new(NonClone("payload".into()));
        let h: Handle<NonClone> = Handle::new(Some(a.clone()));
        let got = h.current().expect("initial Some must surface");
        assert!(Arc::ptr_eq(&a, &got));
        let h2 = h.clone();
        h.replace(None);
        assert!(h2.current().is_none());
        h2.replace(Some(Arc::new(NonClone("replaced".into()))));
        assert!(h.current().is_some());
    }

    #[test]
    fn handle_current_returns_same_arc_across_repeated_reads_without_swap() {
        // The hot-path call site is `let n = handle.current(); if let
        // Some(notifier) = n { notifier.fire(...).await; }` — repeated
        // `current()` calls without an intervening `replace` MUST
        // return Arcs pointing to the SAME underlying T. A refactor
        // that started materializing a fresh Arc on each load (e.g.
        // `Arc::new((**self.inner.load()).clone())` "for snapshot
        // isolation") would silently double the Arc clone cost per
        // request and break any caller that relied on `Arc::ptr_eq`
        // for cache keys. Pin pointer-stability across three reads.
        let w = mk_webhook("https://stable.example");
        let h: NotifierHandle = Handle::new(Some(w.clone()));
        let r1 = h.current().expect("first read Some");
        let r2 = h.current().expect("second read Some");
        let r3 = h.current().expect("third read Some");
        assert!(Arc::ptr_eq(&r1, &r2));
        assert!(Arc::ptr_eq(&r2, &r3));
        assert!(Arc::ptr_eq(&w, &r1));
    }

    #[test]
    fn handle_replace_with_same_arc_value_keeps_current_observable_as_some() {
        // The `/api/v1/notifier/config` endpoint may be invoked twice
        // with byte-identical config (operator click-storm, or a CI
        // sync that re-applies the same TOML); each call constructs a
        // fresh `Arc<WebhookNotifier>` (different Arc pointer) carrying
        // the same logical config. Pin that the post-replace
        // `current()` is `Some` and points to the NEW Arc, not the old
        // one (the swap actually happened — ArcSwap doesn't dedupe on
        // value equality). A refactor that added a value-equality
        // short-circuit "to avoid spurious swaps" would silently drop
        // the second replace's burst-suppressor re-attachment, breaking
        // the §10.3 hot-swap suppressor-survival contract.
        let h: NotifierHandle = Handle::new(None);
        let w1 = mk_webhook("https://example.com/config");
        h.replace(Some(w1.clone()));
        let got1 = h.current().expect("first replace Some");
        assert!(Arc::ptr_eq(&w1, &got1));
        let w2 = mk_webhook("https://example.com/config");
        h.replace(Some(w2.clone()));
        let got2 = h.current().expect("second replace Some");
        assert!(Arc::ptr_eq(&w2, &got2));
        // The two webhook Arcs are distinct pointers (mk_webhook
        // builds a fresh Arc each call) — confirming the second
        // replace actually advanced state.
        assert!(!Arc::ptr_eq(&w1, &w2));
    }

    #[test]
    fn two_independent_empty_bundles_have_independent_handle_state() {
        // `Notifiers::empty()` constructs three fresh `Handle::new(None)`
        // values per call — each call MUST produce independent state.
        // Pin that swapping a webhook into bundle A does NOT surface
        // through bundle B. A refactor that introduced a process-wide
        // singleton ArcSwap "for memory savings" (the kind of change
        // that looks safe under static analysis since every read goes
        // through `Arc<ArcSwap>`) would silently make every
        // `Notifiers::empty()` test fixture share state with the
        // production bundle, cross-contaminating notifier dispatch.
        let a = Notifiers::empty();
        let b = Notifiers::empty();
        a.webhook.replace(Some(mk_webhook("https://a.example")));
        assert!(a.any_configured());
        assert!(
            !b.any_configured(),
            "second empty bundle must not share state"
        );
        // Symmetric: configure B's slack — A's any_configured must NOT
        // flip on the slack arm.
        use crate::notifier::{SlackNotifier, SlackSigningSecret};
        let slack = Arc::new(
            SlackNotifier::new(
                "https://hooks.slack.com/services/T/B/C".into(),
                SlackSigningSecret::new("00112233445566778899aabbccddeeff"),
                "https://proxy.local".into(),
            )
            .unwrap(),
        );
        b.slack.replace(Some(slack));
        // A's slack still unconfigured.
        assert!(a.slack.current().is_none());
        // B's webhook still unconfigured.
        assert!(b.webhook.current().is_none());
    }

    #[test]
    fn handle_clone_chain_three_deep_propagates_swap_to_all_clones() {
        // The hot-swap contract scales: the `/api/v1/notifier/config`
        // endpoint holds one clone, the bundle inside AppState holds
        // another, the per-request handler-derived state holds a third.
        // A swap through ANY of the three MUST surface through all
        // three. Existing tests pin the two-clone case; pin the three-
        // deep chain to defend against a refactor that introduced a
        // copy-on-write semantic (CoW would surface here as the third
        // clone observing the pre-replace state while the first two
        // observed the post-replace state).
        let a: NotifierHandle = Handle::new(None);
        let b = a.clone();
        let c = b.clone(); // clone the clone
        // All three start None.
        assert!(a.current().is_none());
        assert!(b.current().is_none());
        assert!(c.current().is_none());
        // Replace through the deepest clone — both ancestors must see it.
        c.replace(Some(mk_webhook("https://deep.example")));
        assert!(a.current().is_some(), "root must see grandchild's replace");
        assert!(
            b.current().is_some(),
            "middle must see grandchild's replace"
        );
        assert!(c.current().is_some());
        // Clear through the root — both descendants must see it.
        a.replace(None);
        assert!(b.current().is_none());
        assert!(c.current().is_none());
    }

    #[test]
    fn notifiers_empty_produces_three_handles_with_independent_arc_swap_state() {
        // `Notifiers::empty()` builds three INDEPENDENT `Handle::new(None)`
        // values — a swap on webhook MUST NOT surface on slack OR email.
        // The existing `two_independent_empty_bundles_have_independent_handle_state`
        // pin walks bundle-to-bundle isolation; this pin walks the
        // sibling-handle isolation WITHIN a single bundle. A refactor
        // that introduced a shared inner ArcSwap "for memory savings on
        // boot-empty bundles" would silently fan a webhook replace into
        // slack's current() reads. Pin all three pairwise.
        let n = Notifiers::empty();
        n.webhook
            .replace(Some(mk_webhook("https://only-webhook.example")));
        assert!(n.webhook.current().is_some());
        assert!(n.slack.current().is_none(), "slack must remain None");
        assert!(n.email.current().is_none(), "email must remain None");
        // Symmetric: clear webhook + set slack — webhook + email stay None.
        n.webhook.replace(None);
        use crate::notifier::{SlackNotifier, SlackSigningSecret};
        let slack = Arc::new(
            SlackNotifier::new(
                "https://hooks.slack.com/services/T/B/C".into(),
                SlackSigningSecret::new("00112233445566778899aabbccddeeff"),
                "https://proxy.local".into(),
            )
            .unwrap(),
        );
        n.slack.replace(Some(slack));
        assert!(n.webhook.current().is_none());
        assert!(n.slack.current().is_some());
        assert!(n.email.current().is_none());
    }

    #[tokio::test]
    async fn notifiers_clone_shares_all_three_handles_not_just_webhook() {
        // The existing `bundle_clone_shares_handles_with_original` test pins
        // the webhook arm only. The OR-chain in `any_configured` covers
        // three arms — a refactor that gave `slack` or `email` a deep-
        // copying Clone impl (e.g. via a manual derive that wrapped them
        // in `Arc::new(...)` "for explicit ownership") would silently break
        // hot-swap on those two drivers without surfacing in the webhook
        // pin. Pin slack + email Clone-share explicitly.
        use crate::notifier::{SlackNotifier, SlackSigningSecret};
        let n = Notifiers::empty();
        let m = n.clone();
        let slack = Arc::new(
            SlackNotifier::new(
                "https://hooks.slack.com/services/T/B/C".into(),
                SlackSigningSecret::new("00112233445566778899aabbccddeeff"),
                "https://proxy.local".into(),
            )
            .unwrap(),
        );
        n.slack.replace(Some(slack));
        assert!(
            m.slack.current().is_some(),
            "slack replace through n must surface through m",
        );
        // Email arm — build a lazy-pool EmailNotifier (no DB connection
        // required until persist time).
        use crate::notifier::EmailNotifier;
        use sqlx::postgres::PgPoolOptions;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/__handle_clone_email_share_test")
            .expect("lazy connect builds");
        let email = Arc::new(
            EmailNotifier::new(
                "smtp://localhost:25",
                "sec@x.com",
                &["a@x.com".into()],
                "https://proxy.local".into(),
                pool,
            )
            .expect("EmailNotifier::new builds"),
        );
        n.email.replace(Some(email));
        assert!(
            m.email.current().is_some(),
            "email replace through n must surface through m",
        );
    }

    #[test]
    fn handle_new_with_some_arc_strong_count_observably_increments_by_one() {
        // `Handle::new(Some(arc))` stores the Arc inside an
        // `Arc<ArcSwap<Option<Arc<T>>>>` — the input Arc's strong_count
        // MUST increment by exactly one (the Handle's inner reference).
        // A refactor that double-wrapped (`Arc::new((*arc).clone())`,
        // requiring T: Clone or shallow-copying the inner T) would
        // surface here as strong_count == 1 post-construction. Pin the
        // delta explicitly so a Clone-bound regression on the inner T
        // surfaces at this site rather than at the (already-pinned)
        // ptr_eq test.
        let w = mk_webhook("https://strong-count.example");
        assert_eq!(Arc::strong_count(&w), 1, "pre-construct: only the local");
        let h: NotifierHandle = Handle::new(Some(w.clone()));
        // After construction the Handle's inner ArcSwap holds an extra
        // reference — strong_count is now 2 (local + Handle inner).
        assert_eq!(Arc::strong_count(&w), 2, "post-construct: local + Handle");
        // Drop the Handle — strong_count returns to 1.
        drop(h);
        assert_eq!(Arc::strong_count(&w), 1, "post-drop: only the local");
    }

    #[test]
    fn handle_replace_with_new_arc_drops_prior_arc_strong_count_on_swap() {
        // `Handle::replace(Some(new))` MUST drop the prior `Arc<T>` the
        // ArcSwap held — strong_count on the previous Arc should decrement
        // by one (the ArcSwap stops holding it). A refactor that
        // accidentally retained the prior Arc in a Vec "for replace
        // history" would surface here as a strong_count that doesn't
        // drop, leaking notifier instances across every config swap.
        let prev = mk_webhook("https://prev.example");
        let h: NotifierHandle = Handle::new(Some(prev.clone()));
        assert_eq!(
            Arc::strong_count(&prev),
            2,
            "pre-replace: local + Handle inner",
        );
        let new = mk_webhook("https://new.example");
        h.replace(Some(new.clone()));
        // Swap dropped prev from the ArcSwap — strong_count back to 1.
        assert_eq!(
            Arc::strong_count(&prev),
            1,
            "post-replace: prev only held by local",
        );
        // And the new Arc's strong_count is 2 (local + Handle inner).
        assert_eq!(
            Arc::strong_count(&new),
            2,
            "post-replace: new held by local + Handle",
        );
    }

    #[test]
    fn handle_is_send_sync_static_over_arbitrary_inner_type_via_generic_bound() {
        // The existing `handle_is_send_sync_static_for_each_concrete_notifier_type`
        // pin walks the three concrete type aliases. Pin the generic
        // `Handle<T: Send + Sync + 'static>` bound directly via a
        // non-notifier `T` (`String`, `u64`, custom plain struct) so a
        // refactor that constrained the impl to a hand-rolled trait
        // marker (e.g. `T: NotifierDriver`) would surface here on the
        // generic-instantiation site rather than only at the concrete
        // alias sites. The harness is the same `require_send_sync_static`
        // function the sibling pin uses; the difference is the type
        // parameter being arbitrary plain Rust types.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<Handle<String>>();
        require_send_sync_static::<Handle<u64>>();
        struct Plain {
            #[allow(dead_code)]
            x: i32,
        }
        require_send_sync_static::<Handle<Plain>>();
    }

    #[tokio::test]
    async fn notifiers_any_configured_returns_to_false_after_full_set_then_clear_cycle() {
        // The OR-chain `webhook || slack || email` must surface false
        // after EVERY driver has been set + cleared (a complete cycle).
        // A refactor that introduced a "sticky" counter ("once configured,
        // always count as configured" — the natural shape of a metrics-
        // friendly internal flag) would silently keep `any_configured()`
        // true even after the operator cleared every driver. Pin the
        // full set + clear cycle across all three arms.
        use crate::notifier::{EmailNotifier, SlackNotifier, SlackSigningSecret};
        use sqlx::postgres::PgPoolOptions;
        let n = Notifiers::empty();
        assert!(!n.any_configured(), "starts false");
        n.webhook
            .replace(Some(mk_webhook("https://cycle-webhook.example")));
        assert!(n.any_configured());
        let slack = Arc::new(
            SlackNotifier::new(
                "https://hooks.slack.com/services/T/B/C".into(),
                SlackSigningSecret::new("00112233445566778899aabbccddeeff"),
                "https://proxy.local".into(),
            )
            .unwrap(),
        );
        n.slack.replace(Some(slack));
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/__handle_cycle_test")
            .expect("lazy connect builds");
        let email = Arc::new(
            EmailNotifier::new(
                "smtp://localhost:25",
                "sec@x.com",
                &["a@x.com".into()],
                "https://proxy.local".into(),
                pool,
            )
            .expect("EmailNotifier::new builds"),
        );
        n.email.replace(Some(email));
        assert!(n.any_configured(), "all three set");
        // Clear each in turn.
        n.webhook.replace(None);
        assert!(n.any_configured(), "still slack + email");
        n.slack.replace(None);
        assert!(n.any_configured(), "still email");
        n.email.replace(None);
        assert!(!n.any_configured(), "fully cleared returns to false");
    }

    #[test]
    fn handle_current_returns_arc_with_strong_count_greater_than_one_so_caller_owns_a_ref() {
        // `Handle::current()` returns an `Option<Arc<T>>` clone — the
        // caller takes ownership of an Arc whose strong_count is at
        // least 2 (Handle inner + caller). A refactor that returned a
        // `&Arc<T>` "for zero-alloc reads" would surface as a borrow-
        // checker error at the hot-path call sites that fire `.await`
        // on the inner notifier; a refactor that `Arc::try_unwrap()`-ed
        // the inner (e.g. to "take ownership for atomic mutation") would
        // surface here as strong_count == 1. Pin the multi-ref contract.
        let w = mk_webhook("https://multiref.example");
        let h: NotifierHandle = Handle::new(Some(w.clone()));
        let got = h.current().expect("must be Some");
        // strong_count >= 2: at minimum the local `w`, the Handle inner,
        // and the just-returned `got`. With clone in mk_webhook we have
        // exactly: local `w` + Handle inner + got = 3.
        assert!(
            Arc::strong_count(&got) >= 2,
            "caller-owned Arc must have strong_count >= 2, got {}",
            Arc::strong_count(&got),
        );
        // And the returned Arc points to the SAME T as the original.
        assert!(Arc::ptr_eq(&w, &got));
    }

    #[test]
    fn empty_bundle_starts_with_none_for_email_handle_too() {
        // The `webhook_burst` and `slack_burst` Option<BurstSuppressor>
        // fields had their default-None pin (`empty_bundle_has_none_for_burst_suppressors`),
        // but the three Handle fields (webhook/slack/email) were only
        // collectively asserted via `bundle_starts_empty` which goes
        // through the `any_configured` OR chain — a regression that
        // pre-populated the email handle alone wouldn't show up there
        // because the OR short-circuits on the webhook check. Pin the
        // email branch's initial-None directly so an `Arc::new(default_email)`
        // pre-fill regression in `empty()` surfaces here as the wrong
        // default rather than as a phantom email driver firing at boot.
        let n = Notifiers::empty();
        assert!(n.email.current().is_none(), "email handle must start None");
        // Symmetric pin for webhook + slack — defends against the
        // reverse copy-paste (a regression that pre-filled the OTHER two
        // would pass the email check above but fail here).
        assert!(
            n.webhook.current().is_none(),
            "webhook handle must start None"
        );
        assert!(n.slack.current().is_none(), "slack handle must start None");
    }

    // ─── round 202 (2026-05-20): Handle + Notifiers method-signature surfaces ───

    #[test]
    fn handle_current_return_type_is_option_arc_t_for_caller_decides_present_or_absent() {
        // `Handle<T>::current(&self) -> Option<Arc<T>>` — the
        // return is `Option<Arc<T>>`, NOT `Arc<T>` or `Arc<Option<T>>`.
        // The Option captures the "no driver configured yet" semantic
        // distinct from "driver present but disabled" (the latter
        // would be a future inner-T flag). The Arc captures the
        // shared-ownership semantic that lets every adapter request
        // hold a snapshot across `.await` boundaries. A refactor
        // that flattened to `Arc<Option<T>>` "for cheaper Option-on-
        // the-outside" would force every caller to .as_ref().is_some()
        // through the Arc layer AND would foreclose the ArcSwap<Option<Arc<T>>>
        // hot-swap atomic semantics that depend on the Arc-inside-Option
        // shape. Pin return type via let-binding type annotation.
        // Symmetric to round-200 SiemHmacKey::from_hex Result return
        // pin extended to this hot-swap accessor.
        let h: NotifierHandle = Handle::new(None);
        let out: Option<Arc<WebhookNotifier>> = h.current();
        assert!(out.is_none());
    }

    #[test]
    fn handle_replace_return_type_is_unit_for_infallible_hot_swap_atomic_store() {
        // `Handle<T>::replace(&self, new: Option<Arc<T>>)` returns
        // `()` — the hot-swap is infallible by construction (ArcSwap's
        // store is wait-free + lock-free + can't fail). A refactor
        // that promoted to `Result<(), SwapError>` "for future
        // generation-counter conflict detection" would break every
        // `/api/v1/notifier/config` handler call site which today
        // calls `.replace(...)` without `?`. Pin via require_unit
        // + let-binding type annotation. Symmetric to round-201
        // KillCache::mark unit-return + round-199 admit() bool-not-
        // Result pins extended to this hot-swap write helper.
        fn require_unit(_: ()) {}
        let h: NotifierHandle = Handle::new(None);
        let out: () = h.replace(None);
        require_unit(out);
    }

    #[test]
    fn notifier_handle_slack_handle_email_handle_are_distinct_type_aliases_over_handle_generic() {
        // `pub type NotifierHandle = Handle<WebhookNotifier>;`
        // `pub type SlackHandle = Handle<SlackNotifier>;`
        // `pub type EmailHandle = Handle<EmailNotifier>;`
        // — three distinct type aliases over the same `Handle<T>`
        // generic. The aliases are read-clarity aids at call sites
        // (`fn build(webhook: NotifierHandle, slack: SlackHandle,
        // email: EmailHandle)` reads more clearly than `Handle<...>`,
        // `Handle<...>`, `Handle<...>`). Pin that the three aliases
        // resolve to DISTINCT concrete types by constructing one
        // of each and pinning their type via Notifiers field
        // assignment compatibility — a refactor that consolidated
        // them to a single `NotifierHandle = Handle<dyn AnyNotifier>`
        // "for fewer types" would surface here as a type mismatch
        // at the Notifiers field assignments AND would lose the
        // monomorphized hot-swap perf (dyn-trait calls would replace
        // the direct Arc<T> dereferences). The compile-time check
        // is the let-binding type annotation pattern.
        let webhook_h: NotifierHandle = Handle::new(None);
        let slack_h: SlackHandle = Handle::new(None);
        let email_h: EmailHandle = Handle::new(None);
        // Each alias resolves to the right generic over its inner
        // type — verified by Notifiers field assignment.
        let _bundle = Notifiers {
            webhook: webhook_h,
            slack: slack_h,
            email: email_h,
            webhook_burst: None,
            slack_burst: None,
        };
    }

    #[test]
    fn notifiers_burst_suppressor_fields_are_option_burst_suppressor_for_post_boot_attach() {
        // `Notifiers.webhook_burst` and `Notifiers.slack_burst` —
        // both `Option<BurstSuppressor>`, NOT bare `BurstSuppressor`.
        // The Option captures the "no suppressor wired in this
        // configuration" semantic (e.g. test fixtures, minimal
        // setups). The hot-swap path re-attaches the boot-time
        // suppressor to a fresh notifier on `/api/v1/notifier/config`
        // — without the Option, the boot path would have to construct
        // a no-op suppressor as a placeholder, AND tests would have
        // to plumb one through. A refactor to bare BurstSuppressor
        // "for required-by-default semantics" would force every test
        // fixture to construct one (the `Notifiers::empty()` helper
        // depends on these fields being None-defaultable). Pin
        // Option<BurstSuppressor> via require_opt_burst_suppressor
        // on both fields. Symmetric to round-191 CheckItem.fix
        // Option<&'static str> + round-197 Scenario.block_reason
        // Option<&'static str> pins extended to this bundle shape's
        // optional-driver-companion contract.
        fn require_opt_burst_suppressor(_: &Option<BurstSuppressor>) {}
        let n = Notifiers::empty();
        require_opt_burst_suppressor(&n.webhook_burst);
        require_opt_burst_suppressor(&n.slack_burst);
        // And both are None on the empty bundle (existing pin
        // `empty_bundle_has_none_for_burst_suppressors` walks the
        // VALUE; this pin walks the TYPE in lockstep).
        assert!(n.webhook_burst.is_none());
        assert!(n.slack_burst.is_none());
    }

    #[test]
    fn notifiers_any_configured_return_type_is_bool_for_infallible_or_chain_dispatch() {
        // `Notifiers::any_configured(&self) -> bool` — the return
        // is bare `bool`, NOT `Option<bool>` or `Result<bool>`.
        // The `/admin/setup` summary handler calls
        // `notifiers.any_configured()` directly in a boolean
        // context (`if !any_configured { render_setup_hint() }`).
        // A refactor that promoted to `Result<bool, _>` "for
        // future race-with-hot-swap detection" would break every
        // setup-handler call site which today drops the bool into
        // an `if` without `.unwrap()`. Pin via require_bool + let-
        // binding type. Symmetric to round-199 BurstSuppressor::admit
        // bool-not-Result + round-201 KillCache::is_killed bool-not-
        // Optional pins extended to this sibling bundle accessor.
        fn require_bool(_: bool) {}
        let n = Notifiers::empty();
        let out: bool = n.any_configured();
        require_bool(out);
        assert!(!out, "empty bundle's any_configured must be false");
    }

    #[test]
    fn handle_new_constructor_return_type_is_self_for_builder_ergonomics() {
        // `Handle::new(initial: Option<Arc<T>>) -> Self` — the
        // return is `Self` (the generic Handle<T>), NOT `Result<Self,
        // _>`. The constructor is infallible (it builds an ArcSwap
        // from the provided initial, which can't fail). A refactor
        // that promoted to `Result<Self, BuildError>` "for future
        // validation of the inner T" would break the
        // `NotifierHandle::new(None)` boot-path call sites which
        // today use the return value directly without `?` or
        // `.unwrap()`. Pin via let-binding type annotation forcing
        // the Self return shape across all three concrete aliases.
        // Symmetric to round-200 SiemHmacKey::from_hex Result return
        // (the INVERSE — that one IS fallible by design; this one
        // is intentionally infallible). The two constructors document
        // different contracts via their return types — a refactor
        // that flipped either would surface here OR at the sibling
        // round-200 test.
        let webhook: NotifierHandle = Handle::new(None);
        let slack: SlackHandle = Handle::new(None);
        let email: EmailHandle = Handle::new(None);
        // The three concrete aliases all return Self (their
        // respective Handle<T> shape). Sanity: each starts None.
        assert!(webhook.current().is_none());
        assert!(slack.current().is_none());
        assert!(email.current().is_none());
    }

    #[test]
    fn handle_struct_field_count_pinned_at_exactly_one_via_exhaustive_destructure_no_rest_pattern()
    {
        // Pin the Handle<T> struct field count at exactly 1 via
        // exhaustive destructure (no `..`). The 1 field is: inner
        // (Arc<ArcSwap<Option<Arc<T>>>>). A 2nd field landing (e.g.
        // `swap_count: Arc<AtomicU64>` for per-handle observability
        // counting hot-swaps, or `last_swapped_at:
        // Arc<ArcSwap<DateTime<Utc>>>` for "this notifier was last
        // configured at" surfacing on the setup-status panel) would
        // silently bloat every Handle Clone the Notifiers bundle
        // fan-out path uses AND silently change what observers see.
        // The hand-rolled Clone impl wires `inner.clone()` only;
        // a 2nd field landing without matching the Clone impl would
        // surface as a non-cloning regression too.
        let h: NotifierHandle = Handle::new(None);
        let Handle { inner: _ } = h;
    }

    #[test]
    fn notifiers_bundle_field_count_pinned_at_exactly_five_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the Notifiers bundle struct field count at exactly 5
        // via exhaustive destructure (no `..`). The 5 fields are:
        // webhook + slack + email + webhook_burst + slack_burst.
        // A 6th field landing (e.g. `pagerduty: PagerDutyHandle`
        // for the future incident-routing driver per
        // ui-less-surfaces.md §5.3 future-work, or
        // `email_burst: Option<BurstSuppressor>` symmetric to the
        // webhook/slack pair for per-driver email burst suppression)
        // would silently bloat every Notifiers Clone on the adapter
        // hot path AND silently change which drivers fan out at
        // notify time. The existing `empty()` constructor + the
        // existing `any_configured()` predicate would each need
        // updates in lockstep — exhaustive destructure catches a
        // landed field without matching every site.
        let n = Notifiers::empty();
        let Notifiers {
            webhook: _,
            slack: _,
            email: _,
            webhook_burst: _,
            slack_burst: _,
        } = n;
    }

    #[test]
    fn handle_new_signature_pinned_via_fn_pointer_witness() {
        // Pin Handle<WebhookNotifier>::new signature as
        // `fn(Option<Arc<WebhookNotifier>>) -> Handle<WebhookNotifier>`
        // via fn-pointer witness. The constructor takes the initial
        // notifier by VALUE (consuming the Option<Arc<_>>) and
        // returns the owned Handle. A refactor to
        // `fn(&Option<Arc<T>>) -> Self` ("for borrow-on-build
        // clarity") would tie the Handle's ArcSwap-from-pointee
        // step to a borrow lifetime that ArcSwap can't satisfy
        // without an extra clone. Pin the by-value owned-Arc shape
        // at compile time via fn-pointer witness on the most-used
        // concrete instantiation.
        let _f: fn(Option<Arc<WebhookNotifier>>) -> Handle<WebhookNotifier> = Handle::new;
    }

    #[test]
    fn handle_replace_signature_pinned_via_fn_pointer_witness() {
        // Pin Handle<WebhookNotifier>::replace signature as
        // `fn(&Handle<WebhookNotifier>, Option<Arc<WebhookNotifier>>)`
        // via fn-pointer witness. The replace method takes `&self`
        // (NOT `&mut self`) — interior mutability via the inner
        // ArcSwap is the canonical Rust shape for hot-swap APIs.
        // A refactor to `&mut self` ("for clarity") would silently
        // break every call site in `/api/v1/notifier/config` that
        // holds the Handle through an `Arc<dyn ...>`-style
        // shared-borrow chain. The new-notifier arg is by VALUE
        // (consuming the Option<Arc<_>>) — symmetric to the new()
        // pin above. The return type is unit `()` — pin via
        // explicit signature shape so a future `Result<(), _>`
        // refactor "for error-on-failed-swap" surfaces here.
        let _f: fn(&Handle<WebhookNotifier>, Option<Arc<WebhookNotifier>>) = Handle::replace;
    }

    #[test]
    fn handle_current_signature_pinned_via_fn_pointer_witness() {
        // Pin Handle<WebhookNotifier>::current signature as
        // `fn(&Handle<WebhookNotifier>) -> Option<Arc<WebhookNotifier>>`
        // via fn-pointer witness. The accessor takes `&self` and
        // returns an OWNED `Option<Arc<T>>` (the Arc is incref'd by
        // the underlying ArcSwap::load, the Option is built fresh
        // on each call). A refactor to
        // `fn(&self) -> &Option<Arc<T>>` "to avoid the
        // Option-cloning on the hot path" would tie the return
        // lifetime to &self, breaking call sites that drop the
        // Handle clone before consuming the inner Arc (the adapter
        // pattern: `state.notifiers.webhook.current().map(|n| ...)`).
        // The owned-return shape is load-bearing.
        let _f: fn(&Handle<WebhookNotifier>) -> Option<Arc<WebhookNotifier>> = Handle::current;
    }

    #[test]
    fn notifiers_bundle_is_send_sync_static_for_axum_router_state_propagation() {
        // The Notifiers bundle flows through axum's State<T>
        // extractor + survives across `.await` boundaries in the
        // approve_inner / reject_inner paths. All Send + Sync +
        // 'static MUST be satisfied. The existing Clone derive
        // walks the trait; this walks the auto-trait combo
        // directly. A refactor adding an Rc<...> field "for cheap
        // shared metadata" on any of the 5 fields would break
        // Sync and surface at a remote `tower::Service` trait-bound
        // rather than at this module. Pin via require_send_sync_static
        // — symmetric to round-176/177/178 Send+Sync+'static pins
        // extended to the notifier bundle. Also pin Handle<T> via
        // a concrete generic instantiation so a refactor that broke
        // either the generic or the bundle surfaces here.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<Notifiers>();
        require_send_sync_static::<NotifierHandle>();
        require_send_sync_static::<SlackHandle>();
        require_send_sync_static::<EmailHandle>();
    }
}
