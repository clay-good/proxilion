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
}
