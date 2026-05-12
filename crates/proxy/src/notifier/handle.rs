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
    use crate::notifier::{WebhookSecret, WebhookNotifier};

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
}
