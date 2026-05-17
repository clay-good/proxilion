//! Block-burst suppression (ui-less-surfaces.md §5.6).
//!
//! Without suppression, a misconfigured policy can fire dozens of webhook
//! notifications per minute to the operator's Slack channel — at which
//! point the team mutes the channel and Proxilion's approval flow is
//! effectively dead. The suppressor collapses bursts in the same
//! `(policy_id, p_0)` bucket into a single "first + summary" envelope.
//!
//! Algorithm:
//!   * Sliding window keyed by `(policy_id, p_0)`. Each entry is a small
//!     ring of recent timestamps.
//!   * On each notification, prune timestamps older than `window`,
//!     count remaining.
//!   * If count < `threshold`: pass through.
//!   * If count >= `threshold`: drop the notification, increment a
//!     suppressed counter on the bucket. A separate background task
//!     periodically (every `flush_interval`) emits a single "summary"
//!     notification per bucket that has suppressed at least one event.
//!
//! Numbers: defaults to `threshold=50`, `window=60s`, `flush_interval=30s`.
//! Per-policy override is intentionally left to a future iteration (the
//! `policy.yaml` would carry `notifier.burst: { threshold, window }`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::Mutex;
use tracing::warn;

use super::BlockedNotification;

#[derive(Clone, Debug)]
pub struct BurstConfig {
    pub threshold: usize,
    pub window: Duration,
    pub flush_interval: Duration,
}

impl Default for BurstConfig {
    fn default() -> Self {
        Self {
            threshold: 50,
            window: Duration::from_secs(60),
            flush_interval: Duration::from_secs(30),
        }
    }
}

#[derive(Default, Debug)]
struct Bucket {
    /// Timestamps of *passed-through* events in the current window. When
    /// this many accumulate, subsequent events get suppressed.
    timestamps: Vec<Instant>,
    /// How many events we've dropped since the last summary flush.
    suppressed: u64,
    /// First suppressed-event blob — surfaced in the summary so the
    /// operator has at least one canonical exemplar.
    first_suppressed: Option<SuppressedEvent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SuppressedEvent {
    pub policy_id: String,
    pub p_0: Option<String>,
    pub vendor: String,
    pub action: String,
    pub layer: String,
}

impl Bucket {
    fn prune(&mut self, now: Instant, window: Duration) {
        self.timestamps.retain(|t| now.duration_since(*t) <= window);
    }
}

/// A summary the suppressor hands back to the caller when a burst flush
/// is due. The caller (`WebhookNotifier::flush_summaries`) translates
/// this into a single envelope-style notification per bucket.
#[derive(Debug, Clone, Serialize)]
pub struct BurstSummary {
    pub schema: &'static str,
    pub policy_id: String,
    pub p_0: Option<String>,
    pub suppressed_count: u64,
    pub window_seconds: u64,
    pub exemplar: Option<SuppressedEvent>,
    /// Deep link to the filtered blocked-queue view — ui-less-surfaces.md
    /// §5.6 dev 2 "click for the full list." Populated by the caller from
    /// `proxy_public_url + /api/v1/blocked?policy_id=...&p_0=...`. Empty
    /// string when the notifier has no public URL (test fixtures).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub details_url: String,
}

impl BurstSummary {
    pub const SCHEMA: &'static str = "proxilion.blocked_action_burst.v1";

    /// Fill `details_url` with `<base>/api/v1/blocked?policy_id=<id>[&p_0=<email>]`.
    /// Both query values are URL-encoded; empty `base` is a no-op. Lets
    /// each notifier produce the same deep link without duplicating the
    /// URL-format logic.
    pub fn with_details_url(mut self, base: &str) -> Self {
        if base.is_empty() {
            return self;
        }
        let trimmed = base.trim_end_matches('/');
        let pid = urlencoding_encode(&self.policy_id);
        let mut url = format!("{trimmed}/api/v1/blocked?policy_id={pid}");
        if let Some(p_0) = &self.p_0 {
            let e = urlencoding_encode(p_0);
            url.push_str("&p_0=");
            url.push_str(&e);
        }
        self.details_url = url;
        self
    }
}

/// Tiny URL-encoder for query values. The proxy already pulls
/// `percent-encoding` for OAuth callback handling; we use it via a
/// thin wrapper to keep call sites tidy. Kept here to avoid threading
/// an extra dependency into `burst.rs`.
fn urlencoding_encode(s: &str) -> String {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Per-policy override resolver. Returns `(threshold, window)` overrides
/// for a given `policy_id`; each option may be unset (use the global
/// default). ui-less-surfaces.md §5.6.
pub type BurstResolver = Arc<dyn Fn(&str) -> Option<(Option<usize>, Option<u64>)> + Send + Sync>;

#[derive(Clone)]
pub struct BurstSuppressor {
    default_cfg: BurstConfig,
    resolver: Option<BurstResolver>,
    buckets: Arc<Mutex<HashMap<(String, Option<String>), Bucket>>>,
}

impl BurstSuppressor {
    pub fn new(cfg: BurstConfig) -> Self {
        Self {
            default_cfg: cfg,
            resolver: None,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Attach a per-policy override resolver. The proxy wires this to
    /// `PolicyHandle` so a `policy.yaml` change live-updates threshold/window.
    pub fn with_resolver(mut self, r: BurstResolver) -> Self {
        self.resolver = Some(r);
        self
    }

    fn config_for(&self, policy_id: &str) -> BurstConfig {
        let mut cfg = self.default_cfg.clone();
        if let Some(r) = &self.resolver {
            if let Some((thr, win)) = r(policy_id) {
                if let Some(t) = thr {
                    cfg.threshold = t;
                }
                if let Some(w) = win {
                    cfg.window = Duration::from_secs(w);
                }
            }
        }
        cfg
    }

    /// Decide whether the given notification should be forwarded or
    /// suppressed. The return value is true when the notifier should
    /// continue with delivery, false when the event was absorbed.
    ///
    /// `now` is injected for deterministic tests; production callers
    /// pass `Instant::now()`.
    pub async fn admit(&self, n: &BlockedNotification<'_>, now: Instant) -> bool {
        // Suppression keys on `(policy_id, p_0)`. Events without a
        // matched policy id (Layer-A invariant breaks, read-filter
        // blocks) don't participate — they're rare enough that
        // suppression is unnecessary, and they shouldn't be collapsed
        // together since they represent distinct attack signals.
        let Some(policy_id) = n.policy_id.map(|s| s.to_string()) else {
            return true;
        };
        // Resolve per-policy threshold/window. Looked up on every call
        // so a `policy.yaml` reload affects in-flight bursts.
        let cfg = self.config_for(&policy_id);
        let key = (policy_id.clone(), n.p_0.map(|s| s.to_string()));
        let mut buckets = self.buckets.lock().await;
        let bucket = buckets.entry(key.clone()).or_default();
        bucket.prune(now, cfg.window);
        if bucket.timestamps.len() < cfg.threshold {
            bucket.timestamps.push(now);
            true
        } else {
            bucket.suppressed += 1;
            if bucket.first_suppressed.is_none() {
                bucket.first_suppressed = Some(SuppressedEvent {
                    policy_id,
                    p_0: n.p_0.map(|s| s.to_string()),
                    vendor: n.vendor.to_string(),
                    action: n.action.to_string(),
                    layer: n.layer.to_string(),
                });
            }
            metrics::counter!(
                "proxilion_notifier_suppressed_total",
                "policy_id" => key.0.clone()
            )
            .increment(1);
            false
        }
    }

    /// Drain any buckets that suppressed events. Each returned summary
    /// should be forwarded as a single notification by the caller. Resets
    /// `suppressed` and `first_suppressed` on the drained buckets.
    pub async fn drain_summaries(&self) -> Vec<BurstSummary> {
        let mut buckets = self.buckets.lock().await;
        let mut out = Vec::new();
        for ((policy_id, p_0), b) in buckets.iter_mut() {
            if b.suppressed == 0 {
                continue;
            }
            // Look up per-policy window to report on the summary envelope.
            let cfg = self.config_for(policy_id);
            out.push(BurstSummary {
                schema: BurstSummary::SCHEMA,
                policy_id: policy_id.clone(),
                p_0: p_0.clone(),
                suppressed_count: b.suppressed,
                window_seconds: cfg.window.as_secs(),
                exemplar: b.first_suppressed.clone(),
                details_url: String::new(),
            });
            b.suppressed = 0;
            b.first_suppressed = None;
        }
        out
    }

    pub fn flush_interval(&self) -> Duration {
        self.default_cfg.flush_interval
    }
}

/// Background flush loop. Sends one synthetic POST per non-empty bucket
/// every `flush_interval`. Spawned by `server::run` when the notifier is
/// installed.
pub async fn spawn_flush_loop<F, Fut>(suppressor: BurstSuppressor, mut send_one: F)
where
    F: FnMut(BurstSummary) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let interval = suppressor.flush_interval();
    loop {
        tokio::time::sleep(interval).await;
        let summaries = suppressor.drain_summaries().await;
        if summaries.is_empty() {
            continue;
        }
        tracing::info!(count = summaries.len(), "flushing burst summaries");
        for s in summaries {
            send_one(s).await;
        }
    }
}

#[allow(dead_code)] // mirrors `metric_warn` shape; kept for forward consistency
fn debug_dump<T: std::fmt::Debug>(label: &str, v: &T) {
    warn!("{label}: {v:?}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn notification<'a>(
        policy_id: &'a str,
        p_0: &'a str,
        ops: &'a [String],
    ) -> BlockedNotification<'a> {
        BlockedNotification {
            schema: BlockedNotification::SCHEMA,
            blocked_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            p_0: Some(p_0),
            vendor: "google",
            action: "gmail.messages.send",
            method: "POST",
            path: "/gmail/v1/users/me/messages/send",
            layer: "policy",
            policy_id: Some(policy_id),
            detail: None,
            predecessor_pca_id: None,
            requested_ops: ops,
            approve_url: String::new(),
            reject_url: String::new(),
        }
    }

    #[tokio::test]
    async fn passes_through_below_threshold() {
        let s = BurstSuppressor::new(BurstConfig {
            threshold: 3,
            window: Duration::from_secs(60),
            flush_interval: Duration::from_secs(30),
        });
        let now = Instant::now();
        let ops: Vec<String> = vec![];
        for _ in 0..3 {
            let n = notification("gmail-ext", "alice@acme.com", &ops);
            assert!(s.admit(&n, now).await);
        }
    }

    #[tokio::test]
    async fn suppresses_above_threshold() {
        let s = BurstSuppressor::new(BurstConfig {
            threshold: 3,
            window: Duration::from_secs(60),
            flush_interval: Duration::from_secs(30),
        });
        let now = Instant::now();
        let ops: Vec<String> = vec![];
        for _ in 0..3 {
            let n = notification("gmail-ext", "alice@acme.com", &ops);
            assert!(s.admit(&n, now).await);
        }
        for _ in 0..7 {
            let n = notification("gmail-ext", "alice@acme.com", &ops);
            assert!(!s.admit(&n, now).await, "should suppress");
        }
        let summaries = s.drain_summaries().await;
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].suppressed_count, 7);
        assert_eq!(summaries[0].policy_id, "gmail-ext");
        assert_eq!(summaries[0].p_0.as_deref(), Some("alice@acme.com"));
        // Drain clears state.
        let again = s.drain_summaries().await;
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn separate_keys_are_independent() {
        let s = BurstSuppressor::new(BurstConfig {
            threshold: 2,
            window: Duration::from_secs(60),
            flush_interval: Duration::from_secs(30),
        });
        let now = Instant::now();
        let ops: Vec<String> = vec![];
        // alice fills her bucket.
        let na = notification("p", "alice@acme.com", &ops);
        assert!(s.admit(&na, now).await);
        assert!(s.admit(&na, now).await);
        assert!(!s.admit(&na, now).await);
        // bob is unaffected.
        let nb = notification("p", "bob@acme.com", &ops);
        assert!(s.admit(&nb, now).await);
        assert!(s.admit(&nb, now).await);
        assert!(!s.admit(&nb, now).await);
        let summaries = s.drain_summaries().await;
        assert_eq!(summaries.len(), 2);
    }

    #[tokio::test]
    async fn window_expiry_resets_bucket() {
        let s = BurstSuppressor::new(BurstConfig {
            threshold: 2,
            window: Duration::from_millis(50),
            flush_interval: Duration::from_secs(30),
        });
        let t0 = Instant::now();
        let ops: Vec<String> = vec![];
        let n = notification("p", "alice@acme.com", &ops);
        assert!(s.admit(&n, t0).await);
        assert!(s.admit(&n, t0).await);
        // Same instant → suppressed.
        assert!(!s.admit(&n, t0).await);
        // Window elapsed — bucket pruned, new event passes through.
        let t1 = t0 + Duration::from_millis(100);
        assert!(s.admit(&n, t1).await);
    }

    #[tokio::test]
    async fn missing_policy_id_is_not_suppressed() {
        let s = BurstSuppressor::new(BurstConfig {
            threshold: 1,
            window: Duration::from_secs(60),
            flush_interval: Duration::from_secs(30),
        });
        let now = Instant::now();
        let ops: Vec<String> = vec![];
        let mut n = notification("ignored", "alice@acme.com", &ops);
        n.policy_id = None;
        // Threshold is 1 but events with no policy_id bypass the
        // suppressor and always pass through.
        for _ in 0..5 {
            assert!(s.admit(&n, now).await);
        }
        assert!(s.drain_summaries().await.is_empty());
    }

    #[tokio::test]
    async fn per_policy_resolver_overrides_threshold() {
        // Global default threshold is 50; resolver returns 2 for policy "p".
        let resolver: BurstResolver = Arc::new(|pid| {
            if pid == "p" {
                Some((Some(2), None))
            } else {
                None
            }
        });
        let s = BurstSuppressor::new(BurstConfig::default()).with_resolver(resolver);
        let now = Instant::now();
        let ops: Vec<String> = vec![];
        let n = notification("p", "alice@acme.com", &ops);
        // First two pass through, third is suppressed (threshold=2 from resolver).
        assert!(s.admit(&n, now).await);
        assert!(s.admit(&n, now).await);
        assert!(!s.admit(&n, now).await);
    }

    #[tokio::test]
    async fn resolver_window_override_changes_pruning() {
        // Default window 60s; resolver narrows to 0s so every event prunes
        // the bucket — threshold of 1 means second event still passes.
        let resolver: BurstResolver = Arc::new(|_| Some((Some(1), Some(0))));
        let s = BurstSuppressor::new(BurstConfig::default()).with_resolver(resolver);
        let ops: Vec<String> = vec![];
        let n = notification("p", "alice@acme.com", &ops);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(1);
        assert!(s.admit(&n, t0).await);
        // With window=0, the previous timestamp is immediately pruned, so
        // this also passes.
        assert!(s.admit(&n, t1).await);
    }

    #[test]
    fn details_url_round_trip() {
        let s = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "gmail-external".into(),
            p_0: Some("alice@acme.com".into()),
            suppressed_count: 5,
            window_seconds: 60,
            exemplar: None,
            details_url: String::new(),
        }
        .with_details_url("https://proxy.local/");
        assert_eq!(
            s.details_url,
            "https://proxy.local/api/v1/blocked?policy_id=gmail%2Dexternal&p_0=alice%40acme%2Ecom"
        );
    }

    #[test]
    fn details_url_empty_base_is_noop() {
        let s = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "p".into(),
            p_0: None,
            suppressed_count: 1,
            window_seconds: 60,
            exemplar: None,
            details_url: String::new(),
        }
        .with_details_url("");
        assert!(s.details_url.is_empty());
    }

    #[test]
    fn details_url_omits_p_0_when_absent() {
        let s = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "p".into(),
            p_0: None,
            suppressed_count: 1,
            window_seconds: 60,
            exemplar: None,
            details_url: String::new(),
        }
        .with_details_url("https://proxy.local");
        assert_eq!(
            s.details_url,
            "https://proxy.local/api/v1/blocked?policy_id=p"
        );
    }

    #[test]
    fn burst_config_default_pins_documented_threshold_window_and_flush() {
        // The doc-comment commits to "defaults to threshold=50, window=60s,
        // flush_interval=30s" — operators who omit the env override read
        // these numbers out of the troubleshooting docs. A regression that
        // bumped the threshold to 100 (a tempting "more headroom" change)
        // would silently change suppression behavior for every existing
        // install on next restart.
        let c = BurstConfig::default();
        assert_eq!(c.threshold, 50);
        assert_eq!(c.window, Duration::from_secs(60));
        assert_eq!(c.flush_interval, Duration::from_secs(30));
    }

    #[test]
    fn burst_summary_schema_is_versioned_string_consumers_key_on() {
        // Webhook / Slack receivers route on the schema string and may
        // parse v2 differently — the `.v1` suffix is the forward-compat
        // axis. A regression that bumped without coordinating downstream
        // would silently drop summary deliveries.
        assert_eq!(BurstSummary::SCHEMA, "proxilion.blocked_action_burst.v1");
        assert!(BurstSummary::SCHEMA.ends_with(".v1"));
    }

    #[test]
    fn burst_summary_json_skips_empty_details_url_via_serde_attr() {
        // `#[serde(skip_serializing_if = "String::is_empty")]` on
        // `details_url` is load-bearing — receivers test key-presence to
        // decide whether to render the "Open full list" button. A drift
        // to always-serialize would silently render a button pointing at
        // the empty string for test fixtures / installs without a public
        // URL configured.
        let s = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "p".into(),
            p_0: None,
            suppressed_count: 1,
            window_seconds: 60,
            exemplar: None,
            details_url: String::new(),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert!(
            v.get("details_url").is_none(),
            "empty url must be elided: {v}"
        );
        // Symmetric: non-empty url survives.
        let s2 = BurstSummary {
            details_url: "https://x/y".into(),
            ..s
        };
        let v2 = serde_json::to_value(&s2).unwrap();
        assert_eq!(v2["details_url"], "https://x/y");
    }

    #[test]
    fn details_url_collapses_multiple_trailing_slashes_in_base() {
        // `trim_end_matches('/')` strips ALL trailing slashes — an
        // operator who configures `https://proxy.local///` (a common
        // typo when concatenating environment-variable fragments)
        // must still produce a single-slash join, not `///api/v1/...`.
        let s = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "p".into(),
            p_0: None,
            suppressed_count: 1,
            window_seconds: 60,
            exemplar: None,
            details_url: String::new(),
        }
        .with_details_url("https://proxy.local///");
        assert_eq!(
            s.details_url,
            "https://proxy.local/api/v1/blocked?policy_id=p"
        );
    }

    #[test]
    fn flush_interval_round_trips_through_getter() {
        // The `spawn_flush_loop` task drives its ticker off this value —
        // a regression that hard-coded a default inside the getter
        // (instead of returning the configured one) would silently make
        // per-install flush-interval overrides no-ops.
        let s = BurstSuppressor::new(BurstConfig {
            threshold: 1,
            window: Duration::from_secs(60),
            flush_interval: Duration::from_secs(7),
        });
        assert_eq!(s.flush_interval(), Duration::from_secs(7));
    }

    #[tokio::test]
    async fn burst_suppressor_clone_shares_bucket_state() {
        // Clones must share the underlying `Arc<Mutex<HashMap<…>>>` so
        // both the notifier (which calls `admit`) and the flush loop
        // (which calls `drain_summaries`) see the same buckets. A
        // regression that deep-copied the buckets would leave the flush
        // loop forever empty even as suppression accrued on the notifier
        // side.
        let s = BurstSuppressor::new(BurstConfig {
            threshold: 1,
            window: Duration::from_secs(60),
            flush_interval: Duration::from_secs(30),
        });
        let s2 = s.clone();
        let now = Instant::now();
        let ops: Vec<String> = vec![];
        let n = notification("p", "alice@acme.com", &ops);
        // Fire admit on the original, drain on the clone.
        assert!(s.admit(&n, now).await);
        assert!(!s.admit(&n, now).await); // suppressed
        let summaries = s2.drain_summaries().await;
        assert_eq!(summaries.len(), 1, "clone must see same buckets");
        assert_eq!(summaries[0].suppressed_count, 1);
    }

    #[test]
    fn urlencoding_encode_percent_encodes_non_alphanumeric_bytes_per_byte() {
        // The helper powers `details_url`'s query-value escaping; the
        // existing `details_url_round_trip` test exercises it indirectly
        // via the full URL, but the per-byte contract (NON_ALPHANUMERIC
        // alphabet — every non-A-Za-z0-9 byte encodes, including `-`
        // `.` `_` that some encoder alphabets pass through) is the
        // load-bearing invariant. A refactor that switched to
        // `CONTROLS` or `PATH` would silently leak commas / colons
        // into the query string and break receivers that key on the
        // exact percent-encoded shape. Pin three distinct boundary
        // shapes here directly.
        // 1. Alphanumeric passes through unchanged (the unreserved
        //    subset of NON_ALPHANUMERIC).
        assert_eq!(urlencoding_encode("abc123XYZ"), "abc123XYZ");
        // 2. Common policy-id punctuation `-` `.` `_` `:` `@` all
        //    percent-encoded (NON_ALPHANUMERIC encodes everything
        //    outside `[A-Za-z0-9]`, including ASCII unreserved).
        assert_eq!(urlencoding_encode("a-b.c_d:e@f"), "a%2Db%2Ec%5Fd%3Ae%40f");
        // 3. Multibyte UTF-8 encodes per-byte, not per-codepoint —
        //    `é` (C3 A9) → `%C3%A9` so a future internationalized
        //    policy id is wire-safe ASCII regardless of input.
        assert_eq!(urlencoding_encode("é"), "%C3%A9");
    }

    #[tokio::test]
    async fn resolver_threshold_none_keeps_default_window_override() {
        // The third resolver shape `(None, Some(w))` keeps the global
        // threshold and overrides only the window. Existing tests
        // cover `(Some(t), None)` and `(Some(t), Some(0))` but the
        // window-only branch — operationally useful when an operator
        // wants the same suppression cap but a longer / shorter
        // settling period for a noisy policy — was never directly
        // pinned. A refactor that "unified" the two arms (e.g. via
        // a single `.unwrap_or(default_window)` path that bypassed
        // the threshold-keep branch) would surface here.
        let resolver: BurstResolver = Arc::new(|_| Some((None, Some(0))));
        // Global default threshold = 50; resolver narrows window to 0.
        let s = BurstSuppressor::new(BurstConfig::default()).with_resolver(resolver);
        let ops: Vec<String> = vec![];
        let n = notification("p", "alice@acme.com", &ops);
        // With window=0 every prior timestamp is immediately pruned,
        // so each call resets the bucket — the threshold of 50 is
        // never exceeded. Fire 60 events; all admit.
        let t0 = Instant::now();
        for i in 0..60 {
            let t = t0 + Duration::from_millis(i);
            assert!(s.admit(&n, t).await, "event {i} unexpectedly suppressed");
        }
    }

    #[tokio::test]
    async fn drain_summaries_initially_empty_returns_empty_vec() {
        // Boundary: a fresh suppressor that has never admitted an event
        // must drain to an empty Vec. The existing `suppresses_above_threshold`
        // test covers post-drain (after the first drain clears state)
        // but never the pre-first-call case — the `b.suppressed == 0`
        // skip branch is the only thing standing between a no-op flush
        // tick and a spurious notification fan-out. A regression that
        // emitted a synthetic "(no events)" summary on every flush would
        // silently spam every operator's webhook receiver with empty
        // bursts.
        let s = BurstSuppressor::new(BurstConfig::default());
        let summaries = s.drain_summaries().await;
        assert!(
            summaries.is_empty(),
            "fresh suppressor must drain empty, got: {summaries:?}"
        );
    }

    #[test]
    fn burst_summary_exemplar_some_serializes_with_stable_struct_keys() {
        // The existing serialization tests pin `details_url` key
        // presence/absence but the `exemplar` field's nested struct
        // shape (`SuppressedEvent { policy_id, p_0, vendor, action,
        // layer }`) was never directly asserted on the wire. Webhook
        // / Slack receivers render the exemplar block as a 5-field
        // preview — a rename of any inner field would silently break
        // the template. Pin the full key set so a future field rename
        // surfaces here as a wire-shape change.
        let s = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "p".into(),
            p_0: Some("alice@acme.com".into()),
            suppressed_count: 9,
            window_seconds: 60,
            exemplar: Some(SuppressedEvent {
                policy_id: "p".into(),
                p_0: Some("alice@acme.com".into()),
                vendor: "google".into(),
                action: "gmail.messages.send".into(),
                layer: "policy".into(),
            }),
            details_url: String::new(),
        };
        let v = serde_json::to_value(&s).unwrap();
        let ex = v["exemplar"].as_object().expect("exemplar must be object");
        assert!(ex.contains_key("policy_id"));
        assert!(ex.contains_key("p_0"));
        assert!(ex.contains_key("vendor"));
        assert!(ex.contains_key("action"));
        assert!(ex.contains_key("layer"));
        assert_eq!(ex["vendor"], "google");
        assert_eq!(ex["action"], "gmail.messages.send");
    }

    #[test]
    fn bucket_prune_drops_only_timestamps_outside_window_keeps_boundary_inclusive() {
        // `Bucket::prune` is the private helper `admit` calls on every
        // hot-path arrival. The boundary contract is `now - t <= window`
        // (inclusive on the window upper bound) — a regression to strict
        // `<` would silently shrink the window by one tick on every
        // suppressor and start passing through events that should have
        // been counted in the prior window. Existing tests exercised the
        // overall window-expiry path via admit() with sleeps; this test
        // calls prune directly with constructed Instants so the boundary
        // is checked deterministically without thread-timing flake.
        let window = Duration::from_secs(60);
        let now = Instant::now();
        let mut b = Bucket {
            timestamps: vec![
                now - Duration::from_secs(120), // outside window: drop
                now - Duration::from_secs(61),  // outside window (just): drop
                now - Duration::from_secs(60),  // boundary inclusive: keep
                now - Duration::from_secs(30),  // inside: keep
                now,                            // present moment: keep
            ],
            suppressed: 0,
            first_suppressed: None,
        };
        b.prune(now, window);
        assert_eq!(
            b.timestamps.len(),
            3,
            "60s boundary must be inclusive; 61s and 120s must be dropped",
        );
    }

    #[test]
    fn config_for_with_no_resolver_returns_default_unchanged() {
        // `config_for` is called per-admit; the no-resolver branch is the
        // most-common production shape (no per-policy YAML override). The
        // existing resolver tests cover both override axes but never assert
        // that the default config flows through verbatim when no resolver
        // is attached — a regression that pre-populated a "safe" override
        // here would silently shadow operator-configured defaults.
        let default = BurstConfig {
            threshold: 7,
            window: Duration::from_secs(13),
            flush_interval: Duration::from_secs(17),
        };
        let s = BurstSuppressor::new(default);
        let resolved = s.config_for("any-policy-id");
        assert_eq!(resolved.threshold, 7);
        assert_eq!(resolved.window, Duration::from_secs(13));
        assert_eq!(resolved.flush_interval, Duration::from_secs(17));
    }

    #[test]
    fn with_details_url_url_encodes_reserved_chars_in_policy_id_and_p_0() {
        // The percent-encoding happens via `urlencoding_encode` which uses
        // NON_ALPHANUMERIC — round 64 pinned the helper directly, but the
        // composed `with_details_url` path never round-tripped a
        // reserved-char-bearing policy_id + p_0 pair through to the wire
        // URL. A regression that bypassed the encoder for either segment
        // (e.g. switched to `format!("{policy_id}")` for "readability")
        // would silently break every deep link with a `&` or `?` in the
        // policy id (real-world: composed policy ids like
        // "team-a/share?audit" used by tenants that name policies after
        // owning team + intent).
        let s = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "team-a/share?audit".into(),
            p_0: Some("alice+suffix@acme.com".into()),
            suppressed_count: 1,
            window_seconds: 60,
            exemplar: None,
            details_url: String::new(),
        }
        .with_details_url("https://proxy.local");
        assert!(
            s.details_url.contains("policy_id=team%2Da%2Fshare%3Faudit"),
            "policy_id reserved chars must be percent-encoded: {}",
            s.details_url,
        );
        assert!(
            s.details_url.contains("p_0=alice%2Bsuffix%40acme%2Ecom"),
            "p_0 reserved chars must be percent-encoded: {}",
            s.details_url,
        );
    }

    #[tokio::test]
    async fn summary_carries_exemplar() {
        let s = BurstSuppressor::new(BurstConfig {
            threshold: 1,
            window: Duration::from_secs(60),
            flush_interval: Duration::from_secs(30),
        });
        let now = Instant::now();
        let ops: Vec<String> = vec![];
        let n = notification("p", "alice@acme.com", &ops);
        assert!(s.admit(&n, now).await); // first one passes
        assert!(!s.admit(&n, now).await); // second one suppressed
        let summaries = s.drain_summaries().await;
        assert_eq!(summaries.len(), 1);
        let ex = summaries[0].exemplar.as_ref().unwrap();
        assert_eq!(ex.vendor, "google");
        assert_eq!(ex.action, "gmail.messages.send");
        assert_eq!(ex.layer, "policy");
        assert_eq!(ex.policy_id, "p");
    }
}
