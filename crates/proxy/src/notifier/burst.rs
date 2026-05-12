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
