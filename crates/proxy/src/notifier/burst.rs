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

    #[test]
    fn burst_suppressor_and_summary_and_event_and_config_all_send_sync_static() {
        // The four public types in this module flow across boundaries:
        // `BurstSuppressor` is held in AppState and cloned into the
        // flush-loop tokio::spawn; `BurstSummary` and `SuppressedEvent`
        // are passed across .await points in the send_one fan-out path;
        // `BurstConfig` is constructed at boot and held by value in the
        // suppressor. All four MUST be Send+Sync+'static — a refactor
        // adding an `Rc<...>` field "for cheap clone" on any one would
        // break Send at the AppState wire site rather than at this file
        // with an opaque tower::Service trait-bound. Pin all four at
        // compile time.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<BurstSuppressor>();
        require_send_sync_static::<BurstSummary>();
        require_send_sync_static::<SuppressedEvent>();
        require_send_sync_static::<BurstConfig>();
    }

    #[test]
    fn burst_summary_schema_field_is_static_str_lifetime_via_require_static_str() {
        // `schema: &'static str` lives in the read-only binary segment;
        // the existing `burst_summary_schema_is_versioned_string_consumers_key_on`
        // pin checks the literal byte sequence but NOT the lifetime
        // bound. A refactor to `schema: String` "for ergonomic
        // version-from-env runtime selection" would silently
        // heap-allocate on every burst summary emit AND break the
        // free-clone the FnMut send_one path depends on. Pin the
        // `&'static str` lifetime contract via a fn helper that takes
        // `&'static str` only — type coercion alone catches the drift.
        fn require_static_str(_: &'static str) {}
        require_static_str(BurstSummary::SCHEMA);
        // And the constructed-summary field surfaces the same static
        // pointer (not a heap-allocated copy via `into()`).
        let s = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "p".into(),
            p_0: None,
            suppressed_count: 0,
            window_seconds: 0,
            exemplar: None,
            details_url: String::new(),
        };
        require_static_str(s.schema);
    }

    #[test]
    fn burst_summary_serialized_json_object_carries_six_keys_when_details_url_empty_seven_when_set()
    {
        // The struct has 7 fields total (`schema`, `policy_id`, `p_0`,
        // `suppressed_count`, `window_seconds`, `exemplar`, `details_url`)
        // but `details_url` carries `skip_serializing_if = "String::is_empty"`.
        // Pin BOTH the elided-key count AND the all-set count so a
        // refactor that flipped the skip predicate to
        // `Option::is_none` "for consistency" (or wrapped the field in
        // `Option<String>` to match) would silently change the wire
        // shape between empty and absent. The existing
        // `burst_summary_json_skips_empty_details_url_via_serde_attr`
        // pin checks key-presence only; widen to exact count.
        let empty = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "p".into(),
            p_0: None,
            suppressed_count: 0,
            window_seconds: 0,
            exemplar: None,
            details_url: String::new(),
        };
        let v = serde_json::to_value(&empty).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 6, "details_url empty must elide: {obj:?}");
        for k in [
            "schema",
            "policy_id",
            "p_0",
            "suppressed_count",
            "window_seconds",
            "exemplar",
        ] {
            assert!(obj.contains_key(k), "missing key {k}");
        }
        // Symmetric: with details_url set, the count becomes 7.
        let with_url = BurstSummary {
            details_url: "https://x/y".into(),
            ..empty
        };
        let v2 = serde_json::to_value(&with_url).unwrap();
        let obj2 = v2.as_object().unwrap();
        assert_eq!(obj2.len(), 7, "details_url set must surface: {obj2:?}");
        assert!(obj2.contains_key("details_url"));
    }

    #[test]
    fn suppressed_event_serialized_json_object_carries_exactly_five_keys_no_skip_predicates() {
        // The struct has 5 fields (policy_id, p_0, vendor, action,
        // layer) and NO skip-serializing attrs — every field surfaces
        // verbatim. Symmetric to the BurstSummary count pin: a refactor
        // that swapped `policy_id: String` for `Option<String>` "for
        // future read-filter compatibility" plus a skip-if-none attr
        // would silently change the wire object's key count and break
        // Slack-template renderers that iterate the 5 fields by name.
        // Pin EXACTLY 5 keys with no skip-elision across both Some and
        // None for the only Option field (`p_0`).
        for p_0 in [Some("alice@acme.com".to_string()), None] {
            let ev = SuppressedEvent {
                policy_id: "p".into(),
                p_0,
                vendor: "google".into(),
                action: "drive.files.get".into(),
                layer: "policy".into(),
            };
            let v = serde_json::to_value(&ev).unwrap();
            let obj = v
                .as_object()
                .expect("SuppressedEvent must be a JSON object");
            assert_eq!(obj.len(), 5, "field count drift: {obj:?}");
            for k in ["policy_id", "p_0", "vendor", "action", "layer"] {
                assert!(obj.contains_key(k), "missing key {k}: {obj:?}");
            }
        }
    }

    #[test]
    fn burst_config_clone_yields_byte_equal_independent_value() {
        // `#[derive(Clone, Debug)]` on BurstConfig — clone must yield a
        // logically-equivalent value with all three fields byte-equal,
        // AND mutating one clone MUST NOT affect the other (the three
        // fields are owned primitives, so this is trivially true today
        // — but pin both axes so a refactor to `Arc<...>`-shared
        // fields "for cheap clone in a hot loop" would surface as a
        // mutation-leak between clones).
        let a = BurstConfig {
            threshold: 25,
            window: Duration::from_secs(45),
            flush_interval: Duration::from_secs(15),
        };
        let mut b = a.clone();
        assert_eq!(a.threshold, b.threshold);
        assert_eq!(a.window, b.window);
        assert_eq!(a.flush_interval, b.flush_interval);
        // Mutate b — a must be unaffected.
        b.threshold = 999;
        b.window = Duration::from_secs(1);
        b.flush_interval = Duration::from_secs(1);
        assert_eq!(a.threshold, 25);
        assert_eq!(a.window, Duration::from_secs(45));
        assert_eq!(a.flush_interval, Duration::from_secs(15));
        // Sanity that the mutation landed on b (also satisfies the
        // unused-assignments lint — without reading the post-mutation
        // values, clippy flags the assigns as dead stores).
        assert_eq!(b.threshold, 999);
        assert_eq!(b.window, Duration::from_secs(1));
        assert_eq!(b.flush_interval, Duration::from_secs(1));
    }

    #[test]
    fn urlencoding_encode_empty_string_returns_empty_string_boundary() {
        // The helper feeds `with_details_url`'s query-value escaping;
        // a boundary input of `""` must return `""` (NOT a sentinel
        // like `%00` and NOT panic). The existing pins exercise
        // non-empty strings only — pin the empty boundary so a
        // refactor that pre-encoded a leading nul-byte "for path
        // safety" would surface here. Also pin a single-space string
        // (a frequent operator-typo input from CLI pastes) encodes to
        // `%20` (the canonical query-space encoding under
        // NON_ALPHANUMERIC).
        assert_eq!(urlencoding_encode(""), "");
        assert_eq!(urlencoding_encode(" "), "%20");
        // Tab and newline also encode (control chars in
        // NON_ALPHANUMERIC).
        assert_eq!(urlencoding_encode("\t"), "%09");
        assert_eq!(urlencoding_encode("\n"), "%0A");
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

    // ─── round 199 (2026-05-20): BurstConfig + Summary + Event field-type surfaces ───

    #[test]
    fn burst_config_field_types_threshold_usize_window_duration_flush_interval_duration() {
        // `BurstConfig` has 3 fields: `threshold: usize` (matches
        // `Vec::len()`-style count comparison in the suppressor's
        // `bucket.timestamps.len() < cfg.threshold` predicate),
        // `window: Duration` (matches `Instant::duration_since(...) <=
        // window` arithmetic), `flush_interval: Duration` (passed to
        // `tokio::time::sleep` in the flush-loop spawn). A refactor of
        // any field to a unit-stripped numeric type "for simpler config
        // parsing" would force a re-construction at every usage site
        // AND lose the unit-information at the type level. Pin each
        // field via the canonical require_* helper. Symmetric to
        // round-196 DEFAULT_TICK_INTERVAL Duration + round-188
        // ListResponse.policy_count usize + round-197 Scenario.status
        // u16 type pins extended to this BurstConfig shape.
        fn require_usize(_: usize) {}
        fn require_duration(_: Duration) {}
        let cfg = BurstConfig::default();
        require_usize(cfg.threshold);
        require_duration(cfg.window);
        require_duration(cfg.flush_interval);
    }

    #[test]
    fn suppressed_event_four_owned_string_fields_and_p_0_option_string_for_cross_await_outlives() {
        // `SuppressedEvent` has 5 fields: 4 owned `String`
        // (policy_id / vendor / action / layer — all built from
        // `BlockedNotification` borrowed `&str` via `.to_string()`
        // inside `admit()`) and 1 `Option<String>` (p_0). The
        // exemplar is stashed in `Bucket.first_suppressed:
        // Option<SuppressedEvent>` which outlives the
        // BlockedNotification borrow that constructed it — every
        // field MUST be owned (not borrowed) to survive the cross-
        // await drain. A refactor that left any field as `&str`
        // "for zero-alloc on the rare-suppress path" would force a
        // lifetime parameter on SuppressedEvent that breaks the
        // Bucket-stash contract. Pin owned-String on the 4 always-
        // present fields + Option<String> on p_0. Symmetric to
        // round-189 ListRow 6-field + round-196 EscalationRow
        // owned-String sweeps extended to this exemplar-event shape.
        fn require_string(_: &String) {}
        fn require_opt_string(_: &Option<String>) {}
        let ev = SuppressedEvent {
            policy_id: "gmail-ext".into(),
            p_0: Some("alice@acme.com".into()),
            vendor: "google".into(),
            action: "gmail.messages.send".into(),
            layer: "policy".into(),
        };
        require_string(&ev.policy_id);
        require_string(&ev.vendor);
        require_string(&ev.action);
        require_string(&ev.layer);
        require_opt_string(&ev.p_0);
    }

    #[test]
    fn burst_summary_count_fields_suppressed_count_and_window_seconds_both_u64_type() {
        // `BurstSummary.suppressed_count: u64` matches the
        // `Bucket.suppressed: u64` field's type — pin both flow
        // through the type system identically. `window_seconds:
        // u64` matches `Duration::as_secs() -> u64`'s return type
        // at the assignment site `window_seconds: cfg.window.as_secs()`.
        // A refactor of either to `u32` "for narrower telemetry
        // labels" would silently introduce a truncation hazard on
        // the cast site (the suppressed counter could overflow
        // u32 in pathological multi-hour bursts; window_seconds
        // would clip beyond ~136 years which is theoretical but
        // breaks the type-system contract regardless). Pin via
        // require_u64. Symmetric to round-196 ExpirySweepReport.
        // expired_rows + round-190 KillResponse.bearers_revoked u64
        // type pins extended to this sibling summary shape's two
        // u64 fields.
        fn require_u64(_: u64) {}
        let summary = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "p".into(),
            p_0: None,
            suppressed_count: 42,
            window_seconds: 60,
            exemplar: None,
            details_url: String::new(),
        };
        require_u64(summary.suppressed_count);
        require_u64(summary.window_seconds);
    }

    #[tokio::test]
    async fn burst_suppressor_admit_return_type_is_bool_not_result_for_infallible_decision_path() {
        // `admit()` returns `bool` (true=pass-through, false=suppressed)
        // — NOT `Result<bool, _>`. The notifier hot path is documented
        // as infallible (the suppressor never panics, never errors —
        // the worst case is a lock-contention spike under heavy
        // concurrent bursts which surfaces as latency, not as an
        // error to handle). A refactor that promoted to `Result<bool,
        // SuppressorError>` "for future rate-limiter wiring" would
        // break every notifier call site (which today drops the bool
        // into an `if admit { send } else { drop }` shape without `?`).
        // Pin via require_bool. Symmetric to round-192 slack helpers
        // unit-return pins extended to this hot-path decision return.
        fn require_bool(_: bool) {}
        let s = BurstSuppressor::new(BurstConfig {
            threshold: 1,
            window: Duration::from_secs(60),
            flush_interval: Duration::from_secs(30),
        });
        let ops: Vec<String> = vec![];
        let n = notification("p", "alice@acme.com", &ops);
        let result = s.admit(&n, Instant::now()).await;
        require_bool(result);
    }

    #[tokio::test]
    async fn burst_suppressor_drain_summaries_return_type_is_owned_vec_burst_summary() {
        // `drain_summaries()` returns `Vec<BurstSummary>` — owned,
        // not a borrowed slice (`&'a [BurstSummary]`). The summaries
        // flow to `WebhookNotifier::flush_summaries` across `.await`
        // boundaries to be POSTed to the operator webhook one at a
        // time; the Vec must own its contents to survive past the
        // suppressor's Mutex<HashMap<_, Bucket>> lock release that
        // happens at the end of `drain_summaries`. A refactor to
        // `&'a [BurstSummary]` "for zero-copy on small drains" would
        // force the caller to hold the Mutex guard across the
        // network I/O — turning the suppressor into a serialization
        // bottleneck under burst load. Pin via require_vec_burst_summary.
        // Symmetric to round-196 EscalationRow.requested_ops Vec<String>
        // owned + round-191 SetupStatus.items Vec<CheckItem> owned
        // pins extended to this sibling owned-Vec return.
        fn require_vec_burst_summary(_: &Vec<BurstSummary>) {}
        let s = BurstSuppressor::new(BurstConfig::default());
        let summaries = s.drain_summaries().await;
        require_vec_burst_summary(&summaries);
    }

    #[test]
    fn burst_summary_three_owned_string_fields_for_cross_await_drain_outlives_mutex_guard() {
        // `BurstSummary.policy_id`, `BurstSummary.details_url`, and
        // `BurstSummary.p_0` (the inner String when Some) — all 3
        // String-shaped fields are OWNED, NOT borrowed. The summary
        // flows from `drain_summaries()` (where the Mutex guard is
        // dropped at function-end) through the notifier fan-out's
        // `.await` chain. A refactor to `&'a str` for "zero-copy
        // from the HashMap key" would force the lifetime parameter
        // through every consuming notifier crossing .await. The
        // existing `suppressed_event_four_owned_string_fields_...`
        // pin (above) walks the sibling SuppressedEvent shape; pin
        // the BurstSummary shape here in symmetric form. Symmetric
        // to round-191 CheckItem.detail owned-String pin extended
        // to this sibling notification-payload shape.
        fn require_string(_: &String) {}
        fn require_opt_string(_: &Option<String>) {}
        let summary = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "gmail-ext".into(),
            p_0: Some("alice@acme.com".into()),
            suppressed_count: 7,
            window_seconds: 60,
            exemplar: None,
            details_url: "https://proxy.example/api/v1/blocked?policy_id=gmail-ext".into(),
        };
        require_string(&summary.policy_id);
        require_string(&summary.details_url);
        require_opt_string(&summary.p_0);
    }

    // ─── round 235 (2026-05-22): BurstConfig + Bucket + BurstSuppressor +
    // SuppressedEvent + BurstSummary exhaustive destructure, new() Self
    // by-value pin ───

    #[test]
    fn burst_config_field_count_pinned_at_exactly_three_via_exhaustive_destructure_no_rest_pattern()
    {
        // `BurstConfig { threshold, window, flush_interval }` — exactly
        // 3 fields. A 4th field landing (e.g. `summary_throttle: Option
        // <Duration>` for rate-limiting summary emissions themselves,
        // OR `per_bucket_max: Option<usize>` for memory bounding on a
        // long-running suppressor) without matching `Default::default()`
        // construction would silently leave the new field zero-defaulted
        // on every freshly-built suppressor. The exhaustive destructure
        // with no `..` rest pattern forces a 4th field to update this
        // site in lockstep with `Default`. Symmetric to the
        // FilterOutcome 4-field + QuarantineSample 2-field +
        // CompiledFilter 3-field exhaustive-destructure pins.
        let cfg = BurstConfig::default();
        let BurstConfig {
            threshold: _,
            window: _,
            flush_interval: _,
        } = cfg;
    }

    #[test]
    fn bucket_field_count_pinned_at_exactly_three_via_exhaustive_destructure_no_rest_pattern() {
        // `Bucket { timestamps, suppressed, first_suppressed }` — module-
        // private holder type with exactly 3 fields. A 4th field landing
        // (e.g. `last_seen: Option<Instant>` for staleness eviction, OR
        // `policy_id_cache: Option<String>` to avoid re-keying the
        // HashMap entry on every prune call) without matching
        // construction sites in `admit()` / `flush_summaries()` would
        // silently leave the new field default-initialized on every
        // bucket created. The exhaustive destructure forces a 4th
        // field to update this site in lockstep with the per-call
        // construction. Symmetric to the Inner 3-field pin in cat_key.rs
        // round 233 extended to this sibling module-private holder.
        let b = Bucket::default();
        let Bucket {
            timestamps: _,
            suppressed: _,
            first_suppressed: _,
        } = b;
    }

    #[test]
    fn burst_suppressor_field_count_pinned_at_exactly_three_via_exhaustive_destructure_no_rest() {
        // `BurstSuppressor { default_cfg, resolver, buckets }` — exactly
        // 3 fields. A 4th field landing (e.g. `metrics_label: String` for
        // per-suppressor metric bucketing OR `audit_pipe: Option<Sender>`
        // for surfacing every suppression to the audit log) without
        // matching `new()` constructor wiring would silently leave the
        // new field zero-initialized on every suppressor handed out.
        // The exhaustive destructure forces a 4th field to update this
        // site in lockstep with `new()`. Symmetric to the TeeStream
        // 2-field + KillCache 1-field + SlackNotifier 6-field
        // exhaustive-destructure pins.
        let s = BurstSuppressor::new(BurstConfig::default());
        let BurstSuppressor {
            default_cfg: _,
            resolver: _,
            buckets: _,
        } = s;
    }

    #[test]
    fn suppressed_event_field_count_pinned_at_exactly_five_via_exhaustive_destructure_no_rest() {
        // `SuppressedEvent { policy_id, p_0, vendor, action, layer }` —
        // exactly 5 fields. A 6th field landing (e.g. `detail: Option<
        // String>` to surface a representative match reason on the
        // exemplar, OR `at: DateTime<Utc>` to timestamp the exemplar
        // pick) without matching the wire-shape contract (5-key JSON
        // object) would silently change the operator-facing summary
        // payload — Slack receivers iterating known keys would either
        // drop the new field OR raise a parse warning. The exhaustive
        // destructure forces a 6th field to update this site in
        // lockstep with the construction site. Symmetric to the
        // FederationClaims 8-field + GoogleClient 4-field
        // exhaustive-destructure pins extended to this exemplar shape.
        let e = SuppressedEvent {
            policy_id: "p".into(),
            p_0: None,
            vendor: "v".into(),
            action: "a".into(),
            layer: "l".into(),
        };
        let SuppressedEvent {
            policy_id: _,
            p_0: _,
            vendor: _,
            action: _,
            layer: _,
        } = e;
    }

    #[test]
    fn burst_summary_field_count_pinned_at_exactly_seven_via_exhaustive_destructure_no_rest() {
        // `BurstSummary { schema, policy_id, p_0, suppressed_count,
        // window_seconds, exemplar, details_url }` — exactly 7 fields.
        // The existing `burst_summary_serialized_json_object_carries_six_keys_when_details_url_empty_seven_when_set`
        // pin checks the WIRE shape via key counting at the JSON
        // boundary; pin the STRUCT shape via an exhaustive destructure
        // so an 8th field landing (e.g. `severity: Severity` for
        // tiered burst summaries, OR `details_link_label: String` for
        // operator-tunable button text) without matching construction
        // sites in `flush_summaries` / `with_details_url` would break
        // both the destructure AND the wire-key sweep in lockstep.
        // Symmetric to the TokenResponse 4-field + ErrorBody 6-field
        // exhaustive-destructure pins extended to this notification-
        // payload shape.
        let s = BurstSummary {
            schema: BurstSummary::SCHEMA,
            policy_id: "p".into(),
            p_0: None,
            suppressed_count: 0,
            window_seconds: 60,
            exemplar: None,
            details_url: String::new(),
        };
        let BurstSummary {
            schema: _,
            policy_id: _,
            p_0: _,
            suppressed_count: _,
            window_seconds: _,
            exemplar: _,
            details_url: _,
        } = s;
    }

    #[test]
    fn burst_suppressor_new_return_type_is_owned_self_by_value_via_fn_pointer_witness() {
        // `BurstSuppressor::new(BurstConfig) -> Self` is the constructor
        // AppState calls when wiring per-notifier burst suppression
        // (one per webhook/Slack/email driver). The value flows through
        // the fluent builder chain `BurstSuppressor::new(cfg).
        // with_resolver(r)` — both steps consume and return Self by
        // value. Pin via fn-pointer witness `fn(BurstConfig) ->
        // BurstSuppressor`. A refactor to `Arc<Self>` "for ergonomic
        // shared construction" would break the move-chain at the
        // `.with_resolver(r)` site AND would drop the AppState's own
        // Arc-wrap step. Symmetric to the KillCache::new +
        // TeeStream::new + CatKeyRegistry::new owned-Self fn-pointer
        // pins.
        let _f: fn(BurstConfig) -> BurstSuppressor = BurstSuppressor::new;
        fn require_owned_suppressor(_: BurstSuppressor) {}
        require_owned_suppressor(BurstSuppressor::new(BurstConfig::default()));
    }
}
