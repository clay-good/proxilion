//! Edge ingress abuse controls (production-readiness.md PR-2).
//!
//! PR-2 lands four resource-exhaustion controls on the agent-facing ingress.
//! The body cap (`DefaultBodyLimit`) and adapter timeout (`TimeoutLayer`) are
//! wired directly in [`crate::server`]; this module owns the remaining two:
//!
//!   * **Per-IP rate limit** — a dependency-free token bucket keyed by the
//!     *trusted-proxy-resolved* client IP. Over-quota → `429 Too Many
//!     Requests` with a `Retry-After` header. A flood from one source can't
//!     starve the policy/adapter hot path for everyone else.
//!   * **Global concurrency limit + load-shed** — a single `Semaphore` sized
//!     from the operator's CPU/pool budget. When all permits are in flight a
//!     new request is *shed* immediately with `503 Service Unavailable`
//!     (`try_acquire`, never a queue) rather than buffering into memory
//!     exhaustion under overload.
//!
//! Both are implemented as `axum::middleware::from_fn` layers (the same edge
//! style as `request_span` / `count_edge_rejections`) and feed the existing
//! `proxilion_ingress_rejections_total{reason}` counter, so the PR-5 burn-rate
//! alerts watch all four controls through one metric.
//!
//! **Why in-house and not `tower_governor`/`tower::load_shed`.** The
//! security-critical part is *which IP* the limiter keys on: trusting
//! `X-Forwarded-For` blindly (the default of the common extractors) lets any
//! caller spoof a fresh identity per request and defeat the limit entirely
//! (production-readiness.md PR-2 / PR-4 call this out explicitly). The
//! trusted-proxy model below — honor a forwarded header *only* when the direct
//! peer is a configured trusted proxy, otherwise key on the real socket peer —
//! is the whole point, and it's cleaner to own it than to bend a third-party
//! key extractor around it. Token bucket + semaphore need no new dependency
//! (tokio + moka are already in the tree), keeping the supply-chain gates
//! (`cargo deny` / `cargo audit`) untouched.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

const FORWARDED_FOR: &str = "x-forwarded-for";

// =====================================================================
// Trusted-proxy client-IP resolution
// =====================================================================

/// Resolve the client IP to rate-limit on, honoring `X-Forwarded-For`
/// **only** behind a configured trusted proxy.
///
/// - If `trusted_proxies` is empty (the secure default), the forwarded header
///   is ignored entirely and the direct socket peer is used. An untrusted
///   caller cannot spoof its identity.
/// - If the direct `peer` is a configured trusted proxy, walk the
///   `X-Forwarded-For` chain right-to-left and return the first address that
///   is **not** itself a trusted proxy — i.e. the real client as seen by the
///   outermost hop we trust. A spoofed prefix (attacker-supplied left entries)
///   is therefore ignored; only the segment appended by trusted infrastructure
///   is believed. Falls back to `peer` if the chain yields nothing usable.
/// - If the peer is not a trusted proxy, the forwarded header is ignored and
///   `peer` is used.
pub fn client_ip(headers: &HeaderMap, peer: IpAddr, trusted_proxies: &[IpAddr]) -> IpAddr {
    if trusted_proxies.is_empty() || !trusted_proxies.contains(&peer) {
        return peer;
    }
    let Some(xff) = headers.get(FORWARDED_FOR).and_then(|v| v.to_str().ok()) else {
        return peer;
    };
    // Right-to-left: skip hops we ourselves trust; the first untrusted entry
    // is the client the trusted edge observed. `XFF: client, proxy1, proxy2`.
    for raw in xff.split(',').rev() {
        let entry = raw.trim();
        // An entry may be `ip` or (rarely) `ip:port`; IPv6 in XFF is bare.
        let Ok(ip) = entry.parse::<IpAddr>() else {
            continue;
        };
        if !trusted_proxies.contains(&ip) {
            return ip;
        }
    }
    peer
}

// =====================================================================
// Per-IP rate limit — token bucket
// =====================================================================

/// A single refilling token bucket. `tokens` accrue at `rate` per second up
/// to `burst`; each admitted request spends one. Pure and time-injected so
/// the refill arithmetic is unit-testable without sleeping.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(burst: f64, now: Instant) -> Self {
        // Fresh clients start with a full burst allowance.
        Self {
            tokens: burst,
            last: now,
        }
    }

    /// Try to spend one token. `Ok(())` if admitted; `Err(wait)` with the
    /// time until the next token would be available if shed.
    fn try_spend(&mut self, now: Instant, rate: f64, burst: f64) -> Result<(), Duration> {
        // Refill for elapsed wall-clock, saturating at the burst ceiling.
        // `saturating_duration_since` guards against a non-monotonic `now`
        // in tests (and is a no-op on the monotonic clock in production).
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let deficit = 1.0 - self.tokens;
            Err(Duration::from_secs_f64(deficit / rate))
        }
    }
}

/// Per-IP token-bucket rate limiter. Buckets live in a `moka` cache with an
/// idle-eviction TTL and a capacity ceiling, so the limiter's own state is
/// bounded — a spray of distinct source IPs evicts oldest-idle rather than
/// growing without limit (which would itself be the DoS we're preventing).
pub struct RateLimiter {
    buckets: moka::future::Cache<IpAddr, Arc<Mutex<Bucket>>>,
    rate: f64,
    burst: f64,
    trusted_proxies: Arc<Vec<IpAddr>>,
}

impl RateLimiter {
    /// `per_sec` tokens/second steady-state, `burst` bucket capacity. Both
    /// must be > 0 (the server only constructs this when the limit is
    /// enabled). `trusted_proxies` gates `X-Forwarded-For` (see [`client_ip`]).
    pub fn new(per_sec: u32, burst: u32, trusted_proxies: Vec<IpAddr>) -> Self {
        Self {
            // Bound the bucket table: 100k distinct IPs is far more than any
            // legitimate fan-in, and idle entries evict after 10 minutes.
            buckets: moka::future::Cache::builder()
                .max_capacity(100_000)
                .time_to_idle(Duration::from_secs(600))
                .build(),
            rate: f64::from(per_sec),
            burst: f64::from(burst.max(1)),
            trusted_proxies: Arc::new(trusted_proxies),
        }
    }

    fn resolve(&self, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
        client_ip(headers, peer, &self.trusted_proxies)
    }

    /// Admit-or-shed one request from `ip` at `now`. `get_with` dedups
    /// concurrent first-touches of the same key.
    async fn check_at(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let burst = self.burst;
        let bucket = self
            .buckets
            .get_with(
                ip,
                async move { Arc::new(Mutex::new(Bucket::new(burst, now))) },
            )
            .await;
        let mut b = bucket.lock().await;
        b.try_spend(now, self.rate, self.burst)
    }
}

/// `429` body. `Retry-After` is whole seconds (HTTP requires an integer),
/// rounded up and floored at 1 so a sub-second deficit still tells the client
/// to back off.
fn too_many_requests(wait: Duration) -> Response {
    let secs = wait.as_secs_f64().ceil().max(1.0) as u64;
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, secs.to_string())],
        "rate limit exceeded\n",
    )
        .into_response()
}

/// Per-IP rate-limit middleware. Resolves the client IP (trusted-proxy aware)
/// and sheds over-quota requests with `429` + `Retry-After` before any
/// adapter/policy work runs.
pub async fn rate_limit(
    State(limiter): State<Arc<RateLimiter>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let ip = limiter.resolve(req.headers(), peer.ip());
    match limiter.check_at(ip, Instant::now()).await {
        Ok(()) => next.run(req).await,
        Err(wait) => {
            // Same counter the body-cap/timeout controls feed (server.rs
            // count_edge_rejections); emitted here because a `429` status is
            // also produced by upstream rate limits and so isn't edge-unique.
            metrics::counter!("proxilion_ingress_rejections_total", "reason" => "rate_limit")
                .increment(1);
            too_many_requests(wait)
        }
    }
}

// =====================================================================
// Global concurrency limit + load-shed
// =====================================================================

/// Global in-flight concurrency limiter. A `Semaphore` sized to the
/// operator's budget; `try_acquire` (never a blocking acquire) is the
/// load-shed — excess load returns `503` immediately instead of queueing into
/// memory exhaustion.
#[derive(Clone)]
pub struct ConcurrencyLimit {
    sem: Arc<Semaphore>,
}

impl ConcurrencyLimit {
    pub fn new(max_in_flight: usize) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(max_in_flight)),
        }
    }

    /// `Some(permit)` if a slot was free; `None` if at capacity (shed).
    fn try_enter(&self) -> Option<OwnedSemaphorePermit> {
        self.sem.clone().try_acquire_owned().ok()
    }
}

/// Global concurrency-limit + load-shed middleware. Holds a permit for the
/// request's lifetime; sheds to `503` when no permit is free.
pub async fn concurrency_limit(
    State(limit): State<ConcurrencyLimit>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    match limit.try_enter() {
        // `_permit` is dropped (released) when the response future resolves.
        Some(_permit) => next.run(req).await,
        None => {
            // `503` is also returned by `/healthz` when not ready, so count
            // the load-shed at its source rather than reverse-mapping status.
            metrics::counter!("proxilion_ingress_rejections_total", "reason" => "load_shed")
                .increment(1);
            (StatusCode::SERVICE_UNAVAILABLE, "server overloaded\n").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(FORWARDED_FOR, value.parse().unwrap());
        h
    }

    #[test]
    fn client_ip_ignores_forwarded_header_when_no_trusted_proxies() {
        // Secure default: an attacker-supplied XFF is never believed.
        let h = xff("1.2.3.4");
        assert_eq!(client_ip(&h, ip("9.9.9.9"), &[]), ip("9.9.9.9"));
    }

    #[test]
    fn client_ip_ignores_forwarded_header_when_peer_is_not_trusted() {
        // Header present, but the direct peer isn't a declared proxy → peer.
        let h = xff("1.2.3.4");
        let trusted = [ip("10.0.0.1")];
        assert_eq!(client_ip(&h, ip("9.9.9.9"), &trusted), ip("9.9.9.9"));
    }

    #[test]
    fn client_ip_honors_forwarded_header_behind_trusted_proxy() {
        // peer is the trusted edge; the single XFF entry is the real client.
        let h = xff("203.0.113.7");
        let trusted = [ip("10.0.0.1")];
        assert_eq!(client_ip(&h, ip("10.0.0.1"), &trusted), ip("203.0.113.7"));
    }

    #[test]
    fn client_ip_skips_trailing_trusted_hops_in_chain() {
        // XFF: client, proxy-a, proxy-b ; peer=proxy-b. Walking right-to-left
        // skips the trusted proxies and lands on the real client.
        let h = xff("203.0.113.7, 10.0.0.2, 10.0.0.1");
        let trusted = [ip("10.0.0.1"), ip("10.0.0.2")];
        assert_eq!(client_ip(&h, ip("10.0.0.1"), &trusted), ip("203.0.113.7"));
    }

    #[test]
    fn client_ip_does_not_trust_spoofed_left_prefix() {
        // Attacker prepends a fake client; the trusted edge appended the real
        // peer (1.1.1.1). Right-to-left stops at the first untrusted = real.
        let h = xff("66.66.66.66, 1.1.1.1");
        let trusted = [ip("10.0.0.1")];
        // peer is the trusted proxy; XFF's rightmost untrusted is 1.1.1.1.
        assert_eq!(client_ip(&h, ip("10.0.0.1"), &trusted), ip("1.1.1.1"));
    }

    #[test]
    fn client_ip_falls_back_to_peer_when_chain_all_trusted() {
        let h = xff("10.0.0.2, 10.0.0.1");
        let trusted = [ip("10.0.0.1"), ip("10.0.0.2")];
        assert_eq!(client_ip(&h, ip("10.0.0.1"), &trusted), ip("10.0.0.1"));
    }

    #[test]
    fn bucket_admits_up_to_burst_then_sheds() {
        let now = Instant::now();
        let mut b = Bucket::new(3.0, now);
        // Burst of 3: three immediate admits, fourth shed (no time passed).
        assert!(b.try_spend(now, 1.0, 3.0).is_ok());
        assert!(b.try_spend(now, 1.0, 3.0).is_ok());
        assert!(b.try_spend(now, 1.0, 3.0).is_ok());
        assert!(b.try_spend(now, 1.0, 3.0).is_err());
    }

    #[test]
    fn bucket_refills_at_rate_over_time() {
        let t0 = Instant::now();
        let mut b = Bucket::new(1.0, t0);
        assert!(b.try_spend(t0, 1.0, 1.0).is_ok()); // spend the one token
        assert!(b.try_spend(t0, 1.0, 1.0).is_err()); // empty
        // After 1s at 1 token/s, exactly one token is back.
        let t1 = t0 + Duration::from_secs(1);
        assert!(b.try_spend(t1, 1.0, 1.0).is_ok());
        assert!(b.try_spend(t1, 1.0, 1.0).is_err());
    }

    #[test]
    fn bucket_retry_after_reflects_deficit() {
        let t0 = Instant::now();
        let mut b = Bucket::new(1.0, t0);
        assert!(b.try_spend(t0, 2.0, 1.0).is_ok());
        // Empty bucket at 2 tokens/s → next token in 0.5s.
        let wait = b.try_spend(t0, 2.0, 1.0).unwrap_err();
        assert!((wait.as_secs_f64() - 0.5).abs() < 1e-6, "wait={wait:?}");
    }

    #[test]
    fn retry_after_header_rounds_up_and_floors_at_one() {
        let resp = too_many_requests(Duration::from_millis(1));
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let ra = resp.headers().get(axum::http::header::RETRY_AFTER).unwrap();
        assert_eq!(ra, "1");
    }

    #[tokio::test]
    async fn rate_limiter_sheds_after_burst_then_recovers() {
        let rl = RateLimiter::new(1, 2, vec![]);
        let client = ip("203.0.113.9");
        let t0 = Instant::now();
        assert!(rl.check_at(client, t0).await.is_ok());
        assert!(rl.check_at(client, t0).await.is_ok());
        assert!(rl.check_at(client, t0).await.is_err()); // burst of 2 spent
        // A different IP has its own bucket.
        assert!(rl.check_at(ip("203.0.113.10"), t0).await.is_ok());
        // Original IP recovers one token after a second.
        assert!(
            rl.check_at(client, t0 + Duration::from_secs(1))
                .await
                .is_ok()
        );
    }

    #[test]
    fn concurrency_limit_sheds_when_permits_exhausted() {
        let limit = ConcurrencyLimit::new(2);
        let p1 = limit.try_enter();
        let p2 = limit.try_enter();
        assert!(p1.is_some() && p2.is_some());
        assert!(limit.try_enter().is_none(), "third entry must shed");
        drop(p1);
        assert!(
            limit.try_enter().is_some(),
            "slot freed after a permit drops"
        );
    }
}
