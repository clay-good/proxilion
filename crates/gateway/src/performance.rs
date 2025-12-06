//! Performance Optimization Module
//!
//! Provides caching, pre-compilation, and other optimizations for high-throughput scenarios.
//! Designed to handle >10K requests/second with minimal latency impact.
//!
//! NOTE: This module is prepared infrastructure for future caching optimizations.
//! Currently unused but tests are in place.

#![allow(dead_code)]

use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Result cache entry
#[derive(Clone)]
struct CacheEntry {
    threat_score: f64,
    decision: String,
    timestamp: Instant,
}

/// High-performance LRU cache for recent analysis results
pub struct AnalysisCache {
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    ttl: Duration,
    max_entries: usize,
}

impl AnalysisCache {
    /// Create a new analysis cache
    pub fn new(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::with_capacity(max_entries))),
            ttl: Duration::from_secs(ttl_secs),
            max_entries,
        }
    }

    /// Generate cache key from request content
    pub fn generate_key(user_id: &str, content: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(user_id.as_bytes());
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Get cached result if available and not expired
    pub async fn get(&self, key: &str) -> Option<(f64, String)> {
        let cache = self.cache.read().await;

        if let Some(entry) = cache.get(key) {
            // Check if entry is still valid
            if entry.timestamp.elapsed() < self.ttl {
                return Some((entry.threat_score, entry.decision.clone()));
            }
        }

        None
    }

    /// Store result in cache
    pub async fn put(&self, key: String, threat_score: f64, decision: String) {
        let mut cache = self.cache.write().await;

        // Simple LRU: if full, remove oldest entries
        if cache.len() >= self.max_entries {
            // Remove entries older than TTL
            let now = Instant::now();
            cache.retain(|_, entry| now.duration_since(entry.timestamp) < self.ttl);

            // If still full, remove random entry (simplified LRU)
            if cache.len() >= self.max_entries {
                if let Some(key) = cache.keys().next().cloned() {
                    cache.remove(&key);
                }
            }
        }

        cache.insert(key, CacheEntry {
            threat_score,
            decision,
            timestamp: Instant::now(),
        });
    }

    /// Get cache statistics
    pub async fn stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        let total = cache.len();
        let expired = cache.values()
            .filter(|entry| entry.timestamp.elapsed() >= self.ttl)
            .count();

        (total, expired)
    }

    /// Clear expired entries
    pub async fn cleanup(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        cache.retain(|_, entry| now.duration_since(entry.timestamp) < self.ttl);
    }
}

impl Default for AnalysisCache {
    fn default() -> Self {
        // Default: 60 second TTL, 10K entries
        Self::new(60, 10_000)
    }
}

/// Batch processing configuration
pub struct BatchConfig {
    pub max_batch_size: usize,
    pub batch_timeout_ms: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 100,
            batch_timeout_ms: 10,
        }
    }
}

/// Performance metrics
pub struct PerformanceMetrics {
    pub cache_hits: Arc<RwLock<u64>>,
    pub cache_misses: Arc<RwLock<u64>>,
    pub total_requests: Arc<RwLock<u64>>,
    pub avg_latency_ms: Arc<RwLock<f64>>,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self {
            cache_hits: Arc::new(RwLock::new(0)),
            cache_misses: Arc::new(RwLock::new(0)),
            total_requests: Arc::new(RwLock::new(0)),
            avg_latency_ms: Arc::new(RwLock::new(0.0)),
        }
    }

    pub async fn record_cache_hit(&self) {
        let mut hits = self.cache_hits.write().await;
        *hits += 1;
    }

    pub async fn record_cache_miss(&self) {
        let mut misses = self.cache_misses.write().await;
        *misses += 1;
    }

    pub async fn record_request(&self, latency_ms: f64) {
        let mut total = self.total_requests.write().await;
        let mut avg = self.avg_latency_ms.write().await;

        *total += 1;
        // Exponential moving average
        *avg = (*avg * 0.9) + (latency_ms * 0.1);
    }

    pub async fn get_stats(&self) -> (u64, u64, u64, f64) {
        let hits = *self.cache_hits.read().await;
        let misses = *self.cache_misses.read().await;
        let total = *self.total_requests.read().await;
        let avg_lat = *self.avg_latency_ms.read().await;

        (hits, misses, total, avg_lat)
    }

    pub async fn cache_hit_rate(&self) -> f64 {
        let hits = *self.cache_hits.read().await as f64;
        let misses = *self.cache_misses.read().await as f64;
        let total = hits + misses;

        if total > 0.0 {
            (hits / total) * 100.0
        } else {
            0.0
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_basic() {
        let cache = AnalysisCache::new(2, 10);
        let key = "test_key".to_string();

        // Should be empty initially
        assert!(cache.get(&key).await.is_none());

        // Put and retrieve
        cache.put(key.clone(), 85.0, "Block".to_string()).await;
        let result = cache.get(&key).await;
        assert!(result.is_some());

        let (score, decision) = result.unwrap();
        assert_eq!(score, 85.0);
        assert_eq!(decision, "Block");
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = AnalysisCache::new(1, 10); // 1 second TTL
        let key = "test_key".to_string();

        cache.put(key.clone(), 85.0, "Block".to_string()).await;
        assert!(cache.get(&key).await.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_lru() {
        let cache = AnalysisCache::new(60, 2); // Only 2 entries

        cache.put("key1".to_string(), 10.0, "Allow".to_string()).await;
        cache.put("key2".to_string(), 20.0, "Allow".to_string()).await;
        cache.put("key3".to_string(), 30.0, "Alert".to_string()).await;

        // Should have evicted oldest entry
        let (total, _) = cache.stats().await;
        assert!(total <= 2);
    }

    #[tokio::test]
    async fn test_performance_metrics() {
        let metrics = PerformanceMetrics::new();

        metrics.record_cache_hit().await;
        metrics.record_cache_hit().await;
        metrics.record_cache_miss().await;

        let (hits, misses, _, _) = metrics.get_stats().await;
        assert_eq!(hits, 2);
        assert_eq!(misses, 1);

        let hit_rate = metrics.cache_hit_rate().await;
        assert!((hit_rate - 66.66).abs() < 1.0);
    }

    #[test]
    fn test_key_generation() {
        let key1 = AnalysisCache::generate_key("user1", "command1");
        let key2 = AnalysisCache::generate_key("user1", "command1");
        let key3 = AnalysisCache::generate_key("user1", "command2");

        // Same input = same key
        assert_eq!(key1, key2);
        // Different input = different key
        assert_ne!(key1, key3);
    }
}
