//! Bandwidth throttling and rate limiting primitives.
//!
//! Provides human-friendly rate-limit parsing (e.g. `10M`, `10MB`, `10MiB`, `500K`, `1G`)
//! and an asynchronous token bucket limiter with bounded memory and thread-safe sharing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

/// Parses human-readable bandwidth rate limit strings into bytes per second.
///
/// Supported formats:
/// - Plain numbers (bytes/sec): `"1048576"`, `"500000"`
/// - Standard shorthand (powers of 1024): `"10M"`, `"500K"`, `"1G"`
/// - Binary prefix (powers of 1024): `"10MiB"`, `"500KiB"`, `"1GiB"`
/// - Decimal prefix (powers of 1000): `"10MB"`, `"500KB"`, `"1GB"`
/// - Suffixes `/s`, `ps`, `b/s`, `bps`: `"10MB/s"`, `"10MiB/s"`, `"10Mbps"`, `"10M/s"`
/// - Floats: `"1.5M"`, `"2.5MB/s"`
/// - Special values: `"0"`, `"unlimited"` -> `0` (unlimited)
pub fn parse_rate_limit(s: &str) -> Result<u64, String> {
    let raw = s.trim();
    if raw.is_empty() {
        return Err("rate limit cannot be empty".to_string());
    }
    if raw.eq_ignore_ascii_case("unlimited") || raw == "0" {
        return Ok(0);
    }

    let mut lower = raw.to_ascii_lowercase();

    // Strip trailing per-second notations
    if let Some(stripped) = lower.strip_suffix("/s") {
        lower = stripped.trim_end().to_string();
    } else if let Some(stripped) = lower.strip_suffix("ps") {
        lower = stripped.trim_end().to_string();
    }

    // Determine unit multiplier
    let (num_str, multiplier): (&str, f64) = if let Some(s) = lower.strip_suffix("kib") {
        (s, 1024.0)
    } else if let Some(s) = lower.strip_suffix("mib") {
        (s, 1024.0 * 1024.0)
    } else if let Some(s) = lower.strip_suffix("gib") {
        (s, 1024.0 * 1024.0 * 1024.0)
    } else if let Some(s) = lower.strip_suffix("tib") {
        (s, 1024.0 * 1024.0 * 1024.0 * 1024.0)
    } else if let Some(s) = lower.strip_suffix("kb") {
        (s, 1_000.0)
    } else if let Some(s) = lower.strip_suffix("mb") {
        (s, 1_000_000.0)
    } else if let Some(s) = lower.strip_suffix("gb") {
        (s, 1_000_000_000.0)
    } else if let Some(s) = lower.strip_suffix("tb") {
        (s, 1_000_000_000_000.0)
    } else if let Some(s) = lower.strip_suffix('k') {
        (s, 1024.0)
    } else if let Some(s) = lower.strip_suffix('m') {
        (s, 1024.0 * 1024.0)
    } else if let Some(s) = lower.strip_suffix('g') {
        (s, 1024.0 * 1024.0 * 1024.0)
    } else if let Some(s) = lower.strip_suffix('t') {
        (s, 1024.0 * 1024.0 * 1024.0 * 1024.0)
    } else if let Some(s) = lower.strip_suffix('b') {
        (s, 1.0)
    } else {
        (lower.as_str(), 1.0)
    };

    let val: f64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid rate limit value '{raw}'"))?;

    if val < 0.0 {
        return Err("rate limit cannot be negative".to_string());
    }

    let bytes = val * multiplier;
    if bytes > (u64::MAX as f64) {
        return Err("rate limit exceeds maximum allowed value".to_string());
    }

    Ok(bytes.round() as u64)
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
    burst_limit: f64,
}

/// Thread-safe, asynchronous token bucket rate limiter.
///
/// Can be cloned and shared across concurrent QUIC data streams.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<BucketState>>,
    bytes_per_sec: u64,
    parent: Option<Arc<RateLimiter>>,
    hit_counter: Option<Arc<AtomicU64>>,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given bytes per second.
    ///
    /// If `bytes_per_sec == 0`, rate limiting is disabled (unlimited).
    pub fn new(bytes_per_sec: u64) -> Self {
        let burst = (bytes_per_sec as f64 * 2.0).max(2.0 * 1024.0 * 1024.0);
        let initial_tokens = (bytes_per_sec as f64).min(burst);
        Self {
            inner: Arc::new(Mutex::new(BucketState {
                tokens: initial_tokens,
                last_refill: Instant::now(),
                burst_limit: burst,
            })),
            bytes_per_sec,
            parent: None,
            hit_counter: None,
        }
    }

    /// Chain a parent rate limiter (e.g. global server bandwidth cap).
    /// Calls to `acquire` will require permission from both the parent limiter
    /// and this limiter concurrently.
    pub fn with_parent(mut self, parent: Arc<RateLimiter>) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Attach a metric counter that is incremented whenever token deficit causes throttling.
    pub fn with_hit_counter(mut self, counter: Arc<AtomicU64>) -> Self {
        self.hit_counter = Some(counter);
        self
    }

    /// The configured rate limit in bytes per second.
    pub fn bytes_per_sec(&self) -> u64 {
        self.bytes_per_sec
    }

    /// Acquires permission to transmit `bytes`.
    ///
    /// Asynchronously sleeps if insufficient tokens are available,
    /// yielding the Tokio executor without blocking the thread.
    pub async fn acquire(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }

        // Collect ancestors to avoid recursive async future sizing
        let mut cur = self.parent.clone();
        let mut ancestors = Vec::new();
        while let Some(p) = cur {
            ancestors.push(p.clone());
            cur = p.parent.clone();
        }

        // Acquire parent / root limiters first
        for ancestor in ancestors.iter().rev() {
            ancestor.acquire_self(bytes).await;
        }

        self.acquire_self(bytes).await;
    }

    async fn acquire_self(&self, bytes: usize) {
        if self.bytes_per_sec == 0 || bytes == 0 {
            return;
        }

        let req = bytes as f64;
        let mut state = self.inner.lock().await;

        loop {
            let now = Instant::now();
            let elapsed = now.saturating_duration_since(state.last_refill);
            let added_tokens = elapsed.as_secs_f64() * (self.bytes_per_sec as f64);
            state.tokens = (state.tokens + added_tokens).min(state.burst_limit);
            state.last_refill = now;

            if req > state.burst_limit {
                state.burst_limit = req * 2.0;
            }

            if state.tokens >= req {
                state.tokens -= req;
                return;
            }

            if let Some(ref counter) = self.hit_counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }

            let deficit = req - state.tokens;
            let wait_secs = deficit / (self.bytes_per_sec as f64);
            let sleep_dur = Duration::from_secs_f64(wait_secs);

            drop(state);
            tokio::time::sleep(sleep_dur).await;
            state = self.inner.lock().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rate_limit_plain() {
        assert_eq!(parse_rate_limit("1048576").unwrap(), 1048576);
        assert_eq!(parse_rate_limit("0").unwrap(), 0);
        assert_eq!(parse_rate_limit("unlimited").unwrap(), 0);
        assert_eq!(parse_rate_limit("UNLIMITED").unwrap(), 0);
    }

    #[test]
    fn test_parse_rate_limit_units() {
        // Binary / standard abbreviations
        assert_eq!(parse_rate_limit("1K").unwrap(), 1024);
        assert_eq!(parse_rate_limit("500k").unwrap(), 500 * 1024);
        assert_eq!(parse_rate_limit("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_rate_limit("10m").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_rate_limit("1G").unwrap(), 1024 * 1024 * 1024);

        // Explicit KiB / MiB / GiB
        assert_eq!(parse_rate_limit("500KiB").unwrap(), 500 * 1024);
        assert_eq!(parse_rate_limit("10MiB").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_rate_limit("1GiB").unwrap(), 1024 * 1024 * 1024);

        // Decimal KB / MB / GB
        assert_eq!(parse_rate_limit("500KB").unwrap(), 500_000);
        assert_eq!(parse_rate_limit("10MB").unwrap(), 10_000_000);
        assert_eq!(parse_rate_limit("1GB").unwrap(), 1_000_000_000);

        // Suffixes: /s, ps
        assert_eq!(parse_rate_limit("10M/s").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_rate_limit("10MB/s").unwrap(), 10_000_000);
        assert_eq!(parse_rate_limit("10MiB/s").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_rate_limit("10Mbps").unwrap(), 10_000_000);

        // Floats
        assert_eq!(
            parse_rate_limit("1.5M").unwrap(),
            (1.5 * 1024.0 * 1024.0) as u64
        );
        assert_eq!(parse_rate_limit("2.5MB").unwrap(), 2_500_000);
    }

    #[test]
    fn test_parse_rate_limit_errors() {
        assert!(parse_rate_limit("").is_err());
        assert!(parse_rate_limit("   ").is_err());
        assert!(parse_rate_limit("-50M").is_err());
        assert!(parse_rate_limit("abc").is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_unlimited() {
        let limiter = RateLimiter::new(0);
        assert_eq!(limiter.bytes_per_sec(), 0);
        let start = Instant::now();
        limiter.acquire(100_000_000).await;
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_rate_limiter_throttle() {
        // Limit to 100 KB/s = 102,400 bytes/s
        let rate = 100 * 1024;
        let limiter = RateLimiter::new(rate);
        assert_eq!(limiter.bytes_per_sec(), rate);

        // Drain initial tokens
        limiter.acquire(rate as usize).await;

        // Next 50 KB should take ~0.5s (allow small timing variance in test)
        let start = Instant::now();
        limiter.acquire(50 * 1024).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(350),
            "Expected elapsed >= 350ms, got {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_hierarchical_and_hit_counter() {
        let parent_counter = Arc::new(AtomicU64::new(0));
        let child_counter = Arc::new(AtomicU64::new(0));

        let parent =
            Arc::new(RateLimiter::new(100 * 1024).with_hit_counter(Arc::clone(&parent_counter)));
        let child = RateLimiter::new(200 * 1024)
            .with_parent(Arc::clone(&parent))
            .with_hit_counter(Arc::clone(&child_counter));

        // Drain tokens from parent (child has 200KB burst, parent has 100KB)
        child.acquire(100 * 1024).await;

        // Next acquire will be throttled by parent limiter
        let start = Instant::now();
        child.acquire(50 * 1024).await;
        assert!(start.elapsed() >= Duration::from_millis(350));

        // Parent was throttled so parent_counter should be > 0
        assert!(parent_counter.load(Ordering::Relaxed) >= 1);
    }
}
