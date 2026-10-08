#![forbid(unsafe_code)]

//! In-process WAN network simulation and link impairment engine.
//!
//! Implements requirements from:
//! - `docs/REQUIREMENTS.md` §45 ("Network Simulation")
//! - `docs/REQUIREMENTS.md` §46 ("Benchmark Suite")
//! - `docs/REQUIREMENTS.md` §48 ("Example Benchmark")
//! - `docs/REQUIREMENTS.md` §91 ("Performance Targets")
//! - `docs/REQUIREMENTS.md` §92 ("WAN Benchmark Priority")
//! - `docs/DEVELOPMENT.md` §5 ("Network Simulation & WAN Testing")
//! - `docs/PERFORMANCE.md` §7 ("High-BDP WAN Tuning & Multi-Stream Striping")
//!
//! This module provides deterministic, in-process link impairment modeling for
//! round-trip latency (RTT), packet loss, and token-bucket bandwidth throttling
//! in 100% safe Rust without requiring root `tc netem` or Linux network namespaces.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::error::{Result, VelcruxError};
use crate::transport::{BiRecvStream, BiSendStream, UniRecvStream, UniSendStream};

/// WAN impairment profile defining simulated link conditions (§45).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImpairmentProfile {
    /// Human-readable profile name.
    pub name: String,
    /// Round-trip time (RTT). One-way delay is typically `rtt / 2`.
    pub rtt: Duration,
    /// One-way latency applied per direction.
    pub one_way_delay: Duration,
    /// Latency jitter variance (± jitter).
    pub jitter: Duration,
    /// Packet loss probability (e.g. 0.005 for 0.5% loss).
    pub loss_rate: f64,
    /// Link bandwidth in bits per second (e.g. 10_000_000_000 for 10 Gbps).
    /// 0 denotes unlimited.
    pub bandwidth_bps: u64,
}

impl ImpairmentProfile {
    /// Construct a new impairment profile.
    pub fn new(name: impl Into<String>, rtt: Duration, loss_rate: f64, bandwidth_bps: u64) -> Self {
        let one_way = rtt / 2;
        Self {
            name: name.into(),
            rtt,
            one_way_delay: one_way,
            jitter: Duration::ZERO,
            loss_rate: loss_rate.clamp(0.0, 1.0),
            bandwidth_bps,
        }
    }

    /// Add jitter to the profile.
    pub fn with_jitter(mut self, jitter: Duration) -> Self {
        self.jitter = jitter;
        self
    }

    /// High-speed local data center / LAN profile (1ms RTT, 0% loss, 10 Gbps).
    pub fn lan() -> Self {
        Self::new(
            "LAN / Local DC",
            Duration::from_millis(1),
            0.0,
            10_000_000_000,
        )
    }

    /// Metro Area Network (20ms RTT, 0.1% loss, 1 Gbps).
    pub fn metro() -> Self {
        Self::new("Metro WAN", Duration::from_millis(20), 0.001, 1_000_000_000)
    }

    /// Regional WAN (50ms RTT, 0.1% loss, 1 Gbps).
    pub fn regional() -> Self {
        Self::new(
            "Regional WAN",
            Duration::from_millis(50),
            0.001,
            1_000_000_000,
        )
    }

    /// Transcontinental WAN (100ms RTT, 0.5% loss, 1 Gbps).
    pub fn transcontinental() -> Self {
        Self::new(
            "Transcontinental WAN",
            Duration::from_millis(100),
            0.005,
            1_000_000_000,
        )
    }

    /// High-BDP Cross-Pacific Link (§48 flagship: 150ms RTT, 0.5% loss, 10 Gbps).
    pub fn cross_pacific() -> Self {
        Self::new(
            "Cross-Pacific 10G",
            Duration::from_millis(150),
            0.005,
            10_000_000_000,
        )
    }

    /// Intercontinental High-Latency WAN (200ms RTT, 1.0% loss, 1 Gbps).
    pub fn intercontinental() -> Self {
        Self::new(
            "Intercontinental WAN",
            Duration::from_millis(200),
            0.010,
            1_000_000_000,
        )
    }

    /// High-loss long-haul satellite link (300ms RTT, 2.0% loss, 100 Mbps).
    pub fn satellite() -> Self {
        Self::new(
            "Satellite Link",
            Duration::from_millis(300),
            0.020,
            100_000_000,
        )
    }

    /// Hostile WAN environment (§45: 200ms RTT, 5.0% loss, 100 Mbps).
    pub fn hostile_wan() -> Self {
        Self::new(
            "Hostile WAN (5% Loss)",
            Duration::from_millis(200),
            0.050,
            100_000_000,
        )
    }

    /// Compute the Bandwidth-Delay Product (BDP) in bytes for this profile.
    pub fn bdp_bytes(&self) -> u64 {
        if self.bandwidth_bps == 0 {
            return 0;
        }
        let bytes_per_sec = self.bandwidth_bps / 8;
        let rtt_secs = self.rtt.as_secs_f64();
        (bytes_per_sec as f64 * rtt_secs).round() as u64
    }

    /// Compute recommended flow control window (2 × BDP clamped to min 16 MiB).
    pub fn recommended_receive_window(&self) -> u64 {
        let bdp = self.bdp_bytes();
        let double_bdp = bdp.saturating_mul(2);
        double_bdp.clamp(16 * 1024 * 1024, 1024 * 1024 * 1024)
    }
}

/// Cumulative statistics for simulated impairment.
#[derive(Debug, Default)]
pub struct ImpairmentStats {
    pub packets_sent: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_dropped: AtomicU64,
    pub delay_applied_micros: AtomicU64,
}

impl ImpairmentStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> ImpairmentStatsSnapshot {
        ImpairmentStatsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_dropped: self.bytes_dropped.load(Ordering::Relaxed),
            delay_applied_total: Duration::from_micros(
                self.delay_applied_micros.load(Ordering::Relaxed),
            ),
        }
    }
}

/// Value snapshot of impairment statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImpairmentStatsSnapshot {
    pub packets_sent: u64,
    pub packets_dropped: u64,
    pub bytes_sent: u64,
    pub bytes_dropped: u64,
    pub delay_applied_total: Duration,
}

/// Token bucket rate limiter for link bandwidth throttling.
#[derive(Debug)]
pub struct TokenBucket {
    rate_bytes_per_sec: u64,
    capacity_bytes: u64,
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    pub fn new(bandwidth_bps: u64) -> Self {
        let rate = bandwidth_bps / 8;
        // Capacity sized to 100ms burst window
        let burst = (rate / 10).max(64 * 1024);
        Self {
            rate_bytes_per_sec: rate,
            capacity_bytes: burst,
            tokens: burst as f64,
            last_update: Instant::now(),
        }
    }

    /// Consume tokens for `bytes`. Returns duration to wait if throttled.
    pub fn consume(&mut self, bytes: usize) -> Duration {
        if self.rate_bytes_per_sec == 0 {
            return Duration::ZERO;
        }

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        // Refill tokens
        self.tokens = (self.tokens + elapsed * (self.rate_bytes_per_sec as f64))
            .min(self.capacity_bytes as f64);

        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            Duration::ZERO
        } else {
            let deficit = (bytes as f64) - self.tokens;
            self.tokens = 0.0;
            Duration::from_secs_f64(deficit / (self.rate_bytes_per_sec as f64))
        }
    }
}

/// Deterministic, fast PRNG for packet loss decisions (xorshift64).
#[derive(Debug)]
pub struct DeterministicLossPrng {
    state: u64,
}

impl DeterministicLossPrng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x853c49e6748fea9b } else { seed },
        }
    }

    pub fn next_f64(&mut self) -> f64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        (x as f64) / (u64::MAX as f64)
    }

    pub fn should_drop(&mut self, loss_rate: f64) -> bool {
        if loss_rate <= 0.0 {
            false
        } else if loss_rate >= 1.0 {
            true
        } else {
            self.next_f64() < loss_rate
        }
    }
}

/// Simulated delivery item with scheduled arrival time.
struct DelayedPacket<T> {
    payload: T,
    deliver_at: Instant,
}

/// An in-process, async impaired channel queue simulating latency and packet loss.
pub struct ImpairedChannel<T> {
    profile: ImpairmentProfile,
    queue: Mutex<VecDeque<DelayedPacket<T>>>,
    prng: Mutex<DeterministicLossPrng>,
    token_bucket: Mutex<TokenBucket>,
    stats: Arc<ImpairmentStats>,
}

impl<T: Send + 'static> ImpairedChannel<T> {
    /// Create a new channel with the given profile and seed.
    pub fn new(profile: ImpairmentProfile, seed: u64) -> Self {
        let bw = profile.bandwidth_bps;
        Self {
            profile,
            queue: Mutex::new(VecDeque::new()),
            prng: Mutex::new(DeterministicLossPrng::new(seed)),
            token_bucket: Mutex::new(TokenBucket::new(bw)),
            stats: Arc::new(ImpairmentStats::new()),
        }
    }

    /// Retrieve stats handle.
    pub fn stats(&self) -> Arc<ImpairmentStats> {
        self.stats.clone()
    }

    /// Enqueue an item with simulated loss and delay.
    /// Returns `true` if accepted and scheduled; `false` if dropped due to loss.
    pub async fn send(&self, item: T, byte_len: usize) -> bool {
        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);

        let dropped = {
            let mut prng = self.prng.lock().await;
            prng.should_drop(self.profile.loss_rate)
        };

        if dropped {
            self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_dropped
                .fetch_add(byte_len as u64, Ordering::Relaxed);
            return false;
        }

        // Apply bandwidth rate-limiting delay
        let pacing_wait = {
            let mut tb = self.token_bucket.lock().await;
            tb.consume(byte_len)
        };

        let now = Instant::now();
        let delay = self.profile.one_way_delay + pacing_wait;
        let deliver_at = now + delay;

        self.stats
            .bytes_sent
            .fetch_add(byte_len as u64, Ordering::Relaxed);
        self.stats
            .delay_applied_micros
            .fetch_add(delay.as_micros() as u64, Ordering::Relaxed);

        let mut q = self.queue.lock().await;
        q.push_back(DelayedPacket {
            payload: item,
            deliver_at,
        });
        true
    }

    /// Receive the next deliverable item, sleeping until its simulated delivery timestamp arrives.
    pub async fn recv(&self) -> Option<T> {
        loop {
            let next_deliver_at = {
                let q = self.queue.lock().await;
                q.front().map(|p| p.deliver_at)
            };

            match next_deliver_at {
                None => return None,
                Some(deliver_at) => {
                    let now = Instant::now();
                    if now < deliver_at {
                        tokio::time::sleep(deliver_at - now).await;
                    }
                    let mut q = self.queue.lock().await;
                    if let Some(front) = q.front() {
                        if Instant::now() >= front.deliver_at {
                            return q.pop_front().map(|p| p.payload);
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Impaired Stream Wrappers
// ---------------------------------------------------------------------------

/// Stream send wrapper injecting delay, packet loss simulation, and bandwidth pacing.
pub struct ImpairedSendStream<S> {
    inner: S,
    profile: ImpairmentProfile,
    prng: DeterministicLossPrng,
    token_bucket: TokenBucket,
    stats: Arc<ImpairmentStats>,
}

impl<S> ImpairedSendStream<S> {
    pub fn new(
        inner: S,
        profile: ImpairmentProfile,
        seed: u64,
        stats: Arc<ImpairmentStats>,
    ) -> Self {
        let bw = profile.bandwidth_bps;
        Self {
            inner,
            profile,
            prng: DeterministicLossPrng::new(seed),
            token_bucket: TokenBucket::new(bw),
            stats,
        }
    }
}

#[async_trait::async_trait]
impl<S: BiSendStream> BiSendStream for ImpairedSendStream<S> {
    async fn write_all(&mut self, data: Bytes) -> Result<()> {
        let len = data.len();
        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);

        // Bandwidth pacing
        let pacing_delay = self.token_bucket.consume(len);
        let total_delay = self.profile.one_way_delay + pacing_delay;

        if total_delay > Duration::ZERO {
            tokio::time::sleep(total_delay).await;
            self.stats
                .delay_applied_micros
                .fetch_add(total_delay.as_micros() as u64, Ordering::Relaxed);
        }

        // Loss simulation: on drop, we return simulated drop error or swallow
        if self.prng.should_drop(self.profile.loss_rate) {
            self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_dropped
                .fetch_add(len as u64, Ordering::Relaxed);
            // Simulate packet loss error to trigger QUIC transport recovery
            return Err(VelcruxError::Transport(
                crate::error::TransportError::ReadError("simulated WAN packet drop".into()),
            ));
        }

        self.stats
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);
        self.inner.write_all(data).await
    }

    async fn finish(&mut self) -> Result<()> {
        self.inner.finish().await
    }
}

#[async_trait::async_trait]
impl<S: UniSendStream> UniSendStream for ImpairedSendStream<S> {
    async fn write_all(&mut self, data: Bytes) -> Result<()> {
        let len = data.len();
        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);

        let pacing_delay = self.token_bucket.consume(len);
        let total_delay = self.profile.one_way_delay + pacing_delay;

        if total_delay > Duration::ZERO {
            tokio::time::sleep(total_delay).await;
            self.stats
                .delay_applied_micros
                .fetch_add(total_delay.as_micros() as u64, Ordering::Relaxed);
        }

        if self.prng.should_drop(self.profile.loss_rate) {
            self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_dropped
                .fetch_add(len as u64, Ordering::Relaxed);
            return Err(VelcruxError::Transport(
                crate::error::TransportError::ReadError("simulated WAN packet drop".into()),
            ));
        }

        self.stats
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);
        self.inner.write_all(data).await
    }

    async fn finish(&mut self) -> Result<()> {
        self.inner.finish().await
    }
}

/// Stream recv wrapper injecting one-way reception delay.
pub struct ImpairedRecvStream<R> {
    inner: R,
    one_way_delay: Duration,
    stats: Arc<ImpairmentStats>,
}

impl<R> ImpairedRecvStream<R> {
    pub fn new(inner: R, one_way_delay: Duration, stats: Arc<ImpairmentStats>) -> Self {
        Self {
            inner,
            one_way_delay,
            stats,
        }
    }
}

#[async_trait::async_trait]
impl<R: BiRecvStream> BiRecvStream for ImpairedRecvStream<R> {
    async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>> {
        let res = self.inner.read_chunk(max).await?;
        if res.is_some() && self.one_way_delay > Duration::ZERO {
            tokio::time::sleep(self.one_way_delay).await;
            self.stats
                .delay_applied_micros
                .fetch_add(self.one_way_delay.as_micros() as u64, Ordering::Relaxed);
        }
        Ok(res)
    }

    async fn read_exact(&mut self, n: usize) -> Result<Option<Bytes>> {
        let res = self.inner.read_exact(n).await?;
        if res.is_some() && self.one_way_delay > Duration::ZERO {
            tokio::time::sleep(self.one_way_delay).await;
            self.stats
                .delay_applied_micros
                .fetch_add(self.one_way_delay.as_micros() as u64, Ordering::Relaxed);
        }
        Ok(res)
    }
}

#[async_trait::async_trait]
impl<R: UniRecvStream> UniRecvStream for ImpairedRecvStream<R> {
    async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>> {
        let res = self.inner.read_chunk(max).await?;
        if res.is_some() && self.one_way_delay > Duration::ZERO {
            tokio::time::sleep(self.one_way_delay).await;
            self.stats
                .delay_applied_micros
                .fetch_add(self.one_way_delay.as_micros() as u64, Ordering::Relaxed);
        }
        Ok(res)
    }

    async fn read_exact(&mut self, n: usize) -> Result<Option<Bytes>> {
        let res = self.inner.read_exact(n).await?;
        if res.is_some() && self.one_way_delay > Duration::ZERO {
            tokio::time::sleep(self.one_way_delay).await;
            self.stats
                .delay_applied_micros
                .fetch_add(self.one_way_delay.as_micros() as u64, Ordering::Relaxed);
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_impairment_profile_bdp_calculations() {
        let lan = ImpairmentProfile::lan();
        assert_eq!(lan.rtt, Duration::from_millis(1));
        assert_eq!(lan.bandwidth_bps, 10_000_000_000);
        // BDP = (10_000_000_000 / 8) * 0.001 = 1,250,000 bytes (~1.25 MB)
        assert_eq!(lan.bdp_bytes(), 1_250_000);
        // Clamped to minimum receive window (16 MiB)
        assert_eq!(lan.recommended_receive_window(), 16 * 1024 * 1024);

        let pacific = ImpairmentProfile::cross_pacific();
        assert_eq!(pacific.rtt, Duration::from_millis(150));
        assert_eq!(pacific.bandwidth_bps, 10_000_000_000);
        // BDP = 1.25 GB/s * 0.150s = 187,500,000 bytes (~187.5 MB)
        assert_eq!(pacific.bdp_bytes(), 187_500_000);
        // 2 × BDP = 375,000,000 bytes (~375 MB)
        assert_eq!(pacific.recommended_receive_window(), 375_000_000);
    }

    #[test]
    fn test_deterministic_loss_prng() {
        let mut prng = DeterministicLossPrng::new(42);
        let mut drops = 0;
        let total = 10_000;
        let target_loss = 0.05; // 5%

        for _ in 0..total {
            if prng.should_drop(target_loss) {
                drops += 1;
            }
        }

        let observed_loss = (drops as f64) / (total as f64);
        // Within 1% tolerance
        assert!((observed_loss - target_loss).abs() < 0.01);
    }

    #[test]
    fn test_token_bucket_rate_limiter() {
        // 100 Mbps = 12,500,000 bytes/sec
        let mut bucket = TokenBucket::new(100_000_000);
        // Initial burst consumption should not throttle
        let wait = bucket.consume(10_000);
        assert_eq!(wait, Duration::ZERO);

        // Consuming large burst exceeding capacity should compute positive wait
        let wait2 = bucket.consume(20_000_000);
        assert!(wait2 > Duration::ZERO);
    }

    #[tokio::test]
    async fn test_impaired_channel_queue_and_loss() {
        let profile = ImpairmentProfile::new(
            "Test Impairment",
            Duration::from_millis(10),
            0.50, // 50% loss
            1_000_000_000,
        );
        let channel = ImpairedChannel::<String>::new(profile, 12345);

        let mut enqueued = 0;
        for i in 0..20 {
            if channel.send(format!("msg-{}", i), 32).await {
                enqueued += 1;
            }
        }

        // Loss dropped approximately half the items
        let stats = channel.stats().snapshot();
        assert_eq!(stats.packets_sent, 20);
        assert!(stats.packets_dropped > 0 && stats.packets_dropped < 20);
        assert_eq!(enqueued, stats.packets_sent - stats.packets_dropped);

        // Read all enqueued items
        let mut received = 0;
        for _ in 0..enqueued {
            if channel.recv().await.is_some() {
                received += 1;
            }
        }
        assert_eq!(received, enqueued);
    }
}
