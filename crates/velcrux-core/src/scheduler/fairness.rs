//! Dynamic Multi-Tenant Bandwidth Allocator & Fairness Scheduler (Option AS).
//!
//! (`REQUIREMENTS.md` §28, §29; `ARCHITECTURE.md` §5; `OPERATIONS.md` §27).
//!
//! Features:
//! 1. Multi-tier hierarchical bandwidth rate limiting:
//!    `min(per_transfer, per_user, global)`.
//! 2. Token-bucket non-blocking async pacing (never arbitrary thread sleeps).
//! 3. Strict priority scheduling:
//!    - `HIGH`: Control messages, small metadata, interactive transfers (drained to exhaustion).
//!    - `NORMAL`: Standard bulk data streams.
//!    - `LOW`: Background sync & archival.
//!    - 4:1 Weighted Round-Robin (WRR) between `NORMAL` and `LOW`.
//! 4. Sequential chunk offset preservation per transfer.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::util::TransferId;

/// Bandwidth limit rate specification in bytes per second.
/// A rate of 0 indicates unlimited bandwidth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BandwidthRate(pub u64);

impl BandwidthRate {
    /// Unlimited bandwidth (no throttling).
    pub const UNLIMITED: Self = Self(0);

    /// Construct from bits per second (e.g. 100_000_000 for 100 Mbps).
    pub fn from_bps(bps: u64) -> Self {
        Self(bps / 8)
    }

    /// Construct from bytes per second (e.g. 12_500_000 for 12.5 MB/s).
    pub fn from_bytes_per_sec(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Whether this rate specifies unlimited bandwidth.
    pub fn is_unlimited(&self) -> bool {
        self.0 == 0
    }

    /// Bytes per second (0 if unlimited).
    pub fn bytes_per_sec(&self) -> u64 {
        self.0
    }

    /// Bits per second (0 if unlimited).
    pub fn bits_per_sec(&self) -> u64 {
        self.0.saturating_mul(8)
    }
}

impl Default for BandwidthRate {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

impl fmt::Display for BandwidthRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_unlimited() {
            write!(f, "unlimited")
        } else {
            let bps = self.bits_per_sec();
            if bps >= 1_000_000_000 && bps % 1_000_000_000 == 0 {
                write!(f, "{}Gbps", bps / 1_000_000_000)
            } else if bps >= 1_000_000 && bps % 1_000_000 == 0 {
                write!(f, "{}Mbps", bps / 1_000_000)
            } else if bps >= 1_000 && bps % 1_000 == 0 {
                write!(f, "{}kbps", bps / 1_000)
            } else {
                write!(f, "{}B/s", self.0)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseBandwidthError(pub String);

impl fmt::Display for ParseBandwidthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid bandwidth specification: {}", self.0)
    }
}

impl std::error::Error for ParseBandwidthError {}

impl FromStr for BandwidthRate {
    type Err = ParseBandwidthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim().to_lowercase();
        if trimmed == "unlimited" || trimmed == "0" || trimmed == "none" {
            return Ok(Self::UNLIMITED);
        }

        // Check for bps units
        if let Some(num) = trimmed.strip_suffix("gbps") {
            let val: u64 = num
                .trim()
                .parse()
                .map_err(|_| ParseBandwidthError(s.to_string()))?;
            return Ok(Self::from_bps(val.saturating_mul(1_000_000_000)));
        }
        if let Some(num) = trimmed.strip_suffix("mbps") {
            let val: u64 = num
                .trim()
                .parse()
                .map_err(|_| ParseBandwidthError(s.to_string()))?;
            return Ok(Self::from_bps(val.saturating_mul(1_000_000)));
        }
        if let Some(num) = trimmed.strip_suffix("kbps") {
            let val: u64 = num
                .trim()
                .parse()
                .map_err(|_| ParseBandwidthError(s.to_string()))?;
            return Ok(Self::from_bps(val.saturating_mul(1_000)));
        }

        // Check for byte/sec units
        if let Some(num) = trimmed
            .strip_suffix("gb/s")
            .or_else(|| trimmed.strip_suffix("g"))
        {
            let val: u64 = num
                .trim()
                .parse()
                .map_err(|_| ParseBandwidthError(s.to_string()))?;
            return Ok(Self::from_bytes_per_sec(val.saturating_mul(1_000_000_000)));
        }
        if let Some(num) = trimmed
            .strip_suffix("mb/s")
            .or_else(|| trimmed.strip_suffix("m"))
        {
            let val: u64 = num
                .trim()
                .parse()
                .map_err(|_| ParseBandwidthError(s.to_string()))?;
            return Ok(Self::from_bytes_per_sec(val.saturating_mul(1_000_000)));
        }
        if let Some(num) = trimmed
            .strip_suffix("kb/s")
            .or_else(|| trimmed.strip_suffix("k"))
        {
            let val: u64 = num
                .trim()
                .parse()
                .map_err(|_| ParseBandwidthError(s.to_string()))?;
            return Ok(Self::from_bytes_per_sec(val.saturating_mul(1_000)));
        }
        if let Some(num) = trimmed.strip_suffix("b/s") {
            let val: u64 = num
                .trim()
                .parse()
                .map_err(|_| ParseBandwidthError(s.to_string()))?;
            return Ok(Self::from_bytes_per_sec(val));
        }

        // Direct numeric parse as bytes per second
        let val: u64 = trimmed
            .parse()
            .map_err(|_| ParseBandwidthError(s.to_string()))?;
        Ok(Self::from_bytes_per_sec(val))
    }
}

/// Token bucket pacing structure with burst capacity.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate_bytes_per_sec: u64,
    capacity_bytes: u64,
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    pub fn new(rate: BandwidthRate) -> Self {
        let bytes_per_sec = rate.bytes_per_sec();
        // Capacity sized to 100ms burst window, minimum 64 KiB
        let burst = if bytes_per_sec == 0 {
            0
        } else {
            (bytes_per_sec / 10).max(64 * 1024)
        };
        Self {
            rate_bytes_per_sec: bytes_per_sec,
            capacity_bytes: burst,
            tokens: burst as f64,
            last_update: Instant::now(),
        }
    }

    /// Refill rate.
    pub fn rate(&self) -> BandwidthRate {
        BandwidthRate::from_bytes_per_sec(self.rate_bytes_per_sec)
    }

    /// Update rate.
    pub fn set_rate(&mut self, rate: BandwidthRate) {
        let bytes_per_sec = rate.bytes_per_sec();
        let burst = if bytes_per_sec == 0 {
            0
        } else {
            (bytes_per_sec / 10).max(64 * 1024)
        };
        self.rate_bytes_per_sec = bytes_per_sec;
        self.capacity_bytes = burst;
        self.tokens = self.tokens.min(burst as f64);
    }

    /// Consume tokens for `bytes`. Returns delay needed if throttled.
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

/// Priority class for scheduling transfer chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PriorityClass {
    /// Interactive transfers, small metadata, control messages (drained to exhaustion).
    High = 0,
    /// Standard bulk file transfers (4:1 WRR share).
    Normal = 1,
    /// Background sync, archival (1:4 WRR share).
    Low = 2,
}

impl PriorityClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Normal => "normal",
            Self::Low => "low",
        }
    }
}

/// Hierarchical multi-tenant bandwidth allocator managing:
/// - Global server-wide rate limit
/// - Per-user / per-tenant rate limit
/// - Per-transfer rate limit
///
/// Composition rule: `min(per_transfer, per_user, global)`.
#[derive(Debug)]
pub struct HierarchicalBandwidthAllocator {
    global_limiter: Mutex<TokenBucket>,
    user_limiters: Mutex<HashMap<String, TokenBucket>>,
    transfer_limiters: Mutex<HashMap<TransferId, TokenBucket>>,
    total_bytes_admitted: AtomicU64,
    total_throttle_ms: AtomicU64,
}

impl Default for HierarchicalBandwidthAllocator {
    fn default() -> Self {
        Self::new(BandwidthRate::UNLIMITED)
    }
}

impl HierarchicalBandwidthAllocator {
    /// Create new allocator with a global rate ceiling.
    pub fn new(global_rate: BandwidthRate) -> Self {
        Self {
            global_limiter: Mutex::new(TokenBucket::new(global_rate)),
            user_limiters: Mutex::new(HashMap::new()),
            transfer_limiters: Mutex::new(HashMap::new()),
            total_bytes_admitted: AtomicU64::new(0),
            total_throttle_ms: AtomicU64::new(0),
        }
    }

    /// Set server-wide global rate ceiling.
    pub fn set_global_rate(&self, rate: BandwidthRate) {
        let mut global = self.global_limiter.lock().unwrap();
        global.set_rate(rate);
    }

    /// Set user/tenant rate ceiling.
    pub fn set_user_rate(&self, user: &str, rate: BandwidthRate) {
        let mut users = self.user_limiters.lock().unwrap();
        if rate.is_unlimited() {
            users.remove(user);
        } else {
            users.insert(user.to_string(), TokenBucket::new(rate));
        }
    }

    /// Set per-transfer rate ceiling.
    pub fn set_transfer_rate(&self, transfer_id: &TransferId, rate: BandwidthRate) {
        let mut transfers = self.transfer_limiters.lock().unwrap();
        if rate.is_unlimited() {
            transfers.remove(transfer_id);
        } else {
            transfers.insert(*transfer_id, TokenBucket::new(rate));
        }
    }

    /// Remove transfer rate limiter upon transfer completion.
    pub fn remove_transfer(&self, transfer_id: &TransferId) {
        let mut transfers = self.transfer_limiters.lock().unwrap();
        transfers.remove(transfer_id);
    }

    /// Calculate and consume tokens across all 3 tiers.
    /// Returns the maximum delay needed among all tiers.
    pub fn consume(&self, user: &str, transfer_id: &TransferId, bytes: usize) -> Duration {
        // 1. Global tier
        let global_delay = {
            let mut global = self.global_limiter.lock().unwrap();
            global.consume(bytes)
        };

        // 2. User tier
        let user_delay = {
            let mut users = self.user_limiters.lock().unwrap();
            users
                .get_mut(user)
                .map_or(Duration::ZERO, |u| u.consume(bytes))
        };

        // 3. Transfer tier
        let transfer_delay = {
            let mut transfers = self.transfer_limiters.lock().unwrap();
            transfers
                .get_mut(transfer_id)
                .map_or(Duration::ZERO, |t| t.consume(bytes))
        };

        let max_delay = global_delay.max(user_delay).max(transfer_delay);
        self.total_bytes_admitted
            .fetch_add(bytes as u64, Ordering::Relaxed);
        if max_delay > Duration::ZERO {
            self.total_throttle_ms
                .fetch_add(max_delay.as_millis() as u64, Ordering::Relaxed);
        }

        max_delay
    }

    /// Acquire tokens asynchronously. If throttled, sleeps for the required duration.
    pub async fn acquire(&self, user: &str, transfer_id: &TransferId, bytes: usize) -> Duration {
        let delay = self.consume(user, transfer_id, bytes);
        if delay > Duration::ZERO {
            tokio::time::sleep(delay).await;
        }
        delay
    }

    /// Total bytes admitted across all transfers.
    pub fn total_bytes_admitted(&self) -> u64 {
        self.total_bytes_admitted.load(Ordering::Relaxed)
    }

    /// Total cumulative throttling duration in milliseconds.
    pub fn total_throttle_ms(&self) -> u64 {
        self.total_throttle_ms.load(Ordering::Relaxed)
    }
}

/// A scheduled item holding priority and payload.
#[derive(Debug, Clone)]
pub struct ScheduledItem<T> {
    pub item: T,
    pub priority: PriorityClass,
    pub user: String,
    pub transfer_id: TransferId,
}

/// Strict Priority & 4:1 Weighted Round-Robin (WRR) Fairness Scheduler.
#[derive(Debug)]
pub struct FairnessScheduler<T> {
    high_queue: Mutex<VecDeque<ScheduledItem<T>>>,
    normal_queue: Mutex<VecDeque<ScheduledItem<T>>>,
    low_queue: Mutex<VecDeque<ScheduledItem<T>>>,
    wrr_counter: Mutex<u8>,
    allocator: Arc<HierarchicalBandwidthAllocator>,
    total_scheduled: AtomicU64,
}

impl<T> FairnessScheduler<T> {
    /// Create new fairness scheduler with associated bandwidth allocator.
    pub fn new(allocator: Arc<HierarchicalBandwidthAllocator>) -> Self {
        Self {
            high_queue: Mutex::new(VecDeque::new()),
            normal_queue: Mutex::new(VecDeque::new()),
            low_queue: Mutex::new(VecDeque::new()),
            wrr_counter: Mutex::new(0),
            allocator,
            total_scheduled: AtomicU64::new(0),
        }
    }

    /// Enqueue an item into the appropriate priority queue.
    pub fn enqueue(
        &self,
        item: T,
        priority: PriorityClass,
        user: impl Into<String>,
        transfer_id: TransferId,
    ) {
        let scheduled = ScheduledItem {
            item,
            priority,
            user: user.into(),
            transfer_id,
        };

        match priority {
            PriorityClass::High => self.high_queue.lock().unwrap().push_back(scheduled),
            PriorityClass::Normal => self.normal_queue.lock().unwrap().push_back(scheduled),
            PriorityClass::Low => self.low_queue.lock().unwrap().push_back(scheduled),
        }
    }

    /// Dequeue the next item following fairness rules:
    /// 1. `High` queue is drained to exhaustion first.
    /// 2. `Normal` and `Low` queues follow 4:1 Weighted Round-Robin (WRR).
    pub fn dequeue(&self) -> Option<ScheduledItem<T>> {
        // 1. Drain HIGH to exhaustion
        {
            let mut high = self.high_queue.lock().unwrap();
            if let Some(item) = high.pop_front() {
                self.total_scheduled.fetch_add(1, Ordering::Relaxed);
                return Some(item);
            }
        }

        // 2. 4:1 Weighted Round-Robin between NORMAL and LOW
        let mut wrr = self.wrr_counter.lock().unwrap();
        let mut normal = self.normal_queue.lock().unwrap();
        let mut low = self.low_queue.lock().unwrap();

        if normal.is_empty() && low.is_empty() {
            return None;
        }

        let item = if *wrr < 4 {
            // First 4 steps in WRR cycle: favor Normal
            if let Some(item) = normal.pop_front() {
                *wrr = (*wrr + 1) % 5;
                Some(item)
            } else {
                // If Normal is empty, yield to Low
                let item = low.pop_front();
                *wrr = (*wrr + 1) % 5;
                item
            }
        } else {
            // 5th step in WRR cycle (wrr == 4): favor Low
            if let Some(item) = low.pop_front() {
                *wrr = 0;
                Some(item)
            } else {
                // If Low is empty, yield to Normal
                let item = normal.pop_front();
                *wrr = 0;
                item
            }
        };

        if item.is_some() {
            self.total_scheduled.fetch_add(1, Ordering::Relaxed);
        }
        item
    }

    /// Returns queue depths as `(high_count, normal_count, low_count)`.
    pub fn queue_depths(&self) -> (usize, usize, usize) {
        (
            self.high_queue.lock().unwrap().len(),
            self.normal_queue.lock().unwrap().len(),
            self.low_queue.lock().unwrap().len(),
        )
    }

    /// Total number of items queued across all priority levels.
    pub fn len(&self) -> usize {
        let (h, n, l) = self.queue_depths();
        h + n + l
    }

    /// Whether all priority queues are currently empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reference to the underlying bandwidth allocator.
    pub fn allocator(&self) -> &HierarchicalBandwidthAllocator {
        &self.allocator
    }

    /// Total number of items scheduled so far.
    pub fn total_scheduled(&self) -> u64 {
        self.total_scheduled.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_rate_parsing() {
        assert_eq!(
            BandwidthRate::from_str("unlimited").unwrap(),
            BandwidthRate::UNLIMITED
        );
        assert_eq!(
            BandwidthRate::from_str("0").unwrap(),
            BandwidthRate::UNLIMITED
        );
        assert_eq!(
            BandwidthRate::from_str("100Mbps").unwrap(),
            BandwidthRate::from_bps(100_000_000)
        );
        assert_eq!(
            BandwidthRate::from_str("1Gbps").unwrap(),
            BandwidthRate::from_bps(1_000_000_000)
        );
        assert_eq!(
            BandwidthRate::from_str("10Gbps").unwrap(),
            BandwidthRate::from_bps(10_000_000_000)
        );
        assert_eq!(
            BandwidthRate::from_str("12500000").unwrap(),
            BandwidthRate::from_bytes_per_sec(12_500_000)
        );
        assert_eq!(
            BandwidthRate::from_str("50MB/s").unwrap(),
            BandwidthRate::from_bytes_per_sec(50_000_000)
        );
        assert_eq!(
            BandwidthRate::from_str("1GB/s").unwrap(),
            BandwidthRate::from_bytes_per_sec(1_000_000_000)
        );
        assert!(BandwidthRate::from_str("invalid_rate").is_err());
    }

    #[test]
    fn test_bandwidth_rate_display() {
        assert_eq!(BandwidthRate::UNLIMITED.to_string(), "unlimited");
        assert_eq!(BandwidthRate::from_bps(100_000_000).to_string(), "100Mbps");
        assert_eq!(BandwidthRate::from_bps(1_000_000_000).to_string(), "1Gbps");
    }

    #[test]
    fn test_hierarchical_bandwidth_allocation() {
        let global_rate = BandwidthRate::from_bytes_per_sec(1_000_000); // 1 MB/s
        let allocator = HierarchicalBandwidthAllocator::new(global_rate);
        let tid = TransferId::from_bytes(&[1u8; 16]).unwrap();

        // Unthrottled small consume within initial burst capacity
        let delay1 = allocator.consume("alice", &tid, 10_000);
        assert_eq!(delay1, Duration::ZERO);

        // Exceed burst capacity
        let delay2 = allocator.consume("alice", &tid, 2_000_000);
        assert!(delay2 > Duration::ZERO);

        // Per-user limiter set lower than global
        allocator.set_user_rate("bob", BandwidthRate::from_bytes_per_sec(100_000)); // 100 KB/s
        let tid_bob = TransferId::from_bytes(&[2u8; 16]).unwrap();
        let delay_bob = allocator.consume("bob", &tid_bob, 500_000);
        assert!(delay_bob > Duration::ZERO);
        assert!(delay_bob >= Duration::from_secs(4)); // 400KB deficit at 100KB/s takes ~4s
    }

    #[test]
    fn test_fairness_scheduler_high_priority_exhaustion() {
        let allocator = Arc::new(HierarchicalBandwidthAllocator::default());
        let scheduler: FairnessScheduler<i32> = FairnessScheduler::new(allocator);
        let tid = TransferId::from_bytes(&[0u8; 16]).unwrap();

        scheduler.enqueue(1, PriorityClass::Normal, "user1", tid);
        scheduler.enqueue(2, PriorityClass::Low, "user1", tid);
        scheduler.enqueue(3, PriorityClass::High, "user1", tid);
        scheduler.enqueue(4, PriorityClass::Normal, "user1", tid);
        scheduler.enqueue(5, PriorityClass::High, "user1", tid);

        // High priority items must dequeue first, regardless of arrival order
        assert_eq!(scheduler.dequeue().unwrap().item, 3);
        assert_eq!(scheduler.dequeue().unwrap().item, 5);
        assert_eq!(scheduler.queue_depths(), (0, 2, 1));
    }

    #[test]
    fn test_fairness_scheduler_4_to_1_wrr() {
        let allocator = Arc::new(HierarchicalBandwidthAllocator::default());
        let scheduler: FairnessScheduler<String> = FairnessScheduler::new(allocator);
        let tid = TransferId::from_bytes(&[0u8; 16]).unwrap();

        // Enqueue 8 Normal and 4 Low items
        for i in 1..=8 {
            scheduler.enqueue(format!("normal-{}", i), PriorityClass::Normal, "user1", tid);
        }
        for i in 1..=4 {
            scheduler.enqueue(format!("low-{}", i), PriorityClass::Low, "user1", tid);
        }

        // Cycle 1: 4 Normal, followed by 1 Low
        assert_eq!(scheduler.dequeue().unwrap().item, "normal-1");
        assert_eq!(scheduler.dequeue().unwrap().item, "normal-2");
        assert_eq!(scheduler.dequeue().unwrap().item, "normal-3");
        assert_eq!(scheduler.dequeue().unwrap().item, "normal-4");
        assert_eq!(scheduler.dequeue().unwrap().item, "low-1");

        // Cycle 2: 4 Normal, followed by 1 Low
        assert_eq!(scheduler.dequeue().unwrap().item, "normal-5");
        assert_eq!(scheduler.dequeue().unwrap().item, "normal-6");
        assert_eq!(scheduler.dequeue().unwrap().item, "normal-7");
        assert_eq!(scheduler.dequeue().unwrap().item, "normal-8");
        assert_eq!(scheduler.dequeue().unwrap().item, "low-2");

        // Remaining: low-3, low-4
        assert_eq!(scheduler.dequeue().unwrap().item, "low-3");
        assert_eq!(scheduler.dequeue().unwrap().item, "low-4");
        assert!(scheduler.is_empty());
    }
}
