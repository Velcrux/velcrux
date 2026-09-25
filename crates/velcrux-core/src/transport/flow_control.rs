#![forbid(unsafe_code)]

//! Transport flow control, BDP window auto-tuning, and adaptive pipeline scheduling.
//!
//! Implements requirements from `OPERATIONS.md` §4, `PERFORMANCE.md` §2, §10, and
//! `REQUIREMENTS.md` §25, §30.
//!
//! A window smaller than the Bandwidth-Delay Product (BDP) caps throughput at
//! `window / RTT` regardless of link capacity. To saturate high-speed long-haul paths
//! without bubbling or starvation, the flow control window must be sized to at least
//! `2 × BDP`. Conversely, on low-latency LAN links, oversized windows waste kernel and
//! socket buffer memory. This module provides mathematically grounded BDP auto-tuning,
//! dynamic stream concurrency estimation, and burst pacing.

use std::time::Duration;

use crate::transport::stats::TransportStats;

/// Minimum flow control window clamped to prevent starvation (16 MiB).
pub const MIN_RECEIVE_WINDOW: u64 = 16 * 1024 * 1024;

/// Maximum flow control window allowed for massive BDP links (1 GiB).
pub const MAX_RECEIVE_WINDOW: u64 = 1024 * 1024 * 1024;

/// Default BDP multiplier for smooth pipeline buffering (2.0 = 2 × BDP).
pub const DEFAULT_BDP_MULTIPLIER: f64 = 2.0;

/// Bandwidth-Delay Product (BDP) estimator and window sizer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BdpEstimator {
    multiplier: f64,
    min_window: u64,
    max_window: u64,
}

impl Default for BdpEstimator {
    fn default() -> Self {
        Self {
            multiplier: DEFAULT_BDP_MULTIPLIER,
            min_window: MIN_RECEIVE_WINDOW,
            max_window: MAX_RECEIVE_WINDOW,
        }
    }
}

impl BdpEstimator {
    /// Create a new BDP estimator with custom window bounds and multiplier.
    pub fn new(multiplier: f64, min_window: u64, max_window: u64) -> Self {
        Self {
            multiplier: multiplier.max(1.0),
            min_window,
            max_window: max_window.max(min_window),
        }
    }

    /// Calculate raw Bandwidth-Delay Product in bytes:
    /// `BDP = bandwidth (bytes/s) × RTT (seconds)`
    pub fn calculate_bdp(bandwidth_bytes_per_sec: u64, rtt: Duration) -> u64 {
        let rtt_secs = rtt.as_secs_f64();
        (bandwidth_bytes_per_sec as f64 * rtt_secs).round() as u64
    }

    /// Compute the optimal connection receive window:
    /// `W_conn = clamp(multiplier × BDP, min_window, max_window)`
    pub fn optimal_receive_window(&self, bandwidth_bytes_per_sec: u64, rtt: Duration) -> u64 {
        let bdp = Self::calculate_bdp(bandwidth_bytes_per_sec, rtt);
        let target = (bdp as f64 * self.multiplier).round() as u64;
        target.clamp(self.min_window, self.max_window)
    }

    /// Compute the optimal per-stream receive window.
    ///
    /// Sized equal to the connection receive window or capped at connection window limit.
    pub fn optimal_stream_receive_window(
        &self,
        bandwidth_bytes_per_sec: u64,
        rtt: Duration,
    ) -> u64 {
        let conn_win = self.optimal_receive_window(bandwidth_bytes_per_sec, rtt);
        conn_win.clamp(self.min_window, self.max_window)
    }

    /// Calculate optimal chunk concurrency (parallel streams) to saturate the BDP pipe:
    /// `concurrency = clamp(ceil((2 × BDP) / chunk_size), 1, max_concurrency)`
    pub fn optimal_concurrency(
        &self,
        bandwidth_bytes_per_sec: u64,
        rtt: Duration,
        chunk_size: u64,
        max_concurrency: usize,
    ) -> usize {
        if chunk_size == 0 || max_concurrency == 0 {
            return 1;
        }
        let bdp = Self::calculate_bdp(bandwidth_bytes_per_sec, rtt);
        let buffered_pipe = (bdp as f64 * self.multiplier) as u64;
        let streams = ((buffered_pipe + chunk_size - 1) / chunk_size) as usize;
        streams.clamp(1, max_concurrency)
    }
}

/// Dynamic flow controller that tracks live transport telemetry and guides chunk scheduling.
#[derive(Debug, Clone)]
pub struct AdaptiveFlowController {
    estimator: BdpEstimator,
    target_bandwidth_bytes_per_sec: u64,
    measured_rtt: Duration,
    measured_throughput_bytes_per_sec: u64,
    consecutive_loss_events: u64,
    last_loss_count: u64,
}

impl AdaptiveFlowController {
    /// Construct a new adaptive controller with an initial target bandwidth and expected RTT.
    pub fn new(initial_bandwidth_bytes_per_sec: u64, initial_rtt: Duration) -> Self {
        Self {
            estimator: BdpEstimator::default(),
            target_bandwidth_bytes_per_sec: initial_bandwidth_bytes_per_sec,
            measured_rtt: initial_rtt,
            measured_throughput_bytes_per_sec: initial_bandwidth_bytes_per_sec,
            consecutive_loss_events: 0,
            last_loss_count: 0,
        }
    }

    /// Update controller state from transport statistics.
    pub fn update_transport_stats(&mut self, stats: &TransportStats) {
        if let Some(rtt) = stats.rtt {
            if rtt > Duration::ZERO {
                // Exponential moving average for smoothed RTT: 7/8 * old + 1/8 * sample
                let current_micros = self.measured_rtt.as_micros() as f64;
                let sample_micros = rtt.as_micros() as f64;
                let smoothed = (0.875 * current_micros) + (0.125 * sample_micros);
                self.measured_rtt = Duration::from_micros(smoothed.round() as u64);
            }
        }

        if stats.loss_events > self.last_loss_count {
            self.consecutive_loss_events = self
                .consecutive_loss_events
                .saturating_add(stats.loss_events - self.last_loss_count);
            self.last_loss_count = stats.loss_events;
        } else {
            // Decay loss signal when clean
            self.consecutive_loss_events = (self.consecutive_loss_events * 7) / 8;
        }
    }

    /// Record a completed chunk transfer sample to update measured throughput.
    pub fn record_transfer_sample(&mut self, bytes_transferred: u64, elapsed: Duration) {
        if elapsed.as_nanos() == 0 || bytes_transferred == 0 {
            return;
        }
        let sample_throughput = (bytes_transferred as f64 / elapsed.as_secs_f64()).round() as u64;
        let prev = self.measured_throughput_bytes_per_sec as f64;
        let updated = (0.80 * prev) + (0.20 * sample_throughput as f64);
        self.measured_throughput_bytes_per_sec = updated.round() as u64;
    }

    /// Current effective bandwidth used for BDP sizing (combines configured target and observed throughput).
    pub fn effective_bandwidth(&self) -> u64 {
        if self.target_bandwidth_bytes_per_sec > 0 {
            self.target_bandwidth_bytes_per_sec
                .min(self.measured_throughput_bytes_per_sec.max(1024 * 1024))
        } else {
            self.measured_throughput_bytes_per_sec.max(1024 * 1024)
        }
    }

    /// Current target inflight window in bytes:
    /// `inflight_limit = 2 × BDP`, scaled down if experiencing consecutive loss.
    pub fn target_inflight_window(&self) -> u64 {
        let base_win = self
            .estimator
            .optimal_receive_window(self.effective_bandwidth(), self.measured_rtt);
        if self.consecutive_loss_events > 5 {
            // Backoff on sustained congestion
            (base_win * 3 / 4).max(self.estimator.min_window)
        } else {
            base_win
        }
    }

    /// Returns `true` if an additional chunk of `next_chunk_bytes` can be dispatched
    /// without violating the flow control inflight window.
    pub fn can_dispatch(&self, current_inflight_bytes: u64, next_chunk_bytes: u64) -> bool {
        current_inflight_bytes.saturating_add(next_chunk_bytes) <= self.target_inflight_window()
    }

    /// Computes the optimal concurrency limit for the current path state.
    pub fn optimal_concurrency(&self, chunk_size: u64, max_concurrency: usize) -> usize {
        self.estimator.optimal_concurrency(
            self.effective_bandwidth(),
            self.measured_rtt,
            chunk_size,
            max_concurrency,
        )
    }

    /// Get current smoothed RTT.
    pub fn rtt(&self) -> Duration {
        self.measured_rtt
    }

    /// Get current measured throughput in bytes/second.
    pub fn measured_throughput(&self) -> u64 {
        self.measured_throughput_bytes_per_sec
    }
}

/// Application-level rate and burst pacing controller.
///
/// Smooths packet departure to prevent burst-induced buffer overflows.
#[derive(Debug, Clone)]
pub struct PacingController {
    rate_bytes_per_sec: u64,
    burst_allowance_bytes: u64,
    tokens: f64,
    last_update: std::time::Instant,
}

impl PacingController {
    /// Construct a new pacing controller with target rate in bytes/sec and max burst allowance.
    pub fn new(rate_bytes_per_sec: u64, burst_allowance_bytes: u64) -> Self {
        Self {
            rate_bytes_per_sec,
            burst_allowance_bytes,
            tokens: burst_allowance_bytes as f64,
            last_update: std::time::Instant::now(),
        }
    }

    /// Calculate the sleep duration needed before transmitting `chunk_bytes`.
    ///
    /// If sufficient token allowance exists, returns `Duration::ZERO`.
    pub fn calculate_pacing_delay(&mut self, chunk_bytes: u64) -> Duration {
        if self.rate_bytes_per_sec == 0 {
            return Duration::ZERO;
        }

        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        // Refill tokens
        self.tokens = (self.tokens + elapsed * self.rate_bytes_per_sec as f64)
            .min(self.burst_allowance_bytes as f64);

        if self.tokens >= chunk_bytes as f64 {
            self.tokens -= chunk_bytes as f64;
            Duration::ZERO
        } else {
            let deficit = chunk_bytes as f64 - self.tokens;
            self.tokens = 0.0;
            let wait_secs = deficit / self.rate_bytes_per_sec as f64;
            Duration::from_secs_f64(wait_secs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bdp_estimator_lan_wan_profiles() {
        let est = BdpEstimator::default();

        // 1. LAN: 10 Gbps (1.25 GB/s), 1 ms RTT
        // BDP = 1,250,000,000 * 0.001 = 1,250,000 bytes (~1.25 MB)
        // 2 * BDP = ~2.5 MB, clamped to MIN_RECEIVE_WINDOW (16 MiB)
        let lan_bandwidth = 1_250_000_000;
        let lan_rtt = Duration::from_millis(1);
        assert_eq!(
            est.optimal_receive_window(lan_bandwidth, lan_rtt),
            16 * 1024 * 1024
        );

        // 2. Standard WAN: 1 Gbps (125 MB/s), 80 ms RTT
        // BDP = 125,000,000 * 0.08 = 10,000,000 bytes (10 MB)
        // 2 * BDP = 20 MB = 20,000,000 bytes
        let wan_bandwidth = 125_000_000;
        let wan_rtt = Duration::from_millis(80);
        let wan_win = est.optimal_receive_window(wan_bandwidth, wan_rtt);
        assert_eq!(wan_win, 20_000_000);

        // 3. Transatlantic Long-Haul: 10 Gbps (1.25 GB/s), 150 ms RTT (PERFORMANCE.md §2)
        // BDP = 1,250,000,000 * 0.15 = 187,500,000 bytes (187.5 MB)
        // 2 * BDP = 375,000,000 bytes (~375 MB)
        let trans_bandwidth = 1_250_000_000;
        let trans_rtt = Duration::from_millis(150);
        let trans_win = est.optimal_receive_window(trans_bandwidth, trans_rtt);
        assert_eq!(trans_win, 375_000_000);

        // 4. Ultra-WAN / Satellite: 10 Gbps (1.25 GB/s), 300 ms RTT
        // BDP = 375 MB, 2 * BDP = 750 MB
        let sat_rtt = Duration::from_millis(300);
        let sat_win = est.optimal_receive_window(trans_bandwidth, sat_rtt);
        assert_eq!(sat_win, 750_000_000);

        // 5. Extreme link clamped to MAX_RECEIVE_WINDOW (1 GiB)
        let extreme_rtt = Duration::from_millis(600);
        let extreme_win = est.optimal_receive_window(trans_bandwidth, extreme_rtt);
        assert_eq!(extreme_win, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_optimal_concurrency_calculation() {
        let est = BdpEstimator::default();
        let chunk_size = 1024 * 1024; // 1 MiB

        // LAN: BDP ~ 1.25 MB -> 2 * BDP = 2.5 MB -> 3 streams
        let lan_concurrency =
            est.optimal_concurrency(1_250_000_000, Duration::from_millis(1), chunk_size, 32);
        assert_eq!(lan_concurrency, 3);

        // Transatlantic: 2 * BDP = 375 MB -> clamped to max_concurrency 32
        let trans_concurrency =
            est.optimal_concurrency(1_250_000_000, Duration::from_millis(150), chunk_size, 32);
        assert_eq!(trans_concurrency, 32);

        // Slow link: 10 MB/s, 50 ms -> BDP = 500 KB -> 2 * BDP = 1 MB -> 1 stream
        let slow_concurrency =
            est.optimal_concurrency(10_000_000, Duration::from_millis(50), chunk_size, 32);
        assert_eq!(slow_concurrency, 1);
    }

    #[test]
    fn test_adaptive_flow_controller_dispatch_gating() {
        let mut ctrl = AdaptiveFlowController::new(125_000_000, Duration::from_millis(80));
        let win = ctrl.target_inflight_window();
        assert!(win >= 20_000_000);

        // Can dispatch when well within window
        assert!(ctrl.can_dispatch(1_000_000, 1_000_000));

        // Blocked when exceeding target window
        assert!(!ctrl.can_dispatch(win, 1024));

        // Update with stats
        let stats = TransportStats {
            rtt: Some(Duration::from_millis(100)),
            rtt_var: None,
            bytes_in_flight: 5_000_000,
            cwnd: 10_000_000,
            loss_events: 0,
            retransmits: 0,
        };
        ctrl.update_transport_stats(&stats);
        assert!(ctrl.rtt() > Duration::from_millis(80));
    }

    #[test]
    fn test_pacing_controller() {
        let mut pacing = PacingController::new(1_000_000, 2_000_000); // 1 MB/s, 2 MB burst

        // Within burst allowance: delay is zero
        let d1 = pacing.calculate_pacing_delay(1_000_000);
        assert_eq!(d1, Duration::ZERO);

        let d2 = pacing.calculate_pacing_delay(1_000_000);
        assert_eq!(d2, Duration::ZERO);

        // Deficit triggers non-zero pacing delay
        let d3 = pacing.calculate_pacing_delay(500_000);
        assert!(d3 > Duration::ZERO);
        assert!(d3 <= Duration::from_millis(600));
    }
}
