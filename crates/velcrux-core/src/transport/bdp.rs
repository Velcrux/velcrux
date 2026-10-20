//! Adaptive Bandwidth Delay Product (BDP) Auto-Tuning Engine (Option BR).
//!
//! Provides mathematically grounded, real-time BDP auto-tuning for QUIC transport
//! flow control and pipeline buffer scheduling.
//!
//! # Problem
//! In high-speed wide area networks (e.g. 10 Gbps transatlantic or high-latency satellite links),
//! if the transport receive window is smaller than the path Bandwidth-Delay Product (BDP),
//! the sender's transmission is throttled to `Window / RTT`, causing massive throughput collapse
//! regardless of available bandwidth. Conversely, on low-latency local networks (LAN), static
//! 1 GiB windows waste memory and risk severe bufferbloat if a bottleneck queue backs up.
//!
//! # Solution
//! 1. `BdpAutoTuner`: Real-time feedback controller analyzing smoothed RTT, minimum RTT,
//!    observed delivery rate, and packet loss events from QUIC connection telemetry.
//! 2. `BdpTuningPolicy`: Configurable policies (`Auto`, `Fixed`, `Aggressive`, `Conservative`).
//! 3. Bufferbloat Guard: Detects queueing delay inflation when smoothed RTT significantly exceeds
//!    the base propagation delay (`min_rtt`), gently decaying the flow control window.
//! 4. Zero Unsafe Code: Pure `#![forbid(unsafe_code)]` compliance.

#![forbid(unsafe_code)]

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;

/// Absolute minimum flow control window (1 MiB).
pub const ABSOLUTE_MIN_BDP_WINDOW: u64 = 1024 * 1024;

/// Absolute maximum flow control window (1 GiB).
pub const ABSOLUTE_MAX_BDP_WINDOW: u64 = 1024 * 1024 * 1024;

/// Default baseline flow control window (64 MiB).
pub const DEFAULT_INITIAL_BDP_WINDOW: u64 = 64 * 1024 * 1024;

/// Default maximum BDP window ceiling (512 MiB).
pub const DEFAULT_MAX_BDP_WINDOW: u64 = 512 * 1024 * 1024;

/// Default minimum BDP window floor (4 MiB).
pub const DEFAULT_MIN_BDP_WINDOW: u64 = 4 * 1024 * 1024;

/// Default BDP multiplier for pipeline buffering (2.0 = 2 × BDP).
pub const DEFAULT_BDP_MULTIPLIER: f64 = 2.0;

/// BDP tuning policy mode (`Option BR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BdpTuningPolicy {
    /// Dynamically adjust flow control window based on live RTT, delivery rate, and loss (default).
    #[default]
    Auto,
    /// Keep static fixed flow control window without dynamic resizing.
    Fixed,
    /// Aggressively expand window with 3.0× BDP multiplier and reduced decay sensitivity (WAN/Satellite).
    Aggressive,
    /// Conservatively size window with 1.5× BDP multiplier and rapid decay on queue buildup (Shared LAN).
    Conservative,
}

impl fmt::Display for BdpTuningPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BdpTuningPolicy::Auto => write!(f, "auto"),
            BdpTuningPolicy::Fixed => write!(f, "fixed"),
            BdpTuningPolicy::Aggressive => write!(f, "aggressive"),
            BdpTuningPolicy::Conservative => write!(f, "conservative"),
        }
    }
}

impl FromStr for BdpTuningPolicy {
    type Err = VelcruxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "dynamic" | "default" => Ok(BdpTuningPolicy::Auto),
            "fixed" | "static" | "off" => Ok(BdpTuningPolicy::Fixed),
            "aggressive" | "high" | "max" => Ok(BdpTuningPolicy::Aggressive),
            "conservative" | "safe" | "low" => Ok(BdpTuningPolicy::Conservative),
            other => Err(VelcruxError::Config(format!(
                "invalid bdp tuning policy '{other}'; expected auto, fixed, aggressive, or conservative"
            ))),
        }
    }
}

/// Network tier classification based on measured path delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BdpTier {
    /// Local Area Network / Data Center (RTT <= 5 ms).
    #[default]
    Lan,
    /// Metropolitan Network (5 ms < RTT <= 30 ms).
    Metro,
    /// Standard Wide Area Network (30 ms < RTT <= 100 ms).
    Wan,
    /// Long-Haul Transatlantic / Intercontinental (100 ms < RTT <= 200 ms).
    Transatlantic,
    /// High-BDP Satellite / Ultra-WAN (RTT > 200 ms).
    Satellite,
}

impl BdpTier {
    /// Classify link tier from smoothed RTT.
    pub fn from_rtt(rtt: Duration) -> Self {
        let ms = rtt.as_millis();
        if ms <= 5 {
            BdpTier::Lan
        } else if ms <= 30 {
            BdpTier::Metro
        } else if ms <= 100 {
            BdpTier::Wan
        } else if ms <= 200 {
            BdpTier::Transatlantic
        } else {
            BdpTier::Satellite
        }
    }
}

impl fmt::Display for BdpTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BdpTier::Lan => write!(f, "LAN (<=5ms)"),
            BdpTier::Metro => write!(f, "Metro (5-30ms)"),
            BdpTier::Wan => write!(f, "WAN (30-100ms)"),
            BdpTier::Transatlantic => write!(f, "Transatlantic (100-200ms)"),
            BdpTier::Satellite => write!(f, "Satellite (>200ms)"),
        }
    }
}

/// Direction of window adjustment during a tuning cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BdpTuningDirection {
    /// Window expanded to accommodate higher BDP.
    Expand,
    /// Window decayed to alleviate queue buildup or congestion.
    Decay,
    /// Window held constant (optimal steady state).
    Hold,
}

impl fmt::Display for BdpTuningDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BdpTuningDirection::Expand => write!(f, "expand"),
            BdpTuningDirection::Decay => write!(f, "decay"),
            BdpTuningDirection::Hold => write!(f, "hold"),
        }
    }
}

/// Configuration parameters for BDP window sizing and auto-tuning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BdpWindowConfig {
    /// Tuning policy mode.
    pub policy: BdpTuningPolicy,
    /// Minimum window floor in bytes.
    pub min_window_bytes: u64,
    /// Maximum window ceiling in bytes.
    pub max_window_bytes: u64,
    /// Target BDP multiplier (e.g. 2.0 = 2 × BDP).
    pub multiplier: f64,
    /// Bufferbloat detection threshold: ratio of smoothed RTT to min RTT (default: 1.5).
    pub bufferbloat_rtt_ratio: f64,
}

impl Default for BdpWindowConfig {
    fn default() -> Self {
        Self {
            policy: BdpTuningPolicy::Auto,
            min_window_bytes: DEFAULT_MIN_BDP_WINDOW,
            max_window_bytes: DEFAULT_MAX_BDP_WINDOW,
            multiplier: DEFAULT_BDP_MULTIPLIER,
            bufferbloat_rtt_ratio: 1.5,
        }
    }
}

impl BdpWindowConfig {
    /// Create custom configuration with validation.
    pub fn new(policy: BdpTuningPolicy, min_window: u64, max_window: u64, multiplier: f64) -> Self {
        let clamped_min = min_window.clamp(ABSOLUTE_MIN_BDP_WINDOW, ABSOLUTE_MAX_BDP_WINDOW);
        let clamped_max = max_window.clamp(clamped_min, ABSOLUTE_MAX_BDP_WINDOW);
        let eff_mult = match policy {
            BdpTuningPolicy::Aggressive => multiplier.max(3.0),
            BdpTuningPolicy::Conservative => multiplier.clamp(1.2, 1.6),
            _ => multiplier.max(1.0),
        };
        Self {
            policy,
            min_window_bytes: clamped_min,
            max_window_bytes: clamped_max,
            multiplier: eff_mult,
            bufferbloat_rtt_ratio: if policy == BdpTuningPolicy::Conservative {
                1.3
            } else {
                1.5
            },
        }
    }
}

/// Comprehensive inspection report emitted by the BDP auto-tuner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BdpTuningReport {
    /// Current active flow control window in bytes.
    pub current_window_bytes: u64,
    /// Target calculated optimal window in bytes.
    pub target_window_bytes: u64,
    /// Estimated path bandwidth in bits per second.
    pub estimated_bandwidth_bps: u64,
    /// Smoothed round trip time in milliseconds.
    pub smoothed_rtt_ms: f64,
    /// Base propagation round trip time (min RTT) in milliseconds.
    pub min_rtt_ms: f64,
    /// Estimated packet loss rate in parts-per-million (PPM).
    pub loss_rate_ppm: u32,
    /// Classified network delay tier.
    pub tier: BdpTier,
    /// Last adjustment direction.
    pub direction: BdpTuningDirection,
    /// Whether queue buildup / bufferbloat was detected on the link.
    pub bufferbloat_detected: bool,
    /// Cumulative expansion adjustments.
    pub expansions_total: u64,
    /// Cumulative decay adjustments.
    pub decays_total: u64,
    /// Cumulative hold adjustments.
    pub holds_total: u64,
}

/// Adaptive Bandwidth Delay Product (BDP) feedback controller.
#[derive(Debug, Clone)]
pub struct BdpAutoTuner {
    config: BdpWindowConfig,
    current_window: u64,
    smoothed_rtt: Duration,
    min_rtt: Duration,
    estimated_bandwidth_bytes_per_sec: u64,
    loss_events_total: u64,
    last_loss_count: u64,
    expansions_total: u64,
    decays_total: u64,
    holds_total: u64,
    last_direction: BdpTuningDirection,
    bufferbloat_detected: bool,
}

impl Default for BdpAutoTuner {
    fn default() -> Self {
        Self::new(BdpWindowConfig::default())
    }
}

impl BdpAutoTuner {
    /// Construct a new BDP auto-tuner with specified configuration.
    pub fn new(config: BdpWindowConfig) -> Self {
        let initial_win =
            DEFAULT_INITIAL_BDP_WINDOW.clamp(config.min_window_bytes, config.max_window_bytes);
        Self {
            config,
            current_window: initial_win,
            smoothed_rtt: Duration::ZERO,
            min_rtt: Duration::ZERO,
            estimated_bandwidth_bytes_per_sec: 125_000_000, // 1 Gbps initial estimate
            loss_events_total: 0,
            last_loss_count: 0,
            expansions_total: 0,
            decays_total: 0,
            holds_total: 0,
            last_direction: BdpTuningDirection::Hold,
            bufferbloat_detected: false,
        }
    }

    /// Retrieve the current active window in bytes.
    pub fn current_window(&self) -> u64 {
        self.current_window
    }

    /// Retrieve the active network delay tier.
    pub fn current_tier(&self) -> BdpTier {
        BdpTier::from_rtt(self.smoothed_rtt)
    }

    /// Calculate raw BDP in bytes given bandwidth (bytes/sec) and RTT.
    pub fn calculate_bdp(bandwidth_bytes_per_sec: u64, rtt: Duration) -> u64 {
        let rtt_secs = rtt.as_secs_f64();
        (bandwidth_bytes_per_sec as f64 * rtt_secs).round() as u64
    }

    /// Calculate the optimal window target in bytes for given parameters and current policy.
    pub fn calculate_optimal_window(&self, bandwidth_bytes_per_sec: u64, rtt: Duration) -> u64 {
        let raw_bdp = Self::calculate_bdp(bandwidth_bytes_per_sec, rtt);
        let target = (raw_bdp as f64 * self.config.multiplier).round() as u64;
        target.clamp(self.config.min_window_bytes, self.config.max_window_bytes)
    }

    /// Ingest a completed transfer sample and update internal link estimation.
    pub fn record_sample(
        &mut self,
        rtt: Duration,
        bytes_delivered: u64,
        elapsed: Duration,
        loss_events: u64,
    ) -> BdpTuningReport {
        if rtt > Duration::ZERO {
            if self.min_rtt == Duration::ZERO || rtt < self.min_rtt {
                self.min_rtt = rtt;
            }
            if self.smoothed_rtt == Duration::ZERO {
                self.smoothed_rtt = rtt;
            } else {
                // Exponential moving average for smoothed RTT: 7/8 * old + 1/8 * sample (RFC 6298)
                let old_us = self.smoothed_rtt.as_micros() as f64;
                let sample_us = rtt.as_micros() as f64;
                let smoothed_us = (0.875 * old_us) + (0.125 * sample_us);
                self.smoothed_rtt = Duration::from_micros(smoothed_us.round() as u64);
            }
        }

        if elapsed.as_nanos() > 0 && bytes_delivered > 0 {
            let sample_rate = (bytes_delivered as f64 / elapsed.as_secs_f64()).round() as u64;
            let old_rate = self.estimated_bandwidth_bytes_per_sec as f64;
            // Delivery rate filter: 80% previous + 20% sample
            let updated_rate = (0.80 * old_rate) + (0.20 * sample_rate as f64);
            self.estimated_bandwidth_bytes_per_sec = updated_rate.round() as u64;
        }

        if loss_events > self.last_loss_count {
            self.loss_events_total = self
                .loss_events_total
                .saturating_add(loss_events - self.last_loss_count);
            self.last_loss_count = loss_events;
        }

        self.evaluate_tuning()
    }

    /// Execute a tuning evaluation cycle and update the active window.
    pub fn evaluate_tuning(&mut self) -> BdpTuningReport {
        if self.config.policy == BdpTuningPolicy::Fixed {
            self.holds_total += 1;
            self.last_direction = BdpTuningDirection::Hold;
            return self.report();
        }

        // Bufferbloat detection: check if smoothed RTT exceeds min RTT by threshold ratio
        let rtt_ratio = if self.min_rtt.as_micros() > 0 {
            self.smoothed_rtt.as_micros() as f64 / self.min_rtt.as_micros() as f64
        } else {
            1.0
        };

        self.bufferbloat_detected = rtt_ratio >= self.config.bufferbloat_rtt_ratio;

        let target = self
            .calculate_optimal_window(self.estimated_bandwidth_bytes_per_sec, self.smoothed_rtt);

        if self.bufferbloat_detected {
            // Queue is filling up: decay window gently to drain bottleneck buffer
            let decay_factor = match self.config.policy {
                BdpTuningPolicy::Aggressive => 0.90,   // gentle 10% decay
                BdpTuningPolicy::Conservative => 0.70, // steeper 30% decay
                _ => 0.80,                             // standard 20% decay
            };
            let decayed = (self.current_window as f64 * decay_factor).round() as u64;
            self.current_window =
                decayed.clamp(self.config.min_window_bytes, self.config.max_window_bytes);
            self.decays_total += 1;
            self.last_direction = BdpTuningDirection::Decay;
        } else if target > self.current_window {
            // Path can support a larger flow control window
            let diff = target - self.current_window;
            let step = match self.config.policy {
                BdpTuningPolicy::Aggressive => diff, // full step in aggressive mode
                BdpTuningPolicy::Conservative => diff / 4 + 1, // small cautious step
                _ => diff / 2 + 1,                   // half-step exponential convergence
            };
            self.current_window = (self.current_window + step).min(self.config.max_window_bytes);
            self.expansions_total += 1;
            self.last_direction = BdpTuningDirection::Expand;
        } else if self.current_window > target && (self.current_window - target) > (target / 5) {
            // Current window is significantly larger than target: decay towards target
            let step = (self.current_window - target) / 4 + 1;
            self.current_window = self
                .current_window
                .saturating_sub(step)
                .max(self.config.min_window_bytes);
            self.decays_total += 1;
            self.last_direction = BdpTuningDirection::Decay;
        } else {
            self.holds_total += 1;
            self.last_direction = BdpTuningDirection::Hold;
        }

        self.report()
    }

    /// Generate an inspection report snapshot.
    pub fn report(&self) -> BdpTuningReport {
        let target = self
            .calculate_optimal_window(self.estimated_bandwidth_bytes_per_sec, self.smoothed_rtt);
        let bandwidth_bps = self.estimated_bandwidth_bytes_per_sec.saturating_mul(8);
        let loss_rate_ppm = if self.loss_events_total > 0 {
            (self.loss_events_total.min(1000) * 1000) as u32
        } else {
            0
        };

        BdpTuningReport {
            current_window_bytes: self.current_window,
            target_window_bytes: target,
            estimated_bandwidth_bps: bandwidth_bps,
            smoothed_rtt_ms: self.smoothed_rtt.as_secs_f64() * 1000.0,
            min_rtt_ms: self.min_rtt.as_secs_f64() * 1000.0,
            loss_rate_ppm,
            tier: self.current_tier(),
            direction: self.last_direction,
            bufferbloat_detected: self.bufferbloat_detected,
            expansions_total: self.expansions_total,
            decays_total: self.decays_total,
            holds_total: self.holds_total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bdp_tier_classification() {
        assert_eq!(BdpTier::from_rtt(Duration::from_millis(2)), BdpTier::Lan);
        assert_eq!(BdpTier::from_rtt(Duration::from_millis(20)), BdpTier::Metro);
        assert_eq!(BdpTier::from_rtt(Duration::from_millis(80)), BdpTier::Wan);
        assert_eq!(
            BdpTier::from_rtt(Duration::from_millis(150)),
            BdpTier::Transatlantic
        );
        assert_eq!(
            BdpTier::from_rtt(Duration::from_millis(350)),
            BdpTier::Satellite
        );
    }

    #[test]
    fn test_bdp_auto_tuner_expansion_on_wan() {
        let config = BdpWindowConfig::new(
            BdpTuningPolicy::Auto,
            4 * 1024 * 1024,
            512 * 1024 * 1024,
            2.0,
        );
        let mut tuner = BdpAutoTuner::new(config);

        // Feed transatlantic link: 10 Gbps (1.25 GB/s), 150 ms RTT
        // BDP = 1.25 GB/s * 0.15s = 187.5 MB -> target 2 * BDP = 375 MB
        let rtt = Duration::from_millis(150);
        let sample_bytes = 125_000_000;
        let elapsed = Duration::from_millis(100);

        for _ in 0..10 {
            tuner.record_sample(rtt, sample_bytes, elapsed, 0);
        }

        let report = tuner.report();
        assert!(report.current_window_bytes > 100 * 1024 * 1024);
        assert_eq!(report.tier, BdpTier::Transatlantic);
        assert!(report.expansions_total > 0);
        assert!(!report.bufferbloat_detected);
    }

    #[test]
    fn test_bufferbloat_detection_and_decay() {
        let config = BdpWindowConfig::new(
            BdpTuningPolicy::Auto,
            4 * 1024 * 1024,
            256 * 1024 * 1024,
            2.0,
        );
        let mut tuner = BdpAutoTuner::new(config);

        // Baseline min RTT = 20ms
        tuner.record_sample(
            Duration::from_millis(20),
            10_000_000,
            Duration::from_millis(100),
            0,
        );

        // Queue backs up: RTT spikes to 100ms (5x increase)
        let report = tuner.record_sample(
            Duration::from_millis(100),
            10_000_000,
            Duration::from_millis(100),
            1,
        );

        assert!(report.bufferbloat_detected);
        assert_eq!(report.direction, BdpTuningDirection::Decay);
        assert!(tuner.decays_total > 0);
    }

    #[test]
    fn test_policy_parsing_and_clamping() {
        let auto: BdpTuningPolicy = "auto".parse().unwrap();
        assert_eq!(auto, BdpTuningPolicy::Auto);

        let aggressive: BdpTuningPolicy = "aggressive".parse().unwrap();
        assert_eq!(aggressive, BdpTuningPolicy::Aggressive);

        let fixed: BdpTuningPolicy = "fixed".parse().unwrap();
        assert_eq!(fixed, BdpTuningPolicy::Fixed);

        let conservative: BdpTuningPolicy = "conservative".parse().unwrap();
        assert_eq!(conservative, BdpTuningPolicy::Conservative);

        assert!("invalid_policy".parse::<BdpTuningPolicy>().is_err());
    }
}
