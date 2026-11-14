//! Dynamic Rate Pacing & Loss-Adaptive Stream Controller (ADR-082).
//!
//! Dynamically adjusts Fountain code rate and repair symbol pacing based on
//! real-time network loss telemetry and round-trip time bounds.

use serde::{Deserialize, Serialize};

/// Dynamic rate pacer adapting Fountain repair redundancy to network loss.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FountainRatePacer {
    /// Measured network packet loss ratio in range [0.0, 1.0).
    pub loss_ratio: f64,
    /// Safety margin factor beyond theoretical minimum (default: 0.10).
    pub safety_margin: f64,
    /// Measured Round-Trip Time in milliseconds.
    pub rtt_ms: u64,
    /// Total symbols transmitted.
    pub transmitted_symbols: usize,
    /// Total packets confirmed received.
    pub received_symbols: usize,
}

impl Default for FountainRatePacer {
    fn default() -> Self {
        Self::new(0.10)
    }
}

impl FountainRatePacer {
    /// Create a new rate pacer with a specific safety margin.
    #[must_use]
    pub fn new(safety_margin: f64) -> Self {
        Self {
            loss_ratio: 0.0,
            safety_margin: safety_margin.clamp(0.01, 1.0),
            rtt_ms: 20,
            transmitted_symbols: 0,
            received_symbols: 0,
        }
    }

    /// Update telemetry observations from receiver feedback.
    pub fn record_feedback(&mut self, loss_ratio: f64, rtt_ms: u64) {
        // Exponential moving average update (alpha = 0.25)
        self.loss_ratio = (self.loss_ratio * 0.75) + (loss_ratio.clamp(0.0, 0.95) * 0.25);
        self.rtt_ms = rtt_ms;
    }

    /// Compute target repair overhead multiplier.
    ///
    /// For loss rate $L$, transmission multiplier is $\frac{1}{1 - L} \times (1 + \alpha)$.
    #[must_use]
    pub fn target_multiplier(&self) -> f64 {
        let eff_loss = self.loss_ratio.min(0.95);
        (1.0 / (1.0 - eff_loss)) * (1.0 + self.safety_margin)
    }

    /// Calculate total symbols to transmit for $K$ source symbols.
    #[must_use]
    pub fn target_symbols_to_transmit(&self, k: usize) -> usize {
        let mult = self.target_multiplier();
        ((k as f64) * mult).ceil() as usize
    }

    /// Compute pacing inter-packet delay in microseconds for a target throughput in MB/s.
    #[must_use]
    pub fn pace_delay_us(&self, target_mb_s: f64, symbol_size_bytes: usize) -> u64 {
        if target_mb_s <= 0.0 {
            return 0;
        }
        let bytes_per_sec = target_mb_s * 1024.0 * 1024.0;
        let packets_per_sec = bytes_per_sec / (symbol_size_bytes as f64);
        if packets_per_sec <= 0.0 {
            return 0;
        }
        ((1_000_000.0 / packets_per_sec) as u64).max(1)
    }
}
