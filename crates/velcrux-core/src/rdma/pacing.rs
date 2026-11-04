//! RoCEv2 Hardware Congestion Control, DCQCN Flow Pacing, and Priority Flow Control (PFC).
//!
//! Implements Data Center Quantized Congestion Notification (DCQCN) with
//! Multiplicative Decrease, Additive Increase (AI), Hyper-Increase (HI),
//! and 802.1Qbb Priority Flow Control pause accounting.
//!
//! Complies strictly with `#![forbid(unsafe_code)]`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// DCQCN Rate Limiting Stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum DcqcnStage {
    /// Fast recovery stage: ramping back to target rate.
    FastRecovery,
    /// Additive increase stage: steady linear exploration.
    AdditiveIncrease,
    /// Hyper increase stage: aggressive recovery under clean conditions.
    HyperIncrease,
}

/// Parameters configuring DCQCN Congestion Control.
#[derive(Debug, Clone)]
pub struct DcqcnConfig {
    /// Weight parameter `g` for exponential moving average of `alpha` (default: 0.0625).
    pub g: f64,
    /// Minimum rate limit in bytes per second (default: 10 MB/s).
    pub min_rate_bps: u64,
    /// Line rate capacity in bytes per second (default: 100 Gbps = 12.5 GB/s).
    pub line_rate_bps: u64,
    /// Additive increase step in bytes per second (default: 50 MB/s).
    pub rate_ai_bps: u64,
    /// Hyper increase step in bytes per second (default: 200 MB/s).
    pub rate_hai_bps: u64,
    /// Byte counter threshold to advance recovery stages (default: 10 MB).
    pub byte_threshold: u64,
}

impl Default for DcqcnConfig {
    fn default() -> Self {
        Self {
            g: 0.0625,
            min_rate_bps: 10_000_000,           // 10 MB/s
            line_rate_bps: 100_000_000_000 / 8, // 100 Gbps (12.5 GB/s)
            rate_ai_bps: 50_000_000,            // 50 MB/s
            rate_hai_bps: 200_000_000,          // 200 MB/s
            byte_threshold: 10_000_000,         // 10 MB
        }
    }
}

/// State tracking for DCQCN rate limiter per flow/QP.
#[derive(Debug)]
pub struct DcqcnState {
    /// Moving average congestion estimator `alpha` (in [0.0, 1.0]).
    pub alpha: f64,
    /// Current transmission rate in bytes/sec.
    pub current_rate: u64,
    /// Target transmission rate in bytes/sec.
    pub target_rate: u64,
    /// Current recovery stage.
    pub stage: DcqcnStage,
    /// Counter of consecutive recovery intervals.
    pub recovery_step: u32,
    /// Bytes transmitted in current recovery interval.
    pub bytes_in_interval: u64,
}

/// Hardware-Assisted RoCEv2 DCQCN Pacer.
#[derive(Debug)]
pub struct DcqcnPacer {
    config: DcqcnConfig,
    state: RwLock<DcqcnState>,
    cnp_received_count: AtomicU64,
    pfc_pause_count: AtomicU64,
    total_bytes_paced: AtomicU64,
}

impl DcqcnPacer {
    /// Initialize a new DCQCN Pacer with default or custom configuration.
    pub fn new(config: DcqcnConfig) -> Self {
        let initial_rate = config.line_rate_bps;
        Self {
            state: RwLock::new(DcqcnState {
                alpha: 0.0,
                current_rate: initial_rate,
                target_rate: initial_rate,
                stage: DcqcnStage::AdditiveIncrease,
                recovery_step: 0,
                bytes_in_interval: 0,
            }),
            config,
            cnp_received_count: AtomicU64::new(0),
            pfc_pause_count: AtomicU64::new(0),
            total_bytes_paced: AtomicU64::new(0),
        }
    }

    /// Process a received Congestion Notification Packet (CNP).
    ///
    /// Triggers multiplicative rate decrease:
    /// - `TargetRate = CurrentRate`
    /// - `CurrentRate = CurrentRate * (1 - alpha / 2)`
    /// - Updates `alpha = (1 - g) * alpha + g`
    pub fn on_cnp(&self) {
        self.cnp_received_count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut st) = self.state.write() {
            // Update alpha
            st.alpha = (1.0 - self.config.g) * st.alpha + self.config.g;

            // Multiplicative decrease
            st.target_rate = st.current_rate;
            let decrease_factor = (1.0 - (st.alpha / 2.0)).max(0.2);
            let new_rate = (st.current_rate as f64 * decrease_factor) as u64;
            st.current_rate = new_rate.max(self.config.min_rate_bps);

            // Reset recovery cycle
            st.stage = DcqcnStage::FastRecovery;
            st.recovery_step = 0;
            st.bytes_in_interval = 0;
        }
    }

    /// Account for transmitted bytes and advance the rate recovery state machine.
    pub fn on_bytes_transmitted(&self, bytes: u64) {
        self.total_bytes_paced.fetch_add(bytes, Ordering::Relaxed);
        if let Ok(mut st) = self.state.write() {
            st.bytes_in_interval += bytes;

            if st.bytes_in_interval >= self.config.byte_threshold {
                st.bytes_in_interval = 0;
                st.recovery_step += 1;

                // Decay alpha over time / clean intervals
                st.alpha = (1.0 - self.config.g) * st.alpha;

                // Advance recovery stages
                match st.stage {
                    DcqcnStage::FastRecovery => {
                        // Blend current rate towards target rate
                        st.current_rate = (st.current_rate + st.target_rate) / 2;
                        if st.recovery_step >= 5 {
                            st.stage = DcqcnStage::AdditiveIncrease;
                            st.recovery_step = 0;
                        }
                    }
                    DcqcnStage::AdditiveIncrease => {
                        st.target_rate = (st.target_rate + self.config.rate_ai_bps)
                            .min(self.config.line_rate_bps);
                        st.current_rate = (st.current_rate + st.target_rate) / 2;
                        if st.recovery_step >= 5 {
                            st.stage = DcqcnStage::HyperIncrease;
                            st.recovery_step = 0;
                        }
                    }
                    DcqcnStage::HyperIncrease => {
                        st.target_rate = (st.target_rate + self.config.rate_hai_bps)
                            .min(self.config.line_rate_bps);
                        st.current_rate = (st.current_rate + st.target_rate) / 2;
                    }
                }
            }
        }
    }

    /// Record an 802.1Qbb Priority Flow Control (PFC) pause frame event.
    pub fn on_pfc_pause(&self) {
        self.pfc_pause_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Return current transmission rate in Gbps.
    pub fn current_rate_gbps(&self) -> f64 {
        self.state
            .read()
            .map(|st| (st.current_rate as f64 * 8.0) / 1_000_000_000.0)
            .unwrap_or(0.0)
    }

    /// Return comprehensive DCQCN telemetry report.
    pub fn report(&self) -> DcqcnReport {
        let (alpha, curr_rate, target_rate, stage) = self
            .state
            .read()
            .map(|st| (st.alpha, st.current_rate, st.target_rate, st.stage))
            .unwrap_or((0.0, 0, 0, DcqcnStage::AdditiveIncrease));

        DcqcnReport {
            alpha,
            current_rate_bps: curr_rate,
            current_rate_gbps: (curr_rate as f64 * 8.0) / 1_000_000_000.0,
            target_rate_bps: target_rate,
            target_rate_gbps: (target_rate as f64 * 8.0) / 1_000_000_000.0,
            stage,
            cnp_count: self.cnp_received_count.load(Ordering::Relaxed),
            pfc_pause_count: self.pfc_pause_count.load(Ordering::Relaxed),
            total_bytes_paced: self.total_bytes_paced.load(Ordering::Relaxed),
        }
    }
}

/// Structured DCQCN telemetry report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DcqcnReport {
    pub alpha: f64,
    pub current_rate_bps: u64,
    pub current_rate_gbps: f64,
    pub target_rate_bps: u64,
    pub target_rate_gbps: f64,
    pub stage: DcqcnStage,
    pub cnp_count: u64,
    pub pfc_pause_count: u64,
    pub total_bytes_paced: u64,
}
