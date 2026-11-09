#![forbid(unsafe_code)]

//! Autonomous Closed-Loop Self-Healing Traffic Shaper.
//!
//! Applies dynamic pacing throttling, FEC redundancy scaling, subflow rerouting,
//! and queue draining in response to real-time detected transport anomalies.

use serde::{Deserialize, Serialize};

use super::classifier::{AnomalyClassification, AnomalyType};
use super::features::MetricSample;

/// Action commanded by the self-healing traffic shaper actuator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ShaperAction {
    /// Adjusts token bucket pacing transmission rate.
    AdjustPacingRate {
        new_pacing_bps: f64,
        scale_factor: f64,
        reason: String,
    },
    /// Adjusts Reed-Solomon / RaptorQ erasure code parity symbol redundancy.
    ScaleFecRedundancy { new_fec_ratio: f64, reason: String },
    /// Reroutes bulk data traffic away from impaired subflow to a backup path.
    RerouteSubflow {
        target_subflow_id: u32,
        reason: String,
    },
    /// Sheds lower-priority background bulk flows to protect interactive traffic.
    ShedLoad {
        shed_fraction: f64,
        priority_cutoff: u8,
        reason: String,
    },
    /// Forces renegotiation or probing of the Path MTU.
    TriggerPmtuProbe { target_mtu: u16, reason: String },
    /// Temporarily collapses the inflight window to flush intermediate queues.
    DrainQueue {
        drain_duration_ms: u64,
        reason: String,
    },
    /// Maintains current steady-state baseline parameters.
    HoldBaseline,
}

impl ShaperAction {
    pub fn name(&self) -> &'static str {
        match self {
            Self::AdjustPacingRate { .. } => "adjust_pacing_rate",
            Self::ScaleFecRedundancy { .. } => "scale_fec_redundancy",
            Self::RerouteSubflow { .. } => "reroute_subflow",
            Self::ShedLoad { .. } => "shed_load",
            Self::TriggerPmtuProbe { .. } => "trigger_pmtu_probe",
            Self::DrainQueue { .. } => "drain_queue",
            Self::HoldBaseline => "hold_baseline",
        }
    }
}

/// Closed-loop autonomous traffic shaper state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfHealingShaper {
    /// Configured link baseline capacity in bits per second.
    pub baseline_capacity_bps: f64,
    /// Current commanded pacing transmission rate in bits per second.
    pub current_pacing_bps: f64,
    /// Current FEC redundancy ratio [0.0, 0.50].
    pub current_fec_ratio: f64,
    /// Minimum pacing rate clamp.
    pub min_pacing_bps: f64,
    /// Maximum pacing rate clamp.
    pub max_pacing_bps: f64,
    /// Cooldown window in milliseconds between consecutive mitigation actuations.
    pub cooldown_ms: u64,
    /// Timestamp of last applied actuation action.
    pub last_action_ms: u64,
    /// Active anomaly under mitigation, if any.
    pub active_anomaly: Option<AnomalyType>,
    /// Throughput measured right before mitigation was triggered.
    pub pre_mitigation_throughput: f64,
    /// Cumulative count of autonomous self-healing mitigations executed.
    pub total_mitigations_applied: u64,
    /// Consecutive healthy sample counter for gradual rate recovery.
    pub healthy_consecutive_count: u32,
}

impl SelfHealingShaper {
    /// Initializes shaper with link bandwidth baseline.
    pub fn new(baseline_capacity_bps: f64) -> Self {
        let baseline = baseline_capacity_bps.max(10_000_000.0); // min 10 Mbps
        Self {
            baseline_capacity_bps: baseline,
            current_pacing_bps: baseline,
            current_fec_ratio: 0.05,         // default 5% parity
            min_pacing_bps: baseline * 0.10, // min 10%
            max_pacing_bps: baseline * 1.50, // max 150%
            cooldown_ms: 300,                // 300ms cooldown
            last_action_ms: 0,
            active_anomaly: None,
            pre_mitigation_throughput: baseline,
            total_mitigations_applied: 0,
            healthy_consecutive_count: 0,
        }
    }

    /// Evaluates current state and anomaly classification to command an actuation action.
    pub fn decide_action(
        &mut self,
        sample: &MetricSample,
        classification: Option<&AnomalyClassification>,
    ) -> ShaperAction {
        let now = sample.timestamp_ms;

        // If an anomaly is present
        if let Some(anomaly) = classification {
            self.healthy_consecutive_count = 0;

            // Check cooldown
            if now < self.last_action_ms + self.cooldown_ms {
                return ShaperAction::HoldBaseline;
            }

            self.active_anomaly = Some(anomaly.anomaly_type);
            self.pre_mitigation_throughput = sample.throughput_bps;
            self.last_action_ms = now;
            self.total_mitigations_applied += 1;

            match anomaly.anomaly_type {
                AnomalyType::Bufferbloat => {
                    // Step down pacing rate by 30% to drain intermediate buffers
                    let factor = 0.70;
                    let target_rate = (self.current_pacing_bps * factor).max(self.min_pacing_bps);
                    self.current_pacing_bps = target_rate;
                    ShaperAction::AdjustPacingRate {
                        new_pacing_bps: target_rate,
                        scale_factor: factor,
                        reason: format!(
                            "Bufferbloat mitigated: Pacing rate reduced to {:.2} Mbps (-30%) to drain queuing delay",
                            target_rate / 1_000_000.0
                        ),
                    }
                }
                AnomalyType::LinkDegradation => {
                    // Boost FEC redundancy up to 25% to shield against loss spikes
                    let target_fec = (self.current_fec_ratio * 2.5).clamp(0.15, 0.35);
                    self.current_fec_ratio = target_fec;
                    // Slightly moderate pacing rate to leave headroom for parity symbols
                    self.current_pacing_bps =
                        (self.current_pacing_bps * 0.85).max(self.min_pacing_bps);
                    ShaperAction::ScaleFecRedundancy {
                        new_fec_ratio: target_fec,
                        reason: format!(
                            "Link degradation shielded: FEC parity ratio elevated to {:.1}%",
                            target_fec * 100.0
                        ),
                    }
                }
                AnomalyType::MicroburstCongestion => {
                    // Step down pacing rate by 15% and smooth burst limit
                    let factor = 0.85;
                    let target_rate = (self.current_pacing_bps * factor).max(self.min_pacing_bps);
                    self.current_pacing_bps = target_rate;
                    ShaperAction::DrainQueue {
                        drain_duration_ms: 150,
                        reason: "Microburst congestion absorbed: Applied 150ms token bucket smoothing drain"
                            .to_string(),
                    }
                }
                AnomalyType::RouteFlapBlackhole => {
                    // Reroute to secondary subflow ID 2 and probe MTU
                    ShaperAction::RerouteSubflow {
                        target_subflow_id: 2,
                        reason: "Route blackhole bypassed: Traffic rerouted to secondary multipath interface"
                            .to_string(),
                    }
                }
                AnomalyType::CrossTrafficContention => {
                    // Back off pacing rate by 20% to yield fair share
                    let factor = 0.80;
                    let target_rate = (self.current_pacing_bps * factor).max(self.min_pacing_bps);
                    self.current_pacing_bps = target_rate;
                    ShaperAction::AdjustPacingRate {
                        new_pacing_bps: target_rate,
                        scale_factor: factor,
                        reason: "Cross-traffic contention: Backed off pacing rate by 20% for TCP fairness".to_string(),
                    }
                }
                AnomalyType::AsymmetricBdpShift => {
                    // Reset inflight limits and trigger PMTU probe
                    ShaperAction::TriggerPmtuProbe {
                        target_mtu: 1420,
                        reason: "Asymmetric BDP shift recalibrated: Re-probing path MTU and window bounds"
                            .to_string(),
                    }
                }
            }
        } else {
            // No anomaly: gradual recovery towards baseline capacity
            self.healthy_consecutive_count += 1;

            // Once healthy for at least 3 samples and below baseline capacity, step up rate
            if self.healthy_consecutive_count >= 3
                && self.current_pacing_bps < self.baseline_capacity_bps
            {
                let recovery_step = self.baseline_capacity_bps * 0.05; // +5% per step
                self.current_pacing_bps =
                    (self.current_pacing_bps + recovery_step).min(self.baseline_capacity_bps);

                // Gradually restore standard 5% FEC overhead
                if self.current_fec_ratio > 0.05 {
                    self.current_fec_ratio = (self.current_fec_ratio - 0.02).max(0.05);
                }

                if self.healthy_consecutive_count == 3 && self.active_anomaly.is_some() {
                    self.active_anomaly = None;
                    return ShaperAction::AdjustPacingRate {
                        new_pacing_bps: self.current_pacing_bps,
                        scale_factor: 1.05,
                        reason: format!(
                            "Autonomous self-healing recovery: Step up pacing rate to {:.2} Mbps towards baseline",
                            self.current_pacing_bps / 1_000_000.0
                        ),
                    };
                }
            }

            ShaperAction::HoldBaseline
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shaper_mitigate_bufferbloat_and_recover() {
        let mut shaper = SelfHealingShaper::new(1_000_000_000.0); // 1 Gbps
        assert_eq!(shaper.current_pacing_bps, 1_000_000_000.0);

        // Inject bufferbloat anomaly
        let anom = AnomalyClassification {
            anomaly_type: AnomalyType::Bufferbloat,
            confidence: 0.9,
            severity: 0.8,
            root_cause: "Queue delay 3x min RTT".to_string(),
            recommended_action: "Throttle pacing rate".to_string(),
        };

        let sample = MetricSample {
            timestamp_ms: 1000,
            rtt_ms: 120.0,
            rtt_var_ms: 10.0,
            min_rtt_ms: 30.0,
            bytes_in_flight: 2_000_000,
            cwnd_bytes: 2_500_000,
            throughput_bps: 900_000_000.0,
            loss_rate: 0.001,
            retrans_rate: 0.001,
            jitter_ms: 2.0,
            ecn_ce_ratio: 0.0,
        };

        let action = shaper.decide_action(&sample, Some(&anom));
        match action {
            ShaperAction::AdjustPacingRate {
                new_pacing_bps,
                scale_factor,
                ..
            } => {
                assert_eq!(scale_factor, 0.70);
                assert_eq!(new_pacing_bps, 700_000_000.0);
            }
            _ => panic!("expected AdjustPacingRate"),
        }
        assert_eq!(shaper.total_mitigations_applied, 1);

        // Consecutive healthy samples lead to gradual recovery
        for i in 1..=5 {
            let healthy_sample = MetricSample {
                timestamp_ms: 2000 + i * 200,
                rtt_ms: 30.0,
                rtt_var_ms: 1.0,
                min_rtt_ms: 30.0,
                bytes_in_flight: 800_000,
                cwnd_bytes: 1_000_000,
                throughput_bps: 700_000_000.0,
                loss_rate: 0.0,
                retrans_rate: 0.0,
                jitter_ms: 0.5,
                ecn_ce_ratio: 0.0,
            };
            let _ = shaper.decide_action(&healthy_sample, None);
        }

        assert!(shaper.current_pacing_bps > 700_000_000.0);
    }
}
