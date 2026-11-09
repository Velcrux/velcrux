#![forbid(unsafe_code)]

//! Anomaly Classification & Root-Cause Analysis Engine.
//!
//! Categorizes multi-dimensional feature deviations into actionable transport anomaly profiles:
//! Bufferbloat, Link Degradation, Microburst Congestion, Route Flap/Blackhole, and Cross-Traffic Contention.

use serde::{Deserialize, Serialize};

use super::features::{FeatureVector, MetricSample};

/// Network transport anomaly classification taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Intermediate queue buildup inflating latency without packet drop.
    Bufferbloat,
    /// Physical or wireless medium degradation causing high loss/retransmits.
    LinkDegradation,
    /// Sub-millisecond queue saturation and packet drops caused by traffic bursts.
    MicroburstCongestion,
    /// BGP route oscillation, path asymmetry, or sudden link blackhole.
    RouteFlapBlackhole,
    /// Competing flows (e.g. cubic cross-traffic) inducing throughput oscillation.
    CrossTrafficContention,
    /// Reverse-path ACK compression or asymmetric forward/return BDP shift.
    AsymmetricBdpShift,
}

impl AnomalyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bufferbloat => "bufferbloat",
            Self::LinkDegradation => "link_degradation",
            Self::MicroburstCongestion => "microburst_congestion",
            Self::RouteFlapBlackhole => "route_flap_blackhole",
            Self::CrossTrafficContention => "cross_traffic_contention",
            Self::AsymmetricBdpShift => "asymmetric_bdp_shift",
        }
    }
}

/// Detailed classification outcome with root cause analysis and confidence score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyClassification {
    pub anomaly_type: AnomalyType,
    /// Confidence probability in $[0.0, 1.0]$.
    pub confidence: f64,
    /// Impact severity score in $[0.0, 1.0]$.
    pub severity: f64,
    /// Human-readable root cause explanation.
    pub root_cause: String,
    /// Primary mitigation recommendation.
    pub recommended_action: String,
}

/// Rule-assisted multidimensional classifier mapping feature vectors to anomaly types.
pub struct AnomalyClassifier;

impl AnomalyClassifier {
    /// Classifies an anomaly based on the extracted feature vector and raw metric sample.
    pub fn classify(fv: &FeatureVector, sample: &MetricSample) -> AnomalyClassification {
        // 1. Check for Route Flap / Blackhole: extreme RTT jump + severe throughput collapse
        if fv.rtt_z_score > 4.0 && fv.throughput_drop_ratio > 0.7 {
            let conf = (0.7 + (fv.rtt_z_score / 20.0).min(0.25)).min(0.98);
            let sev = (fv.throughput_drop_ratio * 0.9).min(1.0);
            return AnomalyClassification {
                anomaly_type: AnomalyType::RouteFlapBlackhole,
                confidence: conf,
                severity: sev,
                root_cause: format!(
                    "Abrupt path reroute or blackhole: RTT jumped to {:.1}ms (z={:.2}) with {:.1}% throughput drop",
                    sample.rtt_ms, fv.rtt_z_score, fv.throughput_drop_ratio * 100.0
                ),
                recommended_action: "Reroute traffic to alternate multipath subflow and trigger PMTU probe".to_string(),
            };
        }

        // 2. Check for Bufferbloat: massive queue delay ratio with low/minimal loss
        if fv.queue_delay_ratio > 1.5 && fv.loss_rate < 0.02 {
            let conf = (0.75 + (fv.queue_delay_ratio / 10.0).min(0.2)).min(0.99);
            let sev = (fv.queue_delay_ratio / 5.0).clamp(0.4, 0.95);
            return AnomalyClassification {
                anomaly_type: AnomalyType::Bufferbloat,
                confidence: conf,
                severity: sev,
                root_cause: format!(
                    "Bufferbloat queue buildup: Queuing delay is {:.1}x base RTT ({:.1}ms vs min {:.1}ms) with minimal loss ({:.3}%)",
                    fv.queue_delay_ratio, sample.rtt_ms, sample.min_rtt_ms, sample.loss_rate * 100.0
                ),
                recommended_action: "Throttle pacing rate by 30% and temporarily clamp inflight cwnd to drain queue".to_string(),
            };
        }

        // 3. Check for Link Degradation: elevated packet loss without corresponding queue explosion
        if fv.loss_rate > 0.03 || sample.retrans_rate > 0.03 {
            let conf = (0.70 + (fv.loss_rate * 5.0).min(0.28)).min(0.98);
            let sev = (fv.loss_rate * 8.0).clamp(0.5, 1.0);
            return AnomalyClassification {
                anomaly_type: AnomalyType::LinkDegradation,
                confidence: conf,
                severity: sev,
                root_cause: format!(
                    "Physical or wireless link degradation: High packet loss rate ({:.2}%) and retransmissions ({:.2}%)",
                    sample.loss_rate * 100.0, sample.retrans_rate * 100.0
                ),
                recommended_action: "Boost FEC redundancy repair symbol ratio and step down packet pacing burst size".to_string(),
            };
        }

        // 4. Check for Microburst Congestion: sharp jitter spike and transient queue saturation
        if fv.jitter_z_score > 2.5 && fv.rtt_variance_ratio > 0.3 {
            let conf = (0.65 + (fv.jitter_z_score / 15.0).min(0.25)).min(0.95);
            let sev = (fv.rtt_variance_ratio * 1.2).clamp(0.3, 0.85);
            return AnomalyClassification {
                anomaly_type: AnomalyType::MicroburstCongestion,
                confidence: conf,
                severity: sev,
                root_cause: format!(
                    "Microburst congestion: Extreme packet arrival jitter (z={:.2}, jitter={:.2}ms) with high RTT variance",
                    fv.jitter_z_score, sample.jitter_ms
                ),
                recommended_action: "Smooth pacing token bucket interval and activate fine-grained inter-packet spacing".to_string(),
            };
        }

        // 5. Check for Cross-Traffic Contention: high ECN CE marks and periodic throughput drops
        if sample.ecn_ce_ratio > 0.1
            || (fv.throughput_drop_ratio > 0.3 && fv.queue_delay_ratio > 0.5)
        {
            let conf = (0.68 + (sample.ecn_ce_ratio * 0.5).min(0.25)).min(0.95);
            let sev = (fv.throughput_drop_ratio * 0.8).clamp(0.35, 0.9);
            return AnomalyClassification {
                anomaly_type: AnomalyType::CrossTrafficContention,
                confidence: conf,
                severity: sev,
                root_cause: format!(
                    "Cross-traffic bottleneck contention: Elevated ECN marks ({:.1}%) with throughput oscillations",
                    sample.ecn_ce_ratio * 100.0
                ),
                recommended_action: "Yield fair-share bandwidth headroom and prioritize higher-tier QoS flows".to_string(),
            };
        }

        // 6. Default: Asymmetric BDP Shift
        AnomalyClassification {
            anomaly_type: AnomalyType::AsymmetricBdpShift,
            confidence: 0.60,
            severity: 0.40,
            root_cause: format!(
                "Inflight-to-BDP divergence: Inflight ratio is {:.2}x estimated bandwidth-delay product",
                fv.inflight_to_bdp_ratio
            ),
            recommended_action: "Recalibrate BDP window and re-anchor minimum RTT filter".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_bufferbloat() {
        let fv = FeatureVector {
            rtt_z_score: 3.5,
            loss_rate: 0.001,
            throughput_drop_ratio: 0.05,
            queue_delay_ratio: 2.8,
            rtt_variance_ratio: 0.15,
            jitter_z_score: 0.8,
            inflight_to_bdp_ratio: 1.8,
        };
        let sample = MetricSample {
            timestamp_ms: 1000,
            rtt_ms: 110.0,
            rtt_var_ms: 5.0,
            min_rtt_ms: 25.0,
            bytes_in_flight: 1_200_000,
            cwnd_bytes: 1_500_000,
            throughput_bps: 800_000_000.0,
            loss_rate: 0.001,
            retrans_rate: 0.001,
            jitter_ms: 1.2,
            ecn_ce_ratio: 0.0,
        };

        let res = AnomalyClassifier::classify(&fv, &sample);
        assert_eq!(res.anomaly_type, AnomalyType::Bufferbloat);
        assert!(res.confidence > 0.8);
    }

    #[test]
    fn test_classify_link_degradation() {
        let fv = FeatureVector {
            rtt_z_score: 0.8,
            loss_rate: 0.08, // 8% loss
            throughput_drop_ratio: 0.4,
            queue_delay_ratio: 0.2,
            rtt_variance_ratio: 0.1,
            jitter_z_score: 0.5,
            inflight_to_bdp_ratio: 0.7,
        };
        let sample = MetricSample {
            timestamp_ms: 2000,
            rtt_ms: 32.0,
            rtt_var_ms: 3.0,
            min_rtt_ms: 28.0,
            bytes_in_flight: 400_000,
            cwnd_bytes: 500_000,
            throughput_bps: 450_000_000.0,
            loss_rate: 0.08,
            retrans_rate: 0.08,
            jitter_ms: 0.8,
            ecn_ce_ratio: 0.0,
        };

        let res = AnomalyClassifier::classify(&fv, &sample);
        assert_eq!(res.anomaly_type, AnomalyType::LinkDegradation);
        assert!(res.confidence > 0.8);
    }
}
