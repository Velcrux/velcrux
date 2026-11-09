#![forbid(unsafe_code)]

//! Feature Extraction & Streaming Vector Pipeline for Network Telemetry.
//!
//! Maintains rolling window statistics, computes exponentially weighted moving averages (EWMA),
//! and normalizes transport metrics into structured feature vectors for machine learning anomaly detection.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Number of dimensions in the standardized feature vector.
pub const FEATURE_DIMENSIONS: usize = 7;

/// A raw snapshot of transport metrics sampled at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MetricSample {
    /// Milliseconds since UNIX epoch.
    pub timestamp_ms: u64,
    /// Current smoothed RTT in milliseconds.
    pub rtt_ms: f64,
    /// Current RTT variance in milliseconds.
    pub rtt_var_ms: f64,
    /// Minimum observed RTT (base propagation delay) in milliseconds.
    pub min_rtt_ms: f64,
    /// Bytes in flight on the wire.
    pub bytes_in_flight: u64,
    /// Congestion window in bytes.
    pub cwnd_bytes: u64,
    /// Measured throughput in bits per second.
    pub throughput_bps: f64,
    /// Packet loss ratio within the sample interval [0.0, 1.0].
    pub loss_rate: f64,
    /// Retransmission ratio within the sample interval [0.0, 1.0].
    pub retrans_rate: f64,
    /// Inter-arrival packet jitter in milliseconds.
    pub jitter_ms: f64,
    /// Ratio of ECN Congestion Experienced (CE) marks [0.0, 1.0].
    pub ecn_ce_ratio: f64,
}

impl MetricSample {
    /// Creates a baseline synthetic sample representing healthy transport.
    pub fn healthy_baseline(timestamp_ms: u64) -> Self {
        Self {
            timestamp_ms,
            rtt_ms: 30.0,
            rtt_var_ms: 2.0,
            min_rtt_ms: 28.0,
            bytes_in_flight: 1_000_000,
            cwnd_bytes: 1_200_000,
            throughput_bps: 1_000_000_000.0, // 1 Gbps
            loss_rate: 0.0001,
            retrans_rate: 0.0001,
            jitter_ms: 0.5,
            ecn_ce_ratio: 0.0,
        }
    }
}

/// Standardized multi-dimensional feature vector fed into anomaly detection models.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FeatureVector {
    /// Z-score of smoothed RTT relative to rolling mean: $(RTT - \mu_{RTT}) / \sigma_{RTT}$.
    pub rtt_z_score: f64,
    /// Raw packet loss rate [0.0, 1.0].
    pub loss_rate: f64,
    /// Throughput drop ratio relative to baseline: $\max(0, (\mu_{TP} - TP) / \mu_{TP})$.
    pub throughput_drop_ratio: f64,
    /// Normalized bufferbloat queuing delay gradient: $(RTT - minRTT) / \max(1.0, minRTT)$.
    pub queue_delay_ratio: f64,
    /// RTT variance ratio: $rtt\_var / \max(1.0, RTT)$.
    pub rtt_variance_ratio: f64,
    /// Z-score of packet inter-arrival jitter.
    pub jitter_z_score: f64,
    /// Inflight-to-BDP utilization ratio: $bytes\_in\_flight / \max(1.0, BDP_{est})$.
    pub inflight_to_bdp_ratio: f64,
}

impl FeatureVector {
    /// Converts feature vector into flat array for matrix and tree operations.
    pub fn as_slice(&self) -> [f64; FEATURE_DIMENSIONS] {
        [
            self.rtt_z_score,
            self.loss_rate,
            self.throughput_drop_ratio,
            self.queue_delay_ratio,
            self.rtt_variance_ratio,
            self.jitter_z_score,
            self.inflight_to_bdp_ratio,
        ]
    }

    /// Evaluates Euclidean distance squared between two feature vectors.
    pub fn distance_squared(&self, other: &Self) -> f64 {
        let a = self.as_slice();
        let b = other.as_slice();
        let mut sum = 0.0;
        for i in 0..FEATURE_DIMENSIONS {
            let diff = a[i] - b[i];
            sum += diff * diff;
        }
        sum
    }
}

/// Rolling window statistics maintaining running mean, variance, and EWMA over transport metrics.
#[derive(Debug, Clone)]
pub struct RollingWindowStats {
    capacity: usize,
    samples: VecDeque<MetricSample>,
    ewma_alpha: f64,
    ewma_rtt: f64,
    ewma_throughput: f64,
    ewma_jitter: f64,
    min_observed_rtt: f64,
}

impl RollingWindowStats {
    /// Initializes rolling window with a given sample capacity and EWMA smoothing factor.
    pub fn new(capacity: usize, ewma_alpha: f64) -> Self {
        Self {
            capacity: capacity.max(5),
            samples: VecDeque::with_capacity(capacity),
            ewma_alpha: ewma_alpha.clamp(0.01, 0.99),
            ewma_rtt: 0.0,
            ewma_throughput: 0.0,
            ewma_jitter: 0.0,
            min_observed_rtt: f64::MAX,
        }
    }

    /// Adds a new metric sample, updating EWMA and rolling window.
    pub fn push(&mut self, sample: MetricSample) {
        if self.samples.is_empty() {
            self.ewma_rtt = sample.rtt_ms;
            self.ewma_throughput = sample.throughput_bps;
            self.ewma_jitter = sample.jitter_ms;
            self.min_observed_rtt = sample.min_rtt_ms;
        } else {
            let a = self.ewma_alpha;
            self.ewma_rtt = a * sample.rtt_ms + (1.0 - a) * self.ewma_rtt;
            self.ewma_throughput = a * sample.throughput_bps + (1.0 - a) * self.ewma_throughput;
            self.ewma_jitter = a * sample.jitter_ms + (1.0 - a) * self.ewma_jitter;
            if sample.min_rtt_ms < self.min_observed_rtt {
                self.min_observed_rtt = sample.min_rtt_ms;
            }
        }

        if self.samples.len() >= self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    /// Number of samples currently in the window.
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// True if window contains zero samples.
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Computes mean and standard deviation for RTT.
    pub fn rtt_stats(&self) -> (f64, f64) {
        if self.samples.is_empty() {
            return (0.0, 1.0);
        }
        let mean = self.samples.iter().map(|s| s.rtt_ms).sum::<f64>() / (self.samples.len() as f64);
        let variance = self
            .samples
            .iter()
            .map(|s| {
                let d = s.rtt_ms - mean;
                d * d
            })
            .sum::<f64>()
            / (self.samples.len() as f64);
        (mean, variance.sqrt().max(0.1))
    }

    /// Computes mean and standard deviation for Jitter.
    pub fn jitter_stats(&self) -> (f64, f64) {
        if self.samples.is_empty() {
            return (0.0, 1.0);
        }
        let mean =
            self.samples.iter().map(|s| s.jitter_ms).sum::<f64>() / (self.samples.len() as f64);
        let variance = self
            .samples
            .iter()
            .map(|s| {
                let d = s.jitter_ms - mean;
                d * d
            })
            .sum::<f64>()
            / (self.samples.len() as f64);
        (mean, variance.sqrt().max(0.05))
    }

    /// Computes mean throughput across window.
    pub fn throughput_mean(&self) -> f64 {
        if self.samples.is_empty() {
            return 1.0;
        }
        self.samples.iter().map(|s| s.throughput_bps).sum::<f64>() / (self.samples.len() as f64)
    }

    /// Extracts standardized feature vector from the most recent sample against the window baseline.
    pub fn extract_feature_vector(&self, sample: &MetricSample) -> FeatureVector {
        let (rtt_mean, rtt_std) = self.rtt_stats();
        let (jitter_mean, jitter_std) = self.jitter_stats();
        let tp_mean = self.throughput_mean();

        let rtt_z = (sample.rtt_ms - rtt_mean) / rtt_std;
        let jitter_z = (sample.jitter_ms - jitter_mean) / jitter_std;

        let tp_drop = if tp_mean > 0.0 {
            ((tp_mean - sample.throughput_bps) / tp_mean).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let min_rtt = if self.min_observed_rtt > 0.0 && self.min_observed_rtt < f64::MAX {
            self.min_observed_rtt
        } else {
            sample.min_rtt_ms.max(1.0)
        };

        let q_delay_ratio = ((sample.rtt_ms - min_rtt) / min_rtt).max(0.0);
        let rtt_var_ratio = sample.rtt_var_ms / sample.rtt_ms.max(1.0);

        // Estimate BDP = throughput * min_rtt / 8 bytes
        let bdp_bytes = (sample.throughput_bps * (min_rtt / 1000.0) / 8.0).max(10_000.0);
        let inflight_to_bdp = (sample.bytes_in_flight as f64) / bdp_bytes;

        FeatureVector {
            rtt_z_score: rtt_z,
            loss_rate: sample.loss_rate.clamp(0.0, 1.0),
            throughput_drop_ratio: tp_drop,
            queue_delay_ratio: q_delay_ratio,
            rtt_variance_ratio: rtt_var_ratio,
            jitter_z_score: jitter_z,
            inflight_to_bdp_ratio: inflight_to_bdp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_window_feature_extraction() {
        let mut stats = RollingWindowStats::new(10, 0.2);

        // Fill window with healthy baseline
        for i in 0..10 {
            let sample = MetricSample {
                timestamp_ms: 1000 + i * 100,
                rtt_ms: 30.0 + (i as f64) * 0.1,
                rtt_var_ms: 2.0,
                min_rtt_ms: 28.0,
                bytes_in_flight: 500_000,
                cwnd_bytes: 600_000,
                throughput_bps: 1_000_000_000.0,
                loss_rate: 0.0001,
                retrans_rate: 0.0001,
                jitter_ms: 0.5,
                ecn_ce_ratio: 0.0,
            };
            stats.push(sample);
        }

        assert_eq!(stats.len(), 10);
        let (mean, std) = stats.rtt_stats();
        assert!(mean > 29.0 && mean < 32.0);
        assert!(std > 0.0);

        // Extract feature vector for normal sample
        let normal_sample = MetricSample {
            timestamp_ms: 2000,
            rtt_ms: 30.5,
            rtt_var_ms: 2.0,
            min_rtt_ms: 28.0,
            bytes_in_flight: 500_000,
            cwnd_bytes: 600_000,
            throughput_bps: 1_000_000_000.0,
            loss_rate: 0.0,
            retrans_rate: 0.0,
            jitter_ms: 0.5,
            ecn_ce_ratio: 0.0,
        };

        let fv = stats.extract_feature_vector(&normal_sample);
        assert!(fv.rtt_z_score.abs() < 2.0);
        assert_eq!(fv.loss_rate, 0.0);
        assert_eq!(fv.throughput_drop_ratio, 0.0);

        // Extract feature vector for bufferbloat sample
        let bloated_sample = MetricSample {
            timestamp_ms: 2100,
            rtt_ms: 150.0, // huge RTT spike
            rtt_var_ms: 25.0,
            min_rtt_ms: 28.0,
            bytes_in_flight: 2_000_000,
            cwnd_bytes: 2_500_000,
            throughput_bps: 950_000_000.0,
            loss_rate: 0.001,
            retrans_rate: 0.001,
            jitter_ms: 8.0,
            ecn_ce_ratio: 0.1,
        };

        let fv_bloat = stats.extract_feature_vector(&bloated_sample);
        assert!(fv_bloat.rtt_z_score > 3.0);
        assert!(fv_bloat.queue_delay_ratio > 3.0);
    }
}
