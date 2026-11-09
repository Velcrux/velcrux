#![forbid(unsafe_code)]

//! Online Streaming Machine Learning & Statistical Anomaly Detection Engine.
//!
//! Employs a streaming partition Isolation Forest ensemble paired with two-sided CUSUM
//! drift detection to score multi-feature transport anomalies in real time without external C dependencies.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use super::features::{FeatureVector, FEATURE_DIMENSIONS};

/// Harmonic number approximation constant (Euler-Mascheroni constant $\gamma$).
const EULER_MASCHERONI: f64 = 0.5772156649;

/// Average path length of unsuccessful searches in a Binary Search Tree (BST) of size $n$:
/// $c(n) = 2(\ln(n - 1) + 0.5772156649) - \frac{2(n - 1)}{n}$ for $n > 2$.
pub fn average_path_length_c(n: usize) -> f64 {
    if n <= 1 {
        return 1.0;
    }
    if n == 2 {
        return 1.0;
    }
    let n_f = n as f64;
    2.0 * ((n_f - 1.0).ln() + EULER_MASCHERONI) - (2.0 * (n_f - 1.0) / n_f)
}

/// A node in a lightweight random partition tree.
#[derive(Debug, Clone)]
enum TreeNode {
    Leaf {
        size: usize,
    },
    Internal {
        feature_idx: usize,
        split_value: f64,
        left: Box<TreeNode>,
        right: Box<TreeNode>,
    },
}

impl TreeNode {
    /// Computes search path length $h(x)$ for a feature vector traversing the tree.
    fn path_length(&self, x: &[f64; FEATURE_DIMENSIONS], current_depth: usize) -> f64 {
        match self {
            TreeNode::Leaf { size } => {
                if *size <= 1 {
                    current_depth as f64
                } else {
                    current_depth as f64 + average_path_length_c(*size)
                }
            }
            TreeNode::Internal {
                feature_idx,
                split_value,
                left,
                right,
            } => {
                if x[*feature_idx] < *split_value {
                    left.path_length(x, current_depth + 1)
                } else {
                    right.path_length(x, current_depth + 1)
                }
            }
        }
    }
}

/// A single random partition Isolation Tree.
#[derive(Debug, Clone)]
pub struct IsolationTree {
    root: TreeNode,
}

impl IsolationTree {
    /// Recursively builds an isolation tree from a set of sample feature vectors.
    fn build<R: Rng>(
        samples: &[[f64; FEATURE_DIMENSIONS]],
        depth: usize,
        max_depth: usize,
        rng: &mut R,
    ) -> TreeNode {
        if depth >= max_depth || samples.len() <= 1 {
            return TreeNode::Leaf {
                size: samples.len(),
            };
        }

        // Randomly pick a feature dimension that has variance
        let mut available_dims = Vec::new();
        for d in 0..FEATURE_DIMENSIONS {
            let mut min_val = f64::MAX;
            let mut max_val = f64::MIN;
            for s in samples {
                if s[d] < min_val {
                    min_val = s[d];
                }
                if s[d] > max_val {
                    max_val = s[d];
                }
            }
            if max_val > min_val + 1e-6 {
                available_dims.push((d, min_val, max_val));
            }
        }

        if available_dims.is_empty() {
            return TreeNode::Leaf {
                size: samples.len(),
            };
        }

        let pick_idx = rng.gen_range(0..available_dims.len());
        let (feat_idx, min_val, max_val) = available_dims[pick_idx];
        let split_value = rng.gen_range(min_val..max_val);

        let mut left_samples = Vec::new();
        let mut right_samples = Vec::new();

        for s in samples {
            if s[feat_idx] < split_value {
                left_samples.push(*s);
            } else {
                right_samples.push(*s);
            }
        }

        if left_samples.is_empty() || right_samples.is_empty() {
            return TreeNode::Leaf {
                size: samples.len(),
            };
        }

        let left = Box::new(Self::build(&left_samples, depth + 1, max_depth, rng));
        let right = Box::new(Self::build(&right_samples, depth + 1, max_depth, rng));

        TreeNode::Internal {
            feature_idx: feat_idx,
            split_value,
            left,
            right,
        }
    }
}

/// Streaming Ensemble of Isolation Trees for real-time anomaly scoring.
#[derive(Debug, Clone)]
pub struct StreamingIsolationForest {
    trees: Vec<IsolationTree>,
    c_n: f64,
}

impl StreamingIsolationForest {
    /// Constructs and fits an Isolation Forest on a baseline dataset.
    pub fn fit(samples: &[FeatureVector], num_trees: usize, max_depth: usize) -> Self {
        let sample_size = samples.len().max(5);
        let c_n = average_path_length_c(sample_size);
        let mut rng = StdRng::seed_from_u64(42);

        let flat_samples: Vec<[f64; FEATURE_DIMENSIONS]> =
            samples.iter().map(|s| s.as_slice()).collect();

        let mut trees = Vec::with_capacity(num_trees);
        for _ in 0..num_trees {
            let root = IsolationTree::build(&flat_samples, 0, max_depth, &mut rng);
            trees.push(IsolationTree { root });
        }

        Self { trees, c_n }
    }

    /// Evaluates anomaly score $s(x, n) = 2^{-\frac{\mathbb{E}[h(x)]}{c(n)}}$.
    /// Returns score in $[0.0, 1.0]$, where values $> 0.65$ indicate high confidence anomalies.
    pub fn score(&self, x: &FeatureVector) -> f64 {
        if self.trees.is_empty() || self.c_n <= 0.0 {
            return 0.5;
        }

        let slice = x.as_slice();
        let total_path: f64 = self
            .trees
            .iter()
            .map(|t| t.root.path_length(&slice, 0))
            .sum();
        let expected_path = total_path / (self.trees.len() as f64);

        // 2^(-E[h(x)] / c(n))
        2.0f64.powf(-expected_path / self.c_n)
    }
}

/// Two-sided CUSUM (Cumulative Sum) change-point drift detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CusumDetector {
    /// Baseline target mean.
    pub target_mean: f64,
    /// Slack tolerance parameter $k$.
    pub slack_k: f64,
    /// Alert decision threshold $h$.
    pub threshold_h: f64,
    /// Cumulative positive deviation sum $S^+$.
    pub sum_pos: f64,
    /// Cumulative negative deviation sum $S^-$.
    pub sum_neg: f64,
}

impl CusumDetector {
    pub fn new(target_mean: f64, slack_k: f64, threshold_h: f64) -> Self {
        Self {
            target_mean,
            slack_k,
            threshold_h,
            sum_pos: 0.0,
            sum_neg: 0.0,
        }
    }

    /// Updates CUSUM sums with new sample and checks whether threshold $h$ is breached.
    pub fn update(&mut self, value: f64) -> bool {
        // S+ = max(0, S+ + (x - target - k))
        self.sum_pos = (self.sum_pos + (value - self.target_mean - self.slack_k)).max(0.0);
        // S- = max(0, S- - (x - target + k))
        self.sum_neg = (self.sum_neg - (value - self.target_mean + self.slack_k)).max(0.0);

        self.sum_pos > self.threshold_h || self.sum_neg > self.threshold_h
    }

    /// Resets cumulative sums after anomaly resolution.
    pub fn reset(&mut self) {
        self.sum_pos = 0.0;
        self.sum_neg = 0.0;
    }
}

/// Unified anomaly detection evaluation result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyDetectionResult {
    /// True if an anomaly was identified by either model.
    pub is_anomaly: bool,
    /// Composite anomaly score in $[0.0, 1.0]$.
    pub anomaly_score: f64,
    /// Raw isolation forest anomaly score.
    pub isolation_score: f64,
    /// Whether CUSUM drift was flagged on RTT or throughput.
    pub cusum_drift_flag: bool,
    /// Top contributing features and their relative z-scores or ratios.
    pub dominant_features: Vec<(String, f64)>,
}

/// Composite detector orchestrating Streaming Isolation Forest and CUSUM monitoring.
#[derive(Debug, Clone)]
pub struct CompositeAnomalyDetector {
    isolation_forest: StreamingIsolationForest,
    rtt_cusum: CusumDetector,
    score_threshold: f64,
}

impl CompositeAnomalyDetector {
    /// Creates a detector calibrated with baseline training samples.
    pub fn initialize(baseline_samples: &[FeatureVector], score_threshold: f64) -> Self {
        let isolation_forest = StreamingIsolationForest::fit(baseline_samples, 25, 8);
        let rtt_cusum = CusumDetector::new(0.0, 0.5, 4.0); // Z-score drift on RTT

        Self {
            isolation_forest,
            rtt_cusum,
            score_threshold: score_threshold.clamp(0.5, 0.95),
        }
    }

    /// Evaluates incoming feature vector against both AI/ML models.
    pub fn evaluate(&mut self, fv: &FeatureVector) -> AnomalyDetectionResult {
        let isolation_score = self.isolation_forest.score(fv);
        let cusum_drift = self.rtt_cusum.update(fv.rtt_z_score);

        // Composite scoring weighted towards isolation forest + CUSUM boost
        let mut composite_score = isolation_score;
        if cusum_drift {
            composite_score = (composite_score + 0.25).min(1.0);
        }

        // Feature dominance ranking
        let mut features = vec![
            ("rtt_z_score".to_string(), fv.rtt_z_score.abs()),
            ("loss_rate".to_string(), fv.loss_rate * 10.0),
            ("queue_delay_ratio".to_string(), fv.queue_delay_ratio),
            (
                "throughput_drop".to_string(),
                fv.throughput_drop_ratio * 5.0,
            ),
            ("jitter_z_score".to_string(), fv.jitter_z_score.abs()),
            ("rtt_variance".to_string(), fv.rtt_variance_ratio * 5.0),
        ];
        features.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        features.truncate(3);

        let is_anomaly = composite_score >= self.score_threshold || cusum_drift;

        AnomalyDetectionResult {
            is_anomaly,
            anomaly_score: composite_score,
            isolation_score,
            cusum_drift_flag: cusum_drift,
            dominant_features: features,
        }
    }

    /// Resets transient CUSUM drift states.
    pub fn reset_drift(&mut self) {
        self.rtt_cusum.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_average_path_length_c() {
        assert_eq!(average_path_length_c(1), 1.0);
        assert_eq!(average_path_length_c(2), 1.0);
        let c50 = average_path_length_c(50);
        assert!(c50 > 6.0 && c50 < 8.0);
    }

    #[test]
    fn test_isolation_forest_and_cusum_detection() {
        // Generate normal baseline
        let mut baseline = Vec::new();
        for _ in 0..50 {
            baseline.push(FeatureVector {
                rtt_z_score: 0.1,
                loss_rate: 0.0001,
                throughput_drop_ratio: 0.0,
                queue_delay_ratio: 0.05,
                rtt_variance_ratio: 0.05,
                jitter_z_score: 0.1,
                inflight_to_bdp_ratio: 0.9,
            });
        }

        let mut detector = CompositeAnomalyDetector::initialize(&baseline, 0.65);

        // Normal sample should produce low anomaly score
        let normal = FeatureVector {
            rtt_z_score: 0.15,
            loss_rate: 0.0002,
            throughput_drop_ratio: 0.01,
            queue_delay_ratio: 0.06,
            rtt_variance_ratio: 0.05,
            jitter_z_score: 0.12,
            inflight_to_bdp_ratio: 0.92,
        };
        let res_normal = detector.evaluate(&normal);
        assert!(!res_normal.is_anomaly);
        assert!(res_normal.anomaly_score < 0.65);

        // Extreme anomaly (Bufferbloat + loss spike)
        let anomalous = FeatureVector {
            rtt_z_score: 6.5,
            loss_rate: 0.15,
            throughput_drop_ratio: 0.6,
            queue_delay_ratio: 4.8,
            rtt_variance_ratio: 0.8,
            jitter_z_score: 5.0,
            inflight_to_bdp_ratio: 3.5,
        };
        let res_anom = detector.evaluate(&anomalous);
        assert!(res_anom.is_anomaly);
        assert!(res_anom.anomaly_score >= 0.65);
    }
}
