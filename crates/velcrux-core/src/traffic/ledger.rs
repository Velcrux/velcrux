#![forbid(unsafe_code)]

//! Incident Post-Mortem Ledger & Prometheus Telemetry Exporter.
//!
//! Preserves structured post-mortem records of detected transport anomalies,
//! mitigation executions, resolution latencies, and exports Prometheus metrics.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::classifier::{AnomalyClassification, AnomalyType};
use super::features::{FeatureVector, MetricSample};
use super::shaper::ShaperAction;

/// A structured post-mortem record of an anomaly incident and its self-healing outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyIncident {
    /// Unique incident identifier (e.g. `inc-000042`).
    pub incident_id: String,
    /// Milliseconds since UNIX epoch when incident was triggered.
    pub timestamp_ms: u64,
    /// Anomaly classification category.
    pub anomaly_type: AnomalyType,
    /// Impact severity score in $[0.0, 1.0]$.
    pub severity: f64,
    /// Model confidence in $[0.0, 1.0]$.
    pub confidence: f64,
    /// Detailed root cause summary.
    pub root_cause: String,
    /// Self-healing actuation action executed.
    pub mitigation_action: String,
    /// Snapshot of transport metrics at trigger time.
    pub trigger_metrics: MetricSample,
    /// Extracted feature vector at trigger time.
    pub feature_vector: FeatureVector,
    /// Time elapsed in milliseconds before metrics converged back to normal.
    pub recovery_latency_ms: Option<u64>,
    /// Throughput delta (recovered - pre-mitigation) in bits per second.
    pub throughput_delta_bps: Option<f64>,
    /// True if link stabilized and incident is resolved.
    pub resolved: bool,
}

/// In-memory thread-safe audit ledger storing anomaly incidents and post-mortems.
#[derive(Debug, Clone)]
pub struct IncidentLedger {
    incidents: Arc<RwLock<Vec<AnomalyIncident>>>,
    counter: Arc<AtomicU64>,
    max_capacity: usize,
}

impl Default for IncidentLedger {
    fn default() -> Self {
        Self::new(500)
    }
}

impl IncidentLedger {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            incidents: Arc::new(RwLock::new(Vec::with_capacity(max_capacity))),
            counter: Arc::new(AtomicU64::new(1)),
            max_capacity: max_capacity.max(50),
        }
    }

    /// Records a new anomaly incident in the ledger.
    pub async fn record(
        &self,
        classification: &AnomalyClassification,
        action: &ShaperAction,
        sample: &MetricSample,
        fv: &FeatureVector,
    ) -> String {
        let seq = self.counter.fetch_add(1, Ordering::SeqCst);
        let incident_id = format!("inc-{:06}", seq);

        let record = AnomalyIncident {
            incident_id: incident_id.clone(),
            timestamp_ms: sample.timestamp_ms,
            anomaly_type: classification.anomaly_type,
            severity: classification.severity,
            confidence: classification.confidence,
            root_cause: classification.root_cause.clone(),
            mitigation_action: action.name().to_string(),
            trigger_metrics: *sample,
            feature_vector: *fv,
            recovery_latency_ms: None,
            throughput_delta_bps: None,
            resolved: false,
        };

        let mut lock = self.incidents.write().await;
        if lock.len() >= self.max_capacity {
            lock.remove(0);
        }
        lock.push(record);

        incident_id
    }

    /// Marks an active incident as resolved once transport metrics return to baseline.
    pub async fn mark_resolved(
        &self,
        incident_id: &str,
        recovery_latency_ms: u64,
        throughput_delta_bps: f64,
    ) -> bool {
        let mut lock = self.incidents.write().await;
        if let Some(inc) = lock.iter_mut().find(|i| i.incident_id == incident_id) {
            inc.resolved = true;
            inc.recovery_latency_ms = Some(recovery_latency_ms);
            inc.throughput_delta_bps = Some(throughput_delta_bps);
            true
        } else {
            false
        }
    }

    /// Retrieves recent incidents up to the requested limit.
    pub async fn list_recent(&self, limit: usize) -> Vec<AnomalyIncident> {
        let lock = self.incidents.read().await;
        let count = limit.min(lock.len());
        lock.iter().rev().take(count).cloned().collect()
    }

    /// Total count of recorded incidents.
    pub async fn total_count(&self) -> usize {
        self.incidents.read().await.len()
    }

    /// Computes summary breakdown by anomaly type.
    pub async fn counts_by_type(&self) -> HashMap<AnomalyType, usize> {
        let lock = self.incidents.read().await;
        let mut map = HashMap::new();
        for inc in lock.iter() {
            *map.entry(inc.anomaly_type).or_insert(0) += 1;
        }
        map
    }
}

/// Generates Prometheus exposition text format for traffic shaper metrics.
pub fn format_prometheus_metrics(
    anomaly_score: f64,
    pacing_bps: f64,
    fec_ratio: f64,
    counts_by_type: &HashMap<AnomalyType, usize>,
    total_mitigations: u64,
) -> String {
    let mut out = String::with_capacity(1024);

    out.push_str("# HELP velcrux_traffic_anomaly_score Real-time multi-dimensional anomaly score [0.0, 1.0]\n");
    out.push_str("# TYPE velcrux_traffic_anomaly_score gauge\n");
    out.push_str(&format!(
        "velcrux_traffic_anomaly_score {:.4}\n\n",
        anomaly_score
    ));

    out.push_str(
        "# HELP velcrux_traffic_pacing_rate_bps Commanded token bucket pacing rate in bps\n",
    );
    out.push_str("# TYPE velcrux_traffic_pacing_rate_bps gauge\n");
    out.push_str(&format!(
        "velcrux_traffic_pacing_rate_bps {:.2}\n\n",
        pacing_bps
    ));

    out.push_str("# HELP velcrux_traffic_fec_redundancy_ratio Dynamic FEC erasure code parity overhead ratio\n");
    out.push_str("# TYPE velcrux_traffic_fec_redundancy_ratio gauge\n");
    out.push_str(&format!(
        "velcrux_traffic_fec_redundancy_ratio {:.4}\n\n",
        fec_ratio
    ));

    out.push_str(
        "# HELP velcrux_traffic_incidents_total Total detected network anomaly incidents by type\n",
    );
    out.push_str("# TYPE velcrux_traffic_incidents_total counter\n");
    for (atype, count) in counts_by_type {
        out.push_str(&format!(
            "velcrux_traffic_incidents_total{{type=\"{}\"}} {}\n",
            atype.as_str(),
            count
        ));
    }
    out.push('\n');

    out.push_str("# HELP velcrux_traffic_mitigations_total Total autonomous self-healing mitigations applied\n");
    out.push_str("# TYPE velcrux_traffic_mitigations_total counter\n");
    out.push_str(&format!(
        "velcrux_traffic_mitigations_total {}\n",
        total_mitigations
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_incident_ledger_lifecycle() {
        let ledger = IncidentLedger::new(10);

        let sample = MetricSample::healthy_baseline(1000);
        let fv = FeatureVector {
            rtt_z_score: 3.0,
            loss_rate: 0.05,
            throughput_drop_ratio: 0.2,
            queue_delay_ratio: 1.8,
            rtt_variance_ratio: 0.2,
            jitter_z_score: 2.0,
            inflight_to_bdp_ratio: 1.5,
        };

        let classification = AnomalyClassification {
            anomaly_type: AnomalyType::Bufferbloat,
            confidence: 0.88,
            severity: 0.75,
            root_cause: "Queue delay elevated".to_string(),
            recommended_action: "Throttle pacing".to_string(),
        };

        let action = ShaperAction::AdjustPacingRate {
            new_pacing_bps: 700_000_000.0,
            scale_factor: 0.7,
            reason: "Bufferbloat test".to_string(),
        };

        let id = ledger.record(&classification, &action, &sample, &fv).await;
        assert_eq!(id, "inc-000001");
        assert_eq!(ledger.total_count().await, 1);

        let recent = ledger.list_recent(5).await;
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].anomaly_type, AnomalyType::Bufferbloat);
        assert!(!recent[0].resolved);

        // Mark resolved
        let ok = ledger.mark_resolved(&id, 450, 150_000_000.0).await;
        assert!(ok);

        let updated = ledger.list_recent(1).await;
        assert!(updated[0].resolved);
        assert_eq!(updated[0].recovery_latency_ms, Some(450));
    }
}
