#![forbid(unsafe_code)]

//! Comprehensive Integration Tests for Autonomous AI/ML Anomaly Detection & Self-Healing Traffic Shaper (`ADR-070`).

use velcrux_core::traffic::{
    AnomalyClassification, AnomalyClassifier, AnomalyType, CusumDetector, FeatureVector,
    IncidentLedger, MetricSample, RollingWindowStats, SelfHealingShaper, ShaperAction,
    StreamingIsolationForest, TrafficEngine,
};

#[test]
fn test_rolling_window_feature_extraction_accuracy() {
    let mut stats = RollingWindowStats::new(20, 0.2);

    for i in 0..20 {
        let sample = MetricSample {
            timestamp_ms: 1000 + i * 50,
            rtt_ms: 40.0 + (i as f64) * 0.5,
            rtt_var_ms: 2.0,
            min_rtt_ms: 38.0,
            bytes_in_flight: 800_000,
            cwnd_bytes: 1_000_000,
            throughput_bps: 1_000_000_000.0,
            loss_rate: 0.0001,
            retrans_rate: 0.0001,
            jitter_ms: 0.8,
            ecn_ce_ratio: 0.0,
        };
        stats.push(sample);
    }

    assert_eq!(stats.len(), 20);
    let (mean, std) = stats.rtt_stats();
    assert!(mean > 40.0 && mean < 50.0);
    assert!(std > 1.0);

    let test_sample = MetricSample {
        timestamp_ms: 2000,
        rtt_ms: 45.0,
        rtt_var_ms: 2.0,
        min_rtt_ms: 38.0,
        bytes_in_flight: 800_000,
        cwnd_bytes: 1_000_000,
        throughput_bps: 1_000_000_000.0,
        loss_rate: 0.0,
        retrans_rate: 0.0,
        jitter_ms: 0.8,
        ecn_ce_ratio: 0.0,
    };
    let fv = stats.extract_feature_vector(&test_sample);
    assert!(fv.rtt_z_score.abs() < 1.0);
    assert!(fv.queue_delay_ratio < 0.3);
}

#[test]
fn test_streaming_isolation_forest_anomaly_scoring() {
    let mut baseline = Vec::new();
    for i in 0..40 {
        baseline.push(FeatureVector {
            rtt_z_score: (i as f64 * 0.02) - 0.4,
            loss_rate: 0.0001,
            throughput_drop_ratio: 0.01,
            queue_delay_ratio: 0.05,
            rtt_variance_ratio: 0.04,
            jitter_z_score: 0.1,
            inflight_to_bdp_ratio: 0.95,
        });
    }

    let forest = StreamingIsolationForest::fit(&baseline, 30, 8);

    // Normal sample
    let normal_fv = FeatureVector {
        rtt_z_score: 0.05,
        loss_rate: 0.0002,
        throughput_drop_ratio: 0.02,
        queue_delay_ratio: 0.06,
        rtt_variance_ratio: 0.05,
        jitter_z_score: 0.15,
        inflight_to_bdp_ratio: 0.96,
    };
    let normal_score = forest.score(&normal_fv);
    assert!(
        normal_score < 0.60,
        "normal sample score was {}",
        normal_score
    );

    // Extreme anomaly
    let anom_fv = FeatureVector {
        rtt_z_score: 7.2,
        loss_rate: 0.20,
        throughput_drop_ratio: 0.75,
        queue_delay_ratio: 5.5,
        rtt_variance_ratio: 0.85,
        jitter_z_score: 8.0,
        inflight_to_bdp_ratio: 4.2,
    };
    let anom_score = forest.score(&anom_fv);
    assert!(
        anom_score >= 0.65,
        "anomalous sample score was {}",
        anom_score
    );
}

#[test]
fn test_cusum_drift_detection() {
    let mut cusum = CusumDetector::new(0.0, 0.5, 3.0);

    // In control: random oscillations within [-0.4, 0.4]
    for _ in 0..10 {
        assert!(!cusum.update(0.2));
        assert!(!cusum.update(-0.1));
    }

    // Abrupt step drift (+2.0 sustained)
    let mut triggered = false;
    for _ in 0..5 {
        if cusum.update(2.0) {
            triggered = true;
            break;
        }
    }
    assert!(triggered, "CUSUM should have detected positive mean drift");

    cusum.reset();
    assert_eq!(cusum.sum_pos, 0.0);
    assert_eq!(cusum.sum_neg, 0.0);
}

#[test]
fn test_anomaly_classifier_taxonomy() {
    // 1. Bufferbloat
    let bb_fv = FeatureVector {
        rtt_z_score: 3.2,
        loss_rate: 0.001,
        throughput_drop_ratio: 0.05,
        queue_delay_ratio: 2.5,
        rtt_variance_ratio: 0.1,
        jitter_z_score: 0.5,
        inflight_to_bdp_ratio: 1.8,
    };
    let mut bb_sample = MetricSample::healthy_baseline(1000);
    bb_sample.rtt_ms = 110.0;
    bb_sample.min_rtt_ms = 30.0;
    let bb_class = AnomalyClassifier::classify(&bb_fv, &bb_sample);
    assert_eq!(bb_class.anomaly_type, AnomalyType::Bufferbloat);

    // 2. Link Degradation
    let ld_fv = FeatureVector {
        rtt_z_score: 0.5,
        loss_rate: 0.07,
        throughput_drop_ratio: 0.35,
        queue_delay_ratio: 0.2,
        rtt_variance_ratio: 0.1,
        jitter_z_score: 0.6,
        inflight_to_bdp_ratio: 0.8,
    };
    let mut ld_sample = MetricSample::healthy_baseline(2000);
    ld_sample.loss_rate = 0.07;
    let ld_class = AnomalyClassifier::classify(&ld_fv, &ld_sample);
    assert_eq!(ld_class.anomaly_type, AnomalyType::LinkDegradation);

    // 3. Route Flap / Blackhole
    let rf_fv = FeatureVector {
        rtt_z_score: 5.5,
        loss_rate: 0.10,
        throughput_drop_ratio: 0.85,
        queue_delay_ratio: 3.0,
        rtt_variance_ratio: 0.5,
        jitter_z_score: 2.0,
        inflight_to_bdp_ratio: 0.2,
    };
    let mut rf_sample = MetricSample::healthy_baseline(3000);
    rf_sample.rtt_ms = 220.0;
    rf_sample.throughput_bps = 100_000_000.0;
    let rf_class = AnomalyClassifier::classify(&rf_fv, &rf_sample);
    assert_eq!(rf_class.anomaly_type, AnomalyType::RouteFlapBlackhole);

    // 4. Microburst Congestion
    let mb_fv = FeatureVector {
        rtt_z_score: 1.5,
        loss_rate: 0.02,
        throughput_drop_ratio: 0.1,
        queue_delay_ratio: 0.5,
        rtt_variance_ratio: 0.45,
        jitter_z_score: 3.5,
        inflight_to_bdp_ratio: 1.1,
    };
    let mut mb_sample = MetricSample::healthy_baseline(4000);
    mb_sample.jitter_ms = 8.0;
    let mb_class = AnomalyClassifier::classify(&mb_fv, &mb_sample);
    assert_eq!(mb_class.anomaly_type, AnomalyType::MicroburstCongestion);
}

#[test]
fn test_self_healing_shaper_mitigations() {
    let mut shaper = SelfHealingShaper::new(1_000_000_000.0);
    let sample = MetricSample::healthy_baseline(1000);

    // Bufferbloat: Pacing rate throttling
    let bb = AnomalyClassification {
        anomaly_type: AnomalyType::Bufferbloat,
        confidence: 0.9,
        severity: 0.8,
        root_cause: "Queue delay".to_string(),
        recommended_action: "Throttle".to_string(),
    };
    let act_bb = shaper.decide_action(&sample, Some(&bb));
    assert_eq!(act_bb.name(), "adjust_pacing_rate");
    assert_eq!(shaper.current_pacing_bps, 700_000_000.0);

    // Advance time past cooldown
    let sample2 = MetricSample::healthy_baseline(2000);

    // Link Degradation: FEC redundancy scaling
    let ld = AnomalyClassification {
        anomaly_type: AnomalyType::LinkDegradation,
        confidence: 0.85,
        severity: 0.75,
        root_cause: "High loss".to_string(),
        recommended_action: "Scale FEC".to_string(),
    };
    let act_ld = shaper.decide_action(&sample2, Some(&ld));
    assert_eq!(act_ld.name(), "scale_fec_redundancy");
    assert!(shaper.current_fec_ratio >= 0.12);

    // Advance time past cooldown
    let sample3 = MetricSample::healthy_baseline(3000);

    // Route Flap: Subflow rerouting
    let rf = AnomalyClassification {
        anomaly_type: AnomalyType::RouteFlapBlackhole,
        confidence: 0.95,
        severity: 0.9,
        root_cause: "Blackhole".to_string(),
        recommended_action: "Reroute".to_string(),
    };
    let act_rf = shaper.decide_action(&sample3, Some(&rf));
    assert_eq!(act_rf.name(), "reroute_subflow");
}

#[test]
fn test_shaper_gradual_recovery_post_anomaly() {
    let mut shaper = SelfHealingShaper::new(1_000_000_000.0);
    let sample = MetricSample::healthy_baseline(1000);

    let bb = AnomalyClassification {
        anomaly_type: AnomalyType::Bufferbloat,
        confidence: 0.9,
        severity: 0.8,
        root_cause: "Queue delay".to_string(),
        recommended_action: "Throttle".to_string(),
    };
    let _ = shaper.decide_action(&sample, Some(&bb));
    assert_eq!(shaper.current_pacing_bps, 700_000_000.0);

    // Healthy ticks gradually ramp back to line rate
    for i in 1..=10 {
        let h_sample = MetricSample::healthy_baseline(2000 + i * 100);
        let _ = shaper.decide_action(&h_sample, None);
    }

    assert!(shaper.current_pacing_bps > 700_000_000.0);
    assert!(shaper.current_pacing_bps <= 1_000_000_000.0);
}

#[tokio::test]
async fn test_incident_ledger_post_mortem_and_resolution() {
    let ledger = IncidentLedger::new(50);
    let sample = MetricSample::healthy_baseline(1000);
    let fv = FeatureVector {
        rtt_z_score: 3.5,
        loss_rate: 0.04,
        throughput_drop_ratio: 0.3,
        queue_delay_ratio: 2.0,
        rtt_variance_ratio: 0.2,
        jitter_z_score: 1.5,
        inflight_to_bdp_ratio: 1.6,
    };
    let class = AnomalyClassification {
        anomaly_type: AnomalyType::Bufferbloat,
        confidence: 0.89,
        severity: 0.75,
        root_cause: "Bufferbloat test".to_string(),
        recommended_action: "Throttle".to_string(),
    };
    let action = ShaperAction::AdjustPacingRate {
        new_pacing_bps: 700_000_000.0,
        scale_factor: 0.7,
        reason: "Test".to_string(),
    };

    let id = ledger.record(&class, &action, &sample, &fv).await;
    assert_eq!(id, "inc-000001");

    let recent = ledger.list_recent(1).await;
    assert_eq!(recent.len(), 1);
    assert!(!recent[0].resolved);

    let resolved = ledger.mark_resolved(&id, 350, 180_000_000.0).await;
    assert!(resolved);

    let updated = ledger.list_recent(1).await;
    assert!(updated[0].resolved);
    assert_eq!(updated[0].recovery_latency_ms, Some(350));
    assert_eq!(updated[0].throughput_delta_bps, Some(180_000_000.0));
}

#[tokio::test]
async fn test_traffic_engine_end_to_end_synthetic_benchmark() {
    let report = TrafficEngine::run_benchmark(60, Some(AnomalyType::Bufferbloat)).await;
    assert_eq!(report.total_samples, 60);
    assert!(report.anomalies_injected > 0);
    assert!(report.anomalies_detected > 0);
    assert!(report.mitigations_applied > 0);
    assert!(report.accuracy_percent > 70.0);
}

#[tokio::test]
async fn test_prometheus_metric_exposition_format() {
    let engine = TrafficEngine::new(1_000_000_000.0);
    let prom = engine.prometheus_metrics().await;

    assert!(prom.contains("velcrux_traffic_anomaly_score"));
    assert!(prom.contains("velcrux_traffic_pacing_rate_bps"));
    assert!(prom.contains("velcrux_traffic_fec_redundancy_ratio"));
    assert!(prom.contains("velcrux_traffic_incidents_total"));
    assert!(prom.contains("velcrux_traffic_mitigations_total"));
}
