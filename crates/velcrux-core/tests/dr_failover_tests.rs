//! Integration tests for Multi-Cluster Global Disaster Recovery Failover
//! & Split-Brain Fencing Coordinator (ADR-080).

use velcrux_core::dr::{
    ClusterRegion, ClusterRole, DrError, DrFailoverCoordinator, DrFailureDetectorConfig, DrState,
    FailoverMode, HeartbeatMsg, ProbeHealthStatus,
};

fn create_test_cluster() -> DrFailoverCoordinator {
    let config = DrFailureDetectorConfig {
        heartbeat_interval_ms: 100,
        jitter_bound_ms: 30,
        consecutive_loss_threshold: 3,
        history_window_size: 32,
        suspicion_threshold: 0.70,
    };

    let mut coord = DrFailoverCoordinator::new("region-us-east", 1000, 10_000, config);

    // Primary
    coord.register_region(ClusterRegion::new(
        "region-us-east",
        "US East Production",
        ClusterRole::Primary,
        "useast.velcrux.internal:9000",
        1,
        "us-east-1",
    ));

    // Standby 1
    coord.register_region(ClusterRegion::new(
        "region-eu-west",
        "EU West Disaster Recovery",
        ClusterRole::Standby,
        "euwest.velcrux.internal:9000",
        1,
        "eu-west-1",
    ));

    // Standby 2
    coord.register_region(ClusterRegion::new(
        "region-ap-southeast",
        "AP Southeast Disaster Recovery",
        ClusterRole::Standby,
        "apse.velcrux.internal:9000",
        1,
        "ap-southeast-1",
    ));

    // Witness 1
    coord.register_region(ClusterRegion::new(
        "witness-chicago",
        "Chicago Quorum Witness",
        ClusterRole::Witness,
        "witness-chi.velcrux.internal:9000",
        1,
        "us-midwest-1",
    ));

    // Witness 2
    coord.register_region(ClusterRegion::new(
        "witness-dublin",
        "Dublin Quorum Witness",
        ClusterRole::Witness,
        "witness-dub.velcrux.internal:9000",
        1,
        "eu-west-2",
    ));

    // Witness 3
    coord.register_region(ClusterRegion::new(
        "witness-tokyo",
        "Tokyo Quorum Witness",
        ClusterRole::Witness,
        "witness-tyo.velcrux.internal:9000",
        1,
        "ap-northeast-1",
    ));

    // Register cryptographic witness secrets
    coord.register_witness("witness-chicago", b"chicago-secret-key-32b-long!!");
    coord.register_witness("witness-dublin", b"dublin-secret-key-32b-long!!!");
    coord.register_witness("witness-tokyo", b"tokyo-secret-key-32b-long!!!!");

    coord
}

#[test]
fn test_multi_cluster_topology_registration_and_status() {
    let coord = create_test_cluster();
    let status = coord.status(5000);

    assert_eq!(status.current_epoch, 1000);
    assert_eq!(status.active_primary, "region-us-east");
    assert_eq!(status.state, DrState::NormalActive);
    assert_eq!(status.witness_count, 3);
    assert_eq!(status.quorum_size, 2); // (3 / 2) + 1 = 2
    assert_eq!(status.regions.len(), 6);
}

#[test]
fn test_dynamic_failure_detector_and_suspicion_metrics() {
    let mut coord = create_test_cluster();
    let base_time = 10_000;

    // Send heartbeats from eu-west with stable intervals
    for i in 0..5 {
        let t = base_time + (i * 100);
        let msg = HeartbeatMsg {
            sender_cluster: "region-eu-west".to_string(),
            epoch: 1000,
            timestamp_ms: t,
            rpo_lag_ms: 12,
            state: DrState::NormalActive,
        };
        coord.record_heartbeat(msg, t);
    }

    let status = coord.status(base_time + 420);
    let eu_region = status
        .regions
        .iter()
        .find(|r| r.id == "region-eu-west")
        .unwrap();

    assert_eq!(eu_region.health, ProbeHealthStatus::Alive);
    assert_eq!(eu_region.rpo_lag_ms, 12);
    assert!(eu_region.avg_interval_ms > 0.0);

    // Let time pass without heartbeats: at +550ms, missed 1 heartbeat -> Suspect
    let status_suspect = coord.status(base_time + 550);
    let eu_suspect = status_suspect
        .regions
        .iter()
        .find(|r| r.id == "region-eu-west")
        .unwrap();
    assert_eq!(eu_suspect.health, ProbeHealthStatus::Suspect);

    // At +800ms, missed 3+ heartbeats -> Dead
    let status_dead = coord.status(base_time + 800);
    let eu_dead = status_dead
        .regions
        .iter()
        .find(|r| r.id == "region-eu-west")
        .unwrap();
    assert_eq!(eu_dead.health, ProbeHealthStatus::Dead);
}

#[test]
fn test_quorum_witness_lease_and_storage_fencing_barriers() {
    let mut coord = create_test_cluster();
    let now = 1000;

    // 1. Initial write before any token issued is allowed at epoch 1000
    assert!(coord
        .validate_storage_write(1000, "region-us-east", now)
        .is_ok());

    // 2. Issue fencing token to primary with witness quorum approvals
    let witnesses = vec!["witness-chicago".to_string(), "witness-dublin".to_string()];
    let token = coord
        .fencing_engine_mut()
        .issue_fencing_token("region-us-east", 15_000, now, &witnesses)
        .unwrap();

    assert_eq!(token.epoch, 1001);
    assert_eq!(token.quorum_signatures.len(), 2);
    assert_eq!(coord.fencing_engine().current_epoch(), 1001);

    // 3. Valid write with token epoch 1001
    assert!(coord
        .validate_storage_write(1001, "region-us-east", now + 500)
        .is_ok());

    // 4. Stale write with epoch 1000 rejected (Split-brain prevention!)
    let err = coord
        .validate_storage_write(1000, "region-us-east", now + 500)
        .unwrap_err();
    assert_eq!(
        err,
        DrError::FencedObsoleteEpoch {
            attempted: 1000,
            current: 1001
        }
    );

    // 5. Unauthorized cluster rejected
    let err_unauth = coord
        .validate_storage_write(1001, "region-eu-west", now + 500)
        .unwrap_err();
    assert!(matches!(err_unauth, DrError::UnauthorizedCluster { .. }));

    // 6. Expired lease rejected
    let err_expired = coord
        .validate_storage_write(1001, "region-us-east", now + 20_000)
        .unwrap_err();
    assert!(matches!(err_expired, DrError::FencedExpiredLease { .. }));
}

#[test]
fn test_graceful_planned_switchover_flow() {
    let mut coord = create_test_cluster();
    let now = 5000;

    // Send heartbeat from eu-west so it is alive
    let hb = HeartbeatMsg {
        sender_cluster: "region-eu-west".to_string(),
        epoch: 1000,
        timestamp_ms: now,
        rpo_lag_ms: 0,
        state: DrState::NormalActive,
    };
    coord.record_heartbeat(hb, now);

    let report = coord.plan_switchover("region-eu-west", now).unwrap();
    assert_eq!(report.mode, FailoverMode::PlannedSwitchover);
    assert_eq!(report.previous_primary, "region-us-east");
    assert_eq!(report.new_primary, "region-eu-west");
    assert_eq!(report.rpo_lag_ms, 0); // Guaranteed RPO = 0 for planned switchover
    assert_eq!(report.fencing_epoch, 1001);
    assert!(report.success);

    // Verify coordinator state
    assert_eq!(coord.active_primary(), "region-eu-west");
    assert_eq!(coord.state(), DrState::NormalActive);

    // Verify storage write barrier enforces new primary
    assert!(coord
        .validate_storage_write(1001, "region-eu-west", now + 10)
        .is_ok());
    assert!(coord
        .validate_storage_write(1000, "region-us-east", now + 10)
        .is_err());
}

#[test]
fn test_emergency_failover_with_old_primary_fencing_and_split_brain_prevention() {
    let mut coord = create_test_cluster();
    let now = 10_000;

    // Establish healthy heartbeats for standbys with different RPOs
    let hb_eu = HeartbeatMsg {
        sender_cluster: "region-eu-west".to_string(),
        epoch: 1000,
        timestamp_ms: now,
        rpo_lag_ms: 25,
        state: DrState::NormalActive,
    };
    coord.record_heartbeat(hb_eu, now);

    let hb_ap = HeartbeatMsg {
        sender_cluster: "region-ap-southeast".to_string(),
        epoch: 1000,
        timestamp_ms: now,
        rpo_lag_ms: 8, // Lowest lag
        state: DrState::NormalActive,
    };
    coord.record_heartbeat(hb_ap, now);

    // Emergency failover without specifying target cluster -> auto-selects ap-southeast due to lowest RPO (8ms < 25ms)
    let report = coord.execute_emergency_failover(None, true, now).unwrap();
    assert_eq!(report.mode, FailoverMode::EmergencyFailover);
    assert_eq!(report.previous_primary, "region-us-east");
    assert_eq!(report.new_primary, "region-ap-southeast");
    assert_eq!(report.rpo_lag_ms, 8);
    assert_eq!(coord.active_primary(), "region-ap-southeast");

    // Old primary region-us-east is explicitly fenced in the storage fencing barrier
    assert!(coord.fencing_engine().is_cluster_fenced("region-us-east"));
    let fence_check =
        coord.validate_storage_write(report.fencing_epoch, "region-us-east", now + 10);
    assert!(fence_check.is_err());

    // Recover old primary and execute failback
    let recover_hb = HeartbeatMsg {
        sender_cluster: "region-us-east".to_string(),
        epoch: report.fencing_epoch,
        timestamp_ms: now + 500,
        rpo_lag_ms: 0,
        state: DrState::NormalActive,
    };
    coord.record_heartbeat(recover_hb, now + 500);

    let failback_report = coord.execute_failback("region-us-east", now + 500).unwrap();
    assert_eq!(failback_report.new_primary, "region-us-east");
    assert_eq!(coord.active_primary(), "region-us-east");
    assert!(!coord.fencing_engine().is_cluster_fenced("region-us-east"));

    // Write now allowed on restored primary under new epoch
    assert!(coord
        .validate_storage_write(failback_report.fencing_epoch, "region-us-east", now + 510)
        .is_ok());
}

#[test]
fn test_dr_benchmark_simulation() {
    let mut coord = create_test_cluster();
    let bench = coord.run_benchmark(100);

    assert_eq!(bench.iterations, 100);
    assert!(bench.avg_heartbeat_latency_ns > 0.0);
    assert!(bench.avg_fencing_consensus_us > 0.0);
    assert!(bench.write_fencing_ops_per_sec > 1000.0);
    assert!(bench.split_brain_prevented_count > 0);
}
