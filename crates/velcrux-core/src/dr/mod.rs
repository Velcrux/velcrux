//! Autonomous Multi-Cluster Global Disaster Recovery Failover & Split-Brain Fencing Coordinator (ADR-080).
//!
//! Provides pure safe Rust multi-region disaster recovery management:
//! - Multi-region topology roles (`Primary`, `Standby`, `Witness`).
//! - RPO (Recovery Point Objective) and RTO (Recovery Time Objective) tracking.
//! - Decentralized multi-path health probing and dynamic failure detection.
//! - Cryptographically signed fencing generation epochs with witness quorum lease approval.
//! - Monotonic storage write and gateway I/O fencing barriers preventing split-brain writes.
//! - Autonomous failover and failback finite state machine.

pub mod coordinator;
pub mod detector;
pub mod fencing;
pub mod types;

pub use coordinator::DrFailoverCoordinator;
pub use detector::DrFailureDetector;
pub use fencing::StorageFencingEngine;
pub use types::{
    ClusterRegion, ClusterRole, DrBenchmarkReport, DrError, DrFailoverReport,
    DrFailureDetectorConfig, DrResult, DrState, DrStatusReport, FailoverMode, FencingToken,
    HeartbeatMsg, ProbeHealthStatus, RegionStatus,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_topology() -> DrFailoverCoordinator {
        let config = DrFailureDetectorConfig {
            heartbeat_interval_ms: 50,
            jitter_bound_ms: 20,
            consecutive_loss_threshold: 3,
            history_window_size: 16,
            suspicion_threshold: 0.7,
        };

        let mut coord = DrFailoverCoordinator::new("us-east", 100, 5000, config);

        // Register 3 regions: 1 primary, 1 standby, 1 witness
        coord.register_region(ClusterRegion::new(
            "us-east",
            "US East (Virginia)",
            ClusterRole::Primary,
            "10.0.1.1:9000",
            1,
            "us-east-1a",
        ));

        coord.register_region(ClusterRegion::new(
            "eu-west",
            "EU West (Frankfurt)",
            ClusterRole::Standby,
            "10.0.2.1:9000",
            1,
            "eu-central-1a",
        ));

        coord.register_region(ClusterRegion::new(
            "ap-south",
            "AP South (Mumbai)",
            ClusterRole::Witness,
            "10.0.3.1:9000",
            1,
            "ap-south-1a",
        ));

        // Register witness secret
        coord.register_witness("ap-south", b"mumbai-witness-secret-key-32b!!");

        coord
    }

    #[test]
    fn test_role_parsing_and_display() {
        assert_eq!(
            "primary".parse::<ClusterRole>().unwrap(),
            ClusterRole::Primary
        );
        assert_eq!(
            "standby".parse::<ClusterRole>().unwrap(),
            ClusterRole::Standby
        );
        assert_eq!(
            "witness".parse::<ClusterRole>().unwrap(),
            ClusterRole::Witness
        );
        assert_eq!(ClusterRole::Primary.to_string(), "primary");
    }

    #[test]
    fn test_heartbeat_detector_health() {
        let mut detector = DrFailureDetector::new(DrFailureDetectorConfig {
            heartbeat_interval_ms: 100,
            jitter_bound_ms: 25,
            consecutive_loss_threshold: 3,
            history_window_size: 10,
            suspicion_threshold: 0.75,
        });

        let hb = HeartbeatMsg {
            sender_cluster: "us-east".to_string(),
            epoch: 1,
            timestamp_ms: 1000,
            rpo_lag_ms: 5,
            state: DrState::NormalActive,
        };

        detector.record_heartbeat(&hb, 1000);
        assert_eq!(
            detector.check_health("us-east", 1050),
            ProbeHealthStatus::Alive
        );

        // Within jitter threshold
        assert_eq!(
            detector.check_health("us-east", 1120),
            ProbeHealthStatus::Alive
        );

        // 1-2 missed heartbeats -> Suspect
        assert_eq!(
            detector.check_health("us-east", 1210),
            ProbeHealthStatus::Suspect
        );

        // 3 missed heartbeats -> Dead
        assert_eq!(
            detector.check_health("us-east", 1350),
            ProbeHealthStatus::Dead
        );
    }

    #[test]
    fn test_multipath_partition_differentiation() {
        let mut detector = DrFailureDetector::new(DrFailureDetectorConfig {
            heartbeat_interval_ms: 100,
            jitter_bound_ms: 20,
            consecutive_loss_threshold: 3,
            history_window_size: 10,
            suspicion_threshold: 0.7,
        });

        let hb = HeartbeatMsg {
            sender_cluster: "eu-west".to_string(),
            epoch: 1,
            timestamp_ms: 1000,
            rpo_lag_ms: 10,
            state: DrState::NormalActive,
        };
        detector.record_heartbeat(&hb, 1000);

        // Probe secondary WAN at 1200ms
        detector.record_path_probe("eu-west", "secondary_wan", 1200);

        // At 1350ms, primary WAN timed out (last seen 1000ms), but secondary WAN was seen at 1200ms (< 300ms timeout)
        assert!(!detector.is_total_network_partition("eu-west", 1350));

        // At 1600ms, all paths have timed out -> total network partition
        assert!(detector.is_total_network_partition("eu-west", 1600));
    }

    #[test]
    fn test_fencing_epoch_write_barrier() {
        let mut fencing = StorageFencingEngine::new(10);
        fencing.register_witness("witness-1", b"secret-key-1");
        fencing.register_witness("witness-2", b"secret-key-2");

        let witnesses = vec!["witness-1".to_string(), "witness-2".to_string()];
        let token = fencing
            .issue_fencing_token("us-east", 5000, 1000, &witnesses)
            .unwrap();

        assert_eq!(token.epoch, 11);
        assert_eq!(fencing.current_epoch(), 11);

        // Valid write from holder at current epoch
        assert!(fencing.validate_write(11, "us-east", 2000).is_ok());

        // Rejected write with obsolete epoch (split-brain attempt)
        let err = fencing.validate_write(10, "us-east", 2000).unwrap_err();
        match err {
            DrError::FencedObsoleteEpoch { attempted, current } => {
                assert_eq!(attempted, 10);
                assert_eq!(current, 11);
            }
            other => panic!("Expected FencedObsoleteEpoch, got {other:?}"),
        }

        // Rejected write from unauthorized cluster
        let err2 = fencing.validate_write(11, "rogue-node", 2000).unwrap_err();
        match err2 {
            DrError::UnauthorizedCluster { cluster, holder } => {
                assert_eq!(cluster, "rogue-node");
                assert_eq!(holder, "us-east");
            }
            other => panic!("Expected UnauthorizedCluster, got {other:?}"),
        }

        // Rejected write after lease expiry
        let err3 = fencing.validate_write(11, "us-east", 7000).unwrap_err();
        match err3 {
            DrError::FencedExpiredLease { expired_at, now } => {
                assert_eq!(expired_at, 6000);
                assert_eq!(now, 7000);
            }
            other => panic!("Expected FencedExpiredLease, got {other:?}"),
        }
    }

    #[test]
    fn test_planned_switchover() {
        let mut coord = sample_topology();
        let now = 1000;

        // Make standby alive
        let hb = HeartbeatMsg {
            sender_cluster: "eu-west".to_string(),
            epoch: 100,
            timestamp_ms: now,
            rpo_lag_ms: 0,
            state: DrState::NormalActive,
        };
        coord.record_heartbeat(hb, now);

        let report = coord.plan_switchover("eu-west", now).unwrap();
        assert_eq!(report.mode, FailoverMode::PlannedSwitchover);
        assert_eq!(report.previous_primary, "us-east");
        assert_eq!(report.new_primary, "eu-west");
        assert_eq!(report.fencing_epoch, 101);
        assert_eq!(coord.active_primary(), "eu-west");

        // Old primary cannot write under old epoch
        assert!(coord
            .validate_storage_write(100, "us-east", now + 10)
            .is_err());
        // New primary can write under epoch 101
        assert!(coord
            .validate_storage_write(101, "eu-west", now + 10)
            .is_ok());
    }

    #[test]
    fn test_emergency_failover_and_failback() {
        let mut coord = sample_topology();
        let now = 1000;

        // Standby has 15ms RPO lag
        let hb = HeartbeatMsg {
            sender_cluster: "eu-west".to_string(),
            epoch: 100,
            timestamp_ms: now,
            rpo_lag_ms: 15,
            state: DrState::NormalActive,
        };
        coord.record_heartbeat(hb, now);

        // Emergency failover with force
        let report = coord
            .execute_emergency_failover(Some("eu-west"), true, now)
            .unwrap();
        assert_eq!(report.mode, FailoverMode::EmergencyFailover);
        assert_eq!(report.previous_primary, "us-east");
        assert_eq!(report.new_primary, "eu-west");
        assert_eq!(report.rpo_lag_ms, 15);
        assert_eq!(coord.active_primary(), "eu-west");

        // Old primary is fenced
        assert!(coord.fencing_engine().is_cluster_fenced("us-east"));

        // Simulate us-east recovering and sending heartbeat
        let recovered_hb = HeartbeatMsg {
            sender_cluster: "us-east".to_string(),
            epoch: 101,
            timestamp_ms: now + 100,
            rpo_lag_ms: 0,
            state: DrState::NormalActive,
        };
        coord.record_heartbeat(recovered_hb, now + 100);

        // Failback to us-east
        let fb_report = coord.execute_failback("us-east", now + 100).unwrap();
        assert_eq!(fb_report.new_primary, "us-east");
        assert_eq!(coord.active_primary(), "us-east");
        assert!(!coord.fencing_engine().is_cluster_fenced("us-east"));
    }

    #[test]
    fn test_benchmark_execution() {
        let mut coord = sample_topology();
        let bench = coord.run_benchmark(50);
        assert_eq!(bench.iterations, 50);
        assert!(bench.write_fencing_ops_per_sec > 0.0);
        assert!(bench.split_brain_prevented_count > 0);
    }
}
