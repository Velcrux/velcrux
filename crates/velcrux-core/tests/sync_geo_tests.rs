//! Integration tests for cross-cluster WAN geo-replication and conflict resolution (Option BA).

use velcrux_core::sync::{
    ClockOrdering, ConflictAction, ConflictPolicy, GeoItemMetadata, GeoReplicationCoordinator,
    ReplicationChange, VectorClock,
};
use velcrux_core::util::Hash;

#[test]
fn test_three_region_vector_clock_propagation() {
    let mut vc_us = VectorClock::new();
    let mut vc_eu = VectorClock::new();
    let mut vc_ap = VectorClock::new();

    // 1. Mutation originates in us-east
    vc_us.increment("us-east");
    assert_eq!(vc_us.get("us-east"), 1);

    // 2. Replicates to eu-west
    vc_eu.merge(&vc_us);
    assert_eq!(vc_eu.compare(&vc_us), ClockOrdering::Equal);

    // 3. eu-west modifies the file
    vc_eu.increment("eu-west");
    assert_eq!(vc_eu.compare(&vc_us), ClockOrdering::Greater);
    assert_eq!(vc_us.compare(&vc_eu), ClockOrdering::Less);

    // 4. Concurrently, ap-south modifies the original version
    vc_ap.merge(&vc_us);
    vc_ap.increment("ap-south");

    // eu and ap are now concurrent
    assert_eq!(vc_eu.compare(&vc_ap), ClockOrdering::Concurrent);
    assert_eq!(vc_ap.compare(&vc_eu), ClockOrdering::Concurrent);

    // 5. Convergence: merging both gives a clock strictly greater than both
    let mut converged = vc_eu.clone();
    converged.merge(&vc_ap);
    assert_eq!(converged.compare(&vc_eu), ClockOrdering::Greater);
    assert_eq!(converged.compare(&vc_ap), ClockOrdering::Greater);
}

#[test]
fn test_geo_coordinator_primary_authority_conflict_policy() {
    let coord = GeoReplicationCoordinator::new(
        "eu-west",
        ConflictPolicy::PrimaryAuthority {
            primary_region: "us-east".to_string(),
        },
    );

    // Local modification in eu-west
    coord.record_local_mutation("dataset.parquet", 1000, Hash::of(b"eu bytes"), None);

    // Concurrent remote modification from primary region us-east
    let mut us_vc = VectorClock::new();
    us_vc.increment("us-east");
    let us_meta = GeoItemMetadata::file(
        "dataset.parquet",
        1200,
        Hash::of(b"us bytes"),
        us_vc,
        "us-east",
    );

    let res = coord
        .apply_remote_change(&ReplicationChange {
            sequence_id: 1,
            metadata: us_meta,
            payload: None,
        })
        .unwrap();

    assert!(res.was_conflict);
    assert_eq!(
        res.action,
        ConflictAction::ApplyRemote,
        "primary region must win conflict"
    );

    // Concurrent remote modification from non-primary region ap-south
    let mut ap_vc = VectorClock::new();
    ap_vc.increment("ap-south");
    let ap_meta = GeoItemMetadata::file(
        "dataset.parquet",
        900,
        Hash::of(b"ap bytes"),
        ap_vc,
        "ap-south",
    );

    let res2 = coord
        .apply_remote_change(&ReplicationChange {
            sequence_id: 2,
            metadata: ap_meta,
            payload: None,
        })
        .unwrap();

    assert!(res2.was_conflict);
    assert_eq!(
        res2.action,
        ConflictAction::KeepLocal,
        "non-primary remote change must lose"
    );
}

#[test]
fn test_geo_coordinator_tombstone_dominates_stale_mutation() {
    let coord = GeoReplicationCoordinator::new("us-east", ConflictPolicy::LastWriteWins);

    // 1. Create file and then delete it locally in us-east
    coord.record_local_mutation("ephemeral.tmp", 500, Hash::of(b"initial"), None);
    let _del_change = coord.record_local_deletion("ephemeral.tmp").unwrap();

    // 2. Incoming stale modification from a remote region with older vector clock
    let mut stale_vc = VectorClock::new();
    stale_vc.clocks.insert("us-east".to_string(), 1); // older than deletion clock which is 2

    let stale_meta = GeoItemMetadata::file(
        "ephemeral.tmp",
        500,
        Hash::of(b"stale data"),
        stale_vc,
        "eu-west",
    );

    let res = coord
        .apply_remote_change(&ReplicationChange {
            sequence_id: 99,
            metadata: stale_meta,
            payload: None,
        })
        .unwrap();

    assert_eq!(
        res.action,
        ConflictAction::KeepLocal,
        "deletion tombstone must dominate older mutation and prevent resurrecting file"
    );

    let report = coord.generate_status_report();
    assert_eq!(report.active_tombstones, 1);
    assert_eq!(report.tracked_files, 0);
}
