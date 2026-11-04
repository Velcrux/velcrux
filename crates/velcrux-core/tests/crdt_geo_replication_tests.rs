//! Comprehensive integration tests for Option CZ:
//! Distributed Global Multi-Cluster Geo-Replication & Conflict-Free Replicated Data Types (`ADR-068`).

#![forbid(unsafe_code)]

use velcrux_core::crdt::{
    AntiEntropyEngine, CausalOrder, FsNodeKind, GeoMesh, Hlc, LwwRegister, MvRegister, OrSet,
    ReplicatedFsTree, VectorClock,
};

#[test]
fn test_vector_clock_causality_and_concurrency() {
    let mut vc1 = VectorClock::new();
    let mut vc2 = VectorClock::new();

    vc1.tick("us-east");
    assert_eq!(vc1.get("us-east"), 1);
    assert_eq!(vc1.compare(&vc2), CausalOrder::After);
    assert!(vc2.happens_before(&vc1));

    // vc2 observes us-east:1 and ticks eu-west:1
    vc2.update("us-east", 1);
    vc2.tick("eu-west");
    assert_eq!(vc1.compare(&vc2), CausalOrder::Before);
    assert!(vc1.happens_before(&vc2));

    // vc1 ticks us-east:2 concurrently without knowing eu-west:1
    vc1.tick("us-east");
    assert_eq!(vc1.compare(&vc2), CausalOrder::Concurrent);
    assert!(vc1.is_concurrent_with(&vc2));

    // Merge vector clocks
    let merged = vc1.merged(&vc2);
    assert_eq!(merged.get("us-east"), 2);
    assert_eq!(merged.get("eu-west"), 1);
    assert!(merged.dominates(&vc1));
    assert!(merged.dominates(&vc2));
}

#[test]
fn test_hlc_monotonicity_and_ordering() {
    let mut hlc_a = Hlc::with_values("node-a", 1000, 0);
    let mut hlc_b = Hlc::with_values("node-b", 1000, 0);

    // Node A ticks
    let t1 = hlc_a.on_send();
    assert!(t1 > Hlc::with_values("node-a", 1000, 0));

    // Node B receives t1 from Node A
    let t2 = hlc_b.on_recv(&t1);
    assert!(t2 > t1);
    assert!(t2.physical_ms >= t1.physical_ms);

    // Node A and Node B with identical physical/logical time tie-break by node_id
    let h1 = Hlc::with_values("node-a", 2000, 5);
    let h2 = Hlc::with_values("node-b", 2000, 5);
    assert!(h1 < h2);
}

#[test]
fn test_primitive_crdts_lww_orset_mvregister() {
    // 1. Last-Write-Wins Register
    let hlc1 = Hlc::with_values("node-a", 1000, 1);
    let hlc2 = Hlc::with_values("node-b", 1000, 2);

    let mut reg_a = LwwRegister::new("initial_data".to_string(), hlc1);
    let reg_b = LwwRegister::new("newer_data".to_string(), hlc2);

    reg_a.merge(&reg_b);
    assert_eq!(reg_a.get(), "newer_data");

    // 2. Observed-Removed Set (OR-Set / Add-Wins)
    let mut set_a = OrSet::new();
    let mut set_b = OrSet::new();

    set_a.add("chunk-001", "tag-a-1");
    set_a.add("chunk-002", "tag-a-2");

    // Replicate to set_b
    set_b.merge(&set_a);
    assert!(set_b.contains(&"chunk-001"));
    assert!(set_b.contains(&"chunk-002"));

    // set_b removes chunk-001 (tombstones tag-a-1)
    set_b.remove(&"chunk-001");
    assert!(!set_b.contains(&"chunk-001"));

    // Concurrently, set_a re-adds chunk-001 with a fresh tag "tag-a-3"
    set_a.add("chunk-001", "tag-a-3");

    // Merge: Add-Wins semantics ensure chunk-001 survives via tag-a-3
    set_b.merge(&set_a);
    assert!(set_b.contains(&"chunk-001"));
    assert!(set_b.contains(&"chunk-002"));

    // 3. Multi-Value Register (MV-Register)
    let mut vc1 = VectorClock::new();
    vc1.tick("node-a");
    let mut mv = MvRegister::new("val-a", vc1.clone());

    let mut vc2 = VectorClock::new();
    vc2.tick("node-b");
    let mv_concurrent = MvRegister::new("val-b", vc2.clone());

    // Merge concurrent registers: retains both values
    mv.merge(&mv_concurrent);
    let vals = mv.read();
    assert_eq!(vals.len(), 2);
    assert!(vals.contains(&"val-a"));
    assert!(vals.contains(&"val-b"));

    // Dominate with updated vector clock
    let mut vc3 = vc1.merged(&vc2);
    vc3.tick("node-a");
    mv.set("resolved-val", vc3);
    assert_eq!(mv.read(), vec!["resolved-val"]);
}

#[test]
fn test_replicated_fs_tree_mutations_and_cycle_safety() {
    let mut tree = ReplicatedFsTree::new("us-east");

    // Create directories and files
    tree.create_dir("/datasets/vision");
    let file_node = tree.create_file(
        "/datasets/vision/labels.json",
        1024,
        Some("b3-hash-12345678".to_string()),
        16,
    );

    assert_eq!(file_node.kind, FsNodeKind::File);
    assert_eq!(file_node.chunk_count, 16);
    assert!(tree.get("/datasets/vision/labels.json").is_some());
    assert!(tree.get("/datasets/vision").is_some());
    assert!(tree.get("/datasets").is_some());

    // Cycle detection: cannot move /datasets into /datasets/vision/sub
    assert!(tree
        .rename_or_move("/datasets", "/datasets/vision/sub")
        .is_err());

    // Move file successfully
    assert!(tree
        .rename_or_move("/datasets/vision/labels.json", "/datasets/labels_v2.json")
        .is_ok());
    assert!(tree.get("/datasets/vision/labels.json").is_none());
    assert!(tree.get("/datasets/labels_v2.json").is_some());

    // Delete subtree
    let deleted = tree.delete("/datasets");
    assert!(deleted.contains(&"/datasets".to_string()));
    assert!(deleted.contains(&"/datasets/labels_v2.json".to_string()));
    assert!(tree.get("/datasets/labels_v2.json").is_none());
}

#[test]
fn test_concurrent_multi_region_tree_merge_and_conflict_resolution() {
    let mut tree_us = ReplicatedFsTree::new("us-east");
    let mut tree_eu = ReplicatedFsTree::new("eu-west");

    // Region US creates file A
    tree_us.create_file(
        "/shared/dataset.parquet",
        5000,
        Some("hash-initial-v1".to_string()),
        10,
    );

    // Sync US -> EU
    tree_eu.merge(&tree_us);
    assert_eq!(tree_us.state_digest(), tree_eu.state_digest());

    // Concurrent independent edits in both regions:
    // US updates dataset to v2 (lower HLC)
    tree_us.create_file(
        "/shared/dataset.parquet",
        6000,
        Some("hash-us-edit".to_string()),
        12,
    );

    // EU updates dataset to v3 (higher HLC)
    tree_eu.create_file(
        "/shared/dataset.parquet",
        7000,
        Some("hash-eu-edit".to_string()),
        14,
    );

    // EU also creates a unique EU-only file
    tree_eu.create_file(
        "/eu-only/regional.log",
        256,
        Some("hash-eu-log".to_string()),
        1,
    );

    // Perform bidirectional merge
    let report_us = tree_us.merge(&tree_eu);
    let report_eu = tree_eu.merge(&tree_us);

    assert!(report_us.conflicts_resolved >= 1 || report_eu.conflicts_resolved >= 1);
    assert_eq!(tree_us.state_digest(), tree_eu.state_digest());

    // Both replicas converge on EU's edit because its HLC was strictly greater
    let final_node_us = tree_us.get("/shared/dataset.parquet").unwrap();
    let final_node_eu = tree_eu.get("/shared/dataset.parquet").unwrap();
    assert_eq!(final_node_us, final_node_eu);
    assert_eq!(final_node_us.blake3_hash, final_node_eu.blake3_hash);

    // Both replicas contain the EU-only file
    assert!(tree_us.get("/eu-only/regional.log").is_some());
    assert!(tree_eu.get("/eu-only/regional.log").is_some());
}

#[test]
fn test_anti_entropy_delta_gossip_exchange() {
    let mut tree_a = ReplicatedFsTree::new("us-east");
    let mut tree_b = ReplicatedFsTree::new("ap-se");

    tree_a.create_file("/models/gemini.bin", 1_000_000, Some("h1".to_string()), 100);
    tree_b.create_file("/models/gemma.bin", 500_000, Some("h2".to_string()), 50);

    let report = AntiEntropyEngine::exchange(&mut tree_a, &mut tree_b);
    assert!(report.state_divergent_before);
    assert!(report.state_converged_after);
    assert_eq!(tree_a.state_digest(), tree_b.state_digest());
    assert_eq!(report.final_state_digest, tree_a.state_digest());

    // Second exchange should exchange 0 deltas
    let report2 = AntiEntropyEngine::exchange(&mut tree_a, &mut tree_b);
    assert!(!report2.state_divergent_before);
    assert!(report2.state_converged_after);
}

#[test]
fn test_geo_mesh_network_partition_healing_and_benchmark() {
    let mut mesh = GeoMesh::new();
    mesh.add_region("us-east", "US East", "10.0.1.1:7443", 20);
    mesh.add_region("eu-west", "EU West", "10.0.2.1:7443", 90);
    mesh.add_region("ap-se", "AP Southeast", "10.0.3.1:7443", 160);

    // 1. Partition us-east from eu-west
    mesh.set_partition("us-east", "eu-west", true);
    assert!(mesh.is_link_partitioned("us-east", "eu-west"));

    // 2. Perform writes in partitioned regions
    mesh.create_file("us-east", "/data/us.dat", 1024, None, 1)
        .unwrap();
    mesh.create_file("eu-west", "/data/eu.dat", 2048, None, 2)
        .unwrap();

    // 3. Sync: us-east and eu-west cannot talk directly, but ap-se bridges them
    mesh.sync_all();

    // 4. Heal the partition
    mesh.set_partition("us-east", "eu-west", false);
    assert!(!mesh.is_link_partitioned("us-east", "eu-west"));

    // 5. Final sync cycle
    mesh.sync_all();
    assert!(mesh.verify_convergence());

    // 6. Test automated benchmark suite
    let bench = GeoMesh::run_benchmark(3, 10, true);
    assert_eq!(bench.num_regions, 3);
    assert_eq!(bench.total_mutations, 30);
    assert!(bench.partition_simulated);
    assert!(bench.fully_converged);
    assert!(!bench.final_digest.is_empty());
}
