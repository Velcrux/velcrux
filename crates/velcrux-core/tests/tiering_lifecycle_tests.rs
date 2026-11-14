//! Integration tests for Option DK: Autonomous Multi-Cloud Object Storage Tiering & Compaction Engine (`ADR-079`).

#![forbid(unsafe_code)]

use velcrux_core::cloud_tier::{
    CloudProviderKind, CloudTierClass, CloudTieringEngine, HydrationPriority, ReadChunkResult,
    TieringAction,
};

#[test]
fn test_multi_cloud_container_compaction_and_range_reads() {
    let mut engine = CloudTieringEngine::new();

    // 1. Ingest 50 distinct 4 KiB chunks
    let mut chunk_hashes = Vec::new();
    for i in 0..50 {
        let chunk_data = format!("velcrux-chunk-payload-data-block-number-{:04}", i).into_bytes();
        let chunk_hash = *blake3::hash(&chunk_data).as_bytes();
        chunk_hashes.push((chunk_hash, chunk_data));
        engine
            .ingest_chunk(chunk_hash, &chunk_hashes.last().unwrap().1, 1000)
            .unwrap();
    }

    // 2. Flush staging container into AWS S3 Hot tier
    let container_id = engine.flush_staging_container(CloudTierClass::Hot).unwrap();
    assert_eq!(engine.containers.len(), 1);

    let container = engine.containers.get(&container_id).unwrap();
    assert_eq!(container.active_chunk_count(), 50);
    assert_eq!(container.header.tier, CloudTierClass::Hot);
    assert_eq!(container.header.provider, CloudProviderKind::AwsS3);

    // 3. Verify transparent random-access range-reads for all 50 chunks
    for (hash, expected_data) in &chunk_hashes {
        let result = engine.read_chunk_transparent(hash, 1010).unwrap();
        match result {
            ReadChunkResult::Direct(data) => {
                assert_eq!(&data, expected_data);
            }
            _ => panic!("Expected Direct read result from Hot tier"),
        }
    }
}

#[test]
fn test_autonomous_lifecycle_tiering_transitions() {
    let mut engine = CloudTieringEngine::new();

    let data = b"long-term-financial-compliance-archive-payload";
    let hash = *blake3::hash(data).as_bytes();
    engine.ingest_chunk(hash, data, 1000).unwrap();

    let cid = engine.flush_staging_container(CloudTierClass::Hot).unwrap();
    assert_eq!(
        engine.containers.get(&cid).unwrap().header.tier,
        CloudTierClass::Hot
    );

    // Advance 45 days -> Transition to Cool
    let t_45_days = 1000 + 45 * 86400;
    let reports_45 = engine.evaluate_and_rebalance(t_45_days).unwrap();
    assert!(!reports_45.is_empty());
    assert_eq!(
        reports_45[0].action,
        TieringAction::Transition(CloudTierClass::Cool)
    );
    assert_eq!(
        engine.containers.get(&cid).unwrap().header.tier,
        CloudTierClass::Cool
    );

    // Advance to 120 days -> Transition to Cold
    let t_120_days = 1000 + 120 * 86400;
    let reports_120 = engine.evaluate_and_rebalance(t_120_days).unwrap();
    assert_eq!(
        reports_120[0].action,
        TieringAction::Transition(CloudTierClass::Cold)
    );
    assert_eq!(
        engine.containers.get(&cid).unwrap().header.tier,
        CloudTierClass::Cold
    );

    // Advance to 400 days -> Transition to DeepArchive
    let t_400_days = 1000 + 400 * 86400;
    let reports_400 = engine.evaluate_and_rebalance(t_400_days).unwrap();
    assert_eq!(
        reports_400[0].action,
        TieringAction::Transition(CloudTierClass::DeepArchive)
    );
    assert_eq!(
        engine.containers.get(&cid).unwrap().header.tier,
        CloudTierClass::DeepArchive
    );

    // Advance to 800 days -> Expire and purge
    let t_800_days = 1000 + 800 * 86400;
    let reports_800 = engine.evaluate_and_rebalance(t_800_days).unwrap();
    assert_eq!(reports_800[0].action, TieringAction::Expire);
    assert!(!engine.containers.contains_key(&cid));
    assert!(!engine.chunk_locations.contains_key(&hash));
}

#[test]
fn test_tombstone_garbage_collection_compaction() {
    let mut engine = CloudTieringEngine::new();

    let mut hashes = Vec::new();
    for i in 0..10 {
        let chunk = vec![i as u8; 1024];
        let h = *blake3::hash(&chunk).as_bytes();
        hashes.push((h, chunk));
        engine
            .ingest_chunk(h, &hashes.last().unwrap().1, 1000)
            .unwrap();
    }

    let cid = engine.flush_staging_container(CloudTierClass::Hot).unwrap();

    // Tombstone 4 out of 10 chunks (40% fragmentation > 30% threshold)
    {
        let container = engine.containers.get_mut(&cid).unwrap();
        for item in hashes.iter().take(4) {
            container.tombstone_chunk(&item.0);
        }
        assert_eq!(container.active_chunk_count(), 6);
        assert_eq!(container.tombstoned_chunk_count(), 4);
        assert!(container.fragmentation_ratio() >= 0.40);
    }

    // Evaluate rebalance at day 5 (before tier transitions)
    let reports = engine.evaluate_and_rebalance(1000 + 5 * 86400).unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].action, TieringAction::CompactAndRepack);

    // Original container was removed, repacked container is active
    assert!(!engine.containers.contains_key(&cid));
    assert_eq!(engine.containers.len(), 1);

    let repacked_container = engine.containers.values().next().unwrap();
    assert_eq!(repacked_container.active_chunk_count(), 6);
    assert_eq!(repacked_container.tombstoned_chunk_count(), 0);
    assert_eq!(repacked_container.fragmentation_ratio(), 0.0);

    // Remaining 6 active chunks can still be read cleanly
    for item in hashes.iter().take(10).skip(4) {
        let res = engine
            .read_chunk_transparent(&item.0, 1000 + 6 * 86400)
            .unwrap();
        assert_eq!(res, ReadChunkResult::Direct(item.1.clone()));
    }

    // Deleted chunks cannot be read
    for item in hashes.iter().take(4) {
        assert!(engine
            .read_chunk_transparent(&item.0, 1000 + 6 * 86400)
            .is_err());
    }
}

#[test]
fn test_cold_archive_async_hydration_workflow() {
    let mut engine = CloudTieringEngine::new();

    let data = b"cold-storage-payload-for-disaster-recovery-scenario";
    let hash = *blake3::hash(data).as_bytes();
    engine.ingest_chunk(hash, data, 2000).unwrap();

    let cid = engine
        .flush_staging_container(CloudTierClass::Cold)
        .unwrap();

    // Direct read returns HydrationRequired
    let res = engine.read_chunk_transparent(&hash, 2001).unwrap();
    match res {
        ReadChunkResult::HydrationRequired {
            container_id,
            source_tier,
            ..
        } => {
            assert_eq!(container_id, cid);
            assert_eq!(source_tier, CloudTierClass::Cold);
        }
        _ => panic!("Expected HydrationRequired"),
    }

    // Submit Expedited hydration request (60s simulated duration)
    let req_id = engine
        .request_chunk_hydration(hash, HydrationPriority::Expedited, 2002)
        .unwrap();

    // Poll at 2002 + 10s -> still hydrating
    engine.poll_hydrations(2012);
    let pending_status = engine.hydration_pipeline.get_status(&req_id).unwrap();
    assert!(!pending_status.status.is_ready());

    // Poll at 2002 + 65s -> hydrated!
    engine.poll_hydrations(2067);
    let ready_status = engine.hydration_pipeline.get_status(&req_id).unwrap();
    assert!(ready_status.status.is_ready());

    // Subsequent read returns Direct from hydrated cache
    let direct_res = engine.read_chunk_transparent(&hash, 2070).unwrap();
    assert_eq!(direct_res, ReadChunkResult::Direct(data.to_vec()));
}

#[test]
fn test_cloud_cost_and_metrics_accounting() {
    let mut engine = CloudTieringEngine::new();

    let data = vec![0x33u8; 65536];
    let hash = *blake3::hash(&data).as_bytes();
    engine.ingest_chunk(hash, &data, 3000).unwrap();
    let _cid = engine.flush_staging_container(CloudTierClass::Hot).unwrap();

    let report = engine.status_report();
    assert_eq!(report.active_endpoints, 4);
    assert_eq!(report.total_compacted_containers, 1);
    assert!(report.total_uncompressed_bytes >= 65536);
    assert!(report.average_compression_ratio > 0.0);
    assert!(report.containers_by_tier.contains_key("hot"));
}
