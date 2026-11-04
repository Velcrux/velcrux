//! Integration Tests for Distributed Object Storage Sharding & Multi-Bucket Tiering (`ADR-065`).
//!
//! Verifies:
//! 1. Consistent hash distribution across $N$ bucket shards with high Shannon entropy.
//! 2. Scalable two-level hex prefix partitioning (`HexTwoLevel` -> `chunks/aa/bb/<hash>`).
//! 3. Real live TCP wire multi-bucket sharded storage and retrieval (`ShardedChunkStore`).
//! 4. Glacier cold archive lifecycle, REST restore job initiation, and state machine transitions.
//! 5. Sharded lifecycle evaluation engine (`ShardedLifecycleEngine`) over multi-bucket topologies.
//! 6. FastCDC chunk stream distribution and whole-file BLAKE3 reconstruction.

use std::collections::HashSet;
use std::time::Duration;

use velcrux_core::chunking::{ChunkEngine, ChunkMode, ChunkParams};
use velcrux_core::storage::chunk_store::ChunkStore;
use velcrux_core::storage::sharding::{
    BucketShard, GlacierTier, ObjectRestoreState, PrefixPartitionStrategy, S3StorageClass,
    ShardRouter, ShardedChunkStore, ShardedLifecycleEngine, ShardedLifecycleRule,
};
use velcrux_core::storage::{S3ObjectMeta, WireCloudServer};
use velcrux_core::util::Hash;

fn generate_deterministic_content(size: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    let mut state = seed;
    for _ in 0..(size / 8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    let rem = size % 8;
    if rem > 0 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes()[..rem]);
    }
    out
}

#[tokio::test]
async fn test_sharded_router_consistent_hash_distribution() {
    let mut router = ShardRouter::new(128, PrefixPartitionStrategy::HexTwoLevel);

    // Register 4 bucket shards
    router.add_shard(
        BucketShard::new(
            "shard-alpha",
            "bucket-alpha",
            "http://s3.us-east-1.amazonaws.com",
        )
        .with_region("us-east-1"),
    );
    router.add_shard(
        BucketShard::new(
            "shard-beta",
            "bucket-beta",
            "http://s3.us-east-2.amazonaws.com",
        )
        .with_region("us-east-2"),
    );
    router.add_shard(
        BucketShard::new(
            "shard-gamma",
            "bucket-gamma",
            "http://s3.eu-west-1.amazonaws.com",
        )
        .with_region("eu-west-1"),
    );
    router.add_shard(
        BucketShard::new(
            "shard-delta",
            "bucket-delta",
            "http://s3.ap-southeast-1.amazonaws.com",
        )
        .with_region("ap-southeast-1"),
    );

    // Route 2,000 distinct pseudo-random chunk hashes
    let mut sample_hashes = Vec::with_capacity(2000);
    let mut routed_counts = std::collections::HashMap::new();
    for i in 0..2000u64 {
        let payload = generate_deterministic_content(1024, i * 7919);
        let h = Hash::of(&payload);
        sample_hashes.push(h);
        let shard = router.route_hash(&h).expect("route hash to shard");
        *routed_counts.entry(shard.id.clone()).or_insert(0usize) += 1;
    }

    assert_eq!(routed_counts.len(), 4, "all 4 shards should receive chunks");

    let stats = router.distribution_stats(&sample_hashes);
    // In an ideal 4-shard distribution, each shard receives ~500 items (25%). Max entropy is log2(4) = 2.0 bits.
    assert!(
        stats.entropy_bits >= 1.90,
        "entropy {:.3} should exceed 1.90 bits for uniform distribution across 4 shards",
        stats.entropy_bits
    );

    for (shard_id, count) in &routed_counts {
        assert!(
            *count >= 350 && *count <= 650,
            "shard {} count {} should be well balanced around 500",
            shard_id,
            count
        );
    }
}

#[tokio::test]
async fn test_sharded_two_level_hex_prefix_scale() {
    let router = ShardRouter::new(64, PrefixPartitionStrategy::HexTwoLevel);
    let shard =
        BucketShard::new("primary", "my-bucket", "http://127.0.0.1:9000").with_region("us-east-1");

    let mut distinct_prefixes = HashSet::new();
    for i in 0..300u64 {
        let payload = generate_deterministic_content(512, i * 31 + 17);
        let h = Hash::of(&payload);
        let key = router.format_key(&shard, &h);

        // Key should format as chunks/aa/bb/<hex-hash>
        let parts: Vec<&str> = key.split('/').collect();
        assert_eq!(parts.len(), 4, "format must be chunks/aa/bb/<hash>");
        assert_eq!(parts[0], "chunks");
        assert_eq!(parts[1].len(), 2);
        assert_eq!(parts[2].len(), 2);
        assert_eq!(parts[3], h.to_hex());

        distinct_prefixes.insert(format!("{}/{}", parts[1], parts[2]));
    }

    // High diversity: 300 random hashes should touch at least 200 distinct 2-level prefixes
    assert!(
        distinct_prefixes.len() > 200,
        "expected >200 distinct 2-level hex prefixes, got {}",
        distinct_prefixes.len()
    );
}

#[tokio::test]
async fn test_sharded_chunk_store_live_wire_multi_bucket() {
    // 1. Spin up ephemeral wire server
    let server = WireCloudServer::start().await.expect("start wire server");
    let ep = server.endpoint();

    // 2. Set up 3 distinct bucket shards on this live wire server
    let mut router = ShardRouter::new(64, PrefixPartitionStrategy::HexTwoLevel);
    let b1 = format!(
        "velcrux-shard-0-{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );
    let b2 = format!(
        "velcrux-shard-1-{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );
    let b3 = format!(
        "velcrux-shard-2-{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );

    router.add_shard(BucketShard::new("s0", &b1, &ep).with_region("us-east-1"));
    router.add_shard(BucketShard::new("s1", &b2, &ep).with_region("us-east-1"));
    router.add_shard(BucketShard::new("s2", &b3, &ep).with_region("us-east-1"));

    let store = ShardedChunkStore::new(router).with_live_mode(true);

    // 3. Ensure all shard buckets exist on target endpoints
    store
        .ensure_all_buckets_exist()
        .await
        .expect("ensure buckets exist");

    // 4. Generate FastCDC chunks from 256 KiB content
    let original_data = generate_deterministic_content(256 * 1024, 0xABCDEF1234567890);
    let params = ChunkParams {
        min: 2048,
        target: 8192,
        max: 32768,
    };
    let mut chunk_hashes = Vec::new();
    let mut chunk_payloads = Vec::new();

    let cursor = std::io::Cursor::new(&original_data);
    ChunkEngine::chunk_reader(
        cursor,
        ChunkMode::Cdc,
        params,
        64 * 1024,
        |desc, payload| {
            let h = desc.hash.unwrap_or_else(|| Hash::of(payload));
            chunk_hashes.push(h);
            chunk_payloads.push(payload.to_vec());
            Ok(())
        },
    )
    .expect("chunk content");

    assert!(!chunk_hashes.is_empty(), "must produce chunks");

    for (idx, h) in chunk_hashes.iter().enumerate() {
        let payload = &chunk_payloads[idx];
        // Put chunk into distributed store
        store
            .put(h, payload)
            .await
            .expect("put chunk to sharded store");
    }

    // 5. Batch presence query
    let presence = store.has_batch(&chunk_hashes).await.expect("has_batch");
    assert_eq!(presence.len(), chunk_hashes.len());
    for (idx, p) in presence.iter().enumerate() {
        assert!(
            p,
            "chunk {} at index {} must be present in sharded store",
            chunk_hashes[idx], idx
        );
    }

    // 6. Fetch all chunks back and reassemble original data
    let mut reassembled = Vec::new();
    for (idx, h) in chunk_hashes.iter().enumerate() {
        let retrieved = store.get(h).await.expect("get chunk");
        assert_eq!(
            retrieved.to_vec(),
            chunk_payloads[idx],
            "chunk payload match for {}",
            h
        );
        reassembled.extend_from_slice(&retrieved);
    }

    // 7. Whole-file verification
    assert_eq!(
        reassembled, original_data,
        "reassembled content must match bit-for-bit"
    );
    assert_eq!(
        Hash::of(&reassembled),
        Hash::of(&original_data),
        "BLAKE3 hash identity verification"
    );
}

#[tokio::test]
async fn test_glacier_tiering_restore_and_access_state_machine() {
    let server = WireCloudServer::start().await.expect("start wire server");
    let ep = server.endpoint();

    let bucket_name = format!(
        "velcrux-cold-{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );

    let mut router = ShardRouter::new(64, PrefixPartitionStrategy::Flat);
    let cold_shard = BucketShard::new("glacier-shard", &bucket_name, &ep)
        .with_region("us-east-1")
        .with_storage_class(S3StorageClass::GlacierFlexibleRetrieval);

    router.add_shard(cold_shard);

    let store = ShardedChunkStore::new(router).with_live_mode(true);
    store
        .ensure_all_buckets_exist()
        .await
        .expect("create bucket");

    let chunk_data = b"confidential cold compliance archive block for velcrux";
    let chunk_hash = Hash::of(chunk_data);

    // 1. Put chunk directly into Glacier cold storage
    store
        .put(&chunk_hash, chunk_data)
        .await
        .expect("put cold chunk");

    // 2. Query restore state: should be ArchivedNotRestored
    let initial_status = store
        .restore_status(&chunk_hash)
        .await
        .expect("restore_status");
    assert_eq!(
        initial_status,
        ObjectRestoreState::ArchivedNotRestored,
        "object should be cold and unrestored"
    );

    // 3. GET should fail with InvalidObjectState before restoration
    let get_res = store.get(&chunk_hash).await;
    assert!(
        get_res.is_err(),
        "GET on unrestored Glacier object must be rejected with InvalidObjectState"
    );

    // 4. Trigger restoration via Glacier restore coordinator
    store
        .restore_chunk(&chunk_hash, 7, GlacierTier::Standard)
        .await
        .expect("restore_chunk");

    // 5. Query restore state: should now be Restored
    let post_restore_status = store
        .wait_for_restore(
            &chunk_hash,
            Duration::from_millis(50),
            Duration::from_secs(5),
        )
        .await
        .expect("wait_for_restore");

    match post_restore_status {
        ObjectRestoreState::Restored { .. } => {}
        other => panic!("expected Restored state, got {:?}", other),
    }

    // 6. GET should now succeed and return byte-for-byte exact payload
    let retrieved = store.get(&chunk_hash).await.expect("get restored chunk");
    assert_eq!(
        retrieved.to_vec(),
        chunk_data.to_vec(),
        "restored data must match exactly"
    );
}

#[tokio::test]
async fn test_sharded_lifecycle_evaluation_engine() {
    let rules = vec![
        // Rule 1: Age > 30 days -> StandardIa
        ShardedLifecycleRule::new("rule-ia")
            .with_days_to_ia(30)
            .with_min_size(1024),
        // Rule 2: Age > 90 days -> Glacier
        ShardedLifecycleRule::new("rule-glacier")
            .with_days_to_glacier(90)
            .with_min_size(1024),
        // Rule 3: Age > 365 days -> Deep Archive
        ShardedLifecycleRule::new("rule-deep")
            .with_days_to_deep_archive(365)
            .with_min_size(1024),
    ];

    let engine = ShardedLifecycleEngine::new(rules);

    let now_sec = 1700000000u64;
    let day_sec = 86400u64;

    let mock_objects = vec![
        // Young object (5 days old) -> No transition (remains Standard)
        S3ObjectMeta {
            key: "chunks/00/01/recent".to_string(),
            size: 4096,
            etag: "\"etag-1\"".to_string(),
            last_modified_sec: (now_sec - 5 * day_sec) as i64,
            blake3_hash: None,
            mode: Some(0o100644),
            storage_class: Some("STANDARD".to_string()),
            restore_status: None,
        },
        // Intermediate object (45 days old) -> Transition to IA
        S3ObjectMeta {
            key: "chunks/0a/0b/warm".to_string(),
            size: 8192,
            etag: "\"etag-2\"".to_string(),
            last_modified_sec: (now_sec - 45 * day_sec) as i64,
            blake3_hash: None,
            mode: Some(0o100644),
            storage_class: Some("STANDARD".to_string()),
            restore_status: None,
        },
        // Cold object (120 days old) -> Transition to Glacier
        S3ObjectMeta {
            key: "chunks/ab/cd/cold".to_string(),
            size: 16384,
            etag: "\"etag-3\"".to_string(),
            last_modified_sec: (now_sec - 120 * day_sec) as i64,
            blake3_hash: None,
            mode: Some(0o100644),
            storage_class: Some("STANDARD_IA".to_string()),
            restore_status: None,
        },
        // Ancient object (400 days old) -> Transition to Deep Archive
        S3ObjectMeta {
            key: "chunks/ff/ee/ancient".to_string(),
            size: 65536,
            etag: "\"etag-4\"".to_string(),
            last_modified_sec: (now_sec - 400 * day_sec) as i64,
            blake3_hash: None,
            mode: Some(0o100644),
            storage_class: Some("GLACIER".to_string()),
            restore_status: None,
        },
    ];

    let report = engine.evaluate_shard(&mock_objects, now_sec);

    assert_eq!(report.shards_scanned, 1);
    assert_eq!(report.objects_evaluated, 4);
    assert_eq!(report.transitioned_ia, 1);
    assert_eq!(report.transitioned_glacier, 1);
    assert_eq!(report.transitioned_deep_archive, 1);
    assert_eq!(report.bytes_transitioned, 8192 + 16384 + 65536);
    assert_eq!(report.bytes_skipped, 4096);
}
