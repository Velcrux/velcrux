//! Integration test suite for FastCDC tuning, chunk cache pruning, and multi-tenant quota accounting.
//!
//! Validates:
//! - FastCDC sub-chunk normalization, bounds enforcement, and stream reconstruction (`REQUIREMENTS.md` §12).
//! - Comparative deduplication benchmarks (Fixed vs CDC vs FastCDC) under insertion/deletion workloads.
//! - Content-addressed chunk store LRU/TTL cache pruning with reference pinning (`OPERATIONS.md` §6).
//! - Multi-tenant quota accounting with reservation guards and storage tracking (`OPERATIONS.md` §4, §7).

use std::collections::HashSet;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

use velcrux_core::chunking::{ChunkEngine, ChunkMode, ChunkParams, Chunker, FastCdcChunker};
use velcrux_core::session::ServerStats;
use velcrux_core::storage::chunk_store::{ChunkStore, LocalChunkStore, PrunePolicy};
use velcrux_core::util::Hash;
use velcrux_server::config::LimitsCfg;
use velcrux_server::limits::LimitsManager;

fn generate_deterministic_bytes(size: usize, seed: u64) -> Vec<u8> {
    let mut data = vec![0u8; size];
    let mut state = seed.wrapping_add(0x9E3779B97F4A7C15);
    for chunk in data.chunks_mut(8) {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let bytes = state.to_le_bytes();
        let len = chunk.len();
        chunk.copy_from_slice(&bytes[..len]);
    }
    data
}

#[test]
fn test_fastcdc_boundary_distribution_and_invariants() {
    let min = 128 * 1024;
    let target = 512 * 1024;
    let max = 2 * 1024 * 1024;
    let params = ChunkParams::fastcdc(min, target, max).expect("valid fastcdc params");

    let mut chunker = FastCdcChunker::new(params);
    assert_eq!(chunker.mask_s_bits(), 20); // 512 KiB = 2^19 => 19 + 1 = 20
    assert_eq!(chunker.mask_l_bits(), 18); // 19 - 1 = 18

    // Test with 10 MiB of pseudorandom data
    let total_size = 10 * 1024 * 1024;
    let data = generate_deterministic_bytes(total_size, 12345);

    let mut reconstructed = Vec::with_capacity(total_size);
    let mut boundaries = Vec::new();

    // Push in varying buffer sizes (simulating network streaming)
    let slice_sizes = [64 * 1024, 256 * 1024, 1024 * 1024, 300 * 1024];
    let mut offset = 0;
    let mut idx = 0;
    while offset < total_size {
        let chunk_sz = slice_sizes[idx % slice_sizes.len()].min(total_size - offset);
        let bounds = chunker.push(&data[offset..offset + chunk_sz]).unwrap();
        for b in bounds {
            let chunk_data = &data[b.offset as usize..(b.offset + b.length) as usize];
            reconstructed.extend_from_slice(chunk_data);
            boundaries.push(b);
        }
        offset += chunk_sz;
        idx += 1;
    }

    if let Some(final_b) = chunker.finish().unwrap() {
        let chunk_data = &data[final_b.offset as usize..(final_b.offset + final_b.length) as usize];
        reconstructed.extend_from_slice(chunk_data);
        boundaries.push(final_b);
    }

    // Invariant: Exact reproduction of input
    assert_eq!(reconstructed.len(), total_size);
    assert_eq!(reconstructed, data);

    // Invariant: min <= chunk.len <= max (except possibly final chunk)
    for (i, b) in boundaries.iter().enumerate() {
        assert!(
            b.length <= max,
            "chunk {i} length {} exceeded max {max}",
            b.length
        );
        if i + 1 < boundaries.len() {
            assert!(
                b.length >= min,
                "non-terminal chunk {i} length {} below min {min}",
                b.length
            );
        }
    }

    // Test via ChunkEngine and create_chunker
    let reader = Cursor::new(&data);
    let mut engine_chunks = 0;
    let (engine_hash, engine_bytes) = ChunkEngine::chunk_reader(
        reader,
        ChunkMode::FastCdc,
        params,
        64 * 1024,
        |_desc, _payload| {
            engine_chunks += 1;
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(engine_bytes, total_size as u64);
    assert_eq!(engine_hash, Hash::of(&data));
    assert_eq!(engine_chunks, boundaries.len());
}

#[test]
fn test_fastcdc_vs_fixed_vs_cdc_dedup_comparative() {
    // Requirements §12: comparative deduplication benchmarks for workloads with insertions/deletions
    let base_size = 4 * 1024 * 1024; // 4 MiB base
    let base_data = generate_deterministic_bytes(base_size, 9999);

    // Create modified version with an unaligned insertion in the middle (e.g. 73,451 bytes inserted at 1 MiB)
    // Non-aligned insertions shift all subsequent fixed chunk boundaries, defeating fixed dedup.
    let insert_size = 73_451;
    let insertion = generate_deterministic_bytes(insert_size, 8888);
    let mut modified_data = Vec::with_capacity(base_size + insert_size);
    modified_data.extend_from_slice(&base_data[..1024 * 1024]);
    modified_data.extend_from_slice(&insertion);
    modified_data.extend_from_slice(&base_data[1024 * 1024..]);

    fn collect_chunks(mode: ChunkMode, params: ChunkParams, data: &[u8]) -> HashSet<Hash> {
        let mut hashes = HashSet::new();
        let reader = Cursor::new(data);
        let _ = ChunkEngine::chunk_reader(reader, mode, params, 64 * 1024, |desc, _payload| {
            if let Some(h) = desc.hash {
                hashes.insert(h);
            }
            Ok(())
        });
        hashes
    }

    fn calculate_reuse(
        mode: ChunkMode,
        params: ChunkParams,
        base: &[u8],
        modified: &[u8],
    ) -> (f64, usize, usize) {
        let base_hashes = collect_chunks(mode, params, base);
        let mut total_modified_bytes = 0u64;
        let mut reused_bytes = 0u64;
        let mut total_chunks = 0;
        let mut reused_chunks = 0;

        let reader = Cursor::new(modified);
        let _ = ChunkEngine::chunk_reader(reader, mode, params, 64 * 1024, |desc, _payload| {
            total_chunks += 1;
            total_modified_bytes += desc.length;
            if let Some(h) = desc.hash {
                if base_hashes.contains(&h) {
                    reused_chunks += 1;
                    reused_bytes += desc.length;
                }
            }
            Ok(())
        });

        let ratio = reused_bytes as f64 / total_modified_bytes as f64;
        (ratio, reused_chunks, total_chunks)
    }

    // 1. Fixed chunking (64 KiB)
    let fixed_params = ChunkParams::fixed(64 * 1024);
    let (fixed_ratio, fixed_reused, fixed_total) =
        calculate_reuse(ChunkMode::Fixed, fixed_params, &base_data, &modified_data);

    // 2. Standard CDC (min 16k, target 64k, max 256k)
    let cdc_params = ChunkParams::cdc(16 * 1024, 64 * 1024, 256 * 1024).unwrap();
    let (cdc_ratio, cdc_reused, cdc_total) =
        calculate_reuse(ChunkMode::Cdc, cdc_params, &base_data, &modified_data);

    // 3. FastCDC (min 16k, target 64k, max 256k)
    let fastcdc_params = ChunkParams::fastcdc(16 * 1024, 64 * 1024, 256 * 1024).unwrap();
    let (fastcdc_ratio, fastcdc_reused, fastcdc_total) = calculate_reuse(
        ChunkMode::FastCdc,
        fastcdc_params,
        &base_data,
        &modified_data,
    );

    println!(
        "\n--- Deduplication Benchmark on Mid-Stream Insertion ---\n\
         Fixed:   {:.2}% reused ({}/{} chunks)\n\
         CDC:     {:.2}% reused ({}/{} chunks)\n\
         FastCDC: {:.2}% reused ({}/{} chunks)",
        fixed_ratio * 100.0,
        fixed_reused,
        fixed_total,
        cdc_ratio * 100.0,
        cdc_reused,
        cdc_total,
        fastcdc_ratio * 100.0,
        fastcdc_reused,
        fastcdc_total
    );

    // Due to the boundary shift from insertion, fixed chunking only preserves chunks before the insertion point (~25%)
    // Whereas content-defined chunking (CDC and FastCDC) resynchronizes after the insertion, preserving ~70%+!
    assert!(
        fastcdc_ratio > fixed_ratio,
        "FastCDC reuse ratio ({:.2}%) must outperform Fixed chunking ({:.2}%)",
        fastcdc_ratio * 100.0,
        fixed_ratio * 100.0
    );
    assert!(
        fastcdc_ratio >= 0.65,
        "FastCDC should achieve >= 65% reuse on insertion workload (got {:.2}%)",
        fastcdc_ratio * 100.0
    );
}

#[tokio::test]
async fn test_chunk_store_cache_pruning_lru_and_ttl() {
    let dir = tempdir().unwrap();
    let store = LocalChunkStore::new(dir.path()).await.unwrap();

    // Put 5 chunks into the store
    let payloads: [&[u8]; 5] = [
        b"chunk 1 - oldest data alpha",
        b"chunk 2 - second oldest data beta",
        b"chunk 3 - pinned data gamma",
        b"chunk 4 - recent data delta",
        b"chunk 5 - newest data epsilon",
    ];

    let mut hashes = Vec::new();
    for p in &payloads {
        let h = Hash::of(p);
        store.put_sync(&h, p).unwrap();
        hashes.push(h);
        // Sleep 15ms so timestamps are strictly ordered
        std::thread::sleep(Duration::from_millis(15));
    }

    assert_eq!(store.total_chunks().await.unwrap(), 5);
    let _total_bytes_init = store.total_bytes().await.unwrap();

    // Pin chunk 3
    let pinned_hash = hashes[2];
    let _pin = store.acquire_pin(&pinned_hash);
    assert!(store.is_pinned(&pinned_hash));

    // Prune policy 1: Enforce max_chunks = 3
    // Oldest unpinned chunks (chunk 1 and chunk 2) should be evicted.
    // Chunk 3 is pinned and must not be evicted!
    let policy = PrunePolicy {
        max_chunks: Some(3),
        max_bytes: None,
        ttl: None,
        keep_hashes: None,
    };

    let report = store.prune_cache(&policy).await.unwrap();
    assert_eq!(report.chunks_scanned, 5);
    assert_eq!(report.chunks_pruned, 2);
    assert_eq!(report.pinned_skipped, 1);
    assert_eq!(report.chunks_remaining, 3);
    assert!(report.bytes_reclaimed > 0);

    // Verify chunk 1 and 2 were pruned
    assert!(!store.contains_sync(&hashes[0]));
    assert!(!store.contains_sync(&hashes[1]));
    // Verify chunk 3 (pinned), chunk 4, and chunk 5 exist
    assert!(store.contains_sync(&hashes[2]));
    assert!(store.contains_sync(&hashes[3]));
    assert!(store.contains_sync(&hashes[4]));

    // Prune policy 2: Capacity limit (max_bytes)
    let _remaining_bytes = store.total_bytes().await.unwrap();
    let chunk5_len = payloads[4].len() as u64;
    let chunk3_len = payloads[2].len() as u64;
    // Set max_bytes to keep only pinned chunk 3 + chunk 5
    let cap_policy = PrunePolicy {
        max_bytes: Some(chunk3_len + chunk5_len),
        max_chunks: None,
        ttl: None,
        keep_hashes: None,
    };
    let cap_report = store.prune_cache(&cap_policy).await.unwrap();
    assert_eq!(cap_report.chunks_pruned, 1); // chunk 4 evicted
    assert!(!store.contains_sync(&hashes[3]));
    assert!(store.contains_sync(&hashes[2])); // chunk 3 pinned
    assert!(store.contains_sync(&hashes[4])); // chunk 5 retained

    // Drop pin and test TTL-based eviction
    drop(_pin);
    assert!(!store.is_pinned(&pinned_hash));

    // Wait 25ms and prune with TTL = 10ms
    std::thread::sleep(Duration::from_millis(25));
    let ttl_policy = PrunePolicy {
        max_bytes: None,
        max_chunks: None,
        ttl: Some(Duration::from_millis(10)),
        keep_hashes: None,
    };
    let ttl_report = store.prune_cache(&ttl_policy).await.unwrap();
    assert_eq!(ttl_report.chunks_pruned, 2);
    assert_eq!(store.total_chunks().await.unwrap(), 0);
}

#[tokio::test]
async fn test_multi_tenant_concurrent_quota_reservations() {
    let stats = Arc::new(ServerStats::default());
    let limits_cfg = vec![LimitsCfg {
        identity: "tenant-racing".into(),
        max_bandwidth: Some("100MB/s".into()),
        quota_bytes: Some("100KiB".into()),
        soft_quota_bytes: Some("80KiB".into()),
    }];

    let manager = LimitsManager::new(
        Some("10Gbps"),
        Some(100),
        None,
        None,
        &limits_cfg,
        Arc::clone(&stats),
    )
    .unwrap();

    // 1. Initial state
    assert_eq!(manager.get_usage("tenant-racing"), 0);
    assert_eq!(manager.get_reserved("tenant-racing"), 0);
    assert_eq!(manager.get_soft_quota("tenant-racing"), Some(80 * 1024));

    // 2. Transfer A reserves 60 KiB
    let res_a = manager
        .reserve_quota(Some("tenant-racing"), 60 * 1024)
        .expect("Transfer A reservation should succeed");
    assert_eq!(manager.get_reserved("tenant-racing"), 60 * 1024);

    // 3. Concurrent Transfer B attempts to reserve 60 KiB:
    // 60 KiB reserved + 60 KiB requested = 120 KiB > 100 KiB quota!
    // Without reservations, both would have checked usage (0) and passed, causing an over-quota race.
    let res_b_err = manager.reserve_quota(Some("tenant-racing"), 60 * 1024);
    assert!(
        res_b_err.is_err(),
        "Concurrent Transfer B must be rejected due to active Transfer A reservation"
    );
    assert_eq!(
        stats
            .resource_limit_hits_quota
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // 4. Transfer C reserves 30 KiB (60 + 30 = 90 KiB <= 100 KiB) -> succeeds
    let res_c = manager
        .reserve_quota(Some("tenant-racing"), 30 * 1024)
        .expect("Transfer C reservation should succeed");
    assert_eq!(manager.get_reserved("tenant-racing"), 90 * 1024);

    // 5. Transfer A completes and commits its 60 KiB
    res_a.commit();
    assert_eq!(manager.get_usage("tenant-racing"), 60 * 1024);
    assert_eq!(manager.get_reserved("tenant-racing"), 30 * 1024);

    // 6. Transfer C aborts / drops without committing:
    // RAII guard should automatically release reserved 30 KiB back to the tenant pool!
    drop(res_c);
    assert_eq!(manager.get_reserved("tenant-racing"), 0);
    assert_eq!(manager.get_usage("tenant-racing"), 60 * 1024);

    // 7. Now another transfer of 35 KiB (60 + 35 = 95 <= 100) can succeed
    let res_d = manager
        .reserve_quota(Some("tenant-racing"), 35 * 1024)
        .expect("Transfer D should succeed after Transfer C dropped");
    res_d.commit();
    assert_eq!(manager.get_usage("tenant-racing"), 95 * 1024);
}

#[tokio::test]
async fn test_multi_tenant_soft_quota_and_storage_accounting() {
    let stats = Arc::new(ServerStats::default());
    let limits_cfg = vec![LimitsCfg {
        identity: "tenant-store".into(),
        max_bandwidth: None,
        quota_bytes: Some("1MiB".into()),
        soft_quota_bytes: Some("700KiB".into()),
    }];

    let manager =
        LimitsManager::new(None, None, None, None, &limits_cfg, Arc::clone(&stats)).unwrap();

    // Test storage accounting deltas
    assert_eq!(manager.get_storage_usage("tenant-store"), 0);
    manager.record_storage_delta("tenant-store", 250 * 1024);
    assert_eq!(manager.get_storage_usage("tenant-store"), 250 * 1024);

    manager.record_storage_delta("tenant-store", 100 * 1024);
    assert_eq!(manager.get_storage_usage("tenant-store"), 350 * 1024);

    manager.record_storage_delta("tenant-store", -50 * 1024);
    assert_eq!(manager.get_storage_usage("tenant-store"), 300 * 1024);

    // Test directory tree reconciliation
    let temp_tenant_dir = tempdir().unwrap();
    let file_a = temp_tenant_dir.path().join("file_a.bin");
    let file_b = temp_tenant_dir.path().join("sub/file_b.bin");
    std::fs::create_dir_all(file_b.parent().unwrap()).unwrap();

    std::fs::write(&file_a, vec![1u8; 150 * 1024]).unwrap();
    std::fs::write(&file_b, vec![2u8; 250 * 1024]).unwrap();

    let reconciled = manager
        .reconcile_tenant_storage("tenant-store", temp_tenant_dir.path())
        .unwrap();
    assert_eq!(reconciled, 400 * 1024);
    assert_eq!(manager.get_storage_usage("tenant-store"), 400 * 1024);
}
