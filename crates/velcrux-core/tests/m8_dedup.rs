//! Milestone 8 Exit Integration Tests: Chunk Store & Deduplication (`ARCHITECTURE.md` §2, §7, §12).
//!
//! Exit test verification:
//! - "Second copy of a file transfers ≈ 0 bytes"
//! - Cross-file partial deduplication across unrelated destination paths
//! - Content-addressed verification and corruption rejection
//! - Idempotent concurrent chunk storage

use std::fs;
use tempfile::tempdir;

use velcrux_core::chunking::{ChunkMode, ChunkParams};
use velcrux_core::storage::{ChunkStore, LocalChunkStore};
use velcrux_core::sync::{execute_dedup_sync, SyncDecision};
use velcrux_core::util::Hash;

/// Generates pseudorandom non-repeating byte content of `size` bytes.
fn generate_test_content(size: usize, seed: u64) -> Vec<u8> {
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

/// M8 Exit Test:
/// "Second copy of a file transfers ≈ 0 bytes" (`ARCHITECTURE.md` §12).
#[tokio::test]
async fn test_exit_criteria_second_copy_transfers_zero_bytes() {
    let dir = tempdir().unwrap();
    let store_dir = dir.path().join("chunk_store");
    let chunk_store = LocalChunkStore::new(&store_dir).await.unwrap();

    let file_size = 16 * 1024 * 1024; // 16 MiB file
    let content = generate_test_content(file_size, 0x0123_4567_89AB_CDEF);
    let expected_hash = Hash::of(&content);

    let src1_path = dir.path().join("first_source.bin");
    let dst1_path = dir.path().join("first_destination.bin");
    fs::write(&src1_path, &content).unwrap();

    let params = ChunkParams::new(64 * 1024, 256 * 1024, 512 * 1024).unwrap();

    // 1. Initial transfer of first file: populates chunk store
    let report1 = execute_dedup_sync(
        &src1_path,
        &dst1_path,
        ChunkMode::Cdc,
        params,
        256 * 1024,
        Some(&chunk_store),
    )
    .unwrap();

    assert_eq!(report1.total_bytes, file_size as u64);
    assert_eq!(report1.wire_bytes_transferred, file_size as u64);
    assert_eq!(report1.whole_file_hash, expected_hash);
    assert!(dst1_path.exists());
    assert_eq!(fs::read(&dst1_path).unwrap(), content);

    let store_chunks_after_first = chunk_store.total_chunks().await.unwrap();
    assert!(store_chunks_after_first > 0);

    // 2. Transfer of a second copy of the file:
    // Different source filename, and completely different destination path (where destination DOES NOT EXIST).
    let src2_path = dir.path().join("second_copy_source.bin");
    let dst2_path = dir
        .path()
        .join("unrelated_folder/second_copy_destination.bin");
    fs::write(&src2_path, &content).unwrap();

    let report2 = execute_dedup_sync(
        &src2_path,
        &dst2_path,
        ChunkMode::Cdc,
        params,
        256 * 1024,
        Some(&chunk_store),
    )
    .unwrap();

    println!(
        "M8 Exit Test Results (Second Copy Transfer):\n\
         - File Size: {:.2} MiB\n\
         - Wire Bytes Transferred: {} bytes (≈ 0 bytes)\n\
         - Local Path Reused: {} bytes\n\
         - Chunk Store Reused: {} bytes\n\
         - Store Chunks Reused: {} / {}\n\
         - Whole File BLAKE3: {}\n\
         - Destination Exists: {}",
        report2.total_bytes as f64 / (1024.0 * 1024.0),
        report2.wire_bytes_transferred,
        report2.local_bytes_reused,
        report2.store_bytes_reused,
        report2.store_chunks_count,
        report2.total_chunks,
        report2.whole_file_hash,
        dst2_path.exists(),
    );

    // Assert M8 Exit Criteria: Second copy transfers ≈ 0 bytes!
    assert_eq!(report2.decision, SyncDecision::Delta);
    assert_eq!(
        report2.wire_bytes_transferred, 0,
        "Second copy transferred wire data; expected 0 bytes"
    );
    assert_eq!(
        report2.wire_chunks_count, 0,
        "Second copy sent wire chunks; expected 0 chunks"
    );
    assert_eq!(report2.store_bytes_reused, file_size as u64);
    assert_eq!(report2.store_chunks_count, report2.total_chunks);
    assert_eq!(report2.whole_file_hash, expected_hash);

    // Verify destination file was perfectly assembled from chunk store and is intact
    assert!(dst2_path.exists());
    let dest2_content = fs::read(&dst2_path).unwrap();
    assert_eq!(dest2_content.len(), content.len());
    assert_eq!(dest2_content, content);
}

/// Cross-file partial deduplication (e.g. Docker / VM layers).
#[tokio::test]
async fn test_cross_file_partial_deduplication() {
    let dir = tempdir().unwrap();
    let store_dir = dir.path().join("chunk_store");
    let chunk_store = LocalChunkStore::new(&store_dir).await.unwrap();

    let base_size = 12 * 1024 * 1024; // 12 MiB base
    let base_content = generate_test_content(base_size, 0xCAFE_BABE_DEAD_BEEF);

    let src_base = dir.path().join("base_layer.bin");
    let dst_base = dir.path().join("base_layer_dst.bin");
    fs::write(&src_base, &base_content).unwrap();

    let params = ChunkParams::new(64 * 1024, 256 * 1024, 512 * 1024).unwrap();

    // 1. Sync base layer
    let report_base = execute_dedup_sync(
        &src_base,
        &dst_base,
        ChunkMode::Cdc,
        params,
        256 * 1024,
        Some(&chunk_store),
    )
    .unwrap();
    assert_eq!(report_base.wire_bytes_transferred, base_size as u64);

    // 2. Create derived file: 75% identical chunks + 25% new chunks appended
    let new_size = 4 * 1024 * 1024; // 4 MiB new
    let new_content = generate_test_content(new_size, 0x1122_3344_5566_7788);

    let mut derived_content = Vec::with_capacity(base_size + new_size);
    derived_content.extend_from_slice(&base_content);
    derived_content.extend_from_slice(&new_content);
    let derived_hash = Hash::of(&derived_content);

    let src_derived = dir.path().join("derived_image.bin");
    let dst_derived = dir.path().join("separate_target/derived_image.bin");
    fs::write(&src_derived, &derived_content).unwrap();

    // 3. Sync derived file to separate directory
    let report_derived = execute_dedup_sync(
        &src_derived,
        &dst_derived,
        ChunkMode::Cdc,
        params,
        256 * 1024,
        Some(&chunk_store),
    )
    .unwrap();

    println!(
        "Cross-File Partial Dedup:\n\
         - Derived File Total: {} bytes\n\
         - Wire Transferred: {} bytes\n\
         - Chunk Store Reused: {} bytes\n\
         - Store Chunks Reused: {} / {}\n\
         - Dedup Savings: {:.1}%",
        report_derived.total_bytes,
        report_derived.wire_bytes_transferred,
        report_derived.store_bytes_reused,
        report_derived.store_chunks_count,
        report_derived.total_chunks,
        (report_derived.store_bytes_reused as f64 / report_derived.total_bytes as f64) * 100.0,
    );

    // Derived file reused base chunks from the store; only new/boundary chunks were transferred!
    assert_eq!(report_derived.decision, SyncDecision::Delta);
    assert!(
        report_derived.store_bytes_reused >= (base_size as u64) - (512 * 1024),
        "Store bytes reused was {} (expected >= {})",
        report_derived.store_bytes_reused,
        (base_size as u64) - (512 * 1024)
    );
    assert!(
        report_derived.wire_bytes_transferred <= (new_size as u64) + (512 * 1024),
        "Wire bytes was {} (expected <= {})",
        report_derived.wire_bytes_transferred,
        (new_size as u64) + (512 * 1024)
    );
    assert_eq!(report_derived.whole_file_hash, derived_hash);

    let synced_derived = fs::read(&dst_derived).unwrap();
    assert_eq!(synced_derived, derived_content);
}

/// ChunkStore corrupt chunk detection and data integrity enforcement.
#[tokio::test]
async fn test_chunk_store_corruption_defense() {
    let dir = tempdir().unwrap();
    let store_dir = dir.path().join("chunk_store");
    let chunk_store = LocalChunkStore::new(&store_dir).await.unwrap();

    let valid_chunk = b"trusted chunk payload";
    let valid_hash = Hash::of(valid_chunk);

    // Put valid chunk
    chunk_store.put(&valid_hash, valid_chunk).await.unwrap();
    assert!(chunk_store.has(&valid_hash).await.unwrap());

    // Corrupt the chunk on disk
    let chunk_disk_path = chunk_store.chunk_path(&valid_hash);
    fs::write(&chunk_disk_path, b"maliciously corrupted bytes").unwrap();

    // `get` must detect the corruption and reject it
    let res = chunk_store.get(&valid_hash).await;
    assert!(res.is_err());

    // Corrupted chunk was automatically removed
    assert!(!chunk_disk_path.exists());
}

/// Chunk ingestion from existing local files.
#[tokio::test]
async fn test_chunk_store_ingest_file() {
    let dir = tempdir().unwrap();
    let store_dir = dir.path().join("chunk_store");
    let chunk_store = LocalChunkStore::new(&store_dir).await.unwrap();

    let file_path = dir.path().join("preexisting.bin");
    let payload = generate_test_content(2 * 1024 * 1024, 0x9988_7766_5544_3322);
    fs::write(&file_path, &payload).unwrap();

    let params = ChunkParams::new(64 * 1024, 128 * 1024, 256 * 1024).unwrap();
    let count = chunk_store
        .ingest_file_sync(&file_path, ChunkMode::Fixed, params)
        .unwrap();

    assert_eq!(count, 16); // 2 MiB / 128 KiB = 16 chunks
    assert_eq!(chunk_store.total_chunks().await.unwrap(), 16);
    assert_eq!(chunk_store.total_bytes().await.unwrap(), 2 * 1024 * 1024);
}
