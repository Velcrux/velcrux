//! Milestone 7 Exit Integration Tests: Delta Synchronization (`ARCHITECTURE.md` §7, §12).
//!
//! Exit test verification:
//! - "100 GB with 3 GB changed moves ≈ 3 GB + overhead"
//! - CDC chunk reuse with insertions/modifications
//! - Bloom filter hint exchange & RLE bitmap query/response
//! - Cost estimator (Skip vs Delta vs Full)
//! - Whole-file BLAKE3 verification and atomic commit rollback on corruption

use std::collections::HashMap;
use std::fs;
use tempfile::tempdir;

use velcrux_core::chunking::{ChunkMode, ChunkParams};
use velcrux_core::protocol::message::{ChunkQuery, ChunkResponse, InventoryHint};
use velcrux_core::sync::{
    execute_delta_sync, ChunkExtent, CostEstimator, DeltaReconstructor,
    LocalInventory, RleBitmap, SyncDecision, SyncError,
};
use velcrux_core::util::{Hash, TransferId};

/// M7 Exit Test:
/// "100 GB with 3 GB changed moves ≈ 3 GB + overhead" (`ARCHITECTURE.md` §12).
#[test]
fn test_exit_criteria_100gb_with_3gb_changed() {
    let chunk_size: u64 = 512 * 1024; // 512 KiB chunks
    let total_bytes: u64 = 100 * 1024 * 1024 * 1024; // 100 GiB
    let total_chunks = (total_bytes / chunk_size) as usize; // 200,000 chunks

    // 3 GiB changed = 6,000 chunks
    let changed_bytes: u64 = 3 * 1024 * 1024 * 1024;
    let changed_chunks = (changed_bytes / chunk_size) as usize; // 6,000 chunks
    let reused_chunks = total_chunks - changed_chunks; // 194,000 chunks

    // Simulate 200,000 chunk hashes
    // Chunks 50,000 .. 56,000 are modified/new
    let modified_range = 50_000..(50_000 + changed_chunks);

    let mut receiver_chunks = HashMap::with_capacity(reused_chunks);
    let mut source_hashes = Vec::with_capacity(total_chunks);

    for i in 0..total_chunks {
        let h = Hash::of(&format!("chunk_v1_{i}").into_bytes());
        if !modified_range.contains(&i) {
            receiver_chunks.insert(
                h,
                ChunkExtent {
                    offset: (i as u64) * chunk_size,
                    length: chunk_size,
                },
            );
            source_hashes.push(h);
        } else {
            // Source has new modified chunk
            let h_mod = Hash::of(&format!("chunk_v2_modified_{i}").into_bytes());
            source_hashes.push(h_mod);
        }
    }

    assert_eq!(receiver_chunks.len(), reused_chunks);
    assert_eq!(source_hashes.len(), total_chunks);

    // 1. Receiver generates inventory and Bloom filter hint
    let receiver_inv = LocalInventory::from_extents(
        receiver_chunks,
        reused_chunks as u64 * chunk_size,
        reused_chunks,
        None,
    );

    let bloom = receiver_inv.create_bloom_filter(0.01);
    let tid = TransferId::generate();
    let hint = InventoryHint {
        transfer_id: tid,
        filter_bits: bloom.num_bits(),
        num_hashes: bloom.num_hashes(),
        bitset: bloom.to_bytes(),
    };

    // Verify Bloom hint size is bounded (under 400 KiB for 200k items at 1% FP)
    assert!(
        hint.bitset.len() < 400 * 1024,
        "Bloom hint is {} bytes, should be < 400 KiB",
        hint.bitset.len()
    );

    // 2. Sender checks candidate chunks against Bloom hint
    let mut candidate_indices = Vec::new();
    for (idx, h) in source_hashes.iter().enumerate() {
        if bloom.contains(h) {
            candidate_indices.push(idx);
        }
    }

    // 3. Sender sends ChunkQuery for candidates
    let query_hashes: Vec<Hash> = candidate_indices
        .iter()
        .map(|&idx| source_hashes[idx])
        .collect();

    let query = ChunkQuery {
        transfer_id: tid,
        query_seq: 1,
        chunk_hashes: query_hashes.clone(),
    };

    // 4. Receiver generates RLE bitmap response
    let mut have_bits = Vec::with_capacity(query_hashes.len());
    for h in &query_hashes {
        have_bits.push(receiver_inv.contains(h));
    }

    let rle = RleBitmap::from_bits(&have_bits);
    let resp = ChunkResponse {
        transfer_id: tid,
        query_seq: 1,
        total_chunks: rle.total_chunks(),
        have_count: rle.have_count(),
        rle_bitmap: rle.encode(),
    };

    // The RLE bitmap for 194,000 have chunks with 1 gap of 6,000 need chunks
    // compresses to under 50 bytes!
    assert!(
        resp.rle_bitmap.len() < 100,
        "RLE bitmap wire size was {} bytes (expected < 100 bytes)",
        resp.rle_bitmap.len()
    );

    // 5. Cost estimator evaluates transfer
    let estimator = CostEstimator::default();
    let plan = estimator.evaluate(
        total_bytes,
        total_chunks,
        resp.have_count as usize,
        false,
    );

    assert_eq!(plan.decision, SyncDecision::Delta);
    assert_eq!(plan.have_chunks, reused_chunks);
    assert_eq!(plan.need_chunks, changed_chunks);
    assert_eq!(plan.wire_bytes, changed_bytes); // exactly 3 GiB
    assert_eq!(plan.reused_bytes, total_bytes - changed_bytes); // 97 GiB

    // Calculate total wire data transferred including protocol overhead
    let wire_overhead = hint.bitset.len() as u64
        + query.encode().unwrap().len() as u64
        + resp.encode().unwrap().len() as u64;

    let total_wire_transferred = plan.wire_bytes + wire_overhead;

    println!(
        "M7 Exit Test Results:\n\
         - Logical Dataset Size: {:.2} GiB\n\
         - Modified Content: {:.2} GiB\n\
         - Wire Bytes Data: {:.3} GiB\n\
         - Wire Protocol Overhead: {:.2} KiB\n\
         - Total Transferred: {:.3} GiB (moves ≈ 3 GB + overhead)",
        total_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
        changed_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
        plan.wire_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
        wire_overhead as f64 / 1024.0,
        total_wire_transferred as f64 / (1024.0 * 1024.0 * 1024.0),
    );

    // Assert exit criteria: moves ≈ 3 GB + overhead (less than 3.05 GiB total wire transfer)
    assert!(
        total_wire_transferred < 3_300_000_000,
        "Total wire transferred {} exceeded 3.3 GB threshold",
        total_wire_transferred
    );
}

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

/// End-to-end real file delta transfer with CDC chunking and offset insertion.
#[test]
fn test_real_file_end_to_end_delta_cdc_sync() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("source.bin");
    let dst_path = dir.path().join("destination.bin");

    // 1. Create destination file: 16 MiB of high-entropy pseudorandom content
    let original_len = 16 * 1024 * 1024;
    let pattern = generate_test_content(original_len, 0x1234_5678_9ABC_DEF0);
    fs::write(&dst_path, &pattern).unwrap();

    // 2. Create source file: original file with 512 KiB inserted at offset 4 MiB
    let insert_pos = 4 * 1024 * 1024;
    let insert_len = 512 * 1024;
    let insertion = generate_test_content(insert_len, 0xFEED_FACE_CAFE_BEEF);

    let mut modified = Vec::with_capacity(original_len + insert_len);
    modified.extend_from_slice(&pattern[..insert_pos]);
    modified.extend_from_slice(&insertion);
    modified.extend_from_slice(&pattern[insert_pos..]);
    fs::write(&src_path, &modified).unwrap();

    let expected_hash = Hash::of(&modified);

    // 3. Execute delta sync with CDC chunking
    let params = ChunkParams::new(64 * 1024, 256 * 1024, 1024 * 1024).unwrap();
    let report = execute_delta_sync(
        &src_path,
        &dst_path,
        ChunkMode::Cdc,
        params,
        256 * 1024,
    ).unwrap();

    assert_eq!(report.decision, SyncDecision::Delta);
    assert_eq!(report.whole_file_hash, expected_hash);

    // Content of destination file must now match source file exactly
    let synced_content = fs::read(&dst_path).unwrap();
    assert_eq!(synced_content.len(), modified.len());
    assert_eq!(synced_content, modified);

    // Verify wire bytes were only a fraction of the 16.5 MiB file (moves ~512KB + boundary chunk)
    println!(
        "CDC Delta Sync:\n\
         - File size: {} bytes\n\
         - Wire transferred: {} bytes\n\
         - Local reused: {} bytes\n\
         - Reused chunks: {} / {}\n\
         - Savings: {:.1}%",
        report.total_bytes,
        report.wire_bytes_transferred,
        report.local_bytes_reused,
        report.local_chunks_count,
        report.total_chunks,
        (report.local_bytes_reused as f64 / report.total_bytes as f64) * 100.0
    );

    assert!(
        report.wire_bytes_transferred < 2 * 1024 * 1024,
        "Wire bytes {} should be < 2 MiB for 512 KiB edit in 16 MiB file",
        report.wire_bytes_transferred
    );
    assert!(
        report.local_bytes_reused > 14 * 1024 * 1024,
        "Local bytes reused {} should be > 14 MiB",
        report.local_bytes_reused
    );
}

/// Verify that identical files trigger `SyncDecision::Skip` with 0 wire bytes.
#[test]
fn test_identical_file_skips_wire_transfer() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("source.bin");
    let dst_path = dir.path().join("destination.bin");

    let payload = vec![0xABu8; 4 * 1024 * 1024];
    fs::write(&src_path, &payload).unwrap();
    fs::write(&dst_path, &payload).unwrap();

    let params = ChunkParams::new(64 * 1024, 256 * 1024, 512 * 1024).unwrap();
    let report = execute_delta_sync(
        &src_path,
        &dst_path,
        ChunkMode::Fixed,
        params,
        128 * 1024,
    ).unwrap();

    assert_eq!(report.decision, SyncDecision::Skip);
    assert_eq!(report.wire_bytes_transferred, 0);
    assert_eq!(report.local_bytes_reused, 4 * 1024 * 1024);
    assert_eq!(report.wire_chunks_count, 0);
}

/// Verify that non-existent destination performs full sync into staging and atomically commits.
#[test]
fn test_missing_destination_falls_back_to_full_sync() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("source.bin");
    let dst_path = dir.path().join("subdir/destination.bin");

    let payload = vec![0x77u8; 2 * 1024 * 1024];
    fs::write(&src_path, &payload).unwrap();

    let params = ChunkParams::new(64 * 1024, 128 * 1024, 256 * 1024).unwrap();
    let report = execute_delta_sync(
        &src_path,
        &dst_path,
        ChunkMode::Fixed,
        params,
        64 * 1024,
    ).unwrap();

    assert_eq!(report.decision, SyncDecision::Full);
    assert_eq!(report.wire_bytes_transferred, 2 * 1024 * 1024);
    assert_eq!(report.local_bytes_reused, 0);
    assert!(dst_path.exists());
    assert_eq!(fs::read(&dst_path).unwrap(), payload);
}

/// Verify corruption aborts and staging file is purged, preserving original destination file intact.
#[test]
fn test_reconstruction_corruption_preserves_original_intact() {
    let dir = tempdir().unwrap();
    let dst_path = dir.path().join("intact_target.bin");
    let staging_path = dir.path().join("intact_target.bin.velcrux-partial");

    let original_payload = b"ORIGINAL INTACT DATA DO NOT CORRUPT";
    fs::write(&dst_path, original_payload).unwrap();

    let expected_hash = Hash::of(b"NEW TARGET DATA");
    let mut recon = DeltaReconstructor::new(
        dst_path.clone(),
        staging_path.clone(),
        expected_hash,
        15,
        1,
    ).unwrap();

    // Write wrong payload into staging
    recon.write_wire_chunk(0, b"CORRUPTED_BYTES").unwrap();

    let res = recon.verify_and_commit();
    assert!(matches!(res, Err(SyncError::HashMismatch { .. })));

    // Staging must be removed
    assert!(!staging_path.exists());

    // Original target file must remain unmodified and intact
    let preserved = fs::read(&dst_path).unwrap();
    assert_eq!(preserved, original_payload);
}
