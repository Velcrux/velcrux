#![forbid(unsafe_code)]

//! Milestone 11 (Option H): End-to-End Sparse File Detection, Hole Punching,
//! and Zero-Transfer Optimization (REQUIREMENTS.md §33).

use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;

use velcrux_core::chunking::{ChunkMode, ChunkParams};
use velcrux_core::manifest::entry::{ChunkDesc, FileEntry};
use velcrux_core::storage::{ChunkStore, LocalChunkStore, VPath};
use velcrux_core::sync::{execute_dedup_sync, execute_delta_sync};
use velcrux_core::util::Hash;

#[tokio::test]
async fn test_sparse_file_full_sync_zero_wire_for_holes() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("source_sparse.bin");
    let dst_path = dir.path().join("dest_sparse.bin");
    let store_dir = dir.path().join("chunk_store");

    let chunk_store = LocalChunkStore::new(&store_dir).await.unwrap();

    // Construct a sparse file with:
    // - Header: 64 KiB data
    // - Hole 1: 512 KiB zeros
    // - Mid:    64 KiB data
    // - Hole 2: 256 KiB zeros
    // - Footer: 64 KiB data
    // Total size: 960 KiB.
    // Non-zero data: 192 KiB.
    // Sparse holes: 768 KiB.
    let header = vec![0x11u8; 64 * 1024];
    let hole1 = vec![0x00u8; 512 * 1024];
    let mid = vec![0x22u8; 64 * 1024];
    let hole2 = vec![0x00u8; 256 * 1024];
    let footer = vec![0x33u8; 64 * 1024];

    let mut full_content = Vec::new();
    full_content.extend_from_slice(&header);
    full_content.extend_from_slice(&hole1);
    full_content.extend_from_slice(&mid);
    full_content.extend_from_slice(&hole2);
    full_content.extend_from_slice(&footer);

    let total_size = full_content.len() as u64;
    let expected_hash = Hash::of(&full_content);

    {
        let mut f = File::create(&src_path).unwrap();
        f.write_all(&full_content).unwrap();
        f.flush().unwrap();
    }

    // Use fixed 64 KiB chunking so boundaries align perfectly with segments
    let params = ChunkParams::fixed(64 * 1024);

    let report = execute_dedup_sync(
        &src_path,
        &dst_path,
        ChunkMode::Fixed,
        params,
        64 * 1024,
        Some(&chunk_store),
    )
    .unwrap();

    println!(
        "Sparse Full Sync Report:\n\
         - Total bytes: {}\n\
         - Wire bytes transferred: {}\n\
         - Sparse bytes skipped: {}\n\
         - Sparse holes count: {}\n\
         - Wire chunks count: {}\n\
         - Whole file hash: {}",
        report.total_bytes,
        report.wire_bytes_transferred,
        report.sparse_bytes_skipped,
        report.sparse_holes_count,
        report.wire_chunks_count,
        report.whole_file_hash,
    );

    // Assertions per REQUIREMENTS.md §33:
    // 1. Total logical size is 960 KiB
    assert_eq!(report.total_bytes, total_size);

    // 2. Exactly 768 KiB of holes were skipped without wire transfer or disk write
    assert_eq!(report.sparse_bytes_skipped, 768 * 1024);
    assert!(report.sparse_holes_count >= 2);

    // 3. Only the non-zero bytes (192 KiB) were transferred over the wire
    assert_eq!(report.wire_bytes_transferred, 192 * 1024);
    assert_eq!(report.wire_chunks_count, 3); // header (1), mid (1), footer (1)

    // 4. Whole-file digest matches byte-for-byte
    assert_eq!(report.whole_file_hash, expected_hash);

    // 5. Destination exists and reads back identical content
    assert!(dst_path.exists());
    let dst_content = fs::read(&dst_path).unwrap();
    assert_eq!(dst_content.len(), total_size as usize);
    assert_eq!(dst_content, full_content);
    assert_eq!(Hash::of(&dst_content), expected_hash);

    // 6. Chunk store does not store zero hole chunks
    let store_count = chunk_store.total_chunks().await.unwrap();
    assert_eq!(store_count, 3); // Only the 3 data chunks were stored
}

#[tokio::test]
async fn test_sparse_file_delta_sync_with_existing_destination() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("source_sparse.bin");
    let dst_path = dir.path().join("dest_sparse.bin");

    // Source:
    // - Header: 64 KiB of 0xAA
    // - Hole: 256 KiB of 0x00
    // - Footer: 64 KiB of 0xBB (NEW data)
    let mut src_content = Vec::new();
    src_content.extend_from_slice(&vec![0xAAu8; 64 * 1024]);
    src_content.extend_from_slice(&vec![0x00u8; 256 * 1024]);
    src_content.extend_from_slice(&vec![0xBBu8; 64 * 1024]);

    // Destination already has Header and Hole, but old footer:
    let mut dst_content = Vec::new();
    dst_content.extend_from_slice(&vec![0xAAu8; 64 * 1024]);
    dst_content.extend_from_slice(&vec![0x00u8; 256 * 1024]);
    dst_content.extend_from_slice(&vec![0x99u8; 64 * 1024]); // old footer

    fs::write(&src_path, &src_content).unwrap();
    fs::write(&dst_path, &dst_content).unwrap();

    let params = ChunkParams::fixed(64 * 1024);

    let report =
        execute_delta_sync(&src_path, &dst_path, ChunkMode::Fixed, params, 64 * 1024).unwrap();

    println!(
        "Sparse Delta Sync Report:\n\
         - Total bytes: {}\n\
         - Wire bytes: {}\n\
         - Local reused: {}\n\
         - Sparse skipped: {}\n\
         - Decision: {:?}",
        report.total_bytes,
        report.wire_bytes_transferred,
        report.local_bytes_reused,
        report.sparse_bytes_skipped,
        report.decision,
    );

    // 1. Total logical size is 384 KiB
    assert_eq!(report.total_bytes, src_content.len() as u64);

    // 2. Sparse hole (256 KiB) is skipped
    assert_eq!(report.sparse_bytes_skipped, 256 * 1024);

    // 3. Header chunk (64 KiB) is reused from local destination
    assert_eq!(report.local_bytes_reused, 64 * 1024);

    // 4. ONLY the modified footer (64 KiB) is transferred over the wire!
    assert_eq!(report.wire_bytes_transferred, 64 * 1024);

    // 5. Verification on readback
    let updated_dst = fs::read(&dst_path).unwrap();
    assert_eq!(updated_dst, src_content);
    assert_eq!(Hash::of(&updated_dst), Hash::of(&src_content));
}

#[test]
fn test_sparse_file_entry_flags() {
    let vpath = VPath::validate("sparse/data.img").unwrap();

    // 1. Non-sparse chunks
    let normal_chunks = vec![
        ChunkDesc::new(64 * 1024, Hash::of(b"chunk1")),
        ChunkDesc::new(64 * 1024, Hash::of(b"chunk2")),
    ];
    let entry_normal = FileEntry::regular(
        vpath.clone(),
        128 * 1024,
        0o644,
        1000,
        0,
        Hash::ZERO,
        normal_chunks,
    );
    assert!(!entry_normal.flags.is_sparse());

    // 2. Chunks containing a hole
    let sparse_chunks = vec![
        ChunkDesc::new(64 * 1024, Hash::of(b"chunk1")),
        ChunkDesc::hole(1024 * 1024),
        ChunkDesc::new(64 * 1024, Hash::of(b"chunk3")),
    ];
    let entry_sparse = FileEntry::regular(
        vpath,
        64 * 1024 + 1024 * 1024 + 64 * 1024,
        0o644,
        1000,
        0,
        Hash::ZERO,
        sparse_chunks,
    );
    assert!(entry_sparse.flags.is_sparse());
}
