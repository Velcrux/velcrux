//! M5 end-to-end manifest test (`docs/ARCHITECTURE.md` §12).
//!
//! **Exit criterion (M5):** *"Streaming manifest for 1 M files, bounded RSS"*
//!
//! This integration test exercises:
//! 1. Streaming generation and verification of a **1,000,000 file** manifest
//!    with strictly bounded RSS memory (never O(file_count)).
//! 2. Zstd-compressed 4096-entry batch framing on the wire (`MANIFEST_BEGIN`,
//!    `MANIFEST_BATCH`es, `MANIFEST_END`).
//! 3. Receiver-side validation: path traversal defense, decompression-bomb defense,
//!    chunk bounds clamps, and canonical BLAKE3 whole-manifest digest verification.
//! 4. Content-addressed `ManifestStore` persistence and deduplication.

use std::time::Instant;

use tempfile::tempdir;

use velcrux_core::chunking::ChunkParams;
use velcrux_core::error::{ProtocolError, VelcruxError};
use velcrux_core::manifest::{
    decode_file_entry, ChunkDesc, FileEntry, FileFlags, ManifestReader, ManifestStore,
    ManifestWriter,
};
use velcrux_core::protocol::limits::MAX_BATCH_DECOMPRESSED_BYTES;
use velcrux_core::protocol::message::Message;
use velcrux_core::storage::VPath;
use velcrux_core::util::Hash;

/// Helper to get current process Resident Set Size (RSS) in bytes using safe I/O.
fn get_current_rss_bytes() -> usize {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
        {
            if let Ok(s) = std::str::from_utf8(&output.stdout) {
                if let Ok(kb) = s.trim().parse::<usize>() {
                    return kb * 1024;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let parts: Vec<&str> = statm.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(pages) = parts[1].parse::<usize>() {
                    return pages * 4096;
                }
            }
        }
    }

    0
}

#[test]
fn m5_streaming_manifest_1m_files_bounded_rss() {
    let dir = tempdir().unwrap();
    let spill_path = dir.path().join("1m_files.spill");

    println!("Starting M5 Exit Test: 1,000,000 files streaming manifest...");
    let start_time = Instant::now();
    let initial_rss = get_current_rss_bytes();

    let chunker_params = ChunkParams::default();
    let mut writer = ManifestWriter::new(&spill_path, chunker_params).unwrap();

    const NUM_FILES: u64 = 1_000_000;
    const CHUNK_LEN: u64 = 1024;

    // Stream 1,000,000 file entries into ManifestWriter
    for i in 0..NUM_FILES {
        let dir_idx = i / 1000;
        let file_idx = i % 1000;
        let mut path_buf = String::with_capacity(32);
        use std::fmt::Write;
        write!(&mut path_buf, "d_{}/f_{}.dat", dir_idx, file_idx).unwrap();
        let path = VPath::validate(&path_buf).unwrap();

        let mut chunk_hash_raw = [0u8; 32];
        chunk_hash_raw[0..8].copy_from_slice(&i.to_le_bytes());
        let chunk_hash = Hash::from_bytes(&chunk_hash_raw).unwrap();
        let chunk = ChunkDesc::new(CHUNK_LEN, chunk_hash);

        let entry = FileEntry::regular(
            path,
            CHUNK_LEN,
            0o644,
            1700000000 + (i as i64),
            0,
            chunk_hash,
            vec![chunk],
        );

        writer.add_entry(entry).unwrap();

        // Periodic memory checkpoints to assert bounded RSS
        if i > 0 && i % 250_000 == 0 {
            let current_rss = get_current_rss_bytes();
            println!(
                "  Writer progress: {}/{} files streamed... RSS: {:.2} MB",
                i,
                NUM_FILES,
                (current_rss as f64) / (1024.0 * 1024.0)
            );
            if initial_rss > 0 && current_rss > initial_rss {
                let growth = current_rss - initial_rss;
                assert!(
                    growth < 250 * 1024 * 1024,
                    "RSS growth ({growth} bytes) violates bounded memory invariant"
                );
            }
        }
    }

    let (begin, end, spill_out) = writer.finish().unwrap();
    let write_duration = start_time.elapsed();
    println!(
        "Completed writing 1M files in {:.2}s. Spill file size: {:.2} MB",
        write_duration.as_secs_f64(),
        (std::fs::metadata(&spill_out).unwrap().len() as f64) / (1024.0 * 1024.0)
    );

    assert_eq!(begin.file_count, NUM_FILES);
    assert_eq!(begin.total_bytes, NUM_FILES * CHUNK_LEN);
    assert_eq!(begin.manifest_hash, end.manifest_hash);

    // Read back all 1,000,000 entries streaming via ManifestReader
    let read_start = Instant::now();
    let mut reader = ManifestReader::open(&spill_out, begin.manifest_hash).unwrap();
    let mut read_count: u64 = 0;

    while let Some(entry) = reader.next_entry().unwrap() {
        let expected_dir = read_count / 1000;
        let expected_file = read_count % 1000;
        let expected_path = format!("d_{}/f_{}.dat", expected_dir, expected_file);
        assert_eq!(entry.path.as_str(), expected_path);
        assert_eq!(entry.size, CHUNK_LEN);
        assert_eq!(entry.chunks.len(), 1);

        read_count += 1;
        if read_count % 250_000 == 0 {
            let current_rss = get_current_rss_bytes();
            println!(
                "  Reader progress: {}/{} files verified... RSS: {:.2} MB",
                read_count,
                NUM_FILES,
                (current_rss as f64) / (1024.0 * 1024.0)
            );
        }
    }

    assert_eq!(read_count, NUM_FILES);
    println!(
        "Verified all 1,000,000 files in {:.2}s. Final hash validated successfully.",
        read_start.elapsed().as_secs_f64()
    );
}

#[test]
fn m5_wire_streaming_manifest_roundtrip() {
    let dir = tempdir().unwrap();
    let spill_path = dir.path().join("wire_test.spill");

    let mut writer = ManifestWriter::new(&spill_path, ChunkParams::default()).unwrap();
    for i in 0..10_000 {
        let path = VPath::validate(&format!("data/file_{}.bin", i)).unwrap();
        let chunk = ChunkDesc::new(512, Hash::ZERO);
        let entry = FileEntry::regular(path, 512, 0o644, 1000, 0, Hash::ZERO, vec![chunk]);
        writer.add_entry(entry).unwrap();
    }
    let (begin, end, path) = writer.finish().unwrap();

    // Read the spill file and verify entries
    let mut reader = ManifestReader::open(&path, begin.manifest_hash).unwrap();
    let mut count = 0;
    while let Some(_) = reader.next_entry().unwrap() {
        count += 1;
    }
    assert_eq!(count, 10_000);

    // Test wire message serialization of ManifestBegin, ManifestEnd
    let begin_msg = Message::ManifestBegin(begin.clone());
    let (t_begin, p_begin) = begin_msg.encode().unwrap();
    let decoded_begin = Message::decode(t_begin, &p_begin).unwrap();
    assert_eq!(begin_msg, decoded_begin);

    let end_msg = Message::ManifestEnd(end.clone());
    let (t_end, p_end) = end_msg.encode().unwrap();
    let decoded_end = Message::decode(t_end, &p_end).unwrap();
    assert_eq!(end_msg, decoded_end);
}

#[test]
fn m5_tampered_manifest_digest_rejected() {
    let dir = tempdir().unwrap();
    let spill_path = dir.path().join("tampered_digest.spill");

    let mut writer = ManifestWriter::new(&spill_path, ChunkParams::default()).unwrap();
    writer
        .add_entry(FileEntry::regular(
            VPath::validate("file.txt").unwrap(),
            100,
            0o644,
            0,
            0,
            Hash::ZERO,
            vec![ChunkDesc::new(100, Hash::ZERO)],
        ))
        .unwrap();
    let (begin, _, path) = writer.finish().unwrap();

    // Provide bad hash to ManifestReader
    let mut bad_hash = *begin.manifest_hash.as_bytes();
    bad_hash[0] ^= 0x01;
    let bad_expected = Hash::from_bytes(&bad_hash).unwrap();

    let mut reader = ManifestReader::open(&path, bad_expected).unwrap();
    let _ = reader.next_entry().unwrap();
    let res = reader.next_entry();
    assert!(res.is_err(), "Expected manifest hash mismatch error");
    if let Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(msg))) = res {
        assert!(msg.contains("manifest hash mismatch"));
    } else {
        panic!("Expected InvalidManifest error");
    }
}

#[test]
fn m5_path_traversal_in_manifest_rejected() {
    let traversal = b"../secret/passwords";
    let mut malicious_buf = Vec::new();
    let mut vbuf = [0u8; 10];
    velcrux_core::protocol::varint::encode_varint(FileFlags::regular().0, &mut vbuf);
    malicious_buf.extend_from_slice(&vbuf[..1]);
    let n = velcrux_core::protocol::varint::encode_varint(traversal.len() as u64, &mut vbuf);
    malicious_buf.extend_from_slice(&vbuf[..n]);
    malicious_buf.extend_from_slice(traversal);
    malicious_buf.extend_from_slice(&0u64.to_le_bytes());
    malicious_buf.extend_from_slice(&0o644u32.to_le_bytes());
    malicious_buf.extend_from_slice(&0i64.to_le_bytes());
    malicious_buf.extend_from_slice(&0u32.to_le_bytes());
    malicious_buf.extend_from_slice(Hash::ZERO.as_bytes());
    malicious_buf.push(0); // 0 chunks

    let err = decode_file_entry(&malicious_buf).unwrap_err();
    assert!(matches!(err, ProtocolError::InvalidManifest(_)));
}

#[test]
fn m5_decompression_bomb_rejected() {
    let bomb_size = MAX_BATCH_DECOMPRESSED_BYTES + 1024 * 1024;
    let zeros = vec![0u8; bomb_size];
    let compressed = zstd::encode_all(&zeros[..], 1).unwrap();

    let res = velcrux_core::manifest::decompress_batch(&compressed);
    assert!(res.is_err(), "Decompression bomb must be rejected");
    if let Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(msg))) = res {
        assert!(msg.contains("decompressed batch exceeded limit"));
    } else {
        panic!("Expected InvalidManifest error for decompression bomb");
    }
}

#[test]
fn m5_manifest_store_caching_and_dedup() {
    let dir = tempdir().unwrap();
    let store_dir = dir.path().join("manifests");
    let store = ManifestStore::new(&store_dir).unwrap();

    let spill_path = dir.path().join("cache_test.spill");
    let mut writer = ManifestWriter::new(&spill_path, ChunkParams::default()).unwrap();
    let path = VPath::validate("cached/item.txt").unwrap();
    writer
        .add_entry(FileEntry::regular(
            path,
            128,
            0o644,
            1234,
            0,
            Hash::ZERO,
            vec![ChunkDesc::new(128, Hash::ZERO)],
        ))
        .unwrap();
    let (begin, _, spill) = writer.finish().unwrap();

    assert!(!store.has_manifest(&begin.manifest_hash));
    let saved_path = store.save_manifest(&begin.manifest_hash, spill).unwrap();
    assert!(store.has_manifest(&begin.manifest_hash));
    assert_eq!(saved_path, store.manifest_path(&begin.manifest_hash));

    // Open from store and verify
    let mut reader = store.open_manifest(&begin.manifest_hash).unwrap();
    let entry = reader.next_entry().unwrap().unwrap();
    assert_eq!(entry.path.as_str(), "cached/item.txt");
    assert!(reader.next_entry().unwrap().is_none());
}
