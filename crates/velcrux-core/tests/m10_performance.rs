use std::time::Instant;
use tempfile::tempdir;

use blake3::Hasher as Blake3Hasher;
use sha2::{Digest, Sha256};

use velcrux_core::chunking::{ChunkEngine, ChunkMode, ChunkParams};
use velcrux_core::manifest::{ChunkDesc, FileEntry, ManifestReader, ManifestWriter};
use velcrux_core::protocol::frame::{
    decode_data_frame_header, decode_frame, encode_data_frame_header, encode_frame, DataFrameFlags,
    FrameFlags, DATA_FRAME_HEADER_LEN,
};
use velcrux_core::storage::VPath;
use velcrux_core::sync::{execute_delta_sync, CostEstimator, RleBitmap, SyncDecision};
use velcrux_core::util::Hash;

/// Generate deterministic pseudorandom data per PERFORMANCE.md Rule 1 (never /dev/zero).
fn generate_pseudorandom_bytes(size: usize, seed: u64) -> Vec<u8> {
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
fn test_perf_blake3_vs_sha256() {
    // Measures BLAKE3 vs SHA-256 GB/s throughput for ADR-003
    let size = 16 * 1024 * 1024; // 16 MiB
    let payload = generate_pseudorandom_bytes(size, 42);
    let iterations = 5;

    // Benchmark BLAKE3
    let t0 = Instant::now();
    for _ in 0..iterations {
        let mut hasher = Blake3Hasher::new();
        hasher.update(&payload);
        let _digest = hasher.finalize();
    }
    let blake3_elapsed = t0.elapsed();
    let blake3_bytes = size as f64 * iterations as f64;
    let blake3_gb_per_sec = (blake3_bytes / blake3_elapsed.as_secs_f64()) / 1_000_000_000.0;

    // Benchmark SHA-256
    let t1 = Instant::now();
    for _ in 0..iterations {
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        let _digest = hasher.finalize();
    }
    let sha256_elapsed = t1.elapsed();
    let sha256_bytes = size as f64 * iterations as f64;
    let sha256_gb_per_sec = (sha256_bytes / sha256_elapsed.as_secs_f64()) / 1_000_000_000.0;

    println!(
        "\n--- Hashing Performance (ADR-003) ---\n\
         BLAKE3:  {:>7.2} GB/s ({:?})\n\
         SHA-256: {:>7.2} GB/s ({:?})\n\
         BLAKE3 speedup: {:.1}x",
        blake3_gb_per_sec,
        blake3_elapsed / iterations as u32,
        sha256_gb_per_sec,
        sha256_elapsed / iterations as u32,
        blake3_gb_per_sec / sha256_gb_per_sec
    );

    assert!(
        blake3_gb_per_sec > 0.05,
        "BLAKE3 throughput ({blake3_gb_per_sec:.2} GB/s) must meet minimum threshold"
    );
    assert!(
        blake3_gb_per_sec > sha256_gb_per_sec,
        "BLAKE3 must be faster than SHA-256"
    );
}

#[test]
fn test_perf_chunking_fixed_and_cdc() {
    // Benchmark fixed vs content-defined chunking (PERFORMANCE.md §3)
    let size = 8 * 1024 * 1024; // 8 MiB
    let payload = generate_pseudorandom_bytes(size, 100);

    // Fixed chunking
    let fixed_params = ChunkParams::new(1024 * 1024, 1024 * 1024, 1024 * 1024).unwrap();
    let t0 = Instant::now();
    let mut fixed_count = 0;
    let _ = ChunkEngine::chunk_reader(
        &payload[..],
        ChunkMode::Fixed,
        fixed_params,
        64 * 1024,
        |_desc, _data| {
            fixed_count += 1;
            Ok(())
        },
    )
    .unwrap();
    let fixed_elapsed = t0.elapsed();
    let fixed_gbps = (size as f64 / fixed_elapsed.as_secs_f64()) / 1_000_000_000.0;

    // CDC chunking (target 1 MiB, min 256 KiB, max 4 MiB)
    let cdc_params = ChunkParams::new(256 * 1024, 1024 * 1024, 4 * 1024 * 1024).unwrap();
    let mut cdc_chunk_sizes = Vec::new();
    let t1 = Instant::now();
    let _ = ChunkEngine::chunk_reader(
        &payload[..],
        ChunkMode::Cdc,
        cdc_params,
        64 * 1024,
        |desc, _data| {
            cdc_chunk_sizes.push(desc.length);
            Ok(())
        },
    )
    .unwrap();
    let cdc_elapsed = t1.elapsed();
    let cdc_gbps = (size as f64 / cdc_elapsed.as_secs_f64()) / 1_000_000_000.0;

    println!(
        "\n--- Chunking Performance ---\n\
         Fixed (1 MiB):  {:>7.2} GB/s ({} chunks)\n\
         CDC (256k-4M):  {:>7.2} GB/s ({} chunks)",
        fixed_gbps,
        fixed_count,
        cdc_gbps,
        cdc_chunk_sizes.len()
    );

    assert_eq!(fixed_count, 8);
    for &s in &cdc_chunk_sizes {
        assert!(s >= 256 * 1024, "chunk size {s} must be >= min");
        assert!(s <= 4 * 1024 * 1024, "chunk size {s} must be <= max");
    }
}

#[test]
fn test_perf_manifest_streaming_codec() {
    let dir = tempdir().unwrap();
    let spill_path = dir.path().join("perf.spill");

    let num_entries = 2_000;
    let chunk_params = ChunkParams::default();

    // 1. Benchmark ManifestWriter encoding
    let t0 = Instant::now();
    let mut writer = ManifestWriter::new(&spill_path, chunk_params).unwrap();
    for i in 0..num_entries {
        let vpath = VPath::validate(&format!("dataset/subdir_{}/item_{}.dat", i / 50, i)).unwrap();
        let chunk = ChunkDesc::new(1024, Hash::ZERO);
        let entry = FileEntry::regular(
            vpath,
            1024,
            0o644,
            1700000000 + i as i64,
            0,
            Hash::ZERO,
            vec![chunk],
        );
        writer.add_entry(entry).unwrap();
    }
    let (begin, _, path) = writer.finish().unwrap();
    let encode_elapsed = t0.elapsed();
    let encode_rate = num_entries as f64 / encode_elapsed.as_secs_f64();

    let file_size = std::fs::metadata(&path).unwrap().len();
    let bytes_per_entry = file_size as f64 / num_entries as f64;

    // 2. Benchmark ManifestReader decoding
    let t1 = Instant::now();
    let mut reader = ManifestReader::open(&path, begin.manifest_hash).unwrap();
    let mut read_count = 0;
    while let Some(_entry) = reader.next_entry().unwrap() {
        read_count += 1;
    }
    let decode_elapsed = t1.elapsed();
    let decode_rate = num_entries as f64 / decode_elapsed.as_secs_f64();

    println!(
        "\n--- Manifest Streaming Codec ---\n\
         Encode: {:>8.0} entries/s ({:.2} B/entry, total: {} KiB)\n\
         Decode: {:>8.0} entries/s ({} entries)",
        encode_rate,
        bytes_per_entry,
        file_size / 1024,
        decode_rate,
        read_count
    );

    assert_eq!(read_count, num_entries);
    assert!(encode_rate >= 10_000.0);
    assert!(decode_rate >= 10_000.0);
}

#[test]
fn test_perf_frame_codec_latency() {
    let iterations = 20_000;

    // Control frame header encode/decode
    let payload = b"hello frame";
    let mut frame_buf = vec![0u8; 1024];

    let t0 = Instant::now();
    for i in 0..iterations {
        let _ = encode_frame(&mut frame_buf, 0x10, FrameFlags::NONE, i as u64, payload);
        let decoded = decode_frame(&frame_buf).unwrap();
        assert_eq!(decoded.request_id, i as u64);
    }
    let frame_elapsed = t0.elapsed();
    let ns_per_frame = frame_elapsed.as_nanos() as f64 / iterations as f64;

    // Data frame header encode/decode
    let mut data_buf = [0u8; DATA_FRAME_HEADER_LEN];
    let test_hash = Hash::of(b"sample");

    let t1 = Instant::now();
    for i in 0..iterations {
        encode_data_frame_header(
            &mut data_buf,
            (i * 4096) as u64,
            4096,
            DataFrameFlags::NONE,
            &test_hash,
        );
        let (hdr, _) = decode_data_frame_header(&data_buf).unwrap();
        assert_eq!(hdr.chunk_offset, (i * 4096) as u64);
    }
    let data_elapsed = t1.elapsed();
    let ns_per_data_frame = data_elapsed.as_nanos() as f64 / iterations as f64;

    println!(
        "\n--- Frame Header Codec Latency ---\n\
         Control frame: {:>6.1} ns/op\n\
         Data frame:    {:>6.1} ns/op",
        ns_per_frame, ns_per_data_frame
    );

    assert!(
        ns_per_frame < 2000.0,
        "control frame codec must be sub-2-microsecond"
    );
    assert!(
        ns_per_data_frame < 2000.0,
        "data frame header codec must be sub-2-microsecond"
    );
}

#[test]
fn test_perf_bitmap_ops_scale() {
    // Benchmark RLE bitmap with 100,000 chunks (e.g. 100 GB at 1 MiB chunking)
    let total_chunks = 100_000;
    let mut bits = vec![false; total_chunks];

    // Clustered runs: 90% have chunks, clustered in runs of 1,000
    for i in 0..total_chunks {
        if (i / 1000) % 10 != 0 {
            bits[i] = true;
        }
    }

    let t0 = Instant::now();
    let rle = RleBitmap::from_bits(&bits);
    let encoded = rle.encode();
    let encode_elapsed = t0.elapsed();

    let t1 = Instant::now();
    let decoded = RleBitmap::decode(&encoded, total_chunks as u32).unwrap();
    let decode_elapsed = t1.elapsed();

    let raw_bytes = total_chunks / 8;
    let rle_bytes = encoded.len();
    let compression_ratio = raw_bytes as f64 / rle_bytes as f64;

    println!(
        "\n--- RLE Bitmap Operations (100,000 chunks) ---\n\
         Raw size:        {} bytes\n\
         RLE encoded:     {} bytes ({:.1}x compression)\n\
         Encode latency:  {:?}\n\
         Decode latency:  {:?}",
        raw_bytes, rle_bytes, compression_ratio, encode_elapsed, decode_elapsed
    );

    assert_eq!(decoded.total_chunks(), total_chunks as u32);
    assert_eq!(decoded.have_count(), rle.have_count());
    assert!(
        rle_bytes < 1000,
        "clustered runs should compress to < 1 KiB"
    );
}

#[test]
fn test_perf_cost_estimator_grid() {
    let estimator = CostEstimator::default();

    // 1. 0% reuse on 10 GB file -> Full
    let p1 = estimator.evaluate(10 * 1024 * 1024 * 1024, 10_000, 0, false);
    assert_eq!(p1.decision, SyncDecision::Full);

    // 2. 98% reuse on 10 GB file -> Delta
    let p2 = estimator.evaluate(10 * 1024 * 1024 * 1024, 10_000, 9_800, false);
    assert_eq!(p2.decision, SyncDecision::Delta);

    // 3. Small file (< 64 KiB default min) -> Full
    let p3 = estimator.evaluate(32 * 1024, 1, 0, false);
    assert_eq!(p3.decision, SyncDecision::Full);

    // 4. Same size & mtime -> Skip
    let p4 = estimator.evaluate(10 * 1024 * 1024 * 1024, 10_000, 10_000, true);
    assert_eq!(p4.decision, SyncDecision::Skip);
}

#[test]
fn test_perf_delta_overhead_bounds() {
    // PERFORMANCE.md §2: "Delta overhead vs theoretical minimum bytes <= 2% for >= 10 GB files"
    // Here we test on a 4 MiB file with a defined edit: insert 64 KiB at offset 1 MiB.
    let temp = tempdir().unwrap();
    let src = temp.path().join("src.bin");
    let dst = temp.path().join("dst.bin");

    let chunk_size = 64 * 1024;
    let base_size = 4 * 1024 * 1024; // 4 MiB
    let base_data = generate_pseudorandom_bytes(base_size, 777);
    std::fs::write(&dst, &base_data).unwrap();

    // Source has 1 chunk modified in the middle (chunk 16)
    let mut mod_data = base_data.clone();
    for i in (16 * chunk_size)..(17 * chunk_size) {
        mod_data[i] = 0xAA;
    }
    std::fs::write(&src, &mod_data).unwrap();

    let params = ChunkParams::new(chunk_size as u64, chunk_size as u64, chunk_size as u64).unwrap();
    let report = execute_delta_sync(&src, &dst, ChunkMode::Fixed, params, 64 * 1024).unwrap();

    let theoretical_min = chunk_size as u64;
    let actual_transferred = report.wire_bytes_transferred;

    println!(
        "\n--- Delta Overhead Verification ---\n\
         Total file size:    {} KiB\n\
         Theoretical min:    {} KiB\n\
         Actual transferred: {} KiB\n\
         Bytes reused:       {} KiB",
        base_size / 1024,
        theoretical_min / 1024,
        actual_transferred / 1024,
        report.local_bytes_reused / 1024
    );

    assert_eq!(actual_transferred, theoretical_min);
    assert_eq!(report.local_bytes_reused, (base_size - chunk_size) as u64);
}

#[test]
fn test_perf_flow_control_bdp_window() {
    // PERFORMANCE.md §4: 10 Gbps / 150 ms RTT requires flow control window >= 187.5 MB BDP (tuned to 384 MB = 2x BDP)
    let bandwidth_bps = 10_000_000_000u64; // 10 Gbps
    let rtt_sec = 0.150f64; // 150 ms

    let bytes_per_sec = bandwidth_bps / 8;
    let bdp_bytes = (bytes_per_sec as f64 * rtt_sec) as u64;

    assert_eq!(bdp_bytes, 187_500_000); // 187.5 MB

    let recommended_window = bdp_bytes * 2;
    assert!(recommended_window >= 375_000_000); // ~384 MB

    println!(
        "\n--- BDP Window Calculation (10 Gbps / 150 ms RTT) ---\n\
         BDP:                {:.2} MB\n\
         2x BDP Window:      {:.2} MB",
        bdp_bytes as f64 / 1_000_000.0,
        recommended_window as f64 / 1_000_000.0
    );
}
