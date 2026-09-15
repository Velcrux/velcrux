//! Standalone Microbenchmark Suite for velcrux (`docs/PERFORMANCE.md` §3).
//!
//! Implements the 9 microbenchmarks:
//! - hash_blake3
//! - hash_sha256
//! - chunk_fixed
//! - chunk_cdc
//! - manifest_encode
//! - manifest_decode
//! - frame_codec
//! - bitmap_ops
//! - estimator

use std::time::Instant;
use tempfile::tempdir;

use blake3::Hasher as Blake3Hasher;
use sha2::{Digest, Sha256};

use velcrux_core::chunking::{ChunkEngine, ChunkMode, ChunkParams};
use velcrux_core::manifest::{ChunkDesc, FileEntry, ManifestReader, ManifestWriter};
use velcrux_core::protocol::frame::{
    decode_data_frame_header, decode_frame, encode_data_frame_header, encode_frame,
    DataFrameFlags, FrameFlags, DATA_FRAME_HEADER_LEN,
};
use velcrux_core::storage::VPath;
use velcrux_core::sync::{CostEstimator, RleBitmap};
use velcrux_core::util::Hash;

fn generate_data(size: usize, seed: u64) -> Vec<u8> {
    let mut data = vec![0u8; size];
    let mut state = seed.wrapping_add(0x9E3779B97F4A7C15);
    for chunk in data.chunks_mut(8) {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let bytes = state.to_le_bytes();
        let len = chunk.len();
        chunk.copy_from_slice(&bytes[..len]);
    }
    data
}

fn bench_hash_blake3() {
    let size = 32 * 1024 * 1024; // 32 MiB
    let payload = generate_data(size, 1);
    let iterations = 10;

    let t0 = Instant::now();
    for _ in 0..iterations {
        let mut hasher = Blake3Hasher::new();
        hasher.update(&payload);
        let _ = hasher.finalize();
    }
    let elapsed = t0.elapsed();
    let gbps = (size as f64 * iterations as f64 / elapsed.as_secs_f64()) / 1_000_000_000.0;
    println!("  hash_blake3:      {:>7.2} GB/s ({:?} / 32MB)", gbps, elapsed / iterations);
}

fn bench_hash_sha256() {
    let size = 32 * 1024 * 1024; // 32 MiB
    let payload = generate_data(size, 2);
    let iterations = 10;

    let t0 = Instant::now();
    for _ in 0..iterations {
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        let _ = hasher.finalize();
    }
    let elapsed = t0.elapsed();
    let gbps = (size as f64 * iterations as f64 / elapsed.as_secs_f64()) / 1_000_000_000.0;
    println!("  hash_sha256:      {:>7.2} GB/s ({:?} / 32MB)", gbps, elapsed / iterations);
}

fn bench_chunk_fixed() {
    let size = 16 * 1024 * 1024; // 16 MiB
    let payload = generate_data(size, 3);
    let params = ChunkParams::new(1024 * 1024, 1024 * 1024, 1024 * 1024).unwrap();

    let t0 = Instant::now();
    let iterations = 5;
    for _ in 0..iterations {
        let _ = ChunkEngine::chunk_reader(
            &payload[..],
            ChunkMode::Fixed,
            params,
            64 * 1024,
            |_desc, _data| Ok(()),
        );
    }
    let elapsed = t0.elapsed();
    let gbps = (size as f64 * iterations as f64 / elapsed.as_secs_f64()) / 1_000_000_000.0;
    println!("  chunk_fixed:      {:>7.2} GB/s (1 MiB fixed)", gbps);
}

fn bench_chunk_cdc() {
    let size = 16 * 1024 * 1024; // 16 MiB
    let payload = generate_data(size, 4);
    let params = ChunkParams::new(256 * 1024, 1024 * 1024, 4 * 1024 * 1024).unwrap();

    let t0 = Instant::now();
    let iterations = 5;
    for _ in 0..iterations {
        let _ = ChunkEngine::chunk_reader(
            &payload[..],
            ChunkMode::Cdc,
            params,
            64 * 1024,
            |_desc, _data| Ok(()),
        );
    }
    let elapsed = t0.elapsed();
    let gbps = (size as f64 * iterations as f64 / elapsed.as_secs_f64()) / 1_000_000_000.0;
    println!("  chunk_cdc:        {:>7.2} GB/s (256k-4M CDC)", gbps);
}

fn bench_manifest_encode_decode() {
    let dir = tempdir().unwrap();
    let spill_path = dir.path().join("bench.spill");
    let num_entries = 5_000;
    let chunk_params = ChunkParams::default();

    let t0 = Instant::now();
    let mut writer = ManifestWriter::new(&spill_path, chunk_params).unwrap();
    for i in 0..num_entries {
        let vpath = VPath::validate(&format!("data/file_{}.bin", i)).unwrap();
        let chunk = ChunkDesc::new(1024, Hash::ZERO);
        let entry = FileEntry::regular(vpath, 1024, 0o644, 1700000000, 0, Hash::ZERO, vec![chunk]);
        writer.add_entry(entry).unwrap();
    }
    let (begin, _, path) = writer.finish().unwrap();
    let encode_elapsed = t0.elapsed();
    let encode_rate = num_entries as f64 / encode_elapsed.as_secs_f64();

    let t1 = Instant::now();
    let mut reader = ManifestReader::open(&path, begin.manifest_hash).unwrap();
    let mut count = 0;
    while let Some(_) = reader.next_entry().unwrap() {
        count += 1;
    }
    let decode_elapsed = t1.elapsed();
    let decode_rate = count as f64 / decode_elapsed.as_secs_f64();

    println!("  manifest_encode:  {:>8.0} entries/s", encode_rate);
    println!("  manifest_decode:  {:>8.0} entries/s", decode_rate);
}

fn bench_frame_codec() {
    let iterations = 50_000;
    let payload = b"hello world";
    let mut frame_buf = vec![0u8; 1024];

    let t0 = Instant::now();
    for i in 0..iterations {
        let _ = encode_frame(&mut frame_buf, 0x10, FrameFlags::NONE, i as u64, payload);
        let _ = decode_frame(&frame_buf).unwrap();
    }
    let elapsed = t0.elapsed();
    let ns = elapsed.as_nanos() as f64 / iterations as f64;
    println!("  frame_codec:      {:>7.1} ns/op (control roundtrip)", ns);

    let mut data_buf = [0u8; DATA_FRAME_HEADER_LEN];
    let test_hash = Hash::of(b"data");
    let t1 = Instant::now();
    for i in 0..iterations {
        encode_data_frame_header(&mut data_buf, i as u64 * 4096, 4096, DataFrameFlags::NONE, &test_hash);
        let _ = decode_data_frame_header(&data_buf).unwrap();
    }
    let data_elapsed = t1.elapsed();
    let data_ns = data_elapsed.as_nanos() as f64 / iterations as f64;
    println!("  data_frame_codec: {:>7.1} ns/op (data header roundtrip)", data_ns);
}

fn bench_bitmap_ops() {
    let total_chunks = 100_000;
    let mut bits = vec![false; total_chunks];
    for i in 0..total_chunks {
        if (i / 500) % 5 != 0 {
            bits[i] = true;
        }
    }

    let t0 = Instant::now();
    let rle = RleBitmap::from_bits(&bits);
    let encoded = rle.encode();
    let encode_time = t0.elapsed();

    let t1 = Instant::now();
    let _decoded = RleBitmap::decode(&encoded, total_chunks as u32).unwrap();
    let decode_time = t1.elapsed();

    println!(
        "  bitmap_ops:       encode {:?}, decode {:?} (100k chunks, size: {} B)",
        encode_time,
        decode_time,
        encoded.len()
    );
}

fn bench_estimator() {
    let estimator = CostEstimator::default();
    let iterations = 100_000;

    let t0 = Instant::now();
    for i in 0..iterations {
        let _ = estimator.evaluate(
            10 * 1024 * 1024 * 1024,
            10_000,
            (i % 10_000) as usize,
            false,
        );
    }
    let elapsed = t0.elapsed();
    let ns = elapsed.as_nanos() as f64 / iterations as f64;
    println!("  estimator:        {:>7.1} ns/eval (grid decision)", ns);
}

fn main() {
    println!("\n=======================================================");
    println!("       velcrux Microbenchmark Suite (PERFORMANCE.md §3)  ");
    println!("=======================================================\n");

    bench_hash_blake3();
    bench_hash_sha256();
    bench_chunk_fixed();
    bench_chunk_cdc();
    bench_manifest_encode_decode();
    bench_frame_codec();
    bench_bitmap_ops();
    bench_estimator();

    println!("\n=======================================================\n");
}
