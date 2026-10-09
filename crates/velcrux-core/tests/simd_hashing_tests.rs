//! Integration tests for hardware SIMD detection, vectorized scanning,
//! parallel multi-core chunk hashing, and pipelined ingestion.

use std::io::Cursor;
use velcrux_core::chunking::pipeline::PipelineConfig;
use velcrux_core::chunking::{ChunkMode, ChunkParams, PipelinedChunker};
use velcrux_core::error::{ProtocolError, VelcruxError};
use velcrux_core::util::hash::Hash;
use velcrux_core::util::parallel_hash::ParallelHasher;
use velcrux_core::util::simd::{SimdFeatures, VectorizedScanner};

#[test]
fn test_simd_features_host_detection() {
    let features = SimdFeatures::detect();
    println!("Host SIMD Profile: {}", features.description());
    assert!(!features.arch.is_empty());

    #[cfg(target_arch = "x86_64")]
    assert_eq!(features.arch, "x86_64");

    #[cfg(target_arch = "aarch64")]
    assert_eq!(features.arch, "aarch64");

    let desc = features.description();
    assert!(desc.contains(features.arch));
}

#[test]
fn test_vectorized_scanner_comprehensive() {
    // 1. Boundary sizes for zero buffers
    for size in [
        0, 1, 3, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 512, 4096, 65536,
    ] {
        let buf = vec![0u8; size];
        assert!(
            VectorizedScanner::is_all_zeros(&buf),
            "expected all zeros for size {size}"
        );
        assert_eq!(VectorizedScanner::leading_zeros_count(&buf), size);
        assert_eq!(VectorizedScanner::find_first_nonzero(&buf), None);
    }

    // 2. Nonzero bit at every boundary of a 256-byte buffer
    let mut buf = vec![0u8; 256];
    for pos in 0..256 {
        buf[pos] = 0x80;
        assert!(
            !VectorizedScanner::is_all_zeros(&buf),
            "expected non-zero at pos {pos}"
        );
        assert_eq!(VectorizedScanner::find_first_nonzero(&buf), Some(pos));
        assert_eq!(VectorizedScanner::leading_zeros_count(&buf), pos);
        buf[pos] = 0;
    }
}

#[test]
fn test_parallel_hasher_batched_matches_scalar() {
    let hasher = ParallelHasher::new(4);

    let sizes = [1024, 64 * 1024, 256 * 1024, 1024 * 1024];
    let mut raw_buffers = Vec::new();
    for (i, &sz) in sizes.iter().enumerate() {
        let mut buf = vec![0u8; sz];
        for (j, b) in buf.iter_mut().enumerate() {
            *b = ((i * 37 + j) % 256) as u8;
        }
        raw_buffers.push(buf);
    }

    let slices: Vec<&[u8]> = raw_buffers.iter().map(|b| b.as_slice()).collect();
    let parallel_hashes = hasher.hash_chunks_batched(&slices);

    assert_eq!(parallel_hashes.len(), slices.len());
    for (i, slice) in slices.iter().enumerate() {
        let scalar_hash = Hash::of(slice);
        assert_eq!(
            parallel_hashes[i], scalar_hash,
            "chunk {i} parallel hash differs from scalar"
        );
    }
}

#[test]
fn test_parallel_hasher_batch_verification() {
    let hasher = ParallelHasher::new(4);

    let mut buffers = Vec::new();
    let mut pairs = Vec::new();

    for i in 0..8 {
        let buf = vec![(i * 17) as u8; 32 * 1024];
        let hash = Hash::of(&buf);
        buffers.push(buf);
        pairs.push(hash);
    }

    let items: Vec<(&[u8], Hash)> = buffers
        .iter()
        .zip(pairs.iter())
        .map(|(b, &h)| (b.as_slice(), h))
        .collect();

    // Verification succeeds
    assert!(hasher.verify_chunks_batched(&items).is_ok());

    // Corrupt chunk index 5
    let mut corrupted_buffers = buffers.clone();
    corrupted_buffers[5][100] ^= 0x01;

    let corrupted_items: Vec<(&[u8], Hash)> = corrupted_buffers
        .iter()
        .zip(pairs.iter())
        .map(|(b, &h)| (b.as_slice(), h))
        .collect();

    let err = hasher.verify_chunks_batched(&corrupted_items);
    assert!(err.is_err());
    match err.unwrap_err() {
        VelcruxError::Protocol(ProtocolError::ChecksumMismatch { chunk_index, .. }) => {
            assert_eq!(chunk_index, 5);
        }
        other => panic!("expected ChecksumMismatch, got: {other:?}"),
    }
}

#[test]
fn test_parallel_tree_hashing_large_buffer() {
    let hasher = ParallelHasher::new(4).with_tree_threshold(1024 * 1024);

    let mut large_buffer = vec![0u8; 8 * 1024 * 1024]; // 8 MiB
    for (i, b) in large_buffer.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let h1 = hasher.hash_tree_parallel(&large_buffer);
    let h2 = hasher.hash_tree_parallel(&large_buffer);
    assert_eq!(h1, h2, "tree hash must be deterministic");

    // Mutation alters tree hash
    large_buffer[4 * 1024 * 1024] ^= 0x55;
    let h3 = hasher.hash_tree_parallel(&large_buffer);
    assert_ne!(h1, h3, "tree hash must change on mutated byte");
}

#[tokio::test]
async fn test_pipelined_chunker_end_to_end() {
    let config = PipelineConfig {
        mode: ChunkMode::FastCdc,
        params: ChunkParams {
            min: 4096,
            target: 16384,
            max: 65536,
        },
        read_buffer_size: 8192,
        channel_capacity: 16,
        worker_concurrency: 4,
    };
    let pipeline = PipelinedChunker::new(config);

    let mut stream_data = vec![0u8; 256 * 1024];
    for (i, b) in stream_data.iter_mut().enumerate() {
        *b = ((i * 13) % 255) as u8;
    }

    // Process from slice
    let slice_chunks = pipeline.process_slice(&stream_data).unwrap();
    assert!(!slice_chunks.is_empty());

    let mut slice_recon = Vec::new();
    for c in &slice_chunks {
        assert_eq!(c.hash, Hash::of(&c.data));
        slice_recon.extend_from_slice(&c.data);
    }
    assert_eq!(slice_recon, stream_data);

    // Stream from AsyncRead cursor
    let cursor = Cursor::new(stream_data.clone());
    let mut rx = pipeline.stream_reader(cursor);

    let mut stream_recon = Vec::new();
    let mut stream_chunks = Vec::new();
    while let Some(res) = rx.recv().await {
        let chunk = res.unwrap();
        assert_eq!(chunk.hash, Hash::of(&chunk.data));

        stream_recon.extend_from_slice(&chunk.data);
        stream_chunks.push(chunk);
    }

    assert_eq!(stream_recon, stream_data);
    assert_eq!(stream_chunks.len(), slice_chunks.len());
}
