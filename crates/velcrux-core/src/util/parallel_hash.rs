//! Multi-core parallel hashing and batched chunk verification engine.
//!
//! Enforces `CLAUDE.md` §1: 100% safe Rust (`#![forbid(unsafe_code)]`).
//!
//! Provides:
//! - [`ParallelHasher`]: Multi-threaded chunk hashing and verification using `std::thread::scope`
//!   to borrow slices with zero copies and zero heap reallocations.
//! - [`BatchHashResult`]: Outcomes of multi-chunk batch hashing and integrity verification.
//! - Tree hashing for multi-megabyte payloads saturating multi-core SIMD pipelines.

use std::num::NonZeroUsize;
use std::thread;

use crate::error::{ProtocolError, Result, VelcruxError};
use crate::util::hash::{Hash, CHUNK_HASH_BYTES};

/// Configuration and worker pool controller for parallel hashing.
#[derive(Debug, Clone)]
pub struct ParallelHasher {
    /// Number of worker threads to utilize for batch operations.
    concurrency: usize,
    /// Minimum byte threshold before splitting a single payload into parallel sub-hashes.
    tree_threshold_bytes: usize,
}

impl Default for ParallelHasher {
    fn default() -> Self {
        let detected = thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(4);
        Self::new(detected)
    }
}

impl ParallelHasher {
    /// Create a new parallel hasher with a specified worker concurrency limit.
    pub fn new(concurrency: usize) -> Self {
        let concurrency = concurrency.clamp(1, 128);
        Self {
            concurrency,
            tree_threshold_bytes: 4 * 1024 * 1024, // 4 MiB default
        }
    }

    /// Set minimum byte threshold for single-buffer parallel tree hashing.
    pub fn with_tree_threshold(mut self, threshold_bytes: usize) -> Self {
        self.tree_threshold_bytes = threshold_bytes.max(64 * 1024);
        self
    }

    /// Return active concurrency level.
    pub fn concurrency(&self) -> usize {
        self.concurrency
    }

    /// Compute cryptographic BLAKE3 hashes for an ordered slice of chunk buffers in parallel.
    ///
    /// Borrows all chunk slices directly via scoped threads without allocations or cloning.
    /// Preserves exact input ordering in the returned `Vec<Hash>`.
    pub fn hash_chunks_batched(&self, chunks: &[&[u8]]) -> Vec<Hash> {
        if chunks.is_empty() {
            return Vec::new();
        }

        if chunks.len() == 1 || self.concurrency <= 1 {
            return chunks.iter().map(|c| Hash::of(c)).collect();
        }

        let num_workers = self.concurrency.min(chunks.len());
        let chunk_slice = chunks;
        let mut results = vec![Hash::ZERO; chunk_slice.len()];

        thread::scope(|s| {
            let chunk_count = chunk_slice.len();
            let step = chunk_count.div_ceil(num_workers);

            let out_slices = results.chunks_mut(step);

            for (worker_idx, out_chunk) in out_slices.enumerate() {
                let start_idx = worker_idx * step;
                let end_idx = (start_idx + out_chunk.len()).min(chunk_count);
                let input_sub = &chunk_slice[start_idx..end_idx];

                s.spawn(move || {
                    for (i, &buf) in input_sub.iter().enumerate() {
                        out_chunk[i] = Hash::of(buf);
                    }
                });
            }
        });

        results
    }

    /// Verify an ordered batch of `(chunk_data, expected_hash)` pairs in parallel.
    ///
    /// Returns `Ok(())` if all hashes match. If any chunk is corrupted, returns
    /// `Err(VelcruxError::Protocol(ProtocolError::ChecksumMismatch))` with the index of the first failure.
    pub fn verify_chunks_batched(&self, items: &[(&[u8], Hash)]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }

        if items.len() == 1 || self.concurrency <= 1 {
            for (idx, (data, expected)) in items.iter().enumerate() {
                let actual = Hash::of(data);
                if actual != *expected {
                    return Err(VelcruxError::Protocol(ProtocolError::ChecksumMismatch {
                        chunk_index: idx as u64,
                        expected: *expected,
                        actual,
                    }));
                }
            }
            return Ok(());
        }

        let num_workers = self.concurrency.min(items.len());
        let mut failure: Option<(usize, Hash, Hash)> = None;

        let step = items.len().div_ceil(num_workers);

        thread::scope(|s| {
            let mut handles = Vec::new();

            for worker_idx in 0..num_workers {
                let start_idx = worker_idx * step;
                if start_idx >= items.len() {
                    break;
                }
                let end_idx = (start_idx + step).min(items.len());
                let sub_items = &items[start_idx..end_idx];

                let handle = s.spawn(move || {
                    for (local_idx, (data, expected)) in sub_items.iter().enumerate() {
                        let actual = Hash::of(data);
                        if actual != *expected {
                            return Some((start_idx + local_idx, *expected, actual));
                        }
                    }
                    None
                });
                handles.push(handle);
            }

            for handle in handles {
                if let Ok(Some(fail)) = handle.join() {
                    if failure.is_none() || fail.0 < failure.as_ref().unwrap().0 {
                        failure = Some(fail);
                    }
                }
            }
        });

        if let Some((idx, expected, actual)) = failure {
            Err(VelcruxError::Protocol(ProtocolError::ChecksumMismatch {
                chunk_index: idx as u64,
                expected,
                actual,
            }))
        } else {
            Ok(())
        }
    }

    /// Compute a deterministic parallel tree hash over a large contiguous byte slice.
    ///
    /// Splits `data` into 1 MiB sub-blocks, computes sub-hashes concurrently across workers,
    /// and hashes the concatenated sub-hashes into a final 32-byte root hash.
    ///
    /// For inputs smaller than `tree_threshold_bytes`, transparently computes the standard single-pass hash.
    pub fn hash_tree_parallel(&self, data: &[u8]) -> Hash {
        if data.len() < self.tree_threshold_bytes || self.concurrency <= 1 {
            return Hash::of(data);
        }

        const SUB_BLOCK_SIZE: usize = 1024 * 1024; // 1 MiB sub-blocks
        let num_blocks = data.len().div_ceil(SUB_BLOCK_SIZE);

        let mut sub_hashes = vec![Hash::ZERO; num_blocks];
        let num_workers = self.concurrency.min(num_blocks);
        let step = num_blocks.div_ceil(num_workers);

        thread::scope(|s| {
            for (worker_idx, out_chunk) in sub_hashes.chunks_mut(step).enumerate() {
                let start_block = worker_idx * step;

                s.spawn(move || {
                    for (i, out_hash) in out_chunk.iter_mut().enumerate() {
                        let block_idx = start_block + i;
                        let byte_start = block_idx * SUB_BLOCK_SIZE;
                        let byte_end = (byte_start + SUB_BLOCK_SIZE).min(data.len());
                        *out_hash = Hash::of(&data[byte_start..byte_end]);
                    }
                });
            }
        });

        // Combine sub-hashes into deterministic root hash
        let mut combined = Vec::with_capacity(num_blocks * CHUNK_HASH_BYTES);
        for h in &sub_hashes {
            combined.extend_from_slice(h.as_bytes());
        }
        Hash::of(&combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_hashing_matches_scalar() {
        let hasher = ParallelHasher::new(4);
        let chunk1 = vec![1u8; 1024 * 64];
        let chunk2 = vec![2u8; 1024 * 128];
        let chunk3 = vec![3u8; 1024 * 256];
        let chunk4 = vec![4u8; 1024 * 512];

        let chunks: Vec<&[u8]> = vec![&chunk1, &chunk2, &chunk3, &chunk4];

        let parallel_hashes = hasher.hash_chunks_batched(&chunks);
        assert_eq!(parallel_hashes.len(), 4);

        for (i, &chunk) in chunks.iter().enumerate() {
            assert_eq!(parallel_hashes[i], Hash::of(chunk));
        }
    }

    #[test]
    fn test_batch_verify_success() {
        let hasher = ParallelHasher::new(4);
        let data1 = vec![0xAA; 5000];
        let data2 = vec![0xBB; 7000];
        let data3 = vec![0xCC; 9000];

        let h1 = Hash::of(&data1);
        let h2 = Hash::of(&data2);
        let h3 = Hash::of(&data3);

        let items = vec![(&data1[..], h1), (&data2[..], h2), (&data3[..], h3)];
        assert!(hasher.verify_chunks_batched(&items).is_ok());
    }

    #[test]
    fn test_batch_verify_detects_corruption() {
        let hasher = ParallelHasher::new(4);
        let data1 = vec![0xAA; 5000];
        let mut data2 = vec![0xBB; 7000];
        let data3 = vec![0xCC; 9000];

        let h1 = Hash::of(&data1);
        let h2 = Hash::of(&data2);
        let h3 = Hash::of(&data3);

        // Corrupt data2
        data2[100] ^= 0xFF;

        let items = vec![(&data1[..], h1), (&data2[..], h2), (&data3[..], h3)];
        let res = hasher.verify_chunks_batched(&items);
        assert!(res.is_err());
        match res.unwrap_err() {
            VelcruxError::Protocol(ProtocolError::ChecksumMismatch { chunk_index, .. }) => {
                assert_eq!(chunk_index, 1);
            }
            other => panic!("expected ChecksumMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn test_tree_hash_consistency() {
        let hasher = ParallelHasher::new(4).with_tree_threshold(128 * 1024);
        let big_payload = vec![0x42; 512 * 1024]; // 512 KiB

        let h1 = hasher.hash_tree_parallel(&big_payload);
        let h2 = hasher.hash_tree_parallel(&big_payload);
        assert_eq!(h1, h2);
    }
}
