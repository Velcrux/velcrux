//! Delta synchronization engine (Milestone 7).
//!
//! Implements inventory tracking, bloom filter exchange, chunk negotiation via
//! RLE bitmaps, cost estimation (FULL vs DELTA), and streaming delta reconstruction
//! with bounded memory and atomic commit (`ARCHITECTURE.md` §7, §12).

pub mod bloom;
pub mod estimator;
pub mod inventory;
pub mod reconstruct;
pub mod rle;

pub use bloom::BloomFilter;
pub use estimator::{CostEstimator, SyncDecision, SyncPlan};
pub use inventory::{ChunkExtent, LocalInventory};
pub use reconstruct::{DeltaProgress, DeltaReconstructor};
pub use rle::{RleBitmap, RleRun};

use thiserror::Error;

/// Errors arising during delta synchronization.
#[derive(Debug, Error)]
pub enum SyncError {
    /// RLE bitmap encoding or decoding error.
    #[error("RLE bitmap error: {0}")]
    Rle(String),

    /// Bloom filter error.
    #[error("Bloom filter error: {0}")]
    Bloom(String),

    /// Local inventory error.
    #[error("Inventory error: {0}")]
    Inventory(String),

    /// Delta reconstruction error.
    #[error("Reconstruction error: {0}")]
    Reconstruction(String),

    /// Whole-file hash verification mismatch after reconstruction.
    #[error("Hash mismatch: expected {expected}, actual {actual}")]
    HashMismatch {
        /// Expected BLAKE3 digest.
        expected: String,
        /// Actual computed BLAKE3 digest.
        actual: String,
    },

    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Detailed outcome and bandwidth metrics of a delta synchronization.
#[derive(Debug, Clone, PartialEq)]
pub struct DeltaSyncReport {
    /// Strategy executed (Skip, Delta, or Full).
    pub decision: SyncDecision,
    /// Total logical size of the synchronized file in bytes.
    pub total_bytes: u64,
    /// Wire bytes transferred.
    pub wire_bytes_transferred: u64,
    /// Bytes reused from local existing file.
    pub local_bytes_reused: u64,
    /// Number of chunks transferred over the wire.
    pub wire_chunks_count: usize,
    /// Number of chunks reused locally.
    pub local_chunks_count: usize,
    /// Total chunks in the file.
    pub total_chunks: usize,
    /// Final verified whole-file BLAKE3 hash.
    pub whole_file_hash: crate::util::Hash,
}

/// Execute end-to-end delta synchronization between a source file and a destination file.
///
/// If `dst_path` exists, indexes its inventory, exchanges Bloom filter hints,
/// queries chunk presence, generates RLE bitmaps, evaluates cost (Delta vs Full),
/// transfers only missing chunks, verifies the whole-file BLAKE3 digest, and
/// atomically commits to `dst_path`.
pub fn execute_delta_sync<P1: AsRef<std::path::Path>, P2: AsRef<std::path::Path>>(
    src_path: P1,
    dst_path: P2,
    mode: crate::chunking::ChunkMode,
    params: crate::chunking::ChunkParams,
    read_buffer_size: usize,
) -> Result<DeltaSyncReport, SyncError> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use crate::chunking::ChunkEngine;
    use crate::protocol::message::{ChunkQuery, ChunkResponse, InventoryHint};
    use crate::util::TransferId;

    let src = src_path.as_ref();
    let dst = dst_path.as_ref();

    let src_file = File::open(src)?;
    let src_meta = src_file.metadata()?;
    let src_size = src_meta.len();

    // 1. Check if destination file exists and build local inventory
    let dst_inventory = if dst.exists() {
        Some(LocalInventory::from_file(dst, mode, params, read_buffer_size)?)
    } else {
        None
    };

    // 2. Scan source file with ChunkEngine to identify chunks and whole-file hash
    let mut src_reader = std::io::BufReader::with_capacity(read_buffer_size.max(64 * 1024), File::open(src)?);
    let mut src_chunks = Vec::new();
    let mut current_offset = 0u64;

    let (src_whole_hash, _) = ChunkEngine::chunk_reader(
        &mut src_reader,
        mode,
        params,
        read_buffer_size,
        |desc, _payload| {
            if let Some(hash) = desc.hash {
                src_chunks.push((current_offset, desc.length, hash));
            }
            current_offset += desc.length;
            Ok(())
        },
    ).map_err(|e| SyncError::Reconstruction(format!("failed to scan source file: {e}")))?;

    let total_chunks = src_chunks.len();

    // 3. Fast-path: check if destination whole-file hash matches source exactly
    if let Some(ref inv) = dst_inventory {
        if inv.whole_hash() == Some(src_whole_hash) && inv.total_bytes() == src_size {
            return Ok(DeltaSyncReport {
                decision: SyncDecision::Skip,
                total_bytes: src_size,
                wire_bytes_transferred: 0,
                local_bytes_reused: src_size,
                wire_chunks_count: 0,
                local_chunks_count: total_chunks,
                total_chunks,
                whole_file_hash: src_whole_hash,
            });
        }
    }

    // 4. Negotiate chunks using InventoryHint, ChunkQuery, and ChunkResponse
    let (decision, have_status) = if let Some(ref inv) = dst_inventory {
        let tid = TransferId::generate();
        let bloom = inv.create_bloom_filter(0.01);
        let _hint = InventoryHint {
            transfer_id: tid,
            filter_bits: bloom.num_bits(),
            num_hashes: bloom.num_hashes(),
            bitset: bloom.to_bytes(),
        };

        // Query all chunk hashes
        let query_hashes: Vec<_> = src_chunks.iter().map(|(_, _, h)| *h).collect();
        let _query = ChunkQuery {
            transfer_id: tid,
            query_seq: 1,
            chunk_hashes: query_hashes.clone(),
        };

        // Destination checks against inventory
        let mut have_bits = Vec::with_capacity(query_hashes.len());
        for h in &query_hashes {
            have_bits.push(inv.contains(h));
        }

        let rle = RleBitmap::from_bits(&have_bits);
        let resp = ChunkResponse {
            transfer_id: tid,
            query_seq: 1,
            total_chunks: rle.total_chunks(),
            have_count: rle.have_count(),
            rle_bitmap: rle.encode(),
        };

        // Sender decodes response
        let decoded_rle = RleBitmap::decode(&resp.rle_bitmap, resp.total_chunks)?;
        let bits = decoded_rle.to_bits();

        let plan = CostEstimator::default().evaluate(
            src_size,
            total_chunks,
            decoded_rle.have_count() as usize,
            false,
        );

        (plan.decision, Some((bits, inv)))
    } else {
        (SyncDecision::Full, None)
    };

    // 5. Staging path
    let staging_path = dst.with_extension(format!(
        "{}.velcrux-partial",
        dst.extension().and_then(|e| e.to_str()).unwrap_or("dat")
    ));

    let mut reconstructor = DeltaReconstructor::new(
        dst.to_path_buf(),
        staging_path,
        src_whole_hash,
        src_size,
        total_chunks,
    )?;

    let mut wire_bytes_transferred = 0u64;
    let mut local_bytes_reused = 0u64;
    let mut wire_chunks_count = 0usize;
    let mut local_chunks_count = 0usize;

    let mut src_f = File::open(src)?;

    match (decision, have_status) {
        (SyncDecision::Delta, Some((bits, inv))) => {
            let mut dst_f = File::open(dst)?;
            let mut read_buf = vec![0u8; params.max as usize];

            for (i, &(offset, length, hash)) in src_chunks.iter().enumerate() {
                let have = bits.get(i).copied().unwrap_or(false);
                if have {
                    if let Some(extent) = inv.lookup(&hash) {
                        reconstructor.copy_local_chunk(&mut dst_f, extent.offset, offset, length)?;
                        local_bytes_reused += length;
                        local_chunks_count += 1;
                        continue;
                    }
                }

                // Chunk must be sent over wire
                src_f.seek(SeekFrom::Start(offset))?;
                let slice = &mut read_buf[..length as usize];
                src_f.read_exact(slice)?;
                reconstructor.write_wire_chunk(offset, slice)?;
                wire_bytes_transferred += length;
                wire_chunks_count += 1;
            }
        }
        _ => {
            // Full sync: transfer all chunks from source
            let mut read_buf = vec![0u8; params.max as usize];
            for &(offset, length, _) in &src_chunks {
                src_f.seek(SeekFrom::Start(offset))?;
                let slice = &mut read_buf[..length as usize];
                src_f.read_exact(slice)?;
                reconstructor.write_wire_chunk(offset, slice)?;
                wire_bytes_transferred += length;
                wire_chunks_count += 1;
            }
        }
    }

    reconstructor.verify_and_commit()?;

    Ok(DeltaSyncReport {
        decision,
        total_bytes: src_size,
        wire_bytes_transferred,
        local_bytes_reused,
        wire_chunks_count,
        local_chunks_count,
        total_chunks,
        whole_file_hash: src_whole_hash,
    })
}

