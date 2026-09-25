//! Delta synchronization engine (Milestone 7).
//!
//! Implements inventory tracking, bloom filter exchange, chunk negotiation via
//! RLE bitmaps, cost estimation (FULL vs DELTA), and streaming delta reconstruction
//! with bounded memory and atomic commit (`ARCHITECTURE.md` §7, §12).

pub mod bloom;
pub mod directory;
pub mod estimator;
pub mod inventory;
pub mod reconstruct;
pub mod rle;

pub use bloom::BloomFilter;
pub use directory::{
    compute_file_hash, execute_directory_sync, plan_directory_diff, plan_directory_sync,
    recv_directory_manifest, resume_interrupted_commit, scan_dir_entries, send_directory_manifest,
    DeleteMode, DirectoryDiffSummary, DirectoryPlan, DirectorySyncOptions, DirectorySyncResult,
    FileAction, FileActionType, ScannedEntry,
};
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

/// Detailed outcome and bandwidth metrics of a delta or dedup synchronization.
#[derive(Debug, Clone, PartialEq)]
pub struct DeltaSyncReport {
    /// Strategy executed (Skip, Delta, or Full).
    pub decision: SyncDecision,
    /// Total logical size of the synchronized file in bytes.
    pub total_bytes: u64,
    /// Wire bytes transferred.
    pub wire_bytes_transferred: u64,
    /// Bytes reused from local existing file at target path.
    pub local_bytes_reused: u64,
    /// Bytes reused from the content-addressed chunk store.
    pub store_bytes_reused: u64,
    /// Bytes skipped due to sparse holes (zero transfer and zero disk allocation).
    pub sparse_bytes_skipped: u64,
    /// Number of chunks transferred over the wire.
    pub wire_chunks_count: usize,
    /// Number of chunks reused from local file.
    pub local_chunks_count: usize,
    /// Number of chunks reused from chunk store.
    pub store_chunks_count: usize,
    /// Number of sparse hole regions skipped.
    pub sparse_holes_count: usize,
    /// Total chunks in the file.
    pub total_chunks: usize,
    /// Final verified whole-file BLAKE3 hash.
    pub whole_file_hash: crate::util::Hash,
}

/// Execute end-to-end delta synchronization between a source file and a destination file.
pub fn execute_delta_sync<P1: AsRef<std::path::Path>, P2: AsRef<std::path::Path>>(
    src_path: P1,
    dst_path: P2,
    mode: crate::chunking::ChunkMode,
    params: crate::chunking::ChunkParams,
    read_buffer_size: usize,
) -> Result<DeltaSyncReport, SyncError> {
    execute_dedup_sync(src_path, dst_path, mode, params, read_buffer_size, None)
}

/// Execute end-to-end delta and deduplication synchronization between a source file
/// and a destination file, optionally consulting and populating a [`LocalChunkStore`].
pub fn execute_dedup_sync<P1: AsRef<std::path::Path>, P2: AsRef<std::path::Path>>(
    src_path: P1,
    dst_path: P2,
    mode: crate::chunking::ChunkMode,
    params: crate::chunking::ChunkParams,
    read_buffer_size: usize,
    chunk_store: Option<&crate::storage::LocalChunkStore>,
) -> Result<DeltaSyncReport, SyncError> {
    use crate::chunking::ChunkEngine;
    use crate::protocol::message::ChunkResponse;
    use crate::util::TransferId;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    let src = src_path.as_ref();
    let dst = dst_path.as_ref();

    let src_file = File::open(src)?;
    let src_meta = src_file.metadata()?;
    let src_size = src_meta.len();

    // 1. Check if destination file exists and build local inventory
    let dst_inventory = if dst.exists() {
        Some(LocalInventory::from_file(
            dst,
            mode,
            params,
            read_buffer_size,
        )?)
    } else {
        None
    };

    // 2. Scan source file with ChunkEngine to identify chunks and whole-file hash
    let mut src_reader =
        std::io::BufReader::with_capacity(read_buffer_size.max(64 * 1024), File::open(src)?);
    let mut src_chunks = Vec::new();
    let mut current_offset = 0u64;

    let (src_whole_hash, _) = ChunkEngine::chunk_reader(
        &mut src_reader,
        mode,
        params,
        read_buffer_size,
        |desc, _payload| {
            src_chunks.push((current_offset, desc.length, desc.hash));
            current_offset += desc.length;
            Ok(())
        },
    )
    .map_err(|e| SyncError::Reconstruction(format!("failed to scan source file: {e}")))?;

    let total_chunks = src_chunks.len();

    // 3. Fast-path: check if destination whole-file hash matches source exactly
    if let Some(ref inv) = dst_inventory {
        if inv.whole_hash() == Some(src_whole_hash) && inv.total_bytes() == src_size {
            return Ok(DeltaSyncReport {
                decision: SyncDecision::Skip,
                total_bytes: src_size,
                wire_bytes_transferred: 0,
                local_bytes_reused: src_size,
                store_bytes_reused: 0,
                sparse_bytes_skipped: 0,
                wire_chunks_count: 0,
                local_chunks_count: total_chunks,
                store_chunks_count: 0,
                sparse_holes_count: 0,
                total_chunks,
                whole_file_hash: src_whole_hash,
            });
        }
    }

    // 4. Negotiate chunks using InventoryHint, ChunkQuery, and ChunkResponse
    let tid = TransferId::generate();

    // Determine presence in destination file, chunk store, or sparse hole
    let mut have_bits = Vec::with_capacity(src_chunks.len());
    let mut have_sources = Vec::with_capacity(src_chunks.len()); // 0 = wire, 1 = local file, 2 = chunk store, 3 = sparse hole

    for &(_, _, maybe_hash) in &src_chunks {
        if let Some(h) = maybe_hash {
            if let Some(ref inv) = dst_inventory {
                if inv.contains(&h) {
                    have_bits.push(true);
                    have_sources.push(1u8);
                    continue;
                }
            }
            if let Some(store) = chunk_store {
                if store.contains_sync(&h) {
                    have_bits.push(true);
                    have_sources.push(2u8);
                    continue;
                }
            }
            have_bits.push(false);
            have_sources.push(0u8);
        } else {
            // Sparse hole
            have_bits.push(true);
            have_sources.push(3u8);
        }
    }

    let rle = RleBitmap::from_bits(&have_bits);
    let resp = ChunkResponse {
        transfer_id: tid,
        query_seq: 1,
        total_chunks: rle.total_chunks(),
        have_count: rle.have_count(),
        rle_bitmap: rle.encode(),
    };

    let decoded_rle = RleBitmap::decode(&resp.rle_bitmap, resp.total_chunks)?;
    let plan = CostEstimator::default().evaluate(
        src_size,
        total_chunks,
        decoded_rle.have_count() as usize,
        false,
    );

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
    let mut store_bytes_reused = 0u64;
    let mut sparse_bytes_skipped = 0u64;
    let mut wire_chunks_count = 0usize;
    let mut local_chunks_count = 0usize;
    let mut store_chunks_count = 0usize;
    let mut sparse_holes_count = 0usize;

    let mut src_f = File::open(src)?;
    let mut dst_f = if dst.exists() {
        Some(File::open(dst)?)
    } else {
        None
    };

    match plan.decision {
        SyncDecision::Delta => {
            let mut read_buf = vec![0u8; params.max as usize];

            for (i, &(offset, length, maybe_hash)) in src_chunks.iter().enumerate() {
                let source = have_sources[i];
                if source == 3 || maybe_hash.is_none() {
                    // Sparse hole: skip without disk write or wire transfer
                    reconstructor.skip_hole(length)?;
                    sparse_bytes_skipped += length;
                    sparse_holes_count += 1;
                    continue;
                }
                let hash = maybe_hash.unwrap();
                if source == 1 {
                    if let Some(ref inv) = dst_inventory {
                        if let Some(extent) = inv.lookup(&hash) {
                            if let Some(ref mut df) = dst_f {
                                reconstructor.copy_local_chunk(
                                    df,
                                    extent.offset,
                                    offset,
                                    length,
                                )?;
                                local_bytes_reused += length;
                                local_chunks_count += 1;
                                continue;
                            }
                        }
                    }
                } else if source == 2 {
                    if let Some(store) = chunk_store {
                        reconstructor.copy_chunk_from_store(store, &hash, offset)?;
                        store_bytes_reused += length;
                        store_chunks_count += 1;
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

                if let Some(store) = chunk_store {
                    let _ = store.put_sync(&hash, slice);
                }
            }
        }
        _ => {
            // Full sync: transfer non-hole chunks from source
            let mut read_buf = vec![0u8; params.max as usize];
            for &(offset, length, maybe_hash) in &src_chunks {
                if let Some(hash) = maybe_hash {
                    src_f.seek(SeekFrom::Start(offset))?;
                    let slice = &mut read_buf[..length as usize];
                    src_f.read_exact(slice)?;
                    reconstructor.write_wire_chunk(offset, slice)?;
                    wire_bytes_transferred += length;
                    wire_chunks_count += 1;

                    if let Some(store) = chunk_store {
                        let _ = store.put_sync(&hash, slice);
                    }
                } else {
                    // Sparse hole: skip without disk write or wire transfer
                    reconstructor.skip_hole(length)?;
                    sparse_bytes_skipped += length;
                    sparse_holes_count += 1;
                }
            }
        }
    }

    reconstructor.verify_and_commit()?;

    Ok(DeltaSyncReport {
        decision: plan.decision,
        total_bytes: src_size,
        wire_bytes_transferred,
        local_bytes_reused,
        store_bytes_reused,
        sparse_bytes_skipped,
        wire_chunks_count,
        local_chunks_count,
        store_chunks_count,
        sparse_holes_count,
        total_chunks,
        whole_file_hash: src_whole_hash,
    })
}
