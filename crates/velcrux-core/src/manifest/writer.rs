//! Streaming manifest writer (`ARCHITECTURE.md` §3, `ADR-005`).
//!
//! Accumulates up to `MANIFEST_BATCH_SIZE` (4096) entries in memory, encodes
//! each batch to canonical binary format, compresses with zstd (level 3),
//! and appends to a spill file.
//!
//! Invariants:
//! - Memory is `O(MANIFEST_BATCH_SIZE)`, never `O(file_count)`.
//! - Running BLAKE3 digest computed over canonical uncompressed bytes.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use bytes::Bytes;

use crate::chunking::ChunkParams;
use crate::error::{ProtocolError, Result, VelcruxError};
use crate::manifest::codec::encode_file_entry;
use crate::manifest::entry::FileEntry;
use crate::protocol::limits::{MANIFEST_BATCH_SIZE, MAX_MANIFEST_BYTES, MAX_MANIFEST_ENTRIES};
use crate::protocol::message::{ManifestBatch, ManifestBegin, ManifestEnd};
use crate::util::Hash;

/// Spill file batch header magic bytes (`"VXMB"` = Velcrux Manifest Batch).
pub const SPILL_MAGIC: [u8; 4] = *b"VXMB";
/// Current spill file format version.
pub const SPILL_VERSION: u8 = 1;

/// Streaming writer for manifests.
pub struct ManifestWriter {
    /// Destination spill file writer.
    writer: BufWriter<File>,
    /// Path to the spill file.
    path: PathBuf,
    /// Chunker parameters configured for this transfer.
    chunker_params: ChunkParams,
    /// Pending entries in the current batch (max `MANIFEST_BATCH_SIZE`).
    batch_entries: Vec<FileEntry>,
    /// Buffer reused for encoding entries within a batch.
    encode_buf: Vec<u8>,
    /// Incremental whole-manifest BLAKE3 hasher over canonical entries.
    hasher: blake3::Hasher,
    /// Running total file count.
    file_count: u64,
    /// Running total data bytes.
    total_bytes: u64,
    /// Running total manifest raw bytes (uncompressed canonical bytes).
    manifest_bytes: u64,
    /// Sequential batch index counter.
    batch_index: u64,
}

impl ManifestWriter {
    /// Create a new `ManifestWriter` writing to the given `spill_path`.
    pub fn new(spill_path: impl AsRef<Path>, chunker_params: ChunkParams) -> Result<Self> {
        let path = spill_path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;

        let mut writer = BufWriter::new(file);
        // Write file-level header: MAGIC (4B) + VERSION (1B)
        writer.write_all(&SPILL_MAGIC)?;
        writer.write_all(&[SPILL_VERSION])?;

        Ok(Self {
            writer,
            path,
            chunker_params,
            batch_entries: Vec::with_capacity(MANIFEST_BATCH_SIZE),
            encode_buf: Vec::with_capacity(512 * 1024),
            hasher: blake3::Hasher::new(),
            file_count: 0,
            total_bytes: 0,
            manifest_bytes: 0,
            batch_index: 0,
        })
    }

    /// Add a [`FileEntry`] to the streaming manifest.
    ///
    /// If the current batch reaches `MANIFEST_BATCH_SIZE`, it is flushed to disk.
    pub fn add_entry(&mut self, entry: FileEntry) -> Result<()> {
        if self.file_count >= MAX_MANIFEST_ENTRIES {
            return Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(format!(
                "manifest entry count reached limit {MAX_MANIFEST_ENTRIES}"
            ))));
        }

        self.file_count += 1;
        self.total_bytes += entry.size;
        self.batch_entries.push(entry);

        if self.batch_entries.len() >= MANIFEST_BATCH_SIZE {
            self.flush_batch()?;
        }

        Ok(())
    }

    /// Flush pending entries as a zstd-compressed batch to the spill file.
    fn flush_batch(&mut self) -> Result<Option<ManifestBatch>> {
        if self.batch_entries.is_empty() {
            return Ok(None);
        }

        self.encode_buf.clear();
        for entry in &self.batch_entries {
            let start = self.encode_buf.len();
            encode_file_entry(entry, &mut self.encode_buf);
            let canonical_slice = &self.encode_buf[start..];
            self.hasher.update(canonical_slice);
            self.manifest_bytes += canonical_slice.len() as u64;
        }

        if self.manifest_bytes > MAX_MANIFEST_BYTES {
            let manifest_bytes = self.manifest_bytes;
            return Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(format!(
                "manifest size {manifest_bytes} exceeds MAX_MANIFEST_BYTES {MAX_MANIFEST_BYTES}"
            ))));
        }

        // Compress with zstd level 3 (ADR-005, ARCHITECTURE.md §11)
        let compressed = zstd::encode_all(&self.encode_buf[..], 3).map_err(|e| {
            VelcruxError::Protocol(ProtocolError::Malformed("zstd compression failed"))
        })?;

        let entry_count = self.batch_entries.len() as u32;
        let batch = ManifestBatch {
            batch_index: self.batch_index,
            entry_count,
            compressed_payload: Bytes::from(compressed),
        };

        // Write batch to spill file:
        // [batch_index: 8B LE][entry_count: 4B LE][compressed_len: 4B LE][compressed_payload]
        self.writer.write_all(&batch.batch_index.to_le_bytes())?;
        self.writer.write_all(&batch.entry_count.to_le_bytes())?;
        let comp_len = batch.compressed_payload.len() as u32;
        self.writer.write_all(&comp_len.to_le_bytes())?;
        self.writer.write_all(&batch.compressed_payload)?;

        self.batch_index += 1;
        self.batch_entries.clear();

        Ok(Some(batch))
    }

    /// Finish writing the manifest. Flushes any remaining entries, flushes disk I/O,
    /// and returns `(ManifestBegin, ManifestEnd, spill_path)`.
    pub fn finish(mut self) -> Result<(ManifestBegin, ManifestEnd, PathBuf)> {
        self.flush_batch()?;
        self.writer.flush()?;

        let blake3_digest = self.hasher.finalize();
        let manifest_hash = Hash::from_bytes(blake3_digest.as_bytes()).unwrap();

        let begin = ManifestBegin {
            file_count: self.file_count,
            total_bytes: self.total_bytes,
            chunker_params: self.chunker_params,
            manifest_hash,
        };

        let end = ManifestEnd { manifest_hash };

        Ok((begin, end, self.path))
    }

    /// Return the current entry count.
    pub fn file_count(&self) -> u64 {
        self.file_count
    }

    /// Return the current accumulated byte count across files.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}
