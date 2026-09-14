//! Streaming manifest reader (`ARCHITECTURE.md` §3, `ADR-005`).
//!
//! Iterates over manifest batches, decompresses with zstd under bounded memory
//! (`MAX_BATCH_DECOMPRESSED_BYTES` defense against decompression bombs),
//! decodes canonical `FileEntry` structs, and verifies the final whole-manifest
//! BLAKE3 hash against the declared `manifest_hash`.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};



use crate::error::{ProtocolError, Result, VelcruxError};
use crate::manifest::codec::decode_file_entry;
use crate::manifest::entry::FileEntry;
use crate::manifest::writer::{SPILL_MAGIC, SPILL_VERSION};
use crate::protocol::limits::{
    MANIFEST_BATCH_SIZE, MAX_BATCH_DECOMPRESSED_BYTES, MAX_MANIFEST_BYTES, MAX_MANIFEST_ENTRIES,
};
use crate::protocol::message::ManifestBatch;
use crate::util::Hash;

/// Streaming reader for a manifest stored in a spill file.
pub struct ManifestReader {
    reader: BufReader<File>,
    path: PathBuf,
    expected_hash: Hash,
    hasher: blake3::Hasher,
    current_decompressed: Vec<u8>,
    current_cursor: usize,
    entries_remaining_in_batch: u32,
    total_entries_read: u64,
    total_manifest_bytes: u64,
    finished: bool,
}

impl ManifestReader {
    /// Open a manifest spill file for streaming reading.
    pub fn open(path: impl AsRef<Path>, expected_hash: Hash) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let mut reader = BufReader::new(file);

        // Read header
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != SPILL_MAGIC {
            return Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(
                "invalid spill file magic".into(),
            )));
        }

        let mut version = [0u8; 1];
        reader.read_exact(&mut version)?;
        if version[0] != SPILL_VERSION {
            return Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(
                format!("unsupported spill file version {}", version[0]),
            )));
        }

        Ok(Self {
            reader,
            path,
            expected_hash,
            hasher: blake3::Hasher::new(),
            current_decompressed: Vec::new(),
            current_cursor: 0,
            entries_remaining_in_batch: 0,
            total_entries_read: 0,
            total_manifest_bytes: 0,
            finished: false,
        })
    }

    /// Read the next [`FileEntry`].
    ///
    /// Returns `Ok(None)` at clean EOF after validating the whole-manifest BLAKE3 digest.
    pub fn next_entry(&mut self) -> Result<Option<FileEntry>> {
        if self.finished {
            return Ok(None);
        }

        while self.entries_remaining_in_batch == 0 {
            // Read next batch from spill file
            let mut header = [0u8; 16]; // batch_index (8) + entry_count (4) + comp_len (4)
            match self.reader.read_exact(&mut header) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Reached EOF: verify BLAKE3 hash
                    self.finished = true;
                    let computed = self.hasher.finalize();
                    if computed.as_bytes() != self.expected_hash.as_bytes() {
                        return Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(
                            format!(
                                "manifest hash mismatch: computed {}, expected {}",
                                Hash::from_bytes(computed.as_bytes()).unwrap(),
                                self.expected_hash
                            ),
                        )));
                    }
                    return Ok(None);
                }
                Err(e) => return Err(VelcruxError::Io(e)),
            }

            let _batch_index = u64::from_le_bytes(header[0..8].try_into().unwrap());
            let entry_count = u32::from_le_bytes(header[8..12].try_into().unwrap());
            let comp_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;

            if entry_count as usize > MANIFEST_BATCH_SIZE {
                return Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(
                    format!("entry count {entry_count} exceeds MANIFEST_BATCH_SIZE"),
                )));
            }

            let mut compressed = vec![0u8; comp_len];
            self.reader.read_exact(&mut compressed)?;

            // Decompress batch with decompression bomb protection
            let decompressed = decompress_batch(&compressed)?;
            self.total_manifest_bytes += decompressed.len() as u64;
            if self.total_manifest_bytes > MAX_MANIFEST_BYTES {
                return Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(
                    format!("manifest raw bytes exceeded limit {MAX_MANIFEST_BYTES}"),
                )));
            }

            self.current_decompressed = decompressed;
            self.current_cursor = 0;
            self.entries_remaining_in_batch = entry_count;
        }

        if self.total_entries_read >= MAX_MANIFEST_ENTRIES {
            return Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(
                format!("manifest entry count exceeded {MAX_MANIFEST_ENTRIES}"),
            )));
        }

        let slice = &self.current_decompressed[self.current_cursor..];
        let (entry, consumed) = decode_file_entry(slice).map_err(VelcruxError::Protocol)?;

        // Update running whole-manifest hash over canonical bytes
        self.hasher.update(&slice[..consumed]);
        self.current_cursor += consumed;
        self.entries_remaining_in_batch -= 1;
        self.total_entries_read += 1;

        Ok(Some(entry))
    }

    /// Return total entries yielded so far.
    pub fn entries_read(&self) -> u64 {
        self.total_entries_read
    }
}

/// Helper to decode entries from an in-memory `ManifestBatch` message.
pub struct ManifestBatchDecoder {
    expected_hash: Hash,
    hasher: blake3::Hasher,
    total_entries_read: u64,
    total_manifest_bytes: u64,
}

impl ManifestBatchDecoder {
    /// Create a new batch decoder.
    pub fn new(expected_hash: Hash) -> Self {
        Self {
            expected_hash,
            hasher: blake3::Hasher::new(),
            total_entries_read: 0,
            total_manifest_bytes: 0,
        }
    }

    /// Decode entries from a single [`ManifestBatch`].
    pub fn decode_batch(&mut self, batch: &ManifestBatch) -> Result<Vec<FileEntry>> {
        let decompressed = decompress_batch(&batch.compressed_payload)?;
        self.total_manifest_bytes += decompressed.len() as u64;
        if self.total_manifest_bytes > MAX_MANIFEST_BYTES {
            return Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(
                format!("manifest raw bytes exceeded limit {MAX_MANIFEST_BYTES}"),
            )));
        }

        let mut entries = Vec::with_capacity(batch.entry_count as usize);
        let mut cursor = 0;

        for _ in 0..batch.entry_count {
            if cursor >= decompressed.len() {
                return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                    "MANIFEST_BATCH: truncated decompressed entries",
                )));
            }
            let slice = &decompressed[cursor..];
            let (entry, consumed) = decode_file_entry(slice).map_err(VelcruxError::Protocol)?;
            self.hasher.update(&slice[..consumed]);
            cursor += consumed;
            self.total_entries_read += 1;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Finalize and verify the whole-manifest BLAKE3 hash.
    pub fn finish(self) -> Result<()> {
        let computed = self.hasher.finalize();
        if computed.as_bytes() != self.expected_hash.as_bytes() {
            return Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(
                format!(
                    "manifest hash mismatch: computed {}, expected {}",
                    Hash::from_bytes(computed.as_bytes()).unwrap(),
                    self.expected_hash
                ),
            )));
        }
        Ok(())
    }
}

/// Decompress zstd-compressed batch with a strict maximum decompressed size clamp.
pub fn decompress_batch(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = zstd::Decoder::new(compressed).map_err(|_| {
        VelcruxError::Protocol(ProtocolError::Malformed("invalid zstd header"))
    })?;

    let mut out = Vec::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let n = decoder.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if out.len() + n > MAX_BATCH_DECOMPRESSED_BYTES {
            return Err(VelcruxError::Protocol(ProtocolError::InvalidManifest(
                format!("decompressed batch exceeded limit {MAX_BATCH_DECOMPRESSED_BYTES} B"),
            )));
        }
        out.extend_from_slice(&buffer[..n]);
    }

    Ok(out)
}
