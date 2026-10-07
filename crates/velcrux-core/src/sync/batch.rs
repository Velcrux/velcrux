//! Small file batch container pipeline and streaming engine (Milestone 10 / Option AI).
//!
//! Optimizes directory synchronization when transferring hundreds, thousands, or
//! millions of small files (< 128 KiB). Instead of opening per-file QUIC streams and
//! incurring round-trip negotiation latency, files are packed into contiguous,
//! verified streaming containers (`VBATCH/1`) with atomic extraction and BLAKE3 verification
//! (`docs/REQUIREMENTS.md` §56, §31, §25, `docs/ARCHITECTURE.md` §1).

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::storage::VPath;
use crate::sync::directory::{FileAction, FileActionType};
use crate::sync::SyncError;
use crate::util::Hash;

/// Container magic bytes: `b"VBATCH\x01"`.
pub const VBATCH_MAGIC: &[u8; 7] = b"VBATCH\x01";

/// Default size threshold under which regular files are batched (128 KiB).
pub const DEFAULT_SMALL_FILE_THRESHOLD: u64 = 131_072;

/// Default maximum total data bytes per batch container (32 MiB).
pub const DEFAULT_BATCH_MAX_BYTES: u64 = 33_554_432;

/// Default maximum number of files per batch container (1,000).
pub const DEFAULT_BATCH_MAX_FILES: usize = 1_000;

/// Maximum allowable index JSON size (16 MiB) to prevent decompression or memory exhaustion.
pub const MAX_BATCH_INDEX_BYTES: usize = 16 * 1024 * 1024;

/// Configuration for small-file batching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmallFileBatchConfig {
    /// Whether small-file batching is active.
    pub enabled: bool,
    /// Threshold in bytes under which files are batched (default: 128 KiB).
    pub threshold_bytes: u64,
    /// Maximum payload bytes per container (default: 32 MiB).
    pub max_batch_bytes: u64,
    /// Maximum file count per container (default: 1,000).
    pub max_batch_files: usize,
}

impl Default for SmallFileBatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold_bytes: DEFAULT_SMALL_FILE_THRESHOLD,
            max_batch_bytes: DEFAULT_BATCH_MAX_BYTES,
            max_batch_files: DEFAULT_BATCH_MAX_FILES,
        }
    }
}

/// Metadata for a single file entry in a batch container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchEntryMeta {
    /// Relative virtual path (forward-slash delimited, verified against traversal).
    pub rel_path: String,
    /// Exact file payload size in bytes.
    pub size: u64,
    /// POSIX file permissions mode.
    pub mode: u32,
    /// Modification time in nanoseconds since UNIX epoch.
    pub mtime_ns: i64,
    /// Whole-file BLAKE3 hash hex string of this entry.
    pub file_hash: String,
    /// Extended attributes (key, value pairs).
    #[serde(default)]
    pub xattrs: Vec<(String, Vec<u8>)>,
}

/// A planned batch container of small files.
#[derive(Debug, Clone, PartialEq)]
pub struct SmallFileBatch {
    /// Unique batch identifier index (0-indexed).
    pub batch_id: usize,
    /// List of file actions assigned to this batch container.
    pub actions: Vec<FileAction>,
    /// Total payload data bytes across all files in this batch.
    pub total_bytes: u64,
}

/// Result of small-file batch planning.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchedSyncPlan {
    /// Planned batch containers for small files.
    pub batches: Vec<SmallFileBatch>,
    /// Actions that exceed the threshold or cannot be batched (transferred individually).
    pub individual_actions: Vec<FileAction>,
    /// Total number of small files grouped into batches.
    pub small_files_count: usize,
    /// Total number of batch containers generated.
    pub batch_containers_count: usize,
    /// Estimated roundtrips saved (small_files_count - batch_containers_count).
    pub roundtrips_saved: usize,
}

/// Planner that groups eligible small files into batch containers.
pub struct SmallFileBatchPlanner;

impl SmallFileBatchPlanner {
    /// Partition a list of directory reconciliation actions into small file batches and individual transfers.
    pub fn plan(
        src_root: &Path,
        actions: &[FileAction],
        config: &SmallFileBatchConfig,
    ) -> BatchedSyncPlan {
        if !config.enabled || actions.is_empty() {
            return BatchedSyncPlan {
                batches: Vec::new(),
                individual_actions: actions.to_vec(),
                small_files_count: 0,
                batch_containers_count: 0,
                roundtrips_saved: 0,
            };
        }

        let mut batches = Vec::new();
        let mut individual_actions = Vec::new();

        let mut current_batch_actions = Vec::new();
        let mut current_batch_bytes = 0u64;
        let mut small_files_count = 0usize;

        for action in actions {
            // Only transfer actions (Add, Modify) are candidate for batch containers
            if action.action != FileActionType::Add && action.action != FileActionType::Modify {
                individual_actions.push(action.clone());
                continue;
            }

            // Only regular files can be batched (symlinks and special files transfer individually)
            let is_regular_file = src_root
                .join(&action.rel_path)
                .symlink_metadata()
                .map(|m| m.file_type().is_file())
                .unwrap_or(false);

            if !is_regular_file {
                individual_actions.push(action.clone());
                continue;
            }

            // If file size is within small file threshold
            if action.src_size <= config.threshold_bytes {
                let would_exceed_bytes = current_batch_bytes + action.src_size
                    > config.max_batch_bytes
                    && !current_batch_actions.is_empty();
                let would_exceed_files = current_batch_actions.len() >= config.max_batch_files;

                if would_exceed_bytes || would_exceed_files {
                    let batch_id = batches.len();
                    batches.push(SmallFileBatch {
                        batch_id,
                        actions: std::mem::take(&mut current_batch_actions),
                        total_bytes: current_batch_bytes,
                    });
                    current_batch_bytes = 0;
                }

                current_batch_bytes += action.src_size;
                current_batch_actions.push(action.clone());
                small_files_count += 1;
            } else {
                individual_actions.push(action.clone());
            }
        }

        if !current_batch_actions.is_empty() {
            let batch_id = batches.len();
            batches.push(SmallFileBatch {
                batch_id,
                actions: current_batch_actions,
                total_bytes: current_batch_bytes,
            });
        }

        let batch_containers_count = batches.len();
        let roundtrips_saved = small_files_count.saturating_sub(batch_containers_count);

        BatchedSyncPlan {
            batches,
            individual_actions,
            small_files_count,
            batch_containers_count,
            roundtrips_saved,
        }
    }
}

/// Statistics from unpacking a batch container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackedBatchReport {
    /// Number of files successfully extracted and verified.
    pub files_extracted: usize,
    /// Total data bytes extracted.
    pub total_bytes: u64,
    /// List of relative paths unpacked.
    pub unpacked_paths: Vec<String>,
}

/// Writes and streams `VBATCH/1` containers.
pub struct BatchContainerWriter;

impl BatchContainerWriter {
    /// Pack a list of files from `src_root` into a `VBATCH/1` stream.
    pub fn pack<W: Write>(
        src_root: &Path,
        actions: &[FileAction],
        writer: &mut W,
    ) -> Result<u64, SyncError> {
        let mut entries = Vec::with_capacity(actions.len());
        let mut total_payload_bytes = 0u64;

        // 1. Collect and validate metadata for all entries
        for action in actions {
            let file_path = src_root.join(&action.rel_path);
            let metadata = std::fs::symlink_metadata(&file_path)?;

            let size = metadata.len();
            total_payload_bytes += size;

            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::MetadataExt;
                metadata.mode()
            };
            #[cfg(not(unix))]
            let mode = 0o100644;

            let mtime_ns = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);

            // Read extended attributes if available
            let sidecar = crate::storage::xattr_sidecar_path(&file_path);
            let xattrs = if sidecar.exists() {
                if let Ok(bytes) = std::fs::read(&sidecar) {
                    crate::storage::decode_xattrs_canonical(&bytes).unwrap_or_default()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            // Calculate BLAKE3 hash
            let hash = if size == 0 {
                Hash::of(b"")
            } else {
                let mut f = File::open(&file_path)?;
                let mut hasher = blake3::Hasher::new();
                let mut buf = [0u8; 64 * 1024];
                loop {
                    let n = f.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                Hash::from_bytes(hasher.finalize().as_bytes()).unwrap_or(Hash::ZERO)
            };

            entries.push(BatchEntryMeta {
                rel_path: action.rel_path.clone(),
                size,
                mode,
                mtime_ns,
                file_hash: hash.to_string(),
                xattrs,
            });
        }

        // 2. Serialize index table
        let index_json = serde_json::to_vec(&entries).map_err(|e| {
            SyncError::Reconstruction(format!("failed to serialize batch index: {e}"))
        })?;

        if index_json.len() > MAX_BATCH_INDEX_BYTES {
            return Err(SyncError::Reconstruction(format!(
                "batch index size {} exceeds limit {}",
                index_json.len(),
                MAX_BATCH_INDEX_BYTES
            )));
        }

        // 3. Write Container Header
        writer.write_all(VBATCH_MAGIC)?;
        writer.write_all(&[0u8])?; // Flags: 0 = uncompressed raw stream
        writer.write_all(&(entries.len() as u32).to_be_bytes())?;
        writer.write_all(&(index_json.len() as u32).to_be_bytes())?;
        writer.write_all(&total_payload_bytes.to_be_bytes())?;

        // 4. Write Index Table
        writer.write_all(&index_json)?;

        // 5. Write Data Payloads and compute whole-payload BLAKE3
        let mut overall_hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; 64 * 1024];

        for entry in &entries {
            let file_path = src_root.join(&entry.rel_path);
            let mut f = File::open(&file_path)?;
            let mut remaining = entry.size;
            let mut entry_hasher = blake3::Hasher::new();

            while remaining > 0 {
                let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
                f.read_exact(&mut buffer[..to_read])?;
                writer.write_all(&buffer[..to_read])?;
                entry_hasher.update(&buffer[..to_read]);
                overall_hasher.update(&buffer[..to_read]);
                remaining -= to_read as u64;
            }

            let computed =
                Hash::from_bytes(entry_hasher.finalize().as_bytes()).unwrap_or(Hash::ZERO);
            if computed.to_string() != entry.file_hash {
                return Err(SyncError::HashMismatch {
                    expected: entry.file_hash.clone(),
                    actual: computed.to_string(),
                });
            }
        }

        // 6. Write Trailing Checksum (32 bytes BLAKE3)
        let overall_digest = overall_hasher.finalize();
        writer.write_all(overall_digest.as_bytes())?;
        writer.flush()?;

        let total_written =
            7 + 1 + 4 + 4 + 8 + (index_json.len() as u64) + total_payload_bytes + 32;
        Ok(total_written)
    }
}

/// Reads and extracts `VBATCH/1` streaming containers into a target directory.
pub struct BatchContainerReader;

impl BatchContainerReader {
    /// Unpack a `VBATCH/1` stream into `target_staging_root`.
    pub fn unpack<R: Read>(
        reader: &mut R,
        target_staging_root: &Path,
    ) -> Result<UnpackedBatchReport, SyncError> {
        // 1. Read and verify Magic (7 bytes)
        let mut magic = [0u8; 7];
        reader.read_exact(&mut magic)?;
        if magic != *VBATCH_MAGIC {
            return Err(SyncError::Reconstruction(format!(
                "invalid batch magic: expected {:?}, got {:?}",
                VBATCH_MAGIC, magic
            )));
        }

        // 2. Read flags (1 byte)
        let mut flags = [0u8; 1];
        reader.read_exact(&mut flags)?;

        // 3. Read entry count (4 bytes), index length (4 bytes), total bytes (8 bytes)
        let mut header_buf = [0u8; 16];
        reader.read_exact(&mut header_buf)?;
        let entry_count =
            u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]])
                as usize;
        let index_len =
            u32::from_be_bytes([header_buf[4], header_buf[5], header_buf[6], header_buf[7]])
                as usize;
        let total_payload_bytes = u64::from_be_bytes([
            header_buf[8],
            header_buf[9],
            header_buf[10],
            header_buf[11],
            header_buf[12],
            header_buf[13],
            header_buf[14],
            header_buf[15],
        ]);

        if index_len > MAX_BATCH_INDEX_BYTES {
            return Err(SyncError::Reconstruction(format!(
                "batch container index length {} exceeds maximum allowed {}",
                index_len, MAX_BATCH_INDEX_BYTES
            )));
        }

        // 4. Read index table JSON
        let mut index_json = vec![0u8; index_len];
        reader.read_exact(&mut index_json)?;
        let entries: Vec<BatchEntryMeta> = serde_json::from_slice(&index_json)
            .map_err(|e| SyncError::Reconstruction(format!("corrupt batch index JSON: {e}")))?;

        if entries.len() != entry_count {
            return Err(SyncError::Reconstruction(format!(
                "batch entry count mismatch: header declared {}, index contained {}",
                entry_count,
                entries.len()
            )));
        }

        // 5. Unpack each entry with cryptographic hash check and path validation
        let mut overall_hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut unpacked_paths = Vec::with_capacity(entries.len());

        for entry in &entries {
            // Strictly validate VPath against path traversal attacks (SECURITY.md §1)
            let vpath = VPath::validate(&entry.rel_path).map_err(|e| {
                SyncError::Reconstruction(format!("batch entry path rejected: {e}"))
            })?;

            let target_path = target_staging_root.join(vpath.as_path());
            if let Some(parent) = target_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut out_file = File::create(&target_path)?;
            let mut remaining = entry.size;
            let mut entry_hasher = blake3::Hasher::new();

            while remaining > 0 {
                let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
                reader.read_exact(&mut buffer[..to_read])?;
                out_file.write_all(&buffer[..to_read])?;
                entry_hasher.update(&buffer[..to_read]);
                overall_hasher.update(&buffer[..to_read]);
                remaining -= to_read as u64;
            }

            out_file.flush()?;

            let computed =
                Hash::from_bytes(entry_hasher.finalize().as_bytes()).unwrap_or(Hash::ZERO);
            if computed.to_string() != entry.file_hash {
                // Remove damaged file immediately
                let _ = std::fs::remove_file(&target_path);
                return Err(SyncError::HashMismatch {
                    expected: entry.file_hash.clone(),
                    actual: computed.to_string(),
                });
            }

            // Restore POSIX permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(entry.mode);
                let _ = std::fs::set_permissions(&target_path, perms);
            }

            // Restore extended attributes if any
            if !entry.xattrs.is_empty() {
                let sidecar = crate::storage::xattr_sidecar_path(&target_path);
                let encoded = crate::storage::encode_xattrs_canonical(&entry.xattrs);
                let _ = std::fs::write(&sidecar, &encoded);
            }

            // Restore mtime
            if entry.mtime_ns > 0 {
                let st = UNIX_EPOCH + std::time::Duration::from_nanos(entry.mtime_ns as u64);
                if let Ok(f) = std::fs::File::open(&target_path) {
                    let times = std::fs::FileTimes::new().set_modified(st);
                    let _ = f.set_times(times);
                }
            }

            unpacked_paths.push(entry.rel_path.clone());
        }

        // 6. Verify trailing checksum
        let mut expected_trailer = [0u8; 32];
        reader.read_exact(&mut expected_trailer)?;
        let actual_digest = overall_hasher.finalize();
        if actual_digest.as_bytes() != &expected_trailer {
            return Err(SyncError::Reconstruction(
                "batch container payload trailer checksum mismatch (data tampered or corrupted)"
                    .to_string(),
            ));
        }

        Ok(UnpackedBatchReport {
            files_extracted: entries.len(),
            total_bytes: total_payload_bytes,
            unpacked_paths,
        })
    }
}
