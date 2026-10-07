//! Directory synchronization, dry-run, and transactional commit journaling (Milestone 9).
//!
//! Implements directory reconciliation (`Unchanged`, `Modify`, `Add`, `Delete`),
//! dry-run cost estimation, explicit deletion semantics (`DeleteMode::None`, `DeleteMode::DeleteAfter`),
//! and the `PLAN → STAGE → TRANSFER → VERIFY → COMMIT` pipeline with crash-resilient
//! commit journaling (`docs/ARCHITECTURE.md` §9, §12 and `docs/REQUIREMENTS.md` §58–61).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::chunking::{ChunkEngine, ChunkMode, ChunkParams};
use crate::state::{CommitJournalEntry, CommitStatus, StateStore};
use crate::storage::LocalChunkStore;
use crate::sync::cost::TransferMode;
use crate::sync::inventory::LocalInventory;
use crate::sync::reconstruct::DeltaReconstructor;
use crate::sync::SyncError;
use crate::util::{Hash, TransferId};

/// Explicit deletion mode for directory synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteMode {
    /// Safe default: never delete destination files, even if absent on source.
    None,
    /// Delete extraneous destination files only after all transfers and commits have succeeded.
    DeleteAfter,
}

impl Default for DeleteMode {
    fn default() -> Self {
        DeleteMode::None
    }
}

/// Action determined for an individual file during directory reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileActionType {
    /// File is identical on source and destination (same size and hash).
    Unchanged,
    /// File exists on both sides but contents differ.
    Modify,
    /// File exists on source but not on destination.
    Add,
    /// File exists on destination but not on source.
    Delete,
}

/// A planned file action with transfer and reuse estimations.
#[derive(Debug, Clone, PartialEq)]
pub struct FileAction {
    /// Path relative to the sync root (using forward slashes).
    pub rel_path: String,
    /// Reconciliation action type.
    pub action: FileActionType,
    /// Source file size in bytes (0 if Delete).
    pub src_size: u64,
    /// Destination file size in bytes (0 if Add).
    pub dst_size: u64,
    /// Whole-file hash on source (None if Delete).
    pub src_hash: Option<Hash>,
    /// Estimated bytes to transfer over the wire.
    pub bytes_to_transfer: u64,
    /// Estimated bytes reusable from local destination or chunk store.
    pub bytes_reusable: u64,
}

/// Summary metrics of a directory reconciliation.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectoryDiffSummary {
    /// Number of files with identical content.
    pub files_unchanged: usize,
    /// Number of files needing modification/update.
    pub files_modified: usize,
    /// Number of new files to be added.
    pub files_added: usize,
    /// Number of extraneous files identified for deletion.
    pub files_deleted: usize,
    /// Total data in bytes already present and reusable.
    pub data_present: u64,
    /// Total data in bytes required to be transferred.
    pub data_to_transfer: u64,
    /// Estimated reduction ratio percentage (0.0 to 100.0).
    pub estimated_reduction: f64,
}

impl DirectoryDiffSummary {
    /// Formats the summary into the canonical output representation (`REQUIREMENTS.md` §58).
    pub fn format_display(&self) -> String {
        format!(
            "Files unchanged:       {:>10}\n\
             Files modified:        {:>10}\n\
             Files added:           {:>10}\n\
             Files deleted:         {:>10}\n\n\
             Data already present:  {:>10}\n\
             Data to transfer:      {:>10}\n\
             Estimated reduction:   {:>9.1}%",
            self.files_unchanged,
            self.files_modified,
            self.files_added,
            self.files_deleted,
            format_bytes(self.data_present),
            format_bytes(self.data_to_transfer),
            self.estimated_reduction,
        )
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        format!("{:.2} TB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2} GB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// A complete plan for directory synchronization.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectoryPlan {
    /// List of per-file actions in deterministic sorted order.
    pub actions: Vec<FileAction>,
    /// Aggregate diff summary.
    pub summary: DirectoryDiffSummary,
}

/// Options controlling directory synchronization.
#[derive(Debug, Clone)]
pub struct DirectorySyncOptions {
    /// Chunking mode (Fixed or CDC).
    pub mode: ChunkMode,
    /// Chunk size parameters.
    pub params: ChunkParams,
    /// Deletion policy.
    pub delete_mode: DeleteMode,
    /// If true, calculate plan without modifying destination.
    pub dry_run: bool,
    /// Buffer size for file reads.
    pub read_buffer_size: usize,
    /// Transfer mode (Auto, DirectStream, DeltaCDC, DeltaFixed, Skip).
    pub transfer_mode: TransferMode,
    /// Minimum file size in bytes to consider delta synchronization (default: 64 KiB).
    pub min_delta_size: u64,
    /// Whether to bundle small files into streaming batch containers (default: true).
    pub batch_small_files: bool,
    /// Threshold under which regular files are batched into containers (default: 128 KiB).
    pub small_file_threshold: u64,
    /// Maximum container data bytes per batch (default: 32 MiB).
    pub batch_max_bytes: u64,
}

impl Default for DirectorySyncOptions {
    fn default() -> Self {
        Self {
            mode: ChunkMode::Cdc,
            params: ChunkParams::default(),
            delete_mode: DeleteMode::None,
            dry_run: false,
            read_buffer_size: 2 * 1024 * 1024,
            transfer_mode: TransferMode::Auto,
            min_delta_size: 64 * 1024,
            batch_small_files: true,
            small_file_threshold: crate::sync::batch::DEFAULT_SMALL_FILE_THRESHOLD,
            batch_max_bytes: crate::sync::batch::DEFAULT_BATCH_MAX_BYTES,
        }
    }
}

impl DirectorySyncOptions {
    /// Configure dry-run mode.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Configure transfer mode.
    pub fn with_transfer_mode(mut self, mode: TransferMode) -> Self {
        self.transfer_mode = mode;
        self
    }

    /// Configure minimum delta file size threshold.
    pub fn with_min_delta_size(mut self, size: u64) -> Self {
        self.min_delta_size = size;
        self
    }

    /// Configure small files batching enablement.
    pub fn with_batch_small_files(mut self, enabled: bool) -> Self {
        self.batch_small_files = enabled;
        self
    }

    /// Configure small file size threshold in bytes.
    pub fn with_small_file_threshold(mut self, threshold: u64) -> Self {
        self.small_file_threshold = threshold;
        self
    }

    /// Configure maximum batch container payload bytes.
    pub fn with_batch_max_bytes(mut self, max_bytes: u64) -> Self {
        self.batch_max_bytes = max_bytes;
        self
    }
}

/// Outcome of executing a directory synchronization.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectorySyncResult {
    /// The plan that was evaluated.
    pub plan: DirectoryPlan,
    /// Number of files staged and transferred.
    pub files_transferred: usize,
    /// Number of files atomically committed into destination.
    pub files_committed: usize,
    /// Number of extraneous files deleted.
    pub files_deleted: usize,
    /// Actual wire bytes transferred.
    pub wire_bytes_transferred: u64,
    /// Actual local bytes reused from destination.
    pub local_bytes_reused: u64,
    /// Actual store bytes reused from chunk store.
    pub store_bytes_reused: u64,
    /// Total small files bundled into batch containers.
    pub small_files_batched: usize,
    /// Total batch containers generated and streamed.
    pub batch_containers: usize,
    /// Total network roundtrips saved by batch containers.
    pub roundtrips_saved: usize,
}

/// Scanned directory entry with size, whole-file BLAKE3 hash, link metadata, mode, mtime, and xattrs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedEntry {
    pub size: u64,
    pub hash: Hash,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
    pub hardlink_target: Option<String>,
    pub xattrs: Vec<(String, Vec<u8>)>,
    pub mode: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
}

impl ScannedEntry {
    pub fn file(size: u64, hash: Hash) -> Self {
        Self {
            size,
            hash,
            is_symlink: false,
            symlink_target: None,
            hardlink_target: None,
            xattrs: Vec::new(),
            mode: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
        }
    }

    pub fn symlink(target: String) -> Self {
        let digest = blake3::hash(target.as_bytes());
        let hash = Hash::from_bytes(digest.as_bytes()).expect("hash");
        Self {
            size: target.len() as u64,
            hash,
            is_symlink: true,
            symlink_target: Some(target),
            hardlink_target: None,
            xattrs: Vec::new(),
            mode: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
        }
    }

    pub fn hardlink(size: u64, hash: Hash, target: String) -> Self {
        Self {
            size,
            hash,
            is_symlink: false,
            symlink_target: None,
            hardlink_target: Some(target),
            xattrs: Vec::new(),
            mode: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
        }
    }

    pub fn with_xattrs(mut self, xattrs: Vec<(String, Vec<u8>)>) -> Self {
        self.xattrs = xattrs;
        self
    }

    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_mtime(mut self, mtime_sec: i64, mtime_nsec: u32) -> Self {
        self.mtime_sec = mtime_sec;
        self.mtime_nsec = mtime_nsec;
        self
    }
}

/// Recursively scan all files in a directory root and compute their size and whole-file hash.
pub fn scan_dir_entries(root: &Path) -> std::io::Result<BTreeMap<String, ScannedEntry>> {
    let mut files = BTreeMap::new();
    if !root.exists() {
        return Ok(files);
    }

    #[cfg(unix)]
    let mut dev_ino_map = std::collections::HashMap::<(u64, u64), String>::new();

    // First collect all non-ignored file/symlink paths recursively, sorted deterministically by relative path.
    // This guarantees:
    // 1. Filesystem scan order is independent of ext4 hash directory order or APFS creation order.
    // 2. Hardlink primary vs secondary assignment is 100% deterministic (the lexicographically lowest path is primary).
    let mut discovered = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut dir_entries = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            dir_entries.push(entry?);
        }
        dir_entries.sort_by_key(|e| e.file_name());

        for entry in dir_entries {
            let path = entry.path();
            let file_type = entry.file_type()?;

            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            // Skip staging, chunk store, partial files, and xattr sidecars
            if name_str.starts_with(".velcrux-staging")
                || name_str.starts_with(".velcrux-chunks")
                || name_str.ends_with(".velcrux-partial")
                || name_str.ends_with(".velcrux-xattr")
            {
                continue;
            }

            if file_type.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let rel_str = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join("/");
                discovered.push((rel_str, path, file_type));
            }
        }
    }

    // Sort all discovered files and symlinks deterministically by canonical relative path
    discovered.sort_by(|a, b| a.0.cmp(&b.0));

    for (rel_str, path, file_type) in discovered {
        if file_type.is_symlink() {
            // Symlinks are never followed for resolution/traversal (SECURITY.md §4, ARCHITECTURE.md §8)
            let target_path = std::fs::read_link(&path)?;
            let target_str = target_path.to_string_lossy().to_string();
            let sym_meta = std::fs::symlink_metadata(&path)?;
            let (mtime_sec, mtime_nsec) = match sym_meta.modified() {
                Ok(t) => {
                    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
                    (d.as_secs() as i64, d.subsec_nanos())
                }
                Err(_) => (0, 0),
            };

            let sidecar = crate::storage::xattr_sidecar_path(&path);
            let xattrs = if sidecar.exists() {
                match std::fs::read(&sidecar) {
                    Ok(bytes) => {
                        crate::storage::decode_xattrs_canonical(&bytes).unwrap_or_default()
                    }
                    Err(_) => Vec::new(),
                }
            } else {
                Vec::new()
            };
            files.insert(
                rel_str,
                ScannedEntry::symlink(target_str)
                    .with_xattrs(xattrs)
                    .with_mtime(mtime_sec, mtime_nsec),
            );
        } else if file_type.is_file() {
            let metadata = std::fs::metadata(&path)?;
            let hash = compute_file_hash(&path)?;
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode()
            };
            #[cfg(not(unix))]
            let mode = 0o644;

            let (mtime_sec, mtime_nsec) = match metadata.modified() {
                Ok(t) => {
                    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
                    (d.as_secs() as i64, d.subsec_nanos())
                }
                Err(_) => (0, 0),
            };

            let sidecar = crate::storage::xattr_sidecar_path(&path);
            let xattrs = if sidecar.exists() {
                match std::fs::read(&sidecar) {
                    Ok(bytes) => {
                        crate::storage::decode_xattrs_canonical(&bytes).unwrap_or_default()
                    }
                    Err(_) => Vec::new(),
                }
            } else {
                Vec::new()
            };

            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let dev = metadata.dev();
                let ino = metadata.ino();
                let nlink = metadata.nlink();
                if nlink > 1 {
                    if let Some(first_path) = dev_ino_map.get(&(dev, ino)) {
                        files.insert(
                            rel_str,
                            ScannedEntry::hardlink(metadata.len(), hash, first_path.clone())
                                .with_xattrs(xattrs)
                                .with_mode(mode)
                                .with_mtime(mtime_sec, mtime_nsec),
                        );
                        continue;
                    } else {
                        dev_ino_map.insert((dev, ino), rel_str.clone());
                    }
                }
            }

            files.insert(
                rel_str,
                ScannedEntry::file(metadata.len(), hash)
                    .with_xattrs(xattrs)
                    .with_mode(mode)
                    .with_mtime(mtime_sec, mtime_nsec),
            );
        }
    }

    Ok(files)
}

/// Compute whole-file BLAKE3 hash.
pub fn compute_file_hash(path: &Path) -> std::io::Result<Hash> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(Hash::from_bytes(digest.as_bytes()).expect("blake3 length"))
}

/// Plan a directory reconciliation diff between source and destination file maps.
pub fn plan_directory_diff(
    src_files: &BTreeMap<String, ScannedEntry>,
    dst_files: &BTreeMap<String, ScannedEntry>,
) -> DirectoryPlan {
    let mut actions = Vec::new();
    let mut files_unchanged = 0usize;
    let mut files_modified = 0usize;
    let mut files_added = 0usize;
    let mut files_deleted = 0usize;
    let mut data_present = 0u64;
    let mut data_to_transfer = 0u64;

    let mut all_paths = BTreeMap::new();
    for (p, sf) in src_files {
        all_paths.insert(p.clone(), (Some(sf), None));
    }
    for (p, df) in dst_files {
        all_paths
            .entry(p.clone())
            .and_modify(|pair| pair.1 = Some(df))
            .or_insert((None, Some(df)));
    }

    for (rel_path, (sf_opt, df_opt)) in all_paths {
        match (sf_opt, df_opt) {
            (Some(sf), Some(df)) => {
                let is_same = sf.is_symlink == df.is_symlink
                    && sf.symlink_target == df.symlink_target
                    && sf.hardlink_target == df.hardlink_target
                    && sf.size == df.size
                    && sf.hash == df.hash
                    && sf.xattrs == df.xattrs
                    && (sf.is_symlink
                        || sf.mode == 0
                        || df.mode == 0
                        || (sf.mode & 0o777) == (df.mode & 0o777));
                if is_same {
                    files_unchanged += 1;
                    data_present += sf.size;
                    actions.push(FileAction {
                        rel_path,
                        action: FileActionType::Unchanged,
                        src_size: sf.size,
                        dst_size: df.size,
                        src_hash: Some(sf.hash),
                        bytes_to_transfer: 0,
                        bytes_reusable: sf.size,
                    });
                } else {
                    files_modified += 1;
                    data_to_transfer += sf.size;
                    actions.push(FileAction {
                        rel_path,
                        action: FileActionType::Modify,
                        src_size: sf.size,
                        dst_size: df.size,
                        src_hash: Some(sf.hash),
                        bytes_to_transfer: sf.size,
                        bytes_reusable: 0,
                    });
                }
            }
            (Some(sf), None) => {
                files_added += 1;
                data_to_transfer += sf.size;
                actions.push(FileAction {
                    rel_path,
                    action: FileActionType::Add,
                    src_size: sf.size,
                    dst_size: 0,
                    src_hash: Some(sf.hash),
                    bytes_to_transfer: sf.size,
                    bytes_reusable: 0,
                });
            }
            (None, Some(df)) => {
                files_deleted += 1;
                actions.push(FileAction {
                    rel_path,
                    action: FileActionType::Delete,
                    src_size: 0,
                    dst_size: df.size,
                    src_hash: None,
                    bytes_to_transfer: 0,
                    bytes_reusable: 0,
                });
            }
            (None, None) => unreachable!(),
        }
    }

    let total_data = data_present + data_to_transfer;
    let estimated_reduction = if total_data > 0 {
        (data_present as f64 / total_data as f64) * 100.0
    } else {
        0.0
    };

    let summary = DirectoryDiffSummary {
        files_unchanged,
        files_modified,
        files_added,
        files_deleted,
        data_present,
        data_to_transfer,
        estimated_reduction,
    };

    DirectoryPlan { actions, summary }
}

/// Send a directory inventory as a framed streaming manifest (MANIFEST_BEGIN, MANIFEST_BATCH*, MANIFEST_END).
pub async fn send_directory_manifest(
    send: &mut dyn crate::transport::BiSendStream,
    entries: &BTreeMap<String, ScannedEntry>,
) -> crate::error::Result<Hash> {
    use crate::manifest::codec::encode_file_entry;
    use crate::manifest::entry::FileEntry;
    use crate::protocol::limits::MANIFEST_BATCH_SIZE;
    use crate::protocol::message::{ManifestBatch, ManifestBegin, ManifestEnd, Message};
    use crate::session::write_frame;
    use crate::storage::VPath;

    let file_count = entries.len() as u64;
    let total_bytes: u64 = entries.values().map(|e| e.size).sum();
    let chunker_params = ChunkParams::default();

    // Compute canonical manifest hash across all entries
    let mut manifest_hasher = blake3::Hasher::new();
    let mut all_file_entries = Vec::with_capacity(entries.len());
    for (rel_path, entry) in entries {
        let vpath = VPath::validate(rel_path).map_err(|e| {
            crate::error::VelcruxError::Protocol(crate::error::ProtocolError::InvalidManifest(
                e.to_string(),
            ))
        })?;
        let fe = if entry.is_symlink {
            FileEntry::symlink_with_target(
                vpath,
                entry.mode,
                entry.mtime_sec,
                entry.mtime_nsec,
                entry.symlink_target.clone().unwrap_or_default(),
            )
        } else if let Some(ref hard_target) = entry.hardlink_target {
            let mut hfe = FileEntry::hardlink(vpath, hard_target.clone(), entry.size, entry.hash);
            hfe.mode = entry.mode;
            hfe.mtime_sec = entry.mtime_sec;
            hfe.mtime_nsec = entry.mtime_nsec;
            hfe
        } else {
            let mut chunks = Vec::new();
            let mut remaining = entry.size;
            while remaining > 0 {
                let chunk_len = remaining.min(crate::protocol::limits::MAX_CHUNK_SIZE);
                chunks.push(crate::manifest::entry::ChunkDesc::new(
                    chunk_len, entry.hash,
                ));
                remaining -= chunk_len;
            }
            FileEntry::regular(
                vpath,
                entry.size,
                entry.mode,
                entry.mtime_sec,
                entry.mtime_nsec,
                entry.hash,
                chunks,
            )
        };
        let fe = fe.with_xattrs(entry.xattrs.clone());
        let mut buf = Vec::new();
        encode_file_entry(&fe, &mut buf);
        manifest_hasher.update(&buf);
        all_file_entries.push(fe);
    }
    let digest = manifest_hasher.finalize();
    let manifest_hash = Hash::from_bytes(digest.as_bytes()).expect("blake3 length");

    // Send MANIFEST_BEGIN
    let begin = ManifestBegin {
        file_count,
        total_bytes,
        chunker_params,
        manifest_hash,
    };
    write_frame(send, &Message::ManifestBegin(begin), 0).await?;

    // Send MANIFEST_BATCH frames in chunks of MANIFEST_BATCH_SIZE
    let mut batch_index = 0u64;
    for chunk in all_file_entries.chunks(MANIFEST_BATCH_SIZE) {
        let mut raw_batch = Vec::new();
        for fe in chunk {
            encode_file_entry(fe, &mut raw_batch);
        }
        let compressed = zstd::encode_all(&raw_batch[..], 3).map_err(|e| {
            crate::error::VelcruxError::Internal(format!("zstd compress batch: {e}"))
        })?;
        let batch = ManifestBatch {
            batch_index,
            entry_count: chunk.len() as u32,
            compressed_payload: bytes::Bytes::from(compressed),
        };
        write_frame(send, &Message::ManifestBatch(batch), 0).await?;
        batch_index += 1;
    }

    // Send MANIFEST_END
    let end = ManifestEnd { manifest_hash };
    write_frame(send, &Message::ManifestEnd(end), 0).await?;

    Ok(manifest_hash)
}

/// Receive a framed streaming manifest from the wire and return the directory inventory.
pub async fn recv_directory_manifest(
    recv: &mut dyn crate::transport::BiRecvStream,
) -> crate::error::Result<BTreeMap<String, ScannedEntry>> {
    use crate::manifest::reader::ManifestBatchDecoder;
    use crate::protocol::message::ManifestBegin;
    use crate::session::read_frame;

    let frame = read_frame(recv)
        .await?
        .ok_or_else(|| crate::error::VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;

    if frame.type_byte != crate::protocol::message::MANIFEST_BEGIN {
        return Err(crate::error::VelcruxError::Protocol(
            crate::error::ProtocolError::InvalidStateTransition("expected MANIFEST_BEGIN"),
        ));
    }
    let begin = ManifestBegin::decode(&frame.payload)?;
    let mut decoder = ManifestBatchDecoder::new(begin.manifest_hash);
    let mut entries = BTreeMap::new();

    loop {
        let frame = read_frame(recv).await?.ok_or_else(|| {
            crate::error::VelcruxError::Protocol(crate::error::ProtocolError::Empty)
        })?;

        if frame.type_byte == crate::protocol::message::MANIFEST_BATCH {
            let batch = crate::protocol::message::ManifestBatch::decode(&frame.payload)?;
            let file_entries = decoder.decode_batch(&batch)?;
            for fe in file_entries {
                let scanned = if fe.flags.file_type() == crate::manifest::entry::FileType::Symlink {
                    ScannedEntry::symlink(fe.symlink_target.unwrap_or_default())
                        .with_mode(fe.mode)
                        .with_mtime(fe.mtime_sec, fe.mtime_nsec)
                } else if fe.flags.is_hardlink() {
                    ScannedEntry::hardlink(
                        fe.size,
                        fe.file_hash,
                        fe.hardlink_target.unwrap_or_default(),
                    )
                    .with_mode(fe.mode)
                    .with_mtime(fe.mtime_sec, fe.mtime_nsec)
                } else {
                    ScannedEntry::file(fe.size, fe.file_hash)
                        .with_mode(fe.mode)
                        .with_mtime(fe.mtime_sec, fe.mtime_nsec)
                };
                let scanned = scanned.with_xattrs(fe.xattrs);
                entries.insert(fe.path.as_str().to_string(), scanned);
            }
        } else if frame.type_byte == crate::protocol::message::MANIFEST_END {
            let end = crate::protocol::message::ManifestEnd::decode(&frame.payload)?;
            if end.manifest_hash != begin.manifest_hash {
                return Err(crate::error::VelcruxError::Protocol(
                    crate::error::ProtocolError::InvalidManifest(
                        "manifest hash mismatch at MANIFEST_END".into(),
                    ),
                ));
            }
            break;
        } else {
            return Err(crate::error::VelcruxError::Protocol(
                crate::error::ProtocolError::InvalidStateTransition(
                    "expected MANIFEST_BATCH or MANIFEST_END",
                ),
            ));
        }
    }

    Ok(entries)
}

/// Stream a manifest from an existing spill file over a bi-directional send stream without buffering in RAM.
pub async fn send_streaming_manifest_from_spill(
    send: &mut dyn crate::transport::BiSendStream,
    spill_path: impl AsRef<Path>,
    begin: &crate::protocol::message::ManifestBegin,
) -> crate::error::Result<crate::protocol::message::ManifestEnd> {
    use crate::manifest::writer::{SPILL_MAGIC, SPILL_VERSION};
    use crate::protocol::message::{ManifestBatch, Message};
    use crate::session::write_frame;
    use std::fs::File;
    use std::io::Read;

    // Send MANIFEST_BEGIN
    write_frame(send, &Message::ManifestBegin(begin.clone()), 0).await?;

    let file = File::open(spill_path.as_ref())?;
    let mut reader = std::io::BufReader::new(file);

    // Verify spill header
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != SPILL_MAGIC {
        return Err(crate::error::VelcruxError::Protocol(
            crate::error::ProtocolError::InvalidManifest("invalid spill file magic".into()),
        ));
    }
    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != SPILL_VERSION {
        return Err(crate::error::VelcruxError::Protocol(
            crate::error::ProtocolError::InvalidManifest(format!(
                "unsupported spill file version {}",
                version[0]
            )),
        ));
    }

    // Stream batches
    loop {
        let mut header = [0u8; 16]; // batch_index (8) + entry_count (4) + comp_len (4)
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(crate::error::VelcruxError::Io(e)),
        }
        let batch_index = u64::from_le_bytes(header[0..8].try_into().unwrap());
        let entry_count = u32::from_le_bytes(header[8..12].try_into().unwrap());
        let comp_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;

        let mut compressed = vec![0u8; comp_len];
        reader.read_exact(&mut compressed)?;

        let batch = ManifestBatch {
            batch_index,
            entry_count,
            compressed_payload: bytes::Bytes::from(compressed),
        };
        write_frame(send, &Message::ManifestBatch(batch), 0).await?;
    }

    let end = crate::protocol::message::ManifestEnd {
        manifest_hash: begin.manifest_hash,
    };
    write_frame(send, &Message::ManifestEnd(end.clone()), 0).await?;

    Ok(end)
}

/// Receive a streaming manifest from a bi-directional receive stream and save directly to a spill file with bounded RAM.
pub async fn recv_streaming_manifest_to_spill(
    recv: &mut dyn crate::transport::BiRecvStream,
    spill_path: impl AsRef<Path>,
) -> crate::error::Result<(
    crate::protocol::message::ManifestBegin,
    crate::protocol::message::ManifestEnd,
)> {
    use crate::manifest::codec::decode_file_entry;
    use crate::manifest::reader::decompress_batch;
    use crate::manifest::writer::{SPILL_MAGIC, SPILL_VERSION};
    use crate::protocol::limits::{MAX_MANIFEST_BYTES, MAX_MANIFEST_ENTRIES};
    use crate::protocol::message::{
        ManifestBatch, ManifestBegin, ManifestEnd, MANIFEST_BATCH, MANIFEST_BEGIN, MANIFEST_END,
    };
    use crate::session::read_frame;
    use std::fs::OpenOptions;
    use std::io::Write;

    let frame = read_frame(recv)
        .await?
        .ok_or_else(|| crate::error::VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;

    if frame.type_byte != MANIFEST_BEGIN {
        return Err(crate::error::VelcruxError::Protocol(
            crate::error::ProtocolError::InvalidStateTransition("expected MANIFEST_BEGIN"),
        ));
    }
    let begin = ManifestBegin::decode(&frame.payload)?;

    let path = spill_path.as_ref().to_path_buf();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)?;
    let mut writer = std::io::BufWriter::new(file);

    writer.write_all(&SPILL_MAGIC)?;
    writer.write_all(&[SPILL_VERSION])?;

    let mut hasher = blake3::Hasher::new();
    let mut total_entries = 0u64;
    let mut total_manifest_bytes = 0u64;

    let end = loop {
        let frame = read_frame(recv).await?.ok_or_else(|| {
            crate::error::VelcruxError::Protocol(crate::error::ProtocolError::Empty)
        })?;

        if frame.type_byte == MANIFEST_BATCH {
            let batch = ManifestBatch::decode(&frame.payload)?;

            // Decompress to validate entries and compute running hash
            let decompressed = decompress_batch(&batch.compressed_payload)?;
            total_manifest_bytes += decompressed.len() as u64;
            if total_manifest_bytes > MAX_MANIFEST_BYTES {
                return Err(crate::error::VelcruxError::Protocol(
                    crate::error::ProtocolError::InvalidManifest(format!(
                        "manifest raw bytes exceeded limit {MAX_MANIFEST_BYTES}"
                    )),
                ));
            }

            let mut cursor = 0;
            for _ in 0..batch.entry_count {
                if cursor >= decompressed.len() {
                    return Err(crate::error::VelcruxError::Protocol(
                        crate::error::ProtocolError::Malformed(
                            "MANIFEST_BATCH: truncated decompressed entries",
                        ),
                    ));
                }
                let slice = &decompressed[cursor..];
                let (_entry, consumed) =
                    decode_file_entry(slice).map_err(crate::error::VelcruxError::Protocol)?;
                hasher.update(&slice[..consumed]);
                cursor += consumed;
                total_entries += 1;
            }

            if total_entries > MAX_MANIFEST_ENTRIES {
                return Err(crate::error::VelcruxError::Protocol(
                    crate::error::ProtocolError::InvalidManifest(format!(
                        "manifest entries exceeded limit {MAX_MANIFEST_ENTRIES}"
                    )),
                ));
            }

            // Write batch directly to spill file:
            // [batch_index: 8B LE][entry_count: 4B LE][comp_len: 4B LE][compressed_payload]
            writer.write_all(&batch.batch_index.to_le_bytes())?;
            writer.write_all(&batch.entry_count.to_le_bytes())?;
            let comp_len = batch.compressed_payload.len() as u32;
            writer.write_all(&comp_len.to_le_bytes())?;
            writer.write_all(&batch.compressed_payload)?;
        } else if frame.type_byte == MANIFEST_END {
            let end = ManifestEnd::decode(&frame.payload)?;
            if end.manifest_hash != begin.manifest_hash {
                return Err(crate::error::VelcruxError::Protocol(
                    crate::error::ProtocolError::InvalidManifest(
                        "manifest hash mismatch at MANIFEST_END".into(),
                    ),
                ));
            }
            let computed = hasher.finalize();
            if computed.as_bytes() != begin.manifest_hash.as_bytes() {
                return Err(crate::error::VelcruxError::Protocol(
                    crate::error::ProtocolError::InvalidManifest(format!(
                        "manifest content hash mismatch: computed {}, expected {}",
                        Hash::from_bytes(computed.as_bytes()).unwrap(),
                        begin.manifest_hash
                    )),
                ));
            }
            break end;
        } else {
            return Err(crate::error::VelcruxError::Protocol(
                crate::error::ProtocolError::InvalidStateTransition(
                    "expected MANIFEST_BATCH or MANIFEST_END",
                ),
            ));
        }
    };

    writer.flush()?;

    Ok((begin, end))
}

/// Stream-diff two manifest readers in lockstep lexicographical order.
///
/// Computes file actions (Unchanged, Modify, Add, Delete) and aggregates metrics
/// with strictly bounded RSS O(1) memory, regardless of directory size.
pub fn diff_manifest_readers<F>(
    src_reader: &mut crate::manifest::ManifestReader,
    dst_reader: &mut crate::manifest::ManifestReader,
    mut on_action: F,
) -> crate::error::Result<DirectoryDiffSummary>
where
    F: FnMut(FileAction),
{
    let mut files_unchanged = 0usize;
    let mut files_modified = 0usize;
    let mut files_added = 0usize;
    let mut files_deleted = 0usize;
    let mut data_present = 0u64;
    let mut data_to_transfer = 0u64;

    let mut cur_src = src_reader.next_entry()?;
    let mut cur_dst = dst_reader.next_entry()?;

    while cur_src.is_some() || cur_dst.is_some() {
        match (&cur_src, &cur_dst) {
            (Some(sf), Some(df)) => match sf.path.as_str().cmp(df.path.as_str()) {
                std::cmp::Ordering::Equal => {
                    let is_same = sf.flags == df.flags
                        && sf.size == df.size
                        && sf.file_hash == df.file_hash
                        && sf.xattrs == df.xattrs
                        && sf.symlink_target == df.symlink_target
                        && sf.hardlink_target == df.hardlink_target;
                    if is_same {
                        files_unchanged += 1;
                        data_present += sf.size;
                        on_action(FileAction {
                            rel_path: sf.path.as_str().to_string(),
                            action: FileActionType::Unchanged,
                            src_size: sf.size,
                            dst_size: df.size,
                            src_hash: Some(sf.file_hash),
                            bytes_to_transfer: 0,
                            bytes_reusable: sf.size,
                        });
                    } else {
                        files_modified += 1;
                        data_to_transfer += sf.size;
                        on_action(FileAction {
                            rel_path: sf.path.as_str().to_string(),
                            action: FileActionType::Modify,
                            src_size: sf.size,
                            dst_size: df.size,
                            src_hash: Some(sf.file_hash),
                            bytes_to_transfer: sf.size,
                            bytes_reusable: 0,
                        });
                    }
                    cur_src = src_reader.next_entry()?;
                    cur_dst = dst_reader.next_entry()?;
                }
                std::cmp::Ordering::Less => {
                    files_added += 1;
                    data_to_transfer += sf.size;
                    on_action(FileAction {
                        rel_path: sf.path.as_str().to_string(),
                        action: FileActionType::Add,
                        src_size: sf.size,
                        dst_size: 0,
                        src_hash: Some(sf.file_hash),
                        bytes_to_transfer: sf.size,
                        bytes_reusable: 0,
                    });
                    cur_src = src_reader.next_entry()?;
                }
                std::cmp::Ordering::Greater => {
                    files_deleted += 1;
                    on_action(FileAction {
                        rel_path: df.path.as_str().to_string(),
                        action: FileActionType::Delete,
                        src_size: 0,
                        dst_size: df.size,
                        src_hash: None,
                        bytes_to_transfer: 0,
                        bytes_reusable: 0,
                    });
                    cur_dst = dst_reader.next_entry()?;
                }
            },
            (Some(sf), None) => {
                files_added += 1;
                data_to_transfer += sf.size;
                on_action(FileAction {
                    rel_path: sf.path.as_str().to_string(),
                    action: FileActionType::Add,
                    src_size: sf.size,
                    dst_size: 0,
                    src_hash: Some(sf.file_hash),
                    bytes_to_transfer: sf.size,
                    bytes_reusable: 0,
                });
                cur_src = src_reader.next_entry()?;
            }
            (None, Some(df)) => {
                files_deleted += 1;
                on_action(FileAction {
                    rel_path: df.path.as_str().to_string(),
                    action: FileActionType::Delete,
                    src_size: 0,
                    dst_size: df.size,
                    src_hash: None,
                    bytes_to_transfer: 0,
                    bytes_reusable: 0,
                });
                cur_dst = dst_reader.next_entry()?;
            }
            (None, None) => break,
        }
    }

    let total_data = data_present + data_to_transfer;
    let estimated_reduction = if total_data > 0 {
        (data_present as f64 / total_data as f64) * 100.0
    } else {
        0.0
    };

    Ok(DirectoryDiffSummary {
        files_unchanged,
        files_modified,
        files_added,
        files_deleted,
        data_present,
        data_to_transfer,
        estimated_reduction,
    })
}

/// Convenience function to diff two manifest spill files without loading them into memory.
pub fn diff_manifest_spill_files<F>(
    src_spill: impl AsRef<Path>,
    src_hash: Hash,
    dst_spill: impl AsRef<Path>,
    dst_hash: Hash,
    on_action: F,
) -> crate::error::Result<DirectoryDiffSummary>
where
    F: FnMut(FileAction),
{
    let mut src_reader = crate::manifest::ManifestReader::open(src_spill, src_hash)?;
    let mut dst_reader = crate::manifest::ManifestReader::open(dst_spill, dst_hash)?;
    diff_manifest_readers(&mut src_reader, &mut dst_reader, on_action)
}

/// Scan a local directory tree into a temporary spill file and diff it against a remote manifest reader.
pub fn diff_local_dir_with_manifest<F>(
    local_dir: impl AsRef<Path>,
    spill_dir: impl AsRef<Path>,
    remote_reader: &mut crate::manifest::ManifestReader,
    chunk_params: ChunkParams,
    on_action: F,
) -> crate::error::Result<DirectoryDiffSummary>
where
    F: FnMut(FileAction),
{
    let temp_spill = spill_dir.as_ref().join(format!(
        "local_scan_{}.spill",
        crate::util::TransferId::generate()
    ));
    let mut writer = crate::manifest::ManifestWriter::new(&temp_spill, chunk_params)?;
    crate::manifest::scanner::scan_directory_tree(local_dir, &mut writer)?;
    let (begin, _, spill_path) = writer.finish()?;

    let mut local_reader = crate::manifest::ManifestReader::open(&spill_path, begin.manifest_hash)?;
    let summary = diff_manifest_readers(&mut local_reader, remote_reader, on_action);
    let _ = std::fs::remove_file(spill_path);
    summary
}

/// Compute a directory sync plan by scanning source and destination directories.
pub fn plan_directory_sync(
    src_dir: &Path,
    dst_dir: &Path,
    options: &DirectorySyncOptions,
    chunk_store: Option<&LocalChunkStore>,
) -> Result<DirectoryPlan, SyncError> {
    let src_files = scan_dir_entries(src_dir)?;
    let dst_files = scan_dir_entries(dst_dir)?;

    let mut actions = Vec::new();
    let mut files_unchanged = 0usize;
    let mut files_modified = 0usize;
    let mut files_added = 0usize;
    let mut files_deleted = 0usize;
    let mut data_present = 0u64;
    let mut data_to_transfer = 0u64;

    // Collect all relative paths
    let mut all_paths = BTreeMap::new();
    for (p, sf) in &src_files {
        all_paths.insert(p.clone(), (Some(sf), None));
    }
    for (p, df) in &dst_files {
        all_paths
            .entry(p.clone())
            .and_modify(|pair| pair.1 = Some(df))
            .or_insert((None, Some(df)));
    }

    for (rel_path, (sf_opt, df_opt)) in all_paths {
        match (sf_opt, df_opt) {
            (Some(sf), Some(df)) => {
                if sf.is_symlink {
                    let is_same = df.is_symlink
                        && sf.symlink_target == df.symlink_target
                        && sf.xattrs == df.xattrs;
                    if is_same {
                        files_unchanged += 1;
                        data_present += sf.size;
                        actions.push(FileAction {
                            rel_path,
                            action: FileActionType::Unchanged,
                            src_size: sf.size,
                            dst_size: df.size,
                            src_hash: Some(sf.hash),
                            bytes_to_transfer: 0,
                            bytes_reusable: sf.size,
                        });
                    } else {
                        files_modified += 1;
                        data_to_transfer += sf.size;
                        actions.push(FileAction {
                            rel_path,
                            action: FileActionType::Modify,
                            src_size: sf.size,
                            dst_size: df.size,
                            src_hash: Some(sf.hash),
                            bytes_to_transfer: sf.size,
                            bytes_reusable: 0,
                        });
                    }
                    continue;
                }

                if df.is_symlink {
                    files_modified += 1;
                    data_to_transfer += sf.size;
                    actions.push(FileAction {
                        rel_path,
                        action: FileActionType::Modify,
                        src_size: sf.size,
                        dst_size: df.size,
                        src_hash: Some(sf.hash),
                        bytes_to_transfer: sf.size,
                        bytes_reusable: 0,
                    });
                    continue;
                }

                let src_full = src_dir.join(&rel_path);
                let dst_full = dst_dir.join(&rel_path);

                let is_same = sf.size == df.size
                    && sf.hash == df.hash
                    && sf.xattrs == df.xattrs
                    && (sf.mode == 0 || df.mode == 0 || (sf.mode & 0o777) == (df.mode & 0o777));

                if is_same {
                    files_unchanged += 1;
                    data_present += sf.size;
                    actions.push(FileAction {
                        rel_path,
                        action: FileActionType::Unchanged,
                        src_size: sf.size,
                        dst_size: df.size,
                        src_hash: Some(sf.hash),
                        bytes_to_transfer: 0,
                        bytes_reusable: sf.size,
                    });
                } else {
                    files_modified += 1;
                    if options.transfer_mode == TransferMode::DirectStream
                        || sf.size < options.min_delta_size
                    {
                        data_to_transfer += sf.size;
                        actions.push(FileAction {
                            rel_path,
                            action: FileActionType::Modify,
                            src_size: sf.size,
                            dst_size: df.size,
                            src_hash: Some(sf.hash),
                            bytes_to_transfer: sf.size,
                            bytes_reusable: 0,
                        });
                        continue;
                    }

                    // Delta estimation
                    let inv = LocalInventory::from_file(
                        &dst_full,
                        options.mode,
                        options.params,
                        options.read_buffer_size,
                    )?;
                    let mut reusable = 0u64;
                    let mut needed = 0u64;

                    let mut f = File::open(&src_full)?;
                    let _ = ChunkEngine::chunk_reader(
                        &mut f,
                        options.mode,
                        options.params,
                        options.read_buffer_size,
                        |desc, _payload| {
                            let mut found = false;
                            if desc.flags.is_hole() {
                                reusable += desc.length;
                                found = true;
                            } else if let Some(h) = desc.hash {
                                if inv.contains(&h) {
                                    reusable += desc.length;
                                    found = true;
                                } else if let Some(store) = chunk_store {
                                    if store.contains_sync(&h) {
                                        reusable += desc.length;
                                        found = true;
                                    }
                                }
                            }
                            if !found {
                                needed += desc.length;
                            }
                            Ok(())
                        },
                    );

                    data_present += reusable;
                    data_to_transfer += needed;

                    actions.push(FileAction {
                        rel_path,
                        action: FileActionType::Modify,
                        src_size: sf.size,
                        dst_size: df.size,
                        src_hash: Some(sf.hash),
                        bytes_to_transfer: needed,
                        bytes_reusable: reusable,
                    });
                }
            }
            (Some(sf), None) => {
                files_added += 1;
                if sf.is_symlink {
                    data_to_transfer += sf.size;
                    actions.push(FileAction {
                        rel_path,
                        action: FileActionType::Add,
                        src_size: sf.size,
                        dst_size: 0,
                        src_hash: Some(sf.hash),
                        bytes_to_transfer: sf.size,
                        bytes_reusable: 0,
                    });
                    continue;
                }

                let src_full = src_dir.join(&rel_path);
                let sh = sf.hash;

                if chunk_store.is_none()
                    || options.transfer_mode == TransferMode::DirectStream
                    || sf.size < options.min_delta_size
                {
                    data_to_transfer += sf.size;
                    actions.push(FileAction {
                        rel_path,
                        action: FileActionType::Add,
                        src_size: sf.size,
                        dst_size: 0,
                        src_hash: Some(sh),
                        bytes_to_transfer: sf.size,
                        bytes_reusable: 0,
                    });
                    continue;
                }

                let mut reusable = 0u64;
                let mut needed = 0u64;
                let mut f = File::open(&src_full)?;
                let _ = ChunkEngine::chunk_reader(
                    &mut f,
                    options.mode,
                    options.params,
                    options.read_buffer_size,
                    |desc, _payload| {
                        let mut found = false;
                        if desc.flags.is_hole() {
                            reusable += desc.length;
                            found = true;
                        } else if let Some(h) = desc.hash {
                            if let Some(store) = chunk_store {
                                if store.contains_sync(&h) {
                                    reusable += desc.length;
                                    found = true;
                                }
                            }
                        }
                        if !found {
                            needed += desc.length;
                        }
                        Ok(())
                    },
                );

                data_present += reusable;
                data_to_transfer += needed;

                actions.push(FileAction {
                    rel_path,
                    action: FileActionType::Add,
                    src_size: sf.size,
                    dst_size: 0,
                    src_hash: Some(sh),
                    bytes_to_transfer: needed,
                    bytes_reusable: reusable,
                });
            }
            (None, Some(df)) => {
                files_deleted += 1;
                actions.push(FileAction {
                    rel_path,
                    action: FileActionType::Delete,
                    src_size: 0,
                    dst_size: df.size,
                    src_hash: None,
                    bytes_to_transfer: 0,
                    bytes_reusable: 0,
                });
            }
            (None, None) => unreachable!(),
        }
    }

    let total_data = data_present + data_to_transfer;
    let estimated_reduction = if total_data > 0 {
        (data_present as f64 / total_data as f64) * 100.0
    } else {
        0.0
    };

    let summary = DirectoryDiffSummary {
        files_unchanged,
        files_modified,
        files_added,
        files_deleted,
        data_present,
        data_to_transfer,
        estimated_reduction,
    };

    Ok(DirectoryPlan { actions, summary })
}

/// Execute end-to-end directory synchronization with transactional staging,
/// journaled commit, and explicit deletion policy.
pub fn execute_directory_sync(
    src_dir: &Path,
    dst_dir: &Path,
    options: &DirectorySyncOptions,
    state_store: Option<&dyn StateStore>,
    chunk_store: Option<&LocalChunkStore>,
) -> Result<DirectorySyncResult, SyncError> {
    let plan = plan_directory_sync(src_dir, dst_dir, options, chunk_store)?;

    let batch_cfg = crate::sync::batch::SmallFileBatchConfig {
        enabled: options.batch_small_files,
        threshold_bytes: options.small_file_threshold,
        max_batch_bytes: options.batch_max_bytes,
        max_batch_files: crate::sync::batch::DEFAULT_BATCH_MAX_FILES,
    };
    let batched_plan =
        crate::sync::batch::SmallFileBatchPlanner::plan(src_dir, &plan.actions, &batch_cfg);

    // If dry run, return plan without modifying destination
    if options.dry_run {
        return Ok(DirectorySyncResult {
            plan,
            files_transferred: 0,
            files_committed: 0,
            files_deleted: 0,
            wire_bytes_transferred: 0,
            local_bytes_reused: 0,
            store_bytes_reused: 0,
            small_files_batched: batched_plan.small_files_count,
            batch_containers: batched_plan.batch_containers_count,
            roundtrips_saved: batched_plan.roundtrips_saved,
        });
    }

    let transfer_id = TransferId::generate();

    // Ensure dst_dir exists
    if !dst_dir.exists() {
        std::fs::create_dir_all(dst_dir)?;
    }

    // Staging root lives on the same filesystem root under .velcrux-staging
    let staging_root = dst_dir
        .join(".velcrux-staging")
        .join(transfer_id.to_string());
    std::fs::create_dir_all(&staging_root)?;

    let mut staged_files = Vec::new();
    let mut total_wire_bytes = 0u64;
    let mut total_local_reused = 0u64;
    let mut total_store_reused = 0u64;

    let mut batched_action_paths = std::collections::HashSet::new();

    // --- BATCH STREAMING CONTAINER PHASE (Option AI) ---
    for batch in &batched_plan.batches {
        let mut container_buf = Vec::new();
        crate::sync::batch::BatchContainerWriter::pack(
            src_dir,
            &batch.actions,
            &mut container_buf,
        )?;

        let mut cursor = std::io::Cursor::new(&container_buf);
        let report = crate::sync::batch::BatchContainerReader::unpack(&mut cursor, &staging_root)?;

        for action in &batch.actions {
            let staged_file = staging_root.join(&action.rel_path);
            let file_idx = plan
                .actions
                .iter()
                .position(|a| a.rel_path == action.rel_path)
                .unwrap_or(0);
            staged_files.push((file_idx as u64, action.rel_path.clone(), staged_file));
            batched_action_paths.insert(action.rel_path.clone());
        }
        total_wire_bytes += report.total_bytes;
    }

    // --- STAGE & TRANSFER & VERIFY PHASE ---
    for (file_idx, action) in plan.actions.iter().enumerate() {
        if action.action != FileActionType::Add && action.action != FileActionType::Modify {
            continue;
        }
        if batched_action_paths.contains(&action.rel_path) {
            continue;
        }

        let src_file = src_dir.join(&action.rel_path);
        let dst_file = dst_dir.join(&action.rel_path);
        let staged_file = staging_root.join(&action.rel_path);

        if let Some(parent) = staged_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let is_src_symlink = match std::fs::symlink_metadata(&src_file) {
            Ok(m) => m.file_type().is_symlink(),
            Err(_) => false,
        };

        if is_src_symlink {
            let target_path = std::fs::read_link(&src_file)?;
            let target_str = target_path.to_string_lossy().to_string();
            let vpath = crate::storage::VPath::validate(&action.rel_path)
                .map_err(|e| SyncError::Reconstruction(e.to_string()))?;
            crate::storage::VPath::validate_symlink_target(&vpath, &target_str)
                .map_err(|e| SyncError::Reconstruction(e.to_string()))?;

            if staged_file.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&staged_file);
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target_path, &staged_file)?;
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(&target_path, &staged_file)?;

            let src_sidecar = crate::storage::xattr_sidecar_path(&src_file);
            if src_sidecar.symlink_metadata().is_ok() {
                let staged_sidecar = crate::storage::xattr_sidecar_path(&staged_file);
                let _ = std::fs::copy(&src_sidecar, &staged_sidecar);
            }

            staged_files.push((file_idx as u64, action.rel_path.clone(), staged_file));
            total_wire_bytes += action.src_size;
            continue;
        }

        let src_size = action.src_size;
        let src_hash = action.src_hash.expect("src hash present for Add/Modify");

        let use_delta = match options.transfer_mode {
            TransferMode::DirectStream => false,
            TransferMode::DeltaCDC | TransferMode::DeltaFixed => true,
            TransferMode::Skip => false,
            TransferMode::Auto => {
                (dst_file.exists() || chunk_store.is_some()) && src_size >= options.min_delta_size
            }
        };

        if !use_delta {
            if staged_file.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&staged_file);
            }
            std::fs::copy(&src_file, &staged_file)?;

            let src_sidecar = crate::storage::xattr_sidecar_path(&src_file);
            if src_sidecar.symlink_metadata().is_ok() {
                let staged_sidecar = crate::storage::xattr_sidecar_path(&staged_file);
                let _ = std::fs::copy(&src_sidecar, &staged_sidecar);
            }

            if let Ok(src_meta) = std::fs::metadata(&src_file) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &staged_file,
                        std::fs::Permissions::from_mode(src_meta.permissions().mode() & 0o777),
                    );
                }
                if let Ok(modified) = src_meta.modified() {
                    let _ = std::fs::FileTimes::new().set_modified(modified);
                }
            }

            staged_files.push((file_idx as u64, action.rel_path.clone(), staged_file));
            total_wire_bytes += src_size;
            continue;
        }

        // Build local inventory if destination file exists
        let dst_inventory = if dst_file.exists() {
            Some(LocalInventory::from_file(
                &dst_file,
                options.mode,
                options.params,
                options.read_buffer_size,
            )?)
        } else {
            None
        };

        // Scan source chunks
        let mut src_reader = std::io::BufReader::with_capacity(
            options.read_buffer_size.max(64 * 1024),
            File::open(&src_file)?,
        );
        let mut src_chunks = Vec::new();
        let mut current_offset = 0u64;

        let _ = ChunkEngine::chunk_reader(
            &mut src_reader,
            options.mode,
            options.params,
            options.read_buffer_size,
            |desc, _payload| {
                src_chunks.push((current_offset, desc.length, desc.hash));
                current_offset += desc.length;
                Ok(())
            },
        )
        .map_err(|e| SyncError::Reconstruction(format!("failed to scan source file: {e}")))?;

        let total_chunks = src_chunks.len();
        let mut have_sources = Vec::with_capacity(src_chunks.len());
        for &(_, _, maybe_hash) in &src_chunks {
            if let Some(h) = maybe_hash {
                if let Some(ref inv) = dst_inventory {
                    if inv.contains(&h) {
                        have_sources.push(1u8);
                        continue;
                    }
                }
                if let Some(store) = chunk_store {
                    if store.contains_sync(&h) {
                        have_sources.push(2u8);
                        continue;
                    }
                }
                have_sources.push(0u8);
            } else {
                // Sparse hole: 3
                have_sources.push(3u8);
            }
        }

        let temp_partial = staging_root.join(format!("{}.velcrux-partial", file_idx));
        let mut reconstructor = DeltaReconstructor::new(
            staged_file.clone(),
            temp_partial,
            src_hash,
            src_size,
            total_chunks,
        )?;

        let mut src_f = File::open(&src_file)?;
        let mut dst_f = if dst_file.exists() {
            Some(File::open(&dst_file)?)
        } else {
            None
        };
        let mut read_buf = vec![0u8; options.params.max as usize];

        for (i, &(offset, length, maybe_hash)) in src_chunks.iter().enumerate() {
            let src_source = have_sources[i];
            if src_source == 3 || maybe_hash.is_none() {
                reconstructor.skip_hole(length)?;
                total_local_reused += length;
                continue;
            }
            let hash = maybe_hash.unwrap();
            if src_source == 1 {
                if let Some(ref inv) = dst_inventory {
                    if let Some(extent) = inv.lookup(&hash) {
                        if let Some(ref mut df) = dst_f {
                            reconstructor.copy_local_chunk(df, extent.offset, offset, length)?;
                            total_local_reused += length;
                            continue;
                        }
                    }
                }
            } else if src_source == 2 {
                if let Some(store) = chunk_store {
                    reconstructor.copy_chunk_from_store(store, &hash, offset)?;
                    total_store_reused += length;
                    continue;
                }
            }

            // Wire transfer
            src_f.seek(SeekFrom::Start(offset))?;
            let slice = &mut read_buf[..length as usize];
            src_f.read_exact(slice)?;
            reconstructor.write_wire_chunk(offset, slice)?;
            total_wire_bytes += length;

            if let Some(store) = chunk_store {
                let _ = store.put_sync(&hash, slice);
            }
        }

        // Verify hash in staging
        reconstructor.verify_and_commit()?;

        let src_sidecar = crate::storage::xattr_sidecar_path(&src_file);
        if src_sidecar.symlink_metadata().is_ok() {
            let staged_sidecar = crate::storage::xattr_sidecar_path(&staged_file);
            let _ = std::fs::copy(&src_sidecar, &staged_sidecar);
        }

        if let Ok(src_meta) = std::fs::metadata(&src_file) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &staged_file,
                    std::fs::Permissions::from_mode(src_meta.permissions().mode()),
                );
            }
        }

        staged_files.push((file_idx as u64, action.rel_path.clone(), staged_file));
    }

    // --- COMMIT PHASE ---
    // All files are verified in staging. Now atomic renames into dst_dir with commit journal.
    let now_ms = current_time_ms();
    let mut files_committed = 0usize;

    if let Some(store) = state_store {
        let transfer_record = crate::state::TransferRecord {
            transfer_id,
            idempotency_key: format!("dir-sync-{}", transfer_id),
            role: crate::state::Role::Client,
            direction: crate::state::Direction::Upload,
            status: crate::state::TransferStatus::Active,
            remote_path: dst_dir.to_string_lossy().to_string(),
            local_path: src_dir.to_string_lossy().to_string(),
            file_size: plan.summary.data_to_transfer + plan.summary.data_present,
            file_hash: Hash::ZERO,
            verified_up_to: 0,
            last_checkpoint_ms: 0,
            bytes_completed: total_wire_bytes + total_local_reused + total_store_reused,
            staging_relpath: staging_root.to_string_lossy().to_string(),
            created_ms: now_ms,
            updated_ms: now_ms,
        };
        let _ = store.upsert_transfer(&transfer_record);
    }

    for (file_id, rel_path, staged_file) in &staged_files {
        let final_dst = dst_dir.join(rel_path);
        if let Some(p) = final_dst.parent() {
            std::fs::create_dir_all(p)?;
        }

        if let Some(store) = state_store {
            let journal_entry = CommitJournalEntry {
                transfer_id,
                file_id: *file_id,
                remote_path: rel_path.clone(),
                status: CommitStatus::Pending,
                updated_ms: now_ms,
            };
            store
                .write_journal(&journal_entry)
                .map_err(|e| SyncError::Reconstruction(e.to_string()))?;
        }

        // If target file or symlink exists at final destination, remove before rename
        if final_dst.symlink_metadata().is_ok() {
            let _ = std::fs::remove_file(&final_dst);
        }

        // Atomic rename
        std::fs::rename(staged_file, &final_dst)?;

        // If staged xattr sidecar exists, rename it into final location
        let staged_sidecar = crate::storage::xattr_sidecar_path(staged_file);
        if staged_sidecar.symlink_metadata().is_ok() {
            let final_sidecar = crate::storage::xattr_sidecar_path(&final_dst);
            if final_sidecar.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&final_sidecar);
            }
            let _ = std::fs::rename(&staged_sidecar, &final_sidecar);
        }

        // Apply mode permissions and mtime if regular file
        let src_file = src_dir.join(rel_path);
        if let Ok(src_meta) = std::fs::symlink_metadata(&src_file) {
            if !src_meta.file_type().is_symlink() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &final_dst,
                        std::fs::Permissions::from_mode(src_meta.permissions().mode()),
                    );
                }
                if let Ok(modified_time) = src_meta.modified() {
                    if let Ok(f) = std::fs::File::open(&final_dst) {
                        let times = std::fs::FileTimes::new().set_modified(modified_time);
                        let _ = f.set_times(times);
                    }
                }
            }
        }

        if let Some(store) = state_store {
            store
                .mark_journal_committed(transfer_id, *file_id)
                .map_err(|e| SyncError::Reconstruction(e.to_string()))?;
        }

        files_committed += 1;
    }

    // --- DELETIONS PHASE ---
    let mut files_deleted = 0usize;
    if options.delete_mode == DeleteMode::DeleteAfter {
        for action in &plan.actions {
            if action.action == FileActionType::Delete {
                let target = dst_dir.join(&action.rel_path);
                if target.symlink_metadata().is_ok() {
                    let _ = std::fs::remove_file(&target);
                    let sidecar = crate::storage::xattr_sidecar_path(&target);
                    if sidecar.symlink_metadata().is_ok() {
                        let _ = std::fs::remove_file(&sidecar);
                    }
                    files_deleted += 1;
                }
            }
        }
    }

    // Clean up staging directory
    let _ = std::fs::remove_dir_all(&staging_root);

    Ok(DirectorySyncResult {
        plan,
        files_transferred: staged_files.len(),
        files_committed,
        files_deleted,
        wire_bytes_transferred: total_wire_bytes,
        local_bytes_reused: total_local_reused,
        store_bytes_reused: total_store_reused,
        small_files_batched: batched_plan.small_files_count,
        batch_containers: batched_plan.batch_containers_count,
        roundtrips_saved: batched_plan.roundtrips_saved,
    })
}

/// Resume an interrupted commit by inspecting pending rows in the state store journal
/// and completing their renames into the destination directory.
///
/// Returns the number of files successfully resumed and finalized to `Committed`.
pub fn resume_interrupted_commit(
    state_store: &dyn StateStore,
    staging_root: &Path,
    dst_root: &Path,
    filter_transfer_id: Option<TransferId>,
) -> Result<usize, SyncError> {
    let pending = state_store
        .pending_journal()
        .map_err(|e| SyncError::Reconstruction(e.to_string()))?;

    let mut finalized_count = 0usize;

    for entry in pending {
        if let Some(expected_tid) = filter_transfer_id {
            if entry.transfer_id != expected_tid {
                continue;
            }
        }

        let final_dst = dst_root.join(&entry.remote_path);
        let staged_file = staging_root.join(&entry.remote_path);

        match entry.status {
            CommitStatus::Renamed => {
                // Rename already happened before crash; finalize journal row
                state_store
                    .mark_journal_committed(entry.transfer_id, entry.file_id)
                    .map_err(|e| SyncError::Reconstruction(e.to_string()))?;
                finalized_count += 1;
            }
            CommitStatus::Pending => {
                // File was still in staging when crash occurred
                if staged_file.exists() {
                    if let Some(p) = final_dst.parent() {
                        std::fs::create_dir_all(p)?;
                    }
                    std::fs::rename(&staged_file, &final_dst)?;
                    state_store
                        .mark_journal_committed(entry.transfer_id, entry.file_id)
                        .map_err(|e| SyncError::Reconstruction(e.to_string()))?;
                    finalized_count += 1;
                } else if final_dst.exists() {
                    // Rename actually completed immediately before crash
                    state_store
                        .mark_journal_committed(entry.transfer_id, entry.file_id)
                        .map_err(|e| SyncError::Reconstruction(e.to_string()))?;
                    finalized_count += 1;
                } else {
                    return Err(SyncError::Reconstruction(format!(
                        "cannot resume commit for {}: neither staged file {:?} nor destination {:?} exists",
                        entry.remote_path, staged_file, final_dst
                    )));
                }
            }
            CommitStatus::Committed => {
                // Should not appear in pending_journal, but harmless
            }
        }
    }

    Ok(finalized_count)
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_display() {
        let summary = DirectoryDiffSummary {
            files_unchanged: 12431,
            files_modified: 182,
            files_added: 31,
            files_deleted: 7,
            data_present: 4_820_000_000_000,
            data_to_transfer: 183_000_000_000,
            estimated_reduction: 96.4,
        };
        let out = summary.format_display();
        assert!(out.contains("Files unchanged:            12431"));
        assert!(out.contains("Files modified:               182"));
        assert!(out.contains("Files added:                   31"));
        assert!(out.contains("Files deleted:                  7"));
        assert!(out.contains("96.4%"));
    }

    #[test]
    fn test_plan_directory_diff_reconciliation() {
        let mut src = BTreeMap::new();
        let mut dst = BTreeMap::new();

        let h1 = Hash::from_bytes(&[1u8; 32]).unwrap();
        let h2 = Hash::from_bytes(&[2u8; 32]).unwrap();
        let h3 = Hash::from_bytes(&[3u8; 32]).unwrap();

        // 1. Unchanged
        src.insert("unchanged.txt".into(), ScannedEntry::file(100, h1));
        dst.insert("unchanged.txt".into(), ScannedEntry::file(100, h1));

        // 2. Modified
        src.insert("modified.txt".into(), ScannedEntry::file(200, h2));
        dst.insert("modified.txt".into(), ScannedEntry::file(200, h1));

        // 3. Added
        src.insert("added.txt".into(), ScannedEntry::file(300, h3));

        // 4. Deleted
        dst.insert("deleted.txt".into(), ScannedEntry::file(400, h2));

        let plan = plan_directory_diff(&src, &dst);
        assert_eq!(plan.summary.files_unchanged, 1);
        assert_eq!(plan.summary.files_modified, 1);
        assert_eq!(plan.summary.files_added, 1);
        assert_eq!(plan.summary.files_deleted, 1);
        assert_eq!(plan.summary.data_present, 100);
        assert_eq!(plan.summary.data_to_transfer, 500); // modified (200) + added (300)
    }

    #[test]
    fn test_plan_directory_diff_symlinks_and_hardlinks() {
        let mut src = BTreeMap::new();
        let mut dst = BTreeMap::new();

        // 1. Identical symlink
        src.insert(
            "link_same.txt".into(),
            ScannedEntry::symlink("../target1.txt".into()),
        );
        dst.insert(
            "link_same.txt".into(),
            ScannedEntry::symlink("../target1.txt".into()),
        );

        // 2. Modified symlink (target changed)
        src.insert(
            "link_changed.txt".into(),
            ScannedEntry::symlink("../target2_new.txt".into()),
        );
        dst.insert(
            "link_changed.txt".into(),
            ScannedEntry::symlink("../target2_old.txt".into()),
        );

        // 3. New symlink
        src.insert(
            "link_new.txt".into(),
            ScannedEntry::symlink("target3.txt".into()),
        );

        let plan = plan_directory_diff(&src, &dst);
        assert_eq!(plan.summary.files_unchanged, 1);
        assert_eq!(plan.summary.files_modified, 1);
        assert_eq!(plan.summary.files_added, 1);
    }

    #[test]
    fn test_diff_manifest_readers_streaming_reconciliation() {
        use crate::chunking::ChunkParams;
        use crate::manifest::entry::{ChunkDesc, FileEntry};
        use crate::manifest::writer::ManifestWriter;
        use crate::storage::VPath;
        use tempfile::tempdir;

        let td = tempdir().unwrap();
        let src_spill = td.path().join("src.spill");
        let dst_spill = td.path().join("dst.spill");

        let mut src_writer = ManifestWriter::new(&src_spill, ChunkParams::default()).unwrap();
        let mut dst_writer = ManifestWriter::new(&dst_spill, ChunkParams::default()).unwrap();

        let h1 = Hash::from_bytes(&[1u8; 32]).unwrap();
        let h2 = Hash::from_bytes(&[2u8; 32]).unwrap();
        let h3 = Hash::from_bytes(&[3u8; 32]).unwrap();

        // 1. Unchanged: "a_unchanged.dat" (size 100, h1)
        let c1 = ChunkDesc::new(100, h1);
        let e_unc = FileEntry::regular(
            VPath::validate("a_unchanged.dat").unwrap(),
            100,
            0o644,
            1000,
            0,
            h1,
            vec![c1],
        );
        src_writer.add_entry(e_unc.clone()).unwrap();
        dst_writer.add_entry(e_unc).unwrap();

        // 2. Added on src: "b_added.dat" (size 250, h2)
        let c2 = ChunkDesc::new(250, h2);
        let e_add = FileEntry::regular(
            VPath::validate("b_added.dat").unwrap(),
            250,
            0o644,
            1000,
            0,
            h2,
            vec![c2],
        );
        src_writer.add_entry(e_add).unwrap();

        // 3. Modified: "c_modified.dat" (src size 300, h3; dst size 300, h1)
        let c3_src = ChunkDesc::new(300, h3);
        let e_mod_src = FileEntry::regular(
            VPath::validate("c_modified.dat").unwrap(),
            300,
            0o644,
            1000,
            0,
            h3,
            vec![c3_src],
        );
        let c3_dst = ChunkDesc::new(300, h1);
        let e_mod_dst = FileEntry::regular(
            VPath::validate("c_modified.dat").unwrap(),
            300,
            0o644,
            1000,
            0,
            h1,
            vec![c3_dst],
        );
        src_writer.add_entry(e_mod_src).unwrap();
        dst_writer.add_entry(e_mod_dst).unwrap();

        // 4. Deleted on dst: "d_deleted.dat" (size 400, h2)
        let c4 = ChunkDesc::new(400, h2);
        let e_del = FileEntry::regular(
            VPath::validate("d_deleted.dat").unwrap(),
            400,
            0o644,
            1000,
            0,
            h2,
            vec![c4],
        );
        dst_writer.add_entry(e_del).unwrap();

        let (src_begin, _, src_path) = src_writer.finish().unwrap();
        let (dst_begin, _, dst_path) = dst_writer.finish().unwrap();

        let mut actions = Vec::new();
        let summary = diff_manifest_spill_files(
            &src_path,
            src_begin.manifest_hash,
            &dst_path,
            dst_begin.manifest_hash,
            |act| actions.push(act),
        )
        .unwrap();

        assert_eq!(summary.files_unchanged, 1);
        assert_eq!(summary.files_added, 1);
        assert_eq!(summary.files_modified, 1);
        assert_eq!(summary.files_deleted, 1);
        assert_eq!(summary.data_present, 100);
        assert_eq!(summary.data_to_transfer, 550); // added (250) + modified (300)
        assert_eq!(actions.len(), 4);
    }
}
