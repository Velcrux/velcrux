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
}

impl Default for DirectorySyncOptions {
    fn default() -> Self {
        Self {
            mode: ChunkMode::Cdc,
            params: ChunkParams::default(),
            delete_mode: DeleteMode::None,
            dry_run: false,
            read_buffer_size: 2 * 1024 * 1024,
        }
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
}

/// Helper representing scanned file metadata.
#[derive(Debug, Clone)]
struct ScannedFile {
    size: u64,
}

/// Scanned directory entry with size and whole-file BLAKE3 hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedEntry {
    pub size: u64,
    pub hash: Hash,
}

/// Recursively scan all files in a directory root and compute their size and whole-file hash.
pub fn scan_dir_entries(root: &Path) -> std::io::Result<BTreeMap<String, ScannedEntry>> {
    let mut files = BTreeMap::new();
    if !root.exists() {
        return Ok(files);
    }

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;

            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            // Skip staging, chunk store, and partial files
            if name_str.starts_with(".velcrux-staging")
                || name_str.starts_with(".velcrux-chunks")
                || name_str.ends_with(".velcrux-partial")
            {
                continue;
            }

            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let rel_str = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join("/");

                let metadata = entry.metadata()?;
                let hash = compute_file_hash(&path)?;
                files.insert(
                    rel_str,
                    ScannedEntry {
                        size: metadata.len(),
                        hash,
                    },
                );
            }
        }
    }

    Ok(files)
}

fn scan_dir_files(root: &Path) -> std::io::Result<BTreeMap<String, ScannedFile>> {
    let mut files = BTreeMap::new();
    if !root.exists() {
        return Ok(files);
    }

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;

            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            // Skip staging and partial files
            if name_str.starts_with(".velcrux-staging")
                || name_str.starts_with(".velcrux-chunks")
                || name_str.ends_with(".velcrux-partial")
            {
                continue;
            }

            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let rel_str = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join("/");

                let metadata = entry.metadata()?;

                files.insert(
                    rel_str,
                    ScannedFile {
                        size: metadata.len(),
                    },
                );
            }
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
                if sf.size == df.size && sf.hash == df.hash {
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
        let mut chunks = Vec::new();
        let mut remaining = entry.size;
        while remaining > 0 {
            let chunk_len = remaining.min(crate::protocol::limits::MAX_CHUNK_SIZE);
            chunks.push(crate::manifest::entry::ChunkDesc::new(
                chunk_len, entry.hash,
            ));
            remaining -= chunk_len;
        }
        let fe = FileEntry::regular(vpath, entry.size, 0o644, 0, 0, entry.hash, chunks);
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
                entries.insert(
                    fe.path.as_str().to_string(),
                    ScannedEntry {
                        size: fe.size,
                        hash: fe.file_hash,
                    },
                );
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

/// Compute a directory sync plan by scanning source and destination directories.
pub fn plan_directory_sync(
    src_dir: &Path,
    dst_dir: &Path,
    options: &DirectorySyncOptions,
    chunk_store: Option<&LocalChunkStore>,
) -> Result<DirectoryPlan, SyncError> {
    let src_files = scan_dir_files(src_dir)?;
    let dst_files = scan_dir_files(dst_dir)?;

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
                let src_full = src_dir.join(&rel_path);
                let dst_full = dst_dir.join(&rel_path);

                // Quick metadata check: if size matches, check content hash
                let (is_same, src_hash) = if sf.size == df.size {
                    let sh = compute_file_hash(&src_full)?;
                    let dh = compute_file_hash(&dst_full)?;
                    (sh == dh, Some(sh))
                } else {
                    let sh = compute_file_hash(&src_full)?;
                    (false, Some(sh))
                };

                if is_same {
                    files_unchanged += 1;
                    data_present += sf.size;
                    actions.push(FileAction {
                        rel_path,
                        action: FileActionType::Unchanged,
                        src_size: sf.size,
                        dst_size: df.size,
                        src_hash,
                        bytes_to_transfer: 0,
                        bytes_reusable: sf.size,
                    });
                } else {
                    files_modified += 1;
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
                        src_hash,
                        bytes_to_transfer: needed,
                        bytes_reusable: reusable,
                    });
                }
            }
            (Some(sf), None) => {
                files_added += 1;
                let src_full = src_dir.join(&rel_path);
                let sh = compute_file_hash(&src_full)?;

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

    // --- STAGE & TRANSFER & VERIFY PHASE ---
    for (file_idx, action) in plan.actions.iter().enumerate() {
        if action.action != FileActionType::Add && action.action != FileActionType::Modify {
            continue;
        }

        let src_file = src_dir.join(&action.rel_path);
        let dst_file = dst_dir.join(&action.rel_path);
        let staged_file = staging_root.join(&action.rel_path);

        if let Some(parent) = staged_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let src_size = action.src_size;
        let src_hash = action.src_hash.expect("src hash present for Add/Modify");

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

        // Atomic rename
        std::fs::rename(staged_file, &final_dst)?;

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
                if target.exists() {
                    let _ = std::fs::remove_file(target);
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
        src.insert(
            "unchanged.txt".into(),
            ScannedEntry {
                size: 100,
                hash: h1,
            },
        );
        dst.insert(
            "unchanged.txt".into(),
            ScannedEntry {
                size: 100,
                hash: h1,
            },
        );

        // 2. Modified
        src.insert(
            "modified.txt".into(),
            ScannedEntry {
                size: 200,
                hash: h2,
            },
        );
        dst.insert(
            "modified.txt".into(),
            ScannedEntry {
                size: 200,
                hash: h1,
            },
        );

        // 3. Added
        src.insert(
            "added.txt".into(),
            ScannedEntry {
                size: 300,
                hash: h3,
            },
        );

        // 4. Deleted
        dst.insert(
            "deleted.txt".into(),
            ScannedEntry {
                size: 400,
                hash: h2,
            },
        );

        let plan = plan_directory_diff(&src, &dst);
        assert_eq!(plan.summary.files_unchanged, 1);
        assert_eq!(plan.summary.files_modified, 1);
        assert_eq!(plan.summary.files_added, 1);
        assert_eq!(plan.summary.files_deleted, 1);
        assert_eq!(plan.summary.data_present, 100);
        assert_eq!(plan.summary.data_to_transfer, 500); // modified (200) + added (300)
    }
}
