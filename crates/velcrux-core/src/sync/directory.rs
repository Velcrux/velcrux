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
            if name_str.starts_with(".velcrux-staging") || name_str.ends_with(".velcrux-partial") {
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

fn compute_file_hash(path: &Path) -> std::io::Result<Hash> {
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
                            if let Some(h) = desc.hash {
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
                        if let Some(h) = desc.hash {
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
    let staging_root = dst_dir.join(".velcrux-staging").join(transfer_id.to_string());
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
                if let Some(hash) = desc.hash {
                    src_chunks.push((current_offset, desc.length, hash));
                }
                current_offset += desc.length;
                Ok(())
            },
        )
        .map_err(|e| SyncError::Reconstruction(format!("failed to scan source file: {e}")))?;

        let total_chunks = src_chunks.len();
        let query_hashes: Vec<_> = src_chunks.iter().map(|(_, _, h)| *h).collect();

        let mut have_sources = Vec::with_capacity(query_hashes.len());
        for h in &query_hashes {
            if let Some(ref inv) = dst_inventory {
                if inv.contains(h) {
                    have_sources.push(1u8);
                    continue;
                }
            }
            if let Some(store) = chunk_store {
                if store.contains_sync(h) {
                    have_sources.push(2u8);
                    continue;
                }
            }
            have_sources.push(0u8);
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

        for (i, &(offset, length, hash)) in src_chunks.iter().enumerate() {
            let src_source = have_sources[i];
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
}
