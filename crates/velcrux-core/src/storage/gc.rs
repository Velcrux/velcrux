//! Garbage collection for orphaned staging files and unreferenced deduplication chunks (`docs/OPERATIONS.md` §6).

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::chunking::{ChunkEngine, ChunkMode, ChunkParams};
use crate::error::VelcruxError;
use crate::state::{Role, StateStore, TransferStatus};
use crate::storage::chunk_store::LocalChunkStore;
use crate::util::Hash;

/// Report from a staging garbage collection sweep.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StagingGcReport {
    /// Total entries scanned in the staging directory.
    pub entries_scanned: usize,
    /// Number of orphaned staging entries identified.
    pub orphans_found: usize,
    /// Number of orphaned staging entries deleted (0 if dry_run).
    pub orphans_deleted: usize,
    /// Total bytes of disk space reclaimable or reclaimed.
    pub bytes_reclaimed: u64,
}

/// Report from a chunk store garbage collection sweep.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChunkStoreGcReport {
    /// Total chunks scanned in the chunk store.
    pub chunks_scanned: usize,
    /// Number of unreferenced chunks identified.
    pub unreferenced_found: usize,
    /// Number of unreferenced chunks deleted (0 if dry_run).
    pub unreferenced_deleted: usize,
    /// Total bytes of disk space reclaimable or reclaimed.
    pub bytes_reclaimed: u64,
}

/// Recursively calculate total size of a path (file or directory).
fn path_size(path: &Path) -> u64 {
    if let Ok(meta) = path.metadata() {
        if meta.is_file() {
            return meta.len();
        }
    }
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                total += path_size(&p);
            } else if let Ok(m) = p.metadata() {
                total += m.len();
            }
        }
    }
    total
}

/// Garbage-collect orphaned staging directories and partial files.
///
/// Removes any staging files or directories corresponding to completed, cancelled,
/// or non-existent transfers. Active and Resumable transfers are preserved intact.
pub fn gc_staging(
    staging_dir: &Path,
    state_store: &dyn StateStore,
    dry_run: bool,
) -> Result<StagingGcReport, VelcruxError> {
    let mut report = StagingGcReport::default();
    if !staging_dir.exists() {
        return Ok(report);
    }

    // Query transfers from state store
    let mut active_tids = HashSet::new();

    for role in [Role::Server, Role::Client] {
        if let Ok(records) = state_store.list_transfers_by_path(role, "") {
            for record in records {
                let tid = record.transfer_id.to_string();
                let safe_tid: String = tid
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                    .collect();

                match record.status {
                    TransferStatus::Active | TransferStatus::Resumable => {
                        active_tids.insert(tid);
                        active_tids.insert(safe_tid);
                    }
                    TransferStatus::Cancelled | TransferStatus::Committed => {
                        // Terminal: staging should be swept if present
                    }
                }
            }
        }
    }

    let entries = fs::read_dir(staging_dir)?;
    for entry in entries.flatten() {
        report.entries_scanned += 1;
        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Check if this staging entry is associated with an active or resumable transfer
        let is_active = active_tids
            .iter()
            .any(|tid| name_str.starts_with(tid) || tid.starts_with(&*name_str));

        if !is_active {
            // Identified as orphaned staging entry
            report.orphans_found += 1;
            let size = path_size(&path);
            report.bytes_reclaimed += size;

            if !dry_run {
                if path.is_dir() {
                    let _ = fs::remove_dir_all(&path);
                } else {
                    let _ = fs::remove_file(&path);
                }
                report.orphans_deleted += 1;
            }
        }
    }

    Ok(report)
}

/// Recursively walk `dir` and index all chunk hashes belonging to existing files.
fn collect_referenced_hashes(dir: &Path, out: &mut HashSet<Hash>) -> Result<(), VelcruxError> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_referenced_hashes(&path, out)?;
        } else if path.is_file() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with(".velcrux-partial") || name.starts_with(".partial_") {
                continue;
            }

            // Chunk with Fixed 64 KiB
            let fixed_64k = ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap();
            if let Ok(f) = fs::File::open(&path) {
                let reader = std::io::BufReader::new(f);
                let _ = ChunkEngine::chunk_reader(
                    reader,
                    ChunkMode::Fixed,
                    fixed_64k,
                    64 * 1024,
                    |desc, _payload| {
                        if let Some(h) = desc.hash {
                            out.insert(h);
                        }
                        Ok(())
                    },
                );
            }

            // Chunk with Fixed 1 MiB
            let fixed_1m = ChunkParams::new(1024 * 1024, 1024 * 1024, 1024 * 1024).unwrap();
            if let Ok(f) = fs::File::open(&path) {
                let reader = std::io::BufReader::new(f);
                let _ = ChunkEngine::chunk_reader(
                    reader,
                    ChunkMode::Fixed,
                    fixed_1m,
                    1024 * 1024,
                    |desc, _payload| {
                        if let Some(h) = desc.hash {
                            out.insert(h);
                        }
                        Ok(())
                    },
                );
            }

            // Chunk with default CDC
            let cdc_params = ChunkParams::default();
            if let Ok(f) = fs::File::open(&path) {
                let reader = std::io::BufReader::new(f);
                let _ = ChunkEngine::chunk_reader(
                    reader,
                    ChunkMode::Cdc,
                    cdc_params,
                    cdc_params.max as usize,
                    |desc, _payload| {
                        if let Some(h) = desc.hash {
                            out.insert(h);
                        }
                        Ok(())
                    },
                );
            }
        }
    }

    Ok(())
}

/// Garbage-collect unreferenced chunks in a content-addressed chunk store.
///
/// Scans the given `storage_roots` to identify active chunk references, then sweeps
/// any chunks in `chunk_store` that are not referenced by existing storage files.
pub fn gc_chunk_store(
    chunk_store: &LocalChunkStore,
    storage_roots: &[&Path],
    dry_run: bool,
) -> Result<ChunkStoreGcReport, VelcruxError> {
    let mut report = ChunkStoreGcReport::default();

    // 1. Gather all live referenced hashes
    let mut referenced_hashes = HashSet::new();
    for root in storage_roots {
        collect_referenced_hashes(root, &mut referenced_hashes)?;
    }

    let chunks_dir = chunk_store.chunks_dir();
    if !chunks_dir.exists() {
        return Ok(report);
    }

    // 2. Scan all chunks in the two-level directory hierarchy
    let mut chunks_to_delete = Vec::new();
    let mut empty_parents = Vec::new();

    if let Ok(d1_entries) = fs::read_dir(chunks_dir) {
        for d1 in d1_entries.flatten() {
            if d1.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let d1_path = d1.path();
                if let Ok(d2_entries) = fs::read_dir(&d1_path) {
                    for d2 in d2_entries.flatten() {
                        if d2.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                            let d2_path = d2.path();
                            if let Ok(chunk_entries) = fs::read_dir(&d2_path) {
                                for f in chunk_entries.flatten() {
                                    let path = f.path();
                                    let name = f.file_name();
                                    let s = name.to_string_lossy();
                                    if let Some(hex) = s.strip_suffix(".chunk") {
                                        report.chunks_scanned += 1;
                                        if let Some(h) = Hash::from_hex(hex) {
                                            if !referenced_hashes.contains(&h) {
                                                let size =
                                                    f.metadata().map(|m| m.len()).unwrap_or(0);
                                                report.unreferenced_found += 1;
                                                report.bytes_reclaimed += size;
                                                chunks_to_delete.push(path);
                                            }
                                        }
                                    }
                                }
                            }
                            empty_parents.push(d2_path);
                        }
                    }
                }
                empty_parents.push(d1_path);
            }
        }
    }

    // 3. Delete unreferenced chunks if not dry_run
    if !dry_run {
        for p in chunks_to_delete {
            if fs::remove_file(p).is_ok() {
                report.unreferenced_deleted += 1;
            }
        }

        // Clean up empty directories
        for p in empty_parents {
            let _ = fs::remove_dir(p);
        }

        if report.unreferenced_deleted > 0 {
            chunk_store.rebuild_bloom_sync()?;
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Direction, MockStateStore, TransferRecord};
    use crate::util::TransferId;
    use tempfile::tempdir;

    #[test]
    fn test_gc_staging_orphans() {
        let temp = tempdir().unwrap();
        let staging = temp.path().join("staging");
        fs::create_dir_all(&staging).unwrap();

        let state_store = MockStateStore::new();

        let tid_active = TransferId::generate();
        let tid_cancelled = TransferId::generate();

        let rec_active = TransferRecord {
            transfer_id: tid_active,
            idempotency_key: "active-1".into(),
            role: Role::Server,
            direction: Direction::Upload,
            status: TransferStatus::Active,
            remote_path: "/active.bin".into(),
            local_path: String::new(),
            file_size: 1024,
            file_hash: Hash::ZERO,
            verified_up_to: 0,
            last_checkpoint_ms: 0,
            bytes_completed: 0,
            staging_relpath: String::new(),
            created_ms: 0,
            updated_ms: 0,
        };
        state_store.upsert_transfer(&rec_active).unwrap();

        let rec_cancelled = TransferRecord {
            transfer_id: tid_cancelled,
            idempotency_key: "cancelled-1".into(),
            role: Role::Server,
            direction: Direction::Upload,
            status: TransferStatus::Cancelled,
            remote_path: "/cancelled.bin".into(),
            local_path: String::new(),
            file_size: 2048,
            file_hash: Hash::ZERO,
            verified_up_to: 0,
            last_checkpoint_ms: 0,
            bytes_completed: 0,
            staging_relpath: String::new(),
            created_ms: 0,
            updated_ms: 0,
        };
        state_store.upsert_transfer(&rec_cancelled).unwrap();

        // Create staging entries on disk
        let active_dir = staging.join(tid_active.to_string());
        fs::create_dir_all(&active_dir).unwrap();
        fs::write(active_dir.join("part.bin"), &[0xAA; 1024]).unwrap();

        let cancelled_dir = staging.join(tid_cancelled.to_string());
        fs::create_dir_all(&cancelled_dir).unwrap();
        fs::write(cancelled_dir.join("part.bin"), &[0xBB; 2048]).unwrap();

        let unknown_file = staging.join("orphaned_unknown.velcrux-partial");
        fs::write(&unknown_file, &[0xCC; 512]).unwrap();

        // Dry run first
        let report_dry = gc_staging(&staging, &state_store, true).unwrap();
        assert_eq!(report_dry.entries_scanned, 3);
        assert_eq!(report_dry.orphans_found, 2);
        assert_eq!(report_dry.orphans_deleted, 0);
        assert_eq!(report_dry.bytes_reclaimed, 2048 + 512);

        assert!(active_dir.exists());
        assert!(cancelled_dir.exists());
        assert!(unknown_file.exists());

        // Real GC execution
        let report = gc_staging(&staging, &state_store, false).unwrap();
        assert_eq!(report.orphans_found, 2);
        assert_eq!(report.orphans_deleted, 2);
        assert_eq!(report.bytes_reclaimed, 2048 + 512);

        // Active staging is strictly preserved
        assert!(active_dir.exists());
        // Cancelled and unknown orphans are removed
        assert!(!cancelled_dir.exists());
        assert!(!unknown_file.exists());
    }

    #[tokio::test]
    async fn test_gc_chunk_store_unreferenced() {
        let temp = tempdir().unwrap();
        let cs_root = temp.path().join("chunk_store");
        let storage_root = temp.path().join("storage");
        fs::create_dir_all(&storage_root).unwrap();

        let cs = LocalChunkStore::new(&cs_root).await.unwrap();

        // Live file in storage root
        let live_file = storage_root.join("live.bin");
        let live_data = vec![0x42u8; 64 * 1024];
        fs::write(&live_file, &live_data).unwrap();

        // Ingest live file chunks into store
        let params = ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap();
        cs.ingest_file_sync(&live_file, ChunkMode::Fixed, params)
            .unwrap();

        // Add an extra unreferenced chunk
        let dead_data = vec![0x99u8; 1024];
        let dead_hash = Hash::of(&dead_data);
        cs.put_sync(&dead_hash, &dead_data).unwrap();

        assert!(cs.contains_sync(&dead_hash));

        // Dry run
        let report_dry = gc_chunk_store(&cs, &[&storage_root], true).unwrap();
        assert_eq!(report_dry.unreferenced_found, 1);
        assert_eq!(report_dry.unreferenced_deleted, 0);
        assert_eq!(report_dry.bytes_reclaimed, 1024);
        assert!(cs.contains_sync(&dead_hash));

        // Real GC
        let report = gc_chunk_store(&cs, &[&storage_root], false).unwrap();
        assert_eq!(report.unreferenced_found, 1);
        assert_eq!(report.unreferenced_deleted, 1);
        assert_eq!(report.bytes_reclaimed, 1024);

        // Dead chunk was swept, live chunk preserved
        assert!(!cs.contains_sync(&dead_hash));
        let live_hash = Hash::of(&live_data);
        assert!(cs.contains_sync(&live_hash));
    }
}
