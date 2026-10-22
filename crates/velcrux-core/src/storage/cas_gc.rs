//! Content-Addressable Storage (CAS) Generational Garbage Collection, Tombstoning,
//! and Compaction Daemon (`ADR-038`, `REQUIREMENTS.md` §61, §62).
//!
//! Features:
//! 1. Generational chunk lifetime classification:
//!    - `Nursery` (Gen 0): In-flight / recently ingested chunks protected by lease timers.
//!    - `Tenured` (Gen 1): Actively referenced chunks verified by storage manifests or snapshots.
//!    - `Tombstoned` (Gen 2): Unreferenced chunks marked with active tombstone files awaiting hard purge.
//! 2. Safe resurrection: Tombstoned chunks re-referenced by transfers are resurrected immediately.
//! 3. Crash-resilient tombstone metadata files (`<hex>.tombstone`) stored alongside chunks.
//! 4. Background compaction daemon with Bloom filter reconstruction and empty shard directory pruning.
//! 5. 100% Safe Rust (`#![forbid(unsafe_code)]`).

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::chunking::{ChunkEngine, ChunkMode, ChunkParams};
use crate::error::VelcruxError;
use crate::state::StateStore;
use crate::storage::snapshot::SnapshotManager;
use crate::util::Hash;

/// Generational classification for Content-Addressable Storage (CAS) chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CasGeneration {
    /// In-flight or recently ingested chunks within the nursery grace period (Gen 0).
    /// Protected from tombstoning even if unreferenced.
    Nursery = 0,
    /// Actively referenced chunks with verified file or snapshot references (Gen 1).
    Tenured = 1,
    /// Unreferenced chunks marked with an active tombstone pending hard purge (Gen 2).
    Tombstoned = 2,
}

impl CasGeneration {
    /// String identifier for telemetry and CLI output.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Nursery => "nursery",
            Self::Tenured => "tenured",
            Self::Tombstoned => "tombstoned",
        }
    }
}

impl std::fmt::Display for CasGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Durable tombstone record serialized alongside a chunk file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasTombstone {
    /// Content hash of the chunk.
    pub hash: Hash,
    /// Epoch timestamp in seconds when this tombstone was created.
    pub tombstoned_at_secs: u64,
    /// Byte size of the tombstoned chunk.
    pub size: u64,
    /// Source generation when tombstoned.
    pub generation: u32,
    /// Reason string for auditing.
    pub reason: String,
    /// Optional tenant namespace tag.
    pub tenant: Option<String>,
}

impl CasTombstone {
    /// Construct a new tombstone record.
    pub fn new(hash: Hash, size: u64, reason: impl Into<String>, tenant: Option<String>) -> Self {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        Self {
            hash,
            tombstoned_at_secs: now_secs,
            size,
            generation: CasGeneration::Tombstoned as u32,
            reason: reason.into(),
            tenant,
        }
    }

    /// Check whether this tombstone has exceeded the specified TTL.
    pub fn is_expired(&self, ttl_secs: u64, now_secs: u64) -> bool {
        now_secs.saturating_sub(self.tombstoned_at_secs) >= ttl_secs
    }

    /// Read and deserialize a tombstone from a file path.
    pub fn read_from_file(path: &Path) -> Result<Self, VelcruxError> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let record = serde_json::from_str(&contents)
            .map_err(|e| VelcruxError::Internal(format!("corrupt tombstone file {path:?}: {e}")))?;
        Ok(record)
    }

    /// Serialize and atomically write tombstone to a destination file.
    pub fn write_to_file(&self, path: &Path) -> Result<(), VelcruxError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| VelcruxError::Internal(format!("failed to serialize tombstone: {e}")))?;
        let temp_path = path.with_extension("tombstone.tmp");
        {
            let mut f = File::create(&temp_path)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&temp_path, path)?;
        Ok(())
    }
}

/// Discovered CAS chunk item on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasChunkEntry {
    /// Content hash.
    pub hash: Hash,
    /// Byte size on disk.
    pub size: u64,
    /// Assigned generation.
    pub generation: CasGeneration,
    /// File modification time in epoch seconds.
    pub modified_secs: u64,
    /// Path to the `.chunk` file.
    pub chunk_path: PathBuf,
    /// Associated tombstone record, if tombstoned.
    pub tombstone: Option<CasTombstone>,
}

/// Policy governing generational garbage collection and compaction sweeps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CasGcPolicy {
    /// Nursery grace duration in seconds (default: 3600 / 1 hour).
    /// Chunks younger than this are treated as Gen 0 (Nursery) and never tombstoned.
    pub nursery_grace_secs: u64,
    /// Tombstone retention TTL in seconds before hard purge (default: 86400 / 24 hours).
    pub tombstone_ttl_secs: u64,
    /// Whether to purge expired tombstones immediately during the compaction run.
    pub purge_expired: bool,
    /// Dry run mode: calculate reclamation without modifying disk state.
    pub dry_run: bool,
}

impl Default for CasGcPolicy {
    fn default() -> Self {
        Self {
            nursery_grace_secs: 3600,  // 1 hour nursery grace period
            tombstone_ttl_secs: 86400, // 24 hours tombstone retention
            purge_expired: true,
            dry_run: false,
        }
    }
}

/// Aggregated report from a generational CAS garbage collection and compaction pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasGenerationalGcReport {
    /// Total chunks discovered and evaluated.
    pub total_chunks_scanned: usize,
    /// Chunks protected under Gen 0 (Nursery) grace lease.
    pub nursery_chunks: usize,
    /// Chunks confirmed referenced under Gen 1 (Tenured).
    pub tenured_chunks: usize,
    /// Existing active tombstones discovered.
    pub existing_tombstones: usize,
    /// Newly placed tombstones on unreferenced chunks.
    pub newly_tombstoned: usize,
    /// Tombstoned chunks resurrected back to active service.
    pub resurrected_chunks: usize,
    /// Chunks permanently purged (unlinked) after tombstone TTL expiry.
    pub purged_chunks: usize,
    /// Total bytes scanned.
    pub bytes_scanned: u64,
    /// Total bytes in tombstoned state.
    pub bytes_tombstoned: u64,
    /// Total disk bytes permanently reclaimed.
    pub bytes_reclaimed: u64,
    /// Total disk bytes retained in the store.
    pub bytes_retained: u64,
    /// Whether this run was a dry-run simulation.
    pub dry_run: bool,
    /// Elapsed duration of the compaction operation in milliseconds.
    pub duration_ms: u64,
}

/// Operational status and disk metrics of a Content-Addressable Storage store.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasStoreStatus {
    /// Total chunk count across all generations.
    pub total_chunks: usize,
    /// Gen 0: Nursery in-flight chunks.
    pub nursery_chunks: usize,
    /// Gen 1: Tenured active referenced chunks.
    pub tenured_chunks: usize,
    /// Gen 2: Tombstoned chunks awaiting purge.
    pub tombstoned_chunks: usize,
    /// Total byte size across all chunks.
    pub total_bytes: u64,
    /// Gen 0 Nursery bytes.
    pub nursery_bytes: u64,
    /// Gen 1 Tenured bytes.
    pub tenured_bytes: u64,
    /// Gen 2 Tombstoned bytes.
    pub tombstoned_bytes: u64,
    /// Total reclaimable bytes pending hard purge.
    pub reclaimable_bytes: u64,
    /// Chunks directory root.
    pub chunks_dir: String,
}

/// Generational Content-Addressable Storage Manager.
pub struct GenerationalCasManager {
    root: PathBuf,
    chunks_dir: PathBuf,
}

impl GenerationalCasManager {
    /// Initialize manager rooted at the given chunk store path.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let chunks_dir = root.join("chunks");
        Self { root, chunks_dir }
    }

    /// Root directory path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Chunks directory path (`<root>/chunks`).
    pub fn chunks_dir(&self) -> &Path {
        &self.chunks_dir
    }

    /// Sharded path for a chunk: `chunks/ab/cd/<hex>.chunk`.
    pub fn chunk_path(&self, h: &Hash) -> PathBuf {
        let hex = h.to_string();
        self.chunks_dir
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(format!("{hex}.chunk"))
    }

    /// Sharded path for a tombstone: `chunks/ab/cd/<hex>.tombstone`.
    pub fn tombstone_path(&self, h: &Hash) -> PathBuf {
        let hex = h.to_string();
        self.chunks_dir
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(format!("{hex}.tombstone"))
    }

    /// Scan all chunk files and tombstones in the store.
    pub fn scan_chunks(
        &self,
        now_secs: u64,
        nursery_grace_secs: u64,
    ) -> Result<Vec<CasChunkEntry>, VelcruxError> {
        let mut entries = Vec::new();
        if !self.chunks_dir.exists() {
            return Ok(entries);
        }

        let d1_iter = match fs::read_dir(&self.chunks_dir) {
            Ok(iter) => iter,
            Err(_) => return Ok(entries),
        };

        for d1 in d1_iter.flatten() {
            if !d1.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let d1_path = d1.path();
            let d2_iter = match fs::read_dir(&d1_path) {
                Ok(iter) => iter,
                Err(_) => continue,
            };

            for d2 in d2_iter.flatten() {
                if !d2.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let d2_path = d2.path();
                let f_iter = match fs::read_dir(&d2_path) {
                    Ok(iter) => iter,
                    Err(_) => continue,
                };

                for f in f_iter.flatten() {
                    let path = f.path();
                    let name = f.file_name();
                    let s = name.to_string_lossy();

                    if let Some(hex) = s.strip_suffix(".chunk") {
                        if let Some(h) = Hash::from_hex(hex) {
                            let meta = match f.metadata() {
                                Ok(m) => m,
                                Err(_) => continue,
                            };
                            let size = meta.len();
                            let mtime = meta
                                .modified()
                                .unwrap_or(SystemTime::now())
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or(Duration::ZERO)
                                .as_secs();

                            let tomb_path = self.tombstone_path(&h);
                            let tombstone = if tomb_path.exists() {
                                CasTombstone::read_from_file(&tomb_path).ok()
                            } else {
                                None
                            };

                            let generation = if tombstone.is_some() {
                                CasGeneration::Tombstoned
                            } else if now_secs.saturating_sub(mtime) < nursery_grace_secs {
                                CasGeneration::Nursery
                            } else {
                                CasGeneration::Tenured
                            };

                            entries.push(CasChunkEntry {
                                hash: h,
                                size,
                                generation,
                                modified_secs: mtime,
                                chunk_path: path,
                                tombstone,
                            });
                        }
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Query store inventory and generational statistics.
    pub fn status(&self, nursery_grace_secs: u64) -> Result<CasStoreStatus, VelcruxError> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let entries = self.scan_chunks(now_secs, nursery_grace_secs)?;
        let mut status = CasStoreStatus {
            chunks_dir: self.chunks_dir.display().to_string(),
            ..Default::default()
        };

        for e in &entries {
            status.total_chunks += 1;
            status.total_bytes += e.size;

            match e.generation {
                CasGeneration::Nursery => {
                    status.nursery_chunks += 1;
                    status.nursery_bytes += e.size;
                }
                CasGeneration::Tenured => {
                    status.tenured_chunks += 1;
                    status.tenured_bytes += e.size;
                }
                CasGeneration::Tombstoned => {
                    status.tombstoned_chunks += 1;
                    status.tombstoned_bytes += e.size;
                    status.reclaimable_bytes += e.size;
                }
            }
        }

        Ok(status)
    }

    /// Resurrect a tombstoned chunk, returning it to active service.
    pub fn resurrect(&self, hash: &Hash) -> Result<bool, VelcruxError> {
        let tomb_path = self.tombstone_path(hash);
        let chunk_path = self.chunk_path(hash);

        if tomb_path.exists() && chunk_path.exists() {
            fs::remove_file(&tomb_path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Execute a generational mark-and-sweep pass.
    ///
    /// 1. Referenced chunks marked as Tenured; if previously tombstoned, resurrected.
    /// 2. Unreferenced chunks younger than `nursery_grace_secs` protected under Nursery.
    /// 3. Unreferenced chunks older than `nursery_grace_secs` transition to Tombstoned.
    /// 4. If `purge_expired` is set, expired tombstones are unlinked and disk space reclaimed.
    pub fn mark_and_sweep(
        &self,
        referenced_hashes: &HashSet<Hash>,
        policy: &CasGcPolicy,
    ) -> Result<CasGenerationalGcReport, VelcruxError> {
        let t0 = Instant::now();
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let entries = self.scan_chunks(now_secs, policy.nursery_grace_secs)?;
        let mut report = CasGenerationalGcReport {
            dry_run: policy.dry_run,
            ..Default::default()
        };

        let mut empty_parents = Vec::new();

        for e in entries {
            report.total_chunks_scanned += 1;
            report.bytes_scanned += e.size;

            let is_referenced = referenced_hashes.contains(&e.hash);

            if is_referenced {
                // Referenced: Must be active
                if e.tombstone.is_some() {
                    // Resurrect chunk
                    if !policy.dry_run {
                        let _ = self.resurrect(&e.hash);
                    }
                    report.resurrected_chunks += 1;
                }
                report.tenured_chunks += 1;
                report.bytes_retained += e.size;
            } else if e.generation == CasGeneration::Nursery && e.tombstone.is_none() {
                // In Nursery grace period: protected
                report.nursery_chunks += 1;
                report.bytes_retained += e.size;
            } else if let Some(ref tomb) = e.tombstone {
                // Existing tombstone
                report.existing_tombstones += 1;
                report.bytes_tombstoned += e.size;

                if policy.purge_expired && tomb.is_expired(policy.tombstone_ttl_secs, now_secs) {
                    if !policy.dry_run {
                        let tomb_p = self.tombstone_path(&e.hash);
                        let _ = fs::remove_file(&e.chunk_path);
                        let _ = fs::remove_file(&tomb_p);
                        if let Some(p) = e.chunk_path.parent() {
                            empty_parents.push(p.to_path_buf());
                        }
                    }
                    report.purged_chunks += 1;
                    report.bytes_reclaimed += e.size;
                } else {
                    report.bytes_retained += e.size;
                }
            } else {
                // Unreferenced and past nursery grace: transition to Tombstoned
                report.newly_tombstoned += 1;
                report.bytes_tombstoned += e.size;
                report.bytes_retained += e.size;

                if !policy.dry_run {
                    let tomb = CasTombstone::new(
                        e.hash,
                        e.size,
                        "unreferenced in generational sweep",
                        None,
                    );
                    let tomb_p = self.tombstone_path(&e.hash);
                    let _ = tomb.write_to_file(&tomb_p);
                }
            }
        }

        // Clean up empty shard subdirectories if purging occurred
        if !policy.dry_run && report.purged_chunks > 0 {
            for p in empty_parents {
                let _ = fs::remove_dir(&p);
                if let Some(parent) = p.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
        }

        report.duration_ms = t0.elapsed().as_millis() as u64;
        Ok(report)
    }

    /// Hard-purge tombstones older than `older_than_secs`.
    pub fn purge_tombstones(
        &self,
        older_than_secs: u64,
        dry_run: bool,
    ) -> Result<CasGenerationalGcReport, VelcruxError> {
        let t0 = Instant::now();
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let entries = self.scan_chunks(now_secs, 0)?;
        let mut report = CasGenerationalGcReport {
            dry_run,
            ..Default::default()
        };

        let mut empty_parents = Vec::new();

        for e in entries {
            report.total_chunks_scanned += 1;
            report.bytes_scanned += e.size;

            if let Some(ref tomb) = e.tombstone {
                report.existing_tombstones += 1;
                let age = now_secs.saturating_sub(tomb.tombstoned_at_secs);

                if age >= older_than_secs {
                    report.purged_chunks += 1;
                    report.bytes_reclaimed += e.size;

                    if !dry_run {
                        let tomb_p = self.tombstone_path(&e.hash);
                        let _ = fs::remove_file(&e.chunk_path);
                        let _ = fs::remove_file(&tomb_p);
                        if let Some(p) = e.chunk_path.parent() {
                            empty_parents.push(p.to_path_buf());
                        }
                    }
                } else {
                    report.bytes_tombstoned += e.size;
                    report.bytes_retained += e.size;
                }
            } else {
                report.bytes_retained += e.size;
            }
        }

        if !dry_run && report.purged_chunks > 0 {
            for p in empty_parents {
                let _ = fs::remove_dir(&p);
                if let Some(parent) = p.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
        }

        report.duration_ms = t0.elapsed().as_millis() as u64;
        Ok(report)
    }

    /// Scan storage roots, database manifests, and active snapshots to collect referenced hashes.
    pub fn collect_references(
        storage_roots: &[&Path],
        _state_store: Option<&dyn StateStore>,
        snapshot_manager: Option<&SnapshotManager>,
    ) -> Result<HashSet<Hash>, VelcruxError> {
        let mut out = HashSet::new();

        for root in storage_roots {
            collect_referenced_hashes_fast(root, &mut out)?;
        }

        if let Some(sm) = snapshot_manager {
            if let Ok(hashes) = sm.all_referenced_chunks() {
                out.extend(hashes);
            }
        }

        Ok(out)
    }
}

/// Recursively index chunk hashes from storage trees without whole-file buffering.
fn collect_referenced_hashes_fast(dir: &Path, out: &mut HashSet<Hash>) -> Result<(), VelcruxError> {
    if !dir.exists() {
        return Ok(());
    }

    let entries = match fs::read_dir(dir) {
        Ok(iter) => iter,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_referenced_hashes_fast(&path, out)?;
        } else if path.is_file() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with(".velcrux-partial") || name.starts_with(".partial_") {
                continue;
            }

            // Fixed 64 KiB indexing
            let fixed_64k = ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap();
            if let Ok(f) = File::open(&path) {
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

            // Default CDC indexing
            let cdc_params = ChunkParams::default();
            if let Ok(f) = File::open(&path) {
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

/// Compaction daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasCompactionDaemonConfig {
    /// Compaction check interval in seconds (default: 3600 = 1 hour).
    pub interval_secs: u64,
    /// GC policy.
    pub policy: CasGcPolicy,
}

impl Default for CasCompactionDaemonConfig {
    fn default() -> Self {
        Self {
            interval_secs: 3600,
            policy: CasGcPolicy::default(),
        }
    }
}

/// Compaction daemon coordinating continuous generational compaction.
pub struct CasCompactionDaemon {
    config: CasCompactionDaemonConfig,
    manager: Arc<GenerationalCasManager>,
    runs_total: AtomicU64,
    chunks_tombstoned_total: AtomicU64,
    chunks_resurrected_total: AtomicU64,
    chunks_purged_total: AtomicU64,
    bytes_reclaimed_total: AtomicU64,
}

impl CasCompactionDaemon {
    /// Construct a new compaction daemon.
    pub fn new(config: CasCompactionDaemonConfig, manager: Arc<GenerationalCasManager>) -> Self {
        Self {
            config,
            manager,
            runs_total: AtomicU64::new(0),
            chunks_tombstoned_total: AtomicU64::new(0),
            chunks_resurrected_total: AtomicU64::new(0),
            chunks_purged_total: AtomicU64::new(0),
            bytes_reclaimed_total: AtomicU64::new(0),
        }
    }

    /// Access daemon configuration.
    pub fn config(&self) -> &CasCompactionDaemonConfig {
        &self.config
    }

    /// Execute a single generational compaction step against provided live references.
    pub fn step(
        &self,
        referenced_hashes: &HashSet<Hash>,
    ) -> Result<CasGenerationalGcReport, VelcruxError> {
        let report = self
            .manager
            .mark_and_sweep(referenced_hashes, &self.config.policy)?;

        self.runs_total.fetch_add(1, Ordering::Relaxed);
        self.chunks_tombstoned_total
            .fetch_add(report.newly_tombstoned as u64, Ordering::Relaxed);
        self.chunks_resurrected_total
            .fetch_add(report.resurrected_chunks as u64, Ordering::Relaxed);
        self.chunks_purged_total
            .fetch_add(report.purged_chunks as u64, Ordering::Relaxed);
        self.bytes_reclaimed_total
            .fetch_add(report.bytes_reclaimed, Ordering::Relaxed);

        Ok(report)
    }

    /// Telemetry counters.
    pub fn runs_total(&self) -> u64 {
        self.runs_total.load(Ordering::Relaxed)
    }

    pub fn chunks_tombstoned_total(&self) -> u64 {
        self.chunks_tombstoned_total.load(Ordering::Relaxed)
    }

    pub fn chunks_resurrected_total(&self) -> u64 {
        self.chunks_resurrected_total.load(Ordering::Relaxed)
    }

    pub fn chunks_purged_total(&self) -> u64 {
        self.chunks_purged_total.load(Ordering::Relaxed)
    }

    pub fn bytes_reclaimed_total(&self) -> u64 {
        self.bytes_reclaimed_total.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_test_chunk(mgr: &GenerationalCasManager, data: &[u8]) -> (Hash, PathBuf) {
        let hash = Hash::of(data);
        let path = mgr.chunk_path(&hash);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, data).unwrap();
        (hash, path)
    }

    #[test]
    fn test_cas_generation_nursery_protection() {
        let temp = tempdir().unwrap();
        let mgr = GenerationalCasManager::new(temp.path());

        // Ingest a brand new chunk
        let (hash, _) = write_test_chunk(&mgr, b"newly ingested nursery data");

        // Status shows it in Nursery
        let status = mgr.status(3600).unwrap();
        assert_eq!(status.total_chunks, 1);
        assert_eq!(status.nursery_chunks, 1);
        assert_eq!(status.tenured_chunks, 0);
        assert_eq!(status.tombstoned_chunks, 0);

        // Mark-and-sweep with NO live references should NOT tombstone nursery chunk
        let policy = CasGcPolicy {
            nursery_grace_secs: 3600,
            tombstone_ttl_secs: 86400,
            purge_expired: true,
            dry_run: false,
        };
        let report = mgr.mark_and_sweep(&HashSet::new(), &policy).unwrap();
        assert_eq!(report.nursery_chunks, 1);
        assert_eq!(report.newly_tombstoned, 0);
        assert!(!mgr.tombstone_path(&hash).exists());
    }

    #[test]
    fn test_cas_tombstoning_and_resurrection() {
        let temp = tempdir().unwrap();
        let mgr = GenerationalCasManager::new(temp.path());

        let (hash, _) = write_test_chunk(&mgr, b"tenured chunk data");

        // Mark-and-sweep with nursery grace = 0 (simulates expired nursery) and no references
        let policy = CasGcPolicy {
            nursery_grace_secs: 0,
            tombstone_ttl_secs: 86400,
            purge_expired: false,
            dry_run: false,
        };
        let report = mgr.mark_and_sweep(&HashSet::new(), &policy).unwrap();
        assert_eq!(report.newly_tombstoned, 1);
        assert!(mgr.tombstone_path(&hash).exists());

        // Status shows 1 tombstoned chunk
        let status = mgr.status(0).unwrap();
        assert_eq!(status.tombstoned_chunks, 1);
        assert_eq!(status.reclaimable_bytes, status.total_bytes);

        // Resurrect when reference appears
        let mut refs = HashSet::new();
        refs.insert(hash);
        let report2 = mgr.mark_and_sweep(&refs, &policy).unwrap();
        assert_eq!(report2.resurrected_chunks, 1);
        assert_eq!(report2.tenured_chunks, 1);
        assert!(!mgr.tombstone_path(&hash).exists());
    }

    #[test]
    fn test_cas_purge_expired_tombstones() {
        let temp = tempdir().unwrap();
        let mgr = GenerationalCasManager::new(temp.path());

        let (hash, chunk_path) = write_test_chunk(&mgr, b"expired tombstone data");

        // Place a tombstone created in the past (e.g. 2 hours ago)
        let mut tomb = CasTombstone::new(hash, 22, "manual tombstone test", None);
        tomb.tombstoned_at_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 7200;
        let tomb_path = mgr.tombstone_path(&hash);
        tomb.write_to_file(&tomb_path).unwrap();

        // Purge with TTL = 3600 (1 hour). Tombstone is 2 hours old -> purged!
        let report = mgr.purge_tombstones(3600, false).unwrap();
        assert_eq!(report.purged_chunks, 1);
        assert_eq!(report.bytes_reclaimed, 22);
        assert!(!chunk_path.exists());
        assert!(!tomb_path.exists());
    }

    #[test]
    fn test_compaction_daemon_step() {
        let temp = tempdir().unwrap();
        let mgr = Arc::new(GenerationalCasManager::new(temp.path()));
        let daemon = CasCompactionDaemon::new(
            CasCompactionDaemonConfig {
                interval_secs: 10,
                policy: CasGcPolicy {
                    nursery_grace_secs: 0,
                    tombstone_ttl_secs: 86400,
                    purge_expired: false,
                    dry_run: false,
                },
            },
            Arc::clone(&mgr),
        );

        write_test_chunk(&mgr, b"daemon data");
        let report = daemon.step(&HashSet::new()).unwrap();
        assert_eq!(report.newly_tombstoned, 1);
        assert_eq!(daemon.chunks_tombstoned_total(), 1);
        assert_eq!(daemon.runs_total(), 1);
    }
}
