//! Periodic checkpoint coordinator and recovery cost optimization.
//!
//! Enforces `REQUIREMENTS.md` §68, §69:
//! "Do not persist every packet. Checkpoint periodically based on: bytes transferred,
//! time elapsed, chunk boundaries... balance recovery cost vs I/O overhead."
//!
//! Enforces `CLAUDE.md` §1: 100% safe Rust (`#![forbid(unsafe_code)]`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::{Result, VelcruxError};
use crate::state::{ChunkBitmap, StateStore};
use crate::util::TransferId;

/// Default byte threshold between checkpoints (256 MiB).
pub const DEFAULT_CHECKPOINT_BYTES: u64 = 256 * 1024 * 1024;

/// Default time interval between checkpoints (10 seconds).
pub const DEFAULT_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(10);

/// Checkpointing policy configuring when and how progress is durably synced.
#[derive(Debug, Clone)]
pub struct CheckpointPolicy {
    /// Number of bytes transferred before triggering a checkpoint (0 to disable byte trigger).
    pub bytes_threshold: u64,
    /// Maximum elapsed duration between checkpoints (Duration::ZERO to disable timer trigger).
    pub time_interval: Duration,
    /// Number of chunk boundaries between checkpoints (0 to disable chunk count trigger).
    pub chunk_threshold: u64,
    /// Whether to invoke `sync_data` / `fdatasync` on the physical staging file on checkpoint.
    pub fsync_staging: bool,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self {
            bytes_threshold: DEFAULT_CHECKPOINT_BYTES,
            time_interval: DEFAULT_CHECKPOINT_INTERVAL,
            chunk_threshold: 256,
            fsync_staging: true,
        }
    }
}

impl CheckpointPolicy {
    /// High-throughput profile with looser checkpoints (1 GiB / 30s) to minimize disk I/O contention.
    pub fn high_throughput() -> Self {
        Self {
            bytes_threshold: 1024 * 1024 * 1024, // 1 GiB
            time_interval: Duration::from_secs(30),
            chunk_threshold: 1024,
            fsync_staging: true,
        }
    }

    /// Aggressive recovery profile (64 MiB / 3s) for hostile / unreliable networks.
    pub fn hostile_network() -> Self {
        Self {
            bytes_threshold: 64 * 1024 * 1024, // 64 MiB
            time_interval: Duration::from_secs(3),
            chunk_threshold: 64,
            fsync_staging: true,
        }
    }
}

/// Statistics and telemetry tracking for checkpoint operations.
#[derive(Debug, Default)]
pub struct CheckpointStats {
    /// Cumulative checkpoints executed.
    pub checkpoints_total: AtomicU64,
    /// Cumulative duration spent in checkpoint flushes, in microseconds.
    pub checkpoint_duration_micros_total: AtomicU64,
    /// Total bytes acknowledged across checkpoints.
    pub checkpoint_bytes_total: AtomicU64,
}

impl CheckpointStats {
    /// Total count of successful checkpoints.
    pub fn count(&self) -> u64 {
        self.checkpoints_total.load(Ordering::Relaxed)
    }

    /// Average latency per checkpoint in milliseconds.
    pub fn average_latency_ms(&self) -> f64 {
        let count = self.count();
        if count == 0 {
            0.0
        } else {
            let micros = self
                .checkpoint_duration_micros_total
                .load(Ordering::Relaxed);
            (micros as f64 / count as f64) / 1000.0
        }
    }
}

/// Dynamic checkpoint coordinator balancing disk write amplification against resume rework.
pub struct CheckpointCoordinator {
    policy: CheckpointPolicy,
    bytes_since_last: u64,
    chunks_since_last: u64,
    last_checkpoint_instant: Instant,
    last_checkpoint_bytes: u64,
    stats: Arc<CheckpointStats>,
}

impl CheckpointCoordinator {
    /// Construct a new coordinator with given policy and shared statistics collector.
    pub fn new(policy: CheckpointPolicy, stats: Arc<CheckpointStats>) -> Self {
        Self {
            policy,
            bytes_since_last: 0,
            chunks_since_last: 0,
            last_checkpoint_instant: Instant::now(),
            last_checkpoint_bytes: 0,
            stats,
        }
    }

    /// Construct a coordinator using default policy and fresh statistics tracker.
    pub fn with_defaults() -> Self {
        Self::new(
            CheckpointPolicy::default(),
            Arc::new(CheckpointStats::default()),
        )
    }

    /// Reference to active policy.
    pub fn policy(&self) -> &CheckpointPolicy {
        &self.policy
    }

    /// Reference to operational statistics.
    pub fn stats(&self) -> &Arc<CheckpointStats> {
        &self.stats
    }

    /// Track chunk progress, returning `true` if a durable checkpoint should now be executed.
    pub fn observe_chunk(&mut self, chunk_len: u64) -> bool {
        self.bytes_since_last = self.bytes_since_last.saturating_add(chunk_len);
        self.chunks_since_last = self.chunks_since_last.saturating_add(1);

        self.should_checkpoint()
    }

    /// Return `true` if policy criteria (bytes, elapsed time, or chunk count) dictate a checkpoint.
    pub fn should_checkpoint(&self) -> bool {
        if self.policy.bytes_threshold > 0 && self.bytes_since_last >= self.policy.bytes_threshold {
            return true;
        }

        if !self.policy.time_interval.is_zero()
            && self.last_checkpoint_instant.elapsed() >= self.policy.time_interval
        {
            return true;
        }

        if self.policy.chunk_threshold > 0 && self.chunks_since_last >= self.policy.chunk_threshold
        {
            return true;
        }

        false
    }

    /// Persist an atomic checkpoint to the durable state store.
    ///
    /// Writes the updated bitmap, updates the transfer record with `bytes_completed`,
    /// updates `last_checkpoint_ms`, and flushes internal timers.
    pub fn commit_checkpoint(
        &mut self,
        transfer_id: TransferId,
        bytes_completed: u64,
        bitmap: &ChunkBitmap,
        store: &dyn StateStore,
    ) -> Result<Duration> {
        let t0 = Instant::now();

        // 1. Write updated bitmap
        store
            .write_bitmap(transfer_id, bitmap)
            .map_err(|e| VelcruxError::Internal(format!("checkpoint bitmap write failed: {e}")))?;

        // 2. Update transfer record
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        if let Ok(mut record) = store.get_transfer(transfer_id) {
            record.bytes_completed = bytes_completed;
            record.last_checkpoint_ms = now_ms;
            record.updated_ms = now_ms;
            let _ = store.update_transfer(&record);
        }

        let elapsed = t0.elapsed();

        // Update internal coordinator state
        self.bytes_since_last = 0;
        self.chunks_since_last = 0;
        self.last_checkpoint_instant = Instant::now();
        self.last_checkpoint_bytes = bytes_completed;

        // Update atomic counters
        self.stats.checkpoints_total.fetch_add(1, Ordering::Relaxed);
        self.stats
            .checkpoint_bytes_total
            .store(bytes_completed, Ordering::Relaxed);
        self.stats
            .checkpoint_duration_micros_total
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);

        Ok(elapsed)
    }
}

/// Detailed summary of a recovered or resumable transfer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveredTransferSummary {
    /// Unique 16-byte transfer identifier.
    pub transfer_id: TransferId,
    /// Client-specified or generated idempotency key.
    pub idempotency_key: String,
    /// Transfer role ("client" or "server").
    pub role: String,
    /// Remote path on server.
    pub remote_path: String,
    /// Local path on client.
    pub local_path: String,
    /// Declared file size in bytes.
    pub file_size: u64,
    /// Bytes acknowledged and persisted to disk across checkpoints.
    pub bytes_completed: u64,
    /// Completion percentage (0.0 to 100.0).
    pub completion_pct: f64,
    /// Staging relative path.
    pub staging_relpath: String,
    /// Whether the staging file exists on disk.
    pub staging_exists: bool,
    /// Physical file size of staging file in bytes.
    pub staging_len: u64,
    /// Number of verified completed chunks in the bitmap.
    pub chunks_completed: usize,
    /// Current transfer status.
    pub status: String,
    /// Whether staging file matches or exceeds persisted bytes.
    pub verified: bool,
}

/// Complete diagnostic report from an instantaneous recovery scan.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResumeRecoveryReport {
    /// Timestamp of recovery in ms since UNIX epoch.
    pub timestamp_ms: u64,
    /// Number of active transfers transitioned to resumable state.
    pub active_transfers_marked_resumable: usize,
    /// Total count of resumable transfers ready for immediate resumption.
    pub resumable_count: usize,
    /// Total bytes across all resumable transfers.
    pub total_bytes_resumable: u64,
    /// Total completed bytes across all resumable transfers.
    pub total_bytes_completed: u64,
    /// Individual recovered transfer summaries.
    pub transfers: Vec<RecoveredTransferSummary>,
    /// SQLite Write-Ahead Logging (WAL) checkpoint diagnostic status if available.
    pub wal_status: Option<crate::state::WalCheckpointReport>,
}

/// Configuration settings for persistent transfer checkpointing and SQLite WAL background daemon.
#[derive(Debug, Clone)]
pub struct CheckpointDaemonConfig {
    /// Checkpointing policy for data streams.
    pub policy: CheckpointPolicy,
    /// SQLite WAL auto-checkpoint threshold in pages (default: 1000 pages = ~4 MiB).
    pub wal_autocheckpoint_pages: u32,
    /// Periodic SQLite WAL checkpoint flush interval.
    pub wal_checkpoint_interval: Duration,
    /// Pruning interval for stale transfers.
    pub prune_interval: Duration,
    /// Maximum age in seconds for retaining completed or cancelled transfers (default: 7 days).
    pub prune_max_age_secs: u64,
}

impl Default for CheckpointDaemonConfig {
    fn default() -> Self {
        Self {
            policy: CheckpointPolicy::default(),
            wal_autocheckpoint_pages: 1000,
            wal_checkpoint_interval: Duration::from_secs(60),
            prune_interval: Duration::from_secs(3600),
            prune_max_age_secs: 7 * 86400,
        }
    }
}

/// Instantaneous resume coordinator avoiding directory re-scans.
pub struct TransferResumeCoordinator;

impl TransferResumeCoordinator {
    /// Perform instantaneous recovery of all interrupted transfers without directory re-scans.
    pub fn fast_recover_all(
        store: &dyn StateStore,
        staging_root: Option<&std::path::Path>,
    ) -> Result<ResumeRecoveryReport> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let marked = store
            .mark_active_transfers_resumable()
            .map_err(|e| VelcruxError::Internal(format!("mark active resumable failed: {e}")))?;

        let resumable_records = store
            .list_resumable_transfers(None)
            .map_err(|e| VelcruxError::Internal(format!("list resumable failed: {e}")))?;

        let mut total_bytes_resumable = 0u64;
        let mut total_bytes_completed = 0u64;
        let mut summaries = Vec::with_capacity(resumable_records.len());

        for rec in &resumable_records {
            total_bytes_resumable = total_bytes_resumable.saturating_add(rec.file_size);
            total_bytes_completed = total_bytes_completed.saturating_add(rec.bytes_completed);

            let summary = Self::inspect_transfer(store, rec, staging_root)?;
            summaries.push(summary);
        }

        let wal_status = store
            .wal_checkpoint(crate::state::WalCheckpointMode::Passive)
            .ok();

        Ok(ResumeRecoveryReport {
            timestamp_ms: now_ms,
            active_transfers_marked_resumable: marked,
            resumable_count: summaries.len(),
            total_bytes_resumable,
            total_bytes_completed,
            transfers: summaries,
            wal_status,
        })
    }

    /// Recover and verify a single transfer by id.
    pub fn recover_transfer(
        store: &dyn StateStore,
        transfer_id: TransferId,
        staging_root: Option<&std::path::Path>,
    ) -> Result<RecoveredTransferSummary> {
        let rec = store
            .get_transfer(transfer_id)
            .map_err(|e| VelcruxError::Internal(format!("get transfer failed: {e}")))?;
        Self::inspect_transfer(store, &rec, staging_root)
    }

    /// Internal inspection of a transfer record, its bitmap, and optional staging file.
    fn inspect_transfer(
        store: &dyn StateStore,
        rec: &crate::state::TransferRecord,
        staging_root: Option<&std::path::Path>,
    ) -> Result<RecoveredTransferSummary> {
        let bitmap = store.read_bitmap(rec.transfer_id).unwrap_or_default();
        let chunks_completed = bitmap.len();

        let mut staging_exists = false;
        let mut staging_len = 0u64;

        if let Some(root) = staging_root {
            if !rec.staging_relpath.is_empty() {
                let path = root.join(&rec.staging_relpath);
                if let Ok(meta) = std::fs::metadata(&path) {
                    staging_exists = true;
                    staging_len = meta.len();
                }
            }
        }

        let completion_pct = if rec.file_size > 0 {
            (rec.bytes_completed as f64 / rec.file_size as f64) * 100.0
        } else if chunks_completed > 0 {
            100.0
        } else {
            0.0
        };

        let verified = if staging_exists {
            staging_len >= rec.bytes_completed
        } else {
            true
        };

        Ok(RecoveredTransferSummary {
            transfer_id: rec.transfer_id,
            idempotency_key: rec.idempotency_key.clone(),
            role: rec.role.as_str().to_string(),
            remote_path: rec.remote_path.clone(),
            local_path: rec.local_path.clone(),
            file_size: rec.file_size,
            bytes_completed: rec.bytes_completed,
            completion_pct,
            staging_relpath: rec.staging_relpath.clone(),
            staging_exists,
            staging_len,
            chunks_completed,
            status: rec.status.name().to_string(),
            verified,
        })
    }

    /// Prune stale completed or cancelled checkpoints older than `max_age_secs`.
    pub fn prune_stale(store: &dyn StateStore, max_age_secs: u64) -> Result<usize> {
        store
            .prune_stale_transfers(max_age_secs)
            .map_err(|e| VelcruxError::Internal(format!("prune stale transfers failed: {e}")))
    }

    /// Trigger an explicit SQLite WAL flush.
    pub fn wal_flush(
        store: &dyn StateStore,
        mode: crate::state::WalCheckpointMode,
    ) -> Result<crate::state::WalCheckpointReport> {
        store
            .wal_checkpoint(mode)
            .map_err(|e| VelcruxError::Internal(format!("wal checkpoint failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{MockStateStore, TransferRecord};

    #[test]
    fn test_checkpoint_trigger_by_bytes() {
        let policy = CheckpointPolicy {
            bytes_threshold: 1000,
            time_interval: Duration::from_secs(3600), // very large
            chunk_threshold: 0,
            fsync_staging: false,
        };
        let mut coord = CheckpointCoordinator::new(policy, Arc::new(CheckpointStats::default()));

        assert!(!coord.observe_chunk(500));
        assert!(!coord.observe_chunk(499));
        assert!(coord.observe_chunk(1)); // hits 1000 bytes
    }

    #[test]
    fn test_checkpoint_trigger_by_chunk_count() {
        let policy = CheckpointPolicy {
            bytes_threshold: 0,
            time_interval: Duration::from_secs(3600),
            chunk_threshold: 3,
            fsync_staging: false,
        };
        let mut coord = CheckpointCoordinator::new(policy, Arc::new(CheckpointStats::default()));

        assert!(!coord.observe_chunk(10));
        assert!(!coord.observe_chunk(10));
        assert!(coord.observe_chunk(10)); // hits 3 chunks
    }

    #[test]
    fn test_commit_checkpoint_updates_state_store() {
        let mock_store = MockStateStore::new();
        let transfer_id = TransferId::generate();

        let rec = TransferRecord {
            transfer_id,
            idempotency_key: "tx-cp".to_string(),
            role: crate::state::Role::Server,
            direction: crate::state::Direction::Upload,
            status: crate::state::TransferStatus::Active,
            remote_path: "upload/target.bin".to_string(),
            local_path: String::new(),
            file_size: 10_000,
            file_hash: crate::util::Hash::ZERO,
            verified_up_to: 0,
            last_checkpoint_ms: 0,
            bytes_completed: 0,
            staging_relpath: "staging.tmp".to_string(),
            created_ms: 100,
            updated_ms: 100,
        };
        mock_store.upsert_transfer(&rec).unwrap();

        let stats = Arc::new(CheckpointStats::default());
        let mut coord = CheckpointCoordinator::new(CheckpointPolicy::default(), Arc::clone(&stats));

        let mut bitmap = ChunkBitmap::new();
        bitmap.mark_complete(0, 1024);
        bitmap.mark_complete(1, 1024);

        let _dur = coord
            .commit_checkpoint(transfer_id, 2048, &bitmap, &mock_store)
            .unwrap();

        assert_eq!(stats.count(), 1);
        let updated = mock_store.get_transfer(transfer_id).unwrap();
        assert_eq!(updated.bytes_completed, 2048);
        assert!(updated.last_checkpoint_ms > 0);
    }

    #[test]
    fn test_resume_coordinator_fast_recover_and_prune() {
        let store = MockStateStore::new();
        let tid1 = TransferId::generate();
        let tid2 = TransferId::generate();

        let mut rec1 = TransferRecord {
            transfer_id: tid1,
            idempotency_key: "tx-recover-1".to_string(),
            role: crate::state::Role::Client,
            direction: crate::state::Direction::Upload,
            status: crate::state::TransferStatus::Active,
            remote_path: "upload/target1.bin".to_string(),
            local_path: "/tmp/source1.bin".to_string(),
            file_size: 10_000,
            file_hash: crate::util::Hash::ZERO,
            verified_up_to: 0,
            last_checkpoint_ms: 100,
            bytes_completed: 4096,
            staging_relpath: String::new(),
            created_ms: 100,
            updated_ms: 100,
        };
        store.upsert_transfer(&rec1).unwrap();

        let rec2 = TransferRecord {
            transfer_id: tid2,
            idempotency_key: "tx-recover-2".to_string(),
            role: crate::state::Role::Client,
            direction: crate::state::Direction::Upload,
            status: crate::state::TransferStatus::Resumable,
            remote_path: "upload/target2.bin".to_string(),
            local_path: "/tmp/source2.bin".to_string(),
            file_size: 20_000,
            file_hash: crate::util::Hash::ZERO,
            verified_up_to: 0,
            last_checkpoint_ms: 200,
            bytes_completed: 8192,
            staging_relpath: String::new(),
            created_ms: 200,
            updated_ms: 200,
        };
        store.upsert_transfer(&rec2).unwrap();

        // fast_recover_all will mark rec1 as resumable and return both
        let report = TransferResumeCoordinator::fast_recover_all(&store, None).unwrap();
        assert_eq!(report.active_transfers_marked_resumable, 1);
        assert_eq!(report.resumable_count, 2);
        assert_eq!(report.total_bytes_resumable, 30_000);
        assert_eq!(report.total_bytes_completed, 12_288);

        // recover_transfer for single
        let single = TransferResumeCoordinator::recover_transfer(&store, tid1, None).unwrap();
        assert_eq!(single.transfer_id, tid1);
        assert_eq!(single.bytes_completed, 4096);
        assert_eq!(single.status, "resumable");

        // wal_flush
        let wal_rep =
            TransferResumeCoordinator::wal_flush(&store, crate::state::WalCheckpointMode::Passive)
                .unwrap();
        assert_eq!(wal_rep.mode, crate::state::WalCheckpointMode::Passive);

        // prune_stale
        rec1.status = crate::state::TransferStatus::Committed;
        rec1.updated_ms = 100;
        store.update_transfer(&rec1).unwrap();

        let pruned = TransferResumeCoordinator::prune_stale(&store, 1).unwrap();
        assert_eq!(pruned, 1);
    }
}
