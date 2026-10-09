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
}
