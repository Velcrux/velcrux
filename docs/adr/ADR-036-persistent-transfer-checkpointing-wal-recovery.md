# ADR-036: Persistent Transfer Checkpointing with WAL-Backed Fast Recovery & Resume Daemon

Status: Accepted · Date: 2026-10-22

## Context

In multi-terabyte dataset synchronization across wide-area networks (WAN) and enterprise storage environments, unexpected network partitions, server restarts, and process interruptions inevitably occur. Recovering in-flight transfers reliably and efficiently presents critical operational challenges:

1. **Avoid Full Directory & File Tree Re-Scans**:
   - Traditional sync tools (such as rsync) traverse the complete destination directory tree on restart to inspect file lengths, modtimes, and checksums, which takes tens of minutes or hours on multi-million file datasets.
   - Resuming an interrupted transfer must be instantaneous: recovery engines must directly interrogate durable database state and chunk bitmaps without walking storage hierarchies.
2. **SQLite WAL Write Amplification & Growth Management**:
   - High-throughput streaming transfers generate hundreds of periodic progress checkpoints. Under SQLite's default Write-Ahead Logging (WAL) mode, high write frequencies can lead to unbounded WAL file growth if checkpoints are not flushed systematically, increasing disk consumption and startup replay times.
   - The engine must provide explicit programmatic WAL checkpoint control (`PRAGMA wal_checkpoint(PASSIVE|FULL|RESTART|TRUNCATE)`) and threshold-based auto-checkpointing.
3. **Chunk-Level Bitmap Durability & Staging Verification**:
   - Fast recovery requires verifying on-disk staging files against chunk-completion bitmaps. If a process was terminated mid-write, the resume coordinator must verify staging file lengths and recorded chunk boundaries before restarting the stream.
4. **Stale Transfer & Bitmap Pruning**:
   - Without automatic or managed pruning, completed and cancelled transfer records and their associated chunk bitmaps accumulate indefinitely in the state store.
5. **Architectural Safety & Invariants**:
   - Strict adherence to `#![forbid(unsafe_code)]` with zero exceptions across all crates (`CLAUDE.md` §1).
   - Strict bounded memory streaming: bitmap and recovery operations must remain `O(1)` or `O(completed_chunks)`, never allocating memory proportional to whole file sizes.

## Options Considered

1. **Option 1: In-Memory Tracking with Directory Rescanning on Restart**:
   - Track progress solely in process memory and re-scan the destination directory upon interruption.
   - *Rejected*: Incurs massive I/O penalties and delays recovery on large datasets.
2. **Option 2: Commit Every Packet Directly to Disk**:
   - Execute an `fsync` and database update on every individual chunk or network packet.
   - *Rejected*: Violates `REQUIREMENTS.md` §68 ("Do not persist every packet. Checkpoint periodically... balance recovery cost vs I/O overhead"). Destroys NVMe and SSD write longevity via excessive write amplification.
3. **Option 3: Persistent Transfer Checkpointing with WAL Management & Fast Instantaneous Recovery Daemon (`ADR-036`)**:
   - Provide configurable multi-dimensional checkpoint policies (`CheckpointPolicy`) balancing bytes transferred, elapsed time, and chunk boundaries.
   - Extend `StateStore` with native SQLite Write-Ahead Logging control (`wal_checkpoint`) supporting `Passive`, `Full`, `Restart`, and `Truncate` modes.
   - Build `TransferResumeCoordinator` to perform instant recovery (`fast_recover_all`, `recover_transfer`) by verifying chunk bitmaps and staging metadata without directory re-scans.
   - Provide stale transfer pruning (`prune_stale_transfers`), CLI diagnostics (`velcrux checkpoint [status|recover|prune|wal-flush]`), and Prometheus metrics (`velcrux_transfer_checkpoints_total`, `velcrux_wal_checkpoints_total`).

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. SQLite WAL Checkpointing & State Store Extension (`crates/velcrux-core/src/state/`)

`StateStore` trait incorporates first-class WAL management and resumable query operations:

```rust
pub trait StateStore: Send + Sync {
    // ... existing CRUD methods ...

    /// Execute a SQLite Write-Ahead Logging (WAL) checkpoint to control WAL size and flush pages.
    fn wal_checkpoint(&self, mode: WalCheckpointMode) -> StateStoreResult<WalCheckpointReport>;

    /// List all transfers currently in `Resumable` status, optionally filtered by `role`.
    fn list_resumable_transfers(&self, role: Option<Role>) -> StateStoreResult<Vec<TransferRecord>>;

    /// Prune completed or cancelled transfer records and bitmaps older than `max_age_secs`.
    fn prune_stale_transfers(&self, max_age_secs: u64) -> StateStoreResult<usize>;
}
```

The `WalCheckpointMode` maps to SQLite's native PRAGMA options:
- `Passive`: Checkpoints as many frames as possible without blocking readers or writers.
- `Full`: Waits for readers to finish and checkpoints all possible frames.
- `Restart`: Blocks new readers until checkpoint completes.
- `Truncate`: Checkpoints and truncates the WAL file to zero bytes.

### 2. Fast Recovery & Resume Coordinator (`crates/velcrux-core/src/transfer/checkpoint.rs`)

The `TransferResumeCoordinator` enables instantaneous startup recovery:

```rust
pub struct TransferResumeCoordinator;

impl TransferResumeCoordinator {
    pub fn fast_recover_all(
        store: &dyn StateStore,
        staging_root: Option<&std::path::Path>,
    ) -> Result<ResumeRecoveryReport>;

    pub fn recover_transfer(
        store: &dyn StateStore,
        transfer_id: TransferId,
        staging_root: Option<&std::path::Path>,
    ) -> Result<RecoveredTransferSummary>;

    pub fn prune_stale(store: &dyn StateStore, max_age_secs: u64) -> Result<usize>;

    pub fn wal_flush(store: &dyn StateStore, mode: WalCheckpointMode) -> Result<WalCheckpointReport>;
}
```

Recovery steps:
1. Calls `mark_active_transfers_resumable()` to transition uncommitted active transfers to resumable state without data loss.
2. Queries `list_resumable_transfers(None)` directly from the database index.
3. For each transfer, inspects `read_bitmap()` and checks physical staging file length (if staging path provided) to verify integrity without traversing directories.
4. Executes a passive WAL checkpoint to keep the WAL log bounded.

### 3. CLI Management Subcommands (`crates/velcrux-client/src/main.rs`)

Exposes CLI subcommands under `velcrux checkpoint`:

- `velcrux checkpoint status [--role <ROLE>] [--json]`: Display all resumable transfers, completion percentages, and SQLite WAL log page status.
- `velcrux checkpoint recover [--transfer-id <ULID>] [--role <ROLE>] [--json]`: Instantly recover all or specific interrupted transfers without directory re-scans.
- `velcrux checkpoint wal-flush [--mode <MODE>] [--role <ROLE>] [--json]`: Flush the SQLite Write-Ahead Log (`truncate`, `passive`, `full`, `restart`).
- `velcrux checkpoint prune [--older-than-secs <SECS>] [--role <ROLE>] [--json]`: Remove stale completed or cancelled checkpoints and bitmap allocations.

Global tuning flags:
- `--checkpoint-interval <SECS>`: Checkpoint time interval in seconds (default: 10s).
- `--checkpoint-bytes <BYTES>`: Checkpoint byte threshold in bytes (default: 256 MiB).
- `--wal-autocheckpoint <PAGES>`: SQLite WAL auto-checkpoint page threshold (default: 1000 pages / ~4 MiB).

### 4. Telemetry & Prometheus Observability (`crates/velcrux-server/src/metrics.rs`)

Exposes real-time checkpointing and WAL health counters at `/metrics`:
- `velcrux_transfer_checkpoints_total`: Cumulative transfer checkpoints committed to durable store.
- `velcrux_transfer_checkpoint_bytes_total`: Cumulative bytes acknowledged and checkpointed.
- `velcrux_transfer_recoveries_total`: Total transfer recovery operations executed.
- `velcrux_wal_checkpoints_total`: Total SQLite WAL checkpoints executed.

## Consequences

### Positive
- **Instant Recovery**: Zero destination directory re-scans upon resume; transfers restart immediately from the last acknowledged chunk bitmap.
- **Controlled WAL Bloat**: Explicit and automatic WAL checkpointing prevents unbounded log page growth during multi-terabyte data streams.
- **Resource Cleanup**: Automated pruning of obsolete completed/cancelled checkpoints and bitmaps maintains lean database sizes.
- **Full Observability**: Comprehensive text and JSON outputs for operational automation and Prometheus monitoring.

### Neutral / Negative
- Periodic checkpoints incur small synchronous database write latencies (mitigated by bounded-frequency policies).
- WAL truncate requires taking an exclusive lock on the database file for a brief duration.
