# ADR-016: Continuous Real-Time File Watcher & Automated Synchronization Engine

Status: Accepted · Date: 2026-10-12

## Problem

Per `REQUIREMENTS.md` §64–§68 ("Continuous Synchronization & File Watching"), operational workflows in production environments require continuous real-time data replication:
1. **Periodic Polling Inefficiency**: Invoking ad-hoc batch commands on cron schedules introduces significant latency (data is only synced every $N$ minutes) and wastes CPU cycles traversing static directories.
2. **Rapid Write Burst Churn (Editor Saves & Temporary Files)**: Compilers, text editors, and databases rapidly create, modify, and delete intermediate or lock files (e.g. `.swp`, `.tmp`, atomic rename staging). Synchronizing every raw write event immediately floods network pipes and triggers redundant partial chunk uploads.
3. **Safety & Portability**: Native OS filesystem notifications (`inotify` on Linux, `FSEvents` on macOS, `ReadDirectoryChangesW` on Windows) often require external C bindings or unsafe code, run into OS-level watch descriptor limits (`fs.inotify.max_user_watches`), and can drop events during high I/O spikes.

## Options Considered

1. **Kernel-Level OS Watchers via C Bindings (`inotify-sys`, `fsevent-sys`)**:
   - Bind OS-specific APIs via FFI.
   - *Rejected*: Violates `#![forbid(unsafe_code)]` and zero external C dependencies constraints. OS limit exhaustion (`ENOSPC`) can crash daemons on large repos.
2. **Stateless Ad-Hoc Sync in an Infinite Shell Loop (`while true; do velcrux sync ...; done`)**:
   - Shell loop triggering full directory scans repeatedly.
   - *Rejected*: Thrashing disk I/O, no event coalescing, and no debounce window to accommodate multi-step file writes.
3. **Pure-Rust Directory State Scanner with Coalescing Debounce Queue**:
   - `DirectoryScanner` maintaining in-memory snapshots of file metadata (`mtime_secs`, `mtime_nanos`, `size`).
   - Pure-Rust `DebounceQueue` holding pending `FileChangeEvent`s until a quiet window (`debounce_window`, default 200ms) has elapsed.
   - Automated coalescing: merges rapid duplicate modifications, preserves initial creation timestamps, and eliminates short-lived ephemeral files (`Created` + `Deleted`).
   - Continuous `ContinuousSyncCoordinator` with cooperative cancellation (`shutdown_handle`), signal handling (`SIGINT`, `SIGTERM`), and metrics reporting.

## Decision

Option 3. Velcrux implements pure-Rust continuous directory change monitoring, event debouncing, and batch synchronization with `#![forbid(unsafe_code)]`.

## Architecture & Implementation

### 1. State Machine & Event Coalescing

File modifications trigger one of three discrete states:
- `ChangeKind::Created`: New file detected on the filesystem.
- `ChangeKind::Modified`: File length or timestamp altered.
- `ChangeKind::Deleted`: File unlinked or removed from directory tree.

Events for the same relative file path within the debounce window are coalesced:
```text
  Existing State  +  Incoming Event  ===>  Coalesced State
─────────────────────────────────────────────────────────────
  Created         +  Modified        ===>  Created (updated size/mtime)
  Created         +  Deleted         ===>  Cancelled (ephemeral file purged)
  Modified        +  Modified        ===>  Modified (latest state preserved)
  Deleted         +  Created         ===>  Modified (re-created with new content)
```

### 2. Debounce Window Pacing

- **Quiet Window (`debounce_window`, default 200ms)**: Incoming file writes reset the debounce timer for the affected path. Once all queued events remain quiet for at least `debounce_window`, the queue drains into a `ChangeBatch`.
- **Max Queue Depth**: If pending queue entries exceed `max_queue_depth` (default 10,000 events), the queue flushes immediately to prevent unbounded memory growth.
- **Polling Frequency (`poll_interval`, default 500ms)**: Configurable sweep interval balancing CPU utilization against change detection latency.

### 3. CLI Integration

Continuous monitoring is accessible via dedicated command or the `--watch` flag:
```bash
# Dedicated watch command
velcrux watch /data/source velcrux://backup.server/data/ \
  --debounce-ms 200 --poll-interval-ms 500

# Automated sync mode (performs initial full sync, then watches continuously)
velcrux sync /data/source velcrux://backup.server/data/ --watch

# Machine-readable JSON event logging
velcrux --json watch /data/source /data/destination --max-batches 5
```

## Consequences

- **Positive**: Zero unsafe code, zero OS watch limit failures, cross-platform portability.
- **Positive**: Eliminates network thrashing through intelligent coalescing of rapid file updates and ephemeral scratch files.
- **Positive**: Graceful shutdown guarantees in-flight sync passes finish cleanly without corrupted state.
