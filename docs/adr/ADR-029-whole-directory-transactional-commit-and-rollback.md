# ADR-029: Whole-Directory Transactional Commit & Rollback Journaling (`velcrux sync --atomic` & `velcrux tx`)

Status: Accepted · Date: 2026-10-18

## Context

In multi-file synchronization and bulk transfers across complex directory hierarchies, transient network dropouts, disk full conditions, power interruptions, or checksum verification failures can leave destination directories in an inconsistent, partially-written intermediate state (e.g. 50 files copied, 50 files missing, or previous files overwritten while new dependencies are incomplete).

Prior to this decision, Velcrux used per-file atomic staging in `.velcrux-staging/<transfer_id>`, but lacked directory-level atomicity (all-or-nothing commit across multiple files simultaneously) and write-ahead rollback capabilities to restore pre-existing destination directories to their exact baseline after failures or crashes.

Key requirements:
1. **Directory-Level Atomicity (All-or-Nothing Commit)**: 100% of files in a directory transfer/sync operation are committed simultaneously to destination, or 0% are committed (clean rollback with zero partial directory corruption).
2. **Shadow Directory Staging (`.velcrux-shadow/<tx_id>/`)**: All incoming or reconstructed files are staged into an isolated shadow root without mutating live destination files.
3. **Two-Phase Commit (2PC) Protocol**:
   - **Prepare Phase**: Cryptographic BLAKE3 verification, file size validation, and pre-existing file backup (`.velcrux-backup/<tx_id>/`).
   - **Commit Phase**: Write-ahead journal intent logging, atomic rename of staged files into destination.
   - **Rollback Phase**: Automatic or crash-recovery rollback reversing applied moves and restoring original files from backup if any failure occurs.
4. **Crash Recovery (`TransactionManager::recover_pending_transactions`)**: Inspect write-ahead journals on startup and resolve incomplete or interrupted transactions.
5. **Strict `#![forbid(unsafe_code)]` Compliance**: 100% pure, safe Rust across all transaction coordinator and journaling primitives.
6. **CLI Integration**: Seamless `--atomic` flag for `velcrux sync` and dedicated `velcrux tx` subcommand (`list`, `show`, `rollback`, `recover`).

## Options Considered

1. **Filesystem Snapshotting / ZFS / Btrfs Subvolume Cloning**:
   - Leverage underlying filesystem snapshot facilities to revert modified directories.
   - *Rejected*: Incompatible with ext4, NTFS, APFS, NFS, or portable container environments; requires root/administrator privileges and platform-dependent tooling.
2. **Post-Facto File Deletion on Error**:
   - Simply delete staged files on error without backing up overwritten or modified files.
   - *Rejected*: Cannot restore original file versions when files were overwritten or updated, leaving destination in a corrupted or degraded state.
3. **Shadow Staging with Two-Phase Commit, Write-Ahead Journaling, and Backup Roots**:
   - Coordinate whole-directory transactions with shadow staging, pre-commit file backup, cryptographic hash verification, and atomic swap.
   - Persist write-ahead transaction journals (`.velcrux-journal/<tx_id>.json`) for crash recovery and audit trails.
   - Provide interactive rollback capability allowing operators to undo committed transactions.

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. State Machine & Journaling (`crates/velcrux-core/src/sync/transaction.rs`)
- **Transaction States**:
  - `Staging`: Files are written or streamed into isolated `.velcrux-shadow/<tx_id>/`.
  - `Prepared`: All staged files verified against expected BLAKE3 hashes; backups of pre-existing target files created in `.velcrux-backup/<tx_id>/`.
  - `Committing`: Write-ahead intent logged to `.velcrux-journal/<tx_id>.json`; files moved atomically into final locations.
  - `Committed`: All items in place; shadow directory purged; backups retained for operator rollback.
  - `Aborted`: Staging dropped without touching destination.
  - `RolledBack`: Applied changes reversed, new files purged, original files restored from backup.

### 2. Directory Synchronizer Integration (`crates/velcrux-core/src/sync/directory.rs`)
- Added `atomic: bool` to `DirectorySyncOptions` and `transaction_id: Option<String>` to `DirectorySyncResult`.
- Exported `execute_atomic_directory_sync(src, dst, options, state_store, chunk_store)`.
- Staging dynamically points to transaction shadow root when `--atomic` is active.
- Seamless coordination with batch small files packaging (`Option AI`) and delta reconstructors (`Milestone 7`).

### 3. CLI Subcommands & Flags (`crates/velcrux-client/src/main.rs`)
- `velcrux sync <src> <dst> --atomic`: Perform all-or-nothing directory synchronization.
- `velcrux tx list [path] [--json]`: Enumerate transaction histories and statuses.
- `velcrux tx show <tx_id> [--path <path>] [--json]`: Inspect detailed file actions, hashes, and sizes.
- `velcrux tx rollback <tx_id> [--path <path>] [--json]`: Restore pristine pre-transaction baseline.
- `velcrux tx recover [path] [--json]`: Automatically recover interrupted or crashed transactions.

## Consequences

- **Positive**: Zero partial directory corruption on network failure, power cuts, or hash mismatches. Guarantees deterministic, production-grade directory-level atomicity.
- **Positive**: Operators can roll back whole deployments or data sync operations with one CLI command (`velcrux tx rollback <tx_id>`).
- **Considerations**: Temporary additional disk capacity is required during the prepare/commit phase to hold staged shadow files and original file backups until commit or rollback.
