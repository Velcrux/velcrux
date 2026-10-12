# ADR-012: Transfer Planning, Dry-Run Previews & Safe Deletion Semantics

Status: Accepted · Date: 2026-10-12

## Problem

Per `REQUIREMENTS.md` §57 ("Transfer Plan"), §58 ("Dry Run"), §59 ("Delete Semantics"), §60 ("Security of Synchronization"), and §61 ("Transactional Synchronization"), directory synchronization requires explicit pre-flight inspection and rigorous deletion guardrails.

Without pre-flight planning and explicit deletion semantics:
1. Operators running bulk sync cannot predict network bandwidth requirements, local chunk reuse savings, or total file modifications prior to transfer.
2. Inadvertent deletions (e.g. syncing an empty directory or misconfiguring destination paths) can cause catastrophic data loss on destination storage.
3. Disk-constrained destination environments risk out-of-space (`ENOSPC`) errors if new files must be staged before obsolete destination files can be deleted.
4. Filtered or excluded temporary files may linger on destination servers unless explicitly synchronized.

## Options

1. **Implicit Unconditional Deletion**: Mirror source to destination unconditionally, deleting any absent destination files immediately on discovery without confirmation or threshold safety.
2. **Interactive Prompts Only**: Require interactive terminal prompts (`[y/N]`) for every file deletion.
3. **Structured Transfer Planning, Explicit Multi-Mode Deletions, and Guardrails**:
   - Pre-compute a deterministic `TransferPlan` summarizing file reconciliation counts (`unchanged`, `modified`, `added`, `deleted`, `excluded`), reusable bytes, wire transfer bytes, and bandwidth reduction percentage.
   - Support zero-mutation preview via `velcrux plan` and `velcrux sync --dry-run`.
   - Provide explicit deletion modes:
     - `DeleteMode::None` (safe default, never deletes destination files).
     - `DeleteMode::DeleteBefore` (deletes extraneous files prior to transfer to reclaim disk headroom).
     - `DeleteMode::DeleteAfter` (deletes extraneous files only after all staging, transfer, verification, and commits succeed).
     - `DeleteMode::DeleteExcluded` (deletes extraneous files plus any destination files matching exclude patterns).
   - Enforce deletion safety guardrails (`--max-delete`, `--max-delete-pct`, `--force-delete`) and strict lexical root containment to prevent directory traversal or accidental wipes.

## Decision

Option 3. Velcrux implements structured transfer planning, comprehensive dry-run preview, multi-mode deletion sequencing, and threshold guardrails natively in `velcrux-core` and `velcrux-client`.

Option 1 is rejected because catastrophic silent data loss is unacceptable for an enterprise data synchronization engine.
Option 2 is rejected because automated headless CI/CD pipelines, cron jobs, and background daemon synchronization cannot support interactive stdin prompts.

## Architecture & Lifecycle

### 1. Transfer Planning Pipeline
```text
Source Tree Scan + Destination Inventory Scan
                        ↓
             Reconciliation Engine
    (Unchanged, Modify, Add, Delete, Excluded)
                        ↓
              TransferPlan Engine
 (Files, Reusable Bytes, Wire Bytes, Reduction %)
                        ↓
            [Dry-Run Preview / Execution]
```

### 2. Deletion Timing Strategies
- **`DeleteMode::DeleteBefore`**: Evaluated and executed before any chunk transfer begins. Essential when destination storage capacity is near 100% full and disk space must be freed up before staging incoming files.
- **`DeleteMode::DeleteAfter`**: Evaluated beforehand but executed strictly after all files are verified and atomically committed to destination root. Guarantees that if a network failure occurs during transfer, legacy destination files remain intact.
- **`DeleteMode::DeleteExcluded`**: Combines extraneous deletion with deletion of destination paths matching active `--exclude` glob filters.

### 3. Safety Guardrails
- **`MaxFilesExceeded`**: Aborts sync before any file is removed if the scheduled deletion count exceeds `--max-delete <N>`.
- **`MaxPercentageExceeded`**: Aborts sync if scheduled deletions exceed `--max-delete-pct <P>%` of total destination files.
- **`PathEscapeAttempt`**: Validates all deletion paths with lexical normalization, rejecting paths containing `..`, absolute paths, empty strings, or protected Velcrux system paths (`.velcrux-staging`, `.velcrux-chunks`, `.git`).
- **`--force-delete`**: Explicit operator override required to bypass configured thresholds.

## Consequences

- Destructive operations are strictly opt-in; default `sync` never deletes files.
- Full machine-readable `--json` output available for both `velcrux plan` and `velcrux sync`.
- Zero unsafe code (`#![forbid(unsafe_code)]`).
- Documented in `docs/OPERATIONS.md` §30.
