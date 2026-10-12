# ADR-019: Point-in-Time Snapshot Isolation & File Version History Engine

Status: Accepted · Date: 2026-10-12

## Problem

Per `REQUIREMENTS.md` §34 ("Atomicity"), §61 ("Transactional Synchronization"), §63 ("Garbage Collection"), and §94 ("Deliverables"), large-scale dataset distribution and synchronization require point-in-time version isolation and time-travel rollback capabilities:
1. **Zero-Duplication Point-in-Time Versioning**: Duplicating multi-terabyte datasets (`cp -r`) multiplies disk usage, saturates storage I/O, and causes performance degradation. Snapshots must be zero-copy for unchanged data.
2. **Structural Change Analysis & Auditability**: Operators and automated pipelines need instant difference analysis (`added`, `removed`, `modified`, `unchanged` files and byte deltas) between any two arbitrary points in time.
3. **Atomic Point-in-Time Restoration**: Rolling back to a previous known-good state must be atomic, resilient to interruption, and verify every byte against original BLAKE3 cryptographic hashes.
4. **Garbage Collection Safety**: Background garbage collection sweeps (`gc_chunk_store`) must not prune chunks that belong to historical snapshots even if those files are no longer present in the live working directory.

## Options Considered

1. **Full Physical Directory Copies (`cp -r`)**:
   - Duplicate all files on disk under a snapshot subfolder.
   - *Rejected*: Enormous disk space waste, high I/O overhead, and slow creation times for large datasets.
2. **Filesystem-Specific Snapshots (ZFS / Btrfs / LVM)**:
   - Rely on OS-level volume snapshotting.
   - *Rejected*: Platform-dependent, requires elevated OS privileges, and cannot operate across portable chunk stores or cloud backends.
3. **CAS-Backed Point-in-Time Snapshot Isolation Engine (Option BC)**:
   - Lightweight, immutable JSON manifest trees (`SnapshotEntry`) rooted in `.velcrux/snapshots/`.
   - Backed by the content-addressed chunk store (`LocalChunkStore`): file content is sliced into 64 KiB segments and indexed by BLAKE3 hashes.
   - Files sharing identical content across multiple snapshots reference the same physical chunks on disk (100% deduplication).
   - Snapshot-aware garbage collection (`gc_chunk_store_with_snapshots`) protects all snapshot-referenced chunks from pruning.
   - Instant structural diffing and verified atomic time-travel restoration.

## Decision

Option 3. Velcrux implements native point-in-time snapshot isolation, differential change analysis, and CAS-backed time-travel restoration with `#![forbid(unsafe_code)]`.

## Architecture & Implementation

### 1. Data Model & CAS Deduplication Sharing

Every snapshot records an immutable manifest:
```json
{
  "tag": "release-v2.1",
  "created_at_secs": 1710000000,
  "root_path": "/data/datasets/imagenet",
  "file_count": 125000,
  "total_bytes": 142857142857,
  "files": {
    "train/labels.csv": {
      "relative_path": "train/labels.csv",
      "size": 655360,
      "file_hash": "3f9b...",
      "chunk_hashes": ["a1b2...", "c3d4...", "..."],
      "modified_at_secs": 1709990000,
      "is_executable": false
    }
  },
  "metadata": {
    "git_commit": "e9a03b1",
    "pipeline": "prod-build"
  }
}
```
- **Zero Storage Duplication**: Chunks are stored once in `LocalChunkStore`. Subsequent snapshots of the same dataset only record new or modified chunks.
- **Manifest Atomicity**: Snapshots are written to a temporary file (`.json.tmp-...`), flushed with `sync_all()`, and atomically renamed to `<tag>.json`.

### 2. Snapshot Differential Analysis (`SnapshotDiff`)

The diff engine compares any two snapshots `tag_a` and `tag_b`:
- **Added Files**: Present in `tag_b` but absent in `tag_a`.
- **Removed Files**: Present in `tag_a` but absent in `tag_b`.
- **Modified Files**: Present in both, but `file_hash` differs.
- **Unchanged Files**: Identical BLAKE3 whole-file checksums.

### 3. Snapshot-Aware Garbage Collection Protection

`gc_chunk_store_with_snapshots` unifies:
1. Live chunks referenced by active filesystem paths (`storage_roots`).
2. Chunks referenced by all registered point-in-time snapshots (`all_referenced_chunks()`).

Only chunks unreferenced by BOTH the live directories and all active snapshots are purged.

### 4. CLI Administration Reference

```bash
# Create a point-in-time snapshot with CAS deduplication backing
velcrux snapshot create prod-v1.0 /data/app --chunk-store /data/chunks --desc "Production release v1.0"

# List snapshots in catalog
velcrux snapshot list --chunk-store /data/chunks [--json]

# Diff changes between two historical releases
velcrux snapshot diff prod-v1.0 prod-v1.1 --chunk-store /data/chunks [--json]

# Restore a snapshot to a target destination directory
velcrux snapshot restore prod-v1.0 --dest /data/rollback --chunk-store /data/chunks [--json]

# Delete an obsolete snapshot
velcrux snapshot delete prod-v0.9 --chunk-store /data/chunks [--json]
```

## Consequences

### Positive
- Sub-second snapshot creation independent of dataset size.
- 100% deduplication reuse against the local or clustered CAS chunk store.
- Safe rollback with BLAKE3 cryptographic verification.
- Complete garbage collection protection for active snapshot versions.
