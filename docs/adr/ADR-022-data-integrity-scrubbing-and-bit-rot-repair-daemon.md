# ADR-022: In-Flight Data Integrity Scrubbing & Background Bit-Rot Repair Daemon

Status: Accepted · Date: 2026-10-13

## Problem

Per `REQUIREMENTS.md` §18 ("Integrity Verification"), §63 ("Garbage Collection"), §70 ("Graceful Shutdown"), and `ARCHITECTURE.md` §2, storage backends and content-addressed chunk stores are vulnerable to hardware and media degradation over time:
1. **Silent Bit Rot & Physical Media Degradation**: Physical storage media (HDDs, SSDs, NVMe drives, controller caches) suffer from cosmic rays, degraded flash cells, truncated writes, and silent block corruptions. Standard filesystem reads do not reliably detect silent bit rot unless every chunk is cryptographically verified against its BLAKE3 digest.
2. **Cascading Corruptions Across Deduplicated Datasets**: In a content-addressable chunk store (`LocalChunkStore`), a single chunk may be referenced by dozens of files and snapshots. If that chunk suffers silent bit rot, every file and snapshot referencing it becomes corrupted.
3. **Proactive Quarantine vs. Catastrophic Failures**: Corrupted chunks must be immediately detected and quarantined before client sync pipelines serve corrupt bytes to downstream recipients.
4. **Autonomous Self-Healing in Distributed Topologies**: When corrupt or truncated chunks are discovered on a local node, the system should autonomously fetch healthy replicas from peer nodes or backup cluster stores (`ClusteredChunkStore`) and repair the damaged chunk in-place.
5. **Throttled Background Daemon & Non-Intrusive Audits**: Scrubbing terabytes of data must support I/O rate-limiting so that background verification sweeps do not monopolize disk bandwidth or disrupt production transfer workloads.

## Options Considered

1. **Reactive On-Read Hash Checks Only**:
   - Only verify chunks when a client or transfer actively requests them.
   - *Rejected*: Inactive or archival chunks can silently degrade for months undetected, leaving no time to repair them before disaster strikes or before replicas are pruned.
2. **Filesystem-Level Scrubbing (`zpool scrub` / `btrfs scrub`)**:
   - Rely solely on OS filesystem scrubbers.
   - *Rejected*: Requires specific copy-on-write filesystems, root permissions, does not work on ext4/XFS or cloud storage, and cannot coordinate peer-level chunk healing.
3. **Native Data Integrity Scrubber & Bit-Rot Repair Daemon (Option BF)**:
   - Built directly into `velcrux-core` under `#![forbid(unsafe_code)]`.
   - Traverses the 2-level content-addressed chunk store (`chunks/ab/cd/*.chunk`), verifying each chunk against its filename BLAKE3 hash.
   - Multiple operational modes: `VerifyOnly` (read-only audit), `Quarantine` (atomic isolation into `.quarantine/`), and `HealFromPeer` (automatic self-healing from peer chunk stores).
   - Rate-limiting I/O throttling (`rate_limit_mb`) to preserve production disk performance.
   - Persistent report journaling (`.velcrux/last_scrub.json`) recording scanned volumes, bit-rot findings, and repair throughput.
   - Comprehensive CLI integration (`velcrux scrub run`, `status`, `repair`).

## Decision

Option 3. Velcrux implements a native In-Flight Data Integrity Scrubbing & Bit-Rot Repair Daemon under `#![forbid(unsafe_code)]`.

## Architecture & Implementation

### 1. Data Model & Diagnosis Classifications

Each inspected chunk is classified into an exact integrity state:
- `Healthy`: Content matches the expected BLAKE3 digest.
- `BitRotCorrupted`: Content mismatch; bytes have degraded or mutated.
- `Truncated`: Zero-length or incomplete chunk file.
- `Repaired`: Damaged chunk successfully healed and rewritten from a valid peer replica.
- `Quarantined`: Damaged chunk moved to `<store>/.quarantine/<hash>.corrupt`.
- `Unrecoverable`: Corrupted chunk that could not be restored due to missing peer replicas.

Findings are structured into an audit report:
```json
{
  "scanned_chunks": 50000,
  "healthy_chunks": 49998,
  "corrupted_chunks": 2,
  "repaired_chunks": 2,
  "quarantined_chunks": 0,
  "unrecoverable_chunks": 0,
  "scanned_bytes": 3276800000,
  "repaired_bytes": 131072,
  "started_at_secs": 1791807000,
  "duration_ms": 12450,
  "throughput_mb_s": 263.2,
  "target_path": "/var/lib/velcrux/chunks",
  "findings": [
    {
      "chunk_hash": "3f9b8c2a...",
      "path": "/var/lib/velcrux/chunks/3f/9b/3f9b8c2a...chunk",
      "actual_hash": "e1a4d801...",
      "status": "repaired",
      "details": "Corrupt chunk successfully healed and restored from peer"
    }
  ]
}
```

### 2. Autonomous Peer Self-Healing

When `ScrubMode::HealFromPeer` is active:
1. When a chunk hash mismatch or truncation is detected, `DataScrubber` queries the designated peer `ChunkStore` for `expected_hash`.
2. The peer returns its replica; the scrubber verifies `Hash::of(&peer_bytes) == expected_hash`.
3. If authentic, the scrubber writes the healthy bytes to the local chunk path atomically.
4. If the peer is unavailable or lacks the chunk, the finding is marked `Unrecoverable`.

### 3. I/O Throttling & Rate-Limiting

Scrubbing large multi-terabyte stores can saturate storage controllers. The scrubber tracks byte intervals (e.g. 1 MB windows) and computes required delay based on `rate_limit_bytes_per_sec`, calling `tokio::time::sleep` to maintain a smooth I/O profile.

### 4. CLI Administration Reference

- `velcrux scrub run <chunk-store> [--mode <verify|quarantine|heal>] [--peer-store <dir>] [--rate-limit-mb <MB>]`
- `velcrux scrub status <chunk-store>`
- `velcrux scrub repair <chunk-store> --peer-store <dir> [--rate-limit-mb <MB>]`
- Machine-readable `--json` output across all subcommands.

## Consequences

- **Positive**:
  - Eliminates silent bit rot across content-addressed chunk storage.
  - Automatic self-healing prevents data loss without manual operator intervention.
  - Isolates damaged chunks into quarantine before transfers can serve corrupted data.
  - Safe background operation with non-intrusive I/O rate-limiting.
- **Negative / Trade-offs**:
  - Full cryptographic scrubbing reads every byte from disk, consuming storage read bandwidth during active runs.
  - Self-healing requires at least one healthy peer or backup replica.
