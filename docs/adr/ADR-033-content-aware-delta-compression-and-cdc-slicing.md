# ADR-033: Content-Aware Delta Compression Engine with Zstd Dictionary Training & CDC Slicing

Status: Accepted · Date: 2026-10-20

## Context

In distributed delta synchronization (using fixed chunking or FastCDC content-defined chunking), when a file is modified, chunks that differ from the destination baseline must be transferred across the network.

However:
1. **Inefficiency on Small Mutations in Chunks**:
   When a developer edits 1-2 lines in a 512 KiB or 1 MiB chunk, or when an append/edit alters structured logs, database extents, or binary containers, the chunk's BLAKE3 digest changes completely. Traditional deduplication and chunk caches identify the chunk as a miss and transmit the full 512 KiB - 1 MiB over the wire.
2. **Poor Standalone Compression Ratios**:
   Applying standard Zstandard compression (`zstd::bulk::compress`) per individual chunk yields modest compression ratios (typically 1.2× – 2.0×) because the LZ77 dictionary window starts completely empty for each individual chunk.
3. **Zstd Dictionary Training Impedance**:
   While offline Zstd dictionary training works well for uniform batches of small files (as implemented in ADR-021), it requires pre-collected sample corpuses and manual distribution. For arbitrary user files modified in-place, the optimal dictionary is already present on the receiver: the prior version of that exact byte range in the baseline file!
4. **Bandwidth Savings vs CPU Overhead**:
   Dictionary compression adds CPU compression overhead. If the mutated chunk has completely diverged from the baseline (e.g. replaced by random or encrypted bytes), attempting dictionary compression will waste CPU or could even inflate payload size. Therefore, an adaptive savings threshold and policy gate (`Auto`, `Off`, `Aggressive`) are mandatory.

## Options Considered

1. **Option 1: Fixed Chunk Transfer with Vanilla Zstd Only**:
   - Send full modified chunks compressed with standalone Zstandard.
   - *Rejected*: Inefficient for small delta mutations; wastes 80-95% of bandwidth that could be eliminated by using baseline reference extents.
2. **Option 2: Standalone Binary Diff Algorithms (e.g. bsdiff / xdelta3)**:
   - Run external or separate binary diffing algorithms per file.
   - *Rejected*: Requires loading entire files or complex non-streaming state into memory; lacks wire integration with QUIC frames and chunk-level streaming pipelines; separate dependency.
3. **Option 3: Content-Aware Delta Compression Engine with Zstd Dynamic Baseline Extent Dictionaries & CDC Slicing (`ADR-033`)**:
   - Feed the corresponding byte window from the baseline destination file directly into Zstandard as a pre-trained dictionary (`compress_with_dict` / `decompress_with_dict_bounded`).
   - Frame the compressed slice in a canonical binary header (`DeltaSliceHeader`, `DELTA_SLICE_MAGIC = 0xDE17`) specifying the reference offset and length.
   - Guard against compression regressions with an adaptive threshold percentage (default 15%, 5% in aggressive mode), falling back gracefully to vanilla Zstd or raw literal.
   - Provide a standalone CLI inspection tool (`velcrux delta-slice test <source> <baseline>`) and runtime sync integration (`--delta-dict <auto|off|aggressive>`).

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. Canonical Wire Envelope & Framing (`crates/velcrux-core/src/sync/delta_dict.rs`)

Each delta slice is framed with a 55-byte binary header followed by payload bytes:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Magic (0xDE17)          |  Kind (u8)    |  Orig Len (0) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Original Length (cont)    |    Compressed Length (u32)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Reference Offset (u64)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Reference Length (u32)   |     Chunk BLAKE3 Hash         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                       (32 bytes total)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Payload Bytes (Compressed or Literal)          |
|                               ...                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2. Compression Kinds & Fallbacks

- `RawLiteral (0)`: Uncompressed chunk bytes (used when data is high entropy or uncompressible).
- `VanillaZstd (1)`: Standalone Zstd compression without reference dictionary.
- `DictDelta (2)`: Content-aware Zstd compression using baseline reference window as dictionary.
- `ExactMatch (3)`: Chunk identical to baseline at corresponding offset (0 wire bytes).

### 3. Pipeline Integration in `execute_directory_sync`

During directory synchronization:
1. For each chunk transferred across the wire, if destination baseline file exists, sample the baseline extent around `offset`.
2. Compress with `ContentDeltaEngine::compress_chunk`.
3. If savings over raw chunk exceed `--delta-dict-threshold` (default 15%), transmit `DictDelta`.
4. On destination side, `decompress_chunk` reads the specified baseline window, decompresses with bounded memory, and verifies BLAKE3 hash before staging.

### 4. Telemetry & Metrics

Exported via Prometheus `/metrics`:
- `velcrux_delta_slices_total{kind="all|dict|vanilla"}`: Total counter of delta slices processed.
- `velcrux_delta_dict_bytes_saved_total`: Total network bandwidth saved in bytes via dictionary compression.

### 5. CLI Interface

- `velcrux sync <src> <dst> --delta-dict <auto|off|aggressive> --delta-dict-threshold <pct>`
- `velcrux delta-slice test <source> <baseline> [--chunk-size <bytes>] [--policy <policy>] [--threshold <pct>] [--json]`

## Consequences

- **Bandwidth**: 5× to 50× reduction in network transfer for small mutations to large files.
- **Safety**: Pure `#![forbid(unsafe_code)]`; strict bounded memory decompressor preventing decompression bombs per `SECURITY.md` §8.
- **Compatibility**: Backwards compatible; `--delta-dict off` completely disables dictionary logic.
