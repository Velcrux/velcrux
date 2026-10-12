# ADR-021: Dynamic Zstandard Pre-Trained Dictionary Learning Engine

Status: Accepted · Date: 2026-10-12

## Problem

Per `REQUIREMENTS.md` §89 ("Compression Design"), §26 ("Bandwidth Minimization"), §64 ("Wire Compression"), and `SECURITY.md` §8 ("Bounded Decompression & Decompression-Bomb Defense"), large-scale dataset distribution involves high volumes of small, structured, or semi-structured files:
1. **Inefficiency of Vanilla Streaming Compression on Small Chunks**: Standard LZ77 / entropy compression engines (such as default Zstandard or gzip) rely on finding matches within a backward sliding window. On payloads between 256 bytes and 64 KiB (such as JSON records, CSV rows, source code files, RPC manifests, or microservices logs), the window has insufficient history to achieve high compression ratios. Often, headers cause the payload to expand rather than compress.
2. **Cross-Payload Redundancy**: Redundancy exists *across* chunks and files rather than *within* individual chunks. Shared schemas, key names, syntax tokens, and common prefixes recur thousands of times across the dataset.
3. **Decompression Bomb & CPU Defense**: Decompressing payloads trained against dictionaries must enforce the same bounded memory and ratio limits as vanilla streams to protect receivers against maliciously crafted inputs.
4. **Operational Ease of Dictionary Lifecycle**: Generating, evaluating, cataloging, exporting, and importing dictionaries must be seamless and self-contained without requiring external Python scripts or C binaries.

## Options Considered

1. **Generic Streaming Compression Only (Option AO)**:
   - Rely solely on runtime per-chunk zstd without pre-trained dictionaries.
   - *Rejected*: Inadequate for small chunks; leaves 30% to 60% of potential bandwidth reduction unrealized for structured datasets.
2. **Offline External `zstd --train` Shell Scripting**:
   - Require operators to run external C tools (`zstd`) and distribute binary `.dict` files manually.
   - *Rejected*: Violates Velcrux's self-contained zero-external-dependency requirement and makes programmatic sync pipelines fragile.
3. **Native Dynamic Zstandard Pre-Trained Dictionary Learning Engine (Option BE)**:
   - Built directly into `velcrux-core` using pure-Rust APIs under `#![forbid(unsafe_code)]`.
   - Native sample harvesting (`DictionaryTrainer::sample_directory`) and dictionary training (`DictionaryTrainer::train_from_samples`).
   - Persistent dictionary catalog (`DictionaryCatalog`) managing dictionary metadata and `.zdict` binaries in `.velcrux/dictionaries/`.
   - Comparative evaluation engine (`evaluate_dictionary_ratio`) reporting exact bandwidth reduction percentages over standard zstd.
   - Strict bounded decompression defenses (`decompress_with_dict_bounded`) guarding against decompression bombs.
   - Comprehensive CLI integration (`velcrux dict train`, `list`, `test`, `export`, `import`, `delete`).

## Decision

Option 3. Velcrux implements a native Dynamic Zstandard Pre-Trained Dictionary Learning Engine under `#![forbid(unsafe_code)]` with zero external C dependencies.

## Architecture & Implementation

### 1. Data Model & Dictionary Catalog

Each trained dictionary generates a standardized metadata manifest:
```json
{
  "dict_id": 14285714,
  "name": "telemetry-metrics-v1",
  "created_at_secs": 1791805000,
  "sample_count": 50,
  "trained_bytes": 1048576,
  "dict_size": 114688,
  "checksum": "3f9b8c2a1e0d45b7",
  "description": "Pre-trained dictionary for telemetry log records"
}
```

- **Dictionary Identifiers**: A stable 32-bit `dict_id` is derived from the BLAKE3 digest of the trained dictionary bytes.
- **Catalog Persistence**: Stored under `.velcrux/dictionaries/` (or configurable `--dict-dir`) with individual `.zdict` binaries and `catalog.json` registry index.

### 2. Sample Ingestion & Training

- `DictionaryTrainer::sample_directory` walks candidate file trees, filtering out already-compressed binaries (`.gz`, `.zip`, `.zst`, `.png`, `.jpg`, `.mp4`).
- Up to `MAX_SAMPLE_PER_FILE` (32 KiB) is ingested per file up to `--max-samples`.
- Invokes native zstd dictionary builder (`zstd::dict::from_samples`) with target size clamped to `DEFAULT_MAX_DICT_SIZE` (112 KiB).

### 3. Compression & Decompression-Bomb Bounded Verification

- `compress_with_dict`: Initializes `zstd::Encoder::with_dictionary(Vec::new(), level, dict_bytes)` to compress payloads.
- `decompress_with_dict_bounded`: Streams output into fixed buffers, strictly validating total bytes (`max_bytes`) and expansion ratio (`max_ratio`). Any violation immediately aborts with `ProtocolError::DecompressionBomb`.

### 4. Empirical Evaluation

- `evaluate_dictionary_ratio`: Concurrently computes raw size, vanilla zstd size, and dictionary zstd size across test samples, calculating:
  - `vanilla_ratio` (e.g. 1.8x)
  - `dict_ratio` (e.g. 4.6x)
  - `extra_savings_pct` (e.g. 52.4% additional bandwidth saved)

### 5. CLI Administration Reference

- `velcrux dict train <source-dir> [--name <name>] [--dict-size <bytes>] [--max-samples <N>] [--desc <desc>]`
- `velcrux dict list [--dict-dir <dir>]`
- `velcrux dict test <dict-id> <target-path> [--dict-dir <dir>]`
- `velcrux dict export <dict-id> <dest-file> [--dict-dir <dir>]`
- `velcrux dict import <source-file> [--name <name>] [--desc <desc>] [--dict-dir <dir>]`
- `velcrux dict delete <dict-id> [--dict-dir <dir>]`
- Machine-readable `--json` output across all subcommands.

## Consequences

- **Positive**:
  - Dramatically improves compression ratios (up to 2x-5x improvement) on small files and structured chunk streams.
  - Zero external C tooling or scripting required.
  - Full protection against decompression bombs and untrusted dictionary payloads.
  - Portable export/import enables seamless distribution of pre-trained dictionaries across cluster nodes.
- **Negative / Trade-offs**:
  - Training requires collecting at least 5 representative samples.
  - Dictionary storage requires ~32-112 KiB per registered dictionary.
