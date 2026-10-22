# ADR-035: Zero-Copy Kernel Direct I/O (`O_DIRECT` / `F_NOCACHE`) Ring-Buffer Pipeline

Status: Accepted · Date: 2026-10-22

## Context

In high-throughput distributed file synchronization and bulk data replication (e.g. 10–100 Gbps NVMe transfers), standard OS buffered I/O imposes severe scalability bottlenecks:

1. **Page-Cache Double Buffering & Memory Waste**:
   - Traditional I/O reads from the storage controller into kernel page-cache pages, copies data to user-space buffers, copies data again to socket buffers, and finally DMAs out to the NIC.
   - For multi-gigabyte or terabyte dataset transfers, streaming through the OS page cache evicts active operating system memory and application caches, causing heavy OS paging, kernel memory pressure, and translation lookaside buffer (TLB) shootdowns.
2. **Serialization Bubbles in Naive Direct I/O**:
   - Direct I/O (`O_DIRECT` on Linux, `F_NOCACHE` on macOS) completely bypasses the page cache, initiating direct DMA transfers between physical NVMe storage and user-space aligned memory.
   - However, naive synchronous Direct I/O produces serialization bubbles: the storage device idles while the network transport sends chunks, and the network pipe starves while the storage device reads new blocks.
3. **Sector Alignment & Tail Truncation Constraints**:
   - Direct I/O strictly mandates that memory addresses, file offsets, and I/O buffer lengths are aligned to physical storage sector boundaries (standard 4096 bytes).
   - Any fractional file tail (e.g. a 1,234,567-byte file) cannot be written directly without padding to the nearest 4096-byte sector boundary, followed by exact byte truncation.
4. **Safety & Zero-Copy Without Unsafe Code**:
   - In accordance with Velcrux architectural invariants (`CLAUDE.md` §1), all memory alignment and circular ring buffering must strictly enforce `#![forbid(unsafe_code)]` with zero exceptions.

## Options Considered

1. **Option 1: Traditional Buffered I/O with Large Buffers**:
   - Rely solely on OS page cache with `std::io::BufReader` / `BufWriter`.
   - *Rejected*: Thrases kernel page cache on large files, wastes memory bandwidth on double-copying, and limits NVMe streaming throughput.
2. **Option 2: Unsafe Posix `posix_memalign` / `mmap` with `MAP_SHARED`**:
   - Use unsafe C library calls to allocate aligned memory.
   - *Rejected*: Violates `#![forbid(unsafe_code)]` and introduces pointer safety risks.
3. **Option 3: Pure Safe-Rust Zero-Copy Direct I/O Ring-Buffer Pipeline (`ADR-035`)**:
   - Build a circular ring-buffer engine (`DirectIoRingBuffer`) with configurable sector-aligned DMA slots (`AlignedSectorBuffer`).
   - Implement asynchronous read-ahead prefetching (`DirectIoPipelineReader`) and write-behind flushing (`DirectIoPipelineWriter`).
   - Pad fractional sector tails on EOF writes and atomically truncate using `File::set_len`.
   - Provide CLI management (`velcrux direct-io inspect|benchmark`), runtime flags (`--direct-io-slots`, `--direct-io-slot-size`), and Prometheus observability (`velcrux_direct_io_ring_*`).

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. Circular Ring-Buffer (`crates/velcrux-core/src/storage/direct_io.rs`)

The `DirectIoRingBuffer` coordinates an array of circular DMA slots:

```rust
pub struct DirectIoRingBuffer {
    config: DirectIoRingConfig,
    slots: Vec<RingSlot>,
    head: usize,
    tail: usize,
    active_slots: usize,
    next_sequence: u64,
    stats: DirectIoPipelineStats,
}
```

Each `RingSlot` tracks its lifecycle across four discrete states:
- `Empty`: available for acquisition by the storage reader or network receiver.
- `Filling`: actively being populated with incoming sector-aligned DMA blocks.
- `Ready`: populated with valid payload data and queued for consumption.
- `Flushing`: actively being flushed to disk or transmitted across the wire.

When all slots are full or empty, the pipeline records a stall (`pipeline_stalls`), enforcing strict bounded memory consumption ($N \times \text{slot\_capacity}$, e.g. $4 \times 2\text{ MiB} = 8\text{ MiB}$).

### 2. Sector Alignment Engine (`AlignedSectorBuffer`)

To achieve physical NVMe DMA alignment without unsafe memory allocators, `AlignedSectorBuffer` allocates `capacity + alignment` bytes in safe Rust:
$$\text{offset} = (\text{alignment} - (\text{ptr} \pmod{\text{alignment}})) \pmod{\text{alignment}}$$
The usable slice starts precisely at `storage[offset..]`, ensuring that:
$$\text{data\_ptr()} \pmod{4096} = 0$$

### 3. Pipelined Prefetching & Write-Behind

- **`DirectIoPipelineReader`**:
  - Automatically prefetches sequential file data into available empty slots in the ring buffer up to the ring capacity.
  - When the consumer finishes reading slot $k$, releasing it triggers an immediate prefetch into slot $(k + N) \pmod N$, decoupling disk reads from network transmission.
- **`DirectIoPipelineWriter`**:
  - Accumulates incoming network stream chunks into the currently filling ring slot.
  - When a slot reaches capacity, it is marked `Ready` and immediately flushed to disk via write-behind while the next empty slot begins filling.
  - On stream finish, any fractional tail sector is zero-padded to a 4096-byte multiple for the final Direct I/O write, followed by `File::set_len(total_written)` to restore exact byte-level file length.

## Observability & CLI

### CLI Subcommands

- `velcrux direct-io inspect [--path <path>] [--json]`
  - Inspects active Direct I/O policy, sector sizes, ring slot counts, and tests target path Direct I/O eligibility.
- `velcrux direct-io benchmark --path <path> [--size <bytes>] [--slots <n>] [--slot-size <bytes>] [--json]`
  - Executes full-pipeline write-then-read streaming throughput benchmarks, reporting MiB/s transfer speeds, pipeline stalls, and BLAKE3 data integrity verification.

### CLI Flags

- `--direct-io-slots <n>`: Number of ring buffer slots (2 to 32, default: 4).
- `--direct-io-slot-size <bytes>`: Slot capacity in bytes (default: 2 MiB).

### Prometheus Metrics (`OPERATIONS.md` §7)

```prometheus
# HELP velcrux_direct_io_ring_transfers_total Total Direct I/O ring-buffer transfers executed
# TYPE velcrux_direct_io_ring_transfers_total counter
velcrux_direct_io_ring_transfers_total 42

# HELP velcrux_direct_io_ring_bytes_total Total bytes processed through Direct I/O ring-buffer pipeline
# TYPE velcrux_direct_io_ring_bytes_total counter
velcrux_direct_io_ring_bytes_total 35184372088832

# HELP velcrux_direct_io_ring_stalls_total Total ring-buffer pipeline stall events waiting for slots
# TYPE velcrux_direct_io_ring_stalls_total counter
velcrux_direct_io_ring_stalls_total 12
```

## Consequences

- **Positive**:
  - Completely eliminates kernel page cache double-buffering and memory pollution during bulk transfers.
  - Decouples storage latency from network streaming via circular ring prefetching and write-behind.
  - Strict bounded memory consumption with zero heap thrashing.
  - Preserves `#![forbid(unsafe_code)]` with zero exceptions.
- **Negative**:
  - Direct I/O requires 4096-byte alignment and fallback logic for unaligned fractional file tails.
