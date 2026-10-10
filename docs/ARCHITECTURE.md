# ARCHITECTURE

## 1. Layering

Velcrux implements the Raven application-layer bulk data transfer protocol over QUIC:

```text
Velcrux
├── velcrux CLI
├── velcruxd daemon
└── Raven Protocol
        └── QUIC
             └── UDP
```

Strict downward dependency. No layer reaches past its neighbour. The `Transport`
trait is the seam that makes QUIC replaceable.

```
                        CLI / config / progress / --json
                                     │
                        ┌────────────▼────────────┐
                        │     Transfer Engine     │  transfer lifecycle, plans,
                        │                         │  checkpoints, commit
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │       Sync Engine       │  manifests, inventory diff,
                        │                         │  delta decision, dedup
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │  Chunking + Hashing     │  CDC/fixed, BLAKE3
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │   Transfer Scheduler    │  priority, pacing, stream
                        │                         │  assignment, backpressure
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │  Transport (trait)      │  ── QuicTransport (quinn)
                        └────────────┬────────────┘
                                     │
                                    UDP
```

Client and server share every layer below the top. The difference is which side
initiates, and that the server additionally owns authorization and the storage root.

### Client

```
velcrux CLI
  ↓ parse, config merge, URL resolve
Client Session          ── connect, HELLO, capability negotiate, mTLS identity
  ↓
Transfer Manager        ── one entry per active transfer, persists to state DB
  ↓
      ┌──────────────┴──────────────┐
Sync/Delta path                Full-transfer path
      └──────────────┬──────────────┘
  ↓
Chunk Engine           ── streaming chunker + BLAKE3 hasher (worker pool)
  ↓
Scheduler              ── bounded chunk queue, priority, pacing
  ↓
QuicTransport          ── 1 connection, control + metadata + N data streams
  ↓
UDP
```

### Server

```
UDP
  ↓
QuicTransport          ── accept, mTLS peer cert → Identity
  ↓
Connection Actor       ── per-connection state machine, resource accounting
  ↓
Authorizer             ── Identity + operation + path → allow/deny  (before I/O)
  ↓
Request Router         ── control-stream dispatch
  ↓
      ┌──────────────┴──────────────┐
Sync/Delta                     Data plane
 inventory scan                 chunk verify
 manifest diff                  write scheduler
      └──────────────┬──────────────┘
  ↓
Storage Backend        ── LocalFilesystemBackend | (future) object stores
  ↓                        ChunkStore (optional, content-addressed)
File Builder → whole-file BLAKE3 → fsync → atomic rename → COMMIT
```

## 2. Modules

All in `crates/velcrux-core` unless noted.

### `protocol`
Wire encoding/decoding for the Raven Protocol (`RAVEN/1`). No I/O, no filesystem, no allocation driven by
attacker-supplied lengths. Every decoder is a `no_std`-friendly pure function over
a byte slice so it can be fuzzed in isolation. Owns: version constants, message
enums, frame headers, varint codec, error codes, capability bitset.

### `transport`
```rust
#[async_trait]
pub trait Transport: Send + Sync {
    type Conn: Connection;
    async fn connect(&self, addr: SocketAddr, sni: &str) -> Result<Self::Conn>;
    async fn accept(&self) -> Result<Self::Conn>;
}

#[async_trait]
pub trait Connection: Send + Sync {
    async fn open_bi(&self)  -> Result<(BiSend, BiRecv)>;
    async fn open_uni(&self) -> Result<UniSend>;
    async fn accept_uni(&self) -> Result<UniRecv>;
    fn peer_identity(&self) -> Option<Identity>;
    fn stats(&self) -> TransportStats;   // rtt, cwnd, bytes_in_flight, loss
    fn close(&self, code: u32, reason: &[u8]);
}
```
`QuicTransport` is the only implementation. `TransportStats` is what feeds
application-level scheduling — we consume QUIC's congestion signals, we never
replace them.

### `chunking`
`Chunker` is an iterator-shaped state machine fed fixed-size read buffers; it never
sees the whole file.
```rust
pub trait Chunker {
    /// Feed a read buffer. Returns boundaries found within it.
    fn push(&mut self, buf: &[u8]) -> SmallVec<[ChunkBoundary; 4]>;
    fn finish(&mut self) -> Option<ChunkBoundary>;
}
```
Implementations: `FixedChunker`, `CdcChunker` (gear rolling hash, 64-byte window,
mask chosen for the configured target size, hard min/max clamps).

### `hashing`
BLAKE3 wrapper with a rayon-backed worker pool for chunk hashing and a separate
streaming hasher for the whole-file digest. Whole-file hashing is done *in the same
pass* as chunking on the send side, and incrementally on the receive side only when
chunks arrive in order; otherwise it is a second pass over the staged file (see §7).

### `manifest`
Streaming writer/reader over the framed binary format. `ManifestWriter` appends to
a spill file and never holds more than one batch in memory. `ManifestReader` yields
entries. A manifest is content-addressed by the BLAKE3 of its canonical encoding,
so manifests themselves are cacheable and dedupable.

### `sync`
Inventory generation, hash-set reconciliation, the FULL-vs-DELTA estimator, and the
transfer plan. Pure logic over iterators — testable without network or disk.

### `storage`
```rust
pub trait StorageBackend: Send + Sync {
    async fn stat(&self, p: &VPath) -> Result<Option<Meta>>;
    async fn list(&self, p: &VPath) -> Result<BoxStream<Result<DirEntry>>>;
    async fn open_read(&self, p: &VPath) -> Result<Box<dyn RandomRead>>;
    async fn open_staging(&self, p: &VPath, size_hint: u64) -> Result<Staging>;
    async fn commit(&self, s: Staging, meta: &Meta) -> Result<()>;
    async fn remove(&self, p: &VPath) -> Result<()>;
}

pub trait ChunkStore: Send + Sync {
    async fn has(&self, h: &Hash) -> Result<bool>;
    async fn has_batch(&self, h: &[Hash]) -> Result<BitVec>;
    async fn put(&self, h: &Hash, data: &[u8]) -> Result<()>;   // verifies h
    async fn get(&self, h: &Hash) -> Result<Bytes>;             // verifies h
}
```
`VPath` is a newtype that can only be constructed by the authorizer's validation
routine. There is no path in the storage API that has not been validated. That is
the traversal defence, enforced by the type system rather than by discipline.

### `auth`
```rust
pub trait Authenticator { fn authenticate(&self, c: &ConnCreds) -> Result<Identity>; }
pub trait Authorizer   { fn check(&self, id: &Identity, op: Op, raw: &str) -> Result<VPath>; }
```
`MtlsAuthenticator` for MVP. The trait shape leaves room for OIDC/JWT/token
authenticators without touching the protocol layer.

### `scheduler`
Owns the bounded work queues, per-transfer priority, the pacer, and stream
assignment. See §5.

### `state`
SQLite (WAL) persistence for transfers, chunk bitmaps, manifests, and checkpoints.
See §6.

### `telemetry`
`tracing` for structured logs and spans, a Prometheus-format `/metrics` endpoint on
the server, and the `--json` event emitter on the client. No OTLP collector
required for the MVP; the `tracing` subscriber makes it a config change later.

## 3. Control plane vs data plane

One QUIC connection carries:

| Stream            | Type | Contents                                                    |
|-------------------|------|-------------------------------------------------------------|
| Control (id 0)    | bidi | HELLO, AUTH, TRANSFER_CREATE, CHECKPOINT, COMMIT, CANCEL, ERROR, PING |
| Metadata          | bidi | MANIFEST_*, INVENTORY_*, CHUNK_QUERY/RESPONSE               |
| Data (N)          | uni  | DATA frames only                                            |

Data streams carry a 32-byte stream preamble (transfer id, file id) and then chunk
frames with a 24-byte header. Nothing else. No JSON, no per-chunk round trips, no
metadata restated per frame.

Control is small and latency-sensitive, so it is always scheduled ahead of bulk
data — a 10 TB transfer must not delay a `CANCEL` or a `PING`.

## 4. Data pipelines

Upload:
```
Disk ──read (bounded pool of 2 MiB buffers)
   → Chunker (streaming, no copy of the read buffer)
   → Hasher pool (BLAKE3, N = min(cores-2, 8))
   → Delta filter (drop chunks the destination already has)
   → Scheduler (bounded queue, depth = parallelism × 4)
   → QUIC stream write
   → UDP
```
Download:
```
UDP → QUIC → frame decode
   → chunk verify (BLAKE3, reject on mismatch, no write)
   → write scheduler (coalesce adjacent, bounded in-flight writes)
   → staging file (pwrite at offset)
   → whole-file BLAKE3
   → fsync → atomic rename → COMMIT
```
Both directions are the same code with the roles swapped; upload and download are
not two implementations.

## 5. Concurrency, scheduling, backpressure

Task inventory — fixed, not per-packet, not per-chunk:

```
tokio runtime (multi-thread, workers = cores)
├── QUIC driver               (quinn, 1 task)
├── control task              (1 per connection)
├── metadata task             (1 per connection)
├── scheduler task            (1 per connection)
├── disk reader tasks         (bounded pool, spawn_blocking)
├── hashing workers           (rayon pool, sized once at startup)
├── data stream tasks         (1 per active stream, ≤ parallelism)
└── checkpoint/persistence    (1, batched)
```

**Backpressure** is a chain of bounded channels, and every stage awaits on send.
When the network slows, `Scheduler → QUIC` blocks, which fills the chunk queue,
which stalls the hashers, which stops the disk readers. Nothing grows without limit
and nothing needs an explicit rate signal to slow down. The same chain in reverse
protects the disk on the receive side.

Peak buffer memory is bounded by:
```
read_buffers(4 × 2 MiB) + chunk_queue(parallelism × 4 × max_chunk)
  + inflight_writes(parallelism × max_chunk) + quinn windows
```
With defaults (`parallelism=8`, `max_chunk=4 MiB`) that is roughly 400 MiB
regardless of whether the file is 1 GB or 10 TB.

**Priority.** Three classes: `HIGH` (control, small metadata, interactive
transfers), `NORMAL` (bulk files), `LOW` (background sync). The scheduler serves
HIGH to exhaustion, then weighted round-robin across NORMAL and LOW at 4:1. Within
a transfer, chunks are served in offset order to keep receive-side writes sequential
— random-order delivery costs more in disk seeks than it gains in flexibility.

**Pacing.** Bandwidth limits are enforced by a token bucket in the scheduler,
consulted before handing a chunk to a stream. Never `sleep()` between writes;
that interacts badly with QUIC's own pacer and produces bursty, loss-inducing
traffic. Limits compose: `min(per_transfer, per_user, global)`.

**Stream count.** One QUIC stream per file, `parallelism` files concurrently. For a
single huge file, MVP uses one stream and relies on QUIC's connection-level flow
control window (tuned to ≥ 2 × BDP) to keep the pipe full. Multi-stream-per-file
is a measured follow-up, not an assumption — see ADR-007 and `PERFORMANCE.md` §5.

## 6. Storage model

### Filesystem layout (server)

```
/data/velcrux/
├── files/                     storage root, all client-visible paths live here
├── chunks/                    optional content-addressed store
│   └── ab/cd/abcdef...        2-level fanout by hex prefix
├── state.db                   SQLite (WAL): transfers, checkpoints, refs
├── manifests/                 cached manifests by content hash
└── staging/                   in-progress <transfer_id>/<file_id>.velcrux-partial
```

Staging lives on the same filesystem as `files/` so the final `rename` is atomic.
If `storage.root` and `storage.staging` land on different devices, the server
refuses to start rather than silently degrading to a copy.

### State schema (abridged)

```sql
CREATE TABLE transfer (
  id            TEXT PRIMARY KEY,        -- ULID
  direction     TEXT NOT NULL,           -- upload | download | sync
  idempotency   TEXT UNIQUE,             -- client-supplied key
  src           TEXT NOT NULL,
  dst           TEXT NOT NULL,
  manifest_hash BLOB,
  status        TEXT NOT NULL,           -- see PROTOCOL.md §7
  bytes_total   INTEGER NOT NULL,        -- u64
  bytes_done    INTEGER NOT NULL,
  bytes_reused  INTEGER NOT NULL,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

CREATE TABLE file_state (
  transfer_id   TEXT NOT NULL REFERENCES transfer(id),
  file_id       INTEGER NOT NULL,        -- u64
  path          TEXT NOT NULL,
  size          INTEGER NOT NULL,        -- u64
  file_hash     BLOB,
  chunk_bitmap  BLOB NOT NULL,           -- 1 bit per chunk, roaring-compressed
  PRIMARY KEY (transfer_id, file_id)
);

CREATE TABLE chunk_ref (                 -- dedup reference tracking for GC
  chunk_hash BLOB NOT NULL,
  file_id    INTEGER NOT NULL,
  PRIMARY KEY (chunk_hash, file_id)
);
```

`chunk_bitmap` is the resume primitive. A roaring bitmap for a 10 TB / 1 MiB-chunk
file is a few hundred KiB when sparse and tens of KiB once dense — cheap enough to
rewrite at every checkpoint.

**Checkpointing.** Persist on whichever comes first: 1 GiB transferred, 10 seconds
elapsed, or a file boundary. Never per chunk, never per packet. Worst-case rework
after a crash is bounded by the checkpoint interval, which is the knob users tune.

## 7. Delta algorithm

The destination tells the source what it already has. Precisely:

1. **Source scans** its file streaming: chunker → hasher → `ManifestWriter`. It
   computes chunk hashes, offsets, lengths, and the whole-file hash in one pass.
2. **Source sends `MANIFEST_*`** (batched, zstd-framed) on the metadata stream. For
   a huge dataset this streams; the destination processes batch-by-batch and never
   materializes the whole manifest.
3. **Destination builds an inventory.** For each manifest entry it consults, in
   order:
   - the chunk store (`has_batch`), if dedup is enabled;
   - the existing destination file at the *same path*, chunked with the *same
     algorithm and parameters* (negotiated, so both sides agree), producing a local
     hash set.
   A Bloom filter over the destination's local hash set is used as a cheap
   pre-filter for the second lookup; a Bloom hit is then confirmed against the
   authoritative index. **A false positive can only cause an extra lookup, never a
   reuse decision.** That is the invariant that keeps probabilistic structures safe
   here.
4. **Destination replies `CHUNK_RESPONSE`**: a run-length-encoded have/need bitmap
   aligned to manifest entry order, one bit per chunk. For a 10 TB dataset at 1 MiB
   chunks that is ~10 M bits = 1.25 MiB raw, and typically a few KiB after RLE
   because reuse is clustered. This is one message per batch, not one per chunk —
   §14 of the spec's "do not send millions of individual messages".
5. **Source transfers only `need` chunks**, in offset order, on data streams.
6. **Destination reconstructs** into staging: `need` chunks come from the wire,
   `have` chunks are copied from the local file (`copy_file_range` where available)
   or linked/read from the chunk store.
7. **Destination verifies** the whole-file BLAKE3 against the manifest's declared
   value. Reconstruction mixes wire data and local data, so this check is what
   catches a destination file that changed under us, a chunk-store corruption, or a
   hash collision attempt.
8. **Atomic commit**: `fsync(staging)`, `rename`, `fsync(parent_dir)`.
9. **Failure at step 7** discards staging and falls back to a full transfer of that
   file, with the reason logged. It never commits.

Reuse from the *destination's existing file at the same path* is what makes this
rsync-like; reuse from the *chunk store* is what makes it dedup-like. Both feed the
same bitmap.

### FULL vs DELTA decision

Delta costs CPU and disk on both sides. For small or entirely-new files it is pure
overhead. The estimator:

```
full_cost   = size / net_bps

delta_cost  = size / min(src_disk_bps, hash_bps)         # source scan
            + size / min(dst_disk_bps, hash_bps)         # destination scan
            + manifest_bytes / net_bps
            + 2 × rtt                                    # manifest round trip
            + est_changed_bytes / net_bps
```

`est_changed_bytes` comes from (a) size+mtime comparison from `STAT`, (b) a measured
reuse ratio from previous syncs of the same path, defaulting to 0 (assume full) when
there is no history. Rules of thumb baked in as defaults:

- destination has no file at that path → **FULL**, always.
- `size < 8 MiB` → **FULL** (one round trip costs more than the bytes on a WAN).
- `size == dst_size && mtime == dst_mtime && !--checksum` → **SKIP**.
- otherwise compare the two costs; ties go to FULL because it has fewer failure
  modes.

The estimator is a module with its inputs injected, so it is unit-testable at every
RTT/bandwidth/loss point without a network.

## 8. Resume algorithm

1. Client looks up the transfer ID in its state DB, recovering direction, paths,
   manifest hash, and its own view of the chunk bitmap.
2. Client reconnects and sends `RESUME{transfer_id}`.
3. Server looks up the same ID. Cases:
   - **Unknown** → `TRANSFER_NOT_FOUND`; client offers to start fresh.
   - **Known, terminal** → server returns final status; nothing to do.
   - **Known, resumable** → server replies with *its* authoritative chunk bitmap
     and the manifest hash it has on record.
4. **The server's bitmap wins.** The client's bitmap is a hint only. Data the client
   believes it sent but which the server did not durably checkpoint is resent. This
   is the safe direction of disagreement.
5. Manifest hash mismatch (the source file changed since the interrupted run) →
   the transfer is not resumable; the client is told to create a new transfer.
   Resuming into a manifest that no longer describes the source would produce a
   file that matches neither version.
6. Client resumes at the first `0` bit, sending only missing chunks. The staging
   file is reused, not recreated.
7. Verification and commit are unchanged. A resumed transfer is verified exactly as
   strictly as an uninterrupted one — the whole-file hash is computed over the
   final staged bytes regardless of how many sessions contributed them.

Crash matrix:

| Failure                | Consequence                                              |
|------------------------|----------------------------------------------------------|
| Client process killed  | Resume from last client checkpoint; server bitmap wins.  |
| Server process killed  | Staging file survives; bitmap rolls back to checkpoint.  |
| Machine reboot         | Same as above; WAL recovery on state DB open.            |
| Network partition      | QUIC idle timeout → transfer marked `RESUMABLE`.         |
| Disk full mid-transfer | `DISK_FULL`, staging retained, transfer `RESUMABLE`.     |
| Corrupt chunk on wire  | Chunk rejected pre-write, re-requested, `CHECKSUM_MISMATCH` counter incremented. |
| Corrupt staging file   | Caught by whole-file verify; staging discarded, no commit. |

## 9. Transactional directory sync

```
PLAN → STAGE → TRANSFER → VERIFY → COMMIT
```

All files stage under `staging/<transfer_id>/`. Commit renames them into place in a
defined order (files before directory metadata; deletions last). Failure during
STAGE or TRANSFER leaves the destination **untouched**.

What we actually promise, stated plainly: **per-file atomicity is guaranteed** on any
filesystem with atomic `rename`. **Whole-directory atomicity is not** — POSIX gives
us no multi-path atomic rename. A crash during COMMIT can leave some files updated
and some not. It cannot leave any individual file partially written or corrupted.
The commit journal in the state DB records exactly how far COMMIT got, so a
subsequent run finishes it. We do not claim more than the filesystem can deliver;
see `OPERATIONS.md` §6 for the runbook.

## 10. Filesystem semantics

| Feature          | MVP                                    | Notes                          |
|------------------|----------------------------------------|--------------------------------|
| Regular files    | Yes                                    |                                |
| Directories      | Yes                                    |                                |
| Permissions      | Yes (POSIX mode bits)                  | Windows: not mapped            |
| mtime            | Yes, nanosecond where FS supports it   |                                |
| Symlinks         | Preserved as links, never followed at the destination | Target validated to stay inside root; escaping links are refused, not silently rewritten |
| Hard links       | Detected by (dev, ino), preserved within one transfer | Cross-transfer linking not attempted |
| Sparse files     | Yes — `SEEK_HOLE`/`SEEK_DATA` on Linux | Holes carried as extents, recreated with `fallocate(PUNCH_HOLE)`; falls back to writing zeros where unsupported |
| xattrs / ACLs    | **Not implemented in MVP**             | Explicitly documented gap; not silently dropped — `sync` warns once per run |
| Special files    | Skipped with a warning                 | Devices, sockets, FIFOs        |

Nothing in this table is silently discarded. Anything we cannot carry produces a
warning that names the path and the attribute.

## 11. Compression

Off by default. Optional `zstd` at level 3, applied per chunk, *before* handing to
QUIC (which encrypts). Never after — encrypted bytes are high-entropy by design and
compressing them wastes CPU for nothing, and delta-matching them is meaningless.

An entropy probe samples the first 64 KiB of each file; if it does not compress by
at least 10%, the file is marked incompressible and compression is skipped for it.
Incoming compressed frames are bounded by a declared decompressed size that is
checked against `max_chunk_size` *before* allocation — the decompression-bomb
defence.

## 12. MVP milestones and definition of done

| M  | Deliverable                          | Exit test                                        |
|----|--------------------------------------|--------------------------------------------------|
| 1  | QUIC connect, control stream, HELLO  | `velcrux ping` round trip, version negotiation   |
| 2  | Upload + download, streaming I/O     | 100 GB round trip, hash matches, bounded RSS     |
| 3  | Transfer IDs, checkpoints, resume    | SIGKILL at 50%, restart, completes without redo  |
| 4  | mTLS auth + authorization            | Traversal and cross-tenant tests all denied      |
| 5  | Manifests                            | Streaming manifest for 1 M files, bounded RSS    |
| 6  | Fixed + CDC chunking                 | Insertion at offset 0 reuses ≥ 95% under CDC     |
| 7  | Delta                                | 100 GB with 3 GB changed moves ≈ 3 GB + overhead |
| 8  | Chunk store / dedup                  | Second copy of a file transfers ≈ 0 bytes        |
| 9  | Directory sync, dry-run, delete      | Commit journal resumes an interrupted COMMIT     |
| 10 | Performance                          | Targets in `PERFORMANCE.md` §2 met               |

Done when all 15 items in the spec's §83 pass in CI, including the netem loss and
RTT scenarios, with no `unsafe` outside the documented exception crate.

## 13. Deliberate MVP exclusions

Custom congestion control, custom crypto, multipath, object-storage backends,
distributed or cross-server chunk stores, cluster management, web UI, Kubernetes
operator. Session and connection identifiers are designed to permit multipath
later (§74 of the spec) but nothing multipath is implemented.

## 14. Architecture Decision Records (ADRs)

Key architectural decisions are recorded in `docs/adr/` in conformance with `REQUIREMENTS.md` §80:

| ADR | Title | Status | Primary Focus |
|---|---|---|---|
| [ADR-001](adr/ADR-001-quic-transport.md) | QUIC as transport | Accepted | Low latency, multiplexed loss recovery, TLS 1.3 encryption |
| [ADR-002](adr/ADR-002-rust.md) | Rust as implementation language | Accepted | Memory safety, `#![forbid(unsafe_code)]`, zero-copy async I/O |
| [ADR-003](adr/ADR-003-blake3.md) | BLAKE3 vs SHA-256 | Accepted | Tree hashing, SIMD acceleration, SHA-256 interop mode |
| [ADR-004](adr/ADR-004-chunking.md) | Fixed vs content-defined chunking | Accepted | FastCDC with gear hash for boundary shift resilience |
| [ADR-005](adr/ADR-005-persistence.md) | Manifest and state persistence | Accepted | Streaming columnar manifests, SQLite WAL state database |
| [ADR-006](adr/ADR-006-chunk-store.md) | Content-addressed chunk store | Accepted | CAS deduplication, 2-level fanout, generation GC |
| [ADR-007](adr/ADR-007-stream-model.md) | One QUIC stream per file | Accepted | Sequential disk writes, BDP window sizing vs multi-streaming |
| [ADR-008](adr/ADR-008-versioning.md) | Protocol versioning & capabilities | Accepted | Dual version + capability negotiation floor |
| [ADR-009](adr/ADR-009-zero-knowledge-chunk-encryption.md) | Zero-Knowledge Chunk Encryption | Accepted | ChaCha20-Poly1305 / AES-GCM envelope AEAD with AAD binding |
| [ADR-010](adr/ADR-010-quic-connection-migration-and-failover.md) | QUIC Connection Migration & Failover | Accepted | RFC 9000 §9 socket rebind, subnet gating, and rate limiting |

