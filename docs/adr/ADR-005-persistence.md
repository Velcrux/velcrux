# ADR-005: Streaming manifests, and SQLite for transfer state

Status: Accepted · Date: 2026-09-02

## Problem

A 10 TB dataset at 1 MiB chunks is ~10 million chunk descriptors. At ~40 bytes
each that is 400 MB of manifest. Rule 4 says never assume it fits in RAM, and
requirement §31 says a manifest is not a `Vec<Everything>`. Separately, resume
needs durable per-chunk completion state that survives a kill at any instant.

## Options for the manifest

1. In-memory `Vec`. Simple, and fine up to about a TB. Fails the requirement.
2. Streaming framed format with a spill file. Bounded memory, sequential access,
   requires care wherever code wants random access to entries.
3. Full embedded database for manifests. Random access and indexing, but heavier
   and manifests are naturally consumed in order.

## Options for transfer state

1. A JSON or TOML state file rewritten periodically. Simple, but a rewrite of a
   large file at every checkpoint is expensive, and a crash mid-rewrite can lose
   the previous state too.
2. Append-only log with compaction. Fast writes, but we are then implementing
   recovery, compaction, and crash-consistency ourselves.
3. SQLite in WAL mode.

## Decision

Streaming framed manifests (option 2) with 4096-entry batches, zstd-framed on the
wire, spilled to disk when large and content-addressed by hash so they are
cacheable. SQLite in WAL mode for transfer state, chunk bitmaps, and the commit
journal.

## Trade-offs

Streaming manifests mean any algorithm consuming them must work in a single
forward pass. The delta comparison was designed around that constraint rather than
being retrofitted: the destination processes batch-by-batch and replies with a
bitmap per batch, so neither side ever holds the whole thing. Where random access
is unavoidable — the chunk-store index — that lives in SQLite, not in the manifest.

Requirement §31 says not to introduce a database unless it solves a demonstrated
problem. Two problems demonstrate it. First, crash consistency: SQLite's WAL gives
us atomic, durable, recoverable checkpoint writes, and hand-rolling that is
exactly the "reinventing hard infrastructure" this project is otherwise avoiding.
Second, the chunk-store index needs indexed lookups and reference counting for GC,
which is a database-shaped problem.

The cost is a C dependency and a write path that is slower than an append-only
log. Both are acceptable because checkpoints are infrequent by design — 1 GiB or
10 seconds, never per chunk. There is one specific footgun worth writing down: a
relative default DB path combined with a working-directory change silently creates
a fresh empty database and loses all resume state with no error. The DB path is
therefore always absolute and always explicit in config.

Chunk bitmaps use roaring compression: a few hundred KiB when sparse, tens of KiB
once dense, for a 10 M-chunk file. Cheap enough to rewrite whole at every
checkpoint, which avoids incremental-bitmap-update bugs entirely.

## Consequences

- Manifest consumers are single-pass by construction.
- Manifests are content-addressed, so a repeated sync of an unchanged source can
  skip regenerating and resending one.
- One state DB per role, absolute path, WAL mode, checked at startup.
- Losing the state DB loses resumability, not data. It is documented as such in
  `OPERATIONS.md` §10.
