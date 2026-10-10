# ADR-006: Optional content-addressed chunk store

Status: Accepted · Date: 2026-09-02

## Problem

Deduplication can eliminate transfers entirely when content repeats across files —
VM images, container layers, repeated snapshots. It also costs an index, a lookup
per chunk, random reads on reconstruction, and garbage collection. It is not
universally beneficial.

## Options

1. No chunk store. Delta against the destination file at the same path only.
   Simple, no GC, no index, but no cross-file reuse at all.
2. Always-on content-addressed store. Maximum reuse, but every deployment pays the
   index and GC cost whether or not its data repeats.
3. Optional store behind a `ChunkStore` trait, off by default.

## Decision

Option 3. Filesystem-backed store at `chunks/ab/cd/abcdef...` with two-level hex
fanout, off unless `storage.chunk_store` is configured.

## Trade-offs

For a stream of unique large media files the store is pure overhead: 42 MB of
index per TB, a lookup per chunk on the write path, and random reads that are
slower than the sequential reads it replaces. For a fleet of similar VM images it
can eliminate most of the transfer. The ratio decides, and only the operator knows
their data — so the server reports `velcrux_dedup_ratio` as a metric and the decision
is made from observation rather than assumption. The rough threshold is 1.2×.

Three correctness points that are easy to get wrong:

**Hashes are verified on both put and get.** The store never trusts its own
filenames. A chunk read back from the store is hashed before use, so bit rot or
tampering in the store surfaces as an error rather than as silently wrong output.

**Authorization must not be bypassable through the store.** If tenant A uploads a
chunk and tenant B happens to reference the same hash, B learns that a chunk with
that content exists — and if the store served it, B would be reading A's data
without authorization. B must already possess the content to name its hash, so the
practical leak is small, but "small" is not "none". This is unresolved and flagged
in `CLAUDE.md` §4; the per-tenant-namespace option costs dedup ratio and the
shared option costs a confirmed-content oracle. It needs a second reviewer before
multi-tenant dedup ships.

**GC requires real reference tracking and stays manual.** The `chunk_ref` table
tracks references; `velcruxd gc --chunks` reports before it deletes and never
removes a referenced chunk. Automatic background deletion in a content-addressed
store is how data-loss incidents happen, so there is no automatic mode.

## Consequences

- `ChunkStore` is a trait, so an object-store backend is possible later without
  touching the transfer engine.
- Dedup is a negotiated capability; a server without a store advertises it off.
- Multi-tenant dedup is blocked on the namespace decision above.
