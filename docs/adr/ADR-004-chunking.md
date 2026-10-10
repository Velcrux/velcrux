# ADR-004: Content-defined chunking by default

Status: Accepted · Date: 2026-09-02

## Problem

Delta efficiency depends entirely on how the file is divided. Fixed-size chunking
is cheap but has a specific catastrophic failure mode; content-defined chunking
costs CPU to avoid it.

## Options

1. **Fixed-size.** Trivially cheap, perfectly predictable offsets, ideal for
   resume bookkeeping. An insertion or deletion anywhere shifts every subsequent
   boundary, dropping reuse to roughly zero.
2. **Content-defined (rolling hash).** Boundaries follow content, so an edit
   perturbs only the chunks near it. Costs a rolling-hash pass over every byte and
   produces variable-length chunks.
3. **Both, chosen per workload.**

## Decision

Option 3, with CDC as the default. CDC uses a gear rolling hash over a 64-byte
window with a mask tuned to the target size and hard min/max clamps. Defaults:
min 256 KiB, target 1 MiB, max 4 MiB. All configurable, all negotiated per
transfer and recorded in the manifest.

## Trade-offs

The insertion case is the whole argument. Insert one byte at offset 0 of a 10 GB
file: fixed chunking reuses ~0% and transfers 10 GB; CDC reuses ~99% and transfers
a few MB. That is not a marginal improvement, it is the difference between delta
sync working and not working, and it is a completely ordinary thing for a file to
have happen to it.

The cost is a rolling hash over every byte on both sides, roughly 20–30% on top of
BLAKE3, plus variable chunk lengths that make offset bookkeeping slightly more
complex. For workloads that genuinely never insert — VM images written whole,
database snapshots, append-only logs — that cost buys nothing, which is why fixed
chunking stays available rather than being removed.

Chunk size selection is a four-way tension between manifest size, hashing cost,
resume granularity, and delta efficiency, worked through in `PERFORMANCE.md` §5.
The smallest chunk is not the best: 256 KiB chunks on a 1 TB file produce a 168 MB
manifest, which can exceed the payload of a small delta. 1 MiB target is the
balance point — 42 MB of manifest per TB while keeping single-edit blast radius
small.

The hard max of 4 MiB is a security requirement, not just tuning: without it,
adversarial content could steer the rolling hash to produce arbitrarily large
chunks and defeat the per-chunk memory bound in `SECURITY.md` §6.

## Consequences

- Chunker parameters are in the manifest and negotiated. A parameter mismatch
  between sides would silently destroy all reuse, so it must be impossible rather
  than merely discouraged.
- Automatic fixed-vs-CDC selection by the estimator is post-MVP.
- The property test "concatenated chunks reproduce the input exactly" and "prefix
  insertion does not perturb distant boundaries" are the two tests that keep this
  honest.
