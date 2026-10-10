# ADR-007: One QUIC stream per file

Status: Accepted (revisit after Milestone 10) · Date: 2026-09-02

## Problem

Requirement §86 asks this explicitly: should file data use one QUIC stream per
file, or multiple streams per file? The answer affects the scheduler, receive-side
disk access patterns, memory in flight, and single-large-file throughput.

## Options

1. **One stream per file**, N files concurrently.
2. **N streams per file**, splitting a single file across streams.
3. **Multiple QUIC connections** for independent congestion controllers.

## Decision

Option 1 for the MVP. Connection and stream receive windows set to 2× BDP
(384 MB at the primary 10 Gbps / 150 ms target). Option 2 is a benchmark-gated
follow-up; option 3 is rejected.

## Trade-offs

The head-of-line argument that motivates aggressive multi-streaming comes from
HTTP/1-over-TCP, where one connection's loss stalls everything. QUIC already
recovers loss per stream, so one-stream-per-file gives per-file isolation without
further splitting.

Transmitting in offset order within a file keeps destination writes sequential.
Splitting a file across N streams makes those writes arrive out of order, which
costs disk seeks, complicates the resume bitmap, and increases in-flight memory.
On network-backed or spinning storage that cost is likely larger than the
parallelism gain.

Most importantly, the single-huge-file case is a flow-control problem before it is
a parallelism problem. At 10 Gbps and 150 ms RTT we need 187.5 MB in flight; if
the window is smaller than that, throughput is capped at `window / RTT` and adding
streams within one connection does not raise the connection-level cap. Sizing the
window correctly is the fix. Adding streams to work around a small window is
treating a symptom.

Option 3 is rejected on principle as well as design. Opening N connections to
obtain N congestion-control shares is antisocial — it is the behaviour §29 asks us
to avoid, it makes per-user accounting and authorization messier, and it hides a
tuning bug behind unfairness. If we ever need it, that is evidence something else
is wrong.

This decision is deliberately falsifiable. The `streams` axis of the benchmark
matrix (1/2/4/8/16/32) will show where per-file multi-streaming actually helps. If
the 10 Gbps / 150 ms / 0.5% case shows a material gain over a correctly sized
window, this ADR gets superseded — the scheduler's stream-assignment logic is
abstracted specifically so that is a contained change rather than a rewrite.

## Consequences

- `transfer.parallelism` controls concurrent files, not streams per file.
- Receive windows become a first-class operational tuning parameter, documented in
  `OPERATIONS.md` §4 and §5.
- A data stream reset is recoverable: re-open and resume from the chunk bitmap.
- Revisit after Milestone 10 with data.
