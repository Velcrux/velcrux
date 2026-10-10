# ADR-002: Rust as the implementation language

Status: Accepted · Date: 2026-09-02

## Problem

The server parses untrusted binary input from the network, at high throughput,
with heavy concurrency. That combination is precisely where memory-safety bugs
become remote code execution.

## Options

1. **C++.** Best raw control, mature tooling, and the language the team already
   works in daily. But a network-facing binary parser in C++ carries a class of
   risk that requires sustained discipline plus sanitizers plus fuzzing to
   contain, and the failure mode is severe.
2. **Go.** Memory-safe, excellent concurrency, `quic-go` is mature. GC pauses are
   a real consideration at 10 Gbps, and controlling allocation on the hot path is
   harder.
3. **Rust.** Memory-safe without a GC, `quinn` and `rustls` are mature, BLAKE3's
   reference implementation is Rust, and the type system can encode invariants —
   most usefully here, `VPath` being unconstructable without validation.

## Decision

Rust, stable toolchain, cargo workspace. `#![forbid(unsafe_code)]` everywhere.

## Trade-offs

C++ is the team's stronger language and that is a genuine cost — velocity will be
lower initially. It is outweighed by the specific shape of this system: an
internet-facing daemon whose job is to parse attacker-controlled binary messages
and then write to a filesystem. In that role, "the compiler prevents the bug
class" is worth more than "the team writes C++ faster".

The type-system point deserves emphasis because it is not just about memory. The
path-traversal defence in `SECURITY.md` §4 works because `StorageBackend` accepts
only `VPath`, and `VPath` has no public constructor. In C++ that would be a
convention enforced by review; in Rust it is enforced by the compiler. Same for
bounded channels, `Secret<T>` redaction, and the no-wildcard state machine.

Rust's async ecosystem is more complex than Go's goroutines, and async trait
ergonomics are still awkward. Accepted.

## Consequences

- Any `unsafe` needs an isolated crate, documented invariants, dedicated tests, a
  fuzz target, and a benchmark in the PR that justifies it. Four gates, all
  required.
- Zero-copy work is constrained by the borrow checker. Where that bites, the
  answer is buffer pooling and vectored I/O, not `unsafe`.
- If Rust proves untenable for reasons we cannot foresee, this ADR is the place
  the reasoning is recorded for revisiting.
