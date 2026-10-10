# ADR-008: Protocol versioning and capability negotiation

Status: Accepted · Date: 2026-09-02

## Problem

The protocol will change. Chunking algorithms, hash algorithms, compression, and
metadata fidelity will all evolve, and clients and servers will be upgraded
independently. Without a plan from day one, the first incompatible change means a
flag day.

## Options

1. **Version number only.** Simple, but forces lockstep upgrades: a client that
   understands v2 cannot talk to a v1 server at all, even if it only wanted one v2
   feature the server happens to support.
2. **Capability bitset only.** Flexible feature discovery, but no way to make a
   breaking change to existing framing.
3. **Both.** Version governs wire framing and message semantics; capabilities
   govern optional features within a version.

## Decision

Option 3. `HELLO` carries a supported-version list and a capability bitset;
`HELLO_ACK` returns the chosen version and the capability intersection. No feature
is used unless it appears in the intersection. `blake3` and `fixed_chunking` are
mandatory capabilities.

## Trade-offs

Two mechanisms is more machinery than one, and the intersection logic must be
tested against deliberately capability-reduced peers or it will rot into "assume
the peer supports everything". The integration suite includes a server with a
reduced capability set specifically to exercise the degradation paths.

The payoff is that the common case — a newer client meeting an older server —
degrades gracefully instead of failing. A client with CDC, zstd, and Bloom hints
talking to a server with none of them falls back to fixed chunking, no
compression, and no hint, and the transfer succeeds. That is the difference between
"upgrade the fleet in any order" and "coordinate a flag day".

Making `blake3` and `fixed_chunking` mandatory is a deliberate floor. Without a
floor, negotiation can succeed into a state where no mutually supported chunking
or hashing exists, and the failure surfaces later and less clearly than at
handshake.

`HELLO_ACK` also carries the server's resource limits. This is a small addition
with a disproportionate benefit: clients adapt to limits rather than discovering
them by being disconnected mid-transfer, which is both better behaviour and far
better diagnostics.

## Consequences

- Additive-only within a major version: new message types, new capability bits,
  new trailing optional fields. Changing an existing field's meaning, size, or
  position requires a version bump.
- Unknown message types on the control stream get `UNSUPPORTED_MESSAGE` and the
  connection continues. On a data stream they are fatal.
- Version 1 is not frozen until the MVP definition of done is met.
- Every new optional feature needs a capability bit and a tested degradation path.
