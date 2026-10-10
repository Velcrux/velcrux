# ADR-003: BLAKE3 for chunk, file, and manifest hashing

Status: Accepted · Date: 2026-09-02

## Problem

We hash every byte we transfer, at least once per side, sometimes twice. At
10 Gbps that is 1.25 GB/s of hashing per direction minimum. The hash must be
cryptographic — it decides chunk identity, drives deduplication, and is the final
integrity proof — so hashing speed is directly a throughput ceiling.

## Options

| Option | Approx single-core | Cryptographic | Notes |
|--------|-------------------|---------------|-------|
| SHA-256 (no HW) | ~0.4 GB/s | Yes | Ubiquitous, FIPS-approved |
| SHA-256 (SHA-NI) | ~2 GB/s | Yes | Requires hardware support |
| BLAKE3 | ~3 GB/s/core, parallelizes | Yes | SIMD, tree-structured |
| xxHash3 | ~30 GB/s | **No** | Filter only, never authoritative |

## Decision

BLAKE3-256 as the default for chunk identity, file identity, and manifest
integrity. SHA-256 available as a negotiated capability for interop and
compliance. Non-cryptographic hashes may be used only as pre-filters, never as an
integrity mechanism.

## Trade-offs

BLAKE3's tree structure is the deciding property, not just its raw speed. It
parallelizes within a single large input, so a 4 MiB chunk can be hashed across
cores, and it supports verified streaming — a receiver can verify a prefix before
the whole thing arrives. SHA-256 is strictly sequential per input, so scaling it
means hashing different chunks on different cores and nothing more.

SHA-256's advantages are real: it is FIPS-approved, universally available, and has
far more cryptanalytic history. Some deployments will require it. That is why it
is a negotiated capability rather than removed, and why the hash algorithm is
fixed per session by negotiation rather than carried per message.

BLAKE3 is younger. It is built on the well-studied BLAKE2/ChaCha permutation, and
our security does not rest on it alone — QUIC's AEAD independently protects data
in transit, and the whole-file verify is a second, independent check over the
final bytes. A BLAKE3 break would be serious but not silently catastrophic.

The rule about non-cryptographic hashes matters in practice: it is tempting to use
xxHash for chunk identity because it is 10× faster. It must not be, because chunk
identity is a security decision — an attacker who can produce a collision can make
the destination reuse the wrong bytes. Fast hashes are allowed only where a
wrong answer costs a redundant lookup.

## Consequences

- 32-byte hash on the wire; the algorithm is not encoded per message.
- The hashing worker pool is sized at startup (`cores - 2`) and is a benchmark axis.
- `blake3` is a mandatory capability; an intersection lacking it is a hard error.
