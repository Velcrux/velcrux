# ADR-024: Adaptive Multi-Stream Forward Error Correction (FEC)

Status: Accepted · Date: 2026-10-13

## Problem

High-latency and loss-impaired network environments—including LEO/GEO satellite uplinks (Starlink, OneWeb, Viasat), cellular/5G mmWave backhaul, cross-border WANs, and maritime links—suffer from chronic random packet erasure rates (1% to 15%) coupled with high round-trip times (100 ms to 650 ms):
1. **Catastrophic ARQ Retransmission Delays**: Standard transport-level retransmissions (Automatic Repeat reQuest / ARQ) require at least one full round-trip delay to detect loss, signal a NACK/ACK, and retransmit the missing packet. Under 600 ms GEO satellite latency, a single packet drop introduces a 1.2-second stall.
2. **Congestion Window Collapse**: Repeated packet retransmissions falsely trigger congestion control throttling (cubic/BBR backing off), collapsing network goodput even when the underlying link has abundant bandwidth capacity.
3. **Head-of-Line Blocking**: While QUIC streams avoid inter-stream head-of-line blocking, individual data streams carrying sequential bulk chunks stall awaiting retransmission of missing frame segments.
4. **Safety & Zero Unsafe Code Invariant**: Industrial erasure coding libraries (e.g. Jerasure, ISA-L, OpenFEC) rely on C/C++ native bindings, assembly intrinsics, and raw pointer arithmetic, violating Velcrux's strict `#![forbid(unsafe_code)]` guarantee across all crates.

## Options Considered

1. **Rely Exclusively on QUIC ARQ Retransmission**:
   - Transmit without application-layer forward error correction.
   - *Rejected*: In high-loss satellite benchmarks (§47, §88), goodput drops by over 85% at 5% packet loss due to retransmission round-trip delays and sender buffer bloat.
2. **External C/C++ Erasure Coding Libraries (Jerasure / ISA-L)**:
   - Bind to external C libraries via FFI.
   - *Rejected*: Introduces unsafe FFI wrappers, external C toolchain dependencies (CMake/NASM), memory safety risks, and cross-compilation headaches.
3. **Pure-Rust Systematic $(K+M, K)$ FEC over Galois Field $GF(2^8)$ with Cauchy Generator Matrix & Dynamic Loss Adaptation (Option BH)**:
   - Implement pure-Rust, `#![forbid(unsafe_code)]` Galois Field arithmetic over $GF(2^8)$ using primitive polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (`0x11d`) with lookup tables initialized via `std::sync::OnceLock`.
   - Construct Cauchy generator matrices $C_{i, j} = \frac{1}{x_i \oplus y_j}$ ensuring Maximum Distance Separable (MDS) properties: any arbitrary $K$ received symbols out of $K+M$ can reconstruct all source symbols.
   - Provide fast-path XOR parity for single-parity profiles ($M=1$) for near-zero CPU overhead.
   - Gaussian elimination linear system solving over $GF(2^8)$ for multi-parity profiles ($M \ge 1$).
   - Real-time `AdaptiveFecController` dynamically tuning $(K, M)$ redundancy (0% to 25%) based on measured RTT and packet loss telemetry.
   - High-level block framing (`FecBlockEncoder`, `FecBlockDecoder`), channel simulation test harness, and CLI commands (`velcrux fec status`, `velcrux fec test`, `--fec <profile>`).

## Decision

Option 3. Velcrux implements pure-Rust Adaptive Multi-Stream Forward Error Correction over $GF(2^8)$ under `#![forbid(unsafe_code)]`.

## Architecture & Implementation

### 1. Galois Field $GF(2^8)$ Arithmetic

All symbol calculations operate over finite field $GF(2^8)$ using irreducible primitive polynomial:
$$P(x) = x^8 + x^4 + x^3 + x^2 + 1 \quad (\mathtt{0x11d})$$

- Addition and subtraction reduce to bitwise XOR: $a \oplus b$.
- Multiplication and division are accelerated via dual logarithmic/exponential lookup tables:
  $$\mathtt{exp}[i] = \alpha^i \pmod{P(x)}, \quad \mathtt{log}[\alpha^i] = i$$
- Multiplicative inversion satisfies $a \cdot a^{-1} \equiv 1 \pmod{P(x)}$. Tables are generated lazily once into `std::sync::OnceLock`.

### 2. Systematic Cauchy Generator Matrix & MDS Guarantee

For systematic $(K+M, K)$ encoding, the first $K$ symbols are the source data symbols in plain form. The remaining $M$ symbols are computed via Cauchy generator matrix $C \in GF(2^8)^{M \times K}$:
$$C_{i, j} = \frac{1}{x_i \oplus y_j}, \quad x_i = i, \quad y_j = M + j$$

Because disjoint sets $X \cap Y = \emptyset$ are guaranteed, every square submatrix of the augmented systematic generator matrix $[I_K \mid C^T]^T$ is strictly non-singular. Any set of $K$ received symbols (source or repair) can invert the submatrix via Gaussian elimination and reconstruct all $K$ original symbols.

### 3. Fast-Path XOR Parity ($M=1$)

When $M=1$ (single parity symbol), the Cauchy coefficient is uniformly $1 / (0 \oplus (1 + j))$, and the parity symbol is computed as a pure XOR fold:
$$P_0 = S_0 \oplus S_1 \oplus \dots \oplus S_{K-1}$$
Missing symbol $S_e$ is recovered in $O(N)$ with a single pass:
$$S_e = P_0 \oplus \bigoplus_{i \neq e} S_i$$
This achieves wire-speed erasure recovery on high-throughput links without matrix inversion overhead.

### 4. Dynamic Loss Adaptation Tiers

The `AdaptiveFecController` continuously monitors link metrics (packet loss rate $\lambda$ and smoothed RTT) and scales $(K, M)$ redundancy:

| Packet Loss Rate ($\lambda$) | Active Coding $(K, M)$ | Redundancy Overhead | Codec Strategy | Target Topologies |
| :--- | :--- | :--- | :--- | :--- |
| $\lambda < 0.5\%$ | $(20, 0)$ | $0.0\%$ | Disabled | LAN / Pristine Fiber (Max Goodput) |
| $0.5\% \le \lambda < 2.0\%$ | $(20, 1)$ | $5.0\%$ | Fast-Path XOR Parity | Low-loss Trans-continental WAN |
| $2.0\% \le \lambda < 5.0\%$ | $(16, 2)$ | $12.5\%$ | Cauchy MDS Matrix | Cellular / 5G / Trans-oceanic WAN |
| $5.0\% \le \lambda < 10.0\%$ | $(10, 2)$ | $20.0\%$ | Cauchy MDS Matrix | Congested / Hostile Wireless |
| $\lambda \ge 10.0\%$ | $(8, 2)$ | $25.0\%$ | Cauchy MDS Matrix | LEO/GEO Satellite (Starlink, Viasat) |

### 5. Block Framing & Erasure Decoding

Chunks are partitioned into blocks (default: 64 KiB) and sliced into $K$ source symbols. If the final symbol is shorter than `symbol_size`, it is zero-padded during encoding and trimmed after reassembly.

```
+-------------------------------------------------------------+
| FecBlockHeader                                              |
| - block_id: u64                                             |
| - original_len: usize                                       |
| - k: usize, m: usize                                        |
| - symbol_size: usize                                        |
+-------------------------------------------------------------+
| Source Symbols: S_0, S_1, ..., S_{k-1}                      |
+-------------------------------------------------------------+
| Cauchy Repair Symbols: R_0, ..., R_{m-1}                    |
+-------------------------------------------------------------+
```

When receiving $\ge K$ symbols, `FecBlockDecoder` constructs the $K \times K$ submatrix, inverts it over $GF(2^8)$, reconstructs missing symbols, verifies whole-block integrity, and reassembles the original stream with zero ARQ retransmission stalls.

## CLI & Observability Interface

- `velcrux fec status [--profile <profile>] [--json]`: Displays active profile, $GF(2^8)$ Galois Field arithmetic parameters, Cauchy generator matrix configuration, and dynamic loss gating tiers.
- `velcrux fec test [--profile <profile>] [--loss-rate <rate>] [--payload-size <bytes>] [--seed <seed>] [--json]`: Simulates channel packet erasure against deterministic PRNG, measuring recovery success rate, dropped symbols, and goodput ratio.
- Global Flag: `--fec <profile>` (`disabled`, `low`, `medium`, `high`, `satellite`, `auto`).

## Verification & Status

1. Unit tests in `transport::fec`: $GF(2^8)$ axioms, matrix inversion, Cauchy coding, fast-path XOR parity, block framing, simulation harness (8/8 passing).
2. Client CLI tests in `cli_fec.rs`: Status inspection, JSON schema verification, simulation execution, and help flag parity (5/5 passing).
3. Server integration tests in `server_fec_resilience.rs`: Multi-block satellite loss simulation, 100% BLAKE3 hash match under 4% packet drop, and telemetry scaling (7/7 passing).
4. Strict safety: `#![forbid(unsafe_code)]` maintained across all crates.
