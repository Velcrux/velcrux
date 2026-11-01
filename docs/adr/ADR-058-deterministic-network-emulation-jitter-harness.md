# ADR-058: Deterministic Network Emulation & Jitter Harness for Chaos Sync Verification

- **Status**: Accepted
- **Date**: 2026-11-01
- **Deciders**: Velcrux Core Architecture & Transport Working Group
- **Consulted**: Distributed Systems Testing, Site Reliability Engineering, Performance Engineering

---

## 1. Context and Problem Statement

Velcrux is designed to provide high-throughput, low-latency bulk transfer and directory synchronization across heterogeneous and adverse wide-area networks (WANs), including satellite constellations (Starlink), multi-carrier rural 5G, inter-continental fiber, and congested data center interconnects.

Historically, testing transport behavior under hostile network dynamics (asymmetric bandwidth, bufferbloat queue spikes, correlated delay jitter, Gilbert-Elliott burst losses, packet reordering, and payload bit flips) suffered from critical operational drawbacks:
1. **Root Privilege Requirements**: Linux `tc-netem` and BSD `ipfw`/`pfctl` require root or `CAP_NET_ADMIN` privileges, making them impossible to run in unprivileged CI runners or restricted container environments.
2. **Platform Incompatibility**: OS-level traffic shaping tools are non-portable across Linux, macOS, and BSD developer workstations.
3. **Non-Deterministic Flakiness**: Standard packet drops in stochastic test suites introduce test non-determinism, preventing 100% reproducible regression debugging.
4. **Lack of In-Process Programmability**: Testing application-level responses (e.g. FastCDC delta sync recovery, BDP window auto-tuning, QUIC loss recovery) requires fine-grained packet-level interception directly within userspace.

---

## 2. Decision Drivers

- **Zero Root Privileges**: Pure userspace network emulation requiring no OS permissions, kernel modules, or eBPF privileges.
- **Strict Reproducibility**: 100% deterministic pseudo-random stream generation (SplitMix64) so that any chaos sequence can be reproduced identically given seed $S$.
- **Advanced Jitter & Delay Distributions**: Support for Uniform, Gaussian (Normal), and heavy-tailed Pareto distributions with autoregressive delay correlation ($d_i = \rho \cdot d_{i-1} + (1 - \rho) \cdot \delta_i$) to faithfully replicate bufferbloat queuing spikes.
- **Correlated Burst Loss (Gilbert-Elliott)**: 2-state Markov chain modeling packet loss bursts characteristic of wireless and satellite channels.
- **Natural Out-of-Order Packet Reordering**: Virtual release deadlines ($t_{\text{arrival}} + d_i$) scheduled in a min-heap priority queue, allowing faster packets to overtake delayed ones realistically.
- **Strict Safe Rust Invariant**: Pure safe Rust (`#![forbid(unsafe_code)]`) with zero external C/OS dependencies.

---

## 3. Considered Options

- **Option 1: Rely on OS-Level `tc-netem` via Subprocess Scripts**:
  - *Cons*: Fails in macOS development environments, fails in unprivileged CI Docker containers, prone to race conditions and test interference.
- **Option 2: External Proxy Process (e.g. Toxiproxy)**:
  - *Cons*: Additional process management overhead, non-deterministic scheduling, TCP/UDP socket buffering discrepancies.
- **Option 3 (Chosen): Pure Safe Rust Deterministic Userspace Network Emulation Engine (`NetemEngine`)**:
  - In-process packet scheduler with min-heap priority queue.
  - Reproducible 64-bit seedable PRNG (SplitMix64).
  - Gilbert-Elliott Markov burst loss and Box-Muller/Pareto delay distributions.
  - Pre-configured WAN presets (`StarlinkSatellite`, `TransatlanticWan`, `RuralCellular5G`, `BufferbloatAdverse`, `PristineLan`).
  - Staged atomic multi-process disk persistence (`VELCRUX_NETEM_DIR`).

---

## 4. Technical Architecture

```
                                  APPLIED CONFIGURATION
                        (CLI: velcrux netem apply / presets)
                                           │
                                 ┌─────────▼─────────┐
                                 │    NetemConfig    │
                                 └─────────┬─────────┘
                                           │
                           INBOUND PACKET (ID, PAYLOAD)
                                           │
                                 ┌─────────▼─────────┐
                                 │   NetemEngine     │
                                 └─────────┬─────────┘
                                           │
          ┌────────────────────────────────┼────────────────────────────────┐
          │                                │                                │
┌─────────▼─────────┐            ┌─────────▼─────────┐            ┌─────────▼─────────┐
│  Gilbert-Elliott  │            │ Delay & Jitter    │            │ Corruption / Dup  │
│  Markov Loss      │            │ Normal / Pareto   │            │ Bit-flips / Clone │
│  P(G->B), P(B->G) │            │ Autoregressive $\rho$│            │ Verification      │
└─────────┬─────────┘            └─────────┬─────────┘            └─────────┬─────────┘
          │ (Drop)                         │ (Delay $d_i$)                  │
          ▼                                ▼                                ▼
       [DROP]                    ┌───────────────────┐            ┌───────────────────┐
                                 │ Scheduled Release │            │  Duplicated/Bad   │
                                 │ $t = t_0 + d_i$   │            │  Payload Queue    │
                                 └─────────┬─────────┘            └─────────┬─────────┘
                                           │                                │
                                 ┌─────────▼─────────┐                      │
                                 │ Min-Heap Priority │◄─────────────────────┘
                                 │   Queue Scheduler │
                                 └─────────┬─────────┘
                                           │
                                           │ poll_ready(now)
                                           ▼
                                 OUTBOUND EMITTED STREAM
                            (Natural Reorder & Correlated Delay)
```

### 4.1. Mathematical Delay & Jitter Formulation
For base propagation delay $D_{\text{base}}$ and jitter $\sigma_j$:
- **Normal Distribution**: $\delta_i \sim \mathcal{N}(0, \sigma_j)$ computed via Box-Muller transform:
  $$\delta_i = \sigma_j \cdot \sqrt{-2 \ln U_1} \cos(2\pi U_2)$$
- **Pareto Heavy-Tailed Distribution**:
  $$\delta_i = \frac{\sigma_j}{(1 - U)^{1/\alpha}} - \sigma_j$$
- **Autoregressive Correlation**:
  $$d_i = D_{\text{base}} + \left[\rho \cdot (d_{i-1} - D_{\text{base}}) + (1 - \rho) \cdot \delta_i\right]$$

### 4.2. Gilbert-Elliott Burst Loss Model
State transitions between Good ($G$) and Bad ($B$):
- $P(G \to B) = p$ (burst initiation probability)
- $P(B \to G) = r$ (burst recovery probability; expected burst length $1/r$)
- Loss conditional probability: $P(\text{loss} \mid S) = \text{loss}_S$

---

## 5. Security & Safety Implications

- **Memory Safety**: `#![forbid(unsafe_code)]` strictly enforced.
- **No Privilege Escalation**: Runs entirely in userspace with non-root security boundaries.
- **Process Isolation**: Thread-safe configuration backed by atomic staging writes in `VELCRUX_NETEM_DIR`.

---

## 6. Operational Impact & Observability

- **Operator CLI Subcommands**: `velcrux netem [status|apply|clear|simulate|benchmark]`.
- **Prometheus Metrics**:
  - `velcrux_netem_packets_processed_total`
  - `velcrux_netem_packets_delivered_total`
  - `velcrux_netem_packets_dropped_total`
  - `velcrux_netem_packets_reordered_total`
  - `velcrux_netem_packets_duplicated_total`
  - `velcrux_netem_packets_corrupted_total`
  - `velcrux_netem_simulated_rtt_nanoseconds`
  - `velcrux_netem_scheduler_latency_nanoseconds`
