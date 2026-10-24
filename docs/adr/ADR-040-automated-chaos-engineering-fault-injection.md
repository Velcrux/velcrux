# ADR-040: Automated Continuous Chaos Engineering & Network Fault Injection Suite

Status: Accepted · Date: 2026-10-24

## Context

High-throughput bulk data synchronization over wide-area networks (`ARCHITECTURE.md` §2, §7; `REQUIREMENTS.md` §45, §78, §79) encounters volatile and hostile real-world physical transmission impairments:

1. **Burst Packet Loss & Congestion Collapse**:
   - Traditional testing models packet loss as independent Bernoulli coin flips. In real-world networks (congested routers, cellular fading, satellite orbital handoffs), packet loss occurs in dense bursts, challenging QUIC loss recovery and BDP auto-tuning algorithms.
2. **Latency Jitter & Packet Reordering**:
   - Multi-path ECMP routing and cellular radio link retransmissions deliver frames out-of-order with unpredictable delay variance, inducing false loss detections and bufferbloat.
3. **Byzantine Bit-Rot & Memory Corruption**:
   - Cosmic rays, faulty network interface cards, and defective middleboxes silently flip payload bits. The transfer engine must rigorously prove that cryptographic BLAKE3 verification detects and rejects mutated data without panicking, hanging, or corrupting state.
4. **Network Partitions & Asymmetric Blackholing**:
   - Cloud availability zone isolations, cable cuts, and routing flapping blackhole traffic abruptly.
5. **Portability & Safety Invariants**:
   - Traditional testing tools (`tc netem`, Linux network namespaces) require root privileges and fail on macOS, BSD, and unprivileged CI runners.
   - The entire implementation must adhere to `#![forbid(unsafe_code)]` with zero exceptions across all crates (`CLAUDE.md` §1).
   - Strict bounded memory streaming: fault injection must never buffer unbounded packets or whole files in memory.

## Options Considered

1. **Option 1: OS-Level `tc netem` & Linux Network Namespaces**:
   - Configure Linux kernel `tc netem` rules in integration test scripts.
   - *Rejected*: Incompatible with macOS local development; requires root (`sudo`) capabilities; impossible in unprivileged containerized CI pipelines.
2. **Option 2: Simple Bernoulli Uniform Loss Simulator**:
   - Apply single-parameter independent random drops.
   - *Rejected*: Cannot replicate real-world burst loss clusters (e.g. 5 consecutive dropped packets followed by 100 clean packets), failing to stress-test congestion window collapse.
3. **Option 3: In-Process Deterministic Gilbert-Elliott Markov Burst Loss, Byzantine Rot & Partition Chaos Engine (`ADR-040`)**:
   - **Gilbert-Elliott Markov Burst Model**: 2-state discrete-time Markov chain modeling Good ($G$) and Bad ($B$) link states with transition probabilities $p = P(G \to B)$ and $r = P(B \to G)$, producing realistic burst loss clusters with average length $1/r$.
   - **Deterministic Seedable PRNG**: Fast 64-bit Xorshift64* pseudo-random number generator ensuring that chaos tests and benchmarks are 100% reproducible across platforms.
   - **Byzantine Bit-Rot Mutation**: Injects bit flips and byte scrambles to validate that streaming BLAKE3 tree hashes and chunk stores reject corrupted payloads deterministically.
   - **Asymmetric Partition Emulation**: Instantaneous blackhole switching simulating cable cuts and split-brain outages.
   - **Preconfigured WAN Profiles**: Realistic profiles for Subsea Fiber, LEO Satellite (Starlink), Hostile Cellular (4G/5G), Byzantine Adversary, and Flapping Partition.

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. Gilbert-Elliott 2-State Markov Chain (`crates/velcrux-core/src/chaos/mod.rs`)

```rust
pub struct GilbertElliottConfig {
    pub p: f64,          // Probability of transitioning Good -> Bad
    pub r: f64,          // Probability of transitioning Bad -> Good
    pub loss_in_good: f64, // Loss probability in Good state (e.g. 0.001)
    pub loss_in_bad: f64,  // Loss probability in Bad state (e.g. 0.95)
}

pub struct GilbertElliottModel {
    config: GilbertElliottConfig,
    state: MarkovState,
}
```

Average burst loss duration is mathematically governed by $L_B = \frac{1}{r}$ packets.

### 2. Built-in Impairment Profiles

| Profile Name | One-Way Delay | Latency Jitter | Packet Loss Model | Reorder Rate | Byzantine Rot | Blackhole |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`clean`** | 0 ms | 0 ms | 0.0% | 0.0% | 0.0% | No |
| **`subsea`** | 60 ms | ±10 ms | 1.5% Bernoulli | 0.2% | 0.0% | No |
| **`satellite`** | 25 ms | ±20 ms | 3.5% Bernoulli | 1.0% | 0.0% | No |
| **`cellular`** | 80 ms | ±50 ms | 8.0% Gilbert-Elliott Burst | 2.0% | 0.0% | No |
| **`byzantine`** | 5 ms | ±2 ms | 0.0% | 0.0% | 0.5% bit flips | No |
| **`partition`** | 0 ms | 0 ms | 100.0% | 0.0% | 0.0% | Yes (Blackhole) |

### 3. Fault Evaluation Pipeline (`ChaosEngine::process_packet`)

```text
[Inbound Packet]
      │
      ▼
Blackhole Partition Active? ──► YES ──► Drop (Partition Counter++)
      │ NO
      ▼
Gilbert-Elliott Burst or Uniform Loss? ──► YES ──► Drop (Loss Counter++)
      │ NO
      ▼
Add Jitter Delay (± Variance) (Delay Counter++)
      │
      ▼
Byzantine Bit Mutation Triggered? ──► YES ──► Flip Random Bits (Corrupt Counter++)
      │ NO
      ▼
Duplicate Packet? ──► YES ──► Duplicate { copies } (Duplicate Counter++)
      │ NO
      ▼
Reorder Packet? ──► YES ──► Reorder { delay + extra } (Reorder Counter++)
      │ NO
      ▼
Pass { delay_ms, payload }
```

### 4. Telemetry & Prometheus Observability

Exposed in standard Prometheus `/metrics` format (`crates/velcrux-server/src/metrics.rs`):
- `velcrux_chaos_packets_dropped_total`: Cumulative packets dropped by uniform or burst loss.
- `velcrux_chaos_packets_delayed_total`: Cumulative packets delayed via latency and jitter injection.
- `velcrux_chaos_packets_reordered_total`: Packets reordered via out-of-order queueing.
- `velcrux_chaos_packets_duplicated_total`: Duplicate packets emitted into transmission streams.
- `velcrux_chaos_bytes_corrupted_total`: Total payload bytes mutated by Byzantine bit-rot fault injection.
- `velcrux_chaos_partitions_active`: Gauge of active simulated network partitions.

### 5. CLI Management Surface (`velcrux chaos`)

- `velcrux chaos status [--json]`: Inspect active chaos engine status, loss percentage, and fault counters.
- `velcrux chaos profile [name] [--json]`: View parameters for all or specific built-in impairment profiles.
- `velcrux chaos benchmark [--profile <name>] [--packets <count>] [--json]`: Run deterministic fault simulation tests.
- `velcrux chaos inject [--loss L] [--delay-ms D] [--jitter-ms J] [--reorder R] [--duplicate U] [--corrupt C] [--partition] [--json]`: On-demand fault injection.

## Consequences

### Positive
- **100% Hermetic & Cross-Platform**: Operates in userspace safe Rust on macOS, Linux, and Windows without root privileges or `tc netem`.
- **Realistic Burst Modeling**: Gilbert-Elliott Markov chains replicate genuine physical WAN loss behavior.
- **Byzantine Stress Verification**: Proves BLAKE3 cryptographic integrity defenses reject corrupt data in CI before reaching production.
- **Zero-Unsafe Invariant**: Strict compliance with `#![forbid(unsafe_code)]`.

### Negative
- High jitter/delay simulation in real data paths introduces latency by design during active chaos testing runs.
