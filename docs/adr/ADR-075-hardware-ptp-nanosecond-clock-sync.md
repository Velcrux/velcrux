# ADR-075: Hardware PTP (IEEE 1588v2) Nanosecond High-Precision Clock Synchronization & Bounded Transfer Ordering Mesh

- **Status**: Accepted
- **Date**: 2026-11-09
- **Deciders**: Velcrux Distributed Systems, Network Architecture, Precision Timing, and Storage Engineering Teams
- **Consulted**: Cloud-Native Infrastructure, Multi-Region Operations, and Site Reliability Engineering Teams

---

## 1. Context and Problem Statement

High-throughput distributed object transfers, transactional snapshots, and multi-region replication fabrics in Velcrux face fundamental concurrency and ordering limits dictated by time synchronization:
1. **Millisecond Skew in Standard NTP**: Conventional Network Time Protocol (NTP) daemons introduce clock skews ranging from 1 ms to 50 ms across WAN environments and virtualized nodes. Synchronizing globally ordered transfer commit logs across regions with millisecond uncertainty requires pessimistic two-phase locking (2PC) or multi-round Paxos consensus, inflating cross-region transfer commit latencies to hundreds of milliseconds.
2. **Causal Ordering Without Multi-Round Consensus**: High-performance distributed data engines (analogous to Google Spanner's TrueTime) require bounded uncertainty intervals $[t - \epsilon, t + \epsilon]$ where $\epsilon$ is kept in the sub-microsecond or nanosecond realm. If $t_B^{earliest} > t_A^{latest}$, causal ordering ($A \prec B$) is proven monotonically without issuing cross-datacenter locking queries.
3. **Transparent Switch & Router Queueing Jitter**: Under heavy bulk transfer load, packet residency in intermediate network switches causes asymmetric network jitter. Achieving sub-microsecond synchronization requires IEEE 1588v2 sub-nanosecond hardware correction field accumulation ($c / 2^{16}$) to deduct in-flight transit delays.
4. **Dynamic Master Election**: Datacenter clock topologies require autonomous grandmaster election and failover (e.g. atomic clock / GNSS receiver disconnection) via standard Best Master Clock Algorithm (BMCA) conforming to IEEE 1588-2008 §9.3.

To resolve these challenges, Velcrux requires a **Hardware PTP (IEEE 1588v2) Nanosecond High-Precision Clock Synchronization & Bounded Transfer Ordering Mesh** implemented in 100% pure safe Rust.

---

## 2. Decision Drivers

- **IEEE 1588v2 Precision Time Protocol Engine**:
  - Full wire framing of the standard 34-byte PTP common header (`PtpCommonHeader`).
  - Strict nanosecond timestamps (`PtpTimestamp`): 48-bit seconds (6 bytes) + 32-bit nanoseconds (4 bytes).
  - Scaled sub-nanosecond correction fields (`CorrectionField`): 64-bit signed integer representing nanoseconds multiplied by $2^{16}$ (allowing $1/65536\text{ ns} \approx 15.25\text{ fs}$ resolution for transparent clock transit time accumulation).
  - Strongly typed PTP messages: `Sync`, `DelayReq`, `FollowUp`, `DelayResp`, and `Announce`.
- **Best Master Clock Algorithm (BMCA)**:
  - Strict compliance with IEEE 1588-2008 §9.3 dataset comparison.
  - Multi-tier lexical comparison: `priority1` $\to$ `clockClass` (6 = primary GNSS atomic reference, 135 = telecom boundary, 248 = default slave) $\to$ `clockAccuracy` $\to$ `offsetScaledLogVariance` $\to$ `priority2` $\to$ `clockIdentity` (EUI-64 from MAC) $\to$ `stepsRemoved`.
  - Dynamic port state machine: `Initializing`, `Faulty`, `Disabled`, `Listening`, `PreMaster`, `Master`, `Passive`, `Slave`.
  - Autonomous grandmaster failover upon foreign master announcement timeout.
- **Closed-Loop Proportional-Integral (PI) Clock Servo**:
  - Four-timestamp symmetric round-trip delay calculation:
    $$\mu = \frac{(t_2 - t_1) + (t_4 - t_3) - c}{2}$$
  - Clock offset computation:
    $$\theta = (t_2 - t_1) - \mu - c_{sync}$$
  - Closed-loop PI frequency and phase steering ($k_p = 0.7$, $k_i = 0.3$) computing frequency drift in parts-per-billion (ppb).
  - Dynamic lock detection: transitions to `LockedPhase` when $|\theta| \le 50\text{ ns}$ over consecutive cycles, with root-mean-square (RMS) jitter tracking.
- **Bounded-Skew Transfer Ordering Mesh (TrueTime Semantics)**:
  - Timestamp representation as bounded uncertainty intervals: $[t - \epsilon, t + \epsilon]$.
  - Uncertainty bound computation: $\epsilon = |\theta| + \mu_{jitter} + \text{drift} \cdot \Delta t$.
  - Causal order verification: if $t_B - \epsilon_B > t_A + \epsilon_A$, transfer $A$ is guaranteed to have committed strictly before transfer $B$ ($A \prec B$).
  - TrueTime commit-wait coordination: enforcing a $2\epsilon$ wait window at the commit node before broadcasting release guarantees external consistency across geo-distributed nodes without cross-region roundtrips.
- **Zero Unsafe Code**: 100% `#![forbid(unsafe_code)]` compliance with zero external C dependencies.

---

## 3. Technical Architecture

```
                                 [ GNSS / Atomic Grandmaster ]
                                       ClockClass = 6
                                              │
                      Sync (t1)               │             Announce (BMCA)
              ┌───────────────────────────────┼──────────────────────────────┐
              │                               │                              │
              ▼                               ▼                              ▼
    ┌───────────────────┐           ┌───────────────────┐          ┌───────────────────┐
    │  Boundary Clock   │           │  Boundary Clock   │          │ Transparent Clock │
    │    (us-east-1)    │           │    (eu-west-1)    │          │  (Transit Resid)  │
    └─────────┬─────────┘           └─────────┬─────────┘          └─────────┬─────────┘
              │                               │                              │
              │ PTP 4-Timestamp Exchange      │ PTP 4-Timestamp Exchange     │ Correction Field:
              │ (t1, t2, t3, t4)              │ (t1, t2, t3, t4)             │ c = c + t_residence
              ▼                               ▼                              ▼
    ┌──────────────────────────────────────────────────────────────────────────────────┐
    │                       Velcrux PTP Clock Servo Engine                             │
    │  - Mean Path Delay: μ = [ (t2 - t1) + (t4 - t3) - c ] / 2                        │
    │  - Clock Offset:    θ = (t2 - t1) - μ - c_sync                                   │
    │  - PI Filter:       Drift_ppb = kp * θ + ki * ∫ θ dt                             │
    │  - Servo Status:    LOCKED_PHASE (|θ| <= 50 ns, Jitter RMS <= 15 ns)             │
    └─────────────────────────────────────────┬────────────────────────────────────────┘
                                              │
                                              ▼
    ┌──────────────────────────────────────────────────────────────────────────────────┐
    │                 Bounded-Skew Causal Transfer Ordering Mesh                       │
    │  - Bounded Interval: [ t - ε,  t + ε ] where ε = |θ| + jitter_rms               │
    │  - TrueTime Commit Rule: Wait 2ε before release to guarantee causal monotonicity │
    │  - Multi-Region Causal Ordering: t_B.earliest > t_A.latest => A precedes B       │
    └──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Wire Protocol Framing & Data Structures

### 4.1 IEEE 1588v2 Common Header (34 Bytes)

| Field | Size (Bytes) | Description |
|:---|:---:|:---|
| `major_sdo_id_message_type` | 1 | High 4 bits: SDO ID; Low 4 bits: `PtpMessageType` (Sync=0x0, DelayReq=0x1, FollowUp=0x8, DelayResp=0x9, Announce=0xB) |
| `version_ptp` | 1 | PTP Protocol version (0x02 for IEEE 1588-2008) |
| `message_length` | 2 | Total message length in octets (big-endian) |
| `domain_number` | 1 | PTP domain number (0-255) |
| `minor_sdo_id` | 1 | Reserved / Minor SDO ID |
| `flags` | 2 | PTP status flags (TwoStep, Unicast, etc.) |
| `correction_field` | 8 | Scaled sub-nanosecond residence / path correction ($ns \times 2^{16}$) |
| `message_type_specific`| 4 | Reserved / message specific |
| `source_port_identity` | 10 | 8-byte ClockIdentity (EUI-64) + 2-byte port number |
| `sequence_id` | 2 | Monotonic sequence number |
| `control_field` | 1 | IEEE 1588-2002 compatibility control field |
| `log_message_interval` | 1 | Log2 message rate interval |

### 4.2 Best Master Clock Algorithm Comparison Hierarchy

When comparing foreign datasets $D_A$ and $D_B$, dataset $A$ is superior if:
1. $D_A.priority1 < D_B.priority1$
2. $D_A.clockClass < D_B.clockClass$
3. $D_A.clockAccuracy < D_B.clockAccuracy$
4. $D_A.offsetScaledLogVariance < D_B.offsetScaledLogVariance$
5. $D_A.priority2 < D_B.priority2$
6. $D_A.clockIdentity < D_B.clockIdentity$
7. $D_A.stepsRemoved < D_B.stepsRemoved$

---

## 5. Consequences

### 5.1 Positive Consequences
- **TrueTime-Grade Monotonicity Without 2PC**: Achieves bounded-skew ordering across geo-distributed nodes with guaranteed external consistency ($A \prec B$).
- **Sub-50ns Phase Lock**: Proportional-Integral servo filter achieves $\le 50\text{ ns}$ offset under synthetic network conditions and tracks frequency drift in parts-per-billion.
- **Autonomous Grandmaster Failover**: Implements standard BMCA dataset comparison, automatically promoting candidate boundary clocks on grandmaster dropouts.
- **Hardware-Transparent Precision**: Sub-nanosecond correction field accumulation accounts for switch transit residency down to $15.25\text{ fs}$ resolution.
- **100% Memory Safety**: Pure safe Rust (`#![forbid(unsafe_code)]`) with zero external native C dependencies.

### 5.2 Negative Consequences / Tradeoffs
- **Commit Wait Incurred**: To maintain serializability without WAN locks, write transactions must wait $2\epsilon$ ($200\text{ ns} - 100\text{ µs}$) before publicly committing. Under hardware PTP this wait is negligible compared to WAN round-trips.
- **Asymmetric Route Skew**: Asymmetric physical routing between master and slave can bias one-way delay calculations unless compensated via calibrated correction fields.

---

## 6. Implementation References

- Core Module: `crates/velcrux-core/src/ptp/`
  - `types.rs`: Clock identity, timestamps, correction fields, port states.
  - `message.rs`: 34-byte IEEE 1588v2 header and payload framing.
  - `bmca.rs`: Best Master Clock Algorithm engine and dataset comparison.
  - `servo.rs`: Closed-loop PI clock servo filter and delay calculations.
  - `ordering.rs`: Bounded uncertainty intervals and TrueTime commit coordinator.
- Core Integration Tests: `crates/velcrux-core/tests/ptp_clock_sync_tests.rs`
- Operator CLI Suite: `crates/velcrux-client/src/main.rs` (`velcrux ptp status|peers|sync|ordering`)
- CLI Integration Tests: `crates/velcrux-client/tests/cli_ptp.rs`
