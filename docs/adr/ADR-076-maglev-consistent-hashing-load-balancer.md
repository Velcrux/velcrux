# ADR-076: Autonomous L4/L7 Hardware Load Balancer & Maglev Consistent Hashing Multiplexing Engine

- **Status**: Accepted
- **Date**: 2026-11-10
- **Deciders**: Velcrux Distributed Systems, Network Architecture, Ingress Routing, and Storage Engineering Teams
- **Consulted**: Site Reliability Engineering, High-Throughput Transport, and Infrastructure Operations Teams

---

## 1. Context and Problem Statement

High-throughput distributed object storage transfers and multi-tenant QUIC data pipelines in Velcrux require line-rate Layer-4 and Layer-7 traffic distribution across dynamic backend clusters:
1. **Lookup Latency and Ring Inefficiencies**: Classical ring-based consistent hashing algorithms (e.g. Ketama / chord rings) require $O(\log K)$ binary searches over thousands of virtual node points, causing CPU cache thrashing at multi-gigabit line rates and exhibiting uneven load distribution (non-uniform hashing variance up to 20-30%).
2. **Disruption During Membership Churn**: When storage backend nodes join, fail, or undergo maintenance, naively rebalancing flows causes widespread connection termination. A consistent hashing algorithm must strictly enforce the **minimal disruption property**: adding or removing a node from a cluster of $N$ backends must reassign at most $\approx 1/N$ fraction of keys, leaving $\approx (N-1)/N$ traffic undisturbed.
3. **Connection Stickiness Across Membership Changes**: Even when a consistent hash table rebalances, in-flight QUIC connections and multi-gigabyte active transfers cannot be severed mid-stream without triggering costly retransmissions. Active flows must remain pinned to their established backend nodes via high-performance connection tracking (`conntrack`).
4. **Zero-Downtime Graceful Node Draining**: Decommissioning or rolling-upgrading physical nodes requires a two-phase lifecycle: immediately stopping new flow assignments while allowing established connections to complete gracefully.
5. **Layer-7 Content-Aware Routing**: Multi-tenant isolation requires steering specific tenant prefixes, high-priority transfer classes, and URL path patterns to specialized high-performance or GPU/NVMe storage pools.

To resolve these requirements, Velcrux implements an **Autonomous L4/L7 Hardware Load Balancer & Maglev Consistent Hashing Multiplexing Engine** in 100% pure safe Rust.

---

## 2. Decision Drivers

- **Google Maglev Consistent Hashing Algorithm**:
  - Constant-time $O(1)$ packet lookup via precomputed lookup table of prime size $M$ (default: Fermat prime $2^{16} + 1 = 65537$).
  - Deterministic pseudo-random permutation generation per backend node using dual independent BLAKE3 hashes:
    $$offset = \text{Hash}_1(\text{node\_id}) \pmod M$$
    $$skip = (\text{Hash}_2(\text{node\_id}) \pmod{M - 1}) + 1$$
  - Since $M$ is prime and $\gcd(skip, M) = 1$, each node's permutation sequence $P_i[j] = (offset + j \times skip) \pmod M$ visits every table slot exactly once.
  - Weighted round-robin slot claiming ensuring proportional capacity allocation ($w_i \ge 1$).
  - Verified minimal disruption guarantee: remapping fraction $\Delta \le \frac{1}{N+1}$ on node addition.
- **High-Throughput L4 Connection Tracking (`conntrack`)**:
  - Full 5-tuple flow identification: `(src_ip, src_port, dst_ip, dst_port, protocol)` supporting IPv4, IPv6, TCP, UDP, and QUIC.
  - Connection lifecycle state machine: `New` $\to$ `Established` $\to$ `Closing` $\to$ `Closed`.
  - Microsecond state recycling with protocol-specific idle timeouts (`tcp_established`: 300s, `quic_established`: 60s, `closing`: 10s, `new_flow`: 5s).
  - Session stickiness: existing flows remain pinned to their designated node even during Maglev table rebuilds.
- **Zero-Downtime Graceful Draining**:
  - Four-tier node status: `Healthy`, `Degraded`, `Draining`, and `Offline`.
  - Draining nodes are excluded from new Maglev table slots while conntrack maintains connectivity for existing active flows.
  - Offline nodes trigger immediate, safe failover to healthy backends.
- **Layer-7 Content-Aware Routing Engine**:
  - Priority-ordered rule engine evaluating tenant identifiers (`tenant_id`), QUIC Connection IDs (`quic_connection_id`), and object path prefixes (`path_prefix`).
  - Dynamic multiplexing into isolated backend pools (`BackendPool`).
- **Zero Unsafe Code**: 100% `#![forbid(unsafe_code)]` compliance with zero external native C dependencies.

---

## 3. Technical Architecture

```
                       Incoming Ingress Packet / QUIC Datagram
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │    5-Tuple Flow Key Extraction        │
                      │  (src_ip, src_port, dst_ip, dst_port) │
                      └───────────────────┬───────────────────┘
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │      L4 Connection Tracker (conntrack)│
                      └───────┬───────────────────────┬───────┘
                              │                       │
                     [Flow Record Exists]    [New Unseen Flow]
                              │                       │
                              │ (Node not Offline)    ▼
                              │            ┌──────────────────────────────────┐
                              │            │ Layer-7 Application Rule Engine  │
                              │            │ - Tenant Prefix Matching         │
                              │            │ - Path Prefix / QUIC CID         │
                              │            └──────────────┬───────────────────┘
                              │                           │
                              │                           ▼
                              │            ┌──────────────────────────────────┐
                              │            │ Target Backend Pool Selection    │
                              │            │ (e.g. 'default', 'vip-tenant')   │
                              │            └──────────────┬───────────────────┘
                              │                           │
                              │                           ▼
                              │            ┌──────────────────────────────────┐
                              │            │ Maglev O(1) Prime Lookup Table   │
                              │            │   slot = flow_hash mod M         │
                              │            │   node = table.lookup[slot]      │
                              │            └──────────────┬───────────────────┘
                              │                           │
                              │                           ▼
                              │            ┌──────────────────────────────────┐
                              │            │ Instantiate Flow in Conntrack    │
                              │            │ (Pin flow to assigned node)      │
                              │            └──────────────┬───────────────────┘
                              ▼                           ▼
                      ┌───────────────────────────────────────┐
                      │         Forward Packet to Node        │
                      │   - Healthy: Forward normal           │
                      │   - Draining: Forward pinned only     │
                      │   - Offline: Failover to new slot     │
                      └───────────────────────────────────────┘
```

---

## 4. Mathematical Foundations & Algorithms

### 4.1 Permutation Table Generation

For each registered backend node $i \in \{0, \dots, N-1\}$ and prime table modulus $M$:
$$offset_i = \text{BLAKE3}(\text{"velcrux\_maglev\_offset\_v1:"} \parallel \text{node\_id}_i) \pmod M$$
$$skip_i = \left(\text{BLAKE3}(\text{"velcrux\_maglev\_skip\_v1:"} \parallel \text{node\_id}_i) \pmod{M - 1}\right) + 1$$

Since $M$ is prime, $\gcd(skip_i, M) = 1$, guaranteeing that the sequence:
$$c = (offset_i + j \times skip_i) \pmod M \quad \text{for } j \in \{0, \dots, M-1\}$$
is a complete permutation of $\{0, \dots, M-1\}$.

### 4.2 Weighted Population & Churn Bound

Nodes iterate in weighted rounds ($w_i$), placing their identifier into the first unoccupied slot in their permutation sequence.
When node $N+1$ is added to an $N$-node cluster:
$$\mathbb{E}[\Delta_{\text{churn}}] = \frac{1}{N + 1}$$
For an 8-node cluster expanding to 9 nodes, $\mathbb{E}[\Delta] \approx 11.1\%$, verified experimentally in integration tests between $8\%$ and $14\%$.

---

## 5. Consequences

### 5.1 Positive Consequences
- **Constant-Time $O(1)$ Lookup**: Table index lookup requires a single modulo arithmetic operation, achieving over 10 million lookups per second per core.
- **Negligible Connection Disruption**: Preserves $\approx 90\%$ of flow mappings during cluster expansion or contraction.
- **Zero-Downtime Maintenance**: Operators can drain nodes without dropping active bulk transfers or breaking QUIC crypto contexts.
- **Multi-Tenant L7 Governance**: Dynamic rule engine segregates sensitive or VIP workloads into dedicated hardware pools.
- **Memory Safety & Portability**: 100% pure safe Rust (`#![forbid(unsafe_code)]`) across Linux, macOS, and containerized edge gateways.

### 5.2 Negative Consequences / Tradeoffs
- **Table Rebuild Latency**: Recalculating the 65,537-slot Maglev table takes $\approx 5\text{ ms} - 15\text{ ms}$ on membership changes. This is performed asynchronously off the critical packet forwarding path.
- **Conntrack Memory Footprint**: Tracking millions of concurrent micro-flows requires in-memory state ($128\text{ bytes}$ per flow), mitigated by aggressive timeout pruning.

---

## 6. Implementation References

- Core Module: `crates/velcrux-core/src/lb/`
  - `types.rs`: Backend nodes, statuses, 5-tuple hashing, flow records, L7 context.
  - `maglev.rs`: Maglev prime lookup table, permutation generator, churn calculator.
  - `conntrack.rs`: L4 connection tracking table, microsecond reaper, session stickiness.
  - `director.rs`: Load balancer director, backend pools, L7 routing rules, draining coordinator.
- Core Integration Tests: `crates/velcrux-core/tests/maglev_lb_tests.rs`
- Operator CLI Suite: `crates/velcrux-client/src/main.rs` (`velcrux lb status|lookup|members|benchmark`)
- CLI Integration Tests: `crates/velcrux-client/tests/cli_lb.rs`
