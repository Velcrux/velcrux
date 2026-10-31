# ADR-051: Self-Healing Distributed Erasure Coding & Autonomous Shard Scrub Mesh

Status: Accepted · Date: 2026-10-31

## Context

Distributed object storage, cross-cloud data synchronization, and edge cold-archive pipelines in Velcrux must maintain resilient data durability across heterogeneous, failure-prone storage media and untrusted physical infrastructure:
- **Silent Data Corruption & Bit-Rot**: Magnetic drive media degradations, flash NAND wear-out, PCIe bus transmission bit-flips, and uncoordinated firmware bugs corrupt file contents silently without returning OS I/O error codes.
- **Node & Disk Outages**: Drive failures, cloud availability zone partitioning, and storage node ungraceful shutdowns cause permanent or intermittent loss of data fragments.
- **Storage Overhead of Full Replication**: Triplicate replication (3x replication factor) incurs 200% storage overhead, which is economically prohibitive for petabyte-scale datasets and cross-region egress bandwidth.
- **Operational Burden of Manual Rebuilding**: Traditional storage arrays require administrative intervention or heavy background cluster rebalancing daemons that degrade active client I/O performance.

To achieve superior mathematical durability guarantees with bounded storage overhead ($\le 50\%$) and zero operator intervention, Velcrux requires pure safe Rust Reed-Solomon $(K+M, K)$ erasure coding with cryptographic integrity validation and an autonomous self-healing scrub mesh.

---

## Options Considered

1. **Option 1: Hardware/OS RAID Arrays (RAID 5/6)**:
   - Rely on local controller RAID or Linux mdadm.
   - *Rejected*: Inflexible, bound to specific disk configurations, provides no protection against cross-node partitions, and lacks cryptographic BLAKE3 content validation.
2. **Option 2: Third-Party Native C/C++ Erasure Libraries (e.g. Intel ISA-L)**:
   - Integrate Intel ISA-L via FFI or C wrapper bindings.
   - *Rejected*: Violates `#![forbid(unsafe_code)]` with complex unsafe C/Assembly foreign function interfaces, complicates cross-compilation on ARM64 and macOS, and introduces security attack surfaces in memory allocation.
3. **Option 3: Pure Safe Rust Galois Field $\text{GF}(2^8)$ Cauchy MDS Erasure Coding Engine & Autonomous Shard Scrub Mesh (`ADR-051`)**:
   - Pure safe Rust implementation adhering strictly to `#![forbid(unsafe_code)]`.
   - Reed-Solomon Cauchy generator matrix construction guaranteed to satisfy the Maximum Distance Separable (MDS) property.
   - Gaussian elimination over Galois Field $\text{GF}(2^8)$ to invert arbitrary $K \times K$ submatrices for reconstructing missing shards from any $\ge K$ surviving shards.
   - Standardized `ShardEnvelope` binary envelope format with `VEC1` magic header, schema definition, shard index, payload length, BLAKE3 checksum, and object identity.
   - Autonomous background scrubber classifying objects into `Healthy`, `Degraded`, `Critical`, and `Unrecoverable` states, accompanied by on-the-fly autonomous repair.
   - First-class client CLI subcommands (`velcrux ec status|encode|decode|scrub|benchmark`) and Prometheus metrics exposition.

---

## Decision

Adopt **Option 3: Pure Safe Rust Galois Field $\text{GF}(2^8)$ Cauchy MDS Erasure Coding Engine & Autonomous Shard Scrub Mesh (`ADR-051`)**.

### Architectural Design

```
+-----------------------------------------------------------------------------------------+
|                  Velcrux Distributed Erasure Coding & Scrub Architecture                |
|                                                                                         |
|  [ Original Object Payload (N bytes) ]                                                  |
|                   │                                                                     |
|                   ▼                                                                     |
|  ┌─────────────────────────────────────────────────────────┐                            |
|  │ ErasureEngine::encode (Schema: K data + M parity shards)│                            |
|  │  - Partition original bytes into K aligned blocks       │                            |
|  │  - Construct Cauchy Generator Matrix G: (K+M) x K       │                            |
|  │  - Compute M parity shards via GF(2^8) linear comb      │                            |
|  │  - Wrap each shard into VEC1 ShardEnvelope (BLAKE3)     │                            |
|  └────────────────────────┬────────────────────────────────┘                            |
|                           │                                                             |
|           ┌───────────────┼───────────────┐                                             |
|           ▼               ▼               ▼                                             |
|     Shard 0 (Data)  Shard K-1 (Data) Shard K (Parity) ... Shard K+M-1 (Parity)          |
|           │               │               │                                             |
|           ▼               ▼               ▼                                             |
|  [ Disk / Shard Storage Directory (Local or Dispersed across Edge / Cloud Nodes) ]      |
|                           │                                                             |
|                           ▼                                                             |
|  ┌─────────────────────────────────────────────────────────┐                            |
|  │ ShardScrubMesh::scrub_directory / auto_repair_directory │                            |
|  │  - Scan shard envelopes, verify BLAKE3 checksums        │                            |
|  │  - Detect silent bit-rot corruptions or missing shards  │                            |
|  │  - Classify Object Health State:                        │                            |
|  │      * Healthy       (Total == K + M)                   │                            |
|  │      * Degraded      (K < Surviving < K + M)            │                            |
|  │      * Critical      (Surviving == K)                   │                            |
|  │      * Unrecoverable (Surviving < K)                    │                            |
|  │  - Invert surviving Cauchy submatrix via GF(2^8) Gauss   │                            |
|  │  - Reconstruct missing shards and rewrite to disk       │                            |
|  └─────────────────────────────────────────────────────────┘                            |
+-----------------------------------------------------------------------------------------+
```

### Mathematical Formulation

1. **Galois Field $\text{GF}(2^8)$ Arithmetic**:
   Field operations are conducted over the Galois Field $\text{GF}(2^8)$ with primitive irreducible polynomial:
   $$P(x) = x^8 + x^4 + x^3 + x^2 + 1 \quad (\text{0x11d})$$
   Multiplication and division utilize precomputed exponential ($\text{exp}$) and logarithmic ($\text{log}$) tables:
   $$a \cdot b = \text{exp}[(\text{log}[a] + \text{log}[b]) \pmod{255}]$$

2. **Cauchy Generator Matrix Construction**:
   To guarantee that any $K \times K$ submatrix is non-singular (invertible), the $(K+M) \times K$ generator matrix $G$ is constructed such that the top $K \times K$ is the identity matrix $I_K$ (systematic code), and the bottom $M \times K$ Cauchy matrix elements are:
   $$G_{i+K, j} = \frac{1}{X_i \oplus Y_j}$$
   where $X_i = i$ and $Y_j = K + j$ are distinct elements chosen from $\text{GF}(2^8)$ such that $X_i \oplus Y_j \ne 0$.

3. **Reconstruction & Matrix Inversion**:
   Given any set of $K$ surviving shards $S = \{s_1, \dots, s_K\}$, the corresponding rows of $G$ form a $K \times K$ submatrix $G_S$. The original data blocks $D$ are recovered via:
   $$D = G_S^{-1} \cdot S$$
   Matrix inversion $G_S^{-1}$ is computed via Gaussian elimination with partial pivoting in $\text{GF}(2^8)$.

### Binary Wire Format: `ShardEnvelope` (`VEC1`)

Every shard is encapsulated in a self-describing binary format:
```
+---------------------------------------------------------------------------------------+
| Magic (4B) | Ver(1B) | K(1B) | M(1B) | ShardIdx(1B) | OrigSize(8B) | PayloadLen(4B)    |
|   "VEC1"   |   0x01  |  0x04 |  0x02 |    0x00      |  (u64 BE)    |   (u32 BE)        |
+---------------------------------------------------------------------------------------+
| BLAKE3 Checksum (32B) | ObjectIdLen (2B) | ObjectId (UTF-8) | Payload Data (NB)       |
+---------------------------------------------------------------------------------------+
```

---

## Consequences

### Positive
- **Guaranteed Mathematical Recoverability**: Any $M$ missing or corrupted shards out of $(K+M)$ can be reconstructed without loss.
- **Storage Overhead Reduction**: Overhead drops from 200% (3x replication) to 50% ($4+2$) or 25% ($16+4$).
- **Zero-Unsafe Rust**: 100% pure safe Rust adhering strictly to `#![forbid(unsafe_code)]`.
- **Autonomous Healing**: Continuous background scrubbing and self-repair eliminates manual operations and prevents cascading multi-disk failures.
- **Unified Telemetry**: Full Prometheus integration (`velcrux_ec_*`) and CLI diagnostics.

### Negative / Trade-Offs
- **CPU Overhead for Parity Computation**: Galois Field arithmetic incurs CPU cycles compared to raw memory copies. Mitigated via lookup tables and fast-path systematic decoding when all $K$ data shards are present.
- **Reconstruction Latency**: Missing data shards require matrix inversion and linear combinations before data can be returned to readers.

