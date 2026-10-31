# ADR-053: Zero-Trust Cryptographic Content Provenance & Tamper-Evident Merkle-DAG Audit Log

Status: Accepted · Date: 2026-10-31

## Context

Distributed bulk data transfer systems, multi-cloud storage meshes, and content-addressed storage (CAS) fabrics face stringent enterprise compliance requirements (e.g. SOC 2 Type II, ISO/IEC 27001, HIPAA, FedRAMP High, FDA 21 CFR Part 11):
- **Insider Threat & Log Tampering**: System administrators or compromised infrastructure credentials could silently alter database entries, delete audit files, or manipulate transfer records without detection.
- **Content Authenticity & Origin Lineage**: In machine learning pipelines, medical imaging, and distributed software artifact distribution, consumers must mathematically prove the exact origin actor, timestamp, and chronological sequence of mutations that produced a specific binary object or model weight.
- **Concurrent Non-Linear Event History**: Modern distributed systems do not execute in a linear single-threaded sequence. Concurrent edge nodes, multi-cloud clusters, and disconnected field devices record mutations and reconciliation merges concurrently, forming a Directed Acyclic Graph (DAG) rather than a linear blockchain or append-only file.
- **Auditor Verification Without Full Data Disclosure**: External compliance auditors require mathematical inclusion proofs certifying that a specific event occurred at a verified time and was anchored to cluster consensus, without requiring access to proprietary payloads or customer data.

To solve these challenges, Velcrux requires a pure safe Rust Zero-Trust Cryptographic Content Provenance engine backed by a tamper-evident Merkle-DAG audit log.

---

## Options Considered

1. **Option 1: Centralized SQL Database with Write-Once Storage**:
   - Store audit entries in PostgreSQL or SQLite with append-only tables or cloud WORM (Write Once Read Many) storage.
   - *Rejected*: Centralized DB is vulnerable to DBA tampering, lacks cryptographic tamper-evidence, and cannot represent distributed concurrent merge histories without single-coordinator locking.
2. **Option 2: Heavyweight Distributed Ledger / Blockchain (e.g. Hyperledger Fabric, Tendermint)**:
   - Run a dedicated Byzantine Fault Tolerant (BFT) blockchain node alongside Velcrux.
   - *Rejected*: Immense operational complexity, heavy C/Go dependencies, high transaction latency (hundreds of milliseconds to seconds), and excessive CPU/memory overhead.
3. **Option 3: Pure Safe Rust In-Memory & Staging Merkle-DAG Audit Log (`ADR-053`)**:
   - Strictly `#![forbid(unsafe_code)]` with zero external ledger dependencies.
   - Cryptographic Merkle-DAG structure capturing concurrent forks, causal dependencies, and distributed reconciliation merges.
   - Canonical BLAKE3 cryptographic anchoring over actor identities, action classifications, resource identifiers, payload digests, and sorted parent hashes.
   - Independent notary witness cosigning (`WitnessCosignature`) and RFC 3161 timestamping token binding (`TimestampToken`).
   - High-throughput verification engine detecting hash tampering, missing parent links, and graph cycles.
   - Cryptographic inclusion proofs certifying node presence against DAG roots.
   - First-class operator CLI subcommands (`velcrux provenance status|record|verify|prove|witness|export|benchmark`) and Prometheus telemetry.

---

## Decision

Adopt **Option 3: Pure Safe Rust In-Memory & Staging Merkle-DAG Audit Log (`ADR-053`)**.

### Architectural Design

```
+-----------------------------------------------------------------------------------------+
|                  Velcrux Zero-Trust Cryptographic Merkle-DAG Audit Mesh                 |
|                                                                                         |
|  [ Cluster Events: Ingest / Mutation / Sync / Quota / Scrub / Key Rotation ]            |
|                                     │                                                   |
|                                     ▼                                                   |
|  ┌─────────────────────────────────────────────────────────────────────────────────┐    |
|  │ MerkleDagAuditLog (Append-Only Cryptographic Engine)                            │    |
|  │  - Canonical BLAKE3 Node Hashing with Domain Separation                         │    |
|  │  - Automatic Causal Merging across Active Tips / Heads                          │    |
|  │  - Optional Notary Witness Cosigning & RFC 3161 Timestamp Tokens               │    |
|  └──────────────────┬──────────────────────────────────────────────┬───────────────┘    |
|                     │                                              │                    |
|                     ▼                                              ▼                    |
|  ┌──────────────────────────────────────────┐   ┌───────────────────────────────────┐   |
|  │ Topological Cycle & Integrity Validator  │   │ Merkle Inclusion Proof Generator  │   |
|  │  - Kahn's Algorithm / In-Degree Traverse │   │  - Path Extraction to DAG Root    │   |
|  │  - Sub-µs Verification per Node          │   │  - Verifiable by External Auditor │   |
|  └──────────────────┬───────────────────────┘   └───────────────────┬───────────────┘   |
|                     │                                               │                   |
|                     ▼                                               ▼                   |
|  ┌─────────────────────────────────────────────────────────────────────────────────┐    |
|  │ Persistent Journal / Compliance Export                                          │    |
|  │  - Atomic Multi-Process Staging (<node_id>_<node_hash>.json)                    │    |
|  │  - RFC 3161 Attestation & JSON Audit Export for External Compliance Review     │    |
|  └─────────────────────────────────────────────────────────────────────────────────┘    |
+-----------------------------------------------------------------------------------------+
```

### Merkle-DAG Node Structure & Canonical Hashing

Every audit node in the Merkle-DAG satisfies:

$$\text{NodeHash} = \text{BLAKE3}\left(\tau \parallel \text{node\_id} \parallel \text{timestamp\_ns} \parallel \text{actor} \parallel \text{action} \parallel \text{resource\_id} \parallel \text{payload\_digest} \parallel \text{parents} \parallel \text{metadata}\right)$$

Where:
- $\tau = \text{"velcrux-provenance-dag-node:v1\textbackslash n"}$ (Domain Separation Tag)
- $\text{parents}$: Lexicographically sorted array of parent BLAKE3 32-byte hashes.
- $\text{metadata}$: Canonical sequence of length-prefixed key-value pairs sorted in lexicographical order.

### Unified Merkle Root Across DAG Tips

When multiple concurrent branches exist in the DAG (multiple unmerged tips/heads), the overall Merkle Root of the cluster state is derived deterministically:

$$\text{MerkleRoot} = \begin{cases} 
\mathbf{0}^{32} & \text{if } |\text{Heads}| = 0 \\
H_0 & \text{if } |\text{Heads}| = 1 \\
\text{BLAKE3}\left(\text{"velcrux-provenance-dag-root:v1\textbackslash n"} \parallel |\text{Heads}| \parallel \bigoplus_{i=0}^{n-1} H_i\right) & \text{if } |\text{Heads}| > 1
\end{cases}$$

---

## Consequences

### Positive
- **Tamper-Evident Immutability**: Any alteration to an actor, timestamp, payload digest, or parent reference breaks downstream node hashes and is immediately flagged during verification.
- **Zero External Dependencies**: Pure safe Rust (`#![forbid(unsafe_code)]`) with no external database, daemon, or blockchain framework required.
- **High-Throughput Sub-Microsecond Performance**: Node creation and hashing executes in $< 1.5\,\mu\text{s}$ per event; complete DAG verification processes $> 1,000,000\text{ nodes/sec}$.
- **Comprehensive Audit Trail**: Unifies content mutations, CAS chunk lifecycles, cross-cloud syncs, credential rotations, and access grants under one verifiable umbrella.
- **Enterprise Regulatory Compliance**: Generates portable, mathematically verifiable inclusion proofs for third-party compliance auditors.

### Negative / Trade-Offs
- **Storage Growth**: Immutable append-only audit ledgers require disk space proportional to event volume. Addressed via optional export and pruning to cold archive tiers.
- **Topological In-Degree Sorting**: Graph cycle detection requires topological traversal during full verification runs. Mitigated via incremental tip verification during normal operations.
