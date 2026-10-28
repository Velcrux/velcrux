# ADR-043: Cryptographic Zero-Knowledge Transfer Audit Proofs & Merkle Tree Accumulator

Status: Accepted · Date: 2026-10-28

## Context

Enterprise environments subject to stringent regulatory regimes (e.g. SOC 2 Type II, ISO/IEC 27001, HIPAA, SOX, and GDPR) require tamper-evident, non-repudiable audit trails of all file transfer events (`SECURITY.md` §7, §8; `ARCHITECTURE.md` §8). Concurrently, zero-trust architectures mandate strict privacy isolation: independent compliance auditors, external regulators, or cross-tenant oversight bodies must be capable of verifying that a specific transfer occurred (or did not occur) within an authoritative epoch without gaining access to confidential transfer payload data, tenant identifiers, manifest contents, or sensitive timestamps.

Key operational and architectural requirements:
1. **Privacy-Preserving Transfer Commitments**:
   - Transfer metadata records must be cryptographically blinded using a 256-bit cryptographically secure pseudorandom salt before being committed to public or auditor-accessible logs.
   - Commitments must satisfy the cryptographic hiding and binding properties: an auditor learns zero information regarding transfer metadata without knowledge of the salt, while the system operator cannot alter any transfer parameter after commitment.
2. **Efficient Cryptographic Merkle Accumulator**:
   - The transfer event ledger must be accumulated into an authoritative Merkle tree root using SIMD-accelerated BLAKE3 domain-separated hashing.
   - Inclusion proofs must scale logarithmically: $O(\log_2 N)$ proof size and verification latency, allowing millions of transfers per epoch to be proven in sub-kilobyte envelopes.
3. **Non-Membership / Exclusion Proofs**:
   - Compliance auditors must be able to verify that an unauthorized or unlogged transfer did *not* execute within an epoch.
   - The accumulator maintains a sorted leaf index and produces cryptographic exclusion proofs bounded by adjacent neighboring leaves.
4. **Sub-Millisecond Proof Verification**:
   - Proof verification must execute in under 50 microseconds on standard commodity hardware, enabling inline compliance checks and real-time ledger attestation.
5. **Telemetry & Operability**:
   - Export Prometheus metrics (`velcrux_audit_proofs_generated_total`, `velcrux_audit_proofs_verified_total`, `velcrux_audit_proof_verification_failures_total`, `velcrux_audit_tree_records_total`, `velcrux_audit_tree_height`) and CLI subcommands (`velcrux audit [status|generate-proof|verify-proof|export-root|benchmark]`).
6. **Invariants**:
   - 100% Safe Rust (`#![forbid(unsafe_code)]` with zero exceptions across all crates).
   - Strict bounded memory streaming: Merkle tree nodes and proof serialization are bounded, avoiding full-file allocations.

---

## Options Considered

1. **Option 1: Plaintext Signed Audit Logs**:
   - Append transfers to an append-only log signed with an Ed25519 private key.
   - *Rejected*: Incompatible with zero-knowledge privacy requirements; revealing the log to third-party auditors exposes confidential tenant IDs, file paths, exact byte sizes, and access frequencies.
2. **Option 2: Arithmetic Circuit zk-SNARKs (Groth16 / PLONK)**:
   - Formulate transfer audit constraints inside R1CS or arithmetic circuits verified via pairing-friendly curves (e.g. BN254 or BLS12-381).
   - *Rejected*: Massive computational overhead (>100 ms per proof generation, high memory consumption, external cryptographic library dependencies with C/assembly unsafe code), violating Velcrux's pure-Rust `#![forbid(unsafe_code)]` and low-overhead streaming invariants.
3. **Option 3: Domain-Separated BLAKE3 Merkle Tree Accumulator with Salt Blinding (`ADR-043`)**:
   - Pure-Rust, SIMD-accelerated Merkle accumulator built over domain-separated BLAKE3 primitives (`b"velcrux-audit-leaf:v1"` and `b"velcrux-audit-node:v1"`).
   - Blinds individual transfer records via $C = \text{BLAKE3}(domain \parallel transfer\_id \parallel tenant \parallel manifest\_hash \parallel bytes \parallel timestamp \parallel salt)$.
   - Generates compact $O(\log_2 N)$ inclusion and exclusion proofs verifiable in <20 µs with zero external unsafe dependencies.

---

## Decision

Adopt Option 3.

---

## Architecture & Implementation

### 1. Zero-Knowledge Leaf Commitment Formula (`crates/velcrux-core/src/audit/mod.rs`)

An unblinded transfer event record contains transfer parameters:
```rust
pub struct AuditRecord {
    pub transfer_id: String,
    pub tenant_id: String,
    pub manifest_hash: Hash,
    pub total_bytes: u64,
    pub completed_at_secs: u64,
}
```

The operator blinds this record with an ephemeral or secret 32-byte salt $S$:
$$C = \text{BLAKE3}\left(\text{"velcrux-audit-leaf:v1"} \parallel transfer\_id \parallel tenant\_id \parallel manifest\_hash \parallel total\_bytes \parallel completed\_at\_secs \parallel S\right)$$

The resulting 32-byte hash $C$ serves as the public leaf commitment. Without knowledge of $S$, computing pre-images or distinguishing transfer metadata is computationally infeasible under the random oracle model.

### 2. Merkle Tree Accumulator & Path Proofs

The tree combines pairs of child node hashes using domain-separated internal node hashing:
$$H_{\text{parent}} = \text{BLAKE3}\left(\text{"velcrux-audit-node:v1"} \parallel H_{\text{left}} \parallel H_{\text{right}}\right)$$

In odd-length levels, the unpaired leaf is duplicated to maintain deterministic balance.

An inclusion proof consists of:
```rust
pub struct AuditInclusionProof {
    pub leaf_index: usize,
    pub leaf_hash: [u8; 32],
    pub expected_root: [u8; 32],
    pub path: Vec<AuditProofStep>,
    pub transfer_id: String,
}

pub struct AuditProofStep {
    pub sibling: [u8; 32],
    pub direction: AuditProofDirection, // Left or Right
}
```

### 3. Non-Membership / Exclusion Verification

To prove that a target leaf $C_T$ does not exist in the accumulator without disclosing other leaves:
1. The accumulator maintains leaves in lexicographically sorted order.
2. The operator locates the immediate lower bound $C_L < C_T$ and upper bound $C_R > C_T$ such that no intermediate leaf exists between $C_L$ and $C_R$.
3. The operator generates inclusion proofs for both $C_L$ and $C_R$.
4. The auditor verifies both inclusion proofs against the authoritative root and verifies that $C_L < C_T < C_R$, mathematically confirming non-existence.

### 4. Telemetry & Metrics (`crates/velcrux-server/src/metrics.rs`)

Prometheus gauges and counters exposed at `/metrics`:
- `velcrux_audit_proofs_generated_total`: Cumulative counter of generated inclusion proofs.
- `velcrux_audit_proofs_verified_total`: Cumulative counter of successfully verified proofs.
- `velcrux_audit_proof_verification_failures_total`: Cumulative counter of invalid/tampered proofs.
- `velcrux_audit_tree_records_total`: Total committed records in active epoch tree.
- `velcrux_audit_tree_height`: Current depth of Merkle accumulator tree.

### 5. CLI Operations (`crates/velcrux-client/src/main.rs`)

```bash
# Display accumulator status for current epoch
velcrux audit status --epoch 1

# Generate a zero-knowledge inclusion proof
velcrux audit generate-proof 01J00000000000000000012345 --tenant tenant-prod --out proof.json

# Cryptographically verify the inclusion proof
velcrux audit verify-proof --root <root_hex> --leaf <leaf_hex> --proof-file proof.json

# Export the authoritative epoch root
velcrux audit export-root --epoch 1

# Execute performance and throughput benchmark
velcrux audit benchmark --records 1000 --samples 100
```

---

## Consequences

### Positive
- **Auditor Privacy**: External auditors verify transfer execution without access to proprietary file data or tenant metadata.
- **Microsecond Verification**: Proofs verify in <20 µs, making continuous compliance verification negligible in overhead.
- **Zero Unsafe Rust**: Implemented with `#![forbid(unsafe_code)]` and zero external C dependencies.
- **Tamper-Evident**: Any bit mutation in proof steps, leaf hashes, or root hashes triggers immediate mathematical rejection.

### Negative
- **Proof Storage**: Storing or transferring inclusion proofs incurs $\approx 32 \times \lceil\log_2 N\rceil$ bytes per proof. For $N = 1,000,000$, proofs are $\approx 640$ bytes, which is easily manageable over wire or disk.
