# ADR-026: Multi-Tenant Deduplication Poisoning Defense, Proof-of-Ownership & Quarantine Namespacing

Status: Accepted · Date: 2026-10-14  
References: `CLAUDE.md` §4 (Open Questions #3 & #4), `SECURITY.md` §5, §8, §9, `OPERATIONS.md` §44

## Problem

Content-addressed chunk stores (`ADR-006`) maximize transfer efficiency by reusing identical data blocks across files and transfers. However, in multi-tenant shared environments, a naive global deduplication pool introduces severe security and data integrity vulnerabilities:

1. **Cross-Tenant Content Existence Oracles (`CLAUDE.md` §4 Open Question #3)**:
   A malicious tenant probing the server with candidate chunk hashes (e.g. via `CHUNK_QUERY` or `InventoryHint` Bloom filters) can determine whether another tenant has uploaded proprietary or sensitive files (e.g., leaked source code, financial records, medical documents) without possessing read authorization for those files.
2. **Cross-Tenant Chunk Harvesting (`CLAUDE.md` §4 Open Question #4)**:
   If Tenant B references a chunk hash previously uploaded exclusively by Tenant A, a naive server might stage and serve Tenant A's chunk data to Tenant B, completely bypassing the destination grant authorization boundary (`SECURITY.md` §4).
3. **Deduplication Cache Poisoning**:
   An adversary who knows or guesses a target chunk hash can upload modified or malicious payload bytes claiming that hash. If the server does not perform mandatory in-flight cryptographic verification upon every chunk ingestion and copy, subsequent innocent transfers referencing that hash will stage corrupted or adversarial data.
4. **Lack of Automated Quarantine**:
   Bit-rotted or maliciously poisoned chunks residing in the active store remain undetected until a transfer failure, potentially contaminating downstream replica nodes.

## Options Considered

1. **Global Shared Deduplication Pool (Legacy Single-Tenant)**:
   - All tenants share a single flat chunk store (`<root>/chunks/ab/cd/<hash>.chunk`).
   - *Pros*: Maximum deduplication ratio across all organizations.
   - *Cons*: Highly vulnerable to content existence oracles, cross-tenant chunk extraction, and cache poisoning. Unacceptable for multi-tenant cloud or enterprise environments.
2. **Strict Physical Namespace Isolation (`Isolated`)**:
   - Each authenticated tenant identity (`Identity::name`) is assigned an isolated chunk store rooted at `<root>/tenants/<tenant_id>/chunks/ab/cd/<hash>.chunk`.
   - *Pros*: Physical separation eliminates cross-tenant data leakage, content existence oracles, and cross-tenant poisoning by construction.
   - *Cons*: Cannot deduplicate identical public files (e.g. OS base images) across different tenant accounts.
3. **Convergent Deduplication with Cryptographic Proof of Ownership (`ProofOfOwnership`)**:
   - Shared storage pool gated on Proof-of-Ownership (PoW) verification and per-chunk Access Control Lists (`ChunkAclEntry`).
   - A tenant cannot discover or reference a chunk unless they prove cryptographic possession of the chunk data using a BLAKE3-KeyedHash token.
   - *Pros*: Enables secure deduplication across tenants while neutralizing existence oracles and unauthorized chunk extraction.
   - *Cons*: Requires keyed token computation or data presentation.
4. **Hybrid Pluggable Deduplication Namespace Architecture (Option BJ - Selected)**:
   - Provide configurable `DedupNamespacePolicy` (`Isolated` [default], `ProofOfOwnership`, and `Global`).
   - Integrate automated chunk quarantine into `<root>/.quarantine/` upon checksum mismatch.
   - Enforce fail-closed security across `ServerConn`, `handle_transfer_create`, and CLI tools.

## Decision

We adopt Option 4. Velcrux implements a comprehensive multi-tenant deduplication poisoning defense and namespacing architecture across `velcrux-core`, `velcrux-server`, and `velcrux-client`:

1. **Default Policy**: `DedupNamespacePolicy::Isolated` is the default for all multi-tenant server configurations, partitioning chunk storage into `<root>/tenants/<tenant_id>/chunks/`.
2. **Cryptographic Proof of Ownership (PoW)**: When `ProofOfOwnership` is configured, cross-tenant chunk reuse requires verifying a 32-byte BLAKE3-KeyedHash token:
   $$\text{Token} = \text{BLAKE3-KeyedHash}(\text{server\_secret}, \text{chunk\_hash} \mathbin{\Vert} \text{chunk\_data})$$
   Evaluated in constant time (`subtle_slice_eq`) to eliminate timing side channels.
3. **Chunk Provenance ACL**: Each chunk in shared mode tracks `owner_tenant`, `authorized_tenants`, access timestamps, and reference counts (`ChunkAclEntry`).
4. **Automatic Quarantine Manager**: Any chunk failing in-flight BLAKE3 checksum verification during read, write, or copy is instantly quarantined to `<root>/.quarantine/<hash>_<ts>_<rand>.quarantine` and purged from the live index.
5. **Resolution of Open Questions**: Formally resolves `CLAUDE.md` §4 Open Questions #3 & #4.

## Technical Specifications

### 1. `DedupNamespacePolicy` Representation

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DedupNamespacePolicy {
    /// Physical tenant isolation (default): <root>/tenants/<tenant_id>/chunks/...
    Isolated,
    /// Convergent deduplication gated on BLAKE3-KeyedHash Proof of Ownership & ACL
    ProofOfOwnership,
    /// Shared global deduplication pool (single-tenant legacy)
    Global,
}
```

### 2. In-Flight BLAKE3 Verification & Quarantine Pipeline

```
Chunk Ingestion / Copy Request
       │
       ▼
Tenant Authorization Check (Isolated Partition or PoW ACL)
       │
       ├─► Unauthorized ──► Block probe, increment oracle_probes_blocked, return false
       │
       ▼ Authorized
Read Chunk from Disk into Staging File
       │
       ▼
Compute In-Flight BLAKE3 Hash on Stream
       │
       ├──► Hash == Chunk Hash ──► Success, record access in ACL
       │
       └──► Hash != Chunk Hash ──► POISONING / CORRUPTION DETECTED
                                        │
                                        ├─► Atomically move to <root>/.quarantine/
                                        ├─► Increment poison_attempts metric
                                        └─► Return ProtocolError::Malformed
```

### 3. Server Configuration (`server.toml`)

```toml
[storage]
root = "/var/lib/velcrux/data"
staging = "/var/lib/velcrux/staging"
chunk_store = "/var/lib/velcrux/chunks"
dedup_policy = "isolated" # "isolated" (default), "proof-of-ownership", or "global"
# Optional 32-byte hex key for Proof of Ownership token verification
dedup_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

Environment variable overrides:
- `VELCRUX_STORAGE_DEDUP_POLICY="isolated"`
- `VELCRUX_STORAGE_DEDUP_SECRET="<hex>"`

### 4. Operational CLI Commands

```bash
# Inspect deduplication policy, tenant namespaces, and quarantine metrics
velcrux dedup status --chunk-store /var/lib/velcrux/chunks

# Audit chunk store integrity, verifying BLAKE3 hashes and quarantining corrupted chunks
velcrux dedup verify --chunk-store /var/lib/velcrux/chunks

# Inspect quarantined records
velcrux dedup quarantine list --chunk-store /var/lib/velcrux/chunks

# Permanently purge quarantined files
velcrux dedup quarantine purge --chunk-store /var/lib/velcrux/chunks
```

## Security & Verification Guarantees

1. **Zero Cross-Tenant Leakage**: In `Isolated` mode, Tenant A and Tenant B cannot discover or access each other's chunks under any conditions.
2. **Oracle Neutralization**: Probing non-authorized chunks in `ProofOfOwnership` or `Isolated` mode fails closed and increments `oracle_probes_blocked` telemetry.
3. **No Unverified Data Copied**: Chunks copied to staging files are verified on the fly with BLAKE3. If a corrupted chunk is encountered, it is quarantined immediately and never committed.
4. **Strict Concurrency Safety**: `#![forbid(unsafe_code)]` enforced across all namespacing, quarantine, and cryptographic PoW modules.
