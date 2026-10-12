# ADR-020: Distributed Lock Manager (DLM) & Mutex Lease Coordinator

Status: Accepted · Date: 2026-10-12

## Problem

Per `REQUIREMENTS.md` §17 ("Distributed Coordination"), §20 ("High Availability & Quorum"), §31 ("Split-Brain Prevention"), and §61 ("Transactional Synchronization"), multi-node cluster deployments and parallel synchronization pipelines require distributed concurrency control:
1. **Concurrent Mutation Protection**: Multiple cluster workers or synchronization nodes concurrently updating shared directories or files risk race conditions, corrupted states, and split-brain overwrites.
2. **Deadlock & Node Failure Resilience**: If a client crashes, disconnects, or suffers a network partition while holding a lock, the resource must not remain permanently locked. Leases must feature automatic time-to-live (TTL) expiration and heartbeat renewal.
3. **Split-Brain Mitigation via Fencing**: Network pauses, GC pauses, or slow I/O can cause a holder to resume execution after its lease expired. Target storage receivers require monotonically increasing Lamport fencing tokens to validate incoming writes and reject stale operations.
4. **Flexible Access Modes**: High-throughput read pipelines (e.g. distributed snapshot export or integrity scrubbers) should be able to hold shared read locks concurrently, while mutation jobs require exclusive write locks.
5. **State Durability & Disaster Recovery**: The lock coordinator state must persist across daemon restarts without losing active lease reservations or regressing fencing tokens.

## Options Considered

1. **External Consensus Cluster (ZooKeeper / etcd / Consul)**:
   - Require external daemon infrastructure for distributed locking.
   - *Rejected*: Introduces heavyweight external dependencies, operational complexity, and violates Velcrux's self-contained, zero-external-service architectural requirement.
2. **Ad-Hoc Filesystem Lock Files (`.lock`)**:
   - Create empty sentinel files on disk using filesystem locking (`flock`).
   - *Rejected*: Inadequate for cross-node network topologies, prone to stale lock files upon abrupt node termination, lacks fencing token generation, and cannot support shared read leases cleanly.
3. **Native Embedded Distributed Lock Manager (Option BD)**:
   - Pure-Rust, high-performance distributed lock coordinator (`DistributedLockManager`) built into `velcrux-core`.
   - Supports both `Exclusive` write and `Shared` read locking semantics.
   - Time-bounded leases with configurable TTL (default 60s, max 3600s), heartbeat extension (`renew`), and explicit `release`.
   - Atomic monotonically increasing Lamport fencing token generation on every lease grant to prevent split-brain writes.
   - Atomic filesystem persistence stage with transactional staging and reload.
   - Fully accessible via the unified CLI (`velcrux lock acquire`, `renew`, `release`, `list`, `verify`).

## Decision

Option 3. Velcrux implements a native Distributed Lock Manager (DLM) and mutex lease coordinator with Lamport fencing tokens and durability recovery under `#![forbid(unsafe_code)]`.

## Architecture & Implementation

### 1. Data Model & Concurrency Semantics

Locks are identified by an opaque UUID-prefixed token (`lck-<token>-<rand>`) and maintain precise ownership metadata:
```json
{
  "lock_id": "lck-101-39650",
  "resource": "/datasets/imagenet",
  "holder_id": "worker-node-01",
  "mode": "exclusive",
  "fencing_token": 101,
  "granted_at_secs": 1791804645,
  "expires_at_secs": 1791804765,
  "ttl_secs": 120
}
```

- **Exclusive Locks**: Only a single holder may hold an exclusive lock on a resource. Subsequent requests (exclusive or shared) are immediately rejected with `LockError::ResourceBusy` detailing the current holder and remaining TTL.
- **Shared Locks**: Multiple readers may hold overlapping shared locks concurrently. Any exclusive write lock request on the same resource is rejected until all shared readers release their leases or expire.
- **Lamport Fencing Tokens**: Every granted lock lease is issued a strictly increasing `fencing_token` from an atomic counter (`AtomicU64`). Target storage nodes can call `verify_fencing(resource, token)` to detect and reject delayed or stale write requests from pre-empted clients.

### 2. Automatic Expiry & Heartbeat Renewal

- Leases automatically lapse after their configured TTL, eliminating deadlocks caused by client crashes or network partitions.
- Active holders maintain continuous ownership via periodic heartbeats (`dlm.renew(lock_id, holder, extension_secs)`).
- Holders can only renew or release leases matching their registered `holder_id`, preventing unauthorized lease manipulation.

### 3. Durability & Recovery

- When configured with a persistence path (`dlm.with_persistence(path)`), state changes are written to disk using atomic tempfile staging (`tmp-<rand>` -> rename).
- On coordinator restart, active leases and the highest issued fencing token are rehydrated seamlessly, ensuring continuity and monotonic token progression.

### 4. CLI Interface

The client binary exposes the full lock management surface:
- `velcrux lock acquire <resource> [--holder <id>] [--mode <exclusive|shared>] [--ttl-secs <s >] [--state-file <path>]`
- `velcrux lock renew <lock_id> [--holder <id>] [--ttl-secs <s>]`
- `velcrux lock release <lock_id> [--holder <id>]`
- `velcrux lock list [--resource <resource>]`
- `velcrux lock verify <resource> <token>`
- JSON output via global `--json` flag.

## Consequences

- **Positive**:
  - Eliminates split-brain write conflicts across distributed cluster workers.
  - Guarantees deadlock freedom through deterministic lease TTL expiration.
  - Zero external C or daemon dependencies; works out of the box in standalone and clustered modes.
  - Clean auditability via structured CLI table and JSON reporting.
- **Negative / Trade-offs**:
  - Clients with long-running transfers must schedule heartbeat renewals within their lease TTL window.
  - Atomic persistence writes incur minor disk I/O on lease grant and release events.
