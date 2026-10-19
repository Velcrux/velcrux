# ADR-030: Strict RBAC & Policy-Gated Remote Deletion Enforcement (Resolution of Open Question #1)

Status: Accepted · Date: 2026-10-19

## Context

In distributed replication, multi-user environments, and automated sync workflows, remote file deletion represents one of the highest risks for irrecoverable data loss. Specifically, when a client executes `velcrux sync <src> <remote_dst> --delete`, any files on the remote destination that do not exist locally are pruned. If non-admin clients, automated service tokens, or CI/CD workers are permitted to perform bulk deletions without explicit authorization, an accidental misconfiguration or misdirected sync could wipe out remote data.

Prior to this decision, `CLAUDE.md` §4 tracked this issue under **Open Question #1**:
> *"Whether `sync --delete` should ever be allowed for a non-admin role. Currently, remote file deletions (`TransferOp::Delete`) and sync pruning lack a unified server-side RBAC enforcement policy."*

Key requirements:
1. **Resolution of Open Question #1**: Formally define whether and under what conditions `sync --delete` is permitted for non-admin identities.
2. **Fail-Closed RBAC Architecture**: Remote deletion requests must be denied by default unless an identity possesses explicit deletion privileges and conforms to the active server deletion policy.
3. **Distinct Protocol Semantics**: Differentiate targeted single-file deletion (`TransferOp::Delete`) from automated directory synchronization pruning (`TransferOp::SyncDelete`) across the wire protocol.
4. **Predefined RBAC Roles**: Standardize role definitions (`admin`, `operator`, `sync_writer`, `sync_replica`, `read_only`) with explicit permission sets.
5. **Configurable Server-Side Deletion Policy (`DeletionPolicy`)**:
   - `admin-only` (default): Only identities holding administrative rights can perform deletions.
   - `explicit-grant`: Non-admin identities can delete if and only if their grant explicitly contains the `sync_delete` / `delete` permission bit.
   - `disabled`: All remote deletions are globally rejected server-side regardless of user identity.
   - `rate-limited`: Deletions are permitted subject to sliding-window frequency limits to mitigate catastrophic bulk deletion loops.
6. **Sliding-Window Deletion Rate Limiting**: In-memory sliding-window limiter enforcing maximum deletions within a configurable time window.
7. **Telemetry & Auditability**: Export Prometheus metrics (`velcrux_deletions_total{outcome="attempted|executed|blocked"}`) and emit security audit log records.
8. **Strict `#![forbid(unsafe_code)]` Compliance**: 100% pure, safe Rust across all RBAC and policy evaluation components.

## Options Considered

1. **Client-Side Confirmation Prompts Only**:
   - Prompt the user or require a `--force` flag in the CLI before issuing deletions.
   - *Rejected*: Ineffective for headless automation, daemons, or malicious/compromised clients; provides zero server-side security.
2. **Permit Deletion for Any Identity with Write Access (`PermSet::WRITE`)**:
   - Treat file deletion as equivalent to overwriting files.
   - *Rejected*: High risk of accidental catastrophic data loss when automated uploaders or sync replicas misconfigure their source paths.
3. **Strict Server-Side RBAC with Fine-Grained `PermSet::SYNC_DELETE` and Configurable `DeletionPolicy`**:
   - Treat directory sync pruning as an elevated, distinct permission (`PermSet::SYNC_DELETE`) separate from individual file mutation.
   - Implement server-side policy gating (`admin-only` default, `explicit-grant`, `disabled`, `rate-limited`).
   - Wire protocol distinction between `TransferOp::Delete` and `TransferOp::SyncDelete`.

## Decision

Adopt Option 3.

By default, the server operates under `DeletionPolicy::AdminOnly`, ensuring that non-admin tokens cannot execute `sync --delete` out-of-the-box. Operators who wish to grant synchronization pruning rights to non-admin identities (e.g. dedicated sync replica agents) must explicitly configure `deletion_policy = "explicit-grant"` (or `"rate-limited"`) and assign the `sync_delete` permission (or `sync_replica` role) to the identity's grant.

## Architecture & Implementation

### 1. Permissions & RBAC Roles (`crates/velcrux-core/src/auth/mod.rs`)

- **Permission Bitfield (`PermSet`)**:
  - `PermSet::SYNC_DELETE = PermSet(1 << 7)`
  - Added `Op::SyncDelete` to authorizer check operations.
- **Predefined Roles (`Role`)**:
  - `admin`: Full administrative, read, write, resume, delete, and sync deletion privileges (`READ | WRITE | RESUME | DELETE | SYNC_DELETE | ADMIN`).
  - `operator`: Operational management with read, write, resume, and sync deletion (`READ | WRITE | RESUME | DELETE | SYNC_DELETE`).
  - `sync_writer`: Standard push-sync client (`READ | WRITE | RESUME`). Cannot delete files.
  - `sync_replica`: Mirroring replica client (`READ | WRITE | RESUME | SYNC_DELETE`). Permitted to prune destination files when permitted by server deletion policy.
  - `read_only`: Retrieval-only access (`READ`).
- **TOML Grant Expansion**:
  - Grants in server configuration can specify a `role = "sync_replica"` or individual permission flags including `"sync_delete"` / `"sync-delete"`.

### 2. Wire Protocol Differentiation (`crates/velcrux-core/src/protocol/message.rs`)

- Extended `TransferOp` enumeration:
  - `TransferOp::Delete = 7`: Individual file removal.
  - `TransferOp::SyncDelete = 9`: Directory synchronization pruning.
- Client CLI updates (`crates/velcrux-client/src/main.rs`):
  - `delete_remote_file(session, remote_path, is_sync)` sends `TransferOp::SyncDelete` when invoked via `sync --delete` or `--delete-after`.

### 3. Server Policy Enforcement & Sliding-Window Rate Limiter (`crates/velcrux-core/src/session/server.rs`)

- **`DeletionPolicy` Evaluation**:
  - Evaluated on every `TransferOp::Delete` and `TransferOp::SyncDelete`.
  - In `AdminOnly`: Rejects operations if the authenticated subject does not hold `PermSet::ADMIN`.
  - In `Disabled`: Universally rejects all deletions with `ErrorCode::PermissionDenied`.
  - In `ExplicitGrant`: Requires subject to possess `PermSet::SYNC_DELETE` (for sync pruning) or `PermSet::DELETE` (for single-file deletion).
  - In `RateLimited`: Requires proper permissions and verifies that sliding-window rate limit is not exceeded; returns `ErrorCode::QuotaExceeded` upon limit exhaustion.
- **`DeletionLimiter`**:
  - Thread-safe, sliding-window rate limiter (`Mutex<VecDeque<Instant>>`) with configurable capacity and window duration (defaults to 100 deletions per 60 seconds).
- **Session Stats & Telemetry**:
  - Tracks `deletions_attempted`, `deletions_executed`, and `deletions_blocked` on `ServerStats`.
  - Emits Prometheus counters `velcrux_deletions_total{outcome="..."}` via `crates/velcrux-server/src/metrics.rs`.

### 4. Configuration (`crates/velcrux-server/src/config.rs`)

Added server security configuration options under `[security]`:
```toml
[security]
deletion_policy = "admin-only" # "admin-only" | "explicit-grant" | "disabled" | "rate-limited"
deletion_rate_limit = 100
deletion_rate_window_secs = 60

[[security.grants]]
subject = "spiffe://velcrux.internal/sync-agent-prod"
role = "sync_replica"
```

## Consequences

- **Safety**: Unintended or rogue `sync --delete` executions cannot purge remote data unless the server configuration explicitly permits non-admin deletion and the client grant has been assigned the `sync_delete` capability.
- **Compatibility**: Existing read/write workflows remain completely unaffected. Normal file transfers, updates, and resumes proceed under existing `READ | WRITE | RESUME` permissions.
- **Auditability**: Security teams can monitor deletion volume, blocked unauthorized requests, and audit logs in real time.
