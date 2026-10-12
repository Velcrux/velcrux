# ADR-018: Pluggable Webhook Event Notifications & Audit Event Bus

Status: Accepted · Date: 2026-10-12

## Problem

Per `REQUIREMENTS.md` §69–§73 ("Audit Logging & Event Notification Webhooks") and `ARCHITECTURE.md` §11 ("Telemetry & Operational Visibility"), enterprise deployments require real-time notification integration and compliance audit logging:
1. **Compliance & SIEM Ingestion**: SOC2, ISO-27001, and HIPAA compliance mandate tamper-evident audit trails for all data transfers, administrative actions, and data deletion operations.
2. **Operational Alerting**: SRE teams require immediate notification when critical storage anomalies occur (e.g. `ChunkCorrupted`, `TransferFailed`, `ClusterNodeStateChanged`, or multi-region `ConflictResolved`).
3. **Decoupling from Storage Engine**: High-throughput QUIC transfer pipelines (>10 Gbps) cannot perform blocking HTTP calls to third-party endpoints (PagerDuty, Slack, Datadog) without risking pipeline stalls or throughput collapse.
4. **Endpoint Failure & Replay Protection**: Webhook endpoints experience transient outages and link failures. Without automated retries and dead-letter queues (DLQ), notifications are permanently lost. Furthermore, webhooks delivered over public networks must verify origin and reject spoofing or replay attacks.

## Options Considered

1. **Synchronous HTTP Webhooks on Transfer Path**:
   - Issue blocking HTTP POST requests inline during file commit or failure callbacks.
   - *Rejected*: Third-party endpoint latency (200ms–2000ms) directly degrades bulk transfer performance; downstream network downtime can fail user transfers.
2. **External Message Broker Dependency (Apache Kafka / RabbitMQ / NATS)**:
   - Offload events to an external message broker cluster.
   - *Rejected*: Adds heavy external operational dependencies, complex clustering, and violates the zero-external-runtime single-binary architecture.
3. **Pluggable In-Process Event Bus with HMAC Signing, Retries & Dead-Letter Queue (Option BB)**:
   - Pure-Rust, asynchronous `WebhookEventBus` with decoupled subscription dispatch.
   - HMAC-SHA256 request signing with timestamp header (`t={ts},v1={hmac}`) and constant-time verification for replay and tamper prevention.
   - Granular event filtering per subscription (`WebhookEventType`).
   - Exponential backoff retries with bounded Dead-Letter Queue (`WebhookDeadLetterQueue`) for failed delivery buffering and operator replay.
   - Pluggable `WebhookDeliverySink` trait allowing hermetic mock testing and production HTTP dispatch.

## Decision

Option 3. Velcrux implements a pluggable webhook event notification and audit bus (`WebhookEventBus`) under `#![forbid(unsafe_code)]` with zero external C dependencies.

## Architecture & Implementation

### 1. Event Model & Lifecycle Classification

The bus recognizes 8 standardized system and transfer lifecycle events (`WebhookEventType`):
- `TransferStarted` (`transfer.started`): Data transfer session initiated.
- `TransferCompleted` (`transfer.completed`): Data transfer successfully committed.
- `TransferFailed` (`transfer.failed`): Transfer aborted due to network or validation errors.
- `ChunkCorrupted` (`chunk.corrupted`): Checksum validation failure or bit rot detected.
- `ClusterNodeStateChanged` (`cluster.node_changed`): Quorum node transition (Healthy, Suspect, Dead).
- `ConflictResolved` (`geo.conflict_resolved`): Concurrent WAN replication conflict resolved.
- `TombstonePruned` (`geo.tombstone_pruned`): Deletion tombstone expired and purged.
- `AuditAction` (`audit.action`): Administrative security or configuration modification.

### 2. Standardized JSON Payload Schema

Every webhook dispatch carries a structured JSON payload:
```json
{
  "event_id": "evt-1710000000123456789",
  "event_type": "transfer.completed",
  "timestamp": 1710000000,
  "origin_node": "cluster-node-alpha",
  "data": {
    "transfer_id": "tx-99482",
    "bytes": 1048576,
    "elapsed_ms": 124
  }
}
```

### 3. HMAC-SHA256 Signatures & Constant-Time Replay Protection

Each outgoing request includes a signature header (`X-Velcrux-Signature`):
```text
X-Velcrux-Signature: t=1710000000,v1=5d41402abc4b2a76b9719d911017c592...
```
1. **Signature Calculation**: $\text{HMAC-SHA256}(\text{secret}, t \mathbin{\Vert} "." \mathbin{\Vert} \text{payload\_json})$.
2. **Replay Window Tolerance**: Endpoints verify that $|t_{\text{current}} - t| \le \Delta t_{\text{tol}}$ (default: 300 seconds).
3. **Constant-Time Verification**: Verifications use `ring::hmac::verify` to prevent timing side-channel vulnerabilities.

### 4. Exponential Backoff & Dead-Letter Queue (DLQ)

When endpoint delivery fails:
1. The dispatcher retries up to `max_retries` times (default: 3) with exponential backoff.
2. If all retries are exhausted, the event is routed to the `WebhookDeadLetterQueue` with failure reason, attempts made, and timestamp.
3. Operators can inspect or drain the DLQ via `velcrux webhook dlq [--drain]`.

### 5. CLI Interface

```bash
# List configured subscriptions and real-time delivery metrics
velcrux webhook list [--json]

# Send a signed test ping webhook notification
velcrux webhook test https://hooks.slack.com/services/... --secret mysecret --event chunk.corrupted [--json]

# Inspect or clear the dead-letter queue
velcrux webhook dlq [--drain] [--json]
```

## Consequences

### Positive
- Fully decoupled, zero-latency overhead on high-speed QUIC transfers.
- Strict HMAC-SHA256 authentication eliminates spoofing and replay risks.
- Resilient against downstream endpoint outages via automatic retries and DLQ buffering.
- Hermetic testability with zero network port requirements via `MockWebhookSink`.

### Neutral
- Long-term persistent DLQ across server restarts relies on persistent state store ledger entries when configured.
