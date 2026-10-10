# ADR-010: QUIC Connection Migration & Failover Gating

Status: Accepted · Date: 2026-10-09

## Problem

Per `REQUIREMENTS.md` §74 ("Multipath and Failover"), mobile workstations, field edge nodes, and multi-homed servers frequently encounter network interface transitions:
- Wi-Fi to 5G/LTE failover.
- Cellular roaming across towers.
- Dual-homed WAN route flaps.
- Carrier-grade NAT (CGNAT) rebinding.

Under traditional TCP-based transfer protocols (rsync, scp, sftp), an IP or port change breaks the TCP 4-tuple, resulting in immediate `ECONNRESET` or hung sockets, killing in-flight transfers.

## Options

1. **Fail and Resume**: Treat IP change as fatal. Client disconnects, establishes a new connection, and resumes from the last SQLite checkpoint.
2. **Application-Layer Session Reconnect**: Implement a custom application heartbeat protocol that renegotiates socket associations on top of UDP or TCP.
3. **Native RFC 9000 §9 QUIC Connection Migration with Failover Gating**: Leverage QUIC's endpoint-independent Connection IDs (CIDs) and PATH_CHALLENGE / PATH_RESPONSE verification, augmented with enterprise security gating policies (`MigrationCoordinator`).

## Decision

Option 3. Velcrux natively supports QUIC Connection Migration per RFC 9000 §9, coordinated through `MigrationCoordinator` and `MigrationPolicy`.

Option 1 is rejected because re-establishing connections on every Wi-Fi / cellular transition causes unacceptable transfer stutter and latency spikes on WANs.
Option 2 is rejected because building a custom reconnect protocol reinvents QUIC's cryptographically authenticated migration machinery and invites race conditions.

## Policy & Security Gating

Unrestricted connection migration can introduce security risks, such as traffic redirection or amplification attacks from spoofed source addresses. Velcrux implements three operational policy tiers:
1. `MigrationPolicyMode::Permissive`: Accepts all valid RFC 9000 validated migrations (ideal for developer and field mobile workstations).
2. `MigrationPolicyMode::Gated`: Restricts migrations to specific CIDR subnets (e.g., corporate VPN or campus IP blocks) and enforces a sliding rate limit (default: 5 migrations per 60 seconds).
3. `MigrationPolicyMode::Disabled`: Enforces strict single-endpoint pinning for high-security zero-trust perimeters.

## Anti-Amplification & Path Validation

QUIC's cryptographic path validation requires the migrating peer to respond to a randomized 64-bit `PATH_CHALLENGE` frame with a corresponding `PATH_RESPONSE` before the server sends data beyond 3× the validated bytes received. Combined with mTLS SAN URI identity binding, connection hijacking is cryptographically prevented.

## Consequences

- Clients can roam seamlessly across network interfaces mid-transfer without dropping control or data streams.
- Socket rebinding is exposed via `QuicTransport::rebind(UdpSocket)`.
- Telemetry events are broadcast via Tokio broadcast channels to observability pipelines.
- Metrics are tracked: `migrations_total`, `migrations_accepted`, and `migrations_rejected`.
- Documented in `docs/OPERATIONS.md` §24.
