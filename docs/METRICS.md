# Velcrux Telemetry & Prometheus Metrics Reference

This document provides a comprehensive operational reference for all telemetry and Prometheus metrics emitted by `velcruxd` on the `telemetry.metrics_listen` HTTP interface (`OPERATIONS.md` §7, `REQUIREMENTS.md` §14).

---

## 1. Overview & Scraping Architecture

Velcrux embeds a high-performance, non-blocking HTTP metrics server exposing Prometheus text format (`version 0.0.4`), health probes (`/healthz`, `/livez`), readiness probes (`/readyz`), and session operator endpoints (`/admin/sessions`).

### Scraping Configuration

By default, `velcruxd` binds `telemetry.metrics_listen = "127.0.0.1:9443"`. Scrapes should be routed through your internal telemetry network:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'velcrux'
    scrape_interval: 10s
    scrape_timeout: 5s
    static_configs:
      - targets: ['127.0.0.1:9443']
        labels:
          environment: 'production'
          role: 'storage-node'
```

---

## 2. Metric Catalog

### 2.1 Connection & Session Metrics

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `velcrux_connections{state="accepted|active|closed"}` | `gauge` | Current and historical connection counts categorized by lifecycle state. |
| `velcrux_handshakes_total` | `counter` | Total completed TLS 1.3 / mTLS cryptographic handshakes. |
| `velcrux_pings_total` | `counter` | Total low-overhead protocol keepalive PING frames processed. |

### 2.2 Transfer Metrics

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `velcrux_transfers_active` | `gauge` | `direction="bidirectional|upload|download"` | Number of currently executing file transfers. |
| `velcrux_transfers_total` | `counter` | `direction="upload|download"`, `status="committed|resumable|failed"` | Cumulative count of transfer attempts and terminal statuses. |
| `velcrux_transfer_duration_seconds` | `histogram` | `le="0.1", "0.5", "1.0", "5.0", "10.0", "30.0", "60.0", "+Inf"` | Distribution of end-to-end transfer completion durations in seconds. |

### 2.3 Throughput & Data Volume

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `velcrux_bytes_transferred_total` | `counter` | `direction="upload|download"` | Total payload and overhead bytes moved over QUIC streams. |
| `velcrux_bytes_reused_total` | `counter` | _None_ | Total bytes preserved locally via checkpoint resume or CDC reuse. |
| `velcrux_bytes_saved_total` | `counter` | _None_ | Total bytes spared from wire transmission via deduplication, delta transfers, and sparse zero skipping. |
| `velcrux_throughput_bps` | `gauge` | `direction="upload|download"` | Current instantaneous wire bandwidth utilization in bits per second. |

### 2.4 QUIC Transport & Network Health

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `velcrux_rtt_seconds` | `histogram` | Observed smoothed round-trip time (`smoothed_rtt`) histogram across active QUIC connections. |
| `velcrux_quic_loss_ratio` | `gauge` | Moving average packet loss ratio from `0.0` (0%) to `1.0` (100%). |
| `velcrux_quic_bytes_in_flight` | `gauge` | Total unacknowledged data bytes buffered in the congestion controller window across active streams. |

### 2.5 Storage, Deduplication & Chunk Cache

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `velcrux_chunk_hit_ratio` | `gauge` | Content-addressed chunk store index hit ratio (`chunk_hits / chunk_lookups`), bounded `0.0` to `1.0`. |
| `velcrux_dedup_ratio` | `gauge` | Cumulative storage savings ratio from multi-file content-defined deduplication. |
| `velcrux_disk_read_bps` | `gauge` | Disk read throughput sustained by storage backend in bytes per second. |
| `velcrux_disk_write_bps` | `gauge` | Disk write throughput sustained by staging and destination commits in bytes per second. |

### 2.6 Security, Integrity & Enforcements

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `velcrux_checksum_mismatch_total` | `counter` | `side="server|source|destination"` | Number of cryptographic integrity discrepancies detected during chunk or whole-file verification. **Should always be zero.** |
| `velcrux_auth_failures_total` | `counter` | `reason="invalid_cert|bad_token|crl_revoked|max_attempts_exceeded"` | Failed mTLS or token authentication attempts. |
| `velcrux_authz_denials_total` | `counter` | `op="all|read|write"` | Authorization grant violations rejected by `FileAuthorizer`. |
| `velcrux_resource_limit_hits_total` | `counter` | `limit="bandwidth|quota|connections|disk_full|protocol_violation"` | Client requests throttled or rejected due to policy constraints. |
| `velcrux_disk_full_total` | `counter` | _None_ | Storage space exhaustion (`ENOSPC`) rejections safeguarding backend min-free reservations. |
| `velcrux_protocol_violations_total` | `counter` | _None_ | Malformed frames, unexpected state transitions, or illegal sequence numbers rejected by protocol state machines. |

### 2.7 System Resources & Health

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `velcrux_process_cpu_seconds` | `counter` | Cumulative user and system CPU time spent by the daemon process. |
| `velcrux_process_resident_bytes` | `gauge` | Resident set size (RSS) memory consumption in bytes. |

---

## 3. Recommended Prometheus Alerting Rules

Operational alerts recommended for 24/7 production clusters:

```yaml
groups:
  - name: velcrux-alerts
    rules:
      - alert: VelcruxChecksumMismatch
        expr: increase(velcrux_checksum_mismatch_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Cryptographic hash mismatch detected on {{ $labels.instance }}"
          description: "Checksum mismatch on side={{ $labels.side }}. Indicates network corruption, storage hardware degradation, or tampering."

      - alert: VelcruxAuthzDenialSpike
        expr: rate(velcrux_authz_denials_total[5m]) > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Spike in authorization denials on {{ $labels.instance }}"
          description: "High rate of unauthorized path access attempts detected (rate > 5 denials/sec)."

      - alert: VelcruxDiskSpaceExhausted
        expr: increase(velcrux_disk_full_total[5m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Velcrux rejecting transfers due to ENOSPC disk full reservation"
          description: "Storage backend free space has dipped below the configured safety threshold."

      - alert: VelcruxHighPacketLoss
        expr: velcrux_quic_loss_ratio > 0.05
        for: 3m
        labels:
          severity: warning
        annotations:
          summary: "Sustained high QUIC packet loss on {{ $labels.instance }}"
          description: "QUIC loss ratio is {{ $value | humanizePercentage }}, exceeding 5% threshold."
```
