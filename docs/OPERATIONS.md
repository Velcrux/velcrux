# OPERATIONS

## 1. Supported platforms

| Platform         | Server | Client | Notes                                        |
|------------------|--------|--------|----------------------------------------------|
| Linux x86_64     | Yes    | Yes    | Primary target; `openat2` on kernel ≥ 5.6    |
| Linux aarch64    | Yes    | Yes    | Tested, not perf-tuned                       |
| macOS            | No     | Yes    | Client only; no sparse-file support           |
| Windows          | No     | No     | Path validation is written for it; untested   |

Kernel ≥ 5.6 is strongly recommended on the server. Below that, path resolution
falls back to per-component `O_NOFOLLOW` checks — sound, but with more moving
parts (`SECURITY.md` §4).

## 2. Install and layout

```
/usr/local/bin/velcruxd
/usr/local/bin/velcrux
/etc/velcrux/server.toml
/etc/velcrux/server.crt        0644 root:root
/etc/velcrux/server.key        0600 velcrux:velcrux       ← startup fails if group/world-readable
/etc/velcrux/clients-ca.crt
/var/lib/velcrux/              state.db, staging/, manifests/
/data/velcrux/files/           storage root
/data/velcrux/chunks/          chunk store (optional)
```

`storage.root` and `storage.staging` **must be on the same filesystem** so that
commit is an atomic `rename`. The server checks this at startup and refuses to
start otherwise rather than silently degrading to copy-then-delete, which would
break the atomicity guarantee without any visible symptom.

Run as a dedicated unprivileged user. The server needs no capabilities: binding
7443/udp is above 1024.

## 3. systemd

`/etc/systemd/system/velcruxd.service`:

```ini
[Unit]
Description=velcrux transfer server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=velcrux
Group=velcrux
ExecStart=/usr/local/bin/velcruxd --config /etc/velcrux/server.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=120

# graceful drain: stop accepting, checkpoint, persist, close
KillSignal=SIGTERM

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/velcrux /data/velcrux
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
MemoryMax=8G
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

`TimeoutStopSec=120` gives a drain window. `SIGTERM` starts graceful shutdown:
stop accepting new transfers → checkpoint active ones → persist resumable state →
close connections. In-flight transfers become `RESUMABLE` and clients resume
against the same transfer IDs after restart. `SIGKILL` is safe too — it just costs
up to one checkpoint interval of rework.

`SIGHUP` reloads certificates, the CRL, and grants without dropping connections.
It does not reload listen address, storage paths, or limits; those need a restart.

## 4. Configuration reference

```toml
[network]
listen           = "0.0.0.0:7443"
max_bandwidth    = "10Gbps"      # global server cap; "unlimited" to disable
max_connections  = 100
max_connections_per_ip = 10
max_connections_unauth = 20
idle_timeout     = "60s"
keepalive        = "15s"

[quic]
receive_window        = "384MiB"  # ≥ 2 × BDP. See PERFORMANCE.md §9
stream_receive_window = "384MiB"
max_concurrent_streams = 32
initial_rtt           = "150ms"   # hint for known-long links
gso                   = true

[transfer]
chunking          = "cdc"         # "cdc" | "fixed" | "fastcdc"
chunk_min         = "256KiB"
chunk_target      = "1MiB"
chunk_max         = "4MiB"
parallelism       = 8
resume            = true
compression       = "none"        # "none" | "zstd"
checkpoint_bytes  = "1GiB"
checkpoint_secs   = 10
read_buffer       = "2MiB"
max_file_size     = "64TiB"
max_manifest_entries = 50_000_000

[hash]
algorithm = "blake3"              # "blake3" | "sha256"
workers   = 0                     # 0 = cores - 2

[security]
certificate = "/etc/velcrux/server.crt"
private_key = "env:VELCRUX_SERVER_KEY"   # or a file path
client_ca   = "/etc/velcrux/clients-ca.crt"
crl         = "/etc/velcrux/clients.crl"
max_auth_attempts = 3

[storage]
root           = "/data/velcrux/files"
staging        = "/data/velcrux/files/.velcrux-staging"
state_db       = "/var/lib/velcrux/state.db"
chunk_store    = "/data/velcrux/chunks"     # omit to disable dedup
min_free_space = "1GiB"                     # fail closed with 4002 DiskFull if disk space falls below margin
preallocate    = true                       # physical block allocation (fallocate) for staging files

[telemetry]
metrics_listen = "127.0.0.1:9443"
log_format     = "json"              # "json" | "text"
log_level      = "info"

[[grant]]
identity    = "svc-replica"
path        = "/customerA"
permissions = ["upload", "download", "list", "sync", "resume"]

[[limits]]
identity    = "svc-replica"
max_bandwidth = "2Gbps"
quota_bytes   = "50TiB"
soft_quota_bytes = "45TiB"       # warning threshold before hard quota rejection
```

Every value can be overridden by environment variable using the path in caps with
underscores: `VELCRUX_NETWORK_MAX_BANDWIDTH`, `VELCRUX_STORAGE_ROOT`. No environment-
specific path is compiled in; every default is overridable.

The config is validated fully at startup and the server refuses to start on any
invalid value rather than falling back to a default — a silently-defaulted
security setting is worse than a failed start.

## 5. Network, NAT, and firewall

- **UDP 7443 inbound** to the server. That is the only requirement. There is no
  TCP fallback and no second port.
- QUIC needs the **same 5-tuple** for the connection's life. A NAT or stateful
  firewall that rebinds UDP mappings will break connections; QUIC connection IDs
  allow migration, and quinn handles the client's address changing, but a
  middlebox that drops the flow entirely will surface as an idle timeout.
- **Set NAT/firewall UDP timeout above 15 s** or raise `keepalive` to stay under
  it. Many consumer NATs use 30 s; some use 10 s. Symptom of getting this wrong:
  transfers die after a fixed idle interval and resume cleanly on retry.
- Path MTU: QUIC does its own PMTU discovery. **Do not block ICMP** *needs
  fragmentation* / *packet too big*; blocking it forces a conservative small
  datagram size and costs real throughput.
- Rate limiters and DPI middleboxes sometimes deprioritize or police bulk UDP. If
  measured throughput is far below the link and loss is high but netem-free,
  suspect policing before suspecting the code.
- Raise UDP socket buffers for ≥ 10 Gbps:
  ```
  net.core.rmem_max = 33554432
  net.core.wmem_max = 33554432
  ```
  This is one of the two most common causes of disappointing WAN throughput; the
  other is the receive window.
- No custom NAT traversal is implemented and none is planned. Servers are assumed
  reachable.

## 6. Runbooks

### Transfers slower than expected on a WAN

Check in this order: `quic.receive_window` against BDP (`bandwidth × RTT`); UDP
socket buffers; whether GSO is on; whether the disk is the ceiling
(`/metrics` disk throughput vs network); CPU per Gbps against the 0.5 target;
then middlebox policing.

### An interrupted COMMIT left the directory half-updated

Expected and recoverable. Whole-directory commit is not atomic
(`ARCHITECTURE.md` §9); per-file commit is. The commit journal in `state.db`
records exactly which renames completed. Re-run the same `velcrux sync` with the same
idempotency key, or `velcrux resume <transfer-id>` — it replays only the remaining
renames. No individual file is ever left partially written.

### Disk full

Transfers stop with `DISK_FULL` and go `RESUMABLE`. Staging is retained
deliberately. Free space, then resume. To reclaim without resuming, cancel the
transfer, which removes its staging directory. Orphaned staging directories from
transfers that will never resume are cleaned by `velcruxd gc --staging`, which
only removes directories whose transfer is in a terminal state.

### Chunk-store growth

Dedup stores keep chunks until nothing references them. `velcruxd gc --chunks
--dry-run` reports unreferenced chunks; without `--dry-run` it removes them. GC
takes a reference-tracking lock, so it is safe alongside active transfers, but run
it in a quiet window — it is random-read heavy. It never deletes a chunk with a
live reference, and there is no automatic deletion.

For bounded cache topologies, `LocalChunkStore::prune_cache` provides automated
LRU, capacity-based (`max_bytes`, `max_chunks`), and time-to-live (`ttl`) eviction.
Live transfers acquire reference pins (`ChunkPin`), guaranteeing that active chunks
are immune to pruning sweeps. The internal Bloom filter is automatically rebuilt
following any pruning operation.

### Repeated `CHECKSUM_MISMATCH`

Chunks are being corrupted between hashing and verification. QUIC's AEAD makes
on-path corruption essentially impossible, so suspect, in order: source-side
memory (run memtest), source disk (read errors), destination disk, and a version
mismatch in chunking parameters. The mismatch counter in `/metrics` is broken down
by source and destination side, which localizes it quickly.

### Certificate rotation

Replace the cert and key, then `systemctl reload velcruxd`. Existing connections
keep their handshaken identity; new connections use the new cert. Rotate the client
CA by adding the new CA to the bundle, waiting for clients to migrate, then
removing the old one. Never rotate both ends simultaneously.

### Revoking a client

Add the certificate to the CRL and `SIGHUP`. Existing connections are **not**
dropped by a reload — identity is bound at handshake. To terminate active sessions
for a revoked identity, also remove its grant and restart, or use
`velcruxd kill-session --identity <name>`.

## 7. Metrics

Prometheus format on `telemetry.metrics_listen`, bound to localhost by default.
Expose it through your own scrape path; do not put it on a public interface.

```
velcrux_transfers_active{direction}
velcrux_transfers_total{direction,status}
velcrux_bytes_transferred_total{direction}
velcrux_bytes_reused_total
velcrux_bytes_saved_total
velcrux_throughput_bps{direction}
velcrux_transfer_duration_seconds        histogram
velcrux_rtt_seconds                      histogram
velcrux_quic_loss_ratio
velcrux_quic_bytes_in_flight
velcrux_chunk_hit_ratio
velcrux_dedup_ratio
velcrux_checksum_mismatch_total{side}
velcrux_auth_failures_total{reason}
velcrux_authz_denials_total{op}
velcrux_resource_limit_hits_total{limit}
velcrux_disk_read_bps  velcrux_disk_write_bps
velcrux_connections{state}
velcrux_process_cpu_seconds  velcrux_process_resident_bytes
```

Worth alerting on: `velcrux_checksum_mismatch_total` rising at all (it should be
zero — a nonzero rate means hardware or a real bug), `velcrux_authz_denials_total`
spiking (probing), `velcrux_resource_limit_hits_total` sustained (undersized limits or
an abusive client), and `velcrux_process_resident_bytes` exceeding the expected
ceiling from `PERFORMANCE.md` §2 (a bounded-memory regression).

## 8. Logs

Structured JSON by default, with `ts`, `level`, `component`, `conn_id`,
`transfer_id`, `file_id`, `identity`, `msg`. Never contains keys, tokens,
signatures, or configuration dumps (`SECURITY.md` §7).

`log_level = "debug"` adds per-message protocol tracing and is loud enough to
affect throughput at high rates; use it on a single connection, not a busy server.

## 9. Docker

A minimal image is provided for deployment convenience. It is not required for
development and not the recommended production deployment — the systemd unit gives
better control over resource limits and filesystem confinement.

```bash
docker run --rm \
  -p 7443:7443/udp \
  -v /etc/velcrux:/etc/velcrux:ro \
  -v /data/velcrux:/data/velcrux \
  -v /var/lib/velcrux:/var/lib/velcrux \
  velcruxd:latest --config /etc/velcrux/server.toml
```

Mind two things: the port must be mapped as **UDP**, and the state, staging, and
storage volumes must persist across container restarts or resume stops working.

## 10. Capacity planning

- Memory: roughly `parallelism × chunk_max × 4` for buffers, plus the QUIC windows
  per connection, plus ~100 MiB base. With defaults and 100 connections, budget
  8 GiB and enforce it via `MemoryMax`.
- CPU: budget 0.5 core per sustained Gbps, plus one core for the QUIC driver.
- Disk: the storage root, plus staging headroom equal to the largest concurrent
  transfer set. Staging is not free space you can count on.
- Chunk store index: ~40 bytes per chunk, so ~42 MB per TB at 1 MiB chunks.
- State DB: small — tens of MB even with many transfers. Put it on reliable
  storage; losing it loses resumability, not data.

## 11. Documented limitations

- Whole-directory commit is not atomic. Per-file commit is.
- POSIX metadata: Extended Attributes (`xattr`) are supported via canonical binary serialization (`.velcrux-xattr` sidecars and `TransferOp::SetXattr` with namespace security validation); symbolic link replication preserves relative link targets with strict lexical containment defense; POSIX permissions (`mode`) and timestamps (`mtime`) are preserved on destination files. Windows ACL inheritance remains OS-managed.
- No Windows server.
- CRL-based revocation only; no OCSP.
- Server must be directly reachable on UDP; no NAT traversal.
- Sparse-file support is Linux-only; elsewhere holes are written as zeros.
- Chunk-store GC is manual by default; automated LRU/TTL cache pruning is available via `LocalChunkStore::prune_cache`.

## 12. Adaptive Cost Estimator & Transfer Mode Selection (Option AD)

Velcrux incorporates an empirical, network-aware cost estimator (`REQUIREMENTS.md` §55, §88) that dynamically selects between **Direct Stream** and **Delta CDC Reconstruction**:

```text
FullCost  = (file_size / network_bw) + rtt_overhead + (file_size / disk_write_bw)
DeltaCost = (file_size / min(disk_read_bw, hash_bw)) + (delta_rtts × RTT) + (changed_bytes / network_bw) + (reused_bytes / disk_read_bw) + (file_size / disk_write_bw)
```

- **Automatic Selection (`--mode auto`, default)**: Dynamically derives link bandwidth and RTT from live QUIC transport stats (`cwnd / rtt`) and evaluates if data reuse outweighs disk scanning and negotiation latency.
- **Forced Direct Stream (`--mode direct` / `--mode full`)**: Bypasses chunking and negotiation, immediately streaming data over the wire for optimal throughput on high-bandwidth LANs.
- **Forced Delta CDC (`--mode deltacdc` / `--mode fastcdc`)**: Enforces FastCDC chunk negotiation, minimizing bytes sent over metered or high-latency WAN connections.
- **Network Profiles (`--network-profile <auto|lan|wan|satellite>`)**: Supplies network latency and bandwidth presets (`lan` = 10 Gbps / 0.5ms, `wan` = 100 Mbps / 30ms, `satellite` = 15 Mbps / 250ms).
- **Minimum Delta Size Threshold (`--min-delta-size <bytes>`, default 64 KiB)**: Files below this threshold are automatically transferred as direct streams to eliminate multi-roundtrip negotiation overhead.

## 13. Multi-Homed Network Interface & Source IP Binding (Option AE)

Velcrux supports multi-homed hosts and network segmentation (`REQUIREMENTS.md` §74, §75) on both client and server deployments without requiring elevated privileges:

### Client Configuration
By default, the client binds to `0.0.0.0:0` (or `[::]:0` for IPv6 targets). When operating on multi-homed workstations or edge routers with segregated management and storage networks (e.g. 100GbE SAN alongside a 1GbE LAN), traffic can be forced out of a specific interface or IP:
- `--bind-ip <IP>` (env: `VELCRUX_BIND_IP`): Explicit source IP address to bind to for outgoing QUIC UDP packets.
- `--bind-interface <IFACE>` (env: `VELCRUX_BIND_INTERFACE`): Interface name (e.g. `eth1`, `en0`) whose IP address is automatically resolved.
- `--bind-port <PORT>` (env: `VELCRUX_BIND_PORT`, default: `0`): Local source UDP port.

### Server Configuration
In `server.toml`, servers can bind to specific physical or virtual network interfaces:
```toml
[network]
listen         = "0.0.0.0:7443"
bind_interface = "eth1" # Resolves interface IP and binds endpoint socket
```
Or via environment variable:
```bash
VELCRUX_NETWORK_BIND_INTERFACE=eth1 velcruxd --config /etc/velcrux/server.toml
```

### Destination Address Family Matching
When `--bind-interface` or wildcard defaults are used, Velcrux dynamically inspects the destination target's address family (`IPv4` vs `IPv6`) and binds the local socket to a compatible IP address on the interface, preventing socket family mismatch errors in QUIC.

## 14. Priority Scheduling & Concurrent Transfer Control (Option AF)

Velcrux implements priority-weighted bandwidth allocation and bounded concurrency control (`REQUIREMENTS.md` §24, §25, §29, `ARCHITECTURE.md` §1):

### Priority Tiers and Deficit Round-Robin (DRR)
Transfers and streams are scheduled according to four prioritized tiers:
- **Urgent (`urgent`, weight 8×)**: Dedicated to control frames, directory manifests, ping probes, or high-priority interactive jobs. Supports immediate preemption via `pop_next_urgent_preemptive()`.
- **High (`high`, weight 4×)**: Expedited bulk file transfers.
- **Normal (`normal`, weight 2×, default)**: Standard bulk file transfers.
- **Low (`low` / `background`, weight 1×)**: Routine background synchronization and archival replication.

Unlike strict priority schedulers that can completely starve low-priority tasks under sustained high-priority load, Velcrux employs **Deficit Round-Robin (DRR)** fair queueing. Each tier accumulates deficit credits proportional to its weight in each scheduling round, ensuring lower-priority tasks are guaranteed forward progress while higher-priority tasks receive proportionally larger bandwidth and execution quanta.

### Bounded Concurrency Limiter
Active parallel transfers are governed by `ConcurrentTransferLimiter`:
- Enforces an upper bound on active transfers (`active_transfers <= max_concurrency`).
- When all execution slots are full, waiting tasks queue in priority-ordered buckets (`Urgent > High > Normal > Low`).
- When an active transfer completes, its permit drop automatically wakes the highest-priority waiting transfer first.

### Client Configuration
- `--priority <urgent|high|normal|low>` (env: `VELCRUX_PRIORITY`, default: `"normal"`): Sets the transfer priority tier.
- `--concurrency <N>` (env: `VELCRUX_CONCURRENCY`, default: `4`): Configures the maximum number of concurrent file transfers allowed.

### Server Configuration
In `server.toml`, servers can restrict max concurrent transfers per session or overall:
```toml
[transfer]
max_concurrent_transfers = 16 # Must be > 0
```
Or via environment override:
```bash
VELCRUX_TRANSFER_MAX_CONCURRENT_TRANSFERS=16 velcruxd --config /etc/velcrux/server.toml
```

## 15. REST Control Plane, Operator Management API & Live Telemetry Dashboard (Option AG)

`velcruxd` embeds an asynchronous HTTP management control plane and live web dashboard (`REQUIREMENTS.md` §36, §38, §81):

### Configuration
Enabled via `[telemetry] metrics_listen` in `server.toml` (e.g. `metrics_listen = "127.0.0.1:9443"`) or environment variable `VELCRUX_TELEMETRY_METRICS_LISTEN`.

### REST API v1 Surface (`/api/v1/`)
- `GET /api/v1/status`: Comprehensive node operational report in machine-readable JSON:
  - Daemon version, uptime, QUIC listening address, readiness state.
  - Active and total connection counts, active transfers (upload/download), committed transfers.
  - Real-time wire throughput in bits/sec (upload/download).
  - Storage statistics: total transferred, reused, saved via dedup/sparse, dedup ratio, chunk cache hit ratio.
  - Process metrics: CPU time and resident memory (RSS).
- `GET /api/v1/sessions`: Active client session registry:
  - List of sessions with `conn_id`, authenticated `identity`, `remote_addr`, and `uptime_secs`.
- `POST /api/v1/sessions/kill` / `DELETE /api/v1/sessions`: Terminate active connections:
  - Parameters: `?conn_id=<ID>` or `?identity=<NAME>`.
  - Returns `{"killed": N}`.
- `GET /api/v1/quotas`: Multi-tenant quota accounting and current usage:
  - List of configured tenants, current storage usage, quota caps, soft quotas, bandwidth limits, and in-flight reservations.
- `POST /api/v1/gc`: On-demand disk garbage collection sweep:
  - Parameters: `?dry_run=true|false&staging=true|false&chunks=true|false`.
  - Returns structured `ChunkStoreGcReport` and `StagingGcReport` with total reclaimed bytes.

### Live Operator Web Dashboard (`/` and `/dashboard`)
Accessing `http://<metrics_listen>/` or `http://<metrics_listen>/dashboard` renders an embedded Single-Page Application:
- **Aesthetic Dark Theme**: Engineered with deep space palette (`#090D16`), glowing glassmorphism cards, and high-contrast typography.
- **Real-Time Telemetry Cards**: Live-updating connection counts, throughput meters, active transfer counters, and deduplication savings.
- **Active Sessions Table**: Real-time connection list with interactive "Terminate" action buttons.
- **Tenant Quotas Overview**: Storage and transfer usage breakdown per tenant.
- **Storage Maintenance Panel**: One-click "Run Garbage Collection" button providing instant feedback on reclaimed disk space.
- **Air-Gap Capability**: 100% self-contained with zero CDN or external font dependencies, operating reliably in isolated network enclaves.

### Observability & Probes
- `GET /metrics`: Standard Prometheus text format (v0.0.4) metrics.
- `GET /healthz`, `/livez`: Liveness probe (`healthy`).
- `GET /readyz`: Readiness probe (`ready` with HTTP 200, or `unready` with HTTP 503).

## 16. Kernel Zero-Copy, Page-Cache Bypass & Direct I/O (Option AH)

Velcrux includes a high-performance, sector-aligned Direct I/O streaming engine (`REQUIREMENTS.md` §26, §27, `ARCHITECTURE.md` §2) designed for multi-gigabyte and multi-terabyte datasets:

### Motivation & Cache Thrashing Prevention
Standard buffered OS filesystem I/O routes all read and write streams through the kernel page cache. For massive file transfers over 10GbE–100GbE networks, streaming hundreds of gigabytes through the page cache causes severe cache thrashing, evicts active working memory sets (such as database caches and application memory), and introduces memory reclaim latency (`kswapd`).

Direct I/O (`O_DIRECT` on Linux, unbuffered streaming on macOS) bypasses the kernel page cache, transferring data directly between storage controllers (DMA) and user-space memory buffers.

### Safe Aligned Sector Buffers (`AlignedSectorBuffer`)
Direct I/O mandates that user-space memory buffers, file offsets, and I/O lengths align to the physical sector size (typically 4096 bytes / 4 KiB). Velcrux implements `AlignedSectorBuffer` in 100% safe Rust without `#![forbid(unsafe_code)]` violations, ensuring physical sector alignment for DMA operations.

### Fractional Sector Tail Truncation
Files rarely align precisely to 4096-byte boundaries. When writing non-sector-aligned files:
1. All full 4096-byte sectors are streamed directly to disk via Direct I/O.
2. The remaining fractional tail is sector-padded, written, and then the file is atomically truncated to the exact file size via `set_len()`.
3. Whole-file BLAKE3 cryptographic verification ensures identical byte-for-byte fidelity.

### Execution Modes
- **`auto` (default)**: Automatically engages Direct I/O for files >= 16 MiB when supported by the underlying filesystem. Falls back gracefully to standard buffered streaming if the filesystem (e.g. tmpfs, NFS) does not support direct flags.
- **`always`**: Strictly enforces Direct I/O; returns an error if unsupported.
- **`disabled`**: Disables Direct I/O, always using standard buffered streaming.

### Client Configuration
```bash
velcrux sync /data /backup --direct-io auto
```
Or via environment variable:
```bash
VELCRUX_DIRECT_IO=auto velcrux sync /data /backup
```

### Server Configuration
In `server.toml`:
```toml
[storage]
root      = "/data/storage"
staging   = "/data/staging"
direct_io = "auto" # "auto", "always", or "disabled"
```
Or via environment override:
```bash
VELCRUX_STORAGE_DIRECT_IO=auto velcruxd --config /etc/velcrux/server.toml
```

## 17. Small Files Container Pipeline & Batch Streaming Archive Engine (Option AI)

Velcrux includes a high-performance small-file batch aggregation and streaming pipeline (`REQUIREMENTS.md` §56, §31, §25) engineered for repositories and datasets with thousands or millions of small files (< 128 KiB):

### The Small Files Bottleneck
In massive file collections containing hundreds of thousands of small files (source repositories, web asset bundles, ML feature datasets):
- Standard synchronization incurs per-file negotiation roundtrips (manifest lookups, stream openings, staging directory creations).
- Transport protocols suffer from connection stall: streams terminate before congestion windows expand to saturate bandwidth.
- Operating systems incur severe inode and metadata lock contention.

### Streaming Container Architecture (`VBATCH/1`)
The batch engine aggregates small files into contiguous, verified streaming containers:
1. **Adaptive Partitioning**: The directory planner inspects candidate `Add` and `Modify` actions. Files smaller than `small_file_threshold` (default: 128 KiB) are bundled into containers up to `batch_max_bytes` (default: 32 MiB) or 1,000 files per batch.
2. **Compact Binary Index**: The `VBATCH/1` container header includes an inline metadata table detailing relative paths (`VPath`), sizes, POSIX permissions, nanosecond modification times, extended attributes, and BLAKE3 hashes.
3. **Contiguous Streaming**: Payloads are streamed sequentially across a single QUIC data stream, reducing network roundtrip overhead by up to 99.9%.
4. **Single-Pass Secure Extraction**: Receivers stream-unpack containers into staging directories, enforcing lexical path traversal boundaries, computing per-file BLAKE3 hashes on-the-fly, restoring POSIX metadata, and validating trailing checksums before atomic commit.

### Client CLI Usage
```bash
# Enable batch container sync (enabled by default)
velcrux sync ./source_tree velcrux://server:7443/data/repo --batch-small-files

# Disable batch container sync (reverts to individual transfers)
velcrux sync ./source_tree velcrux://server:7443/data/repo --no-batch-small-files

# Tune batching thresholds
velcrux sync ./source_tree velcrux://server:7443/data/repo \
  --small-file-threshold 262144 \
  --batch-max-bytes 67108864
```
Or via environment variables:
```bash
VELCRUX_SMALL_FILE_THRESHOLD=262144 VELCRUX_BATCH_MAX_BYTES=67108864 velcrux sync ./source_tree velcrux://server:7443/data/repo
```

### Server Configuration
In `server.toml`:
```toml
[transfer]
batch_small_files    = true
small_file_threshold = "128KiB"
batch_max_bytes      = "32MiB"
```
Or via environment overrides:
```bash
VELCRUX_TRANSFER_BATCH_SMALL_FILES=true \
VELCRUX_TRANSFER_SMALL_FILE_THRESHOLD=128KiB \
VELCRUX_TRANSFER_BATCH_MAX_BYTES=32MiB \
velcruxd --config /etc/velcrux/server.toml
```

## 18. Pluggable Storage Backend Abstraction & In-Memory Storage Engine

Velcrux provides a fully decoupled, polymorphic storage subsystem through the `StorageBackend` trait (`REQUIREMENTS.md` §42, §43). Storage operations (metadata lookup, staged file writes, atomic commits, random reads, directory enumeration, whole-file hash computations, extended attribute management, and content-addressed chunk caching) are abstracted behind dynamic trait objects (`Arc<dyn StorageBackend>`).

### Supported Backends

1. **`local` (Local POSIX Filesystem Engine)**:
   - Default production backend.
   - Utilizes persistent storage directories for `root`, `staging`, and deduplication chunk stores.
   - Enforces same-filesystem atomic commits via atomic POSIX `rename(2)`.
   - Supports direct I/O (`O_DIRECT`), fallocate reservation, and real filesystem metadata.

2. **`memory` (Virtual In-Memory Storage Engine)**:
   - High-performance, 100% safe Rust in-memory virtual filesystem engine (`MemoryStorageBackend`).
   - Zero disk I/O: files, directories, staging buffers, content-addressed chunks, and extended attributes are held entirely in thread-safe memory structures (`tokio::sync::RwLock`).
   - Fully supports transactional staging: writes are isolated per `transfer_id`, and become atomically visible at the destination path only upon `commit()`.
   - Configurable memory quota and disk reservation margin simulation (`min_free_space`), returning `DISK_FULL` when capacities are exceeded.
   - Ideal for hermetic integration testing, CI pipelines, ephemeral transfer caches, and cloud object store staging buffers.

### Server Configuration

In `server.toml`:
```toml
[storage]
root     = "/data/storage"
staging  = "/data/staging"
backend  = "local"       # Options: "local" (default) or "memory"
min_free_space = "1GiB"
```

Or for in-memory mode:
```toml
[storage]
root     = "/virtual/root"
staging  = "/virtual/staging"
backend  = "memory"
min_free_space = "512MiB"
```

### Environment Variable Overrides
The storage backend can be dynamically selected via the `VELCRUX_STORAGE_BACKEND` environment variable without editing configuration files:
```bash
VELCRUX_STORAGE_BACKEND=memory velcruxd --config /etc/velcrux/server.toml
```

### Architecture Invariants & Guarantees
- **Strict `#![forbid(unsafe_code)]`**: All backend implementations are written in 100% safe Rust.
- **Fail-Closed Validation**: Server refuses to boot if `storage.backend` is set to an unsupported value (must be `"local"` or `"memory"`).
- **Same-Filesystem Check Exemption**: The physical same-device check between `storage.root` and `storage.staging` (Section 2) is automatically bypassed when `backend = "memory"`, allowing arbitrary virtual path roots.
- **Content-Addressed Deduplication**: `MemoryStorageBackend` includes a built-in content-addressed chunk store supporting chunk caching, dedup indexing, and hash-based retrieval.

## 19. WAN Impairment Simulation & Multi-Protocol Benchmark Suite

Velcrux includes an automated, in-process WAN impairment simulation and multi-protocol benchmarking harness (`REQUIREMENTS.md` §45–§48, §91, §92). It allows operators and CI pipelines to benchmark high-latency, packet-lossy, and bandwidth-constrained WAN links deterministically on macOS and Linux without requiring root permissions or Linux network namespaces.

### Link Impairment Matrix Parameters

Link profiles (`ImpairmentProfile`) simulate combinations of real-world WAN topologies:

| Profile Name | Round-Trip Latency (RTT) | Loss Rate | Bandwidth Limit | Simulated Environment |
| :--- | :--- | :--- | :--- | :--- |
| **LAN / Local DC** | 1 ms | 0.0% | 10 Gbps | Low-latency local NVMe data center |
| **Metro WAN** | 20 ms | 0.1% | 1 Gbps | Urban regional interconnect / cross-town fiber |
| **Regional WAN** | 50 ms | 0.1% | 1 Gbps | Inter-state data center WAN |
| **Transcontinental WAN** | 100 ms | 0.5% | 1 Gbps | Coast-to-coast long haul (e.g. NYC to SFO) |
| **Cross-Pacific 10G (§48)**| 150 ms | 0.5% | 10 Gbps | Subsea trans-oceanic link (US to Tokyo / Sydney) |
| **Intercontinental WAN** | 200 ms | 1.0% | 1 Gbps | Europe to Asia-Pacific route |
| **Satellite Link** | 300 ms | 2.0% | 100 Mbps | GEO satellite / remote edge deployment |
| **Hostile WAN** | 200 ms | 5.0% | 100 Mbps | High-loss, congested wireless / tactical network |

### Running the Matrix Benchmarks

#### Automated Shell Runner
```bash
# Execute automated WAN impairment matrix and print formatted comparative table
./scripts/netsim.sh matrix

# Output is stored in:
# - benches/results/wan_matrix_latest_report.json (machine-readable)
# - benches/results/wan_matrix_latest_report.md   (GitHub markdown table)
```

#### In-Process Rust Test Suite
```bash
# Run WAN matrix sweep and report generation tests
cargo test -p velcrux-server --test server_wan_matrix -- --nocapture

# Run the flagship §48 benchmark scenario directly
cargo test -p velcrux-server --test server_wan_matrix -- test_scenario_48_flagship_wan_benchmark --nocapture
```

### Inspecting Benchmark Reports
The generated benchmark results can be analyzed using `scripts/bench-report.py`:
```bash
python3 scripts/bench-report.py benches/results
```

### Interpreting Metrics
- **Goodput (Mbps)**: Effective logical transfer speed ($8 \times \text{File Size} / \text{Duration}$). For delta transfers with 99% match, goodput can exceed physical wire link speed by tens of gigabits per second.
- **Wire Efficiency (%)**: Percentage of transfer data saved through CDC chunk reuse and delta reconciliation ($(\text{Avoided Bytes} / \text{File Size}) \times 100\%$).
- **Speedup Factor**: Relative speedup compared to legacy un-chunked TCP streaming under identical RTT and packet loss conditions ($\text{Duration}_{\text{TCP}} / \text{Duration}_{\text{Velcrux}}$).
- **Peak RSS**: Peak working set memory. In accordance with `CLAUDE.md` §1 invariant #3, memory consumption remains strictly bounded (≤ 48 MiB) regardless of whether transferring 100 MB, 10 GB, or 1 TB.

## 20. Protocol Fuzzing Suite, Parser Security Hardening & Zero-Panic Invariants

Velcrux enforces parser security hardening and continuous fuzzing across all untrusted wire and manifest boundaries (`REQUIREMENTS.md` §49, §50, §22, `CLAUDE.md` §1 invariant #5). Because Velcrux daemons and agents process untrusted network packets from potentially adversarial network endpoints, all binary parsers are architected as pure functions over immutable byte slices (`&[u8]`) and are continuously audited for panic-free, bounded-memory execution.

### Parser Security Principles

1. **Strict `#![forbid(unsafe_code)]`**:
   - Zero `unsafe` blocks across all protocol codecs, framing engines, message decoders, manifest processors, and sync container extractors.
2. **Zero Panic Guarantee**:
   - Every decoder is guaranteed to return `Result<T, ProtocolError>` and must NEVER panic or abort, regardless of corrupted bytes, truncated streams, invalid UTF-8, out-of-order varints, or malicious headers.
3. **Integer Overflow & Slice Bounds Hardening**:
   - All slice offsets and buffer range calculations use `checked_add` and `checked_mul`. Calculations that would wrap `usize` or `u64` are caught immediately, returning `ProtocolError::Malformed` or `ProtocolError::FrameTooLarge`.
4. **Defense Against Pre-Allocation Memory Exhaustion**:
   - Decoders that unpack sequences (such as `ListResult`, `ManifestBatchDecoder`, and `FileEntry::decode`) never pre-allocate `Vec::with_capacity(declared_count)` directly from untrusted count headers. Capacities are clamped to `buffer.len() / min_element_size`, preventing memory exhaustion bombs from tiny payload inputs.
5. **Canonical LEB128 Varint Encoding**:
   - All varint decoders enforce minimal byte length canonicality, rejecting over-long or padded encodings (`ProtocolError::NonCanonicalVarint`) to prevent payload smuggling or signature evasion.

### Running Protocol Fuzzing

#### Automated Multi-Suite Runner
To execute the comprehensive in-process protocol fuzzing suite, live server actor fuzzer, and seed corpus boundary matrix:
```bash
./scripts/fuzz.sh
```

#### Running Specific In-Process Test Suites
```bash
# In-process deterministic property-based fuzzer (100,000+ iterations across all 26+ message decoders, frame decoders, and sync primitives)
cargo test -p velcrux-core --test protocol_fuzzing -- --nocapture

# Live ServerConn connection and actor stream fuzzer (adversarial streams, truncated handshakes, oversized declarations)
cargo test -p velcrux-server --test server_fuzzing -- --nocapture

# Committed seed corpus and adversarial boundary matrix
cargo test -p velcrux-server --test fuzz_corpus -- --nocapture
```

#### Continuous Coverage-Guided libFuzzer Execution
When `cargo-fuzz` is installed on developer or CI workstations, coverage-guided LLVM libFuzzer engines can be executed across all six fuzzing targets (`frame_decoder`, `manifest_decoder`, `path_validator`, `config_parser`, `cert_identity`, `vbatch_decoder`):
```bash
# Run 30 seconds per target:
./scripts/fuzz.sh --libfuzzer 30

# Or execute an individual target directly:
cd fuzz
cargo fuzz run frame_decoder -- -max_total_time=60
```
