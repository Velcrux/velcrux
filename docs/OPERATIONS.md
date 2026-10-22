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

## 21. Hardware SIMD Acceleration, Vectorized Hashing & High-Throughput Pipeline Optimization

Per `REQUIREMENTS.md` §73 ("Hardware Acceleration"), §27 ("Zero-Copy / Copy Reduction"), §54 ("Data Pipeline"), and §91 ("Performance Targets"), Velcrux incorporates an automated hardware vectorization probing and multi-core pipelined hashing engine in 100% safe Rust (`#![forbid(unsafe_code)]`).

### Hardware Vectorization Tiers

At startup, both the client (`velcrux`) and server (`velcruxd`) probe the host CPU architecture and available vector instruction sets:

| Architecture | Vector Extension | Register Width | Throughput Profile |
| :--- | :--- | :--- | :--- |
| **x86_64** | AVX-512 Foundation (`avx512f`) | 512 bits | Extreme vectorization (>8 GB/s) |
| **x86_64** | AVX2 (`avx2`) | 256 bits | High vectorization (>6 GB/s) |
| **x86_64** | SSE4.1 (`sse4.1`) | 128 bits | Baseline vectorization (>3 GB/s) |
| **aarch64** | ARM NEON / ASIMD (`neon`) | 128 bits | Apple Silicon / Graviton (>6.8 GB/s) |
| **Generic** | 64-bit Quad-Word Scalar | 64 bits | Portable fallback baseline |

### Inspecting Hardware Capabilities

Operators can inspect the active hardware acceleration profile using the CLI:
```bash
# Human-readable format
velcrux hardware

# Machine-readable JSON output for monitoring / automation
velcrux --json hardware
```
Example JSON output:
```json
{
  "arch": "aarch64",
  "tier": "neon",
  "vector_width_bits": 128,
  "avx512f": false,
  "avx2": false,
  "sse41": false,
  "neon": true,
  "carryless_mul": true,
  "aes": true,
  "description": "aarch64 (NEON, CLMUL/PMULL, AES-NI)"
}
```

### High-Throughput Pipeline Components

1. **Parallel Multi-Core Chunk Hashing (`ParallelHasher`)**:
   - Cryptographic hashing (BLAKE3-256) operates across worker threads via `std::thread::scope`.
   - Slices are borrowed directly with zero heap reallocations and zero unsafe code, achieving over **6.8 GB/s (54 Gbps)** on standard 8-core hardware.
   - Batch verification short-circuits on the first corrupted chunk, returning `ErrorCode::ChecksumMismatch (3000)`.

2. **Vectorized Zero-Block Scanning (`VectorizedScanner`)**:
   - Zero-block and hole detection for sparse files scans memory in 64-byte `u128` unrolled blocks.
   - LLVM automatically compiles these checks into hardware vector instructions (`VPTEST` on AVX2, `UMAXV` on NEON), reaching **>34 GB/s** scan speeds.

3. **Pipelined Ingestion (`PipelinedChunker`)**:
   - Decouples disk prefetch reads, FastCDC rolling chunk boundary detection, and cryptographic hashing into an asynchronous pipeline.
   - Channel capacities are strictly bounded (e.g. 32 chunks / ~32 MiB), enforcing memory ceiling invariants (`CLAUDE.md` §1 invariant #3, `REQUIREMENTS.md` §23) under backpressure.

### Running Microbenchmarks

To evaluate hashing and scanner throughput on the current host machine:
```bash
cargo bench -p velcrux-core --bench microbenchmarks
```

---

## 22. Transfer Idempotency, Session Replay Protection & Checkpoint Coordination

To eliminate duplicate transfer execution, eliminate race conditions on network reconnects, and survive unexpected interruptions without data corruption, Velcrux implements a two-tier **Idempotency Ledger** combined with an autonomous **Checkpoint Coordinator** (`REQUIREMENTS.md` §67, §68, §69, §70; `ADR-005`).

### Idempotency Key Semantics

Every `TRANSFER_CREATE` packet includes a unique `idempotency_key` (typically client-generated ULID or deterministic application UUID). The server tracks the key across both memory and persistent storage:

1. **In-Memory Fast-Path (`IdempotencyLedger`)**:
   - Maintains an active cache of in-flight and recently completed transfers indexed by `(Role, IdempotencyKey)`.
   - Protects against concurrent race conditions when duplicate `TRANSFER_CREATE` frames arrive concurrently across streams.
2. **Persistent Fallback (`StateStore` / `sqlite`)**:
   - If an idempotency key is not in the in-memory cache (e.g. after daemon restart), the server queries the SQLite state database (`get_transfer_by_idempotency`).
   - If found, the transfer state is dynamically reloaded into the in-memory ledger.

### Session Replay Actions

When receiving a `TRANSFER_CREATE` request:
- **`ProceedNew`**:
  - The key has never been seen. The server generates a fresh ULID `TransferId`, records it in the ledger as `Active`, and begins transfer negotiation.
- **`ReplayActive`**:
  - The key is currently active on an existing connection or stream. The server rejoins the transfer, returning `TRANSFER_CREATED` with `resumed = true` and the reusable byte offset, avoiding duplicate worker spawn.
- **`ReplayCommitted`**:
  - The key represents a transfer that has already finished and committed. The server **immediately** returns a `COMMITTED` message frame without touching staging disk I/O or streaming duplicate chunks.
- **`ResumeExisting`**:
  - The key matches a previously interrupted transfer in `Resumable` state. The server reports the existing `TransferId` and bitmap progress to resume incrementally.
- **`Conflict` (Fail-Closed Rejection)**:
  - If a caller supplies an existing idempotency key but alters the destination path (`dst_path`) or expected file size (`file_size`), the server rejects the request immediately with `ErrorCode::ProtocolViolation (1003)`.

### Checkpoint Coordination (`CheckpointCoordinator`)

Long-running transfers maintain bounded recovery windows via the `CheckpointCoordinator`:

```
Chunk Received ──> Observe Chunk ──> Threshold Reached?
                                            │
                                            ├── [No]  ──> Continue Streaming
                                            │
                                            └── [Yes] ──> fsync Staging (optional)
                                                      ──> Commit Bitmap to StateStore
                                                      ──> Update bytes_completed / timestamp
```

- **Byte Milestone Threshold (`bytes_threshold`)**: Defaults to **256 MiB** (configurable up to 1 GiB for extreme WAN transfers). Triggers checkpoint after every milestone.
- **Time Elapsed Interval (`time_interval`)**: Defaults to **10 seconds**. Guarantees regular checkpoints even on low-bandwidth connections.
- **Chunk Count Threshold (`chunk_threshold`)**: Defaults to **1,024 chunks**.
- **Staging Sync (`fsync_staging`)**: When enabled, performs a disk fsync on the staging file before persisting the checkpoint in the state store, guaranteeing crash consistency across power loss events.

### Graceful Shutdown & Drain Integration

During server graceful shutdown (`SIGTERM` / `SIGINT` drain cycle):
1. In-flight transfers are signalled via drain watch channels.
2. The `CheckpointCoordinator` immediately performs a terminal checkpoint write, syncing all completed chunk extents to `sqlite`.
3. Active entries in the `IdempotencyLedger` transition to `Resumable`.
4. Subsequent reconnection requests using the same idempotency key pick up exactly where the transfer was stopped without re-transmitting verified chunks.

---

## 23. Dynamic Adaptive Compression & Shannon Entropy Sampling

To prevent CPU exhaustion on incompressible streams (such as video, audio, compressed archives, and encrypted payloads) while maximizing compression ratios on compressible text, logs, and structured files, Velcrux implements a **Dynamic Adaptive Compression Selector** (`PROTOCOL.md` §3; `OPERATIONS.md` §4; `SECURITY.md` §8, §10; `REQUIREMENTS.md` §21, §32).

### Shannon Entropy Sampling (`estimate_entropy`)

Before committing CPU cycles to full Zstandard compression passes, chunks are screened using a sub-microsecond Shannon entropy estimator:

$$H(X) = - \sum_{i=0}^{255} p_i \log_2(p_i) \quad \text{where } p_i = \frac{\text{count}(i)}{N}$$

For chunks exceeding 32 KiB, the sampler inspects representative slices from the start, middle, and end, completing the evaluation in under **10 microseconds** without heap allocation.

### Multi-Tier Compression Classification (`EntropyTier`)

Based on the measured Shannon entropy, the chunk is mapped into an optimal processing tier:

| Entropy Range ($H$) | Classification | Action | Zstandard Level | Target Data Types |
| :--- | :--- | :--- | :--- | :--- |
| **$H < 3.0$** | `UltraRepetitive` | Maximum ratio | **Level 7** | Zero-filled blocks, ASCII tables, repetitive logs |
| **$3.0 \le H < 6.0$** | `Standard` | Balanced ratio | **Level 3** | Source code, configuration, markdown, JSON |
| **$6.0 \le H < 7.5$** | `Marginal` | Fast throughput | **Level 1** | Compiled binaries, packed proto buffers |
| **$H \ge 7.5$** | `Incompressible` | **Immediate Bypass** | *None* | MP4/MKV, JPEG/PNG, `.tar.gz`, encrypted blobs |

### Historical Stream Backoff & Probing (`AdaptiveCompressionSelector`)

To eliminate sampling overhead across large contiguous streams of incompressible data:
1. **Failure Tracking**: If `backoff_failure_threshold` (default 3) consecutive chunks fail to achieve minimum byte savings (`min_savings`, default 16 bytes), the stream enters **Cooldown Backoff**.
2. **Backoff Cooldown**: During cooldown, the selector bypasses compression for `backoff_cooldown_chunks` (default 6) without invoking the compression engine.
3. **Adaptive Probe**: When the cooldown expires, the next chunk is probed. If the probe achieves minimum savings, compression is instantly restored. If it fails, cooldown resumes.

### Runtime Telemetry & Saved CPU Tracking

Adaptive compression provides real-time telemetry via `AdaptiveCompressionStats`:
- `total_chunks`: Total chunks evaluated.
- `bypassed_entropy`: Chunks where compression was skipped based on high Shannon entropy.
- `bypassed_backoff`: Chunks skipped during historical backoff cooldown.
- `compressed_chunks`: Chunks successfully compressed and transmitted over the wire.
- `raw_bytes` vs `wire_bytes`: True wire byte reduction across mixed streams.
- `cpu_time_saved_us_est`: Cumulative CPU time saved by avoiding futile zstd compression cycles.

---

## 24. Multi-Path QUIC Connection Migration & Failover Gating

Velcrux supports dynamic **QUIC Connection Migration & Path Failover Gating** conforming strictly to RFC 9000 §9 ("Connection Migration"), `REQUIREMENTS.md` §11, §41, §70, `SECURITY.md` §2, §3, and `OPERATIONS.md` §4.

### Motivation & RFC 9000 §9 Conformance

In traditional TCP-based transfer systems, a change in client IP or port (such as roaming between Wi-Fi and 5G cellular networks, VPN reconnection, or NAT rebinds) terminates the underlying transport 4-tuple, aborting in-flight transfers and requiring expensive session renegotiation.

Under QUIC:
1. **Connection ID Stability**: Connections are uniquely identified by cryptographically authenticated QUIC Connection IDs rather than the IP/UDP 4-tuple.
2. **Seamless Interface Roaming**: When a client changes its local network interface or port, packets arrive at the server with the new source address. QUIC path validation and non-probing frame reception update the active path without resetting control or data streams.
3. **Continuous Transfer Ingestion**: Active chunk streaming and bitmap synchronization continue without interruption across network migrations.

```
+-----------------------------------------------------------------------------------+
|                           QUIC Connection Migration Flow                          |
|                                                                                   |
|  [Client] (Port A)                                           [Velcrux Server]     |
|     │                                                               │             |
|     ├─────── TRANSFER_CREATE / BEGIN / Chunk 0 (Port A) ───────────>│             |
|     │                                                               ├─ Active Path|
|     │    ===> Client Local Interface Rebinds (Port B) ===>          │  Remote: A  |
|     │                                                               │             |
|     ├─────── Chunk 1 / Commit (Port B) ────────────────────────────>│             |
|     │                                                               ├─ Migration! |
|     │                                                               ├─ Evaluate   |
|     │                                                               │  Policy     |
|     │                                                               ├─ Pass       |
|     │<────── Committed / COMMITTED Frame (Port B) ──────────────────┤             |
+-----------------------------------------------------------------------------------+
```

### Failover Gating Policies (`MigrationPolicyMode`)

To prevent connection hijacking, amplification attacks, and unauthorized path hopping in secure enterprise environments, the server enforces strict migration governance:

| Policy Mode | Behavior | Use Case |
| :--- | :--- | :--- |
| **`Permissive`** (Default) | Allows all valid QUIC path migrations regardless of source IP/port changes. | Mobile clients, laptop field engineers, multi-homed WAN uplinks. |
| **`Gated`** | Enforces rate limits (e.g. max 5 migrations per 60s) and/or optional CIDR subnet allowlists. Rejects excessive or out-of-subnet transitions. | High-security enterprise enclaves, DMZ gateways. |
| **`Disabled`** | Strictly forbids any connection migration. Any detected path change triggers immediate `PROTOCOL_VIOLATION` session termination. | Fixed datacenter-to-datacenter backup replication. |

### Configuration (`MigrationPolicy`)

```rust
pub struct MigrationPolicy {
    /// Policy enforcement mode.
    pub mode: MigrationPolicyMode,
    /// Maximum allowed address transitions within the time window.
    pub max_migrations_per_window: usize,
    /// Sliding time window in seconds for migration rate limiting.
    pub rate_window_secs: u64,
    /// Optional CIDR subnets permitted to migrate (empty = all subnets allowed).
    pub allowed_subnets: Vec<ipnet::IpNet>,
}
```

### Telemetry & Event Broadcast (`MigrationCoordinator`)

Operators and observability pipelines can subscribe to real-time migration events via Tokio broadcast channels:

```rust
let mut event_rx = coordinator.subscribe_events();
while let Ok(event) = event_rx.recv().await {
    tracing::info!(
        conn_id = event.connection_id,
        from = %event.prev_addr,
        to = %event.new_addr,
        identity = ?event.peer_identity,
        rtt_ms = event.measured_rtt.as_millis(),
        "Client connection migrated successfully"
    );
}
```

#### Metrics Tracked (`MigrationStats`):
- `migrations_total`: Total detected endpoint transitions across all connections.
- `migrations_accepted`: Total migrations successfully approved and routed.
- `migrations_rejected`: Migrations rejected due to policy restrictions (`Disabled`, rate limit exceeded, or subnet violation).

---

## 25. Zero-Knowledge Client-Side Chunk Encryption & AEAD Tamper-Proof Storage

Velcrux provides native **Zero-Knowledge Client-Side Chunk Encryption** conforming strictly to `REQUIREMENTS.md` §37 ("Chunk Encryption / Security"), §65 ("Encryption Ordering"), and `SECURITY.md` §2, §3, §8.

### Threat Model & Architecture

While QUIC enforces transport-layer TLS 1.3 encryption across the network wire, zero-knowledge chunk encryption protects datasets against:
1. **Untrusted Intermediate Gateways / Proxies**: Storage relays and edge nodes cannot inspect payload contents.
2. **Untrusted Storage Providers**: Staging files and chunk repositories on servers are held exclusively as ciphertext blobs.
3. **Chunk Injection & Splicing Attacks**: Cryptographically authenticated Associated Data (AAD) prevents malicious or accidental reordering, byte substitution, or cross-transfer splicing.
4. **Data Corruption & Bit-Rot**: 128-bit Poly1305 or GHASH tags detect and reject single-bit corruptions before data touches memory or disk.

```
+-----------------------------------------------------------------------------------+
|               Zero-Knowledge Chunk Encryption Pipeline (RFC 8439)                 |
|                                                                                   |
|  [Source File] ──> FastCDC / Fixed Chunker                                        |
|                          │                                                        |
|                          ▼                                                        |
|                   [Chunk Payload]                                                 |
|                          │                                                        |
|                          ├──> (Optional) Zstandard Compression (Level 1..7)       |
|                          │                                                        |
|                          ▼                                                        |
|                   [Compressed Slice]                                              |
|                          │                                                        |
|                          ├──> AEAD Envelope Seal (ChaCha20-Poly1305 / AES-256-GCM)|
|                          │    • 96-bit Secure Nonce                               |
|                          │    • AAD: [TransferId: 16B][Offset: 8B][Index: 4B]     |
|                          │    • 128-bit Authentication Tag                        |
|                          ▼                                                        |
|                   [Encrypted DATA Frame] (Flag: 0x0004 ENCRYPTED)                 |
|                          │                                                        |
|                          ▼                                                        |
|                   [QUIC Transport TLS 1.3] ──> UDP Wire                           |
+-----------------------------------------------------------------------------------+
```

### Encryption Ordering Guarantee (`REQUIREMENTS.md` §65)

Encrypted data is cryptographically indistinguishable from high-entropy white noise and cannot be compressed. Velcrux guarantees the strict order of operations:
1. **Delta / Content Chunking**: Identifies boundary hashes from plain data.
2. **Optional Compression**: Chunks are compressed before encryption while redundancy remains visible.
3. **AEAD Envelope Encryption**: Seals compressed or raw chunk into ciphertext.
4. **QUIC Wire Encryption**: Transmits frames inside authenticated QUIC packets.

### Wire Envelope Format

Every encrypted chunk carries a compact 28-byte overhead:
```text
+-------------------+-----------------------------------+-------------------+
| Nonce (12 bytes)  |      Ciphertext (N bytes)         |  Tag (16 bytes)   |
+-------------------+-----------------------------------+-------------------+
```

### Cryptographic Binding via Associated Authenticated Data (AAD)

To prevent chunk reordering or cross-session injection attacks, each chunk cryptographically incorporates 28 bytes of immutable context into the AEAD tag:

$$\text{AAD} = \text{TransferId (16 bytes)} \parallel \text{chunk\_offset (8 bytes LE)} \parallel \text{chunk\_index (4 bytes LE)}$$

If an adversary alters the chunk index, shifts the offset, or attempts to substitute chunk $i$ for chunk $j$, decryption fails immediately with `CryptoError::AuthenticationFailed`.

### Key Derivation (`derive_transfer_key`, `derive_key_from_passphrase`)

- **Master Key Derivation**: Passphrases derive 256-bit master keys using PBKDF2-HMAC-SHA256 with 100,000 iterations and salt.
- **Per-Transfer Domain Separation**: Each transfer derives an isolated 256-bit key using BLAKE3 KDF:
  $$\text{Key}_{\text{transfer}} = \text{BLAKE3-KDF}(\text{MasterKey}, \text{"velcrux-zero-knowledge-transfer-v1"}, \text{TransferId})$$
- **Zeroize on Drop**: Key structs zero their memory buffers upon destruction.

---

## 26. Enterprise Production Deployment Packaging & ADR Index

Conforming to `REQUIREMENTS.md` §76 ("Deployment"), §77 ("Docker"), §78 ("Configuration Security"), and §80 ("Architecture Decision Records"), Velcrux provides production deployment manifests and an automated packaging generator CLI.

### 1. Automated CLI Manifest Generator (`velcrux package`)

Operators can generate production-grade, validated service units and deployment manifests directly from the client CLI:

```bash
# Generate Linux systemd server daemon unit
velcrux package systemd --server --memory-max 16G --nofile 131072 > /etc/systemd/system/velcruxd.service

# Generate Linux systemd client worker unit
velcrux package systemd --user velcrux --config /etc/velcrux/client.toml > /etc/systemd/system/velcrux.service

# Generate macOS launchd daemon plist
velcrux package launchd --log-path /var/log/velcrux/velcruxd.log > /Library/LaunchDaemons/com.velcrux.velcruxd.plist

# Generate Kubernetes StatefulSet & LoadBalancer Service manifest
velcrux package k8s --image ghcr.io/velcrux/velcrux:v0.1.0 > velcrux-statefulset.yaml

# Generate hardened multi-stage Dockerfile
velcrux package docker > Dockerfile
```

### 2. Linux Systemd Service Units (`packaging/systemd/`)

Both server (`velcruxd.service`) and client (`velcrux.service`) include security hardening complying with `systemd-analyze security`:
- **Unprivileged User**: Runs strictly under `User=velcrux`, `Group=velcrux`.
- **Capability Isolation**: `NoNewPrivileges=true`, `PrivateTmp=true`.
- **Filesystem Isolation**: `ProtectSystem=strict`, `ProtectHome=true`, with restricted `ReadWritePaths` for data directories only.
- **Resource Limits**: `MemoryMax` hard memory caps and `LimitNOFILE=65536` file descriptor headroom.
- **Graceful Shutdown**: `KillSignal=SIGTERM` and `TimeoutStopSec=120` ensuring active transfers flush checkpoints and sync SQLite WAL files.

### 3. Secret References & Environment Overrides (`packaging/systemd/velcruxd.env`)

In compliance with §78 ("Configuration Security"), sensitive TLS keys and passphrases are decoupled from configuration files:
```bash
VELCRUX_LISTEN_ADDR=0.0.0.0:7443
VELCRUX_METRICS_ADDR=127.0.0.1:9443
VELCRUX_TLS_CERT=/etc/velcrux/certs/server.crt
VELCRUX_TLS_KEY=/etc/velcrux/certs/server.key
VELCRUX_CLIENT_CA=/etc/velcrux/certs/ca.crt
```

### 4. Kubernetes Production StatefulSet (`packaging/k8s/`)

The Kubernetes manifest deploys `velcruxd` with:
- **Zero-Privilege Container**: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, and all Linux capabilities dropped (`drop: [ALL]`).
- **Telemetry Probes**: Native readiness and liveness HTTP probes against `/metrics` on port 9443.
- **Persistent Volume Claims**: Separate dedicated storage volumes for bulk files (`1Ti`) and SQLite WAL state database (`50Gi`).

### 5. Complete Architecture Decision Records Catalog (`docs/adr/`)

Per `REQUIREMENTS.md` §80, every critical technical trade-off is recorded with problem definition, evaluated alternatives, decision rationale, and consequences:

- **[ADR-001](adr/ADR-001-quic-transport.md)**: QUIC as Transport Protocol
- **[ADR-002](adr/ADR-002-rust.md)**: Rust Implementation Language & Memory Safety
- **[ADR-003](adr/ADR-003-blake3.md)**: BLAKE3 Cryptographic Tree Hashing
- **[ADR-004](adr/ADR-004-chunking.md)**: FastCDC Gear Hash vs Fixed Chunking
- **[ADR-005](adr/ADR-005-persistence.md)**: SQLite WAL State & Streaming Manifests
- **[ADR-006](adr/ADR-006-chunk-store.md)**: Content-Addressed Chunk Store (CAS) & Generational GC
- **[ADR-007](adr/ADR-007-stream-model.md)**: One QUIC Stream Per File Model
- **[ADR-008](adr/ADR-008-versioning.md)**: Protocol Versioning & Capability Negotiation Floor
- **[ADR-009](adr/ADR-009-zero-knowledge-chunk-encryption.md)**: Zero-Knowledge Client-Side Chunk Encryption & AEAD Tamper-Proof Storage
- **[ADR-010](adr/ADR-010-quic-connection-migration-and-failover.md)**: QUIC Connection Migration & Failover Gating
- **[ADR-011](adr/ADR-011-performance-profiling-and-bottleneck-analysis.md)**: Empirical Performance Profiling & Bottleneck Analysis
- **[ADR-012](adr/ADR-012-transfer-planning-dry-run-and-safe-delete-semantics.md)**: Transfer Planning, Dry-Run Simulation & Safe-Delete Semantics
- **[ADR-013](adr/ADR-013-s3-compatible-object-storage-gateway.md)**: S3-Compatible Cloud Object Storage Gateway Backend
- **[ADR-014](adr/ADR-014-multi-interface-bonding-and-multipath-transport-aggregation.md)**: Multi-Interface Bonding & Multi-Path QUIC Transport Aggregation
- **[ADR-015](adr/ADR-015-distributed-chunk-store-clustering-and-replication.md)**: Distributed Chunk Store Clustering & Quorum Replication
- **[ADR-016](adr/ADR-016-continuous-real-time-file-watcher-and-automated-sync.md)**: Continuous Real-Time File Watcher & Automated Synchronization Engine
- **[ADR-017](adr/ADR-017-cross-cluster-wan-geo-replication-and-conflict-resolution.md)**: Cross-Cluster WAN Geo-Replication & Conflict Resolution Engine
- **[ADR-018](adr/ADR-018-pluggable-webhook-event-notifications-and-audit-event-bus.md)**: Pluggable Webhook Event Notifications & Audit Event Bus
- **[ADR-019](adr/ADR-019-point-in-time-snapshot-isolation-and-file-version-history.md)**: Point-in-Time Snapshot Isolation & File Version History Engine
- **[ADR-020](adr/ADR-020-distributed-lock-manager-and-mutex-lease-coordinator.md)**: Distributed Lock Manager (DLM) & Mutex Lease Coordinator
- **[ADR-021](adr/ADR-021-dynamic-zstandard-pre-trained-dictionary-learning-engine.md)**: Dynamic Zstandard Pre-Trained Dictionary Learning Engine
- **[ADR-022](adr/ADR-022-data-integrity-scrubbing-and-bit-rot-repair-daemon.md)**: In-Flight Data Integrity Scrubbing & Background Bit-Rot Repair Daemon

---

## 27. Dynamic Multi-Tenant Bandwidth Allocator & Fairness Scheduler

In conformance with `REQUIREMENTS.md` §28 ("Bandwidth Control"), §29 ("Fairness"), and `ARCHITECTURE.md` §5, Velcrux provides a hierarchical bandwidth allocator and priority fairness scheduler.

### 1. Hierarchical Multi-Tier Bandwidth Allocation

Velcrux enforces three hierarchical rate limiting tiers:
1. **Global Server Ceiling**: Hard server-wide aggregate bandwidth ceiling (e.g. `10Gbps`).
2. **Per-Tenant / Per-User Ceiling**: Bandwidth quota allocated to an authenticated client identity or organization (e.g. `1Gbps`).
3. **Per-Transfer Session Ceiling**: Rate limit specified on an individual transfer invocation (e.g. `100Mbps`).

#### Composition Rule
The effective transmission rate for any chunk write is the strict mathematical minimum across all three active tiers:
$$\text{EffectiveRate}(t) = \min\left(R_{\text{global}}, R_{\text{user}}, R_{\text{transfer}}\right)$$

### 2. Token Bucket Pacing (No Arbitrary Thread Sleep)

Arbitrary thread sleeping produces bursty, loss-inducing traffic that destabilizes QUIC congestion control. Velcrux employs a fine-grained token bucket with a bounded 100ms burst window. If a tenant exceeds their quota, tokens enter a deficit state:
$$\Delta t = \frac{\text{Bytes} - \text{Tokens}_{\text{available}}}{\text{Rate}_{\text{bytes/sec}}}$$

The scheduler paces writes asynchronously using non-blocking event-driven timers (`tokio::time::sleep`), guaranteeing smooth packet transmission without starvation or UDP flooding.

### 3. Strict Priority Classes & 4:1 Weighted Round-Robin (WRR)

Transfers and metadata are classified into three distinct priority levels:
- **`PriorityClass::High`**: Control messages, small metadata chunks, and interactive CLI sync commands. **High priority queues are drained to complete exhaustion first.**
- **`PriorityClass::Normal`**: Standard bulk data transfers and file streams.
- **`PriorityClass::Low`**: Background synchronization, automated archival, and non-blocking maintenance runs.

#### 4:1 Weighted Round-Robin Interleaving
When `High` priority queues are empty, bandwidth is dynamically shared between `Normal` and `Low` priorities using Weighted Round-Robin with a **4:1 ratio**:
```text
[Step 1] Normal Chunk
[Step 2] Normal Chunk
[Step 3] Normal Chunk
[Step 4] Normal Chunk
[Step 5] Low Chunk
(Repeats modulo 5)
```
If either queue runs dry, the scheduler yields 100% of the remaining cycles to the active queue without stalling or latency penalties.

### 4. Sequential Chunk Offset Preservation

Within any individual transfer session, chunks are strictly queued and dispatched in sequential byte offset order:
$$\text{Offset}_0 < \text{Offset}_1 < \dots < \text{Offset}_n$$
This guarantees sequential disk writes on the receiving peer, maximizing NVMe/SSD streaming bandwidth and eliminating costly random I/O head contention.

---

## 28. Network Path MTU Discovery (PMTU / DPLPMTUD RFC 8899), Blackhole Detection & NAT Firewall Traversal

Per `REQUIREMENTS.md` §75 ("NAT and Firewall Considerations") and RFC 8899 / RFC 9000, Velcrux provides robust transport-layer path adaptation for heterogenous enterprise WANs, firewalls, and NAT gateways.

### 1. Datagram Packetization Layer PMTU Discovery (DPLPMTUD)

Velcrux implements Datagram Packetization Layer Path MTU Discovery (DPLPMTUD RFC 8899) across QUIC datagrams:
- **Baseline Floor**: 1200 bytes (`BASE_PLPMTU`), conforming to RFC 9000 guaranteed baseline across all IPv4 and IPv6 routes.
- **Probe Step Hierarchy**: Candidate packet sizes are progressively probed in ascending order:
  $$\text{Candidates} = [1200, 1280, 1420, 1500, 2048, 4096, 9000]$$
- **Verification via Probe ACKs**: Probing datagrams are dispatched without blocking the data stream. Upon confirmation via QUIC ACK, the transport MTU ceiling is raised to the validated size. If a probe size fails three consecutive attempts, probing terminates and locks to the highest validated MTU.

### 2. Path MTU Blackhole Detection & Downshift

When intermediate WAN routing tables change dynamically (e.g. BGP failover to a path with lower MTU or broken ICMP packet-too-big blackholes), large packets are dropped silently without ICMP generation:
- **Detection Trigger**: If consecutive data packet loss reaches the threshold (default: 4 losses at $>1200$ byte MTU), the coordinator triggers a blackhole alert.
- **Emergency Downshift**: Immediately collapses `current_mtu` to 1200 bytes (`BASE_PLPMTU`) and enters `BlackholeRecovery` state.
- **Zero Session Reset**: Resumes streaming smaller packets immediately without resetting or re-authenticating the TLS/QUIC session.

### 3. Stateful NAT Pinhole & Adaptive Keepalive Scaling

Stateful NAT and firewall devices purge UDP mapping entries when idle:
- **Baseline Interval**: Default 15s keepalive ping interval keeps state tables alive for typical 30s-120s timeouts.
- **Adaptive Tightening**: Upon observing NAT rebinding events (source port changes, mobile roaming, or path migration), the coordinator dynamically scales down the keepalive interval (15s $\rightarrow$ 10s $\rightarrow$ 5s) to guarantee persistent pinholes.
- **Inactivity Reset**: Normal data packet transfers automatically refresh the last activity timer, eliminating unnecessary keepalive overhead during active data streaming.

### 4. Firewall Deployment & Administrator Checklist

For production enterprise deployment behind firewalls and edge load balancers:

| Configuration Item | Recommended Value | Operational Rationale |
| :--- | :--- | :--- |
| **Ingress UDP Port** | `7443/UDP` | Primary QUIC transport listen port. |
| **Firewall UDP State Timeout** | $\ge 60\text{ seconds}$ | Prevents premature NAT table eviction during momentary idle pauses. |
| **ICMP Type 3 Code 4** | Permit Inbound | Allows PMTU Fragmentation Needed messages to reach endpoints. |
| **Jumbo Frames** | `MTU 9000` (LAN/Private WAN) | DPLPMTUD will automatically probe and utilize 9000 byte frames for reduced CPU overhead. |
| **Symmetric NAT Handling** | Enabled | Velcrux QUIC Connection ID migration automatically handles port/IP rebinding. |

---

## 29. Empirical Performance Profiling, Live Diagnostic Telemetry & Bottleneck Analysis

Per `REQUIREMENTS.md` §72 ("Performance Profiling"), §38 ("Observability"), §36 ("Machine-Readable Output"), and §46 ("Benchmark Suite"), Velcrux incorporates an empirical transfer performance profiler and automated bottleneck diagnosis engine (`ADR-011`).

### 1. Granular Pipeline Stage Instrumentation

The profiler measures elapsed wall-clock duration, execution count, and byte volume across all transfer subsystems:
- **`DiskIoRead`**: Storage read operations and file I/O latency.
- **`Chunking`**: Rolling hash chunk boundary evaluation (FastCDC vs fixed-size chunks).
- **`Hashing`**: BLAKE3 chunk cryptographic hashing and SIMD tree hashing.
- **`Encryption`**: Zero-knowledge AEAD chunk payload encryption (ChaCha20-Poly1305 / AES-256-GCM).
- **`NetworkQuic`**: Stream transmission, congestion window pacing, and ACK round-trips.
- **`DiskIoWrite`**: Destination staging writes and filesystem commit fsyncs.
- **`Serialization`**: Frame encoding and state serialization.

### 2. Automated Bottleneck Classification & Diagnosis

The diagnostic engine calculates the relative time distribution across pipeline components and evaluates transport telemetry (RTT, packet loss rate, cwnd) to classify the primary constraint:

| Bottleneck Kind | Identification Criteria | Automated Operational Guidance |
| :--- | :--- | :--- |
| **`NetworkBound`** | Network transport time $\ge 50\%$ or packet loss $> 1\%$. | Verify BDP receive window (`receive_window >= 2 * BDP`), check PMTU blackholing, or inspect WAN link loss. |
| **`DiskIoReadBound`** | Storage read I/O $\ge 45\%$ of total pipeline time. | Enable direct I/O, migrate to NVMe SSD arrays, or optimize OS readahead. |
| **`DiskIoWriteBound`** | Storage write / fsync $\ge 45\%$ of total pipeline time. | Separate staging and storage disks, enable writeback caching, or tune checkpoint intervals. |
| **`CpuHashingBound`** | BLAKE3 hashing $\ge 40\%$ of total pipeline time. | Enable hardware vectorization (`velcrux hardware`) or increase hashing worker concurrency (`--concurrency`). |
| **`CryptoBound`** | AEAD encryption $\ge 40\%$ of total pipeline time. | Enable hardware AES-NI acceleration or configure ChaCha20-Poly1305 cipher suite. |
| **`BalancedOptimized`** | Pipeline stages evenly distributed; no dominant bottleneck. | System is well-balanced and operating near maximum theoretical throughput. |

### 3. CLI Command Usage

```bash
# Profile local file transfer pipeline with ASCII diagnostic report
velcrux profile /path/to/large_file.iso

# Profile end-to-end QUIC transfer across network
velcrux profile /path/to/large_file.iso --url velcrux://storage.internal:7443/staging/

# Output machine-readable JSON for monitoring and CI regression checks
velcrux --json profile /path/to/large_file.iso
```

### 4. Sample Diagnostic Output

```text
========================================================================================
                      VELCRUX EMPIRICAL PERFORMANCE PROFILE REPORT
========================================================================================
Transfer Wall-Clock Time : 124.50 ms
Total Bytes Processed    : 104,857,600 bytes (100.00 MiB)
Effective Goodput        : 6.74 Gbps (842.23 MB/s)
Resident Set Size (RSS)  : 18.25 MiB
Buffer Pool Peak         : 8.00 MiB
----------------------------------------------------------------------------------------
PIPELINE STAGE BREAKDOWN:
Stage Name                     Invocations      Total (ms)      % Time     Throughput
----------------------------------------------------------------------------------------
Storage Read I/O                        1            12.30       9.9%       8.13 GB/s
Chunking (CDC/Fixed)                   64             8.50       6.8%      11.76 GB/s
Cryptographic Hashing                  64            15.40      12.4%       6.49 GB/s
Zero-Knowledge Encryption              64            18.20      14.6%       5.49 GB/s
QUIC Network Transport                 64            68.10      54.7%       1.47 GB/s
Storage Write I/O                       1             2.00       1.6%      50.00 GB/s
----------------------------------------------------------------------------------------

BOTTLENECK DIAGNOSIS & ACTIONABLE TUNING RECOMMENDATIONS:
  Primary Bottleneck: Network Bound
  Confidence Score  : 85.0% (Primary Component: 54.7% of tracked pipeline)
  Summary           : Transfer is primarily bottlenecked by QUIC network transport latency and bandwidth.

  Recommended Actions:
    1. Check QUIC receive_window and stream_receive_window configuration. Ensure receive_window >= 2 * BDP.
    2. Check for intermediate WAN packet loss or rate limits.
========================================================================================
```

---

## 30. Transfer Planning, Dry-Run Previews & Safe Delete Semantics (Option AV)

Per `REQUIREMENTS.md` §57 ("Transfer Plan"), §58 ("Dry Run"), §59 ("Delete Semantics"), §60 ("Security of Synchronization"), §61 ("Transactional Synchronization"), and `ADR-012`:

Velcrux provides a deterministic pre-flight transfer planning engine, full zero-mutation dry-run execution preview, multi-mode deletion sequencing, and safety threshold guardrails to protect against catastrophic data loss.

### 1. Key Capabilities

| Feature | CLI Flag / Command | Operational Behaviour |
| :--- | :--- | :--- |
| **Transfer Plan** | `velcrux plan <src> <dst>` | Pre-computes reconciliation diff, file counts, reusable bytes, wire transfer bytes, and bandwidth reduction percentage without modifying destination. |
| **Dry Run** | `velcrux sync ... --dry-run` | Runs full planning and small-file batching preview; guarantees zero bytes written or deleted at destination. |
| **Post-Commit Delete** | `--delete` or `--delete-after` | Deletes extraneous files only after all staged files are transferred, verified, and committed. Safe default for deletions. |
| **Pre-Transfer Delete** | `--delete-before` | Deletes extraneous destination files before transfer begins. Reclaims disk space on capacity-constrained destination volumes. |
| **Exclude Deletion** | `--delete-excluded` | Deletes extraneous destination files AND any files on destination matching active `--exclude` glob filters. |
| **Pattern Filters** | `--exclude <glob>` | Ignores matching files from source sync (supports `*.tmp`, `build/**`, `node_modules/*`, etc.). |
| **Deletion Guardrails** | `--max-delete <N>`<br>`--max-delete-pct <P>` | Aborts sync before any file is deleted if scheduled deletions exceed absolute count $N$ or percentage $P\%$ of destination files. |
| **Safety Override** | `--force-delete` | Bypasses threshold limits when bulk deletion is explicitly intended by operator. |

### 2. Operational CLI Commands

```bash
# 1. Preview transfer plan and estimated bandwidth savings
velcrux plan /local/dataset /backup/dataset

# 2. Preview transfer plan with machine-readable JSON for CI automation
velcrux --json plan /local/dataset /backup/dataset

# 3. Dry-run directory sync with pattern exclusions
velcrux sync /local/dataset /backup/dataset --dry-run --exclude "*.tmp" --exclude ".git/**"

# 4. Standard safe synchronization with post-commit deletions
velcrux sync /local/dataset /backup/dataset --delete-after

# 5. Disk-constrained sync reclaiming disk space before transfer begins
velcrux sync /local/dataset /backup/dataset --delete-before

# 6. Synchronization with threshold safety guardrail (abort if >50 files would be deleted)
velcrux sync /local/dataset /backup/dataset --delete --max-delete 50

# 7. Operator override to force deletion of large batch
velcrux sync /local/dataset /backup/dataset --delete --max-delete 50 --force-delete

# 8. Clean temporary files on destination matching exclusion filters
velcrux sync /local/dataset /backup/dataset --exclude "*.log" --delete-excluded
```

### 3. Sample Transfer Plan Output

```text
========================================================================================
                   VELCRUX TRANSFER PLAN (DRY-RUN EXECUTION PREVIEW)                   
========================================================================================
Source Directory     : /data/dataset
Destination Directory: /backup/dataset
Deletion Policy      : DeleteAfter (post-commit verified deletion)
----------------------------------------------------------------------------------------
Files total:                    12,431
Files unchanged:                12,218
Files modified:                    182
Files added:                        31
Files deleted:                       7
----------------------------------------------------------------------------------------
Total source data:             5.00 TB
Data already present:          4.82 TB
Data to transfer:               183 GB
Estimated reduction:             96.4%
---

## 31. S3-Compatible Cloud Object Storage Gateway Backend (Option AW)

Per `REQUIREMENTS.md` §42 ("S3 Compatibility") and §43 ("Object Storage Gateway"), Velcrux provides a native, pure-Rust S3-compatible cloud object storage gateway backend, bridging local NVMe filesystems with cloud object stores (AWS S3, MinIO, Cloudflare R2, Ceph, Wasabi).

### 1. Key Capabilities & Zero-Dependency Architecture

1. **Pure-Rust AWS SigV4 Request Signing**: Computes canonical request strings, signed headers, date scopes, and HMAC-SHA256 authorization signatures using workspace cryptography (`ring`, `sha2`) with zero external cloud SDKs or C libraries.
2. **Unified URL Scheme**: Canonical `s3://<bucket>/<key>` addressing with automatic bucket/key parsing and prefix resolution.
3. **Multipart Upload Pipeline**: Files exceeding the configured part size (default: 8 MiB) are uploaded in sequential or concurrent parts with cryptographic multipart ETags (`<hash>-<part_count>`).
4. **Random Byte Range Reads**: Full support for `Range: bytes=start-end` HTTP queries, enabling delta-synchronization, partial chunk reconstruction, and streaming reads without downloading multi-gigabyte objects.
5. **Bidirectional Directory Synchronization**: Fast directory synchronization between local POSIX file hierarchies and flat S3 object namespaces, detecting identical files via size and BLAKE3 checksums to eliminate redundant transfers.
6. **Strict Safety**: Enforces `#![forbid(unsafe_code)]` across the entire storage gateway stack.

### 2. Configuration & Authentication Environment

The gateway automatically resolves credentials from standard environment variables with customizable CLI overrides:

| Environment Variable | CLI Parameter | Default | Description |
|----------------------|---------------|---------|-------------|
| `AWS_ACCESS_KEY_ID` | N/A | `anonymous` | AWS Access Key ID |
| `AWS_SECRET_ACCESS_KEY` | N/A | `anonymous` | AWS Secret Access Key |
| `AWS_SESSION_TOKEN` | N/A | `None` | STS temporary session token |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | `--region` | `us-east-1` | AWS S3 geographic region |
| `AWS_ENDPOINT_URL_S3` / `AWS_ENDPOINT_URL` | `--endpoint` | `https://s3.amazonaws.com` | Custom endpoint (e.g. MinIO `http://127.0.0.1:9000`) |

### 3. CLI Command Reference

#### 1. Upload Object (`s3 put`)
```bash
# Upload a single local file to S3
velcrux s3 put ./dataset.tar.zst s3://my-bucket/backups/dataset.tar.zst

# Upload using custom multipart part size (e.g. 16 MiB)
velcrux s3 put ./large.iso s3://my-bucket/iso/large.iso --multipart-size 16777216

# Upload targeting a local MinIO cluster
velcrux s3 put ./data.bin s3://local-bucket/data.bin --endpoint http://127.0.0.1:9000
```

#### 2. Inspect Object Metadata (`s3 stat`)
```bash
# Human-readable stat inspection
velcrux s3 stat s3://my-bucket/backups/dataset.tar.zst

# Machine-readable JSON output
velcrux --json s3 stat s3://my-bucket/backups/dataset.tar.zst
```

#### 3. List Objects (`s3 ls`)
```bash
# List all objects under a prefix
velcrux s3 ls s3://my-bucket/backups/

# List top-level directory prefixes using delimiter
velcrux s3 ls s3://my-bucket/ --delimiter /
```

#### 4. Download Object & Range Retrieval (`s3 get`)
```bash
# Download complete object
velcrux s3 get s3://my-bucket/backups/dataset.tar.zst ./dataset.tar.zst

# Download byte range (e.g. bytes 0 through 1048575, first 1 MiB)
velcrux s3 get s3://my-bucket/archive.tar ./header.bin --range-start 0 --range-end 1048575
```

#### 5. Delete Object (`s3 delete`)
```bash
velcrux s3 delete s3://my-bucket/backups/obsolete.tar.zst
```

#### 6. Bidirectional Directory Synchronization (`s3 sync`)
```bash
# Upload local directory to S3 prefix
velcrux s3 sync ./local_dataset s3://my-bucket/mirror/dataset

# Download S3 prefix to local directory
velcrux s3 sync s3://my-bucket/mirror/dataset ./restored_dataset

# Seamless top-level delegation via `velcrux sync`
velcrux sync ./local_dataset s3://my-bucket/mirror/dataset
velcrux sync s3://my-bucket/mirror/dataset ./restored_dataset
```

---

## 32. Multi-Interface Bonding & Multi-Path QUIC Transport Aggregation (Option AX)

Per `REQUIREMENTS.md` §74 ("Multi-Path Future") and §75 ("NAT and Firewall Considerations"), Velcrux provides native transport-level multi-interface bonding, path quality monitoring, and multi-path packet/chunk scheduling across heterogeneous network interfaces.

### 1. Multi-Path Bonding Architecture

Velcrux bonds multiple local network interfaces simultaneously:
- **Zero Switch Dependencies**: Does not require switch-level LACP (802.3ad) or identical layer-2 collision domains; bonds across heterogeneous technologies (e.g. 10GbE + Wi-Fi 6 or fiber + cellular).
- **Subflow State Machine**: Dynamically monitors subflow path health across four discrete states:
  - `Active`: Normal operational health.
  - `Degraded`: Latency or loss exceed configured safety thresholds; throttled to prevent head-of-line blocking.
  - `Probing`: Background active health probes checking responsiveness before re-admission.
  - `Dead`: Unresponsive or interface down; automatically excluded from routing.
- **Zero-Downtime Hot Failover**: Automatically redirects data streams to healthy backup subflows within milliseconds of link degradation.

### 2. Multi-Path Scheduling Strategies

Configure the active chunk distribution policy using `--multipath-scheduler`:

| Strategy | Token | Description | Best For |
|----------|-------|-------------|----------|
| **Weighted Bandwidth** (Default) | `weighted` | Proportional split based on measured BDP / bandwidth capacity | Aggregating asymmetric interfaces (e.g. 10G + 1G) |
| **Lowest Latency First** | `min-rtt` | Directs chunks to the lowest RTT subflow, overflowing when window is full | Interactive transfers across low-latency primary paths |
| **Round Robin** | `round-robin` | Uniformly cycles chunks across all active subflows | Symmetric multi-homed links of identical speed |
| **Redundant** | `redundant` | Duplicates chunks across multiple active subflows simultaneously | High-loss, jittery links (satellite, military, field cellular) |
| **Primary-Backup** | `failover` | 100% traffic on primary; shifts to backup only if primary fails | Cost-constrained environments (fiber primary, metered 5G backup) |

### 3. CLI Command & Flag Reference

#### 1. Inspect Local Interfaces & Bonding Status
```bash
# Display human-readable multipath bonding table
velcrux multipath

# Machine-readable JSON metrics
velcrux --json multipath

# Evaluate subflow paths against a target remote server
velcrux multipath --target velcrux://storage.corp:7443/
```

#### 2. Execute Multipath Transfers
```bash
# Upload large file utilizing all available network interfaces
velcrux upload ./dataset.tar velcrux://backup.server/dataset.tar --multipath

# Upload using Min-RTT scheduler prioritizing lowest latency path
velcrux upload ./dataset.tar velcrux://backup.server/dataset.tar \
  --multipath --multipath-scheduler min-rtt

# Bond specific named interfaces (e.g. eth0 and wlan0)
velcrux upload ./dataset.tar velcrux://backup.server/dataset.tar \
  --multipath --interfaces eth0,wlan0

# Primary-backup failover with eth0 as primary
velcrux sync ./data velcrux://backup.server/data \
  --multipath --multipath-scheduler failover --primary-interface eth0

# High-reliability transfer with redundant metadata duplication
velcrux upload ./firmware.bin velcrux://edge.node/firmware.bin \
  --multipath --redundant-metadata
```

---

## 33. Distributed Chunk Store Clustering & Quorum Replication (Option AY)

Per `REQUIREMENTS.md` §15 ("Storage Backend & Local Chunk Store"), §62 ("Scale Targets: 100M Chunks & Multi-PB Datasets"), and §63 ("High Availability & Fault Tolerance"), Velcrux provides native multi-node chunk store clustering and tunable quorum replication.

### 1. Consistent Hashing Ring & Virtual Nodes

The cluster coordinates data layout using a deterministic `ConsistentHashRing`:
- **Virtual Nodes (vnodes)**: Each registered storage node maps to 128 virtual tokens across the 64-bit BLAKE3 token ring, ensuring uniform chunk distribution without hotspots.
- **Clockwise Preference Lists**: For any chunk hash, the coordinator traverses the ring clockwise to select $N$ distinct physical storage nodes designated for replica placement.
- **Topology Scalability**: Adding or removing a node only transfers $\frac{1}{M}$ of total chunks, preventing catastrophic full-corpus reshuffling.

### 2. Tunable Quorum Consistency ($N, W, R$)

Consistency is governed by mathematically sound quorum configuration:
- **$N$ (Replica Factor)**: Total copies written across distinct physical nodes (default: 3).
- **$W$ (Write Quorum)**: Minimum node acknowledgments required for a successful write (default: 2).
- **$R$ (Read Quorum)**: Minimum node responses required for a successful read or probe (default: 2).
- **Strict Consistency**: Enforced when $W + R > N$, guaranteeing that write and read quorums intersect by at least one up-to-date node.
- **Eventual Consistency**: Permitted when $W + R \le N$, maximizing write throughput for high-ingestion pipelines at the cost of eventual convergence.

### 3. Node Lifecycle & Failure Domains

Nodes transition through four lifecycle states:
- `Healthy`: Normal operational state; serves reads and writes.
- `Suspect`: Missed heartbeats or elevated network latency; actively monitored.
- `Draining`: Controlled maintenance drain; serves existing reads but redirects new writes.
- `Dead`: Unreachable or offline; excluded from quorum calculations.

### 4. Asynchronous Read-Repair & Anti-Entropy Reconciliation

- **Read-Repair**: During chunk retrieval, if an alive node in the preference list is missing a chunk found on another node, an asynchronous background task replicates the chunk to restore full $N$-fold redundancy without stalling the client query.
- **Anti-Entropy Rebalance**: Background administrative task that sweeps all registered nodes, detects missing replicas, and backfills replicas across cluster members.

### 5. CLI Command Reference

#### 1. Display Cluster Status & Quorum Health
```bash
# Inspect default cluster status
velcrux cluster status

# Inspect specific cluster topology with custom quorum parameters
velcrux cluster status \
  --nodes 10.0.1.1:8001,10.0.1.2:8001,10.0.1.3:8001 \
  --replicas 3 --write-quorum 2 --read-quorum 2

# Machine-readable JSON output for cluster orchestration and monitoring
velcrux --json cluster status
```

#### 2. Trigger Anti-Entropy Rebalance
```bash
# Run cluster rebalance and verify replica counts
velcrux cluster rebalance --replicas 3

# Machine-readable JSON report
velcrux --json cluster rebalance
```

---

## 34. Continuous Real-Time File Watcher & Automated Synchronization (Option AZ)

Per `REQUIREMENTS.md` §64–§68 ("Continuous Synchronization & File Watching"), Velcrux provides native pure-Rust real-time directory monitoring, intelligent event debouncing, and automated batch synchronization.

### 1. Pure-Rust State Scanner & Ephemeral Event Coalescing

Velcrux uses a deterministic in-memory `DirectoryScanner` and `DebounceQueue`:
- **Zero Kernel Limits**: Avoids OS watch descriptor exhaustion (`inotify` / `FSEvents`) and operates strictly in pure Rust under `#![forbid(unsafe_code)]`.
- **Intelligent Coalescing**:
  - `Created` + `Modified` $\to$ `Created`: Keeps the earliest creation event and newest file contents.
  - `Created` + `Deleted` $\to$ Purged: Automatically suppresses transient compiler artifacts, editor `.swp` files, and staging locks.
  - `Modified` + `Modified` $\to$ `Modified`: Merges rapid write bursts into a single transfer pass.

### 2. Tunable Debounce Pacing

- **Debounce Window (`--debounce-ms`, default: 200ms)**: The quiet interval required before queued modifications are flushed into a batch. Active writing continually resets the timer to ensure partial or in-progress writes are not transferred prematurely.
- **Poll Scan Frequency (`--poll-interval-ms`, default: 500ms)**: The interval between recursive directory tree sweeps.
- **Max Queue Depth**: Flushes immediately when pending changes exceed 10,000 files to bound memory consumption under massive write bursts.

### 3. CLI Command & Flag Reference

#### 1. Dedicated Real-Time Watcher
```bash
# Watch local directory and stream changes to remote server
velcrux watch ./workspace velcrux://backup.server/workspace/ \
  --debounce-ms 250 --poll-interval-ms 500

# Watch with custom exclusion glob filters
velcrux watch ./code velcrux://backup.server/code/ \
  --exclude "target/**" --exclude "*.tmp"

# Limit execution to a finite number of change batches (for automated tests / CI)
velcrux watch ./data velcrux://backup.server/data/ --max-batches 5
```

#### 2. Automated Sync with Continuous Watch Flag
```bash
# Synchronize existing directory contents first, then keep watching continuously
velcrux sync ./data velcrux://backup.server/data/ --watch

# Machine-readable JSON event stream
velcrux --json watch ./data velcrux://backup.server/data/
```

---

## 35. Cross-Cluster WAN Geo-Replication & Conflict Resolution (Option BA)

Per `REQUIREMENTS.md` §50–§55 ("Cross-Cluster WAN Replication & Multi-Datacenter Distribution") and §63 ("Disaster Recovery & High Availability"), Velcrux provides native asynchronous multi-datacenter data geo-replication, vector clock causality tracking, and deterministic conflict resolution.

### 1. Vector Clocks & Distributed Causality

Every replicated file maintains an active `VectorClock` tracking sequence progression per geographic region:
- **Causal Dominance**: When an incoming vector clock strictly dominates the local clock, changes are applied unconditionally without conflicts.
- **Concurrent Conflict Detection**: When concurrent independent mutations occur in separate regions (neither clock dominates the other), the conflict engine evaluates the active `--conflict-policy`.

### 2. Conflict Resolution Policies

Configure cross-region conflict resolution strategies via `--conflict-policy`:
- **`lww` (Last-Write-Wins, Default)**: Compares physical Unix epoch timestamps in milliseconds; ties are broken by lexicographical region ID order.
- **`primary` (Primary Authority)**: A designated authority region specified via `--primary-region <ID>` always wins conflicts against secondary regions.
- **`keep-both` (Branch Preservation)**: Preserves both concurrent versions by saving the losing mutation to a `.conflict-<region>-<ts>` sidecar file.
- **`reject` (Strict Safety)**: Rejects the incoming concurrent change and alerts operators for manual intervention.

### 3. Deletion Tombstones & Anti-Entropy Pacing

- **Tombstones**: File deletions create tombstone markers recording the deletion vector clock. Stale remote mutations with older vector clocks cannot resurrect deleted files.
- **Tombstone Pruning (`--tombstone-ttl-secs`, default: 7 days)**: Prunes tombstones older than the retention period.
- **Replication Pacing**: Outbound queues throttle replication streams to match WAN link bandwidth and prevent packet congestion.

### 4. CLI Administration Reference

#### 1. Inspect Regional Geo-Replication Status & Lag
```bash
# Display human-readable status table
velcrux geo status --local-region us-east-1

# Inspect with custom remote endpoints and Primary Authority policy
velcrux geo status \
  --local-region ap-tokyo-1 \
  --regions "eu-west-1=10.1.0.1:7443,us-east-1=10.2.0.1:7443" \
  --conflict-policy primary --primary-region us-east-1

# Machine-readable JSON metrics
velcrux --json geo status
```

#### 2. Synchronize Regional Clusters
```bash
# Execute cross-region synchronization and tombstone sweep
velcrux geo sync --source-region us-east-1 --target-region eu-central-1

# Machine-readable JSON output
velcrux --json geo sync --source-region us-east-1 --target-region eu-central-1
```

## 36. Pluggable Webhook Event Notifications & Audit Event Bus (Option BB)

Per `REQUIREMENTS.md` §69–§73 ("Audit Logging & Event Notification Webhooks") and `ARCHITECTURE.md` §11 ("Telemetry & Operational Visibility"), Velcrux provides an asynchronous, pluggable event bus (`WebhookEventBus`) for real-time lifecycle notifications and compliance audit logging.

### 1. Webhook Lifecycle Events

The event bus dispatches 8 standardized system events (`WebhookEventType`):
- `transfer.started`: Data transfer session initiated.
- `transfer.completed`: Data transfer successfully committed.
- `transfer.failed`: Transfer aborted due to network or validation errors.
- `chunk.corrupted`: Bit rot or BLAKE3 checksum mismatch detected.
- `cluster.node_changed`: Quorum storage node state transition (Healthy, Suspect, Dead).
- `geo.conflict_resolved`: Concurrent multi-region replication conflict resolved.
- `geo.tombstone_pruned`: Deletion tombstone expired and purged.
- `audit.action`: Security audit action (authentication, configuration changes, safe-deletes).

### 2. HMAC-SHA256 Signatures & Replay Prevention

Every webhook dispatch includes an `X-Velcrux-Signature` header:
```text
X-Velcrux-Signature: t=1710000000,v1=5d41402abc4b2a76b9719d911017c592...
```
- **Integrity**: Generated using `ring::hmac` (`HMAC_SHA256`) over `t={timestamp}.{payload_json}`.
- **Replay Protection**: Reject requests where $|t_{\text{current}} - t| > \Delta t_{\text{tol}}$ (default: 300 seconds).
- **Constant-Time Verification**: Validated in constant-time to resist timing attacks.

### 3. Retries & Dead-Letter Queue (DLQ)

- **Exponential Backoff**: Transient delivery failures trigger automatic retries up to `max_retries` (default: 3).
- **Dead-Letter Queue (DLQ)**: Failed events exceeding retry bounds are buffered into the bounded `WebhookDeadLetterQueue` for operator inspection and replay.

### 4. CLI Administration Reference

#### 1. List Subscriptions & Delivery Metrics
```bash
# Formatted status table
velcrux webhook list

# Machine-readable JSON output
velcrux --json webhook list
```

#### 2. Dispatch Signed Test Webhook Notification
```bash
# Test delivery with HMAC-SHA256 verification
velcrux webhook test https://hooks.slack.com/services/... \
  --secret "my-hmac-secret-k99" \
  --event "transfer.completed"

# Machine-readable JSON output
velcrux --json webhook test https://api.datadoghq.com/v1/events \
  --secret "dd-secret-token" \
  --event "chunk.corrupted"
```

#### 3. Dead-Letter Queue (DLQ) Inspection & Drain
```bash
# View DLQ status
velcrux webhook dlq

# Drain and clear DLQ entries
velcrux webhook dlq --drain

# Machine-readable JSON
velcrux --json webhook dlq --drain
```

## 37. Point-in-Time Snapshot Isolation & File Version History Engine (Option BC)

Per `REQUIREMENTS.md` §34 ("Atomicity"), §61 ("Transactional Synchronization"), §63 ("Garbage Collection"), and §94 ("Deliverables"), Velcrux provides zero-copy point-in-time snapshot isolation, structural change analysis, and verified time-travel rollbacks backed by content-addressed chunk storage (CAS).

### 1. CAS-Backed Deduplication & Zero-Copy Storage

Snapshots are stored as immutable manifests in `.velcrux/snapshots/<tag>.json` (or within `<chunk-store>/snapshots/`):
- **Content-Addressed Sharing**: File data is sliced into 64 KiB segments indexed by BLAKE3 hashes and stored in `LocalChunkStore`. Unchanged files across successive snapshots share identical chunks with zero disk storage overhead.
- **Manifest Atomicity**: Snapshots are staged to a `.json.tmp-...` buffer, flushed via `fsync`, and atomically renamed to guarantee durability against sudden process kills or machine reboots.

### 2. Snapshot Differential Analysis (`SnapshotDiff`)

Compare any two historical snapshots to instantly identify:
- **Added Files (`+`)**: Files present in the target snapshot but absent in the baseline.
- **Removed Files (`-`)**: Files deleted in the target snapshot.
- **Modified Files (`~`)**: Files with matching paths but altered BLAKE3 cryptographic hashes.
- **Unchanged Files**: Files byte-for-byte identical across versions.
- **Byte Deltas**: Exact net added and removed byte metrics.

### 3. Garbage Collection Integration

Snapshot chunks are automatically protected during chunk store maintenance:
```rust
velcrux_core::storage::gc_chunk_store_with_snapshots(
    &chunk_store,
    &[&storage_root],
    Some(&snapshot_manager),
    false,
)?;
```
Chunks referenced by any registered snapshot are pinned and cannot be pruned by garbage collection sweeps.

### 4. CLI Administration Reference

#### 1. Create a Snapshot
```bash
# Capture directory tree with CAS deduplication backing
velcrux snapshot create prod-v1.0 /data/app \
  --chunk-store /data/chunks \
  --desc "Production release v1.0"

# Machine-readable JSON output
velcrux --json snapshot create prod-v1.0 /data/app --chunk-store /data/chunks
```

#### 2. List Registered Snapshots
```bash
# Formatted catalog table
velcrux snapshot list --chunk-store /data/chunks

# Machine-readable JSON catalog
velcrux --json snapshot list --chunk-store /data/chunks
```

#### 3. Diff Two Snapshots
```bash
# Compare baseline and updated release
velcrux snapshot diff prod-v1.0 prod-v1.1 --chunk-store /data/chunks

# Machine-readable JSON diff
velcrux --json snapshot diff prod-v1.0 prod-v1.1 --chunk-store /data/chunks
```

#### 4. Restore a Point-in-Time Snapshot
```bash
# Time-travel rollback to a target destination directory
velcrux snapshot restore prod-v1.0 \
  --dest /data/app-rollback \
  --chunk-store /data/chunks

# Machine-readable JSON restore report
velcrux --json snapshot restore prod-v1.0 --dest /data/app-rollback --chunk-store /data/chunks
```

#### 5. Delete a Snapshot
```bash
# Delete snapshot manifest
velcrux snapshot delete prod-v0.9 --chunk-store /data/chunks

# Machine-readable JSON output
velcrux --json snapshot delete prod-v0.9 --chunk-store /data/chunks
```

---

## 38. Distributed Lock Manager (DLM) & Mutex Lease Coordinator

Per `REQUIREMENTS.md` §17 ("Distributed Coordination"), §20 ("High Availability & Quorum"), §31 ("Split-Brain Prevention"), §61 ("Transactional Synchronization"), and `ADR-020`, Velcrux includes an embedded Distributed Lock Manager (`DistributedLockManager`) to coordinate mutual exclusion across distributed sync nodes and worker instances.

### 1. Architectural Highlights

1. **Lock Modes**:
   - `Exclusive`: Single holder mutual exclusion for write transfers and directory mutations.
   - `Shared`: Multi-reader concurrency for integrity verification and snapshot read pipelines.
2. **Lease TTL & Heartbeats**:
   - Time-bounded leases (default: 60s, configurable up to 3600s) prevent persistent deadlocks on process termination or partition.
   - Heartbeat renewal (`renew`) extends lease expiration without token interruption.
3. **Monotonic Lamport Fencing Tokens**:
   - Strictly increasing tokens issued with every lease grant.
   - Target storage sinks call `verify_fencing(resource, token)` to reject stale out-of-order writes from delayed nodes.
4. **Crash-Resilient State Persistence**:
   - Atomic JSON staging (`tmp-<rand>` -> rename) ensures state recovery across daemon restarts.

### 2. Operational CLI Commands

#### 1. Acquire a Distributed Lock
```bash
# Acquire an exclusive write lock lease with 120s TTL
velcrux lock acquire /datasets/imagenet \
  --holder worker-node-01 \
  --mode exclusive \
  --ttl-secs 120

# Machine-readable JSON acquisition
velcrux --json lock acquire /datasets/imagenet --holder worker-node-01 --mode exclusive
```

#### 2. Renew an Active Lease
```bash
# Heartbeat extension by 300s
velcrux lock renew lck-101-39650 --holder worker-node-01 --ttl-secs 300

# Machine-readable JSON renewal
velcrux --json lock renew lck-101-39650 --holder worker-node-01 --ttl-secs 300
```

#### 3. Release a Lock
```bash
# Explicit lease surrender
velcrux lock release lck-101-39650 --holder worker-node-01

# Machine-readable JSON release
velcrux --json lock release lck-101-39650 --holder worker-node-01
```

#### 4. List Active Leases
```bash
# Formatted table of all active leases
velcrux lock list

# Filter by resource path
velcrux lock list --resource /datasets/imagenet

# Machine-readable JSON registry report
velcrux --json lock list
```

#### 5. Verify a Lamport Fencing Token
```bash
# Verify whether fencing token is active and authorized
velcrux lock verify /datasets/imagenet 101

# Machine-readable JSON verification
velcrux --json lock verify /datasets/imagenet 101
```

---

## 39. Dynamic Zstandard Pre-Trained Dictionary Learning Engine

Per `REQUIREMENTS.md` §89 ("Compression Design"), §26 ("Bandwidth Minimization"), §64 ("Wire Compression"), and `ADR-021`, Velcrux provides a native pre-trained dictionary learning engine to optimize compression ratios on small files and structured payloads (JSON, CSV, source code, microservice logs).

### 1. Key Capabilities

1. **Native Ingestion & Training**:
   - `DictionaryTrainer::sample_directory` walks directory trees, skips incompressible binary media (`.png`, `.jpg`, `.mp4`, `.gz`), and ingests up to 32 KiB per file.
   - Invokes pure-Rust zstd dictionary training (`zstd::dict::from_samples`) with bounded size (default 112 KiB).
2. **Persistent Catalog Management**:
   - Catalog index (`catalog.json`) and dictionary binaries (`<dict_id>.zdict`) stored under `.velcrux/dictionaries/`.
   - Thread-safe registry lookup by 32-bit `dict_id` or string `name`.
3. **Empirical Evaluation**:
   - Compares raw bytes, vanilla zstd, and dictionary zstd side-by-side.
   - Reports exact extra bandwidth savings percentage (typically 30–60% over standard zstd).
4. **Decompression Bomb Protection**:
   - Enforces strict memory ceilings and ratio limits (`decompress_with_dict_bounded`) to fail-closed on maliciously crafted dictionary payloads.

### 2. Operational CLI Commands

#### 1. Train a New Dictionary
```bash
# Train dictionary from directory of JSON logs
velcrux dict train /data/logs \
  --name json-logs-v1 \
  --dict-size 114688 \
  --desc "Trained dictionary for JSON application logs"

# Machine-readable JSON training output
velcrux --json dict train /data/logs --name json-logs-v1
```

#### 2. List Registered Dictionaries
```bash
# Formatted dictionary catalog
velcrux dict list

# Machine-readable JSON catalog
velcrux --json dict list
```

#### 3. Evaluate Dictionary Performance
```bash
# Evaluate compression ratio against a target directory or file
velcrux dict test 14285714 /data/logs/sample_batch

# Machine-readable JSON evaluation
velcrux --json dict test 14285714 /data/logs/sample_batch
```

#### 4. Export Dictionary
```bash
# Export dictionary binary for external sharing
velcrux dict export 14285714 ./exported_logs.zdict

# Machine-readable JSON export
velcrux --json dict export 14285714 ./exported_logs.zdict
```

#### 5. Import Pre-Existing Dictionary
```bash
# Import external dictionary into local catalog
velcrux dict import ./exported_logs.zdict --name imported-logs-v1

# Machine-readable JSON import
velcrux --json dict import ./exported_logs.zdict --name imported-logs-v1
```

#### 6. Delete Dictionary
```bash
# Delete dictionary by ID
velcrux dict delete 14285714

# Machine-readable JSON delete
velcrux --json dict delete 14285714
```

---

## 40. In-Flight Data Integrity Scrubbing & Background Bit-Rot Repair Daemon

Per `REQUIREMENTS.md` §18 ("Integrity Verification"), §63 ("Garbage Collection"), §70 ("Graceful Shutdown"), and `ADR-022`, Velcrux provides proactive cryptographic scrubbing and autonomous bit-rot repair to protect deduplicated storage repositories from silent data corruption.

### 1. Key Capabilities

1. **Cryptographic BLAKE3 Verification**:
   - Traverses the 2-level content-addressed chunk store (`chunks/ab/cd/*.chunk`) and verifies actual bytes against expected BLAKE3 digests.
   - Detects silent bit flips, truncated files, and disk controller corruption.
2. **Flexible Scrubbing Modes**:
   - `verify`: Read-only audit logging anomalies without altering disk.
   - `quarantine`: Moves corrupted chunks into `.quarantine/` holding area to prevent serving corrupted data.
   - `heal`: Automatically fetches healthy replicas from designated peer chunk stores (`--peer-store`) and rewrites damaged chunks in-place.
3. **Throttled I/O Rate-Limiting**:
   - Configurable `--rate-limit-mb` restricts read bandwidth to ensure scrubbing runs smoothly in the background without affecting production sync jobs.
4. **Persistent Audit History**:
   - Automatically saves detailed audit telemetry to `<chunk-store>/.velcrux/last_scrub.json`.
   - Inspectable anytime via `velcrux scrub status`.

### 2. Operational CLI Commands

#### 1. Audit Chunk Store Integrity
```bash
# Run read-only integrity audit across chunk store
velcrux scrub run /data/velcrux/chunks

# Run audit with I/O rate-limiting at 50 MB/s
velcrux scrub run /data/velcrux/chunks --rate-limit-mb 50

# Machine-readable JSON audit output
velcrux --json scrub run /data/velcrux/chunks
```

#### 2. Quarantine Corrupted Chunks
```bash
# Isolate bit-rotted chunks into quarantine directory
velcrux scrub run /data/velcrux/chunks --mode quarantine

# Custom quarantine directory
velcrux scrub run /data/velcrux/chunks --mode quarantine --quarantine-dir /data/quarantine
```

#### 3. Inspect Latest Scrub Status
```bash
# Display health report and findings from the latest scrub pass
velcrux scrub status /data/velcrux/chunks

# Machine-readable JSON status report
velcrux --json scrub status /data/velcrux/chunks
```

#### 4. Self-Healing Repair from Peer Store
```bash
# Repair corrupted or missing chunks using a reference peer store
velcrux scrub repair /data/velcrux/chunks --peer-store /backup/velcrux/chunks

# Machine-readable JSON repair report
velcrux --json scrub repair /data/velcrux/chunks --peer-store /backup/velcrux/chunks
```

---

## 41. Unix Stdin/Stdout Streaming Pipelines (Option BG)

Per `ADR-023`, Velcrux provides high-performance Unix pipe streaming to support continuous standard input (`stdin`) and standard output (`stdout`) operations directly over QUIC without intermediate local disk spooling.

### 1. Key Capabilities

1. **Zero-Spool Ingest & Egress**:
   - Streams bytes directly between OS pipes and network frames with zero disk write amplification.
   - Ideal for live database dumps (`mysqldump`, `pg_dump`), real-time archive creation (`tar`, `cpio`), and raw disk block streaming (`dd`).
2. **Sentinel Negotiation Protocol**:
   - `TransferCreate` utilizes `file_size: 0` and `file_hash: Hash::ZERO` to declare dynamically sized streams.
   - Bypasses upfront Bloom filter queries and FastCDC delta comparisons.
3. **End-to-End Cryptographic BLAKE3 Verification**:
   - Rolling BLAKE3 digests are computed incrementally on-the-fly as chunks are read and written.
   - Verified atomically upon stream EOF before final file commitment on the server.
4. **Log Hygiene & Byte Purity**:
   - Standard output (`stdout`) contains 100% byte-pure binary payload during streaming downloads (`velcrux download <url> -` or `velcrux stream recv <url>`).
   - All tracing, log messages, and transfer progress lines are strictly isolated to standard error (`stderr`), guaranteeing that downstream pipeline utilities never receive corrupted data.

### 2. Operational CLI Commands & Pipeline Examples

#### 1. Stream Upload via `upload -`
```bash
# Archive a directory on the fly and upload directly to remote server
tar czf - /var/log/nginx | velcrux upload - velcrux://server:4433/backups/nginx.tar.gz

# Stream database dump directly to remote storage
pg_dump -Fc mydb | velcrux upload - velcrux://server:4433/db_backups/mydb.dump

# Upload raw disk partition without intermediate image creation
dd if=/dev/sdb1 bs=4M | velcrux upload - velcrux://server:4433/disks/sdb1.raw
```

#### 2. Stream Download via `download <url> -`
```bash
# Download archive directly into tar for on-the-fly extraction
velcrux download velcrux://server:4433/backups/nginx.tar.gz - | tar xzf - -C /restore/nginx

# Restore database dump directly from remote stream
velcrux download velcrux://server:4433/db_backups/mydb.dump - | pg_restore -d mydb_restored

# Stream remote raw disk image directly onto block device
velcrux download velcrux://server:4433/disks/sdb1.raw - | dd of=/dev/sdc1 bs=4M status=progress
```

#### 3. Dedicated `stream` Subcommands
```bash
# Explicit streaming sender
cat sensitive_data.bin | gpg -e -r ops@company.com | velcrux stream send velcrux://server:4433/vault/data.gpg

# Explicit streaming receiver
velcrux stream recv velcrux://server:4433/vault/data.gpg | gpg -d > restored_data.bin
```

#### 4. Machine-Readable JSON Pipeline Telemetry
```bash
# Emit final streaming JSON summary to stderr while piping data
tar cf - /etc | velcrux --json stream send velcrux://server:4433/backups/etc.tar 2> stream_metrics.json
```

---

## 42. Adaptive Multi-Stream Forward Error Correction (Option BH)

Per `ADR-024`, Velcrux incorporates systematic $(K+M, K)$ Forward Error Correction (FEC) over Galois Field $GF(2^8)$ to protect bulk transfers across high-loss, high-latency satellite (LEO/GEO, Starlink, OneWeb), cellular backhaul, and impaired WAN links.

### 1. Key Capabilities

1. **Elimination of Retransmission Stalls (ARQ)**:
   - Recovers lost packet symbols in-flight without incurring full round-trip retransmission delays (100 ms to 650 ms).
   - Prevents QUIC congestion window collapse and head-of-line blocking under persistent packet drops.
2. **Maximum Distance Separable (MDS) Guarantee**:
   - Uses a Cauchy Generator Matrix over $GF(2^8)$ with disjoint coordinate sets $x_i = i, y_j = M + j$.
   - Any arbitrary $K$ received symbols out of $K+M$ can reconstruct 100% of the original payload byte-for-byte.
3. **Fast-Path XOR Parity ($M=1$)**:
   - When single parity is configured, uses SIMD-friendly XOR folding, achieving wire-speed recovery without matrix inversion overhead.
4. **Dynamic Loss Adaptation Tiers**:
   - `AdaptiveFecController` monitors real-time telemetry (packet drop rate $\lambda$ and smoothed RTT) and dynamically shifts coding rates:
     - **$\lambda < 0.5\%$**: $K=20, M=0$ (0.0% overhead, Maximum Goodput)
     - **$0.5\% \le \lambda < 2.0\%$**: $K=20, M=1$ (5.0% overhead, Fast-Path XOR)
     - **$2.0\% \le \lambda < 5.0\%$**: $K=16, M=2$ (12.5% overhead, Cauchy MDS)
     - **$5.0\% \le \lambda < 10.0\%$**: $K=10, M=2$ (20.0% overhead, Cauchy MDS)
     - **$\lambda \ge 10.0\%$**: $K=8, M=2$ (25.0% overhead, Satellite Grade)
5. **Pure-Rust & Zero Unsafe Code**:
   - Strictly `#![forbid(unsafe_code)]` with zero C/C++ dependencies or raw pointer manipulations.

### 2. Operational CLI Commands & Examples

#### 1. Inspect FEC Status & Loss Gating Tiers
```bash
# View active coding rate, Galois Field arithmetic configuration, and loss tiers
velcrux fec status

# Inspect specific profile preset (e.g. satellite)
velcrux fec status --profile satellite

# Machine-readable JSON output for monitoring / telemetry agents
velcrux --json fec status
```

#### 2. Run Loss Channel Erasure Simulation
```bash
# Simulate 5% channel packet drop on a 64 KiB payload using satellite FEC profile
velcrux fec test --profile satellite --loss-rate 0.05 --payload-size 65536

# Simulate 3% loss on high profile with custom PRNG seed
velcrux fec test --profile high --loss-rate 0.03 --payload-size 131072 --seed 12345

# Machine-readable JSON output for automated link validation
velcrux --json fec test --profile satellite --loss-rate 0.05
```

#### 3. Enable Forward Error Correction for Transfers
```bash
# Force satellite-grade FEC profile on high-loss WAN transfer
velcrux --fec satellite upload ./dataset.tar.gz velcrux://sat-gateway:7443/data/

# Use dynamic auto-adaptation (default)
velcrux --fec auto sync ./local_dir velcrux://remote-edge:7443/synced/

# Disable FEC for low-latency pristine local LAN transfers
velcrux --fec disabled upload ./largefile.bin velcrux://lan-host:7443/storage/
```

## 43. Calendar & Time-of-Day Bandwidth Scheduler (Option BI)

Per `ADR-025`, `REQUIREMENTS.md` §28, and `OPERATIONS.md` §4, §7, Velcrux incorporates an automated, calendar-aware and time-of-day bandwidth scheduling engine. It allows operators to dynamically adjust bandwidth pacing across business hours, evenings, and weekends without restarting transfer daemons or dropping active QUIC connections.

### 1. Key Capabilities

1. **Calendar Day-of-Week Matching**:
   - Supports natural day specifications: `Mon-Fri`, `Sat,Sun`, `Weekdays`, `Weekend`, `*` (all days), or contiguous ranges like `Tue-Fri`.
2. **Minute-Accurate & Overnight Windows**:
   - Supports standard daytime windows (`09:00-17:00`) and overnight windows spanning midnight (`22:00-06:00`).
3. **Multi-Rule Priority Cascading**:
   - Rules are evaluated first-match-wins with a fallback `default_rate` (e.g. `1Gbps` or `unlimited`).
4. **Seamless In-Flight Transitions**:
   - As local civil time crosses window boundaries, token refill rates update in real time in `ScheduledBandwidthLimiter`, `RateLimiter`, and `HierarchicalBandwidthAllocator`. Active transfers accelerate or throttle smoothly with **zero connection drops**.
5. **Pure-Rust Civil Time Arithmetic**:
   - Strictly `#![forbid(unsafe_code)]` with zero external date/time library dependencies. Calculates exact local civil time from Unix epoch timestamps and UTC minute offsets.
6. **SIGHUP Hot Reload**:
   - Updates schedule policies dynamically on SIGHUP while preserving accumulated tenant quota usage.

### 2. Server TOML Configuration

In `/etc/velcrux/velcruxd.toml`:

```toml
[network]
listen = "0.0.0.0:7443"
max_bandwidth = "10Gbps" # Server-wide aggregate ceiling

[bandwidth]
default_limit = "1Gbps"
timezone_offset_minutes = -300 # EST (UTC-5)

# Throttled daytime window during peak business hours
[[bandwidth.rule]]
id = "business-hours"
days = "Mon-Fri"
start = "09:00"
end = "17:00"
limit = "50Mbps"

# Uncapped transfer rate during weekends
[[bandwidth.rule]]
id = "weekend-boost"
days = "Sat,Sun"
limit = "unlimited"
```

Alternatively, inline rule strings can be specified directly:
```toml
[bandwidth]
schedule = "Mon-Fri 09:00-17:00: 50Mbps; Sat-Sun: unlimited; default: 1Gbps"
timezone_offset_minutes = 0
```

Environment variable override:
```bash
export VELCRUX_BANDWIDTH_SCHEDULE="Mon-Fri 08:30-17:30: 25Mbps; default: 2.5Gbps"
export VELCRUX_BANDWIDTH_TIMEZONE_OFFSET_MINUTES="-300"
```

### 3. Operational CLI Commands & Examples

#### 1. Inspect Bandwidth Schedule & Transition Countdown
```bash
# Inspect schedule rules, default rate, and current active status
velcrux schedule inspect --schedule "Mon-Fri 09:00-17:00: 50Mbps; Sat-Sun: unlimited; default: 1Gbps"

# Inspect from a policy file with local timezone offset (+330 for IST)
velcrux schedule inspect --schedule /etc/velcrux/bandwidth.sched --utc-offset 330

# Machine-readable JSON output for orchestration agents
velcrux --json schedule inspect --schedule "Mon-Fri 09:00-17:00: 50Mbps; default: 1Gbps"
```

#### 2. Evaluate Specific Epoch Timestamps
```bash
# Evaluate scheduled bandwidth rate at a specific Unix timestamp
velcrux schedule eval --schedule "Mon-Fri 09:00-17:00: 50Mbps; default: 1Gbps" --timestamp 1776162000

# Machine-readable evaluation JSON output
velcrux --json schedule eval --schedule "22:00-06:00: 10Gbps; default: 100Mbps" --timestamp 1776209400
```

#### 3. Client Dynamic Scheduled Transfers
```bash
# Apply dynamic calendar schedule to upload
velcrux --bandwidth-schedule "Mon-Fri 09:00-17:00: 20Mbps; default: 500Mbps" upload ./archive.tar.gz velcrux://backup-node:7443/backups/

# Apply schedule to continuous real-time directory synchronization
velcrux --bandwidth-schedule /etc/velcrux/sync_schedule.sched sync ./dataset velcrux://remote-storage:7443/shared/
```

---

## 44. Multi-Tenant Deduplication Poisoning Defense, Proof-of-Ownership & Quarantine Namespacing (Option BJ)

Per `ADR-026`, `SECURITY.md` §8 & §9, and resolving `CLAUDE.md` §4 Open Questions #3 & #4, Velcrux implements physical and cryptographic multi-tenant deduplication defense. This eliminates cross-tenant data leakage, content existence oracles, and deduplication cache poisoning across shared storage clusters.

### 1. Architectural Model & Policies

| Policy | Storage Path Layout | Security Invariant | Use Case |
|---|---|---|---|
| `isolated` (default) | `<root>/tenants/<tenant_id>/chunks/ab/cd/<hash>.chunk` | Physical directory partitioning. Tenant stores cannot observe or access chunks belonging to other tenants. | Multi-tenant SaaS, enterprise cloud, zero-trust environments. |
| `proof-of-ownership` | `<root>/shared/chunks/ab/cd/<hash>.chunk` + ACL table | Convergent deduplication. Tenants must present a cryptographic BLAKE3-KeyedHash Proof-of-Ownership token before referencing existing chunks. | Multi-tenant clusters sharing identical public datasets or container layers. |
| `global` | `<root>/chunks/ab/cd/<hash>.chunk` | Unrestricted single-tenant deduplication pool. | Single-tenant private clusters and local workstation transfers. |

### 2. In-Flight BLAKE3 Verification & Automated Quarantine

Any chunk copied from disk into a transfer staging file undergoes streaming BLAKE3 verification:
- If the computed hash does not match the chunk's content-addressed identity, the chunk is identified as corrupted or poisoned.
- The manager automatically removes the chunk from the live index and isolates it into `<root>/.quarantine/<hash>_<timestamp>_<random>.quarantine`.
- The in-flight transfer fails closed with `ProtocolError::Malformed`, protecting downstream file integrity and incrementing `poison_attempts` telemetry.

### 3. Server Configuration (`server.toml`)

```toml
[storage]
root = "/var/lib/velcrux/data"
staging = "/var/lib/velcrux/staging"
chunk_store = "/var/lib/velcrux/chunks"
dedup_policy = "isolated" # "isolated" (default), "proof-of-ownership", or "global"
# Optional 32-byte hex secret for Proof of Ownership token validation
dedup_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

Environment variable overrides:
```bash
export VELCRUX_STORAGE_DEDUP_POLICY="isolated"
export VELCRUX_STORAGE_DEDUP_SECRET="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

### 4. Operational CLI Commands & Examples

#### 1. Deduplication Status & Namespace Telemetry (`velcrux dedup status`)
```bash
# Inspect deduplication policy, active tenant stores, and quarantine metrics
velcrux dedup status --chunk-store /var/lib/velcrux/chunks

# Filter status for a specific tenant namespace
velcrux dedup status --chunk-store /var/lib/velcrux/chunks --tenant tenant-alpha

# Machine-readable JSON output for cluster monitoring
velcrux --json dedup status --chunk-store /var/lib/velcrux/chunks
```

#### 2. Deduplication Integrity Audit & Auto-Quarantine (`velcrux dedup verify`)
```bash
# Audit all chunk files across tenant and shared stores
velcrux dedup verify --chunk-store /var/lib/velcrux/chunks

# Verify specific tenant and quarantine corrupted chunks
velcrux dedup verify --chunk-store /var/lib/velcrux/chunks --tenant tenant-alpha --auto-quarantine true

# JSON audit report
velcrux --json dedup verify --chunk-store /var/lib/velcrux/chunks
```

#### 3. Quarantined Chunk Inspection & Purge (`velcrux dedup quarantine`)
```bash
# List all quarantined poisoned/corrupted chunks with timestamps and sizes
velcrux dedup quarantine list --chunk-store /var/lib/velcrux/chunks

# JSON quarantine inventory
velcrux --json dedup quarantine list --chunk-store /var/lib/velcrux/chunks

# Purge (permanently delete) all quarantined chunks to reclaim storage
velcrux dedup quarantine purge --chunk-store /var/lib/velcrux/chunks
```

---

## 45. Multi-Cloud Object Storage Gateways: Google Cloud Storage (GCS) and Azure Blob Storage (Option BK)

### 1. Overview & Architecture

Velcrux provides native, pure-Rust multi-cloud object storage gateways for **Google Cloud Storage (GCS)** and **Microsoft Azure Blob Storage (Azure Blob)** without external cloud SDKs or C libraries:
- **Zero-SDK Pure-Rust Implementation**: Built with `#![forbid(unsafe_code)]` compliance using workspace cryptography (`ring` and `sha2`).
- **URL Interoperability**: Transparent handling of `gs://<bucket>/<key>` and `az://<container>/<blob>` / `azure://<container>/<blob>`.
- **Chunked Resumable Uploads**: GCS Resumable Upload sessions and Azure Block Blob (`Put Block` + `Put Block List`) multi-chunk streaming pipelines.
- **Cryptographic BLAKE3 Metadata Preservation**: Stored in `x-goog-meta-blake3` and `x-ms-meta-blake3` alongside POSIX modes and timestamps.
- **Streaming Byte-Range Access**: Supports HTTP byte ranges for random reads, chunk extractions, and delta syncing.
- **Bi-directional Synchronization**: Bidirectional diffing, hash validation, and idempotent transfers between local filesystems and cloud containers.

---

### 2. Authentication & Environment Configuration

#### Google Cloud Storage (GCS)
| Variable | Description | Default |
|---|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to Google Service Account JSON credentials | None |
| `STORAGE_EMULATOR_HOST` / `GCS_ENDPOINT` | Custom GCS endpoint or local emulator | `https://storage.googleapis.com` |
| `GCS_ACCESS_TOKEN` / `GCS_TOKEN` | OAuth2 Bearer token override | None |

#### Azure Blob Storage
| Variable | Description | Default |
|---|---|---|
| `AZURE_STORAGE_ACCOUNT` | Azure Storage Account name | `devstoreaccount1` |
| `AZURE_STORAGE_KEY` / `AZURE_STORAGE_ACCESS_KEY` | Account SharedKey (base64-encoded) | None |
| `AZURE_STORAGE_SAS_TOKEN` | Shared Access Signature query string (e.g. `?sp=r&...`) | None |
| `AZURE_STORAGE_ENDPOINT` | Custom endpoint (e.g. Azurite emulator) | `https://<account>.blob.core.windows.net` |

---

### 3. Google Cloud Storage CLI Reference (`velcrux gcs`)

#### 1. Upload Object (`velcrux gcs put`)
```bash
# Upload a local file to GCS with automatic resumable chunking
velcrux gcs put ./backups/database.tar.gz gs://prod-backups/database.tar.gz

# Configure custom chunk size (e.g. 16 MiB)
velcrux gcs put ./archive.iso gs://prod-backups/archive.iso --chunk-size 16777216

# Upload via generic velcrux upload command
velcrux upload ./archive.iso gs://prod-backups/archive.iso
```

#### 2. Inspect Object Metadata (`velcrux gcs stat`)
```bash
# Human-readable inspection
velcrux gcs stat gs://prod-backups/database.tar.gz

# Machine-readable JSON output
velcrux --json gcs stat gs://prod-backups/database.tar.gz
```

#### 3. List Objects (`velcrux gcs ls`)
```bash
# List all objects matching prefix
velcrux gcs ls gs://prod-backups/2026/

# Hierarchical directory listing with delimiter
velcrux gcs ls gs://prod-backups/ --delimiter /
```

#### 4. Download Object or Byte Range (`velcrux gcs get`)
```bash
# Download complete object
velcrux gcs get gs://prod-backups/database.tar.gz ./restored.tar.gz

# Download specific byte range (first 64 KiB)
velcrux gcs get gs://prod-backups/database.tar.gz ./header.bin --range-start 0 --range-end 65535

# Download via generic velcrux download command
velcrux download gs://prod-backups/database.tar.gz ./restored.tar.gz
```

#### 5. Delete Object (`velcrux gcs delete`)
```bash
velcrux gcs delete gs://prod-backups/database.tar.gz
```

#### 6. Bi-directional Synchronization (`velcrux gcs sync`)
```bash
# Upload local directory to GCS bucket prefix
velcrux gcs sync ./local_data gs://prod-backups/datasets/

# Download GCS bucket prefix to local directory
velcrux gcs sync gs://prod-backups/datasets/ ./restored_data

# Automatic routing via top-level sync command
velcrux sync ./local_data gs://prod-backups/datasets/
```

---

### 4. Azure Blob Storage CLI Reference (`velcrux azure`)

#### 1. Upload Blob (`velcrux azure put`)
```bash
# Upload a local file to Azure Block Blob
velcrux azure put ./backups/database.tar.gz az://prod-backups/database.tar.gz

# Configure block size for multi-block streaming
velcrux azure put ./dataset.raw az://prod-backups/dataset.raw --block-size 8388608

# Upload via generic velcrux upload command
velcrux upload ./dataset.raw az://prod-backups/dataset.raw
```

#### 2. Inspect Blob Properties (`velcrux azure stat`)
```bash
# Human-readable properties
velcrux azure stat az://prod-backups/database.tar.gz

# Machine-readable JSON output
velcrux --json azure stat az://prod-backups/database.tar.gz
```

#### 3. List Blobs (`velcrux azure ls`)
```bash
# List all blobs in container or prefix
velcrux azure ls az://prod-backups/logs/

# Hierarchical delimiter navigation
velcrux azure ls az://prod-backups/ --delimiter /
```

#### 4. Download Blob or Byte Range (`velcrux azure get`)
```bash
# Download complete blob
velcrux azure get az://prod-backups/database.tar.gz ./restored.tar.gz

# Download byte range (bytes 1024-4096)
velcrux azure get az://prod-backups/database.tar.gz ./chunk.dat --range-start 1024 --range-end 4096

# Download via generic velcrux download command
velcrux download az://prod-backups/database.tar.gz ./restored.tar.gz
```

#### 5. Delete Blob (`velcrux azure delete`)
```bash
velcrux azure delete az://prod-backups/database.tar.gz
```

#### 6. Bi-directional Synchronization (`velcrux azure sync`)
```bash
# Upload local directory to Azure container prefix
velcrux azure sync ./local_data az://prod-backups/datasets/

# Download Azure container prefix to local directory
velcrux azure sync az://prod-backups/datasets/ ./restored_data

# Automatic routing via top-level sync command
velcrux sync ./local_data az://prod-backups/datasets/
```

---

## 46. Interactive Virtual Filesystem Mount Engine (Option BL)

Option BL implements a pure-Rust, `#![forbid(unsafe_code)]` virtual filesystem mount engine (`VirtualMountEngine`). It allows interactive browsing, directory traversal, and byte-range streaming from remote datasets, content-addressed chunk stores, point-in-time snapshots (`snapshot://<tag>`), or cloud object storage backends (`s3://`, `gs://`, `az://`) directly within the local filesystem directory tree.

### 1. Key Architectural Principles

1. **Zero External Kernel/C Dependencies**: Operates 100% in pure safe Rust without linking against `libfuse`, `macfuse`, or requiring OS kernel extensions. Deterministic and fully functional across macOS, Linux, and Windows containers without elevated `sudo` privileges.
2. **Canonical VFS Contract**: Supports standard virtual filesystem operations:
   - `lookup`: Inode resolution by component name.
   - `getattr`: POSIX file metadata (`ino`, `size`, `blocks`, `atime`, `mtime`, `ctime`, `perm`, `file_hash`).
   - `readdir`: Directory enumeration with `.` and `..` support.
   - `read_at`: Sub-range byte retrieval backed by the page cache.
   - `write_at`: Sub-range byte modification, dynamic resizing, and cryptographic BLAKE3 recalculation (on read-write mounts).
   - `create_file` & `remove_entry`: Dynamic file allocation and unlinking.
   - `create_symlink` & `readlink`: Symbolic link handling.
   - `statfs`: Virtual filesystem capacity geometry.
3. **High-Performance Bounded Page Cache**:
   - 64 KiB virtual page caching with monotonic LRU eviction.
   - Configurable memory capacity limits (`--cache-size-mb`) preventing out-of-memory errors on large datasets.
   - Configurable TTL invalidation (`--cache-ttl`) and sequential chunk prefetching (`--prefetch`).
4. **Persistent Mount Session Coordination**:
   - `MountManager` tracks active mount sessions in persistent registry storage (`velcrux_mount_registry.json`).
   - CLI subcommands (`velcrux mount list`, `velcrux mount status`, `velcrux unmount`) work across independent shell sessions.

### 2. Multi-Source Mounting Syntax

| Source Type | Source Specifier Example | Description |
|---|---|---|
| **Local Directory** | `./dataset` or `/var/data` | Physical directory hierarchy imported into virtual VFS |
| **Point-in-Time Snapshot** | `snapshot://prod-release-v1.0` | Read-only point-in-time snapshot catalog |
| **AWS S3 Object Store** | `s3://data-bucket/prefix/` | S3 cloud prefix mounted as virtual directory |
| **Google Cloud Storage** | `gs://ml-models/weights/` | GCS cloud prefix mounted as virtual directory |
| **Azure Blob Storage** | `az://training-data/runs/` | Azure Blob container prefix mounted as virtual directory |

### 3. CLI Command & Flag Reference

#### 1. Mount a Dataset (`velcrux mount attach`)
```bash
# Mount a local directory read-only with default 256 MiB page cache
velcrux mount attach ./raw_data /mnt/virtual_dataset

# Mount a point-in-time snapshot with custom cache size and prefetching
velcrux mount attach snapshot://daily-backup-20261016 /mnt/snapshots/daily \
  --cache-size-mb 512 \
  --prefetch 4

# Mount an S3 cloud prefix in read-write mode
velcrux mount attach s3://ml-datasets/imagenet/ /mnt/imagenet --rw

# Mount a GCS bucket in daemon background mode
velcrux mount attach gs://corp-archives/2026/ /mnt/archives -d

# Machine-readable JSON output
velcrux --json mount attach ./data /mnt/vfs
```

#### 2. List Active Virtual Mounts (`velcrux mount list`)
```bash
# Display human-readable table of active mount sessions
velcrux mount list

# Output format:
# SESSION ID                           PID  MODE  MOUNTPOINT                        SOURCE
# ------------------------------------ ----  ----  --------------------------------  --------------------------------
# vfs_01K...                           8412  RO    /mnt/virtual_dataset              ./raw_data
# vfs_01K...                           8412  RW    /mnt/imagenet                     s3://ml-datasets/imagenet/

# Machine-readable JSON output
velcrux --json mount list
```

#### 3. Inspect Mount Status & Cache Telemetry (`velcrux mount status`)
```bash
# Inspect all mounts
velcrux mount status

# Inspect specific mountpoint
velcrux mount status --mountpoint /mnt/virtual_dataset

# Machine-readable JSON metrics
velcrux --json mount status --mountpoint /mnt/virtual_dataset
```

#### 4. Unmount a Virtual Mountpoint (`velcrux mount detach` or `velcrux unmount`)
```bash
# Detach via mount subcommand
velcrux mount detach /mnt/virtual_dataset

# Detach via top-level unmount shortcut
velcrux unmount /mnt/virtual_dataset

# Machine-readable JSON output
velcrux --json unmount /mnt/virtual_dataset
```

---

## 47. Whole-Directory Transactional Commit & Rollback Journaling (Option BM)

Per `REQUIREMENTS.md` §58–§61 ("Atomic Multi-File Commits & Crash Resilient Journaling") and `ARCHITECTURE.md` §9 & §12, Velcrux provides true **directory-level atomicity** (all-or-nothing multi-file transfers) with write-ahead commit journaling and rollback recovery:
- **100% or 0% Guarantee**: 100% of files in a directory transfer/sync operation are committed simultaneously to destination, or 0% are committed (clean rollback with zero partial directory corruption).
- **Shadow Directory Staging (`.velcrux-shadow/<tx_id>/`)**: Incoming files stage in an isolated shadow directory without mutating live destination files.
- **Two-Phase Commit (2PC)**:
  1. **Prepare Phase**: Cryptographic BLAKE3 verification, file size checking, and original file backup into `.velcrux-backup/<tx_id>/`.
  2. **Commit Phase**: Write-ahead journal intent logging (`.velcrux-journal/<tx_id>.json`), atomic file swap into target directory.
  3. **Rollback Phase**: Automatic on failure or operator-triggered via `velcrux tx rollback <tx_id>`.
- **Startup Crash Recovery (`velcrux tx recover`)**: Scans write-ahead journals on startup to resolve any interrupted or crashed transactions.

### 1. Atomic Directory Synchronization (`--atomic`)

Synchronize a directory hierarchy with full all-or-nothing transactional semantics:

```bash
# Perform all-or-nothing atomic directory sync
velcrux sync ./deploy_bundle /var/www/app --atomic

# Atomic sync with safe deletions (deleted files backed up in journal)
velcrux sync ./release_v2 /var/www/app --atomic --delete-after

# Machine-readable JSON output
velcrux sync ./release_v2 /var/www/app --atomic --log-format json
```

### 2. Transaction Management CLI Reference (`velcrux tx`)

#### 1. Enumerate Historical & Pending Transactions (`velcrux tx list`)
```bash
# List all transactions recorded in target directory
velcrux tx list /var/www/app

# Machine-readable JSON output
velcrux tx list /var/www/app --json
```

Output format:
```text
TRANSACTION ID               STATE        FILES    TARGET
---------------------------- ------------ -------- ------------------------------
tx_1729241800_1              Committed    42       /var/www/app
tx_1729235400_1              RolledBack   18       /var/www/app
```

#### 2. Inspect Transaction Journal (`velcrux tx show`)
```bash
# Inspect transaction metadata and file actions
velcrux tx show tx_1729241800_1 --path /var/www/app

# Output formatted as JSON
velcrux tx show tx_1729241800_1 --path /var/www/app --json
```

Output format:
```text
Transaction ID: tx_1729241800_1
Target:         /var/www/app
State:          Committed
Created:        1729241800
Files:          3

ACTION   SIZE       RELATIVE PATH
-------- ---------- ------------------------------
Create   12.40 KB   assets/app.js
Update   4.20 KB    index.html
Delete   0 B        legacy.tmp
```

#### 3. Roll Back a Transaction (`velcrux tx rollback`)
Restore the target directory to its exact baseline before the transaction took place. Original files are restored from backup and newly created files are purged:

```bash
# Roll back transaction to restore previous baseline
velcrux tx rollback tx_1729241800_1 --path /var/www/app

# Machine-readable JSON output
velcrux tx rollback tx_1729241800_1 --path /var/www/app --json
```

#### 4. Crash Recovery (`velcrux tx recover`)
Scan a directory after a system crash, power failure, or process termination to cleanly recover any incomplete or interrupted transactions:

```bash
# Recover pending transactions in directory
velcrux tx recover /var/www/app

# Output formatted as JSON
velcrux tx recover /var/www/app --json
```

## 48. Strict RBAC & Policy-Gated Remote Deletion Enforcement (Option BN)

Per `CLAUDE.md` §4 Open Question #1 and `SECURITY.md` §4, Velcrux enforces strict server-side role-based access control (RBAC) and explicit policy gating on remote file deletions and directory pruning (`sync --delete`).

### 1. The Threat Model & Default Safety Invariant

Remote deletion is the most catastrophic failure mode in synchronization infrastructure. An unprivileged or compromised replication client with standard write permissions could issue bulk delete commands and permanently wipe remote datasets.

Velcrux resolves Open Question #1 with a fail-closed, multi-tier defense architecture:
1. **`sync` never deletes implicitly**: Only explicit `--delete` or `--delete-after` flags emit deletion commands.
2. **`PermSet::SYNC_DELETE` is distinct from `PermSet::DELETE`**: Standard file write or delete permissions do not authorize bulk synchronization deletions.
3. **`DeletionPolicy::AdminOnly` is the Server Default**: Non-admin clients are strictly forbidden from performing remote deletions regardless of their grant paths.

### 2. Deletion Governance Policies (`security.deletion_policy`)

Configure the governance policy in `velcruxd.toml`:

```toml
[security]
# Options: "admin-only" (default), "explicit-grant", "disabled", "rate-limited"
deletion_policy = "admin-only"

# Optional sliding-window rate limit configuration (for rate-limited policy)
deletion_rate_limit = 60           # Max deletions permitted per window
deletion_rate_window_secs = 60     # Sliding window size in seconds
```

- **`admin-only` (Default)**: Only identities carrying the `admin` permission may delete remote files or run `sync --delete`. Any non-admin deletion request is rejected with `ErrorCode::PermissionDenied`.
- **`explicit-grant`**: Remote deletions are permitted if the caller possesses explicit `delete` (for single files) or `sync_delete` / `role = "sync_replica"` (for directory sync deletions) on the target path.
- **`disabled`**: Remote deletions are globally rejected for all identities including administrators. Ideal for WORM (Write Once, Read Many) compliance and immutable backup repositories.
- **`rate-limited`**: Remote deletions are allowed (subject to permissions) but strictly rate-limited per identity. Exceeding the rate limit returns `ErrorCode::QuotaExceeded` and blocks further deletions until the window rolls over.

### 3. Predefined RBAC Roles

Role templates simplify operator grant management:

| Role | Permissions | Use Case |
|---|---|---|
| `admin` | `admin`, `upload`, `download`, `list`, `sync`, `resume`, `delete`, `sync_delete` | Storage administrators and root management |
| `operator` | `upload`, `download`, `list`, `sync`, `resume`, `delete` | Operations engineers performing targeted file maintenance |
| `sync_writer` | `upload`, `download`, `list`, `sync`, `resume` | Automated ingestion pipelines and backup writers (cannot delete) |
| `sync_replica` | `upload`, `download`, `list`, `sync`, `resume`, `sync_delete` | Active replication replicas authorized to prune extraneous files |
| `read_only` | `download`, `list` | Readers and consumers |

Configuration example:
```toml
[[grant]]
identity = "replica-prod-01"
path = "/data"
role = "sync_replica"

[[grant]]
identity = "ingest-pipeline"
path = "/incoming"
role = "sync_writer"
```

### 4. Operational Telemetry & Prometheus Metrics

Velcrux exports real-time deletion outcomes under the `velcrux_deletions_total` counter:

```text
# HELP velcrux_deletions_total Total remote file deletion attempts and outcomes
# TYPE velcrux_deletions_total counter
velcrux_deletions_total{outcome="attempted"} 142
velcrux_deletions_total{outcome="executed"} 140
velcrux_deletions_total{outcome="blocked"} 2
```

Audit logs log every deletion attempt with identity, path, sync flag, and policy evaluation:
```text
2026-10-19T12:00:00Z WARN velcruxd: deletion blocked: admin role required under AdminOnly policy identity="ingest-pipeline" path="incoming/old.dat" is_sync=true
2026-10-19T12:00:05Z INFO velcruxd: remote deletion executed successfully identity="replica-prod-01" path="data/stale.bin" is_sync=true
```

---

## 49. Cryptographic Detached Manifest Signing & End-to-End Attestation (Option BO)

Per `SECURITY.md` §7 and `ADR-031`, Velcrux provides end-to-end provenance attestation and non-repudiation for file sets and directory trees using detached Ed25519 digital signatures (`.velcrux-manifest.sig`).

### 1. Attestation Architecture & Guarantees

- **Detached Envelope (`AttestationEnvelope`)**: Detached signature files contain canonical claims binding an Ed25519 signature to the BLAKE3 root manifest hash, file count, total byte size, issuer identity, timestamps, expiration windows, and arbitrary key-value metadata.
- **Domain Separation**: All preimages begin with `VELCRUX-MANIFEST-ATTESTATION-V1\0`, preventing cross-protocol signature forgery (such as replaying attestation signatures in SSH authentication).
- **Secret Redaction**: Private keys in memory or configuration are wrapped in `Secret<Vec<u8>>` and render `[redacted]` in all log/debug contexts.
- **Offline & In-Flight Verification**: Attestations can be validated offline against stored directories or verified immediately following a `velcrux sync`.

### 2. CLI Administration Reference

#### Key Generation
```bash
# Generate fresh Ed25519 attestation keypair
velcrux attest keygen --out release.key --pub-out release.pub --comment "release-ci@velcrux.internal"
```

#### Signing Manifests
```bash
# Sign a directory tree or file
velcrux attest sign ./release-build \
  --key release.key \
  --out ./release-build/.velcrux-manifest.sig \
  --issuer "spiffe://velcrux.internal/release-ci" \
  --expires-in 604800 \
  -m build=v2.5.0 -m git=a1b2c3d

# Machine-readable JSON output
velcrux --json attest sign ./release-build --key release.key
```

#### Verifying Attestations
```bash
# Verify directory against detached signature and trusted keyring
velcrux attest verify ./release-build \
  --sig ./release-build/.velcrux-manifest.sig \
  --trusted-keys ./authorized_signers \
  --require-issuer "spiffe://velcrux.internal/release-ci"

# Machine-readable verification report
velcrux --json attest verify ./release-build --trusted-keys ./authorized_signers
```

#### Inspecting Claims
```bash
# Inspect envelope metadata without scanning disk
velcrux attest inspect ./release-build/.velcrux-manifest.sig
```

#### Sync Integration
```bash
# Automatically sign destination manifest on sync completion
velcrux sync ./src ./dst --sign-key release.key --sign-issuer "sync-daemon"

# Verify destination against signed attestation post-sync
velcrux sync ./src ./dst --verify-sig ./dst/.velcrux-manifest.sig --trusted-signers ./authorized_signers
```

### 3. Server Telemetry & Prometheus Metrics

Velcrux exports real-time attestation verification outcomes under `velcrux_attestations_total`:

```text
# HELP velcrux_attestations_total Total manifest attestation verification attempts and outcomes
# TYPE velcrux_attestations_total counter
velcrux_attestations_total{outcome="verified"} 84
velcrux_attestations_total{outcome="invalid"} 0
velcrux_attestations_total{outcome="rejected"} 1
```

## Extended Attribute (xattr) & ACL Transmutation (`ADR-032`, Option BP)

Velcrux automatically bridges Linux `user.*` namespace attributes and macOS reverse-DNS / un-prefixed attributes, while translating POSIX 1003.1e draft ACLs to Darwin NFSv4 ACEs.

### Telemetry & Prometheus Metrics

The server exports cross-platform transmutation counters under `velcrux_xattr_transmutations_total`:

```text
# HELP velcrux_xattr_transmutations_total Total cross-platform extended attribute and ACL transmutations
# TYPE velcrux_xattr_transmutations_total counter
velcrux_xattr_transmutations_total{direction="all"} 42
velcrux_xattr_transmutations_total{direction="linux_to_macos"} 28
velcrux_xattr_transmutations_total{direction="macos_to_linux"} 14
```

### Operational CLI Flags (`velcrux sync`)

- `--xattr-policy <transmute|strict|sidecar|strip>`:
  - `transmute` (default): Translates attribute namespaces bidirectionally (e.g. `user.mime_type` on Linux <-> `mime_type` on macOS).
  - `strict`: Preserves raw attribute names; warns/rejects on invalid namespaces.
  - `sidecar`: Stores attributes directly in `.<filename>.velcrux-xattr` metadata sidecars.
  - `strip`: Discards extended attributes entirely.
- `--acl-policy <transmute|strict|sidecar|strip>`:
  - `transmute` (default): Translates between POSIX 1003.1e draft ACLs (`system.posix_acl_access`) and Darwin NFSv4 ACEs (`com.apple.acl.text`).
  - `strict`: Rejects ACL application if the target format differs.
  - `sidecar`: Preserves original ACLs in metadata sidecars.
  - `strip`: Strips ACL entries, preserving standard POSIX file mode bits.

## Content-Aware Delta Compression Engine (`ADR-033`, Option BQ)

Velcrux uses baseline destination extents as instant, pre-trained Zstandard compression dictionaries to achieve 5× to 50× compression ratios on modified chunks without requiring pre-trained dictionary catalogs.

### Telemetry & Prometheus Metrics

The server exports delta slice processing counters and savings metrics:

```text
# HELP velcrux_delta_slices_total Total content-aware delta slices processed
# TYPE velcrux_delta_slices_total counter
velcrux_delta_slices_total{kind="all"} 1250
velcrux_delta_slices_total{kind="dict"} 1120
velcrux_delta_slices_total{kind="vanilla"} 130

# HELP velcrux_delta_dict_bytes_saved_total Total bytes saved via zstd dictionary delta compression
# TYPE velcrux_delta_dict_bytes_saved_total counter
velcrux_delta_dict_bytes_saved_total 485921800
```

### Operational CLI Flags (`velcrux sync`)

- `--delta-dict <auto|off|aggressive>` (env: `VELCRUX_DELTA_DICT`):
  - `auto` (default): Employs dictionary compression against baseline extents when savings meet or exceed the savings threshold.
  - `off`: Disables delta dictionary compression; transfers standard chunks or standalone Zstd.
  - `aggressive`: Evaluates offset-adjusted reference windows with a lowered savings threshold (5%).
- `--delta-dict-threshold <pct>` (env: `VELCRUX_DELTA_DICT_THRESHOLD`, default: 15):
  - Minimum percentage savings over uncompressed chunk size required to commit dictionary compression.

### CLI Inspection & Testing Tool (`velcrux delta-slice test`)

Operators can evaluate chunk slicing and dictionary compression ratios directly:

```bash
# Evaluate delta compression between source and baseline files
velcrux delta-slice test /path/to/target.log /path/to/baseline.log --chunk-size 65536 --policy auto

# Machine-readable JSON output
velcrux delta-slice test /path/to/target.log /path/to/baseline.log --json
```

## Adaptive Bandwidth Delay Product (BDP) Auto-Tuning Engine (`ADR-034`, Option BR)

Velcrux continuously sizes QUIC flow control windows and pipeline buffering using live path telemetry (smoothed RTT, min RTT, and delivery rate) to sustain 10 Gbps line-rate transfer on high-BDP WAN and satellite paths while preventing bufferbloat.

### Telemetry & Prometheus Metrics

The server exports real-time BDP window sizing and adjustment telemetry:

```text
# HELP velcrux_bdp_current_window_bytes Current active flow control window in bytes
# TYPE velcrux_bdp_current_window_bytes gauge
velcrux_bdp_current_window_bytes 393216000

# HELP velcrux_bdp_estimated_bps Estimated path bandwidth in bits per second
# TYPE velcrux_bdp_estimated_bps gauge
velcrux_bdp_estimated_bps 9850000000

# HELP velcrux_bdp_tuning_adjustments_total Total BDP window auto-tuning adjustments
# TYPE velcrux_bdp_tuning_adjustments_total counter
velcrux_bdp_tuning_adjustments_total{direction="expand"} 18
velcrux_bdp_tuning_adjustments_total{direction="decay"} 2
velcrux_bdp_tuning_adjustments_total{direction="hold"} 45
```

### Global CLI Flags

- `--bdp-tuning <auto|fixed|aggressive|conservative>` (env: `VELCRUX_BDP_TUNING`, default: `auto`):
  - `auto`: Dynamically sizes receive and flow control windows using 2.0× BDP multiplier and 1.5× bufferbloat queue ratio.
  - `fixed`: Static flow control window without dynamic resizing.
  - `aggressive`: Uses 3.0× BDP multiplier and reduced decay sensitivity for high-loss WAN / satellite links.
  - `conservative`: Uses 1.4× BDP multiplier and rapid decay on queue buildup to protect shared enterprise LANs.
- `--max-bdp-window <bytes>` (env: `VELCRUX_MAX_BDP_WINDOW`, default: `536870912` / 512 MiB):
  - Upper ceiling for flow control window expansion.
- `--min-bdp-window <bytes>` (env: `VELCRUX_MIN_BDP_WINDOW`, default: `4194304` / 4 MiB):
  - Lower floor for flow control window decay.

### CLI Management & Simulation Tool (`velcrux bdp`)

Operators can inspect active configuration and simulate path auto-tuning behavior:

```bash
# Inspect current BDP configuration and window floor/ceiling
velcrux bdp inspect

# Machine-readable JSON status
velcrux bdp inspect --json

# Simulate BDP auto-tuning across a transatlantic 10 Gbps 150 ms link
velcrux bdp simulate --bandwidth 10Gbps --rtt-ms 150 --policy aggressive

# Simulate satellite link with packet loss and bufferbloat decay
velcrux bdp simulate --bandwidth 100Mbps --rtt-ms 250 --loss-pct 3.0 --policy conservative --json
```

## 39. Zero-Copy Kernel Direct I/O (`O_DIRECT` / `F_NOCACHE`) Ring-Buffer Pipeline (ADR-035, Option BS)

The Direct I/O ring buffer pipeline allows operators to stream bulk file transfers directly between physical NVMe storage and DMA-aligned memory, completely bypassing the operating system page cache to prevent memory exhaustion, cache eviction, and copy overhead.

### Prometheus Metrics

Exported under `/metrics` matching the specification in §7:

```prometheus
# HELP velcrux_direct_io_ring_transfers_total Total Direct I/O ring-buffer transfers executed
# TYPE velcrux_direct_io_ring_transfers_total counter
velcrux_direct_io_ring_transfers_total 42

# HELP velcrux_direct_io_ring_bytes_total Total bytes processed through Direct I/O ring-buffer pipeline
# TYPE velcrux_direct_io_ring_bytes_total counter
velcrux_direct_io_ring_bytes_total 35184372088832

# HELP velcrux_direct_io_ring_stalls_total Total ring-buffer pipeline stall events waiting for slots
# TYPE velcrux_direct_io_ring_stalls_total counter
velcrux_direct_io_ring_stalls_total 12
```

### Global CLI Flags

- `--direct-io <auto|always|disabled>` (env: `VELCRUX_DIRECT_IO`, default: `auto`):
  - `auto`: Automatically engages Direct I/O for files $\ge$ 16 MiB when supported by the filesystem, with graceful fallback to standard buffered streaming if unsupported.
  - `always`: Strictly enforces Direct I/O; operations fail if unsupported by the target filesystem.
  - `disabled`: Disables Direct I/O entirely, always using standard OS buffered streaming.
- `--direct-io-slots <n>` (env: `VELCRUX_DIRECT_IO_SLOTS`, default: `4`):
  - Number of circular DMA buffer slots in the ring buffer pipeline (valid: 2–32).
- `--direct-io-slot-size <bytes>` (env: `VELCRUX_DIRECT_IO_SLOT_SIZE`, default: `2097152` / 2 MiB):
  - Capacity in bytes for each sector-aligned ring slot (aligned to 4096-byte boundaries).

### Operational CLI Tools (`velcrux direct-io`)

Operators can inspect filesystem sector alignment support and benchmark storage throughput:

```bash
# Inspect current Direct I/O policy, sector sizes, and ring configuration
velcrux direct-io inspect

# Test whether a specific file or storage mount is eligible for Direct I/O
velcrux direct-io inspect --path /mnt/nvme/largefile.tar

# Machine-readable inspection output
velcrux direct-io inspect --path /data --json

# Run end-to-end write-then-read throughput benchmark with 32 MiB test payload
velcrux direct-io benchmark --path /tmp/bench.bin --size 33554432

# High-concurrency benchmark with 8 slots of 4 MiB each and JSON report
velcrux direct-io benchmark --path /data/bench.bin --size 67108864 --slots 8 --slot-size 4194304 --json
```

## 41. Persistent Transfer Checkpointing, SQLite WAL Management & Fast Recovery (ADR-036, Option BT)

Velcrux implements a persistent transfer checkpointing engine with SQLite Write-Ahead Logging (WAL) and bounded chunk-completion bitmaps (`REQUIREMENTS.md` §68, §69, `ADR-036`). It allows interrupted transfers on multi-terabyte datasets to resume instantaneously without directory re-scans, while strictly controlling WAL file bloat and write amplification.

### Architecture Highlights
- **Instantaneous Resume**: Startup recovery interrogates the SQLite database and chunk bitmaps directly. File lengths and verified extents are confirmed in milliseconds without traversing destination directory trees.
- **SQLite WAL Flushing**: Programmatic control over SQLite's Write-Ahead Log via `wal_checkpoint` (`truncate`, `passive`, `full`, `restart`) to prevent unbounded log page accumulation during high-throughput streams.
- **Stale Checkpoint Pruning**: Automatic or operator-driven purging of obsolete completed or cancelled transfer rows and chunk bitmaps.

### Global CLI Flags
- `--checkpoint-interval <seconds>` (env: `VELCRUX_CHECKPOINT_INTERVAL`, default: `10`):
  - Maximum elapsed duration between durable checkpoint commits.
- `--checkpoint-bytes <bytes>` (env: `VELCRUX_CHECKPOINT_BYTES`, default: `268435456` / 256 MiB):
  - Maximum unpersisted byte threshold between checkpoints.
- `--wal-autocheckpoint <pages>` (env: `VELCRUX_WAL_AUTOCHECKPOINT`, default: `1000`):
  - SQLite WAL auto-checkpoint page limit (~4 MiB).

### Operational CLI Tools (`velcrux checkpoint`)

```bash
# Display all active resumable transfers, completion progress, and SQLite WAL status
velcrux checkpoint status

# Machine-readable status report for monitoring or automation
velcrux checkpoint status --json

# Inspect server-side checkpoint database
velcrux checkpoint status --role server

# Perform instantaneous recovery of all interrupted transfers without directory re-scans
velcrux checkpoint recover

# Verify and inspect single transfer recovery status by transfer ID
velcrux checkpoint recover --transfer-id 01H7PZ28ZBN74C5K3X90123456

# Explicitly flush and truncate the SQLite Write-Ahead Log
velcrux checkpoint wal-flush --mode truncate

# Opportunistic background WAL flush without reader/writer lock contention
velcrux checkpoint wal-flush --mode passive

# Prune completed and cancelled transfer checkpoints older than 7 days (default: 604800s)
velcrux checkpoint prune --older-than-secs 604800
```

### Prometheus Observability

Exposed under `/metrics`:
- `velcrux_transfer_checkpoints_total`: Cumulative transfer checkpoints committed to durable store.
- `velcrux_transfer_checkpoint_bytes_total`: Cumulative bytes acknowledged and checkpointed.
- `velcrux_transfer_recoveries_total`: Total transfer recovery operations executed.
- `velcrux_wal_checkpoints_total`: Total SQLite WAL checkpoints executed.

## 42. Hierarchical Token-Bucket (HTB) Quality of Service (QoS) & Flow Priority Multiplexer (ADR-037, Option BU)

Velcrux incorporates a hierarchical fair-queueing and token-bucket Quality of Service (QoS) scheduler across concurrent transfers (`REQUIREMENTS.md` §28, §29, `ADR-037`). It guarantees minimum Committed Information Rates (CIR) for mission-critical and interactive traffic while dynamically borrowing spare capacity up to Peak Information Rate (PIR) ceilings.

### Architecture Highlights
- **Dual-Rate Token Bucket (`HtbTokenBucket`)**: Dedicated CIR and PIR token pools provide guaranteed bandwidth minimums and burst allowances without starvation.
- **Priority Classes & Deficit Round-Robin**:
  - `Realtime`: Strict preemptive drain for interactive commands, pings, and urgent metadata.
  - `Critical`, `Default`, `Background`: Interleaved via 4:2:1 Weighted Round-Robin (WRR) to guarantee proportional fairness.
- **Tenant Bandwidth Isolation**: Operators can bind custom CIR/PIR policies to specific tenant identifiers.

### Global CLI Flags
- `--qos-priority <realtime|critical|default|background>` (env: `VELCRUX_QOS_PRIORITY`, default: `default`):
  - Assigns traffic classification tier to client commands and sync jobs.
- `--qos-bandwidth <rate>` (env: `VELCRUX_QOS_BANDWIDTH`, default: `unlimited`):
  - Root link bandwidth ceiling (e.g. `10Gbps`, `1Gbps`, `500Mbps`, or `unlimited`).

### Operational CLI Tools (`velcrux qos`)

```bash
# Inspect bandwidth allocations, CIR percentages, and PIR ceilings
velcrux qos inspect

# Evaluate class allocations under a custom link speed (e.g. 1 Gbps)
velcrux qos inspect --bandwidth 1Gbps

# Machine-readable JSON allocation schema
velcrux qos inspect --bandwidth 10Gbps --json

# Run in-memory contention benchmark evaluating CIR guarantees and capacity borrowing
velcrux qos benchmark --bandwidth 100Mbps --packets 100

# Machine-readable benchmark report
velcrux qos benchmark --bandwidth 1Gbps --packets 500 --json

# Display current client QoS status and scheduling properties
velcrux qos status

# Inspect active client QoS configuration with custom priority
velcrux --qos-priority critical --qos-bandwidth 2Gbps qos status --json
```

### Prometheus Observability

Exposed under `/metrics`:
- `velcrux_qos_tokens_consumed_total`: Cumulative tokens / bytes admitted across all QoS classes.
- `velcrux_qos_tokens_borrowed_total`: Cumulative tokens borrowed from idle spare link capacity.
- `velcrux_qos_delays_total`: Total rate-throttling events requiring transmission delay.
- `velcrux_qos_class_bytes_total{class="realtime|critical|default|background"}`: Bytes transmitted per QoS priority class.

## 43. Content-Addressable Storage (CAS) Generational GC, Tombstoning & Compaction Daemon (ADR-038, Option BV)

Velcrux implements a generational Content-Addressable Storage (CAS) garbage collector and compaction daemon (`REQUIREMENTS.md` §61, §62, `ADR-038`). It partitions chunk lifecycles into generational tiers to prevent race conditions with in-flight transfers, safely marks unreferenced chunks with resurrectable tombstones, and purges expired data while reclaiming shard directory inodes.

### Architecture Highlights
- **Generational Classification**:
  - `Nursery` (Gen 0): Chunks younger than `--cas-nursery-grace` (default: 3600s / 1 hour) are protected from tombstoning, guaranteeing race-free in-flight uploads.
  - `Tenured` (Gen 1): Actively referenced chunks verified by storage trees, database manifests, and snapshots.
  - `Tombstoned` (Gen 2): Unreferenced chunks marked with a companion `<hex>.tombstone` metadata file.
- **Instantaneous Safe Resurrection**: If a transfer or user references a tombstoned chunk prior to TTL expiry, the tombstone is removed atomically without re-uploading payload bytes.
- **Compaction & Shard Inode Reclamation**: Expired tombstones and underlying payload chunks are unlinked, and empty two-level shard directories (`chunks/ab/cd/`) are pruned automatically.

### Global CLI Flags
- `--cas-tombstone-ttl <seconds>` (env: `VELCRUX_CAS_TOMBSTONE_TTL`, default: `86400` / 24 hours):
  - Retention duration for tombstoned chunks before hard physical purge.
- `--cas-nursery-grace <seconds>` (env: `VELCRUX_CAS_NURSERY_GRACE`, default: `3600` / 1 hour):
  - In-flight lease duration protecting newly written chunks from garbage collection.

### Operational CLI Tools (`velcrux cas`)

```bash
# Display CAS inventory, generational chunk counts, and reclaimable bytes
velcrux cas status

# Inspect remote or custom chunk store root in machine-readable JSON
velcrux cas status --chunk-store /mnt/storage/chunks --json

# Run generational mark-and-sweep garbage collection in dry-run simulation mode
velcrux cas gc --dry-run

# Run mark-and-sweep with custom nursery grace and hard-purge expired tombstones
velcrux cas gc --nursery-grace 1800 --purge-expired

# Resurrect a tombstoned chunk back to active tenured service
velcrux cas resurrect --hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# Hard-purge tombstones older than 7 days (604800s) and reclaim physical disk space
velcrux cas purge --older-than-secs 604800

# JSON report of purge operation for audit trails
velcrux cas purge --older-than-secs 86400 --json
```

### Prometheus Observability

Exposed under `/metrics`:
- `velcrux_cas_gc_runs_total`: Cumulative generational GC compaction sweeps.
- `velcrux_cas_chunks_tombstoned_total`: Cumulative chunks transitioned to tombstone status.
- `velcrux_cas_chunks_resurrected_total`: Cumulative tombstoned chunks resurrected back to active service.
- `velcrux_cas_chunks_purged_total`: Total physical CAS chunk files permanently deleted.
- `velcrux_cas_bytes_reclaimed_total`: Cumulative physical disk bytes reclaimed from storage.

## 44. Distributed Gossip-Based Peer Discovery & Swarm P2P Acceleration Engine (ADR-039, Option BW)

Velcrux includes a high-performance distributed gossip peer discovery and BitTorrent-style cooperative swarm P2P acceleration engine (`REQUIREMENTS.md` §76, §77, `ADR-039`). It allows worker clusters (Kubernetes worker pools, AI training nodes, build farms) to discover adjacent peers via epidemic gossip (SWIM protocol) and cooperatively transfer content chunks using Rarest-First scheduling, reducing origin server egress bandwidth by 80-95%+ while actively defending against Byzantine chunk poisoning with cryptographic BLAKE3 verification.

### Global CLI Flags
- `--swarm` (env: `VELCRUX_SWARM`, default: `false`):
  - Enables swarm peer-to-peer acceleration and gossip discovery.
- `--swarm-port <port>` (env: `VELCRUX_SWARM_PORT`, default: `19444`):
  - Gossip and P2P communication listening port.
- `--swarm-seeds <addr,addr>` (env: `VELCRUX_SWARM_SEEDS`, default: `""`):
  - Comma-delimited list of known bootstrap seed peer socket addresses (e.g. `10.0.0.1:19444,10.0.0.2:19444`).
- `--swarm-max-peers <count>` (env: `VELCRUX_SWARM_MAX_PEERS`, default: `50`):
  - Maximum concurrent peer connections maintained in the swarm mesh.

### Operational CLI Tools (`velcrux swarm`)

```bash
# Display swarm mesh health status, peer state breakdown, and egress offload ratio
velcrux swarm status

# Machine-readable JSON status report for monitoring and alerting agents
velcrux swarm status --json

# List all discovered peers in the mesh, along with incarnation counters and RTT latencies
velcrux swarm peers

# Machine-readable JSON peer inventory
velcrux swarm peers --json

# Bootstrap peer discovery via custom seed addresses
velcrux --swarm-seeds 10.0.1.5:19444,10.0.1.6:19444 swarm peers

# Advertise a file manifest or directory to the swarm gossip mesh
velcrux swarm advertise ./models/checkpoint.bin

# Advertise an entire dataset directory in JSON format
velcrux swarm advertise /data/train_set --json

# Run an in-memory multi-node swarm P2P simulation benchmark
velcrux swarm benchmark --nodes 10 --chunks 50

# Machine-readable benchmark telemetry asserting >80% offload ratio
velcrux swarm benchmark --nodes 20 --chunks 100 --json
```

### Prometheus Observability

Exposed under `/metrics`:
- `velcrux_swarm_peers_active`: Gauge of alive routable peers participating in the swarm mesh.
- `velcrux_swarm_bytes_transferred_total{direction="inbound|outbound"}`: Total bytes transferred cooperatively via peer-to-peer sharing.
- `velcrux_swarm_offloaded_bytes_total`: Total server egress bytes saved through cooperative P2P transfers.
- `velcrux_swarm_chunks_poisoned_rejected_total`: Total corrupted or poisoned chunks detected and blocked, with rogue peers banned.







