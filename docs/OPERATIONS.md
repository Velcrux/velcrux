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




