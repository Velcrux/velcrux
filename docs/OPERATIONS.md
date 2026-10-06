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
