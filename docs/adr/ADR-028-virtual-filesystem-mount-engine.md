# ADR-028: Interactive Virtual Filesystem Mount Engine (`velcrux mount`)

Status: Accepted · Date: 2026-10-16

## Context

While Velcrux excels at bulk and delta point-to-point data synchronization, modern cloud-native, AI/ML, and edge workflows frequently require on-demand, interactive exploration and byte-range streaming from large datasets without downloading terabytes of data in advance.

Key requirements:
1. **Interactive Virtual Directory Hierarchy**: Mount remote datasets, content-addressed chunk stores, point-in-time snapshots (`snapshot://<tag>`), or cloud storage backends (`s3://`, `gs://`, `az://`) directly into the local filesystem namespace.
2. **Strict `#![forbid(unsafe_code)]` Compliance**: Traditional FUSE libraries (such as `fuser` or C-based `libfuse`/`macfuse`) link against external system C libraries or kernel extensions, include substantial `unsafe` blocks, and fail on containerized or minimal CI environments. The solution must be written in 100% pure, safe Rust.
3. **Standard Virtual Filesystem (VFS) Contract**: Support canonical VFS primitives: `lookup`, `getattr`, `readdir`, `read_at`, `write_at`, `create_file`, `create_symlink`, `readlink`, `remove_entry`, and `statfs`.
4. **Bounded Memory Page Cache with Prefetching**: High-performance thread-safe page cache (`VfsPageCache`) with bounded capacity, LRU eviction, time-to-live (TTL) invalidation, and configurable read-ahead prefetching for sequential streaming workloads.
5. **Multi-Source Virtual Mounting**:
   - Local directory hierarchies (`./path`)
   - Point-in-time snapshots (`snapshot://<tag>`)
   - Cloud object storage buckets (`s3://...`, `gs://...`, `az://...`)
6. **Cross-Process Mount Session Management**: Persistent session coordination via `MountManager` and registry storage (`velcrux_mount_registry.json`) allowing CLI commands (`velcrux mount list`, `velcrux mount status`, `velcrux unmount`) to inspect and manage mounts across independent process invocations.

## Options Considered

1. **Kernel FUSE Bindings via External C Libraries (`libfuse` / `macfuse` / `fuser`)**:
   - Bind to operating system FUSE kernel drivers.
   - *Rejected*: Violates `#![forbid(unsafe_code)]` workspace invariant, requires host kernel extensions not present in unprivileged containers or minimal CI runners, and introduces cross-platform fragility.
2. **Network File Sharing Server (NFSv4 or WebDAV Daemon)**:
   - Run a local network file server and invoke OS `mount -t nfs` or `mount_webdav`.
   - *Rejected*: Introduces network port contention, OS-specific credential handling, elevated privileges (`sudo`), and complex network daemon lifecycles.
3. **Pure-Rust Virtual Filesystem Engine (`VirtualMountEngine`) with Persistent Mount Coordinator**:
   - Implement an in-memory virtual inode table (`VfsInodeTable`), standard VFS operational contracts, bounded LRU page cache (`VfsPageCache`), and multi-source initializers in `velcrux-core::storage::vfs`.
   - Provide CLI commands (`velcrux mount attach`, `velcrux mount list`, `velcrux mount status`, `velcrux mount detach`, `velcrux unmount`) with daemon and interactive session modes.
   - Deliver comprehensive mock and integration tests verifying VFS semantics across macOS, Linux, and Windows without root privileges or kernel extensions.

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. Inode Table & Path Resolution (`VfsInodeTable`)
- Monotonic inode allocation beginning at `VFS_ROOT_INODE` (1).
- Bidirectional mapping between relative paths and allocated inodes.
- Node contents represent directories (`BTreeMap<String, u64>`), regular files (`Vec<u8>` or content hashes), and symbolic links (`String` target).
- POSIX attributes (`VfsAttr`): inode, size, 512B blocks, timestamps (`atime`, `mtime`, `ctime`), mode permissions (`perm`), user/group IDs, and cryptographic BLAKE3 content hash.

### 2. High-Performance Bounded Page Cache (`VfsPageCache`)
- Thread-safe memory cache keyed by `(ino, chunk_idx)` using 64 KiB virtual pages.
- Strict memory capacity bounds with automatic LRU eviction based on access counters.
- TTL-based invalidation ensuring stale data is refreshed on subsequent lookups.
- Telemetry reporting: cache hits, misses, evictions, and current memory footprint.

### 3. VFS Operational Contract (`VirtualMountEngine`)
- `lookup(parent_ino, name) -> Option<VfsAttr>`
- `getattr(ino) -> Option<VfsAttr>`
- `readdir(ino) -> Vec<VfsDirEntry>` (including `.` and `..`)
- `read_at(ino, offset, size) -> Vec<u8>` with page cache integration
- `write_at(ino, offset, data) -> usize` with read-only enforcement and BLAKE3 re-hashing
- `create_file(parent_ino, name, mode) -> VfsAttr`
- `create_symlink(parent_ino, name, target) -> VfsAttr` & `readlink(ino) -> String`
- `remove_entry(parent_ino, name)`
- `statfs() -> VfsStatFs` for filesystem capacity and block geometry

### 4. Multi-Source Initializers
- `init_from_local(&Path)`: Scans physical directory tree and registers files into the VFS hierarchy.
- `init_from_snapshot(&SnapshotEntry)`: Populates virtual directory structure from point-in-time snapshot file catalog.
- `init_from_cloud_entries(...)`: Maps remote S3, GCS, or Azure Blob object keys into a navigable directory tree.

### 5. Persistent Session Manager (`MountManager`)
- Manages active in-process mount engine instances.
- Maintains a persistent session registry file (`velcrux_mount_registry.json`) tracking active session IDs, mount sources, mountpoints, PIDs, and cache parameters.
- Supports cross-command lifecycle: `mount`, `unmount`, `list_registered`, and `get_engine`.

### 6. CLI Integration (`velcrux-client`)
- `velcrux mount attach <source> <mountpoint> [--read-only] [--cache-size-mb <MB>] [--cache-ttl <sec>] [--prefetch <N>] [-d/--daemon]`
- `velcrux mount list [--json]`
- `velcrux mount status [--mountpoint <path>] [--json]`
- `velcrux mount detach <mountpoint>`
- `velcrux unmount <mountpoint>`

## Consequences

- **100% Pure Rust**: Zero unsafe code and zero dependency on OS kernel headers or C libraries.
- **Portability**: Operates consistently across macOS, Linux, and Windows in unprivileged execution environments.
- **Fast Startup**: Instantly mounts multi-gigabyte or cloud datasets by fetching directories and page chunks on-demand.
- **Observability**: Rich telemetry reporting cache hit rates, memory consumption, and active mount sessions via human-readable tables or machine-readable JSON.
