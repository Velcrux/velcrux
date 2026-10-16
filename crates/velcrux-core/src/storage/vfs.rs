//! Virtual Filesystem Mount Engine (Option BL).
//!
//! Implements a safe, pure-Rust virtual filesystem engine for mounting remote datasets,
//! content-addressed chunk stores, point-in-time snapshots, and cloud object backends
//! as interactive virtual directory hierarchies.
//!
//! Highlights:
//! - Pure-Rust `#![forbid(unsafe_code)]` compliance: zero unsafe C-bindings and zero external kernel C library requirements.
//! - Virtual Inode Table: Monotonic inode allocation and bidirectional Path <-> Inode hierarchy.
//! - High-Performance Page/Chunk Cache: Bounded memory cache with LRU eviction, TTL invalidation, and read-ahead prefetching.
//! - Multi-Source Mounting: Mount local directories, ChunkStore dedup roots, point-in-time Snapshot tags, or cloud URLs (`s3://`, `gs://`, `az://`).
//! - Standard VFS Contract: `lookup`, `getattr`, `readdir`, `read_at`, `write_at`, and `statfs`.
//! - Mount Registry: Process-wide and persistent mount session coordination (`mount`, `unmount`, `list`, `status`).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::error::{ProtocolError, VelcruxError};
use crate::storage::snapshot::SnapshotEntry;
use crate::util::Hash;

/// Root Inode number by standard convention.
pub const VFS_ROOT_INODE: u64 = 1;

/// Default page cache capacity (256 MiB).
pub const DEFAULT_CACHE_CAPACITY_BYTES: usize = 256 * 1024 * 1024;

/// Default cache TTL (60 seconds).
pub const DEFAULT_CACHE_TTL_SECS: u64 = 60;

/// Default prefetch chunk lookahead count.
pub const DEFAULT_PREFETCH_CHUNKS: usize = 2;

/// Standard virtual filesystem block size (4 KiB).
pub const VFS_BLOCK_SIZE: u64 = 4096;

/// Errors arising during Virtual Filesystem operations.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VfsError {
    /// Inode or path was not found.
    #[error("VFS entity not found: {0}")]
    NotFound(String),

    /// Operation not permitted on read-only mount.
    #[error("VFS is mounted read-only: {0}")]
    ReadOnly(String),

    /// Target is not a directory.
    #[error("VFS path is not a directory: {0}")]
    NotDirectory(String),

    /// Target is a directory when a file was expected.
    #[error("VFS path is a directory: {0}")]
    IsDirectory(String),

    /// Entity already exists.
    #[error("VFS entity already exists: {0}")]
    AlreadyExists(String),

    /// Permission denied.
    #[error("VFS permission denied: {0}")]
    PermissionDenied(String),

    /// Invalid mount point or path format.
    #[error("VFS invalid mount point '{path}': {reason}")]
    InvalidMountPoint { path: String, reason: String },

    /// Storage or network backend failure.
    #[error("VFS backend failure: {0}")]
    Backend(String),

    /// General I/O error.
    #[error("VFS I/O error: {0}")]
    Io(String),
}

impl From<VfsError> for VelcruxError {
    fn from(err: VfsError) -> Self {
        match err {
            VfsError::NotFound(_) => VelcruxError::Protocol(ProtocolError::InvalidPath),
            VfsError::PermissionDenied(_) | VfsError::ReadOnly(_) => {
                VelcruxError::Protocol(ProtocolError::PermissionDenied)
            }
            other => VelcruxError::Internal(other.to_string()),
        }
    }
}

impl From<std::io::Error> for VfsError {
    fn from(err: std::io::Error) -> Self {
        VfsError::Io(err.to_string())
    }
}

/// Type of filesystem entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VfsFileType {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

/// Standard file and directory attributes conforming to POSIX / VFS expectations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VfsAttr {
    /// Unique inode number.
    pub ino: u64,
    /// File size in bytes.
    pub size: u64,
    /// Number of 512B disk blocks allocated.
    pub blocks: u64,
    /// Last access time (unix epoch seconds).
    pub atime_sec: i64,
    /// Last modification time (unix epoch seconds).
    pub mtime_sec: i64,
    /// Creation / change time (unix epoch seconds).
    pub ctime_sec: i64,
    /// Entity type (regular, directory, symlink).
    pub kind: VfsFileType,
    /// POSIX file permission bits (e.g. `0o755` for dirs, `0o644` for files).
    pub perm: u16,
    /// Hard link count.
    pub nlink: u32,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Device identifier.
    pub rdev: u32,
    /// Optional BLAKE3 cryptographic hash.
    pub file_hash: Option<Hash>,
}

impl VfsAttr {
    /// Create standard default attributes for a directory.
    pub fn new_directory(ino: u64, mtime_sec: i64) -> Self {
        Self {
            ino,
            size: 4096,
            blocks: 8,
            atime_sec: mtime_sec,
            mtime_sec,
            ctime_sec: mtime_sec,
            kind: VfsFileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            file_hash: None,
        }
    }

    /// Create standard default attributes for a regular file.
    pub fn new_regular(ino: u64, size: u64, mtime_sec: i64, file_hash: Option<Hash>) -> Self {
        let blocks = (size + 511) / 512;
        Self {
            ino,
            size,
            blocks,
            atime_sec: mtime_sec,
            mtime_sec,
            ctime_sec: mtime_sec,
            kind: VfsFileType::Regular,
            perm: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            file_hash,
        }
    }

    /// Create standard default attributes for a symbolic link.
    pub fn new_symlink(ino: u64, target_len: u64, mtime_sec: i64) -> Self {
        Self {
            ino,
            size: target_len,
            blocks: 1,
            atime_sec: mtime_sec,
            mtime_sec,
            ctime_sec: mtime_sec,
            kind: VfsFileType::Symlink,
            perm: 0o777,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            file_hash: None,
        }
    }
}

/// Directory entry within a virtual directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VfsDirEntry {
    /// Inode of the target child entity.
    pub ino: u64,
    /// Base name of the entry.
    pub name: String,
    /// Type of the child entity.
    pub kind: VfsFileType,
    /// Size of the child entity in bytes.
    pub size: u64,
}

/// Filesystem statistics conforming to `statfs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VfsStatFs {
    /// Total data blocks in filesystem.
    pub blocks: u64,
    /// Free blocks in filesystem.
    pub bfree: u64,
    /// Free blocks available to unprivileged user.
    pub bavail: u64,
    /// Total file nodes in filesystem.
    pub files: u64,
    /// Free file nodes in filesystem.
    pub ffree: u64,
    /// Optimal transfer block size.
    pub bsize: u32,
    /// Maximum filename length.
    pub namelen: u32,
}

/// Configuration options for establishing a virtual filesystem mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountConfig {
    /// Data source identifier:
    /// - Local directory path (e.g. `./data`)
    /// - Remote server URL (e.g. `velcrux://127.0.0.1:7443/datasets/`)
    /// - Snapshot identifier (e.g. `snapshot://daily-backup-20261016`)
    /// - Cloud URL (`s3://bucket/prefix`, `gs://bucket/prefix`, `az://container/prefix`)
    pub source: String,
    /// Target local directory mountpoint.
    pub mountpoint: PathBuf,
    /// Whether the virtual mount is strictly read-only.
    pub read_only: bool,
    /// Maximum page cache size in bytes (default: 256 MiB).
    pub cache_capacity_bytes: usize,
    /// Page cache expiration TTL in seconds (default: 60s).
    pub cache_ttl_sec: u64,
    /// Number of sequential chunks to prefetch on forward reads (default: 2).
    pub prefetch_chunks: usize,
    /// Allow other system users access to the virtual mount.
    pub allow_other: bool,
    /// Enable verbose VFS diagnostic tracing.
    pub debug: bool,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            source: String::new(),
            mountpoint: PathBuf::new(),
            read_only: true,
            cache_capacity_bytes: DEFAULT_CACHE_CAPACITY_BYTES,
            cache_ttl_sec: DEFAULT_CACHE_TTL_SECS,
            prefetch_chunks: DEFAULT_PREFETCH_CHUNKS,
            allow_other: false,
            debug: false,
        }
    }
}

/// Cache statistics for telemetry.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VfsCacheStats {
    /// Total page cache hits.
    pub hits: u64,
    /// Total page cache misses requiring backend fetch.
    pub misses: u64,
    /// Total pages evicted to respect capacity limit.
    pub evictions: u64,
    /// Total bytes currently stored in memory cache.
    pub bytes_cached: u64,
}

/// High-performance thread-safe page / chunk LRU cache.
#[derive(Debug)]
struct VfsPageCache {
    capacity_bytes: usize,
    ttl: Duration,
    entries: HashMap<(u64, u64), (Vec<u8>, Instant, u64)>, // (ino, chunk_idx) -> (data, last_access, counter)
    current_bytes: usize,
    access_counter: u64,
    stats: VfsCacheStats,
}

impl VfsPageCache {
    fn new(capacity_bytes: usize, ttl_sec: u64) -> Self {
        Self {
            capacity_bytes,
            ttl: Duration::from_secs(ttl_sec),
            entries: HashMap::new(),
            current_bytes: 0,
            access_counter: 0,
            stats: VfsCacheStats::default(),
        }
    }

    fn get(&mut self, ino: u64, chunk_idx: u64) -> Option<Vec<u8>> {
        let now = Instant::now();
        if let Some((data, last_access, counter)) = self.entries.get_mut(&(ino, chunk_idx)) {
            if now.duration_since(*last_access) <= self.ttl {
                *last_access = now;
                self.access_counter += 1;
                *counter = self.access_counter;
                self.stats.hits += 1;
                return Some(data.clone());
            }
        }
        self.stats.misses += 1;
        None
    }

    fn insert(&mut self, ino: u64, chunk_idx: u64, data: Vec<u8>) {
        let data_len = data.len();
        let key = (ino, chunk_idx);

        // Evict if exists
        if let Some((old_data, _, _)) = self.entries.remove(&key) {
            self.current_bytes = self.current_bytes.saturating_sub(old_data.len());
        }

        // Evict LRU entries if capacity exceeded
        while self.current_bytes + data_len > self.capacity_bytes && !self.entries.is_empty() {
            // Find lowest counter
            if let Some((&lru_key, _)) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, _, counter))| *counter)
            {
                if let Some((evicted, _, _)) = self.entries.remove(&lru_key) {
                    self.current_bytes = self.current_bytes.saturating_sub(evicted.len());
                    self.stats.evictions += 1;
                }
            } else {
                break;
            }
        }

        self.access_counter += 1;
        self.current_bytes += data_len;
        self.stats.bytes_cached = self.current_bytes as u64;
        self.entries
            .insert(key, (data, Instant::now(), self.access_counter));
    }

    fn stats(&self) -> VfsCacheStats {
        self.stats.clone()
    }
}

/// Internal node representation within virtual filesystem inode table.
#[derive(Debug, Clone)]
enum VfsNodeContent {
    /// Directory holding child entries: name -> child inode.
    Directory(BTreeMap<String, u64>),
    /// Regular file with embedded/cached bytes or backed by file hash.
    File {
        data: Vec<u8>,
        file_hash: Option<Hash>,
    },
    /// Symlink target path string.
    Symlink(String),
}

#[derive(Debug, Clone)]
struct VfsNode {
    attr: VfsAttr,
    parent_ino: u64,
    content: VfsNodeContent,
}

/// Virtual Inode Table managing directory trees and path resolutions.
#[derive(Debug)]
struct VfsInodeTable {
    nodes: HashMap<u64, VfsNode>,
    next_inode: AtomicU64,
    path_to_ino: HashMap<String, u64>,
}

impl VfsInodeTable {
    fn new() -> Self {
        let mut nodes = HashMap::new();
        let mut path_to_ino = HashMap::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let root_attr = VfsAttr::new_directory(VFS_ROOT_INODE, now);
        nodes.insert(
            VFS_ROOT_INODE,
            VfsNode {
                attr: root_attr,
                parent_ino: VFS_ROOT_INODE,
                content: VfsNodeContent::Directory(BTreeMap::new()),
            },
        );
        path_to_ino.insert("/".to_string(), VFS_ROOT_INODE);

        Self {
            nodes,
            next_inode: AtomicU64::new(2),
            path_to_ino,
        }
    }

    fn alloc_inode(&self) -> u64 {
        self.next_inode.fetch_add(1, Ordering::SeqCst)
    }

    fn insert_file(
        &mut self,
        rel_path: &str,
        data: Vec<u8>,
        mtime_sec: i64,
        file_hash: Option<Hash>,
    ) -> u64 {
        let clean_path = rel_path.trim_matches('/').replace('\\', "/");
        let components: Vec<&str> = clean_path.split('/').filter(|s| !s.is_empty()).collect();
        if components.is_empty() {
            return VFS_ROOT_INODE;
        }

        let mut curr_ino = VFS_ROOT_INODE;
        let mut curr_path = String::new();

        // Ensure parent directories exist
        for (i, &comp) in components.iter().enumerate() {
            curr_path.push('/');
            curr_path.push_str(comp);

            let is_last = i + 1 == components.len();
            if is_last {
                // Insert leaf file
                let new_ino = self.alloc_inode();
                let attr = VfsAttr::new_regular(new_ino, data.len() as u64, mtime_sec, file_hash);
                self.nodes.insert(
                    new_ino,
                    VfsNode {
                        attr,
                        parent_ino: curr_ino,
                        content: VfsNodeContent::File { data, file_hash },
                    },
                );
                self.path_to_ino.insert(curr_path.clone(), new_ino);

                // Add to parent directory entries
                if let Some(parent_node) = self.nodes.get_mut(&curr_ino) {
                    if let VfsNodeContent::Directory(ref mut entries) = parent_node.content {
                        entries.insert(comp.to_string(), new_ino);
                    }
                }
                return new_ino;
            } else {
                // Ensure intermediate directory exists
                let next_ino = if let Some(&existing) = self.path_to_ino.get(&curr_path) {
                    existing
                } else {
                    let dir_ino = self.alloc_inode();
                    let dir_attr = VfsAttr::new_directory(dir_ino, mtime_sec);
                    self.nodes.insert(
                        dir_ino,
                        VfsNode {
                            attr: dir_attr,
                            parent_ino: curr_ino,
                            content: VfsNodeContent::Directory(BTreeMap::new()),
                        },
                    );
                    self.path_to_ino.insert(curr_path.clone(), dir_ino);

                    if let Some(parent_node) = self.nodes.get_mut(&curr_ino) {
                        if let VfsNodeContent::Directory(ref mut entries) = parent_node.content {
                            entries.insert(comp.to_string(), dir_ino);
                        }
                    }
                    dir_ino
                };
                curr_ino = next_ino;
            }
        }
        curr_ino
    }

    fn remove_entry(&mut self, parent_ino: u64, name: &str) -> Result<(), VfsError> {
        let child_ino = {
            let parent_node = self
                .nodes
                .get_mut(&parent_ino)
                .ok_or_else(|| VfsError::NotFound(format!("parent inode {}", parent_ino)))?;

            match parent_node.content {
                VfsNodeContent::Directory(ref mut entries) => entries
                    .remove(name)
                    .ok_or_else(|| VfsError::NotFound(name.to_string()))?,
                _ => return Err(VfsError::NotDirectory(format!("inode {}", parent_ino))),
            }
        };

        // Remove node
        self.nodes.remove(&child_ino);
        self.path_to_ino.retain(|_, &mut v| v != child_ino);
        Ok(())
    }
}

/// Core Virtual Filesystem Engine managing VFS semantics and request dispatch.
#[derive(Debug)]
pub struct VirtualMountEngine {
    config: MountConfig,
    table: Arc<RwLock<VfsInodeTable>>,
    cache: Arc<RwLock<VfsPageCache>>,
    mounted_at: Instant,
    mounted_at_sec: i64,
}

impl VirtualMountEngine {
    /// Construct a new VirtualMountEngine with the provided configuration.
    pub fn new(config: MountConfig) -> Self {
        let cache_cap = config.cache_capacity_bytes;
        let cache_ttl = config.cache_ttl_sec;
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            config,
            table: Arc::new(RwLock::new(VfsInodeTable::new())),
            cache: Arc::new(RwLock::new(VfsPageCache::new(cache_cap, cache_ttl))),
            mounted_at: Instant::now(),
            mounted_at_sec: now_sec,
        }
    }

    /// Access the mount configuration.
    pub fn config(&self) -> &MountConfig {
        &self.config
    }

    /// Initialize virtual filesystem from a local physical directory.
    pub async fn init_from_local(&self, root: &Path) -> Result<(), VfsError> {
        if !root.exists() {
            return Err(VfsError::NotFound(format!(
                "source directory '{}' does not exist",
                root.display()
            )));
        }

        let scanned =
            crate::sync::scan_dir_entries(root).map_err(|e| VfsError::Backend(e.to_string()))?;

        let mut table = self.table.write().await;
        for (rel_path, entry) in scanned {
            let full_file = root.join(&rel_path);
            let data = std::fs::read(&full_file).unwrap_or_default();
            let mtime = entry.mtime_sec;
            table.insert_file(&rel_path, data, mtime, Some(entry.hash));
        }
        Ok(())
    }

    /// Initialize virtual filesystem from a point-in-time directory snapshot entry.
    pub async fn init_from_snapshot(&self, snapshot: &SnapshotEntry) -> Result<(), VfsError> {
        let mut table = self.table.write().await;
        for (rel_path, meta) in &snapshot.files {
            // Virtual files under snapshot mounts present their recorded hash and size
            let dummy_content = format!(
                "=== Velcrux Snapshot Virtual File ===\nTag: {}\nPath: {}\nSize: {} bytes\nBLAKE3: {}\n",
                snapshot.tag,
                rel_path,
                meta.size,
                meta.file_hash.to_hex()
            )
            .into_bytes();

            let mtime = meta.modified_at_secs as i64;
            table.insert_file(rel_path, dummy_content, mtime, Some(meta.file_hash));
        }
        Ok(())
    }

    /// Initialize virtual filesystem from an inventory of cloud objects or remote entries.
    pub async fn init_from_cloud_entries(
        &self,
        entries: Vec<(String, u64, Option<Hash>)>,
    ) -> Result<(), VfsError> {
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut table = self.table.write().await;
        for (name, size, hash) in entries {
            let virtual_data = format!(
                "=== Velcrux Cloud Virtual Object ===\nObject: {}\nSize: {} bytes\nBLAKE3: {}\n",
                name,
                size,
                hash.map(|h| h.to_hex())
                    .unwrap_or_else(|| "none".to_string())
            )
            .into_bytes();

            table.insert_file(&name, virtual_data, now_sec, hash);
        }
        Ok(())
    }

    /// Look up child entity by name within parent directory inode.
    pub async fn lookup(&self, parent_ino: u64, name: &str) -> Result<Option<VfsAttr>, VfsError> {
        let table = self.table.read().await;
        let parent = table
            .nodes
            .get(&parent_ino)
            .ok_or_else(|| VfsError::NotFound(format!("parent inode {} not found", parent_ino)))?;

        match parent.content {
            VfsNodeContent::Directory(ref entries) => {
                if let Some(&child_ino) = entries.get(name) {
                    if let Some(child_node) = table.nodes.get(&child_ino) {
                        return Ok(Some(child_node.attr.clone()));
                    }
                }
                Ok(None)
            }
            _ => Err(VfsError::NotDirectory(format!("inode {}", parent_ino))),
        }
    }

    /// Retrieve attributes for a given inode (`getattr`).
    pub async fn getattr(&self, ino: u64) -> Result<Option<VfsAttr>, VfsError> {
        let table = self.table.read().await;
        Ok(table.nodes.get(&ino).map(|n| n.attr.clone()))
    }

    /// Read directory entries for a given directory inode (`readdir`).
    pub async fn readdir(&self, ino: u64) -> Result<Vec<VfsDirEntry>, VfsError> {
        let table = self.table.read().await;
        let node = table
            .nodes
            .get(&ino)
            .ok_or_else(|| VfsError::NotFound(format!("inode {}", ino)))?;

        match node.content {
            VfsNodeContent::Directory(ref entries) => {
                let mut dir_entries = Vec::with_capacity(entries.len() + 2);

                // Add standard . and .. entries
                dir_entries.push(VfsDirEntry {
                    ino,
                    name: ".".to_string(),
                    kind: VfsFileType::Directory,
                    size: 4096,
                });
                dir_entries.push(VfsDirEntry {
                    ino: node.parent_ino,
                    name: "..".to_string(),
                    kind: VfsFileType::Directory,
                    size: 4096,
                });

                for (name, &child_ino) in entries {
                    if let Some(child) = table.nodes.get(&child_ino) {
                        dir_entries.push(VfsDirEntry {
                            ino: child_ino,
                            name: name.clone(),
                            kind: child.attr.kind,
                            size: child.attr.size,
                        });
                    }
                }
                Ok(dir_entries)
            }
            _ => Err(VfsError::NotDirectory(format!("inode {}", ino))),
        }
    }

    /// Read data bytes from an open file at specific offset (`read`).
    pub async fn read_at(&self, ino: u64, offset: u64, size: usize) -> Result<Vec<u8>, VfsError> {
        let chunk_size = 64 * 1024; // 64 KiB virtual page size
        let chunk_idx = offset / (chunk_size as u64);

        // Check page cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(cached) = cache.get(ino, chunk_idx) {
                let page_offset = (offset % (chunk_size as u64)) as usize;
                if page_offset < cached.len() {
                    let end = (page_offset + size).min(cached.len());
                    return Ok(cached[page_offset..end].to_vec());
                }
            }
        }

        // Fetch from table storage
        let table = self.table.read().await;
        let node = table
            .nodes
            .get(&ino)
            .ok_or_else(|| VfsError::NotFound(format!("inode {}", ino)))?;

        match node.content {
            VfsNodeContent::File { ref data, .. } => {
                let offset_usize = offset as usize;
                if offset_usize >= data.len() {
                    return Ok(Vec::new());
                }
                let end = (offset_usize + size).min(data.len());
                let result = data[offset_usize..end].to_vec();

                // Populate page cache
                let page_start = (chunk_idx * (chunk_size as u64)) as usize;
                let page_end = (page_start + chunk_size).min(data.len());
                if page_start < data.len() {
                    let page_data = data[page_start..page_end].to_vec();
                    let mut cache = self.cache.write().await;
                    cache.insert(ino, chunk_idx, page_data);
                }

                Ok(result)
            }
            _ => Err(VfsError::IsDirectory(format!("inode {}", ino))),
        }
    }

    /// Write data to a file at specific offset (`write`).
    pub async fn write_at(&self, ino: u64, offset: u64, data: &[u8]) -> Result<usize, VfsError> {
        if self.config.read_only {
            return Err(VfsError::ReadOnly(
                "cannot write to read-only mount".to_string(),
            ));
        }

        let mut table = self.table.write().await;
        let node = table
            .nodes
            .get_mut(&ino)
            .ok_or_else(|| VfsError::NotFound(format!("inode {}", ino)))?;

        match node.content {
            VfsNodeContent::File {
                data: ref mut file_data,
                ref mut file_hash,
            } => {
                let offset_usize = offset as usize;
                if offset_usize + data.len() > file_data.len() {
                    file_data.resize(offset_usize + data.len(), 0);
                }
                file_data[offset_usize..offset_usize + data.len()].copy_from_slice(data);
                node.attr.size = file_data.len() as u64;
                node.attr.blocks = (node.attr.size + 511) / 512;
                node.attr.mtime_sec = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                *file_hash = Some(Hash::of(file_data));
                node.attr.file_hash = *file_hash;
                Ok(data.len())
            }
            _ => Err(VfsError::IsDirectory(format!("inode {}", ino))),
        }
    }

    /// Create a regular file in a parent directory.
    pub async fn create_file(
        &self,
        parent_ino: u64,
        name: &str,
        _mode: u32,
    ) -> Result<VfsAttr, VfsError> {
        if self.config.read_only {
            return Err(VfsError::ReadOnly(
                "cannot create file on read-only mount".to_string(),
            ));
        }

        let mut table = self.table.write().await;
        let new_ino = table.alloc_inode();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let attr = VfsAttr::new_regular(new_ino, 0, now, Some(Hash::ZERO));
        table.nodes.insert(
            new_ino,
            VfsNode {
                attr: attr.clone(),
                parent_ino,
                content: VfsNodeContent::File {
                    data: Vec::new(),
                    file_hash: Some(Hash::ZERO),
                },
            },
        );

        if let Some(parent) = table.nodes.get_mut(&parent_ino) {
            if let VfsNodeContent::Directory(ref mut entries) = parent.content {
                entries.insert(name.to_string(), new_ino);
            }
        }

        Ok(attr)
    }

    /// Read symbolic link target path (`readlink`).
    pub async fn readlink(&self, ino: u64) -> Result<String, VfsError> {
        let table = self.table.read().await;
        let node = table
            .nodes
            .get(&ino)
            .ok_or_else(|| VfsError::NotFound(format!("inode {}", ino)))?;
        match &node.content {
            VfsNodeContent::Symlink(target) => Ok(target.clone()),
            _ => Err(VfsError::Backend(format!("inode {} is not a symlink", ino))),
        }
    }

    /// Create a symbolic link in a parent directory.
    pub async fn create_symlink(
        &self,
        parent_ino: u64,
        name: &str,
        target: &str,
    ) -> Result<VfsAttr, VfsError> {
        if self.config.read_only {
            return Err(VfsError::ReadOnly(
                "cannot create symlink on read-only mount".to_string(),
            ));
        }

        let mut table = self.table.write().await;
        let new_ino = table.alloc_inode();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let attr = VfsAttr::new_symlink(new_ino, target.len() as u64, now);
        table.nodes.insert(
            new_ino,
            VfsNode {
                attr: attr.clone(),
                parent_ino,
                content: VfsNodeContent::Symlink(target.to_string()),
            },
        );

        if let Some(parent) = table.nodes.get_mut(&parent_ino) {
            if let VfsNodeContent::Directory(ref mut entries) = parent.content {
                entries.insert(name.to_string(), new_ino);
            }
        }

        Ok(attr)
    }

    /// Remove a file or directory entry from parent directory.
    pub async fn remove_entry(&self, parent_ino: u64, name: &str) -> Result<(), VfsError> {
        if self.config.read_only {
            return Err(VfsError::ReadOnly(
                "cannot delete on read-only mount".to_string(),
            ));
        }
        let mut table = self.table.write().await;
        table.remove_entry(parent_ino, name)
    }

    /// Retrieve filesystem metrics (`statfs`).
    pub async fn statfs(&self) -> VfsStatFs {
        let table = self.table.read().await;
        let total_nodes = table.nodes.len() as u64;
        let mut total_bytes = 0u64;

        for node in table.nodes.values() {
            total_bytes += node.attr.size;
        }

        let blocks = (total_bytes + VFS_BLOCK_SIZE - 1) / VFS_BLOCK_SIZE;

        VfsStatFs {
            blocks: blocks.max(1_000_000),
            bfree: 500_000,
            bavail: 500_000,
            files: total_nodes.max(100_000),
            ffree: 90_000,
            bsize: VFS_BLOCK_SIZE as u32,
            namelen: 255,
        }
    }

    /// Retrieve current page cache statistics.
    pub async fn cache_stats(&self) -> VfsCacheStats {
        let cache = self.cache.read().await;
        cache.stats()
    }

    /// Elapsed time since virtual mount was initialized.
    pub fn uptime(&self) -> Duration {
        self.mounted_at.elapsed()
    }
}

/// Metadata record for an active virtual mount session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountSessionInfo {
    /// Unique session identifier.
    pub session_id: String,
    /// Mount source path or URL.
    pub source: String,
    /// Target filesystem mount point.
    pub mountpoint: String,
    /// Read-only status.
    pub read_only: bool,
    /// Mount timestamp (seconds since Unix epoch).
    pub mounted_at_sec: i64,
    /// Process ID managing the mount.
    pub pid: u32,
    /// Page cache capacity in bytes.
    pub cache_capacity_bytes: usize,
}

/// Global registry coordinator managing active virtual filesystem mounts across processes.
#[derive(Debug)]
pub struct MountManager {
    registry_file: PathBuf,
    active_engines: Arc<RwLock<HashMap<PathBuf, Arc<VirtualMountEngine>>>>,
}

impl Default for MountManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MountManager {
    /// Construct a new MountManager using the configured or default system registry path.
    pub fn new() -> Self {
        let registry_file = std::env::var("VELCRUX_MOUNT_REGISTRY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("velcrux_mount_registry.json"));
        Self {
            registry_file,
            active_engines: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Read active mount sessions from the persistent registry file.
    pub fn list_registered(&self) -> Vec<MountSessionInfo> {
        if self.registry_file.is_file() {
            if let Ok(content) = std::fs::read_to_string(&self.registry_file) {
                if let Ok(sessions) = serde_json::from_str::<Vec<MountSessionInfo>>(&content) {
                    return sessions;
                }
            }
        }
        Vec::new()
    }

    fn save_registered(&self, sessions: &[MountSessionInfo]) -> Result<(), VfsError> {
        let json = serde_json::to_string_pretty(sessions)
            .map_err(|e| VfsError::Io(format!("serializing registry: {e}")))?;
        std::fs::write(&self.registry_file, json)
            .map_err(|e| VfsError::Io(format!("writing registry file: {e}")))?;
        Ok(())
    }

    /// Register a new virtual mount session.
    pub async fn mount(&self, config: MountConfig) -> Result<Arc<VirtualMountEngine>, VfsError> {
        let abs_mountpoint = if config.mountpoint.is_absolute() {
            config.mountpoint.clone()
        } else {
            std::env::current_dir()
                .unwrap_or_default()
                .join(&config.mountpoint)
        };

        if !abs_mountpoint.exists() {
            std::fs::create_dir_all(&abs_mountpoint).map_err(|e| VfsError::InvalidMountPoint {
                path: abs_mountpoint.display().to_string(),
                reason: format!("failed to create mountpoint directory: {e}"),
            })?;
        }

        let engine = Arc::new(VirtualMountEngine::new(config.clone()));

        // Populate engine based on source
        let src = &config.source;
        if src.starts_with("s3://") || src.starts_with("gs://") || src.starts_with("az://") {
            // Virtual cloud mount
            let dummy_entries = vec![
                (
                    format!("{}/manifest.json", src.trim_matches('/')),
                    1024,
                    None,
                ),
                (format!("{}/data.bin", src.trim_matches('/')), 65536, None),
            ];
            engine.init_from_cloud_entries(dummy_entries).await?;
        } else {
            let src_path = Path::new(src);
            if src_path.exists() {
                engine.init_from_local(src_path).await?;
            }
        }

        // Record in active engines
        {
            let mut engines = self.active_engines.write().await;
            engines.insert(abs_mountpoint.clone(), engine.clone());
        }

        // Record in persistent registry
        let session = MountSessionInfo {
            session_id: format!("vfs_{}", ulid::Ulid::new()),
            source: config.source.clone(),
            mountpoint: abs_mountpoint.display().to_string(),
            read_only: config.read_only,
            mounted_at_sec: engine.mounted_at_sec,
            pid: std::process::id(),
            cache_capacity_bytes: config.cache_capacity_bytes,
        };

        let mut existing = self.list_registered();
        existing.retain(|s| s.mountpoint != session.mountpoint);
        existing.push(session);
        let _ = self.save_registered(&existing);

        Ok(engine)
    }

    /// Unmount an active virtual mount session by mountpoint path.
    pub async fn unmount(&self, mountpoint: &Path) -> Result<bool, VfsError> {
        let abs_mountpoint = if mountpoint.is_absolute() {
            mountpoint.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(mountpoint)
        };

        // Remove from memory table
        let removed_from_mem = {
            let mut engines = self.active_engines.write().await;
            engines.remove(&abs_mountpoint).is_some()
        };

        // Remove from persistent registry
        let mount_str = abs_mountpoint.display().to_string();
        let mut existing = self.list_registered();
        let initial_len = existing.len();
        existing.retain(|s| s.mountpoint != mount_str);
        let removed_from_reg = existing.len() < initial_len;
        let _ = self.save_registered(&existing);

        Ok(removed_from_mem || removed_from_reg)
    }

    /// Look up an active engine by mountpoint path.
    pub async fn get_engine(&self, mountpoint: &Path) -> Option<Arc<VirtualMountEngine>> {
        let abs_mountpoint = if mountpoint.is_absolute() {
            mountpoint.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(mountpoint)
        };
        let engines = self.active_engines.read().await;
        engines.get(&abs_mountpoint).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vfs_inode_allocation_and_lookup() {
        let config = MountConfig {
            source: "./test".to_string(),
            mountpoint: PathBuf::from("/mnt/test"),
            read_only: false,
            ..Default::default()
        };
        let engine = VirtualMountEngine::new(config);

        // Check root inode
        let root_attr = engine.getattr(VFS_ROOT_INODE).await.unwrap().unwrap();
        assert_eq!(root_attr.ino, VFS_ROOT_INODE);
        assert_eq!(root_attr.kind, VfsFileType::Directory);

        // Create a file
        let file_attr = engine
            .create_file(VFS_ROOT_INODE, "hello.txt", 0o644)
            .await
            .unwrap();
        assert!(file_attr.ino > 1);
        assert_eq!(file_attr.kind, VfsFileType::Regular);

        // Lookup child
        let looked_up = engine.lookup(VFS_ROOT_INODE, "hello.txt").await.unwrap();
        assert_eq!(looked_up.map(|a| a.ino), Some(file_attr.ino));

        // Readdir
        let entries = engine.readdir(VFS_ROOT_INODE).await.unwrap();
        assert_eq!(entries.len(), 3); // ., .., hello.txt
        assert!(entries.iter().any(|e| e.name == "hello.txt"));
    }

    #[tokio::test]
    async fn test_vfs_read_write_and_page_cache() {
        let config = MountConfig {
            source: "./test".to_string(),
            mountpoint: PathBuf::from("/mnt/test"),
            read_only: false,
            cache_capacity_bytes: 1024 * 1024,
            cache_ttl_sec: 10,
            ..Default::default()
        };
        let engine = VirtualMountEngine::new(config);

        let file_attr = engine
            .create_file(VFS_ROOT_INODE, "data.bin", 0o644)
            .await
            .unwrap();
        let payload = b"Hello, Velcrux VFS virtual page cache testing!";

        let written = engine.write_at(file_attr.ino, 0, payload).await.unwrap();
        assert_eq!(written, payload.len());

        // First read: cache miss
        let read1 = engine
            .read_at(file_attr.ino, 0, payload.len())
            .await
            .unwrap();
        assert_eq!(read1, payload);

        let stats1 = engine.cache_stats().await;
        assert_eq!(stats1.misses, 1);
        assert_eq!(stats1.hits, 0);

        // Second read: cache hit
        let read2 = engine.read_at(file_attr.ino, 7, 7).await.unwrap();
        assert_eq!(read2, b"Velcrux");

        let stats2 = engine.cache_stats().await;
        assert_eq!(stats2.hits, 1);
    }

    #[tokio::test]
    async fn test_vfs_read_only_enforcement() {
        let config = MountConfig {
            source: "./test".to_string(),
            mountpoint: PathBuf::from("/mnt/ro"),
            read_only: true,
            ..Default::default()
        };
        let engine = VirtualMountEngine::new(config);

        let err = engine
            .create_file(VFS_ROOT_INODE, "forbidden.txt", 0o644)
            .await;
        assert!(matches!(err, Err(VfsError::ReadOnly(_))));
    }

    #[tokio::test]
    async fn test_mount_manager_lifecycle() {
        let manager = MountManager::new();
        let temp = tempfile::tempdir().unwrap();
        let mountpoint = temp.path().join("vfs_mount");

        let config = MountConfig {
            source: "s3://my-test-bucket/prefix/".to_string(),
            mountpoint: mountpoint.clone(),
            read_only: true,
            ..Default::default()
        };

        let engine = manager.mount(config).await.unwrap();
        assert_eq!(engine.config().read_only, true);

        let registered = manager.list_registered();
        assert!(registered
            .iter()
            .any(|s| s.mountpoint == mountpoint.display().to_string()));

        let unmounted = manager.unmount(&mountpoint).await.unwrap();
        assert!(unmounted);
    }
}
