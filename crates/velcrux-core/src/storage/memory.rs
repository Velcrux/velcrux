//! In-memory virtual storage backend (`REQUIREMENTS.md` §42, §43).
//!
//! Provides a 100% safe, hermetic in-memory virtual filesystem and
//! content-addressed chunk store for ultra-fast testing, mock cloud storage,
//! and environments without disk access.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::error::{ProtocolError, VelcruxError};
use crate::storage::{AsyncRandomRead, FileMeta, Staging, StagingWriter, StorageBackend, VPath};
use crate::util::Hash;

/// An in-memory virtual file storing raw byte payloads, metadata, and extended attributes.
#[derive(Clone, Debug)]
pub struct MemoryFile {
    /// Raw byte payload of the file.
    pub data: Vec<u8>,
    /// Standard file metadata.
    pub meta: FileMeta,
    /// Extended attributes (name, value pairs).
    pub xattrs: Vec<(String, Vec<u8>)>,
}

/// Internal filesystem state held in RAM.
#[derive(Default, Debug)]
pub struct MemoryFileSystem {
    /// Committed regular files keyed by normalized `VPath` string.
    pub files: BTreeMap<String, MemoryFile>,
    /// Symbolic links keyed by normalized `VPath` string -> link target string.
    pub symlinks: BTreeMap<String, String>,
    /// Hard links keyed by destination `VPath` string -> source `VPath` string.
    pub hardlinks: BTreeMap<String, String>,
    /// Directories keyed by normalized `VPath` string.
    pub dirs: HashSet<String>,
    /// In-progress staging buffers keyed by `(transfer_id, rel_path)`.
    pub staging: HashMap<(String, String), Arc<RwLock<Vec<u8>>>>,
    /// Content-addressed chunk store (BLAKE3 hash -> chunk bytes).
    pub chunks: HashMap<Hash, Vec<u8>>,
}

impl MemoryFileSystem {
    /// Calculate total bytes currently stored across all regular files and chunks.
    pub fn total_stored_bytes(&self) -> u64 {
        let files_size: u64 = self.files.values().map(|f| f.data.len() as u64).sum();
        let chunks_size: u64 = self.chunks.values().map(|c| c.len() as u64).sum();
        files_size.saturating_add(chunks_size)
    }
}

/// A random-read handle for in-memory byte buffers.
struct MemoryRandomRead {
    data: Vec<u8>,
}

#[async_trait::async_trait]
impl AsyncRandomRead for MemoryRandomRead {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    async fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, VelcruxError> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0);
        }
        let available = &self.data[offset..];
        let to_read = buf.len().min(available.len());
        buf[..to_read].copy_from_slice(&available[..to_read]);
        Ok(to_read)
    }
}

/// Hermetic in-memory storage backend implementing `StorageBackend`.
#[derive(Clone, Debug)]
pub struct MemoryStorageBackend {
    inner: Arc<RwLock<MemoryFileSystem>>,
    root: PathBuf,
    capacity_bytes: u64,
    min_free_space: u64,
}

impl Default for MemoryStorageBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStorageBackend {
    /// Construct a new in-memory backend with unbounded capacity.
    pub fn new() -> Self {
        Self::new_with_capacity(u64::MAX, 0)
    }

    /// Construct a new in-memory backend with simulated disk capacity and reservation margin.
    pub fn new_with_capacity(capacity_bytes: u64, min_free_space: u64) -> Self {
        let mut dirs = HashSet::new();
        dirs.insert(String::new()); // root directory
        Self {
            inner: Arc::new(RwLock::new(MemoryFileSystem {
                dirs,
                ..Default::default()
            })),
            root: PathBuf::from("/memory"),
            capacity_bytes,
            min_free_space,
        }
    }

    /// Set virtual root path.
    pub fn with_root(mut self, root: PathBuf) -> Self {
        self.root = root;
        self
    }

    /// Set min free space reservation margin.
    pub fn with_min_free_space(mut self, min_free_space: u64) -> Self {
        self.min_free_space = min_free_space;
        self
    }

    /// Directly insert a file into the in-memory backend (convenience for tests and fixtures).
    pub async fn insert_file(
        &self,
        p: &VPath,
        data: Vec<u8>,
        mode: u32,
        mtime_ns: i64,
    ) -> Result<(), VelcruxError> {
        let hash = Hash::of(&data);
        let size = data.len() as u64;
        let meta = FileMeta {
            size,
            mode,
            mtime_ns,
            file_hash: hash,
        };
        let mut fs = self.inner.write().await;
        // Register parent directories
        let path_str = p.as_str().to_string();
        Self::ensure_parent_dirs_locked(&mut fs, &path_str);
        fs.files.insert(
            path_str,
            MemoryFile {
                data,
                meta,
                xattrs: Vec::new(),
            },
        );
        Ok(())
    }

    /// Retrieve raw byte payload of a file if it exists.
    pub async fn get_file_data(&self, p: &VPath) -> Option<Vec<u8>> {
        let fs = self.inner.read().await;
        fs.files.get(p.as_str()).map(|f| f.data.clone())
    }

    /// Return count of committed regular files in memory.
    pub async fn file_count(&self) -> usize {
        let fs = self.inner.read().await;
        fs.files.len()
    }

    /// Return list of all relative file paths stored in memory.
    pub async fn list_all_file_paths(&self) -> Vec<String> {
        let fs = self.inner.read().await;
        fs.files.keys().cloned().collect()
    }

    /// Clear all files, staging buffers, symlinks, and chunks from memory.
    pub async fn clear(&self) {
        let mut fs = self.inner.write().await;
        fs.files.clear();
        fs.symlinks.clear();
        fs.hardlinks.clear();
        fs.dirs.clear();
        fs.dirs.insert(String::new());
        fs.staging.clear();
        fs.chunks.clear();
    }

    fn ensure_parent_dirs_locked(fs: &mut MemoryFileSystem, path_str: &str) {
        let mut current = path_str;
        while let Some(idx) = current.rfind('/') {
            current = &current[..idx];
            fs.dirs.insert(current.to_string());
        }
    }
}

#[async_trait::async_trait]
impl StorageBackend for MemoryStorageBackend {
    fn root(&self) -> &Path {
        &self.root
    }

    fn backend_type(&self) -> &'static str {
        "memory"
    }

    async fn stat(&self, p: &VPath) -> Result<Option<FileMeta>, VelcruxError> {
        let key = p.as_str();
        let fs = self.inner.read().await;

        if let Some(file) = fs.files.get(key) {
            return Ok(Some(file.meta.clone()));
        }

        if let Some(target) = fs.symlinks.get(key) {
            return Ok(Some(FileMeta {
                size: target.len() as u64,
                mode: 0o120777,
                mtime_ns: 0,
                file_hash: Hash::ZERO,
            }));
        }

        if key.is_empty() || fs.dirs.contains(key) {
            return Ok(Some(FileMeta {
                size: 0,
                mode: 0o040755,
                mtime_ns: 0,
                file_hash: Hash::ZERO,
            }));
        }

        Ok(None)
    }

    async fn open_read(&self, p: &VPath) -> Result<Box<dyn AsyncRandomRead>, VelcruxError> {
        let key = p.as_str();
        let fs = self.inner.read().await;

        if let Some(file) = fs.files.get(key) {
            return Ok(Box::new(MemoryRandomRead {
                data: file.data.clone(),
            }));
        }

        Err(VelcruxError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("file not found in memory storage: {key}"),
        )))
    }

    async fn available_space(&self) -> Result<u64, VelcruxError> {
        let fs = self.inner.read().await;
        let used = fs.total_stored_bytes();
        Ok(self.capacity_bytes.saturating_sub(used))
    }

    fn min_free_space(&self) -> u64 {
        self.min_free_space
    }

    fn preallocate_enabled(&self) -> bool {
        false
    }

    async fn open_staging(
        &self,
        transfer_id: &str,
        p: &VPath,
        size_hint: u64,
    ) -> Result<StagingWriter, VelcruxError> {
        self.open_staging_resumable(transfer_id, p, size_hint, false)
            .await
    }

    async fn open_staging_resumable(
        &self,
        transfer_id: &str,
        p: &VPath,
        size_hint: u64,
        resumed: bool,
    ) -> Result<StagingWriter, VelcruxError> {
        // Enforce capacity and reservation constraints
        if self.capacity_bytes < u64::MAX && size_hint > 0 {
            let avail = self.available_space().await?;
            let required = size_hint.saturating_add(self.min_free_space);
            if avail < required {
                return Err(VelcruxError::Protocol(ProtocolError::DiskFull(format!(
                    "memory capacity exhausted: available {avail} B < required {required} B"
                ))));
            }
        }

        let key = (transfer_id.to_string(), p.as_str().to_string());
        let mut fs = self.inner.write().await;

        let buffer = if resumed && fs.staging.contains_key(&key) {
            fs.staging.get(&key).unwrap().clone()
        } else {
            let buf = Arc::new(RwLock::new(Vec::new()));
            fs.staging.insert(key, buf.clone());
            buf
        };

        let staging_path = PathBuf::from(format!("/memory/staging/{transfer_id}/{}", p.as_str()));
        Ok(StagingWriter::new_memory(
            buffer,
            Staging::new(staging_path),
            p.as_str().to_string(),
        ))
    }

    async fn commit(
        &self,
        transfer_id: &str,
        _staging: Staging,
        dest: &VPath,
        meta: &FileMeta,
    ) -> Result<(), VelcruxError> {
        let key = (transfer_id.to_string(), dest.as_str().to_string());
        let mut fs = self.inner.write().await;

        let staged_buf = fs.staging.remove(&key).ok_or_else(|| {
            VelcruxError::Internal(format!(
                "memory commit: staging buffer not found for transfer {transfer_id} at {dest}"
            ))
        })?;

        let data = staged_buf.read().await.clone();
        let computed_hash = Hash::of(&data);
        let mut file_meta = meta.clone();
        file_meta.size = data.len() as u64;
        file_meta.file_hash = computed_hash;

        let path_str = dest.as_str().to_string();
        Self::ensure_parent_dirs_locked(&mut fs, &path_str);

        fs.files.insert(
            path_str,
            MemoryFile {
                data,
                meta: file_meta,
                xattrs: Vec::new(),
            },
        );

        Ok(())
    }

    async fn remove(&self, p: &VPath) -> Result<(), VelcruxError> {
        if p.is_root() {
            return Err(VelcruxError::Protocol(ProtocolError::InvalidPath));
        }
        let key = p.as_str();
        let mut fs = self.inner.write().await;
        fs.files.remove(key);
        fs.symlinks.remove(key);
        fs.hardlinks.remove(key);
        fs.dirs.remove(key);
        Ok(())
    }

    async fn exists(&self, p: &VPath) -> Result<bool, VelcruxError> {
        let key = p.as_str();
        let fs = self.inner.read().await;
        if key.is_empty() {
            return Ok(true);
        }
        Ok(fs.files.contains_key(key) || fs.symlinks.contains_key(key) || fs.dirs.contains(key))
    }

    async fn list_dir(&self, p: &VPath) -> Result<Vec<(String, FileMeta)>, VelcruxError> {
        let prefix = p.as_str();
        let fs = self.inner.read().await;
        let mut results = Vec::new();

        for (path, file) in &fs.files {
            if let Some(child_name) = extract_direct_child(prefix, path) {
                results.push((child_name, file.meta.clone()));
            }
        }

        for (path, target) in &fs.symlinks {
            if let Some(child_name) = extract_direct_child(prefix, path) {
                let meta = FileMeta {
                    size: target.len() as u64,
                    mode: 0o120777,
                    mtime_ns: 0,
                    file_hash: Hash::ZERO,
                };
                results.push((child_name, meta));
            }
        }

        for dir in &fs.dirs {
            if let Some(child_name) = extract_direct_child(prefix, dir) {
                if !results.iter().any(|(name, _)| name == &child_name) {
                    let meta = FileMeta {
                        size: 0,
                        mode: 0o040755,
                        mtime_ns: 0,
                        file_hash: Hash::ZERO,
                    };
                    results.push((child_name, meta));
                }
            }
        }

        Ok(results)
    }

    async fn create_dir_all(&self, p: &VPath) -> Result<(), VelcruxError> {
        let mut fs = self.inner.write().await;
        let path_str = p.as_str().to_string();
        Self::ensure_parent_dirs_locked(&mut fs, &path_str);
        if !path_str.is_empty() {
            fs.dirs.insert(path_str);
        }
        Ok(())
    }

    async fn rename_file(&self, src: &VPath, dest: &VPath) -> Result<(), VelcruxError> {
        let src_key = src.as_str();
        let dest_key = dest.as_str();
        let mut fs = self.inner.write().await;

        if let Some(mut file) = fs.files.remove(src_key) {
            Self::ensure_parent_dirs_locked(&mut fs, dest_key);
            file.meta.file_hash = Hash::of(&file.data);
            fs.files.insert(dest_key.to_string(), file);
            return Ok(());
        }

        if let Some(target) = fs.symlinks.remove(src_key) {
            Self::ensure_parent_dirs_locked(&mut fs, dest_key);
            fs.symlinks.insert(dest_key.to_string(), target);
            return Ok(());
        }

        Err(VelcruxError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("rename source not found: {src_key}"),
        )))
    }

    async fn create_symlink(&self, dest: &VPath, target: &str) -> Result<(), VelcruxError> {
        let mut fs = self.inner.write().await;
        let dest_str = dest.as_str().to_string();
        Self::ensure_parent_dirs_locked(&mut fs, &dest_str);
        fs.symlinks.insert(dest_str, target.to_string());
        Ok(())
    }

    async fn create_hardlink(&self, dest: &VPath, src: &VPath) -> Result<(), VelcruxError> {
        let src_key = src.as_str();
        let dest_key = dest.as_str();
        let mut fs = self.inner.write().await;

        let src_file = fs.files.get(src_key).cloned().ok_or_else(|| {
            VelcruxError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("hardlink source not found: {src_key}"),
            ))
        })?;

        Self::ensure_parent_dirs_locked(&mut fs, dest_key);
        fs.files.insert(dest_key.to_string(), src_file);
        fs.hardlinks
            .insert(dest_key.to_string(), src_key.to_string());
        Ok(())
    }

    async fn get_xattrs(&self, p: &VPath) -> Result<Vec<(String, Vec<u8>)>, VelcruxError> {
        let key = p.as_str();
        let fs = self.inner.read().await;
        Ok(fs
            .files
            .get(key)
            .map(|f| f.xattrs.clone())
            .unwrap_or_default())
    }

    async fn set_xattrs(
        &self,
        p: &VPath,
        xattrs: &[(String, Vec<u8>)],
    ) -> Result<(), VelcruxError> {
        let key = p.as_str();
        let mut fs = self.inner.write().await;
        if let Some(file) = fs.files.get_mut(key) {
            file.xattrs = xattrs.to_vec();
        }
        Ok(())
    }

    async fn compute_file_hash(&self, p: &VPath) -> Result<Hash, VelcruxError> {
        let key = p.as_str();
        let fs = self.inner.read().await;
        let file = fs.files.get(key).ok_or_else(|| {
            VelcruxError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("file not found in memory: {key}"),
            ))
        })?;
        Ok(Hash::of(&file.data))
    }

    async fn compute_staging_hash(
        &self,
        transfer_id: &str,
        p: &VPath,
    ) -> Result<Hash, VelcruxError> {
        let key = (transfer_id.to_string(), p.as_str().to_string());
        let fs = self.inner.read().await;
        let buf_arc = fs.staging.get(&key).ok_or_else(|| {
            VelcruxError::Internal(format!(
                "memory staging buffer not found for transfer {transfer_id} at {p}"
            ))
        })?;
        let buf = buf_arc.read().await;
        Ok(Hash::of(&buf))
    }

    async fn store_chunk(&self, hash: &Hash, data: &[u8]) -> Result<(), VelcruxError> {
        let mut fs = self.inner.write().await;
        fs.chunks.insert(*hash, data.to_vec());
        Ok(())
    }

    async fn get_chunk(&self, hash: &Hash) -> Result<Option<Vec<u8>>, VelcruxError> {
        let fs = self.inner.read().await;
        Ok(fs.chunks.get(hash).cloned())
    }

    async fn has_chunk(&self, hash: &Hash) -> Result<bool, VelcruxError> {
        let fs = self.inner.read().await;
        Ok(fs.chunks.contains_key(hash))
    }

    async fn delete_chunk(&self, hash: &Hash) -> Result<bool, VelcruxError> {
        let mut fs = self.inner.write().await;
        Ok(fs.chunks.remove(hash).is_some())
    }
}

/// Helper to determine if `path` is an immediate child of `dir_prefix`.
fn extract_direct_child(dir_prefix: &str, path: &str) -> Option<String> {
    if dir_prefix.is_empty() {
        if path.is_empty() {
            None
        } else {
            let part = match path.find('/') {
                Some(idx) => &path[..idx],
                None => path,
            };
            Some(part.to_string())
        }
    } else if let Some(stripped) = path.strip_prefix(dir_prefix) {
        if let Some(sub) = stripped.strip_prefix('/') {
            if sub.is_empty() {
                None
            } else {
                let part = match sub.find('/') {
                    Some(idx) => &sub[..idx],
                    None => sub,
                };
                Some(part.to_string())
            }
        } else {
            None
        }
    } else {
        None
    }
}
