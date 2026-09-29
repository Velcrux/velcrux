//! Storage layer.
//!
//! `ARCHITECTURE.md` §2 + `SECURITY.md` §1: validation is enforced by
//! types, not discipline. The only way to reach the filesystem is through a
//! `VPath`, and a `VPath` cannot be constructed except by the validator.
//!
//! M2 scope: a single local-filesystem backend with atomic rename-based
//! commit. The `VPath` is the type-level traversal defence; the staging
//! discipline (`.velcrux-partial`, `fsync`, atomic `rename`, parent-dir
//! `fsync`) is the durability defence.
//!
//! Invariants (CLAUDE.md §1):
//!   - All sizes are u64.
//!   - No byte from the network reaches the filesystem without a length
//!     bound checked first (CLAUDE.md §1 #5).
//!   - Storage is staged, not overwritten; commit is an atomic rename
//!     (CLAUDE.md §1 #8).
//!   - Path validation: rejects `..`, absolute paths, embedded NUL, and
//!     every traversal variant.

use std::fmt;
use std::path::{Path, PathBuf};

pub mod chunk_store;
pub mod gc;
pub use chunk_store::{ChunkStore, LocalChunkStore};
pub use gc::{gc_chunk_store, gc_staging, ChunkStoreGcReport, StagingGcReport};

use crate::error::{ProtocolError, VelcruxError};
use crate::protocol::limits::{MAX_PATH_COMPONENT, MAX_PATH_TOTAL};
use crate::util::Hash;

/// Errors produced by path validation. The variant names are intentionally
/// not exposed to the wire — callers must collapse to a coarse "not found"
/// or "denied" detail per `PROTOCOL.md` §10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VPathError {
    /// Path was empty.
    Empty,
    /// Path contained a NUL byte or other forbidden character.
    ForbiddenChar,
    /// A path component exceeded `MAX_PATH_COMPONENT`.
    ComponentTooLong { len: usize, limit: usize },
    /// Total path length exceeded `MAX_PATH_TOTAL`.
    TooLong { len: usize, limit: usize },
    /// Path was absolute (starts with `/` or, on Windows, a drive letter).
    Absolute,
    /// Path contained a `..` component (traversal attempt).
    Traversal,
    /// Path resolved outside the storage root after normalisation.
    EscapesRoot,
    /// A symlink in the path would point outside the storage root.
    SymlinkEscape,
}

impl fmt::Display for VPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VPathError::Empty => f.write_str("empty path"),
            VPathError::ForbiddenChar => f.write_str("forbidden character"),
            VPathError::ComponentTooLong { len, limit } => {
                write!(f, "component too long ({len} > {limit})")
            }
            VPathError::TooLong { len, limit } => write!(f, "path too long ({len} > {limit})"),
            VPathError::Absolute => f.write_str("absolute path"),
            VPathError::Traversal => f.write_str("traversal"),
            VPathError::EscapesRoot => f.write_str("escapes root"),
            VPathError::SymlinkEscape => f.write_str("symlink escapes root"),
        }
    }
}

impl std::error::Error for VPathError {}

impl From<VPathError> for VelcruxError {
    fn from(_: VPathError) -> Self {
        VelcruxError::Protocol(ProtocolError::InvalidPath)
    }
}

/// A path validated against the storage root.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VPath(String);

impl VPath {
    /// Validate `raw` and return a normalised `VPath`.
    pub fn validate(raw: &str) -> Result<Self, VPathError> {
        if raw.is_empty() {
            return Err(VPathError::Empty);
        }
        if raw.len() > MAX_PATH_TOTAL {
            return Err(VPathError::TooLong {
                len: raw.len(),
                limit: MAX_PATH_TOTAL,
            });
        }
        if raw.starts_with('/') {
            return Err(VPathError::Absolute);
        }
        if raw.chars().any(|c| c.is_control()) {
            return Err(VPathError::ForbiddenChar);
        }
        let mut normalised = String::with_capacity(raw.len());
        let mut first = true;
        let trailing_slash = raw.ends_with('/');
        for component in raw.split('/') {
            if component.is_empty() {
                return Err(VPathError::Traversal);
            }
            if component == "." || component == ".." {
                return Err(VPathError::Traversal);
            }
            if component.len() > MAX_PATH_COMPONENT {
                return Err(VPathError::ComponentTooLong {
                    len: component.len(),
                    limit: MAX_PATH_COMPONENT,
                });
            }
            if !first {
                normalised.push('/');
            }
            normalised.push_str(component);
            first = false;
        }
        if normalised.is_empty() || trailing_slash {
            return Err(VPathError::Traversal);
        }
        Ok(Self(normalised))
    }

    /// Borrow the path as a string. The path is normalised; it does NOT
    /// include any root prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Borrow the path as a `Path`-like relative path.
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// Return the root virtual path (empty relative path).
    pub fn root() -> Self {
        Self(String::new())
    }

    /// True if this virtual path is the root directory.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Return the parent `VPath`, or `None` if this is root or a top-level path.
    pub fn parent(&self) -> Option<Self> {
        let p = self.as_path().parent()?;
        let s = p.to_string_lossy().to_string();
        if s.is_empty() {
            None
        } else {
            Some(Self(s))
        }
    }

    /// Lexically validate that a symlink placed at `link_path` with target `raw_target`
    /// does not escape the virtual root (`SECURITY.md` §4, §5).
    ///
    /// The target is evaluated relative to the parent directory of `link_path`.
    /// Traversal attempts (`..`) above the virtual root are strictly rejected with
    /// `VPathError::SymlinkEscape`. Absolute paths (leading `/`, `\\`, or Windows drive letters)
    /// are also rejected with `VPathError::SymlinkEscape`.
    ///
    /// Never silently rewrites targets.
    pub fn validate_symlink_target(
        link_path: &VPath,
        raw_target: &str,
    ) -> Result<VPath, VPathError> {
        if raw_target.is_empty() {
            return Err(VPathError::Empty);
        }
        if raw_target.contains('\0') {
            return Err(VPathError::ForbiddenChar);
        }
        for b in raw_target.bytes() {
            if b < 0x20 || b == 0x7f {
                return Err(VPathError::ForbiddenChar);
            }
        }
        // Absolute targets are disallowed as they point outside the virtual root
        if raw_target.starts_with('/') || raw_target.starts_with('\\') {
            return Err(VPathError::SymlinkEscape);
        }
        // Check for Windows drive prefix (e.g. "C:")
        if raw_target.len() >= 2 && raw_target.as_bytes()[1] == b':' {
            return Err(VPathError::SymlinkEscape);
        }

        let mut stack: Vec<&str> = Vec::new();
        // Start with the parent directory components of link_path
        let parent_str = link_path
            .as_path()
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("");
        for comp in parent_str.split('/') {
            let comp = comp.trim();
            if !comp.is_empty() && comp != "." {
                stack.push(comp);
            }
        }

        // Process raw_target components
        for comp in raw_target.split(|c| c == '/' || c == '\\') {
            let comp = comp.trim();
            if comp.is_empty() || comp == "." {
                continue;
            }
            if comp == ".." {
                if stack.pop().is_none() {
                    // Traversed above virtual root!
                    return Err(VPathError::SymlinkEscape);
                }
            } else {
                if comp.len() > MAX_PATH_COMPONENT {
                    return Err(VPathError::ComponentTooLong {
                        len: comp.len(),
                        limit: MAX_PATH_COMPONENT,
                    });
                }
                stack.push(comp);
            }
        }

        if stack.is_empty() {
            // Points to the virtual root itself
            Ok(VPath::root())
        } else {
            let resolved = stack.join("/");
            if resolved.len() > MAX_PATH_TOTAL {
                return Err(VPathError::TooLong {
                    len: resolved.len(),
                    limit: MAX_PATH_TOTAL,
                });
            }
            Ok(VPath(resolved))
        }
    }

    /// Construct a `VPath` from a string already known to be valid. The
    /// only public caller is the storage backend resolving relative paths.
    #[allow(dead_code)]
    pub(crate) fn from_validated(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for VPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Metadata about a file: size, content hash, POSIX mode bits, mtime.
///
/// `size` and the offsets in the file system are u64 (`CLAUDE.md` §1 #4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    /// Total file size, in bytes.
    pub size: u64,
    /// POSIX mode bits (regular file, directory, etc.). Reserved for M5.
    pub mode: u32,
    /// Modification time in nanoseconds since the UNIX epoch.
    pub mtime_ns: i64,
    /// Whole-file BLAKE3-256.
    pub file_hash: Hash,
}

impl FileMeta {
    /// Construct a minimal meta record from size and hash.
    pub fn new(size: u64, file_hash: Hash) -> Self {
        Self {
            size,
            mode: 0o100644,
            mtime_ns: 0,
            file_hash,
        }
    }
}
/// A handle to an in-progress staged write. The file is at
/// `<root>/<staging>/<transfer_id>/<name>.velcrux-partial` until commit.
#[derive(Debug)]
pub struct Staging {
    /// Absolute path to the staged file.
    path: PathBuf,
}

impl Staging {
    /// Construct a `Staging` for an arbitrary path. The M3-aware
    /// server uses this to wrap a pre-opened file that may have
    /// been resumed across processes.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Absolute path to the staged file.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

/// Filesystem-backed storage backend.
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    /// Look up a file's metadata. Returns `Ok(None)` if the file does not
    /// exist or is outside the caller's scope.
    async fn stat(&self, p: &VPath) -> Result<Option<FileMeta>, VelcruxError>;

    /// Open a file for reading.
    async fn open_read(&self, p: &VPath) -> Result<Box<dyn AsyncRandomRead>, VelcruxError>;

    /// Open a staging file for writing.
    async fn open_staging(
        &self,
        transfer_id: &str,
        p: &VPath,
        size_hint: u64,
    ) -> Result<StagingWriter, VelcruxError>;

    /// Open a staging file for writing, optionally preserving existing data if resuming.
    async fn open_staging_resumable(
        &self,
        transfer_id: &str,
        p: &VPath,
        size_hint: u64,
        resumed: bool,
    ) -> Result<StagingWriter, VelcruxError> {
        let _ = resumed;
        self.open_staging(transfer_id, p, size_hint).await
    }

    /// Atomically commit a staged file.
    async fn commit(
        &self,
        transfer_id: &str,
        staging: Staging,
        dest: &VPath,
        meta: &FileMeta,
    ) -> Result<(), VelcruxError>;

    /// Remove a file.
    async fn remove(&self, p: &VPath) -> Result<(), VelcruxError>;

    /// Create a symbolic link at `dest` pointing to `target`.
    async fn create_symlink(&self, dest: &VPath, target: &str) -> Result<(), VelcruxError>;

    /// Create a hard link at `dest` pointing to `src`.
    async fn create_hardlink(&self, dest: &VPath, src: &VPath) -> Result<(), VelcruxError>;

    /// Retrieve extended attributes for a file or directory.
    async fn get_xattrs(&self, p: &VPath) -> Result<Vec<(String, Vec<u8>)>, VelcruxError> {
        let _ = p;
        Ok(Vec::new())
    }

    /// Set extended attributes for a file or directory.
    async fn set_xattrs(
        &self,
        p: &VPath,
        xattrs: &[(String, Vec<u8>)],
    ) -> Result<(), VelcruxError> {
        let _ = (p, xattrs);
        Ok(())
    }

    /// Return the available space in bytes on the storage volume.
    async fn available_space(&self) -> Result<u64, VelcruxError> {
        Ok(u64::MAX)
    }

    /// Return the configured minimum free disk space reservation margin in bytes.
    fn min_free_space(&self) -> u64 {
        0
    }

    /// Return whether physical preallocation (`fallocate`) is enabled.
    fn preallocate_enabled(&self) -> bool {
        false
    }

    /// Storage root absolute path.
    fn root(&self) -> &Path;
}

/// Async random-read file handle. Reads at arbitrary offsets.
#[async_trait::async_trait]
pub trait AsyncRandomRead: Send {
    /// Total file size.
    fn len(&self) -> u64;
    /// True if the file is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Read up to `buf.len()` bytes at `offset`. Returns the number of
    /// bytes actually read; `0` indicates EOF.
    async fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, VelcruxError>;
}

/// A writer into a staged file.
#[derive(Debug)]
pub struct StagingWriter {
    staging: Staging,
    file: tokio::fs::File,
    written: u64,
}

impl StagingWriter {
    /// Construct a `StagingWriter` from a pre-opened file and the
    /// staging path. Used by M3-aware server code that needs
    /// fine-grained control over the open mode (e.g. to avoid
    /// truncating an existing partial file on resume).
    pub fn new(file: tokio::fs::File, staging: Staging) -> Self {
        Self {
            staging,
            file,
            written: 0,
        }
    }

    /// `pwrite`: write `data` at `offset`. The staging file is extended
    /// as needed. Out-of-order writes are supported.
    pub async fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), VelcruxError> {
        use tokio::io::AsyncSeekExt;
        use tokio::io::AsyncWriteExt;
        self.file.seek(std::io::SeekFrom::Start(offset)).await?;
        self.file.write_all(data).await?;
        let end = offset + data.len() as u64;
        if end > self.written {
            self.written = end;
        }
        Ok(())
    }

    /// Total bytes written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// `fsync` the file's data and metadata.
    pub async fn fsync(&mut self) -> Result<(), VelcruxError> {
        self.file.sync_all().await?;
        Ok(())
    }

    /// Absolute path to the staged file.
    pub fn path(&self) -> &std::path::Path {
        self.staging.path()
    }

    /// Consume the writer and return the inner `Staging` for commit.
    pub fn into_staging(self) -> Staging {
        self.staging
    }
}

pub struct LocalFilesystemBackend {
    root: PathBuf,
    staging: PathBuf,
    min_free_space: u64,
    preallocate: bool,
}

impl LocalFilesystemBackend {
    /// Absolute path of the staging directory. Exposed so the server-side
    /// transfer pipeline can locate the staged file to compute the
    /// whole-file BLAKE3.
    pub fn staging_dir(&self) -> &Path {
        &self.staging
    }

    /// Construct a backend with the given root and staging directories.
    /// Both must exist and be directories; both must be on the same
    /// filesystem (so atomic `rename` is possible).
    pub async fn new(root: PathBuf, staging: PathBuf) -> Result<Self, VelcruxError> {
        Self::new_with_options(root, staging, 0, false).await
    }

    /// Construct a backend with explicit disk reservation margin and preallocation flag.
    pub async fn new_with_options(
        root: PathBuf,
        staging: PathBuf,
        min_free_space: u64,
        preallocate: bool,
    ) -> Result<Self, VelcruxError> {
        let m1 = tokio::fs::metadata(&root).await?;
        if !m1.is_dir() {
            return Err(VelcruxError::Config(format!(
                "storage root is not a directory: {}",
                root.display()
            )));
        }
        let m2 = tokio::fs::metadata(&staging).await?;
        if !m2.is_dir() {
            return Err(VelcruxError::Config(format!(
                "staging is not a directory: {}",
                staging.display()
            )));
        }
        let c1 = tokio::fs::canonicalize(&root).await?;
        let c2 = tokio::fs::canonicalize(&staging).await?;
        let d1 = dev_of(&c1);
        let d2 = dev_of(&c2);
        if d1 != d2 {
            return Err(VelcruxError::Config(format!(
                "storage root ({}) and staging ({}) are on different filesystems (dev {} vs {})",
                root.display(),
                staging.display(),
                d1,
                d2
            )));
        }
        Ok(Self {
            root,
            staging,
            min_free_space,
            preallocate,
        })
    }

    /// Builder helper to set preallocation and disk reservation margin.
    pub fn with_preallocation(mut self, preallocate: bool, min_free_space: u64) -> Self {
        self.preallocate = preallocate;
        self.min_free_space = min_free_space;
        self
    }

    /// Builder helper to set minimum free space margin in bytes.
    pub fn with_min_free_space(mut self, margin: u64) -> Self {
        self.min_free_space = margin;
        self
    }

    fn resolve(&self, p: &VPath) -> PathBuf {
        self.root.join(p.as_path())
    }

    pub fn staging_path(&self, transfer_id: &str, p: &VPath) -> PathBuf {
        let safe_tid: String = transfer_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let mut out = self.staging.clone();
        out.push(safe_tid);
        let stem = p.as_path();
        out.push(stem);
        out.set_extension(format!(
            "{}.velcrux-partial",
            out.extension().and_then(|e| e.to_str()).unwrap_or("")
        ));
        out
    }
}

fn dev_of(p: &Path) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).map(|m| m.dev()).unwrap_or(0)
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        0
    }
}
#[async_trait::async_trait]
impl StorageBackend for LocalFilesystemBackend {
    fn root(&self) -> &Path {
        &self.root
    }

    async fn stat(&self, p: &VPath) -> Result<Option<FileMeta>, VelcruxError> {
        let path = self.resolve(p);
        match tokio::fs::metadata(&path).await {
            Ok(m) if m.is_file() => {
                let size = m.len();
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    m.permissions().mode()
                };
                #[cfg(not(unix))]
                let mode = 0;
                #[cfg(unix)]
                let mtime_ns = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_nanos() as i64)
                    .unwrap_or(0);
                #[cfg(not(unix))]
                let mtime_ns = 0;
                Ok(Some(FileMeta {
                    size,
                    mode,
                    mtime_ns,
                    file_hash: Hash::ZERO,
                }))
            }
            Ok(_) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn open_read(&self, p: &VPath) -> Result<Box<dyn AsyncRandomRead>, VelcruxError> {
        let path = self.resolve(p);
        let file = tokio::fs::File::open(&path).await?;
        let meta = file.metadata().await?;
        Ok(Box::new(TokioRandomRead {
            file,
            len: meta.len(),
        }))
    }

    async fn available_space(&self) -> Result<u64, VelcruxError> {
        let staging_dir = self.staging.clone();
        tokio::task::spawn_blocking(move || {
            fs4::available_space(&staging_dir).map_err(VelcruxError::Io)
        })
        .await
        .map_err(|e| VelcruxError::Internal(e.to_string()))?
    }

    fn min_free_space(&self) -> u64 {
        self.min_free_space
    }

    fn preallocate_enabled(&self) -> bool {
        self.preallocate
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
        // Enforce free disk space reservation check if configured (SECURITY.md §6)
        if (self.min_free_space > 0 || self.preallocate) && size_hint > 0 {
            if let Ok(avail) = self.available_space().await {
                let required = size_hint.saturating_add(self.min_free_space);
                if avail < required {
                    return Err(VelcruxError::Protocol(
                        crate::error::ProtocolError::DiskFull(format!(
                            "insufficient disk space: available {avail} B < required {required} B (size_hint {size_hint} B + min_free_space {} B)",
                            self.min_free_space
                        )),
                    ));
                }
            }
        }

        let path = self.staging_path(transfer_id, p);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let existed = tokio::fs::try_exists(&path).await.unwrap_or(false);
        let truncate = if resumed && existed { false } else { true };
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(truncate)
            .open(&path)
            .await?;

        // Physical block preallocation via fallocate (SECURITY.md §6)
        if self.preallocate && size_hint > 0 {
            use fs4::tokio::AsyncFileExt;
            match file.allocate(size_hint).await {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(28) || e.kind() == std::io::ErrorKind::Other => {
                    return Err(VelcruxError::Protocol(
                        crate::error::ProtocolError::DiskFull(format!(
                            "preallocation fallocate failed: {e}"
                        )),
                    ));
                }
                Err(_) => {
                    // Filesystem may not support fallocate; fall back to set_len
                    let _ = file.set_len(size_hint).await;
                }
            }
        }

        let written = if resumed && existed {
            tokio::fs::metadata(&path)
                .await
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };
        Ok(StagingWriter {
            staging: Staging::new(path),
            file,
            written,
        })
    }

    async fn commit(
        &self,
        _transfer_id: &str,
        staging: Staging,
        dest: &VPath,
        _meta: &FileMeta,
    ) -> Result<(), VelcruxError> {
        let dest_path = self.resolve(dest);
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        // Atomic rename. POSIX guarantees this is atomic on the same
        // filesystem; we verified that at construction.
        tokio::fs::rename(&staging.path, &dest_path).await?;
        // fsync the parent directory so the rename is durable.
        if let Some(parent) = dest_path.parent() {
            let dir = tokio::fs::File::open(parent).await?;
            dir.sync_all().await?;
        }
        Ok(())
    }

    async fn remove(&self, p: &VPath) -> Result<(), VelcruxError> {
        if p.is_root() {
            return Err(VelcruxError::Protocol(ProtocolError::InvalidPath));
        }
        let path = self.resolve(p);
        let sidecar = xattr_sidecar_path(&path);
        let _ = tokio::fs::remove_file(&sidecar).await;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_xattrs(&self, p: &VPath) -> Result<Vec<(String, Vec<u8>)>, VelcruxError> {
        let path = self.resolve(p);
        let sidecar = xattr_sidecar_path(&path);
        match tokio::fs::read(&sidecar).await {
            Ok(bytes) => decode_xattrs_canonical(&bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    async fn set_xattrs(
        &self,
        p: &VPath,
        xattrs: &[(String, Vec<u8>)],
    ) -> Result<(), VelcruxError> {
        let path = self.resolve(p);
        let sidecar = xattr_sidecar_path(&path);
        if xattrs.is_empty() {
            let _ = tokio::fs::remove_file(&sidecar).await;
            return Ok(());
        }
        if let Some(parent) = sidecar.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let raw = encode_xattrs_canonical(xattrs);
        let tmp = PathBuf::from(format!("{}.tmp-xattr", sidecar.to_string_lossy()));
        tokio::fs::write(&tmp, &raw).await?;
        tokio::fs::rename(&tmp, &sidecar).await?;
        Ok(())
    }

    async fn create_symlink(&self, dest: &VPath, target: &str) -> Result<(), VelcruxError> {
        if dest.is_root() {
            return Err(VelcruxError::Protocol(ProtocolError::InvalidPath));
        }
        let dest_path = self.resolve(dest);
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if let Ok(_) = tokio::fs::symlink_metadata(&dest_path).await {
            let _ = tokio::fs::remove_file(&dest_path).await;
        }

        #[cfg(unix)]
        {
            let target = target.to_string();
            let dest_p = dest_path.clone();
            tokio::task::spawn_blocking(move || std::os::unix::fs::symlink(target, dest_p))
                .await
                .map_err(|e| VelcruxError::Internal(e.to_string()))??;
        }
        #[cfg(windows)]
        {
            let target = target.to_string();
            let dest_p = dest_path.clone();
            tokio::task::spawn_blocking(move || std::os::windows::fs::symlink_file(target, dest_p))
                .await
                .map_err(|e| VelcruxError::Internal(e.to_string()))??;
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (dest_path, target);
            return Err(VelcruxError::Internal(
                "symlinks not supported on this platform".into(),
            ));
        }

        Ok(())
    }

    async fn create_hardlink(&self, dest: &VPath, src: &VPath) -> Result<(), VelcruxError> {
        if dest.is_root() || src.is_root() {
            return Err(VelcruxError::Protocol(ProtocolError::InvalidPath));
        }
        let dest_path = self.resolve(dest);
        let src_path = self.resolve(src);
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if let Ok(_) = tokio::fs::symlink_metadata(&dest_path).await {
            let _ = tokio::fs::remove_file(&dest_path).await;
        }
        tokio::fs::hard_link(&src_path, &dest_path).await?;
        Ok(())
    }
}

struct TokioRandomRead {
    file: tokio::fs::File,
    len: u64,
}

#[async_trait::async_trait]
impl AsyncRandomRead for TokioRandomRead {
    fn len(&self) -> u64 {
        self.len
    }
    async fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, VelcruxError> {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncSeekExt;
        self.file.seek(std::io::SeekFrom::Start(offset)).await?;
        let n = self.file.read(buf).await?;
        Ok(n)
    }
}

/// Helper to construct the xattr sidecar path for a file.
pub fn xattr_sidecar_path(file_path: &Path) -> PathBuf {
    let mut s = file_path.as_os_str().to_os_string();
    s.push(".velcrux-xattr");
    PathBuf::from(s)
}

/// Helper to serialize xattrs to a canonical binary buffer.
pub fn encode_xattrs_canonical(xattrs: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut vbuf = [0u8; 10];
    let n = crate::protocol::varint::encode_varint(xattrs.len() as u64, &mut vbuf);
    out.extend_from_slice(&vbuf[..n]);
    for (name, val) in xattrs {
        let n = crate::protocol::varint::encode_varint(name.len() as u64, &mut vbuf);
        out.extend_from_slice(&vbuf[..n]);
        out.extend_from_slice(name.as_bytes());

        let n = crate::protocol::varint::encode_varint(val.len() as u64, &mut vbuf);
        out.extend_from_slice(&vbuf[..n]);
        out.extend_from_slice(val);
    }
    out
}

/// Helper to deserialize xattrs from a canonical binary buffer.
pub fn decode_xattrs_canonical(buf: &[u8]) -> Result<Vec<(String, Vec<u8>)>, VelcruxError> {
    if buf.is_empty() {
        return Ok(Vec::new());
    }
    let mut offset = 0;
    let (count, c) =
        crate::protocol::varint::decode_varint(buf).map_err(|e| VelcruxError::Protocol(e))?;
    offset += c;
    let mut xattrs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (nlen, c) = crate::protocol::varint::decode_varint(&buf[offset..])
            .map_err(|e| VelcruxError::Protocol(e))?;
        offset += c;
        let nlen = nlen as usize;
        if buf.len() < offset + nlen {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "truncated xattr sidecar name",
            )));
        }
        let name = std::str::from_utf8(&buf[offset..offset + nlen])
            .map_err(|_| {
                VelcruxError::Protocol(ProtocolError::Malformed("xattr sidecar name not UTF-8"))
            })?
            .to_string();
        offset += nlen;

        let (vlen, c) = crate::protocol::varint::decode_varint(&buf[offset..])
            .map_err(|e| VelcruxError::Protocol(e))?;
        offset += c;
        let vlen = vlen as usize;
        if buf.len() < offset + vlen {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "truncated xattr sidecar val",
            )));
        }
        let val = buf[offset..offset + vlen].to_vec();
        offset += vlen;
        xattrs.push((name, val));
    }
    Ok(xattrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpath_validate_accepts_simple() {
        let p = VPath::validate("data/file.bin").unwrap();
        assert_eq!(p.as_str(), "data/file.bin");
    }

    #[test]
    fn vpath_validate_rejects_traversal() {
        assert!(matches!(VPath::validate(".."), Err(VPathError::Traversal)));
        assert!(matches!(
            VPath::validate("data/../etc"),
            Err(VPathError::Traversal)
        ));
        assert!(matches!(
            VPath::validate("data/.."),
            Err(VPathError::Traversal)
        ));
        assert!(matches!(VPath::validate("."), Err(VPathError::Traversal)));
        assert!(matches!(
            VPath::validate("data/"),
            Err(VPathError::Traversal)
        ));
        assert!(matches!(
            VPath::validate("/data"),
            Err(VPathError::Absolute)
        ));
    }

    #[test]
    fn vpath_validate_rejects_absolute_and_empty() {
        assert!(matches!(
            VPath::validate("/etc/passwd"),
            Err(VPathError::Absolute)
        ));
        assert!(matches!(
            VPath::validate("data//file"),
            Err(VPathError::Traversal)
        ));
        assert!(matches!(VPath::validate(""), Err(VPathError::Empty)));
    }

    #[test]
    fn vpath_validate_rejects_overlong_component() {
        let big = "x".repeat(MAX_PATH_COMPONENT + 1);
        let p = format!("data/{big}");
        assert!(matches!(
            VPath::validate(&p),
            Err(VPathError::ComponentTooLong { .. })
        ));
    }

    #[test]
    fn vpath_validate_rejects_overlong_total() {
        let comps = vec!["abc"; (MAX_PATH_TOTAL / 4) + 1];
        let p = comps.join("/");
        assert!(matches!(
            VPath::validate(&p),
            Err(VPathError::TooLong { .. })
        ));
    }

    #[test]
    fn vpath_validate_rejects_null_and_control() {
        assert!(matches!(
            VPath::validate("data/\0bad"),
            Err(VPathError::ForbiddenChar)
        ));
        assert!(matches!(
            VPath::validate("data/\n"),
            Err(VPathError::ForbiddenChar)
        ));
        assert!(matches!(
            VPath::validate("data/\t"),
            Err(VPathError::ForbiddenChar)
        ));
    }

    #[tokio::test]
    async fn local_backend_round_trip() {
        let tmp = tempdir_in_target();
        let root = tmp.join("root");
        let staging = tmp.join("stage");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::create_dir_all(&staging).await.unwrap();

        let backend = LocalFilesystemBackend::new(root.clone(), staging.clone())
            .await
            .unwrap();

        let dest = VPath::validate("foo.bin").unwrap();
        let mut w = backend
            .open_staging("01JB7Q2K9M4X8ZQ3V5N7T1R6C0", &dest, 11)
            .await
            .unwrap();
        w.write_at(0, b"hello").await.unwrap();
        w.write_at(5, b" world").await.unwrap();
        assert_eq!(w.written(), 11);
        w.fsync().await.unwrap();
        let staging_handle = w.into_staging();

        let meta = FileMeta::new(11, Hash::of(b"hello world"));
        backend
            .commit("01JB7Q2K9M4X8ZQ3V5N7T1R6C0", staging_handle, &dest, &meta)
            .await
            .unwrap();

        let m = backend.stat(&dest).await.unwrap().unwrap();
        assert_eq!(m.size, 11);

        let mut r = backend.open_read(&dest).await.unwrap();
        let mut buf = vec![0u8; 16];
        let n = r.read_at(0, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello world");
    }

    #[tokio::test]
    async fn local_backend_commit_replaces_existing() {
        let tmp = tempdir_in_target();
        let root = tmp.join("root");
        let staging = tmp.join("stage");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::create_dir_all(&staging).await.unwrap();
        let backend = LocalFilesystemBackend::new(root.clone(), staging.clone())
            .await
            .unwrap();

        let dest = VPath::validate("replace.bin").unwrap();

        // First commit.
        let mut w1 = backend.open_staging("t1", &dest, 5).await.unwrap();
        w1.write_at(0, b"first").await.unwrap();
        w1.fsync().await.unwrap();
        backend
            .commit(
                "t1",
                w1.into_staging(),
                &dest,
                &FileMeta::new(5, Hash::of(b"first")),
            )
            .await
            .unwrap();
        assert_eq!(backend.stat(&dest).await.unwrap().unwrap().size, 5);

        // Second commit replaces it (atomic rename).
        let mut w2 = backend.open_staging("t2", &dest, 7).await.unwrap();
        w2.write_at(0, b"second!").await.unwrap();
        w2.fsync().await.unwrap();
        backend
            .commit(
                "t2",
                w2.into_staging(),
                &dest,
                &FileMeta::new(7, Hash::of(b"second!")),
            )
            .await
            .unwrap();
        assert_eq!(backend.stat(&dest).await.unwrap().unwrap().size, 7);
    }

    #[test]
    fn vpath_validate_symlink_target_contained() {
        let link_path = VPath::validate("sub/dir/link.txt").unwrap();
        // Points to sibling
        let res = VPath::validate_symlink_target(&link_path, "target.txt").unwrap();
        assert_eq!(res.as_str(), "sub/dir/target.txt");

        // Points up one level
        let res = VPath::validate_symlink_target(&link_path, "../sibling.txt").unwrap();
        assert_eq!(res.as_str(), "sub/sibling.txt");

        // Points up two levels to root file
        let res = VPath::validate_symlink_target(&link_path, "../../root_file.txt").unwrap();
        assert_eq!(res.as_str(), "root_file.txt");
    }

    #[test]
    fn vpath_validate_symlink_target_escapes_rejected() {
        let link_path = VPath::validate("sub/link.txt").unwrap();
        // Escapes above root
        assert_eq!(
            VPath::validate_symlink_target(&link_path, "../../etc/passwd"),
            Err(VPathError::SymlinkEscape)
        );

        // Absolute target
        assert_eq!(
            VPath::validate_symlink_target(&link_path, "/etc/passwd"),
            Err(VPathError::SymlinkEscape)
        );

        // Windows drive target
        assert_eq!(
            VPath::validate_symlink_target(&link_path, "C:\\Windows"),
            Err(VPathError::SymlinkEscape)
        );

        // Top level link escaping
        let top_link = VPath::validate("link.txt").unwrap();
        assert_eq!(
            VPath::validate_symlink_target(&top_link, "../outside"),
            Err(VPathError::SymlinkEscape)
        );

        // Empty and control chars
        assert_eq!(
            VPath::validate_symlink_target(&link_path, ""),
            Err(VPathError::Empty)
        );
        assert_eq!(
            VPath::validate_symlink_target(&link_path, "foo\0bar"),
            Err(VPathError::ForbiddenChar)
        );
    }

    #[tokio::test]
    async fn local_backend_symlink_and_hardlink_creation() {
        let tmp = tempdir_in_target();
        let root = tmp.join("root");
        let staging = tmp.join("stage");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::create_dir_all(&staging).await.unwrap();
        let backend = LocalFilesystemBackend::new(root.clone(), staging.clone())
            .await
            .unwrap();

        // Create original file
        let orig = VPath::validate("orig.txt").unwrap();
        let mut w = backend.open_staging("t1", &orig, 5).await.unwrap();
        w.write_at(0, b"hello").await.unwrap();
        w.fsync().await.unwrap();
        backend
            .commit(
                "t1",
                w.into_staging(),
                &orig,
                &FileMeta::new(5, Hash::of(b"hello")),
            )
            .await
            .unwrap();

        // Create symlink
        let sym = VPath::validate("sym.txt").unwrap();
        backend.create_symlink(&sym, "orig.txt").await.unwrap();
        let meta = tokio::fs::symlink_metadata(root.join("sym.txt"))
            .await
            .unwrap();
        assert!(meta.file_type().is_symlink());

        // Create hard link
        let hard = VPath::validate("hard.txt").unwrap();
        backend.create_hardlink(&hard, &orig).await.unwrap();
        let meta = tokio::fs::metadata(root.join("hard.txt")).await.unwrap();
        assert_eq!(meta.len(), 5);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let orig_meta = tokio::fs::metadata(root.join("orig.txt")).await.unwrap();
            assert_eq!(meta.ino(), orig_meta.ino());
            assert_eq!(meta.nlink(), 2);
        }
    }
}

#[cfg(test)]
fn tempdir_in_target() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("velcrux-test-{pid}-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
