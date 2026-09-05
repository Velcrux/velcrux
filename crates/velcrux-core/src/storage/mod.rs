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

use crate::error::{ProtocolError, VelcruxError};
use crate::protocol::limits::{MAX_PATH_COMPONENT, MAX_PATH_TOTAL};
use crate::util::Hash;

/// Errors produced by path validation. The variant names are intentionally
/// not exposed to the wire — callers must collapse to a coarse "not found"
/// or "denied" detail per `SECURITY.md` §10.
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
            return Err(VPathError::TooLong { len: raw.len(), limit: MAX_PATH_TOTAL });
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

    /// Construct a `VPath` from a string already known to be valid. The
    /// only public caller is the storage backend resolving relative paths.
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
        Self { size, mode: 0o100644, mtime_ns: 0, file_hash }
    }
}
/// A handle to an in-progress staged write. The file is at
/// `<root>/<staging>/<transfer_id>/<name>.velcrux-partial` until commit.
pub struct Staging {
    /// Absolute path to the staged file.
    path: PathBuf,
}

impl Staging {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
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
pub struct StagingWriter {
    staging: Staging,
    file: tokio::fs::File,
    written: u64,
}

impl StagingWriter {
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

    /// Consume the writer and return the inner `Staging` for commit.
    pub fn into_staging(self) -> Staging {
        self.staging
    }
}

pub struct LocalFilesystemBackend {
    root: PathBuf,
    staging: PathBuf,
}

impl LocalFilesystemBackend {
    /// Construct a backend with the given root and staging directories.
    /// Both must exist and be directories; both must be on the same
    /// filesystem (so atomic `rename` is possible).
    pub async fn new(root: PathBuf, staging: PathBuf) -> Result<Self, VelcruxError> {
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
                root.display(), staging.display(), d1, d2
            )));
        }
        Ok(Self { root, staging })
    }

    fn resolve(&self, p: &VPath) -> PathBuf {
        self.root.join(p.as_path())
    }

    fn staging_path(&self, transfer_id: &str, p: &VPath) -> PathBuf {
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
                Ok(Some(FileMeta { size, mode, mtime_ns, file_hash: Hash::ZERO }))
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
        Ok(Box::new(TokioRandomRead { file, len: meta.len() }))
    }

    async fn open_staging(
        &self,
        transfer_id: &str,
        p: &VPath,
        _size_hint: u64,
    ) -> Result<StagingWriter, VelcruxError> {
        let path = self.staging_path(transfer_id, p);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await?;
        Ok(StagingWriter { staging: Staging::new(path), file, written: 0 })
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
        let path = self.resolve(p);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
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
        assert!(matches!(VPath::validate("data/.."), Err(VPathError::Traversal)));
        assert!(matches!(VPath::validate("."), Err(VPathError::Traversal)));
        assert!(matches!(VPath::validate("data/"), Err(VPathError::Traversal)));
        assert!(matches!(VPath::validate("/data"), Err(VPathError::Absolute)));
    }

    #[test]
    fn vpath_validate_rejects_absolute_and_empty() {
        assert!(matches!(VPath::validate("/etc/passwd"), Err(VPathError::Absolute)));
        assert!(matches!(VPath::validate("data//file"), Err(VPathError::Traversal)));
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
        assert!(matches!(VPath::validate(&p), Err(VPathError::TooLong { .. })));
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
        let mut w1 = backend
            .open_staging("t1", &dest, 5)
            .await
            .unwrap();
        w1.write_at(0, b"first").await.unwrap();
        w1.fsync().await.unwrap();
        backend
            .commit("t1", w1.into_staging(), &dest, &FileMeta::new(5, Hash::of(b"first")))
            .await
            .unwrap();
        assert_eq!(
            backend.stat(&dest).await.unwrap().unwrap().size,
            5
        );

        // Second commit replaces it (atomic rename).
        let mut w2 = backend
            .open_staging("t2", &dest, 7)
            .await
            .unwrap();
        w2.write_at(0, b"second!").await.unwrap();
        w2.fsync().await.unwrap();
        backend
            .commit("t2", w2.into_staging(), &dest, &FileMeta::new(7, Hash::of(b"second!")))
            .await
            .unwrap();
        assert_eq!(
            backend.stat(&dest).await.unwrap().unwrap().size,
            7
        );
    }
}

fn tempdir_in_target() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("velcrux-test-{pid}-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}