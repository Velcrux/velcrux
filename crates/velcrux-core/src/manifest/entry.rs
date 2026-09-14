//! Manifest entry and chunk descriptor types (`PROTOCOL.md` §4).
//!
//! All sizes and offsets are `u64` per `CLAUDE.md` §1 #4. Chunk offsets are
//! implicit: they are the running sum of preceding chunk lengths.

use std::fmt;

use crate::storage::VPath;
use crate::util::Hash;

/// Entry type mask in `FileFlags` (bits 0..=1).
pub const FILE_TYPE_MASK: u64 = 0x03;
/// Regular file entry flag value.
pub const FILE_TYPE_REGULAR: u64 = 0x00;
/// Directory entry flag value.
pub const FILE_TYPE_DIR: u64 = 0x01;
/// Symlink entry flag value.
pub const FILE_TYPE_SYMLINK: u64 = 0x02;
/// Sparse file flag (bit 2).
pub const FILE_FLAG_SPARSE: u64 = 0x04;
/// Has extended attributes flag (bit 3).
pub const FILE_FLAG_HAS_XATTRS: u64 = 0x08;

/// File type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    /// Regular file with data chunks.
    Regular,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

/// Bitflags describing file entry properties (`PROTOCOL.md` §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileFlags(pub u64);

impl FileFlags {
    /// Construct empty flags for a regular file.
    pub const fn regular() -> Self {
        Self(FILE_TYPE_REGULAR)
    }

    /// Construct flags for a directory.
    pub const fn directory() -> Self {
        Self(FILE_TYPE_DIR)
    }

    /// Construct flags for a symbolic link.
    pub const fn symlink() -> Self {
        Self(FILE_TYPE_SYMLINK)
    }

    /// Extract the `FileType`.
    pub fn file_type(&self) -> FileType {
        match self.0 & FILE_TYPE_MASK {
            FILE_TYPE_DIR => FileType::Directory,
            FILE_TYPE_SYMLINK => FileType::Symlink,
            _ => FileType::Regular,
        }
    }

    /// True if marked as a sparse file.
    pub fn is_sparse(&self) -> bool {
        (self.0 & FILE_FLAG_SPARSE) != 0
    }

    /// Set or clear sparse flag.
    pub fn with_sparse(mut self, sparse: bool) -> Self {
        if sparse {
            self.0 |= FILE_FLAG_SPARSE;
        } else {
            self.0 &= !FILE_FLAG_SPARSE;
        }
        self
    }

    /// True if marked as possessing xattrs.
    pub fn has_xattrs(&self) -> bool {
        (self.0 & FILE_FLAG_HAS_XATTRS) != 0
    }

    /// Set or clear xattrs flag.
    pub fn with_xattrs(mut self, xattrs: bool) -> Self {
        if xattrs {
            self.0 |= FILE_FLAG_HAS_XATTRS;
        } else {
            self.0 &= !FILE_FLAG_HAS_XATTRS;
        }
        self
    }
}

/// Chunk flags (bit 0: hole).
pub const CHUNK_FLAG_HOLE: u64 = 0x01;

/// Flags on an individual chunk descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ChunkFlags(pub u64);

impl ChunkFlags {
    /// Normal chunk.
    pub const fn normal() -> Self {
        Self(0)
    }

    /// Sparse hole chunk.
    pub const fn hole() -> Self {
        Self(CHUNK_FLAG_HOLE)
    }

    /// True if chunk represents a sparse hole without physical bytes.
    pub fn is_hole(&self) -> bool {
        (self.0 & CHUNK_FLAG_HOLE) != 0
    }
}

/// A single chunk descriptor within a file entry (`PROTOCOL.md` §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkDesc {
    /// Chunk flags (e.g. hole).
    pub flags: ChunkFlags,
    /// Chunk length in bytes. Bounded by `MAX_CHUNK_SIZE`.
    pub length: u64,
    /// Chunk BLAKE3 hash. None if `flags.is_hole()` is true.
    pub hash: Option<Hash>,
}

impl ChunkDesc {
    /// Construct a normal chunk descriptor with a known hash.
    pub fn new(length: u64, hash: Hash) -> Self {
        Self {
            flags: ChunkFlags::normal(),
            length,
            hash: Some(hash),
        }
    }

    /// Construct a sparse hole chunk descriptor.
    pub fn hole(length: u64) -> Self {
        Self {
            flags: ChunkFlags::hole(),
            length,
            hash: None,
        }
    }
}

/// A complete file or directory entry in a manifest (`PROTOCOL.md` §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Entry flags (file type, sparse, xattrs).
    pub flags: FileFlags,
    /// Relative, forward-slash normalized virtual path.
    pub path: VPath,
    /// Total file size in bytes (0 for directories).
    pub size: u64,
    /// POSIX file mode bits (permissions).
    pub mode: u32,
    /// Modification time seconds since UNIX epoch.
    pub mtime_sec: i64,
    /// Modification time nanoseconds component.
    pub mtime_nsec: u32,
    /// Whole-file BLAKE3 hash (or ZERO for directories/symlinks).
    pub file_hash: Hash,
    /// Ordered list of chunk descriptors. Offsets are the running sum of lengths.
    pub chunks: Vec<ChunkDesc>,
}

impl FileEntry {
    /// Create a regular file entry.
    pub fn regular(
        path: VPath,
        size: u64,
        mode: u32,
        mtime_sec: i64,
        mtime_nsec: u32,
        file_hash: Hash,
        chunks: Vec<ChunkDesc>,
    ) -> Self {
        Self {
            flags: FileFlags::regular(),
            path,
            size,
            mode,
            mtime_sec,
            mtime_nsec,
            file_hash,
            chunks,
        }
    }

    /// Create a directory entry.
    pub fn directory(
        path: VPath,
        mode: u32,
        mtime_sec: i64,
        mtime_nsec: u32,
    ) -> Self {
        Self {
            flags: FileFlags::directory(),
            path,
            size: 0,
            mode,
            mtime_sec,
            mtime_nsec,
            file_hash: Hash::ZERO,
            chunks: Vec::new(),
        }
    }

    /// Create a symlink entry.
    pub fn symlink(
        path: VPath,
        mode: u32,
        mtime_sec: i64,
        mtime_nsec: u32,
        target_hash: Hash,
    ) -> Self {
        Self {
            flags: FileFlags::symlink(),
            path,
            size: 0,
            mode,
            mtime_sec,
            mtime_nsec,
            file_hash: target_hash,
            chunks: Vec::new(),
        }
    }

    /// Total sum of all chunk lengths in this entry.
    pub fn chunk_length_sum(&self) -> u64 {
        self.chunks.iter().map(|c| c.length).sum()
    }
}

impl fmt::Display for FileEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({} bytes, {} chunks)",
            self.path.as_str(),
            self.size,
            self.chunks.len()
        )
    }
}
