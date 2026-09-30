//! Sparse file extent detection and hole analysis.
//!
//! (`REQUIREMENTS.md` §33; `ARCHITECTURE.md` §6; `STORAGE.md`).
//!
//! Provides safe zero-copy detection of sparse holes, contiguous extent
//! classification, and sparse file creation across platforms without unsafe code.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Logical classification of a contiguous file extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileExtent {
    /// Starting byte offset within the file.
    pub offset: u64,
    /// Byte length of the extent.
    pub length: u64,
    /// True if this extent represents a sparse hole (all zero bytes).
    pub is_hole: bool,
}

impl FileExtent {
    /// Create a new data extent.
    pub const fn data(offset: u64, length: u64) -> Self {
        Self {
            offset,
            length,
            is_hole: false,
        }
    }

    /// Create a new sparse hole extent.
    pub const fn hole(offset: u64, length: u64) -> Self {
        Self {
            offset,
            length,
            is_hole: true,
        }
    }
}

/// Fast constant-memory check if a slice consists entirely of zero bytes.
#[inline]
pub fn is_all_zeros(slice: &[u8]) -> bool {
    is_zero_slice(slice)
}

/// Safe zero-scanning implementation using 64-bit chunks without unsafe code.
#[inline]
pub fn is_zero_slice(slice: &[u8]) -> bool {
    let mut chunks = slice.chunks_exact(8);
    for chunk in chunks.by_ref() {
        let word = u64::from_ne_bytes(chunk.try_into().unwrap());
        if word != 0 {
            return false;
        }
    }
    chunks.remainder().iter().all(|&b| b == 0)
}

/// Detect contiguous data and hole extents in an open reader.
pub fn detect_reader_extents<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    block_size: usize,
) -> std::io::Result<Vec<FileExtent>> {
    if file_size == 0 {
        return Ok(Vec::new());
    }

    reader.seek(SeekFrom::Start(0))?;
    let block_sz = block_size.max(4096);
    let mut buf = vec![0u8; block_sz];
    let mut extents: Vec<FileExtent> = Vec::new();

    let mut current_offset = 0u64;
    while current_offset < file_size {
        let want = (file_size - current_offset).min(block_sz as u64) as usize;
        reader.read_exact(&mut buf[..want])?;

        let is_hole = is_zero_slice(&buf[..want]);

        if let Some(last) = extents.last_mut() {
            if last.is_hole == is_hole {
                last.length += want as u64;
                current_offset += want as u64;
                continue;
            }
        }

        extents.push(FileExtent {
            offset: current_offset,
            length: want as u64,
            is_hole,
        });
        current_offset += want as u64;
    }

    Ok(extents)
}

/// Detect contiguous data and hole extents for a file at `path`.
pub fn detect_file_extents(
    path: &Path,
    file_size: u64,
    block_size: usize,
) -> std::io::Result<Vec<FileExtent>> {
    let mut file = File::open(path)?;
    detect_reader_extents(&mut file, file_size, block_size)
}

/// Create a physical sparse file with a declared logical size.
///
/// Calling `set_len` on newly created files produces sparse files with
/// unallocated blocks on filesystems that support sparseness (ext4, xfs, btrfs, APFS, NTFS).
pub fn create_sparse_file(path: &Path, logical_size: u64) -> std::io::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.set_len(logical_size)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_is_zero_slice() {
        assert!(is_zero_slice(&[]));
        assert!(is_zero_slice(&[0u8; 1024]));
        let mut mixed = vec![0u8; 1024];
        mixed[512] = 1;
        assert!(!is_zero_slice(&mixed));
        mixed[512] = 0;
        mixed[1023] = 0xFF;
        assert!(!is_zero_slice(&mixed));
    }

    #[test]
    fn test_detect_extents_interleaved() {
        let td = tempdir().unwrap();
        let path = td.path().join("sparse_test.bin");
        {
            let mut f = File::create(&path).unwrap();
            // 64 KiB data
            f.write_all(&vec![0xAA; 64 * 1024]).unwrap();
            // 128 KiB hole (zeros)
            f.write_all(&vec![0x00; 128 * 1024]).unwrap();
            // 64 KiB data
            f.write_all(&vec![0xBB; 64 * 1024]).unwrap();
        }

        let total_size = (64 + 128 + 64) * 1024;
        let extents = detect_file_extents(&path, total_size, 32 * 1024).unwrap();

        assert_eq!(extents.len(), 3);
        assert_eq!(extents[0], FileExtent::data(0, 64 * 1024));
        assert_eq!(extents[1], FileExtent::hole(64 * 1024, 128 * 1024));
        assert_eq!(extents[2], FileExtent::data(192 * 1024, 64 * 1024));
    }

    #[test]
    fn test_create_sparse_file() {
        let td = tempdir().unwrap();
        let path = td.path().join("sparse_created.bin");
        let logical_size = 10 * 1024 * 1024; // 10 MiB
        let f = create_sparse_file(&path, logical_size).unwrap();
        let meta = f.metadata().unwrap();
        assert_eq!(meta.len(), logical_size);
    }
}
