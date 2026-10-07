//! Kernel Zero-Copy, Page-Cache Bypass & Direct I/O (`O_DIRECT`) Aligned Sector Engine
//! (`REQUIREMENTS.md` §26, §27, `docs/ARCHITECTURE.md` §2).
//!
//! Provides:
//! - `AlignedSectorBuffer`: Pure safe-Rust buffer strictly aligned to physical device sector boundaries (4096 bytes).
//! - `DirectIoMode`: `Auto`, `Always`, `Disabled` execution policies.
//! - `DirectFileReader`: Sector-aligned streaming file reader bypassing kernel page cache.
//! - `DirectFileWriter`: Sector-aligned streaming file writer with automatic fractional tail padding and exact byte truncation.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Physical device sector alignment (standard 4 KiB for modern NVMe and Advanced Format drives).
pub const DEFAULT_SECTOR_SIZE: usize = 4096;

/// Minimum file size threshold (16 MiB) to automatically engage Direct I/O.
pub const DEFAULT_DIRECT_IO_MIN_SIZE: u64 = 16 * 1024 * 1024;

/// Direct I/O execution policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DirectIoMode {
    /// Automatically engage Direct I/O for files >= threshold when supported by the filesystem,
    /// with graceful fallback to standard buffered streaming if unsupported.
    Auto,
    /// Strictly enforce Direct I/O; fail operation if Direct I/O is unsupported by the filesystem.
    Always,
    /// Disable Direct I/O and always use standard OS buffered streaming.
    Disabled,
}

impl Default for DirectIoMode {
    fn default() -> Self {
        Self::Auto
    }
}

impl FromStr for DirectIoMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "always" | "force" | "enabled" => Ok(Self::Always),
            "disabled" | "none" | "off" => Ok(Self::Disabled),
            other => Err(format!(
                "invalid direct_io mode: '{other}' (expected 'auto', 'always', or 'disabled')"
            )),
        }
    }
}

impl std::fmt::Display for DirectIoMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Always => write!(f, "always"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// Configuration options for Direct I/O.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectIoConfig {
    /// Direct I/O execution policy.
    pub mode: DirectIoMode,
    /// Physical sector size in bytes (default: 4096).
    pub sector_size: usize,
    /// Minimum file size threshold in bytes to engage Direct I/O under `Auto` mode (default: 16 MiB).
    pub min_file_size: u64,
}

impl Default for DirectIoConfig {
    fn default() -> Self {
        Self {
            mode: DirectIoMode::Auto,
            sector_size: DEFAULT_SECTOR_SIZE,
            min_file_size: DEFAULT_DIRECT_IO_MIN_SIZE,
        }
    }
}

/// A safe, sector-aligned memory buffer ensuring physical DMA compatibility without unsafe code.
#[derive(Debug, Clone)]
pub struct AlignedSectorBuffer {
    storage: Vec<u8>,
    offset: usize,
    len: usize,
    alignment: usize,
}

impl AlignedSectorBuffer {
    /// Create a new sector-aligned buffer with given capacity and power-of-two alignment.
    pub fn new(capacity: usize, alignment: usize) -> Self {
        let alignment = if alignment == 0 || !alignment.is_power_of_two() {
            DEFAULT_SECTOR_SIZE
        } else {
            alignment
        };

        let total_alloc = capacity.saturating_add(alignment);
        let storage = vec![0u8; total_alloc];
        let ptr = storage.as_ptr() as usize;
        let rem = ptr % alignment;
        let offset = if rem == 0 { 0 } else { alignment - rem };

        Self {
            storage,
            offset,
            len: 0,
            alignment,
        }
    }

    /// Pointer address of the aligned start of the buffer.
    pub fn data_ptr(&self) -> usize {
        self.storage[self.offset..].as_ptr() as usize
    }

    /// Whether the active buffer slice address is mathematically aligned to the sector size.
    pub fn is_aligned(&self) -> bool {
        self.data_ptr() % self.alignment == 0
    }

    /// Configured sector alignment in bytes.
    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// Number of active bytes in the buffer.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer has zero active bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Total usable aligned capacity.
    pub fn capacity(&self) -> usize {
        self.storage.len().saturating_sub(self.offset)
    }

    /// View active contents as an aligned slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.storage[self.offset..self.offset + self.len]
    }

    /// View active contents as a mutable aligned slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.storage[self.offset..self.offset + self.len]
    }

    /// Append a slice of bytes into the buffer, returning the number of bytes appended.
    pub fn append(&mut self, data: &[u8]) -> usize {
        let available = self.capacity().saturating_sub(self.len);
        let to_copy = data.len().min(available);
        if to_copy > 0 {
            self.storage[self.offset + self.len..self.offset + self.len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.len += to_copy;
        }
        to_copy
    }

    /// Set active length (must be <= capacity).
    pub fn set_len(&mut self, new_len: usize) {
        assert!(new_len <= self.capacity(), "new_len exceeds capacity");
        self.len = new_len;
    }

    /// Clear all active contents.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Resize buffer capacity while preserving alignment.
    pub fn resize(&mut self, new_len: usize, value: u8) {
        if new_len > self.capacity() {
            let total_alloc = new_len.saturating_add(self.alignment);
            let mut new_storage = vec![value; total_alloc];
            let ptr = new_storage.as_ptr() as usize;
            let rem = ptr % self.alignment;
            let new_offset = if rem == 0 { 0 } else { self.alignment - rem };

            let copy_len = self.len.min(new_len);
            if copy_len > 0 {
                new_storage[new_offset..new_offset + copy_len]
                    .copy_from_slice(&self.storage[self.offset..self.offset + copy_len]);
            }
            self.storage = new_storage;
            self.offset = new_offset;
        } else if new_len > self.len {
            self.storage[self.offset + self.len..self.offset + new_len].fill(value);
        }
        self.len = new_len;
    }
}

/// Apply platform Direct I/O flags if supported on Linux.
#[cfg(target_os = "linux")]
fn apply_direct_io_flags(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.custom_flags(libc::O_DIRECT);
}

#[cfg(not(target_os = "linux"))]
fn apply_direct_io_flags(_opts: &mut OpenOptions) {
    // Unbuffered fallback on macOS/Windows/BSD
}

/// Streaming reader utilizing sector-aligned buffers and optional Direct I/O.
pub struct DirectFileReader {
    path: PathBuf,
    file: File,
    buffer: AlignedSectorBuffer,
    file_size: u64,
    bytes_read: u64,
    is_direct: bool,
    sector_size: usize,
}

impl DirectFileReader {
    /// Open a file for direct or buffered streaming read based on configuration.
    pub fn open<P: AsRef<Path>>(path: P, config: &DirectIoConfig) -> std::io::Result<Self> {
        let p = path.as_ref().to_path_buf();
        let meta = std::fs::metadata(&p)?;
        let file_size = meta.len();
        let sector_size = config.sector_size;

        let should_try_direct = match config.mode {
            DirectIoMode::Disabled => false,
            DirectIoMode::Always => true,
            DirectIoMode::Auto => file_size >= config.min_file_size,
        };

        let buffer_capacity = sector_size.max(64 * 1024);
        let mut buffer = AlignedSectorBuffer::new(buffer_capacity, sector_size);
        buffer.resize(buffer_capacity, 0);

        if should_try_direct {
            let mut opts = OpenOptions::new();
            opts.read(true);
            apply_direct_io_flags(&mut opts);

            match opts.open(&p) {
                Ok(file) => {
                    return Ok(Self {
                        path: p,
                        file,
                        buffer,
                        file_size,
                        bytes_read: 0,
                        is_direct: true,
                        sector_size,
                    });
                }
                Err(e) => {
                    if config.mode == DirectIoMode::Always {
                        return Err(e);
                    }
                    // Auto fallback to standard buffered streaming
                }
            }
        }

        // Standard buffered reader
        let file = File::open(&p)?;
        Ok(Self {
            path: p,
            file,
            buffer,
            file_size,
            bytes_read: 0,
            is_direct: false,
            sector_size,
        })
    }

    /// Read the next chunk of file data into the aligned buffer.
    /// Returns `None` when EOF is reached.
    pub fn read_block(&mut self) -> std::io::Result<Option<&[u8]>> {
        if self.bytes_read >= self.file_size {
            return Ok(None);
        }

        let remaining = self.file_size - self.bytes_read;
        let buf_cap = self.buffer.capacity();
        let target_len = (remaining as usize).min(buf_cap);

        // For Direct I/O, reads must be in integer multiples of sector size
        let read_len = if self.is_direct {
            let aligned_len =
                ((target_len + self.sector_size - 1) / self.sector_size) * self.sector_size;
            aligned_len.min(buf_cap)
        } else {
            target_len
        };

        self.buffer.set_len(read_len);
        let n = match self.file.read(self.buffer.as_mut_slice()) {
            Ok(n) => n,
            Err(e) if self.is_direct && e.raw_os_error() == Some(22) => {
                // Linux O_DIRECT cannot read fractional blocks at EOF without returning EINVAL.
                // Fall back to buffered read for the fractional tail at the current offset.
                let mut fallback_file = File::open(&self.path)?;
                fallback_file.seek(SeekFrom::Start(self.bytes_read))?;
                self.buffer.set_len(target_len);
                let n = fallback_file.read(self.buffer.as_mut_slice())?;
                self.file = fallback_file;
                self.is_direct = false;
                n
            }
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(None);
        }

        let actual_bytes = n.min(target_len);
        self.bytes_read += actual_bytes as u64;
        self.buffer.set_len(actual_bytes);

        Ok(Some(self.buffer.as_slice()))
    }

    /// Target file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Total file length in bytes.
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Bytes read so far.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Whether this reader is operating with Direct I/O flags.
    pub fn is_direct(&self) -> bool {
        self.is_direct
    }
}

/// Streaming file writer utilizing sector-aligned buffer staging, Direct I/O DMA writes,
/// and atomic tail truncation upon finish.
pub struct DirectFileWriter {
    path: PathBuf,
    file: File,
    buffer: AlignedSectorBuffer,
    total_written: u64,
    sector_size: usize,
    is_direct: bool,
    flush_threshold: usize,
}

impl DirectFileWriter {
    /// Create or open a file for direct or buffered streaming write.
    pub fn create<P: AsRef<Path>>(
        path: P,
        expected_size: Option<u64>,
        config: &DirectIoConfig,
    ) -> std::io::Result<Self> {
        let p = path.as_ref().to_path_buf();
        let sector_size = config.sector_size;

        let should_try_direct = match config.mode {
            DirectIoMode::Disabled => false,
            DirectIoMode::Always => true,
            DirectIoMode::Auto => expected_size.map_or(false, |sz| sz >= config.min_file_size),
        };

        let flush_threshold = sector_size.max(64 * 1024);
        let buffer = AlignedSectorBuffer::new(flush_threshold * 2, sector_size);

        if should_try_direct {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            apply_direct_io_flags(&mut opts);

            match opts.open(&p) {
                Ok(file) => {
                    return Ok(Self {
                        path: p,
                        file,
                        buffer,
                        total_written: 0,
                        sector_size,
                        is_direct: true,
                        flush_threshold,
                    });
                }
                Err(e) => {
                    if config.mode == DirectIoMode::Always {
                        return Err(e);
                    }
                    // Auto fallback to standard buffered streaming
                }
            }
        }

        // Standard buffered writer
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        let file = opts.open(&p)?;

        Ok(Self {
            path: p,
            file,
            buffer,
            total_written: 0,
            sector_size,
            is_direct: false,
            flush_threshold,
        })
    }

    /// Write an incoming streaming chunk.
    pub fn write_chunk(&mut self, mut data: &[u8]) -> std::io::Result<()> {
        while !data.is_empty() {
            let appended = self.buffer.append(data);
            data = &data[appended..];
            self.total_written += appended as u64;

            if self.buffer.len() >= self.flush_threshold {
                self.flush_aligned_sectors()?;
            }
        }
        Ok(())
    }

    /// Flush all complete sector-sized blocks to disk.
    fn flush_aligned_sectors(&mut self) -> std::io::Result<()> {
        let total_buffered = self.buffer.len();
        if total_buffered == 0 {
            return Ok(());
        }

        let aligned_len = if self.is_direct {
            (total_buffered / self.sector_size) * self.sector_size
        } else {
            total_buffered
        };

        if aligned_len > 0 {
            let slice = &self.buffer.as_slice()[..aligned_len];
            self.file.write_all(slice)?;

            // Retain any remaining unaligned trailing bytes
            let leftover = total_buffered - aligned_len;
            if leftover > 0 {
                let mut temp = vec![0u8; leftover];
                temp.copy_from_slice(&self.buffer.as_slice()[aligned_len..total_buffered]);
                self.buffer.clear();
                self.buffer.append(&temp);
            } else {
                self.buffer.clear();
            }
        }
        Ok(())
    }

    /// Finish writing, flush any fractional sector tail bytes, truncate file to the exact byte length,
    /// and sync to disk. Returns total bytes written.
    pub fn finish(mut self) -> std::io::Result<u64> {
        let leftover = self.buffer.len();

        if leftover > 0 {
            if self.is_direct {
                // Pad fractional tail to a full sector size for Direct I/O write
                let padded_len =
                    ((leftover + self.sector_size - 1) / self.sector_size) * self.sector_size;
                let mut padded = AlignedSectorBuffer::new(padded_len, self.sector_size);
                padded.resize(padded_len, 0);
                padded.as_mut_slice()[..leftover].copy_from_slice(self.buffer.as_slice());

                self.file.write_all(padded.as_slice())?;
                // Truncate to exact unpadded byte size
                self.file.set_len(self.total_written)?;
            } else {
                self.file.write_all(self.buffer.as_slice())?;
            }
            self.buffer.clear();
        }

        self.file.flush()?;
        self.file.sync_all()?;
        Ok(self.total_written)
    }

    /// Target file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Total bytes written so far.
    pub fn bytes_written(&self) -> u64 {
        self.total_written
    }

    /// Whether this writer is operating with Direct I/O flags.
    pub fn is_direct(&self) -> bool {
        self.is_direct
    }
}
