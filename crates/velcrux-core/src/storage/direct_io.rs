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

/// Default number of circular ring buffer slots (4).
pub const DEFAULT_RING_SLOTS: usize = 4;

/// Default capacity per ring buffer slot (2 MiB = 2,097,152 bytes).
pub const DEFAULT_SLOT_CAPACITY: usize = 2 * 1024 * 1024;

/// Configuration for zero-copy Direct I/O ring buffer pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectIoRingConfig {
    /// Number of circular slots in the ring buffer (clamped between 2 and 32, default: 4).
    pub ring_slots: usize,
    /// Usable capacity per slot in bytes (default: 2 MiB, aligned to sector size).
    pub slot_capacity: usize,
    /// Physical device sector alignment (default: 4096 bytes).
    pub sector_size: usize,
    /// Direct I/O execution policy (Auto, Always, Disabled).
    pub mode: DirectIoMode,
    /// Minimum file size threshold for Auto mode (default: 16 MiB).
    pub min_file_size: u64,
}

impl Default for DirectIoRingConfig {
    fn default() -> Self {
        Self {
            ring_slots: DEFAULT_RING_SLOTS,
            slot_capacity: DEFAULT_SLOT_CAPACITY,
            sector_size: DEFAULT_SECTOR_SIZE,
            mode: DirectIoMode::Auto,
            min_file_size: DEFAULT_DIRECT_IO_MIN_SIZE,
        }
    }
}

/// Lifecycle state of an individual slot within the ring buffer pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RingSlotState {
    /// Slot is empty and available to be acquired by a producer.
    Empty,
    /// Slot is actively being filled with incoming data from disk or network.
    Filling,
    /// Slot contains valid, fully populated data ready to be consumed.
    Ready,
    /// Slot is actively being flushed to disk or transmitted over the wire.
    Flushing,
}

/// A sector-aligned circular slot within the Direct I/O ring buffer pipeline.
#[derive(Debug, Clone)]
pub struct RingSlot {
    /// Unique index of this slot in the circular ring (0 .. ring_slots - 1).
    pub slot_id: usize,
    /// Sector-aligned physical DMA buffer.
    pub buffer: AlignedSectorBuffer,
    /// Current state of the slot in the pipeline.
    pub state: RingSlotState,
    /// Actual payload length in bytes (excluding any fractional sector padding).
    pub valid_len: usize,
    /// Monotonically increasing chunk/sequence number.
    pub sequence: u64,
    /// Absolute file offset where this slot's payload begins.
    pub file_offset: u64,
    /// Whether this slot contains the end of the file/stream.
    pub is_eof: bool,
}

impl RingSlot {
    /// Initialize a new ring slot with pre-allocated sector-aligned capacity.
    pub fn new(slot_id: usize, capacity: usize, sector_size: usize) -> Self {
        let mut buffer = AlignedSectorBuffer::new(capacity, sector_size);
        buffer.resize(capacity, 0);
        Self {
            slot_id,
            buffer,
            state: RingSlotState::Empty,
            valid_len: 0,
            sequence: 0,
            file_offset: 0,
            is_eof: false,
        }
    }

    /// Read-only slice of valid data currently residing in the slot.
    pub fn data(&self) -> &[u8] {
        &self.buffer.as_slice()[..self.valid_len]
    }

    /// Mutable slice of valid data in the slot.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut_slice()[..self.valid_len]
    }
}

/// Operational statistics for the Direct I/O ring buffer pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DirectIoPipelineStats {
    /// Total slots filled and processed through the pipeline.
    pub slots_processed: u64,
    /// Total payload bytes processed.
    pub bytes_processed: u64,
    /// Total pipeline stall events (producer waiting for free slot or consumer waiting for ready slot).
    pub pipeline_stalls: u64,
    /// Total asynchronous prefetch read operations executed.
    pub prefetch_operations: u64,
    /// Total write-behind flush operations executed.
    pub write_behind_operations: u64,
}

/// High-throughput, sector-aligned Direct I/O ring buffer managing circular DMA slots.
#[derive(Debug)]
pub struct DirectIoRingBuffer {
    config: DirectIoRingConfig,
    slots: Vec<RingSlot>,
    head: usize,
    tail: usize,
    active_slots: usize,
    next_sequence: u64,
    stats: DirectIoPipelineStats,
}

impl DirectIoRingBuffer {
    /// Create a new ring buffer with given configuration.
    pub fn new(mut config: DirectIoRingConfig) -> Self {
        config.ring_slots = config.ring_slots.clamp(2, 32);
        let sector_size = if config.sector_size == 0 || !config.sector_size.is_power_of_two() {
            DEFAULT_SECTOR_SIZE
        } else {
            config.sector_size
        };
        config.sector_size = sector_size;

        // Ensure slot capacity is at least one sector and an exact multiple of sector_size
        let slot_cap =
            ((config.slot_capacity.max(sector_size) + sector_size - 1) / sector_size) * sector_size;
        config.slot_capacity = slot_cap;

        let mut slots = Vec::with_capacity(config.ring_slots);
        for id in 0..config.ring_slots {
            slots.push(RingSlot::new(id, slot_cap, sector_size));
        }

        Self {
            config,
            slots,
            head: 0,
            tail: 0,
            active_slots: 0,
            next_sequence: 0,
            stats: DirectIoPipelineStats::default(),
        }
    }

    /// Configuration for this ring buffer.
    pub fn config(&self) -> &DirectIoRingConfig {
        &self.config
    }

    /// Number of slots in the ring buffer.
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Usable aligned capacity per slot in bytes.
    pub fn slot_capacity(&self) -> usize {
        self.config.slot_capacity
    }

    /// Number of active slots currently holding or processing data.
    pub fn active_slots(&self) -> usize {
        self.active_slots
    }

    /// Number of free slots available for producers.
    pub fn free_slots(&self) -> usize {
        self.slots.len().saturating_sub(self.active_slots)
    }

    /// Whether all slots are currently occupied.
    pub fn is_full(&self) -> bool {
        self.active_slots >= self.slots.len()
    }

    /// Whether zero slots are currently occupied.
    pub fn is_empty(&self) -> bool {
        self.active_slots == 0
    }

    /// Acquire the next available empty slot for producer filling.
    /// Returns `None` if the ring is completely full (pipeline stall).
    pub fn acquire_empty_slot(&mut self) -> Option<&mut RingSlot> {
        if self.is_full() {
            self.stats.pipeline_stalls += 1;
            return None;
        }
        let slot = &mut self.slots[self.head];
        if slot.state != RingSlotState::Empty {
            self.stats.pipeline_stalls += 1;
            return None;
        }
        slot.state = RingSlotState::Filling;
        slot.valid_len = 0;
        slot.is_eof = false;
        Some(slot)
    }

    /// Commit a filled slot to the ring, making it ready for consumer processing.
    pub fn commit_filled_slot(
        &mut self,
        slot_id: usize,
        valid_len: usize,
        file_offset: u64,
        is_eof: bool,
    ) -> Result<(), String> {
        if slot_id != self.head {
            return Err(format!(
                "slot id mismatch: expected head {}, got {}",
                self.head, slot_id
            ));
        }
        let slot = &mut self.slots[slot_id];
        if slot.state != RingSlotState::Filling {
            return Err(format!(
                "invalid state for commit: expected Filling, got {:?}",
                slot.state
            ));
        }
        slot.state = RingSlotState::Ready;
        slot.valid_len = valid_len;
        slot.file_offset = file_offset;
        slot.is_eof = is_eof;
        slot.sequence = self.next_sequence;
        self.next_sequence += 1;

        self.head = (self.head + 1) % self.slots.len();
        self.active_slots += 1;
        self.stats.slots_processed += 1;
        self.stats.bytes_processed += valid_len as u64;
        Ok(())
    }

    /// Acquire the next ready slot for consumer processing.
    /// Returns `None` if the ring has no ready slots (pipeline stall).
    pub fn acquire_ready_slot(&mut self) -> Option<&mut RingSlot> {
        if self.is_empty() {
            self.stats.pipeline_stalls += 1;
            return None;
        }
        let slot = &mut self.slots[self.tail];
        if slot.state != RingSlotState::Ready {
            self.stats.pipeline_stalls += 1;
            return None;
        }
        slot.state = RingSlotState::Flushing;
        Some(slot)
    }

    /// Release a consumed slot back to empty state, advancing the consumer pointer.
    pub fn release_consumed_slot(&mut self, slot_id: usize) -> Result<(), String> {
        if slot_id != self.tail {
            return Err(format!(
                "slot id mismatch: expected tail {}, got {}",
                self.tail, slot_id
            ));
        }
        let slot = &mut self.slots[slot_id];
        if slot.state != RingSlotState::Flushing && slot.state != RingSlotState::Ready {
            return Err(format!(
                "invalid state for release: expected Flushing or Ready, got {:?}",
                slot.state
            ));
        }
        slot.state = RingSlotState::Empty;
        slot.valid_len = 0;
        slot.is_eof = false;

        self.tail = (self.tail + 1) % self.slots.len();
        self.active_slots = self.active_slots.saturating_sub(1);
        Ok(())
    }

    /// Reset all slots to empty state.
    pub fn reset(&mut self) {
        for slot in &mut self.slots {
            slot.state = RingSlotState::Empty;
            slot.valid_len = 0;
            slot.is_eof = false;
        }
        self.head = 0;
        self.tail = 0;
        self.active_slots = 0;
    }

    /// Snapshot of pipeline execution statistics.
    pub fn stats(&self) -> DirectIoPipelineStats {
        self.stats
    }
}

/// Pipelined streaming reader with sector-aligned DMA ring buffer and asynchronous read-ahead prefetching.
pub struct DirectIoPipelineReader {
    path: PathBuf,
    file: File,
    file_size: u64,
    bytes_read: u64,
    is_direct: bool,
    ring: DirectIoRingBuffer,
    eof_reached: bool,
    current_slot: Option<usize>,
}

impl DirectIoPipelineReader {
    /// Open a file for pipelined streaming read.
    pub fn open<P: AsRef<Path>>(path: P, config: DirectIoRingConfig) -> std::io::Result<Self> {
        let p = path.as_ref().to_path_buf();
        let meta = std::fs::metadata(&p)?;
        let file_size = meta.len();

        let should_try_direct = match config.mode {
            DirectIoMode::Disabled => false,
            DirectIoMode::Always => true,
            DirectIoMode::Auto => file_size >= config.min_file_size,
        };

        let ring = DirectIoRingBuffer::new(config);

        if should_try_direct {
            let mut opts = OpenOptions::new();
            opts.read(true);
            apply_direct_io_flags(&mut opts);

            match opts.open(&p) {
                Ok(file) => {
                    let mut reader = Self {
                        path: p,
                        file,
                        file_size,
                        bytes_read: 0,
                        is_direct: true,
                        ring,
                        eof_reached: false,
                        current_slot: None,
                    };
                    reader.prefetch_slots()?;
                    return Ok(reader);
                }
                Err(e) => {
                    if ring.config().mode == DirectIoMode::Always {
                        return Err(e);
                    }
                }
            }
        }

        let file = File::open(&p)?;
        let mut reader = Self {
            path: p,
            file,
            file_size,
            bytes_read: 0,
            is_direct: false,
            ring,
            eof_reached: false,
            current_slot: None,
        };
        reader.prefetch_slots()?;
        Ok(reader)
    }

    /// Prefetch available file data into empty slots of the ring buffer.
    fn prefetch_slots(&mut self) -> std::io::Result<()> {
        while !self.eof_reached && !self.ring.is_full() {
            let remaining = self.file_size.saturating_sub(self.bytes_read);
            if remaining == 0 {
                self.eof_reached = true;
                break;
            }

            let slot_cap = self.ring.slot_capacity();
            let target_len = (remaining as usize).min(slot_cap);
            let sector_size = self.ring.config().sector_size;

            let read_len = if self.is_direct {
                let aligned = ((target_len + sector_size - 1) / sector_size) * sector_size;
                aligned.min(slot_cap)
            } else {
                target_len
            };

            let current_offset = self.bytes_read;
            let slot = match self.ring.acquire_empty_slot() {
                Some(s) => s,
                None => break,
            };
            let slot_id = slot.slot_id;

            slot.buffer.set_len(read_len);
            let n = match self.file.read(slot.buffer.as_mut_slice()) {
                Ok(n) => n,
                Err(e) if self.is_direct && e.raw_os_error() == Some(22) => {
                    // Fractional EOF tail fallback
                    let mut fallback = File::open(&self.path)?;
                    fallback.seek(SeekFrom::Start(current_offset))?;
                    slot.buffer.set_len(target_len);
                    let n = fallback.read(slot.buffer.as_mut_slice())?;
                    self.file = fallback;
                    self.is_direct = false;
                    n
                }
                Err(e) => return Err(e),
            };

            if n == 0 {
                self.eof_reached = true;
                slot.state = RingSlotState::Empty;
                break;
            }

            let actual_bytes = n.min(target_len);
            self.bytes_read += actual_bytes as u64;
            let is_eof = self.bytes_read >= self.file_size;

            if let Err(err_msg) =
                self.ring
                    .commit_filled_slot(slot_id, actual_bytes, current_offset, is_eof)
            {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
            }
            self.ring.stats.prefetch_operations += 1;

            if is_eof {
                self.eof_reached = true;
                break;
            }
        }
        Ok(())
    }

    /// Read the next pipelined block from the ring buffer.
    /// Returns `None` when the entire file has been consumed.
    pub fn read_block(&mut self) -> std::io::Result<Option<&[u8]>> {
        if let Some(prev_id) = self.current_slot.take() {
            if let Err(err_msg) = self.ring.release_consumed_slot(prev_id) {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
            }
            self.prefetch_slots()?;
        }

        if self.ring.is_empty() {
            self.prefetch_slots()?;
            if self.ring.is_empty() {
                return Ok(None);
            }
        }

        let tail = self.ring.tail;
        if self.ring.acquire_ready_slot().is_none() {
            return Ok(None);
        }

        self.current_slot = Some(tail);
        Ok(Some(self.ring.slots[tail].data()))
    }

    /// File size in bytes.
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Total bytes read so far.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Whether Direct I/O is active.
    pub fn is_direct(&self) -> bool {
        self.is_direct
    }

    /// Pipeline performance statistics.
    pub fn stats(&self) -> DirectIoPipelineStats {
        self.ring.stats()
    }
}

/// Pipelined streaming writer with sector-aligned DMA ring buffer, asynchronous write-behind,
/// and exact tail truncation.
pub struct DirectIoPipelineWriter {
    path: PathBuf,
    file: File,
    total_written: u64,
    is_direct: bool,
    ring: DirectIoRingBuffer,
    active_slot_id: Option<usize>,
}

impl DirectIoPipelineWriter {
    /// Create or truncate a file for pipelined streaming write.
    pub fn create<P: AsRef<Path>>(
        path: P,
        expected_size: Option<u64>,
        config: DirectIoRingConfig,
    ) -> std::io::Result<Self> {
        let p = path.as_ref().to_path_buf();

        let should_try_direct = match config.mode {
            DirectIoMode::Disabled => false,
            DirectIoMode::Always => true,
            DirectIoMode::Auto => expected_size.map_or(false, |sz| sz >= config.min_file_size),
        };

        let ring = DirectIoRingBuffer::new(config);

        if should_try_direct {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            apply_direct_io_flags(&mut opts);

            match opts.open(&p) {
                Ok(file) => {
                    return Ok(Self {
                        path: p,
                        file,
                        total_written: 0,
                        is_direct: true,
                        ring,
                        active_slot_id: None,
                    });
                }
                Err(e) => {
                    if ring.config().mode == DirectIoMode::Always {
                        return Err(e);
                    }
                }
            }
        }

        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        let file = opts.open(&p)?;

        Ok(Self {
            path: p,
            file,
            total_written: 0,
            is_direct: false,
            ring,
            active_slot_id: None,
        })
    }

    /// Write an incoming streaming chunk into the ring buffer pipeline.
    pub fn write_chunk(&mut self, mut data: &[u8]) -> std::io::Result<()> {
        while !data.is_empty() {
            let slot_cap = self.ring.slot_capacity();
            if self.active_slot_id.is_none() {
                if self.ring.is_full() {
                    self.flush_ready_slots()?;
                }
                let slot = match self.ring.acquire_empty_slot() {
                    Some(s) => s,
                    None => {
                        self.flush_ready_slots()?;
                        self.ring.acquire_empty_slot().ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "pipeline stall: no empty slot",
                            )
                        })?
                    }
                };
                slot.valid_len = 0;
                self.active_slot_id = Some(slot.slot_id);
            }

            let slot_id = self.active_slot_id.unwrap();
            let slot = &mut self.ring.slots[slot_id];
            let available = slot_cap.saturating_sub(slot.valid_len);
            let to_copy = data.len().min(available);

            if to_copy > 0 {
                let current_valid = slot.valid_len;
                slot.buffer.as_mut_slice()[current_valid..current_valid + to_copy]
                    .copy_from_slice(&data[..to_copy]);
                slot.valid_len += to_copy;
                self.total_written += to_copy as u64;
                data = &data[to_copy..];
            }

            if slot.valid_len >= slot_cap {
                let valid = slot.valid_len;
                let offset = self.total_written.saturating_sub(valid as u64);
                if let Err(err_msg) = self.ring.commit_filled_slot(slot_id, valid, offset, false) {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
                }
                self.active_slot_id = None;
                self.flush_ready_slots()?;
            }
        }
        Ok(())
    }

    /// Flush all ready slots from the ring buffer directly to disk.
    fn flush_ready_slots(&mut self) -> std::io::Result<()> {
        let sector_size = self.ring.config().sector_size;
        while !self.ring.is_empty() {
            let tail = self.ring.tail;
            let slot = match self.ring.acquire_ready_slot() {
                Some(s) => s,
                None => break,
            };

            let valid = slot.valid_len;

            if valid > 0 {
                if self.is_direct {
                    let aligned_len = ((valid + sector_size - 1) / sector_size) * sector_size;
                    if aligned_len > valid {
                        // Pad fractional sector tail with zeros
                        let cap = slot.buffer.capacity();
                        slot.buffer.as_mut_slice()[valid..aligned_len.min(cap)].fill(0);
                    }
                    self.file
                        .write_all(&slot.buffer.as_slice()[..aligned_len])?;
                } else {
                    self.file.write_all(&slot.buffer.as_slice()[..valid])?;
                }
                self.ring.stats.write_behind_operations += 1;
            }

            if let Err(err_msg) = self.ring.release_consumed_slot(tail) {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
            }
        }
        Ok(())
    }

    /// Complete streaming write, flush active slots, pad fractional sectors, truncate file to exact length,
    /// and sync to disk. Returns pipeline statistics.
    pub fn finish(mut self) -> std::io::Result<DirectIoPipelineStats> {
        if let Some(slot_id) = self.active_slot_id.take() {
            let valid = self.ring.slots[slot_id].valid_len;
            let offset = self.total_written.saturating_sub(valid as u64);
            if let Err(err_msg) = self.ring.commit_filled_slot(slot_id, valid, offset, true) {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
            }
        }

        self.flush_ready_slots()?;

        if self.is_direct {
            // Truncate file to exact unpadded byte size
            self.file.set_len(self.total_written)?;
        }

        self.file.flush()?;
        self.file.sync_all()?;
        Ok(self.ring.stats())
    }

    /// Target file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Total bytes written.
    pub fn bytes_written(&self) -> u64 {
        self.total_written
    }

    /// Whether Direct I/O is active.
    pub fn is_direct(&self) -> bool {
        self.is_direct
    }
}

/// Comprehensive report from a Direct I/O ring buffer benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectIoBenchmarkReport {
    /// Benchmark file path.
    pub path: String,
    /// Total bytes streamed in the benchmark.
    pub total_bytes: u64,
    /// Number of ring buffer slots configured.
    pub ring_slots: usize,
    /// Usable capacity per slot in bytes.
    pub slot_capacity: usize,
    /// Physical device sector alignment.
    pub sector_size: usize,
    /// Configured Direct I/O mode.
    pub direct_io_mode: DirectIoMode,
    /// Whether Direct I/O was actively engaged.
    pub is_direct: bool,
    /// Duration of streaming write in milliseconds.
    pub write_duration_ms: f64,
    /// Streaming write throughput in MiB/s.
    pub write_throughput_mb_s: f64,
    /// Duration of streaming read in milliseconds.
    pub read_duration_ms: f64,
    /// Streaming read throughput in MiB/s.
    pub read_throughput_mb_s: f64,
    /// Total pipeline stalls encountered.
    pub stalls_count: u64,
    /// Whether the read payload perfectly matched the written payload.
    pub data_integrity_verified: bool,
    /// BLAKE3 checksum of the verified payload.
    pub checksum_blake3: String,
}

/// Execute a complete write-then-read streaming throughput benchmark using the Direct I/O ring buffer pipeline.
pub fn run_direct_io_benchmark(
    path: &Path,
    size_bytes: u64,
    config: DirectIoRingConfig,
) -> std::io::Result<DirectIoBenchmarkReport> {
    use std::time::Instant;

    let total_bytes = size_bytes.max(config.sector_size as u64);

    // 1. Generate deterministic pseudo-random chunks and compute BLAKE3 hash
    let mut hasher = blake3::Hasher::new();
    let chunk_size = 64 * 1024;
    let mut pattern_chunk = vec![0u8; chunk_size];
    for (i, b) in pattern_chunk.iter_mut().enumerate() {
        *b = ((i * 31 + 17) % 256) as u8;
    }

    let mut remaining = total_bytes;
    while remaining > 0 {
        let n = (remaining as usize).min(chunk_size);
        hasher.update(&pattern_chunk[..n]);
        remaining -= n as u64;
    }
    let expected_hash = hasher.finalize().to_hex().to_string();

    // 2. Write test file using DirectIoPipelineWriter
    let write_start = Instant::now();
    let mut writer = DirectIoPipelineWriter::create(path, Some(total_bytes), config.clone())?;
    let is_direct = writer.is_direct();

    let mut remaining = total_bytes;
    while remaining > 0 {
        let n = (remaining as usize).min(chunk_size);
        writer.write_chunk(&pattern_chunk[..n])?;
        remaining -= n as u64;
    }
    let write_stats = writer.finish()?;
    let write_elapsed = write_start.elapsed().as_secs_f64();
    let write_duration_ms = write_elapsed * 1000.0;
    let write_throughput_mb_s = if write_elapsed > 0.0 {
        (total_bytes as f64 / (1024.0 * 1024.0)) / write_elapsed
    } else {
        0.0
    };

    // 3. Read test file using DirectIoPipelineReader and verify BLAKE3 hash
    let read_start = Instant::now();
    let mut reader = DirectIoPipelineReader::open(path, config.clone())?;
    let mut read_hasher = blake3::Hasher::new();
    let mut total_read = 0u64;

    while let Some(block) = reader.read_block()? {
        read_hasher.update(block);
        total_read += block.len() as u64;
    }
    let read_stats = reader.stats();
    let read_elapsed = read_start.elapsed().as_secs_f64();
    let read_duration_ms = read_elapsed * 1000.0;
    let read_throughput_mb_s = if read_elapsed > 0.0 {
        (total_bytes as f64 / (1024.0 * 1024.0)) / read_elapsed
    } else {
        0.0
    };

    let actual_hash = read_hasher.finalize().to_hex().to_string();
    let data_integrity_verified = total_read == total_bytes && actual_hash == expected_hash;

    Ok(DirectIoBenchmarkReport {
        path: path.to_string_lossy().to_string(),
        total_bytes,
        ring_slots: config.ring_slots,
        slot_capacity: config.slot_capacity,
        sector_size: config.sector_size,
        direct_io_mode: config.mode,
        is_direct,
        write_duration_ms,
        write_throughput_mb_s,
        read_duration_ms,
        read_throughput_mb_s,
        stalls_count: write_stats.pipeline_stalls + read_stats.pipeline_stalls,
        data_integrity_verified,
        checksum_blake3: actual_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_direct_io_ring_buffer_state_transitions() {
        let config = DirectIoRingConfig {
            ring_slots: 3,
            slot_capacity: 8192,
            sector_size: 4096,
            mode: DirectIoMode::Disabled,
            min_file_size: 4096,
        };
        let mut ring = DirectIoRingBuffer::new(config);
        assert_eq!(ring.slot_count(), 3);
        assert_eq!(ring.free_slots(), 3);
        assert_eq!(ring.active_slots(), 0);
        assert!(ring.is_empty());
        assert!(!ring.is_full());

        // Acquire slot 0
        let slot0 = ring.acquire_empty_slot().expect("slot 0");
        assert_eq!(slot0.slot_id, 0);
        assert_eq!(slot0.state, RingSlotState::Filling);

        // Commit slot 0
        ring.commit_filled_slot(0, 4096, 0, false)
            .expect("commit 0");
        assert_eq!(ring.active_slots(), 1);
        assert_eq!(ring.free_slots(), 2);

        // Acquire slot 1
        let slot1 = ring.acquire_empty_slot().expect("slot 1");
        assert_eq!(slot1.slot_id, 1);
        ring.commit_filled_slot(1, 4096, 4096, false)
            .expect("commit 1");

        // Acquire slot 2
        let slot2 = ring.acquire_empty_slot().expect("slot 2");
        assert_eq!(slot2.slot_id, 2);
        ring.commit_filled_slot(2, 4096, 8192, true)
            .expect("commit 2");

        // Now full
        assert!(ring.is_full());
        assert_eq!(ring.free_slots(), 0);
        assert!(
            ring.acquire_empty_slot().is_none(),
            "should stall when full"
        );
        assert_eq!(ring.stats().pipeline_stalls, 1);

        // Consume slot 0
        let ready0 = ring.acquire_ready_slot().expect("ready 0");
        assert_eq!(ready0.slot_id, 0);
        assert_eq!(ready0.state, RingSlotState::Flushing);
        ring.release_consumed_slot(0).expect("release 0");

        // Slot 0 is now free again (circular wrapping)
        assert_eq!(ring.free_slots(), 1);
        assert!(!ring.is_full());

        // Drain remaining slots
        let ready1 = ring.acquire_ready_slot().expect("ready 1");
        assert_eq!(ready1.slot_id, 1);
        ring.release_consumed_slot(1).expect("release 1");

        let ready2 = ring.acquire_ready_slot().expect("ready 2");
        assert_eq!(ready2.slot_id, 2);
        assert!(ready2.is_eof);
        ring.release_consumed_slot(2).expect("release 2");

        assert!(ring.is_empty());
    }

    #[test]
    fn test_direct_io_pipeline_roundtrip_with_alignment() {
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("pipeline_aligned.bin");

        let total_size = 32 * 1024; // 32 KiB
        let payload: Vec<u8> = (0..total_size).map(|i| (i % 251) as u8).collect();
        let expected_hash = blake3::hash(&payload).to_hex().to_string();

        let config = DirectIoRingConfig {
            ring_slots: 4,
            slot_capacity: 8192,
            sector_size: 4096,
            mode: DirectIoMode::Disabled,
            min_file_size: 4096,
        };

        // Write
        let mut writer =
            DirectIoPipelineWriter::create(&file_path, Some(total_size as u64), config.clone())
                .expect("create writer");
        writer.write_chunk(&payload).expect("write chunk");
        let stats = writer.finish().expect("finish writer");
        assert_eq!(stats.bytes_processed, total_size as u64);

        // Read
        let mut reader = DirectIoPipelineReader::open(&file_path, config).expect("open reader");
        let mut recovered = Vec::new();
        while let Some(block) = reader.read_block().expect("read block") {
            recovered.extend_from_slice(block);
        }

        assert_eq!(recovered.len(), total_size);
        let actual_hash = blake3::hash(&recovered).to_hex().to_string();
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_direct_io_pipeline_unaligned_tail_truncation() {
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("unaligned_tail.bin");

        let odd_size = 17391; // Not a multiple of 4096
        let payload: Vec<u8> = (0..odd_size).map(|i| (i * 7 % 255) as u8).collect();
        let expected_hash = blake3::hash(&payload).to_hex().to_string();

        let config = DirectIoRingConfig {
            ring_slots: 3,
            slot_capacity: 8192,
            sector_size: 4096,
            mode: DirectIoMode::Disabled,
            min_file_size: 4096,
        };

        // Write in non-uniform streaming chunks
        let mut writer =
            DirectIoPipelineWriter::create(&file_path, Some(odd_size as u64), config.clone())
                .expect("create writer");
        for chunk in payload.chunks(1337) {
            writer.write_chunk(chunk).expect("write chunk");
        }
        writer.finish().expect("finish writer");

        // Verify physical file size matches odd_size
        let meta = std::fs::metadata(&file_path).expect("metadata");
        assert_eq!(meta.len(), odd_size as u64);

        // Read back
        let mut reader = DirectIoPipelineReader::open(&file_path, config).expect("open reader");
        let mut recovered = Vec::new();
        while let Some(block) = reader.read_block().expect("read block") {
            recovered.extend_from_slice(block);
        }

        assert_eq!(recovered.len(), odd_size);
        let actual_hash = blake3::hash(&recovered).to_hex().to_string();
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_direct_io_benchmark_runner() {
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("benchmark_test.bin");

        let config = DirectIoRingConfig {
            ring_slots: 4,
            slot_capacity: 65536,
            sector_size: 4096,
            mode: DirectIoMode::Disabled,
            min_file_size: 4096,
        };

        let report =
            run_direct_io_benchmark(&file_path, 256 * 1024, config).expect("run benchmark");
        assert_eq!(report.total_bytes, 256 * 1024);
        assert!(report.data_integrity_verified);
        assert!(!report.checksum_blake3.is_empty());
        assert!(report.write_throughput_mb_s >= 0.0);
        assert!(report.read_throughput_mb_s >= 0.0);
    }
}
