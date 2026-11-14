//! User-space Memory (UMEM) Pool and Frame Buffer Management (ADR-083).
//!
//! Provides a contiguous, pre-registered user-space memory pool sliced into
//! fixed-size frame buffers for zero-copy DMA packet transfers.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

use super::types::{NicError, NicFrameState, NicResult, NicUmemConfig};

/// Individual descriptor metadata tracking an active UMEM frame.
#[derive(Debug, Clone)]
pub struct NicFrameMetadata {
    /// Frame index ($0..\text{total\_frames}-1$).
    pub index: usize,
    /// Absolute byte offset inside the UMEM pool.
    pub base_addr: u64,
    /// Current lifecycle state.
    pub state: NicFrameState,
    /// Length of packet payload stored in this frame.
    pub payload_len: usize,
}

/// Contiguous user-space memory pool backing AF_XDP zero-copy socket transfers.
pub struct NicUmemPool {
    config: NicUmemConfig,
    /// Backing memory buffer representing physical UMEM contiguous allocation.
    memory: RwLock<Vec<u8>>,
    /// Free-list stack storing indices of currently available frames.
    free_stack: RwLock<Vec<usize>>,
    /// State and metadata tracking for every frame in the pool.
    frames: RwLock<Vec<NicFrameMetadata>>,
    /// Count of frames currently in-flight across hardware rings or application.
    in_flight_count: AtomicUsize,
}

impl NicUmemPool {
    /// Initialize a new UMEM pool with the given configuration.
    pub fn new(config: NicUmemConfig) -> NicResult<Self> {
        config.validate()?;

        let total_bytes = config.frame_size * config.total_frames;
        let memory = vec![0u8; total_bytes];

        let mut free_stack = Vec::with_capacity(config.total_frames);
        let mut frames = Vec::with_capacity(config.total_frames);

        // Pre-populate free stack in reverse so index 0 is popped first
        for idx in (0..config.total_frames).rev() {
            free_stack.push(idx);
        }

        for idx in 0..config.total_frames {
            frames.push(NicFrameMetadata {
                index: idx,
                base_addr: (idx * config.frame_size) as u64,
                state: NicFrameState::Free,
                payload_len: 0,
            });
        }

        Ok(Self {
            config,
            memory: RwLock::new(memory),
            free_stack: RwLock::new(free_stack),
            frames: RwLock::new(frames),
            in_flight_count: AtomicUsize::new(0),
        })
    }

    /// Access pool configuration.
    #[must_use]
    pub fn config(&self) -> &NicUmemConfig {
        &self.config
    }

    /// Total memory footprint in bytes.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.config.frame_size * self.config.total_frames
    }

    /// Number of free frames available in the stack.
    #[must_use]
    pub fn free_frames_count(&self) -> usize {
        self.free_stack.read().unwrap().len()
    }

    /// Number of frames currently in flight.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight_count.load(Ordering::Relaxed)
    }

    /// Allocate a single free frame from the pool.
    pub fn alloc_frame(&self, target_state: NicFrameState) -> NicResult<usize> {
        let mut free = self.free_stack.write().unwrap();
        if let Some(idx) = free.pop() {
            let mut frames = self.frames.write().unwrap();
            frames[idx].state = target_state;
            frames[idx].payload_len = 0;
            self.in_flight_count.fetch_add(1, Ordering::Relaxed);
            Ok(idx)
        } else {
            Err(NicError::UmemExhausted {
                total: self.config.total_frames,
            })
        }
    }

    /// Allocate a batch of free frames.
    pub fn alloc_batch(&self, count: usize, target_state: NicFrameState) -> NicResult<Vec<usize>> {
        let mut free = self.free_stack.write().unwrap();
        if free.len() < count {
            return Err(NicError::UmemExhausted {
                total: self.config.total_frames,
            });
        }

        let mut frames = self.frames.write().unwrap();
        let mut allocated = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(idx) = free.pop() {
                frames[idx].state = target_state;
                frames[idx].payload_len = 0;
                allocated.push(idx);
            }
        }
        self.in_flight_count
            .fetch_add(allocated.len(), Ordering::Relaxed);
        Ok(allocated)
    }

    /// Release an allocated frame back to the free stack.
    pub fn free_frame(&self, frame_index: usize) -> NicResult<()> {
        if frame_index >= self.config.total_frames {
            return Err(NicError::FrameOutOfBounds {
                index: frame_index,
                max: self.config.total_frames,
            });
        }

        let mut frames = self.frames.write().unwrap();
        if frames[frame_index].state == NicFrameState::Free {
            // Already free; ignore double free idempotently
            return Ok(());
        }

        frames[frame_index].state = NicFrameState::Free;
        frames[frame_index].payload_len = 0;

        let mut free = self.free_stack.write().unwrap();
        free.push(frame_index);
        self.in_flight_count.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }

    /// Update the lifecycle state of a frame.
    pub fn update_frame_state(&self, frame_index: usize, state: NicFrameState) -> NicResult<()> {
        if frame_index >= self.config.total_frames {
            return Err(NicError::FrameOutOfBounds {
                index: frame_index,
                max: self.config.total_frames,
            });
        }
        let mut frames = self.frames.write().unwrap();
        frames[frame_index].state = state;
        Ok(())
    }

    /// Read the lifecycle state of a frame.
    pub fn frame_state(&self, frame_index: usize) -> NicResult<NicFrameState> {
        if frame_index >= self.config.total_frames {
            return Err(NicError::FrameOutOfBounds {
                index: frame_index,
                max: self.config.total_frames,
            });
        }
        let frames = self.frames.read().unwrap();
        Ok(frames[frame_index].state)
    }

    /// Calculate the byte offset where packet payload begins (base + headroom).
    #[must_use]
    pub fn packet_addr(&self, frame_index: usize) -> u64 {
        ((frame_index * self.config.frame_size) + self.config.headroom) as u64
    }

    /// Convert a UMEM byte offset back to its frame index.
    #[must_use]
    pub fn addr_to_frame_index(&self, addr: u64) -> usize {
        (addr as usize) / self.config.frame_size
    }

    /// Write raw packet payload into the specified frame at `headroom` offset.
    pub fn write_packet(&self, frame_index: usize, data: &[u8]) -> NicResult<usize> {
        if frame_index >= self.config.total_frames {
            return Err(NicError::FrameOutOfBounds {
                index: frame_index,
                max: self.config.total_frames,
            });
        }

        let max_payload = self.config.frame_size - self.config.headroom;
        let write_len = data.len().min(max_payload);

        let start = (frame_index * self.config.frame_size) + self.config.headroom;
        let end = start + write_len;

        let mut mem = self.memory.write().unwrap();
        mem[start..end].copy_from_slice(&data[..write_len]);

        let mut frames = self.frames.write().unwrap();
        frames[frame_index].payload_len = write_len;

        Ok(write_len)
    }

    /// Read packet payload from the specified frame.
    pub fn read_packet(&self, frame_index: usize) -> NicResult<Vec<u8>> {
        if frame_index >= self.config.total_frames {
            return Err(NicError::FrameOutOfBounds {
                index: frame_index,
                max: self.config.total_frames,
            });
        }

        let frames = self.frames.read().unwrap();
        let payload_len = frames[frame_index].payload_len;

        let start = (frame_index * self.config.frame_size) + self.config.headroom;
        let end = start + payload_len;

        let mem = self.memory.read().unwrap();
        Ok(mem[start..end].to_vec())
    }

    /// Inspect a slice of memory in the frame without allocating.
    pub fn with_packet_slice<F, R>(&self, frame_index: usize, f: F) -> NicResult<R>
    where
        F: FnOnce(&[u8]) -> R,
    {
        if frame_index >= self.config.total_frames {
            return Err(NicError::FrameOutOfBounds {
                index: frame_index,
                max: self.config.total_frames,
            });
        }

        let frames = self.frames.read().unwrap();
        let payload_len = frames[frame_index].payload_len;

        let start = (frame_index * self.config.frame_size) + self.config.headroom;
        let end = start + payload_len;

        let mem = self.memory.read().unwrap();
        Ok(f(&mem[start..end]))
    }
}
