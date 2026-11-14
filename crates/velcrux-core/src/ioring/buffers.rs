//! Fixed Buffer Registry (`IORING_REGISTER_BUFFERS`).
//!
//! Pre-registers pinned memory arenas with the kernel to avoid per-I/O page mapping,
//! TLB shootdowns, and virtual-to-physical address translation overhead.

#![forbid(unsafe_code)]

use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};

/// Pre-registered pinned memory buffer entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixedBuffer {
    pub index: u16,
    pub size_bytes: usize,
    pub data: Vec<u8>,
}

impl FixedBuffer {
    pub fn new(index: u16, size_bytes: usize) -> Self {
        Self {
            index,
            size_bytes,
            data: vec![0u8; size_bytes],
        }
    }

    pub fn with_data(index: u16, data: Vec<u8>) -> Self {
        let size_bytes = data.len();
        Self {
            index,
            size_bytes,
            data,
        }
    }
}

/// Fixed Buffer Registry managing contiguous memory pools for zero-copy I/O.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FixedBufferRegistry {
    pub buffers: Vec<FixedBuffer>,
    pub max_buffers: usize,
    pub total_registered_bytes: usize,
}

impl FixedBufferRegistry {
    pub fn new(max_buffers: usize) -> Self {
        Self {
            buffers: Vec::with_capacity(max_buffers),
            max_buffers,
            total_registered_bytes: 0,
        }
    }

    /// Registers a new fixed buffer of the specified byte size.
    ///
    /// Returns the assigned buffer index (`buf_index`).
    pub fn register(&mut self, size_bytes: usize) -> Result<u16> {
        if self.buffers.len() >= self.max_buffers {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "maximum registered fixed buffers capacity reached",
            )));
        }
        let index = self.buffers.len() as u16;
        let buf = FixedBuffer::new(index, size_bytes);
        self.total_registered_bytes = self.total_registered_bytes.saturating_add(size_bytes);
        self.buffers.push(buf);
        Ok(index)
    }

    /// Registers a fixed buffer populated with initial data.
    pub fn register_with_data(&mut self, data: Vec<u8>) -> Result<u16> {
        if self.buffers.len() >= self.max_buffers {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "maximum registered fixed buffers capacity reached",
            )));
        }
        let index = self.buffers.len() as u16;
        let size = data.len();
        let buf = FixedBuffer::with_data(index, data);
        self.total_registered_bytes = self.total_registered_bytes.saturating_add(size);
        self.buffers.push(buf);
        Ok(index)
    }

    /// Retrieves an immutable reference to a registered fixed buffer.
    pub fn get(&self, index: u16) -> Option<&FixedBuffer> {
        self.buffers.get(index as usize)
    }

    /// Retrieves a mutable reference to a registered fixed buffer.
    pub fn get_mut(&mut self, index: u16) -> Option<&mut FixedBuffer> {
        self.buffers.get_mut(index as usize)
    }

    /// Reads bytes from a registered fixed buffer at offset.
    pub fn read_slice(&self, index: u16, offset: usize, len: usize) -> Result<Vec<u8>> {
        let buf = self.get(index).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("invalid fixed buffer index"))
        })?;

        if offset.saturating_add(len) > buf.size_bytes {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "fixed buffer read slice out of bounds",
            )));
        }

        Ok(buf.data[offset..offset + len].to_vec())
    }

    /// Writes bytes into a registered fixed buffer at offset.
    pub fn write_slice(&mut self, index: u16, offset: usize, slice: &[u8]) -> Result<usize> {
        let buf = self.get_mut(index).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("invalid fixed buffer index"))
        })?;

        if offset.saturating_add(slice.len()) > buf.size_bytes {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "fixed buffer write slice out of bounds",
            )));
        }

        buf.data[offset..offset + slice.len()].copy_from_slice(slice);
        Ok(slice.len())
    }

    /// Releases all registered buffers.
    pub fn unregister_all(&mut self) {
        self.buffers.clear();
        self.total_registered_bytes = 0;
    }

    /// Number of active registered fixed buffers.
    pub fn count(&self) -> usize {
        self.buffers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_buffer_registration_read_write() {
        let mut registry = FixedBufferRegistry::new(16);

        let idx0 = registry.register(65536).expect("register 64K");
        assert_eq!(idx0, 0);
        assert_eq!(registry.total_registered_bytes, 65536);

        let data_to_write = b"velcrux-zero-copy-chunk-payload";
        let written = registry
            .write_slice(idx0, 1024, data_to_write)
            .expect("write slice");
        assert_eq!(written, data_to_write.len());

        let read_back = registry
            .read_slice(idx0, 1024, data_to_write.len())
            .expect("read slice");
        assert_eq!(&read_back, data_to_write);
    }
}
