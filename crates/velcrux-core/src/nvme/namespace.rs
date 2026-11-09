#![forbid(unsafe_code)]

//! NVMe Logical Block Addressing (LBA) Storage Namespace.
//!
//! Provides a safe-Rust LBA block store with sector-aligned buffer management,
//! sparse block allocation, read/write/flush/trim operations, and integrity tracking.

use super::capsule::NvmeIdentifyNamespace;
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// NVMe Logical Block Addressing (LBA) Namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvmeNamespace {
    /// 1-based Namespace Identifier (NSID).
    pub nsid: u32,
    /// Total provisioned storage capacity in bytes.
    pub capacity_bytes: u64,
    /// Sector / LBA size in bytes (e.g. 512 or 4096).
    pub block_size: u32,
    /// Sparse block storage mapping LBA index to sector data.
    blocks: BTreeMap<u64, Vec<u8>>,
    /// Total read I/O operations executed.
    pub read_ops: u64,
    /// Total write I/O operations executed.
    pub write_ops: u64,
    /// Total flush operations executed.
    pub flush_ops: u64,
    /// Total trim/deallocate operations executed.
    pub trim_ops: u64,
    /// Cumulative bytes read.
    pub bytes_read: u64,
    /// Cumulative bytes written.
    pub bytes_written: u64,
    /// Namespace write protect flag.
    pub write_protected: bool,
}

impl NvmeNamespace {
    /// Creates a new NVMe namespace with the specified NSID, capacity, and sector size.
    pub fn new(nsid: u32, capacity_bytes: u64, block_size: u32) -> Result<Self> {
        if nsid == 0 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "NSID 0 is reserved for controller wide commands",
            )));
        }
        if block_size != 512 && block_size != 4096 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "block_size must be 512 or 4096 bytes",
            )));
        }
        if capacity_bytes == 0 || capacity_bytes % (block_size as u64) != 0 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "capacity_bytes must be a non-zero multiple of block_size",
            )));
        }

        Ok(Self {
            nsid,
            capacity_bytes,
            block_size,
            blocks: BTreeMap::new(),
            read_ops: 0,
            write_ops: 0,
            flush_ops: 0,
            trim_ops: 0,
            bytes_read: 0,
            bytes_written: 0,
            write_protected: false,
        })
    }

    /// Total number of logical blocks in this namespace.
    pub fn total_blocks(&self) -> u64 {
        self.capacity_bytes / (self.block_size as u64)
    }

    /// Generates the standard NVMe Identify Namespace structure.
    pub fn identify(&self) -> NvmeIdentifyNamespace {
        NvmeIdentifyNamespace::new(self.capacity_bytes, self.block_size)
    }

    /// Reads `nlb` (0-based count: `nlb + 1` blocks) starting from `slba`.
    pub fn read_blocks(&mut self, slba: u64, nlb: u16) -> Result<Vec<u8>> {
        let count = (nlb as u64) + 1;
        let end_lba = slba.checked_add(count).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("LBA arithmetic overflow"))
        })?;

        if end_lba > self.total_blocks() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "LBA out of range for namespace",
            )));
        }

        let total_bytes = (count as usize) * (self.block_size as usize);
        let mut buffer = vec![0u8; total_bytes];

        for i in 0..count {
            let lba = slba + i;
            let offset = (i as usize) * (self.block_size as usize);
            if let Some(block_data) = self.blocks.get(&lba) {
                buffer[offset..offset + (self.block_size as usize)].copy_from_slice(block_data);
            }
            // Deallocated / unwritten blocks remain zeroes
        }

        self.read_ops += 1;
        self.bytes_read += total_bytes as u64;
        Ok(buffer)
    }

    /// Writes `nlb` (0-based count: `nlb + 1` blocks) starting from `slba`.
    pub fn write_blocks(&mut self, slba: u64, nlb: u16, data: &[u8]) -> Result<()> {
        if self.write_protected {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "namespace is write-protected",
            )));
        }

        let count = (nlb as u64) + 1;
        let required_bytes = (count as usize) * (self.block_size as usize);
        if data.len() < required_bytes {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "insufficient payload data for requested LBA count",
            )));
        }

        let end_lba = slba.checked_add(count).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("LBA arithmetic overflow"))
        })?;

        if end_lba > self.total_blocks() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "LBA out of range for namespace",
            )));
        }

        for i in 0..count {
            let lba = slba + i;
            let offset = (i as usize) * (self.block_size as usize);
            let sector = data[offset..offset + (self.block_size as usize)].to_vec();
            self.blocks.insert(lba, sector);
        }

        self.write_ops += 1;
        self.bytes_written += required_bytes as u64;
        Ok(())
    }

    /// Flushes namespace volatile write buffers.
    pub fn flush(&mut self) -> Result<()> {
        self.flush_ops += 1;
        Ok(())
    }

    /// Deallocates / trims a contiguous range of logical blocks.
    pub fn deallocate(&mut self, slba: u64, nlb: u16) -> Result<()> {
        let count = (nlb as u64) + 1;
        let end_lba = slba.checked_add(count).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("LBA arithmetic overflow"))
        })?;

        if end_lba > self.total_blocks() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "LBA out of range for namespace deallocation",
            )));
        }

        for i in 0..count {
            self.blocks.remove(&(slba + i));
        }

        self.trim_ops += 1;
        Ok(())
    }

    /// Returns the number of actively allocated/dirty sectors in memory.
    pub fn allocated_blocks_count(&self) -> usize {
        self.blocks.len()
    }

    /// Calculates a fast 32-bit CRC32 checksum across all allocated blocks for integrity auditing.
    pub fn calculate_checksum(&self) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for (lba, data) in &self.blocks {
            for b in lba.to_le_bytes() {
                crc ^= b as u32;
                for _ in 0..8 {
                    if (crc & 1) != 0 {
                        crc = (crc >> 1) ^ 0xEDB8_8320;
                    } else {
                        crc >>= 1;
                    }
                }
            }
            for &byte in data {
                crc ^= byte as u32;
                for _ in 0..8 {
                    if (crc & 1) != 0 {
                        crc = (crc >> 1) ^ 0xEDB8_8320;
                    } else {
                        crc >>= 1;
                    }
                }
            }
        }
        !crc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_allocation_and_rw() {
        let mut ns = NvmeNamespace::new(1, 1024 * 1024, 4096).expect("create ns");
        assert_eq!(ns.total_blocks(), 256);

        // Read unwritten block should be all zeroes
        let zeroes = ns.read_blocks(0, 0).expect("read zeroes");
        assert_eq!(zeroes.len(), 4096);
        assert!(zeroes.iter().all(|&b| b == 0));

        // Write 2 blocks
        let mut test_payload = vec![0xAB; 8192];
        test_payload[4096..].fill(0xCD);
        ns.write_blocks(10, 1, &test_payload)
            .expect("write 2 blocks");

        let read_back = ns.read_blocks(10, 1).expect("read 2 blocks");
        assert_eq!(read_back, test_payload);
        assert_eq!(ns.allocated_blocks_count(), 2);

        // Trim block 10
        ns.deallocate(10, 0).expect("deallocate block 10");
        assert_eq!(ns.allocated_blocks_count(), 1);

        let read_trimmed = ns.read_blocks(10, 0).expect("read trimmed");
        assert!(read_trimmed.iter().all(|&b| b == 0));

        let read_block11 = ns.read_blocks(11, 0).expect("read block 11");
        assert!(read_block11.iter().all(|&b| b == 0xCD));
    }

    #[test]
    fn test_out_of_range_error() {
        let mut ns = NvmeNamespace::new(1, 4096 * 4, 4096).expect("create ns");
        assert_eq!(ns.total_blocks(), 4);

        let err = ns.read_blocks(4, 0).unwrap_err();
        assert!(err.to_string().contains("LBA out of range"));
    }
}
