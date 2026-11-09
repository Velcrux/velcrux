#![forbid(unsafe_code)]

//! NVMe-oF (NVM Express over Fabrics 1.1) Capsule Framing & Wire Protocol Descriptors.
//!
//! Provides pure safe-Rust 64-byte Submission Queue Entry (SQE) commands,
//! 16-byte Completion Queue Entry (CQE) responses, Keyed SGL descriptors,
//! and Fabric Connect/Identify wire payload serialization.

use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};

// Standard NVMe Command Opcodes
pub const NVME_OP_FLUSH: u8 = 0x00;
pub const NVME_OP_WRITE: u8 = 0x01;
pub const NVME_OP_READ: u8 = 0x02;
pub const NVME_OP_IDENTIFY: u8 = 0x06;
pub const NVME_OP_FABRIC: u8 = 0x7F;

// Fabric Command Types (fctype)
pub const NVME_FABRIC_CONNECT: u8 = 0x00;
pub const NVME_FABRIC_DISCONNECT: u8 = 0x01;
pub const NVME_FABRIC_AUTH: u8 = 0x05;

// SGL Descriptor Subtypes
pub const SGL_TYPE_DATA_BLOCK: u8 = 0x00;
pub const SGL_TYPE_KEYED_DATA_BLOCK: u8 = 0x04;
pub const SGL_TYPE_TRANSPORT_DATA_BLOCK: u8 = 0x05;

// Standard NVMe Status Codes
pub const NVME_STATUS_SUCCESS: u16 = 0x0000;
pub const NVME_STATUS_INVALID_OPCODE: u16 = 0x0001;
pub const NVME_STATUS_INVALID_FIELD: u16 = 0x0002;
pub const NVME_STATUS_LBA_OUT_OF_RANGE: u16 = 0x0080;
pub const NVME_STATUS_CAPACITY_EXCEEDED: u16 = 0x0081;
pub const NVME_STATUS_NAMESPACE_NOT_READY: u16 = 0x0082;
pub const NVME_STATUS_FABRIC_CONNECT_REJECTED: u16 = 0x0008;

/// Scatter-Gather List (SGL) Descriptor for direct RDMA zero-copy payload offload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeSglDescriptor {
    /// Remote host 64-bit memory address for RDMA Read/Write.
    pub address: u64,
    /// Length of the target buffer in bytes.
    pub length: u32,
    /// Remote memory key (`rkey`) for authorized RDMA hardware direct access.
    pub key: u32,
    /// SGL Type (e.g. `0x04` for Keyed SGL Data Block).
    pub sgl_type: u8,
    /// SGL Subtype (e.g. `0x00` address / key).
    pub sgl_subtype: u8,
}

impl NvmeSglDescriptor {
    pub const SIZE_BYTES: usize = 16;

    /// Creates an empty SGL descriptor.
    pub const fn empty() -> Self {
        Self {
            address: 0,
            length: 0,
            key: 0,
            sgl_type: 0,
            sgl_subtype: 0,
        }
    }

    /// Creates a Keyed SGL Data Block descriptor specifying RDMA address and key.
    pub fn keyed_data_block(address: u64, length: u32, rkey: u32) -> Self {
        Self {
            address,
            length,
            key: rkey,
            sgl_type: SGL_TYPE_KEYED_DATA_BLOCK,
            sgl_subtype: 0,
        }
    }

    /// Serializes SGL descriptor into standard 16 bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        let mut out = [0u8; Self::SIZE_BYTES];
        out[..8].copy_from_slice(&self.address.to_le_bytes());
        out[8..12].copy_from_slice(&self.length.to_le_bytes());
        // For Keyed SGL, key is stored in bytes 12..15
        out[12..15].copy_from_slice(&self.key.to_le_bytes()[..3]);
        out[15] = (self.sgl_type << 4) | (self.sgl_subtype & 0x0F);
        out
    }

    /// Deserializes SGL descriptor from 16 bytes.
    pub fn from_bytes(bytes: &[u8; Self::SIZE_BYTES]) -> Self {
        let address = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let mut key_buf = [0u8; 4];
        key_buf[..3].copy_from_slice(&bytes[12..15]);
        let key = u32::from_le_bytes(key_buf);
        let sgl_type = bytes[15] >> 4;
        let sgl_subtype = bytes[15] & 0x0F;

        Self {
            address,
            length,
            key,
            sgl_type,
            sgl_subtype,
        }
    }
}

/// Standard 64-byte NVMe Submission Queue Entry (SQE) Command Capsule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeSubmissionQueueEntry {
    /// Command Opcode (e.g. Read, Write, Identify, Fabric).
    pub opcode: u8,
    /// Command Flags (Fused operation, SGL specification).
    pub flags: u8,
    /// Command Identifier assigned by initiator.
    pub command_id: u16,
    /// Target Namespace Identifier (1-based, 0 for controller).
    pub nsid: u32,
    /// Command Dword 2 (Fabric command type if opcode == 0x7F).
    pub cdw2: u32,
    /// Command Dword 3.
    pub cdw3: u32,
    /// Metadata Pointer.
    pub mptr: u64,
    /// Data Pointer: 16-byte SGL descriptor for fabrics.
    pub dptr: NvmeSglDescriptor,
    /// Starting LBA (Logical Block Address) for block operations.
    pub slba: u64,
    /// Number of Logical Blocks (0-based: 0 = 1 block).
    pub nlb: u16,
    /// Command control flags (e.g. FUA - Force Unit Access).
    pub control: u16,
    /// Dataset Management attributes (e.g. TRIM/Deallocate).
    pub dsmgmt: u32,
}

impl NvmeSubmissionQueueEntry {
    pub const SIZE_BYTES: usize = 64;

    /// Serializes SQE into standard 64-byte NVMe wire format.
    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        let mut out = [0u8; Self::SIZE_BYTES];
        out[0] = self.opcode;
        out[1] = self.flags;
        out[2..4].copy_from_slice(&self.command_id.to_le_bytes());
        out[4..8].copy_from_slice(&self.nsid.to_le_bytes());
        out[8..12].copy_from_slice(&self.cdw2.to_le_bytes());
        out[12..16].copy_from_slice(&self.cdw3.to_le_bytes());
        out[16..24].copy_from_slice(&self.mptr.to_le_bytes());
        out[24..40].copy_from_slice(&self.dptr.to_bytes());
        out[40..48].copy_from_slice(&self.slba.to_le_bytes());
        out[48..50].copy_from_slice(&self.nlb.to_le_bytes());
        out[50..52].copy_from_slice(&self.control.to_le_bytes());
        out[52..56].copy_from_slice(&self.dsmgmt.to_le_bytes());
        out
    }

    /// Deserializes SQE from 64 bytes.
    pub fn from_bytes(bytes: &[u8; Self::SIZE_BYTES]) -> Self {
        let opcode = bytes[0];
        let flags = bytes[1];
        let command_id = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
        let nsid = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let cdw2 = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let cdw3 = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let mptr = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let mut dptr_bytes = [0u8; 16];
        dptr_bytes.copy_from_slice(&bytes[24..40]);
        let dptr = NvmeSglDescriptor::from_bytes(&dptr_bytes);
        let slba = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let nlb = u16::from_le_bytes(bytes[48..50].try_into().unwrap());
        let control = u16::from_le_bytes(bytes[50..52].try_into().unwrap());
        let dsmgmt = u32::from_le_bytes(bytes[52..56].try_into().unwrap());

        Self {
            opcode,
            flags,
            command_id,
            nsid,
            cdw2,
            cdw3,
            mptr,
            dptr,
            slba,
            nlb,
            control,
            dsmgmt,
        }
    }

    /// Helper to construct a standard NVMe Read command capsule.
    pub fn read_command(
        command_id: u16,
        nsid: u32,
        slba: u64,
        nlb: u16,
        sgl: NvmeSglDescriptor,
    ) -> Self {
        Self {
            opcode: NVME_OP_READ,
            flags: 0x40, // SGL used
            command_id,
            nsid,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            dptr: sgl,
            slba,
            nlb,
            control: 0,
            dsmgmt: 0,
        }
    }

    /// Helper to construct a standard NVMe Write command capsule.
    pub fn write_command(
        command_id: u16,
        nsid: u32,
        slba: u64,
        nlb: u16,
        sgl: NvmeSglDescriptor,
    ) -> Self {
        Self {
            opcode: NVME_OP_WRITE,
            flags: 0x40, // SGL used
            command_id,
            nsid,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            dptr: sgl,
            slba,
            nlb,
            control: 0,
            dsmgmt: 0,
        }
    }

    /// Helper to construct a Fabric Connect command capsule.
    pub fn fabric_connect_command(command_id: u16, sgl: NvmeSglDescriptor) -> Self {
        Self {
            opcode: NVME_OP_FABRIC,
            flags: 0x40,
            command_id,
            nsid: 0,
            cdw2: NVME_FABRIC_CONNECT as u32,
            cdw3: 0,
            mptr: 0,
            dptr: sgl,
            slba: 0,
            nlb: 0,
            control: 0,
            dsmgmt: 0,
        }
    }
}

/// Standard 16-byte NVMe Completion Queue Entry (CQE) Response Capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeCompletionQueueEntry {
    /// Command-specific result (Dword 0 and Dword 1).
    pub result: u64,
    /// Submission Queue Head Pointer.
    pub sq_head: u16,
    /// Submission Queue Identifier.
    pub sq_id: u16,
    /// Command Identifier matching the corresponding SQE.
    pub command_id: u16,
    /// Status Field: Phase Tag (bit 0) and Status Code (bits 1..15).
    pub status: u16,
}

impl NvmeCompletionQueueEntry {
    pub const SIZE_BYTES: usize = 16;

    /// Serializes CQE into standard 16 bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        let mut out = [0u8; Self::SIZE_BYTES];
        out[..8].copy_from_slice(&self.result.to_le_bytes());
        out[8..10].copy_from_slice(&self.sq_head.to_le_bytes());
        out[10..12].copy_from_slice(&self.sq_id.to_le_bytes());
        out[12..14].copy_from_slice(&self.command_id.to_le_bytes());
        out[14..16].copy_from_slice(&self.status.to_le_bytes());
        out
    }

    /// Deserializes CQE from 16 bytes.
    pub fn from_bytes(bytes: &[u8; Self::SIZE_BYTES]) -> Self {
        let result = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let sq_head = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
        let sq_id = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
        let command_id = u16::from_le_bytes(bytes[12..14].try_into().unwrap());
        let status = u16::from_le_bytes(bytes[14..16].try_into().unwrap());

        Self {
            result,
            sq_head,
            sq_id,
            command_id,
            status,
        }
    }

    /// Constructs a successful CQE.
    pub fn success(command_id: u16, sq_id: u16, sq_head: u16, result: u64) -> Self {
        Self {
            result,
            sq_head,
            sq_id,
            command_id,
            status: NVME_STATUS_SUCCESS | 0x0001, // bit 0 = phase tag 1
        }
    }

    /// Constructs an error CQE.
    pub fn error(command_id: u16, sq_id: u16, sq_head: u16, status_code: u16) -> Self {
        Self {
            result: 0,
            sq_head,
            sq_id,
            command_id,
            status: (status_code << 1) | 0x0001,
        }
    }

    /// True if the command completed with success.
    pub fn is_success(&self) -> bool {
        (self.status >> 1) == (NVME_STATUS_SUCCESS >> 1)
    }

    /// Extracts standard status code.
    pub fn status_code(&self) -> u16 {
        self.status >> 1
    }
}

/// Fabric Connect Request Data Payload (1024 bytes per NVMe-oF specification).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeFabricConnectData {
    /// Host UUID (16 bytes).
    pub host_id: [u8; 16],
    /// Controller ID requested (0xFFFF for dynamic).
    pub controller_id: u16,
    /// Subsystem NVMe Qualified Name (NQN).
    pub subsystem_nqn: String,
    /// Host NVMe Qualified Name (NQN).
    pub host_nqn: String,
}

impl NvmeFabricConnectData {
    pub const SIZE_BYTES: usize = 1024;

    /// Serializes Connect Data payload into 1024 bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        let mut out = [0u8; Self::SIZE_BYTES];
        out[..16].copy_from_slice(&self.host_id);
        out[16..18].copy_from_slice(&self.controller_id.to_le_bytes());

        // Subsystem NQN at byte offset 256 (up to 256 bytes)
        let sub_bytes = self.subsystem_nqn.as_bytes();
        let sub_len = sub_bytes.len().min(256);
        out[256..256 + sub_len].copy_from_slice(&sub_bytes[..sub_len]);

        // Host NQN at byte offset 512 (up to 256 bytes)
        let host_bytes = self.host_nqn.as_bytes();
        let host_len = host_bytes.len().min(256);
        out[512..512 + host_len].copy_from_slice(&host_bytes[..host_len]);

        out
    }

    /// Deserializes Connect Data payload from 1024 bytes.
    pub fn from_bytes(bytes: &[u8; Self::SIZE_BYTES]) -> Result<Self> {
        let mut host_id = [0u8; 16];
        host_id.copy_from_slice(&bytes[..16]);
        let controller_id = u16::from_le_bytes(bytes[16..18].try_into().unwrap());

        let sub_str = std::str::from_utf8(&bytes[256..512])
            .map_err(|_| {
                VelcruxError::Protocol(ProtocolError::Malformed("invalid subsystem NQN UTF-8"))
            })?
            .trim_end_matches('\0')
            .to_string();

        let host_str = std::str::from_utf8(&bytes[512..768])
            .map_err(|_| {
                VelcruxError::Protocol(ProtocolError::Malformed("invalid host NQN UTF-8"))
            })?
            .trim_end_matches('\0')
            .to_string();

        Ok(Self {
            host_id,
            controller_id,
            subsystem_nqn: sub_str,
            host_nqn: host_str,
        })
    }
}

/// NVMe Identify Controller Data payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeIdentifyController {
    pub vid: u16,
    pub ssvid: u16,
    pub sn: String,
    pub mn: String,
    pub fr: String,
    pub mdts: u8,
    pub cntlid: u16,
    pub nn: u32,
}

impl NvmeIdentifyController {
    pub fn default_dpu_controller(cntlid: u16, num_namespaces: u32) -> Self {
        Self {
            vid: 0x15B3, // Mellanox / NVIDIA BlueField PCI Vendor ID
            ssvid: 0x15B3,
            sn: "VX-DPU-2026110901".to_string(),
            mn: "Velcrux SmartNIC DPU NVMe-oF Controller".to_string(),
            fr: "2.1.0".to_string(),
            mdts: 8, // Max Data Transfer Size: 2^8 * 4KB = 1 MB
            cntlid,
            nn: num_namespaces,
        }
    }
}

/// NVMe Identify Namespace Data payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeIdentifyNamespace {
    /// Total namespace size in logical blocks.
    pub nsze: u64,
    /// Capacity in logical blocks.
    pub ncap: u64,
    /// Logical block size in bytes (e.g. 512 or 4096).
    pub lba_size: u32,
    /// Formatted LBA size index.
    pub flbas: u8,
}

impl NvmeIdentifyNamespace {
    pub fn new(capacity_bytes: u64, lba_size: u32) -> Self {
        let blocks = capacity_bytes / (lba_size as u64);
        Self {
            nsze: blocks,
            ncap: blocks,
            lba_size,
            flbas: if lba_size == 4096 { 1 } else { 0 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sgl_descriptor_roundtrip() {
        let sgl = NvmeSglDescriptor::keyed_data_block(0x7FFF_8000_1000, 65536, 0x123456);
        let bytes = sgl.to_bytes();
        let recovered = NvmeSglDescriptor::from_bytes(&bytes);
        assert_eq!(sgl.address, recovered.address);
        assert_eq!(sgl.length, recovered.length);
        assert_eq!(sgl.key, recovered.key);
        assert_eq!(sgl.sgl_type, recovered.sgl_type);
    }

    #[test]
    fn test_sqe_and_cqe_roundtrip() {
        let sgl = NvmeSglDescriptor::keyed_data_block(0x1000_0000, 4096, 0xABCDEF);
        let sqe = NvmeSubmissionQueueEntry::read_command(42, 1, 1024, 7, sgl);
        let sqe_bytes = sqe.to_bytes();
        assert_eq!(sqe_bytes.len(), 64);
        let recovered_sqe = NvmeSubmissionQueueEntry::from_bytes(&sqe_bytes);
        assert_eq!(sqe, recovered_sqe);

        let cqe = NvmeCompletionQueueEntry::success(42, 1, 10, 0);
        let cqe_bytes = cqe.to_bytes();
        assert_eq!(cqe_bytes.len(), 16);
        let recovered_cqe = NvmeCompletionQueueEntry::from_bytes(&cqe_bytes);
        assert_eq!(cqe, recovered_cqe);
        assert!(recovered_cqe.is_success());
    }

    #[test]
    fn test_fabric_connect_roundtrip() {
        let connect = NvmeFabricConnectData {
            host_id: [0x5A; 16],
            controller_id: 0x0001,
            subsystem_nqn: "nqn.2026-11.io.velcrux:subsys.nvme01".to_string(),
            host_nqn: "nqn.2026-11.io.velcrux:host.node01".to_string(),
        };

        let bytes = connect.to_bytes();
        assert_eq!(bytes.len(), 1024);
        let recovered = NvmeFabricConnectData::from_bytes(&bytes).expect("parse connect");
        assert_eq!(connect, recovered);
    }
}
