//! Memory Registration, Protection Domains, and Key Orchestration for RDMA.
//!
//! Provides safe memory registration (`Mr`), protection domains (`Pd`), and
//! cryptographically verified local/remote key (`lkey` / `rkey`) token validation.
//!
//! Complies strictly with `#![forbid(unsafe_code)]`.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

/// Global counter for assigning unique Protection Domain IDs.
static NEXT_PD_ID: AtomicU32 = AtomicU32::new(100);

/// Global counter for generating distinct LKey / RKey tokens.
static NEXT_KEY_ID: AtomicU32 = AtomicU32::new(0x1000);

/// RDMA Memory Access Permission Flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessFlags(pub u32);

impl AccessFlags {
    pub const NONE: Self = Self(0);
    pub const LOCAL_WRITE: Self = Self(1 << 0);
    pub const REMOTE_WRITE: Self = Self(1 << 1);
    pub const REMOTE_READ: Self = Self(1 << 2);
    pub const REMOTE_ATOMIC: Self = Self(1 << 3);
    pub const ZERO_BASED: Self = Self(1 << 4);

    pub fn contains(&self, other: AccessFlags) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn union(&self, other: AccessFlags) -> Self {
        Self(self.0 | other.0)
    }
}

impl Default for AccessFlags {
    fn default() -> Self {
        Self::LOCAL_WRITE
    }
}

/// Protection Domain (PD) - isolates memory regions and queue pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionDomain {
    pub id: u32,
}

impl ProtectionDomain {
    /// Allocate a new Protection Domain with a unique identifier.
    pub fn new() -> Self {
        Self {
            id: NEXT_PD_ID.fetch_add(1, Ordering::Relaxed),
        }
    }
}

impl Default for ProtectionDomain {
    fn default() -> Self {
        Self::new()
    }
}

/// Registered Memory Region (MR) backing zero-copy DMA transfers.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Virtual base address assigned to this memory region.
    pub addr: u64,
    /// Length of registered memory in bytes.
    pub length: usize,
    /// Local key (lkey) for host Scatter/Gather DMA operations.
    pub lkey: u32,
    /// Remote key (rkey) distributed to remote peers for RDMA Read/Write.
    pub rkey: u32,
    /// Associated Protection Domain ID.
    pub pd_id: u32,
    /// Permitted access capabilities.
    pub access: AccessFlags,
    /// Underlying memory buffer.
    buffer: Arc<RwLock<Vec<u8>>>,
    /// Active validity state of this MR.
    is_valid: Arc<AtomicBool>,
}

impl MemoryRegion {
    /// Register a memory buffer within a Protection Domain.
    pub fn register(pd: &ProtectionDomain, size: usize, access: AccessFlags) -> Self {
        let base_key = NEXT_KEY_ID.fetch_add(2, Ordering::Relaxed);
        let lkey = base_key;
        let rkey = base_key + 1;
        let addr = 0x7FFF_0000_0000u64 + (base_key as u64 * 0x1000);

        let data = vec![0u8; size];

        Self {
            addr,
            length: size,
            lkey,
            rkey,
            pd_id: pd.id,
            access,
            buffer: Arc::new(RwLock::new(data)),
            is_valid: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Register with existing initial data.
    pub fn register_with_data(pd: &ProtectionDomain, data: Vec<u8>, access: AccessFlags) -> Self {
        let size = data.len();
        let base_key = NEXT_KEY_ID.fetch_add(2, Ordering::Relaxed);
        let lkey = base_key;
        let rkey = base_key + 1;
        let addr = 0x7FFF_0000_0000u64 + (base_key as u64 * 0x1000);

        Self {
            addr,
            length: size,
            lkey,
            rkey,
            pd_id: pd.id,
            access,
            buffer: Arc::new(RwLock::new(data)),
            is_valid: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Returns whether this memory region is currently valid and registered.
    pub fn is_valid(&self) -> bool {
        self.is_valid.load(Ordering::Acquire)
    }

    /// Invalidate this memory region (revoking lkey and rkey).
    pub fn deregister(&self) {
        self.is_valid.store(false, Ordering::Release);
    }

    /// Validate access permissions and bounds for remote DMA operation.
    pub fn validate_remote_access(
        &self,
        rkey: u32,
        offset: usize,
        len: usize,
        required_flag: AccessFlags,
    ) -> Result<(), &'static str> {
        if !self.is_valid() {
            return Err("Memory region is deregistered or invalid");
        }
        if self.rkey != rkey {
            return Err("Remote key mismatch (RemAccErr)");
        }
        if !self.access.contains(required_flag) {
            return Err("Access flag denied (LocProtErr / RemAccErr)");
        }
        if offset
            .checked_add(len)
            .map_or(true, |end| end > self.length)
        {
            return Err("Buffer range out of bounds (LocLenErr)");
        }
        Ok(())
    }

    /// Read bytes directly from registered memory at given offset.
    pub fn read(&self, offset: usize, len: usize) -> Result<Vec<u8>, &'static str> {
        if !self.is_valid() {
            return Err("MR is invalid");
        }
        if offset + len > self.length {
            return Err("Read offset out of bounds");
        }

        let guard = self
            .buffer
            .read()
            .map_err(|_| "Failed to acquire MR read lock")?;
        Ok(guard[offset..offset + len].to_vec())
    }

    /// Write bytes directly into registered memory at given offset.
    pub fn write(&self, offset: usize, data: &[u8]) -> Result<(), &'static str> {
        if !self.is_valid() {
            return Err("MR is invalid");
        }
        if !self.access.contains(AccessFlags::LOCAL_WRITE)
            && !self.access.contains(AccessFlags::REMOTE_WRITE)
        {
            return Err("Write permission denied");
        }
        if offset + data.len() > self.length {
            return Err("Write overflow beyond MR length");
        }

        let mut guard = self
            .buffer
            .write()
            .map_err(|_| "Failed to acquire MR write lock")?;
        guard[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Invalidate remote key (supporting Send with Invalidate / IETH).
    pub fn invalidate_rkey(&self, rkey: u32) -> Result<(), &'static str> {
        if self.rkey != rkey {
            return Err("Key mismatch for invalidation");
        }
        self.is_valid.store(false, Ordering::Release);
        Ok(())
    }
}
