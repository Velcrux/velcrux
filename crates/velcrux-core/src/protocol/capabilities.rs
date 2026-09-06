//! Capability bitset (`PROTOCOL.md` §6).
//!
//! Bits 0..10 are defined; bits 10..32 are reserved and must be zero on send
//! (`PROTOCOL.md` §1). The server picks the intersection of client and
//! server bits; an intersection lacking `BLAKE3` or any chunking mode is
//! `PROTOCOL_VERSION_UNSUPPORTED`.

/// A single capability bit. We use an enum (not a raw u32) so the call site
/// is self-documenting and the wire value is named, not magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Capability {
    /// Fixed-size chunking.
    FixedChunking = 0,
    /// Content-defined (gear rolling hash) chunking.
    CdcChunking = 1,
    /// BLAKE3-256 hashing. Mandatory.
    Blake3 = 2,
    /// SHA-256 hashing. Interop/compliance mode only (ADR-003).
    Sha256 = 3,
    /// Content-addressed dedup chunk store.
    DedupChunkStore = 4,
    /// zstd compression.
    CompressionZstd = 5,
    /// Sparse file support (SEEK_HOLE/SEEK_DATA on Linux).
    SparseFiles = 6,
    /// Symlink preservation.
    Symlinks = 7,
    /// Hardlink preservation.
    Hardlinks = 8,
    /// Bloom filter inventory hint.
    InventoryBloom = 9,
}

/// The set of capabilities. Backed by a u32 bitset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Capabilities(pub u32);

impl Capabilities {
    /// Empty capability set.
    pub const EMPTY: Self = Self(0);

    /// Construct from a raw bitset as received on the wire. Reserved bits
    /// (10..=31) are zeroed.
    pub const fn from_wire(bits: u32) -> Self {
        Self(bits & 0x0000_0FFF)
    }

    /// Raw bitset as transmitted on the wire. Reserved bits are zeroed.
    pub const fn to_wire(self) -> u32 {
        self.0 & 0x0000_0FFF
    }

    /// Set a single capability.
    pub fn set(&mut self, c: Capability) -> &mut Self {
        self.0 |= 1u32 << (c as u8);
        self
    }

    /// Clear a single capability.
    pub fn clear(&mut self, c: Capability) -> &mut Self {
        self.0 &= !(1u32 << (c as u8));
        self
    }

    /// Test a single capability.
    pub const fn has(self, c: Capability) -> bool {
        (self.0 & (1u32 << (c as u8))) != 0
    }

    /// Bitwise intersection of two capability sets.
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// True if this set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Mandatory checks per `PROTOCOL.md` §6: a non-empty intersection must
    /// include `BLAKE3` and at least one chunking mode.
    pub fn validate_intersection(intersection: Self) -> Result<(), &'static str> {
        if !intersection.has(Capability::Blake3) {
            return Err("intersection lacks mandatory BLAKE3");
        }
        if !intersection.has(Capability::FixedChunking)
            && !intersection.has(Capability::CdcChunking)
        {
            return Err("intersection lacks any chunking mode");
        }
        Ok(())
    }
}

impl std::ops::BitOr for Capabilities {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for Capabilities {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::fmt::Display for Capabilities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<&'static str> = Vec::new();
        let all = [
            (Capability::FixedChunking, "fixed"),
            (Capability::CdcChunking, "cdc"),
            (Capability::Blake3, "blake3"),
            (Capability::Sha256, "sha256"),
            (Capability::DedupChunkStore, "dedup"),
            (Capability::CompressionZstd, "zstd"),
            (Capability::SparseFiles, "sparse"),
            (Capability::Symlinks, "symlinks"),
            (Capability::Hardlinks, "hardlinks"),
            (Capability::InventoryBloom, "bloom"),
        ];
        for (cap, name) in all {
            if self.has(cap) {
                parts.push(name);
            }
        }
        write!(f, "{{{}}}", parts.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intersect_basic() {
        let mut a = Capabilities::EMPTY;
        a.set(Capability::Blake3);
        a.set(Capability::CdcChunking);
        a.set(Capability::CompressionZstd);

        let mut b = Capabilities::EMPTY;
        b.set(Capability::Blake3);
        b.set(Capability::FixedChunking);
        b.set(Capability::DedupChunkStore);

        let i = a.intersect(b);
        assert!(i.has(Capability::Blake3));
        assert!(!i.has(Capability::CdcChunking));
        assert!(!i.has(Capability::FixedChunking));
        assert!(!i.has(Capability::CompressionZstd));
        assert!(!i.has(Capability::DedupChunkStore));
    }

    #[test]
    fn intersection_must_have_blake3() {
        let mut a = Capabilities::EMPTY;
        a.set(Capability::FixedChunking);
        let mut b = Capabilities::EMPTY;
        b.set(Capability::FixedChunking);
        let i = a.intersect(b);
        assert!(Capabilities::validate_intersection(i).is_err());
    }

    #[test]
    fn intersection_must_have_chunking() {
        let mut a = Capabilities::EMPTY;
        a.set(Capability::Blake3);
        let i = a.intersect(Capabilities::EMPTY);
        assert!(Capabilities::validate_intersection(i).is_err());
    }

    #[test]
    fn reserved_bits_masked_on_wire() {
        // Bits 10..=31 are reserved; to_wire() must zero them.
        let c = Capabilities(0xFFFF_FFFF);
        assert_eq!(c.to_wire(), 0x0000_0FFF);
    }
}
