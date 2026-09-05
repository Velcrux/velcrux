//! 32-byte content hashes.
//!
//! `PROTOCOL.md` §1: `Hash` is 32 bytes. The algorithm that produced it is
//! fixed for the session by capability negotiation (`PROTOCOL.md` §6); it is
//! never per-message. For the MVP the only algorithm is BLAKE3-256.
//!
//! Invariants (CLAUDE.md §1):
//!   - A hash is always 32 bytes. All wire sizes/offsets are u64 (CLAUDE.md §1 #4).
//!   - Never invent crypto: BLAKE3 and rustls/QUIC-TLS only (CLAUDE.md §1 #2).
//!   - No allocation driven by attacker-supplied lengths.

use blake3::Hasher as Blake3;
use std::fmt;

/// Number of bytes in a `Hash` on the wire and in storage.
pub const CHUNK_HASH_BYTES: usize = 32;

/// Which algorithm produced a hash. The protocol can negotiate this; for M2
/// the only implementation is BLAKE3. SHA-256 is reserved for compliance
/// modes per `ADR-003` and lands with M5 manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// BLAKE3-256. Mandatory capability per `PROTOCOL.md` §6.
    Blake3,
    /// Reserved; not used in M2.
    Sha256,
}

impl HashAlgorithm {
    /// Stable, machine-readable name (logs, config).
    pub const fn name(self) -> &'static str {
        match self {
            HashAlgorithm::Blake3 => "blake3",
            HashAlgorithm::Sha256 => "sha256",
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A 32-byte content hash. Wire- and storage-stable.
///
/// `Hash` is `Copy` so it can be passed by value freely. Equality is
/// byte-equality; there is no normalisation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash([u8; CHUNK_HASH_BYTES]);

impl Hash {
    /// All-zero hash. Useful as a sentinel.
    pub const ZERO: Hash = Hash([0u8; CHUNK_HASH_BYTES]);

    /// Borrow the 32 raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; CHUNK_HASH_BYTES] {
        &self.0
    }

    /// Construct from a raw 32-byte slice. Returns `None` on length mismatch.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != CHUNK_HASH_BYTES {
            return None;
        }
        let mut out = [0u8; CHUNK_HASH_BYTES];
        out.copy_from_slice(b);
        Some(Self(out))
    }

    /// True if this is the all-zero hash.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; CHUNK_HASH_BYTES]
    }

    /// Hash a single byte buffer in one shot.
    pub fn of(bytes: &[u8]) -> Self {
        Self::from_blake3(blake3::hash(bytes))
    }

    fn from_blake3(h: blake3::Hash) -> Self {
        let bytes = *h.as_bytes();
        debug_assert_eq!(bytes.len(), CHUNK_HASH_BYTES);
        Self(bytes)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Lower-case hex, 64 chars.
        let mut buf = [0u8; CHUNK_HASH_BYTES * 2];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, b) in self.0.iter().enumerate() {
            buf[i * 2] = HEX[(b >> 4) as usize];
            buf[i * 2 + 1] = HEX[(b & 0x0f) as usize];
        }
        f.write_str(std::str::from_utf8(&buf).expect("hex is ASCII"))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
/// Streaming BLAKE3-256 hasher. Construct with [`HashHasher::new`], feed
/// bytes with [`HashHasher::feed`], finalise with [`HashHasher::finalize`].
///
/// Not `Clone`: cloning a BLAKE3 hasher mid-feed is not meaningful. For
/// parallel chunk hashing, use `blake3::join` with separate `HashHasher`
/// instances.
pub struct HashHasher(Blake3);

impl HashHasher {
    /// Construct a new hasher.
    pub fn new() -> Self {
        Self(Blake3::new())
    }

    /// Feed bytes. Any number of calls; the order matters.
    pub fn feed(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update(bytes);
        self
    }

    /// Consume the hasher and return the resulting [`Hash`].
    pub fn finalize(self) -> Hash {
        Hash::from_blake3(self.0.finalize())
    }

    /// Finalise as raw bytes (32).
    pub fn finalize_to_bytes(self) -> [u8; CHUNK_HASH_BYTES] {
        *self.0.finalize().as_bytes()
    }
}

impl Default for HashHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(Hash::from_bytes(&[0u8; 31]).is_none());
        assert!(Hash::from_bytes(&[0u8; 33]).is_none());
        assert!(Hash::from_bytes(&[]).is_none());
    }

    #[test]
    fn from_bytes_roundtrip() {
        let bytes = [7u8; CHUNK_HASH_BYTES];
        let h = Hash::from_bytes(&bytes).unwrap();
        assert_eq!(h.as_bytes(), &bytes);
        assert_eq!(h.as_ref(), &bytes);
    }

    #[test]
    fn hash_of_empty_is_blake3_empty() {
        // BLAKE3 of empty input: well-known constant.
        let h = Hash::of(&[]);
        let expected = [
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
            0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
            0xe4, 0x1f, 0x32, 0x62,
        ];
        assert_eq!(h.as_bytes(), &expected);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let chunks: &[&[u8]] = &[b"hello, ", b"world", b"!"];
        let mut h = HashHasher::new();
        for c in chunks {
            h.feed(c);
        }
        let streaming = h.finalize();

        let mut all = Vec::new();
        for c in chunks {
            all.extend_from_slice(c);
        }
        let one_shot = Hash::of(&all);
        assert_eq!(streaming, one_shot);
    }

    #[test]
    fn display_is_64_hex_chars() {
        let h = Hash::of(b"hello");
        let s = format!("{h}");
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn zero_hash_is_zero() {
        assert!(Hash::ZERO.is_zero());
        let h = Hash::from_bytes(&[0u8; CHUNK_HASH_BYTES]).unwrap();
        assert!(h.is_zero());
        let h2 = Hash::of(b"x");
        assert!(!h2.is_zero());
    }

    #[test]
    fn algo_name_is_stable() {
        assert_eq!(HashAlgorithm::Blake3.name(), "blake3");
        assert_eq!(format!("{}", HashAlgorithm::Blake3), "blake3");
    }
}