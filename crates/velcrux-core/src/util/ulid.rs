//! 16-byte transfer identifiers.
//!
//! `PROTOCOL.md` §4: `transfer_id` is 16 bytes. M1 uses the `ulid` crate
//! (monotonic, lexically sortable, 128 bits, Crockford base32). When
//! monotonicity across processes matters (M2+), we layer the per-process
//! monotonic counter on top.

use rand::RngCore;
use std::fmt;
use ulid::Ulid;

/// A 16-byte transfer identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransferId([u8; 16]);

impl TransferId {
    /// Number of bytes in a transfer id on the wire.
    pub const LEN: usize = 16;

    /// Generate a fresh transfer id. Uses process-local randomness for M1;
    /// will be replaced with a monotonic generator in M2.
    pub fn generate() -> Self {
        let u = Ulid::new();
        Self(u.to_bytes())
    }

    /// Wrap a raw 16-byte identifier received from a peer. Returns `None` on
    /// length mismatch.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != Self::LEN {
            return None;
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(b);
        Some(Self(out))
    }

    /// Parse a canonical 26-character ULID string (Crockford base32).
    /// Returns `None` on length or alphabet mismatch. This is the
    /// inverse of the `Display` impl.
    pub fn from_string(s: &str) -> Option<Self> {
        if s.len() != 26 {
            return None;
        }
        // Decode Crockford base32. The 26-char alphabet is
        // `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I, L, O, U).
        fn val(c: char) -> Option<u8> {
            match c {
                '0'..='9' => Some(c as u8 - b'0'),
                'A'..='H' => Some(c as u8 - b'A' + 10),
                // Skip I (conflicts with 1) and L (conflicts with 1).
                'J' => Some(17),
                'K' => Some(18),
                'M'..='N' => Some(c as u8 - b'M' + 19),
                'P'..='Z' => Some(c as u8 - b'P' + 22),
                // Skip U (conflicts with V).
                'V' => Some(31),
                'W' => Some(32),
                'X' => Some(33),
                'Y' => Some(34),
                'Z' => Some(35),
                _ => None,
            }
        }
        // 26 chars × 5 bits = 130 bits; the high 2 bits of a
        // canonical ULID are always 0 (per spec), so the 128-bit
        // value fits in `acc: u64` only after the top 2 bits are
        // shifted out. We accumulate 26 × 5 = 130 bits in a `u128`.
        let mut acc: u128 = 0;
        for c in s.chars() {
            let v = val(c)? as u128;
            acc = (acc << 5) | v;
        }
        if (acc >> 127) & 1 != 0 {
            // High bit set means the top 2 bits of the 130-bit
            // encoding weren't zero — not a canonical ULID.
            return None;
        }
        let bytes = acc.to_be_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes[..16]);
        Some(Self(out))
    }

    /// Borrow the 16 raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display in canonical ULID form (26 chars, Crockford base32).
        // Ulid::from_bytes requires the [u8; 16] form.
        let u = Ulid::from_bytes(self.0);
        write!(f, "{u}")
    }
}

impl fmt::Debug for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransferId({self})")
    }
}

/// Convenience: random nonces for PING (8 bytes) using a caller-supplied RNG.
pub fn random_nonce<R: RngCore>(rng: &mut R) -> u64 {
    rng.next_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_unique() {
        let a = TransferId::generate();
        let b = TransferId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn from_bytes_roundtrip() {
        let a = TransferId::generate();
        let bytes = *a.as_bytes();
        let b = TransferId::from_bytes(&bytes).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(TransferId::from_bytes(&[0u8; 15]).is_none());
        assert!(TransferId::from_bytes(&[0u8; 17]).is_none());
    }

    #[test]
    fn display_is_26_chars() {
        let a = TransferId::generate();
        let s = format!("{a}");
        assert_eq!(s.len(), 26);
    }
}
