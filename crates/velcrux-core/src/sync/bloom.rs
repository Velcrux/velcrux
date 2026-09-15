//! Bloom filter for inventory hints (`ARCHITECTURE.md` §7, `PROTOCOL.md` §4).

use super::SyncError;
use crate::util::Hash;
use bytes::Bytes;

/// Maximum allowed bloom filter size in bits (16 MB = 134,217,728 bits).
pub const MAX_BLOOM_BITS: u32 = 16 * 1024 * 1024 * 8;

/// Minimum bloom filter size in bits.
pub const MIN_BLOOM_BITS: u32 = 64;

/// Space-efficient probabilistic set representation of local chunk inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomFilter {
    num_bits: u32,
    num_hashes: u8,
    bitset: Vec<u8>,
}

impl BloomFilter {
    /// Create a new bloom filter sized for `expected_items` with target `fp_rate` (0.0 < fp_rate < 1.0).
    pub fn new(expected_items: usize, fp_rate: f64) -> Self {
        let n = (expected_items.max(1)) as f64;
        let p = fp_rate.clamp(1e-6, 0.5);

        let ln2 = std::f64::consts::LN_2;
        // m = - (n * ln(p)) / (ln(2)^2)
        let m_bits = (-(n * p.ln()) / (ln2 * ln2)).ceil() as u64;
        let num_bits = (m_bits as u32).clamp(MIN_BLOOM_BITS, MAX_BLOOM_BITS);

        // k = (m / n) * ln(2)
        let k = ((num_bits as f64 / n) * ln2).round() as u64;
        let num_hashes = (k as u8).clamp(1, 16);

        Self::with_dimensions(num_bits, num_hashes)
    }

    /// Construct a filter with explicit bit count and hash count.
    pub fn with_dimensions(num_bits: u32, num_hashes: u8) -> Self {
        let num_bits = num_bits.clamp(MIN_BLOOM_BITS, MAX_BLOOM_BITS);
        let num_hashes = num_hashes.clamp(1, 16);
        let byte_len = ((num_bits as usize) + 7) / 8;
        Self {
            num_bits,
            num_hashes,
            bitset: vec![0u8; byte_len],
        }
    }

    /// Reconstitute from raw bytes, bit count, and hash count.
    pub fn from_bytes(bitset: &[u8], num_bits: u32, num_hashes: u8) -> Result<Self, SyncError> {
        if num_bits < MIN_BLOOM_BITS || num_bits > MAX_BLOOM_BITS {
            return Err(SyncError::Bloom(format!("invalid bit count {num_bits}")));
        }
        if num_hashes == 0 || num_hashes > 16 {
            return Err(SyncError::Bloom(format!("invalid hash count {num_hashes}")));
        }
        let expected_bytes = ((num_bits as usize) + 7) / 8;
        if bitset.len() != expected_bytes {
            return Err(SyncError::Bloom(format!(
                "bitset length mismatch: expected {expected_bytes} bytes, got {}",
                bitset.len()
            )));
        }
        Ok(Self {
            num_bits,
            num_hashes,
            bitset: bitset.to_vec(),
        })
    }

    /// Number of bits in the filter.
    #[inline]
    pub fn num_bits(&self) -> u32 {
        self.num_bits
    }

    /// Number of hash functions evaluated per item.
    #[inline]
    pub fn num_hashes(&self) -> u8 {
        self.num_hashes
    }

    /// Return the raw underlying byte representation.
    #[inline]
    pub fn bitset_bytes(&self) -> &[u8] {
        &self.bitset
    }

    /// Export bitset into [`Bytes`].
    pub fn to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(&self.bitset)
    }

    /// Insert a 32-byte BLAKE3 chunk hash into the filter.
    pub fn insert(&mut self, hash: &Hash) {
        let (h1, h2) = self.hash_pair(hash);
        for i in 0..self.num_hashes as u64 {
            let bit_idx = (h1.wrapping_add(i.wrapping_mul(h2))) % (self.num_bits as u64);
            let byte_idx = (bit_idx / 8) as usize;
            let bit_pos = (bit_idx % 8) as u8;
            self.bitset[byte_idx] |= 1 << bit_pos;
        }
    }

    /// Test whether `hash` may be present in the filter.
    ///
    /// Returns `true` if all probed bits are set (false positive possible),
    /// returns `false` if definitely absent (zero false negatives).
    pub fn contains(&self, hash: &Hash) -> bool {
        let (h1, h2) = self.hash_pair(hash);
        for i in 0..self.num_hashes as u64 {
            let bit_idx = (h1.wrapping_add(i.wrapping_mul(h2))) % (self.num_bits as u64);
            let byte_idx = (bit_idx / 8) as usize;
            let bit_pos = (bit_idx % 8) as u8;
            if (self.bitset[byte_idx] & (1 << bit_pos)) == 0 {
                return false;
            }
        }
        true
    }

    #[inline]
    fn hash_pair(&self, hash: &Hash) -> (u64, u64) {
        let bytes = hash.as_bytes();
        let h1 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        // Force h2 to be odd to ensure full period over modulo
        let h2 = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) | 1;
        (h1, h2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bloom_roundtrip_and_query() {
        let mut bloom = BloomFilter::new(100, 0.01);
        let h1 = Hash::of(b"chunk1");
        let h2 = Hash::of(b"chunk2");
        let h3 = Hash::of(b"chunk3");

        bloom.insert(&h1);
        bloom.insert(&h2);

        assert!(bloom.contains(&h1));
        assert!(bloom.contains(&h2));
        assert!(!bloom.contains(&h3));

        let bytes = bloom.to_bytes();
        let decoded =
            BloomFilter::from_bytes(&bytes, bloom.num_bits(), bloom.num_hashes()).unwrap();
        assert_eq!(bloom, decoded);
        assert!(decoded.contains(&h1));
        assert!(decoded.contains(&h2));
        assert!(!decoded.contains(&h3));
    }

    #[test]
    fn bloom_false_positive_rate() {
        let n = 1000;
        let mut bloom = BloomFilter::new(n, 0.05);
        for i in 0..n {
            let h = Hash::of(&i.to_le_bytes());
            bloom.insert(&h);
        }

        // Test non-members
        let test_count = 2000;
        let mut fps = 0;
        for i in n..(n + test_count) {
            let h = Hash::of(&i.to_le_bytes());
            if bloom.contains(&h) {
                fps += 1;
            }
        }
        let rate = fps as f64 / test_count as f64;
        assert!(rate <= 0.10, "FP rate was {rate}, expected <= 0.10");
    }
}
