//! FastCDC: Fast and Efficient Content-Defined Chunking (`docs/REQUIREMENTS.md` §12, `PERFORMANCE.md` §3).
//!
//! Implements sub-chunk normalization (dual-mask gear hashing) and fast minimum chunk skipping
//! based on the FastCDC algorithm (USENIX ATC '16).
//!
//! Invariants:
//! - All sizes and offsets are `u64`.
//! - Chunks strictly respect `min <= len <= max` (except the final EOF chunk which may be shorter than `min`).
//! - Concatenation of all chunk boundaries reproduces the exact stream input.
//! - Dual masks normalize chunk boundaries around `target`, dampening size variance.

#![forbid(unsafe_code)]

use crate::chunking::{ChunkBoundary, ChunkParams, Chunker};
use crate::error::{ProtocolError, Result};

/// Generate 64-bit gear mixing table deterministically using the golden-ratio constant `0x9E3779B97F4A7C15`.
pub const fn generate_gear_64() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut state = 0x9E3779B97F4A7C15u64;
    let mut i = 0;
    while i < 256 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        table[i] = state;
        i += 1;
    }
    table
}

/// Constant 64-bit gear hash lookup table.
pub static GEAR_64: [u64; 256] = generate_gear_64();

/// FastCDC chunker with sub-chunk normalization and fast minimum chunk skipping.
#[derive(Debug, Clone)]
pub struct FastCdcChunker {
    params: ChunkParams,
    mask_s: u64,
    mask_l: u64,
    mask_s_bits: u32,
    mask_l_bits: u32,
    fingerprint: u64,
    in_chunk: u64,
    next_offset: u64,
    finished: bool,
}

impl FastCdcChunker {
    /// Create a new `FastCdcChunker` with the specified parameters.
    pub fn new(params: ChunkParams) -> Self {
        let mut bits = 0u32;
        let mut t = params.target;
        while t > 1 {
            t >>= 1;
            bits += 1;
        }

        // FastCDC sub-chunk normalization:
        // - Small region [min, target): stricter mask_s (bits + 1) discourages premature cuts
        // - Large region [target, max]: looser mask_l (bits - 1) encourages cuts before hitting max
        let mask_s_bits = (bits + 1).min(63).max(1);
        let mask_l_bits = bits.saturating_sub(1).min(63).max(1);

        let mask_s = (1u64 << mask_s_bits) - 1;
        let mask_l = (1u64 << mask_l_bits) - 1;

        Self {
            params,
            mask_s,
            mask_l,
            mask_s_bits,
            mask_l_bits,
            fingerprint: 0,
            in_chunk: 0,
            next_offset: 0,
            finished: false,
        }
    }

    /// Bits required in stricter mask (small region).
    #[inline]
    pub fn mask_s_bits(&self) -> u32 {
        self.mask_s_bits
    }

    /// Bits required in looser mask (large region).
    #[inline]
    pub fn mask_l_bits(&self) -> u32 {
        self.mask_l_bits
    }
}

impl Chunker for FastCdcChunker {
    fn push(&mut self, buf: &[u8]) -> Result<Vec<ChunkBoundary>> {
        if self.finished {
            return Err(ProtocolError::Malformed("FastCdcChunker: pushed after finish").into());
        }

        let mut out = Vec::new();
        let mut offset_in_buf = 0;
        let buf_len = buf.len();

        while offset_in_buf < buf_len {
            // Phase 1: Fast skipping.
            // No chunk boundary can occur in the first `min` bytes, so skip hash calculations.
            if self.in_chunk < self.params.min {
                let needed = (self.params.min - self.in_chunk) as usize;
                let available = buf_len - offset_in_buf;
                let to_skip = needed.min(available);
                self.in_chunk += to_skip as u64;
                offset_in_buf += to_skip;
                if self.in_chunk < self.params.min {
                    break;
                }
            }

            // Phase 2: Normalized gear hash rolling boundary detection.
            while offset_in_buf < buf_len {
                let b = buf[offset_in_buf];
                offset_in_buf += 1;
                self.fingerprint = (self.fingerprint << 1).wrapping_add(GEAR_64[b as usize]);
                self.in_chunk += 1;

                // Sub-chunk normalization: select mask depending on progress toward target
                let mask = if self.in_chunk < self.params.target {
                    self.mask_s
                } else {
                    self.mask_l
                };

                let hit_natural = (self.fingerprint & mask) == 0;
                let hit_max = self.in_chunk >= self.params.max;

                if hit_natural || hit_max {
                    let cut_at = self.in_chunk;
                    out.push(ChunkBoundary {
                        offset: self.next_offset,
                        length: cut_at,
                    });
                    self.next_offset += cut_at;
                    self.in_chunk = 0;
                    self.fingerprint = 0;
                    // Break inner loop so the subsequent chunk begins with Phase 1 fast skipping
                    break;
                }
            }
        }

        Ok(out)
    }

    fn finish(&mut self) -> Result<Option<ChunkBoundary>> {
        if self.finished {
            return Err(ProtocolError::Malformed("FastCdcChunker: finish called twice").into());
        }
        self.finished = true;
        if self.in_chunk == 0 {
            return Ok(None);
        }
        let cut_at = self.in_chunk;
        let b = ChunkBoundary {
            offset: self.next_offset,
            length: cut_at,
        };
        self.next_offset += cut_at;
        self.in_chunk = 0;
        Ok(Some(b))
    }

    fn is_finished(&self) -> bool {
        self.finished
    }

    fn offset(&self) -> u64 {
        self.next_offset + self.in_chunk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gear_64_deterministic() {
        let t1 = generate_gear_64();
        let t2 = generate_gear_64();
        assert_eq!(t1, t2);
        assert_eq!(t1[0], GEAR_64[0]);
        assert_eq!(t1[255], GEAR_64[255]);
    }

    #[test]
    fn test_fastcdc_exact_reconstruction() {
        let params = ChunkParams::new(64, 256, 1024).unwrap();
        let mut chunker = FastCdcChunker::new(params);

        let data: Vec<u8> = (0..10_000).map(|i| (i * 31 % 256) as u8).collect();
        let mut reconstructed_len = 0u64;

        // Push in arbitrary buffer slices
        for chunk_slice in data.chunks(300) {
            let boundaries = chunker.push(chunk_slice).unwrap();
            for b in boundaries {
                assert!(b.length >= 64, "chunk length {} < min 64", b.length);
                assert!(b.length <= 1024, "chunk length {} > max 1024", b.length);
                assert_eq!(b.offset, reconstructed_len);
                reconstructed_len += b.length;
            }
        }

        if let Some(b) = chunker.finish().unwrap() {
            assert_eq!(b.offset, reconstructed_len);
            reconstructed_len += b.length;
        }

        assert_eq!(reconstructed_len, data.len() as u64);
    }
}
