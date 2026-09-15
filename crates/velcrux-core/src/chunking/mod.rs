//! Content-defined chunking.
//!
//! `ARCHITECTURE.md` §2 + `ADR-004`: CDC default, fixed-size fallback. The
//! chunker is an iterator-shaped state machine over a stream of read buffers
//! (typically 2 MiB); it never sees the whole file at once.
//!
//! Invariants (CLAUDE.md §1):
//!   - All sizes/offsets are u64.
//!   - Chunks have hard min and hard max clamps (`ADR-004`); the max is not
//!     just tuning — without it, adversarial content could steer the rolling
//!     hash to produce arbitrarily large chunks and defeat the per-chunk
//!     memory bound.
//!   - Concatenating chunks reproduces the input exactly (property test).
//!
//! The default parameters per `ADR-004`: min 256 KiB, target 1 MiB, max 4 MiB.
//! All are configurable, and both sides must agree (negotiated in HELLO_ACK).

use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, Result};
use crate::manifest::entry::ChunkDesc;
use crate::util::Hash;

/// Default minimum chunk size, in bytes (`ADR-004`).
pub const CHUNK_DEFAULT_MIN: u64 = 256 * 1024;
/// Default target chunk size, in bytes (`ADR-004`).
pub const CHUNK_DEFAULT_TARGET: u64 = 1024 * 1024;
/// Default maximum chunk size, in bytes (`ADR-004`).
pub const CHUNK_DEFAULT_MAX: u64 = 4 * 1024 * 1024;

/// Chunking strategy selected for a transfer or dataset (`ADR-004`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum ChunkMode {
    /// Content-defined chunking (gear rolling hash). Boundaries adapt to content edits.
    #[default]
    Cdc,
    /// Fixed-size chunking. Fast, zero hash-rolling overhead, but sensitive to insertions.
    Fixed,
}

/// Parameters for a chunker. Both sides of a transfer must use identical
/// parameters or reuse is silently destroyed (`ADR-004`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkParams {
    /// Minimum chunk size, in bytes.
    pub min: u64,
    /// Target chunk size, in bytes.
    pub target: u64,
    /// Maximum chunk size, in bytes.
    pub max: u64,
}

impl Default for ChunkParams {
    fn default() -> Self {
        Self {
            min: CHUNK_DEFAULT_MIN,
            target: CHUNK_DEFAULT_TARGET,
            max: CHUNK_DEFAULT_MAX,
        }
    }
}

impl ChunkParams {
    /// Build with the three named values.
    ///
    /// Validates either `min < target < max` (CDC mode) or `min == target == max` (Fixed mode).
    pub fn new(min: u64, target: u64, max: u64) -> Option<Self> {
        if min == 0 || max == 0 {
            return None;
        }
        if min == target && target == max {
            return Some(Self { min, target, max });
        }
        if min >= max || target <= min || target >= max {
            return None;
        }
        Some(Self { min, target, max })
    }

    /// Construct parameters for fixed-size chunking with the given chunk size.
    pub fn fixed(chunk_size: u64) -> Self {
        Self {
            min: chunk_size,
            target: chunk_size,
            max: chunk_size,
        }
    }

    /// Construct parameters for content-defined chunking.
    pub fn cdc(min: u64, target: u64, max: u64) -> Option<Self> {
        if min == 0 || max == 0 || min >= max || target <= min || target >= max {
            return None;
        }
        Some(Self { min, target, max })
    }

    /// True if these parameters represent a fixed-size chunker (`min == target == max`).
    pub fn is_fixed(&self) -> bool {
        self.min == self.target && self.target == self.max
    }
}

/// A boundary emitted by a [`Chunker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkBoundary {
    /// Inclusive start offset of the chunk, in bytes.
    pub offset: u64,
    /// Length of the chunk, in bytes.
    pub length: u64,
}

impl ChunkBoundary {
    /// End offset (exclusive) of the chunk.
    #[inline]
    pub fn end(self) -> u64 {
        self.offset + self.length
    }
}

/// Iterator-shaped chunker over a stream of byte buffers.
pub trait Chunker {
    /// Feed a read buffer; returns boundaries found within it.
    fn push(&mut self, buf: &[u8]) -> Result<Vec<ChunkBoundary>>;
    /// End-of-input: emit the trailing chunk boundary, if any.
    fn finish(&mut self) -> Result<Option<ChunkBoundary>>;
    /// True once `finish` has been called.
    fn is_finished(&self) -> bool;
    /// Current stream offset (bytes fed so far).
    fn offset(&self) -> u64;
}

/// Fixed-size chunker. Emits a chunk every `params.target` bytes (final
/// chunk may be shorter). Trivially cheap; reuse is fragile under edits
/// (`ADR-004`).
#[derive(Debug, Clone)]
pub struct FixedChunker {
    params: ChunkParams,
    in_chunk: u64,
    next_offset: u64,
    finished: bool,
}

impl FixedChunker {
    pub fn new(params: ChunkParams) -> Self {
        Self {
            params,
            in_chunk: 0,
            next_offset: 0,
            finished: false,
        }
    }
}

impl Chunker for FixedChunker {
    fn push(&mut self, buf: &[u8]) -> Result<Vec<ChunkBoundary>> {
        if self.finished {
            return Err(ProtocolError::Malformed("FixedChunker: pushed after finish").into());
        }
        let mut out = Vec::new();
        let cut_at = self.params.target;
        if cut_at == 0 {
            return Err(ProtocolError::Malformed("FixedChunker: target chunk size is 0").into());
        }
        let mut offset_in_buf = 0usize;
        let buf_len = buf.len();

        while offset_in_buf < buf_len {
            let needed = cut_at.saturating_sub(self.in_chunk);
            let available = (buf_len - offset_in_buf) as u64;
            if available < needed {
                self.in_chunk += available;
                break;
            } else {
                self.in_chunk += needed;
                offset_in_buf += needed as usize;
                out.push(ChunkBoundary {
                    offset: self.next_offset,
                    length: self.in_chunk,
                });
                self.next_offset += self.in_chunk;
                self.in_chunk = 0;
            }
        }
        Ok(out)
    }
    fn finish(&mut self) -> Result<Option<ChunkBoundary>> {
        if self.finished {
            return Err(ProtocolError::Malformed("FixedChunker: finish called twice").into());
        }
        self.finished = true;
        if self.in_chunk == 0 {
            return Ok(None);
        }
        let b = ChunkBoundary {
            offset: self.next_offset,
            length: self.in_chunk,
        };
        self.next_offset += self.in_chunk;
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

/// The buzhash mixing table. A fixed permutation of `0..=255`, generated
/// deterministically with `xorshift64` seeded with a constant
/// (`0x9E3779B97F4A7C15`, the golden-ratio constant). Both sides of every
/// velcrux transfer compile the same source, so they have the same table;
/// the table is not on the wire.
///
/// This is NOT a cryptographic primitive; it is a fast additive mixing
/// table of the same shape rsync and bup use for their rolling-chunk
/// indexes (`ADR-004`).
const GEAR: [u8; 256] = [
    0xc4, 0x08, 0xae, 0x34, 0x74, 0x88, 0xc6, 0xf5, 0xb8, 0x36, 0x71, 0x97, 0x49, 0x4b, 0xff, 0x64,
    0x6e, 0x60, 0x4e, 0x6a, 0x87, 0x29, 0x55, 0x17, 0xb0, 0x1c, 0x46, 0xde, 0xef, 0x2a, 0xd7, 0x93,
    0x5c, 0xda, 0x37, 0x48, 0x83, 0x01, 0x65, 0xf9, 0xdd, 0xa1, 0xe3, 0x53, 0xc9, 0x2b, 0xd3, 0x20,
    0x51, 0x9f, 0x3b, 0xc5, 0xdb, 0xd2, 0x59, 0xd8, 0x96, 0x68, 0x3c, 0x00, 0x84, 0x8d, 0x52, 0xdc,
    0x58, 0xa4, 0xc8, 0x38, 0x67, 0x54, 0x30, 0x2e, 0xa7, 0x42, 0x06, 0x61, 0x81, 0xca, 0x76, 0xe7,
    0x07, 0x92, 0x14, 0x9e, 0x0b, 0x0f, 0xcb, 0xb7, 0xf1, 0x1b, 0x8f, 0x7c, 0xd5, 0xed, 0x40, 0xa0,
    0x5d, 0xc1, 0xa9, 0x5f, 0x91, 0x85, 0x90, 0xaa, 0x2f, 0x1d, 0xa5, 0xe1, 0xb6, 0xd6, 0x0c, 0x8c,
    0xf6, 0x3e, 0xe8, 0xec, 0xf0, 0x6d, 0x02, 0x78, 0x12, 0x9d, 0xba, 0xab, 0x16, 0x0e, 0x9b, 0x3f,
    0xfa, 0xea, 0x13, 0x56, 0x9c, 0xc3, 0xf8, 0x09, 0xdf, 0x89, 0xcd, 0x69, 0xe0, 0x50, 0xc0, 0xb2,
    0x6b, 0x21, 0x44, 0xc2, 0x8a, 0x31, 0x1a, 0xbe, 0x2c, 0x35, 0x1f, 0x63, 0xa8, 0x23, 0x4c, 0x5b,
    0xe6, 0xd1, 0x15, 0xe4, 0x82, 0x10, 0xbd, 0x7e, 0x41, 0xfe, 0xb5, 0x9a, 0x77, 0x47, 0xaf, 0xfd,
    0xb9, 0x98, 0x73, 0x4f, 0xbf, 0x24, 0x99, 0xfb, 0x72, 0xb3, 0xb4, 0x79, 0x6c, 0x22, 0xcf, 0x33,
    0x70, 0x27, 0xbc, 0xe5, 0x8e, 0xf7, 0x18, 0xf4, 0xee, 0x5e, 0xe2, 0xf2, 0xd0, 0x95, 0xe9, 0x39,
    0x7a, 0xeb, 0x80, 0xbb, 0xcc, 0x25, 0x5a, 0xce, 0x8b, 0x43, 0x1e, 0x32, 0x3d, 0x7d, 0x57, 0x3a,
    0x86, 0x0d, 0xac, 0x05, 0x66, 0x03, 0xd9, 0x4d, 0x7f, 0xa6, 0xa2, 0xb1, 0x62, 0x2d, 0x04, 0x28,
    0xfc, 0x6f, 0x0a, 0x11, 0x26, 0xc7, 0x94, 0xa3, 0x7b, 0x75, 0x19, 0xd4, 0xf3, 0x4a, 0x45, 0xad,
];

/// Content-defined chunker (rolling-hash, gear hash, rsync-style).
///
/// The hash is `hash = ((hash * 16) + GEAR[b]) mod 2^32`, a 32-bit additive
/// hash. We cut when `(hash & mask) == 0` and we have already fed at least
/// `min` bytes into the current chunk; the hard `max` clamp forces a cut at
/// that point regardless.
#[derive(Debug, Clone)]
pub struct RollingChunker {
    params: ChunkParams,
    mask: u64,
    mask_bits: u32,
    sum: u32,
    in_chunk: u64,
    next_offset: u64,
    finished: bool,
}

impl RollingChunker {
    pub fn new(params: ChunkParams) -> Self {
        let mut bits = 0u32;
        let mut t = params.target;
        while t > 1 {
            t >>= 1;
            bits += 1;
        }
        let mask_bits = bits.max(1);
        let mask = if mask_bits >= 32 {
            u32::MAX as u64
        } else {
            (1u64 << mask_bits) - 1
        };
        Self {
            params,
            mask,
            mask_bits,
            sum: 0,
            in_chunk: 0,
            next_offset: 0,
            finished: false,
        }
    }

    /// Number of low bits that must be zero to cut. Diagnostic / test only.
    pub fn mask_bits(&self) -> u32 {
        self.mask_bits
    }
}

impl Chunker for RollingChunker {
    fn push(&mut self, buf: &[u8]) -> Result<Vec<ChunkBoundary>> {
        if self.finished {
            return Err(ProtocolError::Malformed("RollingChunker: pushed after finish").into());
        }
        let mut out = Vec::new();
        let max = self.params.max;
        let min = self.params.min;
        for &b in buf {
            self.sum = self
                .sum
                .wrapping_mul(16)
                .wrapping_add(GEAR[b as usize] as u32);
            self.in_chunk += 1;
            let hit_natural = (self.sum as u64 & self.mask) == 0 && self.in_chunk >= min;
            let hit_max = self.in_chunk >= max;
            if hit_natural || hit_max {
                let cut_at = self.in_chunk;
                out.push(ChunkBoundary {
                    offset: self.next_offset,
                    length: cut_at,
                });
                self.next_offset += cut_at;
                self.in_chunk = 0;
                self.sum = 0;
            }
        }
        Ok(out)
    }
    fn finish(&mut self) -> Result<Option<ChunkBoundary>> {
        if self.finished {
            return Err(ProtocolError::Malformed("RollingChunker: finish called twice").into());
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

/// Alias for [`RollingChunker`] matching `ARCHITECTURE.md` §2 and ADR-004 nomenclature.
pub type CdcChunker = RollingChunker;

/// Create a boxed [`Chunker`] matching the given mode and parameters.
pub fn create_chunker(mode: ChunkMode, params: ChunkParams) -> Box<dyn Chunker + Send> {
    match mode {
        ChunkMode::Fixed => Box::new(FixedChunker::new(params)),
        ChunkMode::Cdc => Box::new(RollingChunker::new(params)),
    }
}

/// High-throughput streaming chunk engine with strictly bounded memory (`ARCHITECTURE.md` §2).
///
/// Feeds chunks to a callback while calculating per-chunk BLAKE3 digests and
/// the whole-stream BLAKE3 digest in a single streaming pass. At no point is the
/// whole stream or file buffered in memory.
pub struct ChunkEngine;

impl ChunkEngine {
    /// Stream-chunks an `std::io::Read` source with a bounded read buffer.
    ///
    /// For every chunk identified by the chunker, invokes `on_chunk` with its [`ChunkDesc`]
    /// and payload slice.
    /// Returns the whole-stream BLAKE3 [`Hash`] and total bytes read.
    pub fn chunk_reader<R: std::io::Read, F>(
        mut reader: R,
        mode: ChunkMode,
        params: ChunkParams,
        read_buffer_size: usize,
        mut on_chunk: F,
    ) -> Result<(Hash, u64)>
    where
        F: FnMut(ChunkDesc, &[u8]) -> Result<()>,
    {
        let mut chunker = create_chunker(mode, params);
        let mut whole_hasher = blake3::Hasher::new();
        let mut read_buf = vec![0u8; read_buffer_size.max(4096)];
        let mut pending = Vec::with_capacity(params.max.max(read_buffer_size as u64) as usize);
        let mut pending_offset: u64 = 0;
        let mut total_bytes: u64 = 0;

        loop {
            let n = reader.read(&mut read_buf)?;
            if n == 0 {
                break;
            }
            let slice = &read_buf[..n];
            whole_hasher.update(slice);
            pending.extend_from_slice(slice);
            total_bytes += n as u64;

            let boundaries = chunker.push(slice)?;
            for b in boundaries {
                let target = b.end();
                let need = (target - pending_offset) as usize;
                let chunk_bytes = &pending[..need];
                let hash = Hash::of(chunk_bytes);
                let desc = ChunkDesc::new(need as u64, hash);
                on_chunk(desc, chunk_bytes)?;
                pending.drain(..need);
                pending_offset = target;
            }
        }

        if let Some(b) = chunker.finish()? {
            let target = b.end();
            let need = (target - pending_offset) as usize;
            let chunk_bytes = &pending[..need];
            let hash = Hash::of(chunk_bytes);
            let desc = ChunkDesc::new(need as u64, hash);
            on_chunk(desc, chunk_bytes)?;
            pending.drain(..need);
        }

        let whole_hash = Hash::from_bytes(whole_hasher.finalize().as_bytes()).unwrap();
        Ok((whole_hash, total_bytes))
    }
}

/// Delta reuse statistics between an original file/dataset and a modified version (`PERFORMANCE.md` §6).
#[derive(Debug, Clone, PartialEq)]
pub struct ReuseStats {
    /// Total bytes in the modified version.
    pub total_bytes: u64,
    /// Bytes from chunks that exist in the original chunk set.
    pub reused_bytes: u64,
    /// Total chunks in the modified version.
    pub total_chunks: usize,
    /// Chunks found in the original chunk set.
    pub reused_chunks: usize,
    /// Ratio of reused bytes to total bytes (0.0 to 1.0).
    pub byte_reuse_ratio: f64,
    /// Ratio of reused chunks to total chunks (0.0 to 1.0).
    pub chunk_reuse_ratio: f64,
}

impl ReuseStats {
    /// Compute reuse of `modified_chunks` against `original_chunks`.
    pub fn compute(original_chunks: &[ChunkDesc], modified_chunks: &[ChunkDesc]) -> Self {
        let original_hashes: std::collections::HashSet<Hash> =
            original_chunks.iter().filter_map(|c| c.hash).collect();

        let mut reused_bytes = 0u64;
        let mut reused_chunks = 0usize;
        let mut total_bytes = 0u64;

        for c in modified_chunks {
            total_bytes += c.length;
            if let Some(h) = c.hash {
                if original_hashes.contains(&h) {
                    reused_bytes += c.length;
                    reused_chunks += 1;
                }
            }
        }

        let byte_reuse_ratio = if total_bytes > 0 {
            reused_bytes as f64 / total_bytes as f64
        } else {
            1.0
        };

        let chunk_reuse_ratio = if !modified_chunks.is_empty() {
            reused_chunks as f64 / modified_chunks.len() as f64
        } else {
            1.0
        };

        Self {
            total_bytes,
            reused_bytes,
            total_chunks: modified_chunks.len(),
            reused_chunks,
            byte_reuse_ratio,
            chunk_reuse_ratio,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The GEAR table MUST be a permutation of `0..=255`. A chunker built on
    /// a non-permutation table degrades to poor hash distribution and breaks
    /// CDC's whole point. This test catches accidental copy-paste errors.
    #[test]
    fn gear_table_is_a_permutation() {
        let mut seen = [false; 256];
        for &b in GEAR.iter() {
            let i = b as usize;
            assert!(i < 256, "gear value {i} out of range");
            assert!(!seen[i], "gear value {i} appears twice");
            seen[i] = true;
        }
        assert!(seen.iter().all(|&x| x), "gear table misses some values");
    }

    fn chunk_all(input: &[u8], mode: &str) -> Vec<Vec<u8>> {
        let params = ChunkParams::default();
        let mut cursor: Box<dyn Chunker> = match mode {
            "fixed" => Box::new(FixedChunker::new(params)),
            "rolling" => Box::new(RollingChunker::new(params)),
            _ => panic!("unknown mode"),
        };
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut start = 0usize;
        let boundaries = cursor.push(input).unwrap();
        for b in boundaries {
            chunks.push(input[start..start + b.length as usize].to_vec());
            start += b.length as usize;
        }
        let last = cursor.finish().unwrap();
        if let Some(b) = last {
            chunks.push(input[start..start + b.length as usize].to_vec());
        }
        chunks
    }

    #[test]
    fn empty_input_yields_zero_chunks() {
        let params = ChunkParams::default();
        let mut c = RollingChunker::new(params);
        assert!(c.push(&[]).unwrap().is_empty());
        assert!(c.finish().unwrap().is_none());
        assert!(c.is_finished());
    }

    #[test]
    fn empty_input_yields_zero_chunks_fixed() {
        let params = ChunkParams::default();
        let mut c = FixedChunker::new(params);
        assert!(c.push(&[]).unwrap().is_empty());
        assert!(c.finish().unwrap().is_none());
    }

    #[test]
    fn concatenation_reproduces_input_rolling() {
        let inputs: Vec<Vec<u8>> = vec![
            vec![],
            vec![0; 1],
            vec![0; 4096],
            vec![0; 4097],
            (0..=255u8).cycle().take(100_000).collect(),
            (0..=255u8).cycle().take(1024 * 1024).collect(),
        ];
        for input in inputs {
            let chunks = chunk_all(&input, "rolling");
            let joined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
            assert_eq!(joined, input, "concat mismatch for len {}", input.len());
        }
    }

    #[test]
    fn concatenation_reproduces_input_fixed() {
        let inputs: Vec<Vec<u8>> = vec![
            vec![],
            vec![1, 2, 3],
            (0..=255u8).cycle().take(2 * 1024 * 1024).collect(),
        ];
        for input in inputs {
            let chunks = chunk_all(&input, "fixed");
            let joined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
            assert_eq!(joined, input);
        }
    }

    #[test]
    fn rolling_chunker_is_bounded_by_max() {
        let input = vec![0u8; 16 * 1024 * 1024];
        let chunks = chunk_all(&input, "rolling");
        for c in &chunks {
            assert!(c.len() as u64 <= CHUNK_DEFAULT_MAX);
        }
        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(joined.len(), input.len());
        assert_eq!(joined, input);
    }

    #[test]
    fn rolling_chunker_respects_min() {
        let params = ChunkParams::default();
        let mut c = RollingChunker::new(params);
        let input = vec![0u8; (params.min - 1) as usize];
        let bs = c.push(&input).unwrap();
        assert!(bs.is_empty(), "first chunk must not cut before min");
        let _ = c.finish().unwrap();
    }

    #[test]
    fn double_finish_is_an_error() {
        let mut c = RollingChunker::new(ChunkParams::default());
        c.finish().unwrap();
        assert!(c.finish().is_err());
    }

    #[test]
    fn push_after_finish_is_an_error() {
        let mut c = RollingChunker::new(ChunkParams::default());
        c.finish().unwrap();
        assert!(c.push(&[1, 2, 3]).is_err());
    }

    #[test]
    fn params_validation() {
        assert!(ChunkParams::new(0, 1024, 4096).is_none());
        assert!(ChunkParams::new(256, 1024, 256).is_none());
        assert!(ChunkParams::new(256, 1024, 1024).is_none());
        assert!(ChunkParams::new(256, 100, 4096).is_none());
        assert!(ChunkParams::new(256, 1024, 4096).is_some());
    }

    /// Boundary-stability property (`ADR-004`): inserting a small prefix
    /// shifts all boundaries by the size of the prefix, but the *deltas*
    /// between adjacent boundaries past the insertion point must match
    /// the deltas in the unprefixed file. This is the property that makes
    /// CDC worth its cost: distant chunks reuse even after small edits.
    #[test]
    fn boundary_stability_under_prefix_insertion() {
        let params = ChunkParams {
            min: 1024,
            target: 2048,
            max: 4096,
        };
        let base: Vec<u8> = (0..=255u8).cycle().take(64 * 1024).collect();
        let prefix = vec![0xAAu8; 32];
        let mut with_prefix = Vec::with_capacity(prefix.len() + base.len());
        with_prefix.extend_from_slice(&prefix);
        with_prefix.extend_from_slice(&base);

        let mut c1 = RollingChunker::new(params);
        let mut c2 = RollingChunker::new(params);
        let b1 = c1.push(&base).unwrap();
        let b2 = c2.push(&with_prefix).unwrap();
        let f1 = c1.finish().unwrap();
        let f2 = c2.finish().unwrap();
        let mut offsets1: Vec<u64> = b1.iter().map(|b| b.end()).collect();
        let mut offsets2: Vec<u64> = b2.iter().map(|b| b.end()).collect();
        if let Some(f) = f1 {
            offsets1.push(f.end());
        }
        if let Some(f) = f2 {
            offsets2.push(f.end());
        }

        // Compare deltas (gaps) in the two streams. The deltas must be
        // identical regardless of the absolute offsets — this is what
        // lets a content-defined chunker re-use the same chunks at the
        // same byte positions in the *new* file.
        let blast = 16 * 1024;
        // Skip the first delta after the blast radius — it necessarily
        // absorbs the prefix shift because the previous boundary lives at
        // a different position on each side. We compare the second and
        // later deltas: those capture gap-to-gap, which is what CDC
        // re-uses.
        let mut deltas1: Vec<u64> = offsets1
            .iter()
            .filter(|&&o| o >= blast)
            .scan(0u64, |prev, &o| {
                let d = o - *prev;
                *prev = o;
                Some(d)
            })
            .collect();
        let mut deltas2: Vec<u64> = offsets2
            .iter()
            .filter(|&&o| o >= blast + prefix.len() as u64)
            .scan(0u64, |prev, &o| {
                let d = o - *prev;
                *prev = o;
                Some(d)
            })
            .collect();
        if !deltas1.is_empty() {
            deltas1.remove(0);
        }
        if !deltas2.is_empty() {
            deltas2.remove(0);
        }
        // The last delta is the trailing partial chunk and naturally differs
        // when file size differs (it's `64 KiB - last_full_chunk`).
        if !deltas1.is_empty() {
            deltas1.pop();
        }
        if !deltas2.is_empty() {
            deltas2.pop();
        }
        assert_eq!(
            deltas1, deltas2,
            "boundary deltas past the insertion must match (deltas1={deltas1:?}, deltas2={deltas2:?})"
        );
    }

    #[test]
    fn params_fixed_constructor_and_helpers() {
        let fixed = ChunkParams::fixed(1024 * 1024);
        assert!(fixed.is_fixed());
        assert_eq!(fixed.min, 1024 * 1024);
        assert_eq!(fixed.target, 1024 * 1024);
        assert_eq!(fixed.max, 1024 * 1024);

        let from_new = ChunkParams::new(512, 512, 512).unwrap();
        assert!(from_new.is_fixed());

        let cdc = ChunkParams::cdc(256, 1024, 4096).unwrap();
        assert!(!cdc.is_fixed());
        assert_eq!(cdc.min, 256);
        assert_eq!(cdc.target, 1024);
        assert_eq!(cdc.max, 4096);
    }

    #[test]
    fn fixed_chunker_arbitrary_buffer_slicing() {
        let chunk_size = 1000u64;
        let params = ChunkParams::fixed(chunk_size);
        let mut chunker = FixedChunker::new(params);

        // Feed data in varying chunk sizes: 300, 700, 2500, 500
        let b1 = chunker.push(&vec![0u8; 300]).unwrap();
        assert!(b1.is_empty());

        let b2 = chunker.push(&vec![1u8; 700]).unwrap();
        assert_eq!(b2.len(), 1);
        assert_eq!(b2[0].offset, 0);
        assert_eq!(b2[0].length, 1000);

        let b3 = chunker.push(&vec![2u8; 2500]).unwrap();
        assert_eq!(b3.len(), 2);
        assert_eq!(b3[0].offset, 1000);
        assert_eq!(b3[0].length, 1000);
        assert_eq!(b3[1].offset, 2000);
        assert_eq!(b3[1].length, 1000);

        let b4 = chunker.push(&vec![3u8; 500]).unwrap();
        assert_eq!(b4.len(), 1);
        assert_eq!(b4[0].offset, 3000);
        assert_eq!(b4[0].length, 1000);

        let last = chunker.finish().unwrap();
        assert!(last.is_none());
        assert_eq!(chunker.offset(), 4000);
    }

    #[test]
    fn create_chunker_factory() {
        let fixed_params = ChunkParams::fixed(1024);
        let mut fixed_c = create_chunker(ChunkMode::Fixed, fixed_params);
        let b = fixed_c.push(&vec![0u8; 2048]).unwrap();
        assert_eq!(b.len(), 2);

        let cdc_params = ChunkParams::default();
        let cdc_c = create_chunker(ChunkMode::Cdc, cdc_params);
        assert_eq!(cdc_c.offset(), 0);
    }

    #[test]
    fn chunk_engine_reader_streaming() {
        let data: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        let expected_whole_hash = Hash::of(&data);

        let mut collected_chunks = Vec::new();
        let (whole_hash, total_bytes) = ChunkEngine::chunk_reader(
            data.as_slice(),
            ChunkMode::Fixed,
            ChunkParams::fixed(4000),
            1024,
            |desc, bytes| {
                assert_eq!(desc.length as usize, bytes.len());
                assert_eq!(desc.hash.unwrap(), Hash::of(bytes));
                collected_chunks.push(desc);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(total_bytes, 10_000);
        assert_eq!(whole_hash, expected_whole_hash);
        assert_eq!(collected_chunks.len(), 3);
        assert_eq!(collected_chunks[0].length, 4000);
        assert_eq!(collected_chunks[1].length, 4000);
        assert_eq!(collected_chunks[2].length, 2000);
    }

    #[test]
    fn reuse_stats_calculation() {
        let h1 = Hash::of(b"chunk1");
        let h2 = Hash::of(b"chunk2");
        let h3 = Hash::of(b"chunk3");
        let h4 = Hash::of(b"chunk4");

        let orig = vec![
            ChunkDesc::new(1000, h1),
            ChunkDesc::new(1000, h2),
            ChunkDesc::new(1000, h3),
        ];

        let modified = vec![
            ChunkDesc::new(500, h4),  // new chunk
            ChunkDesc::new(1000, h2), // reused
            ChunkDesc::new(1000, h3), // reused
        ];

        let stats = ReuseStats::compute(&orig, &modified);
        assert_eq!(stats.total_bytes, 2500);
        assert_eq!(stats.reused_bytes, 2000);
        assert_eq!(stats.total_chunks, 3);
        assert_eq!(stats.reused_chunks, 2);
        assert!((stats.byte_reuse_ratio - 0.8).abs() < 1e-6);
        assert!((stats.chunk_reuse_ratio - (2.0 / 3.0)).abs() < 1e-6);
    }
}
