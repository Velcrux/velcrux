//! Bounded-memory chunk completion bitmap.
//!
//! Per `CLAUDE.md` §1 #3 nothing in this project is sized by the file or
//! dataset. The set of completed chunk indices is therefore a sparse
//! `BTreeSet<u64>` rather than a `Vec<bool>` proportional to the file.
//! Memory is `O(completed_chunks)` and the persisted form is the sorted
//! list of those indices.
//!
//! The wire/persisted codec is a length-prefixed `Vec<u64>` of sorted,
//! distinct chunk indices. Length is varint, each entry is varint.
//! Decoders reject non-canonical encodings and reject entries that are
//! not strictly increasing.
//!
//! The `roaring` crate is intentionally not pulled in for M3: the sparse
//! set is bounded by the per-transfer checkpoint cadence, and ADR-005's
//! note about roaring applies once the manifest pipeline (M5) needs
//! per-batch dense bitmaps.

use std::collections::BTreeSet;

use crate::error::ProtocolError;
use crate::protocol::varint;

/// Maximum number of distinct chunk indices that may be transmitted in
/// a single wire field (CHECKPOINT / RESUME_STATE). 1 M chunks at the
/// maximum 4 MiB chunk size is about 4 PiB, well past any practical
/// single transfer; this is a hard wire-side bound checked *before* any
/// allocation (`CLAUDE.md` §1 #5).
pub const MAX_WIRE_CHUNKS: u64 = 1_000_000;

/// Sparse set of completed chunk indices. Bounded memory: `O(n)` in
/// the number of completed chunks, never `O(file)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChunkBitmap {
    /// Sorted set of completed chunk indices.
    set: BTreeSet<u64>,
    /// Running total of bytes that the bitmap represents.
    bytes_completed: u64,
}

impl ChunkBitmap {
    /// Construct an empty bitmap.
    pub fn new() -> Self {
        Self {
            set: BTreeSet::new(),
            bytes_completed: 0,
        }
    }

    /// Construct from a pre-populated sorted, distinct list of indices.
    pub fn from_sorted_indices(indices: &[u64], bytes_completed: u64) -> Self {
        let mut set = BTreeSet::new();
        for &i in indices {
            set.insert(i);
        }
        Self {
            set,
            bytes_completed,
        }
    }

    /// Mark chunk `index` complete with `chunk_len` bytes. Returns true
    /// if newly inserted (duplicate inserts are idempotent and do not
    /// double-count bytes).
    pub fn mark_complete(&mut self, index: u64, chunk_len: u64) -> bool {
        if self.set.insert(index) {
            self.bytes_completed = self.bytes_completed.saturating_add(chunk_len);
            true
        } else {
            false
        }
    }

    /// True if `index` is in the set.
    pub fn contains(&self, index: u64) -> bool {
        self.set.contains(&index)
    }

    /// Number of completed chunks.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// True if no chunks have been marked complete.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Bytes completed (running total maintained on insert).
    pub fn bytes_completed(&self) -> u64 {
        self.bytes_completed
    }

    /// All completed indices, in ascending order.
    pub fn indices(&self) -> impl Iterator<Item = u64> + '_ {
        self.set.iter().copied()
    }

    /// Number of *missing* chunks in `0..total_chunks`.
    pub fn missing_count(&self, total_chunks: u64) -> u64 {
        let completed = (self.set.len() as u64).min(total_chunks);
        total_chunks.saturating_sub(completed)
    }

    /// First chunk index that is *not* in the set, starting at `from`.
    /// Returns `None` if every index >= from is complete.
    pub fn first_missing_from(&self, from: u64) -> Option<u64> {
        let mut i = from;
        while self.set.contains(&i) {
            i = i.saturating_add(1);
            if i == u64::MAX {
                return None;
            }
        }
        Some(i)
    }

    /// Encode the bitmap as `varint(count) || varint(idx_0) || ...`.
    /// The count is checked against `max_entries` before any payload is
    /// written.
    pub fn encode(&self, out: &mut Vec<u8>, max_entries: u64) -> Result<(), ProtocolError> {
        let n = self.set.len() as u64;
        if n > max_entries || n > MAX_WIRE_CHUNKS {
            return Err(ProtocolError::Malformed("too many completed chunks"));
        }
        let mut tmp = [0u8; 10];
        let n_bytes = varint::encode_varint(n, &mut tmp);
        out.extend_from_slice(&tmp[..n_bytes]);
        for idx in &self.set {
            let b = varint::encode_varint(*idx, &mut tmp);
            out.extend_from_slice(&tmp[..b]);
        }
        Ok(())
    }

    /// Decode a bitmap from a length-prefixed varint array. Rejects
    /// over-long, non-canonical, or non-monotonic encodings.
    pub fn decode(buf: &[u8], bytes_completed: u64) -> Result<Self, ProtocolError> {
        let (n, mut pos) = varint::decode_varint(buf)?;
        if n > MAX_WIRE_CHUNKS {
            return Err(ProtocolError::Malformed("too many completed chunks"));
        }
        let mut set = BTreeSet::new();
        let mut prev: Option<u64> = None;
        for _ in 0..n {
            if pos >= buf.len() {
                return Err(ProtocolError::Malformed("truncated chunk index"));
            }
            let (idx, consumed) = varint::decode_varint(&buf[pos..])?;
            pos += consumed;
            if let Some(p) = prev {
                if idx <= p {
                    return Err(ProtocolError::Malformed("non-monotonic chunk index list"));
                }
            }
            set.insert(idx);
            prev = Some(idx);
        }
        Ok(Self {
            set,
            bytes_completed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_complete_idempotent() {
        let mut bm = ChunkBitmap::new();
        assert!(bm.mark_complete(0, 1024));
        assert!(!bm.mark_complete(0, 1024));
        assert_eq!(bm.len(), 1);
        assert_eq!(bm.bytes_completed(), 1024);
    }

    #[test]
    fn bytes_completed_saturates() {
        let mut bm = ChunkBitmap::new();
        bm.mark_complete(0, u64::MAX);
        bm.mark_complete(1, 16);
        assert_eq!(bm.bytes_completed(), u64::MAX);
    }

    #[test]
    fn first_missing_from() {
        let mut bm = ChunkBitmap::new();
        assert_eq!(bm.first_missing_from(0), Some(0));
        bm.mark_complete(0, 1);
        bm.mark_complete(1, 1);
        bm.mark_complete(2, 1);
        assert_eq!(bm.first_missing_from(0), Some(3));
        assert_eq!(bm.first_missing_from(1), Some(3));
        assert_eq!(bm.first_missing_from(3), Some(3));
        assert_eq!(bm.first_missing_from(4), Some(4));
    }

    #[test]
    fn roundtrip_empty() {
        let bm = ChunkBitmap::new();
        let mut buf = Vec::new();
        bm.encode(&mut buf, MAX_WIRE_CHUNKS).unwrap();
        let bm2 = ChunkBitmap::decode(&buf, 0).unwrap();
        assert_eq!(bm, bm2);
    }

    #[test]
    fn roundtrip_sparse() {
        let mut bm = ChunkBitmap::new();
        for i in [0u64, 5, 9, 1023, 999_999] {
            bm.mark_complete(i, 4096);
        }
        let mut buf = Vec::new();
        bm.encode(&mut buf, MAX_WIRE_CHUNKS).unwrap();
        let bm2 = ChunkBitmap::decode(&buf, bm.bytes_completed()).unwrap();
        assert_eq!(bm, bm2);
    }

    fn write_varint(out: &mut Vec<u8>, v: u64) {
        let mut tmp = [0u8; 10];
        let n = varint::encode_varint(v, &mut tmp);
        out.extend_from_slice(&tmp[..n]);
    }

    #[test]
    fn reject_non_monotonic() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 2);
        write_varint(&mut buf, 5);
        write_varint(&mut buf, 3);
        assert!(ChunkBitmap::decode(&buf, 0).is_err());
    }

    #[test]
    fn reject_duplicate_indices() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 2);
        write_varint(&mut buf, 7);
        write_varint(&mut buf, 7);
        assert!(ChunkBitmap::decode(&buf, 0).is_err());
    }

    #[test]
    fn reject_truncated() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 3);
        write_varint(&mut buf, 1);
        assert!(ChunkBitmap::decode(&buf, 0).is_err());
    }

    #[test]
    fn reject_oversized_count() {
        let mut buf = Vec::new();
        write_varint(&mut buf, MAX_WIRE_CHUNKS + 1);
        assert!(ChunkBitmap::decode(&buf, 0).is_err());
    }

    #[test]
    fn encode_rejects_oversized_set() {
        let bm = ChunkBitmap {
            set: (0..(MAX_WIRE_CHUNKS + 2)).collect(),
            bytes_completed: 0,
        };
        let mut buf = Vec::new();
        assert!(bm.encode(&mut buf, MAX_WIRE_CHUNKS).is_err());
    }

    #[test]
    fn missing_count_bounded_by_total() {
        let mut bm = ChunkBitmap::new();
        bm.mark_complete(0, 1);
        assert_eq!(bm.missing_count(10), 9);
        assert_eq!(bm.missing_count(0), 0);
    }
}
