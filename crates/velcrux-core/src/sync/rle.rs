//! Run-length encoded bitmap for chunk have/need negotiation (`PROTOCOL.md` §4).

use super::SyncError;
use crate::protocol::varint;
use bytes::Bytes;

/// A single run in an RLE bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RleRun {
    /// Bit value: `true` indicates destination has the chunk, `false` indicates missing.
    pub bit: bool,
    /// Number of consecutive chunks with this status.
    pub count: u32,
}

/// Run-length encoded bitmap representing chunk presence status.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RleBitmap {
    runs: Vec<RleRun>,
    total_chunks: u32,
    have_count: u32,
}

impl RleBitmap {
    /// Construct an RLE bitmap from a slice of booleans (`true` = have, `false` = need).
    pub fn from_bits(bits: &[bool]) -> Self {
        if bits.is_empty() {
            return Self::default();
        }

        let mut runs = Vec::new();
        let mut current_bit = bits[0];
        let mut current_count: u32 = 0;
        let mut have_count: u32 = 0;

        for &bit in bits {
            if bit {
                have_count = have_count.saturating_add(1);
            }
            if bit == current_bit {
                current_count = current_count.saturating_add(1);
            } else {
                runs.push(RleRun {
                    bit: current_bit,
                    count: current_count,
                });
                current_bit = bit;
                current_count = 1;
            }
        }
        if current_count > 0 {
            runs.push(RleRun {
                bit: current_bit,
                count: current_count,
            });
        }

        Self {
            runs,
            total_chunks: bits.len() as u32,
            have_count,
        }
    }

    /// Construct directly from runs and validate counts.
    pub fn from_runs(runs: Vec<RleRun>) -> Result<Self, SyncError> {
        let mut total_chunks: u32 = 0;
        let mut have_count: u32 = 0;

        for run in &runs {
            if run.count == 0 {
                return Err(SyncError::Rle("run count cannot be zero".into()));
            }
            total_chunks = total_chunks
                .checked_add(run.count)
                .ok_or_else(|| SyncError::Rle("total chunk count overflowed u32".into()))?;
            if run.bit {
                have_count = have_count
                    .checked_add(run.count)
                    .ok_or_else(|| SyncError::Rle("have count overflowed u32".into()))?;
            }
        }

        Ok(Self {
            runs,
            total_chunks,
            have_count,
        })
    }

    /// Total number of chunks represented.
    #[inline]
    pub fn total_chunks(&self) -> u32 {
        self.total_chunks
    }

    /// Number of chunks the receiver already has (`bit == true`).
    #[inline]
    pub fn have_count(&self) -> u32 {
        self.have_count
    }

    /// Number of chunks the receiver needs from the sender (`bit == false`).
    #[inline]
    pub fn need_count(&self) -> u32 {
        self.total_chunks.saturating_sub(self.have_count)
    }

    /// Returns the underlying runs.
    #[inline]
    pub fn runs(&self) -> &[RleRun] {
        &self.runs
    }

    /// Returns the status of the chunk at `index` (`true` = have, `false` = need),
    /// or `None` if `index >= total_chunks`.
    pub fn get(&self, index: usize) -> Option<bool> {
        if index >= self.total_chunks as usize {
            return None;
        }
        let mut cursor = 0usize;
        for run in &self.runs {
            let next = cursor + run.count as usize;
            if index < next {
                return Some(run.bit);
            }
            cursor = next;
        }
        None
    }

    /// Expand the RLE bitmap back into a boolean vector.
    pub fn to_bits(&self) -> Vec<bool> {
        let mut out = Vec::with_capacity(self.total_chunks as usize);
        for run in &self.runs {
            out.resize(out.len() + run.count as usize, run.bit);
        }
        out
    }

    /// Encode the runs into binary payload.
    ///
    /// Each run is serialized as a LEB128 varint: `(count << 1) | (bit as u64)`.
    pub fn encode(&self) -> Bytes {
        let mut buf = Vec::with_capacity(self.runs.len() * 3);
        let mut tmp = [0u8; 10];
        for run in &self.runs {
            let payload = ((run.count as u64) << 1) | if run.bit { 1 } else { 0 };
            let n = varint::encode_varint(payload, &mut tmp);
            buf.extend_from_slice(&tmp[..n]);
        }
        Bytes::from(buf)
    }

    /// Decode runs from binary payload given `expected_total_chunks`.
    pub fn decode(buf: &[u8], expected_total_chunks: u32) -> Result<Self, SyncError> {
        if expected_total_chunks == 0 {
            if !buf.is_empty() {
                return Err(SyncError::Rle(
                    "expected 0 chunks but buffer not empty".into(),
                ));
            }
            return Ok(Self::default());
        }

        let mut runs = Vec::new();
        let mut offset = 0;
        let mut total_chunks: u32 = 0;
        let mut have_count: u32 = 0;

        while offset < buf.len() {
            let (val, consumed) = varint::decode_varint(&buf[offset..])
                .map_err(|e| SyncError::Rle(format!("varint decode failed: {e}")))?;
            offset += consumed;

            let bit = (val & 1) == 1;
            let count_u64 = val >> 1;
            if count_u64 == 0 {
                return Err(SyncError::Rle("decoded zero run count".into()));
            }
            if count_u64 > u32::MAX as u64 {
                return Err(SyncError::Rle("run count exceeds u32::MAX".into()));
            }
            let count = count_u64 as u32;

            total_chunks = total_chunks
                .checked_add(count)
                .ok_or_else(|| SyncError::Rle("total chunk count overflowed".into()))?;

            if bit {
                have_count = have_count
                    .checked_add(count)
                    .ok_or_else(|| SyncError::Rle("have count overflowed".into()))?;
            }

            runs.push(RleRun { bit, count });
        }

        if total_chunks != expected_total_chunks {
            return Err(SyncError::Rle(format!(
                "chunk count mismatch: expected {expected_total_chunks}, decoded {total_chunks}"
            )));
        }

        Ok(Self {
            runs,
            total_chunks,
            have_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rle_empty() {
        let rle = RleBitmap::from_bits(&[]);
        assert_eq!(rle.total_chunks(), 0);
        assert_eq!(rle.have_count(), 0);
        assert_eq!(rle.need_count(), 0);
        assert!(rle.to_bits().is_empty());
        let encoded = rle.encode();
        assert!(encoded.is_empty());
        let decoded = RleBitmap::decode(&encoded, 0).unwrap();
        assert_eq!(rle, decoded);
    }

    #[test]
    fn rle_roundtrip_various_patterns() {
        let patterns: Vec<Vec<bool>> = vec![
            vec![true; 100],
            vec![false; 500],
            vec![true, false, true, false, true],
            {
                let mut p = vec![true; 200];
                p.extend_from_slice(&[false; 10]);
                p.extend_from_slice(&[true; 100_000]);
                p
            },
        ];

        for pattern in patterns {
            let rle = RleBitmap::from_bits(&pattern);
            assert_eq!(rle.total_chunks(), pattern.len() as u32);
            assert_eq!(rle.to_bits(), pattern);

            for i in [0, 1, pattern.len() / 2, pattern.len() - 1] {
                assert_eq!(rle.get(i), Some(pattern[i]));
            }
            assert_eq!(rle.get(pattern.len()), None);

            let encoded = rle.encode();
            let decoded = RleBitmap::decode(&encoded, pattern.len() as u32).unwrap();
            assert_eq!(rle, decoded);
        }
    }
}
