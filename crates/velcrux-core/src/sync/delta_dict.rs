//! Content-Aware Delta Compression Engine with Zstd Dictionary Training & CDC Slicing (Option BQ).
//!
//! Provides content-aware delta compression between modified files or chunks using
//! dynamically constructed dictionaries from baseline reference extents and CDC sub-slicing.
//!
//! # Problem
//! In standard delta synchronization (CDC or fixed chunking), when a chunk is modified
//! even by a few bytes, its BLAKE3 hash changes and the entire chunk (e.g. 256 KiB - 1 MiB)
//! must be transferred over the wire. Standard standalone Zstandard compression on small
//! individual chunks achieves only modest compression (1.2x - 2x) because the LZ77 sliding
//! window has no prior context.
//!
//! # Solution
//! 1. `ContentDeltaEngine`: Uses the corresponding baseline reference extent as an instantaneous
//!    pre-trained dictionary for Zstandard (`zstd::bulk::compress_using_dict`).
//! 2. `DeltaDictPolicy`: Configurable policy (`Auto`, `Off`, `Aggressive`) with adaptive savings
//!    thresholding to prevent compression regressions.
//! 3. `DeltaSlice`: Canonical self-describing framing for raw, vanilla zstd, and dictionary-compressed
//!    delta slices with whole-chunk BLAKE3 verification.
//! 4. Bounded memory: All operations stream chunk-by-chunk without loading full files into RAM.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, VelcruxError};
use crate::util::Hash;

/// Magic byte identifier for delta slice envelopes (0xDE17 -> "DELT").
pub const DELTA_SLICE_MAGIC: u16 = 0xDE17;

/// Maximum reference dictionary window size sampled from baseline (128 KiB).
pub const MAX_DELTA_DICT_WINDOW: usize = 128 * 1024;

/// Default compression level for delta dictionary compression (level 3 for balanced CPU/ratio).
pub const DEFAULT_DELTA_COMPRESSION_LEVEL: i32 = 3;

/// Default minimum savings percentage (15%) required to adopt dictionary compression over raw.
pub const DEFAULT_DELTA_DICT_THRESHOLD_PCT: u8 = 15;

/// Delta dictionary compression policy (`Option BQ`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeltaDictPolicy {
    /// Automatically apply dictionary compression against baseline extents when savings exceed threshold (default).
    #[default]
    Auto,
    /// Disable delta dictionary compression (transfer standard chunks or vanilla zstd).
    Off,
    /// Aggressively test candidate reference windows with a lower savings threshold (5%).
    Aggressive,
}

impl fmt::Display for DeltaDictPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeltaDictPolicy::Auto => write!(f, "auto"),
            DeltaDictPolicy::Off => write!(f, "off"),
            DeltaDictPolicy::Aggressive => write!(f, "aggressive"),
        }
    }
}

impl FromStr for DeltaDictPolicy {
    type Err = VelcruxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "default" => Ok(DeltaDictPolicy::Auto),
            "off" | "none" | "disabled" => Ok(DeltaDictPolicy::Off),
            "aggressive" | "high" | "max" => Ok(DeltaDictPolicy::Aggressive),
            other => Err(VelcruxError::Config(format!(
                "invalid delta dict policy '{other}'; expected auto, off, or aggressive"
            ))),
        }
    }
}

/// Compression format utilized for a delta slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DeltaCompressionKind {
    /// Raw uncompressed chunk literal.
    RawLiteral = 0,
    /// Standalone Zstandard compression without dictionary.
    VanillaZstd = 1,
    /// Content-aware Zstandard compression using baseline dictionary slice.
    DictDelta = 2,
    /// Identical chunk match (0 payload bytes transferred, copied locally).
    ExactMatch = 3,
}

impl DeltaCompressionKind {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(DeltaCompressionKind::RawLiteral),
            1 => Some(DeltaCompressionKind::VanillaZstd),
            2 => Some(DeltaCompressionKind::DictDelta),
            3 => Some(DeltaCompressionKind::ExactMatch),
            _ => None,
        }
    }
}

/// Header describing a delta slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaSliceHeader {
    /// Magic identifier (0xDE17).
    pub magic: u16,
    /// Compression kind.
    pub kind: DeltaCompressionKind,
    /// Original uncompressed chunk length in bytes.
    pub original_length: u32,
    /// Compressed payload length in bytes.
    pub compressed_length: u32,
    /// Byte offset within the baseline file used as dictionary (if DictDelta).
    pub ref_offset: u64,
    /// Length of the baseline dictionary slice in bytes (if DictDelta).
    pub ref_length: u32,
    /// BLAKE3 digest of the uncompressed chunk.
    pub chunk_hash: Hash,
}

/// A complete self-describing delta slice containing metadata header and payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaSlice {
    pub header: DeltaSliceHeader,
    pub payload: Vec<u8>,
}

impl DeltaSlice {
    /// Serialize the delta slice into a canonical binary byte buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 1 + 4 + 4 + 8 + 4 + 32 + self.payload.len());
        buf.extend_from_slice(&self.header.magic.to_le_bytes());
        buf.push(self.header.kind as u8);
        buf.extend_from_slice(&self.header.original_length.to_le_bytes());
        buf.extend_from_slice(&self.header.compressed_length.to_le_bytes());
        buf.extend_from_slice(&self.header.ref_offset.to_le_bytes());
        buf.extend_from_slice(&self.header.ref_length.to_le_bytes());
        buf.extend_from_slice(self.header.chunk_hash.as_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize a delta slice from a binary slice. Returns `(DeltaSlice, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), VelcruxError> {
        const HEADER_LEN: usize = 2 + 1 + 4 + 4 + 8 + 4 + 32;
        if buf.len() < HEADER_LEN {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "truncated delta slice header",
            )));
        }

        let magic = u16::from_le_bytes([buf[0], buf[1]]);
        if magic != DELTA_SLICE_MAGIC {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "invalid delta slice magic identifier",
            )));
        }

        let kind = DeltaCompressionKind::from_u8(buf[2]).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("invalid delta compression kind"))
        })?;

        let original_length = u32::from_le_bytes([buf[3], buf[4], buf[5], buf[6]]);
        let compressed_length = u32::from_le_bytes([buf[7], buf[8], buf[9], buf[10]]);
        let ref_offset = u64::from_le_bytes([
            buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18],
        ]);
        let ref_length = u32::from_le_bytes([buf[19], buf[20], buf[21], buf[22]]);

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&buf[23..55]);
        let chunk_hash = Hash::from_bytes(&hash_bytes).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("invalid delta chunk hash"))
        })?;

        let total_len = HEADER_LEN + compressed_length as usize;
        if buf.len() < total_len {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "truncated delta slice payload",
            )));
        }

        let payload = buf[HEADER_LEN..total_len].to_vec();
        Ok((
            DeltaSlice {
                header: DeltaSliceHeader {
                    magic,
                    kind,
                    original_length,
                    compressed_length,
                    ref_offset,
                    ref_length,
                    chunk_hash,
                },
                payload,
            },
            total_len,
        ))
    }
}

/// Aggregate performance statistics for content-aware delta compression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeltaCompressionReport {
    /// Raw uncompressed bytes across all evaluated chunks.
    pub original_bytes: u64,
    /// Transferred compressed bytes over wire.
    pub transferred_bytes: u64,
    /// Total bytes saved by delta dictionary compression and chunk reuse.
    pub bytes_saved: u64,
    /// Aggregate compression ratio (original_bytes / transferred_bytes).
    pub compression_ratio: f64,
    /// Total chunks that matched baseline identically (zero bytes transferred).
    pub exact_matches: usize,
    /// Total chunks compressed using baseline dictionary.
    pub dict_compressed_chunks: usize,
    /// Total chunks compressed with standalone Zstandard.
    pub vanilla_compressed_chunks: usize,
    /// Total chunks transferred as raw literals.
    pub raw_literal_chunks: usize,
}

impl DeltaCompressionReport {
    /// Render human-readable performance summary.
    pub fn format_display(&self) -> String {
        format!(
            "Delta Slicing & Dictionary Compression Summary:\n\
             Original Bytes      : {:>10} B\n\
             Transferred Bytes   : {:>10} B\n\
             Bytes Saved         : {:>10} B ({:.1}%)\n\
             Compression Ratio   : {:>10.2}x\n\
             Exact Chunk Matches : {:>10}\n\
             Dict-Delta Chunks   : {:>10}\n\
             Vanilla Zstd Chunks : {:>10}\n\
             Raw Literal Chunks  : {:>10}",
            self.original_bytes,
            self.transferred_bytes,
            self.bytes_saved,
            if self.original_bytes > 0 {
                (self.bytes_saved as f64 / self.original_bytes as f64) * 100.0
            } else {
                0.0
            },
            self.compression_ratio,
            self.exact_matches,
            self.dict_compressed_chunks,
            self.vanilla_compressed_chunks,
            self.raw_literal_chunks,
        )
    }
}

/// Content-Aware Delta Compression Engine.
pub struct ContentDeltaEngine {
    policy: DeltaDictPolicy,
    threshold_pct: u8,
    level: i32,
}

impl Default for ContentDeltaEngine {
    fn default() -> Self {
        Self::new(
            DeltaDictPolicy::Auto,
            DEFAULT_DELTA_DICT_THRESHOLD_PCT,
            DEFAULT_DELTA_COMPRESSION_LEVEL,
        )
    }
}

impl ContentDeltaEngine {
    /// Construct a new content-aware delta compression engine.
    pub fn new(policy: DeltaDictPolicy, threshold_pct: u8, level: i32) -> Self {
        Self {
            policy,
            threshold_pct,
            level,
        }
    }

    /// Configure the delta dictionary policy.
    pub fn with_policy(mut self, policy: DeltaDictPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Configure minimum savings percentage threshold.
    pub fn with_threshold(mut self, threshold_pct: u8) -> Self {
        self.threshold_pct = threshold_pct;
        self
    }

    /// Compress a modified chunk against an optional baseline file extent.
    pub fn compress_chunk(
        &self,
        chunk_data: &[u8],
        chunk_hash: Hash,
        baseline_file: Option<&mut File>,
        baseline_offset: u64,
    ) -> Result<DeltaSlice, VelcruxError> {
        let orig_len = chunk_data.len() as u32;

        if self.policy == DeltaDictPolicy::Off || orig_len == 0 {
            // Policy off: fallback to vanilla zstd or raw literal
            let vanilla = zstd::bulk::compress(chunk_data, self.level)
                .map_err(|e| VelcruxError::Internal(format!("zstd compress failed: {e}")))?;

            if vanilla.len() < chunk_data.len() {
                return Ok(DeltaSlice {
                    header: DeltaSliceHeader {
                        magic: DELTA_SLICE_MAGIC,
                        kind: DeltaCompressionKind::VanillaZstd,
                        original_length: orig_len,
                        compressed_length: vanilla.len() as u32,
                        ref_offset: 0,
                        ref_length: 0,
                        chunk_hash,
                    },
                    payload: vanilla,
                });
            } else {
                return Ok(DeltaSlice {
                    header: DeltaSliceHeader {
                        magic: DELTA_SLICE_MAGIC,
                        kind: DeltaCompressionKind::RawLiteral,
                        original_length: orig_len,
                        compressed_length: orig_len,
                        ref_offset: 0,
                        ref_length: 0,
                        chunk_hash,
                    },
                    payload: chunk_data.to_vec(),
                });
            }
        }

        // Try reading reference window from baseline file
        let mut ref_slice_buf = Vec::new();
        let mut actual_ref_offset = baseline_offset;

        if let Some(bf) = baseline_file {
            let win_size = (chunk_data.len() * 2).clamp(16 * 1024, MAX_DELTA_DICT_WINDOW);
            // In aggressive mode, allow reading slightly before baseline_offset to catch insertions
            let read_start = if self.policy == DeltaDictPolicy::Aggressive {
                baseline_offset.saturating_sub((win_size / 4) as u64)
            } else {
                baseline_offset
            };

            if let Ok(_) = bf.seek(SeekFrom::Start(read_start)) {
                let mut temp = vec![0u8; win_size];
                if let Ok(n) = bf.read(&mut temp) {
                    if n > 0 {
                        temp.truncate(n);
                        ref_slice_buf = temp;
                        actual_ref_offset = read_start;
                    }
                }
            }
        }

        // Evaluate dictionary compression if reference slice is available
        let mut best_slice: Option<(DeltaCompressionKind, Vec<u8>, u64, u32)> = None;

        if !ref_slice_buf.is_empty() {
            if let Ok(dict_compressed) =
                crate::protocol::compress_with_dict(chunk_data, self.level, &ref_slice_buf)
            {
                let dict_len = dict_compressed.len();
                let threshold = if self.policy == DeltaDictPolicy::Aggressive {
                    5
                } else {
                    self.threshold_pct
                };

                // Check if savings threshold over raw chunk is satisfied
                let savings_bytes = (chunk_data.len() as i64) - (dict_len as i64);
                let savings_pct = if chunk_data.len() > 0 {
                    (savings_bytes.max(0) as f64 / chunk_data.len() as f64) * 100.0
                } else {
                    0.0
                };

                if savings_pct >= (threshold as f64) {
                    best_slice = Some((
                        DeltaCompressionKind::DictDelta,
                        dict_compressed,
                        actual_ref_offset,
                        ref_slice_buf.len() as u32,
                    ));
                }
            }
        }

        // Evaluate standalone vanilla zstd compression
        let vanilla_compressed = zstd::bulk::compress(chunk_data, self.level)
            .map_err(|e| VelcruxError::Internal(format!("zstd compress failed: {e}")))?;

        match best_slice {
            Some((kind, payload, r_off, r_len)) => {
                // If vanilla was somehow smaller, prefer vanilla
                if vanilla_compressed.len() < payload.len() {
                    Ok(DeltaSlice {
                        header: DeltaSliceHeader {
                            magic: DELTA_SLICE_MAGIC,
                            kind: DeltaCompressionKind::VanillaZstd,
                            original_length: orig_len,
                            compressed_length: vanilla_compressed.len() as u32,
                            ref_offset: 0,
                            ref_length: 0,
                            chunk_hash,
                        },
                        payload: vanilla_compressed,
                    })
                } else {
                    Ok(DeltaSlice {
                        header: DeltaSliceHeader {
                            magic: DELTA_SLICE_MAGIC,
                            kind,
                            original_length: orig_len,
                            compressed_length: payload.len() as u32,
                            ref_offset: r_off,
                            ref_length: r_len,
                            chunk_hash,
                        },
                        payload,
                    })
                }
            }
            None => {
                if vanilla_compressed.len() < chunk_data.len() {
                    Ok(DeltaSlice {
                        header: DeltaSliceHeader {
                            magic: DELTA_SLICE_MAGIC,
                            kind: DeltaCompressionKind::VanillaZstd,
                            original_length: orig_len,
                            compressed_length: vanilla_compressed.len() as u32,
                            ref_offset: 0,
                            ref_length: 0,
                            chunk_hash,
                        },
                        payload: vanilla_compressed,
                    })
                } else {
                    Ok(DeltaSlice {
                        header: DeltaSliceHeader {
                            magic: DELTA_SLICE_MAGIC,
                            kind: DeltaCompressionKind::RawLiteral,
                            original_length: orig_len,
                            compressed_length: orig_len,
                            ref_offset: 0,
                            ref_length: 0,
                            chunk_hash,
                        },
                        payload: chunk_data.to_vec(),
                    })
                }
            }
        }
    }

    /// Decompress a delta slice back into its original raw chunk bytes.
    pub fn decompress_chunk(
        &self,
        slice: &DeltaSlice,
        baseline_file: Option<&mut File>,
    ) -> Result<Vec<u8>, VelcruxError> {
        let orig_len = slice.header.original_length as usize;

        let decompressed = match slice.header.kind {
            DeltaCompressionKind::RawLiteral => slice.payload.clone(),
            DeltaCompressionKind::VanillaZstd => zstd::bulk::decompress(&slice.payload, orig_len)
                .map_err(|_e| {
                VelcruxError::Protocol(ProtocolError::Malformed("zstd decompress failed"))
            })?,
            DeltaCompressionKind::DictDelta => {
                let bf = baseline_file.ok_or_else(|| {
                    VelcruxError::Protocol(ProtocolError::Malformed(
                        "dict-delta slice requires baseline file handle",
                    ))
                })?;

                bf.seek(SeekFrom::Start(slice.header.ref_offset))?;
                let mut dict_buf = vec![0u8; slice.header.ref_length as usize];
                bf.read_exact(&mut dict_buf)?;

                crate::protocol::decompress_with_dict_bounded(
                    &slice.payload,
                    &dict_buf,
                    orig_len,
                    None,
                )
                .map_err(|_e| {
                    VelcruxError::Protocol(ProtocolError::Malformed("zstd dict decompress failed"))
                })?
            }
            DeltaCompressionKind::ExactMatch => {
                return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                    "exact match slice carries no payload",
                )));
            }
        };

        if decompressed.len() != orig_len {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "decompressed length mismatch",
            )));
        }

        // Verify hash integrity
        let hash = Hash::of(&decompressed);
        if hash != slice.header.chunk_hash {
            return Err(VelcruxError::Protocol(ProtocolError::ChecksumMismatch {
                chunk_index: 0,
                expected: slice.header.chunk_hash,
                actual: hash,
            }));
        }

        Ok(decompressed)
    }

    /// Evaluate delta dictionary compression between two in-memory file buffers.
    pub fn evaluate_delta(
        &self,
        target_data: &[u8],
        baseline_data: &[u8],
        chunk_size: usize,
    ) -> DeltaCompressionReport {
        let mut total_orig = 0u64;
        let mut total_wire = 0u64;
        let mut exact_matches = 0;
        let mut dict_chunks = 0;
        let mut vanilla_chunks = 0;
        let mut raw_chunks = 0;

        let mut offset = 0;
        while offset < target_data.len() {
            let end = (offset + chunk_size).min(target_data.len());
            let chunk = &target_data[offset..end];
            total_orig += chunk.len() as u64;

            // Check exact match in baseline at same offset
            if offset < baseline_data.len() {
                let base_end = (offset + chunk.len()).min(baseline_data.len());
                let base_chunk = &baseline_data[offset..base_end];
                if chunk == base_chunk {
                    exact_matches += 1;
                    offset = end;
                    continue;
                }
            }

            // Reference slice around offset
            let ref_start = offset.saturating_sub(16 * 1024);
            let ref_end = (offset + chunk.len() + 16 * 1024).min(baseline_data.len());
            let ref_slice = if ref_start < baseline_data.len() {
                &baseline_data[ref_start..ref_end]
            } else {
                &[]
            };

            let vanilla =
                zstd::bulk::compress(chunk, self.level).unwrap_or_else(|_| chunk.to_vec());
            let dict = if !ref_slice.is_empty() {
                crate::protocol::compress_with_dict(chunk, self.level, ref_slice)
                    .unwrap_or_else(|_| vanilla.clone())
            } else {
                vanilla.clone()
            };

            if dict.len() < vanilla.len() && dict.len() < chunk.len() {
                dict_chunks += 1;
                total_wire += dict.len() as u64;
            } else if vanilla.len() < chunk.len() {
                vanilla_chunks += 1;
                total_wire += vanilla.len() as u64;
            } else {
                raw_chunks += 1;
                total_wire += chunk.len() as u64;
            }

            offset = end;
        }

        let bytes_saved = total_orig.saturating_sub(total_wire);
        let compression_ratio = if total_wire > 0 {
            total_orig as f64 / total_wire as f64
        } else {
            1.0
        };

        DeltaCompressionReport {
            original_bytes: total_orig,
            transferred_bytes: total_wire,
            bytes_saved,
            compression_ratio,
            exact_matches,
            dict_compressed_chunks: dict_chunks,
            vanilla_compressed_chunks: vanilla_chunks,
            raw_literal_chunks: raw_chunks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_delta_slice_header_roundtrip() {
        let dummy_hash = Hash::of(b"test chunk");
        let slice = DeltaSlice {
            header: DeltaSliceHeader {
                magic: DELTA_SLICE_MAGIC,
                kind: DeltaCompressionKind::DictDelta,
                original_length: 65536,
                compressed_length: 1234,
                ref_offset: 1048576,
                ref_length: 32768,
                chunk_hash: dummy_hash,
            },
            payload: vec![0xAA; 1234],
        };

        let encoded = slice.encode();
        let (decoded, consumed) = DeltaSlice::decode(&encoded).expect("decode must succeed");
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.header, slice.header);
        assert_eq!(decoded.payload, slice.payload);
    }

    #[test]
    fn test_delta_compression_and_decompression_lifecycle() {
        // Create baseline file with representative structured log/code data
        let mut baseline_temp = NamedTempFile::new().unwrap();
        let baseline_text = "fn compute_metrics(cluster: &Cluster) -> Result<(), Error> {\n    let val = 42;\n    println!(\"val={val}\");\n}\n".repeat(200);
        baseline_temp.write_all(baseline_text.as_bytes()).unwrap();
        baseline_temp.flush().unwrap();

        // Modified version with minor edit
        let target_text = "fn compute_metrics(cluster: &Cluster) -> Result<(), Error> {\n    let val = 43;\n    println!(\"val={val}\");\n}\n".repeat(200);
        let target_bytes = target_text.as_bytes();
        let target_hash = Hash::of(target_bytes);

        let engine = ContentDeltaEngine::default();
        let mut file_reader = File::open(baseline_temp.path()).unwrap();

        // Compress modified chunk
        let slice = engine
            .compress_chunk(target_bytes, target_hash, Some(&mut file_reader), 0)
            .expect("compression must succeed");

        assert_eq!(slice.header.kind, DeltaCompressionKind::DictDelta);
        // Dict-compressed size should be massively smaller than original length
        assert!(slice.payload.len() < target_bytes.len() / 5);

        // Decompress chunk using baseline file
        let mut file_reader_dec = File::open(baseline_temp.path()).unwrap();
        let decompressed = engine
            .decompress_chunk(&slice, Some(&mut file_reader_dec))
            .expect("decompression must succeed");

        assert_eq!(decompressed, target_bytes);
    }

    #[test]
    fn test_evaluate_delta_metrics() {
        let base = "fn process() { let a = 1; let b = 2; }\n".repeat(500);
        let target = "fn process() { let a = 99; let b = 2; }\n".repeat(500);

        let engine = ContentDeltaEngine::default();
        let report = engine.evaluate_delta(target.as_bytes(), base.as_bytes(), 4096);

        assert!(report.bytes_saved > 0);
        assert!(report.compression_ratio > 2.0);
        assert!(report.dict_compressed_chunks > 0);
    }
}
