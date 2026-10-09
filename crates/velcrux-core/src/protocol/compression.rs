//! Wire-level Zstandard (zstd) compression, decompression-bomb defense, and
//! dynamic adaptive compression selection (Option AO).
//!
//! Conforms to `PROTOCOL.md` §3 (bit 1 `COMPRESSED`), `OPERATIONS.md` §4
//! (`[transfer] compression = "none" | "zstd"`), `SECURITY.md` §8, §10
//! (strict bounded memory decompression, ratio clamping, and fail-closed validation),
//! and `REQUIREMENTS.md` §21, §32.

#![forbid(unsafe_code)]

use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::error::ProtocolError;

/// Default zstd compression level (level 3: high throughput, good ratio; ADR-005, ARCHITECTURE.md §11).
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;

/// Fast zstd compression level for marginal / medium-entropy data.
pub const FAST_ZSTD_LEVEL: i32 = 1;

/// High zstd compression level for highly repetitive text / logs / zero-filled blocks.
pub const HIGH_ZSTD_LEVEL: i32 = 7;

/// Minimum payload size (in bytes) to attempt compression. Payloads smaller
/// than this often expand due to zstd frame headers and are not worth the CPU overhead.
pub const MIN_COMPRESSIBLE_SIZE: usize = 128;

/// Minimum byte savings required to justify sending compressed data over the wire.
pub const DEFAULT_MIN_SAVINGS: usize = 16;

/// Default Shannon entropy ceiling in bits/byte (out of 8.0) above which
/// compression is bypassed immediately to avoid wasting CPU cycles on incompressible payloads.
pub const DEFAULT_ENTROPY_BYPASS_THRESHOLD: f64 = 7.5;

/// Maximum sample size to inspect for entropy calculation (32 KiB).
pub const MAX_ENTROPY_SAMPLE_SIZE: usize = 32 * 1024;

// ---------------------------------------------------------------------------
// Shannon Entropy Sampler
// ---------------------------------------------------------------------------

/// Compute the exact Shannon entropy of `data` in bits per byte (0.0 to 8.0).
///
/// Returns `0.0` for empty inputs or inputs consisting entirely of identical bytes.
/// Returns approximately `8.0` for pure random / encrypted / compressed data.
pub fn compute_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Estimate the Shannon entropy of `data`.
///
/// For slices up to [`MAX_ENTROPY_SAMPLE_SIZE`], computes exact entropy.
/// For larger slices, samples representative segments from the start, middle,
/// and end of the slice for sub-microsecond evaluation.
pub fn estimate_entropy(data: &[u8]) -> f64 {
    if data.len() <= MAX_ENTROPY_SAMPLE_SIZE {
        compute_shannon_entropy(data)
    } else {
        let segment_len = MAX_ENTROPY_SAMPLE_SIZE / 3;
        let mut counts = [0u32; 256];
        let mid_start = (data.len() / 2).saturating_sub(segment_len / 2);
        let end_start = data.len().saturating_sub(segment_len);

        for &b in &data[..segment_len] {
            counts[b as usize] += 1;
        }
        for &b in &data[mid_start..mid_start + segment_len] {
            counts[b as usize] += 1;
        }
        for &b in &data[end_start..] {
            counts[b as usize] += 1;
        }

        let total = (segment_len * 2 + (data.len() - end_start)) as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

// ---------------------------------------------------------------------------
// Entropy Classification & Adaptive Tiers
// ---------------------------------------------------------------------------

/// Classification of payload compressibility based on Shannon entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyTier {
    /// Highly repetitive data (entropy < 3.0 bits/byte), e.g. zeroes, repeated text.
    UltraRepetitive,
    /// Standard compressible text / structured data (3.0 <= entropy < 6.0 bits/byte).
    Standard,
    /// Moderately complex data (6.0 <= entropy < 7.5 bits/byte), e.g. binaries, dense JSON.
    Marginal,
    /// High-entropy data (entropy >= 7.5 bits/byte), e.g. video, compressed archives, encrypted blocks.
    Incompressible,
}

impl EntropyTier {
    /// Classify a Shannon entropy value into an [`EntropyTier`].
    pub fn classify(entropy: f64) -> Self {
        if entropy >= DEFAULT_ENTROPY_BYPASS_THRESHOLD {
            Self::Incompressible
        } else if entropy >= 6.0 {
            Self::Marginal
        } else if entropy >= 3.0 {
            Self::Standard
        } else {
            Self::UltraRepetitive
        }
    }

    /// Recommended zstd compression level for this tier.
    pub fn recommended_level(&self) -> Option<i32> {
        match self {
            Self::UltraRepetitive => Some(HIGH_ZSTD_LEVEL),
            Self::Standard => Some(DEFAULT_ZSTD_LEVEL),
            Self::Marginal => Some(FAST_ZSTD_LEVEL),
            Self::Incompressible => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Adaptive Compression Configuration, Stats & Selector
// ---------------------------------------------------------------------------

/// Configuration tunables for adaptive compression selection.
#[derive(Debug, Clone)]
pub struct AdaptiveCompressionConfig {
    /// Minimum raw byte length to attempt compression (default 128 bytes).
    pub min_compressible_size: usize,
    /// Minimum byte savings required to use compressed form (default 16 bytes).
    pub min_savings: usize,
    /// Shannon entropy ceiling above which compression is bypassed immediately (default 7.5).
    pub entropy_bypass_threshold: f64,
    /// Number of consecutive failed compression attempts before entering cooldown (default 3).
    pub backoff_failure_threshold: usize,
    /// Number of chunks to skip compression for during backoff cooldown (default 6).
    pub backoff_cooldown_chunks: usize,
}

impl Default for AdaptiveCompressionConfig {
    fn default() -> Self {
        Self {
            min_compressible_size: MIN_COMPRESSIBLE_SIZE,
            min_savings: DEFAULT_MIN_SAVINGS,
            entropy_bypass_threshold: DEFAULT_ENTROPY_BYPASS_THRESHOLD,
            backoff_failure_threshold: 3,
            backoff_cooldown_chunks: 6,
        }
    }
}

/// Runtime telemetry counters for adaptive compression.
#[derive(Debug, Default)]
pub struct AdaptiveCompressionStats {
    /// Total chunks evaluated.
    pub total_chunks: AtomicU64,
    /// Chunks bypassed due to payload size smaller than `min_compressible_size`.
    pub bypassed_small: AtomicU64,
    /// Chunks bypassed immediately due to high Shannon entropy (0 CPU wasted on zstd).
    pub bypassed_entropy: AtomicU64,
    /// Chunks bypassed because stream is in historical backoff cooldown.
    pub bypassed_backoff: AtomicU64,
    /// Chunks successfully compressed and sent over the wire.
    pub compressed_chunks: AtomicU64,
    /// Total raw (uncompressed) payload bytes processed.
    pub raw_bytes: AtomicU64,
    /// Total bytes sent over the wire for these chunks.
    pub wire_bytes: AtomicU64,
    /// Estimated CPU time saved (in microseconds) by bypassing compression on incompressible data.
    pub cpu_time_saved_us_est: AtomicU64,
}

/// Resulting decision made by the adaptive compression selector for a chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionDecision {
    /// Bypassed because payload is too small.
    BypassTooSmall,
    /// Bypassed because entropy is above threshold (measured entropy * 100).
    BypassHighEntropy { entropy_centibits: u16 },
    /// Bypassed because stream is in historical backoff cooldown.
    BypassBackoff { cooldown_remaining: usize },
    /// Successfully compressed using the given level with measured byte savings.
    Compressed {
        level: i32,
        raw_len: usize,
        compressed_len: usize,
    },
    /// Attempted compression at given level but savings were insufficient; uncompressed used.
    FailedSavings {
        level: i32,
        raw_len: usize,
        attempted_len: usize,
    },
}

/// Stateful selector that adaptively decides whether and how to compress chunks.
#[derive(Debug)]
pub struct AdaptiveCompressionSelector {
    config: AdaptiveCompressionConfig,
    consecutive_failures: usize,
    cooldown_remaining: usize,
    stats: Arc<AdaptiveCompressionStats>,
}

impl AdaptiveCompressionSelector {
    /// Construct a new selector with custom configuration and stats tracker.
    pub fn new(config: AdaptiveCompressionConfig, stats: Arc<AdaptiveCompressionStats>) -> Self {
        Self {
            config,
            consecutive_failures: 0,
            cooldown_remaining: 0,
            stats,
        }
    }

    /// Construct a new selector with default settings and a fresh stats tracker.
    pub fn with_defaults() -> Self {
        Self::new(
            AdaptiveCompressionConfig::default(),
            Arc::new(AdaptiveCompressionStats::default()),
        )
    }

    /// Reference to active telemetry statistics.
    pub fn stats(&self) -> &Arc<AdaptiveCompressionStats> {
        &self.stats
    }

    /// Active configuration.
    pub fn config(&self) -> &AdaptiveCompressionConfig {
        &self.config
    }

    /// Reset historical stream backoff state (e.g. when beginning a new file).
    pub fn reset_stream_state(&mut self) {
        self.consecutive_failures = 0;
        self.cooldown_remaining = 0;
    }

    /// Process a payload chunk, adaptively determining whether to compress.
    ///
    /// Returns `(Option<Vec<u8>>, CompressionDecision)`. If `Some(bytes)` is returned,
    /// the compressed payload saved at least `min_savings` bytes and should be sent with
    /// `DataFrameFlags::COMPRESSED`. Otherwise, the raw payload should be sent verbatim.
    pub fn process_payload(&mut self, payload: &[u8]) -> (Option<Vec<u8>>, CompressionDecision) {
        self.stats.total_chunks.fetch_add(1, Ordering::Relaxed);
        self.stats
            .raw_bytes
            .fetch_add(payload.len() as u64, Ordering::Relaxed);

        // 1. Check minimum compressible size
        if payload.len() < self.config.min_compressible_size {
            self.stats.bypassed_small.fetch_add(1, Ordering::Relaxed);
            self.stats
                .wire_bytes
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
            return (None, CompressionDecision::BypassTooSmall);
        }

        // 2. Check historical stream cooldown
        if self.cooldown_remaining > 0 {
            self.cooldown_remaining -= 1;
            self.stats.bypassed_backoff.fetch_add(1, Ordering::Relaxed);
            self.stats
                .wire_bytes
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
            // ~30 ns/byte estimated saved CPU time for zstd encode
            let saved_us = (payload.len() as u64 * 30) / 1000;
            self.stats
                .cpu_time_saved_us_est
                .fetch_add(saved_us, Ordering::Relaxed);
            return (
                None,
                CompressionDecision::BypassBackoff {
                    cooldown_remaining: self.cooldown_remaining,
                },
            );
        }

        // 3. Shannon Entropy Sampling
        let entropy = estimate_entropy(payload);
        if entropy >= self.config.entropy_bypass_threshold {
            self.stats.bypassed_entropy.fetch_add(1, Ordering::Relaxed);
            self.stats
                .wire_bytes
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
            let saved_us = (payload.len() as u64 * 30) / 1000;
            self.stats
                .cpu_time_saved_us_est
                .fetch_add(saved_us, Ordering::Relaxed);

            self.consecutive_failures += 1;
            if self.consecutive_failures >= self.config.backoff_failure_threshold {
                self.cooldown_remaining = self.config.backoff_cooldown_chunks;
            }

            return (
                None,
                CompressionDecision::BypassHighEntropy {
                    entropy_centibits: (entropy * 100.0).round() as u16,
                },
            );
        }

        // 4. Select level based on entropy tier
        let tier = EntropyTier::classify(entropy);
        let level = tier.recommended_level().unwrap_or(DEFAULT_ZSTD_LEVEL);

        // 5. Attempt compression at selected level
        match compress_payload(payload, level) {
            Ok(compressed) if compressed.len() + self.config.min_savings <= payload.len() => {
                self.consecutive_failures = 0;
                self.cooldown_remaining = 0;
                self.stats.compressed_chunks.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .wire_bytes
                    .fetch_add(compressed.len() as u64, Ordering::Relaxed);

                (
                    Some(compressed.clone()),
                    CompressionDecision::Compressed {
                        level,
                        raw_len: payload.len(),
                        compressed_len: compressed.len(),
                    },
                )
            }
            Ok(compressed) => {
                self.consecutive_failures += 1;
                if self.consecutive_failures >= self.config.backoff_failure_threshold {
                    self.cooldown_remaining = self.config.backoff_cooldown_chunks;
                }
                self.stats
                    .wire_bytes
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                (
                    None,
                    CompressionDecision::FailedSavings {
                        level,
                        raw_len: payload.len(),
                        attempted_len: compressed.len(),
                    },
                )
            }
            Err(_) => {
                self.consecutive_failures += 1;
                if self.consecutive_failures >= self.config.backoff_failure_threshold {
                    self.cooldown_remaining = self.config.backoff_cooldown_chunks;
                }
                self.stats
                    .wire_bytes
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                (
                    None,
                    CompressionDecision::FailedSavings {
                        level,
                        raw_len: payload.len(),
                        attempted_len: payload.len(),
                    },
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Core Compression & Decompression-Bomb Safe Decoders
// ---------------------------------------------------------------------------

/// Compress `data` using zstd with the given compression level.
pub fn compress_payload(data: &[u8], level: i32) -> Result<Vec<u8>, ProtocolError> {
    zstd::encode_all(data, level).map_err(|_| ProtocolError::Malformed("zstd compression failed"))
}

/// Compress `data` if it is large enough, passes entropy screening, and the compressed output
/// yields at least `min_savings` bytes reduction compared to the raw payload.
///
/// Returns `Some(compressed)` if beneficial, or `None` if uncompressed should be used.
pub fn compress_if_beneficial(data: &[u8], min_savings: usize) -> Option<Vec<u8>> {
    if data.len() < MIN_COMPRESSIBLE_SIZE {
        return None;
    }
    // High-entropy fast-bypass (Option AO)
    if estimate_entropy(data) >= DEFAULT_ENTROPY_BYPASS_THRESHOLD {
        return None;
    }
    match compress_payload(data, DEFAULT_ZSTD_LEVEL) {
        Ok(compressed) if compressed.len() + min_savings <= data.len() => Some(compressed),
        _ => None,
    }
}

/// Decompress `compressed` data with strict bounds protection against decompression bombs.
///
/// - `max_bytes`: Hard ceiling on the total decompressed output size. If decompression
///   exceeds this size, it immediately aborts with [`ProtocolError::DecompressionBomb`].
/// - `max_ratio`: Optional multiplier ceiling (e.g. 500x). If the output expands by more than
///   `max_ratio` relative to the compressed input size (checked once output > 64 KiB),
///   decompression immediately aborts.
pub fn decompress_payload_bounded(
    compressed: &[u8],
    max_bytes: usize,
    max_ratio: Option<usize>,
) -> Result<Vec<u8>, ProtocolError> {
    if compressed.is_empty() {
        return Err(ProtocolError::Malformed("empty compressed payload"));
    }

    let mut decoder = zstd::Decoder::new(compressed)
        .map_err(|_| ProtocolError::Malformed("invalid zstd header"))?;

    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|_| ProtocolError::Malformed("zstd decode error"))?;
        if n == 0 {
            break;
        }
        if out.len() + n > max_bytes {
            return Err(ProtocolError::DecompressionBomb(format!(
                "decompressed size exceeds limit of {max_bytes} bytes"
            )));
        }
        if let Some(ratio) = max_ratio {
            let total = out.len() + n;
            if total > 64 * 1024 && total > compressed.len().max(1) * ratio {
                return Err(ProtocolError::DecompressionBomb(format!(
                    "decompression expansion ratio exceeded {ratio}x limit"
                )));
            }
        }
        out.extend_from_slice(&buf[..n]);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_calculation() {
        // All zeroes -> entropy is 0.0
        let zeroes = vec![0u8; 1024];
        assert_eq!(compute_shannon_entropy(&zeroes), 0.0);

        // Alternating two bytes -> entropy is 1.0 bit
        let alternating = [0u8, 1u8].repeat(512);
        let ent = compute_shannon_entropy(&alternating);
        assert!((ent - 1.0).abs() < 1e-4);

        // English text / ASCII logs -> entropy between 3.0 and 5.0
        let text = b"The quick brown fox jumps over the lazy dog. 1234567890 repetitious text logs";
        let text_ent = compute_shannon_entropy(text);
        assert!(
            text_ent > 3.0 && text_ent < 5.5,
            "text entropy was {text_ent}"
        );

        // Random pseudorandom data -> entropy close to 8.0
        let mut random_data = Vec::with_capacity(256 * 10);
        for _ in 0..10 {
            for b in 0..=255u8 {
                random_data.push(b);
            }
        }
        let rand_ent = compute_shannon_entropy(&random_data);
        assert!(
            (rand_ent - 8.0).abs() < 1e-4,
            "uniform byte entropy was {rand_ent}"
        );
    }

    #[test]
    fn test_entropy_tier_classification() {
        assert_eq!(EntropyTier::classify(0.5), EntropyTier::UltraRepetitive);
        assert_eq!(EntropyTier::classify(2.9), EntropyTier::UltraRepetitive);
        assert_eq!(EntropyTier::classify(3.0), EntropyTier::Standard);
        assert_eq!(EntropyTier::classify(5.9), EntropyTier::Standard);
        assert_eq!(EntropyTier::classify(6.0), EntropyTier::Marginal);
        assert_eq!(EntropyTier::classify(7.4), EntropyTier::Marginal);
        assert_eq!(EntropyTier::classify(7.5), EntropyTier::Incompressible);
        assert_eq!(EntropyTier::classify(7.99), EntropyTier::Incompressible);

        assert_eq!(EntropyTier::UltraRepetitive.recommended_level(), Some(7));
        assert_eq!(EntropyTier::Standard.recommended_level(), Some(3));
        assert_eq!(EntropyTier::Marginal.recommended_level(), Some(1));
        assert_eq!(EntropyTier::Incompressible.recommended_level(), None);
    }

    #[test]
    fn test_adaptive_selector_high_entropy_bypass() {
        let mut selector = AdaptiveCompressionSelector::with_defaults();

        // 256 bytes of uniform distinct bytes (entropy = 8.0)
        let mut high_entropy = Vec::with_capacity(1024);
        for _ in 0..4 {
            for b in 0..=255u8 {
                high_entropy.push(b);
            }
        }

        let (compressed, decision) = selector.process_payload(&high_entropy);
        assert!(compressed.is_none());
        assert!(matches!(
            decision,
            CompressionDecision::BypassHighEntropy { .. }
        ));

        let stats = selector.stats();
        assert_eq!(stats.total_chunks.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bypassed_entropy.load(Ordering::Relaxed), 1);
        assert_eq!(stats.compressed_chunks.load(Ordering::Relaxed), 0);
        assert!(stats.cpu_time_saved_us_est.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_adaptive_selector_compressible_stream() {
        let mut selector = AdaptiveCompressionSelector::with_defaults();
        let compressible = b"key=value&name=velcrux&status=ok&time=123456789".repeat(50);

        let (compressed, decision) = selector.process_payload(&compressible);
        assert!(compressed.is_some());
        let comp = compressed.unwrap();
        assert!(comp.len() < compressible.len() / 2);
        assert!(matches!(decision, CompressionDecision::Compressed { .. }));

        let stats = selector.stats();
        assert_eq!(stats.compressed_chunks.load(Ordering::Relaxed), 1);
        assert_eq!(stats.wire_bytes.load(Ordering::Relaxed), comp.len() as u64);
    }

    #[test]
    fn test_adaptive_selector_backoff_cooldown() {
        let config = AdaptiveCompressionConfig {
            min_compressible_size: 16,
            min_savings: 16,
            entropy_bypass_threshold: 7.5,
            backoff_failure_threshold: 2,
            backoff_cooldown_chunks: 3,
        };
        let stats = Arc::new(AdaptiveCompressionStats::default());
        let mut selector = AdaptiveCompressionSelector::new(config, stats.clone());

        // Feed 2 incompressible chunks to trigger backoff
        let mut incompressible = Vec::new();
        for b in 0..=255u8 {
            incompressible.push(b);
        }
        let (_, d1) = selector.process_payload(&incompressible);
        let (_, d2) = selector.process_payload(&incompressible);
        assert!(matches!(d1, CompressionDecision::BypassHighEntropy { .. }));
        assert!(matches!(d2, CompressionDecision::BypassHighEntropy { .. }));

        // Next 3 chunks must be bypassed via Backoff cooldown without entropy check
        let (_, d3) = selector.process_payload(&incompressible);
        let (_, d4) = selector.process_payload(&incompressible);
        let (_, d5) = selector.process_payload(&incompressible);

        assert!(matches!(
            d3,
            CompressionDecision::BypassBackoff {
                cooldown_remaining: 2
            }
        ));
        assert!(matches!(
            d4,
            CompressionDecision::BypassBackoff {
                cooldown_remaining: 1
            }
        ));
        assert!(matches!(
            d5,
            CompressionDecision::BypassBackoff {
                cooldown_remaining: 0
            }
        ));
        assert_eq!(stats.bypassed_backoff.load(Ordering::Relaxed), 3);

        // 6th chunk probes again
        let (_, d6) = selector.process_payload(&incompressible);
        assert!(matches!(d6, CompressionDecision::BypassHighEntropy { .. }));
    }

    #[test]
    fn test_compression_roundtrip() {
        let original =
            b"Hello, Velcrux! Repeated repeated repeated text for compression testing.".repeat(20);
        let compressed = compress_payload(&original, DEFAULT_ZSTD_LEVEL).expect("compress");
        assert!(compressed.len() < original.len());

        let decompressed =
            decompress_payload_bounded(&compressed, original.len() + 1024, Some(100))
                .expect("decompress");
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_compress_if_beneficial() {
        // Highly compressible data
        let compressible = vec![0x42; 4096];
        let res = compress_if_beneficial(&compressible, 16);
        assert!(res.is_some());
        assert!(res.unwrap().len() < 100);

        // Incompressible data (random or short)
        let short = b"tiny text";
        assert!(compress_if_beneficial(short, 16).is_none());
    }

    #[test]
    fn test_decompression_bomb_size_limit() {
        // 1 MiB of zeroes compresses to very few bytes (~40 bytes)
        let zeroes = vec![0u8; 1024 * 1024];
        let compressed = compress_payload(&zeroes, 3).expect("compress zeroes");

        // Set max_bytes limit to 64 KiB -> must fail with DecompressionBomb
        let err = decompress_payload_bounded(&compressed, 64 * 1024, None)
            .expect_err("should reject oversized decompressed payload");

        assert!(matches!(err, ProtocolError::DecompressionBomb(_)));
        assert!(err.to_string().contains("exceeds limit of 65536 bytes"));
    }

    #[test]
    fn test_decompression_bomb_ratio_limit() {
        // Highly repetitive data
        let repetitive = vec![0xAA; 512 * 1024];
        let compressed = compress_payload(&repetitive, 3).expect("compress");

        // Ratio limit 10x with compressed size ~100 bytes -> 512 KiB exceeds ratio limit
        let err = decompress_payload_bounded(&compressed, 10 * 1024 * 1024, Some(10))
            .expect_err("should reject high expansion ratio");

        assert!(matches!(err, ProtocolError::DecompressionBomb(_)));
        assert!(err.to_string().contains("ratio exceeded"));
    }

    #[test]
    fn test_invalid_and_corrupt_payload() {
        let bad = b"not a valid zstd stream";
        let err = decompress_payload_bounded(bad, 1024, None).expect_err("should fail");
        assert!(matches!(err, ProtocolError::Malformed(_)));

        let empty = b"";
        let err_empty =
            decompress_payload_bounded(empty, 1024, None).expect_err("should fail on empty");
        assert!(matches!(err_empty, ProtocolError::Malformed(_)));
    }
}
