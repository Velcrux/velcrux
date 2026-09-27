//! Wire-level Zstandard (zstd) compression and decompression-bomb defense.
//!
//! Conforms to `PROTOCOL.md` §3 (bit 1 `COMPRESSED`), `OPERATIONS.md` §4
//! (`[transfer] compression = "none" | "zstd"`), and `SECURITY.md` §8, §10
//! (strict bounded memory decompression, ratio clamping, and fail-closed validation).

#![forbid(unsafe_code)]

use std::io::Read;

use crate::error::ProtocolError;

/// Default zstd compression level (level 3: high throughput, good ratio; ADR-005, ARCHITECTURE.md §11).
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;

/// Minimum payload size (in bytes) to attempt compression. Payloads smaller
/// than this often expand due to zstd frame headers and are not worth the CPU overhead.
pub const MIN_COMPRESSIBLE_SIZE: usize = 128;

/// Minimum byte savings required to justify sending compressed data over the wire.
pub const DEFAULT_MIN_SAVINGS: usize = 16;

/// Compress `data` using zstd with the given compression level.
pub fn compress_payload(data: &[u8], level: i32) -> Result<Vec<u8>, ProtocolError> {
    zstd::encode_all(data, level).map_err(|_| ProtocolError::Malformed("zstd compression failed"))
}

/// Compress `data` if it is large enough and the compressed output yields at least
/// `min_savings` bytes reduction compared to the raw payload.
///
/// Returns `Some(compressed)` if beneficial, or `None` if uncompressed should be used.
pub fn compress_if_beneficial(data: &[u8], min_savings: usize) -> Option<Vec<u8>> {
    if data.len() < MIN_COMPRESSIBLE_SIZE {
        return None;
    }
    match compress_payload(data, DEFAULT_ZSTD_LEVEL) {
        Ok(compressed) if compressed.len() + min_savings < data.len() => Some(compressed),
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
