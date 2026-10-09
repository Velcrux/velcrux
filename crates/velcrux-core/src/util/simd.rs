//! Hardware SIMD feature probing and vectorized memory scanning.
//!
//! Enforces `CLAUDE.md` §1: 100% safe Rust (`#![forbid(unsafe_code)]`).
//!
//! Provides:
//! - [`SimdFeatures`]: Runtime probing of CPU instruction set vector extensions
//!   (AVX-512, AVX2, SSE4.1 on x86/x86_64; NEON on AArch64).
//! - [`VectorizedScanner`]: High-speed zero-block detection and sparse extent scanning
//!   using 64-byte and 128-byte unrolled safe word comparisons.

use std::fmt;

/// Highest detected SIMD acceleration tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SimdTier {
    /// Scalar baseline fallback.
    Scalar,
    /// SSE4.1 (128-bit vector registers).
    Sse41,
    /// ARM NEON (128-bit vector registers).
    Neon,
    /// AVX2 (256-bit vector registers).
    Avx2,
    /// AVX-512 (512-bit vector registers).
    Avx512,
}

impl SimdTier {
    /// Short human-readable display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::Sse41 => "sse4.1",
            Self::Neon => "neon",
            Self::Avx2 => "avx2",
            Self::Avx512 => "avx512",
        }
    }

    /// Nominal vector width in bits.
    pub const fn vector_width_bits(self) -> usize {
        match self {
            Self::Scalar => 64,
            Self::Sse41 | Self::Neon => 128,
            Self::Avx2 => 256,
            Self::Avx512 => 512,
        }
    }
}

impl fmt::Display for SimdTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Runtime-detected hardware SIMD capabilities of the host processor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimdFeatures {
    /// Active CPU architecture (e.g. "x86_64", "aarch64").
    pub arch: &'static str,
    /// Highest detected SIMD acceleration tier.
    pub tier: SimdTier,
    /// AVX-512 Foundation supported.
    pub has_avx512f: bool,
    /// AVX2 (Advanced Vector Extensions 2) supported.
    pub has_avx2: bool,
    /// SSE4.1 supported.
    pub has_sse41: bool,
    /// ARM NEON / ASIMD supported.
    pub has_neon: bool,
    /// PCLMULQDQ / ARM PMULL carry-less multiplication supported.
    pub has_carryless_mul: bool,
    /// AES-NI / ARM AES hardware acceleration supported.
    pub has_aes: bool,
}

impl SimdFeatures {
    /// Probe hardware capabilities of the host system at runtime.
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            let has_avx512f = std::is_x86_feature_detected!("avx512f");
            let has_avx2 = std::is_x86_feature_detected!("avx2");
            let has_sse41 = std::is_x86_feature_detected!("sse4.1");
            let has_carryless_mul = std::is_x86_feature_detected!("pclmulqdq");
            let has_aes = std::is_x86_feature_detected!("aes");

            let tier = if has_avx512f {
                SimdTier::Avx512
            } else if has_avx2 {
                SimdTier::Avx2
            } else if has_sse41 {
                SimdTier::Sse41
            } else {
                SimdTier::Scalar
            };

            Self {
                arch: "x86_64",
                tier,
                has_avx512f,
                has_avx2,
                has_sse41,
                has_neon: false,
                has_carryless_mul,
                has_aes,
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            #[cfg(target_os = "macos")]
            let has_neon = true; // All Apple Silicon aarch64 cores support NEON

            #[cfg(not(target_os = "macos"))]
            let has_neon = std::is_aarch64_feature_detected!("neon");

            #[cfg(target_os = "macos")]
            let has_aes = true; // Supported on all Apple Silicon M-series

            #[cfg(not(target_os = "macos"))]
            let has_aes = std::is_aarch64_feature_detected!("aes");

            #[cfg(target_os = "macos")]
            let has_carryless_mul = true;

            #[cfg(not(target_os = "macos"))]
            let has_carryless_mul = std::is_aarch64_feature_detected!("pmull");

            let tier = if has_neon {
                SimdTier::Neon
            } else {
                SimdTier::Scalar
            };

            Self {
                arch: "aarch64",
                tier,
                has_avx512f: false,
                has_avx2: false,
                has_sse41: false,
                has_neon,
                has_carryless_mul,
                has_aes,
            }
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Self {
                arch: std::env::consts::ARCH,
                tier: SimdTier::Scalar,
                has_avx512f: false,
                has_avx2: false,
                has_sse41: false,
                has_neon: false,
                has_carryless_mul: false,
                has_aes: false,
            }
        }
    }

    /// Return a human-readable summary string of detected extensions.
    pub fn description(&self) -> String {
        let mut extensions = Vec::new();
        if self.has_avx512f {
            extensions.push("AVX-512F");
        }
        if self.has_avx2 {
            extensions.push("AVX2");
        }
        if self.has_sse41 {
            extensions.push("SSE4.1");
        }
        if self.has_neon {
            extensions.push("NEON");
        }
        if self.has_carryless_mul {
            extensions.push("CLMUL/PMULL");
        }
        if self.has_aes {
            extensions.push("AES-NI");
        }

        if extensions.is_empty() {
            format!("{} (scalar baseline)", self.arch)
        } else {
            format!("{} ({})", self.arch, extensions.join(", "))
        }
    }
}

impl Default for SimdFeatures {
    fn default() -> Self {
        Self::detect()
    }
}

/// High-speed vectorized zero scanner and sparse extent detector.
///
/// Implemented in 100% safe Rust without `unsafe` pointers or `align_to`.
/// Leverages 64-byte `u128` unrolled chunks which modern LLVM compilers
/// automatically lower to vectorized instructions (`VPCMPEQB`/`VPTEST` on AVX2,
/// `CMEQ`/`UMAXV` on NEON).
pub struct VectorizedScanner;

impl VectorizedScanner {
    /// Return `true` if every byte in `buf` is zero (`0x00`).
    #[inline]
    pub fn is_all_zeros(buf: &[u8]) -> bool {
        let mut chunks = buf.chunks_exact(64);
        for chunk in &mut chunks {
            let arr: &[u8; 64] = match chunk.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };

            let q0 = u128::from_ne_bytes(arr[0..16].try_into().unwrap());
            let q1 = u128::from_ne_bytes(arr[16..32].try_into().unwrap());
            let q2 = u128::from_ne_bytes(arr[32..48].try_into().unwrap());
            let q3 = u128::from_ne_bytes(arr[48..64].try_into().unwrap());

            if (q0 | q1 | q2 | q3) != 0 {
                return false;
            }
        }

        let remainder = chunks.remainder();
        let mut rem_chunks = remainder.chunks_exact(8);
        for word in &mut rem_chunks {
            let val = u64::from_ne_bytes(word.try_into().unwrap());
            if val != 0 {
                return false;
            }
        }

        for &b in rem_chunks.remainder() {
            if b != 0 {
                return false;
            }
        }

        true
    }

    /// Count total consecutive zero bytes from the start of `buf`.
    #[inline]
    pub fn leading_zeros_count(buf: &[u8]) -> usize {
        let mut count = 0;
        let mut chunks = buf.chunks_exact(64);
        for chunk in &mut chunks {
            let arr: &[u8; 64] = chunk.try_into().unwrap();
            let q0 = u128::from_ne_bytes(arr[0..16].try_into().unwrap());
            let q1 = u128::from_ne_bytes(arr[16..32].try_into().unwrap());
            let q2 = u128::from_ne_bytes(arr[32..48].try_into().unwrap());
            let q3 = u128::from_ne_bytes(arr[48..64].try_into().unwrap());

            if (q0 | q1 | q2 | q3) == 0 {
                count += 64;
            } else {
                for &b in chunk {
                    if b == 0 {
                        count += 1;
                    } else {
                        return count;
                    }
                }
            }
        }

        for &b in chunks.remainder() {
            if b == 0 {
                count += 1;
            } else {
                break;
            }
        }

        count
    }

    /// Find the index of the first non-zero byte in `buf`, if any.
    #[inline]
    pub fn find_first_nonzero(buf: &[u8]) -> Option<usize> {
        let count = Self::leading_zeros_count(buf);
        if count < buf.len() {
            Some(count)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_features_detection() {
        let features = SimdFeatures::detect();
        assert!(!features.arch.is_empty());
        let desc = features.description();
        assert!(!desc.is_empty());
        assert!(features.tier.vector_width_bits() >= 64);
    }

    #[test]
    fn test_vectorized_scanner_all_zeros() {
        let zeros = vec![0u8; 4096];
        assert!(VectorizedScanner::is_all_zeros(&zeros));

        let small_zeros = vec![0u8; 17];
        assert!(VectorizedScanner::is_all_zeros(&small_zeros));

        let empty: [u8; 0] = [];
        assert!(VectorizedScanner::is_all_zeros(&empty));
    }

    #[test]
    fn test_vectorized_scanner_detects_nonzeros() {
        let mut data = vec![0u8; 1024];
        data[0] = 1;
        assert!(!VectorizedScanner::is_all_zeros(&data));
        assert_eq!(VectorizedScanner::find_first_nonzero(&data), Some(0));

        data[0] = 0;
        data[63] = 0xFF;
        assert!(!VectorizedScanner::is_all_zeros(&data));
        assert_eq!(VectorizedScanner::find_first_nonzero(&data), Some(63));

        data[63] = 0;
        data[64] = 0x01;
        assert!(!VectorizedScanner::is_all_zeros(&data));
        assert_eq!(VectorizedScanner::find_first_nonzero(&data), Some(64));

        data[64] = 0;
        data[1023] = 0x42;
        assert!(!VectorizedScanner::is_all_zeros(&data));
        assert_eq!(VectorizedScanner::find_first_nonzero(&data), Some(1023));
    }

    #[test]
    fn test_leading_zeros_count() {
        let mut data = vec![0u8; 200];
        assert_eq!(VectorizedScanner::leading_zeros_count(&data), 200);

        data[130] = 1;
        assert_eq!(VectorizedScanner::leading_zeros_count(&data), 130);
    }
}
