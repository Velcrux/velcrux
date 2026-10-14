//! Adaptive Multi-Stream Forward Error Correction (FEC) Engine (Option BH).
//!
//! Implements `REQUIREMENTS.md` §13 ("Encrypting all data in transit"), §47 ("Benchmark Against Existing Technologies"),
//! and §88 ("Full vs Delta / High-Loss WAN").
//!
//! Provides systematic $(K+M, K)$ erasure coding over Galois Field $GF(2^8)$ to protect bulk data
//! transfers across high-loss, high-latency satellite, trans-oceanic, and hostile WAN topologies:
//! - Eliminates retransmission round-trip delays (ARQ stalls) by recovering lost packets/symbols on the fly.
//! - Uses a Cauchy Generator Matrix over $GF(2^8)$ guaranteeing the Maximum Distance Separable (MDS) property.
//! - Fast-path SIMD-friendly XOR parity when $M = 1$.
//! - Adaptive rate scaling (`AdaptiveFecController`) that dynamically adjusts parity ratio based on
//!   real-time measured packet loss and RTT telemetry.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Galois Field GF(2^8) Arithmetic
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

/// Irreducible primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1 (0x11d).
const GF_POLYNOMIAL: u16 = 0x11d;

static GF_TABLES: OnceLock<(Box<[u8; 512]>, Box<[u8; 256]>)> = OnceLock::new();

fn get_gf_tables() -> &'static (Box<[u8; 512]>, Box<[u8; 256]>) {
    GF_TABLES.get_or_init(init_gf_tables)
}

fn init_gf_tables() -> (Box<[u8; 512]>, Box<[u8; 256]>) {
    let mut exp = Box::new([0u8; 512]);
    let mut log = Box::new([0u8; 256]);

    let mut val: u16 = 1;
    for i in 0..255 {
        exp[i] = val as u8;
        exp[i + 255] = val as u8;
        log[val as usize] = i as u8;

        val <<= 1;
        if (val & 0x100) != 0 {
            val ^= GF_POLYNOMIAL;
        }
    }
    // exp[255..510] duplicated for wrap-around without modulo
    exp[510] = exp[0];
    exp[511] = exp[1];

    (exp, log)
}

#[inline(always)]
pub fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

#[inline(always)]
pub fn gf_sub(a: u8, b: u8) -> u8 {
    a ^ b
}

#[inline(always)]
pub fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        let (exp, log) = get_gf_tables();
        let sum = (log[a as usize] as usize) + (log[b as usize] as usize);
        exp[sum]
    }
}

#[inline(always)]
pub fn gf_div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "GF(2^8) division by zero");
    if a == 0 {
        0
    } else {
        let (exp, log) = get_gf_tables();
        let diff = (log[a as usize] as usize) + 255 - (log[b as usize] as usize);
        exp[diff]
    }
}

#[inline(always)]
pub fn gf_inv(a: u8) -> u8 {
    gf_div(1, a)
}

// ---------------------------------------------------------------------------
// Matrix Operations over GF(2^8)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GfMatrix {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<u8>,
}

impl GfMatrix {
    pub fn zeros(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![0u8; rows * cols],
        }
    }

    #[inline(always)]
    pub fn get(&self, r: usize, c: usize) -> u8 {
        self.data[r * self.cols + c]
    }

    #[inline(always)]
    pub fn set(&mut self, r: usize, c: usize, val: u8) {
        self.data[r * self.cols + c] = val;
    }

    /// Construct a Cauchy Generator Matrix for (K + M, K) erasure coding.
    /// Parity row i, column j: C[i, j] = 1 / (x_i ^ y_j)
    /// Disjoint sets: x_i = i, y_j = M + j.
    pub fn cauchy(rows: usize, cols: usize) -> Self {
        let mut m = Self::zeros(rows, cols);
        for i in 0..rows {
            let x = i as u8;
            for j in 0..cols {
                let y = (rows + j) as u8;
                let denom = x ^ y;
                assert!(denom != 0, "Cauchy matrix disjointness violation");
                m.set(i, j, gf_inv(denom));
            }
        }
        m
    }

    /// Invert a square matrix over GF(2^8) using Gaussian elimination.
    /// Returns None if the matrix is singular.
    pub fn invert(&self) -> Option<Self> {
        assert_eq!(self.rows, self.cols, "Matrix must be square to invert");
        let n = self.rows;

        // Augmented matrix [A | I]
        let mut aug = Self::zeros(n, 2 * n);
        for r in 0..n {
            for c in 0..n {
                aug.set(r, c, self.get(r, c));
            }
            aug.set(r, n + r, 1);
        }

        // Forward and backward elimination
        for col in 0..n {
            // Find pivot
            let mut pivot_row = col;
            while pivot_row < n && aug.get(pivot_row, col) == 0 {
                pivot_row += 1;
            }
            if pivot_row == n {
                return None; // Singular matrix
            }

            // Swap rows if necessary
            if pivot_row != col {
                for c in 0..2 * n {
                    let tmp = aug.get(col, c);
                    aug.set(col, c, aug.get(pivot_row, c));
                    aug.set(pivot_row, c, tmp);
                }
            }

            // Normalize pivot row
            let pivot_val = aug.get(col, col);
            let inv_pivot = gf_inv(pivot_val);
            for c in 0..2 * n {
                aug.set(col, c, gf_mul(aug.get(col, c), inv_pivot));
            }

            // Eliminate column in all other rows
            for r in 0..n {
                if r != col {
                    let factor = aug.get(r, col);
                    if factor != 0 {
                        for c in 0..2 * n {
                            let sub = gf_mul(factor, aug.get(col, c));
                            aug.set(r, c, gf_sub(aug.get(r, c), sub));
                        }
                    }
                }
            }
        }

        // Extract right half [I | A^-1]
        let mut inv = Self::zeros(n, n);
        for r in 0..n {
            for c in 0..n {
                inv.set(r, c, aug.get(r, n + c));
            }
        }

        Some(inv)
    }
}

// ---------------------------------------------------------------------------
// Systematic (K + M, K) Erasure Encoder / Decoder
// ---------------------------------------------------------------------------

/// A coded symbol with its original symbol index in the (K + M) sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FecSymbol {
    /// Symbol sequence index: 0..K are source symbols; K..(K+M) are repair symbols.
    pub index: usize,
    /// Raw payload bytes of symbol.
    pub data: Vec<u8>,
}

/// Systematic Reed-Solomon / Cauchy Erasure Codec.
pub struct FecCodec {
    /// Number of source data symbols (K).
    pub k: usize,
    /// Number of parity / repair symbols (M).
    pub m: usize,
    cauchy_matrix: GfMatrix,
}

impl FecCodec {
    pub fn new(k: usize, m: usize) -> Self {
        assert!(k > 0, "K must be > 0");
        assert!(k + m <= 256, "K + M must fit in GF(2^8)");
        let cauchy_matrix = if m > 0 {
            GfMatrix::cauchy(m, k)
        } else {
            GfMatrix::zeros(0, k)
        };
        Self { k, m, cauchy_matrix }
    }

    /// Encode K source symbols into M repair symbols.
    /// All source symbols must have identical length.
    pub fn encode(&self, source_symbols: &[Vec<u8>]) -> Vec<FecSymbol> {
        assert_eq!(source_symbols.len(), self.k, "Must provide exactly K source symbols");
        if self.m == 0 {
            return Vec::new();
        }

        let symbol_len = source_symbols[0].len();
        for s in source_symbols {
            assert_eq!(s.len(), symbol_len, "All symbols must have identical length");
        }

        let mut repair = Vec::with_capacity(self.m);

        // Fast-path: M = 1 is pure XOR parity across all source symbols
        if self.m == 1 {
            let mut parity = vec![0u8; symbol_len];
            for src in source_symbols {
                for (dst_b, src_b) in parity.iter_mut().zip(src.iter()) {
                    *dst_b ^= *src_b;
                }
            }
            repair.push(FecSymbol {
                index: self.k,
                data: parity,
            });
            return repair;
        }

        // General Cauchy matrix encoding for M > 1
        for i in 0..self.m {
            let mut parity = vec![0u8; symbol_len];
            for j in 0..self.k {
                let coeff = self.cauchy_matrix.get(i, j);
                if coeff != 0 {
                    let src = &source_symbols[j];
                    for b_idx in 0..symbol_len {
                        parity[b_idx] = gf_add(parity[b_idx], gf_mul(coeff, src[b_idx]));
                    }
                }
            }
            repair.push(FecSymbol {
                index: self.k + i,
                data: parity,
            });
        }

        repair
    }

    /// Decode and reconstruct all K source symbols from any K received symbols.
    /// Returns `Some(Vec<Vec<u8>>)` of length K if recovery succeeds, or `None` if
    /// fewer than K distinct symbols are available or matrix inversion fails.
    pub fn decode(&self, received: &[FecSymbol]) -> Option<Vec<Vec<u8>>> {
        if received.len() < self.k {
            return None; // Too few symbols received to reconstruct K data blocks
        }

        // Deduplicate received symbols by index
        let mut distinct = Vec::new();
        let mut seen = vec![false; self.k + self.m];
        for s in received {
            if s.index < (self.k + self.m) && !seen[s.index] {
                seen[s.index] = true;
                distinct.push(s.clone());
            }
        }

        if distinct.len() < self.k {
            return None;
        }

        let symbol_len = distinct[0].data.len();

        // Check if all K source symbols are already present (no packet loss)
        let mut all_source_present = true;
        for i in 0..self.k {
            if !seen[i] {
                all_source_present = false;
                break;
            }
        }

        if all_source_present {
            let mut result = vec![Vec::new(); self.k];
            for s in distinct {
                if s.index < self.k {
                    result[s.index] = s.data;
                }
            }
            return Some(result);
        }

        // Fast-path for M = 1 with exactly 1 missing source symbol
        if self.m == 1 {
            let missing_idx = (0..self.k).find(|&i| !seen[i]);
            let has_parity = seen[self.k];
            if let (Some(missing), true) = (missing_idx, has_parity) {
                let mut reconstructed = vec![0u8; symbol_len];
                let parity_sym = distinct.iter().find(|s| s.index == self.k).unwrap();
                for (r, p) in reconstructed.iter_mut().zip(parity_sym.data.iter()) {
                    *r = *p;
                }
                for s in &distinct {
                    if s.index < self.k && s.index != missing {
                        for (r, b) in reconstructed.iter_mut().zip(s.data.iter()) {
                            *r ^= *b;
                        }
                    }
                }

                let mut result = vec![Vec::new(); self.k];
                for s in distinct {
                    if s.index < self.k {
                        result[s.index] = s.data;
                    }
                }
                result[missing] = reconstructed;
                return Some(result);
            }
        }

        // General M >= 1 Cauchy Decoding:
        // Build K x K linear equation matrix from the first K received symbols.
        let selected = &distinct[..self.k];
        let mut submatrix = GfMatrix::zeros(self.k, self.k);

        for (row_idx, sym) in selected.iter().enumerate() {
            if sym.index < self.k {
                // Systematic identity row
                submatrix.set(row_idx, sym.index, 1);
            } else {
                // Cauchy parity row
                let parity_row = sym.index - self.k;
                for col in 0..self.k {
                    submatrix.set(row_idx, col, self.cauchy_matrix.get(parity_row, col));
                }
            }
        }

        let inv = submatrix.invert()?;

        // Multiply inverted matrix by received vectors
        let mut result = vec![vec![0u8; symbol_len]; self.k];
        for src_idx in 0..self.k {
            for col_idx in 0..self.k {
                let coeff = inv.get(src_idx, col_idx);
                if coeff != 0 {
                    let sym_data = &selected[col_idx].data;
                    for b in 0..symbol_len {
                        result[src_idx][b] =
                            gf_add(result[src_idx][b], gf_mul(coeff, sym_data[b]));
                    }
                }
            }
        }

        Some(result)
    }
}

// ---------------------------------------------------------------------------
// Adaptive FEC Profiles & Controller
// ---------------------------------------------------------------------------

/// FEC operational mode configuration preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FecProfile {
    /// FEC disabled (0% repair overhead).
    Disabled,
    /// Low overhead (K=20, M=1 -> 5% redundancy).
    Low,
    /// Medium overhead (K=16, M=2 -> 12.5% redundancy).
    Medium,
    /// High overhead (K=10, M=2 -> 20% redundancy).
    High,
    /// Satellite link profile (K=8, M=2 -> 25% redundancy).
    Satellite,
    /// Dynamic loss adaptation based on real-time link packet loss.
    Auto,
}

impl FecProfile {
    pub fn from_str_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "disabled" | "off" | "none" => Some(Self::Disabled),
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            "satellite" | "sat" => Some(Self::Satellite),
            "auto" | "adaptive" => Some(Self::Auto),
            _ => None,
        }
    }

    /// Return static (K, M) parameters for this profile.
    pub fn static_params(&self) -> (usize, usize) {
        match self {
            Self::Disabled => (16, 0),
            Self::Low => (20, 1),
            Self::Medium => (16, 2),
            Self::High => (10, 2),
            Self::Satellite => (8, 2),
            Self::Auto => (16, 2), // Default initial
        }
    }
}

/// Real-time adaptive FEC coordinator monitoring channel telemetry.
pub struct AdaptiveFecController {
    profile: FecProfile,
    current_k: usize,
    current_m: usize,
    stats: Arc<FecStats>,
}

#[derive(Debug, Default)]
pub struct FecStats {
    pub blocks_encoded: AtomicU64,
    pub source_symbols_sent: AtomicU64,
    pub repair_symbols_sent: AtomicU64,
    pub symbols_recovered: AtomicU64,
    pub unrecoverable_blocks: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecStatsSnapshot {
    pub profile: FecProfile,
    pub active_k: usize,
    pub active_m: usize,
    pub redundancy_pct: f64,
    pub blocks_encoded: u64,
    pub source_symbols_sent: u64,
    pub repair_symbols_sent: u64,
    pub symbols_recovered: u64,
    pub unrecoverable_blocks: u64,
}

impl AdaptiveFecController {
    pub fn new(profile: FecProfile) -> Self {
        let (k, m) = profile.static_params();
        Self {
            profile,
            current_k: k,
            current_m: m,
            stats: Arc::new(FecStats::default()),
        }
    }

    pub fn stats(&self) -> Arc<FecStats> {
        self.stats.clone()
    }

    /// Adapt (K, M) parameters based on observed packet loss rate [0.0, 1.0].
    pub fn adapt_to_loss(&mut self, loss_rate: f64) -> (usize, usize) {
        if self.profile != FecProfile::Auto {
            return (self.current_k, self.current_m);
        }

        // Dynamic loss gating
        let (k, m) = if loss_rate < 0.005 {
            (20, 0) // <0.5% loss: disable FEC for maximum goodput
        } else if loss_rate < 0.02 {
            (20, 1) // 0.5% - 2.0% loss: 5% parity
        } else if loss_rate < 0.05 {
            (16, 2) // 2.0% - 5.0% loss: 12.5% parity
        } else if loss_rate < 0.10 {
            (10, 2) // 5.0% - 10.0% loss: 20% parity
        } else {
            (8, 2) // >=10.0% loss: 25% satellite-grade parity
        };

        self.current_k = k;
        self.current_m = m;
        (k, m)
    }

    pub fn snapshot(&self) -> FecStatsSnapshot {
        let k = self.current_k;
        let m = self.current_m;
        let redundancy_pct = if k > 0 { (m as f64 / k as f64) * 100.0 } else { 0.0 };

        FecStatsSnapshot {
            profile: self.profile,
            active_k: k,
            active_m: m,
            redundancy_pct,
            blocks_encoded: self.stats.blocks_encoded.load(Ordering::Relaxed),
            source_symbols_sent: self.stats.source_symbols_sent.load(Ordering::Relaxed),
            repair_symbols_sent: self.stats.repair_symbols_sent.load(Ordering::Relaxed),
            symbols_recovered: self.stats.symbols_recovered.load(Ordering::Relaxed),
            unrecoverable_blocks: self.stats.unrecoverable_blocks.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// Block-Level FEC Framing, Encoding & Recovery
// ---------------------------------------------------------------------------

/// Header metadata for an FEC block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FecBlockHeader {
    pub block_id: u64,
    pub original_len: usize,
    pub k: usize,
    pub m: usize,
    pub symbol_size: usize,
}

/// Recovery metrics for an individual FEC block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FecRecoveryReport {
    pub block_id: u64,
    pub k: usize,
    pub m: usize,
    pub received_source_count: usize,
    pub received_repair_count: usize,
    pub lost_source_count: usize,
    pub recovered_source_count: usize,
    pub is_successful: bool,
    pub bytes_recovered: usize,
}

/// High-level block encoder slicing chunks into symbols and generating Cauchy parity.
pub struct FecBlockEncoder;

impl FecBlockEncoder {
    /// Slice raw data into K source symbols, zero-padding the last symbol if necessary,
    /// and compute M repair parity symbols.
    pub fn encode_block(
        block_id: u64,
        data: &[u8],
        k: usize,
        m: usize,
    ) -> (FecBlockHeader, Vec<FecSymbol>) {
        assert!(k > 0, "K must be > 0");
        let original_len = data.len();
        let symbol_size = original_len.div_ceil(k).max(1);

        let mut sources = Vec::with_capacity(k);
        for i in 0..k {
            let start = i * symbol_size;
            let end = (start + symbol_size).min(original_len);
            let mut sym = vec![0u8; symbol_size];
            if start < original_len {
                let slice = &data[start..end];
                sym[..slice.len()].copy_from_slice(slice);
            }
            sources.push(sym);
        }

        let codec = FecCodec::new(k, m);
        let repair_symbols = codec.encode(&sources);

        let mut all_symbols = Vec::with_capacity(k + m);
        for (i, s) in sources.into_iter().enumerate() {
            all_symbols.push(FecSymbol {
                index: i,
                data: s,
            });
        }
        all_symbols.extend(repair_symbols);

        let header = FecBlockHeader {
            block_id,
            original_len,
            k,
            m,
            symbol_size,
        };

        (header, all_symbols)
    }
}

/// High-level block decoder recovering erased symbols and reassembling the original payload.
pub struct FecBlockDecoder;

impl FecBlockDecoder {
    /// Reassemble the original block data from any >= K received symbols.
    pub fn decode_block(
        header: &FecBlockHeader,
        received: &[FecSymbol],
    ) -> (Option<Vec<u8>>, FecRecoveryReport) {
        let k = header.k;
        let m = header.m;

        let mut source_count = 0usize;
        let mut repair_count = 0usize;
        for s in received {
            if s.index < k {
                source_count += 1;
            } else if s.index < k + m {
                repair_count += 1;
            }
        }

        let lost_source = k.saturating_sub(source_count);
        let codec = FecCodec::new(k, m);

        let decoded_symbols = codec.decode(received);

        let is_successful = decoded_symbols.is_some();
        let recovered_count = if is_successful && lost_source > 0 {
            lost_source
        } else {
            0
        };
        let bytes_recovered = recovered_count * header.symbol_size;

        let report = FecRecoveryReport {
            block_id: header.block_id,
            k,
            m,
            received_source_count: source_count,
            received_repair_count: repair_count,
            lost_source_count: lost_source,
            recovered_source_count: recovered_count,
            is_successful,
            bytes_recovered,
        };

        let reconstructed_data = decoded_symbols.map(|symbols| {
            let mut buf = Vec::with_capacity(k * header.symbol_size);
            for s in symbols {
                buf.extend_from_slice(&s);
            }
            buf.truncate(header.original_len);
            buf
        });

        (reconstructed_data, report)
    }
}

// ---------------------------------------------------------------------------
// Simulation & Benchmarking Harness
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecSimulationReport {
    pub profile: FecProfile,
    pub k: usize,
    pub m: usize,
    pub total_blocks: usize,
    pub payload_bytes: usize,
    pub simulated_loss_rate: f64,
    pub total_symbols_sent: usize,
    pub symbols_dropped: usize,
    pub actual_drop_pct: f64,
    pub symbols_recovered: usize,
    pub unrecoverable_blocks: usize,
    pub successful_recovery_pct: f64,
    pub effective_goodput_ratio: f64,
}

/// Simulate transmission of data over an impaired channel with packet erasure
/// and verify FEC recovery performance.
pub fn simulate_fec_recovery(
    data: &[u8],
    profile: FecProfile,
    loss_rate: f64,
    seed: u64,
) -> FecSimulationReport {
    let mut ctrl = AdaptiveFecController::new(profile);
    let (k, m) = ctrl.adapt_to_loss(loss_rate);

    let block_size = 64 * 1024; // 64 KiB block chunks
    let mut total_blocks = 0usize;
    let mut total_symbols_sent = 0usize;
    let mut symbols_dropped = 0usize;
    let mut symbols_recovered = 0usize;
    let mut unrecoverable_blocks = 0usize;

    let mut prng = crate::transport::impairment::DeterministicLossPrng::new(seed);

    for (chunk_idx, chunk) in data.chunks(block_size).enumerate() {
        total_blocks += 1;
        let (header, all_symbols) =
            FecBlockEncoder::encode_block(chunk_idx as u64, chunk, k, m);

        total_symbols_sent += all_symbols.len();

        // Simulate channel loss
        let mut received = Vec::new();
        for sym in all_symbols {
            if prng.should_drop(loss_rate) {
                symbols_dropped += 1;
            } else {
                received.push(sym);
            }
        }

        let (recovered, report) = FecBlockDecoder::decode_block(&header, &received);
        if let Some(ref rec_bytes) = recovered {
            assert_eq!(rec_bytes, chunk, "Reconstructed block must match original byte-for-byte");
            symbols_recovered += report.recovered_source_count;
        } else {
            unrecoverable_blocks += 1;
        }
    }

    let actual_drop_pct = if total_symbols_sent > 0 {
        (symbols_dropped as f64 / total_symbols_sent as f64) * 100.0
    } else {
        0.0
    };

    let successful_recovery_pct = if total_blocks > 0 {
        ((total_blocks - unrecoverable_blocks) as f64 / total_blocks as f64) * 100.0
    } else {
        100.0
    };

    let redundancy_multiplier = if k > 0 { 1.0 + (m as f64 / k as f64) } else { 1.0 };
    let effective_goodput_ratio = if unrecoverable_blocks == 0 {
        1.0 / redundancy_multiplier
    } else {
        (successful_recovery_pct / 100.0) / redundancy_multiplier
    };

    FecSimulationReport {
        profile,
        k,
        m,
        total_blocks,
        payload_bytes: data.len(),
        simulated_loss_rate: loss_rate,
        total_symbols_sent,
        symbols_dropped,
        actual_drop_pct,
        symbols_recovered,
        unrecoverable_blocks,
        successful_recovery_pct,
        effective_goodput_ratio,
    }
}

// ---------------------------------------------------------------------------
// Unit & Integration Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_tables_and_arithmetic() {
        assert_eq!(gf_add(5, 5), 0);
        assert_eq!(gf_add(5, 3), 6);
        assert_eq!(gf_mul(0, 10), 0);
        assert_eq!(gf_mul(1, 42), 42);
        assert_eq!(gf_div(42, 1), 42);

        // Inversion test
        for a in 1..=255 {
            let inv = gf_inv(a);
            assert_eq!(gf_mul(a, inv), 1, "inversion failed for {}", a);
        }
    }

    #[test]
    fn test_cauchy_matrix_inversion() {
        let m = GfMatrix::cauchy(4, 4);
        let inv = m.invert().expect("Cauchy matrix must be invertible");

        // Multiply m * inv == I
        for r in 0..4 {
            for c in 0..4 {
                let mut sum = 0u8;
                for k in 0..4 {
                    sum = gf_add(sum, gf_mul(m.get(r, k), inv.get(k, c)));
                }
                let expected = if r == c { 1 } else { 0 };
                assert_eq!(sum, expected, "Identity mismatch at ({}, {})", r, c);
            }
        }
    }

    #[test]
    fn test_fec_single_parity_xor_roundtrip() {
        let codec = FecCodec::new(4, 1);
        let s0 = b"Hello world 1234".to_vec();
        let s1 = b"Velcrux QUIC WAN".to_vec();
        let s2 = b"Forward Error Cr".to_vec();
        let s3 = b"Erasure Code 042".to_vec();
        let sources = vec![s0.clone(), s1.clone(), s2.clone(), s3.clone()];

        let repair = codec.encode(&sources);
        assert_eq!(repair.len(), 1);
        assert_eq!(repair[0].index, 4);

        // Simulate losing symbol S1
        let received = vec![
            FecSymbol { index: 0, data: s0.clone() },
            // S1 is lost!
            FecSymbol { index: 2, data: s2.clone() },
            FecSymbol { index: 3, data: s3.clone() },
            repair[0].clone(), // Parity symbol R0
        ];

        let decoded = codec.decode(&received).expect("decode must succeed");
        assert_eq!(decoded[0], s0);
        assert_eq!(decoded[1], s1, "Lost symbol S1 must be recovered exactly");
        assert_eq!(decoded[2], s2);
        assert_eq!(decoded[3], s3);
    }

    #[test]
    fn test_fec_cauchy_dual_parity_roundtrip() {
        // (6, 4) code -> 4 data symbols, 2 repair symbols
        // Can recover from ANY 2 lost symbols out of 6!
        let codec = FecCodec::new(4, 2);
        let s0 = b"Block A payload!".to_vec();
        let s1 = b"Block B payload!".to_vec();
        let s2 = b"Block C payload!".to_vec();
        let s3 = b"Block D payload!".to_vec();
        let sources = vec![s0.clone(), s1.clone(), s2.clone(), s3.clone()];

        let repair = codec.encode(&sources);
        assert_eq!(repair.len(), 2);

        // Case 1: Lose S0 and S2, receive S1, S3, R0, R1
        let received = vec![
            FecSymbol { index: 1, data: s1.clone() },
            FecSymbol { index: 3, data: s3.clone() },
            repair[0].clone(),
            repair[1].clone(),
        ];

        let decoded = codec.decode(&received).expect("decode dual loss");
        assert_eq!(decoded[0], s0, "S0 must be recovered");
        assert_eq!(decoded[1], s1);
        assert_eq!(decoded[2], s2, "S2 must be recovered");
        assert_eq!(decoded[3], s3);

        // Case 2: Lose S2 and S3, receive S0, S1, R0, R1
        let received2 = vec![
            FecSymbol { index: 0, data: s0.clone() },
            FecSymbol { index: 1, data: s1.clone() },
            repair[0].clone(),
            repair[1].clone(),
        ];

        let decoded2 = codec.decode(&received2).expect("decode dual loss 2");
        assert_eq!(decoded2[0], s0);
        assert_eq!(decoded2[1], s1);
        assert_eq!(decoded2[2], s2);
        assert_eq!(decoded2[3], s3);
    }

    #[test]
    fn test_fec_insufficient_symbols_fails_gracefully() {
        let codec = FecCodec::new(4, 2);
        let s0 = b"Data 000".to_vec();
        let s1 = b"Data 001".to_vec();
        let s2 = b"Data 002".to_vec();
        let s3 = b"Data 003".to_vec();
        let sources = vec![s0, s1, s2, s3];
        let repair = codec.encode(&sources);

        // Receive only 3 symbols (4 required)
        let received = vec![
            FecSymbol { index: 0, data: b"Data 000".to_vec() },
            repair[0].clone(),
            repair[1].clone(),
        ];

        let decoded = codec.decode(&received);
        assert!(decoded.is_none(), "Decode must return None when fewer than K symbols are present");
    }

    #[test]
    fn test_adaptive_controller_gating() {
        let mut ctrl = AdaptiveFecController::new(FecProfile::Auto);

        // Clean link -> Disabled / 0%
        let (_k, m) = ctrl.adapt_to_loss(0.001);
        assert_eq!(m, 0);

        // Normal WAN 1% loss -> 5% parity
        let (k, m) = ctrl.adapt_to_loss(0.015);
        assert_eq!(k, 20);
        assert_eq!(m, 1);

        // Satellite 3% loss -> 12.5% parity
        let (k, m) = ctrl.adapt_to_loss(0.035);
        assert_eq!(k, 16);
        assert_eq!(m, 2);

        // Hostile 8% loss -> 20% parity
        let (k, m) = ctrl.adapt_to_loss(0.08);
        assert_eq!(k, 10);
        assert_eq!(m, 2);

        // Extreme satellite link 15% loss -> 25% parity
        let (k, m) = ctrl.adapt_to_loss(0.15);
        assert_eq!(k, 8);
        assert_eq!(m, 2);
    }

    #[test]
    fn test_fec_block_encoding_and_reassembly() {
        let payload = b"The quick brown fox jumps over the lazy dog. 1234567890! Fast erasure coding.";
        let (header, all_symbols) = FecBlockEncoder::encode_block(101, payload, 8, 2);
        assert_eq!(all_symbols.len(), 10); // 8 source + 2 parity

        // Simulate dropping 2 source symbols (index 2 and index 5)
        let mut received = Vec::new();
        for sym in all_symbols {
            if sym.index != 2 && sym.index != 5 {
                received.push(sym);
            }
        }
        assert_eq!(received.len(), 8);

        let (reconstructed, report) = FecBlockDecoder::decode_block(&header, &received);
        assert!(report.is_successful);
        assert_eq!(report.lost_source_count, 2);
        assert_eq!(report.recovered_source_count, 2);
        assert_eq!(reconstructed.unwrap(), payload);
    }

    #[test]
    fn test_simulate_fec_recovery_satellite() {
        let test_data = vec![0xFEu8; 256 * 1024]; // 256 KiB
        let report = simulate_fec_recovery(&test_data, FecProfile::Satellite, 0.02, 42);
        assert_eq!(report.unrecoverable_blocks, 0, "All blocks must be recovered under 2% satellite loss");
        assert_eq!(report.successful_recovery_pct, 100.0);
        assert!(report.symbols_recovered > 0, "Must recover erased symbols");
    }
}
