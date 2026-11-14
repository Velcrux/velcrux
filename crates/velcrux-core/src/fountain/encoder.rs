//! Dynamic Rateless Fountain Encoder (ADR-082).
//!
//! Slices arbitrary binary payloads into K source blocks and produces an unbounded,
//! infinite stream of encoded Fountain repair symbols.

use super::distribution::sample_neighbors;
use super::types::{
    FountainConfig, FountainError, FountainHeader, FountainResult, FountainSymbol, FOUNTAIN_MAGIC,
    FOUNTAIN_VERSION,
};

/// Rateless Fountain encoder producing boundless repair packets.
#[derive(Debug, Clone)]
pub struct FountainEncoder {
    config: FountainConfig,
    header: FountainHeader,
    source_symbols: Vec<Vec<u8>>,
    k: usize,
}

impl FountainEncoder {
    /// Create a new FountainEncoder from raw data payload.
    pub fn new(data: &[u8], config: FountainConfig) -> FountainResult<Self> {
        config.validate()?;
        if data.is_empty() {
            return Err(FountainError::DataTooShort);
        }

        let blake3_hash = *blake3::hash(data).as_bytes();
        let sym_size = config.symbol_size;
        let k = data.len().div_ceil(sym_size);

        let mut source_symbols = Vec::with_capacity(k);
        for chunk in data.chunks(sym_size) {
            let mut sym = chunk.to_vec();
            if sym.len() < sym_size {
                sym.resize(sym_size, 0u8); // Zero-padding final chunk
            }
            source_symbols.push(sym);
        }

        let header = FountainHeader {
            magic: *FOUNTAIN_MAGIC,
            version: FOUNTAIN_VERSION,
            original_len: data.len() as u64,
            k_source_symbols: k as u32,
            symbol_size: sym_size as u32,
            blake3_hash,
        };

        Ok(Self {
            config,
            header,
            source_symbols,
            k,
        })
    }

    /// Number of source blocks (K).
    #[must_use]
    pub fn k(&self) -> usize {
        self.k
    }

    /// Access header metadata.
    #[must_use]
    pub fn header(&self) -> &FountainHeader {
        &self.header
    }

    /// Access configuration.
    #[must_use]
    pub fn config(&self) -> &FountainConfig {
        &self.config
    }

    /// Generate a single Fountain symbol with the specified Encoding Symbol ID (ESI).
    #[must_use]
    pub fn encode_symbol(&self, esi: u32) -> FountainSymbol {
        // Fast-path systematic symbol
        if self.config.systematic && (esi as usize) < self.k {
            let idx = esi as usize;
            return FountainSymbol {
                esi,
                degree: 1,
                neighbors: vec![idx],
                data: self.source_symbols[idx].clone(),
            };
        }

        let (degree, neighbors) = sample_neighbors(esi, self.k, &self.config);
        let mut data = vec![0u8; self.config.symbol_size];

        for &n in &neighbors {
            let src = &self.source_symbols[n];
            for (dst_byte, &src_byte) in data.iter_mut().zip(src.iter()) {
                *dst_byte ^= src_byte;
            }
        }

        FountainSymbol {
            esi,
            degree,
            neighbors,
            data,
        }
    }

    /// Generate a batch of sequential Fountain symbols starting at `start_esi`.
    #[must_use]
    pub fn encode_batch(&self, start_esi: u32, count: usize) -> Vec<FountainSymbol> {
        (0..count)
            .map(|offset| self.encode_symbol(start_esi.saturating_add(offset as u32)))
            .collect()
    }
}
