//! Dynamic Rateless Fountain Decoder (ADR-082).
//!
//! Implements a hybrid Peeling Decoder (Belief Propagation) + Gaussian Elimination
//! solver over GF(2) to reconstruct original source data from an arbitrary subset of
//! received Fountain symbols with near-zero overhead.

use std::collections::VecDeque;

use super::types::{
    FountainConfig, FountainDecoderStatus, FountainError, FountainHeader, FountainResult,
    FountainSymbol,
};

/// Rateless Fountain decoder reconstructing source payloads.
#[derive(Debug, Clone)]
pub struct FountainDecoder {
    header: FountainHeader,
    config: FountainConfig,
    k: usize,
    decoded_source: Vec<Option<Vec<u8>>>,
    decoded_count: usize,
    buffered_equations: Vec<(Vec<usize>, Vec<u8>)>,
    received_count: usize,
}

impl FountainDecoder {
    /// Create a new decoder initialized with container header metadata.
    #[must_use]
    pub fn new(header: FountainHeader, config: FountainConfig) -> Self {
        let k = header.k_source_symbols as usize;
        Self {
            header,
            config,
            k,
            decoded_source: vec![None; k],
            decoded_count: 0,
            buffered_equations: Vec::new(),
            received_count: 0,
        }
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

    /// Number of source symbols (K).
    #[must_use]
    pub fn k(&self) -> usize {
        self.k
    }

    /// Number of source symbols successfully decoded so far.
    #[must_use]
    pub fn decoded_count(&self) -> usize {
        self.decoded_count
    }

    /// Total symbols received so far.
    #[must_use]
    pub fn received_count(&self) -> usize {
        self.received_count
    }

    /// Whether all K source symbols have been successfully recovered.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.decoded_count >= self.k
    }

    /// Feed an incoming Fountain symbol into the decoder.
    ///
    /// Executes the belief-propagation peeling algorithm; if peeling pauses and sufficient
    /// symbols have been received, triggers Gaussian elimination over GF(2) to solve remaining
    /// dependencies.
    pub fn add_symbol(&mut self, symbol: FountainSymbol) {
        self.received_count += 1;
        if self.is_complete() {
            return;
        }

        let mut neighbors = symbol.neighbors;
        let mut data = symbol.data;

        // Step 1: Substitute all already-known source symbols
        let mut i = 0;
        while i < neighbors.len() {
            let n = neighbors[i];
            if let Some(known) = &self.decoded_source[n] {
                for (dst, &src) in data.iter_mut().zip(known.iter()) {
                    *dst ^= src;
                }
                neighbors.swap_remove(i);
            } else {
                i += 1;
            }
        }
        neighbors.sort_unstable();

        // Step 2: Handle resulting degree
        if neighbors.is_empty() {
            // Redundant symbol (already fully explained)
            return;
        }

        if neighbors.len() == 1 {
            let resolved_id = neighbors[0];
            if self.decoded_source[resolved_id].is_none() {
                self.decoded_source[resolved_id] = Some(data);
                self.decoded_count += 1;
                self.cascade_peeling(resolved_id);
            }
        } else {
            self.buffered_equations.push((neighbors, data));
        }

        // Step 3: If peeling paused and we have enough equations, run linear elimination
        if !self.is_complete() && (self.decoded_count + self.buffered_equations.len()) >= self.k {
            self.solve_gaussian_elimination();
        }
    }

    /// Cascade peeling decoder when a new source symbol is resolved.
    fn cascade_peeling(&mut self, initial_resolved: usize) {
        let mut queue = VecDeque::new();
        queue.push_back(initial_resolved);

        while let Some(resolved_id) = queue.pop_front() {
            let resolved_data = self.decoded_source[resolved_id].clone().unwrap();

            let mut i = 0;
            while i < self.buffered_equations.len() {
                let (neighbors, data) = &mut self.buffered_equations[i];

                if let Some(pos) = neighbors.iter().position(|&x| x == resolved_id) {
                    neighbors.swap_remove(pos);
                    neighbors.sort_unstable();

                    for (dst, &src) in data.iter_mut().zip(resolved_data.iter()) {
                        *dst ^= src;
                    }

                    if neighbors.len() == 1 {
                        let new_resolved = neighbors[0];
                        let new_data = data.clone();
                        self.buffered_equations.swap_remove(i);

                        if self.decoded_source[new_resolved].is_none() {
                            self.decoded_source[new_resolved] = Some(new_data);
                            self.decoded_count += 1;
                            queue.push_back(new_resolved);
                        }
                        continue;
                    } else if neighbors.is_empty() {
                        self.buffered_equations.swap_remove(i);
                        continue;
                    }
                }
                i += 1;
            }
        }
    }

    /// Gaussian elimination solver over GF(2) for remaining unsolved source symbols.
    fn solve_gaussian_elimination(&mut self) {
        if self.is_complete() || self.buffered_equations.is_empty() {
            return;
        }

        // Map unsolved source symbols to dense local indices
        let unsolved_indices: Vec<usize> = (0..self.k)
            .filter(|&idx| self.decoded_source[idx].is_none())
            .collect();
        let num_vars = unsolved_indices.len();
        if num_vars == 0 {
            return;
        }

        let mut var_to_col = vec![None; self.k];
        for (col, &var) in unsolved_indices.iter().enumerate() {
            var_to_col[var] = Some(col);
        }

        // Build binary augmented matrix: (row_bits, data_payload)
        struct Row {
            cols: Vec<bool>,
            data: Vec<u8>,
        }

        let mut rows = Vec::with_capacity(self.buffered_equations.len());
        for (neighbors, data) in &self.buffered_equations {
            let mut cols = vec![false; num_vars];
            let mut has_unsolved = false;
            for &n in neighbors {
                if let Some(col) = var_to_col[n] {
                    cols[col] = !cols[col];
                    has_unsolved = true;
                }
            }
            if has_unsolved {
                rows.push(Row {
                    cols,
                    data: data.clone(),
                });
            }
        }

        let num_rows = rows.len();
        let mut pivot_row = 0;

        // Forward elimination (Row Echelon Form)
        for col in 0..num_vars {
            if pivot_row >= num_rows {
                break;
            }

            // Find pivot row with 1 in this column
            let mut pivot = None;
            for r in pivot_row..num_rows {
                if rows[r].cols[col] {
                    pivot = Some(r);
                    break;
                }
            }

            let Some(p) = pivot else {
                continue;
            };

            rows.swap(pivot_row, p);

            let pivot_cols = rows[pivot_row].cols.clone();
            let pivot_data = rows[pivot_row].data.clone();

            // Eliminate column from all other rows
            for r in 0..num_rows {
                if r != pivot_row && rows[r].cols[col] {
                    for c in 0..num_vars {
                        rows[r].cols[c] ^= pivot_cols[c];
                    }
                    for (dst, &src) in rows[r].data.iter_mut().zip(pivot_data.iter()) {
                        *dst ^= src;
                    }
                }
            }

            pivot_row += 1;
        }

        // Identify solved single-variable rows and update buffered equations
        let mut new_solved = Vec::new();
        let mut new_buffered = Vec::new();

        for row in rows {
            let ones: Vec<usize> = row
                .cols
                .iter()
                .enumerate()
                .filter_map(|(col, &val)| if val { Some(col) } else { None })
                .collect();

            if ones.len() == 1 {
                let col = ones[0];
                let var_id = unsolved_indices[col];
                if self.decoded_source[var_id].is_none() {
                    self.decoded_source[var_id] = Some(row.data);
                    self.decoded_count += 1;
                    new_solved.push(var_id);
                }
            } else if ones.len() > 1 {
                let neighbors: Vec<usize> = ones.into_iter().map(|c| unsolved_indices[c]).collect();
                new_buffered.push((neighbors, row.data));
            }
        }

        self.buffered_equations = new_buffered;
        for var_id in new_solved {
            self.cascade_peeling(var_id);
        }
    }

    /// Retrieve the current decoder telemetry status.
    #[must_use]
    pub fn status(&self) -> FountainDecoderStatus {
        let needed = self.k.saturating_sub(self.decoded_count);
        let overhead_pct = if self.k > 0 {
            (self.received_count.saturating_sub(self.k) as f64 / self.k as f64) * 100.0
        } else {
            0.0
        };

        FountainDecoderStatus {
            k_source_symbols: self.k,
            received_symbols: self.received_count,
            symbols_needed: needed,
            decoded_source_symbols: self.decoded_count,
            is_complete: self.is_complete(),
            overhead_percentage: overhead_pct,
        }
    }

    /// Finalize decoding, assemble payload, strip padding, and verify BLAKE3 checksum.
    pub fn finish(&self) -> FountainResult<Vec<u8>> {
        if !self.is_complete() {
            return Err(FountainError::InsufficientSymbols {
                required: self.k,
                current: self.decoded_count,
            });
        }

        let mut payload = Vec::with_capacity(self.k * self.config.symbol_size);
        for i in 0..self.k {
            let sym = self.decoded_source[i].as_ref().ok_or_else(|| {
                FountainError::DecodingFailed(format!("Missing resolved source symbol {i}"))
            })?;
            payload.extend_from_slice(sym);
        }

        // Truncate zero-padding back to exact original length
        let orig_len = self.header.original_len as usize;
        if payload.len() < orig_len {
            return Err(FountainError::DecodingFailed(
                "Assembled payload smaller than original length".to_string(),
            ));
        }
        payload.truncate(orig_len);

        // Verify cryptographic BLAKE3 checksum
        let computed_hash = *blake3::hash(&payload).as_bytes();
        if computed_hash != self.header.blake3_hash {
            return Err(FountainError::ChecksumMismatch {
                expected: hex_encode(&self.header.blake3_hash),
                actual: hex_encode(&computed_hash),
            });
        }

        Ok(payload)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}
