//! Distributed Homomorphic Encrypted Search Index & Query Evaluator (ADR-084).
//!
//! Stores encrypted metadata records across untrusted storage nodes and evaluates
//! encrypted search predicates without decrypting stored index records or query parameters.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::Instant;

use super::bfv::FheEvaluator;
use super::types::{
    FheEncryptedRecord, FheError, FheParams, FhePlaintext, FheQuery, FheQueryResult, FheResult,
    FheStatus,
};

/// Encrypted search index over sharded object metadata.
pub struct FheSearchIndex {
    params: FheParams,
    records: HashMap<String, FheEncryptedRecord>,
    total_evaluations: usize,
}

impl FheSearchIndex {
    /// Initialize a new encrypted index with specified FHE parameters.
    pub fn new(params: FheParams) -> Self {
        Self {
            params,
            records: HashMap::new(),
            total_evaluations: 0,
        }
    }

    /// Access scheme parameters.
    #[must_use]
    pub fn params(&self) -> &FheParams {
        &self.params
    }

    /// Insert or update an encrypted metadata record.
    pub fn insert_record(&mut self, record: FheEncryptedRecord) {
        self.records.insert(record.chunk_id.clone(), record);
    }

    /// Retrieve an encrypted record by chunk ID.
    #[must_use]
    pub fn get_record(&self, chunk_id: &str) -> Option<&FheEncryptedRecord> {
        self.records.get(chunk_id)
    }

    /// Remove a record from the index.
    pub fn remove_record(&mut self, chunk_id: &str) -> Option<FheEncryptedRecord> {
        self.records.remove(chunk_id)
    }

    /// Number of records currently indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Evaluate an encrypted query across all records matching tenant_id.
    ///
    /// For each record, evaluates the homomorphic difference $(c_{rec} - c_{query})$.
    /// When secret key `sk` is provided (client-assisted verification), decrypts the difference
    /// vector and confirms exact attribute match ($m_{diff}[0] == 0$).
    /// When `sk` is None (untrusted server mode), performs threshold evaluation over difference norm.
    pub fn execute_search(
        &mut self,
        query: &FheQuery,
        sk: Option<&super::types::FheSecretKey>,
    ) -> FheResult<FheQueryResult> {
        let start = Instant::now();
        let mut matching_chunk_ids = Vec::new();
        let mut min_noise = i64::MAX;
        let mut scanned = 0;

        for record in self.records.values() {
            if record.tenant_id != query.tenant_id {
                continue;
            }
            scanned += 1;

            // Homomorphic difference: c_diff = c_record - c_query
            let diff_ct = FheEvaluator::sub(
                &record.encrypted_attributes,
                &query.query_vector,
                &self.params,
            )?;

            min_noise = min_noise.min(diff_ct.noise_budget_bits);
            self.total_evaluations += 1;

            let is_match = if let Some(secret_key) = sk {
                if let Ok(decrypted) =
                    super::bfv::FheDecryptor::decrypt(secret_key, &diff_ct, &self.params)
                {
                    decrypted.poly.coeffs.first().copied().unwrap_or(1) == 0
                } else {
                    false
                }
            } else {
                let diff_norm: u64 = diff_ct
                    .c0
                    .coeffs
                    .iter()
                    .take(4)
                    .map(|&c| {
                        if c > self.params.coeff_modulus / 2 {
                            self.params.coeff_modulus - c
                        } else {
                            c
                        }
                    })
                    .sum();
                diff_norm < (self.params.delta / 4)
            };

            if is_match {
                matching_chunk_ids.push(record.chunk_id.clone());
            }
        }

        matching_chunk_ids.sort();

        let elapsed_us = start.elapsed().as_micros() as u64;

        Ok(FheQueryResult {
            query_id: query.query_id.clone(),
            matching_chunk_ids,
            total_records_scanned: scanned,
            evaluation_time_us: elapsed_us,
            min_noise_budget_remaining_bits: if min_noise == i64::MAX {
                self.params.initial_noise_budget_bits() as i64
            } else {
                min_noise
            },
        })
    }

    /// Evaluate a homomorphic weighted relevance score for a record without decrypting.
    ///
    /// Computes $c_{score} = \sum w_i \cdot c_i \pmod q$.
    pub fn evaluate_weighted_score(
        &self,
        record: &FheEncryptedRecord,
        weights: &[u64],
    ) -> FheResult<super::types::FheCiphertext> {
        if weights.is_empty() {
            return Err(FheError::InvalidParams(
                "Weights slice is empty".to_string(),
            ));
        }

        let pt_weights =
            FhePlaintext::from_values(weights, self.params.poly_degree, self.params.plain_modulus);

        FheEvaluator::mul_plain(&record.encrypted_attributes, &pt_weights, &self.params)
    }

    /// Telemetry status snapshot.
    #[must_use]
    pub fn status(&self) -> FheStatus {
        FheStatus {
            engine_status: "ACTIVE (BFV Cyclotomic Leveled Homomorphic Ring)".to_string(),
            poly_degree: self.params.poly_degree,
            coeff_modulus: self.params.coeff_modulus,
            plain_modulus: self.params.plain_modulus,
            scale_factor_delta: self.params.delta,
            initial_noise_budget_bits: self.params.initial_noise_budget_bits(),
            total_indexed_records: self.records.len(),
        }
    }
}
