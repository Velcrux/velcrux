//! Pure Safe Rust Reed-Solomon Erasure Coding Engine over Galois Field GF(2^8).
//!
//! Provides systematic (K + M, K) Maximum Distance Separable (MDS) erasure coding
//! using Cauchy generator matrices, binary shard envelopes with cryptographic BLAKE3
//! checksums, fast-path systematic reconstruction, and arbitrary shard recovery.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use crate::error::VelcruxError;
use crate::transport::fec::{gf_add, gf_mul, GfMatrix};

/// Magic bytes prefix for Velcrux Erasure Shard Envelope: "VEC1".
pub const SHARD_MAGIC: &[u8; 4] = b"VEC1";
/// Format version number for shard envelopes.
pub const SHARD_VERSION: u8 = 1;

/// Configuration schema for (K + M) Reed-Solomon Erasure Coding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureSchema {
    /// Number of data shards (K)
    pub data_shards: usize,
    /// Number of parity shards (M)
    pub parity_shards: usize,
}

impl ErasureSchema {
    /// Construct a new validated ErasureSchema.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, VelcruxError> {
        if data_shards == 0 || parity_shards == 0 {
            return Err(VelcruxError::Config(
                "Data shards (K) and parity shards (M) must both be >= 1".to_string(),
            ));
        }
        if data_shards + parity_shards > 256 {
            return Err(VelcruxError::Config(
                "Total shards (K + M) cannot exceed 256 in Galois Field GF(2^8)".to_string(),
            ));
        }
        Ok(Self {
            data_shards,
            parity_shards,
        })
    }

    /// Total number of shards (K + M).
    #[inline(always)]
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}

impl Default for ErasureSchema {
    fn default() -> Self {
        Self {
            data_shards: 4,
            parity_shards: 2,
        }
    }
}

/// Binary envelope encapsulating a single data or parity shard with integrity metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardEnvelope {
    /// Unique object identifier (e.g. ULID / UUID / filename)
    pub object_id: String,
    /// Erasure coding configuration schema (K, M)
    pub schema: ErasureSchema,
    /// Zero-based shard index (0..K are data shards; K..K+M are parity shards)
    pub shard_index: usize,
    /// Total original byte size of unpadded object
    pub original_size: u64,
    /// Cryptographic BLAKE3 checksum of the shard payload
    pub checksum: [u8; 32],
    /// Shard payload byte contents
    pub payload: Vec<u8>,
}

impl ShardEnvelope {
    /// Create a new ShardEnvelope and compute its BLAKE3 checksum.
    pub fn new(
        object_id: String,
        schema: ErasureSchema,
        shard_index: usize,
        original_size: u64,
        payload: Vec<u8>,
    ) -> Self {
        let checksum = *blake3::hash(&payload).as_bytes();
        Self {
            object_id,
            schema,
            shard_index,
            original_size,
            checksum,
            payload,
        }
    }

    /// Returns true if this shard is a systematic original data shard (index < K).
    #[inline(always)]
    pub fn is_data_shard(&self) -> bool {
        self.shard_index < self.schema.data_shards
    }

    /// Returns true if this shard is an erasure parity shard (index >= K).
    #[inline(always)]
    pub fn is_parity_shard(&self) -> bool {
        self.shard_index >= self.schema.data_shards
    }

    /// Verify the cryptographic BLAKE3 checksum of the shard payload.
    pub fn verify_checksum(&self) -> bool {
        let computed = *blake3::hash(&self.payload).as_bytes();
        computed == self.checksum
    }

    /// Serialize this shard envelope into a binary buffer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let obj_bytes = self.object_id.as_bytes();
        let header_len = 4 + 1 + 1 + 1 + 1 + 8 + 4 + 32 + 2 + obj_bytes.len();
        let mut buf = Vec::with_capacity(header_len + self.payload.len());

        buf.extend_from_slice(SHARD_MAGIC);
        buf.push(SHARD_VERSION);
        buf.push(self.schema.data_shards as u8);
        buf.push(self.schema.parity_shards as u8);
        buf.push(self.shard_index as u8);
        buf.extend_from_slice(&self.original_size.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.checksum);
        buf.extend_from_slice(&(obj_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(obj_bytes);
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Parse a ShardEnvelope from a binary buffer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VelcruxError> {
        const MIN_HEADER: usize = 4 + 1 + 1 + 1 + 1 + 8 + 4 + 32 + 2;
        if bytes.len() < MIN_HEADER {
            return Err(VelcruxError::Protocol(
                crate::error::ProtocolError::Malformed(
                    "Shard envelope buffer is shorter than minimum header size",
                ),
            ));
        }

        if &bytes[0..4] != SHARD_MAGIC {
            return Err(VelcruxError::Protocol(
                crate::error::ProtocolError::Malformed(
                    "Invalid shard envelope magic bytes (expected 'VEC1')",
                ),
            ));
        }

        let version = bytes[4];
        if version != SHARD_VERSION {
            return Err(VelcruxError::Protocol(
                crate::error::ProtocolError::Malformed("Unsupported shard envelope format version"),
            ));
        }

        let data_shards = bytes[5] as usize;
        let parity_shards = bytes[6] as usize;
        let shard_index = bytes[7] as usize;

        let mut orig_size_buf = [0u8; 8];
        orig_size_buf.copy_from_slice(&bytes[8..16]);
        let original_size = u64::from_be_bytes(orig_size_buf);

        let mut payload_len_buf = [0u8; 4];
        payload_len_buf.copy_from_slice(&bytes[16..20]);
        let payload_len = u32::from_be_bytes(payload_len_buf) as usize;

        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&bytes[20..52]);

        let mut obj_len_buf = [0u8; 2];
        obj_len_buf.copy_from_slice(&bytes[52..54]);
        let obj_len = u16::from_be_bytes(obj_len_buf) as usize;

        let total_header_len = MIN_HEADER + obj_len;
        if bytes.len() < total_header_len + payload_len {
            return Err(VelcruxError::Protocol(
                crate::error::ProtocolError::Malformed("Truncated shard envelope payload buffer"),
            ));
        }

        let object_id = std::str::from_utf8(&bytes[54..54 + obj_len])
            .map_err(|_| {
                VelcruxError::Protocol(crate::error::ProtocolError::Malformed(
                    "Invalid UTF-8 in shard envelope object_id",
                ))
            })?
            .to_string();

        let payload = bytes[total_header_len..total_header_len + payload_len].to_vec();

        let schema = ErasureSchema::new(data_shards, parity_shards)?;
        let env = Self {
            object_id,
            schema,
            shard_index,
            original_size,
            checksum,
            payload,
        };

        if !env.verify_checksum() {
            return Err(VelcruxError::Internal(format!(
                "Shard {} checksum mismatch: payload corrupted or altered",
                shard_index
            )));
        }

        Ok(env)
    }

    /// Save this shard envelope directly to a file on disk.
    pub fn save_to_file(&self, path: &Path) -> Result<(), VelcruxError> {
        let bytes = self.to_bytes();
        let mut file = File::create(path).map_err(VelcruxError::Io)?;
        file.write_all(&bytes).map_err(VelcruxError::Io)?;
        file.sync_all().map_err(VelcruxError::Io)?;
        Ok(())
    }

    /// Load a shard envelope from a file on disk.
    pub fn load_from_file(path: &Path) -> Result<Self, VelcruxError> {
        let mut file = File::open(path).map_err(VelcruxError::Io)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(VelcruxError::Io)?;
        Self::from_bytes(&bytes)
    }
}

/// Pure safe Rust Reed-Solomon (K + M) Erasure Coding Engine.
pub struct ErasureEngine;

impl ErasureEngine {
    /// Encode raw payload into (K + M) systematic data and Cauchy parity shards.
    pub fn encode(
        data: &[u8],
        schema: ErasureSchema,
        object_id: &str,
    ) -> Result<Vec<ShardEnvelope>, VelcruxError> {
        let k = schema.data_shards;
        let m = schema.parity_shards;
        let original_size = data.len() as u64;

        // Calculate uniform shard size (padded to multiple of K)
        let shard_size = if data.is_empty() {
            1
        } else {
            data.len().div_ceil(k)
        };

        // Split into K data shards with zero padding
        let mut data_shards: Vec<Vec<u8>> = Vec::with_capacity(k);
        for i in 0..k {
            let start = i * shard_size;
            let end = ((i + 1) * shard_size).min(data.len());
            let mut shard = vec![0u8; shard_size];
            if start < data.len() {
                let slice = &data[start..end];
                shard[..slice.len()].copy_from_slice(slice);
            }
            data_shards.push(shard);
        }

        // Cauchy generator matrix of size (M x K)
        let cauchy = GfMatrix::cauchy(m, k);

        // Compute M parity shards: P_i = sum_j (C[i, j] * D_j)
        let mut parity_shards: Vec<Vec<u8>> = Vec::with_capacity(m);
        for i in 0..m {
            let mut p_shard = vec![0u8; shard_size];
            for j in 0..k {
                let factor = cauchy.get(i, j);
                if factor != 0 {
                    let d_shard = &data_shards[j];
                    for b in 0..shard_size {
                        let term = gf_mul(factor, d_shard[b]);
                        p_shard[b] = gf_add(p_shard[b], term);
                    }
                }
            }
            parity_shards.push(p_shard);
        }

        // Package all K + M shards into envelopes
        let mut envelopes = Vec::with_capacity(k + m);
        for (i, shard_payload) in data_shards.into_iter().enumerate() {
            envelopes.push(ShardEnvelope::new(
                object_id.to_string(),
                schema,
                i,
                original_size,
                shard_payload,
            ));
        }
        for (i, shard_payload) in parity_shards.into_iter().enumerate() {
            envelopes.push(ShardEnvelope::new(
                object_id.to_string(),
                schema,
                k + i,
                original_size,
                shard_payload,
            ));
        }

        Ok(envelopes)
    }

    /// Decode raw payload from any surviving subset containing at least K valid shards.
    pub fn decode(
        shards: &[Option<ShardEnvelope>],
        schema: ErasureSchema,
    ) -> Result<Vec<u8>, VelcruxError> {
        let k = schema.data_shards;
        let m = schema.parity_shards;

        // 1. Gather valid shards with verified checksums
        let mut valid_shards: Vec<(usize, &ShardEnvelope)> = Vec::new();
        for (idx, opt) in shards.iter().enumerate() {
            if let Some(shard) = opt {
                if shard.verify_checksum() {
                    valid_shards.push((shard.shard_index.min(idx), shard));
                }
            }
        }

        if valid_shards.len() < k {
            return Err(VelcruxError::Internal(format!(
                "Unrecoverable object: {} valid shards available, but {} required",
                valid_shards.len(),
                k
            )));
        }

        let original_size = valid_shards[0].1.original_size as usize;
        let shard_size = valid_shards[0].1.payload.len();

        // 2. Fast path: All K original data shards are intact
        let mut has_all_data = true;
        for i in 0..k {
            if !valid_shards.iter().any(|(idx, _)| *idx == i) {
                has_all_data = false;
                break;
            }
        }

        if has_all_data {
            let mut out = Vec::with_capacity(k * shard_size);
            for i in 0..k {
                let (_, shard) = valid_shards.iter().find(|(idx, _)| *idx == i).unwrap();
                out.extend_from_slice(&shard.payload);
            }
            out.truncate(original_size);
            return Ok(out);
        }

        // 3. Reconstruction path: Select any K valid shards and build decoding matrix
        let selected: Vec<(usize, &ShardEnvelope)> = valid_shards.into_iter().take(k).collect();
        let cauchy = GfMatrix::cauchy(m, k);

        // Submatrix A of size (K x K) from generator matrix G = [ I_K | C ]
        let mut a = GfMatrix::zeros(k, k);
        for (row, &(shard_idx, _)) in selected.iter().enumerate() {
            if shard_idx < k {
                // Identity row: A[row, shard_idx] = 1
                a.set(row, shard_idx, 1);
            } else {
                // Cauchy row: C[shard_idx - K, :]
                let c_row = shard_idx - k;
                for col in 0..k {
                    a.set(row, col, cauchy.get(c_row, col));
                }
            }
        }

        // Invert submatrix A
        let inv_a = a.invert().ok_or_else(|| {
            VelcruxError::Internal("Erasure coding decoding matrix inversion failed".to_string())
        })?;

        // Recover original K data shards: D_j = sum_r (inv_A[j, r] * Selected_r)
        let mut recovered_data: Vec<Vec<u8>> = vec![vec![0u8; shard_size]; k];
        for j in 0..k {
            for (r, &(_, env)) in selected.iter().enumerate() {
                let factor = inv_a.get(j, r);
                if factor != 0 {
                    let s_shard = &env.payload;
                    for b in 0..shard_size {
                        let term = gf_mul(factor, s_shard[b]);
                        recovered_data[j][b] = gf_add(recovered_data[j][b], term);
                    }
                }
            }
        }

        // Concatenate recovered data and truncate to original size
        let mut out = Vec::with_capacity(k * shard_size);
        for d_shard in recovered_data {
            out.extend_from_slice(&d_shard);
        }
        out.truncate(original_size);

        Ok(out)
    }

    /// Reconstruct all (K + M) complete envelopes from any valid subset with >= K shards.
    pub fn reconstruct_all(
        available: &[ShardEnvelope],
        schema: ErasureSchema,
    ) -> Result<Vec<ShardEnvelope>, VelcruxError> {
        let total = schema.total_shards();
        let mut slots: Vec<Option<ShardEnvelope>> = vec![None; total];
        for env in available {
            if env.shard_index < total && env.verify_checksum() {
                slots[env.shard_index] = Some(env.clone());
            }
        }

        // Decode original data
        let decoded_payload = Self::decode(&slots, schema)?;
        let object_id = if let Some(first) = available.first() {
            first.object_id.clone()
        } else {
            "reconstructed_object".to_string()
        };

        // Re-encode freshly to produce the canonical full set of K + M shards
        Self::encode(&decoded_payload, schema, &object_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_validation() {
        assert!(ErasureSchema::new(4, 2).is_ok());
        assert!(ErasureSchema::new(8, 4).is_ok());
        assert!(ErasureSchema::new(0, 2).is_err());
        assert!(ErasureSchema::new(4, 0).is_err());
        assert!(ErasureSchema::new(200, 100).is_err()); // > 256
    }

    #[test]
    fn test_shard_envelope_binary_roundtrip() {
        let schema = ErasureSchema::new(4, 2).unwrap();
        let payload = vec![0x42; 1024];
        let env = ShardEnvelope::new(
            "object-alpha-123".to_string(),
            schema,
            1,
            3500,
            payload.clone(),
        );

        assert!(env.is_data_shard());
        assert!(!env.is_parity_shard());
        assert!(env.verify_checksum());

        let bytes = env.to_bytes();
        let decoded = ShardEnvelope::from_bytes(&bytes).expect("decode envelope");

        assert_eq!(decoded.object_id, "object-alpha-123");
        assert_eq!(decoded.schema, schema);
        assert_eq!(decoded.shard_index, 1);
        assert_eq!(decoded.original_size, 3500);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_erasure_encode_and_decode_clean() {
        let schema = ErasureSchema::new(4, 2).unwrap();
        let original_data = b"Hello, Velcrux Distributed Erasure Coding World! 2026";
        let shards = ErasureEngine::encode(original_data, schema, "obj-test").unwrap();

        assert_eq!(shards.len(), 6); // 4 data + 2 parity

        // Decode with all shards present
        let slots: Vec<Option<ShardEnvelope>> = shards.into_iter().map(Some).collect();
        let decoded = ErasureEngine::decode(&slots, schema).unwrap();
        assert_eq!(decoded, original_data);
    }

    #[test]
    fn test_erasure_decode_missing_data_shards() {
        let schema = ErasureSchema::new(4, 2).unwrap();
        let original_data = b"Testing reconstruction with 2 lost data shards in a (4+2) schema.";
        let shards = ErasureEngine::encode(original_data, schema, "obj-loss").unwrap();

        // Simulate loss of data shard 0 and data shard 2 (leaving data shards 1, 3 and parity shards 4, 5)
        let mut slots: Vec<Option<ShardEnvelope>> = vec![None; 6];
        slots[1] = Some(shards[1].clone());
        slots[3] = Some(shards[3].clone());
        slots[4] = Some(shards[4].clone());
        slots[5] = Some(shards[5].clone());

        let decoded = ErasureEngine::decode(&slots, schema).unwrap();
        assert_eq!(decoded, original_data);
    }

    #[test]
    fn test_erasure_decode_unrecoverable() {
        let schema = ErasureSchema::new(4, 2).unwrap();
        let original_data = b"Short payload";
        let shards = ErasureEngine::encode(original_data, schema, "obj-unrec").unwrap();

        // Only 3 shards survive out of 4 required (loss of 3 shards in 4+2)
        let mut slots: Vec<Option<ShardEnvelope>> = vec![None; 6];
        slots[0] = Some(shards[0].clone());
        slots[1] = Some(shards[1].clone());
        slots[4] = Some(shards[4].clone());

        let res = ErasureEngine::decode(&slots, schema);
        assert!(res.is_err());
        let err_msg = format!("{:?}", res.unwrap_err());
        assert!(err_msg.contains("Unrecoverable object"));
    }

    #[test]
    fn test_reconstruct_all_shards() {
        let schema = ErasureSchema::new(4, 2).unwrap();
        let original_data = b"Reconstructing full shard set from partial surviving subset.";
        let shards = ErasureEngine::encode(original_data, schema, "obj-recon").unwrap();

        // Provide only shards 0, 1, 4, 5 (missing 2 and 3)
        let available = vec![
            shards[0].clone(),
            shards[1].clone(),
            shards[4].clone(),
            shards[5].clone(),
        ];

        let reconstructed = ErasureEngine::reconstruct_all(&available, schema).unwrap();
        assert_eq!(reconstructed.len(), 6);
        for i in 0..6 {
            assert_eq!(reconstructed[i].shard_index, i);
            assert_eq!(reconstructed[i].payload, shards[i].payload);
        }
    }
}
