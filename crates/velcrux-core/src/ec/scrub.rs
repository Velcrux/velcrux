//! Autonomous Shard Scrubbing & Self-Healing Repair Mesh (Option CI, ADR-051).
//!
//! Inspects distributed shard replicas across storage tiers, identifies cryptographic
//! corruption or missing shards, computes degraded/critical health states, and
//! automatically executes on-the-fly Galois Field reconstruction to restore full redundancy.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::ec::engine::{ErasureEngine, ErasureSchema, ShardEnvelope, SHARD_MAGIC};
use crate::error::VelcruxError;

/// Health status of an erasure-coded object in distributed storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectHealthState {
    /// All (K + M) shards are present, intact, and cryptographically verified.
    Healthy,
    /// Between K and (K + M - 1) valid shards survive. Can be fully self-healed.
    Degraded,
    /// Exactly K valid shards survive. Zero fault tolerance remaining before permanent data loss.
    Critical,
    /// Fewer than K valid shards survive. Unrecoverable without external backups.
    Unrecoverable,
}

impl ObjectHealthState {
    /// Returns true if the object can be repaired or decoded.
    #[inline(always)]
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded | Self::Critical)
    }

    /// Canonical status string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Critical => "critical",
            Self::Unrecoverable => "unrecoverable",
        }
    }
}

/// Inspection summary for a single erasure-coded object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcObjectScrubSummary {
    /// Unique object identifier
    pub object_id: String,
    /// Erasure coding schema (K, M)
    pub schema: ErasureSchema,
    /// Total expected shards (K + M)
    pub total_expected_shards: usize,
    /// Number of valid verified shards present on disk
    pub valid_shards: usize,
    /// Number of corrupted shards detected (checksum mismatch or malformed)
    pub corrupted_shards: usize,
    /// Number of missing shard indices
    pub missing_shards: usize,
    /// Current health state
    pub state: ObjectHealthState,
    /// Missing or corrupted shard indices needing reconstruction
    pub repairable_indices: Vec<usize>,
}

/// Aggregated report from scrubbing a storage directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcScrubReport {
    /// Total raw files inspected
    pub total_files_scanned: usize,
    /// Valid shard envelopes identified
    pub valid_shards: usize,
    /// Corrupted shard envelopes identified
    pub corrupted_shards: usize,
    /// Total unique erasure-coded objects scanned
    pub objects_scanned: usize,
    /// Objects with full (K + M) redundancy
    pub healthy_objects: usize,
    /// Objects with surviving shards >= K, but < K + M
    pub degraded_objects: usize,
    /// Objects with exactly K surviving shards
    pub critical_objects: usize,
    /// Objects with surviving shards < K (permanent data loss)
    pub unrecoverable_objects: usize,
    /// Detailed summaries for each scanned object
    pub object_summaries: Vec<EcObjectScrubSummary>,
}

/// Outcome of repairing a degraded or critical erasure-coded object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcRepairReport {
    /// Object identifier repaired
    pub object_id: String,
    /// Erasure coding schema (K, M)
    pub schema: ErasureSchema,
    /// Number of shards reconstructed and restored to disk
    pub shards_repaired: usize,
    /// Specific shard indices reconstructed
    pub repaired_indices: Vec<usize>,
    /// Repair operation latency in nanoseconds
    pub repair_latency_nanoseconds: u64,
}

/// Outcome of automatic directory scrubbing and self-healing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcAutoRepairReport {
    /// Scrub report results before repair
    pub scrub_report: EcScrubReport,
    /// Objects successfully repaired
    pub objects_repaired: usize,
    /// Total individual shards reconstructed
    pub shards_reconstructed: usize,
    /// Individual repair operation reports
    pub repairs: Vec<EcRepairReport>,
}

/// Microsecond performance benchmark results for Erasure Coding and Self-Healing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcBenchmarkReport {
    /// Number of benchmark iterations evaluated
    pub iterations: usize,
    /// Tested payload size in bytes per iteration
    pub payload_size_bytes: usize,
    /// Erasure coding schema used
    pub schema: ErasureSchema,
    /// Average encoding latency in nanoseconds
    pub encode_latency_nanoseconds: f64,
    /// Encoding throughput in bytes per second
    pub encode_throughput_bytes_per_sec: f64,
    /// Average decoding latency in nanoseconds (with parity reconstruction)
    pub decode_latency_nanoseconds: f64,
    /// Decoding throughput in bytes per second
    pub decode_throughput_bytes_per_sec: f64,
    /// Average single-shard repair latency in nanoseconds
    pub single_shard_repair_latency_nanoseconds: f64,
}

/// Autonomous Shard Scrubbing & Self-Healing Repair Mesh.
pub struct ShardScrubMesh {
    encoded_shards_total: AtomicU64,
    repaired_shards_total: AtomicU64,
    scrubbed_shards_total: AtomicU64,
    corrupted_shards_total: AtomicU64,
    degraded_objects: AtomicU64,
    repair_latency_nanoseconds: AtomicU64,
}

impl Default for ShardScrubMesh {
    fn default() -> Self {
        Self::new()
    }
}

impl ShardScrubMesh {
    /// Create a new ShardScrubMesh instance.
    pub fn new() -> Self {
        Self {
            encoded_shards_total: AtomicU64::new(0),
            repaired_shards_total: AtomicU64::new(0),
            scrubbed_shards_total: AtomicU64::new(0),
            corrupted_shards_total: AtomicU64::new(0),
            degraded_objects: AtomicU64::new(0),
            repair_latency_nanoseconds: AtomicU64::new(0),
        }
    }

    /// Read telemetry counters:
    /// `(encoded_total, repaired_total, scrubbed_total, corrupted_total, degraded_objects, last_latency_ns)`
    pub fn stats(&self) -> (u64, u64, u64, u64, u64, u64) {
        (
            self.encoded_shards_total.load(Ordering::Relaxed),
            self.repaired_shards_total.load(Ordering::Relaxed),
            self.scrubbed_shards_total.load(Ordering::Relaxed),
            self.corrupted_shards_total.load(Ordering::Relaxed),
            self.degraded_objects.load(Ordering::Relaxed),
            self.repair_latency_nanoseconds.load(Ordering::Relaxed),
        )
    }

    /// Record newly encoded shards.
    pub fn record_encoded_shards(&self, count: u64) {
        self.encoded_shards_total
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Autonomous background scrubber: scans a directory for shard envelopes and validates integrity.
    pub fn scrub_directory(&self, dir: &Path) -> Result<EcScrubReport, VelcruxError> {
        let mut total_files = 0;
        let mut valid_count = 0;
        let mut corrupt_count = 0;

        // Group shards by object_id: (object_id -> HashMap<shard_idx, Result<ShardEnvelope, PathBuf>>)
        let mut object_shards: HashMap<
            String,
            (
                ErasureSchema,
                HashMap<usize, Result<ShardEnvelope, PathBuf>>,
            ),
        > = HashMap::new();

        if dir.exists() && dir.is_dir() {
            let entries = fs::read_dir(dir).map_err(VelcruxError::Io)?;
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    total_files += 1;
                    self.scrubbed_shards_total.fetch_add(1, Ordering::Relaxed);

                    let bytes = match fs::read(&path) {
                        Ok(b) => b,
                        Err(_) => continue,
                    };

                    if bytes.len() >= 4 && &bytes[0..4] == SHARD_MAGIC {
                        match ShardEnvelope::from_bytes(&bytes) {
                            Ok(env) => {
                                valid_count += 1;
                                let entry = object_shards
                                    .entry(env.object_id.clone())
                                    .or_insert_with(|| (env.schema, HashMap::new()));
                                entry.1.insert(env.shard_index, Ok(env));
                            }
                            Err(_) => {
                                corrupt_count += 1;
                                self.corrupted_shards_total.fetch_add(1, Ordering::Relaxed);
                                // Attempt partial parse to extract object_id and shard_index
                                if bytes.len() >= 54 {
                                    let shard_idx = bytes[7] as usize;
                                    let obj_len =
                                        u16::from_be_bytes([bytes[52], bytes[53]]) as usize;
                                    if bytes.len() >= 54 + obj_len {
                                        if let Ok(obj_id) =
                                            std::str::from_utf8(&bytes[54..54 + obj_len])
                                        {
                                            let schema = ErasureSchema::new(
                                                bytes[5] as usize,
                                                bytes[6] as usize,
                                            )
                                            .unwrap_or_default();
                                            let entry = object_shards
                                                .entry(obj_id.to_string())
                                                .or_insert_with(|| (schema, HashMap::new()));
                                            entry.1.insert(shard_idx, Err(path));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut healthy_objs = 0;
        let mut degraded_objs = 0;
        let mut critical_objs = 0;
        let mut unrecoverable_objs = 0;
        let mut summaries = Vec::new();

        for (object_id, (schema, shards_map)) in object_shards {
            let total_expected = schema.total_shards();
            let mut valid_shards_for_obj = 0;
            let mut corrupt_shards_for_obj = 0;
            let mut repairable_indices = Vec::new();

            for idx in 0..total_expected {
                match shards_map.get(&idx) {
                    Some(Ok(_)) => valid_shards_for_obj += 1,
                    Some(Err(_)) => {
                        corrupt_shards_for_obj += 1;
                        repairable_indices.push(idx);
                    }
                    None => repairable_indices.push(idx),
                }
            }

            let missing_shards = total_expected - valid_shards_for_obj - corrupt_shards_for_obj;

            let state = if valid_shards_for_obj == total_expected {
                healthy_objs += 1;
                ObjectHealthState::Healthy
            } else if valid_shards_for_obj >= schema.data_shards {
                if valid_shards_for_obj == schema.data_shards {
                    critical_objs += 1;
                    ObjectHealthState::Critical
                } else {
                    degraded_objs += 1;
                    ObjectHealthState::Degraded
                }
            } else {
                unrecoverable_objs += 1;
                ObjectHealthState::Unrecoverable
            };

            summaries.push(EcObjectScrubSummary {
                object_id,
                schema,
                total_expected_shards: total_expected,
                valid_shards: valid_shards_for_obj,
                corrupted_shards: corrupt_shards_for_obj,
                missing_shards,
                state,
                repairable_indices,
            });
        }

        let total_degraded = degraded_objs + critical_objs;
        self.degraded_objects
            .store(total_degraded as u64, Ordering::Relaxed);

        Ok(EcScrubReport {
            total_files_scanned: total_files,
            valid_shards: valid_count,
            corrupted_shards: corrupt_count,
            objects_scanned: summaries.len(),
            healthy_objects: healthy_objs,
            degraded_objects: degraded_objs,
            critical_objects: critical_objs,
            unrecoverable_objects: unrecoverable_objs,
            object_summaries: summaries,
        })
    }

    /// Autonomous repair: Reconstruct missing or corrupted shards for a specific object in directory.
    pub fn repair_object(
        &self,
        dir: &Path,
        object_id: &str,
    ) -> Result<EcRepairReport, VelcruxError> {
        let start = Instant::now();

        // 1. Gather all valid shards for this object
        let mut available_shards: Vec<ShardEnvelope> = Vec::new();
        let mut schema_opt: Option<ErasureSchema> = None;

        if dir.exists() && dir.is_dir() {
            for entry in fs::read_dir(dir).map_err(VelcruxError::Io)?.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(env) = ShardEnvelope::load_from_file(&path) {
                        if env.object_id == object_id {
                            schema_opt = Some(env.schema);
                            available_shards.push(env);
                        }
                    }
                }
            }
        }

        let schema = schema_opt.ok_or_else(|| {
            VelcruxError::Internal(format!("No valid shards found for object '{}'", object_id))
        })?;

        if available_shards.len() < schema.data_shards {
            return Err(VelcruxError::Internal(format!(
                "Cannot repair object '{}': only {} valid shards available, {} required",
                object_id,
                available_shards.len(),
                schema.data_shards
            )));
        }

        // 2. Identify missing shard indices
        let total_shards = schema.total_shards();
        let mut missing_indices = Vec::new();
        for i in 0..total_shards {
            if !available_shards.iter().any(|s| s.shard_index == i) {
                missing_indices.push(i);
            }
        }

        if missing_indices.is_empty() {
            // Already fully healthy
            return Ok(EcRepairReport {
                object_id: object_id.to_string(),
                schema,
                shards_repaired: 0,
                repaired_indices: Vec::new(),
                repair_latency_nanoseconds: start.elapsed().as_nanos() as u64,
            });
        }

        // 3. Reconstruct all shards
        let all_reconstructed = ErasureEngine::reconstruct_all(&available_shards, schema)?;

        // 4. Write missing shards to disk
        let mut repaired_count = 0;
        for &idx in &missing_indices {
            if let Some(shard) = all_reconstructed.iter().find(|s| s.shard_index == idx) {
                let shard_filename = format!("{}.shard.{}", object_id, idx);
                let target_path = dir.join(shard_filename);
                shard.save_to_file(&target_path)?;
                repaired_count += 1;
                self.repaired_shards_total.fetch_add(1, Ordering::Relaxed);
            }
        }

        let elapsed_ns = start.elapsed().as_nanos() as u64;
        self.repair_latency_nanoseconds
            .store(elapsed_ns, Ordering::Relaxed);

        Ok(EcRepairReport {
            object_id: object_id.to_string(),
            schema,
            shards_repaired: repaired_count,
            repaired_indices: missing_indices,
            repair_latency_nanoseconds: elapsed_ns,
        })
    }

    /// Autonomous scrub & self-heal: inspects storage directory and repairs all degraded/critical objects.
    pub fn auto_repair_directory(&self, dir: &Path) -> Result<EcAutoRepairReport, VelcruxError> {
        let scrub_report = self.scrub_directory(dir)?;
        let mut repairs = Vec::new();
        let mut total_reconstructed = 0;

        for summary in &scrub_report.object_summaries {
            if matches!(
                summary.state,
                ObjectHealthState::Degraded | ObjectHealthState::Critical
            ) {
                if let Ok(rep) = self.repair_object(dir, &summary.object_id) {
                    total_reconstructed += rep.shards_repaired;
                    repairs.push(rep);
                }
            }
        }

        let repaired_objs = repairs.len();
        Ok(EcAutoRepairReport {
            scrub_report,
            objects_repaired: repaired_objs,
            shards_reconstructed: total_reconstructed,
            repairs,
        })
    }

    /// Microsecond benchmark measuring encoding, decoding with losses, and single-shard repair.
    pub fn run_benchmark(&self, iterations: usize, payload_size: usize) -> EcBenchmarkReport {
        let iters = iterations.max(1);
        let size = payload_size.max(64);
        let schema = ErasureSchema::default(); // 4 + 2

        // Generate synthetic payload
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let object_id = "ec_benchmark_synthetic_obj";

        // 1. Benchmark encoding
        let enc_start = Instant::now();
        let mut sample_shards = None;
        for _ in 0..iters {
            let shards =
                ErasureEngine::encode(&payload, schema, object_id).expect("encode in bench");
            sample_shards = Some(shards);
        }
        let enc_total_ns = enc_start.elapsed().as_nanos() as f64;
        let enc_avg_ns = enc_total_ns / (iters as f64);
        let enc_bytes_per_sec = ((size * iters) as f64) / (enc_total_ns / 1_000_000_000.0);

        let shards = sample_shards.unwrap();

        // 2. Benchmark decoding with 2 missing data shards
        let mut partial_slots: Vec<Option<ShardEnvelope>> = vec![None; schema.total_shards()];
        // Shards 1, 3, 4, 5 survive (shards 0, 2 lost)
        partial_slots[1] = Some(shards[1].clone());
        partial_slots[3] = Some(shards[3].clone());
        partial_slots[4] = Some(shards[4].clone());
        partial_slots[5] = Some(shards[5].clone());

        let dec_start = Instant::now();
        for _ in 0..iters {
            let _ = ErasureEngine::decode(&partial_slots, schema).expect("decode in bench");
        }
        let dec_total_ns = dec_start.elapsed().as_nanos() as f64;
        let dec_avg_ns = dec_total_ns / (iters as f64);
        let dec_bytes_per_sec = ((size * iters) as f64) / (dec_total_ns / 1_000_000_000.0);

        // 3. Benchmark single-shard reconstruction
        let surviving = vec![
            shards[0].clone(),
            shards[1].clone(),
            shards[2].clone(),
            shards[4].clone(),
            shards[5].clone(),
        ]; // missing shard 3

        let rep_start = Instant::now();
        for _ in 0..iters {
            let _ = ErasureEngine::reconstruct_all(&surviving, schema).expect("repair in bench");
        }
        let rep_total_ns = rep_start.elapsed().as_nanos() as f64;
        let rep_avg_ns = rep_total_ns / (iters as f64);

        EcBenchmarkReport {
            iterations: iters,
            payload_size_bytes: size,
            schema,
            encode_latency_nanoseconds: enc_avg_ns,
            encode_throughput_bytes_per_sec: enc_bytes_per_sec,
            decode_latency_nanoseconds: dec_avg_ns,
            decode_throughput_bytes_per_sec: dec_bytes_per_sec,
            single_shard_repair_latency_nanoseconds: rep_avg_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_scrub_and_auto_repair_flow() {
        let tmp = tempdir().expect("create tempdir");
        let dir = tmp.path();

        let schema = ErasureSchema::new(4, 2).unwrap();
        let payload = b"Autonomous Shard Scrubbing and Self-Healing Unit Test Payload 2026";
        let object_id = "test-obj-scrub";

        // 1. Encode into 6 shards
        let shards = ErasureEngine::encode(payload, schema, object_id).unwrap();

        // 2. Write all shards to disk
        for s in &shards {
            let p = dir.join(format!("{}.shard.{}", object_id, s.shard_index));
            s.save_to_file(&p).unwrap();
        }

        let mesh = ShardScrubMesh::new();

        // 3. Initial scrub: healthy
        let rep1 = mesh.scrub_directory(dir).unwrap();
        assert_eq!(rep1.objects_scanned, 1);
        assert_eq!(rep1.healthy_objects, 1);
        assert_eq!(rep1.degraded_objects, 0);

        // 4. Simulate corruption of shard 1 and deletion of shard 4
        // Corrupt shard 1
        let shard1_path = dir.join(format!("{}.shard.1", object_id));
        let mut raw_bytes = fs::read(&shard1_path).unwrap();
        let last_idx = raw_bytes.len() - 1;
        raw_bytes[last_idx] ^= 0xff; // flip bits in payload
        fs::write(&shard1_path, raw_bytes).unwrap();

        // Delete shard 4
        let shard4_path = dir.join(format!("{}.shard.4", object_id));
        fs::remove_file(&shard4_path).unwrap();

        // 5. Scrub after corruption: should detect degraded (4 valid shards survive: 0, 2, 3, 5)
        let rep2 = mesh.scrub_directory(dir).unwrap();
        assert_eq!(rep2.objects_scanned, 1);
        assert_eq!(rep2.healthy_objects, 0);
        assert_eq!(rep2.degraded_objects, 0);
        assert_eq!(rep2.critical_objects, 1); // exactly 4 valid shards survive
        assert_eq!(rep2.corrupted_shards, 1);

        // Remove corrupted file so repair replaces it
        fs::remove_file(&shard1_path).unwrap();

        // 6. Execute autonomous repair
        let auto_rep = mesh.auto_repair_directory(dir).unwrap();
        assert_eq!(auto_rep.objects_repaired, 1);
        assert_eq!(auto_rep.shards_reconstructed, 2);

        // 7. Verify directory is healthy again
        let rep3 = mesh.scrub_directory(dir).unwrap();
        assert_eq!(rep3.healthy_objects, 1);
        assert_eq!(rep3.degraded_objects, 0);
        assert_eq!(rep3.critical_objects, 0);

        // 8. Reconstruct and verify payload matches original
        let restored_slots: Vec<Option<ShardEnvelope>> = (0..6)
            .map(|i| {
                let p = dir.join(format!("{}.shard.{}", object_id, i));
                ShardEnvelope::load_from_file(&p).ok()
            })
            .collect();

        let restored_data = ErasureEngine::decode(&restored_slots, schema).unwrap();
        assert_eq!(restored_data, payload);
    }
}
