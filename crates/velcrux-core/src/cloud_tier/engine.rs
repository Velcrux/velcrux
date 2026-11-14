//! Autonomous Multi-Cloud Object Storage Tiering & Lifecycle Compaction Engine (`ADR-079`).
//!
//! Orchestrates small-chunk container aggregation, multi-cloud lifecycle policies,
//! transparent byte-range read-through, tombstone garbage collection / compaction,
//! and asynchronous archive hydration.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::container::CompactedContainer;
use super::hydration::CloudHydrationPipeline;
use super::policy::{CloudLifecyclePolicyEngine, TieringAction};
use super::provider::CloudStorageEndpoint;
use super::types::{
    CloudProviderKind, CloudTierClass, CompressionCodec, HydrationPriority,
    DEFAULT_TARGET_CONTAINER_BYTES,
};
use crate::error::{ProtocolError, Result, VelcruxError};

/// Result of a transparent chunk read operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadChunkResult {
    /// Chunk was read directly (from Hot/Cool tier or hydrated cache).
    Direct(Vec<u8>),
    /// Chunk resides in cold/deep-archive storage and requires asynchronous hydration.
    HydrationRequired {
        container_id: String,
        source_tier: CloudTierClass,
        estimated_duration_secs: u64,
    },
}

/// Action outcome from an autonomous rebalance cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebalanceReport {
    pub container_id: String,
    pub endpoint_id: String,
    pub action: TieringAction,
    pub details: String,
}

/// Overall engine diagnostic and metrics status report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTierStatusReport {
    pub active_endpoints: usize,
    pub total_compacted_containers: usize,
    pub total_indexed_chunks: usize,
    pub total_uncompressed_bytes: u64,
    pub total_compressed_bytes: u64,
    pub average_compression_ratio: f64,
    pub containers_by_tier: HashMap<String, usize>,
    pub bytes_by_tier: HashMap<String, u64>,
    pub pending_hydrations: usize,
    pub completed_hydrations: usize,
    pub estimated_monthly_cloud_cost_usd: f64,
}

/// Unified Multi-Cloud Object Storage Tiering & Compaction Engine.
#[derive(Debug, Clone)]
pub struct CloudTieringEngine {
    /// Configured cloud storage endpoints (S3, GCS, Azure, Local).
    pub endpoints: HashMap<String, CloudStorageEndpoint>,
    /// Default target endpoint for newly ingested data.
    pub default_endpoint_id: String,
    /// Active in-memory staging container accumulating chunks before upload.
    pub staging_container: CompactedContainer,
    /// In-memory catalog of containers currently managed by the engine.
    pub containers: HashMap<String, CompactedContainer>,
    /// Content-addressed chunk index mapping: `chunk_hash -> (endpoint_id, container_id)`.
    pub chunk_locations: HashMap<[u8; 32], (String, String)>,
    /// Declarative lifecycle policy evaluator.
    pub policy_engine: CloudLifecyclePolicyEngine,
    /// Asynchronous cold-archive hydration pipeline.
    pub hydration_pipeline: CloudHydrationPipeline,
    /// Next container sequential ID counter.
    pub container_counter: u64,
}

impl CloudTieringEngine {
    /// Initializes an engine with standard default endpoints (AWS S3, Google GCS, Azure Blob, Local Posix).
    pub fn new() -> Self {
        let mut endpoints = HashMap::new();

        endpoints.insert(
            "aws-us-east-1".into(),
            CloudStorageEndpoint::new(
                "aws-us-east-1",
                CloudProviderKind::AwsS3,
                "velcrux-primary-bucket",
                "us-east-1",
            ),
        );
        endpoints.insert(
            "gcs-eu-west1".into(),
            CloudStorageEndpoint::new(
                "gcs-eu-west1",
                CloudProviderKind::GoogleGcs,
                "velcrux-gcs-archive",
                "europe-west1",
            ),
        );
        endpoints.insert(
            "azure-eastus".into(),
            CloudStorageEndpoint::new(
                "azure-eastus",
                CloudProviderKind::AzureBlob,
                "velcrux-az-cold",
                "eastus",
            ),
        );
        endpoints.insert(
            "local-nvme-tier".into(),
            CloudStorageEndpoint::new(
                "local-nvme-tier",
                CloudProviderKind::LocalPosix,
                "/var/lib/velcrux/hot",
                "local",
            ),
        );

        let default_endpoint_id = "aws-us-east-1".to_string();
        let staging_container = CompactedContainer::new(
            "stage-init-0",
            CloudProviderKind::AwsS3,
            CloudTierClass::Hot,
            CompressionCodec::Zstd,
        );

        Self {
            endpoints,
            default_endpoint_id,
            staging_container,
            containers: HashMap::new(),
            chunk_locations: HashMap::new(),
            policy_engine: CloudLifecyclePolicyEngine::new(),
            hydration_pipeline: CloudHydrationPipeline::new(),
            container_counter: 1,
        }
    }

    /// Registers a custom cloud storage endpoint.
    pub fn add_endpoint(&mut self, endpoint: CloudStorageEndpoint) {
        self.endpoints
            .insert(endpoint.endpoint_id.clone(), endpoint);
    }

    /// Ingests a small FastCDC chunk into the engine.
    ///
    /// The chunk is appended to the active staging container. When the container reaches
    /// target capacity (default 64 MiB), it is automatically flushed and committed to cloud storage.
    pub fn ingest_chunk(&mut self, chunk_hash: [u8; 32], raw_data: &[u8], now: u64) -> Result<()> {
        if self.chunk_locations.contains_key(&chunk_hash) {
            // Already present across the tiering mesh
            return Ok(());
        }

        self.staging_container
            .append_chunk(chunk_hash, raw_data, now)?;

        // Auto-flush when container hits target size
        if (self.staging_container.payload.len() as u64) >= DEFAULT_TARGET_CONTAINER_BYTES {
            self.flush_staging_container(CloudTierClass::Hot)?;
        }

        Ok(())
    }

    /// Flushes the active staging container and uploads it as a compacted object to cloud storage.
    pub fn flush_staging_container(&mut self, target_tier: CloudTierClass) -> Result<String> {
        if self.staging_container.index.is_empty() {
            return Ok(self.staging_container.header.container_id.clone());
        }

        let container_id = format!("cont-{:06}", self.container_counter);
        self.container_counter += 1;

        let mut container = self.staging_container.clone();
        container.header.container_id = container_id.clone();
        container.header.tier = target_tier;
        container.finalize();

        let serialized_bytes = container.serialize_to_bytes()?;
        let object_key = format!("containers/{}.vlxt", container_id);

        let endpoint_id = self.default_endpoint_id.clone();
        let endpoint = self.endpoints.get_mut(&endpoint_id).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("default endpoint not found"))
        })?;

        endpoint.put_object(&object_key, serialized_bytes, target_tier)?;

        // Update chunk location index
        for &ch in container.index.keys() {
            self.chunk_locations
                .insert(ch, (endpoint_id.clone(), container_id.clone()));
        }

        self.containers.insert(container_id.clone(), container);

        // Reset staging container
        self.staging_container = CompactedContainer::new(
            format!("stage-init-{}", self.container_counter),
            CloudProviderKind::AwsS3,
            CloudTierClass::Hot,
            CompressionCodec::Zstd,
        );

        Ok(container_id)
    }

    /// Transparently reads a chunk from the multi-cloud storage mesh.
    ///
    /// 1. If currently in staging: reads directly from memory.
    /// 2. If in hydrated cache: returns restored data immediately.
    /// 3. If in Hot / Cool tier: executes random-access byte-range read from compacted container.
    /// 4. If in Cold / DeepArchive tier: returns `HydrationRequired`.
    pub fn read_chunk_transparent(
        &mut self,
        chunk_hash: &[u8; 32],
        now: u64,
    ) -> Result<ReadChunkResult> {
        // 1. Check staging container
        if self.staging_container.index.contains_key(chunk_hash) {
            let data = self.staging_container.read_chunk(chunk_hash, now)?;
            return Ok(ReadChunkResult::Direct(data));
        }

        // 2. Check hydrated cache
        if let Some(cached) = self.hydration_pipeline.read_hydrated_chunk(chunk_hash, now) {
            return Ok(ReadChunkResult::Direct(cached.to_vec()));
        }

        // 3. Check committed cloud containers
        let (_endpoint_id, container_id) = self
            .chunk_locations
            .get(chunk_hash)
            .cloned()
            .ok_or_else(|| {
                VelcruxError::Protocol(ProtocolError::Malformed("chunk not found in tiering mesh"))
            })?;

        let container = self.containers.get_mut(&container_id).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("container not found"))
        })?;

        let tier = container.header.tier;

        if tier.requires_hydration() {
            return Ok(ReadChunkResult::HydrationRequired {
                container_id: container_id.clone(),
                source_tier: tier,
                estimated_duration_secs: tier.typical_latency_secs(),
            });
        }

        // Hot or Cool: Range GET
        let data = container.read_chunk(chunk_hash, now)?;
        Ok(ReadChunkResult::Direct(data))
    }

    /// Initiates asynchronous archive hydration for a cold chunk.
    pub fn request_chunk_hydration(
        &mut self,
        chunk_hash: [u8; 32],
        priority: HydrationPriority,
        now: u64,
    ) -> Result<String> {
        let (_endpoint_id, container_id) = self
            .chunk_locations
            .get(&chunk_hash)
            .cloned()
            .ok_or_else(|| VelcruxError::Protocol(ProtocolError::Malformed("chunk not found")))?;

        let container = self.containers.get(&container_id).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("container not found"))
        })?;

        self.hydration_pipeline.request_hydration(
            &container_id,
            chunk_hash,
            container.header.tier,
            priority,
            now,
        )
    }

    /// Advances active hydration requests.
    pub fn poll_hydrations(&mut self, now: u64) -> usize {
        let containers = &mut self.containers;
        self.hydration_pipeline.poll_hydrations(now, |cid, ch| {
            if let Some(c) = containers.get_mut(cid) {
                c.read_chunk(ch, now).ok()
            } else {
                None
            }
        })
    }

    /// Evaluates lifecycle policies across all containers and executes migrations or compactions.
    pub fn evaluate_and_rebalance(&mut self, now: u64) -> Result<Vec<RebalanceReport>> {
        let mut reports = Vec::new();
        let container_ids: Vec<String> = self.containers.keys().cloned().collect();

        for cid in container_ids {
            let (action, endpoint_id, frag_ratio) = {
                let c = match self.containers.get(&cid) {
                    Some(c) => c,
                    None => continue,
                };
                let key = format!("containers/{}.vlxt", cid);
                let age =
                    now.saturating_sub(c.index.values().map(|d| d.added_at).min().unwrap_or(now));
                let frag = c.fragmentation_ratio();
                let action =
                    self.policy_engine
                        .evaluate_container(&key, None, c.header.tier, age, frag);
                (action, self.default_endpoint_id.clone(), frag)
            };

            match action {
                TieringAction::Retain => {}
                TieringAction::Transition(new_tier) => {
                    if let Some(c) = self.containers.get_mut(&cid) {
                        c.header.tier = new_tier;
                    }
                    if let Some(ep) = self.endpoints.get_mut(&endpoint_id) {
                        let _ = ep
                            .transition_object_tier(&format!("containers/{}.vlxt", cid), new_tier);
                    }
                    reports.push(RebalanceReport {
                        container_id: cid.clone(),
                        endpoint_id: endpoint_id.clone(),
                        action,
                        details: format!("Transitioned container to {:?}", new_tier),
                    });
                }
                TieringAction::CompactAndRepack => {
                    let old_container = match self.containers.get(&cid) {
                        Some(c) => c.clone(),
                        None => continue,
                    };
                    let repacked_id = format!("cont-{:06}-repacked", self.container_counter);
                    self.container_counter += 1;

                    let mut repacked = old_container.compact_and_repack(&repacked_id)?;
                    let bytes = repacked.serialize_to_bytes()?;
                    let object_key = format!("containers/{}.vlxt", repacked_id);

                    if let Some(ep) = self.endpoints.get_mut(&endpoint_id) {
                        ep.put_object(&object_key, bytes, repacked.header.tier)?;
                        ep.delete_object(&format!("containers/{}.vlxt", cid));
                    }

                    // Update index references
                    for &ch in repacked.index.keys() {
                        self.chunk_locations
                            .insert(ch, (endpoint_id.clone(), repacked_id.clone()));
                    }

                    self.containers.remove(&cid);
                    self.containers.insert(repacked_id.clone(), repacked);

                    reports.push(RebalanceReport {
                        container_id: cid.clone(),
                        endpoint_id: endpoint_id.clone(),
                        action,
                        details: format!(
                            "Repacked container into {} (reclaimed {:.1}% dead space)",
                            repacked_id,
                            frag_ratio * 100.0
                        ),
                    });
                }
                TieringAction::Expire => {
                    if let Some(ep) = self.endpoints.get_mut(&endpoint_id) {
                        ep.delete_object(&format!("containers/{}.vlxt", cid));
                    }
                    if let Some(c) = self.containers.remove(&cid) {
                        for &ch in c.index.keys() {
                            self.chunk_locations.remove(&ch);
                        }
                    }
                    reports.push(RebalanceReport {
                        container_id: cid.clone(),
                        endpoint_id: endpoint_id.clone(),
                        action,
                        details: "Expired and purged container from cloud storage".into(),
                    });
                }
            }
        }

        Ok(reports)
    }

    /// Generates a diagnostic summary status report.
    pub fn status_report(&self) -> CloudTierStatusReport {
        let mut total_chunks = self.staging_container.index.len();
        let mut total_uncompressed = self.staging_container.header.total_uncompressed_bytes;
        let mut total_compressed = self.staging_container.header.total_compressed_bytes;

        let mut by_tier: HashMap<String, usize> = HashMap::new();
        let mut bytes_tier: HashMap<String, u64> = HashMap::new();

        // Staging count
        *by_tier.entry("hot".into()).or_default() += 1;
        *bytes_tier.entry("hot".into()).or_default() += self.staging_container.payload.len() as u64;

        let mut total_cost = 0.0;
        for ep in self.endpoints.values() {
            total_cost += ep.estimate_monthly_cost_usd();
        }

        for c in self.containers.values() {
            total_chunks += c.index.len();
            total_uncompressed += c.header.total_uncompressed_bytes;
            total_compressed += c.header.total_compressed_bytes;

            let tier_str = c.header.tier.as_str().to_string();
            *by_tier.entry(tier_str.clone()).or_default() += 1;
            *bytes_tier.entry(tier_str).or_default() += c.payload.len() as u64;
        }

        let ratio = if total_uncompressed > 0 {
            total_compressed as f64 / total_uncompressed as f64
        } else {
            1.0
        };

        CloudTierStatusReport {
            active_endpoints: self.endpoints.len(),
            total_compacted_containers: self.containers.len(),
            total_indexed_chunks: total_chunks,
            total_uncompressed_bytes: total_uncompressed,
            total_compressed_bytes: total_compressed,
            average_compression_ratio: ratio,
            containers_by_tier: by_tier,
            bytes_by_tier: bytes_tier,
            pending_hydrations: self.hydration_pipeline.active_hydrations_count(),
            completed_hydrations: self.hydration_pipeline.total_completed as usize,
            estimated_monthly_cloud_cost_usd: total_cost,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_ingest_flush_and_transparent_read() {
        let mut engine = CloudTieringEngine::new();

        let c1 = b"chunk-payload-01-testing-full-tiering-pipeline";
        let c2 = b"chunk-payload-02-another-piece-of-data";
        let h1 = *blake3::hash(c1).as_bytes();
        let h2 = *blake3::hash(c2).as_bytes();

        engine.ingest_chunk(h1, c1, 1000).unwrap();
        engine.ingest_chunk(h2, c2, 1000).unwrap();

        // Direct read from staging
        let r1 = engine.read_chunk_transparent(&h1, 1001).unwrap();
        assert_eq!(r1, ReadChunkResult::Direct(c1.to_vec()));

        // Flush staging container to S3
        let cid = engine.flush_staging_container(CloudTierClass::Hot).unwrap();
        assert_eq!(engine.containers.len(), 1);
        assert!(engine.chunk_locations.contains_key(&h1));

        // Direct range read from committed container
        let r2 = engine.read_chunk_transparent(&h2, 1002).unwrap();
        assert_eq!(r2, ReadChunkResult::Direct(c2.to_vec()));

        // Transition container to Cold
        engine.containers.get_mut(&cid).unwrap().header.tier = CloudTierClass::Cold;

        // Reading now reports HydrationRequired
        let r_cold = engine.read_chunk_transparent(&h1, 1003).unwrap();
        match r_cold {
            ReadChunkResult::HydrationRequired { source_tier, .. } => {
                assert_eq!(source_tier, CloudTierClass::Cold);
            }
            _ => panic!("Expected HydrationRequired"),
        }

        // Request hydration and advance
        let req_id = engine
            .request_chunk_hydration(h1, HydrationPriority::Expedited, 1004)
            .unwrap();
        assert!(!req_id.is_empty());

        engine.poll_hydrations(1004 + 70); // Past 60s expedited duration

        // Reading now succeeds directly from the hydrated cache!
        let r_hydrated = engine.read_chunk_transparent(&h1, 1004 + 71).unwrap();
        assert_eq!(r_hydrated, ReadChunkResult::Direct(c1.to_vec()));
    }
}
