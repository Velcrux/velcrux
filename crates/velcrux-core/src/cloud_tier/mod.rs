//! Autonomous Multi-Cloud Object Storage Tiering & Compaction Engine (`ADR-079`).
//!
//! Provides small-chunk container aggregation (`VLXT` container format), multi-cloud
//! lifecycle policy automation (S3 / GCS / Azure Blob), transparent byte-range read-through,
//! dead-space compaction / garbage collection, and asynchronous archive hydration.

#![forbid(unsafe_code)]

pub mod container;
pub mod engine;
pub mod hydration;
pub mod policy;
pub mod provider;
pub mod types;

pub use container::CompactedContainer;
pub use engine::{CloudTierStatusReport, CloudTieringEngine, ReadChunkResult, RebalanceReport};
pub use hydration::CloudHydrationPipeline;
pub use policy::{CloudLifecyclePolicyEngine, CloudLifecycleRule, TieringAction};
pub use provider::CloudStorageEndpoint;
pub use types::{
    compute_crc32c, ChunkDescriptor, CloudProviderKind, CloudStorageUri, CloudTierClass,
    CompressionCodec, ContainerHeader, HydrationPriority, HydrationRequest, HydrationStatus,
    DEFAULT_COMPACTION_FRAGMENTATION_THRESHOLD, DEFAULT_TARGET_CONTAINER_BYTES,
    MIN_CONTAINER_BYTES, VLXT_CONTAINER_MAGIC, VLXT_CONTAINER_VERSION,
};
