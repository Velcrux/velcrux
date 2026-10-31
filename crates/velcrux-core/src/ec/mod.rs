//! Distributed Erasure Coding & Autonomous Shard Scrub Mesh (Option CI, ADR-051).

pub mod engine;
pub mod scrub;

pub use engine::{ErasureEngine, ErasureSchema, ShardEnvelope, SHARD_MAGIC, SHARD_VERSION};
pub use scrub::{
    EcAutoRepairReport, EcBenchmarkReport, EcObjectScrubSummary, EcRepairReport, EcScrubReport,
    ObjectHealthState, ShardScrubMesh,
};
