//! Conflict-Free Replicated Data Types (CRDTs) & Global Geo-Replication Subsystem.
//!
//! Complies strictly with `#![forbid(unsafe_code)]`.

pub mod clock;
pub mod mesh;
pub mod sync;
pub mod tree;
pub mod types;

pub use clock::{CausalOrder, Hlc, VectorClock};
pub use mesh::{GeoBenchmarkReport, GeoMesh, RegionInfo};
pub use sync::{AntiEntropyEngine, AntiEntropyReport, CrdtDelta, DigestSummary};
pub use tree::{FsMergeReport, FsNode, FsNodeKind, ReplicatedFsTree};
pub use types::{LwwRegister, MvRegister, OrSet};
