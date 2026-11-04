//! Hardware-Accelerated RDMA (RoCEv2 / InfiniBand) Zero-Copy Direct Memory Subsystem.
//!
//! Complies strictly with `#![forbid(unsafe_code)]`.

pub mod engine;
pub mod frame;
pub mod mr;
pub mod pacing;
pub mod verbs;

pub use engine::{HcaDeviceAttributes, RdmaBenchmarkReport, RdmaTransferEngine};
pub use frame::{
    calculate_icrc, Aeth, Bth, BthOpcode, Ieth, ImmDt, Reth, RocePacket, IB_DEFAULT_PKEY,
    ROCEV2_UDP_PORT,
};
pub use mr::{AccessFlags, MemoryRegion, ProtectionDomain};
pub use pacing::{DcqcnConfig, DcqcnPacer, DcqcnReport, DcqcnStage};
pub use verbs::{
    CompletionQueue, QpInitAttr, QpState, QpType, QueuePair, RecvWr, SendFlags, SendWr, Sge,
    WcOpcode, WcStatus, WorkCompletion, WrOpcode,
};
