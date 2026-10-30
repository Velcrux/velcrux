//! Autonomous Multi-Path WAN Slicing & Dynamic Interface Bonding (Option CF, ADR-048).

pub mod slicer;

pub use slicer::{
    ReassembledChunk, WanBenchmarkResult, WanBondingEngine, WanInterface, WanInterfaceInfo,
    WanLinkType, WanPathState, WanSlice,
};
