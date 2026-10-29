//! eBPF-Driven Programmable L7 Proxying & Dynamic Layer-7 Load Shedding (`ADR-047`).

#![forbid(unsafe_code)]

pub mod l7;

pub use l7::{
    run_l7_benchmark, FlowTier, L7Action, L7BenchmarkReport, L7ProxyEngine, L7ProxyStatus,
    L7RequestInfo, L7Rule, L7StreamType, L7TokenBucket, PressureSensor,
};
