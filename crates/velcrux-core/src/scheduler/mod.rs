//! Transfer scheduling, bandwidth allocation, and fairness algorithms.

#![forbid(unsafe_code)]

pub mod fairness;

pub use fairness::{
    BandwidthRate, FairnessScheduler, HierarchicalBandwidthAllocator, ParseBandwidthError,
    PriorityClass, ScheduledItem, TokenBucket as SchedulerTokenBucket,
};
