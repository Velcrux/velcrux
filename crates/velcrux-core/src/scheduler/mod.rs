//! Transfer scheduling, bandwidth allocation, and fairness algorithms.

#![forbid(unsafe_code)]

pub mod fairness;
pub mod schedule;

pub use fairness::{
    BandwidthRate, FairnessScheduler, HierarchicalBandwidthAllocator, ParseBandwidthError,
    PriorityClass, ScheduledItem, TokenBucket as SchedulerTokenBucket,
};
pub use schedule::{
    civil_time_from_timestamp, ActiveScheduleStatus, BandwidthSchedule, BandwidthScheduleRule,
    DayMatcher, DayOfWeek, ParseScheduleError, ScheduledBandwidthLimiter, TimeWindow,
};
