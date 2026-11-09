#![forbid(unsafe_code)]

//! Hardware PTP (IEEE 1588v2) Nanosecond High-Precision Clock Synchronization & Bounded Transfer Ordering Mesh.
//!
//! Provides pure safe-Rust IEEE 1588v2 message framing, Best Master Clock Algorithm (BMCA),
//! closed-loop Proportional-Integral (PI) clock servo filtering, and TrueTime-style bounded
//! uncertainty transfer ordering.

pub mod bmca;
pub mod message;
pub mod ordering;
pub mod servo;
pub mod types;

pub use types::{
    ClockIdentity, ClockQuality, CorrectionField, PortIdentity, PtpClockRole, PtpPortState,
    PtpTimestamp, ServoLockStatus, DEFAULT_PTP_DOMAIN, PTP_EVENT_PORT, PTP_GENERAL_PORT,
    PTP_VERSION_2,
};

pub use message::{
    PtpAnnounce, PtpDelayRespPayload, PtpHeader, PtpMessage, PtpMessageType, PtpTimestampPayload,
    PTP_COMMON_HEADER_LEN, PTP_FLAG_TWO_STEP,
};

pub use bmca::{compare_datasets, BmcaEngine, ClockDataset, ForeignMasterRecord};

pub use servo::{
    ClockServo, PtpExchangeSample, DEFAULT_SERVO_KI, DEFAULT_SERVO_KP, PHASE_LOCK_THRESHOLD_NANOS,
};

pub use ordering::{BoundedOrderMesh, BoundedTimestamp, OrderedTransferCommit};
