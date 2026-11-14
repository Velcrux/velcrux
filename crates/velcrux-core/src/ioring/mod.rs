//! Autonomous Zero-Copy User-Space Storage Engine via `io_uring` Kernel Ring Buffers (`ADR-078`).
//!
//! Features:
//! - Pure safe Rust submission (`SqRing`) and completion (`CqRing`) queues.
//! - Fixed buffer pre-registration (`IORING_REGISTER_BUFFERS`) eliminating TLB and page mapping costs.
//! - Direct zero-copy splice pipelining (`IORING_OP_SPLICE`, `IORING_OP_TEE`) between sockets and block storage.
//! - Kernel SQPOLL worker mode (`IORING_SETUP_SQPOLL`) for zero-syscall high-frequency I/O.
//! - Complete opcode and feature capability probe (`IoUringProbe`).

#![forbid(unsafe_code)]

pub mod buffers;
pub mod engine;
pub mod probe;
pub mod ring;
pub mod splice;
pub mod types;

pub use buffers::{FixedBuffer, FixedBufferRegistry};
pub use engine::IoUringStorageEngine;
pub use probe::IoUringProbe;
pub use ring::{IoUringCompletionQueue, IoUringSubmissionQueue};
pub use splice::{splice_flags, SpliceChannel, ZeroCopySplicePipeline};
pub use types::{
    cqe_flags, feature_flags, setup_flags, sqe_flags, IoUringCqe, IoUringOp, IoUringParams,
    IoUringSqe,
};
