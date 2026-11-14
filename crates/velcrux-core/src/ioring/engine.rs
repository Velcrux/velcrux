//! Autonomous Zero-Copy User-Space Storage Engine.
//!
//! Orchestrates submission and completion queue rings, fixed buffer pools, zero-copy
//! splice channels, and kernel SQPOLL worker polling.

#![forbid(unsafe_code)]

use super::buffers::FixedBufferRegistry;
use super::probe::IoUringProbe;
use super::ring::{IoUringCompletionQueue, IoUringSubmissionQueue};
use super::splice::ZeroCopySplicePipeline;
use super::types::{IoUringCqe, IoUringOp, IoUringParams, IoUringSqe};
use crate::error::Result;
use serde::{Deserialize, Serialize};

/// High-Performance io_uring Zero-Copy Storage Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoUringStorageEngine {
    pub params: IoUringParams,
    pub sq: IoUringSubmissionQueue,
    pub cq: IoUringCompletionQueue,
    pub buffers: FixedBufferRegistry,
    pub splice_pipeline: ZeroCopySplicePipeline,
    pub probe: IoUringProbe,
    pub total_submitted: u64,
    pub total_completed: u64,
    pub total_zero_copy_bytes: u64,
    pub sqpoll_cycles: u64,
    pub syscalls_avoided_by_sqpoll: u64,
}

impl IoUringStorageEngine {
    pub fn new(params: IoUringParams) -> Self {
        let sq_cap = params.sq_entries as usize;
        let cq_cap = params.cq_entries as usize;
        Self {
            params,
            sq: IoUringSubmissionQueue::new(sq_cap),
            cq: IoUringCompletionQueue::new(cq_cap),
            buffers: FixedBufferRegistry::new(256),
            splice_pipeline: ZeroCopySplicePipeline::new(),
            probe: IoUringProbe::standard_linux_probe(),
            total_submitted: 0,
            total_completed: 0,
            total_zero_copy_bytes: 0,
            sqpoll_cycles: 0,
            syscalls_avoided_by_sqpoll: 0,
        }
    }

    /// Convenience constructor with default parameters and optional SQPOLL mode.
    pub fn with_capacity(entries: u32, sqpoll: bool) -> Self {
        let mut params = IoUringParams {
            sq_entries: entries,
            cq_entries: entries * 2,
            ..Default::default()
        };
        if sqpoll {
            params = params.with_sqpoll(0, 2000);
        }
        Self::new(params)
    }

    /// Submits a single Submission Queue Entry (SQE).
    pub fn submit(&mut self, sqe: IoUringSqe) -> Result<()> {
        self.sq.push(sqe)?;
        self.total_submitted = self.total_submitted.saturating_add(1);
        if self.params.is_sqpoll_enabled() {
            self.syscalls_avoided_by_sqpoll = self.syscalls_avoided_by_sqpoll.saturating_add(1);
        }
        Ok(())
    }

    /// Submits a batch of SQEs in a single pass.
    pub fn submit_batch(&mut self, sqes: &[IoUringSqe]) -> Result<usize> {
        let mut count = 0;
        for sqe in sqes {
            self.submit(*sqe)?;
            count += 1;
        }
        Ok(count)
    }

    /// Simulates a kernel worker or system-call completion cycle, executing queued SQEs.
    pub fn process_submissions(&mut self, max_process: usize) -> usize {
        let mut processed = 0;

        while processed < max_process && !self.sq.is_empty() {
            if let Some(sqe) = self.sq.pop() {
                let res = match sqe.opcode {
                    IoUringOp::Nop => 0,
                    IoUringOp::ReadFixed => {
                        self.total_zero_copy_bytes =
                            self.total_zero_copy_bytes.saturating_add(sqe.len as u64);
                        sqe.len as i32
                    }
                    IoUringOp::WriteFixed => {
                        self.total_zero_copy_bytes =
                            self.total_zero_copy_bytes.saturating_add(sqe.len as u64);
                        sqe.len as i32
                    }
                    IoUringOp::Splice => {
                        self.total_zero_copy_bytes =
                            self.total_zero_copy_bytes.saturating_add(sqe.len as u64);
                        sqe.len as i32
                    }
                    IoUringOp::Fsync => 0,
                    IoUringOp::Read | IoUringOp::Write => sqe.len as i32,
                    _ => 0,
                };

                let cqe = IoUringCqe::new(sqe.user_data, res, 0);
                self.cq.push(cqe);
                self.total_completed = self.total_completed.saturating_add(1);
                processed += 1;
            }
        }

        if self.params.is_sqpoll_enabled() && processed > 0 {
            self.sqpoll_cycles = self.sqpoll_cycles.saturating_add(1);
        }

        processed
    }

    /// Reaps up to `max_reap` completed operations from the Completion Queue.
    pub fn reap_completions(&mut self, max_reap: usize) -> Vec<IoUringCqe> {
        let mut results = Vec::with_capacity(max_reap);
        while results.len() < max_reap && !self.cq.is_empty() {
            if let Some(cqe) = self.cq.pop() {
                results.push(cqe);
            }
        }
        results
    }

    /// High-level helper: Enqueues a chunk write using a registered fixed buffer.
    pub fn write_chunk_fixed(
        &mut self,
        fd: i32,
        buf_index: u16,
        offset: u64,
        len: u32,
        user_data: u64,
    ) -> Result<()> {
        let sqe = IoUringSqe::write_fixed(fd, buf_index, offset, len, user_data);
        self.submit(sqe)
    }

    /// High-level helper: Enqueues a chunk read into a registered fixed buffer.
    pub fn read_chunk_fixed(
        &mut self,
        fd: i32,
        buf_index: u16,
        offset: u64,
        len: u32,
        user_data: u64,
    ) -> Result<()> {
        let sqe = IoUringSqe::read_fixed(fd, buf_index, offset, len, user_data);
        self.submit(sqe)
    }

    /// High-level helper: Enqueues a zero-copy splice from input to output descriptor.
    pub fn splice_direct(
        &mut self,
        fd_in: i32,
        off_in: u64,
        fd_out: i32,
        off_out: u64,
        len: u32,
        user_data: u64,
    ) -> Result<()> {
        let sqe = IoUringSqe::splice(fd_in, off_in, fd_out, off_out, len, 0, user_data);
        self.submit(sqe)
    }

    /// Active operations currently in flight.
    pub fn in_flight_count(&self) -> u64 {
        self.total_submitted.saturating_sub(self.total_completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_submit_process_and_reap_lifecycle() {
        let mut engine = IoUringStorageEngine::with_capacity(64, false);

        // Submit 10 NOP and 5 WriteFixed operations
        for i in 0..10 {
            engine
                .submit(IoUringSqe::new(IoUringOp::Nop, -1, i as u64))
                .unwrap();
        }
        for i in 10..15 {
            engine
                .write_chunk_fixed(3, 0, (i * 4096) as u64, 4096, i as u64)
                .unwrap();
        }

        assert_eq!(engine.total_submitted, 15);
        assert_eq!(engine.in_flight_count(), 15);

        // Process all submissions
        let processed = engine.process_submissions(32);
        assert_eq!(processed, 15);
        assert_eq!(engine.total_completed, 15);
        assert_eq!(engine.in_flight_count(), 0);

        // Reap completions from CQ
        let cqes = engine.reap_completions(32);
        assert_eq!(cqes.len(), 15);
        for (i, cqe) in cqes.iter().enumerate() {
            assert_eq!(cqe.user_data, i as u64);
            assert!(cqe.is_success());
        }
    }

    #[test]
    fn test_sqpoll_mode_syscall_accounting() {
        let mut engine = IoUringStorageEngine::with_capacity(64, true); // SQPOLL = true

        for i in 0..8 {
            engine
                .submit(IoUringSqe::new(IoUringOp::Nop, -1, i as u64))
                .unwrap();
        }

        assert_eq!(engine.syscalls_avoided_by_sqpoll, 8);
        let processed = engine.process_submissions(8);
        assert_eq!(processed, 8);
        assert_eq!(engine.sqpoll_cycles, 1);
    }
}
