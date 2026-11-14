//! Circular Ring Buffer Implementations for Submission Queue (SQ) and Completion Queue (CQ).

#![forbid(unsafe_code)]

use super::types::{IoUringCqe, IoUringSqe};
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};

/// Submission Queue (SQ) Circular Ring Buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoUringSubmissionQueue {
    pub entries: Vec<IoUringSqe>,
    pub capacity: usize,
    pub mask: usize,
    pub head: u32,
    pub tail: u32,
    pub dropped: u32,
}

impl IoUringSubmissionQueue {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.next_power_of_two().max(16);
        let mask = cap - 1;
        Self {
            entries: vec![IoUringSqe::default(); cap],
            capacity: cap,
            mask,
            head: 0,
            tail: 0,
            dropped: 0,
        }
    }

    pub fn len(&self) -> usize {
        (self.tail.wrapping_sub(self.head)) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity
    }

    pub fn push(&mut self, sqe: IoUringSqe) -> Result<()> {
        if self.is_full() {
            self.dropped = self.dropped.saturating_add(1);
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "io_uring submission queue is full (ring buffer overflow)",
            )));
        }
        let idx = (self.tail as usize) & self.mask;
        self.entries[idx] = sqe;
        self.tail = self.tail.wrapping_add(1);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<IoUringSqe> {
        if self.is_empty() {
            None
        } else {
            let idx = (self.head as usize) & self.mask;
            let sqe = self.entries[idx];
            self.head = self.head.wrapping_add(1);
            Some(sqe)
        }
    }

    pub fn peek(&self) -> Option<&IoUringSqe> {
        if self.is_empty() {
            None
        } else {
            let idx = (self.head as usize) & self.mask;
            Some(&self.entries[idx])
        }
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
    }
}

/// Completion Queue (CQ) Circular Ring Buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoUringCompletionQueue {
    pub entries: Vec<IoUringCqe>,
    pub capacity: usize,
    pub mask: usize,
    pub head: u32,
    pub tail: u32,
    pub overflow: u32,
}

impl IoUringCompletionQueue {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.next_power_of_two().max(32);
        let mask = cap - 1;
        Self {
            entries: vec![IoUringCqe::default(); cap],
            capacity: cap,
            mask,
            head: 0,
            tail: 0,
            overflow: 0,
        }
    }

    pub fn len(&self) -> usize {
        (self.tail.wrapping_sub(self.head)) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity
    }

    pub fn push(&mut self, cqe: IoUringCqe) {
        if self.is_full() {
            self.overflow = self.overflow.saturating_add(1);
            // Overwrite oldest or record overflow
            return;
        }
        let idx = (self.tail as usize) & self.mask;
        self.entries[idx] = cqe;
        self.tail = self.tail.wrapping_add(1);
    }

    pub fn pop(&mut self) -> Option<IoUringCqe> {
        if self.is_empty() {
            None
        } else {
            let idx = (self.head as usize) & self.mask;
            let cqe = self.entries[idx];
            self.head = self.head.wrapping_add(1);
            Some(cqe)
        }
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioring::types::IoUringOp;

    #[test]
    fn test_submission_queue_fifo_and_capacity() {
        let mut sq = IoUringSubmissionQueue::new(4);
        assert_eq!(sq.capacity, 16); // minimum power of two is 16

        for i in 0..10 {
            let sqe = IoUringSqe::new(IoUringOp::Nop, 1, i as u64);
            sq.push(sqe).expect("push must succeed");
        }
        assert_eq!(sq.len(), 10);

        for i in 0..10 {
            let popped = sq.pop().expect("pop must return item");
            assert_eq!(popped.user_data, i as u64);
        }
        assert!(sq.is_empty());
    }

    #[test]
    fn test_completion_queue_fifo_and_overflow() {
        let mut cq = IoUringCompletionQueue::new(32);
        assert_eq!(cq.capacity, 32);

        for i in 0..32 {
            cq.push(IoUringCqe::new(i as u64, 4096, 0));
        }
        assert!(cq.is_full());
        assert_eq!(cq.overflow, 0);

        // Next push should trigger overflow
        cq.push(IoUringCqe::new(999, 4096, 0));
        assert_eq!(cq.overflow, 1);

        let first = cq.pop().expect("pop first");
        assert_eq!(first.user_data, 0);
        assert_eq!(cq.len(), 31);
    }
}
