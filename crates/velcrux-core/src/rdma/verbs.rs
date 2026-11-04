//! InfiniBand / RoCEv2 Verbs Architecture, Queue Pairs, and Completion Queues.
//!
//! Provides safe implementations of Work Queue Pairs (`Qp`), Work Requests (`SendWr`, `RecvWr`),
//! Work Completions (`Wc`), and Completion Queues (`CompletionQueue`).
//!
//! Complies strictly with `#![forbid(unsafe_code)]`.

use crate::rdma::mr::{AccessFlags, MemoryRegion, ProtectionDomain};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

static NEXT_QP_NUM: AtomicU32 = AtomicU32::new(0x2000);
static NEXT_CQ_ID: AtomicU32 = AtomicU32::new(0x3000);

/// Queue Pair Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QpType {
    /// Reliable Connected (RC) - hardware sequenced, ACKs, flow controlled.
    ReliableConnected,
    /// Unreliable Connected (UC).
    UnreliableConnected,
    /// Unreliable Datagram (UD) - connectionless, unreliable.
    UnreliableDatagram,
}

/// Queue Pair State Lifecycle Machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QpState {
    /// Initial reset state.
    Reset,
    /// Initialized with access and port attributes.
    Init,
    /// Ready to Receive (RTR) - connected to remote peer QPN and PSN.
    ReadyToReceive,
    /// Ready to Send (RTS) - active for bidirectional transmission.
    ReadyToSend,
    /// Send Queue Error.
    SendQueueError,
    /// Fatal Error state.
    Error,
}

/// Scatter / Gather Element (SGE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sge {
    /// Virtual address of local memory buffer.
    pub addr: u64,
    /// Length of memory in bytes.
    pub length: u32,
    /// Local key (lkey) authorized for this buffer.
    pub lkey: u32,
}

/// Work Request Operation Code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrOpcode {
    Send,
    SendWithImm,
    RdmaWrite,
    RdmaWriteWithImm,
    RdmaRead,
    AtomicCmpSwap,
    AtomicFetchAdd,
}

/// Flags controlling Work Request execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SendFlags(pub u32);

impl SendFlags {
    pub const NONE: Self = Self(0);
    pub const FENCE: Self = Self(1 << 0);
    pub const SIGNALED: Self = Self(1 << 1);
    pub const SOLICITED: Self = Self(1 << 2);
    pub const INLINE: Self = Self(1 << 3);

    pub fn contains(&self, other: SendFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Send Work Request (posted to Send Queue).
#[derive(Debug, Clone)]
pub struct SendWr {
    /// User-defined identifier returned in Work Completion.
    pub wr_id: u64,
    /// Opcode to execute.
    pub opcode: WrOpcode,
    /// Execution flags (e.g. `SIGNALED`, `SOLICITED`).
    pub send_flags: SendFlags,
    /// Scatter/Gather list referencing local memory regions.
    pub sg_list: Vec<Sge>,
    /// Remote target virtual address (for RDMA Write/Read).
    pub remote_addr: u64,
    /// Remote key authorizing access (for RDMA Write/Read).
    pub rkey: u32,
    /// Immediate 32-bit data payload.
    pub imm_data: Option<u32>,
}

/// Receive Work Request (posted to Receive Queue).
#[derive(Debug, Clone)]
pub struct RecvWr {
    /// User-defined identifier returned in Work Completion.
    pub wr_id: u64,
    /// Scatter/Gather list referencing local memory to receive incoming data.
    pub sg_list: Vec<Sge>,
}

/// Work Completion Status Code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WcStatus {
    Success,
    LocLenErr,
    LocProtErr,
    RemAccErr,
    RemOpErr,
    RnrRetryExcErr,
    BadRespErr,
    GeneralErr,
}

/// Work Completion Opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WcOpcode {
    Send,
    RdmaWrite,
    RdmaRead,
    Recv,
    RecvImm,
}

/// Work Completion (WC) retrieved from Completion Queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkCompletion {
    /// Work request identifier assigned when posted.
    pub wr_id: u64,
    /// Status code of completion.
    pub status: WcStatus,
    /// Opcode of completed operation.
    pub opcode: WcOpcode,
    /// Total bytes transferred.
    pub byte_len: u32,
    /// Immediate data if present.
    pub imm_data: Option<u32>,
    /// Local Queue Pair number.
    pub qp_num: u32,
    /// Remote source Queue Pair number.
    pub src_qp: u32,
}

/// Completion Queue (CQ) holding asynchronous Work Completions.
#[derive(Debug)]
pub struct CompletionQueue {
    pub id: u32,
    pub capacity: usize,
    entries: Mutex<VecDeque<WorkCompletion>>,
}

impl CompletionQueue {
    /// Create a new Completion Queue with the specified capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            id: NEXT_CQ_ID.fetch_add(1, Ordering::Relaxed),
            capacity,
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
        }
    }

    /// Post a completion entry to this CQ.
    pub fn post(&self, wc: WorkCompletion) -> Result<(), &'static str> {
        let mut queue = self
            .entries
            .lock()
            .map_err(|_| "Failed to lock CQ entries")?;
        if queue.len() >= self.capacity {
            return Err("CQ overflow: capacity exceeded");
        }
        queue.push_back(wc);
        Ok(())
    }

    /// Poll up to `max_entries` from this CQ.
    pub fn poll(&self, max_entries: usize) -> Vec<WorkCompletion> {
        if let Ok(mut queue) = self.entries.lock() {
            let count = max_entries.min(queue.len());
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                if let Some(wc) = queue.pop_front() {
                    out.push(wc);
                }
            }
            out
        } else {
            Vec::new()
        }
    }

    /// Return the current number of pending completion entries.
    pub fn len(&self) -> usize {
        self.entries.lock().map(|q| q.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Attributes required to initialize a Queue Pair.
#[derive(Debug, Clone)]
pub struct QpInitAttr {
    pub qp_type: QpType,
    pub sq_capacity: usize,
    pub rq_capacity: usize,
    pub send_cq: Arc<CompletionQueue>,
    pub recv_cq: Arc<CompletionQueue>,
}

/// Reliable Connected Queue Pair (QP).
#[derive(Debug)]
pub struct QueuePair {
    /// Unique local QP Number.
    pub qp_num: u32,
    /// QP Type.
    pub qp_type: QpType,
    /// Active state machine status.
    pub state: RwLock<QpState>,
    /// Associated Protection Domain.
    pub pd_id: u32,
    /// Send Completion Queue.
    pub send_cq: Arc<CompletionQueue>,
    /// Receive Completion Queue.
    pub recv_cq: Arc<CompletionQueue>,
    /// Remote connected peer QP Number.
    pub remote_qpn: AtomicU32,
    /// Local starting Packet Sequence Number (PSN).
    pub local_psn: AtomicU32,
    /// Expected remote Packet Sequence Number (PSN).
    pub remote_psn: AtomicU32,
    /// Maximum Transmission Unit in bytes (default: 4096).
    pub mtu: u32,
    /// Send Queue capacity.
    pub sq_capacity: usize,
    /// Receive Queue capacity.
    pub rq_capacity: usize,
    /// Internal posted Receive Work Requests.
    pending_rq: Mutex<VecDeque<RecvWr>>,
}

impl QueuePair {
    /// Instantiate a new Queue Pair in the `Reset` state.
    pub fn new(pd: &ProtectionDomain, attr: QpInitAttr) -> Self {
        let qp_num = NEXT_QP_NUM.fetch_add(1, Ordering::Relaxed);
        Self {
            qp_num,
            qp_type: attr.qp_type,
            state: RwLock::new(QpState::Reset),
            pd_id: pd.id,
            send_cq: attr.send_cq,
            recv_cq: attr.recv_cq,
            remote_qpn: AtomicU32::new(0),
            local_psn: AtomicU32::new(0x100),
            remote_psn: AtomicU32::new(0x100),
            mtu: 4096,
            sq_capacity: attr.sq_capacity,
            rq_capacity: attr.rq_capacity,
            pending_rq: Mutex::new(VecDeque::with_capacity(attr.rq_capacity)),
        }
    }

    /// Transition QP State: Reset -> Init.
    pub fn modify_to_init(&self) -> Result<(), &'static str> {
        let mut st = self
            .state
            .write()
            .map_err(|_| "Failed to acquire QP state lock")?;
        if *st != QpState::Reset {
            return Err("QP must be in Reset state to transition to Init");
        }
        *st = QpState::Init;
        Ok(())
    }

    /// Transition QP State: Init -> ReadyToReceive (RTR).
    pub fn modify_to_rtr(&self, remote_qpn: u32, remote_psn: u32) -> Result<(), &'static str> {
        let mut st = self
            .state
            .write()
            .map_err(|_| "Failed to acquire QP state lock")?;
        if *st != QpState::Init {
            return Err("QP must be in Init state to transition to RTR");
        }
        self.remote_qpn.store(remote_qpn, Ordering::Release);
        self.remote_psn.store(remote_psn, Ordering::Release);
        *st = QpState::ReadyToReceive;
        Ok(())
    }

    /// Transition QP State: ReadyToReceive -> ReadyToSend (RTS).
    pub fn modify_to_rts(&self, local_psn: u32) -> Result<(), &'static str> {
        let mut st = self
            .state
            .write()
            .map_err(|_| "Failed to acquire QP state lock")?;
        if *st != QpState::ReadyToReceive {
            return Err("QP must be in RTR state to transition to RTS");
        }
        self.local_psn.store(local_psn, Ordering::Release);
        *st = QpState::ReadyToSend;
        Ok(())
    }

    /// Check if the QP is ready to transmit (RTS).
    pub fn is_rts(&self) -> bool {
        self.state
            .read()
            .map(|st| *st == QpState::ReadyToSend)
            .unwrap_or(false)
    }

    /// Post Receive Work Requests (RQ).
    pub fn post_recv(&self, requests: &[RecvWr]) -> Result<(), &'static str> {
        let mut rq = self
            .pending_rq
            .lock()
            .map_err(|_| "Failed to lock Receive Queue")?;
        for wr in requests {
            if rq.len() >= self.rq_capacity {
                return Err("Receive Queue capacity exceeded (RNR)");
            }
            rq.push_back(wr.clone());
        }
        Ok(())
    }

    /// Execute an RDMA Write directly into remote memory region without remote CPU invocation.
    ///
    /// The local MR data referenced by `wr.sg_list` is transferred to `dest_mr` at `wr.remote_addr`.
    /// If `wr.imm_data` is specified, the remote peer's receive queue receives an immediate notification.
    pub fn execute_rdma_write(
        &self,
        wr: &SendWr,
        src_mr: &MemoryRegion,
        dest_mr: &MemoryRegion,
        remote_qp: Option<&QueuePair>,
    ) -> Result<WorkCompletion, &'static str> {
        if !self.is_rts() {
            return Err("QP is not in ReadyToSend (RTS) state");
        }

        let total_bytes: usize = wr.sg_list.iter().map(|s| s.length as usize).sum();
        let remote_offset = (wr.remote_addr.saturating_sub(dest_mr.addr)) as usize;

        // Verify remote access permissions on destination MR
        dest_mr.validate_remote_access(
            wr.rkey,
            remote_offset,
            total_bytes,
            AccessFlags::REMOTE_WRITE,
        )?;

        // Gather bytes from source MR
        let mut buffer = Vec::with_capacity(total_bytes);
        for sge in &wr.sg_list {
            if sge.lkey != src_mr.lkey {
                return Err("Local SGE lkey mismatch (LocProtErr)");
            }
            let local_offset = (sge.addr.saturating_sub(src_mr.addr)) as usize;
            let slice = src_mr.read(local_offset, sge.length as usize)?;
            buffer.extend_from_slice(&slice);
        }

        // Direct DMA write to destination MR
        dest_mr.write(remote_offset, &buffer)?;

        // If immediate data was provided, trigger completion on remote QP's Receive Queue
        if let Some(imm) = wr.imm_data {
            if let Some(target_qp) = remote_qp {
                let recv_wc = WorkCompletion {
                    wr_id: 0,
                    status: WcStatus::Success,
                    opcode: WcOpcode::RecvImm,
                    byte_len: total_bytes as u32,
                    imm_data: Some(imm),
                    qp_num: target_qp.qp_num,
                    src_qp: self.qp_num,
                };
                let _ = target_qp.recv_cq.post(recv_wc);
            }
        }

        // Generate local send completion
        let send_wc = WorkCompletion {
            wr_id: wr.wr_id,
            status: WcStatus::Success,
            opcode: WcOpcode::RdmaWrite,
            byte_len: total_bytes as u32,
            imm_data: wr.imm_data,
            qp_num: self.qp_num,
            src_qp: self.remote_qpn.load(Ordering::Relaxed),
        };

        if wr.send_flags.contains(SendFlags::SIGNALED) {
            let _ = self.send_cq.post(send_wc.clone());
        }

        Ok(send_wc)
    }

    /// Execute an RDMA Read from remote memory directly into local memory.
    pub fn execute_rdma_read(
        &self,
        wr: &SendWr,
        dest_mr: &MemoryRegion,
        remote_mr: &MemoryRegion,
    ) -> Result<WorkCompletion, &'static str> {
        if !self.is_rts() {
            return Err("QP is not in ReadyToSend (RTS) state");
        }

        let total_bytes: usize = wr.sg_list.iter().map(|s| s.length as usize).sum();
        let remote_offset = (wr.remote_addr.saturating_sub(remote_mr.addr)) as usize;

        // Verify remote read permission
        remote_mr.validate_remote_access(
            wr.rkey,
            remote_offset,
            total_bytes,
            AccessFlags::REMOTE_READ,
        )?;

        // Read directly from remote MR
        let remote_data = remote_mr.read(remote_offset, total_bytes)?;

        // Scatter into local MR
        let mut cursor = 0;
        for sge in &wr.sg_list {
            if sge.lkey != dest_mr.lkey {
                return Err("Local SGE lkey mismatch");
            }
            let local_offset = (sge.addr.saturating_sub(dest_mr.addr)) as usize;
            let chunk = &remote_data[cursor..cursor + sge.length as usize];
            dest_mr.write(local_offset, chunk)?;
            cursor += sge.length as usize;
        }

        let send_wc = WorkCompletion {
            wr_id: wr.wr_id,
            status: WcStatus::Success,
            opcode: WcOpcode::RdmaRead,
            byte_len: total_bytes as u32,
            imm_data: None,
            qp_num: self.qp_num,
            src_qp: self.remote_qpn.load(Ordering::Relaxed),
        };

        if wr.send_flags.contains(SendFlags::SIGNALED) {
            let _ = self.send_cq.post(send_wc.clone());
        }

        Ok(send_wc)
    }
}
