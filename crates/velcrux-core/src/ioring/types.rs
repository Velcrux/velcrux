//! Core data types and structures for the Linux io_uring Zero-Copy User-Space Storage Engine.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

/// Standard io_uring Operation Opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum IoUringOp {
    Nop = 0,
    Readv = 1,
    Writev = 2,
    Fsync = 3,
    ReadFixed = 4,
    WriteFixed = 5,
    PollAdd = 6,
    PollRemove = 7,
    SyncFileRange = 8,
    Sendmsg = 9,
    Recvmsg = 10,
    Timeout = 11,
    TimeoutRemove = 12,
    Accept = 13,
    AsyncCancel = 14,
    LinkTimeout = 15,
    Connect = 16,
    Fallocate = 17,
    Openat = 18,
    Close = 19,
    FilesUpdate = 20,
    Statx = 21,
    Read = 22,
    Write = 23,
    Fadvise = 24,
    Madvise = 25,
    Send = 26,
    Recv = 27,
    Openat2 = 28,
    EpollCtl = 29,
    Splice = 30,
    ProvideBuffers = 31,
    RemoveBuffers = 32,
    Tee = 33,
    Shutdown = 34,
    Renameat = 35,
    Unlinkat = 36,
    Mkdirat = 37,
    Symlinkat = 38,
    Linkat = 39,
    MsgRing = 40,
    Fsetxattr = 41,
    Setxattr = 42,
    Fgetxattr = 43,
    Getxattr = 44,
    Socket = 45,
    UringCmd = 46,
    SendZc = 47,
    SendmsgZc = 48,
}

impl IoUringOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nop => "IORING_OP_NOP",
            Self::Readv => "IORING_OP_READV",
            Self::Writev => "IORING_OP_WRITEV",
            Self::Fsync => "IORING_OP_FSYNC",
            Self::ReadFixed => "IORING_OP_READ_FIXED",
            Self::WriteFixed => "IORING_OP_WRITE_FIXED",
            Self::PollAdd => "IORING_OP_POLL_ADD",
            Self::PollRemove => "IORING_OP_POLL_REMOVE",
            Self::SyncFileRange => "IORING_OP_SYNC_FILE_RANGE",
            Self::Sendmsg => "IORING_OP_SENDMSG",
            Self::Recvmsg => "IORING_OP_RECVMSG",
            Self::Timeout => "IORING_OP_TIMEOUT",
            Self::TimeoutRemove => "IORING_OP_TIMEOUT_REMOVE",
            Self::Accept => "IORING_OP_ACCEPT",
            Self::AsyncCancel => "IORING_OP_ASYNC_CANCEL",
            Self::LinkTimeout => "IORING_OP_LINK_TIMEOUT",
            Self::Connect => "IORING_OP_CONNECT",
            Self::Fallocate => "IORING_OP_FALLOCATE",
            Self::Openat => "IORING_OP_OPENAT",
            Self::Close => "IORING_OP_CLOSE",
            Self::FilesUpdate => "IORING_OP_FILES_UPDATE",
            Self::Statx => "IORING_OP_STATX",
            Self::Read => "IORING_OP_READ",
            Self::Write => "IORING_OP_WRITE",
            Self::Fadvise => "IORING_OP_FADVISE",
            Self::Madvise => "IORING_OP_MADVISE",
            Self::Send => "IORING_OP_SEND",
            Self::Recv => "IORING_OP_RECV",
            Self::Openat2 => "IORING_OP_OPENAT2",
            Self::EpollCtl => "IORING_OP_EPOLL_CTL",
            Self::Splice => "IORING_OP_SPLICE",
            Self::ProvideBuffers => "IORING_OP_PROVIDE_BUFFERS",
            Self::RemoveBuffers => "IORING_OP_REMOVE_BUFFERS",
            Self::Tee => "IORING_OP_TEE",
            Self::Shutdown => "IORING_OP_SHUTDOWN",
            Self::Renameat => "IORING_OP_RENAMEAT",
            Self::Unlinkat => "IORING_OP_UNLINKAT",
            Self::Mkdirat => "IORING_OP_MKDIRAT",
            Self::Symlinkat => "IORING_OP_SYMLINKAT",
            Self::Linkat => "IORING_OP_LINKAT",
            Self::MsgRing => "IORING_OP_MSG_RING",
            Self::Fsetxattr => "IORING_OP_FSETXATTR",
            Self::Setxattr => "IORING_OP_SETXATTR",
            Self::Fgetxattr => "IORING_OP_FGETXATTR",
            Self::Getxattr => "IORING_OP_GETXATTR",
            Self::Socket => "IORING_OP_SOCKET",
            Self::UringCmd => "IORING_OP_URING_CMD",
            Self::SendZc => "IORING_OP_SEND_ZC",
            Self::SendmsgZc => "IORING_OP_SENDMSG_ZC",
        }
    }

    pub fn is_zero_copy(&self) -> bool {
        matches!(
            self,
            Self::ReadFixed
                | Self::WriteFixed
                | Self::Splice
                | Self::Tee
                | Self::SendZc
                | Self::SendmsgZc
        )
    }
}

impl fmt::Display for IoUringOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Submission Queue Entry (SQE) flags.
pub mod sqe_flags {
    pub const IOSQE_FIXED_FILE: u8 = 1 << 0;
    pub const IOSQE_IO_DRAIN: u8 = 1 << 1;
    pub const IOSQE_IO_LINK: u8 = 1 << 2;
    pub const IOSQE_IO_HARDLINK: u8 = 1 << 3;
    pub const IOSQE_ASYNC: u8 = 1 << 4;
    pub const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
    pub const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;
}

/// Submission Queue Entry (SQE) representation conforming to the 64-byte kernel layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoUringSqe {
    pub opcode: IoUringOp,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub offset: u64,
    pub addr: u64,
    pub len: u32,
    pub rw_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
}

impl Default for IoUringSqe {
    fn default() -> Self {
        Self {
            opcode: IoUringOp::Nop,
            flags: 0,
            ioprio: 0,
            fd: -1,
            offset: 0,
            addr: 0,
            len: 0,
            rw_flags: 0,
            user_data: 0,
            buf_index: 0,
            personality: 0,
            splice_fd_in: -1,
        }
    }
}

impl IoUringSqe {
    pub fn new(opcode: IoUringOp, fd: i32, user_data: u64) -> Self {
        Self {
            opcode,
            fd,
            user_data,
            ..Default::default()
        }
    }

    pub fn read_fixed(fd: i32, buf_index: u16, offset: u64, len: u32, user_data: u64) -> Self {
        Self {
            opcode: IoUringOp::ReadFixed,
            fd,
            buf_index,
            offset,
            len,
            user_data,
            ..Default::default()
        }
    }

    pub fn write_fixed(fd: i32, buf_index: u16, offset: u64, len: u32, user_data: u64) -> Self {
        Self {
            opcode: IoUringOp::WriteFixed,
            fd,
            buf_index,
            offset,
            len,
            user_data,
            ..Default::default()
        }
    }

    pub fn splice(
        fd_in: i32,
        off_in: u64,
        fd_out: i32,
        off_out: u64,
        len: u32,
        flags: u32,
        user_data: u64,
    ) -> Self {
        Self {
            opcode: IoUringOp::Splice,
            fd: fd_out,
            offset: off_out,
            splice_fd_in: fd_in,
            addr: off_in,
            len,
            rw_flags: flags,
            user_data,
            ..Default::default()
        }
    }
}

/// Completion Queue Entry (CQE) flags.
pub mod cqe_flags {
    pub const IORING_CQE_F_BUFFER: u32 = 1 << 0;
    pub const IORING_CQE_F_MORE: u32 = 1 << 1;
    pub const IORING_CQE_F_SOCK_NONEMPTY: u32 = 1 << 2;
    pub const IORING_CQE_F_NOTIF: u32 = 1 << 3;
}

/// Completion Queue Entry (CQE) representing completion status of an asynchronous request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32, // bytes transferred or negative errno
    pub flags: u32,
}

impl IoUringCqe {
    pub fn new(user_data: u64, res: i32, flags: u32) -> Self {
        Self {
            user_data,
            res,
            flags,
        }
    }

    pub fn is_success(&self) -> bool {
        self.res >= 0
    }

    pub fn bytes_transferred(&self) -> Option<u32> {
        if self.res >= 0 {
            Some(self.res as u32)
        } else {
            None
        }
    }

    pub fn errno(&self) -> Option<i32> {
        if self.res < 0 {
            Some(-self.res)
        } else {
            None
        }
    }
}

/// Setup flags passed during io_uring instantiation (`io_uring_setup`).
pub mod setup_flags {
    pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;
    pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
    pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;
    pub const IORING_SETUP_CQSIZE: u32 = 1 << 3;
    pub const IORING_SETUP_CLAMP: u32 = 1 << 4;
    pub const IORING_SETUP_ATTACH_WQ: u32 = 1 << 5;
    pub const IORING_SETUP_R_DISABLED: u32 = 1 << 6;
    pub const IORING_SETUP_SUBMIT_ALL: u32 = 1 << 7;
    pub const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;
    pub const IORING_SETUP_TASKRUN_FLAG: u32 = 1 << 9;
    pub const IORING_SETUP_SQE128: u32 = 1 << 10;
    pub const IORING_SETUP_CQE32: u32 = 1 << 11;
    pub const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
    pub const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;
}

/// Feature flags reported by the kernel (`features` field in `io_uring_params`).
pub mod feature_flags {
    pub const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
    pub const IORING_FEAT_NODROP: u32 = 1 << 1;
    pub const IORING_FEAT_SUBMIT_STABLE: u32 = 1 << 2;
    pub const IORING_FEAT_RW_CUR_POS: u32 = 1 << 3;
    pub const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;
    pub const IORING_FEAT_FAST_POLL: u32 = 1 << 5;
    pub const IORING_FEAT_POLL_32BITS: u32 = 1 << 6;
    pub const IORING_FEAT_SQPOLL_NONFIXED: u32 = 1 << 7;
    pub const IORING_FEAT_EXT_ARG: u32 = 1 << 8;
    pub const IORING_FEAT_NATIVE_WORKERS: u32 = 1 << 9;
    pub const IORING_FEAT_RSRC_TAGS: u32 = 1 << 10;
    pub const IORING_FEAT_CQE_SKIP: u32 = 1 << 11;
}

/// io_uring initialization parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle_ms: u32,
    pub features: u32,
}

impl Default for IoUringParams {
    fn default() -> Self {
        Self {
            sq_entries: 512,
            cq_entries: 1024,
            flags: 0,
            sq_thread_cpu: 0,
            sq_thread_idle_ms: 2000,
            features: feature_flags::IORING_FEAT_SINGLE_MMAP
                | feature_flags::IORING_FEAT_NODROP
                | feature_flags::IORING_FEAT_SUBMIT_STABLE
                | feature_flags::IORING_FEAT_FAST_POLL
                | feature_flags::IORING_FEAT_SQPOLL_NONFIXED
                | feature_flags::IORING_FEAT_CQE_SKIP,
        }
    }
}

impl IoUringParams {
    pub fn with_sqpoll(mut self, cpu: u32, idle_ms: u32) -> Self {
        self.flags |= setup_flags::IORING_SETUP_SQPOLL;
        self.sq_thread_cpu = cpu;
        self.sq_thread_idle_ms = idle_ms;
        self
    }

    pub fn is_sqpoll_enabled(&self) -> bool {
        (self.flags & setup_flags::IORING_SETUP_SQPOLL) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_uring_op_properties() {
        assert!(IoUringOp::ReadFixed.is_zero_copy());
        assert!(IoUringOp::Splice.is_zero_copy());
        assert!(!IoUringOp::Read.is_zero_copy());
        assert_eq!(IoUringOp::Splice.as_str(), "IORING_OP_SPLICE");
    }

    #[test]
    fn test_cqe_success_and_error_evaluation() {
        let success = IoUringCqe::new(101, 65536, 0);
        assert!(success.is_success());
        assert_eq!(success.bytes_transferred(), Some(65536));
        assert_eq!(success.errno(), None);

        let err = IoUringCqe::new(102, -2, 0); // -ENOENT
        assert!(!err.is_success());
        assert_eq!(err.bytes_transferred(), None);
        assert_eq!(err.errno(), Some(2));
    }
}
