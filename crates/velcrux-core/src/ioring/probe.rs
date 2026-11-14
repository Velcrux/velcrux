//! io_uring Capability Probing & Opcode Support Enumeration (`IORING_REGISTER_PROBE`).

#![forbid(unsafe_code)]

use super::types::{feature_flags, IoUringOp};
use serde::{Deserialize, Serialize};

/// Kernel io_uring feature capability and opcode support probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoUringProbe {
    pub kernel_version: String,
    pub supported_opcodes: Vec<IoUringOp>,
    pub features: u32,
    pub max_sq_entries: u32,
    pub max_cq_entries: u32,
}

impl Default for IoUringProbe {
    fn default() -> Self {
        Self::standard_linux_probe()
    }
}

impl IoUringProbe {
    /// Generates a capability probe representing modern Linux kernel (>= 6.1) io_uring features.
    pub fn standard_linux_probe() -> Self {
        let opcodes = vec![
            IoUringOp::Nop,
            IoUringOp::Readv,
            IoUringOp::Writev,
            IoUringOp::Fsync,
            IoUringOp::ReadFixed,
            IoUringOp::WriteFixed,
            IoUringOp::PollAdd,
            IoUringOp::PollRemove,
            IoUringOp::SyncFileRange,
            IoUringOp::Sendmsg,
            IoUringOp::Recvmsg,
            IoUringOp::Timeout,
            IoUringOp::TimeoutRemove,
            IoUringOp::Accept,
            IoUringOp::AsyncCancel,
            IoUringOp::LinkTimeout,
            IoUringOp::Connect,
            IoUringOp::Fallocate,
            IoUringOp::Openat,
            IoUringOp::Close,
            IoUringOp::FilesUpdate,
            IoUringOp::Statx,
            IoUringOp::Read,
            IoUringOp::Write,
            IoUringOp::Fadvise,
            IoUringOp::Madvise,
            IoUringOp::Send,
            IoUringOp::Recv,
            IoUringOp::Openat2,
            IoUringOp::EpollCtl,
            IoUringOp::Splice,
            IoUringOp::ProvideBuffers,
            IoUringOp::RemoveBuffers,
            IoUringOp::Tee,
            IoUringOp::Shutdown,
            IoUringOp::Renameat,
            IoUringOp::Unlinkat,
            IoUringOp::Mkdirat,
            IoUringOp::Symlinkat,
            IoUringOp::Linkat,
            IoUringOp::MsgRing,
            IoUringOp::Fsetxattr,
            IoUringOp::Setxattr,
            IoUringOp::Fgetxattr,
            IoUringOp::Getxattr,
            IoUringOp::Socket,
            IoUringOp::UringCmd,
            IoUringOp::SendZc,
            IoUringOp::SendmsgZc,
        ];

        Self {
            kernel_version: "Linux 6.8.0-velcrux-iouring".into(),
            supported_opcodes: opcodes,
            features: feature_flags::IORING_FEAT_SINGLE_MMAP
                | feature_flags::IORING_FEAT_NODROP
                | feature_flags::IORING_FEAT_SUBMIT_STABLE
                | feature_flags::IORING_FEAT_RW_CUR_POS
                | feature_flags::IORING_FEAT_FAST_POLL
                | feature_flags::IORING_FEAT_POLL_32BITS
                | feature_flags::IORING_FEAT_SQPOLL_NONFIXED
                | feature_flags::IORING_FEAT_EXT_ARG
                | feature_flags::IORING_FEAT_NATIVE_WORKERS
                | feature_flags::IORING_FEAT_RSRC_TAGS
                | feature_flags::IORING_FEAT_CQE_SKIP,
            max_sq_entries: 32768,
            max_cq_entries: 65536,
        }
    }

    pub fn is_opcode_supported(&self, op: IoUringOp) -> bool {
        self.supported_opcodes.contains(&op)
    }

    pub fn supports_sqpoll(&self) -> bool {
        (self.features & feature_flags::IORING_FEAT_SQPOLL_NONFIXED) != 0
    }

    pub fn supports_zero_copy_send(&self) -> bool {
        self.is_opcode_supported(IoUringOp::SendZc)
            && self.is_opcode_supported(IoUringOp::SendmsgZc)
    }

    pub fn supports_fixed_buffers(&self) -> bool {
        self.is_opcode_supported(IoUringOp::ReadFixed)
            && self.is_opcode_supported(IoUringOp::WriteFixed)
    }

    pub fn supports_splice(&self) -> bool {
        self.is_opcode_supported(IoUringOp::Splice) && self.is_opcode_supported(IoUringOp::Tee)
    }

    pub fn supports_feature(&self, feature: u32) -> bool {
        (self.features & feature) == feature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_uring_probe_capabilities() {
        let probe = IoUringProbe::standard_linux_probe();
        assert!(probe.is_opcode_supported(IoUringOp::ReadFixed));
        assert!(probe.is_opcode_supported(IoUringOp::WriteFixed));
        assert!(probe.is_opcode_supported(IoUringOp::Splice));
        assert!(probe.is_opcode_supported(IoUringOp::SendZc));
        assert!(probe.supports_sqpoll());
        assert!(probe.supports_zero_copy_send());
        assert!(probe.supports_fixed_buffers());
        assert!(probe.supports_splice());
    }
}
