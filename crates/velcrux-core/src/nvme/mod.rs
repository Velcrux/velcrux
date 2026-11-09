#![forbid(unsafe_code)]

//! NVMe-oF (NVM Express over Fabrics 1.1) SmartNIC / DPU Offload Storage Fabric.
//!
//! Provides pure safe-Rust capsule framing, 64-byte SQE / 16-byte CQE wire protocols,
//! Keyed SGL RDMA descriptors, LBA block storage namespaces, virtual subsystem/controllers,
//! Asymmetric Namespace Access (ANA), direct-to-NVMe P2P DMA engine, and multipath routing.

pub mod capsule;
pub mod dpu;
pub mod namespace;
pub mod router;
pub mod subsystem;

pub use capsule::{
    NvmeCompletionQueueEntry, NvmeFabricConnectData, NvmeIdentifyController, NvmeIdentifyNamespace,
    NvmeSglDescriptor, NvmeSubmissionQueueEntry, NVME_FABRIC_AUTH, NVME_FABRIC_CONNECT,
    NVME_FABRIC_DISCONNECT, NVME_OP_FABRIC, NVME_OP_FLUSH, NVME_OP_IDENTIFY, NVME_OP_READ,
    NVME_OP_WRITE, NVME_STATUS_CAPACITY_EXCEEDED, NVME_STATUS_FABRIC_CONNECT_REJECTED,
    NVME_STATUS_INVALID_FIELD, NVME_STATUS_INVALID_OPCODE, NVME_STATUS_LBA_OUT_OF_RANGE,
    NVME_STATUS_NAMESPACE_NOT_READY, NVME_STATUS_SUCCESS, SGL_TYPE_DATA_BLOCK,
    SGL_TYPE_KEYED_DATA_BLOCK, SGL_TYPE_TRANSPORT_DATA_BLOCK,
};

pub use namespace::NvmeNamespace;

pub use subsystem::{AnaState, NvmeController, NvmeSubsystem};

pub use dpu::{
    DpuBenchmarkSummary, DpuDmaExecutionResult, DpuHardwareProfile, DpuOffloadEngine,
    CPU_CYCLES_PER_BYTE, CPU_CYCLES_PER_IO_OVERHEAD,
};

pub use router::{ControllerPath, MultipathPolicy, NvmeMultipathRouter};
