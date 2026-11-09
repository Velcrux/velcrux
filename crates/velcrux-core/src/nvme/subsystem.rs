#![forbid(unsafe_code)]

//! NVMe Subsystem, Controller State Machine, and Asymmetric Namespace Access (ANA).
//!
//! Models NVMe-oF target subsystems containing virtual controllers, Admin Queue Pairs (ASQ/ACQ),
//! I/O Queue Pairs (IOSQ/IOCQ), and multi-controller Asymmetric Namespace Access (ANA) reporting.

use super::capsule::{
    NvmeCompletionQueueEntry, NvmeFabricConnectData, NvmeIdentifyController,
    NvmeSubmissionQueueEntry, NVME_FABRIC_CONNECT, NVME_FABRIC_DISCONNECT, NVME_OP_FABRIC,
    NVME_OP_FLUSH, NVME_OP_IDENTIFY, NVME_OP_READ, NVME_OP_WRITE, NVME_STATUS_CAPACITY_EXCEEDED,
    NVME_STATUS_FABRIC_CONNECT_REJECTED, NVME_STATUS_INVALID_FIELD, NVME_STATUS_INVALID_OPCODE,
    NVME_STATUS_LBA_OUT_OF_RANGE, NVME_STATUS_NAMESPACE_NOT_READY,
};
use super::namespace::NvmeNamespace;
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Asymmetric Namespace Access (ANA) Group State.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnaState {
    /// Controller has direct, optimal low-latency PCIe/RDMA connectivity to namespace.
    Optimized = 0x01,
    /// Controller can service I/O via inter-node mesh fabrics with sub-optimal latency.
    NonOptimized = 0x02,
    /// Storage target path is temporarily partitioned or recovering.
    Inaccessible = 0x03,
    /// Permanent hardware failure or link detachment.
    PersistentLoss = 0x04,
    /// ANA state change in progress.
    Change = 0x0F,
}

impl AnaState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Optimized => "optimized",
            Self::NonOptimized => "non-optimized",
            Self::Inaccessible => "inaccessible",
            Self::PersistentLoss => "persistent-loss",
            Self::Change => "change",
        }
    }
}

/// Virtual NVMe-oF Controller instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvmeController {
    /// Controller Identifier (CNTLID).
    pub cntlid: u16,
    /// Subsystem NQN to which this controller belongs.
    pub subsystem_nqn: String,
    /// Connected Host NQN (if active session established).
    pub host_nqn: Option<String>,
    /// Connection state.
    pub is_connected: bool,
    /// Submission Queue Head tracker for Admin QP.
    pub admin_sq_head: u16,
    /// Submission Queue Head tracker for I/O QP.
    pub io_sq_head: u16,
    /// Controller ANA multipathing state.
    pub ana_state: AnaState,
    /// Commands executed by this controller.
    pub command_count: u64,
}

impl NvmeController {
    pub fn new(cntlid: u16, subsystem_nqn: String, ana_state: AnaState) -> Self {
        Self {
            cntlid,
            subsystem_nqn,
            host_nqn: None,
            is_connected: false,
            admin_sq_head: 0,
            io_sq_head: 0,
            ana_state,
            command_count: 0,
        }
    }

    /// Generates standard Identify Controller structure for this controller.
    pub fn identify(&self, num_namespaces: u32) -> NvmeIdentifyController {
        let mut id = NvmeIdentifyController::default_dpu_controller(self.cntlid, num_namespaces);
        id.sn = format!("VX-DPU-{:04X}", self.cntlid);
        id
    }
}

/// Virtual NVMe Storage Subsystem aggregating controllers and LBA namespaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvmeSubsystem {
    /// Subsystem NVMe Qualified Name (NQN).
    pub subsystem_nqn: String,
    /// Model string.
    pub model_number: String,
    /// Serial number.
    pub serial_number: String,
    /// Hosted namespaces indexed by NSID (1-based).
    pub namespaces: HashMap<u32, NvmeNamespace>,
    /// Allocated controllers indexed by CNTLID.
    pub controllers: HashMap<u16, NvmeController>,
}

impl NvmeSubsystem {
    /// Creates a new NVMe Subsystem.
    pub fn new(
        subsystem_nqn: impl Into<String>,
        model_number: impl Into<String>,
        serial_number: impl Into<String>,
    ) -> Self {
        Self {
            subsystem_nqn: subsystem_nqn.into(),
            model_number: model_number.into(),
            serial_number: serial_number.into(),
            namespaces: HashMap::new(),
            controllers: HashMap::new(),
        }
    }

    /// Adds a storage namespace to the subsystem.
    pub fn add_namespace(&mut self, namespace: NvmeNamespace) -> Result<()> {
        let nsid = namespace.nsid;
        if self.namespaces.contains_key(&nsid) {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "namespace with this NSID already exists in subsystem",
            )));
        }
        self.namespaces.insert(nsid, namespace);
        Ok(())
    }

    /// Registers a controller with initial ANA state.
    pub fn register_controller(&mut self, cntlid: u16, ana_state: AnaState) -> &mut NvmeController {
        let nqn = self.subsystem_nqn.clone();
        self.controllers
            .entry(cntlid)
            .or_insert_with(|| NvmeController::new(cntlid, nqn, ana_state))
    }

    /// Dispatches an incoming Submission Queue Entry (SQE) to the target controller.
    ///
    /// Returns the resulting Completion Queue Entry (CQE) along with any read data bytes.
    pub fn dispatch_sqe(
        &mut self,
        cntlid: u16,
        sqe: &NvmeSubmissionQueueEntry,
        write_payload: Option<&[u8]>,
    ) -> Result<(NvmeCompletionQueueEntry, Option<Vec<u8>>)> {
        let controller = self.controllers.get_mut(&cntlid).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("controller not found"))
        })?;

        controller.command_count += 1;
        let command_id = sqe.command_id;

        // Check ANA status for I/O commands
        if (sqe.opcode == NVME_OP_READ
            || sqe.opcode == NVME_OP_WRITE
            || sqe.opcode == NVME_OP_FLUSH)
            && (controller.ana_state == AnaState::Inaccessible
                || controller.ana_state == AnaState::PersistentLoss)
        {
            let cqe = NvmeCompletionQueueEntry::error(
                command_id,
                1,
                controller.io_sq_head,
                NVME_STATUS_NAMESPACE_NOT_READY,
            );
            return Ok((cqe, None));
        }

        match sqe.opcode {
            NVME_OP_FABRIC => {
                let fctype = sqe.cdw2 as u8;
                controller.admin_sq_head = controller.admin_sq_head.wrapping_add(1);
                match fctype {
                    NVME_FABRIC_CONNECT => {
                        // In NVMe-oF Connect, write_payload contains NvmeFabricConnectData
                        if let Some(payload) = write_payload {
                            if payload.len() >= NvmeFabricConnectData::SIZE_BYTES {
                                let mut fixed = [0u8; NvmeFabricConnectData::SIZE_BYTES];
                                fixed
                                    .copy_from_slice(&payload[..NvmeFabricConnectData::SIZE_BYTES]);
                                if let Ok(connect_data) = NvmeFabricConnectData::from_bytes(&fixed)
                                {
                                    if connect_data.subsystem_nqn != self.subsystem_nqn {
                                        let cqe = NvmeCompletionQueueEntry::error(
                                            command_id,
                                            0,
                                            controller.admin_sq_head,
                                            NVME_STATUS_FABRIC_CONNECT_REJECTED,
                                        );
                                        return Ok((cqe, None));
                                    }
                                    controller.host_nqn = Some(connect_data.host_nqn);
                                    controller.is_connected = true;
                                    let cqe = NvmeCompletionQueueEntry::success(
                                        command_id,
                                        0,
                                        controller.admin_sq_head,
                                        cntlid as u64,
                                    );
                                    return Ok((cqe, None));
                                }
                            }
                        }
                        // Default connect if payload omitted or valid
                        controller.is_connected = true;
                        let cqe = NvmeCompletionQueueEntry::success(
                            command_id,
                            0,
                            controller.admin_sq_head,
                            cntlid as u64,
                        );
                        Ok((cqe, None))
                    }
                    NVME_FABRIC_DISCONNECT => {
                        controller.is_connected = false;
                        controller.host_nqn = None;
                        let cqe = NvmeCompletionQueueEntry::success(
                            command_id,
                            0,
                            controller.admin_sq_head,
                            0,
                        );
                        Ok((cqe, None))
                    }
                    _ => {
                        let cqe = NvmeCompletionQueueEntry::error(
                            command_id,
                            0,
                            controller.admin_sq_head,
                            NVME_STATUS_INVALID_FIELD,
                        );
                        Ok((cqe, None))
                    }
                }
            }
            NVME_OP_IDENTIFY => {
                controller.admin_sq_head = controller.admin_sq_head.wrapping_add(1);
                let cns = sqe.cdw2 & 0xFF;
                match cns {
                    0x01 => {
                        // Identify Controller
                        let id = controller.identify(self.namespaces.len() as u32);
                        let json = serde_json::to_vec(&id).unwrap_or_default();
                        let cqe = NvmeCompletionQueueEntry::success(
                            command_id,
                            0,
                            controller.admin_sq_head,
                            0,
                        );
                        Ok((cqe, Some(json)))
                    }
                    0x00 => {
                        // Identify Namespace
                        if let Some(ns) = self.namespaces.get(&sqe.nsid) {
                            let id = ns.identify();
                            let json = serde_json::to_vec(&id).unwrap_or_default();
                            let cqe = NvmeCompletionQueueEntry::success(
                                command_id,
                                0,
                                controller.admin_sq_head,
                                0,
                            );
                            Ok((cqe, Some(json)))
                        } else {
                            let cqe = NvmeCompletionQueueEntry::error(
                                command_id,
                                0,
                                controller.admin_sq_head,
                                NVME_STATUS_INVALID_FIELD,
                            );
                            Ok((cqe, None))
                        }
                    }
                    _ => {
                        let cqe = NvmeCompletionQueueEntry::error(
                            command_id,
                            0,
                            controller.admin_sq_head,
                            NVME_STATUS_INVALID_FIELD,
                        );
                        Ok((cqe, None))
                    }
                }
            }
            NVME_OP_READ => {
                controller.io_sq_head = controller.io_sq_head.wrapping_add(1);
                let ns = match self.namespaces.get_mut(&sqe.nsid) {
                    Some(n) => n,
                    None => {
                        let cqe = NvmeCompletionQueueEntry::error(
                            command_id,
                            1,
                            controller.io_sq_head,
                            NVME_STATUS_INVALID_FIELD,
                        );
                        return Ok((cqe, None));
                    }
                };

                match ns.read_blocks(sqe.slba, sqe.nlb) {
                    Ok(data) => {
                        let cqe = NvmeCompletionQueueEntry::success(
                            command_id,
                            1,
                            controller.io_sq_head,
                            0,
                        );
                        Ok((cqe, Some(data)))
                    }
                    Err(_) => {
                        let cqe = NvmeCompletionQueueEntry::error(
                            command_id,
                            1,
                            controller.io_sq_head,
                            NVME_STATUS_LBA_OUT_OF_RANGE,
                        );
                        Ok((cqe, None))
                    }
                }
            }
            NVME_OP_WRITE => {
                controller.io_sq_head = controller.io_sq_head.wrapping_add(1);
                let ns = match self.namespaces.get_mut(&sqe.nsid) {
                    Some(n) => n,
                    None => {
                        let cqe = NvmeCompletionQueueEntry::error(
                            command_id,
                            1,
                            controller.io_sq_head,
                            NVME_STATUS_INVALID_FIELD,
                        );
                        return Ok((cqe, None));
                    }
                };

                let payload = match write_payload {
                    Some(p) => p,
                    None => {
                        let cqe = NvmeCompletionQueueEntry::error(
                            command_id,
                            1,
                            controller.io_sq_head,
                            NVME_STATUS_INVALID_FIELD,
                        );
                        return Ok((cqe, None));
                    }
                };

                match ns.write_blocks(sqe.slba, sqe.nlb, payload) {
                    Ok(()) => {
                        let cqe = NvmeCompletionQueueEntry::success(
                            command_id,
                            1,
                            controller.io_sq_head,
                            0,
                        );
                        Ok((cqe, None))
                    }
                    Err(_) => {
                        let cqe = NvmeCompletionQueueEntry::error(
                            command_id,
                            1,
                            controller.io_sq_head,
                            NVME_STATUS_CAPACITY_EXCEEDED,
                        );
                        Ok((cqe, None))
                    }
                }
            }
            NVME_OP_FLUSH => {
                controller.io_sq_head = controller.io_sq_head.wrapping_add(1);
                if let Some(ns) = self.namespaces.get_mut(&sqe.nsid) {
                    let _ = ns.flush();
                }
                let cqe =
                    NvmeCompletionQueueEntry::success(command_id, 1, controller.io_sq_head, 0);
                Ok((cqe, None))
            }
            _ => {
                controller.io_sq_head = controller.io_sq_head.wrapping_add(1);
                let cqe = NvmeCompletionQueueEntry::error(
                    command_id,
                    1,
                    controller.io_sq_head,
                    NVME_STATUS_INVALID_OPCODE,
                );
                Ok((cqe, None))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::capsule::NvmeSglDescriptor;
    use super::*;

    #[test]
    fn test_subsystem_connect_and_io() {
        let mut subsys = NvmeSubsystem::new(
            "nqn.2026-11.io.velcrux:subsys.nvme01",
            "Velcrux-Storage",
            "SN-12345",
        );
        let ns = NvmeNamespace::new(1, 1024 * 1024, 4096).unwrap();
        subsys.add_namespace(ns).unwrap();
        subsys.register_controller(1, AnaState::Optimized);

        // Connect
        let sgl = NvmeSglDescriptor::keyed_data_block(0x1000, 1024, 0x11);
        let connect_sqe = NvmeSubmissionQueueEntry::fabric_connect_command(1, sgl);
        let connect_data = NvmeFabricConnectData {
            host_id: [1; 16],
            controller_id: 1,
            subsystem_nqn: "nqn.2026-11.io.velcrux:subsys.nvme01".to_string(),
            host_nqn: "nqn.2026-11.io.velcrux:host.client".to_string(),
        };
        let (cqe, _) = subsys
            .dispatch_sqe(1, &connect_sqe, Some(&connect_data.to_bytes()))
            .unwrap();
        assert!(cqe.is_success());
        assert!(subsys.controllers.get(&1).unwrap().is_connected);

        // Write
        let write_data = vec![0xEE; 4096];
        let write_sqe = NvmeSubmissionQueueEntry::write_command(2, 1, 0, 0, sgl);
        let (cqe_write, _) = subsys
            .dispatch_sqe(1, &write_sqe, Some(&write_data))
            .unwrap();
        assert!(cqe_write.is_success());

        // Read
        let read_sqe = NvmeSubmissionQueueEntry::read_command(3, 1, 0, 0, sgl);
        let (cqe_read, data_read) = subsys.dispatch_sqe(1, &read_sqe, None).unwrap();
        assert!(cqe_read.is_success());
        assert_eq!(data_read.unwrap(), write_data);
    }
}
