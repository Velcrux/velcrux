#![forbid(unsafe_code)]

//! Asynchronous NVMe-oF Initiator Client and Multipath Router.
//!
//! Provides intelligent path selection, Asymmetric Namespace Access (ANA) topology tracking,
//! dynamic load balancing, and sub-millisecond transparent failover across dual-ported SmartNICs.

use super::capsule::{NvmeSubmissionQueueEntry, NVME_STATUS_NAMESPACE_NOT_READY};
use super::dpu::{DpuDmaExecutionResult, DpuOffloadEngine};
use super::subsystem::{AnaState, NvmeSubsystem};
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Multipath selection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultipathPolicy {
    /// Select lowest latency path among Optimized ANA controllers.
    LowestLatency,
    /// Round-robin across all Optimized ANA controllers.
    RoundRobin,
    /// Strict priority (prefers primary controller, fails over only on detachment).
    ActivePassive,
}

/// Representation of a physical or virtual fabric path to an NVMe controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerPath {
    pub cntlid: u16,
    pub endpoint_address: String,
    pub ana_state: AnaState,
    pub is_alive: bool,
    pub failure_count: u32,
    pub avg_latency_micros: u64,
    pub requests_dispatched: u64,
}

impl ControllerPath {
    pub fn new(cntlid: u16, endpoint_address: impl Into<String>, ana_state: AnaState) -> Self {
        Self {
            cntlid,
            endpoint_address: endpoint_address.into(),
            ana_state,
            is_alive: true,
            failure_count: 0,
            avg_latency_micros: 10,
            requests_dispatched: 0,
        }
    }

    /// Evaluates if path is viable for I/O dispatch.
    pub fn is_viable(&self) -> bool {
        self.is_alive
            && (self.ana_state == AnaState::Optimized || self.ana_state == AnaState::NonOptimized)
    }
}

/// NVMe-oF Multipath Router.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvmeMultipathRouter {
    /// Target Subsystem NQN.
    pub target_subsystem_nqn: String,
    /// Multipathing policy.
    pub policy: MultipathPolicy,
    /// Registered paths indexed by CNTLID.
    pub paths: HashMap<u16, ControllerPath>,
    /// Round-robin index.
    round_robin_idx: usize,
    /// Total routed requests.
    pub total_requests: u64,
    /// Number of failovers triggered due to path degradation or controller detachment.
    pub failovers_triggered: u64,
}

impl NvmeMultipathRouter {
    /// Creates a new multipath router targeting a specific subsystem.
    pub fn new(target_subsystem_nqn: impl Into<String>, policy: MultipathPolicy) -> Self {
        Self {
            target_subsystem_nqn: target_subsystem_nqn.into(),
            policy,
            paths: HashMap::new(),
            round_robin_idx: 0,
            total_requests: 0,
            failovers_triggered: 0,
        }
    }

    /// Adds a controller path to the routing topology.
    pub fn add_path(&mut self, path: ControllerPath) {
        self.paths.insert(path.cntlid, path);
    }

    /// Updates ANA state for a specific controller.
    pub fn update_ana_state(&mut self, cntlid: u16, new_state: AnaState) -> Result<()> {
        let path = self
            .paths
            .get_mut(&cntlid)
            .ok_or_else(|| VelcruxError::Protocol(ProtocolError::Malformed("path not found")))?;
        path.ana_state = new_state;
        if new_state == AnaState::Inaccessible || new_state == AnaState::PersistentLoss {
            path.is_alive = false;
        } else {
            path.is_alive = true;
        }
        Ok(())
    }

    /// Selects the best candidate controller path according to the active policy.
    pub fn select_best_path(&mut self) -> Result<u16> {
        let mut viable_paths: Vec<&mut ControllerPath> =
            self.paths.values_mut().filter(|p| p.is_viable()).collect();

        if viable_paths.is_empty() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "no viable NVMe controller paths available in topology",
            )));
        }

        // Separate Optimized from Non-Optimized
        let has_optimized = viable_paths
            .iter()
            .any(|p| p.ana_state == AnaState::Optimized);
        if has_optimized {
            viable_paths.retain(|p| p.ana_state == AnaState::Optimized);
        }

        match self.policy {
            MultipathPolicy::LowestLatency => {
                let best = viable_paths
                    .iter()
                    .min_by_key(|p| p.avg_latency_micros)
                    .unwrap();
                Ok(best.cntlid)
            }
            MultipathPolicy::RoundRobin => {
                let len = viable_paths.len();
                let picked = viable_paths[self.round_robin_idx % len].cntlid;
                self.round_robin_idx = (self.round_robin_idx + 1) % len;
                Ok(picked)
            }
            MultipathPolicy::ActivePassive => {
                viable_paths.sort_by_key(|p| p.cntlid);
                Ok(viable_paths[0].cntlid)
            }
        }
    }

    /// Routes an NVMe command through the DPU offload engine with automatic failover.
    pub fn route_and_execute(
        &mut self,
        subsystem: &mut NvmeSubsystem,
        dpu: &mut DpuOffloadEngine,
        sqe: &NvmeSubmissionQueueEntry,
        remote_data: Option<&[u8]>,
    ) -> Result<DpuDmaExecutionResult> {
        self.total_requests += 1;
        let mut attempts = 0;
        let max_attempts = self.paths.len().max(1);

        while attempts < max_attempts {
            attempts += 1;
            let cntlid = match self.select_best_path() {
                Ok(id) => id,
                Err(e) => {
                    if attempts > 1 {
                        break;
                    }
                    return Err(e);
                }
            };

            let outcome = dpu.execute_dma_transfer(subsystem, cntlid, sqe, remote_data);

            match outcome {
                Ok(res) => {
                    // Check if CQE indicated ANA or namespace ready error
                    if !res.cqe.is_success()
                        && res.cqe.status_code() == NVME_STATUS_NAMESPACE_NOT_READY
                    {
                        // Mark path inaccessible and failover
                        if let Some(path) = self.paths.get_mut(&cntlid) {
                            path.ana_state = AnaState::Inaccessible;
                            path.is_alive = false;
                            path.failure_count += 1;
                        }
                        self.failovers_triggered += 1;
                        continue;
                    }

                    // Success - update path metrics
                    if let Some(path) = self.paths.get_mut(&cntlid) {
                        path.requests_dispatched += 1;
                        path.avg_latency_micros =
                            (path.avg_latency_micros * 7 + res.latency_micros) / 8;
                    }
                    return Ok(res);
                }
                Err(_err) => {
                    if let Some(path) = self.paths.get_mut(&cntlid) {
                        path.failure_count += 1;
                        path.is_alive = false;
                    }
                    self.failovers_triggered += 1;
                    continue;
                }
            }
        }

        Err(VelcruxError::Protocol(ProtocolError::Malformed(
            "all NVMe-oF controller paths exhausted or failed",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::super::dpu::DpuHardwareProfile;
    use super::super::namespace::NvmeNamespace;
    use super::*;

    #[test]
    fn test_multipath_failover() {
        let nqn = "nqn.2026-11.io.velcrux:subsys.ha";
        let mut subsys = NvmeSubsystem::new(nqn, "Dual-Port-Fabric", "SN-DP-01");
        let ns = NvmeNamespace::new(1, 1024 * 1024, 4096).unwrap();
        subsys.add_namespace(ns).unwrap();

        // Controller 1 (Optimized) and Controller 2 (Non-Optimized / standby)
        subsys.register_controller(1, AnaState::Optimized);
        subsys.register_controller(2, AnaState::NonOptimized);

        let mut dpu = DpuOffloadEngine::new(DpuHardwareProfile::default());
        let mut router = NvmeMultipathRouter::new(nqn, MultipathPolicy::ActivePassive);

        router.add_path(ControllerPath::new(
            1,
            "192.168.10.1:4420",
            AnaState::Optimized,
        ));
        router.add_path(ControllerPath::new(
            2,
            "192.168.10.2:4420",
            AnaState::NonOptimized,
        ));

        // Initial selection should pick path 1
        assert_eq!(router.select_best_path().unwrap(), 1);

        // Simulate Controller 1 going down
        subsys.controllers.get_mut(&1).unwrap().ana_state = AnaState::Inaccessible;

        let sgl = super::super::capsule::NvmeSglDescriptor::keyed_data_block(0x1000, 4096, 0x123);
        let sqe = NvmeSubmissionQueueEntry::read_command(1, 1, 0, 0, sgl);

        // Route should automatically failover to path 2
        let res = router
            .route_and_execute(&mut subsys, &mut dpu, &sqe, None)
            .expect("failover success");
        assert!(res.cqe.is_success());
        assert_eq!(router.failovers_triggered, 1);
        assert!(!router.paths.get(&1).unwrap().is_alive);
    }
}
