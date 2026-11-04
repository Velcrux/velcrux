//! RDMA Transfer Engine, HCA Device Emulation, and Zero-Copy Pipeline Orchestrator.
//!
//! Complies strictly with `#![forbid(unsafe_code)]`.

use crate::rdma::mr::{AccessFlags, MemoryRegion, ProtectionDomain};
use crate::rdma::pacing::{DcqcnConfig, DcqcnPacer, DcqcnReport};
use crate::rdma::verbs::{
    CompletionQueue, QpInitAttr, QpType, QueuePair, SendFlags, SendWr, Sge, WcOpcode, WcStatus,
    WrOpcode,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Host Channel Adapter (HCA) Device Attributes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HcaDeviceAttributes {
    pub device_name: String,
    pub vendor_id: u32,
    pub max_qp: u32,
    pub max_cq: u32,
    pub max_mr: u32,
    pub max_mr_size: u64,
    pub max_sge: u32,
    pub active_mtu: u32,
    pub link_layer: String,
    pub active_speed: String,
    pub port_state: String,
}

impl Default for HcaDeviceAttributes {
    fn default() -> Self {
        Self {
            device_name: "mlx5_0".to_string(),
            vendor_id: 0x15b3, // Mellanox Technologies
            max_qp: 65536,
            max_cq: 65536,
            max_mr: 131072,
            max_mr_size: 1024 * 1024 * 1024 * 1024, // 1 TiB
            max_sge: 16,
            active_mtu: 4096,
            link_layer: "RoCEv2".to_string(),
            active_speed: "100 Gbps (4X EDR/HDR)".to_string(),
            port_state: "Active (LinkUp)".to_string(),
        }
    }
}

/// RDMA Zero-Copy Transfer Benchmark Report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RdmaBenchmarkReport {
    pub device: String,
    pub qp_type: String,
    pub num_chunks: usize,
    pub chunk_size_bytes: usize,
    pub total_bytes: u64,
    pub duration_millis: f64,
    pub throughput_mpps: f64,
    pub throughput_gbps: f64,
    pub zero_copy_verified: bool,
    pub dcqcn: DcqcnReport,
}

/// RDMA Transfer Engine orchestrating peer-to-peer hardware bypass memory transfers.
pub struct RdmaTransferEngine {
    device_attr: HcaDeviceAttributes,
    pacer: Arc<DcqcnPacer>,
    total_zero_copy_bytes: AtomicU64,
    total_rdma_ops: AtomicU64,
}

impl RdmaTransferEngine {
    /// Create a new RDMA Transfer Engine with standard 100 Gbps HCA attributes.
    pub fn new() -> Self {
        Self {
            device_attr: HcaDeviceAttributes::default(),
            pacer: Arc::new(DcqcnPacer::new(DcqcnConfig::default())),
            total_zero_copy_bytes: AtomicU64::new(0),
            total_rdma_ops: AtomicU64::new(0),
        }
    }

    /// Query the physical HCA device attributes.
    pub fn device_attributes(&self) -> &HcaDeviceAttributes {
        &self.device_attr
    }

    /// Query active DCQCN flow pacer.
    pub fn pacer(&self) -> &Arc<DcqcnPacer> {
        &self.pacer
    }

    /// Execute a benchmark session transferring chunks using direct RDMA Write with Immediate.
    pub fn run_benchmark(
        &self,
        num_chunks: usize,
        chunk_size: usize,
        inject_cnp: bool,
    ) -> Result<RdmaBenchmarkReport, &'static str> {
        let start = Instant::now();

        // 1. Setup Client and Server Protection Domains
        let client_pd = ProtectionDomain::new();
        let server_pd = ProtectionDomain::new();

        // 2. Setup Client and Server Completion Queues
        let client_cq = Arc::new(CompletionQueue::new(num_chunks + 64));
        let server_cq = Arc::new(CompletionQueue::new(num_chunks + 64));

        // 3. Setup Client and Server Queue Pairs
        let client_qp = QueuePair::new(
            &client_pd,
            QpInitAttr {
                qp_type: QpType::ReliableConnected,
                sq_capacity: num_chunks + 64,
                rq_capacity: num_chunks + 64,
                send_cq: client_cq.clone(),
                recv_cq: client_cq.clone(),
            },
        );

        let server_qp = QueuePair::new(
            &server_pd,
            QpInitAttr {
                qp_type: QpType::ReliableConnected,
                sq_capacity: num_chunks + 64,
                rq_capacity: num_chunks + 64,
                send_cq: server_cq.clone(),
                recv_cq: server_cq.clone(),
            },
        );

        // 4. Transition QPs: Reset -> Init -> RTR -> RTS
        client_qp.modify_to_init()?;
        server_qp.modify_to_init()?;

        client_qp.modify_to_rtr(server_qp.qp_num, 0x1000)?;
        server_qp.modify_to_rtr(client_qp.qp_num, 0x2000)?;

        client_qp.modify_to_rts(0x2000)?;
        server_qp.modify_to_rts(0x1000)?;

        // 5. Register Memory Regions
        let total_size = num_chunks * chunk_size;
        let mut sample_data = Vec::with_capacity(total_size);
        for i in 0..total_size {
            sample_data.push(((i ^ 0x5C) & 0xFF) as u8);
        }

        let client_mr = MemoryRegion::register_with_data(
            &client_pd,
            sample_data.clone(),
            AccessFlags::LOCAL_WRITE.union(AccessFlags::REMOTE_READ),
        );

        let server_mr = MemoryRegion::register(
            &server_pd,
            total_size,
            AccessFlags::LOCAL_WRITE.union(AccessFlags::REMOTE_WRITE),
        );

        // 6. Execute Pipelined RDMA Write with Immediate transfers
        for i in 0..num_chunks {
            let offset = i * chunk_size;

            let wr = SendWr {
                wr_id: (i + 1) as u64,
                opcode: WrOpcode::RdmaWriteWithImm,
                send_flags: SendFlags::SIGNALED,
                sg_list: vec![Sge {
                    addr: client_mr.addr + offset as u64,
                    length: chunk_size as u32,
                    lkey: client_mr.lkey,
                }],
                remote_addr: server_mr.addr + offset as u64,
                rkey: server_mr.rkey,
                imm_data: Some(i as u32),
            };

            let wc = client_qp.execute_rdma_write(&wr, &client_mr, &server_mr, Some(&server_qp))?;

            if wc.status != WcStatus::Success {
                return Err("Work completion failure in RDMA Write");
            }

            self.pacer.on_bytes_transmitted(chunk_size as u64);
            self.total_zero_copy_bytes
                .fetch_add(chunk_size as u64, Ordering::Relaxed);
            self.total_rdma_ops.fetch_add(1, Ordering::Relaxed);

            // Optional simulated congestion event midway through transfer
            if inject_cnp && i == num_chunks / 2 {
                self.pacer.on_cnp();
            }
        }

        // 7. Poll Completions from Server Receive CQ
        let server_completions = server_cq.poll(num_chunks);
        if server_completions.len() != num_chunks {
            return Err("Mismatched receive completion count");
        }

        for (idx, comp) in server_completions.iter().enumerate() {
            if comp.status != WcStatus::Success || comp.opcode != WcOpcode::RecvImm {
                return Err("Invalid server receive completion");
            }
            if comp.imm_data != Some(idx as u32) {
                return Err("Mismatched immediate data sequence");
            }
        }

        // 8. Verify Bit-for-bit data in server memory without CPU copy
        let destination_bytes = server_mr.read(0, total_size)?;
        let zero_copy_verified = destination_bytes == sample_data;

        let elapsed = start.elapsed();
        let elapsed_secs = elapsed.as_secs_f64().max(0.000001);
        let throughput_mpps = (num_chunks as f64) / (elapsed_secs * 1_000_000.0);
        let throughput_gbps = (total_size as f64 * 8.0) / (elapsed_secs * 1_000_000_000.0);

        Ok(RdmaBenchmarkReport {
            device: self.device_attr.device_name.clone(),
            qp_type: "ReliableConnected (RC)".to_string(),
            num_chunks,
            chunk_size_bytes: chunk_size,
            total_bytes: total_size as u64,
            duration_millis: elapsed.as_secs_f64() * 1000.0,
            throughput_mpps,
            throughput_gbps,
            zero_copy_verified,
            dcqcn: self.pacer.report(),
        })
    }
}

impl Default for RdmaTransferEngine {
    fn default() -> Self {
        Self::new()
    }
}
