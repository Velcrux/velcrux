#![forbid(unsafe_code)]

//! Integration Test Suite for NVMe-oF SmartNIC / DPU Offload Storage Fabric.
//!
//! Validates:
//! - 64-byte SQE and 16-byte CQE wire serialization & parsing.
//! - Keyed SGL descriptors and Fabric Connect capsules.
//! - LBA storage namespace block allocation, write/read, flush, and TRIM operations.
//! - Virtual NVMe Subsystem, multi-controller ANA states, and command dispatch.
//! - SmartNIC DPU offload engine (P2P DMA, CPU cycles saved, throughput & IOPS calculation).
//! - NVMe Multipath Router failover across dual-ported SmartNIC controllers.

use velcrux_core::nvme::{
    AnaState, ControllerPath, DpuHardwareProfile, DpuOffloadEngine, MultipathPolicy,
    NvmeFabricConnectData, NvmeMultipathRouter, NvmeNamespace, NvmeSglDescriptor,
    NvmeSubmissionQueueEntry, NvmeSubsystem, NVME_STATUS_FABRIC_CONNECT_REJECTED,
    NVME_STATUS_NAMESPACE_NOT_READY,
};

#[test]
fn test_sqe_cqe_fabric_capsule_wire_protocol() {
    let sgl = NvmeSglDescriptor::keyed_data_block(0x7FFF_DEAD_BEEF, 8192, 0x1A2B3C);
    assert_eq!(sgl.address, 0x7FFF_DEAD_BEEF);
    assert_eq!(sgl.length, 8192);
    assert_eq!(sgl.key, 0x1A2B3C);

    let raw_sgl = sgl.to_bytes();
    let parsed_sgl = NvmeSglDescriptor::from_bytes(&raw_sgl);
    assert_eq!(sgl, parsed_sgl);

    // Read SQE
    let sqe_read = NvmeSubmissionQueueEntry::read_command(42, 1, 100, 3, sgl);
    let raw_sqe = sqe_read.to_bytes();
    assert_eq!(raw_sqe.len(), 64);
    let parsed_sqe = NvmeSubmissionQueueEntry::from_bytes(&raw_sqe);
    assert_eq!(sqe_read, parsed_sqe);

    // Fabric Connect data capsule
    let connect_data = NvmeFabricConnectData {
        host_id: [0x77; 16],
        controller_id: 1,
        subsystem_nqn: "nqn.2026-11.io.velcrux:subsys.alpha".to_string(),
        host_nqn: "nqn.2026-11.io.velcrux:host.node01".to_string(),
    };
    let connect_raw = connect_data.to_bytes();
    assert_eq!(connect_raw.len(), 1024);
    let parsed_connect = NvmeFabricConnectData::from_bytes(&connect_raw).expect("parsed connect");
    assert_eq!(connect_data, parsed_connect);
}

#[test]
fn test_lba_namespace_operations_and_integrity() {
    let mut ns = NvmeNamespace::new(1, 4 * 1024 * 1024, 4096).expect("create ns");
    assert_eq!(ns.total_blocks(), 1024);

    // Write 4 sectors (16 KB)
    let payload = vec![0x33; 16384];
    ns.write_blocks(10, 3, &payload).expect("write 4 blocks");
    assert_eq!(ns.allocated_blocks_count(), 4);
    assert_eq!(ns.write_ops, 1);
    assert_eq!(ns.bytes_written, 16384);

    // Read back 4 sectors
    let read_data = ns.read_blocks(10, 3).expect("read 4 blocks");
    assert_eq!(read_data, payload);
    assert_eq!(ns.read_ops, 1);
    assert_eq!(ns.bytes_read, 16384);

    // Trim 2 sectors
    ns.deallocate(10, 1).expect("deallocate blocks 10 and 11");
    assert_eq!(ns.allocated_blocks_count(), 2);
    assert_eq!(ns.trim_ops, 1);

    // Read back trimmed blocks should be zeros
    let trimmed = ns.read_blocks(10, 1).expect("read trimmed");
    assert!(trimmed.iter().all(|&b| b == 0));

    // Remaining blocks still have data
    let remaining = ns.read_blocks(12, 1).expect("read remaining");
    assert_eq!(remaining, vec![0x33; 8192]);

    // Checksum verification
    let csum = ns.calculate_checksum();
    assert_ne!(csum, 0);

    // Out of bounds detection
    let err = ns.read_blocks(1024, 0).unwrap_err();
    assert!(err.to_string().contains("LBA out of range"));
}

#[test]
fn test_virtual_subsystem_and_ana_state_transitions() {
    let mut subsys = NvmeSubsystem::new(
        "nqn.2026-11.io.velcrux:subsys.prod",
        "Velcrux-Enterprise-NVMe",
        "SN-PROD-001",
    );
    let ns = NvmeNamespace::new(1, 2 * 1024 * 1024, 4096).unwrap();
    subsys.add_namespace(ns).unwrap();

    // Register primary controller 1 as Optimized, secondary controller 2 as NonOptimized
    subsys.register_controller(1, AnaState::Optimized);
    subsys.register_controller(2, AnaState::NonOptimized);

    let sgl = NvmeSglDescriptor::keyed_data_block(0x5000_0000, 4096, 0x999);

    // Connect controller 1 with correct Subsystem NQN
    let connect_sqe = NvmeSubmissionQueueEntry::fabric_connect_command(1, sgl);
    let connect_ok = NvmeFabricConnectData {
        host_id: [1; 16],
        controller_id: 1,
        subsystem_nqn: "nqn.2026-11.io.velcrux:subsys.prod".to_string(),
        host_nqn: "nqn.2026-11.io.velcrux:host.app01".to_string(),
    };
    let (cqe_conn, _) = subsys
        .dispatch_sqe(1, &connect_sqe, Some(&connect_ok.to_bytes()))
        .unwrap();
    assert!(cqe_conn.is_success());

    // Connect with incorrect Subsystem NQN should be rejected
    let connect_bad = NvmeFabricConnectData {
        host_id: [1; 16],
        controller_id: 1,
        subsystem_nqn: "nqn.2026-11.io.velcrux:wrong.subsys".to_string(),
        host_nqn: "nqn.2026-11.io.velcrux:host.app01".to_string(),
    };
    let (cqe_bad, _) = subsys
        .dispatch_sqe(1, &connect_sqe, Some(&connect_bad.to_bytes()))
        .unwrap();
    assert_eq!(cqe_bad.status_code(), NVME_STATUS_FABRIC_CONNECT_REJECTED);

    // Transition controller 1 to Inaccessible -> I/O commands return NAMESPACE_NOT_READY
    subsys.controllers.get_mut(&1).unwrap().ana_state = AnaState::Inaccessible;
    let read_sqe = NvmeSubmissionQueueEntry::read_command(10, 1, 0, 0, sgl);
    let (cqe_inaccessible, _) = subsys.dispatch_sqe(1, &read_sqe, None).unwrap();
    assert_eq!(
        cqe_inaccessible.status_code(),
        NVME_STATUS_NAMESPACE_NOT_READY
    );
}

#[test]
fn test_dpu_direct_dma_offload_and_cpu_savings() {
    let mut subsys = NvmeSubsystem::new(
        "nqn.2026-11.io.velcrux:subsys.dpu",
        "BF3-Storage",
        "SN-BF3-TEST",
    );
    let ns = NvmeNamespace::new(1, 16 * 1024 * 1024, 4096).unwrap();
    subsys.add_namespace(ns).unwrap();
    subsys.register_controller(1, AnaState::Optimized);

    let mut dpu = DpuOffloadEngine::new(DpuHardwareProfile::default());

    // Benchmark direct DMA
    let bench = dpu
        .run_benchmark(&mut subsys, 1, 1, 100, 4096)
        .expect("run dpu bench");

    assert_eq!(bench.iterations, 100);
    assert_eq!(bench.total_bytes, 4096 * 100);
    assert!(bench.throughput_mb_s > 0.0);
    assert!(bench.iops > 0.0);
    assert!(bench.host_cpu_cycles_saved > 0);
    assert_eq!(bench.p2p_dma_efficiency_pct, 99.4);
    assert_eq!(dpu.total_dma_transfers, 100);
}

#[test]
fn test_nvme_multipath_router_active_passive_failover() {
    let nqn = "nqn.2026-11.io.velcrux:subsys.cluster";
    let mut subsys = NvmeSubsystem::new(nqn, "Cluster-Storage", "SN-CLS-01");
    let ns = NvmeNamespace::new(1, 8 * 1024 * 1024, 4096).unwrap();
    subsys.add_namespace(ns).unwrap();

    subsys.register_controller(10, AnaState::Optimized);
    subsys.register_controller(20, AnaState::NonOptimized);

    let mut dpu = DpuOffloadEngine::new(DpuHardwareProfile::default());
    let mut router = NvmeMultipathRouter::new(nqn, MultipathPolicy::ActivePassive);

    router.add_path(ControllerPath::new(
        10,
        "10.0.1.1:4420",
        AnaState::Optimized,
    ));
    router.add_path(ControllerPath::new(
        20,
        "10.0.1.2:4420",
        AnaState::NonOptimized,
    ));

    let sgl = NvmeSglDescriptor::keyed_data_block(0x6000_0000, 4096, 0xABC);
    let data = vec![0x7A; 4096];
    let write_sqe = NvmeSubmissionQueueEntry::write_command(1, 1, 0, 0, sgl);

    // Initial write goes to controller 10
    let res = router
        .route_and_execute(&mut subsys, &mut dpu, &write_sqe, Some(&data))
        .expect("first write succeeds");
    assert!(res.cqe.is_success());
    assert_eq!(router.failovers_triggered, 0);

    // Sever controller 10 (simulate link failure / partition)
    subsys.controllers.get_mut(&10).unwrap().ana_state = AnaState::Inaccessible;

    let read_sqe = NvmeSubmissionQueueEntry::read_command(2, 1, 0, 0, sgl);
    let res2 = router
        .route_and_execute(&mut subsys, &mut dpu, &read_sqe, None)
        .expect("failover read succeeds");
    assert!(res2.cqe.is_success());
    assert_eq!(res2.read_payload.unwrap(), data);
    assert_eq!(router.failovers_triggered, 1);
    assert!(!router.paths.get(&10).unwrap().is_alive);
}
