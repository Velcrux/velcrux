//! Comprehensive integration tests for Option CY:
//! Hardware-Accelerated RDMA (RoCEv2 / InfiniBand) Direct Memory Pacing (`ADR-067`).

#![forbid(unsafe_code)]

use std::sync::Arc;
use velcrux_core::rdma::{
    calculate_icrc, AccessFlags, Aeth, Bth, BthOpcode, CompletionQueue, DcqcnConfig, DcqcnPacer,
    DcqcnStage, ImmDt, MemoryRegion, ProtectionDomain, QpInitAttr, QpState, QpType, QueuePair,
    RdmaTransferEngine, Reth, RocePacket, SendFlags, SendWr, Sge, WcOpcode, WcStatus, WrOpcode,
};

#[test]
fn test_rocev2_bth_reth_aeth_framing_and_icrc() {
    // 1. Construct BTH for RDMA Write Only with Immediate
    let bth = Bth {
        opcode: BthOpcode::RcRdmaWriteOnlyWithImm,
        solicited: true,
        mig_req: false,
        pad_count: 2,
        tver: 0,
        pkey: 0xFFFF,
        dest_qp: 0x123456,
        ack_req: true,
        psn: 0x654321,
    };

    let bth_bytes = bth.serialize();
    assert_eq!(bth_bytes.len(), Bth::LEN);

    let parsed_bth = Bth::parse(&bth_bytes).expect("parse bth");
    assert_eq!(parsed_bth.opcode, BthOpcode::RcRdmaWriteOnlyWithImm);
    assert!(parsed_bth.solicited);
    assert!(!parsed_bth.mig_req);
    assert_eq!(parsed_bth.pad_count, 2);
    assert_eq!(parsed_bth.pkey, 0xFFFF);
    assert_eq!(parsed_bth.dest_qp, 0x123456);
    assert!(parsed_bth.ack_req);
    assert_eq!(parsed_bth.psn, 0x654321);

    // 2. Construct RETH
    let reth = Reth {
        va: 0x7FFF_1234_5678,
        rkey: 0xAABBCCDD,
        dma_len: 2048,
    };
    let reth_bytes = reth.serialize();
    assert_eq!(reth_bytes.len(), Reth::LEN);
    let parsed_reth = Reth::parse(&reth_bytes).expect("parse reth");
    assert_eq!(parsed_reth.va, 0x7FFF_1234_5678);
    assert_eq!(parsed_reth.rkey, 0xAABBCCDD);
    assert_eq!(parsed_reth.dma_len, 2048);

    // 3. Construct Immediate Data Header
    let imm = ImmDt { data: 0xCAFEBABE };
    let imm_bytes = imm.serialize();
    let parsed_imm = ImmDt::parse(&imm_bytes).expect("parse imm");
    assert_eq!(parsed_imm.data, 0xCAFEBABE);

    // 4. Construct AETH
    let aeth = Aeth {
        syndrome: Aeth::SYNDROME_ACK | 0x1F, // ACK with 31 credits
        msn: 42,
    };
    assert!(aeth.is_ack());
    assert!(!aeth.is_rnr());
    let aeth_bytes = aeth.serialize();
    let parsed_aeth = Aeth::parse(&aeth_bytes).expect("parse aeth");
    assert_eq!(parsed_aeth.syndrome, Aeth::SYNDROME_ACK | 0x1F);
    assert_eq!(parsed_aeth.msn, 42);

    // 5. Test complete RocePacket wire serialization and parsing
    let payload = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let packet = RocePacket {
        bth: bth.clone(),
        reth: Some(reth),
        aeth: None,
        imm: Some(imm),
        ieth: None,
        payload: payload.clone(),
        icrc: 0, // Computed on serialization
    };

    let serialized = packet.serialize();
    assert!(serialized.len() >= 12 + 16 + 4 + 6 + 4);

    let parsed_packet = RocePacket::parse(&serialized).expect("parse full roce packet");
    assert_eq!(parsed_packet.bth.dest_qp, 0x123456);
    assert_eq!(parsed_packet.payload, payload);
    assert_eq!(parsed_packet.imm.unwrap().data, 0xCAFEBABE);
    assert_eq!(parsed_packet.reth.unwrap().dma_len, 2048);

    // 6. Test ICRC calculation determinism
    let sample_data = b"RoCEv2 Invariant Transport Data Payload";
    let icrc1 = calculate_icrc(sample_data);
    let icrc2 = calculate_icrc(sample_data);
    assert_eq!(icrc1, icrc2);
    assert_ne!(icrc1, 0);
}

#[test]
fn test_rdma_protection_domain_and_mr_registration() {
    let pd = ProtectionDomain::new();
    assert!(pd.id >= 100);

    let access = AccessFlags::LOCAL_WRITE.union(AccessFlags::REMOTE_WRITE);
    let mr = MemoryRegion::register(&pd, 4096, access);

    assert_eq!(mr.length, 4096);
    assert_eq!(mr.pd_id, pd.id);
    assert!(mr.is_valid());
    assert_ne!(mr.lkey, 0);
    assert_ne!(mr.rkey, 0);

    // Test Local Write and Read
    let test_bytes = b"RDMA Zero-Copy Kernel Bypass Memory Block";
    mr.write(64, test_bytes).expect("write to mr");
    let read_back = mr.read(64, test_bytes.len()).expect("read from mr");
    assert_eq!(read_back, test_bytes);

    // Test Validate Remote Access
    assert!(mr
        .validate_remote_access(mr.rkey, 64, test_bytes.len(), AccessFlags::REMOTE_WRITE)
        .is_ok());

    // Test Key Mismatch
    assert!(mr
        .validate_remote_access(
            mr.rkey + 999,
            64,
            test_bytes.len(),
            AccessFlags::REMOTE_WRITE
        )
        .is_err());

    // Test Access Flag Denied (e.g. requesting REMOTE_READ when only REMOTE_WRITE permitted)
    assert!(mr
        .validate_remote_access(mr.rkey, 64, test_bytes.len(), AccessFlags::REMOTE_READ)
        .is_err());

    // Test Buffer Out of Bounds
    assert!(mr
        .validate_remote_access(mr.rkey, 4000, 200, AccessFlags::REMOTE_WRITE)
        .is_err());

    // Test Deregistration
    mr.deregister();
    assert!(!mr.is_valid());
    assert!(mr.read(0, 10).is_err());
    assert!(mr.write(0, b"data").is_err());
}

#[test]
fn test_verbs_queue_pair_lifecycle_state_machine() {
    let pd = ProtectionDomain::new();
    let cq = Arc::new(CompletionQueue::new(64));

    let qp = QueuePair::new(
        &pd,
        QpInitAttr {
            qp_type: QpType::ReliableConnected,
            sq_capacity: 64,
            rq_capacity: 64,
            send_cq: cq.clone(),
            recv_cq: cq.clone(),
        },
    );

    assert_eq!(*qp.state.read().unwrap(), QpState::Reset);
    assert!(!qp.is_rts());

    // Cannot transition directly from Reset to RTS
    assert!(qp.modify_to_rts(0x100).is_err());

    // Reset -> Init
    qp.modify_to_init().expect("modify to init");
    assert_eq!(*qp.state.read().unwrap(), QpState::Init);

    // Init -> RTR
    qp.modify_to_rtr(0x5000, 0x123).expect("modify to rtr");
    assert_eq!(*qp.state.read().unwrap(), QpState::ReadyToReceive);

    // RTR -> RTS
    qp.modify_to_rts(0x456).expect("modify to rts");
    assert_eq!(*qp.state.read().unwrap(), QpState::ReadyToSend);
    assert!(qp.is_rts());
}

#[test]
fn test_rdma_zero_copy_direct_write_with_immediate() {
    let client_pd = ProtectionDomain::new();
    let server_pd = ProtectionDomain::new();

    let client_cq = Arc::new(CompletionQueue::new(16));
    let server_cq = Arc::new(CompletionQueue::new(16));

    let client_qp = QueuePair::new(
        &client_pd,
        QpInitAttr {
            qp_type: QpType::ReliableConnected,
            sq_capacity: 16,
            rq_capacity: 16,
            send_cq: client_cq.clone(),
            recv_cq: client_cq.clone(),
        },
    );

    let server_qp = QueuePair::new(
        &server_pd,
        QpInitAttr {
            qp_type: QpType::ReliableConnected,
            sq_capacity: 16,
            rq_capacity: 16,
            send_cq: server_cq.clone(),
            recv_cq: server_cq.clone(),
        },
    );

    // Transition both to RTS
    client_qp.modify_to_init().unwrap();
    server_qp.modify_to_init().unwrap();
    client_qp.modify_to_rtr(server_qp.qp_num, 100).unwrap();
    server_qp.modify_to_rtr(client_qp.qp_num, 200).unwrap();
    client_qp.modify_to_rts(200).unwrap();
    server_qp.modify_to_rts(100).unwrap();

    // Setup source and destination Memory Regions
    let source_data = b"High-Bandwidth Zero-Copy RoCEv2 Chunk 0042".to_vec();
    let client_mr = MemoryRegion::register_with_data(
        &client_pd,
        source_data.clone(),
        AccessFlags::LOCAL_WRITE.union(AccessFlags::REMOTE_READ),
    );

    let server_mr = MemoryRegion::register(
        &server_pd,
        1024,
        AccessFlags::LOCAL_WRITE.union(AccessFlags::REMOTE_WRITE),
    );

    // Execute RDMA Write with Immediate
    let wr = SendWr {
        wr_id: 101,
        opcode: WrOpcode::RdmaWriteWithImm,
        send_flags: SendFlags::SIGNALED,
        sg_list: vec![Sge {
            addr: client_mr.addr,
            length: source_data.len() as u32,
            lkey: client_mr.lkey,
        }],
        remote_addr: server_mr.addr + 128,
        rkey: server_mr.rkey,
        imm_data: Some(0xDEADBEEF),
    };

    let send_wc = client_qp
        .execute_rdma_write(&wr, &client_mr, &server_mr, Some(&server_qp))
        .expect("execute rdma write");

    assert_eq!(send_wc.status, WcStatus::Success);
    assert_eq!(send_wc.opcode, WcOpcode::RdmaWrite);
    assert_eq!(send_wc.byte_len, source_data.len() as u32);

    // Verify completion was posted to client Send CQ
    let client_completions = client_cq.poll(10);
    assert_eq!(client_completions.len(), 1);
    assert_eq!(client_completions[0].wr_id, 101);

    // Verify completion was posted to server Receive CQ with immediate data
    let server_completions = server_cq.poll(10);
    assert_eq!(server_completions.len(), 1);
    assert_eq!(server_completions[0].opcode, WcOpcode::RecvImm);
    assert_eq!(server_completions[0].imm_data, Some(0xDEADBEEF));

    // Verify destination memory received exact bytes without CPU copy
    let server_dest_bytes = server_mr.read(128, source_data.len()).unwrap();
    assert_eq!(server_dest_bytes, source_data);
}

#[test]
fn test_rdma_direct_read() {
    let client_pd = ProtectionDomain::new();
    let server_pd = ProtectionDomain::new();

    let cq = Arc::new(CompletionQueue::new(16));

    let qp = QueuePair::new(
        &client_pd,
        QpInitAttr {
            qp_type: QpType::ReliableConnected,
            sq_capacity: 16,
            rq_capacity: 16,
            send_cq: cq.clone(),
            recv_cq: cq.clone(),
        },
    );

    qp.modify_to_init().unwrap();
    qp.modify_to_rtr(0x3000, 100).unwrap();
    qp.modify_to_rts(100).unwrap();

    let server_data = b"Remote Datacenter Memory Content via RDMA Read".to_vec();
    let server_mr = MemoryRegion::register_with_data(
        &server_pd,
        server_data.clone(),
        AccessFlags::LOCAL_WRITE.union(AccessFlags::REMOTE_READ),
    );

    let client_mr = MemoryRegion::register(&client_pd, 256, AccessFlags::LOCAL_WRITE);

    let wr = SendWr {
        wr_id: 202,
        opcode: WrOpcode::RdmaRead,
        send_flags: SendFlags::SIGNALED,
        sg_list: vec![Sge {
            addr: client_mr.addr + 16,
            length: server_data.len() as u32,
            lkey: client_mr.lkey,
        }],
        remote_addr: server_mr.addr,
        rkey: server_mr.rkey,
        imm_data: None,
    };

    let wc = qp
        .execute_rdma_read(&wr, &client_mr, &server_mr)
        .expect("execute rdma read");

    assert_eq!(wc.status, WcStatus::Success);
    assert_eq!(wc.opcode, WcOpcode::RdmaRead);

    let client_read_bytes = client_mr.read(16, server_data.len()).unwrap();
    assert_eq!(client_read_bytes, server_data);
}

#[test]
fn test_dcqcn_congestion_control_and_flow_pacing() {
    let mut config = DcqcnConfig::default();
    config.line_rate_bps = 100_000_000_000 / 8; // 100 Gbps
    config.byte_threshold = 1_000_000; // 1 MB per interval

    let pacer = DcqcnPacer::new(config);
    assert_eq!(pacer.current_rate_gbps().round() as u64, 100);

    // 1. Simulate packet congestion: receive CNP packet
    pacer.on_cnp();
    let report_after_cnp = pacer.report();
    assert_eq!(report_after_cnp.cnp_count, 1);
    assert_eq!(report_after_cnp.stage, DcqcnStage::FastRecovery);
    assert!(report_after_cnp.current_rate_gbps < 100.0);
    assert!(report_after_cnp.alpha > 0.0);

    // 2. Transmit bytes to advance recovery stages
    for _ in 0..10 {
        pacer.on_bytes_transmitted(1024 * 1024);
    }

    let report_after_recovery = pacer.report();
    assert_ne!(report_after_recovery.stage, DcqcnStage::FastRecovery);

    // 3. Record PFC pause frames
    pacer.on_pfc_pause();
    pacer.on_pfc_pause();
    assert_eq!(pacer.report().pfc_pause_count, 2);
}

#[test]
fn test_rdma_transfer_engine_pipelined_benchmark() {
    let engine = RdmaTransferEngine::new();
    assert_eq!(engine.device_attributes().device_name, "mlx5_0");
    assert_eq!(engine.device_attributes().link_layer, "RoCEv2");

    let report = engine
        .run_benchmark(64, 4096, true)
        .expect("run rdma benchmark");

    assert_eq!(report.num_chunks, 64);
    assert_eq!(report.chunk_size_bytes, 4096);
    assert_eq!(report.total_bytes, 64 * 4096);
    assert!(report.zero_copy_verified);
    assert!(report.throughput_mpps > 0.0);
    assert!(report.throughput_gbps > 0.0);
    assert!(report.dcqcn.cnp_count >= 1);
}
