//! Integration Tests for eBPF / XDP Kernel Bypass Acceleration & AF_XDP Multi-Queue Steering (`ADR-066`).
//!
//! Verifies:
//! 1. Canonical eBPF instruction encoding, disassembly, and static verifier passes.
//! 2. In-memory eBPF Virtual Machine (`EbpfVm`) execution of QUIC UDP packet filter bytecode.
//! 3. Wire-speed dual-stack packet dissection (IPv4, IPv6, 802.1Q VLAN, QUIC Long/Short headers).
//! 4. AF_XDP lock-free descriptor ring buffer pairs (Fill, RX, TX, Completion).
//! 5. Multi-queue flow steering (`XskMap`) by QUIC Connection ID across $N$ CPU worker queues.
//! 6. Exact per-connection affinity: identical QUIC DCIDs consistently map to the identical queue.

use std::sync::Arc;

use velcrux_core::xdp::bpf::{
    EbpfInsn, EbpfProgram, EbpfVerifier, EbpfVm, QuicFilterAssembler, XdpMd, BPF_REG_0, BPF_REG_1,
    BPF_REG_10, BPF_REG_2, BPF_SIZE_B,
};
use velcrux_core::xdp::parser::{dissect_packet, QuicHeaderForm, ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use velcrux_core::xdp::ring::XskQueuePair;
use velcrux_core::xdp::steering::{SteeringPolicy, XdpSocketRouter, XskMap};
use velcrux_core::xdp::{UmemConfig, UmemPool, XdpAction, XdpDescriptor};

/// Helper to generate a synthetic IPv4 UDP QUIC packet.
fn build_ipv4_quic_packet(dst_port: u16, dcid: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 14 + 20 + 8 + 1 + dcid.len() + 32];
    // 1. Ethernet (14 bytes)
    pkt[12] = 0x08;
    pkt[13] = 0x00; // IPv4
                    // 2. IPv4 Header (20 bytes)
    pkt[14] = 0x45; // Version 4, IHL 5 (20 bytes)
    pkt[14 + 9] = 17; // UDP
    pkt[14 + 12..14 + 16].copy_from_slice(&[192, 168, 1, 100]); // Src IP
    pkt[14 + 16..14 + 20].copy_from_slice(&[10, 0, 0, 1]); // Dst IP
                                                           // 3. UDP Header (8 bytes)
    pkt[34..36].copy_from_slice(&45678u16.to_be_bytes()); // Src Port
    pkt[36..38].copy_from_slice(&dst_port.to_be_bytes()); // Dst Port
    let udp_len = (8 + 1 + dcid.len() + 32) as u16;
    pkt[38..40].copy_from_slice(&udp_len.to_be_bytes());
    // 4. QUIC Short Header (1-RTT: 0x40 fixed bit set)
    pkt[42] = 0x43;
    pkt[43..43 + dcid.len()].copy_from_slice(dcid);
    pkt
}

/// Helper to generate a synthetic IPv6 UDP QUIC packet.
fn build_ipv6_quic_packet(dst_port: u16, dcid: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 14 + 40 + 8 + 6 + dcid.len() + 32];
    // 1. Ethernet (14 bytes)
    pkt[12] = 0x86;
    pkt[13] = 0xdd; // IPv6
                    // 2. IPv6 Header (40 bytes)
    pkt[14] = 0x60; // Version 6
    let payload_len = (8 + 6 + dcid.len() + 32) as u16;
    pkt[14 + 4..14 + 6].copy_from_slice(&payload_len.to_be_bytes());
    pkt[14 + 6] = 17; // Next Header: UDP
    pkt[14 + 8..14 + 24]
        .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    pkt[14 + 24..14 + 40]
        .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    // 3. UDP Header (8 bytes)
    pkt[54..56].copy_from_slice(&51234u16.to_be_bytes());
    pkt[56..58].copy_from_slice(&dst_port.to_be_bytes());
    pkt[58..60].copy_from_slice(&payload_len.to_be_bytes());
    // 4. QUIC Long Header (Initial: 0x80 | 0x00)
    pkt[62] = 0xc0;
    pkt[63..67].copy_from_slice(&1u32.to_be_bytes()); // Version 1
    pkt[67] = dcid.len() as u8;
    pkt[68..68 + dcid.len()].copy_from_slice(dcid);
    pkt
}

/// Helper to generate an 802.1Q VLAN encapsulated packet.
fn build_vlan_quic_packet(vlan_id: u16, dst_port: u16, dcid: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 18 + 20 + 8 + 1 + dcid.len() + 16];
    // 1. Ethernet with VLAN (18 bytes)
    pkt[12] = 0x81;
    pkt[13] = 0x00; // 802.1Q
    pkt[14..16].copy_from_slice(&(vlan_id & 0x0fff).to_be_bytes());
    pkt[16] = 0x08;
    pkt[17] = 0x00; // Encapsulated IPv4
                    // 2. IPv4 Header
    pkt[18] = 0x45;
    pkt[18 + 9] = 17; // UDP
    pkt[18 + 12..18 + 16].copy_from_slice(&[10, 10, 1, 5]);
    pkt[18 + 16..18 + 20].copy_from_slice(&[10, 10, 1, 1]);
    // 3. UDP Header
    pkt[38..40].copy_from_slice(&33333u16.to_be_bytes());
    pkt[40..42].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + 1 + dcid.len() + 16) as u16;
    pkt[42..44].copy_from_slice(&udp_len.to_be_bytes());
    // 4. QUIC Short Header
    pkt[46] = 0x43;
    pkt[47..47 + dcid.len()].copy_from_slice(dcid);
    pkt
}

#[test]
fn test_ebpf_instruction_encoding_and_disassembly() {
    let mut insns = Vec::new();
    // r1 = 100
    insns.push(EbpfInsn::mov64_imm(BPF_REG_1, 100));
    // r2 = r1
    insns.push(EbpfInsn::mov64_reg(BPF_REG_2, BPF_REG_1));
    // r2 += 42
    insns.push(EbpfInsn::add64_imm(BPF_REG_2, 42));
    // r0 = *(u8 *)(r2 + 0)
    insns.push(EbpfInsn::ldx_mem(BPF_SIZE_B, BPF_REG_0, BPF_REG_2, 0));
    // if r0 == 17 goto +1
    insns.push(EbpfInsn::jeq_imm(BPF_REG_0, 17, 1));
    // r0 = 2 (XDP_PASS)
    insns.push(EbpfInsn::mov64_imm(BPF_REG_0, 2));
    // exit
    insns.push(EbpfInsn::exit());

    let prog = EbpfProgram::new("test_filter", insns);
    let asm = prog.disassemble();

    assert!(asm.contains("r1 = 100"));
    assert!(asm.contains("r2 = r1"));
    assert!(asm.contains("r2 += 42"));
    assert!(asm.contains("r0 = *(u8 *)(r2 + 0)"));
    assert!(asm.contains("if r0 == 17 goto +1"));
    assert!(asm.contains("exit"));
}

#[test]
fn test_ebpf_kernel_verifier_validation() {
    // 1. Valid program must pass verification
    let valid_prog = QuicFilterAssembler::build(7443);
    let report = EbpfVerifier::verify(&valid_prog).expect("verify valid program");
    assert!(report.passed);
    assert_eq!(report.total_instructions, valid_prog.instructions.len());

    // 2. Empty program rejected
    let empty_prog = EbpfProgram::new("empty", vec![]);
    assert!(EbpfVerifier::verify(&empty_prog).is_err());

    // 3. Program without exit instruction rejected
    let no_exit = EbpfProgram::new("no_exit", vec![EbpfInsn::mov64_imm(BPF_REG_0, 1)]);
    assert!(EbpfVerifier::verify(&no_exit).is_err());

    // 4. Modifying R10 (read-only frame pointer) rejected
    let bad_r10 = EbpfProgram::new(
        "bad_r10",
        vec![EbpfInsn::mov64_imm(BPF_REG_10, 0), EbpfInsn::exit()],
    );
    assert!(EbpfVerifier::verify(&bad_r10).is_err());

    // 5. Out-of-bounds jump rejected
    let bad_jmp = EbpfProgram::new(
        "bad_jmp",
        vec![
            EbpfInsn::jeq_imm(BPF_REG_0, 10, 50), // Jumps way past end
            EbpfInsn::exit(),
        ],
    );
    assert!(EbpfVerifier::verify(&bad_jmp).is_err());
}

#[test]
fn test_ebpf_vm_quic_packet_execution() {
    let prog = QuicFilterAssembler::build(7443);
    EbpfVerifier::verify(&prog).expect("verify program");

    // Case 1: Matching QUIC UDP packet on port 7443 -> XdpAction::Redirect
    let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let matching_pkt = build_ipv4_quic_packet(7443, &dcid);
    let ctx = XdpMd {
        data: &matching_pkt,
    };
    let mut vm = EbpfVm::new(&ctx);
    let verdict = vm.execute(&prog).expect("execute matching packet");
    assert_eq!(
        verdict,
        XdpAction::Redirect,
        "matching port 7443 must be redirected"
    );

    // Case 2: Non-matching UDP packet on port 80 -> XdpAction::Pass
    let non_matching_pkt = build_ipv4_quic_packet(80, &dcid);
    let ctx = XdpMd {
        data: &non_matching_pkt,
    };
    let mut vm = EbpfVm::new(&ctx);
    let verdict = vm.execute(&prog).expect("execute non-matching packet");
    assert_eq!(
        verdict,
        XdpAction::Pass,
        "non-target port must pass to kernel"
    );

    // Case 3: Truncated frame (< 42 bytes) -> XdpAction::Pass
    let truncated_pkt = vec![0u8; 30];
    let ctx = XdpMd {
        data: &truncated_pkt,
    };
    let mut vm = EbpfVm::new(&ctx);
    let verdict = vm.execute(&prog).expect("execute truncated frame");
    assert_eq!(
        verdict,
        XdpAction::Pass,
        "truncated frame must pass to kernel safely"
    );
}

#[test]
fn test_wire_speed_dual_stack_packet_dissection() {
    let dcid = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];

    // 1. IPv4 QUIC Short Header
    let ipv4_pkt = build_ipv4_quic_packet(7443, &dcid);
    let d1 = dissect_packet(&ipv4_pkt).expect("dissect ipv4");
    assert_eq!(d1.ethertype, ETHERTYPE_IPV4);
    assert!(!d1.is_ipv6);
    assert_eq!(d1.src_ip, "192.168.1.100");
    assert_eq!(d1.dst_ip, "10.0.0.1");
    assert_eq!(d1.dst_port, 7443);
    assert!(d1.is_quic);
    assert_eq!(d1.quic_header_form, Some(QuicHeaderForm::Short));
    assert_eq!(d1.quic_dcid.as_deref(), Some("aabbccdd11223344"));

    // 2. IPv6 QUIC Long Header
    let ipv6_pkt = build_ipv6_quic_packet(7443, &dcid);
    let d2 = dissect_packet(&ipv6_pkt).expect("dissect ipv6");
    assert_eq!(d2.ethertype, ETHERTYPE_IPV6);
    assert!(d2.is_ipv6);
    assert!(d2.src_ip.contains("2001:db8:"));
    assert_eq!(d2.dst_port, 7443);
    assert!(d2.is_quic);
    assert_eq!(d2.quic_header_form, Some(QuicHeaderForm::Long));
    assert_eq!(d2.quic_version, Some(1));
    assert_eq!(d2.quic_dcid.as_deref(), Some("aabbccdd11223344"));

    // 3. 802.1Q VLAN Tagged Packet
    let vlan_pkt = build_vlan_quic_packet(2048, 7443, &dcid);
    let d3 = dissect_packet(&vlan_pkt).expect("dissect vlan");
    assert_eq!(d3.vlan_id, Some(2048 & 0x0fff));
    assert_eq!(d3.dst_port, 7443);
    assert!(d3.is_quic);
    assert_eq!(d3.quic_dcid.as_deref(), Some("aabbccdd11223344"));
}

#[test]
fn test_af_xdp_lock_free_multi_queue_ring_pairs() {
    let qp = XskQueuePair::new(0, 64);

    // 1. Fill ring operations
    assert_eq!(qp.fill_ring.len(), 0);
    assert!(qp.fill_ring.is_empty());
    assert_eq!(qp.fill_ring.capacity(), 64);

    let addrs: Vec<u64> = (0..32).map(|i| i * 2048).collect();
    let produced = qp.fill_ring.produce_batch(&addrs);
    assert_eq!(produced, 32);
    assert_eq!(qp.fill_ring.len(), 32);

    let consumed = qp.fill_ring.consume_batch(16);
    assert_eq!(consumed.len(), 16);
    assert_eq!(qp.fill_ring.len(), 16);

    // 2. RX ring descriptor delivery
    for i in 0..10 {
        let desc = XdpDescriptor {
            addr: i * 2048,
            len: 1200,
            flags: 0,
        };
        assert!(qp.deliver_rx(desc));
    }
    assert_eq!(qp.rx_ring.len(), 10);
    assert_eq!(qp.rx_packets.load(std::sync::atomic::Ordering::Relaxed), 10);
    assert_eq!(
        qp.rx_bytes.load(std::sync::atomic::Ordering::Relaxed),
        12000
    );

    let polled = qp.poll_rx(5);
    assert_eq!(polled.len(), 5);
    assert_eq!(qp.rx_ring.len(), 5);

    let stats = qp.stats();
    assert_eq!(stats.queue_id, 0);
    assert_eq!(stats.rx_packets, 10);
    assert_eq!(stats.rx_bytes, 12000);
}

#[test]
fn test_af_xdp_multi_queue_steering_cid_hash_balance() {
    // 8 hardware queues
    let xsk_map = Arc::new(XskMap::new(8, 512));
    assert_eq!(xsk_map.queue_count(), 8);

    let umem_cfg = UmemConfig {
        frame_size: 2048,
        frame_count: 4096,
        ..Default::default()
    };
    let umem = Arc::new(UmemPool::new(umem_cfg));
    let router = XdpSocketRouter::new(SteeringPolicy::CidHash, xsk_map.clone(), umem);

    // Steer 1,600 packets across 8 queues with diverse CIDs
    let mut cid_to_queue_map = std::collections::HashMap::new();

    for i in 0..1600u64 {
        // Diverse 8-byte DCID
        let dcid = i.wrapping_mul(0x517cc1b727220a95).to_be_bytes();
        let raw = build_ipv4_quic_packet(7443, &dcid);
        let parsed = dissect_packet(&raw).expect("dissect packet");

        let (action, qid) = router.steer_packet(&parsed, 7443).expect("steer packet");
        assert_eq!(action, XdpAction::Redirect);
        let queue = qid.expect("must return assigned queue");
        assert!(queue < 8);

        // Record for connection consistency verification
        cid_to_queue_map.insert(dcid, queue);
    }

    let report = router.report();
    assert_eq!(report.total_steered, 1600);
    assert_eq!(report.total_dropped, 0);

    // Verify all 8 queues received packets and load is balanced (expected ~200 per queue)
    for q in &report.queues {
        assert!(
            q.rx_packets >= 120 && q.rx_packets <= 280,
            "queue {} count {} should be well balanced around 200",
            q.queue_id,
            q.rx_packets
        );
    }

    // Crucial Invariant: Re-sending identical CIDs must always steer to the exact same queue
    for (dcid, expected_q) in cid_to_queue_map.iter().take(100) {
        let raw = build_ipv4_quic_packet(7443, dcid);
        let parsed = dissect_packet(&raw).expect("dissect packet");
        let (_action, qid) = router.steer_packet(&parsed, 7443).expect("re-steer");
        assert_eq!(
            qid,
            Some(*expected_q),
            "CID must consistently map to the identical queue"
        );
    }
}
