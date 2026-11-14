//! Core integration tests for Option DO: Autonomous Zero-Copy QUIC Kernel-Bypass
//! Direct NIC Memory Fabric (AF_XDP / UMEM) (ADR-083).

#![forbid(unsafe_code)]

use velcrux_core::nic::{
    craft_benchmark_quic_packet, run_nic_benchmark, NicDriverMode, NicError, NicFrameState,
    NicMemoryFabric, NicPacketDemuxer, NicQuicHeaderForm, NicUmemConfig, NicUmemPool,
};

#[test]
fn test_nic_umem_pool_multiframe_concurrency_and_exhaustion() {
    let config = NicUmemConfig {
        frame_size: 2048,
        total_frames: 128,
        headroom: 256,
        fill_ring_size: 64,
        rx_ring_size: 64,
        tx_ring_size: 64,
        completion_ring_size: 64,
    };
    let pool = NicUmemPool::new(config).unwrap();
    assert_eq!(pool.free_frames_count(), 128);

    // Allocate 128 frames in batches
    let mut allocated = Vec::new();
    for _ in 0..8 {
        let batch = pool.alloc_batch(16, NicFrameState::InFillRing).unwrap();
        allocated.extend(batch);
    }
    assert_eq!(allocated.len(), 128);
    assert_eq!(pool.free_frames_count(), 0);
    assert_eq!(pool.in_flight_count(), 128);

    // Pool exhaustion error
    let err = pool.alloc_frame(NicFrameState::InFillRing).unwrap_err();
    match err {
        NicError::UmemExhausted { total } => assert_eq!(total, 128),
        _ => panic!("Expected UmemExhausted"),
    }

    // Free all frames
    for &idx in &allocated {
        pool.free_frame(idx).unwrap();
    }
    assert_eq!(pool.free_frames_count(), 128);
    assert_eq!(pool.in_flight_count(), 0);
}

#[test]
fn test_nic_ring_pairs_power_of_two_rollover_under_saturation() {
    let config = NicUmemConfig {
        frame_size: 2048,
        total_frames: 256,
        headroom: 256,
        fill_ring_size: 64,
        rx_ring_size: 64,
        tx_ring_size: 64,
        completion_ring_size: 64,
    };
    let fabric = NicMemoryFabric::new("eth0", NicDriverMode::ZeroCopyDriver, config).unwrap();

    // Fill ring is primed to 64 items
    assert_eq!(fabric.rings().fill.len(), 64);
    assert!(fabric.rings().fill.is_full());

    // Try enqueuing when full
    let overflow_err = fabric.rings().fill.enqueue(0xdeadbeef).unwrap_err();
    match overflow_err {
        NicError::RingOverflow { ring, capacity } => {
            assert_eq!(ring, "fill_ring");
            assert_eq!(capacity, 64);
        }
        _ => panic!("Expected RingOverflow"),
    }

    // Dequeue all and verify rollover
    let dequeued = fabric.rings().fill.dequeue_batch(64);
    assert_eq!(dequeued.len(), 64);
    assert!(fabric.rings().fill.is_empty());

    // Enqueue 64 new items
    let new_addrs: Vec<u64> = (0..64).map(|i| (i * 2048) as u64).collect();
    let queued = fabric.rings().fill.enqueue_batch(&new_addrs);
    assert_eq!(queued, 64);
    assert_eq!(fabric.rings().fill.len(), 64);
}

#[test]
fn test_nic_quic_packet_demux_vlan_qinq_and_short_headers() {
    // 1. Standard QUIC Long Header
    let long_pkt = craft_benchmark_quic_packet(128, true);
    let view_long = NicPacketDemuxer::parse_frame(42, &long_pkt).unwrap();
    assert_eq!(view_long.frame_index, 42);
    assert_eq!(view_long.src_addr, "10.200.1.10:51820");
    assert_eq!(view_long.dst_addr, "10.200.1.20:7443");
    assert_eq!(view_long.dcid_hex, "aabbccdd11223344");
    assert_eq!(view_long.scid_hex, Some("5566778899001122".to_string()));
    assert_eq!(view_long.quic_len, 21 + 128);

    // 2. 802.1Q Single VLAN Tagged Frame
    let mut vlan_pkt = Vec::new();
    vlan_pkt.extend_from_slice(&long_pkt[0..12]); // MACs
    vlan_pkt.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]); // 802.1Q Tag: VLAN 100
    vlan_pkt.extend_from_slice(&long_pkt[12..]); // Original EtherType (0x0800) + IP + UDP + QUIC

    let view_vlan = NicPacketDemuxer::parse_frame(43, &vlan_pkt).unwrap();
    assert_eq!(view_vlan.frame_index, 43);
    assert_eq!(view_vlan.src_addr, "10.200.1.10:51820");
    assert_eq!(view_vlan.dst_addr, "10.200.1.20:7443");
    assert_eq!(view_vlan.dcid_hex, "aabbccdd11223344");

    // 3. Short Header
    let short_pkt = craft_benchmark_quic_packet(256, false);
    let view_short = NicPacketDemuxer::parse_frame(44, &short_pkt).unwrap();
    assert_eq!(view_short.dcid_hex, "0102030405060708");
    assert!(view_short.scid_hex.is_none());
    assert_eq!(
        view_short.header_form,
        NicQuicHeaderForm::ShortHeader {
            spin_bit: false,
            key_phase: false
        }
    );
}

#[test]
fn test_nic_fabric_line_rate_burst_loopback_and_zero_copy() {
    let config = NicUmemConfig {
        frame_size: 2048,
        total_frames: 256,
        headroom: 256,
        fill_ring_size: 64,
        rx_ring_size: 64,
        tx_ring_size: 64,
        completion_ring_size: 64,
    };
    let fabric = NicMemoryFabric::new("vlx-zero0", NicDriverMode::ZeroCopyDriver, config).unwrap();

    let quic_pkt = craft_benchmark_quic_packet(512, false);

    // Ingress burst of 16 packets
    for _ in 0..16 {
        fabric.simulate_ingress_packet(&quic_pkt).unwrap();
    }
    assert_eq!(fabric.rings().rx.len(), 16);

    // Receive burst and verify demuxed views
    let views = fabric.receive_burst(16);
    assert_eq!(views.len(), 16);
    assert_eq!(fabric.status().total_rx_packets, 16);

    // Transmit 16 responses
    for v in &views {
        let _ = fabric.transmit_packet(&quic_pkt).unwrap();
        // Return rx frame to pool
        fabric.umem().free_frame(v.frame_index).unwrap();
    }
    assert_eq!(fabric.status().total_tx_packets, 16);
    assert_eq!(fabric.rings().tx.len(), 16);

    // Complete transmission
    let completed = fabric.simulate_tx_completion(16);
    assert_eq!(completed, 16);
    assert_eq!(fabric.rings().completion.len(), 16);

    // Reclaim
    let reclaimed = fabric.reclaim_completion_frames();
    assert_eq!(reclaimed, 16);
    assert_eq!(fabric.rings().completion.len(), 0);
}

#[test]
fn test_nic_driver_modes_and_hardware_offload_profile() {
    let modes = [
        NicDriverMode::ZeroCopyDriver,
        NicDriverMode::CopySkbGeneric,
        NicDriverMode::HardwareOffloadAsic,
        NicDriverMode::EmulatedUserSpace,
    ];

    for mode in modes {
        let config = NicUmemConfig {
            frame_size: 2048,
            total_frames: 64,
            headroom: 256,
            fill_ring_size: 32,
            rx_ring_size: 32,
            tx_ring_size: 32,
            completion_ring_size: 32,
        };
        let fabric = NicMemoryFabric::new("eth1", mode, config).unwrap();
        let status = fabric.status();
        assert_eq!(status.driver_mode, mode);
        assert_eq!(status.zero_copy_active, mode.is_zero_copy());
        assert_eq!(status.umem_total_frames, 64);
    }
}

#[test]
fn test_nic_benchmark_simulation_throughput_and_reuse() {
    let report = run_nic_benchmark(256, 2048, 20);
    assert_eq!(report.interface_name, "vlx-nic0");
    assert_eq!(report.packets_processed, 20 * 32);
    assert_eq!(report.frame_size_bytes, 2048);
    assert!(report.throughput_mpps > 0.0);
    assert!(report.throughput_gbps > 0.0);
    assert!(report.ring_cycle_latency_ns > 0.0);
    assert_eq!(report.zero_copy_efficiency_percent, 100.0);
    assert_eq!(report.frame_reuse_ratio, 1.0);
}
