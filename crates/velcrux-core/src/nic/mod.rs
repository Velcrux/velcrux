//! Autonomous Zero-Copy QUIC Kernel-Bypass Direct NIC Memory Fabric (AF_XDP / UMEM) (ADR-083).
//!
//! Provides ultra-low-latency, zero-copy packet bypassing directly into user-space
//! UMEM memory pools, lockless AF_XDP descriptor ring pairs (Fill, Rx, Tx, Completion),
//! wire-speed L2-L7 QUIC connection ID classification, and SmartNIC/FPGA hardware offloading.

#![forbid(unsafe_code)]

pub mod benchmark;
pub mod demux;
pub mod fabric;
pub mod rings;
pub mod types;
pub mod umem;

pub use benchmark::{craft_benchmark_quic_packet, run_nic_benchmark};
pub use demux::NicPacketDemuxer;
pub use fabric::NicMemoryFabric;
pub use rings::{
    NicCircularRing, NicCompletionRing, NicFillRing, NicRingSet, NicRxRing, NicTxRing,
};
pub use types::{
    NicBenchmarkReport, NicDriverMode, NicError, NicFrameState, NicPacketDescriptor,
    NicQuicHeaderForm, NicQuicPacketView, NicResult, NicRingStats, NicStatus, NicUmemConfig,
    NIC_DEFAULT_FRAME_SIZE, NIC_DEFAULT_HEADROOM, NIC_DEFAULT_RING_SIZE, NIC_DEFAULT_TOTAL_FRAMES,
};
pub use umem::{NicFrameMetadata, NicUmemPool};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nic_umem_allocation_and_bounds() {
        let config = NicUmemConfig {
            frame_size: 2048,
            total_frames: 64,
            headroom: 256,
            fill_ring_size: 32,
            rx_ring_size: 32,
            tx_ring_size: 32,
            completion_ring_size: 32,
        };
        let pool = NicUmemPool::new(config).unwrap();
        assert_eq!(pool.total_bytes(), 64 * 2048);
        assert_eq!(pool.free_frames_count(), 64);
        assert_eq!(pool.in_flight_count(), 0);

        // Allocate batch of 10 frames
        let batch = pool.alloc_batch(10, NicFrameState::InFillRing).unwrap();
        assert_eq!(batch.len(), 10);
        assert_eq!(pool.free_frames_count(), 54);
        assert_eq!(pool.in_flight_count(), 10);

        // Write and read packet
        let payload = b"Hello, AF_XDP direct UMEM zero-copy!";
        let written = pool.write_packet(batch[0], payload).unwrap();
        assert_eq!(written, payload.len());

        let read_back = pool.read_packet(batch[0]).unwrap();
        assert_eq!(read_back, payload);

        // Free the frame
        pool.free_frame(batch[0]).unwrap();
        assert_eq!(pool.free_frames_count(), 55);
        assert_eq!(pool.in_flight_count(), 9);
    }

    #[test]
    fn test_nic_circular_rings_wrap_around_and_batch() {
        let ring = NicCircularRing::<u64>::new("test_ring", 16);
        assert_eq!(ring.capacity(), 16);
        assert!(ring.is_empty());

        let items: Vec<u64> = (1..=12).collect();
        let enqueued = ring.enqueue_batch(&items);
        assert_eq!(enqueued, 12);
        assert_eq!(ring.len(), 12);

        // Dequeue batch of 8
        let dequeued = ring.dequeue_batch(8);
        assert_eq!(dequeued.len(), 8);
        assert_eq!(dequeued[0], 1);
        assert_eq!(dequeued[7], 8);
        assert_eq!(ring.len(), 4);

        // Enqueue 10 more (should wrap around circular power-of-two buffer)
        let items_more: Vec<u64> = (100..110).collect();
        let enqueued2 = ring.enqueue_batch(&items_more);
        assert_eq!(enqueued2, 10);
        assert_eq!(ring.len(), 14);

        let dequeued_all = ring.dequeue_batch(16);
        assert_eq!(dequeued_all.len(), 14);
        assert_eq!(dequeued_all[0], 9);
        assert_eq!(dequeued_all[4], 100);
        assert!(ring.is_empty());
    }

    #[test]
    fn test_nic_quic_packet_demuxing_long_and_short_headers() {
        // 1. Long Header
        let long_pkt = craft_benchmark_quic_packet(64, true);
        let view_long = NicPacketDemuxer::parse_frame(0, &long_pkt).unwrap();
        assert_eq!(view_long.src_addr, "10.200.1.10:51820");
        assert_eq!(view_long.dst_addr, "10.200.1.20:7443");
        assert_eq!(view_long.dcid_hex, "aabbccdd11223344");
        assert_eq!(view_long.scid_hex, Some("5566778899001122".to_string()));
        match view_long.header_form {
            NicQuicHeaderForm::LongHeader { version, .. } => {
                assert_eq!(version, 1);
            }
            _ => panic!("Expected LongHeader"),
        }

        // 2. Short Header
        let short_pkt = craft_benchmark_quic_packet(128, false);
        let view_short = NicPacketDemuxer::parse_frame(1, &short_pkt).unwrap();
        assert_eq!(view_short.dcid_hex, "0102030405060708");
        assert_eq!(view_short.scid_hex, None);
        match view_short.header_form {
            NicQuicHeaderForm::ShortHeader {
                spin_bit,
                key_phase,
            } => {
                assert!(!spin_bit);
                assert!(!key_phase);
            }
            _ => panic!("Expected ShortHeader"),
        }
    }

    #[test]
    fn test_nic_fabric_replenish_and_reclaim_lifecycle() {
        let config = NicUmemConfig {
            frame_size: 2048,
            total_frames: 64,
            headroom: 256,
            fill_ring_size: 32,
            rx_ring_size: 32,
            tx_ring_size: 32,
            completion_ring_size: 32,
        };
        let fabric = NicMemoryFabric::new("vlx0", NicDriverMode::ZeroCopyDriver, config).unwrap();
        assert_eq!(fabric.interface_name(), "vlx0");
        assert!(fabric.driver_mode().is_zero_copy());

        let status = fabric.status();
        assert!(status.fill_ring_count > 0);
        assert_eq!(status.tx_ring_count, 0);

        // Transmit packet
        let tx_data = b"QUIC frame out";
        let frame_tx = fabric.transmit_packet(tx_data).unwrap();
        assert_eq!(fabric.status().tx_ring_count, 1);

        // Simulate Tx completion
        let completed = fabric.simulate_tx_completion(1);
        assert_eq!(completed, 1);
        assert_eq!(fabric.status().completion_ring_count, 1);

        // Reclaim
        let reclaimed = fabric.reclaim_completion_frames();
        assert_eq!(reclaimed, 1);
        assert_eq!(fabric.status().completion_ring_count, 0);
        assert_eq!(
            fabric.umem().frame_state(frame_tx).unwrap(),
            NicFrameState::Free
        );
    }

    #[test]
    fn test_nic_end_to_end_ingress_demux_and_tx_loopback() {
        let config = NicUmemConfig {
            frame_size: 2048,
            total_frames: 64,
            headroom: 256,
            fill_ring_size: 32,
            rx_ring_size: 32,
            tx_ring_size: 32,
            completion_ring_size: 32,
        };
        let fabric = NicMemoryFabric::new("vlx0", NicDriverMode::ZeroCopyDriver, config).unwrap();

        let raw_quic = craft_benchmark_quic_packet(256, true);
        fabric.simulate_ingress_packet(&raw_quic).unwrap();

        let views = fabric.receive_burst(10);
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].dst_addr, "10.200.1.20:7443");
        assert_eq!(views[0].dcid_hex, "aabbccdd11223344");

        // Clean up received frame
        fabric.umem().free_frame(views[0].frame_index).unwrap();
    }

    #[test]
    fn test_nic_benchmark_execution() {
        let report = run_nic_benchmark(128, 2048, 10);
        assert_eq!(report.interface_name, "vlx-nic0");
        assert_eq!(report.packets_processed, 10 * 32);
        assert!(report.throughput_mpps > 0.0);
        assert!(report.throughput_gbps > 0.0);
        assert_eq!(report.zero_copy_efficiency_percent, 100.0);
        assert_eq!(report.frame_reuse_ratio, 1.0);
    }
}
